"""C10 — supervision: the optional Supervision Profile (§6.1).

Spec: aicash-spec-v0.4.md §5.2, §5.3, §6.1, §7.3 (custodial rules), §8(c).
Locked: L13 (controls bind only operator-registered custodial agents; Layer 0
stays authless and un-capped), L17 (per-principal random bearer API keys,
injected clock, Ed25519 statement signatures). Depends: C04 (ledgerstore),
C05 (signing), C06 (mintapi — this module mounts routes onto a C06 server).

Design notes
------------
* All supervision state lives in the mint's sqlite database (C10-owned
  ``sup_*`` tables, never touching C04's or C06's), via a dedicated
  connection guarded by one lock — the same shared-file discipline C06 uses.
* The custodial/ledger bridge (§5.3): a deposit is a REAL C04 exchange
  spending the presented bearer tokens into a mint-custody entry (a by-hash
  output whose secret the mint itself generated and holds in ``sup_custody``);
  a withdrawal is a C04 exchange spending mint-custody entries into the
  CALLER-specified by-hash outputs (the mint never sees the new secrets) plus
  a change output back into custody. Invariant maintained by construction:
  ``sum(unspent custody) == sum(agent balances) - sup_mint.absorbed_mc``
  (the ledger-level burn the mint has absorbed under §7.3/R17).
* Custodial transfers and pulls never touch C04 and never burn (§7.3).
  Deposits/withdrawals burn exactly as the exchange calls they are; the
  withdrawal's full gross debit (amount + burn) counts against caps.
* Withdrawal burn attribution (§7.3, pinned by resolution R17 in
  OPEN-QUESTIONS.md): the agent is charged ``compute_burn(amount_withdrawn)``
  on the REQUESTED amount, never on the mint's internally selected custody
  inputs. The exchange itself still burns per L12 on its actual inputs; the
  difference (>= 0, since the selected inputs always cover the request and
  ``compute_burn`` is monotone) comes out of the mint's custody pool and is
  tracked in ``sup_mint.absorbed_mc``. Deposits are symmetric and unchanged:
  the agent is charged the burn on the deposited tokens' sum, which it
  controls.
* Persist-before-send (§5.1, mandatory; §5.3 "no exceptions" for
  withdrawals): the supervision core IS the wallet for custody money, so
  every secret it generates (deposit custody secret, withdrawal change
  secret) is committed to ``sup_custody`` in a ``pending`` state — together
  with a ``sup_pending_ops`` staging record describing the follow-up work —
  BEFORE ``ledger.exchange`` is called. On success the staged op is
  finalized (activate pending outputs, mark inputs spent, adjust balance,
  journal lines); on ``ExchangeRejected`` it is discarded. A crash between
  the exchange commit and the finalize commit is reconciled at startup by
  probing ``/v3/status`` for whether the staged exchange committed, then
  rolling the op forward or back. Custody inputs selected for an in-flight
  withdrawal are marked ``reserved`` so a crashed withdrawal can never
  wedge the selector on ledger-spent rows.
* Caps (§6.1(2)): trailing 3_600s / 86_400s rolling windows over the
  debit-like statement lines, evaluated at debit commit with the injected
  mint clock; ``absolute`` is the lifetime debit total. A line aged exactly
  window ms no longer counts (strict ``t > now - window``).
* Statement (§6.1(7)): built from the ``sup_lines`` journal, pinned schema,
  signed with the mint key over canonical JSON (C05). Generation enforces
  the balance invariant: the journal-derived balance must equal both the
  stored balance and ``closing - opening``; a mismatch is a 500, never a
  silently wrong statement.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import sqlite3
import threading
import urllib.parse

from aicash.burncalc import compute_burn
from aicash.ledgerstore import ExchangeRejected, Ledger, OutputSpec
from aicash.lockeval import InputForm
from aicash.mintapi import MintConfig, MintServer, _Handler, _MintHTTPServer
from aicash.signing import attach_sig
from aicash.tokencodec import (
    Token,
    TokenError,
    b64u_decode,
    b64u_encode,
    ledger_key,
    new_secret,
    parse_token,
)

__all__ = ["SupervisionServer"]

HOUR_MS = 3_600_000
DAY_MS = 86_400_000

#: §6.1(7) pinned kind partition. freeze/unfreeze are amount-0 events,
#: excluded from both sums (and from cap windows, which sum debit-like only).
DEBIT_KINDS = ("debit", "pull_out", "withdrawal", "burn")
CREDIT_KINDS = ("credit", "pull_in", "deposit", "issuance")

_DEBIT_SQL = "('debit','pull_out','withdrawal','burn')"
_CREDIT_SQL = "('credit','pull_in','deposit','issuance')"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sup_operators (
  operator_id TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  key_sha256  TEXT NOT NULL UNIQUE,
  created_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sup_agents (
  agent_id             TEXT PRIMARY KEY,
  operator_id          TEXT NOT NULL,
  name                 TEXT NOT NULL,
  key_sha256           TEXT NOT NULL UNIQUE,
  balance_mc           INTEGER NOT NULL DEFAULT 0,
  frozen               INTEGER NOT NULL DEFAULT 0,
  no_bearer_withdrawal INTEGER NOT NULL DEFAULT 0,
  cap_per_hour_mc      INTEGER,
  cap_per_day_mc       INTEGER,
  cap_absolute_mc      INTEGER,
  created_at           INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sup_lines (
  seq                  INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_id             TEXT NOT NULL,
  t                    INTEGER NOT NULL,
  kind                 TEXT NOT NULL,
  amount_mc            INTEGER NOT NULL,
  counterparty_account TEXT,
  ref                  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS sup_lines_agent_t ON sup_lines (agent_id, t);
CREATE TABLE IF NOT EXISTS sup_pull_auths (
  auth_id           TEXT PRIMARY KEY,
  granting_agent_id TEXT NOT NULL,
  payee_account     TEXT NOT NULL,
  cap_mc_per_day    INTEGER NOT NULL,
  expires_at        INTEGER NOT NULL,
  revoked           INTEGER NOT NULL DEFAULT 0,
  created_at        INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sup_pull_uses (
  seq       INTEGER PRIMARY KEY AUTOINCREMENT,
  auth_id   TEXT NOT NULL,
  t         INTEGER NOT NULL,
  amount_mc INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sup_custody (
  hash        TEXT PRIMARY KEY,
  secret_b64u TEXT NOT NULL,
  amount_mc   INTEGER NOT NULL,
  -- 'pending'  : secret persisted, creating exchange not yet known committed
  -- 'unspent'  : active custody money
  -- 'reserved' : selected as input by an in-flight withdrawal
  -- 'spent'    : consumed by a committed withdrawal exchange
  state       TEXT NOT NULL DEFAULT 'unspent'
);
CREATE TABLE IF NOT EXISTS sup_pending_ops (
  op_id        TEXT PRIMARY KEY,
  kind         TEXT NOT NULL,   -- 'deposit' | 'withdraw'
  agent_id     TEXT NOT NULL,
  probe_hash   TEXT NOT NULL,   -- ledger hash whose state reveals commit
  details_json TEXT NOT NULL    -- everything the finalize/unwind needs
);
-- §7.3/R17 mint-side accounting: cumulative ledger-level withdrawal burn
-- the mint has absorbed (ledger burn on custody inputs minus the
-- agent-charged burn on the requested amount). One row, id = 1.
-- Invariant: sum(unspent custody) == sum(agent balances) - absorbed_mc.
CREATE TABLE IF NOT EXISTS sup_mint (
  id          INTEGER PRIMARY KEY CHECK (id = 1),
  absorbed_mc INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO sup_mint (id, absorbed_mc) VALUES (1, 0);
"""

_AGENT_COLS = (
    "agent_id",
    "operator_id",
    "name",
    "balance_mc",
    "frozen",
    "no_bearer_withdrawal",
    "cap_per_hour_mc",
    "cap_per_day_mc",
    "cap_absolute_mc",
)
_AGENT_SELECT = "SELECT %s FROM sup_agents" % ", ".join(_AGENT_COLS)


def _rejected(reason: str) -> tuple[int, dict]:
    return 400, {"status": "rejected", "reason": reason}


def _unknown_agent() -> tuple[int, dict]:
    # A missing agent and another operator's agent answer identically
    # (no cross-operator existence oracle).
    return 404, {"status": "rejected", "reason": "unknown_agent"}


def _plain_int(v: object) -> bool:
    return type(v) is int  # bool is excluded: type(True) is bool


def _new_id(prefix: str) -> str:
    return prefix + "-" + b64u_encode(os.urandom(9))


def _new_key() -> str:
    # Per-principal random bearer API key (L17 / OPEN-QUESTIONS #5).
    return b64u_encode(os.urandom(32))


def _key_digest(key: str) -> str:
    """sha256 of a bearer API key. Keys are stored and looked up ONLY by
    digest: the database never holds a raw key, and the B-tree equality
    probe compares digests — matching-prefix timing on the digest reveals
    nothing about the key itself."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


#: (method, path) -> (required role, handler method name).
#: role "none" = authless (test bootstrap); "either" = agent or operator.
_ROUTES = {
    ("POST", "/v3/operator/register"): ("none", "op_register"),
    ("POST", "/v3/operator/agents"): ("operator", "op_agents"),
    ("POST", "/v3/operator/caps"): ("operator", "op_caps"),
    ("POST", "/v3/operator/freeze"): ("operator", "op_freeze"),
    ("POST", "/v3/operator/unfreeze"): ("operator", "op_unfreeze"),
    ("POST", "/v3/operator/flags"): ("operator", "op_flags"),
    ("GET", "/v3/operator/statement"): ("operator", "op_statement"),
    ("GET", "/v3/agent/balance"): ("either", "agent_balance"),
    ("POST", "/v3/agent/authorize_pull"): ("agent", "agent_authorize_pull"),
    ("POST", "/v3/agent/revoke_pull"): ("agent", "agent_revoke_pull"),
    ("POST", "/v3/pull"): ("agent", "agent_pull"),
    ("POST", "/v3/agent/transfer"): ("agent", "agent_transfer"),
    ("POST", "/v3/agent/deposit"): ("agent", "agent_deposit"),
    ("POST", "/v3/agent/withdraw"): ("agent", "agent_withdraw"),
}


class _SupCore:
    """Supervision Profile state + route logic on the mint's sqlite."""

    def __init__(self, config: MintConfig, ledger: Ledger):
        self.config = config
        self.ledger = ledger
        self._lock = threading.RLock()
        # Same shared-database discipline as C06's _Core (private-attribute
        # access recorded in C06's build notes; C10 follows it).
        self._conn = sqlite3.connect(
            ledger._db_path,
            timeout=30.0,
            isolation_level=None,  # manual txn control
            check_same_thread=False,  # guarded by self._lock
        )
        self._conn.executescript(_SCHEMA)
        with self._lock:
            self._recover_pending()

    # -- plumbing ---------------------------------------------------------

    def _now(self) -> int:
        # The injected mint clock, observed through C04's public API (L17).
        return self.ledger.status([])[0]

    def _txn(self):
        self._conn.execute("BEGIN IMMEDIATE")

    def _commit(self):
        self._conn.execute("COMMIT")

    def _rollback(self):
        self._conn.execute("ROLLBACK")

    def _principal(self, auth_header: object):
        """Resolve a bearer API key to ('operator'|'agent', id) or None."""
        if not isinstance(auth_header, str) or not auth_header.startswith(
            "Bearer "
        ):
            return None
        digest = _key_digest(auth_header[len("Bearer "):])
        row = self._conn.execute(
            "SELECT operator_id FROM sup_operators WHERE key_sha256 = ?",
            (digest,),
        ).fetchone()
        if row is not None:
            return ("operator", row[0])
        row = self._conn.execute(
            "SELECT agent_id FROM sup_agents WHERE key_sha256 = ?", (digest,)
        ).fetchone()
        if row is not None:
            return ("agent", row[0])
        return None

    def dispatch(self, method, path, body, body_ok, auth_header, params):
        """Auth (§6.1(1)) then route. 401 = no/unknown key on an authed
        route; 403 = a valid key of the wrong role. Auth is decided before
        body validation so the B8 matrix is exact."""
        role_req, fn_name = _ROUTES[(method, path)]
        with self._lock:
            principal = self._principal(auth_header)
            if role_req != "none":
                if principal is None:
                    return 401, {"status": "unauthorized"}
                if role_req in ("operator", "agent") and principal[0] != role_req:
                    return 403, {"status": "forbidden"}
            if method == "POST" and (not body_ok or not isinstance(body, dict)):
                return _rejected("bad_format")
            return getattr(self, fn_name)(principal, body, params)

    # -- row helpers ------------------------------------------------------

    def _agent(self, agent_id: object) -> dict | None:
        if not isinstance(agent_id, str):
            return None
        row = self._conn.execute(
            _AGENT_SELECT + " WHERE agent_id = ?", (agent_id,)
        ).fetchone()
        if row is None:
            return None
        return dict(zip(_AGENT_COLS, row))

    def _add_line(self, agent_id, t, kind, amount_mc, counterparty, ref):
        self._conn.execute(
            "INSERT INTO sup_lines (agent_id, t, kind, amount_mc,"
            " counterparty_account, ref) VALUES (?, ?, ?, ?, ?, ?)",
            (agent_id, t, kind, amount_mc, counterparty, ref),
        )

    def _debits_since(self, agent_id: str, since: int) -> int:
        """Sum of debit-like lines strictly newer than ``since`` (trailing
        window: a line aged exactly the window no longer counts)."""
        return self._conn.execute(
            "SELECT COALESCE(SUM(amount_mc), 0) FROM sup_lines"
            f" WHERE agent_id = ? AND t > ? AND kind IN {_DEBIT_SQL}",
            (agent_id, since),
        ).fetchone()[0]

    def _debits_lifetime(self, agent_id: str) -> int:
        return self._conn.execute(
            "SELECT COALESCE(SUM(amount_mc), 0) FROM sup_lines"
            f" WHERE agent_id = ? AND kind IN {_DEBIT_SQL}",
            (agent_id,),
        ).fetchone()[0]

    def _cap_violation(self, agent: dict, gross_mc: int, now: int) -> bool:
        """True iff adding a gross debit of ``gross_mc`` at ``now`` would
        exceed any configured cap (§6.1(2): trailing 3600s/86400s windows,
        absolute = lifetime)."""
        aid = agent["agent_id"]
        for cap, window in (
            (agent["cap_per_hour_mc"], HOUR_MS),
            (agent["cap_per_day_mc"], DAY_MS),
        ):
            if cap is not None and self._debits_since(aid, now - window) + gross_mc > cap:
                return True
        cap = agent["cap_absolute_mc"]
        if cap is not None and self._debits_lifetime(aid) + gross_mc > cap:
            return True
        return False

    def _balance_from_lines(self, agent_ids, t_before=None, t_through=None):
        """Journal-derived balance: sum(credit-like) - sum(debit-like) over
        the given agents, restricted to t < t_before or t <= t_through."""
        marks = ",".join("?" for _ in agent_ids)
        cond, args = "", list(agent_ids)
        if t_before is not None:
            cond, args = " AND t < ?", args + [t_before]
        elif t_through is not None:
            cond, args = " AND t <= ?", args + [t_through]
        row = self._conn.execute(
            f"SELECT COALESCE(SUM(CASE WHEN kind IN {_CREDIT_SQL} THEN amount_mc"
            f" WHEN kind IN {_DEBIT_SQL} THEN -amount_mc ELSE 0 END), 0)"
            f" FROM sup_lines WHERE agent_id IN ({marks})" + cond,
            args,
        ).fetchone()
        return row[0]

    # -- operator routes --------------------------------------------------

    def op_register(self, principal, body, params):
        """POST /v3/operator/register — authless test bootstrap (C10 API)."""
        name = body.get("operator_name")
        if not isinstance(name, str) or not name:
            return _rejected("bad_format")
        operator_id, key = _new_id("op"), _new_key()
        self._txn()
        try:
            self._conn.execute(
                "INSERT INTO sup_operators (operator_id, name, key_sha256,"
                " created_at) VALUES (?, ?, ?, ?)",
                (operator_id, name, _key_digest(key), self._now()),
            )
            self._commit()
        except BaseException:
            self._rollback()
            raise
        return 200, {
            "status": "ok",
            "operator_id": operator_id,
            "operator_key": key,
        }

    def op_agents(self, principal, body, params):
        name = body.get("agent_name")
        if not isinstance(name, str) or not name:
            return _rejected("bad_format")
        agent_id, key = _new_id("ag"), _new_key()
        self._txn()
        try:
            self._conn.execute(
                "INSERT INTO sup_agents (agent_id, operator_id, name,"
                " key_sha256, created_at) VALUES (?, ?, ?, ?, ?)",
                (agent_id, principal[1], name, _key_digest(key), self._now()),
            )
            self._commit()
        except BaseException:
            self._rollback()
            raise
        return 200, {"status": "ok", "agent_id": agent_id, "agent_key": key}

    def _operator_agent(self, principal, agent_id):
        agent = self._agent(agent_id)
        if agent is None or agent["operator_id"] != principal[1]:
            return None
        return agent

    def op_caps(self, principal, body, params):
        agent = self._operator_agent(principal, body.get("agent_id"))
        if agent is None:
            return _unknown_agent()
        caps = {}
        for field in ("per_hour_mc", "per_day_mc", "absolute_mc"):
            v = body.get(field)  # absent and explicit null both mean no cap
            if v is not None and (not _plain_int(v) or v < 0):
                return _rejected("bad_format")
            caps[field] = v
        self._txn()
        try:
            self._conn.execute(
                "UPDATE sup_agents SET cap_per_hour_mc = ?, cap_per_day_mc = ?,"
                " cap_absolute_mc = ? WHERE agent_id = ?",
                (
                    caps["per_hour_mc"],
                    caps["per_day_mc"],
                    caps["absolute_mc"],
                    agent["agent_id"],
                ),
            )
            self._commit()
        except BaseException:
            self._rollback()
            raise
        return 200, {"status": "ok", "agent_id": agent["agent_id"], "caps": caps}

    def _set_frozen(self, principal, body, frozen: bool):
        target = body.get("agent_id")
        if target == "ALL":
            rows = self._conn.execute(
                "SELECT agent_id, frozen FROM sup_agents WHERE operator_id = ?"
                " ORDER BY agent_id",
                (principal[1],),
            ).fetchall()
        else:
            agent = self._operator_agent(principal, target)
            if agent is None:
                return _unknown_agent()
            rows = [(agent["agent_id"], agent["frozen"])]
        now = self._now()
        kind = "freeze" if frozen else "unfreeze"
        # Response field: 'frozen' / 'unfrozen' (pre-1.0 wire fix: the
        # field was originally misspelled 'freezed'/'unfreezed'; renamed
        # before any external caller could depend on it — see
        # components/C10-supervision.md). The journal *kind* strings
        # ('freeze'/'unfreeze') are §6.1(7)-pinned and unchanged.
        field = "frozen" if frozen else "unfrozen"
        changed = []
        self._txn()
        try:
            for agent_id, was in rows:
                if bool(was) == frozen:
                    continue  # idempotent: no duplicate journal events
                self._conn.execute(
                    "UPDATE sup_agents SET frozen = ? WHERE agent_id = ?",
                    (1 if frozen else 0, agent_id),
                )
                # §6.1(7): freeze/unfreeze are amount-0 non-monetary lines.
                self._add_line(agent_id, now, kind, 0, None, "")
                changed.append(agent_id)
            self._commit()
        except BaseException:
            self._rollback()
            raise
        return 200, {"status": "ok", field: changed}

    def op_freeze(self, principal, body, params):
        return self._set_frozen(principal, body, True)

    def op_unfreeze(self, principal, body, params):
        return self._set_frozen(principal, body, False)

    def op_flags(self, principal, body, params):
        agent = self._operator_agent(principal, body.get("agent_id"))
        if agent is None:
            return _unknown_agent()
        flag = body.get("no_bearer_withdrawal")
        if not isinstance(flag, bool):
            return _rejected("bad_format")
        self._txn()
        try:
            self._conn.execute(
                "UPDATE sup_agents SET no_bearer_withdrawal = ?"
                " WHERE agent_id = ?",
                (1 if flag else 0, agent["agent_id"]),
            )
            self._commit()
        except BaseException:
            self._rollback()
            raise
        return 200, {
            "status": "ok",
            "agent_id": agent["agent_id"],
            "no_bearer_withdrawal": flag,
        }

    def op_statement(self, principal, body, params):
        """GET /v3/operator/statement — §6.1(7)/§8(c) signed statement,
        producible on demand for any in-retention period (this reference
        implementation retains the custodial journal indefinitely)."""
        try:
            t_from = int(params["from"])
            t_to = int(params["to"])
        except (KeyError, ValueError, TypeError):
            return _rejected("bad_format")
        if t_from < 0 or t_to < t_from:
            return _rejected("bad_format")
        agent_param = params.get("agent_id")
        if agent_param is None or agent_param == "fleet":
            scope_agent = "fleet"
            rows = self._conn.execute(
                "SELECT agent_id, balance_mc FROM sup_agents"
                " WHERE operator_id = ?",
                (principal[1],),
            ).fetchall()
            agent_ids = [r[0] for r in rows]
            stored_balance = sum(r[1] for r in rows)
        else:
            agent = self._operator_agent(principal, agent_param)
            if agent is None:
                return _unknown_agent()
            scope_agent = agent["agent_id"]
            agent_ids = [scope_agent]
            stored_balance = agent["balance_mc"]

        if agent_ids:
            opening = self._balance_from_lines(agent_ids, t_before=t_from)
            closing = self._balance_from_lines(agent_ids, t_through=t_to)
            current = self._balance_from_lines(agent_ids)
            marks = ",".join("?" for _ in agent_ids)
            line_rows = self._conn.execute(
                "SELECT t, kind, amount_mc, counterparty_account, ref"
                f" FROM sup_lines WHERE agent_id IN ({marks})"
                " AND t >= ? AND t <= ? ORDER BY seq",
                agent_ids + [t_from, t_to],
            ).fetchall()
        else:
            opening = closing = current = 0
            line_rows = []

        lines = [
            {
                "t": t,
                "kind": kind,
                "amount_mc": amount,
                "counterparty_account": counterparty,
                "ref": ref,
            }
            for (t, kind, amount, counterparty, ref) in line_rows
        ]
        credit_sum = sum(
            ln["amount_mc"] for ln in lines if ln["kind"] in CREDIT_KINDS
        )
        debit_sum = sum(
            ln["amount_mc"] for ln in lines if ln["kind"] in DEBIT_KINDS
        )
        # Balance invariant, enforced at generation (§6.1(7)): the pinned
        # partition must reproduce closing - opening, AND the journal must
        # agree with the stored balances. A violation is an internal error
        # (500 via the handler), never a silently wrong signed statement.
        if credit_sum - debit_sum != closing - opening:
            raise RuntimeError("statement invariant violated (partition)")
        if current != stored_balance:
            raise RuntimeError("statement invariant violated (balance)")

        statement = {
            "v": 4,
            "mint_id": self.config.mint_id,
            "scope": {"operator_id": principal[1], "agent_id": scope_agent},
            "period": {"from": t_from, "to": t_to},
            "opening_balance_mc": opening,
            "closing_balance_mc": closing,
            "lines": lines,
        }
        # Signed over canonical JSON with the mint's published key (C05).
        return 200, attach_sig(statement, self.config.signing_private)

    # -- balance / spend-rate --------------------------------------------

    def agent_balance(self, principal, body, params):
        """GET /v3/agent/balance — §6.1(5) balance and spend-rate, no
        counterparty identities. Agents see themselves; operators any of
        their own agents (?agent_id required)."""
        role, pid = principal
        agent_param = params.get("agent_id")
        if role == "agent":
            if agent_param is not None and agent_param != pid:
                return 403, {"status": "forbidden"}
            agent = self._agent(pid)
        else:
            if agent_param is None:
                return _rejected("bad_format")
            agent = self._operator_agent(principal, agent_param)
            if agent is None:
                return _unknown_agent()
        now = self._now()
        return 200, {
            "status": "ok",
            "agent_id": agent["agent_id"],
            "balance_mc": agent["balance_mc"],
            "frozen": bool(agent["frozen"]),
            "no_bearer_withdrawal": bool(agent["no_bearer_withdrawal"]),
            "caps": {
                "per_hour_mc": agent["cap_per_hour_mc"],
                "per_day_mc": agent["cap_per_day_mc"],
                "absolute_mc": agent["cap_absolute_mc"],
            },
            "spend_rate": {
                "trailing_hour_mc": self._debits_since(
                    agent["agent_id"], now - HOUR_MS
                ),
                "trailing_day_mc": self._debits_since(
                    agent["agent_id"], now - DAY_MS
                ),
                "lifetime_mc": self._debits_lifetime(agent["agent_id"]),
            },
        }

    # -- pull authorizations (§6.1(6)) ------------------------------------

    def agent_authorize_pull(self, principal, body, params):
        payee = body.get("payee_account")
        cap = body.get("cap_mc_per_day")
        expires_at = body.get("expires_at")
        if not _plain_int(cap) or cap <= 0 or not _plain_int(expires_at) or expires_at < 0:
            return _rejected("bad_format")
        if self._agent(payee) is None:
            # §6.1(6): the payee must hold a custodial account at this mint.
            return _rejected("unknown_account")
        auth_id = _new_id("auth")
        self._txn()
        try:
            self._conn.execute(
                "INSERT INTO sup_pull_auths (auth_id, granting_agent_id,"
                " payee_account, cap_mc_per_day, expires_at, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (auth_id, principal[1], payee, cap, expires_at, self._now()),
            )
            self._commit()
        except BaseException:
            self._rollback()
            raise
        return 200, {"status": "ok", "auth_id": auth_id}

    def agent_revoke_pull(self, principal, body, params):
        auth_id = body.get("auth_id")
        if not isinstance(auth_id, str):
            return _rejected("bad_format")
        row = self._conn.execute(
            "SELECT granting_agent_id FROM sup_pull_auths WHERE auth_id = ?",
            (auth_id,),
        ).fetchone()
        if row is None or row[0] != principal[1]:
            return _rejected("authorization_missing")
        self._txn()
        try:
            # Revocation is immediate (§6.1(6)); revoking twice is a no-op.
            self._conn.execute(
                "UPDATE sup_pull_auths SET revoked = 1 WHERE auth_id = ?",
                (auth_id,),
            )
            self._commit()
        except BaseException:
            self._rollback()
            raise
        return 200, {"status": "ok", "auth_id": auth_id}

    def agent_pull(self, principal, body, params):
        """POST /v3/pull — payee-initiated, mint-executed atomic debit of
        the granting account and credit of the payee (§6.1(6))."""
        auth_id = body.get("auth_id")
        amount = body.get("amount_mc")
        ref = body.get("ref")
        if not isinstance(auth_id, str) or not _plain_int(amount) or amount <= 0:
            return _rejected("bad_format")
        if ref is None:
            ref = ""
        if not isinstance(ref, str):
            return _rejected("bad_format")
        now = self._now()
        self._txn()
        try:
            auth = self._conn.execute(
                "SELECT granting_agent_id, payee_account, cap_mc_per_day,"
                " expires_at, revoked FROM sup_pull_auths WHERE auth_id = ?",
                (auth_id,),
            ).fetchone()
            # An auth granted to a different payee answers exactly like a
            # missing one (no authorization-existence oracle).
            if auth is None or auth[1] != principal[1]:
                self._rollback()
                return _rejected("authorization_missing")
            granter_id, payee_id, day_cap, expires_at, revoked = auth
            if revoked:
                self._rollback()
                return _rejected("authorization_revoked")
            if now >= expires_at:  # expiry boundary: at/after -> expired
                self._rollback()
                return _rejected("authorization_expired")
            granter = self._agent(granter_id)
            payee = self._agent(payee_id)
            if granter["frozen"]:
                # L13/§6.1(3): freeze suspends pulls; nothing queues.
                self._rollback()
                return _rejected("account_frozen")
            used = self._conn.execute(
                "SELECT COALESCE(SUM(amount_mc), 0) FROM sup_pull_uses"
                " WHERE auth_id = ? AND t > ?",
                (auth_id, now - DAY_MS),
            ).fetchone()[0]
            if used + amount > day_cap:
                self._rollback()
                return _rejected("pull_cap_exceeded")
            if self._cap_violation(granter, amount, now):
                # Pulls count against the granting agent's caps (L13).
                self._rollback()
                return _rejected("agent_cap_exceeded")
            if granter["balance_mc"] < amount:
                self._rollback()
                return _rejected("insufficient_balance")
            self._conn.execute(
                "UPDATE sup_agents SET balance_mc = balance_mc - ?"
                " WHERE agent_id = ?",
                (amount, granter_id),
            )
            self._conn.execute(
                "UPDATE sup_agents SET balance_mc = balance_mc + ?"
                " WHERE agent_id = ?",
                (amount, payee_id),
            )
            self._add_line(granter_id, now, "pull_out", amount, payee_id, ref)
            self._add_line(payee_id, now, "pull_in", amount, granter_id, ref)
            self._conn.execute(
                "INSERT INTO sup_pull_uses (auth_id, t, amount_mc)"
                " VALUES (?, ?, ?)",
                (auth_id, now, amount),
            )
            self._commit()
        except BaseException:
            self._rollback()
            raise
        return 200, {
            "status": "ok",
            "amount_mc": amount,
            "balance_mc": payee["balance_mc"] + amount,
        }

    # -- custodial transfer (never touches C04, never burns — §7.3) -------

    def agent_transfer(self, principal, body, params):
        to_account = body.get("to_account")
        amount = body.get("amount_mc")
        ref = body.get("ref")
        if not _plain_int(amount) or amount <= 0:
            return _rejected("bad_format")
        if ref is None:
            ref = ""
        if not isinstance(ref, str):
            return _rejected("bad_format")
        if to_account == principal[1]:
            # A self-transfer nets to zero yet would consume cap headroom
            # and journal a spurious debit/credit pair; refuse it outright.
            return _rejected("bad_format")
        now = self._now()
        self._txn()
        try:
            sender = self._agent(principal[1])
            target = self._agent(to_account)
            if target is None:
                self._rollback()
                return _rejected("unknown_account")
            if sender["frozen"]:
                self._rollback()
                return _rejected("account_frozen")
            if self._cap_violation(sender, amount, now):
                self._rollback()
                return _rejected("agent_cap_exceeded")
            if sender["balance_mc"] < amount:
                self._rollback()
                return _rejected("insufficient_balance")
            self._conn.execute(
                "UPDATE sup_agents SET balance_mc = balance_mc - ?"
                " WHERE agent_id = ?",
                (amount, sender["agent_id"]),
            )
            self._conn.execute(
                "UPDATE sup_agents SET balance_mc = balance_mc + ?"
                " WHERE agent_id = ?",
                (amount, target["agent_id"]),
            )
            self._add_line(
                sender["agent_id"], now, "debit", amount, target["agent_id"], ref
            )
            self._add_line(
                target["agent_id"], now, "credit", amount, sender["agent_id"], ref
            )
            self._commit()
        except BaseException:
            self._rollback()
            raise
        return 200, {
            "status": "ok",
            "balance_mc": sender["balance_mc"] - amount,
        }

    # -- deposit: bearer -> balance via a real C04 exchange (§5.3) --------

    def agent_deposit(self, principal, body, params):
        tokens = body.get("tokens")
        ref = body.get("ref")
        if not isinstance(tokens, list) or not tokens:
            return _rejected("bad_format")
        if ref is None:
            ref = ""
        if not isinstance(ref, str):
            return _rejected("bad_format")
        parsed = []
        for t in tokens:
            try:
                tok = parse_token(t)
            except TokenError:
                return _rejected("bad_format")
            if tok.mint_id != self.config.mint_id:
                return _rejected("bad_format")
            parsed.append(tok)
        total = sum(tok.amount_mc for tok in parsed)
        burn = compute_burn(total, self.ledger._burn_policy)
        net = total - burn
        # Mint-custody output: the mint generates and holds this secret;
        # it is custody money, not a client secret (§5.3 bridge).
        custody_secret = new_secret()
        custody_hash = ledger_key(custody_secret)
        inputs = [InputForm(kind="plain", token=tok) for tok in parsed]
        outputs = [OutputSpec(amount_mc=net, secret_hash=custody_hash)]
        idem = "sup-deposit-" + b64u_encode(os.urandom(18))
        now = self._now()
        op_id = _new_id("pend")
        details = {"custody_hash": custody_hash, "net_mc": net, "t": now,
                   "ref": ref}
        # Persist-before-send (§5.1, mandatory client ordering; §5.3): the
        # custody secret and the staged follow-up are durably committed
        # BEFORE the exchange that creates the entry can commit. A crash
        # anywhere after this point is reconciled by _recover_pending.
        self._txn()
        try:
            self._conn.execute(
                "INSERT INTO sup_custody (hash, secret_b64u, amount_mc,"
                " state) VALUES (?, ?, ?, 'pending')",
                (custody_hash, b64u_encode(custody_secret), net),
            )
            self._conn.execute(
                "INSERT INTO sup_pending_ops (op_id, kind, agent_id,"
                " probe_hash, details_json) VALUES (?, 'deposit', ?, ?, ?)",
                (op_id, principal[1], custody_hash,
                 json.dumps(details, sort_keys=True)),
            )
            self._commit()
        except BaseException:
            self._rollback()
            raise
        try:
            result = self.ledger.exchange(idem, idem, inputs, outputs=outputs)
        except ExchangeRejected as exc:
            # The exchange rolled back atomically: the custody entry was
            # never created, so the staged secret is discarded.
            self._txn()
            try:
                self._conn.execute(
                    "DELETE FROM sup_custody WHERE hash = ?"
                    " AND state = 'pending'",
                    (custody_hash,),
                )
                self._conn.execute(
                    "DELETE FROM sup_pending_ops WHERE op_id = ?", (op_id,)
                )
                self._commit()
            except BaseException:
                self._rollback()
                raise
            return 400, {"status": "rejected", "errors": exc.errors}
        self._finalize_deposit(op_id, principal[1], details)
        agent = self._agent(principal[1])
        return 200, {
            "status": "ok",
            "deposited_mc": net,
            "burn_mc": result["burn_mc"],
            "balance_mc": agent["balance_mc"],
        }

    def _finalize_deposit(self, op_id, agent_id, details):
        """Post-exchange half of a deposit: activate the custody entry,
        credit the balance, journal the line, clear the staged op. Called
        on the request path and by startup recovery (idempotent-safe: the
        staged op row exists exactly until this commits)."""
        self._txn()
        try:
            self._conn.execute(
                "UPDATE sup_custody SET state = 'unspent' WHERE hash = ?"
                " AND state = 'pending'",
                (details["custody_hash"],),
            )
            self._conn.execute(
                "UPDATE sup_agents SET balance_mc = balance_mc + ?"
                " WHERE agent_id = ?",
                (details["net_mc"], agent_id),
            )
            # §6.1(7): the deposit line is the net amount credited. The
            # deposit's burn is an exchange-side event, not an agent debit,
            # so it neither appears as a debit line nor counts against caps
            # (§6.1(2) lists transfer/pull/withdrawal-gross only).
            self._add_line(
                agent_id, details["t"], "deposit", details["net_mc"], None,
                details["ref"],
            )
            self._conn.execute(
                "DELETE FROM sup_pending_ops WHERE op_id = ?", (op_id,)
            )
            self._commit()
        except BaseException:
            self._rollback()
            raise

    # -- withdraw: balance -> bearer via a C04 exchange from custody ------

    def agent_withdraw(self, principal, body, params):
        outputs = body.get("outputs")
        if not isinstance(outputs, list) or not outputs:
            return _rejected("bad_format")
        specs = []
        total_out = 0
        for o in outputs:
            if not isinstance(o, dict) or set(o) != {"amount_mc", "secret_hash"}:
                return _rejected("bad_format")
            amount, secret_hash = o["amount_mc"], o["secret_hash"]
            if not _plain_int(amount) or amount <= 0:
                return _rejected("bad_format")
            try:
                b64u_decode(secret_hash, expect_len=32)
            except TokenError:
                return _rejected("bad_format")
            # By-hash only (§5.3): the mint never sees the new secrets.
            specs.append(OutputSpec(amount_mc=amount, secret_hash=secret_hash))
            total_out += amount
        now = self._now()
        agent = self._agent(principal[1])
        if agent["frozen"]:
            return _rejected("account_frozen")
        if agent["no_bearer_withdrawal"]:
            # §6.1(4): while the flag is set, withdrawals fail.
            return _rejected("withdrawal_disabled")

        # §7.3/R17: the agent-charged burn is computed on the REQUESTED
        # amount, never on the mint's internally selected custody inputs
        # (custody fragmentation is the mint's own operational artifact).
        burn = compute_burn(total_out, self.ledger._burn_policy)
        gross = total_out + burn  # §7.3: full debit including burn
        if self._cap_violation(agent, gross, now):
            return _rejected("agent_cap_exceeded")
        if agent["balance_mc"] < gross:
            return _rejected("insufficient_balance")

        # Select custody inputs, smallest first (minimizes the ledger-level
        # burn the mint must absorb); accumulate until inputs cover the
        # outputs + the exchange's own L12 burn. Only 'unspent' rows are
        # eligible: rows reserved by an in-flight (or crashed,
        # not-yet-reconciled) withdrawal are never re-picked.
        custody = self._conn.execute(
            "SELECT hash, secret_b64u, amount_mc FROM sup_custody"
            " WHERE state = 'unspent' ORDER BY amount_mc ASC, hash ASC"
        ).fetchall()
        selected, in_sum = [], 0
        for row in custody:
            selected.append(row)
            in_sum += row[2]
            if in_sum - compute_burn(in_sum, self.ledger._burn_policy) >= total_out:
                break
        ledger_burn = compute_burn(in_sum, self.ledger._burn_policy)
        if in_sum - ledger_burn < total_out:
            # Custody can only fall short of a within-balance request in a
            # degenerate burn corner; report it as insufficient funds.
            return _rejected("insufficient_balance")
        # The exchange still burns per L12 on its actual inputs; the
        # difference vs the agent-charged burn is absorbed by the mint's
        # custody pool (§7.3/R17). >= 0: in_sum >= total_out and
        # compute_burn is monotone.
        absorbed = ledger_burn - burn

        change = in_sum - total_out - ledger_burn
        change_secret = change_hash = None
        exchange_outputs = list(specs)
        if change > 0:
            change_secret = new_secret()
            change_hash = ledger_key(change_secret)
            exchange_outputs.append(
                OutputSpec(amount_mc=change, secret_hash=change_hash)
            )
        inputs = [
            InputForm(
                kind="plain",
                token=Token(
                    mint_id=self.config.mint_id,
                    amount_mc=amt,
                    secret=b64u_decode(secret_b64u, expect_len=32),
                ),
            )
            for (_h, secret_b64u, amt) in selected
        ]
        idem = "sup-withdraw-" + b64u_encode(os.urandom(18))
        op_id = _new_id("pend")
        details = {
            "input_hashes": [h for (h, _s, _a) in selected],
            "change_hash": change_hash,  # None when no change output
            "total_out_mc": total_out,
            "burn_mc": burn,  # agent-charged: compute_burn(total_out)
            "ledger_burn_mc": ledger_burn,  # L12 burn on the actual inputs
            "absorbed_mc": absorbed,  # mint-absorbed difference (§7.3/R17)
            "gross_mc": gross,
            "t": now,
        }
        # Persist-before-send with no exceptions (§5.3): the change secret
        # is durable, the selected inputs are reserved (so a crash can
        # never wedge the selector on ledger-spent rows), and the staged
        # follow-up is committed BEFORE the exchange runs.
        self._txn()
        try:
            for h in details["input_hashes"]:
                self._conn.execute(
                    "UPDATE sup_custody SET state = 'reserved'"
                    " WHERE hash = ? AND state = 'unspent'",
                    (h,),
                )
            if change > 0:
                self._conn.execute(
                    "INSERT INTO sup_custody (hash, secret_b64u, amount_mc,"
                    " state) VALUES (?, ?, ?, 'pending')",
                    (change_hash, b64u_encode(change_secret), change),
                )
            self._conn.execute(
                "INSERT INTO sup_pending_ops (op_id, kind, agent_id,"
                " probe_hash, details_json) VALUES (?, 'withdraw', ?, ?, ?)",
                (op_id, principal[1], details["input_hashes"][0],
                 json.dumps(details, sort_keys=True)),
            )
            self._commit()
        except BaseException:
            self._rollback()
            raise
        try:
            self.ledger.exchange(idem, idem, inputs, outputs=exchange_outputs)
        except ExchangeRejected as exc:
            # Atomic rollback inside C04 — release the staged state too.
            self._unwind_withdraw(op_id, details)
            return 400, {"status": "rejected", "errors": exc.errors}
        self._finalize_withdraw(op_id, principal[1], details)
        return 200, {
            "status": "ok",
            "withdrawn_mc": total_out,
            "burn_mc": burn,
            "balance_mc": agent["balance_mc"] - gross,
        }

    def _finalize_withdraw(self, op_id, agent_id, details):
        """Post-exchange half of a withdrawal: consume the reserved inputs,
        activate the change entry, debit the gross, journal the pinned
        lines, clear the staged op. Called on the request path and by
        startup recovery."""
        self._txn()
        try:
            for h in details["input_hashes"]:
                self._conn.execute(
                    "UPDATE sup_custody SET state = 'spent'"
                    " WHERE hash = ? AND state = 'reserved'",
                    (h,),
                )
            if details["change_hash"] is not None:
                self._conn.execute(
                    "UPDATE sup_custody SET state = 'unspent'"
                    " WHERE hash = ? AND state = 'pending'",
                    (details["change_hash"],),
                )
            self._conn.execute(
                "UPDATE sup_agents SET balance_mc = balance_mc - ?"
                " WHERE agent_id = ?",
                (details["gross_mc"], agent_id),
            )
            # §7.3/R17: the ledger burned on the actual custody inputs but
            # the agent was only charged compute_burn(amount); the custody
            # pool absorbed the difference — record it so the invariant
            # custody == balances - absorbed stays auditable.
            self._conn.execute(
                "UPDATE sup_mint SET absorbed_mc = absorbed_mc + ?"
                " WHERE id = 1",
                (details.get("absorbed_mc", 0),),
            )
            # §6.1(7) pinned: withdrawal net of burn + burn as its own line;
            # both are debit-like, so the gross counts against caps. The
            # burn line is the agent-charged burn (§7.3/R17), not the
            # ledger-level burn on the mint-selected inputs.
            self._add_line(
                agent_id, details["t"], "withdrawal",
                details["total_out_mc"], None, "",
            )
            if details["burn_mc"] > 0:
                self._add_line(
                    agent_id, details["t"], "burn", details["burn_mc"],
                    None, "",
                )
            self._conn.execute(
                "DELETE FROM sup_pending_ops WHERE op_id = ?", (op_id,)
            )
            self._commit()
        except BaseException:
            self._rollback()
            raise

    def _unwind_withdraw(self, op_id, details):
        """Discard a staged withdrawal whose exchange did NOT commit:
        release the reserved inputs, drop the pending change secret,
        clear the staged op. No balance was touched."""
        self._txn()
        try:
            for h in details["input_hashes"]:
                self._conn.execute(
                    "UPDATE sup_custody SET state = 'unspent'"
                    " WHERE hash = ? AND state = 'reserved'",
                    (h,),
                )
            if details["change_hash"] is not None:
                self._conn.execute(
                    "DELETE FROM sup_custody WHERE hash = ?"
                    " AND state = 'pending'",
                    (details["change_hash"],),
                )
            self._conn.execute(
                "DELETE FROM sup_pending_ops WHERE op_id = ?", (op_id,)
            )
            self._commit()
        except BaseException:
            self._rollback()
            raise

    # -- startup reconciliation of the §5.3 bridge ------------------------

    def _recover_pending(self):
        """Reconcile staged deposit/withdraw ops left by a crash between
        the C04 exchange commit and the supervision follow-up commit.

        For each staged op, /v3/status of its probe hash tells whether the
        exchange committed: a deposit's custody output exists iff it did;
        a withdrawal's first custody input is spent iff it did. Committed
        ops roll FORWARD via the same finalize used on the request path;
        uncommitted ops roll BACK (discard staged secrets, release
        reservations). Either way no money is lost: every secret was
        durable before its exchange could commit (§5.1/§5.3)."""
        ops = self._conn.execute(
            "SELECT op_id, kind, agent_id, probe_hash, details_json"
            " FROM sup_pending_ops ORDER BY op_id"
        ).fetchall()
        for op_id, kind, agent_id, probe_hash, details_json in ops:
            details = json.loads(details_json)
            _t, results = self.ledger.status([probe_hash])
            probe_state = results[0]["state"]
            if kind == "deposit":
                if probe_state == "unknown":
                    # The exchange never committed; the depositor's tokens
                    # are untouched. Discard the staged custody secret.
                    self._txn()
                    try:
                        self._conn.execute(
                            "DELETE FROM sup_custody WHERE hash = ?"
                            " AND state = 'pending'",
                            (details["custody_hash"],),
                        )
                        self._conn.execute(
                            "DELETE FROM sup_pending_ops WHERE op_id = ?",
                            (op_id,),
                        )
                        self._commit()
                    except BaseException:
                        self._rollback()
                        raise
                else:
                    self._finalize_deposit(op_id, agent_id, details)
            elif kind == "withdraw":
                if probe_state == "spent":
                    self._finalize_withdraw(op_id, agent_id, details)
                else:
                    self._unwind_withdraw(op_id, details)
            else:  # pragma: no cover — unreachable by construction
                raise RuntimeError("unknown staged op kind: %r" % (kind,))


# ---------------------------------------------------------------------------
# HTTP mounting: supervision routes in front of the unchanged C06 handler.
# ---------------------------------------------------------------------------


class _SupHTTPServer(_MintHTTPServer):
    sup: _SupCore  # set by SupervisionServer.start


class _SupHandler(_Handler):
    """C06's handler + the Supervision Profile routes.

    Unmatched paths fall through to the parent, so every Layer 0 route
    stays authless and byte-identical to a plain C06 mint (L13/B9).
    """

    def _dispatch_sup(self, method: str, path: str) -> None:
        self._route = path  # fixed route pattern; never logs bodies/keys
        try:
            if method == "POST":
                body, ok = self._read_json()
                params = {}
            else:
                body, ok = None, True
                query = urllib.parse.urlsplit(self.path).query
                params = {
                    k: v[-1]
                    for k, v in urllib.parse.parse_qs(query).items()
                }
            code, obj = self.server.sup.dispatch(
                method,
                path,
                body,
                ok,
                self.headers.get("Authorization"),
                params,
            )
            self._send(code, obj)
        except Exception:
            self._safe_500()

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if ("GET", path) in _ROUTES:
            self._dispatch_sup("GET", path)
            return
        super().do_GET()

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if ("POST", path) in _ROUTES:
            self._dispatch_sup("POST", path)
            return
        super().do_POST()


class SupervisionServer(MintServer):
    """A C06 mint with the Supervision Profile mounted.

    The descriptor's ``profiles`` gains ``"supervision"`` automatically
    (C10 requirement 8) — the config passed in need not list it.
    """

    def __init__(self, config: MintConfig, ledger: Ledger):
        if "supervision" not in config.profiles:
            config = dataclasses.replace(
                config, profiles=tuple(config.profiles) + ("supervision",)
            )
        super().__init__(config, ledger)
        self.sup = _SupCore(config, ledger)

    def start(self) -> int:
        """Bind 127.0.0.1:0 and serve; same contract as MintServer.start."""
        if self._httpd is not None:
            raise RuntimeError("server already started")
        self._httpd = _SupHTTPServer(("127.0.0.1", 0), _SupHandler)
        self._httpd.core = self._core
        self._httpd.sup = self.sup
        self._thread = threading.Thread(
            target=self._httpd.serve_forever,
            name="aicash-supervision",
            daemon=True,
        )
        self._thread.start()
        return self._httpd.server_address[1]
