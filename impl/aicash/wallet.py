"""C07 — wallet: the bearer client (spec §5.1, §5.3, §7.2, §9.5, §4.2).

Durable local token store with the MANDATORY persist-before-send ordering
(§5.1), receive-and-re-exchange, ladder-aware coin selection (§4.2), and
crash recovery via `/v3/status` batches.  Locked decisions L1 (no expiry /
revocation on bearer value) and L8 (bearer loss unrecoverable; the store
IS the money) apply.

Persist-before-send, enforced structurally (component requirement 1):
the ONLY call site of ``MintClient.exchange`` inside ``Wallet`` is
``Wallet._send_exchange``, and that method re-reads the sqlite store over
a FRESH connection before sending — a fresh connection can only see
committed (and, with ``PRAGMA synchronous=FULL``, fsynced) data, so the
assertion "every referenced output secret is durably persisted as
``pending``" is checked against the disk, not against process memory.

State machine (component requirement 2):

    pending  -> confirmed | orphan        (outputs of a planned exchange)
    confirmed (== "held", spendable) -> spent_out
    handed_over                            (payment outputs whose token
                                            strings were returned by
                                            ``pay()`` — value in flight to
                                            the payee, never counted in
                                            ``balance()``)

Received token strings are never stored as held value (§5.1) — only their
freshly generated replacements are.  The received string does appear
inside the stored exchange *plan* (``wallet_ops.request_json``), which is
what crash recovery replays status checks against; the plan is a record
of an operation, not a held token.

Secret hygiene: this module never logs anything, and no exception message
ever embeds a token string or secret.  The store file is chmod 0600 on
creation (bearer secrets are the money — L8).

Time: the wallet needs no clock at all.  Burn-policy selection uses the
mint's own ``mint_time`` as reported in its descriptor (L17: never read
wall time in money logic).
"""

from __future__ import annotations

import http.client
import json
import os
import sqlite3
import uuid
from urllib.parse import urlsplit

from aicash.burncalc import BurnPolicy, compute_burn, effective_policy
from aicash.tokencodec import (
    TokenError,
    b64u_decode,
    b64u_encode,
    canonical_json,
    format_token,
    ledger_key,
    parse_token,
)

__all__ = [
    "MintClient",
    "MintRejected",
    "MintUnavailable",
    "PaymentInvalid",
    "InsufficientFunds",
    "Wallet",
]


# ---------------------------------------------------------------------------
# exceptions
# ---------------------------------------------------------------------------


class MintRejected(Exception):
    """`/v3/exchange` returned a §3.8 rejection.  ``errors`` is the list of
    ``{index, kind, reason}`` objects.  The message is deliberately free of
    request contents (requests contain live secrets)."""

    def __init__(self, errors: list):
        self.errors = list(errors) if isinstance(errors, list) else []
        reasons = sorted(
            {
                str(e.get("reason"))
                for e in self.errors
                if isinstance(e, dict) and e.get("reason") is not None
            }
        )
        super().__init__("exchange rejected: " + (",".join(reasons) or "?"))


class MintUnavailable(Exception):
    """Transport-level failure (connection refused, timeout, non-JSON or
    unexpected response).  The operation may or may not have reached the
    mint — resolve with ``Wallet.recover()``."""


class PaymentInvalid(Exception):
    """A received/refused token failed validation or was rejected by the
    mint (§3.8 reasons: spent, unknown, bad_format, ...)."""

    def __init__(self, errors: list):
        self.errors = list(errors)
        self.reasons = [
            e.get("reason") for e in self.errors if isinstance(e, dict)
        ]
        super().__init__(
            "invalid payment: " + ",".join(str(r) for r in self.reasons)
        )


class InsufficientFunds(Exception):
    """Held balance cannot cover amount + burn."""


# ---------------------------------------------------------------------------
# MintClient — thin HTTP client for the C06 endpoints (reused by C08–C11)
# ---------------------------------------------------------------------------


class MintClient:
    """Thin JSON-over-HTTP client for a C06 mint.

    Sends §3.3 canonical JSON bytes so that a retried request is
    byte-identical to the original (idempotency-key replay requires it).
    Never sends credentials of any kind — Layer 0 has none (L2, §3.7) —
    and never logs.
    """

    def __init__(self, base_url: str, timeout: float = 30.0):
        parts = urlsplit(base_url)
        if parts.scheme != "http" or parts.hostname is None:
            raise ValueError("base_url must look like http://host:port")
        self._host = parts.hostname
        self._port = parts.port or 80
        self._timeout = timeout

    # -- transport seam (tests may subclass to instrument / inject faults) --

    def _transport(
        self,
        method: str,
        path: str,
        body: bytes | None,
        extra_headers: dict | None = None,
    ) -> tuple[int, bytes]:
        conn = http.client.HTTPConnection(
            self._host, self._port, timeout=self._timeout
        )
        try:
            headers = {"Content-Type": "application/json"} if body else {}
            if extra_headers:
                headers.update(extra_headers)
            conn.request(method, path, body, headers)
            resp = conn.getresponse()
            return resp.status, resp.read()
        finally:
            conn.close()

    def _request(self, method: str, path: str, obj=None, extra_headers=None):
        body = None if obj is None else canonical_json(obj)
        try:
            if extra_headers:
                status, raw = self._transport(method, path, body, extra_headers)
            else:
                # three-arg form kept for subclassed seams (C07/C08 tests)
                status, raw = self._transport(method, path, body)
        except (OSError, TimeoutError, http.client.HTTPException) as exc:
            # message carries the exception TYPE only — never request data
            raise MintUnavailable(
                f"transport failure: {type(exc).__name__}"
            ) from exc
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise MintUnavailable("unparseable mint response") from exc
        return status, parsed

    # -- C06 endpoints ------------------------------------------------------

    def exchange(self, idempotency_key: str, inputs: list, outputs: list) -> dict:
        """POST /v3/exchange.  Returns the §3.3 success body; raises
        MintRejected on a §3.8 rejection, MintUnavailable otherwise."""
        body = {
            "idempotency_key": idempotency_key,
            "inputs": inputs,
            "outputs": outputs,
        }
        status, obj = self._request("POST", "/v3/exchange", body)
        if status == 200 and isinstance(obj, dict) and obj.get("status") == "ok":
            return obj
        if isinstance(obj, dict) and obj.get("status") == "rejected":
            raise MintRejected(obj.get("errors", []))
        raise MintUnavailable(f"unexpected exchange response (http {status})")

    def status(self, hashes: list) -> tuple[int, list]:
        """POST /v3/status (batch).  Returns ``(mint_time, results)``."""
        status, obj = self._request("POST", "/v3/status", {"hashes": list(hashes)})
        if status == 200 and isinstance(obj, dict) and "results" in obj:
            return obj["mint_time"], obj["results"]
        if isinstance(obj, dict) and obj.get("status") == "rejected":
            raise MintRejected(obj.get("errors", []))
        raise MintUnavailable(f"unexpected status response (http {status})")

    def descriptor(self) -> dict:
        """GET /v3/mints — the §3.6 descriptor."""
        status, obj = self._request("GET", "/v3/mints")
        if status == 200 and isinstance(obj, dict) and "mint_id" in obj:
            return obj
        raise MintUnavailable(f"unexpected descriptor response (http {status})")

    def admin_issue(self, outputs: list, admin_token: str | None = None) -> dict:
        """POST /admin/issue — the non-normative §7.1 operator funding path.

        ``outputs`` are §3.3 wire output dicts (``{amount_mc, secret_hash |
        secret, lock?}``); the by-hash form is preferred (§3.3: the mint
        never touches a spendable secret).  When ``admin_token`` is given
        it is presented as the ``X-Admin-Token`` header; Layer 0 endpoints
        never require it (L2, §3.7) — only this operator path may.
        Returns the success body; raises MintRejected on a §3.8 rejection
        and MintUnavailable otherwise (including 401 unauthorized).
        """
        extra = (
            {"X-Admin-Token": admin_token} if admin_token is not None else None
        )
        status, obj = self._request(
            "POST", "/admin/issue", {"outputs": list(outputs)}, extra_headers=extra
        )
        if status == 200 and isinstance(obj, dict) and obj.get("status") == "ok":
            return obj
        if isinstance(obj, dict) and obj.get("status") == "rejected":
            raise MintRejected(obj.get("errors", []))
        raise MintUnavailable(f"unexpected admin_issue response (http {status})")


# ---------------------------------------------------------------------------
# Wallet
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS wallet_tokens (
  key         TEXT PRIMARY KEY,   -- b64u(sha256(secret)) — the ledger key
  secret      TEXT NOT NULL,      -- b64u secret (the store IS the money; L8)
  amount_mc   INTEGER NOT NULL,
  state       TEXT NOT NULL,      -- pending|confirmed|handed_over|spent_out|orphan
  role        TEXT NOT NULL,      -- receive|payment|change|refund
  op_id       TEXT NOT NULL,      -- op that created this output
  reserved_by TEXT                -- op currently spending it (NULL = free)
);
CREATE TABLE IF NOT EXISTS wallet_ops (
  op_id        TEXT PRIMARY KEY,  -- doubles as the §3.3 idempotency key
  kind         TEXT NOT NULL,     -- receive|pay|refused
  state        TEXT NOT NULL,     -- planned|done|failed
  request_json TEXT NOT NULL      -- the exact §3.3 body (canonical JSON):
                                  -- the stored plan recovery resolves against
);
CREATE INDEX IF NOT EXISTS wallet_tokens_op ON wallet_tokens (op_id);
"""

#: Output states that count as held, spendable value.
_HELD = "confirmed"


class Wallet:
    """The bearer client over one sqlite store and one mint."""

    MAX_ATTEMPTS = 3  # transport retries per operation, same idempotency key

    def __init__(self, store_path: str, client: MintClient, mint_id: str):
        self._store_path = store_path
        self.client = client
        self.mint_id = mint_id
        #: optional instrumentation hook, called as hook(event, op_id) with
        #: event == "persist_fsync" right after the plan commit (B2 tests)
        self.event_hook = None
        existed = os.path.exists(store_path)
        self._db = sqlite3.connect(store_path, isolation_level=None)
        # §5.1 durability: COMMIT must reach the platter before we send.
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.executescript(_SCHEMA)
        if not existed:
            try:
                os.chmod(store_path, 0o600)  # secrets are the money (L8)
            except OSError:
                pass

    @classmethod
    def connect(cls, store_path: str, base_url: str) -> "Wallet":
        """Zero-config entry point (§7.2): construct a MintClient for
        ``base_url``, fetch the §3.6 descriptor, and return a Wallet bound
        to the descriptor's ``mint_id``.  No registration, no credentials
        (§3.7/L2) — a fresh store created here can immediately
        ``receive()`` its first token."""
        client = MintClient(base_url)
        return cls(store_path, client, client.descriptor()["mint_id"])

    # ------------------------------------------------------------------
    # descriptor / policy helpers
    # ------------------------------------------------------------------

    def _mint_params(self) -> tuple[BurnPolicy, list[int], int]:
        """(effective burn policy, denominations descending, max_batch).

        The policy in force is computed against the MINT's clock as
        published in the descriptor (`mint_time`) — the wallet never reads
        wall time (L17)."""
        desc = self.client.descriptor()
        bp = desc["burn_policy"]
        current = BurnPolicy(
            rate_ppm=bp["rate_ppm"],
            cap_mc=bp["cap_mc"],
            exempt_below_mc=bp["exempt_below_mc"],
        )
        nxt = desc.get("burn_policy_next")
        next_t = None
        if nxt is not None:
            np = nxt["policy"]
            next_t = (
                BurnPolicy(
                    rate_ppm=np["rate_ppm"],
                    cap_mc=np["cap_mc"],
                    exempt_below_mc=np["exempt_below_mc"],
                ),
                nxt["effective_at"],
            )
        policy = effective_policy(current, next_t, desc["mint_time"])
        denoms = sorted(set(desc["denominations_mc"]), reverse=True)
        if not denoms or denoms[-1] != 1:
            # ladder decomposition needs a unit rung; every conformant
            # descriptor publishes one (§4.2)
            raise MintUnavailable("descriptor ladder lacks the 1 mc rung")
        return policy, denoms, desc["limits"]["max_batch"]

    @staticmethod
    def _decompose(amount_mc: int, denoms_desc: list[int]) -> list[int]:
        """§4.2 ladder decomposition (largest-first; exact since 1 ∈ ladder)."""
        coins = []
        remaining = amount_mc
        for d in denoms_desc:
            n = remaining // d
            coins.extend([d] * n)
            remaining -= n * d
        return coins

    # ------------------------------------------------------------------
    # store plumbing
    # ------------------------------------------------------------------

    def _txn(self, fn):
        self._db.execute("BEGIN IMMEDIATE")
        try:
            result = fn(self._db)
            self._db.execute("COMMIT")
            return result
        except BaseException:
            self._db.execute("ROLLBACK")
            raise

    def balance(self) -> int:
        row = self._db.execute(
            "SELECT COALESCE(SUM(amount_mc), 0) FROM wallet_tokens"
            " WHERE state = ?",
            (_HELD,),
        ).fetchone()
        return row[0]

    def _held_coins(self) -> list[tuple[str, str, int]]:
        """Free held coins as (key, secret_b64u, amount_mc), largest first."""
        return self._db.execute(
            "SELECT key, secret, amount_mc FROM wallet_tokens"
            " WHERE state = ? AND reserved_by IS NULL"
            " ORDER BY amount_mc DESC, key",
            (_HELD,),
        ).fetchall()

    # ------------------------------------------------------------------
    # persist-before-send (§5.1 — component requirement 1)
    # ------------------------------------------------------------------

    def _persist_plan(self, op_id, kind, body, new_outputs, input_keys):
        """Write the full operation plan and every new output secret with
        state ``pending``, COMMIT (== fsync under synchronous=FULL), then
        fire the ``persist_fsync`` instrumentation event.  MUST complete
        before any exchange referencing these outputs is sent."""

        def _do(c):
            c.execute(
                "INSERT INTO wallet_ops (op_id, kind, state, request_json)"
                " VALUES (?, ?, 'planned', ?)",
                (op_id, kind, canonical_json(body).decode("utf-8")),
            )
            for secret, amount, role in new_outputs:
                c.execute(
                    "INSERT INTO wallet_tokens"
                    " (key, secret, amount_mc, state, role, op_id, reserved_by)"
                    " VALUES (?, ?, ?, 'pending', ?, ?, NULL)",
                    (
                        ledger_key(secret),
                        b64u_encode(secret),
                        amount,
                        role,
                        op_id,
                    ),
                )
            for k in input_keys:
                c.execute(
                    "UPDATE wallet_tokens SET reserved_by = ? WHERE key = ?",
                    (op_id, k),
                )

        self._txn(_do)
        if self.event_hook is not None:
            self.event_hook("persist_fsync", op_id)

    def _assert_persisted(self, op_id: str, output_keys: list[str]) -> None:
        """Structural guard: verify — over a FRESH sqlite connection, which
        can only see committed data — that the op plan and every output
        secret are durably on disk in state ``pending``."""
        check = sqlite3.connect(self._store_path, isolation_level=None)
        try:
            row = check.execute(
                "SELECT state FROM wallet_ops WHERE op_id = ?", (op_id,)
            ).fetchone()
            if row is None or row[0] != "planned":
                raise RuntimeError(
                    "persist-before-send violated: op plan not durably stored"
                )
            for k in output_keys:
                row = check.execute(
                    "SELECT state FROM wallet_tokens WHERE key = ?", (k,)
                ).fetchone()
                if row is None or row[0] != "pending":
                    raise RuntimeError(
                        "persist-before-send violated: output secret not"
                        " durably persisted before send"
                    )
        finally:
            check.close()

    def _send_exchange(self, op_id: str, body: dict) -> dict:
        """The ONLY code path to ``client.exchange`` (requirement 1).

        Asserts persistence structurally, then sends; transport failures
        are retried up to MAX_ATTEMPTS with the SAME idempotency key and
        the same canonical bytes (requirement 7, §3.3), so a timeout retry
        replays.  §3.8 rejections are definitive and never retried."""
        output_keys = [o["secret_hash"] for o in body["outputs"]]
        self._assert_persisted(op_id, output_keys)
        last = None
        for _ in range(self.MAX_ATTEMPTS):
            try:
                return self.client.exchange(
                    body["idempotency_key"], body["inputs"], body["outputs"]
                )
            except MintUnavailable as exc:
                last = exc
        raise last

    # ------------------------------------------------------------------
    # op resolution
    # ------------------------------------------------------------------

    def _resolve_success(self, op_id: str) -> None:
        """Exchange committed: pending outputs -> confirmed (held), except
        payment outputs -> handed_over; reserved inputs -> spent_out."""

        def _do(c):
            c.execute(
                "UPDATE wallet_tokens SET state = 'handed_over'"
                " WHERE op_id = ? AND state = 'pending' AND role = 'payment'",
                (op_id,),
            )
            c.execute(
                "UPDATE wallet_tokens SET state = 'confirmed'"
                " WHERE op_id = ? AND state = 'pending'",
                (op_id,),
            )
            c.execute(
                "UPDATE wallet_tokens SET state = 'spent_out',"
                " reserved_by = NULL WHERE reserved_by = ?",
                (op_id,),
            )
            c.execute(
                "UPDATE wallet_ops SET state = 'done' WHERE op_id = ?",
                (op_id,),
            )

        self._txn(_do)

    def _resolve_failed(self, op_id: str) -> None:
        """Exchange definitively rejected: pending outputs -> orphan,
        reserved inputs restored (stay confirmed, reservation cleared)."""

        def _do(c):
            c.execute(
                "UPDATE wallet_tokens SET state = 'orphan'"
                " WHERE op_id = ? AND state = 'pending'",
                (op_id,),
            )
            c.execute(
                "UPDATE wallet_tokens SET reserved_by = NULL"
                " WHERE reserved_by = ?",
                (op_id,),
            )
            c.execute(
                "UPDATE wallet_ops SET state = 'failed' WHERE op_id = ?",
                (op_id,),
            )

        self._txn(_do)

    def _mark_dead_if_ours(self, key: str) -> None:
        """A token string we also hold in the store was consumed on the
        ledger (received back / retired): its local copy is dead value."""
        self._db.execute(
            "UPDATE wallet_tokens SET state = 'spent_out'"
            " WHERE key = ? AND state IN ('confirmed', 'handed_over')",
            (key,),
        )

    # ------------------------------------------------------------------
    # receive (§5.1 on-receipt, §7.2 receive-first)
    # ------------------------------------------------------------------

    def receive(self, token_str: str) -> int:
        """Re-exchange a received token for fresh self-generated secrets
        (ladder-split).  Returns the net amount credited (face amount minus
        the §7.3 burn).  Raises PaymentInvalid with the §3.8 reasons for a
        spent/unknown/malformed token.  Receive-first (§7.2): works on a
        fresh zero-balance wallet; there is no registration anywhere."""
        try:
            tok = parse_token(token_str)
        except TokenError:
            raise PaymentInvalid(
                [{"index": 0, "kind": "input", "reason": "bad_format"}]
            ) from None
        if tok.mint_id != self.mint_id:
            raise PaymentInvalid(
                [{"index": 0, "kind": "input", "reason": "bad_format"}]
            )
        policy, denoms, _ = self._mint_params()
        burn = compute_burn(tok.amount_mc, policy)
        net = tok.amount_mc - burn
        new_outputs = [
            (os.urandom(32), amount, "receive")
            for amount in self._decompose(net, denoms)
        ]
        op_id = str(uuid.uuid4())
        body = {
            "idempotency_key": op_id,
            "inputs": [token_str],
            "outputs": [
                {"amount_mc": a, "secret_hash": ledger_key(s), "lock": None}
                for s, a, _r in new_outputs
            ],
        }
        # §5.1 mandatory ordering: the replacement secrets hit the disk
        # before the mint ever hears about them.
        self._persist_plan(op_id, "receive", body, new_outputs, input_keys=[])
        try:
            self._send_exchange(op_id, body)
        except MintRejected as exc:
            self._resolve_failed(op_id)
            raise PaymentInvalid(exc.errors) from exc
        self._resolve_success(op_id)
        # If the received string was one of our own outputs (self-receive /
        # round-trip), its store row is now dead value on the ledger.
        self._mark_dead_if_ours(ledger_key(tok.secret))
        return net

    def receive_batch(self, tokens: list[str]) -> dict:
        """Redeem N received tokens in ONE `/v3/exchange` call — one burn
        assessed on sum(inputs) (§3.3 burn-once, §7.3), the §9.2
        serve-then-batch-redeem pattern: a seller MUST NOT pay per-token
        burns to settle a batch.

        Tokens that fail locally (malformed / foreign mint) or that the
        mint enumerates as bad (§3.8: spent, unknown, ...) are dropped and
        recorded as ``{"index", "reason"}`` against the caller's list; the
        good remainder is retried under a FRESH idempotency key (the body
        changed, so replaying the old key would be an §3.3
        ``idempotency_conflict``).  Returns ``{"credited_mc": net amount
        credited, "dead": [...]}``; an empty good set credits 0.
        Persist-before-send and idempotent transport retry are identical
        to ``receive`` (§5.1)."""
        if not isinstance(tokens, list):
            raise ValueError("tokens must be a list of token strings")
        dead: list[dict] = []
        good: list[tuple[int, str, object]] = []
        for i, t in enumerate(tokens):
            try:
                tok = parse_token(t)
            except TokenError:
                dead.append({"index": i, "reason": "bad_format"})
                continue
            if tok.mint_id != self.mint_id:
                dead.append({"index": i, "reason": "bad_format"})
                continue
            good.append((i, t, tok))
        credited = 0
        while good:
            policy, denoms, _ = self._mint_params()
            total = sum(tok.amount_mc for _i, _s, tok in good)
            burn = compute_burn(total, policy)
            net = total - burn
            new_outputs = [
                (os.urandom(32), a, "receive")
                for a in self._decompose(net, denoms)
            ]
            op_id = str(uuid.uuid4())
            body = {
                "idempotency_key": op_id,
                "inputs": [s for _i, s, _tok in good],
                "outputs": [
                    {"amount_mc": a, "secret_hash": ledger_key(s), "lock": None}
                    for s, a, _r in new_outputs
                ],
            }
            self._persist_plan(op_id, "receive", body, new_outputs, input_keys=[])
            try:
                self._send_exchange(op_id, body)
            except MintRejected as exc:
                self._resolve_failed(op_id)
                bad: dict[int, str] = {}  # position in `good` -> reason
                for e in exc.errors:
                    if (
                        isinstance(e, dict)
                        and e.get("kind") == "input"
                        and isinstance(e.get("index"), int)
                        and 0 <= e["index"] < len(good)
                    ):
                        bad.setdefault(e["index"], str(e.get("reason")))
                if not bad:
                    raise PaymentInvalid(exc.errors) from exc
                for pos in sorted(bad, reverse=True):
                    i, _s, tok = good.pop(pos)
                    dead.append({"index": i, "reason": bad[pos]})
                    # the string was consumed elsewhere: a copy we hold
                    # (self-receive round-trip) is dead value
                    self._mark_dead_if_ours(ledger_key(tok.secret))
                continue  # retry the good remainder, fresh idempotency key
            self._resolve_success(op_id)
            for _i, _s, tok in good:
                self._mark_dead_if_ours(ledger_key(tok.secret))
            credited += net
            good = []
        dead.sort(key=lambda d: d["index"])
        return {"credited_mc": credited, "dead": dead}

    # ------------------------------------------------------------------
    # coin selection (§4.2 — component requirement 3)
    # ------------------------------------------------------------------

    def _select(self, coins, target: int, policy: BurnPolicy, denoms_desc):
        """Ladder-preferring greedy selection plus a consolidation sweep.

        Greedy: repeatedly take the largest held coin that does not exceed
        the current deficit (target + burn-so-far − selected-so-far); when
        no coin fits, take the smallest available coin (bounded overshoot,
        absorbed by change).  The burn is recomputed as the input sum grows
        (§7.3: burn is a function of sum(inputs)).

        Consolidation sweep (B5 anti-fragmentation invariant): after
        selection, for every rung below the top, if more than base−1 free
        coins of that rung would remain, sweep whole multiples of ``base``
        of them into the inputs — their value returns as ladder change one
        rung up.  Post-pay the store therefore never holds more than
        (base−1) leftover + (base−1) change = 2·(base−1) coins per rung.
        """
        pool = list(coins)  # already sorted largest-first
        picked: list[tuple[str, str, int]] = []
        total = 0
        while True:
            burn = compute_burn(total, policy)
            if total >= target + burn:
                break
            if not pool:
                raise InsufficientFunds(
                    f"need {target + burn} mc (amount + burn), only"
                    f" {total} mc of held coins selectable"
                )
            deficit = target + burn - total
            idx = None
            for i, c in enumerate(pool):
                if c[2] <= deficit:
                    idx = i  # pool is descending: first fit is largest fit
                    break
            if idx is None:
                idx = len(pool) - 1  # smallest coin overall (overshoot)
            coin = pool.pop(idx)
            picked.append(coin)
            total += coin[2]
        # consolidation sweep
        denoms_asc = sorted(denoms_desc)
        remaining_by_amount: dict[int, list] = {}
        for c in pool:
            remaining_by_amount.setdefault(c[2], []).append(c)
        for j, d in enumerate(denoms_asc[:-1]):
            base = denoms_asc[j + 1] // d
            rem = remaining_by_amount.get(d, [])
            if len(rem) > base - 1:
                k = -(-(len(rem) - (base - 1)) // base)  # ceil
                sweep = rem[: min(k * base, len(rem))]
                for c in sweep:
                    picked.append(c)
                    total += c[2]
                remaining_by_amount[d] = rem[len(sweep):]
        return picked, total

    # ------------------------------------------------------------------
    # pay
    # ------------------------------------------------------------------

    def pay(self, amount_mc: int) -> list[str]:
        """Select held coins covering amount + burn (+ change), exchange
        into ladder payment outputs summing ``amount_mc`` plus ladder
        change outputs, and return the payment token strings.  The burn is
        charged to the payer (requirement 3); change returns to the store."""
        if type(amount_mc) is not int or amount_mc <= 0:
            raise ValueError("amount_mc must be a positive int")
        policy, denoms, _ = self._mint_params()
        picked, total = self._select(
            self._held_coins(), amount_mc, policy, denoms
        )
        burn = compute_burn(total, policy)
        change = total - amount_mc - burn
        new_outputs = [
            (os.urandom(32), a, "payment")
            for a in self._decompose(amount_mc, denoms)
        ] + [
            (os.urandom(32), a, "change") for a in self._decompose(change, denoms)
        ]
        op_id = str(uuid.uuid4())
        body = {
            "idempotency_key": op_id,
            "inputs": [
                format_token(self.mint_id, amt, b64u_decode(sec, expect_len=32))
                for _key, sec, amt in picked
            ],
            "outputs": [
                {"amount_mc": a, "secret_hash": ledger_key(s), "lock": None}
                for s, a, _r in new_outputs
            ],
        }
        self._persist_plan(
            op_id, "pay", body, new_outputs, input_keys=[c[0] for c in picked]
        )
        try:
            self._send_exchange(op_id, body)
        except MintRejected:
            self._resolve_failed(op_id)
            raise
        self._resolve_success(op_id)
        return [
            format_token(self.mint_id, a, s)
            for s, a, r in new_outputs
            if r == "payment"
        ]

    def quote(self, amount_mc: int) -> dict:
        """Dry-run of ``pay``'s coin selection (§4.2, §7.3) so a payer can
        budget before spending.

        Runs the exact selection ``pay(amount_mc)`` would run against the
        current held set and the descriptor's EFFECTIVE burn policy
        (``burn_policy_next`` applied per the mint's own ``mint_time`` —
        L17), and returns ``{"burn_mc", "change_mc", "inputs_mc"}`` with
        ``inputs_mc == amount_mc + burn_mc + change_mc``.  The burn is a
        function of sum(inputs), NOT of ``amount_mc`` (§7.3) — overshoot
        and the consolidation sweep can raise it, which is exactly what
        this call exposes.  Read-only: no store mutation, no HTTP call
        beyond the descriptor read; raises InsufficientFunds like pay."""
        if type(amount_mc) is not int or amount_mc <= 0:
            raise ValueError("amount_mc must be a positive int")
        policy, denoms, _ = self._mint_params()
        _picked, total = self._select(
            self._held_coins(), amount_mc, policy, denoms
        )
        burn = compute_burn(total, policy)
        return {
            "burn_mc": burn,
            "change_mc": total - amount_mc - burn,
            "inputs_mc": total,
        }

    def pay_many(self, amounts: list[int]) -> list[list[str]]:
        """Multi-recipient fan-out in ONE `/v3/exchange` call — one burn
        assessed on sum(inputs) (§3.3 burn-once, §7.3), never one call per
        recipient.

        Selects held coins ONCE covering ``sum(amounts) + burn``, emits
        each recipient's payment outputs ladder-decomposed exactly as
        ``pay`` would (§4.2) plus ladder change back to the store, and
        returns one token-string list per recipient, in order.
        Persist-before-send (§5.1) and idempotency-retry semantics are
        identical to ``pay``.  If the call would exceed the mint's
        published ``limits.max_batch`` (§3.6 bounds len(inputs) +
        len(outputs) of one call), raises ValueError BEFORE persisting
        anything — chunk the amounts across multiple pay_many calls."""
        if not isinstance(amounts, list) or not amounts:
            raise ValueError("amounts must be a non-empty list")
        for a in amounts:
            if type(a) is not int or a <= 0:
                raise ValueError("every amount_mc must be a positive int")
        policy, denoms, max_batch = self._mint_params()
        picked, total = self._select(
            self._held_coins(), sum(amounts), policy, denoms
        )
        burn = compute_burn(total, policy)
        change = total - sum(amounts) - burn
        per_recipient: list[list[tuple[bytes, int]]] = [
            [(os.urandom(32), d) for d in self._decompose(a, denoms)]
            for a in amounts
        ]
        new_outputs = [
            (s, d, "payment") for outs in per_recipient for s, d in outs
        ] + [
            (os.urandom(32), d, "change") for d in self._decompose(change, denoms)
        ]
        if len(picked) + len(new_outputs) > max_batch:
            raise ValueError(
                f"pay_many would need {len(picked)} inputs +"
                f" {len(new_outputs)} outputs, exceeding the mint's"
                f" limits.max_batch of {max_batch} (§3.6); chunk the"
                " amounts across multiple pay_many calls"
            )
        op_id = str(uuid.uuid4())
        body = {
            "idempotency_key": op_id,
            "inputs": [
                format_token(self.mint_id, amt, b64u_decode(sec, expect_len=32))
                for _key, sec, amt in picked
            ],
            "outputs": [
                {"amount_mc": a, "secret_hash": ledger_key(s), "lock": None}
                for s, a, _r in new_outputs
            ],
        }
        self._persist_plan(
            op_id, "pay", body, new_outputs, input_keys=[c[0] for c in picked]
        )
        try:
            self._send_exchange(op_id, body)
        except MintRejected:
            self._resolve_failed(op_id)
            raise
        self._resolve_success(op_id)
        return [
            [format_token(self.mint_id, d, s) for s, d in outs]
            for outs in per_recipient
        ]

    # ------------------------------------------------------------------
    # refused payments (§9.5 — retire the payee's copies)
    # ------------------------------------------------------------------

    def handle_refused(self, tokens: list[str]) -> dict:
        """Re-exchange refused token strings for fresh secrets, making the
        payee's copies dead (§9.5).  Tokens the payee redeemed anyway
        (mint says spent/unknown) are dropped and counted as dead loss.
        Returns {"recovered_mc": int, "dead": [token indices lost]}."""
        parsed = []
        for i, t in enumerate(tokens):
            try:
                tok = parse_token(t)
            except TokenError:
                raise PaymentInvalid(
                    [{"index": i, "kind": "input", "reason": "bad_format"}]
                ) from None
            if tok.mint_id != self.mint_id:
                raise PaymentInvalid(
                    [{"index": i, "kind": "input", "reason": "bad_format"}]
                )
            parsed.append((t, tok))
        remaining = list(parsed)
        recovered = 0
        dead: list[int] = []
        while remaining:
            policy, denoms, _ = self._mint_params()
            total = sum(tok.amount_mc for _s, tok in remaining)
            burn = compute_burn(total, policy)
            net = total - burn
            new_outputs = [
                (os.urandom(32), a, "refund") for a in self._decompose(net, denoms)
            ]
            input_keys = []
            for _s, tok in remaining:
                key = ledger_key(tok.secret)
                row = self._db.execute(
                    "SELECT 1 FROM wallet_tokens WHERE key = ?", (key,)
                ).fetchone()
                if row is not None:
                    input_keys.append(key)
            op_id = str(uuid.uuid4())
            body = {
                "idempotency_key": op_id,
                "inputs": [s for s, _tok in remaining],
                "outputs": [
                    {"amount_mc": a, "secret_hash": ledger_key(s), "lock": None}
                    for s, a, _r in new_outputs
                ],
            }
            self._persist_plan(op_id, "refused", body, new_outputs, input_keys)
            try:
                self._send_exchange(op_id, body)
            except MintRejected as exc:
                self._resolve_failed(op_id)
                bad = sorted(
                    {
                        e["index"]
                        for e in exc.errors
                        if isinstance(e, dict)
                        and e.get("kind") == "input"
                        and e.get("reason") in ("spent", "unknown")
                        and isinstance(e.get("index"), int)
                        and 0 <= e["index"] < len(remaining)
                    },
                    reverse=True,
                )
                if not bad:
                    raise
                for i in bad:
                    tstr, tok = remaining.pop(i)
                    dead.append(tokens.index(tstr))
                    # the payee redeemed it: our copy (if stored) is gone
                    self._mark_dead_if_ours(ledger_key(tok.secret))
                continue
            self._resolve_success(op_id)
            for _s, tok in remaining:
                # reserved inputs already flipped by _resolve_success;
                # handed_over copies not reserved get retired here
                self._mark_dead_if_ours(ledger_key(tok.secret))
            recovered += net
            remaining = []
        return {"recovered_mc": recovered, "dead": sorted(dead)}

    # ------------------------------------------------------------------
    # crash recovery (§5.1 recovery via /v3/status — requirement 2, B3)
    # ------------------------------------------------------------------

    def _status_chunked(self, keys: list[str], max_batch: int) -> list[dict]:
        results: list[dict] = []
        step = max(1, max_batch)
        for i in range(0, len(keys), step):
            _mt, part = self.client.status(keys[i : i + step])
            results.extend(part)
        return results

    def _plan_input_keys(self, request_json: str) -> list[str]:
        """Ledger keys of the stored plan's plain-token inputs that exist
        in this store ("input tokens restored per the stored plan")."""
        keys = []
        try:
            body = json.loads(request_json)
            inputs = body.get("inputs", [])
        except (json.JSONDecodeError, AttributeError):
            return keys
        for item in inputs:
            if not isinstance(item, str):
                continue
            try:
                tok = parse_token(item)
            except TokenError:
                continue
            key = ledger_key(tok.secret)
            row = self._db.execute(
                "SELECT 1 FROM wallet_tokens WHERE key = ?", (key,)
            ).fetchone()
            if row is not None:
                keys.append(key)
        return keys

    def recover(self) -> dict:
        """Resolve every planned (in-flight at crash) operation against the
        mint via batch `/v3/status` (§5.1).

        Outputs known to the ledger  -> the exchange committed: outputs
        become confirmed (a spent output — impossible unless its string
        left this wallet — becomes spent_out), plan inputs become
        spent_out, op done.  All outputs unknown -> the exchange
        definitively did not commit (nothing is in flight after a crash):
        outputs become orphan and the plan's input tokens are restored to
        held iff the mint still reports them unspent."""
        _policy, _denoms, max_batch = self._mint_params()
        summary = {
            "ops_resolved": 0,
            "ops_confirmed": 0,
            "ops_orphaned": 0,
            "outputs_confirmed": 0,
            "outputs_orphaned": 0,
            "inputs_restored": 0,
            "inputs_lost": 0,
        }
        ops = self._db.execute(
            "SELECT op_id, kind, request_json FROM wallet_ops"
            " WHERE state = 'planned' ORDER BY op_id"
        ).fetchall()
        for op_id, _kind, request_json in ops:
            out_rows = self._db.execute(
                "SELECT key FROM wallet_tokens"
                " WHERE op_id = ? AND state = 'pending' ORDER BY key",
                (op_id,),
            ).fetchall()
            out_keys = [r[0] for r in out_rows]
            results = self._status_chunked(out_keys, max_batch)
            committed = any(r.get("state") != "unknown" for r in results)
            input_keys = self._plan_input_keys(request_json)
            if committed:
                def _confirm(c, op_id=op_id, pairs=list(zip(out_keys, results)),
                             input_keys=input_keys):
                    n_conf = 0
                    for key, res in pairs:
                        new_state = (
                            "confirmed"
                            if res.get("state") == "unspent"
                            else "spent_out"
                        )
                        c.execute(
                            "UPDATE wallet_tokens SET state = ?"
                            " WHERE key = ? AND state = 'pending'",
                            (new_state, key),
                        )
                        if new_state == "confirmed":
                            n_conf += 1
                    for key in input_keys:
                        c.execute(
                            "UPDATE wallet_tokens SET state = 'spent_out',"
                            " reserved_by = NULL WHERE key = ?",
                            (key,),
                        )
                    c.execute(
                        "UPDATE wallet_ops SET state = 'done'"
                        " WHERE op_id = ?",
                        (op_id,),
                    )
                    return n_conf

                summary["outputs_confirmed"] += self._txn(_confirm)
                summary["ops_confirmed"] += 1
            else:
                input_results = (
                    self._status_chunked(input_keys, max_batch)
                    if input_keys
                    else []
                )

                def _orphan(c, op_id=op_id, out_keys=out_keys,
                            pairs=list(zip(input_keys, input_results))):
                    for key in out_keys:
                        c.execute(
                            "UPDATE wallet_tokens SET state = 'orphan'"
                            " WHERE key = ? AND state = 'pending'",
                            (key,),
                        )
                    restored = lost = 0
                    for key, res in pairs:
                        if res.get("state") == "unspent":
                            c.execute(
                                "UPDATE wallet_tokens SET state = 'confirmed',"
                                " reserved_by = NULL WHERE key = ?",
                                (key,),
                            )
                            restored += 1
                        else:
                            # spent elsewhere or unknown: not spendable
                            c.execute(
                                "UPDATE wallet_tokens SET state = 'spent_out',"
                                " reserved_by = NULL WHERE key = ?",
                                (key,),
                            )
                            lost += 1
                    c.execute(
                        "UPDATE wallet_ops SET state = 'failed'"
                        " WHERE op_id = ?",
                        (op_id,),
                    )
                    return restored, lost

                restored, lost = self._txn(_orphan)
                summary["outputs_orphaned"] += len(out_keys)
                summary["inputs_restored"] += restored
                summary["inputs_lost"] += lost
                summary["ops_orphaned"] += 1
            summary["ops_resolved"] += 1
        return summary
