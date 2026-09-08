"""C04 — ledgerstore: the sqlite-backed trust core.

Spec: aicash-spec-v0.4.md §3.2 (state), §3.3 (exchange), §3.5 (status
schema), §7.1 (issuance), §7.3 (burn assessment point), §8 (retention).
Locked decisions L1–L6, L12. Depends on C01 (tokencodec), C02 (lockeval),
C03 (burncalc).

This module holds the one atomic operation. `exchange` runs inside a single
sqlite transaction opened with ``BEGIN IMMEDIATE`` — the write lock is taken
before the first read, so concurrent exchanges are fully serialized and
double-spending is prevented here and only here (§3.3: "cannot be
best-effort"). Every failure rolls back all ledger mutations; only the
idempotency record of the rejection is committed (§3.3 / R7).

Secret hygiene (code-inspection requirements):
- By-secret outputs are hashed immediately; the raw secret is never written
  to sqlite, never logged, never stored on the Ledger object.
- Idempotency records store ``key -> (body_digest, result_json)`` only —
  never request bodies (bodies contain live secrets).
- Input token secrets are hashed to their ledger key and discarded.

Clock discipline (L17): the clock is injected, and ``now`` is captured
exactly once per exchange call so every lock in a batch is evaluated
against the same instant.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from typing import Callable, NamedTuple

from aicash.burncalc import BurnPolicy, compute_burn, validate_policy
from aicash.lockeval import InputForm, Lock, LockError, evaluate, validate_lock
from aicash.tokencodec import TokenError, b64u_decode, b64u_encode, ledger_key

__all__ = ["ExchangeRejected", "OutputSpec", "Ledger", "parse_output_wire"]


class ExchangeRejected(Exception):
    """§3.8 enumerated rejection.

    ``errors`` is a list of ``{"index": int | None, "kind": str,
    "reason": str}`` dicts. ``index`` is None for call-level errors
    (``amount_mismatch``, ``idempotency_conflict``), whose ``kind`` is
    ``"call"``; otherwise ``kind`` is ``"input"`` or ``"output"`` and
    ``index`` is the offending position in that array. The
    ``amount_mismatch`` entry additionally carries ``expected_burn_mc``
    — the burn the mint computed from its published policy (public
    information), so a mis-budgeted caller can fix the batch without
    re-deriving the policy arithmetic.

    ``message``, when given, replaces the default exception text (the
    error shape carried in ``errors`` is unaffected).
    """

    def __init__(self, errors: list[dict], message: str | None = None):
        super().__init__(message or "exchange rejected: %r" % (errors,))
        self.errors = errors


class OutputSpec(NamedTuple):
    """One requested output (§3.3): exactly one of secret_hash/secret set.

    ``secret_hash`` is the preferred by-hash form (b64u sha256 of a 32-byte
    secret); ``secret`` is the accepted by-secret form (raw 32 bytes, hashed
    immediately and discarded). ``lock`` is a C02 Lock, an equivalent §3.4
    dict, or None.
    """

    amount_mc: int
    secret_hash: str | None = None
    secret: bytes | None = None
    lock: object | None = None


#: Human-readable statement of the accepted §3.3 output forms, used by
#: error messages that must name them.
OUTPUT_FORMS = (
    'an OutputSpec, or a §3.3 wire dict of exactly '
    '{"amount_mc", "secret_hash"} (by-hash form) or '
    '{"amount_mc", "secret"} (by-secret form), each with an optional '
    '"lock" key (absent and null both mean unlocked)'
)


def parse_output_wire(val: object):
    """Parse one §3.3 wire-form output dict into an ``OutputSpec``.

    This is THE output-dict parser: C06's HTTP layer uses it verbatim, and
    ``Ledger.issue`` accepts wire dicts through it, so the two surfaces can
    never drift. Recognized forms are exactly ``{"amount_mc",
    "secret_hash"}`` and ``{"amount_mc", "secret"}`` (the latter's
    ``secret`` a b64u string of 32 bytes, decoded here), each with an
    optional ``lock`` key — absent and explicit ``null`` both mean
    unlocked. Anything else is returned unchanged so callers report
    ``bad_format`` at that index (§3.8), exactly as the HTTP layer does.
    """
    if not isinstance(val, dict):
        return val
    keys = set(val.keys()) - {"lock"}
    lock = val.get("lock")  # absent and explicit null both mean unlocked
    if keys == {"amount_mc", "secret_hash"}:
        return OutputSpec(
            amount_mc=val["amount_mc"],
            secret_hash=val["secret_hash"],
            lock=lock,
        )
    if keys == {"amount_mc", "secret"}:
        try:
            secret = b64u_decode(val["secret"], expect_len=32)
        except TokenError:
            return val
        return OutputSpec(amount_mc=val["amount_mc"], secret=secret, lock=lock)
    return val


_SCHEMA = """
CREATE TABLE IF NOT EXISTS entries (
  hash               TEXT PRIMARY KEY,
  amount_mc          INTEGER NOT NULL,
  spent              INTEGER NOT NULL DEFAULT 0,
  lock_preimage_hash TEXT,
  lock_expiry        INTEGER,
  lock_refund_hash   TEXT,
  created_at         INTEGER NOT NULL,
  spent_at           INTEGER,
  claim_witness      TEXT
);
CREATE TABLE IF NOT EXISTS supply (
  id                   INTEGER PRIMARY KEY CHECK (id = 1),
  cumulative_issued_mc INTEGER NOT NULL,
  cumulative_burned_mc INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS idempotency (
  key         TEXT PRIMARY KEY,
  body_digest TEXT NOT NULL,
  result_json TEXT NOT NULL,
  created_at  INTEGER NOT NULL
);
"""

_ENTRY_COLS = (
    "hash, amount_mc, spent, lock_preimage_hash, lock_expiry,"
    " lock_refund_hash, created_at, spent_at, claim_witness"
)


def _lock_from_row(row) -> Lock | None:
    """Reconstruct the Lock of an entries row (columns 3..5), or None."""
    if row[3] is None:
        return None
    return Lock(preimage_hash=row[3], expiry=row[4], refund_hash=row[5])


class Ledger:
    """The sqlite-backed Layer 0 ledger (§3.2/§3.3).

    One instance may be shared across threads: each thread gets its own
    sqlite connection, and every write path runs under ``BEGIN IMMEDIATE``
    so sqlite's write lock serializes the critical section end to end.
    """

    def __init__(
        self,
        db_path: str,
        clock: Callable[[], int],
        burn_policy: BurnPolicy,
        recovery_window_ms: int,
        max_lock_expiry_ms: int | None,
    ):
        validate_policy(burn_policy)
        if db_path == ":memory:":
            raise ValueError(
                "db_path ':memory:' is not supported: the Ledger (and the"
                " C06/C10 servers built on it) opens an independent sqlite"
                " connection per thread, and each in-memory connection is"
                " its own separate empty database — the threads would never"
                " see each other's entries. Use a file path instead (e.g."
                " one inside a tempfile.TemporaryDirectory for tests)."
            )
        if type(recovery_window_ms) is not int or recovery_window_ms < 0:
            raise ValueError("recovery_window_ms must be a non-negative int")
        if max_lock_expiry_ms is not None and (
            type(max_lock_expiry_ms) is not int or max_lock_expiry_ms <= 0
        ):
            raise ValueError("max_lock_expiry_ms must be None or a positive int")
        self._db_path = db_path
        self._clock = clock
        self._burn_policy = burn_policy
        self._recovery_window_ms = recovery_window_ms
        self._max_lock_expiry_ms = max_lock_expiry_ms
        self._local = threading.local()
        conn = self._conn()
        conn.executescript(_SCHEMA)
        conn.execute(
            "INSERT OR IGNORE INTO supply"
            " (id, cumulative_issued_mc, cumulative_burned_mc) VALUES (1, 0, 0)"
        )
        conn.commit()

    # ------------------------------------------------------------------
    # read-only configuration views (shared-parameter consistency checks:
    # C06's MintServer verifies at boot that its MintConfig agrees with
    # the Ledger it was handed on these values)
    # ------------------------------------------------------------------

    @property
    def burn_policy(self) -> BurnPolicy:
        """The §7.3 burn policy this ledger assesses (read-only)."""
        return self._burn_policy

    @property
    def recovery_window_ms(self) -> int:
        """The §8(b) retention window used by ``prune`` (read-only)."""
        return self._recovery_window_ms

    @property
    def max_lock_expiry_ms(self) -> int | None:
        """The finite lock horizon (§8(b)), or None (read-only)."""
        return self._max_lock_expiry_ms

    # ------------------------------------------------------------------
    # connection plumbing
    # ------------------------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            # isolation_level=None: manual transaction control — we issue
            # BEGIN IMMEDIATE ourselves (requirement 1).
            conn = sqlite3.connect(
                self._db_path, timeout=30.0, isolation_level=None
            )
            self._local.conn = conn
        return conn

    # ------------------------------------------------------------------
    # input / output resolution (validation reads; no mutation)
    # ------------------------------------------------------------------

    def _fetch_entry(self, conn, key: str):
        cur = conn.execute(
            f"SELECT {_ENTRY_COLS} FROM entries WHERE hash = ?", (key,)
        )
        return cur.fetchone()

    def _resolve_input(self, conn, form, now: int, seen_keys: set):
        """Validate one input against the ledger at ``now``.

        Returns ``(key, amount_mc, reason, claim_witness_b64u)`` where
        ``reason`` is None on success and a §3.8 reason otherwise;
        ``amount_mc`` is the LEDGER entry's amount whenever the entry was
        found (even if the input ultimately fails), else None.
        """
        if not isinstance(form, InputForm):
            return None, None, "bad_format", None

        # Resolve the ledger key (§3.3 step 2): hash of the token secret
        # for plain/claim forms, the literal hash for refund forms.
        if form.kind in ("plain", "claim"):
            token = form.token
            if token is None:
                return None, None, "bad_format", None
            try:
                key = ledger_key(token.secret)
            except (TokenError, AttributeError, TypeError):
                return None, None, "bad_format", None
        elif form.kind == "refund":
            try:
                b64u_decode(form.hash, expect_len=32)
            except TokenError:
                return None, None, "bad_format", None
            key = form.hash
        else:
            return None, None, "bad_format", None

        row = self._fetch_entry(conn, key)
        if row is None:
            return key, None, "unknown", None
        amount = row[1]

        if key in seen_keys:
            # The same ledger entry presented twice in one call: the later
            # occurrence is spending an entry this very call already spends.
            return key, amount, "spent", None
        seen_keys.add(key)

        if row[2]:  # spent
            return key, amount, "spent", None

        # Claim binding (requirement 3): a presented token must agree with
        # the ledger entry it resolves to. Amount is checkable here;
        # mint_id belongs to C06 (the ledger stores no mint_id — see
        # OPEN-QUESTIONS note recorded by this component's build).
        if form.kind in ("plain", "claim"):
            tok_amount = form.token.amount_mc
            if type(tok_amount) is not int or tok_amount != amount:
                return key, amount, "bad_format", None

        lock = _lock_from_row(row)
        verdict = evaluate(lock, form, now)
        if verdict != "ok":
            return key, amount, verdict, None

        witness_b64u = None
        if form.kind == "claim" and lock is not None:
            witness_b64u = b64u_encode(form.witness)
        return key, amount, None, witness_b64u

    def _resolve_output(self, conn, spec, now: int, seen_out_keys: set):
        """Validate one OutputSpec.

        Returns ``(key, amount_mc, lock_or_None, reason_or_None)``.
        The raw secret (by-secret form) is hashed here and never kept
        (requirement 5).
        """
        if not isinstance(spec, OutputSpec):
            return None, None, None, "bad_format"

        amount = spec.amount_mc
        if type(amount) is not int or amount <= 0:
            return None, None, None, "bad_format"

        # Exactly one of secret_hash / secret (§3.3 output forms).
        if (spec.secret_hash is None) == (spec.secret is None):
            return None, amount, None, "bad_format"
        if spec.secret is not None:
            try:
                key = ledger_key(spec.secret)  # hash immediately; discard raw
            except TokenError:
                return None, amount, None, "bad_format"
        else:
            try:
                b64u_decode(spec.secret_hash, expect_len=32)
            except TokenError:
                return None, amount, None, "bad_format"
            key = spec.secret_hash

        lock = None
        if spec.lock is not None:
            lock_obj = spec.lock
            if isinstance(lock_obj, Lock):
                lock_obj = {
                    "preimage_hash": lock_obj.preimage_hash,
                    "expiry": lock_obj.expiry,
                    "refund_hash": lock_obj.refund_hash,
                }
            try:
                lock = validate_lock(lock_obj)
            except LockError:
                return key, amount, None, "bad_format"
            # Requirement 6 / §8(b): finite lock horizon when configured.
            if (
                self._max_lock_expiry_ms is not None
                and lock.expiry > now + self._max_lock_expiry_ms
            ):
                return key, amount, None, "bad_format"

        # Duplicate-output check: against the table (any state — spent
        # history included) AND within the batch (requirement 1).
        if key in seen_out_keys or self._fetch_entry(conn, key) is not None:
            return key, amount, lock, "output_exists"
        seen_out_keys.add(key)
        return key, amount, lock, None

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------

    def issue(self, outputs: list) -> None:
        """§7.1 operator funding: insert unspent entries, no inputs, no burn.

        Each output is an ``OutputSpec`` or a §3.3 wire-form output dict
        (``{"amount_mc", "secret_hash"}`` / ``{"amount_mc", "secret"}``
        with optional ``"lock"``), parsed with the same
        ``parse_output_wire`` helper the HTTP layer uses.
        ``cumulative_issued_mc`` grows by the sum of the amounts,
        transactionally with the inserts (requirement 7). Raises
        ExchangeRejected with enumerated output errors on any invalid
        spec; a dict of unrecognized shape gets ``bad_format`` at its
        index and an exception message naming the expected forms.
        """
        parsed = []
        bad_shape: list[int] = []
        for j, spec in enumerate(outputs):
            if isinstance(spec, dict):
                wire = parse_output_wire(spec)
                if not isinstance(wire, OutputSpec):
                    bad_shape.append(j)
                parsed.append(wire)
            else:
                parsed.append(spec)
        now = self._clock()
        conn = self._conn()
        conn.execute("BEGIN IMMEDIATE")
        try:
            errors = []
            resolved = []
            seen: set = set()
            for j, spec in enumerate(parsed):
                key, amount, lock, reason = self._resolve_output(
                    conn, spec, now, seen
                )
                if reason is not None:
                    errors.append(
                        {"index": j, "kind": "output", "reason": reason}
                    )
                else:
                    resolved.append((key, amount, lock))
            if errors:
                conn.execute("ROLLBACK")
                message = None
                if bad_shape:
                    message = (
                        "issue rejected: outputs at index(es) %s are not a"
                        " recognized output form — each output must be %s;"
                        " full §3.8 errors: %r"
                        % (bad_shape, OUTPUT_FORMS, errors)
                    )
                raise ExchangeRejected(errors, message)
            total = 0
            for key, amount, lock in resolved:
                self._insert_entry(conn, key, amount, lock, now)
                total += amount
            conn.execute(
                "UPDATE supply SET cumulative_issued_mc ="
                " cumulative_issued_mc + ? WHERE id = 1",
                (total,),
            )
            conn.execute("COMMIT")
        except ExchangeRejected:
            raise
        except BaseException:
            conn.execute("ROLLBACK")
            raise

    def _insert_entry(self, conn, key, amount, lock, now):
        conn.execute(
            "INSERT INTO entries (hash, amount_mc, spent, lock_preimage_hash,"
            " lock_expiry, lock_refund_hash, created_at, spent_at,"
            " claim_witness) VALUES (?, ?, 0, ?, ?, ?, ?, NULL, NULL)",
            (
                key,
                amount,
                lock.preimage_hash if lock else None,
                lock.expiry if lock else None,
                lock.refund_hash if lock else None,
                now,
            ),
        )

    def exchange(
        self,
        idempotency_key: str,
        body_digest: str,
        inputs: list,
        input_amount_hint: None = None,
        outputs: list | None = None,
    ) -> dict:
        """The one atomic operation (§3.3), single ``BEGIN IMMEDIATE`` txn.

        Returns ``{"status": "ok", "outputs_confirmed": n, "burn_mc": b}``
        or raises ExchangeRejected with §3.8 enumerated errors. Rejections
        are stored under the idempotency key too (never the request body).
        """
        if input_amount_hint is not None:
            raise ValueError("input_amount_hint must be None")
        if not isinstance(idempotency_key, str) or not idempotency_key:
            raise ValueError("idempotency_key must be a non-empty string")
        if not isinstance(body_digest, str) or not body_digest:
            raise ValueError("body_digest must be a non-empty string")
        if outputs is None:
            raise ValueError("outputs is required")

        now = self._clock()  # captured ONCE per call (requirement 8)
        conn = self._conn()
        conn.execute("BEGIN IMMEDIATE")
        try:
            return self._exchange_locked(
                conn, idempotency_key, body_digest, inputs, outputs, now
            )
        except ExchangeRejected:
            raise
        except BaseException:
            conn.execute("ROLLBACK")
            raise

    def _exchange_locked(
        self, conn, idempotency_key, body_digest, inputs, outputs, now
    ):
        # --- idempotency (§3.3 / R7): replay before any evaluation -----
        row = conn.execute(
            "SELECT body_digest, result_json FROM idempotency WHERE key = ?",
            (idempotency_key,),
        ).fetchone()
        if row is not None:
            stored_digest, result_json = row
            conn.execute("ROLLBACK")  # read-only so far
            if stored_digest != body_digest:
                raise ExchangeRejected(
                    [
                        {
                            "index": None,
                            "kind": "call",
                            "reason": "idempotency_conflict",
                        }
                    ]
                )
            result = json.loads(result_json)
            if result.get("status") == "rejected":
                raise ExchangeRejected(result["errors"])
            return result

        errors: list[dict] = []

        # --- resolve inputs + evaluate locks (requirement 1 order) ------
        seen_in: set = set()
        in_records = []  # (key, amount, claim_witness_b64u) for good inputs
        in_amounts = []
        resolved_keys: list = []
        duplicate_input = False
        for i, form in enumerate(inputs):
            key, amount, reason, witness_b64u = self._resolve_input(
                conn, form, now, seen_in
            )
            in_amounts.append(amount)
            if key is not None:
                # A within-batch duplicate makes sum(in) double-count one
                # entry, so the conservation diagnostic is skipped then.
                if key in resolved_keys:
                    duplicate_input = True
                resolved_keys.append(key)
            if reason is not None:
                errors.append({"index": i, "kind": "input", "reason": reason})
            else:
                in_records.append((key, amount, witness_b64u))

        # --- resolve outputs (incl. duplicate-output check) -------------
        seen_out: set = set()
        out_records = []
        out_amounts = []
        for j, spec in enumerate(outputs):
            key, amount, lock, reason = self._resolve_output(
                conn, spec, now, seen_out
            )
            out_amounts.append(amount)
            if reason is not None:
                errors.append({"index": j, "kind": "output", "reason": reason})
            else:
                out_records.append((key, amount, lock))

        # --- conservation (§3.3 step 1, burn per L12/§7.3) --------------
        # The check is a call-level diagnostic; it is only computable when
        # every input resolved to a known ledger amount (no unknowns, no
        # duplicates) and every output amount parsed.
        burn = None
        if (
            all(a is not None for a in in_amounts)
            and not duplicate_input
            and all(a is not None for a in out_amounts)
        ):
            sum_in = sum(in_amounts)
            burn = compute_burn(sum_in, self._burn_policy)
            if sum_in != sum(out_amounts) + burn:
                # The rejection detail includes the burn the mint computed
                # (public information — it follows from the published §7.3
                # policy and the input sum), so a mis-budgeted caller can
                # rebalance the batch without re-deriving the arithmetic.
                errors.append(
                    {
                        "index": None,
                        "kind": "call",
                        "reason": "amount_mismatch",
                        "expected_burn_mc": burn,
                    }
                )

        if errors:
            # Nothing was mutated. Commit ONLY the stored rejection (R7).
            self._store_idempotency(
                conn,
                idempotency_key,
                body_digest,
                {"status": "rejected", "errors": errors},
                now,
            )
            conn.execute("COMMIT")
            raise ExchangeRejected(errors)

        assert burn is not None
        # --- mark spent -------------------------------------------------
        for key, _amount, witness_b64u in in_records:
            cur = conn.execute(
                "UPDATE entries SET spent = 1, spent_at = ?,"
                " claim_witness = ? WHERE hash = ? AND spent = 0",
                (now, witness_b64u, key),
            )
            if cur.rowcount != 1:  # pragma: no cover — serialized by lock
                raise RuntimeError("input vanished inside transaction")

        # --- insert outputs ----------------------------------------------
        for key, amount, lock in out_records:
            self._insert_entry(conn, key, amount, lock, now)

        # --- supply counters, transactionally (requirement 7) ------------
        conn.execute(
            "UPDATE supply SET cumulative_burned_mc ="
            " cumulative_burned_mc + ? WHERE id = 1",
            (burn,),
        )

        result = {
            "status": "ok",
            "outputs_confirmed": len(out_records),
            "burn_mc": burn,
        }
        self._store_idempotency(conn, idempotency_key, body_digest, result, now)
        conn.execute("COMMIT")
        return result

    def _store_idempotency(self, conn, key, digest, result, now):
        # Digest + result only — NEVER request bodies or secrets (§3.3).
        conn.execute(
            "INSERT INTO idempotency (key, body_digest, result_json,"
            " created_at) VALUES (?, ?, ?, ?)",
            (key, digest, json.dumps(result, sort_keys=True), now),
        )

    def status(self, hashes: list) -> tuple[int, list[dict]]:
        """§3.5 batch status: ``(mint_time, results)`` order-aligned.

        Pinned per-hash schema: known entries get ``state``, ``amount_mc``,
        full ``lock`` object or null, ``spent_at``, ``claim_witness``
        (b64u, present only for claim-path spends still retained).
        Unknown (or unparseable) hashes get ``{"state": "unknown"}`` only.
        Read-only; never spends.
        """
        mint_time = self._clock()
        conn = self._conn()
        results = []
        for h in hashes:
            try:
                b64u_decode(h, expect_len=32)
            except TokenError:
                results.append({"state": "unknown"})
                continue
            row = self._fetch_entry(conn, h)
            if row is None:
                results.append({"state": "unknown"})
                continue
            lock = _lock_from_row(row)
            results.append(
                {
                    "state": "spent" if row[2] else "unspent",
                    "amount_mc": row[1],
                    "lock": None
                    if lock is None
                    else {
                        "preimage_hash": lock.preimage_hash,
                        "expiry": lock.expiry,
                        "refund_hash": lock.refund_hash,
                    },
                    "spent_at": row[7],
                    "claim_witness": row[8],
                }
            )
        return mint_time, results

    def supply(self) -> dict:
        """§3.6 supply aggregates (unsigned; C05/C06 sign the snapshot).

        ``outstanding_mc`` is the actual sum of unspent entry amounts — not
        derived from the counters — so the §3.6 invariant
        ``outstanding == issued − burned`` is observable, not tautological.
        """
        conn = self._conn()
        row = conn.execute(
            "SELECT (SELECT COALESCE(SUM(amount_mc), 0) FROM entries"
            " WHERE spent = 0), cumulative_issued_mc, cumulative_burned_mc"
            " FROM supply WHERE id = 1"
        ).fetchone()
        return {
            "outstanding_mc": row[0],
            "cumulative_issued_mc": row[1],
            "cumulative_burned_mc": row[2],
        }

    def prune(self) -> int:
        """§8(b): delete spent records older than the recovery window.

        Only entries with ``spent = 1`` and ``spent_at < now − window`` are
        deleted — unspent and locked-unspent entries are never pruned.
        Expired idempotency records are deleted on the same schedule.
        ``claim_witness`` disappears with its record (§8 design). Returns
        the number of ledger entries deleted.
        """
        now = self._clock()
        cutoff = now - self._recovery_window_ms
        conn = self._conn()
        conn.execute("BEGIN IMMEDIATE")
        try:
            cur = conn.execute(
                "DELETE FROM entries WHERE spent = 1 AND spent_at < ?",
                (cutoff,),
            )
            count = cur.rowcount
            conn.execute(
                "DELETE FROM idempotency WHERE created_at < ?", (cutoff,)
            )
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        return count
