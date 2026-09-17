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
against the same instant — and, since a mint may have a §7.3 change
notice outstanding, so is the burn policy: the SAME ``now`` selects it
through ``burncalc.effective_policy``. §3.3 step 1 says the burn is
computed "per the mint's published burn policy (§7.3)", and §7.3 says an
announced ``burn_policy_next`` is in force from its ``effective_at``; the
published policy at the instant of a call is therefore the one this
ledger must charge at that instant, not the one it was built with. A
ledger holding a single frozen policy disagreed with every client the
moment a scheduled change took effect (every reference client already
selects through ``effective_policy``), so a plain receive failed
``amount_mismatch`` fleet-wide — found by outside review 2026-09-16.
The selection rule has exactly one public entry point,
``Ledger.effective_burn_policy(now)``: ``exchange`` prices through it, and
so must any mint-side caller that pre-computes a burn before calling
``exchange`` (C10's supervision profile does). Reading the private
``_burn_policy`` instead is the same bug one layer up — the two sides
agree until ``effective_at`` and then reject each other's arithmetic.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from typing import Callable, NamedTuple

from aicash.burncalc import (
    BurnPolicy,
    compute_burn,
    effective_policy,
    validate_policy,
)
from aicash.lockeval import InputForm, Lock, LockError, evaluate, validate_lock
from aicash.tokencodec import (
    MAX_AMOUNT_MC,
    TokenError,
    b64u_decode,
    b64u_encode,
    ledger_key,
)

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

#: Inclusive bounds of SQLite's INTEGER storage class — a signed 64-bit
#: value. Every number this module binds into a column (``amount_mc``,
#: ``lock_expiry``, the two supply counters) has to live in here, because
#: outside it ``conn.execute`` raises ``OverflowError`` — not a
#: ``sqlite3.Error``, not an ``ExchangeRejected``, but a bare exception out
#: of the driver that every ``except ExchangeRejected`` in the tree walks
#: past. The maximum is C01's ``MAX_AMOUNT_MC`` and not a second literal:
#: tokencodec already answers "how big can an amount be" with exactly this
#: number and for exactly this reason (the column), so a repository with
#: two spellings of it is a repository where one of them can be retuned
#: alone. C10's ``_plain_int`` states the same pair for the supervision
#: tables; these three are one bound with one cause.
_SQLITE_INT_MIN = -(2 ** 63)
_SQLITE_INT_MAX = MAX_AMOUNT_MC


def _storable_int(v: object) -> bool:
    """True for an integer this ledger can actually put in a column.

    THE chokepoint for every caller-supplied number on its way into
    sqlite, and stated as a bound on the VALUE rather than as a guard on
    the one field a report happened to name.

    A type check is not a validity check. ``_resolve_output`` checked
    ``type(amount) is not int or amount <= 0`` and stopped there, and
    Python's ``int`` is unbounded while SQLite's is not: nineteen nines
    (9999999999999999999) is valid JSON, the correct type, and positive,
    so it passed every guard on ``/admin/issue``, reached
    ``conn.execute`` in ``_insert_entry`` and raised ``OverflowError``.
    ``issue``'s ``except BaseException: rollback; raise`` re-raised it
    into C06's blanket 500 handler, and the caller got a bare 500 with no
    ``errors`` list — which §3.8 forbids: a value the mint refuses owes an
    ENUMERATED reason.

    Nobody noticed because the identical value through ``/v3/exchange``
    was refused correctly, and refused by a DIFFERENT check: conservation
    (inputs must equal outputs plus burn) cannot be satisfied by an amount
    no entry can hold, so the route that had no bound was covered by
    arithmetic that happens to also catch it. A check that covers a case
    by accident is a check that stops covering it the moment the accident
    changes — ``issue`` has no inputs and therefore no conservation, which
    is exactly why it was the route that broke.

    The reason is ``bad_format``: §3.8's vocabulary is ratified and has no
    length- or range-specific entry, and "an integer larger than the mint
    can store" is a malformed field rather than an internal fault. C01
    says the same thing in its own vocabulary (``TokenError``) about the
    same number, and C10's ``_plain_int`` says it about the supervision
    columns.
    """
    # bool is excluded: type(True) is bool, not int — and a bool bound
    # into an INTEGER column would silently become 0 or 1.
    return type(v) is int and _SQLITE_INT_MIN <= v <= _SQLITE_INT_MAX


def _validate_next(next_: object) -> tuple[BurnPolicy, int] | None:
    """Normalize and validate a §7.3 change notice for the Ledger.

    Accepts None or a 2-sequence ``(BurnPolicy, effective_at_ms)`` and
    returns it as a tuple. A malformed notice is refused HERE, at
    construction, rather than at the first exchange that would have to
    select through it: a burn policy the ledger cannot evaluate is not a
    payment-time error to discover under load.
    """
    if next_ is None:
        return None
    try:
        policy, effective_at = next_
    except (TypeError, ValueError):
        raise ValueError(
            "burn_policy_next must be None or a (BurnPolicy, effective_at)"
            " pair, got %r" % (next_,)
        ) from None
    validate_policy(policy)
    if type(effective_at) is not int or effective_at < 0:
        raise ValueError(
            "burn_policy_next effective_at must be a non-negative plain int"
            " of milliseconds, got %r" % (effective_at,)
        )
    return (policy, effective_at)


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
        burn_policy_next: tuple[BurnPolicy, int] | None = None,
    ):
        validate_policy(burn_policy)
        burn_policy_next = _validate_next(burn_policy_next)
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
        self._burn_policy_next = burn_policy_next
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
        """The §7.3 burn policy this ledger was CONFIGURED with (read-only).

        This is the mint's published ``burn_policy`` descriptor field, and
        it is what C06 checks its ``MintConfig`` against at boot — a
        configuration value, fixed for the life of the object. It is NOT
        necessarily the policy a call made right now would be charged: an
        announced ``burn_policy_next`` supersedes it from its
        ``effective_at`` onwards. Anything pricing a call must ask
        ``effective_burn_policy(now)`` instead.
        """
        return self._burn_policy

    @property
    def burn_policy_next(self) -> tuple[BurnPolicy, int] | None:
        """The announced §7.3 change notice as ``(policy, effective_at)``,
        or None (read-only). From ``effective_at`` onwards ``exchange``
        assesses THIS policy; before it, ``burn_policy``."""
        return self._burn_policy_next

    def effective_burn_policy(self, now: int | None = None) -> BurnPolicy:
        """The §7.3 policy ``exchange`` CHARGES at ``now`` (§3.3 step 1).

        The one public answer to "what does this ledger cost at this
        instant": ``burn_policy`` before an announced change, the
        ``burn_policy_next`` policy from its ``effective_at`` onwards.
        ``exchange`` itself prices every call through this method with the
        single instant it captured, so a caller that budgets a batch
        through it agrees with the conservation check by construction.

        ``now`` defaults to a read of this ledger's own clock. Pass the
        instant explicitly whenever the caller already has one for the
        operation it is building — that is the only way a mint-side caller
        and the exchange it is about to make can be certain they priced
        the same instant. A caller that quotes in the last microseconds
        before ``effective_at`` and calls after it still gets a clean
        call-level ``amount_mismatch`` carrying ``expected_burn_mc``, not
        a corrupted ledger; it can rebuild and retry.

        Exposed because the alternative is what mint-side callers were
        actually doing: reaching for the private ``_burn_policy`` (or
        re-importing ``burncalc.effective_policy`` and re-assembling the
        pair by hand) to pre-compute a burn, which silently drifts from
        what ``exchange`` charges the day a change notice takes effect.
        Do not reimplement the selection rule — call this.
        """
        if now is None:
            now = self._clock()
        return effective_policy(self._burn_policy, self._burn_policy_next, now)

    @property
    def recovery_window_ms(self) -> int:
        """The §8(b) retention window used by ``prune`` (read-only)."""
        return self._recovery_window_ms

    @property
    def max_lock_expiry_ms(self) -> int | None:
        """The finite lock horizon (§8(b)), or None (read-only)."""
        return self._max_lock_expiry_ms

    def adopt_burn_policy_next(self, next_: tuple[BurnPolicy, int]) -> None:
        """Complete a ledger that was never told about a §7.3 change notice.

        A BOOT-TIME reconciliation, not a setter. It is legal exactly once
        and exactly when this ledger holds no notice at all: a ledger that
        already has one keeps it, and the caller gets a ValueError rather
        than a silent re-schedule. C06's ``MintServer`` calls it for the
        hand-wired case — a ``MintConfig`` that publishes
        ``burn_policy_next`` handed to a ``Ledger`` built without it — so
        the mint cannot advertise a scheduled change it would then fail to
        charge (``make_mint`` passes it to the constructor and never comes
        here). Call it before serving; it is not synchronized against
        in-flight exchanges.
        """
        normalized = _validate_next(next_)
        if normalized is None:
            raise ValueError(
                "adopt_burn_policy_next needs a (BurnPolicy, effective_at)"
                " pair; None would be a way to CLEAR an announced change,"
                " which this method deliberately cannot do"
            )
        if self._burn_policy_next is not None:
            raise ValueError(
                "this Ledger already carries a burn_policy_next %r;"
                " adopt_burn_policy_next completes a ledger that was never"
                " told about a change notice, it never replaces one"
                % (self._burn_policy_next,)
            )
        self._burn_policy_next = normalized

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
        if not _storable_int(amount) or amount <= 0:
            # Bounded HERE, at the one place an output amount enters the
            # ledger, so `issue` and `exchange` both get it rather than
            # whichever route someone remembers to patch. See
            # _storable_int: the upper bound is the column's, and an
            # amount past it used to reach conn.execute and answer a bare
            # 500 out of /admin/issue.
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
            if not _storable_int(lock.expiry):
                # The SECOND caller-supplied number on an entries row, and
                # the same defect one column across: C02's validate_lock
                # pins expiry's FORM (a positive int of milliseconds) and
                # says nothing about its size, so `{"expiry": 10**19}` is
                # a valid §3.4 lock that raises OverflowError out of
                # `_insert_entry` exactly as an oversized amount did.
                # Found by sweeping this module for the shape rather than
                # by a second report.
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
            # The THIRD number this call binds, and the one no per-value
            # bound reaches: `cumulative_issued_mc + total`. Every amount
            # can be individually storable and their SUM still not be —
            # two outputs of _SQLITE_INT_MAX apiece bound a total of
            # 2**64-2 into the supply UPDATE below and raised the same
            # OverflowError, the same bare 500, from the same route. So
            # the headroom is read once inside the transaction (BEGIN
            # IMMEDIATE is already held, so no other writer can move it)
            # and the batch is walked against it, which also names the
            # index at which the ledger ran out of column — §3.8 wants an
            # index, and "somewhere in this batch" is not one.
            issued = conn.execute(
                "SELECT cumulative_issued_mc FROM supply WHERE id = 1"
            ).fetchone()[0]
            running = issued
            for j, spec in enumerate(parsed):
                key, amount, lock, reason = self._resolve_output(
                    conn, spec, now, seen
                )
                if reason is None and running > _SQLITE_INT_MAX - amount:
                    # Not a statement about this amount on its own (it
                    # passed _storable_int) but about this mint: the
                    # supply counter cannot record it. `bad_format` for
                    # the same reason _storable_int gives — §3.8's
                    # vocabulary is ratified, carries no range reason, and
                    # an enumerated reason at the right index beats a bare
                    # 500 by the whole of §3.8.
                    reason = "bad_format"
                if reason is not None:
                    errors.append(
                        {"index": j, "kind": "output", "reason": reason}
                    )
                else:
                    running += amount
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
            # §3.3 step 1 / §7.3: the policy in force AT THIS CALL'S
            # clock. `now` is the single instant `exchange` captured for
            # this call (requirement 8) and carried into the transaction,
            # the same one every lock in the batch was evaluated against —
            # so one call is priced under exactly one policy, and a
            # scheduled change flips for the ledger at the instant it flips
            # for every client reading the descriptor.
            burn = compute_burn(sum_in, self.effective_burn_policy(now))
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
