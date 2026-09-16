"""C06 — mintapi: the HTTP surface of a mint.

Spec: aicash-spec-v0.4.md §3.3 (exchange wire forms), §3.5 (status),
§3.6 (descriptor), §3.7 (anonymous bearer access), §3.8 (error semantics).
Locked: L2 (no auth on Layer 0), L11 (performance self-attested/nullable),
L17 (Ed25519 static key, rate limits published-not-enforced, plain HTTP,
injected clock). Depends: C04 (ledgerstore), C05 (signing), and through
them C01–C03.

JSON in/out over stdlib ``ThreadingHTTPServer``. The server holds no
money logic of its own: it parses §3.3 wire forms into C04's typed forms,
lets the ledger's single atomic transaction decide, and serializes results
with C01's canonical JSON so response bytes are stable (byte-identical
idempotency replays, reproducible client-side digests).

Time discipline (L17): C06 never reads wall time. The mint clock is
whatever clock the injected Ledger was built with, observed through the
public ``Ledger.status`` return value.

Snapshot integrity (§3.6): ``snapshot_seq`` is persisted in the same
sqlite database as the ledger (C06-owned tables, never touching C04's),
as the HIGH-WATER MARK of a reserved block that the server hands out from
memory. A restarted mint therefore resumes strictly above every seq it
could have signed — it can never sign two snapshots that violate §3.6
monotonicity ("portable proof of nonconformance") merely by restarting —
while a descriptor fetch stays a read, so an anonymous poller cannot take
the payment database's write lock (see ``_Core.descriptor``). Because the
ordering of a snapshot's supply read against its seq is now held by an
in-process mutex rather than by sqlite's write lock, one ledger file may
be served by exactly ONE mint process: ``_Core._claim_single_writer``
takes an advisory ``flock`` on the ledger and a second server refuses to
start or to serve a descriptor (§3.6's proof-of-nonconformance is not
something an honest mint may leave to a deployment convention). Activity
counters live in the same store: windowed to the current mint-clock day
and counted at most once per idempotency key, so §3.3 replays never
double-count and "daily" figures never accumulate process-lifetime
totals.

Resource bounds (deployment, not §3.7 rate limiting — L17 scopes
enforcement out): ``MAX_BODY_BYTES`` caps what one request may make the
server allocate, ``MAX_IDEMPOTENCY_KEY_LEN`` caps what one caller may
write into the §8 recovery window, ``_Handler.timeout`` caps how long one
recv may block, and ``MAX_REQUEST_SECONDS`` caps the WALL-CLOCK life of a
whole request so a peer that drips a byte at a time — resetting the idle
timeout on every recv — still cannot hold a thread (see
``_DeadlineRaw``). All four bound a SINGLE request; none of them counts
requests per caller. None is published in §3.6's ``limits``: that object
is the pinned home of the protocol limit (``max_batch``) and its scope
guard is explicit, so a body the mint declines to read is reported with
the §3.8 reason for an envelope it cannot parse — ``bad_format``, which
is permanent — and never with ``over_batch_limit``, which §9.5 classifies
as retryable with backoff and which would send a payer into a retry loop
over bytes that can never succeed.

Secret hygiene (§3.1, requirement 5): request bodies are never logged.
The access log (logger ``aicash.mintapi``) carries route pattern + status
code only — even the path is normalized to a fixed route pattern so a
confused client that puts a token in a URL still cannot make the server
log secret material. Never a stack trace in a response body.
"""

from __future__ import annotations

import hmac
import io
import json
import logging
import os
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:  # POSIX only; the reference build targets Linux (see DEPLOYMENT).
    import fcntl
except ImportError:  # pragma: no cover - no advisory locking available
    fcntl = None

from aicash.burncalc import BurnPolicy, validate_policy
from aicash.clock import system_clock
from aicash.ledgerstore import (
    ExchangeRejected,
    Ledger,
    OutputSpec,
    parse_output_wire,
)
from aicash.lockeval import InputForm
from aicash.signing import attach_sig, pubkey_b64u
from aicash.tokencodec import (
    MINT_ID_RE,
    TokenError,
    b64u_decode,
    body_digest,
    canonical_json,
    parse_token,
)

__all__ = ["MintConfig", "MintServer", "make_mint"]

logger = logging.getLogger("aicash.mintapi")

_DAY_MS = 86_400_000

# Largest request body the server will read, in bytes (§3.3/§3.6 limits).
# Sized from the ONE published limit that bounds a legal call: max_batch
# (default 256) entries. The fattest legal entry is a claim input
# ``{"token": "...", "witness": "..."}`` or an output carrying a §3.4 lock:
# a token is "v3:<mint_id<=64>:<amount>:<secret b64u 43>" and every hash or
# witness is a 43-character b64u of 32 bytes, so ~300 bytes of JSON per
# entry is already generous. 256 entries then need ~77 KiB; 1 MiB leaves
# better than 13x headroom AT THAT DEFAULT for whitespace, a long mint_id and
# the envelope, while still refusing the unbounded ``Content-Length`` a single
# client used to be able to make the server allocate. That headroom is a
# property of the default max_batch, not of this cap: max_batch is
# configurable, and at the largest value this cap admits (_max_batch_ceiling)
# the cap is only ~1.5x a maximal call, not 13x it (677 KB canonical, 707 KB
# as json.dumps writes it, against 1 MiB). Not a
# rate limit (L17 scopes those out) — a per-request allocation bound. A
# deployment that raises max_batch past what this cap can carry is refused at
# construction rather than left to publish an impossible limit: see
# _max_batch_ceiling and MintConfig.
MAX_BODY_BYTES = 1_048_576

# §3.3 idempotency keys are caller-chosen and are PERSISTED by C04 for the
# whole §8 recovery window (90 days by default), so an unbounded key is
# unbounded storage a caller writes into the mint for free. 128 characters
# fits every sane construction with room to spare: a UUID is 36, a b64u
# SHA-256 is 43, a "<caller>:<uuid>" namespaced pair well under 100.
MAX_IDEMPOTENCY_KEY_LEN = 128

# Per-entry byte ALLOWANCE for the max_batch cross-check against
# MAX_BODY_BYTES (see MintConfig.__post_init__), so a mint can never publish
# in limits.max_batch a batch size whose maximal call its own body cap always
# refuses. MEASURED against the fattest entry a CONFORMING caller sends: an
# output carrying a §3.4 lock,
#   {"amount_mc":<19 digits>,"secret_hash":"<43>","lock":{"preimage_hash":
#    "<43>","expiry":<13 digits>,"refund_hash":"<43>"}}
# at 247 bytes with no insignificant whitespace and 257 the way json.dumps
# writes it by default; the fattest input, a claim {"token","witness"} whose
# token carries a 64-character mint_id, is 206 / 209. 384 keeps better than
# 50% headroom over the worst of those, for the whitespace a client is free
# to send and for any future field that grows an entry.
#
# NOT an upper bound over every entry the mint will parse, and deliberately
# not claimed as one. §3.1 pins an amount's FORM (^[1-9][0-9]*$) but not its
# LENGTH, so {"amount_mc": <1000 digits>, "secret_hash": "<43>"} is an entry
# the mint reads and answers `amount_mismatch` — not `bad_format` — at ~1074
# bytes, 2.8x this allowance. A caller sending max_batch entries of that
# shape can still put a body over MAX_BODY_BYTES. The ceiling below NARROWS
# that hole (it closes max_batch=8000, where every maximal call of the
# ordinary shape was refused) rather than closing it; closing it needs a
# length bound on amounts in C01, which is a protocol question and not a
# deployment-config one. test_c06 pins both halves of this.
_FAT_ENTRY_BYTES = 384

# Allowance for everything outside the two entry arrays: the idempotency_key
# (bounded by MAX_IDEMPOTENCY_KEY_LEN above), the three envelope keys, the
# brackets and the separators — under 300 bytes in the worst case. 1024 is
# deliberate slack, not a measurement.
_ENVELOPE_BYTES = 1024


def _max_batch_ceiling(body_cap: int | None = None) -> int:
    """Largest ``max_batch`` a body cap of ``body_cap`` bytes can carry.

    ``body_cap`` defaults to the LIVE value of MAX_BODY_BYTES, read at call
    time. Spelling that default as ``body_cap: int = MAX_BODY_BYTES`` binds
    it at IMPORT instead, which is the same cap-versus-cap drift this
    arithmetic exists to prevent: ``_Handler._read_json`` reads the global
    per request, so a deployment that retunes MAX_BODY_BYTES would have had
    its config validated against the old number while the reader enforced
    the new one — and the refusal it printed quoted the new one while
    refusing on the old, making its own remedy inert.

    At least 1: a mint that cannot carry one entry is broken in a way this
    arithmetic is not the place to report.
    """
    if body_cap is None:
        body_cap = MAX_BODY_BYTES
    return max(1, (body_cap - _ENVELOPE_BYTES) // _FAT_ENTRY_BYTES)


# Wall-clock life of ONE request: request line, headers and body together.
# ``_Handler.timeout`` is a per-recv IDLE timeout and nothing more — a peer
# that sends one byte every few seconds resets it on every recv, so
# ``Content-Length: 1048576`` (exactly at MAX_BODY_BYTES, so the byte cap
# never fires) plus a drip holds a daemon thread and a file descriptor for
# as long as the attacker keeps dripping; ThreadingHTTPServer caps neither
# connections nor threads, so N such sockets are N parked threads. That is
# the same exhaustion the idle timeout was added for, only cheaper to mount,
# so the deadline is enforced in wall clock, not idleness (``_DeadlineRaw``).
# 30s against the ~77 KiB of a full max_batch call is a floor of ~2.5 KiB/s,
# far below any link a mint is reachable on and far above what a drip is.
MAX_REQUEST_SECONDS = 30.0

# §3.6 snapshot_seq allocation block. See _Core._next_snapshot_seq: the seq
# is handed out from a reserved in-memory block so a descriptor fetch is a
# read, not a write, amortizing one sqlite write over this many snapshots.
_SEQ_BLOCK = 1024

_PERFORMANCE_FIELDS = frozenset(
    {"p99_exchange_ms", "sustained_qps", "window_days", "measured_at"}
)


def _require_plain_int(name: str, value: object, minimum: int | None = None):
    if type(value) is not int:
        raise ValueError(f"{name} must be a plain int")
    if minimum is not None and value < minimum:
        raise ValueError(f"{name} must be >= {minimum}")
    return value


def _default_rate() -> dict:
    # §3.6 pinned schema: per_caller_rps, burst, scope. OPEN-QUESTIONS R15
    # closed the old Open #3 and pinned scope as mandatory; this function was
    # still emitting the pre-resolution shape. Found 2026-09-08 by an outside
    # implementation reading the descriptor against §3.6.
    return {"per_caller_rps": 50, "burst": 200, "scope": "ip"}


RATE_SCOPES = ("ip", "connection", "global")


def _validate_rate(name: str, r: object) -> None:
    """Enforce the §3.6 pinned rate schema.

    Nothing checked this, which is how the descriptor shipped without `scope`
    against a decision (OPEN-QUESTIONS R15) that had already closed pinning it
    as mandatory. A published descriptor is a conformance claim; an unvalidated
    one is a claim nobody checked.
    """
    if not isinstance(r, dict):
        raise ValueError(f"{name} must be a dict")
    missing = {"per_caller_rps", "burst", "scope"} - set(r)
    if missing:
        raise ValueError(f"{name} missing §3.6 pinned field(s): "
                         f"{', '.join(sorted(missing))}")
    if isinstance(r["per_caller_rps"], bool) or not isinstance(
            r["per_caller_rps"], (int, float)):
        raise ValueError(f"{name}.per_caller_rps must be a number")
    _require_plain_int(f"{name}.burst", r["burst"], 0)
    if r["scope"] not in RATE_SCOPES:
        raise ValueError(f"{name}.scope must be one of {', '.join(RATE_SCOPES)}")


def _policy_dict(p: BurnPolicy) -> dict:
    return {
        "rate_ppm": p.rate_ppm,
        "cap_mc": p.cap_mc,
        "exempt_below_mc": p.exempt_below_mc,
    }


@dataclass(frozen=True)
class MintConfig:
    """Everything a mint advertises and enforces at the HTTP surface.

    ``burn_policy_next`` is ``None`` or ``(BurnPolicy, effective_at_ms)``
    (§7.3 change notice, rendered as the §3.6 descriptor field).
    ``performance`` is ``None`` or the §3.6 self-attested dict (rendered
    ``null`` when stale — L11). ``admin_token``, when set, gates the
    non-normative ``/admin/issue`` path via the ``X-Admin-Token`` header;
    Layer 0 endpoints never require it (L2/§3.7).
    """

    mint_id: str
    baseline_model_class: str
    burn_policy: BurnPolicy
    signing_private: bytes
    signing_public: bytes
    denominations_mc: tuple[int, ...] = (1, 10, 100, 1_000, 10_000, 100_000)
    burn_policy_next: tuple[BurnPolicy, int] | None = None
    max_batch: int = 256
    anonymous_rate: dict = field(default_factory=_default_rate)
    registered_rate: dict = field(default_factory=_default_rate)
    grace_ms: int = 5_000
    timestamp_precision_ms: int = 1
    max_lock_expiry_ms: int | None = 30 * _DAY_MS
    recovery_window_ms: int = 90 * _DAY_MS
    prunes_spent_records: bool = False
    policy_url: str = "about:blank"
    performance: dict | None = None
    profiles: tuple[str, ...] = ()
    admin_token: str | None = None

    def __post_init__(self):
        if not isinstance(self.mint_id, str) or not self.mint_id:
            raise ValueError("mint_id must be a non-empty string")
        if not MINT_ID_RE.fullmatch(self.mint_id):
            # The exact §3.1 rule C01 pins for token strings — a config
            # that violates it would mint tokens no parser accepts.
            raise ValueError(
                "invalid mint_id %r: a mint_id must be 1-64 characters of"
                " lowercase ASCII letters, digits, or hyphen"
                " (regex ^[a-z0-9-]{1,64}$; tokencodec.MINT_ID_RE)"
                % (self.mint_id,)
            )
        if not isinstance(self.baseline_model_class, str):
            raise ValueError("baseline_model_class must be a string")
        validate_policy(self.burn_policy)
        if self.burn_policy_next is not None:
            next_policy, effective_at = self.burn_policy_next
            validate_policy(next_policy)
            _require_plain_int("burn_policy_next effective_at", effective_at, 0)
        _validate_rate("anonymous_rate", self.anonymous_rate)
        _validate_rate("registered_rate", self.registered_rate)
        for kb in ("signing_private", "signing_public"):
            v = getattr(self, kb)
            if not isinstance(v, bytes) or len(v) != 32:
                raise ValueError(f"{kb} must be 32 raw bytes")
        for d in self.denominations_mc:
            _require_plain_int("denomination", d, 1)
        _require_plain_int("max_batch", self.max_batch, 1)
        # max_batch is PUBLISHED (§3.6 limits.max_batch) and MAX_BODY_BYTES
        # is not, so a config whose published limit the byte cap cannot carry
        # makes the mint advertise a batch size whose maximal call it
        # always refuses — and refuses with `bad_format`, which §9.5 pins as
        # PERMANENT, so a payer aiming at the published limit with entries of
        # ordinary size has no conforming recovery. (Smaller entries still
        # get through at such a max_batch, which is what made this silent:
        # the limit is not unusable, only unreachable at the size it
        # promises.)
        # The two numbers were never cross-checked: max_batch=8000 was
        # accepted silently. Refused at construction instead, because the
        # alternative is a descriptor that lies.
        ceiling = _max_batch_ceiling(MAX_BODY_BYTES)
        if self.max_batch > ceiling:
            # The BUDGET, not a measurement: _FAT_ENTRY_BYTES is an
            # allowance over the fattest conforming entry (see its comment),
            # so this number is what the mint sizes against, which is what
            # an operator has to move to get past this refusal. Raising
            # MAX_BODY_BYTES to exactly this figure admits exactly this
            # max_batch — the arithmetic below is the same one, inverted.
            budget = _ENVELOPE_BYTES + self.max_batch * _FAT_ENTRY_BYTES
            raise ValueError(
                "max_batch=%d exceeds what this mint's request body cap can"
                " carry: at an allowance of %d bytes per entry plus %d for"
                " the envelope, a call at that published limit is budgeted"
                " at about %d bytes against a MAX_BODY_BYTES of %d, so the"
                " mint would advertise in limits.max_batch a batch size its"
                " own body cap refuses with a permanent bad_format. Lower"
                " max_batch to %d or below, or raise MAX_BODY_BYTES to at"
                " least %d."
                % (self.max_batch, _FAT_ENTRY_BYTES, _ENVELOPE_BYTES,
                   budget, MAX_BODY_BYTES, ceiling, budget)
            )
        _require_plain_int("grace_ms", self.grace_ms, 0)
        _require_plain_int(
            "timestamp_precision_ms", self.timestamp_precision_ms, 1
        )
        if self.max_lock_expiry_ms is not None:
            _require_plain_int("max_lock_expiry_ms", self.max_lock_expiry_ms, 1)
        _require_plain_int("recovery_window_ms", self.recovery_window_ms, 0)
        if self.prunes_spent_records and self.max_lock_expiry_ms is None:
            # §8(b): prunes_spent_records: true REQUIRES a finite lock horizon.
            raise ValueError(
                "prunes_spent_records requires a finite max_lock_expiry_ms"
            )
        # (rate schemas validated above by _validate_rate against the §3.6
        # pinned shape. The loop that stood here required every value to be a
        # plain int, which did not merely omit the mandatory `scope` field —
        # it made adding it raise. The descriptor could not have conformed.)
        if self.performance is not None:
            perf = self.performance
            if not isinstance(perf, dict) or set(perf) != _PERFORMANCE_FIELDS:
                raise ValueError(
                    "performance must be None or have exactly the fields "
                    f"{sorted(_PERFORMANCE_FIELDS)}"
                )
            for k in _PERFORMANCE_FIELDS:
                _require_plain_int(f"performance.{k}", perf[k], 0)
            _require_plain_int("performance.window_days", perf["window_days"], 1)
        if self.admin_token is not None and (
            not isinstance(self.admin_token, str) or not self.admin_token
        ):
            raise ValueError("admin_token must be None or a non-empty string")


def _call_rejection(reason: str) -> tuple[int, dict]:
    """§3.8 call-level rejection body (same shape C04 uses for call errors)."""
    return 400, {
        "status": "rejected",
        "errors": [{"index": None, "kind": "call", "reason": reason}],
    }


_STATE_SCHEMA = """
CREATE TABLE IF NOT EXISTS mintapi_state (
  id                 INTEGER PRIMARY KEY CHECK (id = 1),
  snapshot_seq       INTEGER NOT NULL,
  activity_day       INTEGER NOT NULL,
  activity_count     INTEGER NOT NULL,
  activity_volume_mc INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS mintapi_counted (
  idempotency_key TEXT PRIMARY KEY
);
"""


class _Core:
    """Route logic, shared by all handler threads. Wire in/out only.

    Durable C06 state (``snapshot_seq`` high-water mark, day-windowed
    activity) lives in C06-owned tables inside the ledger's sqlite file,
    via a dedicated connection. All access is serialized by ``self._lock``.
    Writes (activity counting, seq-block reservation) run under ``BEGIN
    IMMEDIATE``; a descriptor serve does not, because it is a read —
    ``self._lock`` alone orders the supply read against seq allocation, so
    (seq, cumulatives) stay jointly monotone (§3.6). See
    ``_next_snapshot_seq`` for why that also holds across restarts.
    """

    def __init__(self, config: MintConfig, ledger: Ledger):
        self.config = config
        self.ledger = ledger
        self._lock = threading.Lock()
        # The Ledger does not expose its db path publicly; the reference
        # implementation reads the private attribute rather than widening
        # C04's API from outside (recorded in the build notes).
        self._state = sqlite3.connect(
            ledger._db_path,
            timeout=30.0,
            isolation_level=None,  # manual txn control, like C04
            check_same_thread=False,  # guarded by self._lock
        )
        # Reserved §3.6 snapshot_seq block, [_seq_next, _seq_limit).
        # Empty at boot; the first descriptor fetch reserves one.
        self._seq_next = 0
        self._seq_limit = 0
        # Single-writer claim over the ledger file; see _claim_single_writer.
        self._lock_path = ledger._db_path
        self._lock_fd: int | None = None
        self._state.executescript(_STATE_SCHEMA)
        self._state.execute(
            "INSERT OR IGNORE INTO mintapi_state (id, snapshot_seq,"
            " activity_day, activity_count, activity_volume_mc)"
            " VALUES (1, 0, -1, 0, 0)"
        )
        self._state.commit()

    # -- single-writer claim over the ledger (§3.6 monotonicity) ---------

    def _claim_single_writer(self) -> None:
        """Take the advisory single-writer lock on this ledger file.

        §3.6 makes "any two signed snapshots violating monotonicity"
        PORTABLE PROOF OF NONCONFORMANCE — it is a property of the mint_id
        and its signing key, not of a process. Snapshot ordering used to be
        held by sqlite: the supply read and the seq bump ran inside one
        ``BEGIN IMMEDIATE`` on the shared file, so any number of processes
        serving one ledger were still jointly monotone. Making the
        descriptor a read moved that ordering onto ``self._lock``, a
        ``threading.Lock`` that exists once per process. Two mints on one
        db file then draw disjoint seq blocks (the reservation is still
        atomic) but order their supply READS independently, so the process
        holding the higher block can sign a higher seq over an older
        supply — an honest mint framed by its own signatures.

        The precondition is therefore enforced, not documented: exactly one
        process may serve a given ledger. ``flock`` is advisory but
        whole-file and released by the kernel on exit, so a crashed mint
        does not wedge its own restart, and it conflicts between two open
        file descriptions even inside one process — two MintServers on one
        db in one interpreter have the same ordering bug and are refused
        the same way. Idempotent: a re-claim by the holder is a no-op.

        Held on the LEDGER FILE itself rather than on a sidecar: nothing
        to leave behind next to a deployment's mint.db, and the claim
        cannot drift from the thing it claims. ``flock`` is safe to put
        there because sqlite's unix VFS locks with POSIX record locks
        (``fcntl(F_SETLK)``), an independent mechanism on Linux — this
        lock neither blocks nor is blocked by any sqlite connection,
        including C04's.

        Raises RuntimeError when another mint holds the ledger.
        """
        if self._lock_fd is not None:
            return
        if fcntl is None:  # pragma: no cover - POSIX-only build target
            return
        fd = os.open(self._lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            raise RuntimeError(
                "another mint process already serves this ledger (%s). One"
                " ledger file is served by exactly one mint: §3.6 snapshot"
                " monotonicity is ordered per process, so a second server"
                " could sign snapshots that are portable proof of"
                " nonconformance against this mint_id. Stop the other"
                " process, or give this mint its own ledger."
                % self._lock_path
            ) from None
        self._lock_fd = fd

    def _release_single_writer(self) -> None:
        fd, self._lock_fd = self._lock_fd, None
        if fd is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    # -- clock (via the Ledger's injected clock; L17 — never wall time) --

    def _mint_time(self) -> int:
        return self.ledger.status([])[0]

    # -- §3.3 wire form parsing ------------------------------------------
    #
    # Anything that fails to parse is passed through raw: C04 reports any
    # non-typed value as `bad_format` at its index (§3.8), which keeps
    # index attribution exact without duplicating the error plumbing.

    def _parse_input(self, val: object):
        if isinstance(val, str):
            try:
                tok = parse_token(val)
            except TokenError:
                return val
            if tok.mint_id != self.config.mint_id:
                return val  # foreign-mint token → bad_format at this index
            return InputForm(kind="plain", token=tok)
        if isinstance(val, dict):
            keys = set(val.keys())
            if keys == {"token", "witness"}:
                try:
                    tok = parse_token(val["token"])
                    witness = b64u_decode(val["witness"])
                except TokenError:
                    return val
                if tok.mint_id != self.config.mint_id:
                    return val
                return InputForm(kind="claim", token=tok, witness=witness)
            if keys == {"hash", "witness"}:
                if not isinstance(val["hash"], str):
                    return val
                try:
                    witness = b64u_decode(val["witness"])
                except TokenError:
                    return val
                return InputForm(
                    kind="refund", hash=val["hash"], witness=witness
                )
        return val

    def _parse_output(self, val: object):
        # C04's parse_output_wire IS the wire parser (shared, never
        # duplicated): Ledger.issue accepts wire dicts through the same
        # code path this HTTP layer uses.
        return parse_output_wire(val)

    # -- POST /v3/exchange ------------------------------------------------

    def exchange(self, body: object) -> tuple[int, dict]:
        if not isinstance(body, dict):
            return _call_rejection("bad_format")
        key = body.get("idempotency_key")
        inputs = body.get("inputs")
        outputs = body.get("outputs")
        if (
            not isinstance(key, str)
            or not key
            # An over-length idempotency key is a malformed envelope, not a
            # property of any one item: §3.8 `bad_format`, kind "call",
            # index null. (The §3.8 vocabulary has no length-specific
            # reason, and §3.8's own example of a call-level rejection is
            # exactly "a malformed envelope".) Enforced HERE rather than in
            # C04 because the cost being bounded is C06's: the key is what
            # a caller writes into the ledger's 90-day recovery window.
            or len(key) > MAX_IDEMPOTENCY_KEY_LEN
            or not isinstance(inputs, list)
            or not isinstance(outputs, list)
        ):
            return _call_rejection("bad_format")
        if len(inputs) + len(outputs) > self.config.max_batch:
            return _call_rejection("over_batch_limit")
        try:
            digest = body_digest(body)  # §3.3: digest over canonical body
        except TokenError:
            return _call_rejection("bad_format")  # e.g. floats — never legal
        parsed_inputs = [self._parse_input(v) for v in inputs]
        parsed_outputs = [self._parse_output(v) for v in outputs]
        try:
            result = self.ledger.exchange(
                key, digest, parsed_inputs, outputs=parsed_outputs
            )
        except ExchangeRejected as exc:
            return 400, {"status": "rejected", "errors": exc.errors}
        volume = result["burn_mc"] + sum(
            spec.amount_mc
            for spec in parsed_outputs
            if isinstance(spec, OutputSpec)
        )
        self._record_activity(key, volume)
        return 200, result

    def _record_activity(self, idempotency_key: str, volume_mc: int) -> None:
        """Count one successful exchange toward the §3.6 activity figures.

        At most once per idempotency key, ever (the ``mintapi_counted``
        primary key persists), so §3.3 replays of an already-executed call
        never double-count. Counters are windowed to the current mint-clock
        day: the first counted exchange of a new day resets them, so
        ``daily_*`` never accumulates a process- or ledger-lifetime total.
        """
        with self._lock:
            self._state.execute("BEGIN IMMEDIATE")
            try:
                cur = self._state.execute(
                    "INSERT OR IGNORE INTO mintapi_counted"
                    " (idempotency_key) VALUES (?)",
                    (idempotency_key,),
                )
                if cur.rowcount == 1:  # first time this call is counted
                    day = self._mint_time() // _DAY_MS
                    row = self._state.execute(
                        "SELECT activity_day, activity_count,"
                        " activity_volume_mc FROM mintapi_state WHERE id = 1"
                    ).fetchone()
                    if row[0] == day:
                        count, vol = row[1] + 1, row[2] + volume_mc
                    else:  # mint-clock day rolled over: fresh window
                        count, vol = 1, volume_mc
                    self._state.execute(
                        "UPDATE mintapi_state SET activity_day = ?,"
                        " activity_count = ?, activity_volume_mc = ?"
                        " WHERE id = 1",
                        (day, count, vol),
                    )
                self._state.execute("COMMIT")
            except BaseException:
                self._state.execute("ROLLBACK")
                raise

    # -- §3.5 status ------------------------------------------------------

    @staticmethod
    def _wire_entry(entry: dict) -> dict:
        """§3.5 pinned per-hash schema: unknown entries carry explicit
        ``lock/spent_at/claim_witness: null`` and no ``amount_mc``."""
        if entry.get("state") == "unknown":
            return {
                "state": "unknown",
                "lock": None,
                "spent_at": None,
                "claim_witness": None,
            }
        return entry

    def status_single(self, h: str) -> tuple[int, dict]:
        mint_time, results = self.ledger.status([h])
        return 200, {"mint_time": mint_time, "result": self._wire_entry(results[0])}

    def status_batch(self, body: object) -> tuple[int, dict]:
        if not isinstance(body, dict):
            return _call_rejection("bad_format")
        hashes = body.get("hashes")
        if not isinstance(hashes, list):
            return _call_rejection("bad_format")
        if len(hashes) > self.config.max_batch:
            return _call_rejection("over_batch_limit")
        mint_time, results = self.ledger.status(hashes)
        return 200, {
            "mint_time": mint_time,
            "results": [self._wire_entry(r) for r in results],
        }

    # -- §3.6 descriptor --------------------------------------------------

    def _next_snapshot_seq(self) -> int:
        """Allocate the next §3.6 ``snapshot_seq``. Caller holds ``_lock``.

        Numbers come from a block reserved with ONE sqlite write per
        ``_SEQ_BLOCK`` snapshots, instead of a write per serve. The value
        PERSISTED at reservation time is the block's high-water mark — the
        largest seq this process may hand out — so any restart, crash
        included, resumes strictly above every seq that could already have
        been signed. §3.6 requires ``snapshot_seq`` to increase, not to be
        contiguous, so the gap an unused block tail leaves is conformant;
        what would be nonconformant (a repeated or regressing seq across a
        restart, §3.6's "portable proof of nonconformance") is exactly what
        persisting the high-water mark rules out.
        """
        if self._seq_next >= self._seq_limit:
            self._state.execute("BEGIN IMMEDIATE")
            try:
                self._state.execute(
                    "UPDATE mintapi_state SET snapshot_seq ="
                    " snapshot_seq + ? WHERE id = 1",
                    (_SEQ_BLOCK,),
                )
                high = self._state.execute(
                    "SELECT snapshot_seq FROM mintapi_state WHERE id = 1"
                ).fetchone()[0]
                self._state.execute("COMMIT")
            except BaseException:
                self._state.execute("ROLLBACK")
                raise
            # Reserved: (high - _SEQ_BLOCK, high]. BEGIN IMMEDIATE makes the
            # bump atomic, so two mints sharing one ledger file get disjoint
            # blocks and neither can reuse the other's numbers.
            self._seq_next = high - _SEQ_BLOCK + 1
            self._seq_limit = high + 1
        seq = self._seq_next
        self._seq_next += 1
        return seq

    def descriptor(self) -> tuple[int, dict]:
        c = self.config
        # Snapshot construction (§3.6). This used to run BEGIN IMMEDIATE and
        # UPDATE snapshot_seq on EVERY fetch, which made an unauthenticated
        # GET /v3/mints take sqlite's write lock on the payment database: a
        # descriptor poller serialized against real exchanges and could stall
        # them for free. A descriptor serve is now a READ — reservation
        # aside, which is one write per _SEQ_BLOCK serves.
        #
        # Monotonicity is preserved by ``self._lock`` instead of by sqlite's
        # write lock. Every snapshot is built while holding it, and the
        # supply read happens BEFORE the seq is allocated, so snapshots
        # ordered by snapshot_seq are also ordered by the instant their
        # supply was read; C04 commits exchanges atomically, so a later read
        # can only see equal-or-greater cumulatives. (seq, cumulatives)
        # therefore stay jointly monotone, and each snapshot still satisfies
        # ``outstanding == issued − burned`` because Ledger.supply() reads
        # all three in a single statement. Nothing is cached: the counters
        # served are read fresh per fetch, never stale behind a completed
        # exchange.
        #
        # That argument holds only for ONE process per ledger, so the claim
        # is re-checked here rather than trusted to whoever started the
        # server: a mint that cannot hold the single-writer lock refuses to
        # sign a snapshot at all (RuntimeError → 500) instead of signing one
        # that might be §3.6 proof of nonconformance against its own key.
        with self._lock:
            self._claim_single_writer()
            mint_time = self._mint_time()
            supply = self.ledger.supply()  # one atomic read (C04)
            snapshot_seq = self._next_snapshot_seq()
            row = self._state.execute(
                "SELECT activity_day, activity_count, activity_volume_mc"
                " FROM mintapi_state WHERE id = 1"
            ).fetchone()
        if row[0] == mint_time // _DAY_MS:
            activity_count, activity_volume = row[1], row[2]
        else:  # counters belong to an earlier mint-clock day: none today
            activity_count, activity_volume = 0, 0
        # mint_id and baseline_model_class ride INSIDE the signed body. §4.1
        # calls a contradicting descriptor portable proof of nonconformance,
        # and that proof is only constructible if a signature covers the
        # field: the supply invariant is portable precisely because each
        # snapshot is signed. Carrying them here also means the archiver
        # network already diffing signed snapshots sees a baseline change with
        # no new code. Found 2026-09-08 by outside review of the fix that
        # introduced the §4.1 claim.
        snapshot = dict(
            supply,
            mint_id=c.mint_id,
            baseline_model_class=c.baseline_model_class,
            snapshot_seq=snapshot_seq,
            snapshot_time=mint_time,
        )
        snapshot = attach_sig(snapshot, c.signing_private)  # C05

        performance = c.performance
        if performance is not None:
            # L11 honesty: stale measurements MUST render null, never zeros.
            age_ms = mint_time - performance["measured_at"]
            if age_ms > performance["window_days"] * _DAY_MS:
                performance = None

        if c.burn_policy_next is None:
            burn_policy_next = None
        else:
            next_policy, effective_at = c.burn_policy_next
            burn_policy_next = {
                "policy": _policy_dict(next_policy),
                "effective_at": effective_at,
            }

        return 200, {
            "mint_id": c.mint_id,
            "baseline_model_class": c.baseline_model_class,
            "mint_time": mint_time,
            "denominations_mc": list(c.denominations_mc),
            "burn_policy": _policy_dict(c.burn_policy),
            "burn_policy_next": burn_policy_next,
            "supply": snapshot,
            "performance": performance,
            "limits": {
                "max_batch": c.max_batch,
                "anonymous_rate": dict(c.anonymous_rate),
                "registered_rate": dict(c.registered_rate),
            },
            "lock_params": {
                "grace_ms": c.grace_ms,
                "timestamp_precision_ms": c.timestamp_precision_ms,
                "max_lock_expiry_ms": c.max_lock_expiry_ms,
            },
            "retention": {
                "recovery_window_ms": c.recovery_window_ms,
                "prunes_spent_records": c.prunes_spent_records,
                "policy_url": c.policy_url,
            },
            "profiles": list(c.profiles),
            "activity": {
                "daily_exchange_count": activity_count,
                "daily_volume_mc": activity_volume,
                "as_of": mint_time,
            },
            "signing_pubkey": pubkey_b64u(c.signing_public),
        }

    # -- POST /admin/issue (non-normative §7.1 operator funding) ----------

    def admin_authorized(self, presented_token: str | None) -> bool:
        """Constant-time admin-token check (credential-comparison hygiene).

        True when no token is configured (open test/ops path) or when the
        presented header matches. ``hmac.compare_digest`` over utf-8 bytes
        avoids the timing side channel of ordinary string inequality.
        """
        configured = self.config.admin_token
        if configured is None:
            return True
        presented = presented_token if isinstance(presented_token, str) else ""
        return hmac.compare_digest(
            configured.encode("utf-8", "surrogateescape"),
            presented.encode("utf-8", "surrogateescape"),
        )

    def admin_issue(self, body: object, presented_token: str | None):
        if not self.admin_authorized(presented_token):
            return 401, {"status": "unauthorized"}
        if not isinstance(body, dict):
            return _call_rejection("bad_format")
        outputs = body.get("outputs")
        if not isinstance(outputs, list):
            return _call_rejection("bad_format")
        parsed = [self._parse_output(v) for v in outputs]
        try:
            self.ledger.issue(parsed)
        except ExchangeRejected as exc:
            return 400, {"status": "rejected", "errors": exc.errors}
        return 200, {"status": "ok", "outputs_confirmed": len(parsed)}


class _MintHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    core: _Core  # set by MintServer.start

    def handle_error(self, request, client_address):
        # Never print tracebacks (default behavior) — log route-free notice.
        logger.info("connection error")


class _DeadlineRaw(io.RawIOBase):
    """The handler's raw read side, under a WALL-CLOCK request deadline.

    An idle timeout alone does not bound a request. ``_Handler.timeout``
    is applied per recv, so a peer that sends one byte every few seconds
    resets it forever: a declared body at exactly MAX_BODY_BYTES (the cap
    never fires) dripped one byte at a time parks a daemon thread and an
    fd indefinitely, and ThreadingHTTPServer caps neither. So every recv
    of a request — request line, headers and body alike — gets the SMALLER
    of the idle timeout and the time left on ``handler.request_deadline``,
    and an expired deadline raises before the syscall.

    Sitting under ``io.BufferedReader`` rather than replacing it is what
    makes this whole-request: BufferedReader's own loops (``readline``
    over headers, ``read(n)`` over a body) come back through ``readinto``
    for every refill, so each refill re-checks the clock. Wrapping the
    BufferedReader instead would have set one timeout for an entire
    blocking read and bounded nothing.

    The exception raised is ``TimeoutError`` — ``socket.timeout`` since
    3.10 — which BaseHTTPRequestHandler.handle_one_request already turns
    into a silent close for the header phase, and which
    ``_Handler._read_json`` catches for the body phase.

    ``time.monotonic`` here is transport bookkeeping, not the mint clock:
    L17 keeps C06 off wall time because mint_time is a SERVED value, and
    no value computed here is ever served, signed or persisted.
    """

    def __init__(self, sock, handler):
        self._sock = sock
        self._handler = handler

    def readable(self) -> bool:
        return True

    def readinto(self, buf) -> int:
        idle = self._handler.timeout
        deadline = self._handler.request_deadline
        if deadline is None:
            budget = idle
        else:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError("request deadline exceeded")
            budget = left if idle is None else min(idle, left)
        self._sock.settimeout(budget)
        try:
            return self._sock.recv_into(buf)
        finally:
            # Restored so the response write side is never left running
            # under whatever sliver of the read budget happened to remain.
            self._sock.settimeout(idle)


class _Handler(BaseHTTPRequestHandler):
    server_version = "AICashMint/0.4"
    protocol_version = "HTTP/1.1"
    _route = "<unknown>"  # normalized route pattern, for the access log

    # socketserver.StreamRequestHandler.setup() applies this to the accepted
    # socket; the class default is None, i.e. NO timeout. With HTTP/1.1
    # keep-alive that meant one anonymous client (§3.7 — anyone) could open
    # a connection, send nothing or half a request, and park a daemon thread
    # and a file descriptor for the life of the process. 10s is far longer
    # than any Layer 0 call needs (they are single sqlite transactions) and
    # short enough that a stalled peer cannot accumulate. A timeout fires as
    # socket.timeout inside BaseHTTPRequestHandler.handle_one_request, which
    # routes it to self.log_error (silenced below) and closes — no traceback
    # on stdout; _MintHTTPServer.handle_error covers anything that escapes.
    #
    # It is an IDLE bound and only that: `request_timeout` below is what
    # stops a peer from resetting it forever a byte at a time.
    timeout = 10

    # Wall-clock ceiling on one whole request, armed in handle_one_request
    # and enforced by _DeadlineRaw on every recv. A class attribute for the
    # same reason `timeout` is: a deployment (or a test) overrides it by
    # subclassing, without reaching into module state.
    request_timeout = MAX_REQUEST_SECONDS

    #: Absolute monotonic instant this request must be read by; None
    #: between requests, when only the idle timeout applies.
    request_deadline: float | None = None

    def setup(self):
        super().setup()
        # socketserver made rfile = connection.makefile('rb', rbufsize).
        # Swap in the same buffered reader over a deadline-checking raw
        # layer; closing the original only drops its socket refcount (it
        # does not close the fd), which keeps connection.close() honest.
        original = self.rfile
        self.rfile = io.BufferedReader(
            _DeadlineRaw(self.connection, self),
            io.DEFAULT_BUFFER_SIZE if self.rbufsize <= 0 else self.rbufsize,
        )
        original.close()

    def handle_one_request(self):
        # Arm the deadline for this request. Keep-alive idle time between
        # requests is covered by `timeout` alone, which is the shorter of
        # the two, so nothing legitimate is cut short by arming here.
        self.request_deadline = time.monotonic() + self.request_timeout
        try:
            super().handle_one_request()
        finally:
            self.request_deadline = None

    # ---- logging: route pattern + status only (requirement 5) ----------

    def log_request(self, code="-", size="-"):
        if hasattr(code, "value"):  # HTTPStatus from send_error paths
            code = code.value
        logger.info("%s %s %s", self.command, self._route, code)

    def log_error(self, format, *args):  # noqa: A002 - stdlib signature
        pass  # default would log free text; the access log above is enough

    def log_message(self, format, *args):  # noqa: A002 - stdlib signature
        pass

    # ---- plumbing -------------------------------------------------------

    def _send(self, code: int, obj: object) -> None:
        body = canonical_json(obj)  # C01 canonical JSON: stable bytes (req 6)
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if self.close_connection:
            # Announce the close AND (via BaseHTTPRequestHandler.send_header)
            # set self.close_connection. Mandatory whenever we answer without
            # having consumed the declared body: leftover octets would be
            # parsed as the next request on a keep-alive connection.
            self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _body_rejection(self):
        """Refuse this request's body and hang up.

        Every refusal answers with ONE §3.8 reason, ``bad_format``, so the
        reason is a property of the route rather than of handler state a
        body reader happened to leave behind. An earlier version carried it
        out of band on the handler, which quietly extended the contract of
        an OVERRIDABLE method: a subclass that replaces ``_read_json``
        (C10's Supervision Profile handler is the live example) cannot know
        to set a private attribute, and the inherited Layer 0 routes would
        then answer from a stale class default — the same wire request
        getting two different §3.8 reasons depending on profile, which
        L13/B9 forbid. Nothing to leave behind, nothing to go stale.
        """
        self.close_connection = True
        return None, False

    def _read_json(self):
        """Returns (parsed, ok). Any trouble with the body → (None, False).

        The caller answers (None, False) with §3.8 ``bad_format``, kind
        "call", index null — §3.8's own example of a call-level rejection
        is "a malformed envelope", and a body this layer declines to read
        is exactly that. Deliberately NOT ``over_batch_limit``, even for a
        body past MAX_BODY_BYTES: §9.5 pins that reason as "retryable with
        backoff", but identical bytes over the cap fail identically
        forever, so a spec-conforming payer would retry a call that can
        never succeed instead of splitting it or giving up. MAX_BODY_BYTES
        is also not a §3.6 published limit and cannot become one (that
        object's scope guard is explicit), so no client can be expected to
        aim at it — which is precisely what makes a permanent reason the
        honest one. It is NOT, however, out of a published limit's reach:
        at the largest max_batch MintConfig admits (_max_batch_ceiling) this
        cap is only ~1.5x a maximal call, and an entry the mint
        parses can exceed the per-entry allowance that ceiling is derived
        from (see _FAT_ENTRY_BYTES), so a caller aiming at a published limit
        CAN land here. The permanent reason still holds on its own ground:
        identical bytes over the cap fail identically forever, so "retryable
        with backoff" would be advice that can never work, while the
        recovery that does work — split the call — is exactly what a
        permanent reason tells a payer to go find.
        """
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            return self._body_rejection()
        if length < 0:
            return self._body_rejection()
        if length > MAX_BODY_BYTES:
            # Refuse BEFORE allocating: the old code trusted the header and
            # called rfile.read(length), so `Content-Length: 4294967296` was
            # a one-line memory-exhaustion request from any anonymous caller
            # (§3.7). Nothing is read, so the connection cannot be reused.
            return self._body_rejection()
        try:
            raw = self.rfile.read(length) if length > 0 else b""
        except OSError:
            # A reset peer, the idle `timeout`, or the whole-request
            # deadline (_DeadlineRaw raises TimeoutError, an OSError, when
            # a driblet of a body outlasts request_timeout). The socket is
            # unusable either way; hang up rather than let the exception
            # reach handle_error.
            return self._body_rejection()
        if len(raw) != length:
            # Short read: the peer half-closed or died mid-body. Without this
            # a truncated body either parsed as a shorter valid document
            # (silently accepting a call the client never finished sending)
            # or surfaced as a confusing JSONDecodeError. Either way the
            # stream is desynchronized, so the connection does not survive.
            return self._body_rejection()
        try:
            return json.loads(raw.decode("utf-8")), True
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None, False

    # ---- routes ---------------------------------------------------------

    def _close_if_body_goes_unread(self) -> None:
        """Hang up after answering a GET that declared a body.

        A GET body is never read by this layer, so a declared one leaves
        octets on the wire that a keep-alive peer or a pipelining proxy
        frames as the NEXT request line — the same desync the POST path
        closes by hanging up on a body it refuses. There is nothing here
        to reject (the GET itself is well formed and §3.7 says anyone may
        make it), so the request is answered and THEN the connection is
        dropped, rather than reusing a stream that can no longer be
        framed. Transfer-Encoding counts too: the stdlib handler does not
        dechunk, so a chunked body is equally unconsumed.

        Shared rather than duplicated because C10's ``_SupHandler``
        answers its own GET routes without reaching this class's
        ``do_GET`` (it returns before ``super().do_GET()`` for a
        supervision route), and a framing guard that only covers Layer 0
        leaves the profile's routes smuggleable — one server, one socket,
        so it has to be one rule.
        """
        try:
            declared = int(self.headers.get("Content-Length", 0))
        except ValueError:
            declared = -1  # unparseable is not "no body"
        if declared != 0 or self.headers.get("Transfer-Encoding"):
            self.close_connection = True

    def do_GET(self):
        core: _Core = self.server.core
        try:
            self._close_if_body_goes_unread()
            path = self.path.split("?", 1)[0]
            if path == "/v3/mints":
                self._route = "/v3/mints"
                code, obj = core.descriptor()
            elif path.startswith("/v3/status/") and len(path) > len("/v3/status/"):
                self._route = "/v3/status/<hash>"
                code, obj = core.status_single(path[len("/v3/status/"):])
            else:
                self._route = "<unknown>"
                code, obj = 404, {"status": "not_found"}
            self._send(code, obj)
        except Exception:
            self._safe_500()

    def do_POST(self):
        core: _Core = self.server.core
        try:
            path = self.path.split("?", 1)[0]
            body, ok = self._read_json()
            # A body this layer would not read is a malformed envelope:
            # §3.8 bad_format, kind "call", index null. Computed here from
            # `ok` alone, never from state the reader left on the handler —
            # `_read_json` is overridable and a subclass cannot be asked to
            # maintain a private attribute (see _body_rejection).
            if path == "/v3/exchange":
                self._route = "/v3/exchange"
                code, obj = (
                    core.exchange(body) if ok else _call_rejection("bad_format")
                )
            elif path == "/v3/status":
                self._route = "/v3/status"
                code, obj = (
                    core.status_batch(body)
                    if ok
                    else _call_rejection("bad_format")
                )
            elif path == "/admin/issue":
                self._route = "/admin/issue"
                token = self.headers.get("X-Admin-Token")
                if not core.admin_authorized(token):
                    code, obj = 401, {"status": "unauthorized"}
                elif ok:
                    code, obj = core.admin_issue(body, token)
                else:
                    code, obj = _call_rejection("bad_format")
            else:
                self._route = "<unknown>"
                code, obj = 404, {"status": "not_found"}
            self._send(code, obj)
        except Exception:
            self._safe_500()

    def _safe_500(self):
        # Requirement 4: never a stack trace in a response body.
        try:
            self._send(500, {"status": "error"})
        except Exception:
            pass


class MintServer:
    """A real mint over HTTP, and the in-process test harness for one."""

    def __init__(self, config: MintConfig, ledger: Ledger):
        if not isinstance(config, MintConfig):
            raise TypeError("config must be a MintConfig")
        if not isinstance(ledger, Ledger):
            raise TypeError("ledger must be a C04 Ledger")
        # Shared-parameter consistency (fail fast at boot, not at payment
        # time): the descriptor advertises the config's burn_policy /
        # retention / lock horizon, but the LEDGER enforces its own — a
        # hand-wired mismatch would make the mint publish one policy and
        # charge another. ``make_mint`` builds the pair from one source of
        # truth; this check catches everyone who wires by hand.
        for name in ("burn_policy", "recovery_window_ms", "max_lock_expiry_ms"):
            cfg_v, led_v = getattr(config, name), getattr(ledger, name)
            if cfg_v != led_v:
                raise ValueError(
                    "config/ledger mismatch on %s: MintConfig has %r but the"
                    " Ledger was built with %r — the mint would advertise one"
                    " value and enforce another. Build both from the config"
                    " via make_mint(config, db_path), or construct the Ledger"
                    " with the config's values." % (name, cfg_v, led_v)
                )
        self._core = _Core(config, ledger)
        self._httpd: _MintHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self, port: int = 0, host: str = "127.0.0.1") -> int:
        """Bind and serve on background threads; return the bound port.

        Defaults to 127.0.0.1:0 — an ephemeral port on loopback, which is
        what the tests want. A deployed mint needs a FIXED port instead: its
        URL is published in the descriptor and held by counterparties, so an
        address that moves on every restart is not addressable. Pass one.

        `host` stays loopback by default. Transport is plain HTTP (L17), so
        binding a routable interface publishes an unencrypted mint; put TLS
        in front before widening this.
        """
        if self._httpd is not None:
            raise RuntimeError("server already started")
        # Before binding: exactly one mint process may serve a ledger, or
        # §3.6 snapshot monotonicity is no longer a property of the mint_id
        # (see _Core._claim_single_writer). Fail here, loudly, rather than
        # at the first descriptor a second process signs.
        self._core._claim_single_writer()
        self._httpd = _MintHTTPServer((host, port), _Handler)
        self._httpd.core = self._core
        self._thread = threading.Thread(
            target=self._httpd.serve_forever,
            name="aicash-mintapi",
            daemon=True,
        )
        self._thread.start()
        return self._httpd.server_address[1]

    def stop(self) -> None:
        if self._httpd is None:
            self._core._release_single_writer()
            return
        self._httpd.shutdown()
        self._httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=10)
        self._httpd = None
        self._thread = None
        # Released last: while a serving thread could still be building a
        # snapshot, this mint is still the single writer.
        self._core._release_single_writer()


def make_mint(
    config: MintConfig, db_path: str, clock=system_clock
) -> tuple[MintServer, Ledger]:
    """Build a Ledger and a MintServer from ONE source of truth.

    The Ledger is constructed from the config's ``burn_policy``,
    ``recovery_window_ms`` and ``max_lock_expiry_ms``, so the values the
    descriptor advertises are, by construction, the values the ledger
    enforces — no hand-wired duplication to drift. ``clock`` defaults to
    the wall-clock ``aicash.clock.system_clock``; tests inject a
    ``FakeClock`` (L17). Returns ``(server, ledger)``; call
    ``server.start()`` to bind a port. The ledger is returned too so
    callers can drive it directly (issuance, pruning, tests).
    """
    if not isinstance(config, MintConfig):
        raise TypeError("config must be a MintConfig")
    ledger = Ledger(
        db_path,
        clock,
        config.burn_policy,
        recovery_window_ms=config.recovery_window_ms,
        max_lock_expiry_ms=config.max_lock_expiry_ms,
    )
    return MintServer(config, ledger), ledger
