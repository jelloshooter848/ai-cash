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
read-and-incremented under sqlite's write lock together with the supply
read. A restarted mint therefore continues the sequence — it can never
sign two snapshots that violate §3.6 monotonicity ("portable proof of
nonconformance") merely by restarting. Activity counters live in the
same store: windowed to the current mint-clock day and counted at most
once per idempotency key, so §3.3 replays never double-count and
"daily" figures never accumulate process-lifetime totals.

Secret hygiene (§3.1, requirement 5): request bodies are never logged.
The access log (logger ``aicash.mintapi``) carries route pattern + status
code only — even the path is normalized to a fixed route pattern so a
confused client that puts a token in a URL still cannot make the server
log secret material. Never a stack trace in a response body.
"""

from __future__ import annotations

import hmac
import json
import logging
import sqlite3
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

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

    Durable C06 state (``snapshot_seq``, day-windowed activity) lives in
    C06-owned tables inside the ledger's sqlite file, via a dedicated
    connection. All access is serialized by ``self._lock`` and runs under
    ``BEGIN IMMEDIATE``, so a snapshot's seq bump shares sqlite's write
    lock with its supply read: no exchange can commit between them, and
    (seq, cumulatives) stay jointly monotone across restarts (§3.6).
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
        self._state.executescript(_STATE_SCHEMA)
        self._state.execute(
            "INSERT OR IGNORE INTO mintapi_state (id, snapshot_seq,"
            " activity_day, activity_count, activity_volume_mc)"
            " VALUES (1, 0, -1, 0, 0)"
        )
        self._state.commit()

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

    def descriptor(self) -> tuple[int, dict]:
        c = self.config
        # Snapshot construction (§3.6): BEGIN IMMEDIATE takes sqlite's
        # write lock on the shared database, so no exchange can commit
        # between the supply read and the persisted seq bump — signed
        # cumulatives are monotone across snapshot_seq, including across
        # server restarts on the same ledger.
        with self._lock:
            self._state.execute("BEGIN IMMEDIATE")
            try:
                mint_time = self._mint_time()
                supply = self.ledger.supply()  # one atomic read (C04)
                self._state.execute(
                    "UPDATE mintapi_state SET snapshot_seq ="
                    " snapshot_seq + 1 WHERE id = 1"
                )
                row = self._state.execute(
                    "SELECT snapshot_seq, activity_day, activity_count,"
                    " activity_volume_mc FROM mintapi_state WHERE id = 1"
                ).fetchone()
                self._state.execute("COMMIT")
            except BaseException:
                self._state.execute("ROLLBACK")
                raise
        snapshot_seq = row[0]
        if row[1] == mint_time // _DAY_MS:
            activity_count, activity_volume = row[2], row[3]
        else:  # counters belong to an earlier mint-clock day: none today
            activity_count, activity_volume = 0, 0
        snapshot = dict(
            supply, snapshot_seq=snapshot_seq, snapshot_time=mint_time
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


class _Handler(BaseHTTPRequestHandler):
    server_version = "AICashMint/0.4"
    protocol_version = "HTTP/1.1"
    _route = "<unknown>"  # normalized route pattern, for the access log

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
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        """Returns (parsed, ok). Any parse trouble → (None, False)."""
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            return None, False
        raw = self.rfile.read(length) if length > 0 else b""
        try:
            return json.loads(raw.decode("utf-8")), True
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None, False

    # ---- routes ---------------------------------------------------------

    def do_GET(self):
        core: _Core = self.server.core
        try:
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
            return
        self._httpd.shutdown()
        self._httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=10)
        self._httpd = None
        self._thread = None


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
