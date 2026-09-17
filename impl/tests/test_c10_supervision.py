"""C10 — supervision tests: the Supervision Profile over real HTTP.

Every test drives a real SupervisionServer (a C06 mint with the profile
mounted) on 127.0.0.1 with stdlib http.client. All time comes from a
FakeClock injected through the Ledger (L17). Benchmark items B1–B9 from
components/C10-supervision.md are named in each test's docstring.
"""

import concurrent.futures
import http.client
import inspect
import io
import json
import logging
import os
import re
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from typing import NamedTuple

from aicash.burncalc import BurnPolicy, compute_burn
from aicash.clock import FakeClock
from aicash.ledgerstore import Ledger
from aicash import mintapi
from aicash.mintapi import (
    ADMIN_ISSUANCE_DISABLED,
    ADMIN_ISSUANCE_OPEN,
    MintConfig,
    MintServer,
)
from aicash.signing import generate_keypair, verify_obj
from aicash import supervision
from aicash.supervision import MAX_TEXT_LEN, SupervisionServer
from aicash.tokencodec import (
    b64u_decode,
    b64u_encode,
    format_token,
    ledger_key,
    new_secret,
)

T0 = 1_756_000_000_000
HOUR_MS = 3_600_000
DAY_MS = 86_400_000
MINT_ID = "testmint"

#: Burn-free policy (rate 0) so cap/pull arithmetic is exact.
NO_BURN = BurnPolicy(rate_ppm=0, cap_mc=0, exempt_below_mc=10)
#: 1% capped burn for the bridge/round-trip/statement tests.
BURN = BurnPolicy(rate_ppm=10_000, cap_mc=1_000, exempt_below_mc=10)

CREDIT_KINDS = {"credit", "pull_in", "deposit", "issuance"}
DEBIT_KINDS = {"debit", "pull_out", "withdrawal", "burn"}

STATEMENT_KEYS = {
    "v",
    "mint_id",
    "scope",
    "period",
    "opening_balance_mc",
    "closing_balance_mc",
    "lines",
    "signature",
}
LINE_KEYS = {"t", "kind", "amount_mc", "counterparty_account", "ref"}

#: Sentinel for "this class declares no such attribute of its own".
_MISSING = object()


def _sup_body_cap():
    """The request-body bound C10 is required to enforce, in bytes.

    Read from supervision.py when it declares one so a retune keeps the
    tests in step, but DEFAULTED on purpose: a missing constant must make
    the cap tests fail on behaviour (an over-cap body being read, parsed
    and served) rather than on an AttributeError about a module constant.
    """
    return getattr(supervision, "_MAX_BODY_BYTES", 1 << 20)



# This suite funds bearer tokens over C06's /admin/issue (see issue_token),
# so its mints need a real operator credential. It is a fixed literal because
# it is a test harness secret with no confidentiality value -- what matters is
# that the mints here are GATED, so a regression that reopens /admin/issue is
# caught by test_admin_issue_is_refused_without_the_harness_credential rather
# than passing silently on an open mint.
ADMIN_TOKEN = "c10-harness-operator-credential"


def api(port, method, path, obj=None, key=None, admin=None):
    """One HTTP round trip; returns (status, parsed json body).

    ``admin`` sets X-Admin-Token explicitly (pass ``False`` to force the
    header off on a route the helper would otherwise credential).
    """
    headers = {}
    if key is not None:
        headers["Authorization"] = "Bearer " + key
    if admin not in (None, False):
        headers["X-Admin-Token"] = admin
    elif admin is None and path in ("/admin/issue", "/v3/operator/register"):
        # Both routes are gated on the mint operator's credential: C06
        # issuance, and (since the two-operator bypass) C10 operator
        # registration. The harness presents the credential its mints were
        # built with; tests that want to prove a gate exists pass
        # admin=False or build the request by hand.
        headers["X-Admin-Token"] = ADMIN_TOKEN
    body = None if obj is None else json.dumps(obj).encode("utf-8")
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    try:
        conn.request(method, path, body, headers)
        resp = conn.getresponse()
        raw = resp.read()
        return resp.status, json.loads(raw.decode("utf-8"))
    finally:
        conn.close()


def raw_json(port, method, path, obj=None, headers=None):
    """One HTTP round trip with EXACTLY the headers given.

    ``api()`` credentials /v3/operator/register for the caller, which is
    the right default for the ninety tests that only want an operator and
    the wrong one for every test about the gate itself. This helper adds
    nothing: what is in ``headers`` is what goes on the wire."""
    headers = dict(headers or {})
    body = None if obj is None else json.dumps(obj).encode("utf-8")
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    try:
        conn.request(method, path, body, headers)
        resp = conn.getresponse()
        raw = resp.read()
        return resp.status, json.loads(raw.decode("utf-8"))
    finally:
        conn.close()


def _response_complete(buf):
    """True once `buf` holds a whole response (our mint always sends
    Content-Length, so framing never needs chunk parsing)."""
    head, sep, body = buf.partition(b"\r\n\r\n")
    if not sep:
        return False
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            return len(body) >= int(value.strip())
    return False


def raw_api(port, request_bytes, read_timeout=10.0):
    """Send hand-built request bytes (so the declared Content-Length can
    lie) and read the answer. Returns (status, parsed json), or
    (None, None) if the server never answered — which is exactly what an
    unbounded body read looks like from the client side."""
    sock = socket.create_connection(("127.0.0.1", port), timeout=read_timeout)
    try:
        sock.sendall(request_bytes)
        buf = b""
        while not _response_complete(buf):
            try:
                chunk = sock.recv(65536)
            except OSError:  # includes the client-side TimeoutError
                return None, None
            if not chunk:  # server hung up without a full response
                return None, None
            buf += chunk
        head, _, body = buf.partition(b"\r\n\r\n")
        status = int(head.split(b" ")[1])
        return status, json.loads(body.decode("utf-8"))
    finally:
        sock.close()


def raw_probe(port, request_bytes, half_close=False, read_timeout=10.0):
    """Send hand-built bytes and read back ONE response.

    Returns (status_line, connection_header, parsed-or-raw body) — the
    parts of an answer that are behaviour rather than environment (Date
    and Server carry the clock and the version). (None, None, None) means
    the server never produced a whole response, which is what an unbounded
    read looks like from the client side. ``half_close`` shuts the write
    side after sending, so a deliberately short body reaches the server as
    EOF instead of as a stall.
    """
    sock = socket.create_connection(("127.0.0.1", port), timeout=read_timeout)
    try:
        sock.sendall(request_bytes)
        if half_close:
            sock.shutdown(socket.SHUT_WR)
        buf = b""
        while not _response_complete(buf):
            try:
                chunk = sock.recv(65536)
            except OSError:  # includes the client-side TimeoutError
                return None, None, None
            if not chunk:
                return None, None, None
            buf += chunk
        head, _, body = buf.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        connection = None
        for line in lines[1:]:
            name, _sep, value = line.partition(b":")
            if name.strip().lower() == b"connection":
                connection = value.strip().lower()
        try:
            parsed = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            parsed = body
        return lines[0], connection, parsed
    finally:
        sock.close()


def raw_to_eof(port, request_bytes, read_timeout=5.0):
    """Send hand-built bytes and read until the server hangs up. Returns
    (bytes, closed): ``closed`` is False when the server was still holding
    the connection when the client gave up."""
    sock = socket.create_connection(("127.0.0.1", port), timeout=read_timeout)
    try:
        sock.sendall(request_bytes)
        buf = b""
        while True:
            try:
                chunk = sock.recv(65536)
            except OSError:  # client-side timeout: still open
                return buf, False
            if not chunk:
                return buf, True
            buf += chunk
    finally:
        sock.close()


def raw_to_eof_timed(port, request_bytes, read_timeout=30.0):
    """``raw_to_eof`` with a wall clock on it.

    Returns (bytes, closed, seconds). The seconds are the point for the
    request-line shapes that are answered with NOTHING: "the server hung
    up eventually" and "the server held a thread for its whole budget
    first" are the same tuple from ``raw_to_eof`` and are not the same
    fact, and the second one is what an unauthenticated 20-byte request
    line costs this mint.
    """
    started = time.monotonic()
    raw, closed = raw_to_eof(port, request_bytes, read_timeout=read_timeout)
    return raw, closed, time.monotonic() - started


def status_lines(raw):
    """How many HTTP responses are in ``raw``.

    Counts occurrences rather than LINES beginning with the status line.
    Two pipelined responses arrive glued — the second status line follows
    the first response's body with no CRLF in front of it
    (``...{"status":"unauthorized"}HTTP/1.1 401 ...``) — so a line-prefix
    scan reports 1 for exactly the desync these tests exist to catch.
    """
    return raw.count(b"HTTP/1.1 ")


def trailing_bytes(raw):
    """Everything the server sent AFTER the first complete response.

    ``status_lines`` is not enough on its own, and the finding this exists
    for is why. When the leftover octets of a mis-framed body are parsed as
    the next request line, ``BaseHTTPRequestHandler.parse_request`` fails
    before it has learned a request version, so ``send_error`` suppresses
    the status line and headers entirely (``request_version`` is still
    HTTP/0.9) and writes a BARE HTML error page onto the socket. Two
    responses went out, ``raw.count(b"HTTP/1.1 ")`` is 1, and the desync is
    invisible to a status-line count. Anything non-empty here is a second
    answer to a single request.
    """
    head, sep, body = raw.partition(b"\r\n\r\n")
    if not sep:
        return b""
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            return body[int(value.strip()):]
    return body


class Mint(NamedTuple):
    port: int
    clock: FakeClock
    ledger: Ledger
    pub: bytes
    db_path: str
    server: object
    burn: object  # the BurnPolicy the mint runs


class SupervisionTest(unittest.TestCase):
    maxDiff = None

    # ------------------------------------------------------------------ #
    # harness                                                            #
    # ------------------------------------------------------------------ #

    _NO_REGISTRATION_ARG = object()

    def start_mint(self, *, burn_policy=NO_BURN, clock=None, profiles=(),
                   admin_token=ADMIN_TOKEN, burn_policy_next=None,
                   burn_policy_announced_at=None,
                   registration_token=_NO_REGISTRATION_ARG):
        """Start a supervision mint.

        ``burn_policy_next`` is threaded to BOTH the Ledger and the
        MintConfig, exactly as a real deployment wires it -- without it no
        test in this suite could build a mint carrying a §7.3 change
        notice, and the profile's burn arithmetic would go untested across
        an ``effective_at`` boundary.
        """
        clock = clock or FakeClock(T0)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db_path = os.path.join(tmp.name, "ledger.sqlite3")
        priv, pub = generate_keypair()
        ledger = Ledger(
            db_path,
            clock,
            burn_policy,
            recovery_window_ms=90 * DAY_MS,
            max_lock_expiry_ms=30 * DAY_MS,
            burn_policy_next=burn_policy_next,
        )
        config = MintConfig(
            mint_id=MINT_ID,
            baseline_model_class="frontier-2026",
            burn_policy=burn_policy,
            signing_private=priv,
            signing_public=pub,
            profiles=profiles,
            admin_token=admin_token,
            burn_policy_next=burn_policy_next,
            burn_policy_announced_at=burn_policy_announced_at,
        )
        if registration_token is self._NO_REGISTRATION_ARG:
            # Not passed through as a default value: the DEFAULT resolution
            # (follow admin_token, generate where there is none) is what
            # most of this suite is testing, and a sentinel keeps "the
            # argument was omitted" distinguishable from "the argument was
            # given something falsy" -- which is itself a case under test.
            server = SupervisionServer(config, ledger)
        else:
            server = SupervisionServer(
                config, ledger, registration_token=registration_token)
        port = server.start()
        self.addCleanup(server.stop)
        return Mint(port, clock, ledger, pub, db_path, server, burn_policy)

    def restart_mint(self, m):
        """Simulate a process restart: stop the server and bring up a
        fresh SupervisionServer over the SAME database and clock. The new
        _SupCore runs the §5.3 startup reconciliation of staged ops."""
        m.server.stop()
        priv, pub = generate_keypair()
        ledger = Ledger(
            m.db_path,
            m.clock,
            m.burn,
            recovery_window_ms=90 * DAY_MS,
            max_lock_expiry_ms=30 * DAY_MS,
        )
        config = MintConfig(
            mint_id=MINT_ID,
            baseline_model_class="frontier-2026",
            burn_policy=m.burn,
            signing_private=priv,
            signing_public=pub,
            profiles=(),
            admin_token=ADMIN_TOKEN,
        )
        server = SupervisionServer(config, ledger)
        port = server.start()
        self.addCleanup(server.stop)
        return Mint(port, m.clock, ledger, pub, m.db_path, server, m.burn)

    def sup_rows(self, m, sql, args=()):
        """Read supervision tables through an independent connection (what
        durable state a crashed process would leave behind)."""
        conn = sqlite3.connect(m.db_path)
        try:
            return conn.execute(sql, args).fetchall()
        finally:
            conn.close()

    def new_operator(self, m, name="op"):
        status, r = api(
            m.port, "POST", "/v3/operator/register", {"operator_name": name}
        )
        self.assertEqual(status, 200)
        return r["operator_id"], r["operator_key"]

    def new_agent(self, m, op_key, name="agent"):
        status, r = api(
            m.port,
            "POST",
            "/v3/operator/agents",
            {"agent_name": name},
            key=op_key,
        )
        self.assertEqual(status, 200)
        return r["agent_id"], r["agent_key"]

    def issue_token(self, m, amount_mc):
        """Operator-fund a bearer token via C06's /admin/issue."""
        secret = new_secret()
        status, r = api(
            m.port,
            "POST",
            "/admin/issue",
            {"outputs": [{"amount_mc": amount_mc, "secret_hash": ledger_key(secret)}]},
        )
        self.assertEqual(status, 200, r)
        return format_token(MINT_ID, amount_mc, secret)

    def fund(self, m, agent_key, amount_mc):
        """Issue a bearer token and deposit it into the agent's balance."""
        token = self.issue_token(m, amount_mc)
        status, r = api(
            m.port,
            "POST",
            "/v3/agent/deposit",
            {"tokens": [token]},
            key=agent_key,
        )
        self.assertEqual(status, 200, r)
        return r

    def balance(self, m, key, agent_id=None):
        path = "/v3/agent/balance"
        if agent_id is not None:
            path += "?agent_id=" + agent_id
        status, r = api(m.port, "GET", path, key=key)
        self.assertEqual(status, 200, r)
        return r

    def transfer(self, m, key, to_account, amount_mc, ref=None):
        body = {"to_account": to_account, "amount_mc": amount_mc}
        if ref is not None:
            body["ref"] = ref
        return api(m.port, "POST", "/v3/agent/transfer", body, key=key)

    def assertRejected(self, resp, reason, status=400):
        code, body = resp
        self.assertEqual(code, status, body)
        self.assertEqual(body, {"status": "rejected", "reason": reason})

    def statement(self, m, op_key, t_from, t_to, agent_id=None):
        path = "/v3/operator/statement?from=%d&to=%d" % (t_from, t_to)
        if agent_id is not None:
            path += "&agent_id=" + agent_id
        return api(m.port, "GET", path, key=op_key)

    def check_statement(self, m, stmt, operator_id, agent_scope):
        """Schema + signature + §6.1(7) partition invariant."""
        self.assertEqual(set(stmt), STATEMENT_KEYS)
        self.assertEqual(stmt["v"], 4)
        self.assertEqual(stmt["mint_id"], MINT_ID)
        self.assertEqual(
            stmt["scope"], {"operator_id": operator_id, "agent_id": agent_scope}
        )
        self.assertEqual(set(stmt["period"]), {"from", "to"})
        for line in stmt["lines"]:
            self.assertEqual(set(line), LINE_KEYS)
            self.assertGreaterEqual(line["t"], stmt["period"]["from"])
            self.assertLessEqual(line["t"], stmt["period"]["to"])
            if line["kind"] in ("freeze", "unfreeze"):
                self.assertEqual(line["amount_mc"], 0)
        credit = sum(
            ln["amount_mc"] for ln in stmt["lines"] if ln["kind"] in CREDIT_KINDS
        )
        debit = sum(
            ln["amount_mc"] for ln in stmt["lines"] if ln["kind"] in DEBIT_KINDS
        )
        self.assertEqual(
            credit - debit,
            stmt["closing_balance_mc"] - stmt["opening_balance_mc"],
        )
        # Signature verifies against the key the descriptor publishes.
        status, desc = api(m.port, "GET", "/v3/mints")
        self.assertEqual(status, 200)
        pub = b64u_decode(desc["signing_pubkey"], expect_len=32)
        self.assertTrue(verify_obj(stmt, pub))

    def assert_statement_is_renderable(self, obj, path="statement"):
        """Every string ANYWHERE in a signed statement renders.

        Stated over the whole document rather than field by field, so a
        statement field added later inherits it. The document is signed
        and its `ref` values are written by the agent the document
        audits, so "the mint signed it" must not be the only thing true
        of the text inside it.
        """
        if isinstance(obj, str):
            self.assertTrue(obj.isprintable(), "%s: %r" % (path, obj))
            obj.encode("utf-8")  # must not raise
        elif isinstance(obj, dict):
            for k, v in obj.items():
                self.assert_statement_is_renderable(k, path + " key")
                self.assert_statement_is_renderable(v, "%s.%s" % (path, k))
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                self.assert_statement_is_renderable(v, "%s[%d]" % (path, i))

    # ------------------------------------------------------------------ #
    # B1 — the three coherence clauses                                   #
    # ------------------------------------------------------------------ #

    def test_b1a_freeze_suspends_pulls_nothing_queues(self):
        """B1(a): freeze suspends pulls with account_frozen; nothing queues;
        after unfreeze a NEW pull succeeds and the failed one never ran."""
        m = self.start_mint()
        op_id, op_key = self.new_operator(m)
        g_id, g_key = self.new_agent(m, op_key, "granter")
        p_id, p_key = self.new_agent(m, op_key, "payee")
        self.fund(m, g_key, 100)
        status, r = api(
            m.port,
            "POST",
            "/v3/agent/authorize_pull",
            {"payee_account": p_id, "cap_mc_per_day": 100, "expires_at": T0 + 10 * DAY_MS},
            key=g_key,
        )
        self.assertEqual(status, 200)
        auth_id = r["auth_id"]

        status, r = api(
            m.port, "POST", "/v3/operator/freeze", {"agent_id": g_id}, key=op_key
        )
        self.assertEqual(status, 200)
        self.assertRejected(
            api(m.port, "POST", "/v3/pull", {"auth_id": auth_id, "amount_mc": 30}, key=p_key),
            "account_frozen",
        )
        # Nothing queued, nothing moved.
        self.assertEqual(self.balance(m, g_key)["balance_mc"], 100)
        self.assertEqual(self.balance(m, p_key)["balance_mc"], 0)

        status, r = api(
            m.port, "POST", "/v3/operator/unfreeze", {"agent_id": g_id}, key=op_key
        )
        self.assertEqual(status, 200)
        status, r = api(
            m.port, "POST", "/v3/pull", {"auth_id": auth_id, "amount_mc": 30}, key=p_key
        )
        self.assertEqual(status, 200, r)
        # Exactly ONE pull executed: the suspended one did not run later.
        self.assertEqual(self.balance(m, g_key)["balance_mc"], 70)
        self.assertEqual(self.balance(m, p_key)["balance_mc"], 30)

    def test_b1b_pull_counts_against_granter_caps_atomically(self):
        """B1(b): pulls count against the granting agent's caps; a pull that
        would exceed per-hour fails atomically (no partial debit)."""
        m = self.start_mint()
        op_id, op_key = self.new_operator(m)
        g_id, g_key = self.new_agent(m, op_key, "granter")
        p_id, p_key = self.new_agent(m, op_key, "payee")
        self.fund(m, g_key, 500)
        status, _ = api(
            m.port,
            "POST",
            "/v3/operator/caps",
            {"agent_id": g_id, "per_hour_mc": 100, "per_day_mc": None, "absolute_mc": None},
            key=op_key,
        )
        self.assertEqual(status, 200)
        status, r = api(
            m.port,
            "POST",
            "/v3/agent/authorize_pull",
            {"payee_account": p_id, "cap_mc_per_day": 1000, "expires_at": T0 + 10 * DAY_MS},
            key=g_key,
        )
        self.assertEqual(status, 200)
        auth_id = r["auth_id"]

        status, _ = self.transfer(m, g_key, p_id, 60)
        self.assertEqual(status, 200)
        # 60 already in the trailing hour; a 50 pull would make 110 > 100.
        self.assertRejected(
            api(m.port, "POST", "/v3/pull", {"auth_id": auth_id, "amount_mc": 50}, key=p_key),
            "agent_cap_exceeded",
        )
        self.assertEqual(self.balance(m, g_key)["balance_mc"], 440)
        self.assertEqual(self.balance(m, p_key)["balance_mc"], 60)
        status, r = api(
            m.port, "POST", "/v3/pull", {"auth_id": auth_id, "amount_mc": 40}, key=p_key
        )
        self.assertEqual(status, 200, r)
        self.assertEqual(self.balance(m, g_key)["balance_mc"], 400)
        self.assertEqual(self.balance(m, p_key)["balance_mc"], 100)

    def test_b1c_statement_on_demand_for_just_closed_period(self):
        """B1(c): a statement for a just-closed period is produced on demand
        and verifies — schema, mint signature, balance invariant."""
        m = self.start_mint()
        op_id, op_key = self.new_operator(m)
        a_id, a_key = self.new_agent(m, op_key, "a")
        b_id, b_key = self.new_agent(m, op_key, "b")
        self.fund(m, a_key, 100)
        status, _ = self.transfer(m, a_key, b_id, 25, ref="job-1")
        self.assertEqual(status, 200)
        t_close = m.clock()
        m.clock.advance(HOUR_MS)  # the period is now closed

        status, stmt = self.statement(m, op_key, T0, t_close, agent_id=a_id)
        self.assertEqual(status, 200, stmt)
        self.check_statement(m, stmt, op_id, a_id)
        self.assertEqual(stmt["opening_balance_mc"], 0)
        self.assertEqual(stmt["closing_balance_mc"], 75)
        self.assertEqual(
            [(ln["kind"], ln["amount_mc"], ln["counterparty_account"], ln["ref"]) for ln in stmt["lines"]],
            [("deposit", 100, None, ""), ("debit", 25, b_id, "job-1")],
        )

    # ------------------------------------------------------------------ #
    # B2 — no-bearer-withdrawal flag                                     #
    # ------------------------------------------------------------------ #

    def test_b2_withdrawal_flag(self):
        """B2: flag set -> withdraw fails withdrawal_disabled with no ledger
        change; deposits still land; unset -> withdraw succeeds; the flag is
        settable by the operator key only (agent attempt -> 403)."""
        m = self.start_mint()
        op_id, op_key = self.new_operator(m)
        a_id, a_key = self.new_agent(m, op_key)
        self.fund(m, a_key, 100)

        # Agent keys cannot set flags (§6.1(1)).
        status, body = api(
            m.port,
            "POST",
            "/v3/operator/flags",
            {"agent_id": a_id, "no_bearer_withdrawal": True},
            key=a_key,
        )
        self.assertEqual(status, 403)
        self.assertEqual(body, {"status": "forbidden"})

        status, _ = api(
            m.port,
            "POST",
            "/v3/operator/flags",
            {"agent_id": a_id, "no_bearer_withdrawal": True},
            key=op_key,
        )
        self.assertEqual(status, 200)

        supply_before = m.ledger.supply()
        secret = new_secret()
        self.assertRejected(
            api(
                m.port,
                "POST",
                "/v3/agent/withdraw",
                {"outputs": [{"amount_mc": 10, "secret_hash": ledger_key(secret)}]},
                key=a_key,
            ),
            "withdrawal_disabled",
        )
        self.assertEqual(m.ledger.supply(), supply_before)  # no ledger change
        self.assertEqual(self.balance(m, a_key)["balance_mc"], 100)
        # Deposits still allowed while the flag is set (§6.1(4)).
        self.fund(m, a_key, 20)
        self.assertEqual(self.balance(m, a_key)["balance_mc"], 120)

        status, _ = api(
            m.port,
            "POST",
            "/v3/operator/flags",
            {"agent_id": a_id, "no_bearer_withdrawal": False},
            key=op_key,
        )
        self.assertEqual(status, 200)
        status, r = api(
            m.port,
            "POST",
            "/v3/agent/withdraw",
            {"outputs": [{"amount_mc": 10, "secret_hash": ledger_key(secret)}]},
            key=a_key,
        )
        self.assertEqual(status, 200, r)
        self.assertEqual(r["withdrawn_mc"], 10)
        self.assertEqual(self.balance(m, a_key)["balance_mc"], 110)
        _, entry = api(m.port, "GET", "/v3/status/" + ledger_key(secret))
        self.assertEqual(entry["result"]["state"], "unspent")
        self.assertEqual(entry["result"]["amount_mc"], 10)

    # ------------------------------------------------------------------ #
    # B3 — rolling trailing windows with the fake clock                  #
    # ------------------------------------------------------------------ #

    def test_b3_trailing_hour_window_and_not_calendar(self):
        """B3: cap 100/hour; 60 at t=0 and 40 at t=30min fill it; +1 fails;
        at t=61min the t=0 spend ages out and 60 more succeeds. Windows are
        trailing, never calendar: 100 spent at 23:59 still blocks at 00:01."""
        m = self.start_mint()
        op_id, op_key = self.new_operator(m)
        a_id, a_key = self.new_agent(m, op_key, "hourly")
        z_id, _ = self.new_agent(m, op_key, "sink")
        self.fund(m, a_key, 1000)
        status, _ = api(
            m.port,
            "POST",
            "/v3/operator/caps",
            {"agent_id": a_id, "per_hour_mc": 100, "per_day_mc": None, "absolute_mc": None},
            key=op_key,
        )
        self.assertEqual(status, 200)

        self.assertEqual(self.transfer(m, a_key, z_id, 60)[0], 200)  # t=0
        m.clock.advance(30 * 60_000)  # t = 30min
        self.assertEqual(self.transfer(m, a_key, z_id, 40)[0], 200)
        self.assertRejected(self.transfer(m, a_key, z_id, 1), "agent_cap_exceeded")
        m.clock.advance(31 * 60_000)  # t = 61min: the 60 has aged out
        self.assertEqual(self.transfer(m, a_key, z_id, 60)[0], 200)
        self.assertRejected(self.transfer(m, a_key, z_id, 1), "agent_cap_exceeded")

        # Trailing, not calendar: fresh agent, spend right before a UTC
        # midnight, cross it, cap still binds two minutes later.
        b_id, b_key = self.new_agent(m, op_key, "midnight")
        self.fund(m, b_key, 1000)
        status, _ = api(
            m.port,
            "POST",
            "/v3/operator/caps",
            {"agent_id": b_id, "per_hour_mc": 100},
            key=op_key,
        )
        self.assertEqual(status, 200)
        midnight = (m.clock() // DAY_MS + 1) * DAY_MS
        m.clock.set(midnight - 60_000)  # 23:59 UTC
        self.assertEqual(self.transfer(m, b_key, z_id, 100)[0], 200)
        m.clock.advance(120_000)  # 00:01 UTC next day
        self.assertRejected(self.transfer(m, b_key, z_id, 1), "agent_cap_exceeded")

    def test_b3_trailing_day_window_and_absolute(self):
        """B3: per-day trailing 86400s window behaves like the hour window;
        the absolute cap is a lifetime total that never ages out."""
        m = self.start_mint()
        op_id, op_key = self.new_operator(m)
        d_id, d_key = self.new_agent(m, op_key, "daily")
        e_id, e_key = self.new_agent(m, op_key, "lifetime")
        z_id, _ = self.new_agent(m, op_key, "sink")
        self.fund(m, d_key, 1000)
        self.fund(m, e_key, 1000)
        status, _ = api(
            m.port,
            "POST",
            "/v3/operator/caps",
            {"agent_id": d_id, "per_day_mc": 100},
            key=op_key,
        )
        self.assertEqual(status, 200)
        status, _ = api(
            m.port,
            "POST",
            "/v3/operator/caps",
            {"agent_id": e_id, "absolute_mc": 200},
            key=op_key,
        )
        self.assertEqual(status, 200)

        self.assertEqual(self.transfer(m, d_key, z_id, 60)[0], 200)  # t
        m.clock.advance(12 * HOUR_MS)
        self.assertEqual(self.transfer(m, d_key, z_id, 40)[0], 200)  # t+12h
        self.assertRejected(self.transfer(m, d_key, z_id, 1), "agent_cap_exceeded")
        m.clock.advance(12 * HOUR_MS + 60_000)  # t+24h+1min: 60 aged out
        self.assertEqual(self.transfer(m, d_key, z_id, 60)[0], 200)
        self.assertRejected(self.transfer(m, d_key, z_id, 1), "agent_cap_exceeded")

        # Absolute = lifetime: aging never frees it.
        self.assertEqual(self.transfer(m, e_key, z_id, 150)[0], 200)
        m.clock.advance(3 * DAY_MS)
        self.assertEqual(self.transfer(m, e_key, z_id, 50)[0], 200)
        self.assertRejected(self.transfer(m, e_key, z_id, 1), "agent_cap_exceeded")
        m.clock.advance(30 * DAY_MS)
        self.assertRejected(self.transfer(m, e_key, z_id, 1), "agent_cap_exceeded")

    # ------------------------------------------------------------------ #
    # B4 — operator-wide freeze                                          #
    # ------------------------------------------------------------------ #

    def test_b4_operator_wide_freeze_scoped_to_one_operator(self):
        """B4: freeze ALL halts every agent of that operator in one call and
        only that operator's agents; credits INTO frozen accounts still land
        (incoming transfer and deposit)."""
        m = self.start_mint()
        op1_id, op1_key = self.new_operator(m, "op1")
        op2_id, op2_key = self.new_operator(m, "op2")
        a_id, a_key = self.new_agent(m, op1_key, "a")
        b_id, b_key = self.new_agent(m, op1_key, "b")
        c_id, c_key = self.new_agent(m, op2_key, "c")
        for k in (a_key, b_key, c_key):
            self.fund(m, k, 100)

        # Cross-operator targeting is refused.
        status, _ = api(
            m.port, "POST", "/v3/operator/freeze", {"agent_id": c_id}, key=op1_key
        )
        self.assertEqual(status, 404)

        status, r = api(
            m.port, "POST", "/v3/operator/freeze", {"agent_id": "ALL"}, key=op1_key
        )
        self.assertEqual(status, 200)
        self.assertEqual(sorted(r["frozen"]), sorted([a_id, b_id]))

        self.assertRejected(self.transfer(m, a_key, c_id, 10), "account_frozen")
        self.assertRejected(self.transfer(m, b_key, c_id, 10), "account_frozen")
        # Only op1's agents are frozen: op2's agent still spends freely.
        self.assertEqual(self.transfer(m, c_key, a_id, 10)[0], 200)
        # ... and that credit INTO frozen a landed.
        self.assertEqual(self.balance(m, a_key)["balance_mc"], 110)
        # Deposits into a frozen account land too (§6.1(3): credits in).
        self.fund(m, a_key, 5)
        self.assertEqual(self.balance(m, a_key)["balance_mc"], 115)

        status, r = api(
            m.port, "POST", "/v3/operator/unfreeze", {"agent_id": "ALL"}, key=op1_key
        )
        self.assertEqual(status, 200)
        self.assertEqual(sorted(r["unfrozen"]), sorted([a_id, b_id]))
        self.assertEqual(self.transfer(m, a_key, c_id, 10)[0], 200)
        self.assertEqual(self.transfer(m, b_key, c_id, 10)[0], 200)

    # ------------------------------------------------------------------ #
    # B5 — deposit/withdraw round trip through the real ledger           #
    # ------------------------------------------------------------------ #

    def test_b5_deposit_withdraw_round_trip(self):
        """B5: bearer -> custodial -> bearer conserves value minus exactly
        the two exchange burns; the custodial transfer in between burns
        nothing; withdrawal is by-hash and the withdrawn secret never
        appears anywhere in the mint database."""
        m = self.start_mint(burn_policy=BURN)
        op_id, op_key = self.new_operator(m)
        a_id, a_key = self.new_agent(m, op_key, "a")
        b_id, b_key = self.new_agent(m, op_key, "b")

        # Deposit 1000: burn 1% = 10, net credit 990.
        token = self.issue_token(m, 1000)
        status, r = api(
            m.port, "POST", "/v3/agent/deposit", {"tokens": [token]}, key=a_key
        )
        self.assertEqual(status, 200, r)
        self.assertEqual(r["burn_mc"], 10)
        self.assertEqual(r["deposited_mc"], 990)
        self.assertEqual(r["balance_mc"], 990)
        supply = m.ledger.supply()
        self.assertEqual(supply["cumulative_issued_mc"], 1000)
        self.assertEqual(supply["cumulative_burned_mc"], 10)
        self.assertEqual(supply["outstanding_mc"], 990)

        # Custodial transfer burns NOTHING (§7.3).
        status, _ = self.transfer(m, a_key, b_id, 490)
        self.assertEqual(status, 200)
        self.assertEqual(m.ledger.supply()["cumulative_burned_mc"], 10)

        # Withdraw 480 by hash: the agent is charged burn(480) = 4 on the
        # REQUESTED amount (§7.3/R17); the ledger's exchange still burns
        # burn(990) = 9 on the custody input, mint custody absorbs 5.
        secret = new_secret()
        status, r = api(
            m.port,
            "POST",
            "/v3/agent/withdraw",
            {"outputs": [{"amount_mc": 480, "secret_hash": ledger_key(secret)}]},
            key=b_key,
        )
        self.assertEqual(status, 200, r)
        self.assertEqual(r["withdrawn_mc"], 480)
        self.assertEqual(r["burn_mc"], 4)  # compute_burn(480), not burn(990)
        self.assertEqual(r["balance_mc"], 6)  # 490 - 484

        # Conservation: 1000 in, 10 + 9 burned across the two exchanges.
        supply = m.ledger.supply()
        self.assertEqual(supply["cumulative_burned_mc"], 19)
        self.assertEqual(supply["outstanding_mc"], 981)
        # Outstanding = withdrawn bearer entry (480) + mint custody (501);
        # custody equals the sum of balances (500 + 6) minus the 5 mc the
        # mint absorbed (ledger burn 9 vs agent-charged 4 — §7.3/R17).
        self.assertEqual(supply["outstanding_mc"] - 480, 501)
        self.assertEqual(self.balance(m, a_key)["balance_mc"], 500)
        self.assertEqual(self.balance(m, b_key)["balance_mc"], 6)
        ((absorbed,),) = self.sup_rows(m, "SELECT absorbed_mc FROM sup_mint")
        self.assertEqual(absorbed, 5)
        self.assertEqual(501, 500 + 6 - absorbed)

        # The new entry exists, unspent, at the requested hash.
        _, entry = api(m.port, "GET", "/v3/status/" + ledger_key(secret))
        self.assertEqual(entry["result"]["state"], "unspent")
        self.assertEqual(entry["result"]["amount_mc"], 480)

        # By-hash means the mint NEVER saw the secret: neither the raw
        # bytes nor its b64u encoding occur anywhere in the mint database.
        with open(m.db_path, "rb") as fh:
            db_bytes = fh.read()
        self.assertNotIn(secret, db_bytes)
        self.assertNotIn(b64u_encode(secret).encode("ascii"), db_bytes)

        # And it is real bearer value: an unregistered Layer 0 exchange
        # of the withdrawn token succeeds (burn 1% of 480 = 4).
        fresh = new_secret()
        status, r = api(
            m.port,
            "POST",
            "/v3/exchange",
            {
                "idempotency_key": "roundtrip-1",
                "inputs": [format_token(MINT_ID, 480, secret)],
                "outputs": [{"amount_mc": 476, "secret_hash": ledger_key(fresh)}],
            },
        )
        self.assertEqual(status, 200, r)

    # ------------------------------------------------------------------ #
    # B6 — pull lifecycle                                                #
    # ------------------------------------------------------------------ #

    def test_b6_pull_lifecycle(self):
        """B6: authorize -> pull ok -> revoke -> authorization_revoked;
        expiry via the fake clock -> authorization_expired; the per-auth
        trailing-day cap is enforced atomically."""
        m = self.start_mint()
        op_id, op_key = self.new_operator(m)
        g_id, g_key = self.new_agent(m, op_key, "granter")
        p_id, p_key = self.new_agent(m, op_key, "payee")
        p2_id, p2_key = self.new_agent(m, op_key, "payee2")
        self.fund(m, g_key, 500)

        def authorize(payee, cap, expires_at):
            status, r = api(
                m.port,
                "POST",
                "/v3/agent/authorize_pull",
                {"payee_account": payee, "cap_mc_per_day": cap, "expires_at": expires_at},
                key=g_key,
            )
            self.assertEqual(status, 200, r)
            return r["auth_id"]

        def pull(key, auth_id, amount):
            return api(
                m.port, "POST", "/v3/pull", {"auth_id": auth_id, "amount_mc": amount}, key=key
            )

        auth1 = authorize(p_id, 100, T0 + 20 * DAY_MS)
        self.assertEqual(pull(p_key, auth1, 60)[0], 200)
        # Per-auth trailing-day cap: 60 + 50 > 100 fails atomically.
        self.assertRejected(pull(p_key, auth1, 50), "pull_cap_exceeded")
        self.assertEqual(self.balance(m, g_key)["balance_mc"], 440)
        self.assertEqual(self.balance(m, p_key)["balance_mc"], 60)
        self.assertEqual(pull(p_key, auth1, 40)[0], 200)
        self.assertRejected(pull(p_key, auth1, 1), "pull_cap_exceeded")
        # The day window is trailing: 24h+1min later it has emptied.
        m.clock.advance(DAY_MS + 60_000)
        self.assertEqual(pull(p_key, auth1, 100)[0], 200)
        self.assertEqual(self.balance(m, g_key)["balance_mc"], 300)

        # Revocation is immediate.
        status, _ = api(
            m.port, "POST", "/v3/agent/revoke_pull", {"auth_id": auth1}, key=g_key
        )
        self.assertEqual(status, 200)
        self.assertRejected(pull(p_key, auth1, 10), "authorization_revoked")

        # Expiry against the mint clock; the boundary belongs to expiry.
        auth2 = authorize(p_id, 100, m.clock() + HOUR_MS)
        self.assertEqual(pull(p_key, auth2, 5)[0], 200)
        m.clock.advance(61 * 60_000)
        self.assertRejected(pull(p_key, auth2, 5), "authorization_expired")

        # Unknown auth, and an auth granted to a DIFFERENT payee, both
        # answer authorization_missing.
        self.assertRejected(pull(p_key, "auth-nope", 5), "authorization_missing")
        auth3 = authorize(p2_id, 100, m.clock() + DAY_MS)
        self.assertRejected(pull(p_key, auth3, 5), "authorization_missing")
        self.assertEqual(pull(p2_key, auth3, 5)[0], 200)

    # ------------------------------------------------------------------ #
    # B7 — scripted-week statement cross-check                           #
    # ------------------------------------------------------------------ #

    def test_b7_statement_week_cross_check(self):
        """B7: a scripted week (issue+deposit, transfer, pull, withdrawal
        with burn, freeze period); the statement's lines reproduce it
        exactly, the pinned partition sums match, and an independently
        recomputed balance equals closing_balance_mc."""
        m = self.start_mint(burn_policy=BURN)
        op_id, op_key = self.new_operator(m)
        a_id, a_key = self.new_agent(m, op_key, "a")
        b_id, b_key = self.new_agent(m, op_key, "b")

        t0 = m.clock()
        # Day 0: operator issues a 1000 mc bearer token; A deposits it
        # (burn 10, net 990).
        self.fund(m, a_key, 1000)
        # Day 1: A transfers 200 to B.
        m.clock.set(t0 + 1 * DAY_MS)
        t1 = m.clock()
        self.assertEqual(self.transfer(m, a_key, b_id, 200, ref="wages")[0], 200)
        # Day 2: A grants B a pull authorization; B pulls 50.
        m.clock.set(t0 + 2 * DAY_MS)
        t2 = m.clock()
        status, r = api(
            m.port,
            "POST",
            "/v3/agent/authorize_pull",
            {"payee_account": b_id, "cap_mc_per_day": 100, "expires_at": t0 + 30 * DAY_MS},
            key=a_key,
        )
        self.assertEqual(status, 200)
        status, _ = api(
            m.port,
            "POST",
            "/v3/pull",
            {"auth_id": r["auth_id"], "amount_mc": 50, "ref": "meter"},
            key=b_key,
        )
        self.assertEqual(status, 200)
        # Day 3: A withdraws 100 — charged burn(100) = 1 on the requested
        # amount (§7.3/R17), gross 101; the ledger burns 9 on the 990
        # custody input and the mint absorbs the 8 mc difference.
        m.clock.set(t0 + 3 * DAY_MS)
        t3 = m.clock()
        w_secret = new_secret()
        status, r = api(
            m.port,
            "POST",
            "/v3/agent/withdraw",
            {"outputs": [{"amount_mc": 100, "secret_hash": ledger_key(w_secret)}]},
            key=a_key,
        )
        self.assertEqual(status, 200, r)
        self.assertEqual(r["burn_mc"], 1)
        # Day 4: freeze A; half a day later unfreeze.
        m.clock.set(t0 + 4 * DAY_MS)
        t4 = m.clock()
        status, _ = api(
            m.port, "POST", "/v3/operator/freeze", {"agent_id": a_id}, key=op_key
        )
        self.assertEqual(status, 200)
        m.clock.set(t0 + 4 * DAY_MS + 12 * HOUR_MS)
        t5 = m.clock()
        status, _ = api(
            m.port, "POST", "/v3/operator/unfreeze", {"agent_id": a_id}, key=op_key
        )
        self.assertEqual(status, 200)

        # Close the week; produce statements on demand (§8(c)).
        m.clock.set(t0 + 8 * DAY_MS)
        status, stmt = self.statement(m, op_key, t0, t0 + 7 * DAY_MS, agent_id=a_id)
        self.assertEqual(status, 200, stmt)
        self.check_statement(m, stmt, op_id, a_id)
        self.assertEqual(stmt["period"], {"from": t0, "to": t0 + 7 * DAY_MS})
        self.assertEqual(stmt["opening_balance_mc"], 0)
        self.assertEqual(stmt["closing_balance_mc"], 639)  # 990-200-50-100-1
        expected_lines = [
            {"t": t0, "kind": "deposit", "amount_mc": 990, "counterparty_account": None, "ref": ""},
            {"t": t1, "kind": "debit", "amount_mc": 200, "counterparty_account": b_id, "ref": "wages"},
            {"t": t2, "kind": "pull_out", "amount_mc": 50, "counterparty_account": b_id, "ref": "meter"},
            {"t": t3, "kind": "withdrawal", "amount_mc": 100, "counterparty_account": None, "ref": ""},
            {"t": t3, "kind": "burn", "amount_mc": 1, "counterparty_account": None, "ref": ""},
            {"t": t4, "kind": "freeze", "amount_mc": 0, "counterparty_account": None, "ref": ""},
            {"t": t5, "kind": "unfreeze", "amount_mc": 0, "counterparty_account": None, "ref": ""},
        ]
        self.assertEqual(stmt["lines"], expected_lines)
        # Independent recomputation of the closing balance.
        recomputed = stmt["opening_balance_mc"]
        for ln in stmt["lines"]:
            if ln["kind"] in CREDIT_KINDS:
                recomputed += ln["amount_mc"]
            elif ln["kind"] in DEBIT_KINDS:
                recomputed -= ln["amount_mc"]
        self.assertEqual(recomputed, stmt["closing_balance_mc"])
        self.assertEqual(self.balance(m, a_key)["balance_mc"], 639)

        # Fleet statement: both agents, same invariant, closing = 639+250.
        status, fleet = self.statement(m, op_key, t0, t0 + 7 * DAY_MS)
        self.assertEqual(status, 200, fleet)
        self.check_statement(m, fleet, op_id, "fleet")
        self.assertEqual(fleet["opening_balance_mc"], 0)
        self.assertEqual(fleet["closing_balance_mc"], 889)
        self.assertEqual(len(fleet["lines"]), 9)  # + B's credit and pull_in
        b_kinds = [
            (ln["kind"], ln["amount_mc"])
            for ln in fleet["lines"]
            if ln["counterparty_account"] == a_id
        ]
        self.assertEqual(b_kinds, [("credit", 200), ("pull_in", 50)])

    # ------------------------------------------------------------------ #
    # B8 — auth separation matrix                                        #
    # ------------------------------------------------------------------ #

    def test_b8_auth_separation_matrix(self):
        """B8 (and requirement 1): every supervision route crossed with
        {no key, agent key, operator key} yields the expected 401/403/200."""
        m = self.start_mint()
        op_id, op_key = self.new_operator(m, "matrix-op")
        a_id, a_key = self.new_agent(m, op_key, "actor")
        s_id, s_key = self.new_agent(m, op_key, "sacrificial")
        g_id, g_key = self.new_agent(m, op_key, "granter")
        self.fund(m, a_key, 100)
        self.fund(m, g_key, 100)
        # granter -> actor pull authorization (for the /v3/pull row).
        status, r = api(
            m.port,
            "POST",
            "/v3/agent/authorize_pull",
            {"payee_account": a_id, "cap_mc_per_day": 50, "expires_at": T0 + 10 * DAY_MS},
            key=g_key,
        )
        self.assertEqual(status, 200)
        auth_pull = r["auth_id"]
        # actor -> granter authorization (for the revoke row).
        status, r = api(
            m.port,
            "POST",
            "/v3/agent/authorize_pull",
            {"payee_account": g_id, "cap_mc_per_day": 50, "expires_at": T0 + 10 * DAY_MS},
            key=a_key,
        )
        self.assertEqual(status, 200)
        auth_rev = r["auth_id"]
        deposit_token = self.issue_token(m, 50)
        far = T0 + 30 * DAY_MS

        # (method, path, body, per-role query, {role: expected status})
        rows = [
            # No bearer key of EITHER kind registers an operator: the route
            # takes the mint's own credential (X-Admin-Token), which the
            # loop below deliberately withholds from every row.
            ("POST", "/v3/operator/register", {"operator_name": "x"}, None,
             {"none": 401, "agent": 401, "operator": 401}),
            ("POST", "/v3/operator/agents", {"agent_name": "x"}, None,
             {"none": 401, "agent": 403, "operator": 200}),
            ("POST", "/v3/operator/caps",
             {"agent_id": s_id, "per_hour_mc": 1_000_000}, None,
             {"none": 401, "agent": 403, "operator": 200}),
            ("POST", "/v3/operator/flags",
             {"agent_id": s_id, "no_bearer_withdrawal": False}, None,
             {"none": 401, "agent": 403, "operator": 200}),
            ("GET", "/v3/agent/balance", None,
             {"agent": "", "operator": "?agent_id=" + a_id},
             {"none": 401, "agent": 200, "operator": 200}),
            ("POST", "/v3/agent/authorize_pull",
             {"payee_account": g_id, "cap_mc_per_day": 10, "expires_at": far}, None,
             {"none": 401, "agent": 200, "operator": 403}),
            ("POST", "/v3/agent/revoke_pull", {"auth_id": auth_rev}, None,
             {"none": 401, "agent": 200, "operator": 403}),
            ("POST", "/v3/pull", {"auth_id": auth_pull, "amount_mc": 5}, None,
             {"none": 401, "agent": 200, "operator": 403}),
            ("POST", "/v3/agent/transfer", {"to_account": g_id, "amount_mc": 5}, None,
             {"none": 401, "agent": 200, "operator": 403}),
            ("POST", "/v3/agent/deposit", {"tokens": [deposit_token]}, None,
             {"none": 401, "agent": 200, "operator": 403}),
            ("POST", "/v3/agent/withdraw",
             {"outputs": [{"amount_mc": 5, "secret_hash": ledger_key(new_secret())}]},
             None, {"none": 401, "agent": 200, "operator": 403}),
            ("GET", "/v3/operator/statement", None,
             {"operator": "?agent_id=%s&from=0&to=%d" % (s_id, far),
              "agent": "?agent_id=%s&from=0&to=%d" % (s_id, far),
              "none": "?agent_id=%s&from=0&to=%d" % (s_id, far)},
             {"none": 401, "agent": 403, "operator": 200}),
            ("POST", "/v3/operator/freeze", {"agent_id": s_id}, None,
             {"none": 401, "agent": 403, "operator": 200}),
            ("POST", "/v3/operator/unfreeze", {"agent_id": s_id}, None,
             {"none": 401, "agent": 403, "operator": 200}),
        ]
        keys = {"none": None, "agent": a_key, "operator": op_key}
        for method, path, body, queries, expected in rows:
            # Wrong/absent credentials first so only the correct role mutates.
            for role in ("none", "agent", "operator"):
                want = expected[role]
                query = (queries or {}).get(role, "") if queries else ""
                with self.subTest(route=path, role=role):
                    status, resp = api(
                        m.port, method, path + query, body, key=keys[role],
                        admin=False,  # bearer keys only; see the first row
                    )
                    self.assertEqual(status, want, (path, role, resp))
                    if want == 401:
                        self.assertEqual(resp, {"status": "unauthorized"})
                    elif want == 403:
                        self.assertEqual(resp, {"status": "forbidden"})

        # The register row above is a 401 matrix, so prove the route still
        # works for the one credential that opens it — otherwise "401 for
        # everyone" would pass on a route that had simply been removed.
        status, resp = api(
            m.port, "POST", "/v3/operator/register",
            {"operator_name": "credentialed"}, admin=ADMIN_TOKEN,
        )
        self.assertEqual(status, 200, resp)
        self.assertIn("operator_key", resp)

        # A garbage bearer key is 401 (unknown), not 403.
        status, resp = api(
            m.port, "POST", "/v3/agent/transfer",
            {"to_account": g_id, "amount_mc": 1}, key="not-a-real-key",
        )
        self.assertEqual(status, 401)

    # ------------------------------------------------------------------ #
    # B9 — L13 scope: Layer 0 stays authless and un-capped               #
    # ------------------------------------------------------------------ #

    def test_b9_bearer_layer0_unaffected_and_profile_advertised(self):
        """B9 (and requirement 8): on a Supervision mint, bearer-mode Layer 0
        calls by unregistered callers stay fully functional and un-capped
        even while agents carry tiny caps; the descriptor advertises the
        'supervision' profile."""
        m = self.start_mint()  # note: config passed WITHOUT the profile
        status, desc = api(m.port, "GET", "/v3/mints")
        self.assertEqual(status, 200)
        self.assertIn("supervision", desc["profiles"])

        # Register an agent and give it a 1 mc/hour cap: L13 says this must
        # not leak onto bearer callers.
        op_id, op_key = self.new_operator(m)
        a_id, a_key = self.new_agent(m, op_key)
        status, _ = api(
            m.port,
            "POST",
            "/v3/operator/caps",
            {"agent_id": a_id, "per_hour_mc": 1},
            key=op_key,
        )
        self.assertEqual(status, 200)

        # Unregistered bearer caller: repeated large exchanges, no auth
        # header, no caps, no burn under NO_BURN policy.
        secret = new_secret()
        token = self.issue_token(m, 50_000)
        for i in range(3):
            nxt = new_secret()
            status, r = api(
                m.port,
                "POST",
                "/v3/exchange",
                {
                    "idempotency_key": "bearer-%d" % i,
                    "inputs": [token],
                    "outputs": [{"amount_mc": 50_000, "secret_hash": ledger_key(nxt)}],
                },
            )
            self.assertEqual(status, 200, r)
            token = format_token(MINT_ID, 50_000, nxt)
        _, entry = api(m.port, "GET", "/v3/status/" + ledger_key(nxt))
        self.assertEqual(entry["result"]["state"], "unspent")

    def test_admin_issue_is_refused_without_the_harness_credential(self):
        """The harness funds over /admin/issue with a credential, so it would
        keep passing if the gate were removed and the mint went open. This
        pins the gate directly, bypassing api()'s header: a supervision mint
        must answer 401 to an /admin/issue with NO X-Admin-Token and with a
        WRONG one, and must issue nothing in either case.

        The supervision profile inherits C06's admin route, so an open
        /admin/issue here mints without limit on a mint that also holds
        operator credentials, caps and freezes.
        """
        m = self.start_mint()
        secret = new_secret()
        body = json.dumps(
            {"outputs": [{"amount_mc": 1000,
                          "secret_hash": ledger_key(secret)}]}
        ).encode("utf-8")

        def raw_issue(headers):
            conn = http.client.HTTPConnection("127.0.0.1", m.port, timeout=30)
            try:
                conn.request("POST", "/admin/issue", body, headers)
                resp = conn.getresponse()
                resp.read()
                return resp.status
            finally:
                conn.close()

        self.assertEqual(raw_issue({}), 401)
        self.assertEqual(raw_issue({"X-Admin-Token": ""}), 401)
        self.assertEqual(raw_issue({"X-Admin-Token": "wrong"}), 401)
        self.assertEqual(raw_issue({"X-Admin-Token": ADMIN_TOKEN + "x"}), 401)
        # Nothing was created by any of those.
        _, desc = api(m.port, "GET", "/v3/mints")
        self.assertEqual(desc["supply"]["cumulative_issued_mc"], 0)
        _, entry = api(m.port, "GET", "/v3/status/" + ledger_key(secret))
        self.assertEqual(entry["result"]["state"], "unknown")
        # And the credential the harness holds does work, so the 401s above
        # are the gate refusing, not the route being broken.
        self.assertEqual(raw_issue({"X-Admin-Token": ADMIN_TOKEN}), 200)
        _, desc = api(m.port, "GET", "/v3/mints")
        self.assertEqual(desc["supply"]["cumulative_issued_mc"], 1000)

    # ------------------------------------------------------------------ #
    # requirement sweep: errors, scoping, invariant enforcement          #
    # ------------------------------------------------------------------ #

    def test_transfer_and_withdraw_errors(self):
        """Requirements 2/5/6: bad_format on malformed amounts, unknown
        target account, insufficient_balance on transfer and withdraw."""
        m = self.start_mint()
        op_id, op_key = self.new_operator(m)
        a_id, a_key = self.new_agent(m, op_key)
        b_id, b_key = self.new_agent(m, op_key)
        self.fund(m, a_key, 50)

        self.assertRejected(self.transfer(m, a_key, "nobody", 10), "unknown_account")
        for bad in (0, -5, "x", 5.5, True, None):
            self.assertRejected(self.transfer(m, a_key, b_id, bad), "bad_format")
        self.assertRejected(self.transfer(m, a_key, b_id, 51), "insufficient_balance")
        self.assertEqual(self.balance(m, a_key)["balance_mc"], 50)

        self.assertRejected(
            api(
                m.port,
                "POST",
                "/v3/agent/withdraw",
                {"outputs": [{"amount_mc": 51, "secret_hash": ledger_key(new_secret())}]},
                key=a_key,
            ),
            "insufficient_balance",
        )
        self.assertRejected(
            api(m.port, "POST", "/v3/agent/withdraw", {"outputs": []}, key=a_key),
            "bad_format",
        )
        # Withdrawals are by-hash ONLY: a by-secret output shape is refused.
        self.assertRejected(
            api(
                m.port,
                "POST",
                "/v3/agent/withdraw",
                {"outputs": [{"amount_mc": 5, "secret": b64u_encode(new_secret())}]},
                key=a_key,
            ),
            "bad_format",
        )
        # Pull authorization requires a custodial payee at this mint (§6.1(6)).
        self.assertRejected(
            api(
                m.port,
                "POST",
                "/v3/agent/authorize_pull",
                {"payee_account": "nobody", "cap_mc_per_day": 10, "expires_at": T0 + DAY_MS},
                key=a_key,
            ),
            "unknown_account",
        )

    def test_statement_scoping_and_bad_params(self):
        """Requirement 7/1: an operator cannot obtain another operator's
        agent statement; malformed periods are rejected."""
        m = self.start_mint()
        op1_id, op1_key = self.new_operator(m, "op1")
        op2_id, op2_key = self.new_operator(m, "op2")
        a_id, a_key = self.new_agent(m, op1_key)

        status, _ = self.statement(m, op2_key, T0, T0 + DAY_MS, agent_id=a_id)
        self.assertEqual(status, 404)
        status, _ = api(
            m.port, "GET", "/v3/operator/statement?from=5", key=op1_key
        )
        self.assertEqual(status, 400)
        status, _ = api(
            m.port,
            "GET",
            "/v3/operator/statement?from=10&to=5&agent_id=" + a_id,
            key=op1_key,
        )
        self.assertEqual(status, 400)
        # Operators can read their own agents' balances; agents cannot read
        # each other's (auth separation, §6.1(1)/(5)).
        b_id, b_key = self.new_agent(m, op1_key, "b")
        r = self.balance(m, op1_key, agent_id=a_id)
        self.assertEqual(r["balance_mc"], 0)
        status, _ = api(
            m.port, "GET", "/v3/agent/balance?agent_id=" + a_id, key=b_key
        )
        self.assertEqual(status, 403)

    def test_statement_invariant_enforced_at_generation(self):
        """Requirement 7: the balance invariant is enforced when the
        statement is generated — a tampered stored balance makes the mint
        refuse (500) rather than sign a wrong statement."""
        m = self.start_mint()
        op_id, op_key = self.new_operator(m)
        a_id, a_key = self.new_agent(m, op_key)
        self.fund(m, a_key, 100)
        t_close = m.clock()
        m.clock.advance(1000)
        status, _ = self.statement(m, op_key, T0, t_close, agent_id=a_id)
        self.assertEqual(status, 200)

        # Corrupt the stored balance behind the journal's back.
        conn = sqlite3.connect(m.db_path)
        conn.execute(
            "UPDATE sup_agents SET balance_mc = balance_mc + 1 WHERE agent_id = ?",
            (a_id,),
        )
        conn.commit()
        conn.close()
        status, body = self.statement(m, op_key, T0, t_close, agent_id=a_id)
        self.assertEqual(status, 500)
        self.assertEqual(body, {"status": "error"})

    def test_withdrawal_burn_counts_against_caps(self):
        """Requirement 2 + §7.3/R17: the withdrawal GROSS charged against
        caps is amount + compute_burn(amount) — the burn on the REQUESTED
        amount, never on the mint's internally selected custody inputs.
        Withdrawing 95 against a single 990 mc custody entry charges
        burn(95) = 0 (the superseded input-sum rule would have charged
        burn(990) = 9 and tripped the cap); the ledger still burns 9 on
        the actual input per L12 and mint custody absorbs the difference.
        Statement invariant and ledger supply invariant both still hold."""
        m = self.start_mint(burn_policy=BURN)
        op_id, op_key = self.new_operator(m)
        a_id, a_key = self.new_agent(m, op_key)
        self.fund(m, a_key, 1000)  # burn 10 -> balance 990, ONE 990 custody entry
        status, _ = api(
            m.port,
            "POST",
            "/v3/operator/caps",
            {"agent_id": a_id, "per_hour_mc": 100},
            key=op_key,
        )
        self.assertEqual(status, 200)
        supply_before = m.ledger.supply()
        # burn(100) = 1: withdrawing 100 costs 100 + 1 = 101 > 100 — the
        # requested amount's OWN burn trips the cap, atomically (no ledger
        # or balance change).
        self.assertRejected(
            api(
                m.port,
                "POST",
                "/v3/agent/withdraw",
                {"outputs": [{"amount_mc": 100, "secret_hash": ledger_key(new_secret())}]},
                key=a_key,
            ),
            "agent_cap_exceeded",
        )
        self.assertEqual(m.ledger.supply(), supply_before)
        self.assertEqual(self.balance(m, a_key)["balance_mc"], 990)
        # burn(95) = 0: gross 95 <= 100 passes even though the only custody
        # input the mint can select is the 990 entry with burn(990) = 9 —
        # under the old input-sum rule this was gross 104 and failed.
        status, r = api(
            m.port,
            "POST",
            "/v3/agent/withdraw",
            {"outputs": [{"amount_mc": 95, "secret_hash": ledger_key(new_secret())}]},
            key=a_key,
        )
        self.assertEqual(status, 200, r)
        self.assertEqual(r["withdrawn_mc"], 95)
        self.assertEqual(r["burn_mc"], 0)  # compute_burn(95), NOT burn(990)
        self.assertEqual(r["balance_mc"], 895)  # charged exactly 95
        self.assertEqual(self.balance(m, a_key)["balance_mc"], 895)
        # ...and the spend-rate shows the new gross (95 + 0).
        rate = self.balance(m, a_key)["spend_rate"]
        self.assertEqual(rate["trailing_hour_mc"], 95)
        self.assertEqual(rate["lifetime_mc"], 95)

        # Ledger supply invariant: the exchange still burned per L12 on its
        # actual 990 input (9), on top of the deposit's 10.
        supply = m.ledger.supply()
        self.assertEqual(supply["cumulative_issued_mc"], 1000)
        self.assertEqual(supply["cumulative_burned_mc"], 19)
        self.assertEqual(supply["outstanding_mc"], 981)
        self.assertEqual(
            supply["cumulative_issued_mc"] - supply["cumulative_burned_mc"],
            supply["outstanding_mc"],
        )
        # Mint custody absorbed ALL of the ledger-level burn (9 - 0):
        # unspent custody is 990 - 95 - 9 = 886 = balance - absorbed, and
        # outstanding = withdrawn bearer entry + custody.
        ((custody_sum,),) = self.sup_rows(
            m,
            "SELECT COALESCE(SUM(amount_mc), 0) FROM sup_custody"
            " WHERE state = 'unspent'",
        )
        self.assertEqual(custody_sum, 886)
        ((absorbed,),) = self.sup_rows(m, "SELECT absorbed_mc FROM sup_mint")
        self.assertEqual(absorbed, 9)
        self.assertEqual(custody_sum, 895 - absorbed)
        self.assertEqual(supply["outstanding_mc"], 95 + custody_sum)

        # Statement invariant still holds: withdrawal line is the net 95,
        # and a zero agent-charged burn produces NO burn line.
        t_close = m.clock()
        m.clock.advance(1000)
        status, stmt = self.statement(m, op_key, T0, t_close, agent_id=a_id)
        self.assertEqual(status, 200, stmt)
        self.check_statement(m, stmt, op_id, a_id)
        self.assertEqual(stmt["opening_balance_mc"], 0)
        self.assertEqual(stmt["closing_balance_mc"], 895)
        self.assertEqual(
            [(ln["kind"], ln["amount_mc"]) for ln in stmt["lines"]],
            [("deposit", 990), ("withdrawal", 95)],
        )

    # ------------------------------------------------------------------ #
    # self-transfer is refused (nets to zero, would eat cap headroom)    #
    # ------------------------------------------------------------------ #

    def test_self_transfer_rejected(self):
        """A transfer to the caller's own account is bad_format: nothing
        moves, no journal lines are written, no cap headroom is consumed."""
        m = self.start_mint()
        op_id, op_key = self.new_operator(m)
        a_id, a_key = self.new_agent(m, op_key)
        self.fund(m, a_key, 100)
        status, _ = api(
            m.port,
            "POST",
            "/v3/operator/caps",
            {"agent_id": a_id, "per_hour_mc": 50},
            key=op_key,
        )
        self.assertEqual(status, 200)

        self.assertRejected(self.transfer(m, a_key, a_id, 10), "bad_format")
        r = self.balance(m, a_key)
        self.assertEqual(r["balance_mc"], 100)
        # No debit line landed: the full cap is still available.
        self.assertEqual(r["spend_rate"]["trailing_hour_mc"], 0)
        self.assertEqual(self.transfer(m, a_key, a_id, 50)[0], 400)
        # ...and a real transfer of the full headroom still succeeds.
        b_id, _ = self.new_agent(m, op_key, "b")
        self.assertEqual(self.transfer(m, a_key, b_id, 50)[0], 200)

    # ------------------------------------------------------------------ #
    # F3 — the no-bearer-withdrawal flag means what the threat model says #
    # ------------------------------------------------------------------ #
    #
    # §6.1(4) says withdrawals from a flagged account fail, and the spec's
    # threat model claims that closes "supervised agent exfiltrates its
    # allowance to bearer". It did not. Two doors stood open behind it:
    # /v3/agent/transfer never looked at the flag (nor at whether sender and
    # target shared an operator), and /v3/operator/register was authless, so
    # the holder of a flagged agent registered an operator of its own,
    # registered an agent under it, transferred the allowance across and
    # withdrew it as bearer. The tests below lock BOTH doors independently:
    # each one holds with the other reverted.

    def test_flagged_agent_cannot_reach_bearer_through_a_second_operator(self):
        """The full bypass, as reproduced by the review, as a regression:
        5000 deposited, withdrawal refused, 4000 transferred to an agent of
        a second operator, 3000 withdrawn there as bearer.

        The second operator is registered WITH the mint credential here on
        purpose. The gate added alongside this fix
        (test_operator_register_requires_the_mint_credential) already stops
        an outsider at the first step, but a bypass that needs two locks to
        both hold is a bypass that returns the moment either is relaxed —
        so this test hands itself the credential and proves the transfer
        rule stops the exfiltration on its own.
        """
        m = self.start_mint()
        op_id, op_key = self.new_operator(m, "principal")
        a_id, a_key = self.new_agent(m, op_key, "flagged")
        self.fund(m, a_key, 5000)
        status, r = api(
            m.port, "POST", "/v3/operator/flags",
            {"agent_id": a_id, "no_bearer_withdrawal": True}, key=op_key,
        )
        self.assertEqual(status, 200, r)

        direct_secret = new_secret()
        self.assertRejected(
            api(
                m.port, "POST", "/v3/agent/withdraw",
                {"outputs": [{"amount_mc": 3000,
                              "secret_hash": ledger_key(direct_secret)}]},
                key=a_key,
            ),
            "withdrawal_disabled",
        )

        # The mule: a second operator, and an agent under it.
        _op2_id, op2_key = self.new_operator(m, "attacker")
        mule_id, mule_key = self.new_agent(m, op2_key, "mule")

        self.assertRejected(
            self.transfer(m, a_key, mule_id, 4000),
            "external_transfer_disabled",
        )
        # Nothing moved, nothing was journalled, no cap headroom went.
        flagged = self.balance(m, a_key)
        self.assertEqual(flagged["balance_mc"], 5000)
        self.assertEqual(flagged["spend_rate"]["lifetime_mc"], 0)
        self.assertEqual(self.balance(m, mule_key)["balance_mc"], 0)

        # ...so the mule has nothing to withdraw, and no bearer token
        # exists at either secret_hash.
        mule_secret = new_secret()
        self.assertRejected(
            api(
                m.port, "POST", "/v3/agent/withdraw",
                {"outputs": [{"amount_mc": 3000,
                              "secret_hash": ledger_key(mule_secret)}]},
                key=mule_key,
            ),
            "insufficient_balance",
        )
        _t, results = m.ledger.status(
            [ledger_key(direct_secret), ledger_key(mule_secret)]
        )
        self.assertEqual([r["state"] for r in results], ["unknown", "unknown"])

    def test_flag_stops_transfers_out_of_the_operator_only(self):
        """The line is the OPERATOR, and that choice is asserted, not
        assumed.

        A flagged agent may still settle to a SIBLING agent of its own
        operator: the sibling is inside the same perimeter (same operator's
        caps, freeze, flags, fleet statement), so refusing it would break
        ordinary intra-fleet accounting and buy nothing — as the second
        half of this test records, that sibling CAN still withdraw unless
        the operator flags it too. That residual is the honest bound and it
        belongs in a test rather than in prose. What the flag now denies is
        the hop the operator cannot supervise: value landing under another
        operator.
        """
        m = self.start_mint()
        op_id, op_key = self.new_operator(m, "principal")
        a_id, a_key = self.new_agent(m, op_key, "flagged")
        sib_id, sib_key = self.new_agent(m, op_key, "sibling")
        _op2_id, op2_key = self.new_operator(m, "other")
        out_id, _out_key = self.new_agent(m, op2_key, "outsider")
        self.fund(m, a_key, 1000)

        # Unflagged, both directions work: the restriction is the flag,
        # not a blanket ban on cross-operator transfer.
        self.assertEqual(self.transfer(m, a_key, out_id, 100)[0], 200)
        self.assertEqual(self.transfer(m, a_key, sib_id, 100)[0], 200)

        status, r = api(
            m.port, "POST", "/v3/operator/flags",
            {"agent_id": a_id, "no_bearer_withdrawal": True}, key=op_key,
        )
        self.assertEqual(status, 200, r)

        self.assertRejected(
            self.transfer(m, a_key, out_id, 100),
            "external_transfer_disabled",
        )
        self.assertEqual(self.transfer(m, a_key, sib_id, 100)[0], 200)
        self.assertEqual(self.balance(m, sib_key)["balance_mc"], 200)

        # The residual, stated out loud: the sibling is not flagged, so it
        # can still withdraw. The operator's remedy is its own flag.
        secret = new_secret()
        status, r = api(
            m.port, "POST", "/v3/agent/withdraw",
            {"outputs": [{"amount_mc": 150, "secret_hash": ledger_key(secret)}]},
            key=sib_key,
        )
        self.assertEqual(status, 200, r)
        status, r = api(
            m.port, "POST", "/v3/operator/flags",
            {"agent_id": sib_id, "no_bearer_withdrawal": True}, key=op_key,
        )
        self.assertEqual(status, 200, r)
        self.assertRejected(
            api(
                m.port, "POST", "/v3/agent/withdraw",
                {"outputs": [{"amount_mc": 10,
                              "secret_hash": ledger_key(new_secret())}]},
                key=sib_key,
            ),
            "withdrawal_disabled",
        )

    def test_flagged_agent_cannot_pull_value_out_of_its_operator(self):
        """A pull grant is a transfer the payee triggers, so it carries the
        same rule — enforced at BOTH ends.

        At grant time a flagged agent cannot open one that points out of
        its operator. At pull time the check runs again, because a grant
        made before the operator set the flag would otherwise be a standing
        exit the flag never reached: the flag has to bind the money, not
        the paperwork.

        The two ends answer with DIFFERENT reasons, and the difference is
        normative, not cosmetic: §6.1(6) pins a closed enumeration for
        pull errors (seven reasons, `external_transfer_disabled` not among
        them) while /v3/agent/authorize_pull has no pinned enumeration at
        all. So the grant end names the flag and the pull end answers
        `authorization_revoked`, the member of the pinned set that is
        true here — the grant confers no debit right any more. Asserted
        exactly, not with assertIn: a client switch-casing §6.1(6)'s seven
        reasons must never fall through on this route.
        """
        m = self.start_mint()
        op_id, op_key = self.new_operator(m, "principal")
        g_id, g_key = self.new_agent(m, op_key, "granter")
        sib_id, sib_key = self.new_agent(m, op_key, "sibling")
        _op2_id, op2_key = self.new_operator(m, "other")
        out_id, out_key = self.new_agent(m, op2_key, "outsider")
        self.fund(m, g_key, 1000)
        far = T0 + 10 * DAY_MS

        def authorize(payee):
            return api(
                m.port, "POST", "/v3/agent/authorize_pull",
                {"payee_account": payee, "cap_mc_per_day": 500,
                 "expires_at": far},
                key=g_key,
            )

        # Grants opened BEFORE the flag, to both kinds of payee.
        status, r = authorize(out_id)
        self.assertEqual(status, 200, r)
        stale_auth = r["auth_id"]
        status, r = authorize(sib_id)
        self.assertEqual(status, 200, r)
        sibling_auth = r["auth_id"]

        status, r = api(
            m.port, "POST", "/v3/operator/flags",
            {"agent_id": g_id, "no_bearer_withdrawal": True}, key=op_key,
        )
        self.assertEqual(status, 200, r)

        # A new grant out of the operator is refused outright...
        self.assertRejected(authorize(out_id), "external_transfer_disabled")
        # ...and the one that predates the flag no longer pulls, with a
        # reason drawn from §6.1(6)'s closed list.
        self.assertRejected(
            api(m.port, "POST", "/v3/pull",
                {"auth_id": stale_auth, "amount_mc": 400}, key=out_key),
            "authorization_revoked",
        )
        self.assertEqual(self.balance(m, out_key)["balance_mc"], 0)
        self.assertEqual(self.balance(m, g_key)["balance_mc"], 1000)
        # The refusal did not actually revoke the grant: the flag is the
        # operator's, revocation is the granting agent's (§6.1(6),
        # "revocable-at-will"), so clearing the flag restores the grant
        # rather than leaving the payee to beg for a new one.
        status, r = api(
            m.port, "POST", "/v3/operator/flags",
            {"agent_id": g_id, "no_bearer_withdrawal": False}, key=op_key,
        )
        self.assertEqual(status, 200, r)
        status, r = api(
            m.port, "POST", "/v3/pull",
            {"auth_id": stale_auth, "amount_mc": 400}, key=out_key,
        )
        self.assertEqual(status, 200, r)
        self.assertEqual(self.balance(m, out_key)["balance_mc"], 400)
        # Put it back and confirm the refusal returns, so the rest of the
        # test runs against a flagged granter as before.
        status, r = api(
            m.port, "POST", "/v3/operator/flags",
            {"agent_id": g_id, "no_bearer_withdrawal": True}, key=op_key,
        )
        self.assertEqual(status, 200, r)
        self.assertRejected(
            api(m.port, "POST", "/v3/pull",
                {"auth_id": stale_auth, "amount_mc": 400}, key=out_key),
            "authorization_revoked",
        )
        self.assertEqual(self.balance(m, out_key)["balance_mc"], 400)
        self.assertEqual(self.balance(m, g_key)["balance_mc"], 600)

        # Inside the operator, pulls keep working, granted either side of
        # the flag.
        status, r = api(
            m.port, "POST", "/v3/pull",
            {"auth_id": sibling_auth, "amount_mc": 400}, key=sib_key,
        )
        self.assertEqual(status, 200, r)
        status, r = authorize(sib_id)
        self.assertEqual(status, 200, r)
        self.assertEqual(self.balance(m, g_key)["balance_mc"], 200)

    # ------------------------------------------------------------------ #
    # F3 — /v3/operator/register is credential-gated, and says so         #
    # ------------------------------------------------------------------ #

    def test_operator_register_requires_the_mint_credential(self):
        """Registering an operator creates a whole supervision perimeter —
        a fleet that no existing operator's caps, freezes or flags reach —
        so it takes the mint operator's credential, the same X-Admin-Token
        that gates /admin/issue. A supervision bearer key is not that
        credential, in either role.
        """
        m = self.start_mint()
        op_id, op_key = self.new_operator(m, "incumbent")
        a_id, a_key = self.new_agent(m, op_key, "agent")
        body = {"operator_name": "intruder"}

        cases = [
            ("no credential", None, False),
            ("wrong credential", None, "not-" + ADMIN_TOKEN),
            ("empty credential", None, ""),
            ("operator bearer key", op_key, False),
            ("agent bearer key", a_key, False),
            # A supervision key in the admin header is still not the
            # mint's credential.
            ("operator key as admin token", None, op_key),
        ]
        for label, key, admin in cases:
            with self.subTest(case=label):
                status, resp = api(
                    m.port, "POST", "/v3/operator/register", body,
                    key=key, admin=admin,
                )
                self.assertEqual(status, 401, resp)
                self.assertEqual(resp, {"status": "unauthorized"})

        # Only the incumbent exists: no refusal registered anything.
        self.assertEqual(
            self.sup_rows(m, "SELECT COUNT(*) FROM sup_operators")[0][0], 1
        )
        status, resp = api(
            m.port, "POST", "/v3/operator/register", body, admin=ADMIN_TOKEN
        )
        self.assertEqual(status, 200, resp)
        self.assertEqual(
            self.sup_rows(m, "SELECT COUNT(*) FROM sup_operators")[0][0], 2
        )

    def test_register_gate_is_announced_at_mount(self):
        """The gate is discoverable, not silent.

        A route that used to answer everyone now answers 401, and the
        operator whose bootstrap script breaks should be able to learn why
        from the mint itself. Each of the three admin_token states says
        which one it is, once, at mount — the alarming one loudly, in the
        same shape C06 announces unauthenticated issuance — and none of
        them prints the credential.
        """
        cases = [
            (ADMIN_TOKEN, logging.INFO, b"X-Admin-Token"),
            (ADMIN_ISSUANCE_DISABLED, logging.INFO, b"DISABLED"),
            # Not a shortcut past a credential: this asserts that the mint
            # SHOUTS when operator registration is unauthenticated. Nothing
            # in this case is made to pass by the open mode.
            (ADMIN_ISSUANCE_OPEN, logging.WARNING, b"UNAUTHENTICATED"),
        ]
        for token, level, needle in cases:
            with self.subTest(admin_token=repr(token)):
                records = []

                class Capture(logging.Handler):
                    def emit(self, record):
                        records.append(record)

                log = logging.getLogger("aicash.supervision")
                handler = Capture()
                log.addHandler(handler)
                old_level = log.level
                log.setLevel(logging.DEBUG)
                try:
                    self.start_mint(admin_token=token)
                finally:
                    log.removeHandler(handler)
                    log.setLevel(old_level)

                said = [
                    r for r in records
                    if "/v3/operator/register" in r.getMessage()
                ]
                self.assertEqual(len(said), 1, [r.getMessage() for r in records])
                self.assertEqual(said[0].levelno, level)
                message = said[0].getMessage()
                self.assertIn(needle.decode("ascii"), message)
                self.assertIn(MINT_ID, message)
                self.assertNotIn(ADMIN_TOKEN, message)

    # ------------------------------------------------------------------ #
    # API keys are stored hashed (lookup by digest, no raw keys at rest) #
    # ------------------------------------------------------------------ #

    def test_api_keys_stored_hashed(self):
        """Raw operator/agent bearer keys never appear in the mint
        database — only sha256 digests are stored and looked up — while
        both keys keep authenticating normally."""
        m = self.start_mint()
        op_id, op_key = self.new_operator(m)
        a_id, a_key = self.new_agent(m, op_key)
        with open(m.db_path, "rb") as fh:
            db_bytes = fh.read()
        self.assertNotIn(op_key.encode("ascii"), db_bytes)
        self.assertNotIn(a_key.encode("ascii"), db_bytes)
        # Digest lookup still authenticates both roles...
        self.assertEqual(self.balance(m, a_key)["balance_mc"], 0)
        self.assertEqual(self.balance(m, op_key, agent_id=a_id)["balance_mc"], 0)
        # ...and a garbage key is still just 401.
        status, _ = api(m.port, "GET", "/v3/agent/balance", key="nope")
        self.assertEqual(status, 401)

    # ------------------------------------------------------------------ #
    # §5.1/§5.3 persist-before-send on the custodial/ledger bridge       #
    # ------------------------------------------------------------------ #

    def spy_exchange(self, m):
        """Wrap ledger.exchange to snapshot the durable supervision state
        the moment the exchange is entered (i.e. what a crash during the
        exchange would leave on disk)."""
        real = m.ledger.exchange
        seen = {}

        def spy(idem, digest, inputs, input_amount_hint=None, outputs=None):
            seen["custody"] = self.sup_rows(
                m, "SELECT hash, secret_b64u, amount_mc, state"
                " FROM sup_custody ORDER BY hash"
            )
            seen["ops"] = self.sup_rows(
                m, "SELECT kind FROM sup_pending_ops"
            )
            seen["outputs"] = outputs
            return real(idem, digest, inputs, outputs=outputs)

        m.ledger.exchange = spy
        return seen

    def test_deposit_persists_custody_secret_before_exchange(self):
        """§5.1 mandatory ordering: the mint-custody secret is durable in
        sup_custody (state 'pending', with a staged op) BEFORE the C04
        exchange runs, and is activated afterwards."""
        m = self.start_mint(burn_policy=BURN)
        op_id, op_key = self.new_operator(m)
        a_id, a_key = self.new_agent(m, op_key)
        token = self.issue_token(m, 1000)
        seen = self.spy_exchange(m)
        status, r = api(
            m.port, "POST", "/v3/agent/deposit", {"tokens": [token]}, key=a_key
        )
        self.assertEqual(status, 200, r)
        # At exchange time: exactly one custody row, pending, whose stored
        # secret hashes to the exchange's output hash.
        ((h, secret_b64u, amount, state),) = seen["custody"]
        self.assertEqual(state, "pending")
        self.assertEqual(amount, 990)
        self.assertEqual(
            ledger_key(b64u_decode(secret_b64u, expect_len=32)), h
        )
        self.assertEqual([o.secret_hash for o in seen["outputs"]], [h])
        self.assertEqual(seen["ops"], [("deposit",)])
        # Afterwards: activated, staged op cleared.
        self.assertEqual(
            self.sup_rows(m, "SELECT state FROM sup_custody"), [("unspent",)]
        )
        self.assertEqual(self.sup_rows(m, "SELECT 1 FROM sup_pending_ops"), [])

    def test_withdraw_persists_change_secret_before_exchange(self):
        """§5.3 'no exceptions': the withdrawal's change secret is durable
        (pending) and the selected custody inputs reserved BEFORE the
        exchange runs."""
        m = self.start_mint(burn_policy=BURN)
        op_id, op_key = self.new_operator(m)
        a_id, a_key = self.new_agent(m, op_key)
        self.fund(m, a_key, 1000)  # custody: one 990 entry
        seen = self.spy_exchange(m)
        w_hash = ledger_key(new_secret())
        status, r = api(
            m.port,
            "POST",
            "/v3/agent/withdraw",
            {"outputs": [{"amount_mc": 100, "secret_hash": w_hash}]},
            key=a_key,
        )
        self.assertEqual(status, 200, r)
        self.assertEqual(r["burn_mc"], 1)  # burn(100) on the REQUESTED amount
        # At exchange time: the 990 input reserved, the 881 change pending
        # (990 - 100 - the ledger's L12 burn(990) = 9) with its secret
        # already durable, staged op present.
        by_state = {state: (h, s, a) for (h, s, a, state) in seen["custody"]}
        self.assertEqual(set(by_state), {"reserved", "pending"})
        self.assertEqual(by_state["reserved"][2], 990)
        ch, cs, ca = by_state["pending"]
        self.assertEqual(ca, 881)  # 990 - 100 - 9
        self.assertEqual(ledger_key(b64u_decode(cs, expect_len=32)), ch)
        self.assertEqual(
            sorted(o.secret_hash for o in seen["outputs"]),
            sorted([w_hash, ch]),
        )
        self.assertEqual(seen["ops"], [("withdraw",)])
        # Afterwards: input spent, change active, staged op cleared.
        self.assertEqual(
            self.sup_rows(
                m, "SELECT state FROM sup_custody ORDER BY state"
            ),
            [("spent",), ("unspent",)],
        )
        self.assertEqual(self.sup_rows(m, "SELECT 1 FROM sup_pending_ops"), [])

    def test_deposit_exchange_rejection_discards_staged_secret(self):
        """An ExchangeRejected deposit (already-spent token) cleans up its
        staged custody row and op in-process; nothing was credited."""
        m = self.start_mint(burn_policy=BURN)
        op_id, op_key = self.new_operator(m)
        a_id, a_key = self.new_agent(m, op_key)
        token = self.issue_token(m, 1000)
        self.assertEqual(
            api(m.port, "POST", "/v3/agent/deposit", {"tokens": [token]},
                key=a_key)[0],
            200,
        )
        status, body = api(
            m.port, "POST", "/v3/agent/deposit", {"tokens": [token]}, key=a_key
        )
        self.assertEqual(status, 400)
        self.assertEqual(body["status"], "rejected")
        self.assertEqual(self.balance(m, a_key)["balance_mc"], 990)
        self.assertEqual(self.sup_rows(m, "SELECT 1 FROM sup_pending_ops"), [])
        self.assertEqual(
            self.sup_rows(m, "SELECT state FROM sup_custody"), [("unspent",)]
        )

    def test_deposit_crash_before_exchange_commit_rolls_back(self):
        """Crash while the deposit exchange is in flight and NOT committed:
        the staged secret is discarded at restart, the depositor's tokens
        were never spent, and the same deposit succeeds afterwards."""
        m = self.start_mint(burn_policy=BURN)
        op_id, op_key = self.new_operator(m)
        a_id, a_key = self.new_agent(m, op_key)
        secret = new_secret()
        status, _ = api(
            m.port,
            "POST",
            "/admin/issue",
            {"outputs": [{"amount_mc": 1000, "secret_hash": ledger_key(secret)}]},
        )
        self.assertEqual(status, 200)
        token = format_token(MINT_ID, 1000, secret)

        def crash(*args, **kwargs):
            raise RuntimeError("simulated crash before exchange commit")

        m.ledger.exchange = crash
        status, body = api(
            m.port, "POST", "/v3/agent/deposit", {"tokens": [token]}, key=a_key
        )
        self.assertEqual(status, 500)
        # Durable crash state: staged secret + op, no credit.
        self.assertEqual(
            self.sup_rows(m, "SELECT state FROM sup_custody"), [("pending",)]
        )
        self.assertEqual(
            self.sup_rows(m, "SELECT kind FROM sup_pending_ops"),
            [("deposit",)],
        )
        self.assertEqual(self.balance(m, a_key)["balance_mc"], 0)

        m2 = self.restart_mint(m)
        # Reconciliation rolled the op back; the token is still unspent.
        self.assertEqual(self.sup_rows(m2, "SELECT 1 FROM sup_custody"), [])
        self.assertEqual(self.sup_rows(m2, "SELECT 1 FROM sup_pending_ops"), [])
        self.assertEqual(self.balance(m2, a_key)["balance_mc"], 0)
        _, entry = api(m2.port, "GET", "/v3/status/" + ledger_key(secret))
        self.assertEqual(entry["result"]["state"], "unspent")
        # Nothing was lost: the deposit simply retries.
        status, r = api(
            m2.port, "POST", "/v3/agent/deposit", {"tokens": [token]}, key=a_key
        )
        self.assertEqual(status, 200, r)
        self.assertEqual(r["balance_mc"], 990)

    def test_deposit_crash_after_exchange_commit_rolls_forward(self):
        """Crash AFTER the deposit exchange committed but before the
        supervision follow-up: the depositor's tokens are spent into a
        custody entry whose secret was already durable, so restart
        reconciliation credits the balance — no money is stranded."""
        m = self.start_mint(burn_policy=BURN)
        op_id, op_key = self.new_operator(m)
        a_id, a_key = self.new_agent(m, op_key)
        token = self.issue_token(m, 1000)

        def crash(*args, **kwargs):
            raise RuntimeError("simulated crash before finalize")

        m.server.sup._finalize_deposit = crash
        status, _ = api(
            m.port, "POST", "/v3/agent/deposit", {"tokens": [token]}, key=a_key
        )
        self.assertEqual(status, 500)
        # The exchange DID commit: custody entry exists on the ledger...
        ((custody_hash,),) = self.sup_rows(
            m, "SELECT hash FROM sup_custody WHERE state = 'pending'"
        )
        _, entry = api(m.port, "GET", "/v3/status/" + custody_hash)
        self.assertEqual(entry["result"]["state"], "unspent")
        # ...but the balance was not yet credited.
        self.assertEqual(self.balance(m, a_key)["balance_mc"], 0)

        m2 = self.restart_mint(m)
        # Rolled forward: credited, journaled, activated, staging cleared.
        self.assertEqual(self.balance(m2, a_key)["balance_mc"], 990)
        self.assertEqual(
            self.sup_rows(m2, "SELECT state FROM sup_custody"), [("unspent",)]
        )
        self.assertEqual(self.sup_rows(m2, "SELECT 1 FROM sup_pending_ops"), [])
        status, r = api(
            m2.port,
            "POST",
            "/v3/agent/withdraw",
            {"outputs": [{"amount_mc": 100, "secret_hash": ledger_key(new_secret())}]},
            key=a_key,
        )
        self.assertEqual(status, 200, r)
        self.assertEqual(r["balance_mc"], 889)  # 990 - (100 + burn(100))

    def test_withdraw_crash_after_exchange_commit_rolls_forward(self):
        """Crash AFTER the withdrawal exchange committed but before the
        supervision follow-up: the caller already holds real bearer value;
        the reserved inputs are never re-selected (no retry wedge); restart
        reconciliation debits the gross and restores the invariant."""
        m = self.start_mint(burn_policy=BURN)
        op_id, op_key = self.new_operator(m)
        a_id, a_key = self.new_agent(m, op_key)
        self.fund(m, a_key, 1000)  # balance 990, custody 990

        def crash(*args, **kwargs):
            raise RuntimeError("simulated crash before finalize")

        m.server.sup._finalize_withdraw = crash
        w_secret = new_secret()
        status, _ = api(
            m.port,
            "POST",
            "/v3/agent/withdraw",
            {"outputs": [{"amount_mc": 100, "secret_hash": ledger_key(w_secret)}]},
            key=a_key,
        )
        self.assertEqual(status, 500)
        # Persist-before-send held: the caller's bearer output EXISTS.
        _, entry = api(m.port, "GET", "/v3/status/" + ledger_key(w_secret))
        self.assertEqual(entry["result"]["state"], "unspent")
        self.assertEqual(entry["result"]["amount_mc"], 100)
        # The consumed input stays reserved — a retry does NOT re-select
        # the ledger-spent rows and 400 on ExchangeRejected forever; it
        # sees no available custody instead.
        self.assertRejected(
            api(
                m.port,
                "POST",
                "/v3/agent/withdraw",
                {"outputs": [{"amount_mc": 50, "secret_hash": ledger_key(new_secret())}]},
                key=a_key,
            ),
            "insufficient_balance",
        )

        m2 = self.restart_mint(m)
        # Rolled forward: gross debited (100 + burn(100) = 101 — §7.3/R17),
        # change activated (881 = 990 - 100 - ledger burn 9).
        r = self.balance(m2, a_key)
        self.assertEqual(r["balance_mc"], 889)
        self.assertEqual(r["spend_rate"]["lifetime_mc"], 101)
        self.assertEqual(
            self.sup_rows(
                m2,
                "SELECT amount_mc FROM sup_custody WHERE state = 'unspent'",
            ),
            [(881,)],
        )
        self.assertEqual(self.sup_rows(m2, "SELECT 1 FROM sup_pending_ops"), [])
        # Custody again equals balance minus the mint-absorbed burn (8);
        # further withdrawals work.
        self.assertEqual(
            self.sup_rows(m2, "SELECT absorbed_mc FROM sup_mint"), [(8,)]
        )
        status, r = api(
            m2.port,
            "POST",
            "/v3/agent/withdraw",
            {"outputs": [{"amount_mc": 50, "secret_hash": ledger_key(new_secret())}]},
            key=a_key,
        )
        self.assertEqual(status, 200, r)
        self.assertEqual(r["burn_mc"], 0)  # burn(50), not burn(881)
        self.assertEqual(r["balance_mc"], 839)

    def test_withdraw_crash_before_exchange_commit_rolls_back(self):
        """Crash while the withdrawal exchange is in flight and NOT
        committed: restart releases the reserved inputs, discards the
        staged change secret, and the withdrawal simply retries."""
        m = self.start_mint(burn_policy=BURN)
        op_id, op_key = self.new_operator(m)
        a_id, a_key = self.new_agent(m, op_key)
        self.fund(m, a_key, 1000)

        def crash(*args, **kwargs):
            raise RuntimeError("simulated crash before exchange commit")

        m.ledger.exchange = crash
        status, _ = api(
            m.port,
            "POST",
            "/v3/agent/withdraw",
            {"outputs": [{"amount_mc": 100, "secret_hash": ledger_key(new_secret())}]},
            key=a_key,
        )
        self.assertEqual(status, 500)
        self.assertEqual(
            self.sup_rows(
                m, "SELECT state FROM sup_custody ORDER BY state"
            ),
            [("pending",), ("reserved",)],
        )

        m2 = self.restart_mint(m)
        self.assertEqual(
            self.sup_rows(m2, "SELECT amount_mc, state FROM sup_custody"),
            [(990, "unspent")],
        )
        self.assertEqual(self.sup_rows(m2, "SELECT 1 FROM sup_pending_ops"), [])
        self.assertEqual(self.balance(m2, a_key)["balance_mc"], 990)
        status, r = api(
            m2.port,
            "POST",
            "/v3/agent/withdraw",
            {"outputs": [{"amount_mc": 100, "secret_hash": ledger_key(new_secret())}]},
            key=a_key,
        )
        self.assertEqual(status, 200, r)
        self.assertEqual(r["balance_mc"], 889)  # 990 - (100 + burn(100))

    # ------------------------------------------------------------------ #
    # Freeze response field name (pre-1.0 wire fix)                      #
    # ------------------------------------------------------------------ #

    def test_freeze_response_field_named_frozen(self):
        """The freeze/unfreeze responses list affected agents under
        'frozen'/'unfrozen' (pre-1.0 wire fix: the field was originally
        misspelled 'freezed'/'unfreezed'). Exact body shape pinned; the
        §6.1(7) journal *kinds* stay 'freeze'/'unfreeze'."""
        m = self.start_mint()
        _op_id, op_key = self.new_operator(m)
        a_id, _a_key = self.new_agent(m, op_key, "a")

        status, r = api(
            m.port, "POST", "/v3/operator/freeze", {"agent_id": a_id},
            key=op_key,
        )
        self.assertEqual(status, 200)
        self.assertEqual(r, {"status": "ok", "frozen": [a_id]})
        self.assertNotIn("freezed", r)

        # Idempotent re-freeze: still 'frozen', now empty (no change).
        status, r = api(
            m.port, "POST", "/v3/operator/freeze", {"agent_id": a_id},
            key=op_key,
        )
        self.assertEqual(status, 200)
        self.assertEqual(r, {"status": "ok", "frozen": []})

        status, r = api(
            m.port, "POST", "/v3/operator/unfreeze", {"agent_id": a_id},
            key=op_key,
        )
        self.assertEqual(status, 200)
        self.assertEqual(r, {"status": "ok", "unfrozen": [a_id]})
        self.assertNotIn("unfreezed", r)

        # Journal kinds are unchanged by the wire rename.
        kinds = [
            row[0]
            for row in self.sup_rows(
                m,
                "SELECT kind FROM sup_lines WHERE agent_id = ? ORDER BY seq",
                (a_id,),
            )
        ]
        self.assertEqual(kinds, ["freeze", "unfreeze"])

    # ------------------------------------------------------------------ #
    # hardening: request-body cap, connection timeout, credential logging #
    # ------------------------------------------------------------------ #
    #
    # Every test below that claims C10 hardened something first NEUTRALIZES
    # the equivalent guard C06's handler carries. _SupHandler subclasses
    # _Handler, so without that step an assertion like "an over-size body is
    # refused" passes by inheritance and proves nothing about supervision.py
    # — it would keep passing with this whole change reverted. Relaxing C06's
    # cap / removing C06's timeout for the duration of one test leaves only
    # supervision.py's own bound standing, which is the thing under test.

    def relax_inherited_body_cap(self):
        """Raise C06's body cap out of reach for this test.

        MAX_BODY_BYTES is read per request, so this disarms the inherited
        guard without touching C06's code. Only a cap C10 enforces itself
        can refuse an over-size body while this is in force.
        """
        original = mintapi.MAX_BODY_BYTES
        mintapi.MAX_BODY_BYTES = 1 << 40
        self.addCleanup(setattr, mintapi, "MAX_BODY_BYTES", original)

    def drop_inherited_socket_timeout(self):
        """Remove C06's handler timeout for this test.

        socketserver reads ``timeout`` off the handler CLASS, so an
        inherited value would bound the connection even if _SupHandler
        declared none. With it gone, a connection survives only if C10
        bounds it.
        """
        parent = mintapi._Handler
        original = parent.__dict__.get("timeout", _MISSING)
        parent.timeout = None

        def restore():
            if original is _MISSING:  # pragma: no cover - C06 declares one
                del parent.timeout
            else:
                parent.timeout = original

        self.addCleanup(restore)

    def shrink_c10_socket_timeout(self, seconds=0.3):
        """Exercise the real stalled-client mechanism at a test-sized
        timeout — but only if _SupHandler declares a timeout of its own.

        Setting one unconditionally would CREATE the very attribute under
        test, so a handler with no bound of its own is left exactly as it
        is: the behavioural assertions then fail on a connection that is
        never released, which is the failure this guards against.
        """
        own = supervision._SupHandler.__dict__.get("timeout", _MISSING)
        if own is _MISSING:  # pragma: no cover - fix present
            return
        self.assertIsNotNone(own)
        self.assertLessEqual(own, 300.0)
        supervision._SupHandler.timeout = seconds
        self.addCleanup(setattr, supervision._SupHandler, "timeout", own)

    def start_plain_mint(self):
        """A plain C06 mint with no Supervision Profile, for the L13/B9
        identity comparison: same config, same ledger shape, different
        server class."""
        clock = FakeClock(T0)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db_path = os.path.join(tmp.name, "plain.sqlite3")
        priv, pub = generate_keypair()
        ledger = Ledger(
            db_path,
            clock,
            NO_BURN,
            recovery_window_ms=90 * DAY_MS,
            max_lock_expiry_ms=30 * DAY_MS,
        )
        config = MintConfig(
            mint_id=MINT_ID,
            baseline_model_class="frontier-2026",
            burn_policy=NO_BURN,
            signing_private=priv,
            signing_public=pub,
            profiles=(),
            # The SAME credential the supervision mint gets, deliberately:
            # test_layer0_body_refusals_match_a_plain_c06_mint compares the
            # two servers on identical wire bytes, so any config difference
            # between them would be a difference this comparison is not about.
            admin_token=ADMIN_TOKEN,
        )
        server = MintServer(config, ledger)
        port = server.start()
        self.addCleanup(server.stop)
        return port

    # -- L13/B9: Layer 0 is untouched by the supervision hardening ------

    def test_layer0_body_refusals_match_a_plain_c06_mint(self):
        """L13/B9: a supervision mint must answer Layer 0 exactly as a
        plain C06 mint does, refusals included.

        C06 chooses the §3.8 reason for a body it will not read, and the
        choice is normative: `over_batch_limit` is retryable with backoff
        and tells the caller to split the call, `bad_format` says the
        envelope must not be resent as-is (spec §3.8 and the retry rules
        under "Error semantics on invalid payment"). A C10 handler that
        re-answered the INHERITED routes with its own reason would hand a
        Layer 0 client the wrong recovery signal for the same bytes. So
        this compares the two servers on identical wire bytes rather than
        asserting any particular reason string.
        """
        plain = self.start_plain_mint()
        sup = self.start_mint().port

        def head(path, length):
            return (
                "POST " + path + " HTTP/1.1\r\n"
                "Host: 127.0.0.1\r\n"
                "Content-Type: application/json\r\n"
                "Content-Length: " + str(length) + "\r\n\r\n"
            ).encode("ascii")

        cases = [
            # over C06's published cap: the reason that diverged.
            (head("/v3/exchange", mintapi.MAX_BODY_BYTES + 1), b"", False),
            (head("/v3/status", mintapi.MAX_BODY_BYTES + 1), b"", False),
            (head("/admin/issue", mintapi.MAX_BODY_BYTES + 1), b"", False),
            # unparseable declared length.
            (head("/v3/exchange", "not-a-number"), b"{}", True),
            # declared longer than sent: EOF mid-body.
            (head("/v3/exchange", 4096), b'{"inputs":[]}', True),
            # well-framed but not JSON.
            (head("/v3/exchange", 7), b"nonJSON", False),
        ]
        for request_head, body, half_close in cases:
            with self.subTest(request=request_head.split(b"\r\n")[0]):
                want = raw_probe(
                    plain, request_head + body, half_close=half_close
                )
                got = raw_probe(
                    sup, request_head + body, half_close=half_close
                )
                self.assertIsNotNone(want[0], "plain C06 mint gave no answer")
                self.assertEqual(got, want)

    def test_malformed_content_length_closes_the_connection(self):
        """An unparseable Content-Length on a SUPERVISION route leaves the
        declared body unread, so the connection can no longer be framed:
        it must be closed, not returned to the keep-alive pool.

        Left open, the unconsumed octets are parsed as the next request
        line — a pipelining client or a connection-reusing proxy turns
        request N's body into request N+1, and the stdlib's 501 page
        echoes the attacker's bytes back to the peer. On the server that
        holds operator credentials, caps, freezes and pulls, that is the
        shape of request smuggling.
        """
        m = self.start_mint()
        smuggled = b'{"operator_name":"smuggled"}'
        request = (
            b"POST /v3/operator/register HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            # The route is credential-gated (see
            # test_operator_register_requires_the_mint_credential). The
            # credential is PRESENT so the answer under test is the body
            # refusal, not the 401 that auth-before-body would give first.
            b"X-Admin-Token: " + ADMIN_TOKEN.encode("ascii") + b"\r\n"
            b"Content-Type: application/json\r\n"
            # int() would accept "1_0" or " 10 "; an RFC-conformant proxy
            # would not. The disagreement is exactly what desyncs framing.
            b"Content-Length: 0x10\r\n\r\n"
        ) + smuggled + b"GET /v3/mints HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        raw, closed = raw_to_eof(m.port, request)
        self.assertTrue(closed, "connection held open after a refused body")
        self.assertEqual(status_lines(raw), 1, raw[:400])
        self.assertIn(b"400", raw.split(b"\r\n")[0])
        self.assertIn(b"\r\nConnection: close\r\n", raw)
        self.assertNotIn(b"smuggled", raw)
        # Nothing was registered by either the refused or the smuggled half.
        self.assertEqual(
            self.sup_rows(m, "SELECT COUNT(*) FROM sup_operators")[0][0], 0
        )

    def test_supervision_get_with_a_declared_body_cannot_frame_a_request(self):
        """A GET on a SUPERVISION route that declares a body must close.

        C06's do_GET gained this guard, but ``_SupHandler.do_GET`` returns
        before ever reaching it for a route in ``_ROUTES`` — so the two
        GET routes this profile adds (/v3/operator/statement and
        /v3/agent/balance) kept answering on a connection whose framing
        was already gone. Nothing reads a GET body, so the declared octets
        stay on the wire and the stdlib parses them as the NEXT request
        line: the pipelined GET below got its own 200 on the same socket.
        Behind the connection-reusing reverse proxy DEPLOYMENT.md tells
        the operator to run, that extra response is delivered to whoever
        holds the pooled connection next.

        Asserted on the supervision route specifically: the equivalent
        Layer 0 test lives in test_c06_mintapi and passes either way, so
        only this one fails if the guard is dropped from _SupHandler.
        """
        m = self.start_mint()
        smuggled = b"GET /v3/mints HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        request = (
            b"GET /v3/agent/balance HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Length: %d\r\n\r\n" % len(smuggled)
        ) + smuggled
        raw, closed = raw_to_eof(m.port, request)
        self.assertTrue(closed, "connection held open after an unread body")
        self.assertEqual(
            status_lines(raw),
            1,
            "the smuggled request line was answered as a second response: "
            + repr(raw[:400]),
        )
        self.assertIn(b"\r\nConnection: close\r\n", raw)

    def test_supervision_get_without_a_body_still_keeps_the_connection(self):
        """The framing guard must not hang up on an ordinary GET.

        Closing every supervision GET would be a correct-but-useless fix:
        HTTP/1.1 keep-alive is what makes a statement poller cheap. Only a
        DECLARED-but-unread body may cost the connection.
        """
        m = self.start_mint()
        request = (
            b"GET /v3/agent/balance HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n\r\n"
            b"GET /v3/agent/balance HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Connection: close\r\n\r\n"
        )
        raw, _closed = raw_to_eof(m.port, request)
        self.assertEqual(
            status_lines(raw),
            2,
            "keep-alive was dropped on a bodiless GET: " + repr(raw[:400]),
        )

    def test_chunked_body_on_a_supervision_route_cannot_frame_a_request(self):
        """A transfer-coded POST body must be refused and the connection
        dropped: nothing in this stack dechunks it.

        This reader looked at Content-Length and nothing else, so a
        `Transfer-Encoding: chunked` POST — which carries no
        Content-Length — read as a zero-length body, was answered
        `bad_format`, and KEPT the connection with every octet of the
        declared body still on the wire. The stdlib then parsed those
        octets as the next request line. Both halves below show it: a
        raw pipelined request as the "chunked body" got its own 200 on the
        same socket, and a properly chunked body got the stdlib's error
        page echoing the attacker's chunk-size line back to whoever holds
        that pooled connection next. Same desync as the malformed
        Content-Length above, through the other door in the same reader.
        """
        m = self.start_mint()
        head = (
            b"POST /v3/operator/register HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            # Credentialed, so the answer under test is the body refusal
            # rather than the route's 401.
            b"X-Admin-Token: " + ADMIN_TOKEN.encode("ascii") + b"\r\n"
            b"Content-Type: application/json\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
        )
        payload = b'{"operator_name":"smuggled"}'
        bodies = {
            # The whole "body" is a second request.
            "pipelined": b"GET /v3/mints HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            # A well-formed chunked body, as a proxy would forward it.
            "chunked": (b"%x\r\n" % len(payload)) + payload + b"\r\n0\r\n\r\n",
        }
        for name, body in bodies.items():
            with self.subTest(body=name):
                raw, closed = raw_to_eof(m.port, head + body)
                self.assertTrue(
                    closed, "connection held open after an unread body"
                )
                self.assertEqual(
                    status_lines(raw),
                    1,
                    "the unread body was framed as a second request: "
                    + repr(raw[:400]),
                )
                self.assertIn(b"400", raw.split(b"\r\n")[0])
                self.assertIn(b'"reason":"bad_format"', raw)
                self.assertIn(b"\r\nConnection: close\r\n", raw)
                # Neither the body nor anything derived from it was ever
                # parsed, let alone echoed back to the peer.
                self.assertNotIn(b"smuggled", raw)
                self.assertNotIn(b"Bad request syntax", raw)
        self.assertEqual(
            self.sup_rows(m, "SELECT COUNT(*) FROM sup_operators")[0][0], 0
        )

    def test_duplicate_content_length_cannot_frame_a_request(self):
        """Two Content-Length headers on one request must be refused and
        the connection dropped.

        ``self.headers.get("Content-Length")`` silently returns the FIRST
        of a conflicting pair, so `Content-Length: 2` followed by
        `Content-Length: 46` read two octets and left the other
        forty-four on the wire for the stdlib to parse as the next
        request line: ONE request in, TWO responses out, connection still
        pooled. Reproduced against this server before the fix — a 401 for
        the refused register followed by a full 200 descriptor for the
        smuggled `GET /v3/mints` — which is the same desync the
        Transfer-Encoding guard closes, through the other door in the
        same reader.

        The pair is the classic CL.CL smuggling shape, and the danger is
        exactly that the intermediary in front of us may honour the OTHER
        value; RFC 7230 §3.3.3 requires rejecting the message rather than
        picking one. A body whose length two parties compute differently
        is as unframable to us as a transfer-coded one, so it gets the
        same answer.

        Credentialed, so the answer under test is the body refusal rather
        than the route's 401 (dispatch decides auth before body validity).
        The authless shape the reviewer probed with is covered too: the
        framing is the reader's job either way, and a 401 delivered on a
        connection that still holds a smuggled request is the same bug.
        """
        m = self.start_mint()
        smuggled = b"GET /v3/mints HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        body = b"{}" + smuggled
        credential = b"X-Admin-Token: " + ADMIN_TOKEN.encode("ascii") + b"\r\n"
        for name, headers in {
            # Two separate header lines: get() takes the first (2), the
            # rest of the body becomes a request.
            "two_headers": (
                b"Content-Length: 2\r\n"
                b"Content-Length: %d\r\n" % len(body)
            ),
            # ...and the same conflict in the reverse order, so a fix
            # that just took the LAST value would not pass either.
            "two_headers_reversed": (
                b"Content-Length: %d\r\n" % len(body)
                + b"Content-Length: 2\r\n"
            ),
            # The single-header spelling of the same pair.
            "one_header_two_values": (
                b"Content-Length: 2, %d\r\n" % len(body)
            ),
        }.items():
            for authed in (True, False):
                with self.subTest(shape=name, credentialed=authed):
                    request = (
                        b"POST /v3/operator/register HTTP/1.1\r\n"
                        b"Host: 127.0.0.1\r\n"
                        b"Content-Type: application/json\r\n"
                        + (credential if authed else b"")
                        + headers
                        + b"\r\n"
                    ) + body
                    raw, closed = raw_to_eof(m.port, request)
                    self.assertTrue(
                        closed, "connection held open after a refused body"
                    )
                    self.assertEqual(
                        status_lines(raw),
                        1,
                        "the unread body was framed as a second request: "
                        + repr(raw[:400]),
                    )
                    self.assertIn(b"\r\nConnection: close\r\n", raw)
                    if authed:
                        self.assertIn(b"400", raw.split(b"\r\n")[0])
                        self.assertIn(b'"reason":"bad_format"', raw)
                    else:
                        self.assertIn(b"401", raw.split(b"\r\n")[0])
                    # No trace of the smuggled request having been answered.
                    self.assertNotIn(b"activity", raw)
        self.assertEqual(
            self.sup_rows(m, "SELECT COUNT(*) FROM sup_operators")[0][0], 0
        )

    def test_a_single_content_length_still_frames_a_keep_alive_request(self):
        """The duplicate-header guard must not cost ordinary keep-alive.

        Refusing every POST would be a correct-but-useless fix, and a
        guard that mis-read one header as two would do exactly that. One
        Content-Length, two pipelined POSTs, two answers on one socket.
        """
        m = self.start_mint()
        body = b'{"operator_name":"real"}'
        one = (
            b"POST /v3/operator/register HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"X-Admin-Token: " + ADMIN_TOKEN.encode("ascii") + b"\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: %d\r\n" % len(body)
        )
        request = (one + b"\r\n" + body) + (
            one + b"Connection: close\r\n\r\n" + body
        )
        raw, _closed = raw_to_eof(m.port, request)
        self.assertEqual(
            status_lines(raw),
            2,
            "keep-alive was dropped on a well-framed POST: "
            + repr(raw[:400]),
        )
        self.assertEqual(raw.count(b"HTTP/1.1 200"), 2, raw[:400])
        self.assertEqual(
            self.sup_rows(m, "SELECT COUNT(*) FROM sup_operators")[0][0], 2
        )

    def test_json_bodies_that_raise_past_jsondecodeerror_are_bad_format(self):
        """A body the parser refuses is `bad_format`, however it refuses.

        This reader caught only (UnicodeDecodeError, JSONDecodeError), and
        json.loads has two other ways to say no:

        * a bare ValueError — CPython's int-string digit limit, so an
          integer of 5,000 digits is VALID JSON that raises out of int();
        * RecursionError — `[[[[...` deep enough is a small body, well
          inside the cap, that blows the C parser's stack.

        Both escaped the reader, met _dispatch_sup's blanket
        ``except Exception`` and answered a bare 500 — an unenumerated
        status to an ANONYMOUS caller, since the body is read before auth
        is decided, and a contradiction of this component's own
        "every POST route can also return bad_format" line. The
        byte-identical bodies on Layer 0's /v3/exchange answer 400
        bad_format, so the two readers were also divergent.

        Probed both ways. Anonymously, because that is how the reviewer
        reached it and the 500 was the whole finding: the route's own 401
        is the correct answer there (dispatch decides auth before body
        validity) and anything 5xx is the bug. Credentialed, because that
        is where the enumerated `bad_format` becomes visible and where a
        regression would otherwise hide behind the 401.
        """
        m = self.start_mint()
        credential = b"X-Admin-Token: " + ADMIN_TOKEN.encode("ascii") + b"\r\n"
        bodies = {
            "recursion": b"[" * 100_000 + b"]" * 100_000,
            "int_digit_limit": b'{"operator_name": ' + b"9" * 5000 + b"}",
        }
        for name, body in bodies.items():
            for authed in (True, False):
                with self.subTest(body=name, credentialed=authed):
                    request = (
                        b"POST /v3/operator/register HTTP/1.1\r\n"
                        b"Host: 127.0.0.1\r\n"
                        b"Content-Type: application/json\r\n"
                        b"Connection: close\r\n"
                        + (credential if authed else b"")
                        + b"Content-Length: %d\r\n\r\n" % len(body)
                    ) + body
                    raw, _closed = raw_to_eof(m.port, request)
                    first = raw.split(b"\r\n")[0]
                    self.assertNotIn(b"500", first, repr(raw[:400]))
                    if authed:
                        self.assertIn(b"400", first, repr(raw[:400]))
                        self.assertIn(
                            b'"reason":"bad_format"', raw, repr(raw[:400])
                        )
                    else:
                        self.assertIn(b"401", first, repr(raw[:400]))
        self.assertEqual(
            self.sup_rows(m, "SELECT COUNT(*) FROM sup_operators")[0][0], 0
        )

    # -- C10's own body cap ---------------------------------------------

    def test_oversize_body_refused_before_it_is_read(self):
        """A Content-Length above C10's cap is refused without reading (or
        allocating) a byte of the declared body, so one request cannot
        exhaust the mint's memory or park its thread waiting for a body the
        client never sends. The refusal reuses this module's existing
        'bad_format' rejection.

        C06's cap is raised and C06's handler timeout removed first, so
        the only thing that can produce an answer here is a bound
        supervision.py enforces itself: with this change reverted the
        server reads 16 GiB that never arrive and never replies.
        """
        self.relax_inherited_body_cap()
        self.drop_inherited_socket_timeout()
        m = self.start_mint()
        _op_id, op_key = self.new_operator(m)
        head = (
            "POST /v3/operator/agents HTTP/1.1\r\n"
            "Host: 127.0.0.1\r\n"
            "Authorization: Bearer " + op_key + "\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: " + str(1 << 34) + "\r\n\r\n"
        ).encode("ascii")
        # No body follows: an uncapped reader blocks here until the peer
        # sends 16 GiB, which it never will.
        started = time.monotonic()
        status, connection, body = raw_probe(m.port, head, read_timeout=5.0)
        elapsed = time.monotonic() - started
        self.assertIsNotNone(
            status, "no answer: the declared body was being read"
        )
        self.assertLess(elapsed, 2.0, "answered only after reading/waiting")
        self.assertIn(b"400", status)
        self.assertEqual(body, {"status": "rejected", "reason": "bad_format"})
        self.assertEqual(connection, b"close")  # body unread => unframable
        # ...and nothing was created by the refused request.
        self.assertEqual(
            self.sup_rows(m, "SELECT COUNT(*) FROM sup_agents")[0][0], 0
        )

    def test_body_cap_boundary_exact_size_still_accepted(self):
        """The cap is a bound, not a blanket refusal: a body of exactly
        the cap is served normally, one byte more is rejected.

        Both bodies are sent in full, so neither timeouts nor C06's
        (relaxed) cap can decide the outcome — only C10's own comparison
        can. Reverted, the over-cap body is read, parsed and registers an
        operator, and the count below is 2.
        """
        self.relax_inherited_body_cap()
        cap = _sup_body_cap()
        m = self.start_mint()

        def sized(name, total):
            obj = {"operator_name": name, "pad": ""}
            obj["pad"] = "a" * (total - len(json.dumps(obj).encode("utf-8")))
            self.assertEqual(len(json.dumps(obj).encode("utf-8")), total)
            return obj

        status, r = api(
            m.port, "POST", "/v3/operator/register", sized("exact", cap)
        )
        self.assertEqual(status, 200, r)
        self.assertIn("operator_key", r)

        status, r = api(
            m.port, "POST", "/v3/operator/register", sized("over", cap + 1)
        )
        self.assertEqual(status, 400, r)
        self.assertEqual(r, {"status": "rejected", "reason": "bad_format"})
        # Only the accepted request registered an operator.
        self.assertEqual(
            self.sup_rows(m, "SELECT COUNT(*) FROM sup_operators")[0][0], 1
        )

    # -- C10's own connection timeout -----------------------------------

    def test_handler_has_socket_timeout_and_drops_a_stalled_client(self):
        """A client that announces a body and then sends nothing has its
        connection released (rejected and closed, or just closed) instead
        of holding a ThreadingHTTPServer thread until it decides to
        finish.

        C06's inherited timeout is removed first, so the release can only
        come from a bound _SupHandler declares itself; reverted, this
        connection is held until the client gives up.
        """
        self.drop_inherited_socket_timeout()
        self.shrink_c10_socket_timeout(0.3)
        m = self.start_mint()
        head = (
            "POST /v3/operator/register HTTP/1.1\r\n"
            "Host: 127.0.0.1\r\n"
            "X-Admin-Token: " + ADMIN_TOKEN + "\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: 40\r\n\r\n"
        ).encode("ascii")
        # ...and never the 40 promised bytes.
        seen, closed = raw_to_eof(m.port, head, read_timeout=5.0)
        self.assertTrue(closed, "connection still held after C10's timeout")
        if seen:  # if it answered first, only with the module's own reason
            self.assertIn(b"400", seen.split(b"\r\n")[0])
            self.assertIn(b'"reason":"bad_format"', seen)
        # The stall cost the mint nothing: it still serves everyone else.
        self.assertTrue(self.new_operator(m, "after")[1])

    def test_idle_keep_alive_connection_is_not_held_forever(self):
        """An HTTP/1.1 keep-alive connection left idle after a completed
        request is closed by C10's timeout — otherwise every abandoned
        client permanently costs one server thread. C06's timeout is
        removed first, so only C10's own bound can close it."""
        self.drop_inherited_socket_timeout()
        self.shrink_c10_socket_timeout(0.3)
        m = self.start_mint()
        conn = http.client.HTTPConnection("127.0.0.1", m.port, timeout=10.0)
        try:
            conn.request(
                "POST",
                "/v3/operator/register",
                json.dumps({"operator_name": "idle"}).encode("utf-8"),
                {"X-Admin-Token": ADMIN_TOKEN},
            )
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            json.loads(resp.read().decode("utf-8"))
            conn.sock.settimeout(5.0)
            try:
                self.assertEqual(
                    conn.sock.recv(1), b"", "idle connection stayed open"
                )
            except ConnectionError:
                pass  # reset instead of a clean close: also released
            except TimeoutError:
                self.fail("idle keep-alive connection was never released")
        finally:
            conn.close()

    def test_internal_timeout_answers_with_a_500(self):
        """A TimeoutError raised while PRODUCING the answer is an internal
        fault and owes the caller a 500.

        The handler catches TimeoutError to cope with its own socket
        timeout firing on a stalled peer. Catching it around the whole
        dispatch would also swallow one raised inside _SupCore (a lock
        wait, a clock, anything) and answer nothing at all — a caller
        cannot tell 'the mint failed internally' from 'my connection
        died', and the mint's 'never a stack trace, always a status'
        contract silently stops holding.
        """
        m = self.start_mint()
        core = m.server.sup
        original = core.dispatch

        def boom(*args, **kwargs):
            raise TimeoutError("internal wait, not a dead peer")

        core.dispatch = boom
        self.addCleanup(setattr, core, "dispatch", original)

        body = json.dumps({"operator_name": "x"}).encode("utf-8")
        request = (
            "POST /v3/operator/register HTTP/1.1\r\n"
            "Host: 127.0.0.1\r\n"
            "X-Admin-Token: " + ADMIN_TOKEN + "\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: " + str(len(body)) + "\r\n\r\n"
        ).encode("ascii") + body
        status, _conn, parsed = raw_probe(
            m.port, request, read_timeout=5.0
        )
        self.assertIsNotNone(status, "the connection was dropped in silence")
        self.assertIn(b"500", status)
        self.assertEqual(parsed, {"status": "error"})  # never a traceback

    # -- standing guard (no fix behind it; see the docstring) ------------

    def test_no_credential_reaches_the_access_log(self):
        """STANDING GUARD on §6.1(1) bearer keys, not a regression test:
        the inherited access log records route pattern + status only, and
        supervision.py's own logger says exactly one thing — how operator
        registration is gated, once, at mount. This test exists so that
        stays true: it is meant to fail the day a body, a header, a query
        string or a key starts being logged by either module. Both loggers
        are captured, because a credential leaking into C10's own log
        would be just as public as one leaking into C06's."""
        m = self.start_mint()
        _op_id, op_key = self.new_operator(m)
        a_id, a_key = self.new_agent(m, op_key)

        records = []

        class Capture(logging.Handler):
            def emit(self, record):
                records.append(record.getMessage())

        handler = Capture()
        for name in ("aicash.mintapi", "aicash.supervision"):
            logger = logging.getLogger(name)
            logger.addHandler(handler)
            old_level, old_prop = logger.level, logger.propagate
            logger.setLevel(logging.DEBUG)
            self.addCleanup(
                lambda lg=logger, lvl=old_level, prop=old_prop: (
                    lg.removeHandler(handler),
                    lg.setLevel(lvl),
                    setattr(lg, "propagate", prop),
                )
            )
        # A mint started while the capture is live, so C10's own mount-time
        # line is in the sample the assertions below run over.
        m2 = self.start_mint()
        _op2_id, op2_key = self.new_operator(m2, "captured")

        self.balance(m, a_key)
        self.balance(m, op_key, agent_id=a_id)
        api(m.port, "GET", "/v3/agent/balance?agent_id=" + a_id, key="nope")
        api(m.port, "POST", "/v3/operator/agents", {"agent_name": "x"},
            key=op_key)

        self.assertTrue(records, "nothing logged: the guard would be vacuous")
        joined = "\n".join(records)
        self.assertNotIn(op_key, joined)
        self.assertNotIn(a_key, joined)
        self.assertNotIn(op2_key, joined)
        self.assertNotIn(ADMIN_TOKEN, joined)
        self.assertNotIn("Bearer", joined)
        self.assertNotIn("nope", joined)

    # ------------------------------------------------------------------ #
    # Framing parity: one socket, one verdict                            #
    # ------------------------------------------------------------------ #
    #
    # C06 and C10 answer a refused body with DIFFERENT envelopes on
    # purpose (L13/B9). What they must not do is disagree about WHICH
    # bodies are unframable: they are two readers on one server and one
    # socket, so a shape Layer 0 reads and the profile refuses (or the
    # reverse) is a smuggling gap in whichever half is laxer. That is what
    # happened this round -- C10 closed the duplicate-Content-Length door
    # while Layer 0 kept it open -- so the VERDICT is now a single shared
    # method and these tests pin the two servers to it behaviourally.

    #: Every wire shape whose body this stack cannot frame, built as raw
    #: bytes with a pipelined GET behind it: if the reader mis-sizes the
    #: body, the leftover octets become that GET and a second response
    #: comes back on the same socket.
    UNFRAMABLE_BODIES = {
        "chunked": (b"Transfer-Encoding: chunked\r\n",
                    b"5\r\nhello\r\n0\r\n\r\n"),
        "dup-cl-low-then-high": (b"Content-Length: 2\r\nContent-Length: 46\r\n",
                                 b"a" * 46),
        "dup-cl-high-then-low": (b"Content-Length: 46\r\nContent-Length: 2\r\n",
                                 b"a" * 46),
        "one-header-comma": (b"Content-Length: 2, 46\r\n", b"a" * 46),
    }

    def unframable_request(self, path, headers, body, admin=True):
        cred = (b"X-Admin-Token: " + ADMIN_TOKEN.encode() + b"\r\n") if admin else b""
        return (
            b"POST " + path + b" HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Type: application/json\r\n"
            + cred + headers + b"\r\n" + body +
            b"GET /v3/mints HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        )

    #: The corpus the cross-server test was missing. ``UNFRAMABLE_BODIES``
    #: above is four shapes BOTH servers already refused, and a test that
    #: only feeds inputs both sides reject cannot detect that the two sides
    #: disagree -- which is exactly what it failed to detect: 435 header
    #: names that this server refused and that a plain C06 mint (and the
    #: operator GUI, and the console, which import C06's rule) framed. Each
    #: entry below is a NAME whose confusion the two halves of the shared
    #: rule reach by different routes: the regex half covers substitution
    #: at the hyphen, the fold half covers a separator added, moved, or
    #: stuck on either end, and the token half covers a name that is not a
    #: token at all. A server missing any half fails on some row here.
    RENAMED_SPELLINGS = (
        "Transfer-Encoding", "Transfer_Encoding", "Transfer.Encoding",
        "Transfer0Encoding", "TransferEncoding", "Transfer--Encoding",
        "Transfer-Encoding.", "Transfer-Encoding;", "Transfer-Encoding_",
        "Transfer-Encoding'", "_Transfer-Encoding", ".Transfer-Encoding",
        "Trans-fer-Encoding", "Transfer-Encod-ing",
        "Content_Length", "Content.Length", "Content--Length",
        "Content0Length", "ContentLength",
        "Content-Length;", "Content-Length.", "Content-Length-",
        "Content-Length_", "-Content-Length", "_Content-Length",
        "Con-tent-Length", "ContentLength-",
    )

    def renamed_spelling_request(self, method, path, name):
        """``Content-Length: 0`` (honest, so no length clause can help)
        plus ONE renamed framing header, with a complete second request
        pipelined behind it."""
        return (
            method + b" " + path + b" HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\nContent-Type: application/json\r\n"
            b"X-Admin-Token: " + ADMIN_TOKEN.encode() + b"\r\n"
            b"Content-Length: 0\r\n"
            + name.encode("ascii") + b": chunked\r\n\r\n"
            + b"GET /v3/mints HTTP/1.1\r\nHost: smuggled\r\n\r\n"
        )

    def test_both_servers_reach_the_same_framing_verdict(self):
        """Identical wire bytes, identical framing decision, on a plain C06
        mint and on a supervision mint: one response, connection closed,
        and no descriptor smuggled out of the leftover octets.

        Driven over BOTH corpora. ``UNFRAMABLE_BODIES`` is the body-shape
        half (chunked, duplicated and comma-list lengths). ``RENAMED_
        SPELLINGS`` is the half this test did not have, and its absence is
        why the two servers could disagree on 435 names with the suite
        green: the four body shapes were refused by both sides before and
        after the divergence, so nothing here could see it. A cross-server
        test has to be fed inputs that could tell the two sides apart.
        """
        sup = self.start_mint()
        plain = self.start_plain_mint()
        for name, (headers, body) in self.UNFRAMABLE_BODIES.items():
            request = self.unframable_request(b"/v3/exchange", headers, body)
            for server, port in (("supervision", sup.port), ("plain C06", plain)):
                with self.subTest(shape=name, server=server):
                    raw, closed = raw_to_eof(port, request)
                    self.assertEqual(status_lines(raw), 1, raw[:400])
                    self.assertTrue(closed, "connection held open: %r" % raw[:200])
                    self.assertIn(b"400", raw.split(b"\r\n")[0])
                    self.assertNotIn(b"mint_id", raw)
        for method, path in ((b"POST", b"/v3/exchange"),
                             (b"POST", b"/admin/issue"),
                             (b"GET", b"/v3/status/deadbeef")):
            for name in self.RENAMED_SPELLINGS:
                request = self.renamed_spelling_request(method, path, name)
                for server, port in (("supervision", sup.port),
                                     ("plain C06", plain)):
                    with self.subTest(shape=name, server=server,
                                      route=path.decode()):
                        raw, closed = raw_to_eof(port, request)
                        self.assertEqual(
                            status_lines(raw), 1,
                            "%s answered twice on %r: %r"
                            % (server, name, raw[:400]))
                        self.assertEqual(
                            trailing_bytes(raw), b"",
                            "%s sent a second answer: %r"
                            % (server, raw[:400]))
                        self.assertTrue(
                            closed,
                            "%s held the connection on %r: %r"
                            % (server, name, raw[:200]))
                        self.assertNotIn(b"mint_id", raw)

    def test_a_supervision_route_is_framed_like_a_layer_0_one(self):
        """The profile's OWN routes get the same verdict in C10's own
        vocabulary -- the envelope differs, the framing does not."""
        m = self.start_mint()
        for name, (headers, body) in self.UNFRAMABLE_BODIES.items():
            with self.subTest(shape=name):
                raw, closed = raw_to_eof(
                    m.port,
                    self.unframable_request(
                        b"/v3/operator/register", headers, body
                    ),
                )
                self.assertEqual(status_lines(raw), 1, raw[:400])
                self.assertTrue(closed, "connection held open: %r" % raw[:200])
                self.assertIn(b"400", raw.split(b"\r\n")[0])
                parsed = json.loads(raw.partition(b"\r\n\r\n")[2])
                # C10's envelope: a flat reason, not C06's `errors` list.
                self.assertEqual(
                    parsed, {"status": "rejected", "reason": "bad_format"}
                )
                # ...and nothing was registered out of the refused body.
                self.assertEqual(
                    self.sup_rows(m, "SELECT COUNT(*) FROM sup_operators")[0][0],
                    0,
                )

    def test_the_verdict_itself_is_not_duplicated(self):
        """Source-level, and deliberately so: the two readers may differ
        everywhere EXCEPT here. A second, separately-worded copy of the
        rule is how the two halves drifted apart in the first place, and
        the behavioural tests above cannot see a copy that happens to
        agree today."""
        self.assertIn(
            "_body_framing_is_unreadable",
            inspect.getsource(supervision._SupHandler._read_sup_json),
        )
        self.assertNotIn(
            "_body_framing_is_unreadable",
            supervision._SupHandler.__dict__,
        )
        self.assertIs(
            supervision._SupHandler._body_framing_is_unreadable,
            mintapi._Handler._body_framing_is_unreadable,
        )



    # ------------------------------------------------------------------ #
    # Registration is gated on its OWN credential, not on issuance       #
    # ------------------------------------------------------------------ #
    #
    # The round that closed the two-operator bypass gated
    # /v3/operator/register on the mint's issuance check. That check is
    # unconditionally false on a mint built ADMIN_ISSUANCE_DISABLED, so on
    # such a mint registration answered 401 to no credential, an empty one,
    # a wrong one, and the literal name of the disabled mode alike. With no
    # operator there are no agents, no deposits, no pulls, no withdrawals
    # and no statements: the profile mounted, advertised itself in the
    # descriptor and could do nothing -- in exactly the configuration the
    # rest of this work pushes operators toward.
    #
    # Nothing tested it. The three tests that combined the profile with
    # disabled issuance never registered anything. These do.
    #
    # Creating an operator account and creating credits from nothing are
    # two different powers; the fix is a registration credential with its
    # own header and its own named states, defaulting to the issuance
    # secret wherever the mint has one (so a deployment still has ONE
    # answer to "who administers this mint") and GENERATING one where it
    # does not.

    def issue_direct(self, m, amount_mc):
        """A bearer token funded through the LEDGER, not /admin/issue.

        The bootstrap a mint with issuance disabled really has: §7.1
        operator funding is an in-process act (an operator holding the
        mint), which is the same distinction provision_operator draws for
        operator identities. Needed here because /admin/issue is exactly
        what these mints have turned off."""
        secret = new_secret()
        m.ledger.issue([{"amount_mc": amount_mc, "secret_hash": ledger_key(secret)}])
        return format_token(MINT_ID, amount_mc, secret)

    def test_registration_survives_a_mint_that_disabled_issuance(self):
        """THE REGRESSION. A mint built ADMIN_ISSUANCE_DISABLED gets a
        GENERATED registration credential rather than a dead route: the
        route stays gated, and it is reachable."""
        m = self.start_mint(admin_token=ADMIN_ISSUANCE_DISABLED)
        self.assertIsInstance(m.server.registration_token, str)
        self.assertEqual(m.server.registration_source, "generated")
        body = {"operator_name": "bootstrap"}

        # Every spelling the reviewer tried, still refused.
        for label, headers in [
            ("no credential", {}),
            ("empty credential", {"X-Admin-Token": ""}),
            ("empty registration header", {"X-Registration-Token": ""}),
            ("wrong credential", {"X-Admin-Token": "not-the-token"}),
            ("wrong registration header", {"X-Registration-Token": "nope"}),
            ("the literal name of the mode",
             {"X-Admin-Token": "ADMIN_ISSUANCE_DISABLED"}),
            ("the repr of the mode",
             {"X-Registration-Token": repr(ADMIN_ISSUANCE_DISABLED)}),
            ("the harness issuance credential", {"X-Admin-Token": ADMIN_TOKEN}),
        ]:
            with self.subTest(case=label):
                status, resp = raw_json(m.port, "POST", "/v3/operator/register",
                                        body, headers)
                self.assertEqual(status, 401, resp)
                self.assertEqual(resp, {"status": "unauthorized"})
        self.assertEqual(
            self.sup_rows(m, "SELECT COUNT(*) FROM sup_operators")[0][0], 0)

        # ...and the credential the mint actually generated works, in its
        # own header.
        status, resp = raw_json(
            m.port, "POST", "/v3/operator/register", body,
            {"X-Registration-Token": m.server.registration_token})
        self.assertEqual(status, 200, resp)
        self.assertEqual(
            self.sup_rows(m, "SELECT COUNT(*) FROM sup_operators")[0][0], 1)

        # Issuance is still off: the two powers really are separate, and
        # this is not "the gate got weaker".
        status, resp = api(m.port, "POST", "/admin/issue",
                           {"outputs": []}, admin=False)
        self.assertEqual(status, 401, resp)
        status, resp = api(m.port, "POST", "/admin/issue", {"outputs": []},
                           admin=m.server.registration_token)
        self.assertEqual(status, 401, resp)

    def test_the_whole_journey_works_with_issuance_disabled(self):
        """The configuration nobody tested, end to end: issuance disabled,
        register, agents, deposit, transfer, withdraw, statement.

        Before the fix this stopped at step one with a 401 and there was no
        second step to reach. Caps and the freeze are exercised too, since
        "the profile mounts and does nothing" is precisely what a smoke
        test of registration alone would not have caught."""
        m = self.start_mint(admin_token=ADMIN_ISSUANCE_DISABLED, burn_policy=BURN)
        reg = m.server.registration_token

        status, r = raw_json(m.port, "POST", "/v3/operator/register",
                             {"operator_name": "ops"},
                             {"X-Registration-Token": reg})
        self.assertEqual(status, 200, r)
        op_key = r["operator_key"]
        op_id = r["operator_id"]
        a_id, a_key = self.new_agent(m, op_key, "worker")
        b_id, b_key = self.new_agent(m, op_key, "helper")

        # Deposit real bearer value.
        token = self.issue_direct(m, 10_000)
        status, r = api(m.port, "POST", "/v3/agent/deposit",
                        {"tokens": [token]}, key=a_key)
        self.assertEqual(status, 200, r)
        deposited = r["deposited_mc"]
        self.assertGreater(deposited, 0)
        self.assertEqual(self.balance(m, a_key)["balance_mc"], deposited)

        # A custodial transfer inside the fleet.
        status, r = self.transfer(m, a_key, b_id, 1_000)
        self.assertEqual(status, 200, r)
        self.assertEqual(self.balance(m, b_key)["balance_mc"], 1_000)

        # Caps still bind the agents of an operator registered this way.
        status, r = api(m.port, "POST", "/v3/operator/caps",
                        {"agent_id": b_id, "per_hour_mc": 100,
                         "per_day_mc": None, "absolute_mc": None}, key=op_key)
        self.assertEqual(status, 200, r)
        self.assertRejected(self.transfer(m, b_key, a_id, 500),
                            "agent_cap_exceeded")

        # ...and the withdrawal the finding says is unreachable.
        secret = new_secret()
        amount = 2_000
        status, r = api(m.port, "POST", "/v3/agent/withdraw",
                        {"outputs": [{"amount_mc": amount,
                                      "secret_hash": ledger_key(secret)}]},
                        key=a_key)
        self.assertEqual(status, 200, r)
        _, entry = api(m.port, "GET", "/v3/status/" + ledger_key(secret))
        self.assertEqual(entry["result"]["state"], "unspent")
        self.assertEqual(entry["result"]["amount_mc"], amount)

        # ...and a signed statement over all of it.
        status, stmt = self.statement(m, op_key, T0 - 1, T0 + DAY_MS)
        self.assertEqual(status, 200, stmt)
        self.check_statement(m, stmt, op_id, "fleet")

    def test_a_flagged_agent_still_cannot_stand_up_its_own_operator(self):
        """The bypass, re-run against the NEW authorisation.

        The holder of a no-bearer-withdrawal agent knows its own agent key
        and its operator's key, and on a generated-credential mint it knows
        neither the issuance credential nor the registration one. It must
        not be able to register a second operator, and therefore must not
        be able to move the value out of the supervised perimeter. Run on
        the mint configuration the fix introduced, because a fix that
        reopened the hole in the new configuration would pass every test
        that only looks at the old one."""
        m = self.start_mint(admin_token=ADMIN_ISSUANCE_DISABLED)
        reg = m.server.registration_token
        status, r = raw_json(m.port, "POST", "/v3/operator/register",
                             {"operator_name": "incumbent"},
                             {"X-Registration-Token": reg})
        self.assertEqual(status, 200, r)
        op_key = r["operator_key"]
        a_id, a_key = self.new_agent(m, op_key, "flagged")

        token = self.issue_direct(m, 5_000)
        status, r = api(m.port, "POST", "/v3/agent/deposit",
                        {"tokens": [token]}, key=a_key)
        self.assertEqual(status, 200, r)
        funded = self.balance(m, a_key)["balance_mc"]

        status, r = api(m.port, "POST", "/v3/operator/flags",
                        {"agent_id": a_id, "no_bearer_withdrawal": True},
                        key=op_key)
        self.assertEqual(status, 200, r)

        # Step one of the bypass: stand up an operator of your own. Every
        # secret this holder actually possesses, tried as the credential.
        for label, headers in [
            ("no credential", {}),
            ("its own agent key", {"X-Registration-Token": a_key}),
            ("its operator's key", {"X-Registration-Token": op_key}),
            ("its agent key in the admin header", {"X-Admin-Token": a_key}),
            ("its operator's key in the admin header",
             {"X-Admin-Token": op_key}),
            ("a bearer-style guess", {"X-Registration-Token": "Bearer " + a_key}),
        ]:
            with self.subTest(case=label):
                status, resp = raw_json(
                    m.port, "POST", "/v3/operator/register",
                    {"operator_name": "intruder"}, headers)
                self.assertEqual(status, 401, resp)

        # One operator, one agent: no second perimeter exists to move into.
        self.assertEqual(
            self.sup_rows(m, "SELECT COUNT(*) FROM sup_operators")[0][0], 1)

        # ...and the flagged agent's own exits are still shut.
        secret = new_secret()
        self.assertRejected(
            api(m.port, "POST", "/v3/agent/withdraw",
                {"outputs": [{"amount_mc": 1_000,
                              "secret_hash": ledger_key(secret)}]}, key=a_key),
            "withdrawal_disabled")
        _, entry = api(m.port, "GET", "/v3/status/" + ledger_key(secret))
        self.assertEqual(entry["result"]["state"], "unknown")
        self.assertEqual(self.balance(m, a_key)["balance_mc"], funded)

    def test_registration_can_be_held_by_a_different_person_than_issuance(self):
        """The separation, stated as behaviour: with an explicit
        registration credential, the issuance secret does not register and
        the registration secret does not issue -- in either header. This is
        the property the old code could not express at all, and its absence
        is what made 'issuance off' mean 'registration off'."""
        m = self.start_mint(admin_token=ADMIN_TOKEN,
                            registration_token="registration-only-secret")
        self.assertEqual(m.server.registration_source, "explicit-token")
        body = {"operator_name": "ops"}
        for label, headers in [
            ("issuance secret, admin header", {"X-Admin-Token": ADMIN_TOKEN}),
            ("issuance secret, registration header",
             {"X-Registration-Token": ADMIN_TOKEN}),
        ]:
            with self.subTest(case=label):
                status, resp = raw_json(m.port, "POST",
                                        "/v3/operator/register", body, headers)
                self.assertEqual(status, 401, resp)
        status, resp = raw_json(m.port, "POST", "/v3/operator/register", body,
                                {"X-Registration-Token": "registration-only-secret"})
        self.assertEqual(status, 200, resp)
        # ...and the registration secret is not a minting credential.
        status, resp = api(m.port, "POST", "/admin/issue", {"outputs": []},
                           admin="registration-only-secret")
        self.assertEqual(status, 401, resp)
        status, resp = api(m.port, "POST", "/admin/issue", {"outputs": []},
                           admin=ADMIN_TOKEN)
        self.assertEqual(status, 200, resp)

    def test_the_admin_header_still_registers_on_an_inheriting_mint(self):
        """The default must not break a bootstrap script that exists. A
        mint with a string admin_token has ONE secret, and it is still
        accepted under the header every existing caller sends."""
        m = self.start_mint()
        self.assertEqual(m.server.registration_source, "inherited")
        self.assertEqual(m.server.registration_token, ADMIN_TOKEN)
        status, r = raw_json(m.port, "POST", "/v3/operator/register",
                             {"operator_name": "ops"},
                             {"X-Admin-Token": ADMIN_TOKEN})
        self.assertEqual(status, 200, r)
        # ...and under the new one, since it is the same secret.
        status, r = raw_json(m.port, "POST", "/v3/operator/register",
                             {"operator_name": "ops2"},
                             {"X-Registration-Token": ADMIN_TOKEN})
        self.assertEqual(status, 200, r)

    def test_registration_can_be_disabled_and_then_bootstrapped_in_process(self):
        """REGISTRATION_DISABLED is now an honest state: the route refuses
        everyone AND there is a mechanism behind the promise. Both this
        module and C10-supervision.md used to say such a mint 'provisions
        operators out of band' while the only writer of sup_operators was
        the gated route itself."""
        m = self.start_mint(registration_token=supervision.REGISTRATION_DISABLED)
        self.assertIsNone(m.server.registration_token)
        for headers in ({}, {"X-Admin-Token": ADMIN_TOKEN},
                        {"X-Registration-Token": ADMIN_TOKEN}):
            status, resp = raw_json(m.port, "POST", "/v3/operator/register",
                                    {"operator_name": "x"}, headers)
            self.assertEqual(status, 401, resp)
        self.assertEqual(
            self.sup_rows(m, "SELECT COUNT(*) FROM sup_operators")[0][0], 0)

        op_id, op_key = m.server.provision_operator("out-of-band")
        self.assertTrue(op_id.startswith("op-"))
        # The key it returns is a working operator key, and the raw key is
        # not in the database (hashed at rest, like every other).
        a_id, a_key = self.new_agent(m, op_key, "agent")
        self.assertEqual(self.balance(m, a_key)["balance_mc"], 0)
        rows = self.sup_rows(m, "SELECT operator_id, name, key_sha256"
                                " FROM sup_operators")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][:2], (op_id, "out-of-band"))
        self.assertNotIn(op_key, rows[0][2])

    def test_open_registration_is_opted_into_by_name_only(self):
        """The unauthenticated state still exists and is still reachable
        only by naming it -- on the profile's own sentinel now, as well as
        by inheriting ADMIN_ISSUANCE_OPEN. Nothing here is a shortcut past
        a credential: the point is that it cannot be reached by omission."""
        m = self.start_mint(registration_token=supervision.REGISTRATION_OPEN)
        status, r = raw_json(m.port, "POST", "/v3/operator/register",
                             {"operator_name": "anyone"}, {})
        self.assertEqual(status, 200, r)

    def test_a_registration_credential_that_is_not_one_is_refused_at_build(self):
        """A mint that comes up is the mint that runs for a week, so an
        unusable credential is refused at construction rather than at the
        first request. Same discipline as MintConfig.admin_token."""
        for bad in ("", "   ", None, 17, b"bytes", ADMIN_ISSUANCE_DISABLED):
            with self.subTest(value=repr(bad)):
                with self.assertRaises(ValueError):
                    self.start_mint(registration_token=bad)

    def test_the_gate_state_is_announced_for_the_generated_case_too(self):
        """Every state says which one it is, once, at mount, and none of
        them prints the credential -- including the generated one, which is
        the only copy of a secret that exists anywhere at that moment."""
        records = []

        class Capture(logging.Handler):
            def emit(self, record):
                records.append(record)

        log = logging.getLogger("aicash.supervision")
        handler = Capture()
        log.addHandler(handler)
        old_level = log.level
        log.setLevel(logging.DEBUG)
        try:
            m = self.start_mint(admin_token=ADMIN_ISSUANCE_DISABLED)
        finally:
            log.removeHandler(handler)
            log.setLevel(old_level)
        said = [r for r in records if "/v3/operator/register" in r.getMessage()]
        self.assertEqual(len(said), 1, [r.getMessage() for r in records])
        self.assertEqual(said[0].levelno, logging.INFO)
        message = said[0].getMessage()
        self.assertIn("DISABLED", message)
        self.assertIn("X-Registration-Token", message)
        self.assertNotIn(m.server.registration_token, message)

    def test_the_server_can_be_told_which_port_to_bind(self):
        """A launcher publishes a fixed address; this override used to take
        no port at all, so run_mint.py could not put the profile anywhere
        but on an ephemeral port of the profile's choosing."""
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        wanted = probe.getsockname()[1]
        probe.close()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        priv, pub = generate_keypair()
        ledger = Ledger(os.path.join(tmp.name, "l.sqlite3"), FakeClock(T0),
                        NO_BURN, recovery_window_ms=90 * DAY_MS,
                        max_lock_expiry_ms=30 * DAY_MS)
        config = MintConfig(mint_id=MINT_ID, baseline_model_class="frontier-2026",
                            burn_policy=NO_BURN, signing_private=priv,
                            signing_public=pub, admin_token=ADMIN_TOKEN)
        server = SupervisionServer(config, ledger)
        self.addCleanup(server.stop)
        self.assertEqual(server.start(wanted), wanted)
        status, desc = api(wanted, "GET", "/v3/mints")
        self.assertEqual(status, 200)
        self.assertIn("supervision", desc["profiles"])

    def test_make_supervision_mint_builds_both_halves_from_the_config(self):
        """The builder run_mint.py uses. The Ledger must carry the config's
        own burn policy and windows, or the mint advertises one thing and
        enforces another -- MintServer.__init__ refuses that outright, so
        this asserts the builder does not have to be trusted."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        priv, pub = generate_keypair()
        config = MintConfig(mint_id=MINT_ID, baseline_model_class="frontier-2026",
                            burn_policy=BURN, signing_private=priv,
                            signing_public=pub, admin_token=ADMIN_TOKEN)
        server, ledger = supervision.make_supervision_mint(
            config, os.path.join(tmp.name, "l.sqlite3"))
        self.addCleanup(server.stop)
        self.assertEqual(ledger.burn_policy, BURN)
        self.assertEqual(ledger.recovery_window_ms, config.recovery_window_ms)
        self.assertEqual(ledger.max_lock_expiry_ms, config.max_lock_expiry_ms)
        port = server.start()
        status, r = raw_json(port, "POST", "/v3/operator/register",
                             {"operator_name": "ops"},
                             {"X-Admin-Token": ADMIN_TOKEN})
        self.assertEqual(status, 200, r)

    # ------------------------------------------------------------------ #
    # The framing CLASS: a header the parser never registered            #
    # ------------------------------------------------------------------ #
    #
    # The round before this one closed `Transfer-Encoding: chunked` and the
    # duplicated `Content-Length` -- the two spellings that were reported.
    # Both fixes asked `self.headers` for a header BY NAME, and
    # `self.headers` is not the wire: it is what email.parser made of the
    # wire. email's header line regex is `[\041-\071\073-\176]*:`, which
    # excludes SP and HTAB, so ONE SPACE before the colon makes a line stop
    # being a header -- and takes every line after it with it, into the
    # message payload. `get("Transfer-Encoding")` then answers None on a
    # request whose body is unambiguously chunked to anything else on the
    # path.
    #
    # So the shapes below are not four more spellings to enumerate. They are
    # the same defect reached through the view rather than through the name,
    # which is why the fix is stated about the view (a parser defect, an
    # unparsed remainder, an obs-fold, a length int() would read
    # differently) and not about any header.

    #: (extra header lines, body octets) -- each hides a framing header from
    #: the parser, or hides the body itself, while an intermediary reads it.
    #: Every one of these desynced a supervision route before this round:
    #: one request in, a 400 with NO `Connection: close`, and then a second
    #: answer built out of the octets left on the wire.
    HIDDEN_FRAMING = {
        # The reported shape, on this server.
        "te-space-before-colon": (
            b"Transfer-Encoding : chunked\r\n", b"5\r\nhello\r\n0\r\n\r\n"),
        # HTAB is excluded from the same regex for the same reason.
        "te-tab-before-colon": (
            b"Transfer-Encoding\t: chunked\r\n", b"5\r\nhello\r\n0\r\n\r\n"),
        # Case is not the variable; the space is.
        "te-lowercase-space-before-colon": (
            b"transfer-encoding : chunked\r\n", b"5\r\nhello\r\n0\r\n\r\n"),
        # A NEIGHBOURING FIELD, hidden the same way: nothing here mentions
        # Transfer-Encoding at all, and the body still goes unread.
        "cl-space-before-colon": (
            b"Content-Length : 34\r\n", b'{"operator_name":"smuggled-in-a-cl"}'[:34]),
        # ...and the field hidden by a malformed line BELONGING TO SOMETHING
        # ELSE. The Content-Length here is perfectly well formed; the
        # X-Junk line above it is what swallowed it.
        "cl-hidden-behind-a-malformed-line": (
            b"X-Junk : v\r\nContent-Length: 34\r\n",
            b'{"operator_name":"smuggled-in-a-cl"}'[:34]),
        # A good Content-Length the reader DOES see, with a transfer-coding
        # hidden behind it: we read 5 octets, a proxy dechunks. Proof the
        # rule is not "did we find a length".
        "te-hidden-after-a-good-cl": (
            b"Content-Length: 5\r\nTransfer-Encoding : chunked\r\n",
            b"5\r\nhello\r\n0\r\n\r\n"),
        # obs-fold: parses cleanly into ONE header here and into two for
        # anything that unfolds (RFC 7230 3.2.4 says reject rather than
        # guess which reading the next hop took).
        "obs-folded-te": (
            b"X-Junk: a\r\n Transfer-Encoding: chunked\r\n",
            b"5\r\nhello\r\n0\r\n\r\n"),
        # Lengths int() accepts and RFC 7230's 1*DIGIT does not. These
        # framed correctly on OUR side, which is exactly the problem: the
        # hop in front may read 0 and start framing the body as a request.
        "cl-with-a-plus-sign": (b"Content-Length: +34\r\n",
                                b'{"operator_name":"smuggled-in-a-cl"}'[:34]),
        "cl-with-an-underscore": (b"Content-Length: 3_4\r\n",
                                  b'{"operator_name":"smuggled-in-a-cl"}'[:34]),
    }

    def hidden_framing_request(self, path, headers, body, admin=True):
        """The unframable request, with a pipelined GET behind it. If the
        reader mis-sizes the body, that GET is what the leftover octets
        become."""
        cred = (b"X-Admin-Token: " + ADMIN_TOKEN.encode() + b"\r\n") if admin else b""
        return (
            b"POST " + path + b" HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Type: application/json\r\n"
            + cred + headers + b"\r\n" + body +
            b"GET /v3/mints HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        )

    def test_a_framing_header_hidden_from_the_parser_still_refuses_and_closes(self):
        """THE CLASS, on the route the reviewer reported it on.

        One request in, one answer out, connection closed, nothing left on
        the wire, and no operator created out of a body the mint never
        read. Asserted for every way of hiding a framing header from
        email.parser, not only for the space-before-colon that was
        reported."""
        m = self.start_mint()
        for name, (headers, body) in self.HIDDEN_FRAMING.items():
            with self.subTest(shape=name):
                raw, closed = raw_to_eof(
                    m.port,
                    self.hidden_framing_request(
                        b"/v3/operator/register", headers, body),
                )
                self.assertEqual(status_lines(raw), 1, raw[:400])
                self.assertEqual(
                    trailing_bytes(raw), b"",
                    "a second answer went out on this socket: %r" % raw[:600],
                )
                self.assertTrue(closed, "connection held open: %r" % raw[:200])
                self.assertIn(b"400", raw.split(b"\r\n")[0])
                self.assertIn(b"Connection: close", raw.split(b"\r\n\r\n")[0])
                parsed = json.loads(raw.partition(b"\r\n\r\n")[2])
                self.assertEqual(
                    parsed, {"status": "rejected", "reason": "bad_format"})
                self.assertEqual(
                    self.sup_rows(m, "SELECT COUNT(*) FROM sup_operators")[0][0],
                    0, "a hidden-framing body was parsed and acted on",
                )

    def test_the_profile_is_never_laxer_than_layer_0_about_framing(self):
        """One socket, and the profile must refuse everything Layer 0
        refuses -- plus the hidden-view class above, which Layer 0's copy of
        the rule cannot see yet.

        The shared verdict (`_body_framing_is_unreadable`, C06's, asked by
        both readers) is still asked FIRST by `_read_sup_json`; C10's own
        rule can only ever refuse MORE. That direction matters: a profile
        route laxer than Layer 0 would be a smuggling gap in the profile,
        while a profile stricter than Layer 0 merely refuses a request
        Layer 0 would have refused differently. The reverse gap -- Layer 0
        laxer than the profile -- lives in mintapi.py's
        `_body_framing_is_unreadable` and is not this component's to close;
        see the class comment above."""
        m = self.start_mint()
        shapes = dict(self.UNFRAMABLE_BODIES)
        shapes.update(self.HIDDEN_FRAMING)
        for name, (headers, body) in shapes.items():
            with self.subTest(shape=name):
                raw, closed = raw_to_eof(
                    m.port,
                    self.hidden_framing_request(
                        b"/v3/operator/register", headers, body),
                )
                self.assertEqual(trailing_bytes(raw), b"", raw[:600])
                self.assertTrue(closed, "connection held open: %r" % raw[:200])
                self.assertEqual(
                    json.loads(raw.partition(b"\r\n\r\n")[2]),
                    {"status": "rejected", "reason": "bad_format"},
                )

    def test_the_same_shapes_cannot_frame_an_inherited_route_either(self):
        """One socket, one verdict — asserted across the two readers.

        A supervision mint serves Layer 0 and the profile on the SAME
        socket, so the profile's routes are not the only door: a shape
        Layer 0 reads and the profile refuses is a smuggling gap in Layer
        0, and vice versa. C06 closed this class in its own reader, in its
        own `errors` envelope, in the same round; this asserts the two
        halves actually agree on the wire rather than by inspection.

        If it fails while the C10-route test above passes, the regression
        is in mintapi.py's `_body_framing_is_unreadable` (C06's file), not
        in this component. The reverse would be this module's.
        """
        m = self.start_mint()
        shapes = dict(self.UNFRAMABLE_BODIES)
        shapes.update(self.HIDDEN_FRAMING)
        for name, (headers, body) in shapes.items():
            with self.subTest(shape=name):
                raw, closed = raw_to_eof(
                    m.port,
                    self.hidden_framing_request(b"/v3/exchange", headers, body),
                )
                self.assertEqual(
                    trailing_bytes(raw), b"",
                    "a second answer went out on this socket: %r" % raw[:600])
                self.assertTrue(closed, "connection held open: %r" % raw[:200])
                self.assertNotIn(b"mint_id", raw)

    def test_the_parsed_headers_really_do_hide_the_framing_header(self):
        """Why the fix cannot key on a header name -- stated as a fact
        about the parser rather than as a claim about the mint.

        This is the mechanism behind every shape above: for these wire
        bytes `headers.get("Transfer-Encoding")` and
        `headers.get_all("Content-Length")` answer None, so ANY reader that
        decides framing by asking for a name decides it wrong. What the
        parser does leave behind is a defect and an unparsed payload, and
        those are what the rule reads."""
        import email.message
        import http.client as _http

        for name, (headers, _body) in self.HIDDEN_FRAMING.items():
            if name in ("cl-with-a-plus-sign", "cl-with-an-underscore"):
                continue  # these parse fine; they lie about the LENGTH
            with self.subTest(shape=name):
                block = b"Host: 127.0.0.1\r\n" + headers + b"\r\n"
                parsed = _http.parse_headers(io.BufferedReader(io.BytesIO(block)))
                self.assertIsInstance(parsed, email.message.Message)
                self.assertIsNone(parsed.get("Transfer-Encoding"))
                if name.startswith("cl-"):
                    self.assertIsNone(parsed.get("Content-Length"))
                # ...and the two things the rule DOES read.
                hid = bool(parsed.defects) or bool(parsed.get_payload())
                folded = any("\n" in v for v in parsed.values())
                self.assertTrue(hid or folded, parsed.items())

    def test_a_supervision_GET_is_framed_by_the_same_rule(self):
        """The profile answers its own GET routes without reaching C06's
        do_GET, so a framing guard that only covered POST would leave
        /v3/agent/balance and /v3/operator/statement smuggleable through the
        same socket. A GET body is never read here, so a hidden one leaves
        octets behind exactly as a POST body does."""
        m = self.start_mint()
        _op_id, op_key = self.new_operator(m)
        a_id, a_key = self.new_agent(m, op_key)
        request = (
            b"GET /v3/agent/balance?agent_id=" + a_id.encode() + b" HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Authorization: Bearer " + a_key.encode() + b"\r\n"
            b"Content-Length : 34\r\n"
            b"\r\n" + b"x" * 34 +
            b"GET /v3/mints HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        )
        raw, closed = raw_to_eof(m.port, request)
        self.assertEqual(status_lines(raw), 1, raw[:400])
        self.assertEqual(trailing_bytes(raw), b"", raw[:600])
        self.assertTrue(closed, "connection held open: %r" % raw[:200])

    def test_an_ordinary_supervision_request_is_not_caught_by_the_rule(self):
        """The guard must refuse mis-framed requests, not traffic. An
        ordinary http.client POST and GET keep working, keep their
        connection, and answer normally -- otherwise the rule above would
        be indistinguishable from turning the profile off."""
        m = self.start_mint()
        _op_id, op_key = self.new_operator(m)
        a_id, a_key = self.new_agent(m, op_key)
        self.assertEqual(self.balance(m, a_key)["balance_mc"], 0)
        conn = http.client.HTTPConnection("127.0.0.1", m.port, timeout=30)
        try:
            for _ in range(3):
                conn.request(
                    "POST", "/v3/operator/agents",
                    json.dumps({"agent_name": "keepalive"}).encode("utf-8"),
                    {"Authorization": "Bearer " + op_key},
                )
                resp = conn.getresponse()
                self.assertEqual(resp.status, 200)
                json.loads(resp.read().decode("utf-8"))
                # Three round trips on ONE connection: the rule did not
                # start hanging up on well-formed traffic.
                self.assertFalse(resp.will_close)
        finally:
            conn.close()

    # ------------------------------------------------------------------ #
    # The same class reached by RENAMING instead of by BREAKING          #
    # ------------------------------------------------------------------ #
    #
    # Everything above hides a framing header from `email.parser` by making
    # the LINE unparseable: a space before the colon, a fold, a junk line
    # that swallows the rest of the block. All of those leave a defect or an
    # unparsed payload behind, which is what clauses (1) and (2) of the rule
    # read -- and neither clause needs to know a single header NAME.
    #
    # Outside review then walked one step off that: you do not have to break
    # the line at all. `Transfer_Encoding: chunked` parses PERFECTLY. No
    # defect, empty payload, no fold, one clean header registered under the
    # name `Transfer_Encoding` -- so clauses (1), (2) and (3) are all silent,
    # and the only thing left standing between the request and a desync is
    # the clause that looks at names. That clause used to `strip().lower()`
    # and compare against two literal spellings, and `transfer_encoding` is
    # not `transfer-encoding`. Every front end, CGI gateway and WSGI server
    # that round-trips a header through an environment variable folds `_` to
    # `-`, so the hop in front reads a chunked body and this server reads
    # `Content-Length: 0` and answers with the chunk octets still on the
    # socket. The neighbouring field is worse, because it mentions no
    # transfer coding at all: `Content_Length: 125` on a GET needs nothing
    # else to leave 125 octets behind.
    #
    # So this table is NOT more spellings bolted onto a list. Every shape in
    # it parses cleanly (asserted below, as a fact about the parser), which
    # means the only rule that can refuse them is one that decides by
    # NORMALISING a name rather than by recognising one -- and the fix is a
    # fold, so a separator nobody has thought of yet folds away with the
    # rest.

    #: (extra header lines, octets the mint must NOT frame as this body).
    #: Each parses into ordinary, defect-free headers.
    RENAMED_FRAMING = {
        # The reported shape: a transfer coding an intermediary honours,
        # beside a length THIS server can compute. The computable length is
        # the point -- it switches off the "no computable length is
        # unframable" backstop, which is why the underscore alone is not
        # what makes this dangerous.
        "te-underscore-beside-a-zero-length": (
            b"Transfer_Encoding: chunked\r\nContent-Length: 0\r\n"),
        "te-underscore-uppercase": (
            b"TRANSFER_ENCODING: chunked\r\nContent-Length: 0\r\n"),
        # Case is not the variable and neither is the transfer coding: the
        # NEIGHBOURING FIELD under the same rename states a body all by
        # itself.
        "cl-underscore": (b"Content_Length: 40\r\n"),
        "cl-underscore-uppercase": (b"CONTENT_LENGTH: 40\r\n"),
        # Punctuation the previous round's honest_limitations dismissed as
        # "not a real vector" because it was reasoned about and never paired
        # with a computable length. Weaker in the wild (no common
        # intermediary reads these as framing) and included because they
        # prove the shape of the rule: a list would still miss them, a fold
        # and a token check cannot.
        "te-semicolon-beside-a-zero-length": (
            b"Transfer-Encoding;: chunked\r\nContent-Length: 0\r\n"),
        "te-dot-beside-a-zero-length": (
            b"Transfer-Encoding.: chunked\r\nContent-Length: 0\r\n"),
        "cl-semicolon": (b"Content-Length;: 40\r\n"),
        "cl-doubled-separator": (b"Content--Length: 40\r\n"),
    }

    #: A COMPLETE second request, admin-credentialled, that registers an
    #: operator by a name nothing else in this suite uses. If the mint
    #: mis-frames the request in front of it, these octets stop being a body
    #: and become the next request on the socket -- and the proof is not a
    #: byte count, it is a row in sup_operators and a live operator_key in
    #: a second response.
    SMUGGLED_NAME = "SMUGGLED-OPS"

    def smuggled_request(self):
        payload = json.dumps(
            {"operator_name": self.SMUGGLED_NAME}).encode("utf-8")
        return (
            b"POST /v3/operator/register HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"X-Admin-Token: " + ADMIN_TOKEN.encode() + b"\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(payload)).encode() + b"\r\n"
            b"\r\n" + payload
        )

    def renamed_framing_request(self, method, path, headers):
        """The renamed-framing request with a COMPLETE smuggled request
        immediately behind it, on one socket, from an ANONYMOUS caller.

        Anonymous on purpose: the body is read before authorization is
        decided, so the 401 path desyncs exactly as well as the 200 path
        and a gate on the route is not a defence."""
        return (
            method + b" " + path + b" HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Type: application/json\r\n"
            + headers + b"\r\n" + self.smuggled_request()
        )

    def assert_one_answer_and_hang_up(self, m, raw, closed):
        self.assertEqual(status_lines(raw), 1, raw[:600])
        self.assertEqual(
            trailing_bytes(raw), b"",
            "a second answer went out on this socket: %r" % raw[:600])
        self.assertTrue(closed, "connection held open: %r" % raw[:300])
        self.assertIn(b"Connection: close", raw.split(b"\r\n\r\n")[0])
        self.assertNotIn(b"operator_key", raw)
        self.assertEqual(
            self.sup_rows(
                m, "SELECT COUNT(*) FROM sup_operators WHERE name = ?",
                (self.SMUGGLED_NAME,))[0][0],
            0, "the smuggled request executed: %r" % raw[:600])

    def test_a_renamed_framing_header_parses_cleanly_and_is_still_refused(self):
        """The mechanism, stated as a fact about the parser first.

        For every shape in RENAMED_FRAMING the parser reports NO defect, an
        EMPTY payload and no folded value -- so the view preconditions of
        the framing rule are all silent, and `get`/`get_all` of the
        canonical names answer nothing. This is the test the previous
        round's shape table did not have: every one of its nine shapes
        landed on a defect or a payload, so nothing in the suite exercised
        the NAME clause at all and it could be a two-item list without any
        test noticing. These shapes can ONLY be refused by the name
        clause, and the second half asserts it refuses them.

        RETARGETED this round from `_SupHandler._sup_framing_is_
        unreadable` to the shared rule, because that method is gone: its
        token check and its hard fold are inside
        `aicash.mintapi.framing_verdict` now, where the plain mint, the
        operator GUI and the operator console reach them too. Both ends
        are asserted -- the exported function directly, and the handler
        that C10 serves these routes with -- so "the profile refuses these
        shapes" and "every server refuses these shapes" are the same
        assertion instead of two that can drift apart, which is exactly
        how they did drift apart."""
        import email.message
        import http.client as _http

        class _HeadersOnly(supervision._SupHandler):
            def __init__(self, headers):  # no socket, no dispatch
                self.headers = headers

        for name, headers in self.RENAMED_FRAMING.items():
            with self.subTest(shape=name):
                block = b"Host: 127.0.0.1\r\n" + headers + b"\r\n"
                parsed = _http.parse_headers(io.BufferedReader(io.BytesIO(block)))
                self.assertIsInstance(parsed, email.message.Message)
                # (1), (2), (3) -- all silent.
                self.assertEqual(list(parsed.defects), [])
                self.assertEqual(parsed.get_payload(), "")
                for value in parsed.values():
                    self.assertNotIn("\n", value)
                    self.assertNotIn("\r", value)
                # ...and the request looks harmless to a reader that asks
                # for a name: no transfer coding, and at most the honest
                # `Content-Length: 0` some of these carry.
                self.assertIsNone(parsed.get("Transfer-Encoding"))
                self.assertIn(parsed.get_all("Content-Length"), (None, ["0"]))
                # The rule refuses anyway, on the fold or on the token
                # check -- asked of the EXPORTED function, which is the
                # only copy of it there is.
                for expected in (True, False):
                    verdict = mintapi.framing_verdict(
                        parsed, body_expected=expected)
                    self.assertIs(
                        verdict.framed, False,
                        "the name clause did not see %r" % (parsed.items(),))
                    self.assertIs(verdict.must_close, True, verdict)
                    # ...and therefore no length is computable for it on
                    # the handler C10 serves these routes with, on either
                    # method: the one chokepoint the whole server frames
                    # from, reached without an override.
                    self.assertIsNone(
                        _HeadersOnly(parsed)._framed_body_length(
                            body_expected=expected))
                    self.assertIs(
                        _HeadersOnly(parsed)._framing_verdict(
                            body_expected=expected).must_close, True)

    def test_a_renamed_framing_header_cannot_frame_a_supervision_post(self):
        """The reported variation, end to end, on every supervision POST
        route and from an anonymous caller: one answer, `Connection:
        close`, nothing left on the wire, and no SMUGGLED-OPS operator."""
        for path in (b"/v3/operator/register", b"/v3/agent/deposit",
                     b"/v3/agent/withdraw", b"/v3/pull"):
            m = self.start_mint()
            for name, headers in self.RENAMED_FRAMING.items():
                with self.subTest(route=path.decode(), shape=name):
                    raw, closed = raw_to_eof(
                        m.port,
                        self.renamed_framing_request(b"POST", path, headers))
                    self.assert_one_answer_and_hang_up(m, raw, closed)

    def test_a_renamed_framing_header_cannot_frame_a_supervision_get(self):
        """The GET half, which needs no Content-Length at all to desync.

        C06's length rule answers 0 for "no Content-Length" on a GET by
        design (every conforming GET says nothing about a body), so the
        "no computable length is unframable" backstop that protects the
        POST path is switched off here. That leaves the name rule as the
        only guard on a supervision GET, which is exactly why the name rule
        has to be a normalisation rather than a list: a spelling it misses
        is a GET smuggle with no second condition to satisfy."""
        m = self.start_mint()
        _op_id, op_key = self.new_operator(m)
        a_id, a_key = self.new_agent(m, op_key)
        paths = (
            b"/v3/agent/balance",
            b"/v3/agent/balance?agent_id=" + a_id.encode(),
            b"/v3/operator/statement?agent_id=" + a_id.encode(),
        )
        for path in paths:
            for name, headers in self.RENAMED_FRAMING.items():
                for anonymous in (True, False):
                    with self.subTest(route=path.decode(), shape=name,
                                      anonymous=anonymous):
                        auth = b"" if anonymous else (
                            b"Authorization: Bearer " + a_key.encode() + b"\r\n")
                        raw, closed = raw_to_eof(
                            m.port,
                            self.renamed_framing_request(
                                b"GET", path, auth + headers))
                        self.assertEqual(status_lines(raw), 1, raw[:600])
                        self.assertEqual(
                            trailing_bytes(raw), b"",
                            "a second answer went out: %r" % raw[:600])
                        self.assertTrue(
                            closed, "connection held open: %r" % raw[:300])
                        self.assertNotIn(b"operator_key", raw)
                        self.assertEqual(
                            self.sup_rows(
                                m,
                                "SELECT COUNT(*) FROM sup_operators"
                                " WHERE name = ?",
                                (self.SMUGGLED_NAME,))[0][0],
                            0, raw[:600])

    def test_a_renamed_framing_header_cannot_frame_an_inherited_route(self):
        """Same socket, same server, the OTHER layer.

        A supervision mint serves /v3/exchange, /admin/issue and /v3/mints
        beside the profile, so a shape Layer 0 frames and the profile
        refuses is not a stricter profile -- it is an open door with a
        supervision mint behind it, and outside review drove exactly that.
        The fix is an override of the ONE method every framing decision in
        this server is built on (`_framed_body_length`), which is why the
        inherited routes are covered by it without a second rule and
        without touching C06's reader.

        C06 is closing the same class in its own file with a differently
        shaped rule (a confusable-name regex, one character per hyphen).
        This test does not depend on that and does not assert where the
        refusal comes from: C10's fold is the wider of the two -- it drops
        every non-alphanumeric character and refuses any name that is not
        an RFC 7230 token -- so the punctuated shapes in the table are
        refused here regardless. Asserting which layer said no would lock
        the two halves together in exactly the way that let this class
        survive the last round."""
        m = self.start_mint()
        for method, path in ((b"POST", b"/v3/exchange"),
                             (b"POST", b"/admin/issue"),
                             (b"GET", b"/v3/mints"),
                             (b"GET", b"/v3/status/deadbeef")):
            for name, headers in self.RENAMED_FRAMING.items():
                with self.subTest(route=path.decode(), shape=name):
                    raw, closed = raw_to_eof(
                        m.port,
                        self.renamed_framing_request(method, path, headers))
                    self.assertEqual(status_lines(raw), 1, raw[:600])
                    self.assertEqual(
                        trailing_bytes(raw), b"",
                        "a second answer went out: %r" % raw[:600])
                    self.assertTrue(
                        closed, "connection held open: %r" % raw[:300])
                    self.assertNotIn(b"operator_key", raw)
                    self.assertEqual(
                        self.sup_rows(
                            m,
                            "SELECT COUNT(*) FROM sup_operators WHERE name = ?",
                            (self.SMUGGLED_NAME,))[0][0],
                        0, raw[:600])

    def test_the_fold_refuses_framing_aliases_without_refusing_traffic(self):
        """The cost of a fold is over-refusal, so bound it.

        A name only has to fold onto `content-length` or
        `transfer-encoding` to be refused; a header that merely CONTAINS
        those words, or that is an ordinary vendor extension, still frames
        and still keeps its connection. Without this, "refuse everything"
        would pass every other test in this section."""
        m = self.start_mint()
        _op_id, op_key = self.new_operator(m)
        conn = http.client.HTTPConnection("127.0.0.1", m.port, timeout=30)
        try:
            for extra in ({"X-Content-Length": "40"},
                          {"X-Transfer-Encoding": "chunked"},
                          {"Content-Length-Note": "40"},
                          {"X-Trace-Id": "a.b_c-d"},
                          {"X-Underscored_Name": "v"}):
                with self.subTest(header=sorted(extra)[0]):
                    headers = {"Authorization": "Bearer " + op_key}
                    headers.update(extra)
                    conn.request(
                        "POST", "/v3/operator/agents",
                        json.dumps({"agent_name": "ok"}).encode("utf-8"),
                        headers)
                    resp = conn.getresponse()
                    self.assertEqual(resp.status, 200)
                    json.loads(resp.read().decode("utf-8"))
                    self.assertFalse(
                        resp.will_close,
                        "the fold refused a header that frames nothing")
        finally:
            conn.close()

    #: Framing constructs. Not "words that look suspicious": each one is a
    #: thing the shared rule OWNS, and a copy of the rule cannot be written
    #: without at least one of them.
    FRAMING_CONSTRUCTS = (
        "get_all", "Content-Length", "Transfer-Encoding", "int(",
        ".defects", "get_payload", "_TCHAR", "_FOLDED_FRAMING_NAMES",
        "_FRAMING_CONFUSABLE_RE",
    )

    def test_c10_holds_no_second_framing_rule_anywhere_in_the_class(self):
        """Source-level, over the WHOLE handler class, and that scope is
        the finding.

        What stood here checked one method -- ``_framed_body_length``, the
        one that had no arithmetic left in it -- and forbade exactly the
        constructs a framing copy is made of: ``get_all``,
        ``Content-Length``, ``int(``. The method immediately below it in
        the same class, ``_read_sup_json``, contained all three:

            declared = self.headers.get_all("Content-Length") or []
            length = int(declared[0]) if declared else 0

        ...and ``_read_sup_json`` is the one that actually pulls bytes off
        the socket, on the profile's twelve POST routes. An anti-copy check
        that polices the method with nothing left in it and exempts the
        method that kept the arithmetic is not an anti-copy check; it is a
        shape. So this asks the class, not a method, and a new method
        cannot be added outside its reach.

        Nothing in ``_SupHandler`` may compute a body length or normalise a
        header name. The rule is ``aicash.mintapi.framing_verdict`` and the
        only legal thing to do with framing here is to ASK it.
        """
        offenders = []
        for name, member in sorted(supervision._SupHandler.__dict__.items()):
            if not callable(member):
                continue
            try:
                source = inspect.getsource(member)
            except (TypeError, OSError):    # pragma: no cover - builtins
                continue
            # Prose about the rule is not an implementation of it, and
            # neither is a comment saying what used to be here.
            code = re.sub(r'(?s)""".*?"""', "", source)
            code = "\n".join(
                line for line in code.split("\n")
                if not line.strip().startswith("#")
            )
            for construct in self.FRAMING_CONSTRUCTS:
                if construct in code:
                    offenders.append((name, construct))
        self.assertEqual(
            offenders, [],
            "a second framing rule is growing back inside _SupHandler",
        )

    def test_c10_overrides_none_of_the_framing_chokepoints(self):
        """C10 narrows framing nowhere, because there is nothing left to
        narrow: its token check and its hard fold are inside
        ``framing_verdict`` now, where the mint, the operator GUI and the
        operator console reach them too.

        The three names below are the whole chokepoint. While
        ``_framed_body_length`` was overridden here the supervision
        profile was the STRICTEST of the four servers and the other three
        were smuggleable on 435 header names -- an override on this class
        is, by construction, a rule three servers do not have.
        """
        self.assertNotIn(
            "_sup_framing_is_unreadable", supervision._SupHandler.__dict__,
            "the C10-only framing rule grew back: its token check and its"
            " fold belong to framing_verdict, where all four servers get"
            " them, and a named method with no caller on the class that"
            " used to own the rule is where the rule comes back")
        for method in ("_framing_verdict", "_framed_body_length",
                       "_body_framing_is_unreadable",
                       "_close_if_body_goes_unread"):
            with self.subTest(method=method):
                self.assertNotIn(
                    method, supervision._SupHandler.__dict__,
                    "C10 overrode %s: a framing rule the other three"
                    " servers do not have is how this started" % method)
                self.assertIs(
                    getattr(supervision._SupHandler, method),
                    getattr(mintapi._Handler, method),
                )
        # ...and the fold that used to be C10's alone is now literally the
        # same object the mint uses. Identity, not equality: two functions
        # with the same body are two functions.
        self.assertIs(
            supervision._fold_header_name, mintapi._fold_header_name)
        self.assertIs(supervision.framing_verdict, mintapi.framing_verdict)

    def test_every_supervision_route_asks_the_shared_rule(self):
        """All fourteen profile routes, through a recorder on the module
        global.

        The mint-side version of this test covered "every route on this
        server" and this server was the plain mint's seven. The profile's
        routes run on the same socket and were never driven through the
        recorder at all -- so a supervision route that grew its own
        framing rule would have been invisible, which is the exact shape
        of the defect the recorder exists to catch.
        """
        m = self.start_mint()
        _op_id, op_key = self.new_operator(m)
        a_id, a_key = self.new_agent(m, op_key)

        calls = []
        real = mintapi.framing_verdict

        def recorder(headers, **kwargs):
            verdict = real(headers, **kwargs)
            calls.append((headers.get("X-Framing-Probe"), kwargs, verdict))
            return verdict

        mintapi.framing_verdict = recorder
        self.addCleanup(setattr, mintapi, "framing_verdict", real)

        routes = [
            ("POST", "/v3/operator/register", {"operator_name": "p"}, None),
            ("POST", "/v3/operator/agents", {"agent_name": "p"}, op_key),
            ("POST", "/v3/operator/caps", {"agent_id": a_id}, op_key),
            ("POST", "/v3/operator/freeze", {"agent_id": a_id}, op_key),
            ("POST", "/v3/operator/unfreeze", {"agent_id": a_id}, op_key),
            ("POST", "/v3/operator/flags",
             {"agent_id": a_id, "no_bearer_withdrawal": False}, op_key),
            ("POST", "/v3/agent/deposit", {"tokens": []}, a_key),
            ("POST", "/v3/agent/withdraw", {"amount_mc": 1}, a_key),
            ("POST", "/v3/agent/transfer",
             {"to_account": a_id, "amount_mc": 1}, a_key),
            ("POST", "/v3/agent/authorize_pull", {}, a_key),
            ("POST", "/v3/agent/revoke_pull", {}, a_key),
            ("POST", "/v3/pull", {}, a_key),
            ("GET", "/v3/agent/balance", None, a_key),
            ("GET", "/v3/operator/statement?from=0&to=1", None, op_key),
        ]
        for i, (method, path, body, key) in enumerate(routes):
            with self.subTest(route=path, method=method):
                tag = "sup%d" % i
                payload = (json.dumps(body).encode("utf-8")
                           if body is not None else b"")
                request = (
                    ("%s %s HTTP/1.1\r\n" % (method, path)).encode("ascii")
                    + b"Host: 127.0.0.1\r\n"
                    + b"Content-Type: application/json\r\n"
                    + b"X-Framing-Probe: " + tag.encode() + b"\r\n"
                    + (b"Authorization: Bearer " + key.encode() + b"\r\n"
                       if key else b"")
                    + b"X-Admin-Token: " + ADMIN_TOKEN.encode() + b"\r\n"
                    + b"Content-Length: %d\r\n" % len(payload)
                    + b"Connection: close\r\n\r\n" + payload
                )
                raw, _closed = raw_to_eof(m.port, request)
                self.assertTrue(raw, "%s %s answered nothing" % (method, path))
                self.assertTrue(
                    [c for c in calls if c[0] == tag],
                    "%s %s answered without asking framing_verdict"
                    % (method, path))

    # ------------------------------------------------------------------ #
    # An integer the mint cannot store is a bad field, not a 500         #
    # ------------------------------------------------------------------ #
    #
    # `_plain_int` checked `type(v) is int` and stopped there. Python's int
    # is unbounded and SQLite's INTEGER is signed 64-bit, so 2**63 is valid
    # JSON, the correct type, and non-negative -- it passed every guard on
    # the route, reached conn.execute, and raised OverflowError out of the
    # driver into `_dispatch_sup`'s blanket handler. The caller got a bare
    # 500 where §3.8 owes an enumerated reason. Fixed at the predicate
    # every integer field already goes through rather than at the five
    # fields outside review happened to name.

    #: Integers no SQLite column can hold. 10**600 is here because the
    #: failure is about the VALUE's magnitude, not about 64 bits.
    UNSTORABLE = (2 ** 63, -(2 ** 63) - 1, 10 ** 600, -(10 ** 600))

    def test_an_unstorable_integer_is_rejected_not_a_500(self):
        m = self.start_mint()
        _op_id, op_key = self.new_operator(m)
        a_id, a_key = self.new_agent(m, op_key)
        b_id, _b_key = self.new_agent(m, op_key, name="payee")
        cases = (
            ("/v3/operator/caps", op_key,
             lambda v, f: {"agent_id": a_id, f: v}),
            ("/v3/agent/authorize_pull", a_key,
             lambda v, f: {"payee_account": b_id, "cap_mc_per_day": 5,
                           "expires_at": T0 + DAY_MS, f: v}),
            ("/v3/agent/transfer", a_key,
             lambda v, f: {"to_account": b_id, f: v}),
            ("/v3/pull", a_key, lambda v, f: {"auth_id": "auth-x", f: v}),
        )
        fields = {
            "/v3/operator/caps": ("per_hour_mc", "per_day_mc", "absolute_mc"),
            "/v3/agent/authorize_pull": ("cap_mc_per_day", "expires_at"),
            "/v3/agent/transfer": ("amount_mc",),
            "/v3/pull": ("amount_mc",),
        }
        for path, key, build in cases:
            for field in fields[path]:
                for value in self.UNSTORABLE:
                    with self.subTest(path=path, field=field, value=str(value)[:8]):
                        status, r = api(m.port, "POST", path,
                                        build(value, field), key=key)
                        self.assertEqual(status, 400, (path, field, r))
                        self.assertEqual(
                            r, {"status": "rejected", "reason": "bad_format"})

    def test_a_query_parameter_no_column_can_hold_is_not_a_500(self):
        """THE ONE THE LAST SWEEP MISSED, and it was missed the way this
        class of defect is always missed: the route was listed as swept
        because its two integers "go through ``int()`` inside a
        try/except". A try/except around ``int()`` catches a non-numeric
        string; it does not BOUND the value, and ``op_statement``'s
        ``from``/``to`` are bound straight into sqlite.

        ``?to=9223372036854775808`` -- one past the column's range -- raised
        ``OverflowError`` out of ``_balance_from_lines`` and answered HTTP
        500 ``{"status":"error"}`` with no enumerated reason, to any
        authenticated operator, on a GET. That is the literal error-model
        violation ``_plain_int`` was written to eliminate, surviving on a
        route that converted its integers by hand instead of through it.

        ``"9" * 25`` answered 400 already -- but by ACCIDENT, because
        CPython's int/str conversion limit raises ValueError before the
        value ever reaches SQLite. A different check happening to catch a
        neighbouring value is exactly what makes a hole look swept, so
        both are asserted here and the 2**63 boundary is asserted from
        both sides.
        """
        m = self.start_mint()
        _op_id, op_key = self.new_operator(m)
        a_id, _a_key = self.new_agent(m, op_key)
        unstorable = (
            "9223372036854775808",          # 2**63, the reported value
            "18446744073709551616",         # 2**64
            "9" * 25,                       # caught by accident before
            "9" * 4400,                     # caught by the int/str limit
            "-9223372036854775809",         # the other end of the column
        )
        for value in unstorable:
            for query in ("from=0&to=" + value, "from=" + value + "&to=" + value):
                with self.subTest(query=query[:40]):
                    status, r = api(
                        m.port, "GET",
                        "/v3/operator/statement?" + query, key=op_key)
                    self.assertEqual(status, 400, r)
                    self.assertEqual(
                        r, {"status": "rejected", "reason": "bad_format"})
        # ...and with an agent scope, which takes the other branch into
        # `_balance_from_lines`.
        status, r = api(
            m.port, "GET",
            "/v3/operator/statement?from=0&to=9223372036854775808"
            "&agent_id=" + a_id, key=op_key)
        self.assertEqual(status, 400, r)
        self.assertEqual(r, {"status": "rejected", "reason": "bad_format"})

    def test_the_statement_boundary_itself_still_works(self):
        """The bound refuses what no column can hold and nothing else:
        2**63 - 1 is exactly representable and still answers a signed
        statement, so this is a range check and not a smaller arbitrary
        limit that would truncate an honest in-retention window."""
        m = self.start_mint()
        _op_id, op_key = self.new_operator(m)
        self.new_agent(m, op_key)
        status, r = api(
            m.port, "GET",
            "/v3/operator/statement?from=0&to=%d" % (2 ** 63 - 1),
            key=op_key)
        self.assertEqual(status, 200, r)
        self.assertEqual(r["period"]["to"], 2 ** 63 - 1)

    def test_a_storable_integer_at_the_boundary_still_works(self):
        """The bound must refuse what cannot be stored and nothing else: a
        cap of 2**63 - 1 is exactly representable and still accepted, so
        the fix is a range check rather than a smaller arbitrary limit."""
        m = self.start_mint()
        _op_id, op_key = self.new_operator(m)
        a_id, _a_key = self.new_agent(m, op_key)
        biggest = 2 ** 63 - 1
        status, r = api(
            m.port, "POST", "/v3/operator/caps",
            {"agent_id": a_id, "per_hour_mc": biggest,
             "per_day_mc": biggest, "absolute_mc": biggest},
            key=op_key)
        self.assertEqual(status, 200, r)
        self.assertEqual(r["caps"]["absolute_mc"], biggest)
        self.assertEqual(
            self.sup_rows(
                m, "SELECT cap_absolute_mc FROM sup_agents WHERE agent_id = ?",
                (a_id,))[0][0],
            biggest)

    # ------------------------------------------------------------------ #
    # §7.3 scheduled burn change: the profile and its ledger agree       #
    # ------------------------------------------------------------------ #
    #
    # The §7.3 change notice must flip for the Supervision Profile at the
    # same instant it flips for the ledger underneath it and for every client.
    #
    # Found by outside review 2026-09-16 (F2, relocated into C10). The
    # profile pre-computes a burn before calling ``exchange``: on deposit to
    # charge the depositing agent, on withdrawal to debit it and to size the
    # custody inputs. Those four computations read the ledger's CONFIGURED
    # policy, which a change notice supersedes. From ``effective_at`` onward
    # every deposit was refused ``amount_mismatch`` (the profile built an
    # exchange priced under the old policy, the ledger charged the new one)
    # and every withdrawal drifted -- a fleet-wide break at a date announced
    # in the descriptor, not at a moment anyone was watching.
    #
    # No test in this suite could see it before this round because no test
    # could build a mint with a change notice at all; ``start_mint`` gained
    # ``burn_policy_next`` for these.
    #

    #: 0.1% before the flip, 1% after it -- a tenfold INCREASE, so the
    #: notice must also satisfy §7.3's notice period (>= max_lock_expiry,
    #: 30 days here), which is why the flip is 31 days out.
    LOW = BurnPolicy(rate_ppm=1_000, cap_mc=1_000_000, exempt_below_mc=10)
    HIGH = BurnPolicy(rate_ppm=10_000, cap_mc=1_000_000, exempt_below_mc=10)
    FLIP = T0 + 31 * DAY_MS

    def scheduled_mint(self):
        m = self.start_mint(
            burn_policy=self.LOW,
            burn_policy_next=(self.HIGH, self.FLIP),
            burn_policy_announced_at=T0,
        )
        _, op_key = self.new_operator(m)
        agent_id, a_key = self.new_agent(m, op_key)
        return m, agent_id, a_key

    def test_deposit_is_charged_the_policy_in_force_at_the_call(self):
        """Before the flip: 0.1%. After it: 1%. Both succeed."""
        m, _, a_key = self.scheduled_mint()

        status, r = api(
            m.port,
            "POST",
            "/v3/agent/deposit",
            {"tokens": [self.issue_token(m, 50_000)]},
            key=a_key,
        )
        self.assertEqual(status, 200, r)
        self.assertEqual(r["burn_mc"], 50)        # 50_000 * 0.1%
        self.assertEqual(r["deposited_mc"], 49_950)

        m.clock.advance(32 * DAY_MS)              # past FLIP
        status, r = api(
            m.port,
            "POST",
            "/v3/agent/deposit",
            {"tokens": [self.issue_token(m, 50_000)]},
            key=a_key,
        )
        self.assertEqual(status, 200, r)          # was 400 amount_mismatch
        self.assertEqual(r["burn_mc"], 500)       # 50_000 * 1%
        self.assertEqual(r["deposited_mc"], 49_500)
        self.assertEqual(
            self.balance(m, a_key)["balance_mc"], 49_950 + 49_500
        )

    def test_withdraw_is_charged_the_policy_in_force_at_the_call(self):
        """The agent-charged burn, and the custody selection that has to
        cover the ledger's own burn, both follow the flip."""
        m, _, a_key = self.scheduled_mint()
        status, r = api(
            m.port,
            "POST",
            "/v3/agent/deposit",
            {"tokens": [self.issue_token(m, 50_000)]},
            key=a_key,
        )
        self.assertEqual(status, 200, r)
        balance = r["deposited_mc"]

        m.clock.advance(32 * DAY_MS)              # past FLIP
        secret = new_secret()
        status, r = api(
            m.port,
            "POST",
            "/v3/agent/withdraw",
            {"outputs": [{"amount_mc": 10_000, "secret_hash": ledger_key(secret)}]},
            key=a_key,
        )
        self.assertEqual(status, 200, r)          # was 400 insufficient_balance
        self.assertEqual(r["withdrawn_mc"], 10_000)
        self.assertEqual(r["burn_mc"], 100)       # 10_000 * 1%, not 10
        self.assertEqual(
            self.balance(m, a_key)["balance_mc"], balance - 10_100
        )
        _, entry = api(m.port, "GET", "/v3/status/" + ledger_key(secret))
        self.assertEqual(entry["result"]["state"], "unspent")
        self.assertEqual(entry["result"]["amount_mc"], 10_000)

    def test_the_profile_and_its_ledger_never_price_a_call_differently(self):
        """Behavioural parity, not source-text: whatever the profile
        charges an agent, the ledger charges the same policy at the same
        instant -- checked on both sides of the flip through the ledger's
        own public accessor, and against the descriptor every client reads.
        """
        m, _, a_key = self.scheduled_mint()
        for label, advance, expected in (("before", 0, 50), ("after", 32 * DAY_MS, 500)):
            with self.subTest(label):
                m.clock.advance(advance)
                now = m.clock.now_ms
                dstatus, desc = api(m.port, "GET", "/v3/mints")
                self.assertEqual(dstatus, 200, desc)
                status, r = api(
                    m.port,
                    "POST",
                    "/v3/agent/deposit",
                    {"tokens": [self.issue_token(m, 50_000)]},
                    key=a_key,
                )
                self.assertEqual(status, 200, r)
                self.assertEqual(r["burn_mc"], expected)
                # The ledger's public selection rule agrees with what the
                # agent was actually charged...
                self.assertEqual(
                    compute_burn(50_000, m.ledger.effective_burn_policy(now)),
                    r["burn_mc"],
                )
                # ...and so does the descriptor a client would price from,
                # selected by the §3.6/§7.3 rule a client applies by hand.
                nxt = desc["burn_policy_next"]
                self.assertIsNotNone(nxt, desc)  # the notice IS published
                client_policy = BurnPolicy(**desc["burn_policy"])
                if now >= nxt["effective_at"]:
                    client_policy = BurnPolicy(**nxt["policy"])
                self.assertEqual(
                    compute_burn(50_000, client_policy), r["burn_mc"]
                )

    # ------------------------------------------------------------------ #
    # A route that accepts what it cannot render has already acted        #
    # ------------------------------------------------------------------ #
    #
    # Two findings on POST /v3/operator/register, both behind the
    # registration credential so neither is anonymous:
    #
    #   * an `operator_name` containing an UNPAIRED SURROGATE ("op\ud800" —
    #     json.loads produces it happily, because JSON's \uXXXX escape has no
    #     pairing rule) was accepted, and the failure surfaced from a UTF-8
    #     encode with the operator already made. There is nothing correct
    #     for an encoder to do at that point: the row, the identity and the
    #     bearer key all exist, and the caller is told {"status":"error"}
    #     with no §3.8 reason at all. So the fix is INPUT validation, the
    #     way C01 refuses an unrenderable document on the way in rather
    #     than on the way out;
    #   * a FIVE THOUSAND character `operator_name` returned 200 and a real
    #     operator, with the size of the field set by whoever called it.
    #
    # Both are one defect — accepting what the mint cannot render or would
    # rather not hold — so what follows sweeps every caller-supplied string
    # this module stores, echoes or looks a row up by, rather than the one
    # field each finding was reported on. Seven further routes answered a
    # bare 500 on the first finding's value, all through one unguarded
    # lookup in `_agent`.

    #: JSON source (ASCII bytes) for a string carrying an unpaired
    #: surrogate. Written as raw bytes because `json.dumps(...).encode()`
    #: cannot produce it — which is itself the point of the finding.
    SURROGATE_JSON = b'"bad\\ud800name"'
    LONG = "A" * 5000

    #: The third finding's reported value, written the same way and for a
    #: related reason: `json.dumps` WOULD produce it, but a NUL cannot be
    #: typed into a test file without putting a control character in the
    #: source, and the point is that it arrives over the wire as an escape
    #: an ordinary JSON parser expands without comment.
    NUL_JSON = b'"acme\\u0000evil"'

    #: One spelling per family of "a code point that has no rendering of
    #: its own, or whose rendering is an instruction rather than a glyph".
    #: Sent as JSON escapes; every one of these was accepted with a 200
    #: before this round.
    UNRENDERABLE = {
        "NUL (C0)": b"\\u0000",
        "BEL (C0)": b"\\u0007",
        "BS (C0)": b"\\u0008",
        "TAB (C0)": b"\\t",
        "LF (C0)": b"\\n",
        "CR (C0)": b"\\r",
        "ESC (C0)": b"\\u001b",
        "DEL": b"\\u007f",
        "NEL (C1)": b"\\u0085",
        "C1 0x9b": b"\\u009b",
        "LINE SEPARATOR": b"\\u2028",
        "PARAGRAPH SEPARATOR": b"\\u2029",
        "NBSP": b"\\u00a0",
        "RLO (bidi override)": b"\\u202e",
        "ZWSP (format)": b"\\u200b",
        "SOFT HYPHEN (format)": b"\\u00ad",
        "PRIVATE USE": b"\\ue000",
    }

    #: Names that must keep working. A bound that also refused these
    #: would be worse than the defect it closes.
    RENDERABLE = {
        "ascii": b"acme-ops",
        "spaces": b"ACME Operations, Inc.",
        "punctuation": b"invoice #42 (Q3/2026) \\u2014 net-30",
        "accented": b"Soci\\u00e9t\\u00e9 G\\u00e9n\\u00e9rale",
        "cjk": b"\\u6771\\u4eac\\u652f\\u5e97",
        "emoji (surrogate PAIR)": b"rocket \\ud83d\\ude80",
        "combining mark": b"e\\u0301quipe",
    }

    def raw_post(self, port, path, body: bytes, headers=None):
        """A hand-built POST, because these bodies cannot be built with
        json.dumps: the value under test is one Python declines to
        encode."""
        head = {"Content-Type": "application/json"}
        head.update(headers or {})
        request = ("POST %s HTTP/1.1\r\nHost: 127.0.0.1\r\n" % path).encode()
        for k, v in head.items():
            request += ("%s: %s\r\n" % (k, v)).encode()
        request += b"Content-Length: %d\r\n\r\n" % len(body)
        return raw_api(port, request + body)

    def assert_enumerated(self, status, body, allowed=None):
        """400/404 with a §3.8 reason — never a 5xx, never a bare
        ``{"status":"error"}``."""
        self.assertIsNotNone(status, body)
        self.assertLess(status, 500, (status, body))
        self.assertEqual(body.get("status"), "rejected", body)
        self.assertIn("reason", body, body)
        if allowed is not None:
            self.assertIn(body["reason"], allowed, body)

    # -- finding 1: an operator name that cannot be rendered -------------

    def test_an_unrenderable_operator_name_creates_no_operator(self):
        m = self.start_mint()
        status, body = self.raw_post(
            m.port, "/v3/operator/register",
            b'{"operator_name": ' + self.SURROGATE_JSON + b"}",
            {"X-Admin-Token": ADMIN_TOKEN},
        )
        self.assert_enumerated(status, body, {"bad_format"})
        self.assertEqual(status, 400, body)
        # The whole point of doing it on the way IN.
        self.assertEqual(
            self.sup_rows(m, "SELECT COUNT(*) FROM sup_operators")[0][0], 0
        )

    def test_every_lone_surrogate_is_refused_not_just_the_reported_one(self):
        """D800 was the reported code point. The class is the whole
        surrogate range, and the predicate asks by ENCODING rather than by
        recognising a code point, so the boundaries come for free."""
        m = self.start_mint()
        for code in ("d800", "dbff", "dc00", "dfff"):
            with self.subTest(code=code):
                status, body = self.raw_post(
                    m.port, "/v3/operator/register",
                    b'{"operator_name": "op\\u' + code.encode() + b'"}',
                    {"X-Admin-Token": ADMIN_TOKEN},
                )
                self.assert_enumerated(status, body, {"bad_format"})
        self.assertEqual(
            self.sup_rows(m, "SELECT COUNT(*) FROM sup_operators")[0][0], 0
        )

    def test_a_paired_surrogate_is_an_ordinary_name(self):
        """The refusal is about what cannot be ENCODED, not about the
        escape syntax: a well-formed pair is an ordinary astral character
        and an ordinary name."""
        m = self.start_mint()
        status, body = self.raw_post(
            m.port, "/v3/operator/register",
            b'{"operator_name": "rocket \\ud83d\\ude80"}',
            {"X-Admin-Token": ADMIN_TOKEN},
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(
            self.sup_rows(m, "SELECT name FROM sup_operators")[0][0],
            "rocket \U0001f680",
        )

    # -- finding 2: an operator name nobody bounded ----------------------

    def test_a_five_thousand_character_operator_name_is_refused(self):
        m = self.start_mint()
        status, r = api(
            m.port, "POST", "/v3/operator/register",
            {"operator_name": self.LONG},
        )
        self.assertEqual(status, 400, r)
        self.assertEqual(r["reason"], "bad_format", r)
        self.assertEqual(
            self.sup_rows(m, "SELECT COUNT(*) FROM sup_operators")[0][0], 0
        )

    def test_the_bound_is_exact_and_an_ordinary_name_still_works(self):
        """A bound that also refused a real name would be worse than the
        defect, so both sides of it are driven."""
        m = self.start_mint()
        status, r = api(
            m.port, "POST", "/v3/operator/register",
            {"operator_name": "x" * MAX_TEXT_LEN},
        )
        self.assertEqual(status, 200, r)
        status, r = api(
            m.port, "POST", "/v3/operator/register",
            {"operator_name": "x" * (MAX_TEXT_LEN + 1)},
        )
        self.assertEqual(status, 400, r)
        self.assertEqual(r["reason"], "bad_format", r)

    # -- the sweep: the two findings were a sample -----------------------

    def test_no_caller_string_anywhere_answers_a_bare_500(self):
        """Every caller-supplied string this module stores, echoes or
        looks a row up by, with both values. The reported route is two
        rows of this table."""
        m = self.start_mint()
        op_id, op_key = self.new_operator(m)
        ag_id, ag_key = self.new_agent(m, op_key)
        ag2_id, _ = self.new_agent(m, op_key, name="a2")

        def body(field, value_json, extra=b""):
            return b"{" + extra + b'"' + field + b'": ' + value_json + b"}"

        cases = [
            # (label, path, body bytes builder, headers)
            ("operator_name", "/v3/operator/register", b"operator_name", b"",
             {"X-Admin-Token": ADMIN_TOKEN}),
            ("agent_name", "/v3/operator/agents", b"agent_name", b"",
             {"Authorization": "Bearer " + op_key}),
            ("caps agent_id", "/v3/operator/caps", b"agent_id", b"",
             {"Authorization": "Bearer " + op_key}),
            ("freeze agent_id", "/v3/operator/freeze", b"agent_id", b"",
             {"Authorization": "Bearer " + op_key}),
            ("unfreeze agent_id", "/v3/operator/unfreeze", b"agent_id", b"",
             {"Authorization": "Bearer " + op_key}),
            ("flags agent_id", "/v3/operator/flags", b"agent_id",
             b'"no_bearer_withdrawal": true, ',
             {"Authorization": "Bearer " + op_key}),
            ("authorize_pull payee", "/v3/agent/authorize_pull",
             b"payee_account",
             b'"cap_mc_per_day": 10, "expires_at": 99999999999999, ',
             {"Authorization": "Bearer " + ag_key}),
            ("revoke_pull auth_id", "/v3/agent/revoke_pull", b"auth_id", b"",
             {"Authorization": "Bearer " + ag_key}),
            ("pull auth_id", "/v3/pull", b"auth_id", b'"amount_mc": 1, ',
             {"Authorization": "Bearer " + ag_key}),
            ("pull ref", "/v3/pull", b"ref",
             b'"auth_id": "auth-x", "amount_mc": 1, ',
             {"Authorization": "Bearer " + ag_key}),
            ("transfer to_account", "/v3/agent/transfer", b"to_account",
             b'"amount_mc": 1, ',
             {"Authorization": "Bearer " + ag_key}),
            ("transfer ref", "/v3/agent/transfer", b"ref",
             ('"to_account": "%s", "amount_mc": 1, ' % ag2_id).encode(),
             {"Authorization": "Bearer " + ag_key}),
            ("deposit ref", "/v3/agent/deposit", b"ref",
             b'"tokens": ["v3:testmint:1:AAAA"], ',
             {"Authorization": "Bearer " + ag_key}),
        ]
        long_json = ('"%s"' % self.LONG).encode()
        for label, path, field, extra, headers in cases:
            for kind, value_json in (("surrogate", self.SURROGATE_JSON),
                                     ("5000 chars", long_json),
                                     ("NUL", self.NUL_JSON),
                                     ("LF", b'"a\\nb"'),
                                     ("ESC", b'"a\\u001bb"'),
                                     ("DEL", b'"a\\u007fb"'),
                                     ("U+2028", b'"a\\u2028b"'),
                                     ("RLO", b'"a\\u202eb"')):
                with self.subTest(field=label, value=kind):
                    status, parsed = self.raw_post(
                        m.port, path, body(field, value_json, extra), headers
                    )
                    self.assert_enumerated(status, parsed)

    def test_a_ref_that_cannot_be_rendered_never_reaches_a_statement(self):
        """`ref` is the field that really does surface from the response
        encoder: it is stored on BOTH journal lines of a transfer and
        re-rendered inside every signed statement that covers them, so one
        accepted value poisons a read path the caller never touches again.
        """
        m = self.start_mint()
        op_id, op_key = self.new_operator(m)
        ag_id, ag_key = self.new_agent(m, op_key)
        ag2_id, _ = self.new_agent(m, op_key, name="payee")
        self.fund(m, ag_key, 100_000)

        status, parsed = self.raw_post(
            m.port, "/v3/agent/transfer",
            ('{"to_account": "%s", "amount_mc": 10, "ref": ' % ag2_id).encode()
            + self.SURROGATE_JSON + b"}",
            {"Authorization": "Bearer " + ag_key},
        )
        self.assert_enumerated(status, parsed, {"bad_format"})
        status, r = api(
            m.port, "POST", "/v3/agent/transfer",
            {"to_account": ag2_id, "amount_mc": 10, "ref": self.LONG},
            key=ag_key,
        )
        self.assertEqual(status, 400, r)
        self.assertEqual(r["reason"], "bad_format", r)
        # No journal line carries either of them...
        refs = [row[0] for row in
                self.sup_rows(m, "SELECT ref FROM sup_lines")]
        for ref in refs:
            self.assertLessEqual(len(ref), MAX_TEXT_LEN, refs)
        # ...and the statement that renders them still renders.
        status, statement = api(
            m.port, "GET", "/v3/operator/statement?from=0&to=99999999999999",
            key=op_key,
        )
        self.assertEqual(status, 200, statement)
        json.dumps(statement).encode("utf-8")  # must not raise

    def test_an_ordinary_ref_still_rides_through_to_the_statement(self):
        m = self.start_mint()
        op_id, op_key = self.new_operator(m)
        ag_id, ag_key = self.new_agent(m, op_key)
        ag2_id, _ = self.new_agent(m, op_key, name="payee")
        self.fund(m, ag_key, 100_000)
        status, r = api(
            m.port, "POST", "/v3/agent/transfer",
            {"to_account": ag2_id, "amount_mc": 10, "ref": "invoice-42 ☕"},
            key=ag_key,
        )
        self.assertEqual(status, 200, r)
        status, statement = api(
            m.port, "GET", "/v3/operator/statement?from=0&to=99999999999999",
            key=op_key,
        )
        self.assertEqual(status, 200, statement)
        self.assertIn(
            "invoice-42 ☕",
            [line["ref"] for line in statement["lines"]],
        )

    def test_an_id_this_mint_cannot_render_is_simply_not_found(self):
        """The unguarded lookup that made seven routes 500. An id the mint
        cannot encode is an id it cannot be holding, so `unknown_agent` is
        the TRUE answer and not merely a quieter one — and it is the same
        answer another operator's real agent gets, so nothing new leaks."""
        m = self.start_mint()
        op_id, op_key = self.new_operator(m)
        for path, extra in (
            ("/v3/operator/caps", b""),
            ("/v3/operator/freeze", b""),
            ("/v3/operator/unfreeze", b""),
            ("/v3/operator/flags", b'"no_bearer_withdrawal": true, '),
        ):
            with self.subTest(path=path):
                status, parsed = self.raw_post(
                    m.port, path,
                    b"{" + extra + b'"agent_id": ' + self.SURROGATE_JSON + b"}",
                    {"Authorization": "Bearer " + op_key},
                )
                self.assertEqual(status, 404, parsed)
                self.assertEqual(parsed["reason"], "unknown_agent", parsed)

    def test_a_query_parameter_is_a_caller_string_too(self):
        """Same class, different door: `?agent_id=` is percent-decoded by
        the stdlib and handed to the same lookup.

        A NEIGHBOURING DOOR, AND SOUND BEFORE THIS ROUND AS WELL — said
        here so nobody counts these ten cells as certification of the
        renderability clause. Measured with the clause reverted at
        runtime: every row below still answers exactly as it does now.
        That is not an accident and it is not luck about which values
        were tried — this parameter is only ever LOOKED UP, never stored
        and never echoed, and an id the mint cannot render is an id it
        cannot be holding, so `unknown_agent` is the true answer with or
        without `isprintable()` (the surrogate row is the exception: it
        was a bare 500 from the sqlite binding before `_agent` grew its
        guard, which is the PREVIOUS round's clause, certified in
        `test_an_id_this_mint_cannot_render_is_simply_not_found`).
        The clause this round added is certified where the string is
        STORED or SIGNED: the two name routes, the three `ref` routes and
        the whole-document statement invariant, each of which fails when
        it is reverted.

        What this test is for, then, is the two properties that could
        stop being true here: no 5xx from an unguarded lookup, and no
        echo — the refusal carries `status` and `reason` and nothing
        else, so no caller-chosen octet comes back out through the error
        path either.
        """
        m = self.start_mint()
        op_id, op_key = self.new_operator(m)
        for query in ("agent_id=%ED%A0%80x", "agent_id=" + "A" * 5000,
                      # the third finding, through the query door: a
                      # percent-encoded NUL, ESC and line separator are
                      # decoded by the stdlib into the same unrenderable
                      # string the body routes refuse.
                      "agent_id=a%00b", "agent_id=a%1Bb",
                      "agent_id=a%E2%80%A8b"):
            for path in ("/v3/agent/balance",
                         "/v3/operator/statement?from=0&to=9&"):
                with self.subTest(query=query[:20], path=path):
                    sep = "" if path.endswith("&") else "?"
                    status, parsed = api(
                        m.port, "GET", path + sep + query, key=op_key
                    )
                    self.assertLess(status, 500, parsed)
                    self.assertEqual(parsed["status"], "rejected", parsed)
                    self.assertEqual(
                        set(parsed), {"status", "reason"},
                        "the refusal grew a field that could carry the"
                        " caller's own string back out: %r" % (parsed,))

    # -- the predicate, so the next field inherits it --------------------

    def test_the_rule_is_one_predicate_about_the_value(self):
        """`_plain_text` is to strings what `_plain_int` is to integers:
        the chokepoint, stated about the VALUE, so a field added later is
        covered by writing one call and not one rule.

        `"line\\nbreak"` and `"\\x00null"` used to sit in the GOOD column
        of this very table, which is how a green suite came to certify an
        open door: the two values the next reviewer drove over a raw
        socket were the two this test asserted were fine. They are BAD
        rows now — the table grew, it did not shrink.
        """
        for good in ("a", "", "x" * MAX_TEXT_LEN, "☕", "\U0001f680",
                     "invoice-42 ☕", "  leading and trailing  ",
                     "é combining"):
            self.assertTrue(supervision._plain_text(good), repr(good))
        for bad in ("x" * (MAX_TEXT_LEN + 1), "\ud800", "a\udfffb",
                    b"bytes", 5, None, True, ["a"],
                    # the reported value, and the class it is one of
                    "\x00null", "line\nbreak", "carriage\rreturn",
                    "tab\tstop", "bell\a", "esc\x1b[31m", "del\x7f",
                    "nel\x85", "linesep ", "parasep ",
                    "rlo‮", "zwsp​", "nbsp ",
                    "privateuse", "unassigned\U000e0001"):
            self.assertFalse(supervision._plain_text(bad), repr(bad))

    def test_the_predicate_asks_by_encoding_not_by_recognising(self):
        """It must fail exactly where the downstream operations fail —
        the sqlite binding and the response encoder both do
        ``str.encode('utf-8')`` — rather than by matching a shape.

        THIS CERTIFIES THE PREVIOUS ROUND'S CLAUSE (the unpaired
        surrogate), not this one: it passes with `isprintable()`
        reverted, because a lone surrogate is refused by the encode
        clause beside it. Kept, and named, so the count of green tests in
        this block is not read as the count of tests that bite."""
        for candidate in ("\ud800", "\udfff", "a\ud800b", "\ud800\ud800"):
            with self.subTest(candidate=repr(candidate)):
                self.assertFalse(supervision._plain_text(candidate))
                with self.assertRaises(UnicodeEncodeError):
                    candidate.encode("utf-8")
        source = inspect.getsource(supervision._plain_text)
        self.assertIn('encode("utf-8")', source)
        # NOT a list of code points — that is the shape that has already
        # been wrong three times in this repository.
        self.assertNotIn("0xD800", source.upper())
        self.assertNotIn("SURROGATEPASS", source.upper())

    # ------------------------------------------------------------------ #
    # Finding 3: a name that encodes but does not RENDER                  #
    # ------------------------------------------------------------------ #
    #
    # Reported as one value on two routes: `operator_name` and `agent_name`
    # carrying a NUL answered 200 and created the account. The predicate
    # above already asked "can this be encoded" and "is this bounded", and
    # a NUL passes both -- `"acme\x00evil"` is nine UTF-8 bytes and well
    # under the bound. Encodability is a question about bytes; what a
    # stored, echoed, re-rendered label needs is a question about a string.
    #
    # The sweep below is not the reported value plus a few neighbours. It
    # is the three requirements such a string actually has -- bounded,
    # encodable, renders-and-forges-no-structure -- asked of every
    # caller-supplied string this module stores or echoes. The two the
    # reviewer tried are two rows of it.
    #
    # NOTE ON THE SUITE THAT CERTIFIED THIS: the value driven over a raw
    # socket to find this finding was, at the time, asserted GOOD by name
    # in `test_the_rule_is_one_predicate_about_the_value` -- `"\x00null"`
    # sat in that test's happy column, with `"line\nbreak"` beside it. A
    # green suite over the wrong shape reads as coverage, which is worse
    # than no suite. Those rows are in that test's BAD column now, and the
    # table below is here as well: the class, over HTTP, on the routes,
    # not only at the predicate, because a predicate-level assertion is
    # what was wrong and a predicate-level assertion cannot notice that.

    def test_a_nul_in_an_operator_name_creates_no_operator(self):
        """The reported value, on the reported route, over a raw socket.

        Reverted, this is 200 with a live `operator_key` and a row whose
        name no terminal, log or report can display as written."""
        m = self.start_mint()
        status, body = self.raw_post(
            m.port, "/v3/operator/register",
            b'{"operator_name": ' + self.NUL_JSON + b"}",
            {"X-Admin-Token": ADMIN_TOKEN},
        )
        self.assert_enumerated(status, body, {"bad_format"})
        self.assertEqual(status, 400, body)
        self.assertNotIn("operator_key", body)
        self.assertEqual(
            self.sup_rows(m, "SELECT COUNT(*) FROM sup_operators")[0][0], 0
        )

    def test_a_nul_in_an_agent_name_creates_no_agent(self):
        """The reported value on the second reported route. Same column,
        same rule, and the agent is the principal a statement audits."""
        m = self.start_mint()
        _op_id, op_key = self.new_operator(m)
        status, body = self.raw_post(
            m.port, "/v3/operator/agents",
            b'{"agent_name": ' + self.NUL_JSON + b"}",
            {"Authorization": "Bearer " + op_key},
        )
        self.assert_enumerated(status, body, {"bad_format"})
        self.assertEqual(status, 400, body)
        self.assertNotIn("agent_key", body)
        self.assertEqual(
            self.sup_rows(m, "SELECT COUNT(*) FROM sup_agents")[0][0], 0
        )

    def test_the_whole_unrenderable_class_is_refused_on_both_names(self):
        """NUL was one spelling. The rule is about what a code point IS,
        so every family of it goes the same way: the C0 controls, DEL, the
        C1 range, the line and paragraph separators, the non-ASCII spaces,
        the bidi overrides, the zero-width format characters and the
        private-use area. Every one of these returned 200 before the fix.
        """
        m = self.start_mint()
        _op_id, op_key = self.new_operator(m, name="fleet")
        for label, esc in self.UNRENDERABLE.items():
            for route, field, headers in (
                ("/v3/operator/register", b"operator_name",
                 {"X-Admin-Token": ADMIN_TOKEN}),
                ("/v3/operator/agents", b"agent_name",
                 {"Authorization": "Bearer " + op_key}),
            ):
                with self.subTest(char=label, route=route):
                    status, body = self.raw_post(
                        m.port, route,
                        b'{"' + field + b'": "a' + esc + b'b"}', headers,
                    )
                    self.assert_enumerated(status, body, {"bad_format"})
        # Exactly the one operator this test made on purpose, and no agent.
        self.assertEqual(
            self.sup_rows(m, "SELECT COUNT(*) FROM sup_operators")[0][0], 1
        )
        self.assertEqual(
            self.sup_rows(m, "SELECT COUNT(*) FROM sup_agents")[0][0], 0
        )

    def test_real_names_still_register(self):
        """The other side of the rule, and the reason it is `isprintable`
        and not an ASCII allow-list: a bound that refused ordinary
        operator names would be a worse defect than the one it closes.

        AN OVER-REFUSAL GUARD, NOT A CERTIFICATION, and it passes with
        this round's clause reverted BY CONSTRUCTION — every name here is
        one both predicates accept. It is worth keeping for exactly that
        reason (the narrowing costs these names nothing, and a future
        clause that ate them would be caught here), and it is labelled so
        a reader counting green tests does not count it as coverage of
        the defect. The cells that fail when the clause is reverted are
        the two name routes, the three `ref` routes,
        `test_provision_operator_holds_the_route_s_name_rule` and the
        whole-document statement invariant."""
        m = self.start_mint()
        for label, name_json in self.RENDERABLE.items():
            with self.subTest(name=label):
                status, body = self.raw_post(
                    m.port, "/v3/operator/register",
                    b'{"operator_name": "' + name_json + b'"}',
                    {"X-Admin-Token": ADMIN_TOKEN},
                )
                self.assertEqual(status, 200, body)
                self.assertIn("operator_key", body)
        self.assertEqual(
            self.sup_rows(m, "SELECT COUNT(*) FROM sup_operators")[0][0],
            len(self.RENDERABLE),
        )
        # And what was stored is what was sent: a space is a space, a
        # surrogate PAIR is one astral character, a combining mark stays.
        stored = {row[0] for row in
                  self.sup_rows(m, "SELECT name FROM sup_operators")}
        self.assertIn("ACME Operations, Inc.", stored)
        self.assertIn("rocket \U0001f680", stored)
        self.assertIn("équipe", stored)

    # -- the signature-bearing path -------------------------------------

    def test_a_control_character_ref_never_reaches_a_signed_statement(self):
        """`ref` is the ONLY caller-supplied string in this module that is
        re-rendered inside a signed document, and its author is the agent
        the document audits.

        That is what makes this row of the sweep different in kind from
        the two that were reported. An operator name is stored and read
        back by the operator who chose it; a `ref` is written by the
        agent, copied onto BOTH journal lines of the transfer, and
        re-rendered inside every statement the mint signs over that
        period, for as long as the journal is retained. A signature over
        a document whose text the audited party chose is worth less if
        that text can carry an ESC sequence into the reader's terminal or
        a line separator into a line-oriented export.

        Reverted, the statement below comes back signed with
        `"ref":"r\\u0000x\\ne"` inside it, twice.
        """
        m = self.start_mint()
        op_id, op_key = self.new_operator(m)
        ag_id, ag_key = self.new_agent(m, op_key)
        ag2_id, _ = self.new_agent(m, op_key, name="payee")
        self.fund(m, ag_key, 100_000)

        for label, esc in self.UNRENDERABLE.items():
            with self.subTest(char=label):
                status, body = self.raw_post(
                    m.port, "/v3/agent/transfer",
                    ('{"to_account": "%s", "amount_mc": 10, "ref": "r'
                     % ag2_id).encode() + esc + b'x"}',
                    {"Authorization": "Bearer " + ag_key},
                )
                self.assert_enumerated(status, body, {"bad_format"})

        # Nothing was debited by any of them...
        self.assertEqual(self.balance(m, ag_key)["balance_mc"], 100_000)
        # ...no journal line carries one...
        for (ref,) in self.sup_rows(m, "SELECT ref FROM sup_lines"):
            self.assertTrue(ref.isprintable(), repr(ref))
        # ...and the signed statement is renderable text throughout.
        status, stmt = self.statement(m, op_key, 0, 99999999999999)
        self.assertEqual(status, 200, stmt)
        self.check_statement(m, stmt, op_id, "fleet")
        self.assert_statement_is_renderable(stmt)

    def test_the_same_holds_for_a_pull_ref_and_a_deposit_ref(self):
        """`ref` reaches the journal from three routes, not one. The
        reported finding was a field on two routes and the field it most
        matters for is on three."""
        m = self.start_mint()
        op_id, op_key = self.new_operator(m)
        g_id, g_key = self.new_agent(m, op_key, "granter")
        p_id, p_key = self.new_agent(m, op_key, "payee")
        self.fund(m, g_key, 100_000)
        status, r = api(
            m.port, "POST", "/v3/agent/authorize_pull",
            {"payee_account": p_id, "cap_mc_per_day": 10_000,
             "expires_at": T0 + DAY_MS},
            key=g_key,
        )
        self.assertEqual(status, 200, r)
        auth_id = r["auth_id"]

        token = self.issue_token(m, 1_000)
        cases = [
            ("/v3/pull",
             ('{"auth_id": "%s", "amount_mc": 5, "ref": "p' % auth_id).encode(),
             p_key),
            ("/v3/agent/deposit",
             ('{"tokens": ["%s"], "ref": "d' % token).encode(),
             g_key),
        ]
        for path, prefix, key in cases:
            for label, esc in self.UNRENDERABLE.items():
                with self.subTest(path=path, char=label):
                    status, body = self.raw_post(
                        m.port, path, prefix + esc + b'x"}',
                        {"Authorization": "Bearer " + key},
                    )
                    self.assert_enumerated(status, body, {"bad_format"})
        for (ref,) in self.sup_rows(m, "SELECT ref FROM sup_lines"):
            self.assertTrue(ref.isprintable(), repr(ref))
        # The token the deposit attempts named is still unspent: a refusal
        # on the way in never touched the ledger.
        status, entry = api(m.port, "GET", "/v3/status/" + ledger_key(
            b64u_decode(token.rsplit(":", 1)[1], expect_len=32)))
        self.assertEqual(entry["result"]["state"], "unspent", entry)

    def test_an_ordinary_ref_with_spaces_still_rides_to_the_statement(self):
        """The bound must not eat a real payment reference.

        OVER-REFUSAL GUARD, like `test_real_names_still_register`: this
        `ref` is renderable, so it passes with this round's clause
        reverted too. It is here because `isprintable()` IS a narrowing —
        ZWJ emoji sequences, NBSP and TAB are refused by it — and the
        line between "a label" and "a document" has to be held from both
        sides. It certifies nothing about the defect."""
        m = self.start_mint()
        op_id, op_key = self.new_operator(m)
        ag_id, ag_key = self.new_agent(m, op_key)
        ag2_id, _ = self.new_agent(m, op_key, name="payee")
        self.fund(m, ag_key, 100_000)
        ref = "INV #42 — Société Générale ☕"
        status, r = self.transfer(m, ag_key, ag2_id, 10, ref=ref)
        self.assertEqual(status, 200, r)
        status, stmt = self.statement(m, op_key, 0, 99999999999999)
        self.assertEqual(status, 200, stmt)
        self.assertIn(ref, [ln["ref"] for ln in stmt["lines"]])
        self.assert_statement_is_renderable(stmt)

    def test_every_string_a_signature_covers_is_renderable_text(self):
        """The invariant, stated once over the whole document rather than
        field by field, so a statement field added later is covered.

        A scripted run with the hostile values attempted at every door
        that can write one, then: every string anywhere in the signed
        statement renders, and the signature still verifies."""
        m = self.start_mint()
        op_id, op_key = self.new_operator(m)
        a_id, a_key = self.new_agent(m, op_key, "worker")
        b_id, b_key = self.new_agent(m, op_key, "treasury")
        self.fund(m, a_key, 100_000)
        for esc in self.UNRENDERABLE.values():
            self.raw_post(
                m.port, "/v3/operator/agents",
                b'{"agent_name": "x' + esc + b'y"}',
                {"Authorization": "Bearer " + op_key})
            self.raw_post(
                m.port, "/v3/agent/transfer",
                ('{"to_account": "%s", "amount_mc": 1, "ref": "x' % b_id
                 ).encode() + esc + b'y"}',
                {"Authorization": "Bearer " + a_key})
        # A few real moves so the statement is not empty.
        self.assertEqual(self.transfer(m, a_key, b_id, 25, ref="ok-1")[0], 200)
        self.assertEqual(api(m.port, "POST", "/v3/operator/freeze",
                             {"agent_id": a_id}, key=op_key)[0], 200)
        status, stmt = self.statement(m, op_key, 0, 99999999999999)
        self.assertEqual(status, 200, stmt)
        self.check_statement(m, stmt, op_id, "fleet")   # includes the signature
        self.assert_statement_is_renderable(stmt)
        self.assertIn("ok-1", [ln["ref"] for ln in stmt["lines"]])

    # -- the out-of-band door writes the same column --------------------

    def test_provision_operator_holds_the_route_s_name_rule(self):
        """`provision_operator` is in-process, so it needs no credential —
        but it writes `sup_operators.name`, and the reason that column has
        a rule is a property of the column, not of who was trusted. It
        checked `isinstance(str) and non-empty` while the route ran the
        predicate, which made `run_mint.py --provision-operator` a way in
        for exactly the values the route refuses."""
        m = self.start_mint()
        for bad in ("acme\x00evil", "line\nbreak", "esc\x1b[31m",
                    "rlo‮", "\ud800", "x" * (MAX_TEXT_LEN + 1)):
            with self.subTest(name=repr(bad)):
                with self.assertRaises(ValueError):
                    m.server.provision_operator(bad)
        with self.assertRaises(ValueError):
            m.server.provision_operator("")
        self.assertEqual(
            self.sup_rows(m, "SELECT COUNT(*) FROM sup_operators")[0][0], 0
        )
        # ...and it still provisions a real one.
        op_id, op_key = m.server.provision_operator("ACME Operations ☕")
        self.assertTrue(op_id.startswith("op-"))
        self.assertEqual(
            self.sup_rows(m, "SELECT name FROM sup_operators")[0][0],
            "ACME Operations ☕",
        )

    def test_the_predicate_covers_all_three_requirements_it_is_named_for(self):
        """Bounded, encodable, renderable — one value per requirement,
        each violating exactly ONE of the three, driven at a route that
        writes a row, against the predicate this round REPLACED.

        WHAT THIS TEST USED TO DO, and why it was rewritten: it computed
        "bounded", "encodable" and "renderable" with ``len(v) <=
        MAX_TEXT_LEN``, ``v.encode("utf-8")`` and ``v.isprintable()`` —
        the same three expressions the implementation ANDs — asserted
        that ``_plain_text`` equalled their conjunction, and then grepped
        ``inspect.getsource`` for the string ``isprintable()``. The first
        half is a restatement of the code in the code's own terms: it
        holds for any implementation that ANDs those three, and fails for
        none that does not, because it recomputes rather than knows. The
        second half pins the implementation's SHAPE, so it also goes
        green on a predicate that calls ``isprintable()`` and ignores the
        answer. Neither half is behaviour.

        THE CONTROL IS THE OLD PREDICATE. ``two_of_three`` below is what
        this module enforced before this round — bounded and encodable,
        no third clause — written out here rather than imported, because
        the only honest way to show a clause is load-bearing is to show a
        value the clause refuses and the predicate without it accepts.
        The renderable row is that value: ``two_of_three`` says yes, the
        mint says ``400 bad_format`` and stores nothing. Reverted, it is
        ``200 OK`` with a live ``operator_key``.
        """
        m = self.start_mint()

        def two_of_three(v):
            if type(v) is not str or len(v) > MAX_TEXT_LEN:
                return False
            try:
                v.encode("utf-8")
            except UnicodeEncodeError:
                return False
            return True

        cases = (
            # requirement, value, its JSON source, accepted by the old
            # two-clause predicate?
            ("bounded", self.LONG,
             b'"' + self.LONG.encode() + b'"', False),
            ("encodable", "bad\ud800name", self.SURROGATE_JSON, False),
            ("renderable", "acme\x00evil", self.NUL_JSON, True),
        )
        for requirement, value, value_json, old_verdict in cases:
            with self.subTest(requirement=requirement):
                # Exactly one clause refuses it, and the whole predicate
                # does. (Stated as the predicate's ANSWER, not as its
                # arithmetic re-run beside it.)
                self.assertFalse(supervision._plain_text(value), repr(value))
                self.assertEqual(
                    two_of_three(value), old_verdict,
                    "%s: the control predicate no longer separates this"
                    " row" % requirement)
                # At the route, over a raw socket, on a name that would
                # be stored: an enumerated refusal and no row.
                status, body = self.raw_post(
                    m.port, "/v3/operator/register",
                    b'{"operator_name": ' + value_json + b"}",
                    {"X-Admin-Token": ADMIN_TOKEN},
                )
                self.assert_enumerated(status, body, {"bad_format"})
                self.assertEqual(status, 400, body)
                self.assertNotIn("operator_key", body, body)
                self.assertEqual(
                    self.sup_rows(
                        m, "SELECT COUNT(*) FROM sup_operators")[0][0],
                    0, requirement)

        # And the clause the control accepts is the one this round added:
        # every unrenderable family, not just the NUL that was reported.
        for label, esc in self.UNRENDERABLE.items():
            with self.subTest(family=label):
                value = json.loads(b'"x' + esc + b'y"')
                self.assertTrue(two_of_three(value), repr(value))
                self.assertFalse(supervision._plain_text(value), repr(value))

    def test_the_mint_keeps_serving_after_every_refusal(self):
        """A refusal is not a wound."""
        m = self.start_mint()
        for _ in range(3):
            self.raw_post(
                m.port, "/v3/operator/register",
                b'{"operator_name": ' + self.SURROGATE_JSON + b"}",
                {"X-Admin-Token": ADMIN_TOKEN},
            )
        op_id, op_key = self.new_operator(m, name="after")
        self.assertTrue(op_id.startswith("op-"))

class SupervisionStartupTest(unittest.TestCase):
    """A Supervision Profile mint must start exactly like a plain C06 mint.

    ``SupervisionServer.start`` binds its own socket instead of calling
    ``super().start()``, and it used to bind WITHOUT first taking the
    single-writer claim on the ledger. That did not break a lone mint: the
    claim is lazy and idempotent, so ``_Core.descriptor`` took it at the
    first fetch and everything served correctly. What it broke was
    FAIL-FAST. Between the bind and the first descriptor there is a window
    in which another process can take the claim; after that this mint is
    bound and serving but can never sign a snapshot again — every
    ``GET /v3/mints`` is a 500, forever — where a plain C06 mint would have
    refused to come up at all. One line, in the same place C06 has it.
    """

    def build(self, db_path, clock=None):
        """An UNSTARTED SupervisionServer over `db_path`."""
        priv, pub = generate_keypair()
        ledger = Ledger(
            db_path,
            clock or FakeClock(T0),
            NO_BURN,
            recovery_window_ms=90 * DAY_MS,
            max_lock_expiry_ms=30 * DAY_MS,
        )
        config = MintConfig(
            mint_id=MINT_ID,
            baseline_model_class="frontier-2026",
            burn_policy=NO_BURN,
            signing_private=priv,
            signing_public=pub,
            # This harness never issues; it only contends for the ledger file.
            admin_token=ADMIN_ISSUANCE_DISABLED,
        )
        server = SupervisionServer(config, ledger)
        self.addCleanup(server.stop)
        return server

    def shared_ledger(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        return os.path.join(tmp.name, "ledger.sqlite3")

    def test_supervision_mint_refuses_to_start_when_the_ledger_is_held(self):
        """The deployment slip this has to survive: two mint processes on
        one ledger file, bound to different ports (a port collision is the
        only clash a launcher can see by itself). The second must fail at
        the door, not serve a mint that cannot sign."""
        db_path = self.shared_ledger()
        holder = self.build(db_path)
        holder.start()
        second = self.build(db_path)
        with self.assertRaises(RuntimeError) as caught:
            second.start()
        self.assertIn("ledger", str(caught.exception).lower())
        # Refused BEFORE the bind: no socket, no serving thread, no port.
        self.assertIsNone(second._httpd)
        self.assertIsNone(second._thread)
        # The mint that does hold the ledger is untouched.
        status, desc = api(holder._httpd.server_address[1], "GET", "/v3/mints")
        self.assertEqual(status, 200)
        self.assertIn("supervision", desc["profiles"])

    def test_a_held_supervision_mint_is_refused_by_a_plain_c06_mint_too(self):
        """The claim is over the LEDGER, not over a server class: a plain
        C06 mint must not be able to take a ledger a supervision mint is
        serving, or the profile would be a hole in the guarantee."""
        db_path = self.shared_ledger()
        holder = self.build(db_path)
        holder.start()
        priv, pub = generate_keypair()
        ledger = Ledger(
            db_path,
            FakeClock(T0),
            NO_BURN,
            recovery_window_ms=90 * DAY_MS,
            max_lock_expiry_ms=30 * DAY_MS,
        )
        plain = MintServer(
            MintConfig(
                mint_id=MINT_ID,
                baseline_model_class="frontier-2026",
                burn_policy=NO_BURN,
                signing_private=priv,
                signing_public=pub,
                admin_token=ADMIN_ISSUANCE_DISABLED,
            ),
            ledger,
        )
        self.addCleanup(plain.stop)
        with self.assertRaises(RuntimeError):
            plain.start()

    def test_a_stopped_supervision_mint_hands_the_ledger_back(self):
        """Claiming at start() must not turn a restart into an outage: the
        successor takes the ledger once the holder is stopped."""
        db_path = self.shared_ledger()
        holder = self.build(db_path)
        holder.start()
        second = self.build(db_path)
        with self.assertRaises(RuntimeError):
            second.start()
        holder.stop()
        port = second.start()  # must not raise now
        status, desc = api(port, "GET", "/v3/mints")
        self.assertEqual(status, 200)
        self.assertEqual(desc["mint_id"], MINT_ID)


class BodyCapParityTest(unittest.TestCase):
    """C10's body cap is C06's number, not a second one that looks like it.

    ``_MAX_BODY_BYTES`` was written out independently (``1 << 20`` against
    C06's ``1_048_576``) and nothing tied them together, so retuning one
    would have moved the supervision routes' bound away from Layer 0's
    silently. The READERS stay separate on purpose — C06 and C10 answer a
    refused body with different envelopes (L13/B9) — so only the number is
    shared.

    Note on what each test here is worth. The two equality tests below are
    guards against FUTURE drift: because ``1 << 20 == 1_048_576`` they pass
    against the two independent literals as well, so they cannot tell the
    fix from the bug. ``test_the_c10_cap_is_derived_not_copied`` is the one
    that can, and it fails on the pre-fix file.
    """

    def test_the_two_caps_are_one_number(self):
        self.assertEqual(supervision._MAX_BODY_BYTES, mintapi.MAX_BODY_BYTES)

    def test_the_c10_cap_is_derived_not_copied(self):
        """One number with one SOURCE, not two numbers that happen to be
        equal today.

        The equality tests cannot see the difference: the old literal
        ``1 << 20`` equals C06's ``1_048_576``, so they pass either way.
        This retunes C06's cap and re-executes supervision.py's module body
        against it — the import a redeployed mint with a retuned cap would
        do. Derived, C10's cap is the retuned number; copied, it is still
        1 MiB and this fails. Run in a subprocess because a reload would
        leave this process with rebound C10 classes that every other test
        in the file would then be running against.
        """
        impl = os.path.dirname(os.path.dirname(os.path.abspath(
            supervision.__file__)))
        retuned = 3_145_728  # 3 MiB: nothing in either module is this
        self.assertNotEqual(retuned, mintapi.MAX_BODY_BYTES)
        env = dict(os.environ, PYTHONPATH=impl)
        proc = subprocess.run(
            [
                sys.executable,
                "-c",
                "import importlib\n"
                "from aicash import mintapi, supervision\n"
                "mintapi.MAX_BODY_BYTES = %d\n"
                "importlib.reload(supervision)\n"
                "print(supervision._MAX_BODY_BYTES)\n" % retuned,
            ],
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(int(proc.stdout.strip()), retuned, proc.stdout)

    def test_the_c10_cap_does_not_follow_c06_at_runtime(self):
        """Derived at IMPORT, deliberately not a live alias.

        Four tests above prove C10 enforces its own bound by raising
        ``mintapi.MAX_BODY_BYTES`` out of reach for the duration of a test.
        A cap that tracked C06's attribute at request time would rise with
        it and those tests would go vacuous — they would pass with C10's
        guard deleted. This pins the property they depend on.
        """
        original = mintapi.MAX_BODY_BYTES
        mintapi.MAX_BODY_BYTES = 1 << 40
        try:
            self.assertEqual(supervision._MAX_BODY_BYTES, original)
        finally:
            mintapi.MAX_BODY_BYTES = original

    def test_the_readers_were_not_merged(self):
        """C10's cap lives on its own reader, and C06's reader is C06's.

        If ``_read_sup_json`` ever became an override of ``_read_json``,
        the inherited Layer 0 routes would start answering with C10's error
        envelope for the same wire bytes — which L13/B9 forbid.

        A structural guard, and it holds on the unmodified file too — but
        it is not redundant with the behavioural comparison. I checked:
        with an override actually installed
        (``_read_json = lambda self: self._read_sup_json()``),
        ``test_layer0_body_refusals_match_a_plain_c06_mint`` still PASSES,
        because both readers return the same ``(None, False)`` and C06's
        ``do_POST`` picks the §3.8 reason either way — and because the two
        caps are equal today, so the bound Layer 0 got would be the same
        number. What a merge really changes is WHICH constant bounds Layer
        0 (``_MAX_BODY_BYTES`` instead of ``MAX_BODY_BYTES``): invisible
        now, an L13/B9 break the moment either moves. That is the drift
        this whole class exists for, and this is the test that sees it.

        Checked by identity across the WHOLE MRO, so an override installed
        by assignment, by a mixin, or on any base between the two classes
        is caught — not only one written into _SupHandler's own body.
        """
        self.assertIs(
            supervision._SupHandler._read_json, mintapi._Handler._read_json
        )
        self.assertIn("_read_sup_json", supervision._SupHandler.__dict__)


class TheProfileInheritsTheRequestLineRefusalsTest(unittest.TestCase):
    """The profile inherits the handler, so it inherited the defect —
    verified HERE rather than assumed from the inheritance.

    ``_SupHandler`` subclasses ``_Handler`` and overrides ``do_GET`` and
    ``do_POST``, returning BEFORE the parent's versions for any path in
    ``_ROUTES``. That is exactly the shape that has already made this
    profile miss a framing guard twice: C06's GET guard covered Layer 0 and
    not the profile's own two GET routes, and C06's body reader was not the
    one the profile's POST routes used. So "the parent was fixed" is a
    claim about the parent, and the fourteen routes this file adds are the
    thing to measure.

    The defect: ``default_request_version`` was the standard library's
    ``"HTTP/0.9"``, in which ``send_response_only``, ``send_header`` and
    ``end_headers`` are no-ops — so on every one of this profile's
    twenty-one routes a request line the library could not version was
    answered with a NAKED BODY. ``GET /v3/mints`` with no version produced
    this mint's signed descriptor — roughly a kilobyte of signed mint
    state, exact length depending on the mint_id and the signature — with
    no status line in front of it; ``@@@@`` produced the standard
    library's own HTML error page the same way.
    """

    #: The profile's own fourteen, plus the Layer 0 seven it inherits. A
    #: fix that reached the parent's routes and not these would pass the
    #: C06 sweep and fail here, which is the point of measuring both.
    #:
    #: The shapes below are the doors, and ``explicit 0.9`` is the one that
    #: was missing: the first fix refused 0.9 by WORD COUNT, so a request
    #: line that spells ``HTTP/0.9`` out walked past it and this profile
    #: went on answering every one of these routes with a naked body.
    ROUTES = tuple(sorted(supervision._ROUTES)) + (
        ("GET", "/v3/mints"),
        ("GET", "/v3/status/abc"),
        ("POST", "/v3/exchange"),
        ("POST", "/v3/status"),
        ("POST", "/admin/issue"),
        ("GET", "/no-such-route"),
        ("POST", "/no-such-route"),
    )

    def start_mint(self):
        """A supervision mint, and NOT ``SupervisionTest``'s.

        Deliberately not a subclass of ``SupervisionTest``: that class is
        one TestCase carrying ninety-odd test methods, and inheriting it to
        borrow ``start_mint`` re-runs every one of them under this class's
        name — ninety re-executions that test nothing new and roughly
        double the file's runtime. Nothing here needs a clock, a burn
        policy or a credential: every request below is refused before any
        route runs, so the mint only has to be listening.
        """
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        priv, pub = generate_keypair()
        ledger = Ledger(
            os.path.join(tmp.name, "ledger.sqlite3"),
            FakeClock(T0),
            NO_BURN,
            recovery_window_ms=90 * DAY_MS,
            max_lock_expiry_ms=30 * DAY_MS,
        )
        config = MintConfig(
            mint_id=MINT_ID,
            baseline_model_class="frontier-2026",
            burn_policy=NO_BURN,
            signing_private=priv,
            signing_public=pub,
            profiles=(),
            admin_token=ADMIN_TOKEN,
        )
        server = SupervisionServer(config, ledger)
        port = server.start()
        self.addCleanup(server.stop)
        return Mint(port, FakeClock(T0), ledger, pub,
                    os.path.join(tmp.name, "ledger.sqlite3"), server, NO_BURN)

    #: THE TERMINATED SHAPES: every one of these ends its header block,
    #: so ``super().parse_request()`` reaches its verdict without ever
    #: blocking on the socket and the refusal below is the whole answer.
    #: That is a real sweep and it stays — but read ``WIRE_SHAPES`` after
    #: it before counting these 126 cells as coverage of HTTP/0.9. "Two
    #: words" here appends ``\r\n\r\n``, and 0.9 has no header block to
    #: terminate: the blank line is this harness's, not a client's.
    SHAPES = {
        "unparseable": lambda m, p: b"@@@@\r\n\r\n",
        # TWO WORDS, TERMINATED — the shape a *test* sends. A 0.9 client
        # sends `GET /v3/mints\r\n` and stops; see WIRE_SHAPES, where
        # that spelling is driven and where it still gets no answer.
        "two words": lambda m, p: ("%s %s\r\n\r\n" % (m, p)).encode(),
        # THE OTHER 0.9 SPELLING, and the one the first fix missed on this
        # profile as well: three words, a version token the library CAN
        # read, ``request_version`` set to ``"HTTP/0.9"`` off the wire — and
        # every header the route composes is a no-op again. Measured on this
        # profile before the version check, on every one of its routes:
        # ``GET /v3/agent/balance HTTP/0.9`` -> a naked 25-octet
        # ``{"status":"unauthorized"}``, ``GET /v3/mints HTTP/0.9`` -> 1,080
        # octets of signed descriptor with no status line.
        "explicit 0.9": lambda m, p: (
            "%s %s HTTP/0.9\r\nHost: h\r\n\r\n" % (m, p)).encode(),
        "bad version": lambda m, p: (
            "%s %s HTTP/9.9\r\nHost: h\r\n\r\n" % (m, p)).encode(),
        "absolute form": lambda m, p: (
            "%s http://127.0.0.1%s HTTP/1.1\r\nHost: h\r\n\r\n"
            % (m, p)).encode(),
        "over-long target": lambda m, p: (
            ("%s /" % m).encode() + b"a" * 70000
            + b" HTTP/1.1\r\nHost: h\r\n\r\n"),
    }

    def test_every_supervision_route_frames_every_request_line(self):
        """One hundred and twenty-six cells: twenty-one routes, six shapes.

        Each must be exactly one response, with a status line, with a
        Content-Length, with nothing after it, and with the socket closed.
        """
        m = self.start_mint()
        for method, path in self.ROUTES:
            for name, make in self.SHAPES.items():
                with self.subTest(route="%s %s" % (method, path), shape=name):
                    raw, closed = raw_to_eof(m.port, make(method, path))
                    where = "%s %s / %s" % (method, path, name)
                    self.assertTrue(raw, "%s: no answer at all" % where)
                    self.assertTrue(
                        raw.startswith(b"HTTP/1.1 "),
                        "%s: a response with NO STATUS LINE: %r"
                        % (where, raw[:160]))
                    self.assertEqual(
                        status_lines(raw), 1, "%s: %r" % (where, raw[:200]))
                    self.assertEqual(
                        trailing_bytes(raw), b"",
                        "%s: octets follow the declared Content-Length: %r"
                        % (where, trailing_bytes(raw)[:160]))
                    self.assertIn(b"\r\nConnection: close\r\n", raw, where)
                    self.assertTrue(closed, "%s: socket held open" % where)

    def test_a_two_word_request_line_no_longer_leaks_the_descriptor(self):
        """The loudest cell on this server too, and what it leaked was
        signed mint state: the whole descriptor, with no status line, no
        length and no ``Connection: close`` in front of it.

        BOTH LINES HERE ARE TERMINATED — ``\r\n\r\n`` on the two-word
        one, a ``Host`` header and a blank line on the spelled-out one —
        so both are shapes this mint can reach a verdict on without
        waiting for a header block that is not coming. They were the
        leaks and they are closed. The UNterminated spelling, which is
        the one a 0.9 client actually writes, is driven in
        ``test_the_wire_spelling_of_0_9_is_never_answered_naked`` and
        still gets no status line at all."""
        m = self.start_mint()
        for line in (b"GET /v3/mints\r\n\r\n",
                     b"GET /v3/mints HTTP/0.9\r\nHost: h\r\n\r\n"):
            with self.subTest(line=line):
                raw, closed = raw_to_eof(m.port, line)
                self.assertTrue(raw.startswith(b"HTTP/1.1 400 "), raw[:160])
                self.assertNotIn(b"signature", raw)
                self.assertTrue(closed)
                status, _conn, body = raw_probe(m.port, line)[0:3]
                self.assertEqual(body, {"status": "bad_request",
                                        "reason": "bad_version"}, body)

        # And the profile's OWN routes, whose naked answers were this
        # server's authorization decisions rather than the descriptor.
        for line in (b"GET /v3/agent/balance HTTP/0.9\r\nHost: h\r\n\r\n",
                     b"GET /v3/operator/statement HTTP/0.9\r\nHost: h\r\n\r\n",
                     b"POST /v3/operator/register HTTP/0.9\r\nHost: h\r\n"
                     b"Content-Length: 2\r\n\r\n{}"):
            with self.subTest(line=line):
                raw, closed = raw_to_eof(m.port, line)
                self.assertTrue(raw.startswith(b"HTTP/1.1 400 "), raw[:160])
                self.assertIn(b"\r\nConnection: close\r\n", raw)
                self.assertEqual(trailing_bytes(raw), b"")
                self.assertTrue(closed)

    def test_one_empty_line_before_the_request_line_is_ignored_here_too(self):
        """RFC 7230 §3.5, inherited. A well-formed request preceded by one
        CRLF used to be discarded with no answer at all on this profile as
        well — the parent reads the request line for both.

        AND THE TOLERANCE STOPS AT ONE, which is the other half of the
        measurement and is not asserted here because it is not a property
        worth pinning: the same request behind TWO leading CRLFs comes
        back as zero bytes with the socket closed in 0.01s, on this route
        and on every other one swept. One is answered, two is discarded.
        The second case is driven in
        ``test_the_wire_spelling_of_0_9_is_never_answered_naked``, with
        the reason the bounded-loop fix belongs in the parent."""
        m = self.start_mint()
        raw, _closed = raw_to_eof(
            m.port,
            b"\r\nGET /v3/agent/balance HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            b"Connection: close\r\n\r\n")
        self.assertTrue(raw.startswith(b"HTTP/1.1 "), raw[:160])
        self.assertEqual(status_lines(raw), 1, raw[:200])
        self.assertEqual(trailing_bytes(raw), b"")

    #: THE SPELLINGS A 0.9 CLIENT AND A TOLERANT PEER ACTUALLY EMIT, and
    #: not one of them is in ``SHAPES`` above.
    #:
    #: HTTP/0.9 is a request line and nothing else: ``GET /v3/mints`` and
    #: a line terminator, no header block, so no blank line to end one.
    #: Every 0.9 cell this suite (and C06's, and the GUI's) drove before
    #: today appended ``\r\n\r\n``, which is the harness telling the
    #: server that an empty header block has ended — the one thing that
    #: lets ``super().parse_request()`` reach its verdict without waiting
    #: on the socket. The terminated cells go green, and the spelling on
    #: the wire is the one that never gets an answer.
    #:
    #: The last two are the same silence one door over: RFC 7230 §3.5
    #: lets a peer put empty lines before a request line, the parent
    #: tolerates exactly ONE, and the second one is read as a request
    #: line it cannot parse — so a well-formed, complete request behind
    #: two CRLFs is discarded with nothing written.
    #: name -> (bytes builder, the only honest answer is a REFUSAL).
    #: The flag is what keeps this test true after the parent is fixed:
    #: a 0.9 request line can only ever be refused, so anything that
    #: comes back must be a closing 400 carrying no mint state — but a
    #: well-formed request behind leading empty lines is a REQUEST, and
    #: the fix for it is to answer it, descriptor, keep-alive and all.
    #: Asserting "Connection: close" on those cells would have made this
    #: test fight the fix it exists to ask for (measured: it does, on all
    #: eight of them, with the ordering patched in at runtime).
    WIRE_SHAPES = {
        "0.9, CRLF, no header block": (
            lambda m, p: ("%s %s\r\n" % (m, p)).encode(), True),
        "0.9, bare LF": (lambda m, p: ("%s %s\n" % (m, p)).encode(), True),
        "0.9, CR only": (lambda m, p: ("%s %s\r" % (m, p)).encode(), True),
        "two leading empty lines": (lambda m, p: (
            "\r\n\r\n%s %s HTTP/1.1\r\nHost: h\r\n\r\n"
            % (m, p)).encode(), False),
        "five leading empty lines": (lambda m, p: (
            "\r\n" * 5 + "%s %s HTTP/1.1\r\nHost: h\r\n\r\n"
            % (m, p)).encode(), False),
    }

    #: Five routes rather than twenty-one: each cell of the sweep below
    #: parks a socket for the handler's whole budget, so the sweep is
    #: driven in parallel and its wall time is one budget no matter how
    #: wide it is — but every parked cell is also a held server thread,
    #: and a hundred of those is a load test, not a test. One Layer 0
    #: route, one authless profile route, one credentialled profile
    #: route, one POST (which CPython refuses before the header read, so
    #: it is the asymmetry rather than a duplicate cell) and one unrouted
    #: path.
    WIRE_ROUTES = (
        ("GET", "/v3/mints"),
        ("GET", "/v3/agent/balance"),
        ("GET", "/v3/operator/statement"),
        ("POST", "/v3/operator/register"),
        ("GET", "/no-such-route"),
    )

    def test_the_wire_spelling_of_0_9_is_never_answered_naked(self):
        """THE SHAPE NOBODY DROVE, DRIVEN — and what it does today.

        MEASURED HERE on 2026-09-17, twenty-five cells in parallel
        against a live supervision mint (wall time 11.03s, one budget):

        * ``GET <route>\r\n`` — /v3/mints, /v3/agent/balance,
          /v3/operator/statement, /no-such-route: ZERO BYTES, the handler
          held 10.01-10.02s, then a silent close. The bare-LF spelling
          is identical; the CR-only one measures the same for a
          different reason, below.
        * ``POST /v3/operator/register\r\n`` — a framed
          ``HTTP/1.1 400`` in 0.01s, because CPython's ``parse_request``
          refuses a two-word line whose method is not GET *before* it
          reads the header block. GET, the only method 0.9 ever had, is
          the one that goes unanswered.
        * ``\r\n\r\n`` (and five CRLFs) before a well-formed request:
          zero bytes, immediate close, the request behind them never
          read. ONE leading CRLF is answered, which is where the
          tolerance stops — see
          ``test_one_empty_line_before_the_request_line_is_ignored_here_too``.

        WHAT THIS TEST CERTIFIES, and it is deliberately less than a
        reader would assume from its length: on every spelling above,
        this profile never answers NAKED. Nothing comes back that is not
        a complete framed response, no descriptor, no signed mint state,
        no stdlib HTML page, no second answer — and the thread is
        released at this handler's budget rather than held forever. That
        is the class this round exists to close and it is the half of it
        that is true here.

        AND WHAT THE FIX BUYS, measured the same way with the ordering
        patched into ``mintapi._Handler.parse_request`` AT RUNTIME (no
        file edited: the parent belongs to C06 this round):

        * ``GET <route>\r\n`` and the bare-LF spelling — framed
          ``HTTP/1.1 400 bad_version``, ``Connection: close``, 221
          octets, in 0.01-0.02s instead of ten seconds of nothing.
        * leading empty lines, with the single tolerance made a bounded
          loop — the request behind them is READ AND ANSWERED (200 on
          /v3/mints, 401 on the credentialled routes, 404 on an unrouted
          path) in 0.01s; the ten seconds left on those cells is the
          keep-alive idle close after a complete answer, which is what it
          should be.
        * ``GET <route>\r`` — STILL zero bytes at the budget, and this
          one is not an ordering defect at all: a lone CR is not a line
          terminator, so ``readline`` has not yet been given a request
          line to act on. Nothing complete was ever asked, there is
          nothing to frame an answer to, and the only thing owed is the
          bound — which fires (10.02s, closed). It is in this sweep so
          that the distinction is measured rather than assumed.

        This test is written to pass in BOTH worlds, and that is not
        laxity: an assertion that the cells stay empty would make the
        suite fight the fix, and "Connection: close" asserted on the
        leading-empty-line cells does exactly that (measured: eight
        failures with the ordering patched in). What is pinned is what is
        true of an unanswerable request line either way.

        WHAT IT DOES NOT CERTIFY: that these requests get a status line
        at all. They do not. Zero bytes is not an answer — no status line
        for an intermediary to log, frame or attribute, and one held
        thread per socket for ten seconds against a twenty-byte
        unauthenticated request line. The fix is an ORDERING change in
        ``mintapi._Handler.parse_request`` (act on the two-word verdict
        before ``super().parse_request()`` reads the header block) plus a
        bounded loop over leading empty lines instead of the single one,
        and it is deliberately not made here: this profile INHERITS that
        method, ``test_the_profile_holds_no_request_line_rule_of_its_own``
        asserts it carries no copy, and a copy here would close the door
        on the one server that already inherits every transport refusal
        while the plain mint, the operator console and the operator GUI
        stayed open — which is the drift that produced this class three
        times. When C06 lands the ordering, this test passes unchanged
        and the cells below start arriving as framed 400s.
        """
        m = self.start_mint()
        budget = supervision._HANDLER_TIMEOUT_S
        cells = [(method, path, name, make, refusal_only)
                 for method, path in self.WIRE_ROUTES
                 for name, (make, refusal_only) in self.WIRE_SHAPES.items()]

        def drive(cell):
            method, path, name, make, refusal_only = cell
            raw, closed, seconds = raw_to_eof_timed(
                m.port, make(method, path), read_timeout=budget + 15.0)
            return ("%s %s / %s" % (method, path, name), raw, closed,
                    seconds, refusal_only)

        with concurrent.futures.ThreadPoolExecutor(
                max_workers=len(cells)) as pool:
            results = list(pool.map(drive, cells))

        for where, raw, closed, seconds, refusal_only in results:
            with self.subTest(cell=where):
                # The thread comes back. A budget that stopped firing —
                # a `timeout` dropped from the handler, a deadline armed
                # and never checked — turns every one of these sockets
                # into a parked thread, which is what this cell watches.
                self.assertTrue(
                    closed,
                    "%s: still holding the connection after %.2fs"
                    % (where, seconds))
                # Generous on purpose: the property is "released at a
                # budget", and "not released at all" is what `closed`
                # above catches (the client waits `budget + 15` before it
                # gives up). This bound is the one that notices a handler
                # whose `timeout` stopped being applied but whose socket
                # still eventually dies of something else, and it is wide
                # enough not to go red because twenty-five sockets and a
                # busy machine added a second.
                self.assertLess(
                    seconds, budget + 10.0,
                    "%s: held %.2fs against a %.1fs budget"
                    % (where, seconds, budget))
                # No stdlib HTML error page, ever: that is what comes
                # out when a request line is answered in 0.9 by the
                # library's own error path, and it carries no framing.
                self.assertNotIn(b"<html", raw.lower(), where)
                if refusal_only:
                    # A 0.9 request line cannot become a call, so nothing
                    # of this mint's state may ride out on one — not a
                    # signature, not the descriptor, not a route's answer.
                    self.assertNotIn(b"signature", raw, where)
                    self.assertNotIn(b"mint_id", raw, where)
                if not raw:
                    continue  # the open half, named in the docstring
                # Whatever DID come back is one complete framed answer.
                self.assertTrue(
                    raw.startswith(b"HTTP/1.1 "),
                    "%s: a response with NO STATUS LINE: %r"
                    % (where, raw[:160]))
                self.assertEqual(status_lines(raw), 1, "%s: %r"
                                 % (where, raw[:200]))
                self.assertEqual(
                    trailing_bytes(raw), b"",
                    "%s: octets follow the declared Content-Length: %r"
                    % (where, trailing_bytes(raw)[:160]))
                if refusal_only:
                    self.assertTrue(
                        raw.startswith(b"HTTP/1.1 4"),
                        "%s: a 0.9 request line was ANSWERED: %r"
                        % (where, raw[:160]))
                    self.assertIn(b"\r\nConnection: close\r\n", raw, where)

    def test_keep_alive_never_splices_a_body_past_a_declared_length(self):
        """THE REGRESSION, on a supervision route.

        A well-formed request to a route that holds operator credentials,
        then a two-word request line on the same socket. What came back was
        a correct response with a declared Content-Length followed by MORE
        octets that were not part of it and carried no framing of their own
        — response splitting, behind the reverse proxy DEPLOYMENT.md makes
        mandatory, on the server that answers freezes, caps and pulls.

        Driven on a GET route so the first answer is a real one rather than
        a 401: the splice is a property of the SECOND request's version,
        not of the first request's outcome.
        """
        m = self.start_mint()
        # BOTH 0.9 SPELLINGS behind the good request. The two-word one was
        # already refused when this fixture was written; the spelled-out one
        # was still SERVED — a 200 declaring a length, then that many
        # further octets of signed descriptor carrying no framing of their
        # own (1,073 in this file's harness, 1,080 against a mint built the
        # way the verification pass built one; the mint_id and the
        # signature move the count, the defect does not).
        for label, second in (
                ("two words", b"GET /v3/mints\r\n\r\n"),
                ("explicit 0.9",
                 b"GET /v3/mints HTTP/0.9\r\nHost: 127.0.0.1\r\n\r\n"),
        ):
            with self.subTest(second=label):
                raw, closed = raw_to_eof(
                    m.port,
                    b"GET /v3/agent/balance HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\n\r\n" + second)
                head, sep, rest = raw.partition(b"\r\n\r\n")
                self.assertTrue(sep, raw[:200])
                declared = None
                for line in head.split(b"\r\n")[1:]:
                    name, _, value = line.partition(b":")
                    if name.strip().lower() == b"content-length":
                        declared = int(value.strip())
                self.assertIsNotNone(declared, head[:200])
                trailing = rest[declared:]
                self.assertTrue(
                    trailing.startswith(b"HTTP/1.1 "),
                    "%d octets follow the declared length with no framing of"
                    " their own: %r" % (len(trailing), trailing[:200]))
                self.assertNotIn(b"signature", trailing)
                self.assertTrue(closed)

    def test_the_profile_holds_no_request_line_rule_of_its_own(self):
        """One rule, one place — the same thing this file already asserts
        about the body-framing rule.

        The profile must reach the parent's refusals by INHERITING them,
        not by carrying its own ``parse_request``/``send_error``/
        ``default_request_version``. A private copy here is how the two
        servers drifted apart on framing the first three times, and a copy
        of a REQUEST-LINE rule would drift the same way.
        """
        self.assertIs(
            supervision._SupHandler.parse_request,
            mintapi._Handler.parse_request)
        self.assertIs(
            supervision._SupHandler.send_error, mintapi._Handler.send_error)
        self.assertEqual(
            supervision._SupHandler.default_request_version, "HTTP/1.1")
        for name in ("parse_request", "send_error",
                     "default_request_version"):
            self.assertNotIn(
                name, supervision._SupHandler.__dict__,
                "the profile grew its own %r; the request-line rule is the"
                " parent's, exactly as the framing rule is"
                " framing_verdict's" % (name,))


if __name__ == "__main__":
    unittest.main()
