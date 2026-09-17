#!/usr/bin/env python3
"""Tests for gui/app.py and gui/page.html.

Three kinds of test, because this component has three kinds of claim.

  * THE SERVER. A real GuiServer on a real loopback port, driven with raw
    sockets so the tests can send the headers a browser sends and the ones
    an attacker sends. The two components app.py talks to are faked here
    ON PURPOSE (mintctl.py and walletops.py have their own test files):
    what is under test is the HTTP skin — authentication, the origin
    controls, the error envelope, input validation, credential redaction.

    Every one of these runs AUTHENTICATED: ServerCase performs the real
    key-for-cookie exchange in setUpClass and carries the cookie on every
    request, exactly as a browser would. That is deliberate: exactly ONE
    test in this file starts a server with --no-auth
    (test_no_auth_opens_the_api_and_shouts_about_it), and one more starts
    one with no flags at all to prove authentication is what you get by
    default. A suite that passed --no-auth everywhere would be testing a
    server nobody ships.

  * THE PAGE. page.html's real JavaScript, executed under a small DOM by
    node, against a fake GUI API. This is the only way to test the page's
    behaviour rather than its source text: that the cost line predicts
    what the payment actually does, that a stale quote cannot be paid,
    that a restart does not rewrite the mint's burn policy.

  * THE MONEY. One end-to-end run against a real mint, a real wallet and
    the real components, which pins the numbers the page puts on screen
    to the numbers the mint actually produces.

Run:  cd <repo> && python3 -m unittest gui.test_app -v
"""
import email.parser
import ast
import errno
import http.client
import http.server
import inspect
import io
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import tokenize
import types
import unittest
import urllib.parse

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "impl"))

ADMIN_TOKEN = "TOP-SECRET-ADMIN-TOKEN-0123456789"


# ----------------------------------------------------------------------
# fake components, installed before gui.app imports the real ones
# ----------------------------------------------------------------------
class FakeMintControlError(Exception):
    pass


class FakeMintControl:
    """Enough of the pinned MintControl contract to exercise the server.

    The identity it reports is the identity it was last told to start, and
    it is kept in the workdir rather than in this object, because the real
    MintControl keeps it in mint-control.json: a second controller built on
    the same workdir (a restarted GUI) reads the same record. A fake whose
    status() contradicts its own start() is not a model of the contract --
    it is a component with a bug, and a test written against it pins
    behaviour no real supervisor can produce.
    """

    RECORD = "fake-mint-control.json"

    def __init__(self, workdir):
        self.workdir = workdir
        self.running = True
        self.started = []
        self.stopped = []

    def _record(self):
        try:
            with open(os.path.join(self.workdir, self.RECORD)) as handle:
                blob = json.load(handle)
            if isinstance(blob, dict):
                return blob
        except (OSError, ValueError):
            pass
        return {"mint_id": "fake-mint", "port": 8787}

    def status(self):
        record = self._record()
        port = record["port"]
        return {"running": self.running,
                "pid": 4242 if self.running else None,
                "port": port,
                "mint_id": record["mint_id"],
                "base_url": "http://127.0.0.1:%d" % port,
                "started_at_ms": 1700000000000 if self.running else None,
                "last_error": None}

    def start(self, *, mint_id, baseline_model_class, port, rate_ppm,
              cap_mc, exempt_below_mc):
        self.started.append(dict(mint_id=mint_id,
                                 baseline_model_class=baseline_model_class,
                                 port=port, rate_ppm=rate_ppm, cap_mc=cap_mc,
                                 exempt_below_mc=exempt_below_mc))
        self.running = True
        try:
            with open(os.path.join(self.workdir, self.RECORD), "w") as handle:
                json.dump({"mint_id": mint_id, "port": port}, handle)
        except OSError:                              # pragma: no cover
            pass
        return self.status()

    def stop(self, *, drain_seconds=10):
        self.stopped.append(drain_seconds)
        self.running = False
        return self.status()

    def logs(self, *, lines=200):
        return ["mint line %d" % i for i in range(min(lines, 3))]

    def admin_token(self):
        return ADMIN_TOKEN


class FakeWalletOpsError(Exception):
    """Like the real one: a reason, a detail, and WHY it failed.

    ``cause`` is optional here on purpose — a component build that predates
    the cause vocabulary must not crash this server, it must read as
    ``unknown``.
    """

    def __init__(self, reason, detail, cause=None):
        super().__init__("%s: %s" % (reason, detail))
        self.reason = reason
        self.detail = detail
        if cause is not None:
            self.cause = cause


class FakeWalletOps:
    """Records every call, so a test can assert that money did NOT move."""

    calls = []
    fail_with = None          # (reason, detail[, cause]) | Exception | None
    history_rows = None       # override what history() returns
    outstanding = None        # override what outstanding_payments() returns

    def __init__(self, store_path, base_url):
        self.store_path = store_path
        self.base_url = base_url
        self.name = os.path.basename(store_path)[:-3]
        open(store_path, "a").close()

    def _maybe_fail(self):
        if isinstance(FakeWalletOps.fail_with, BaseException):
            raise FakeWalletOps.fail_with
        if FakeWalletOps.fail_with:
            raise FakeWalletOpsError(*FakeWalletOps.fail_with)

    def summary(self):
        return {"balance_mc": 1000, "mint_id": "fake-mint", "coin_count": 3,
                "connected": True}

    def quote(self, amount_mc):
        FakeWalletOps.calls.append(("quote", self.name, amount_mc))
        self._maybe_fail()
        return {"amount_mc": amount_mc, "burn_mc": 1, "change_mc": 0,
                "inputs_mc": amount_mc + 1}

    def pay(self, amount_mc, *, to=None, deliver=None):
        FakeWalletOps.calls.append(("pay", self.name, amount_mc))
        self._maybe_fail()
        tokens = ["aicash:v3:fake-mint:%d:zz" % amount_mc]
        out = {"tokens": tokens, "amount_mc": amount_mc, "burn_mc": 1,
               "change_mc": 0, "op_id": "op-pay",
               "recipient": to or "",
               "recipient_kind": "wallet" if to else "bearer",
               "delivery": "unknown", "delivery_cause": "",
               "delivery_attempt": ("attempted" if deliver is not None
                                    else "not_attempted"),
               "delivery_detail": "not delivered by this wallet"}
        if to is not None and deliver is not None:
            FakeWalletOps.calls.append(("deliver", self.name, to))
            got = deliver(tokens)
            if isinstance(got, dict) and got.get("rejected"):
                out.update(delivery="undelivered",
                           delivery_cause="already_spent",
                           delivery_detail="%s refused it" % to)
            else:
                out.update(delivery="delivered",
                           delivery_detail="delivered to %s" % to)
        return out

    rejected = None           # override what receive() reports as rejected

    def receive(self, tokens):
        FakeWalletOps.calls.append(("receive", self.name, list(tokens)))
        self._maybe_fail()
        rejected = FakeWalletOps.rejected or []
        return {"accepted_mc": 10, "accepted": len(tokens) - len(rejected),
                "rejected": list(rejected)}

    settled = None            # override what settle_delivery() returns

    def settle_delivery(self, op_id, *, result=None, error=None,
                        recipient=""):
        FakeWalletOps.calls.append(
            ("settle", self.name, op_id, recipient,
             "error" if error is not None else
             ("result" if result is not None else "nothing")))
        if FakeWalletOps.settled is not None:
            return FakeWalletOps.settled
        if error is not None:
            return {"op_id": op_id, "recorded": True,
                    "delivery": "undelivered",
                    "delivery_cause": getattr(error, "cause", "unknown"),
                    "delivery_detail": "refused"}
        if result is None:
            return {"op_id": op_id, "recorded": False, "delivery": "unknown",
                    "delivery_cause": "", "delivery_detail": "nothing seen"}
        delivered = not (result.get("rejected") or [])
        return {"op_id": op_id, "recorded": True,
                "delivery": "delivered" if delivered else "undelivered",
                "delivery_cause": "" if delivered else "already_spent",
                "delivery_detail": "watched from %s's side" % recipient}

    def recover(self):
        FakeWalletOps.calls.append(("recover", self.name))
        self._maybe_fail()
        return {"recovered": 0}

    def history(self, *, limit=50):
        FakeWalletOps.calls.append(("history", self.name, limit))
        self._maybe_fail()
        if FakeWalletOps.history_rows is not None:
            return list(FakeWalletOps.history_rows)
        return [{"ts_ms": 1, "kind": "pay", "amount_mc": 5, "detail": "x",
                 "cause": ""}]

    def unredeemed_payments(self, *, limit=20):
        return self.outstanding_payments(limit=limit)

    def outstanding_payments(self, *, limit=20):
        FakeWalletOps.calls.append(("outstanding", self.name, limit))
        self._maybe_fail()
        if FakeWalletOps.outstanding is not None:
            return dict(FakeWalletOps.outstanding)
        return {"checked": True, "mint_id": "fake-mint",
                "payments": [{"op_id": "op-1", "amount_mc": 7, "live_mc": 7,
                              "tokens": [{"token": "aicash:v3:fake-mint:7:zz",
                                          "amount_mc": 7, "key": "kk",
                                          "state": "unspent"}]}]}

    def close(self):
        pass


# What sys.modules held for these names BEFORE this file touched them.
# app.py reaches its components with a top-level ``__import__("mintctl")``,
# so testing it against stubs means putting stubs under those exact names --
# which is process-global state, and this file is not the only test file in
# the process. Whatever we borrow here gets handed back in tearDownModule;
# without that, gui/test_walletops.py's own lazy ``import walletops`` picks
# up FakeWalletOps and fails on a name the real module has.
_BORROWED = {name: sys.modules.get(name) for name in ("mintctl", "walletops")}


def install_fakes():
    mintctl = types.ModuleType("mintctl")
    mintctl.MintControl = FakeMintControl
    mintctl.MintControlError = FakeMintControlError
    walletops = types.ModuleType("walletops")
    walletops.WalletOps = FakeWalletOps
    walletops.WalletOpsError = FakeWalletOpsError
    sys.modules["mintctl"] = mintctl
    sys.modules["walletops"] = walletops


def tearDownModule():
    """Give the process back the sys.modules it lent us.

    Runs after every test in this file, so the stubs are in place for all
    of them; it only stops the stubs outliving this module and reaching a
    sibling test file, or anything else that imports by top-level name.
    """
    for name, module in _BORROWED.items():
        if module is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = module


install_fakes()
from gui import app as gui_app  # noqa: E402  (after the fakes are in place)
from gui import walletops      # noqa: E402  (the cause lists live there)


# ----------------------------------------------------------------------
# raw HTTP, because the interesting headers are the ones a library adds
# for you or refuses to omit
# ----------------------------------------------------------------------
def raw_request(port, text, wait=5.0):
    """Send bytes exactly as written; return the whole response.

    Reads until Content-Length is satisfied (the server may hold the
    connection open for another request), or until it closes, or the
    deadline passes.
    """
    sock = socket.create_connection(("127.0.0.1", port), timeout=wait)
    try:
        sock.sendall(text.encode() if isinstance(text, str) else text)
        sock.settimeout(wait)
        buf = b""
        deadline = time.monotonic() + wait
        while time.monotonic() < deadline:
            head, sep, body = buf.partition(b"\r\n\r\n")
            if sep:
                length = None
                for line in head.split(b"\r\n")[1:]:
                    if line.lower().startswith(b"content-length:"):
                        length = int(line.split(b":")[1])
                if length is not None and len(body) >= length:
                    break
            try:
                data = sock.recv(65536)
            except (socket.timeout, TimeoutError):
                break
            if not data:
                break
            buf += data
        return buf
    finally:
        sock.close()


def http_call(port, method, path, body=None, headers=None,
              host="127.0.0.1", timeout=10):
    """One request through http.client; returns (status, headers, body).

    Headers come back because two things this file has to prove live in
    them: that a correct key is answered with a Set-Cookie, and that a
    wrong one is answered with none.
    """
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    payload = None if body is None else json.dumps(body)
    head = {"Accept": "application/json"}
    if payload is not None:
        head["Content-Type"] = "application/json"
    head.update(headers or {})
    conn.request(method, path, payload, head)
    response = conn.getresponse()
    raw = response.read()
    got = {k.lower(): v for k, v in response.getheaders()}
    conn.close()
    return response.status, got, raw


def exchange_cookie(httpd, host="127.0.0.1"):
    """The real thing a browser does with the URL printed on the terminal.

    GET / with the capability key, keep the session cookie, throw the key
    away. Every authenticated test below starts here; none of them is
    handed a credential the server did not actually issue.
    """
    port = httpd.server_address[1]
    # Connection: close so the server hangs up when it is done rather than
    # holding a keep-alive socket this helper will never use again.
    status, headers, raw = http_call(port, "GET", "/?k=" + httpd.auth.key,
                                     headers={"Connection": "close"},
                                     host=host)
    assert status == 200, "the capability URL did not open the page: %d %r" % (
        status, raw[:200])
    cookie = headers.get("set-cookie", "")
    assert cookie, "a correct key was not answered with a session cookie"
    return cookie.split(";")[0]


def split_response(raw):
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("iso-8859-1").split("\r\n")
    status = int(lines[0].split()[1])
    headers = {}
    for line in lines[1:]:
        k, _, v = line.partition(":")
        headers[k.strip().lower()] = v.strip()
    return status, headers, body


class ServerCase(unittest.TestCase):
    """One real server, one temp workdir, for the whole class."""

    @classmethod
    def setUpClass(cls):
        cls.workdir = tempfile.mkdtemp(prefix="guiapp-")
        os.makedirs(os.path.join(cls.workdir, "wallets"), exist_ok=True)
        for name in ("alice", "bob"):
            open(os.path.join(cls.workdir, "wallets", name + ".db"), "a").close()
        cls.httpd = gui_app.serve(0, cls.workdir, "127.0.0.1")
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever,
                                      kwargs={"poll_interval": 0.05},
                                      daemon=True)
        cls.thread.start()
        # serve() binds one handler class per server; the Api is on that.
        cls.api = cls.httpd.RequestHandlerClass.api
        cls.control = cls.api.components.mint()
        # Authenticate the way the operator's browser does, once, and carry
        # the cookie from here on. Nothing below fakes a credential.
        cls.cookie = exchange_cookie(cls.httpd)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=5)
        shutil.rmtree(cls.workdir, ignore_errors=True)

    def setUp(self):
        FakeWalletOps.calls = []
        FakeWalletOps.fail_with = None
        FakeWalletOps.history_rows = None
        FakeWalletOps.outstanding = None
        FakeWalletOps.rejected = None
        FakeWalletOps.settled = None
        self.control.running = True

    # -- helpers --------------------------------------------------------
    def fetch(self, method, path, body=None, headers=None, cookie=True):
        """(status, headers, body). ``cookie=False`` sends no credential."""
        head = dict(headers or {})
        if cookie and "Cookie" not in head:
            head["Cookie"] = self.cookie
        return http_call(self.port, method, path, body, head)

    def call(self, method, path, body=None, headers=None, cookie=True):
        status, _headers, raw = self.fetch(method, path, body, headers, cookie)
        try:
            return status, json.loads(raw or b"{}"), raw
        except ValueError:
            return status, None, raw

    def assert_envelope(self, status, obj, raw):
        self.assertGreaterEqual(status, 400)
        self.assertIsInstance(obj, dict, "not JSON: %r" % raw[:200])
        self.assertIn("error", obj)
        self.assertIn("reason", obj["error"])
        self.assertIn("detail", obj["error"])
        # Every failure says WHY, from one closed vocabulary, including the
        # failures this server raises on its own account.
        self.assertIn("cause", obj["error"])
        self.assertIn(obj["error"]["cause"], gui_app.CAUSES)
        self.assertNotIn(b"Traceback", raw)
        self.assertNotIn(b"<html", raw.lower())


# ======================================================================
# THE SERVER
# ======================================================================
class TestOriginControls(ServerCase):
    """A local tool with no login lives or dies on who is allowed to ask."""

    def test_same_origin_post_moves_money(self):
        status, obj, _ = self.call(
            "POST", "/api/wallet/pay", {"name": "alice", "amount_mc": 11},
            {"Origin": "http://127.0.0.1:%d" % self.port,
             "Sec-Fetch-Site": "same-origin"})
        self.assertEqual(status, 200, obj)
        self.assertIn(("pay", "alice", 11), FakeWalletOps.calls)

    def test_cross_site_post_is_refused_and_moves_nothing(self):
        """The finding: a page on any other site can POST here with a simple
        content type, no preflight, and the browser attaches our own Host."""
        for headers in (
            {"Origin": "https://evil.example.com",
             "Sec-Fetch-Site": "cross-site",
             "Content-Type": "text/plain;charset=UTF-8"},
            {"Origin": "https://evil.example.com"},          # older browser
            {"Sec-Fetch-Site": "cross-site"},                # no Origin sent
            {"Sec-Fetch-Site": "same-site"},                 # a sibling site
            {"Origin": "null"},                              # sandboxed frame
            {"Origin": "http://127.0.0.1:1"},                # another local port
        ):
            with self.subTest(headers=headers):
                status, obj, raw = self.call(
                    "POST", "/api/wallet/pay",
                    {"name": "alice", "amount_mc": 11}, headers)
                self.assertEqual(status, 403, raw[:200])
                self.assertEqual(obj["error"]["reason"], "cross_site")
        self.assertEqual(FakeWalletOps.calls, [],
                         "a cross-site request reached the wallet")

    def test_cross_site_cannot_stop_the_mint_or_issue(self):
        evil = {"Origin": "https://evil.example.com",
                "Sec-Fetch-Site": "cross-site"}
        for path, body in (("/api/mint/stop", {"drain_seconds": 0}),
                           ("/api/mint/issue", {"amount_mc": 10, "count": 1}),
                           ("/api/wallet/create", {"name": "mallory"})):
            status, obj, _ = self.call("POST", path, body, evil)
            self.assertEqual(status, 403, path)
        self.assertEqual(self.control.stopped, [])
        self.assertTrue(self.control.running)

    def test_a_browser_navigation_still_works(self):
        """Sec-Fetch-Site: none is the address bar; same-origin is our page."""
        for site in ("none", "same-origin"):
            status, _obj, raw = self.call(
                "GET", "/api/mint/status", None, {"Sec-Fetch-Site": site})
            self.assertEqual(status, 200, raw[:200])

    def test_missing_host_header_is_refused(self):
        raw = raw_request(
            self.port,
            "GET /api/mint/status HTTP/1.0\r\nCookie: %s\r\n\r\n"
            % self.cookie)
        status, _headers, body = split_response(raw)
        self.assertEqual(status, 403, body[:200])
        self.assertEqual(json.loads(body)["error"]["reason"], "not_loopback")

    def test_foreign_host_header_is_refused(self):
        raw = raw_request(
            self.port,
            "GET /api/mint/status HTTP/1.1\r\nHost: mint.evil.example\r\n"
            "Cookie: %s\r\nConnection: close\r\n\r\n" % self.cookie)
        status, _headers, body = split_response(raw)
        self.assertEqual(status, 403, body[:200])
        self.assertEqual(json.loads(body)["error"]["reason"], "not_loopback")


class TestAuthentication(ServerCase):
    """The finding this round exists for.

    Before this, anyone who could reach the port could mint money and spend
    every wallet in the workdir: loopback was the whole boundary, and
    loopback does not separate two users of a machine, does not stop any
    other local process, and does not stop a web page in the operator's own
    browser from fetching 127.0.0.1.

    Every test below deletes exactly one defence's reason to exist. If the
    check it names is removed from app.py, the test fails; if it is
    weakened (a `==` instead of compare_digest, a prefix match instead of an
    exact origin, a `k` accepted on an API route), it still fails.
    """

    def key(self):
        return self.httpd.auth.key

    # -- 3. every /api/* route needs the cookie -------------------------
    def test_an_api_get_with_no_cookie_is_401(self):
        """GET, not only POST. /api/wallet/list names every wallet and its
        balance, /api/mint/logs is the mint's log: reading is not harmless."""
        for path in ("/api/mint/status", "/api/wallet/list",
                     "/api/mint/logs?lines=50", "/api/mint/descriptor",
                     "/api/wallet/summary?name=alice",
                     "/api/wallet/history?name=alice"):
            with self.subTest(path=path):
                status, obj, raw = self.call("GET", path, cookie=False)
                self.assertEqual(status, 401, raw[:200])
                self.assertEqual(obj["error"]["reason"], "unauthorized")
                self.assert_envelope(status, obj, raw)

    def test_an_api_post_with_no_cookie_is_401_and_moves_nothing(self):
        for path, body in (
                ("/api/wallet/pay", {"name": "alice", "amount_mc": 11}),
                ("/api/wallet/receive", {"name": "alice", "tokens": ["x"]}),
                ("/api/wallet/quote", {"name": "alice", "amount_mc": 11}),
                ("/api/wallet/recover", {"name": "alice"}),
                ("/api/wallet/create", {"name": "mallory"}),
                ("/api/mint/issue", {"amount_mc": 10, "count": 1}),
                ("/api/mint/start", {"mint_id": "evil",
                                     "baseline_model_class": "b", "port": 1,
                                     "rate_ppm": 0, "cap_mc": 0,
                                     "exempt_below_mc": 0}),
                ("/api/mint/stop", {"drain_seconds": 0})):
            with self.subTest(path=path):
                status, obj, raw = self.call("POST", path, body, cookie=False)
                self.assertEqual(status, 401, raw[:200])
                self.assertEqual(obj["error"]["reason"], "unauthorized")
        self.assertEqual(FakeWalletOps.calls, [],
                         "an unauthenticated request reached a wallet")
        self.assertEqual(self.control.stopped, [])
        self.assertEqual(self.control.started, [])
        self.assertTrue(self.control.running)
        self.assertNotIn("mallory", self.api.wallet_names())

    def test_every_route_in_the_table_is_behind_the_cookie(self):
        """Not a sample: the whole ROUTES table, so a route added later
        cannot quietly ship unprotected."""
        self.assertTrue(gui_app.ROUTES)
        for method, path in sorted(gui_app.ROUTES):
            with self.subTest(route="%s %s" % (method, path)):
                status, obj, raw = self.call(method, path, {}, cookie=False)
                self.assertEqual(status, 401, raw[:200])
                self.assertEqual(obj["error"]["reason"], "unauthorized")

    # -- 2/3. the key opens the page, never the API ---------------------
    def test_the_key_in_a_query_string_does_not_open_the_api(self):
        """A URL ends up in history files, proxy logs, Referer headers and
        over a shoulder. It is spent once on a cookie and then retired."""
        key = self.key()
        for method, path, body in (
                ("GET", "/api/wallet/list?k=" + key, None),
                ("GET", "/api/mint/status?k=" + key, None),
                ("POST", "/api/wallet/pay?k=" + key,
                 {"name": "alice", "amount_mc": 11}),
                ("POST", "/api/mint/issue?k=" + key,
                 {"amount_mc": 10, "count": 1})):
            with self.subTest(path=path):
                status, obj, raw = self.call(method, path, body, cookie=False)
                self.assertEqual(status, 401, raw[:200])
                self.assertEqual(obj["error"]["reason"], "unauthorized")
                self.assertNotIn(key.encode(), raw)
        self.assertEqual(FakeWalletOps.calls, [])
        # ...and the very same key does open the page.
        status, _obj, raw = self.call("GET", "/?k=" + key, cookie=False)
        self.assertEqual(status, 200, raw[:200])

    # -- 2. the cookie exchange ------------------------------------------
    def test_a_correct_key_is_answered_with_a_locked_down_cookie(self):
        status, headers, raw = self.fetch("GET", "/?k=" + self.key(),
                                          cookie=False)
        self.assertEqual(status, 200, raw[:200])
        cookie = headers.get("set-cookie", "")
        name, _, rest = cookie.partition("=")
        self.assertEqual(name, gui_app.SESSION_COOKIE)
        value = rest.split(";")[0]
        lowered = cookie.lower()
        for attribute in ("httponly", "samesite=strict", "path=/"):
            self.assertIn(attribute, lowered, cookie)
        # The session is its own secret. If it were the key, or built from
        # it, one leaked cookie would hand over the other credential too.
        self.assertNotEqual(value, self.key())
        self.assertNotIn(value, self.key())
        self.assertNotIn(self.key(), value)
        self.assertGreaterEqual(len(value), 32)
        # and it actually works
        status, _obj, raw = self.call("GET", "/api/mint/status", None,
                                      {"Cookie": "%s=%s" % (name, value)},
                                      cookie=False)
        self.assertEqual(status, 200, raw[:200])

    def test_a_wrong_key_is_401_and_is_handed_no_cookie(self):
        """The one that catches a `==` softened into `startswith`, or a
        missing key treated as a match."""
        key = self.key()
        for path in ("/", "/index.html", "/?k=", "/?k=wrong",
                     "/?k=" + key[:-1], "/?k=" + key + "x",
                     "/?k=" + key.upper(), "/?j=" + key):
            with self.subTest(path=path):
                status, headers, raw = self.fetch("GET", path, cookie=False)
                self.assertEqual(status, 401, raw[:200])
                self.assertNotIn("set-cookie", headers,
                                 "a session was issued for a wrong key")
                self.assertIn(b"terminal", raw)
                self.assertNotIn(key.encode(), raw)

    def test_a_reload_without_the_key_still_works_and_re_issues_nothing(self):
        """The browser drops the query string as soon as the operator
        navigates. A reload must not send them back to the terminal, and
        must not hand out a second credential for the same browser."""
        status, headers, raw = self.fetch("GET", "/")
        self.assertEqual(status, 200, raw[:200])
        self.assertNotIn("set-cookie", headers,
                         "a browser that already has a session was issued "
                         "another one")

    def test_a_second_browser_gets_its_own_session_and_both_work(self):
        second = exchange_cookie(self.httpd)
        self.assertNotEqual(second, self.cookie)
        for cookie in (self.cookie, second):
            status, _obj, raw = self.call("GET", "/api/mint/status", None,
                                          {"Cookie": cookie}, cookie=False)
            self.assertEqual(status, 200, raw[:200])

    def test_a_forged_or_stale_cookie_is_401(self):
        for value in ("", "nope", "a" * 43, self.key(),
                      self.cookie.split("=", 1)[1][:-1]):
            with self.subTest(value=value[:12]):
                status, obj, raw = self.call(
                    "GET", "/api/mint/status", None,
                    {"Cookie": "%s=%s" % (gui_app.SESSION_COOKIE, value)},
                    cookie=False)
                self.assertEqual(status, 401, raw[:200])
                self.assertEqual(obj["error"]["reason"], "unauthorized")

    def test_a_shadow_cookie_cannot_displace_the_real_one(self):
        """A page that cannot read our cookie can still try to set another
        with the same name. Checking only the first value sent would let
        that log the operator out -- or worse, be the value checked."""
        status, _obj, raw = self.call(
            "GET", "/api/mint/status", None,
            {"Cookie": "%s=forged; %s" % (gui_app.SESSION_COOKIE, self.cookie)},
            cookie=False)
        self.assertEqual(status, 200, raw[:200])

    # -- 4. Host: the DNS-rebinding defence -----------------------------
    def test_a_foreign_host_is_403_even_with_a_valid_cookie(self):
        """The attack the bind address does not stop: evil.example resolves
        its own name to 127.0.0.1, so the packets ARE loopback packets. The
        Host header is the one thing the attacker cannot change."""
        for host in ("evil.example.com", "evil.example.com:%d" % self.port,
                     "127.0.0.1.evil.example.com", "localhost.evil.example",
                     "evil.example.com:80", "mint.internal", "127.0.0.2"):
            with self.subTest(host=host):
                status, obj, raw = self.call("GET", "/api/wallet/list", None,
                                             {"Host": host})
                self.assertEqual(status, 403, raw[:200])
                self.assertEqual(obj["error"]["reason"], "not_loopback")
        # a POST that would have moved money, with the same good cookie
        status, obj, raw = self.call("POST", "/api/wallet/pay",
                                     {"name": "alice", "amount_mc": 11},
                                     {"Host": "evil.example.com"})
        self.assertEqual(status, 403, raw[:200])
        self.assertEqual(FakeWalletOps.calls, [])
        # and the page is not reachable under a foreign name either, so the
        # rebinding page cannot even fetch the exchange for itself
        status, headers, raw = self.fetch("GET", "/?k=" + self.key(), None,
                                          {"Host": "evil.example.com"},
                                          cookie=False)
        self.assertEqual(status, 403, raw[:200])
        self.assertNotIn("set-cookie", headers)

    def test_a_loopback_literal_with_junk_after_it_is_403(self):
        """An "optional :port" means a port, not "anything at all".

        The tempting way to write the Host check is to validate the part
        before the colon (or before the "]") and let the rest through. That
        accepts every host below: each one opens with a real loopback
        literal and then carries a foreign name, so a check that stops at
        the separator says yes. Whether a browser can be made to send one
        is not the point -- the pinned rule is a literal plus an optional
        numeric port, and anything wider is an accepted-host space nobody
        chose.
        """
        for host in ("127.0.0.1:%d.evil.example" % self.port,
                     "127.0.0.1:evil.example",
                     "127.0.0.1:not-a-port",
                     "127.0.0.1:",
                     "localhost:evil.example",
                     "localhost:80/../x",
                     "localhost:%d:9" % self.port,
                     "[::1]evil.example",
                     "[::1].evil.example",
                     "[::1]:%d@evil.example" % self.port,
                     "[::1]:%d.evil.example" % self.port,
                     "[::1]:",
                     "::1:%d" % self.port,
                     "::1.evil.example"):
            with self.subTest(host=host):
                status, obj, raw = self.call("GET", "/api/wallet/list", None,
                                             {"Host": host})
                self.assertEqual(status, 403, raw[:200])
                self.assertEqual(obj["error"]["reason"], "not_loopback")
        # and it is a gate, not a label: the POST never reaches the route
        status, _obj, raw = self.call(
            "POST", "/api/wallet/pay", {"name": "alice", "amount_mc": 11},
            {"Host": "127.0.0.1:%d.evil.example" % self.port})
        self.assertEqual(status, 403, raw[:200])
        self.assertEqual(FakeWalletOps.calls, [])

    def test_the_loopback_literals_are_accepted(self):
        for host in ("127.0.0.1", "127.0.0.1:%d" % self.port, "localhost",
                     "localhost:%d" % self.port, "LocalHost", "[::1]",
                     "[::1]:%d" % self.port, "::1"):
            with self.subTest(host=host):
                status, _obj, raw = self.call("GET", "/api/mint/status", None,
                                              {"Host": host})
                self.assertEqual(status, 200, raw[:200])

    # -- 5. Origin and Referer ------------------------------------------
    def test_a_foreign_origin_is_403_even_with_a_valid_cookie(self):
        for origin in ("http://evil.example.com",
                       "https://evil.example.com",
                       "http://127.0.0.1.evil.example.com",
                       "http://127.0.0.1:9",
                       "https://127.0.0.1:%d" % self.port,
                       "null"):
            with self.subTest(origin=origin):
                status, obj, raw = self.call("GET", "/api/wallet/list", None,
                                             {"Origin": origin})
                self.assertEqual(status, 403, raw[:200])
                self.assertEqual(obj["error"]["reason"], "cross_site")
        status, obj, raw = self.call("POST", "/api/wallet/pay",
                                     {"name": "alice", "amount_mc": 11},
                                     {"Origin": "http://evil.example.com"})
        self.assertEqual(status, 403, raw[:200])
        self.assertEqual(FakeWalletOps.calls, [])

    def test_a_foreign_referer_is_403_and_our_own_is_allowed(self):
        status, obj, raw = self.call("GET", "/api/wallet/list", None,
                                     {"Referer": "http://evil.example.com/go"})
        self.assertEqual(status, 403, raw[:200])
        self.assertEqual(obj["error"]["reason"], "cross_site")
        status, _obj, raw = self.call(
            "GET", "/api/wallet/list", None,
            {"Referer": "http://127.0.0.1:%d/" % self.port})
        self.assertEqual(status, 200, raw[:200])

    def test_no_origin_and_no_referer_with_a_valid_cookie_is_allowed(self):
        """Absent must stay allowed: a same-origin fetch omits Origin on a
        GET, this server sends Referrer-Policy: no-referrer, and curl sends
        neither. Refusing an absent header would break the shipped page."""
        status, _obj, raw = self.call("GET", "/api/wallet/list")
        self.assertEqual(status, 200, raw[:200])
        status, _obj, raw = self.call("POST", "/api/wallet/pay",
                                      {"name": "alice", "amount_mc": 7})
        self.assertEqual(status, 200, raw[:200])
        self.assertIn(("pay", "alice", 7), FakeWalletOps.calls)

    # -- 1. neither secret ever leaves this process ---------------------
    def test_neither_credential_appears_in_any_response_body(self):
        key, session = self.key(), self.cookie.split("=", 1)[1]
        for method, path, body, cookie in (
                ("GET", "/", None, True),
                ("GET", "/", None, False),
                ("GET", "/?k=" + key, None, False),
                ("GET", "/api/mint/status", None, True),
                ("GET", "/api/mint/status", None, False),
                ("GET", "/api/wallet/list", None, True),
                ("GET", "/api/mint/logs?lines=50", None, True),
                ("GET", "/api/nope?k=" + key, None, True),
                ("GET", "/api/wallet/summary?name=" + key, None, True),
                ("POST", "/api/wallet/pay",
                 {"name": "alice", "amount_mc": 1}, True),
                ("PUT", "/api/mint/status", None, True)):
            with self.subTest(path=path, cookie=cookie):
                _s, _o, raw = self.call(method, path, body, cookie=cookie)
                self.assertNotIn(key.encode(), raw, "the key came back")
                self.assertNotIn(session.encode(), raw, "the session came back")

    def test_a_component_that_quotes_a_credential_cannot_leak_it(self):
        """Nothing here serialises either secret on purpose. Component
        error messages are pasted through verbatim, though, and one of them
        could quote a command line -- so they are scrubbed on the way out,
        the same way the mint's admin token is."""
        key = self.key()
        FakeWalletOps.fail_with = FakeWalletOpsError(
            "leaky", "the operator ran: curl 'http://127.0.0.1/?k=%s'" % key)
        status, obj, raw = self.call("POST", "/api/wallet/pay",
                                     {"name": "alice", "amount_mc": 1})
        self.assertEqual(status, 400, raw[:200])
        self.assertNotIn(key.encode(), raw)
        self.assertIn(b"[credential redacted]", raw)

    def test_neither_credential_is_written_under_the_workdir(self):
        key, session = self.key(), self.cookie.split("=", 1)[1]
        for method, path, body in (
                ("POST", "/api/mint/start",
                 {"mint_id": "leak-check", "baseline_model_class": "b",
                  "port": 8787, "rate_ppm": 0, "cap_mc": 0,
                  "exempt_below_mc": 0}),
                ("GET", "/api/wallet/list", None),
                ("POST", "/api/wallet/pay", {"name": "alice", "amount_mc": 1})):
            self.call(method, path, body)
        seen = 0
        for root, _dirs, files in os.walk(self.workdir):
            for name in files:
                full = os.path.join(root, name)
                self.assertNotIn(key, name)
                self.assertNotIn(session, name)
                with open(full, "rb") as handle:
                    blob = handle.read()
                self.assertNotIn(key.encode(), blob, full)
                self.assertNotIn(session.encode(), blob, full)
                seen += 1
        self.assertGreater(seen, 0, "nothing was written at all; vacuous")


    def test_a_non_ascii_credential_is_an_answer_not_a_crash(self):
        """The gate must not raise on anything a stranger can send.

        hmac.compare_digest raises TypeError on a str holding a non-ASCII
        character, and BOTH values compared in the gate are
        attacker-supplied: the ?k= of an unauthenticated GET and the Cookie
        header of every request. Before this was fixed, `GET /?k=%C3%A9`
        raised inside _authorize, fell through the handler's catch-all and
        answered 500 with a traceback on stderr -- a crash in the
        authentication path that any process able to open a socket could
        produce at will, unauthenticated, in one request.

        It failed CLOSED, which is why this is 401-vs-500 and not a bypass.
        It is still a defect: an unauthenticated stranger should not be able
        to drive an exception through the gate at all.
        """
        for raw, label in ((b"%C3%A9", "e-acute"),
                           (b"%F0%9F%98%80", "emoji"),
                           (b"%ED%A0%80", "lone surrogate"),
                           (b"%FF%FE", "not valid utf-8"),
                           (b"%C3%A9%C3%A9%C3%A9", "several")):
            with self.subTest(key=label):
                request = (b"GET /?k=" + raw + b" HTTP/1.1\r\n"
                           b"Host: 127.0.0.1:%d\r\n"
                           b"Connection: close\r\n\r\n"
                           % self.port)
                status, headers, _body = split_response(
                    raw_request(self.port, request))
                self.assertEqual(
                    status, 401,
                    "a non-ASCII key answered %d, not 401: the comparison "
                    "raised instead of returning False" % status)
                self.assertNotIn(
                    "set-cookie", headers,
                    "a non-ASCII key was answered with a session cookie")

    def test_a_non_ascii_cookie_is_an_answer_not_a_crash(self):
        """The same hole, reached through the Cookie header instead.

        This one matters more than the ?k= case: the cookie is checked on
        EVERY route, so before the fix any local process could 500 every
        API route of this GUI without holding any credential at all.
        """
        for value, label in (("\u00e9", "e-acute"),
                             ("\U0001f600", "emoji"),
                             (self.cookie.split("=", 1)[1] + "\u00e9",
                              "real session plus one non-ASCII char")):
            with self.subTest(cookie=label):
                request = (
                    "GET /api/wallet/list HTTP/1.1\r\n"
                    "Host: 127.0.0.1:%d\r\n"
                    "Cookie: %s=%s\r\n"
                    "Connection: close\r\n\r\n"
                    % (self.port, gui_app.SESSION_COOKIE, value)
                ).encode("utf-8")
                status, _headers, body = split_response(
                    raw_request(self.port, request))
                self.assertEqual(
                    status, 401,
                    "a non-ASCII cookie answered %d, not 401 (%r)"
                    % (status, body[:200]))
                self.assertEqual(
                    json.loads(body or b"{}")["error"]["reason"],
                    "unauthorized")

    def test_a_non_ascii_cookie_does_not_reach_a_money_route(self):
        """Proof the above is a gate and not a label on a crash.

        A 500 from the catch-all and a 401 from the gate are both
        non-200; only this says the route body never ran.
        """
        body = json.dumps({"from": "alice", "to": "bob", "amount_mc": 5})
        request = (
            "POST /api/wallet/pay HTTP/1.1\r\n"
            "Host: 127.0.0.1:%d\r\n"
            "Cookie: %s=\u00e9\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: %d\r\n"
            "Connection: close\r\n\r\n%s"
            % (self.port, gui_app.SESSION_COOKIE, len(body), body)
        ).encode("utf-8")
        status, _headers, out = split_response(raw_request(self.port, request))
        self.assertEqual(status, 401)
        self.assertEqual(FakeWalletOps.calls, [],
                         "a request with a non-ASCII cookie reached "
                         "walletops; the gate did not stop it")

    def test_secret_eq_returns_false_rather_than_raising(self):
        """The helper itself, on the inputs that used to raise."""
        good = "k" * 43
        for other in ("\u00e9", "\U0001f600", "\ud800", good + "\u00e9",
                      "\u00e9" + good, "e\u0301"):
            with self.subTest(value=repr(other)):
                self.assertIs(gui_app._secret_eq(good, other), False)
                self.assertIs(gui_app._secret_eq(other, good), False)
        # and it still says True for the one case that should be True
        self.assertIs(gui_app._secret_eq(good, good), True)
        # non-str, empty, None: False, never a raise
        for junk in (None, b"x", 5, [], {}, "", 0, True):
            with self.subTest(value=repr(junk)):
                self.assertIs(gui_app._secret_eq(good, junk), False)
                self.assertIs(gui_app._secret_eq(junk, good), False)


def code_tokens(func):
    """``func``'s source as tokens, with comments and strings dropped.

    Dropping them is the whole point: _Auth.session_ok *discusses* ``==``
    in a comment explaining why it does not use one, so a substring search
    over the source text cannot tell an explanation from an
    implementation. Tokens can.
    """
    source = textwrap.dedent(inspect.getsource(func))
    skip = {tokenize.COMMENT, tokenize.STRING, tokenize.NL, tokenize.NEWLINE,
            tokenize.INDENT, tokenize.DEDENT, tokenize.ENDMARKER}
    return code_tokens_of_source(source)


def code_tokens_of_source(source):
    """``source`` as tokens, with comments and strings dropped.

    Same reason as code_tokens: gui/app.py's own docstrings and comments
    discuss ``==`` and name compare_digest while explaining why they are
    not used, so only a token stream can count real call sites.
    """
    skip = {tokenize.COMMENT, tokenize.STRING, tokenize.NL, tokenize.NEWLINE,
            tokenize.INDENT, tokenize.DEDENT, tokenize.ENDMARKER}
    return [tok for tok in tokenize.generate_tokens(io.StringIO(source).readline)
            if tok.type not in skip]


class TestAuthInternals(unittest.TestCase):
    """Two claims about _Auth that a request cannot observe from outside.

    Both were holes the round's own review found: the suite could not tell
    ``hmac.compare_digest`` from ``==`` (a mutation run proved it: both
    substitutions left every test green), and the session cap had no test
    at all. Neither is reachable through HTTP -- one is a timing property,
    the other needs 30-odd exchanges to observe -- so they are checked here,
    directly, rather than pretended at through the socket.
    """

    def test_the_secrets_are_compared_with_compare_digest_not_equals(self):
        """A source-level check, and deliberately not a timing measurement.

        Timing a comparison from Python is noise at this scale; what can be
        stated exactly is the thing the design actually pins, which is that
        these two functions call hmac.compare_digest and never put a secret
        on either side of ``==``. Without this, a future edit can quietly put
        ``presented == self.key`` back and ship green -- which is exactly
        what the mutation run found.
        """
        # The comparison now lives in one helper, _secret_eq, because a
        # bare compare_digest on a str RAISES on any non-ASCII character
        # and every value compared here is attacker-supplied. So this
        # asserts two things, not one: the two callers delegate to that
        # helper and compare nothing themselves, and the helper is the
        # constant-time, encode-first comparison it claims to be.
        for func in (gui_app._Auth.key_ok, gui_app._Auth.session_ok):
            with self.subTest(func=func.__name__):
                tokens = code_tokens(func)
                names = [t.string for t in tokens if t.type == tokenize.NAME]
                ops = [t.string for t in tokens if t.type == tokenize.OP]
                self.assertIn(
                    "_secret_eq", names,
                    "%s does not route its comparison through _secret_eq, "
                    "which is the only place a secret is compared in "
                    "constant time AND without raising on non-ASCII"
                    % func.__name__)
                for operator in ("==", "!="):
                    self.assertNotIn(
                        operator, ops,
                        "%s compares with %s; secrets are compared with "
                        "hmac.compare_digest, in constant time, or the "
                        "wrong guess is distinguishable from the nearly "
                        "right one by how long the answer takes"
                        % (func.__name__, operator))

        helper = code_tokens(gui_app._secret_eq)
        names = [t.string for t in helper if t.type == tokenize.NAME]
        ops = [t.string for t in helper if t.type == tokenize.OP]
        self.assertIn("compare_digest", names,
                      "_secret_eq does not call hmac.compare_digest")
        self.assertIn(
            "encode", names,
            "_secret_eq must encode both sides before comparing them: "
            "hmac.compare_digest raises TypeError on a str holding a "
            "non-ASCII character, and that str is attacker-supplied")
        for operator in ("==", "!="):
            self.assertNotIn(
                operator, ops,
                "_secret_eq compares with %s" % operator)

        # Exactly one call site in the whole module. Without this, a future
        # edit can add a second bare compare_digest somewhere else and
        # reintroduce the raise this helper exists to absorb.
        module = code_tokens_of_source(
            inspect.getsource(gui_app).replace("\r\n", "\n"))
        calls = [t.string for t in module if t.type == tokenize.NAME]
        self.assertEqual(
            calls.count("compare_digest"), 1,
            "hmac.compare_digest is called at %d sites in gui/app.py; it "
            "must be called at exactly one, inside _secret_eq, so that "
            "'secrets are compared in constant time and never raise' is a "
            "property of one function instead of a habit"
            % calls.count("compare_digest"))

    def test_sessions_are_capped_and_the_oldest_is_the_one_dropped(self):
        """MAX_SESSIONS is a bound on this process's credential set.

        Not an attack surface -- minting a session needs the key -- but an
        unbounded list on a long-running server is a slow leak, and a cap
        that drops the WRONG end would log the operator's live browser out
        while keeping stale sessions valid.
        """
        cap = gui_app.MAX_SESSIONS
        auth = gui_app._Auth(enabled=True)
        issued = [auth.new_session() for _ in range(cap + 3)]
        self.assertEqual(len(auth.sessions()), cap)
        self.assertEqual(auth.sessions(), issued[3:],
                         "the cap dropped the wrong end of the list")
        for stale in issued[:3]:
            self.assertFalse(
                auth.session_ok("%s=%s" % (gui_app.SESSION_COOKIE, stale)),
                "an evicted session still authenticates")
        for live in (issued[3], issued[-1]):
            self.assertTrue(
                auth.session_ok("%s=%s" % (gui_app.SESSION_COOKIE, live)),
                "a session inside the cap stopped working")


class TestErrorEnvelope(ServerCase):
    """The contract: every failure is JSON {"error": {reason, detail}}."""

    def test_unused_methods_are_json_not_html(self):
        for method in ("PUT", "PATCH", "DELETE", "OPTIONS"):
            with self.subTest(method=method):
                status, obj, raw = self.call(method, "/api/mint/status")
                self.assertEqual(status, 405, raw[:200])
                self.assert_envelope(status, obj, raw)

    def test_a_method_with_no_handler_at_all_is_json(self):
        """TRACE never reaches a do_* method: BaseHTTPRequestHandler answers
        it itself, with an HTML page, unless send_error is overridden."""
        raw = raw_request(
            self.port,
            "TRACE / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        status, headers, body = split_response(raw)
        self.assertGreaterEqual(status, 400)
        self.assertIn("application/json", headers.get("content-type", ""))
        self.assertIn("error", json.loads(body))

    def test_unknown_route_and_wrong_method(self):
        status, obj, raw = self.call("GET", "/api/nope")
        self.assertEqual(status, 404)
        self.assert_envelope(status, obj, raw)
        status, obj, raw = self.call("GET", "/api/wallet/pay")
        self.assertEqual(status, 405)
        self.assert_envelope(status, obj, raw)

    def test_component_crash_is_one_sentence_not_a_traceback(self):
        FakeWalletOps.fail_with = RuntimeError("something internal exploded")
        status, obj, raw = self.call("POST", "/api/wallet/pay",
                                     {"name": "alice", "amount_mc": 5})
        self.assertEqual(status, 500)
        self.assert_envelope(status, obj, raw)
        self.assertEqual(obj["error"]["reason"], "component_error")

    def test_reasons_are_one_vocabulary(self):
        """walletops phrases its reasons for a human ("insufficient funds");
        a client cannot switch on a mixture of those and snake_case."""
        FakeWalletOps.fail_with = ("insufficient funds", "alice holds 4 mc")
        status, obj, _ = self.call("POST", "/api/wallet/pay",
                                   {"name": "alice", "amount_mc": 5000})
        self.assertEqual(status, 400)
        self.assertEqual(obj["error"]["reason"], "insufficient_funds")
        self.assertEqual(obj["error"]["detail"], "alice holds 4 mc")
        for reason in self.every_reason():
            self.assertRegex(reason, r"^[a-z0-9]+(_[a-z0-9]+)*$")

    def every_reason(self):
        out = []
        for method, path, body in (
                ("GET", "/api/nope", None),
                ("POST", "/api/wallet/pay", {"name": "../x", "amount_mc": 1}),
                ("POST", "/api/wallet/pay", {"name": "ghost", "amount_mc": 1}),
                ("POST", "/api/wallet/quote", {"name": "alice", "amount_mc": 0}),
                ("POST", "/api/mint/issue", {"amount_mc": -1}),
        ):
            _s, obj, _raw = self.call(method, path, body)
            out.append(obj["error"]["reason"])
        return out


class TestInputIsMoney(ServerCase):
    def test_a_fractional_amount_is_refused_not_rounded(self):
        for amount in (12.7, "12.7", "12abc", None, True, [12], 1e400):
            with self.subTest(amount=amount):
                body = json.dumps({"name": "alice", "amount_mc": amount})
                conn = http.client.HTTPConnection("127.0.0.1", self.port,
                                                  timeout=10)
                conn.request("POST", "/api/wallet/pay", body,
                             {"Content-Type": "application/json",
                              "Cookie": self.cookie})
                response = conn.getresponse()
                raw = response.read()
                conn.close()
                self.assertEqual(response.status, 400, raw[:200])
        self.assertEqual([c for c in FakeWalletOps.calls if c[0] == "pay"], [],
                         "a non-integer amount reached the wallet")

    def test_a_whole_number_as_a_float_still_works(self):
        status, obj, raw = self.call("POST", "/api/wallet/pay",
                                     {"name": "alice", "amount_mc": 12.0})
        self.assertEqual(status, 200, raw[:200])
        self.assertIn(("pay", "alice", 12), FakeWalletOps.calls)

    def test_absurd_amounts_get_a_sentence_not_the_mints_500(self):
        status, obj, _ = self.call("POST", "/api/wallet/pay",
                                   {"name": "alice", "amount_mc": 10 ** 25})
        self.assertEqual(status, 400)
        self.assertIn("at most", obj["error"]["detail"])

    def test_wallet_names_cannot_escape_the_workdir(self):
        for name in ("../../etc/passwd", "..", "/tmp/pwn", "a" * 80,
                     "aliçe", "a\x00b"):
            with self.subTest(name=name):
                status, obj, _ = self.call("POST", "/api/wallet/create",
                                           {"name": name})
                self.assertEqual(status, 400)
                self.assertEqual(obj["error"]["reason"], "bad_name")


class TestCredentialAndSideEffects(ServerCase):
    def test_the_admin_token_never_leaves_this_process(self):
        FakeWalletOps.fail_with = FakeWalletOpsError(
            "mint refused", "ran: curl -H 'X-Admin-Token: %s'" % ADMIN_TOKEN)
        seen = []
        for method, path, body in (
                ("GET", "/", None),
                ("GET", "/api/mint/status", None),
                ("GET", "/api/mint/logs?lines=50", None),
                ("GET", "/api/wallet/list", None),
                ("POST", "/api/wallet/pay", {"name": "alice", "amount_mc": 1}),
        ):
            _s, _o, raw = self.call(method, path, body)
            seen.append(raw)
        for raw in seen:
            self.assertNotIn(ADMIN_TOKEN.encode(), raw)
        self.assertIn(b"[admin token redacted]", seen[-1])
        with open(os.path.join(REPO, "gui", "page.html"), "rb") as handle:
            self.assertNotIn(b"X-Admin-Token", handle.read())

    def test_get_status_does_not_write_to_the_workdir(self):
        def snapshot():
            out = {}
            for root, _dirs, files in os.walk(self.workdir):
                for name in files:
                    path = os.path.join(root, name)
                    out[path] = os.stat(path).st_mtime_ns
            return out
        before = snapshot()
        for _ in range(3):
            self.call("GET", "/api/mint/status")
            self.call("GET", "/api/wallet/list")
        self.assertEqual(snapshot(), before)

    def test_start_remembers_what_it_started(self):
        """So a later Stop/Start cannot quietly re-send a default policy."""
        body = {"mint_id": "policy-mint", "baseline_model_class": "baseline-v1",
                "port": 8787, "rate_ppm": 10000, "cap_mc": 1000,
                "exempt_below_mc": 10}
        status, obj, raw = self.call("POST", "/api/mint/start", body)
        self.assertEqual(status, 200, raw[:300])
        self.assertEqual(obj["last_start"], body)
        status, obj, _ = self.call("GET", "/api/mint/status")
        self.assertEqual(obj["last_start"], body)
        # and it survives this GUI process forgetting everything
        fresh = gui_app.Api(self.workdir)
        self.assertEqual(fresh.mint_status()["last_start"], body)

    def test_a_refused_start_is_actionable(self):
        for body, word in (
            ({"mint_id": "NOPE", "baseline_model_class": "b", "port": 1,
              "rate_ppm": 0, "cap_mc": 0, "exempt_below_mc": 10}, "lowercase"),
            ({"mint_id": "ok", "baseline_model_class": "", "port": 1,
              "rate_ppm": 0, "cap_mc": 0, "exempt_below_mc": 10}, "empty"),
            ({"mint_id": "ok", "baseline_model_class": "b", "port": 99999,
              "rate_ppm": 0, "cap_mc": 0, "exempt_below_mc": 10}, "65535"),
            ({"mint_id": "ok", "baseline_model_class": "b", "port": 1,
              "rate_ppm": 1.5, "cap_mc": 0, "exempt_below_mc": 10}, "whole"),
        ):
            status, obj, _ = self.call("POST", "/api/mint/start", body)
            self.assertEqual(status, 400)
            self.assertIn(word, obj["error"]["detail"])


class TestConnectionHygiene(ServerCase):
    def test_a_half_sent_body_cannot_pin_a_thread_forever(self):
        """Content-Length: 500 followed by four bytes and silence."""
        # The shipped default is what protects a real operator; the test
        # then shortens it so the mechanism can be watched in two seconds.
        self.assertIsNotNone(gui_app.Handler.timeout,
                             "no deadline on a connection at all")
        self.assertLessEqual(gui_app.Handler.timeout, 60)
        old = gui_app.Handler.timeout
        gui_app.Handler.timeout = 2
        try:
            started = time.monotonic()
            sock = socket.create_connection(("127.0.0.1", self.port), timeout=20)
            try:
                sock.sendall(b"POST /api/wallet/pay HTTP/1.1\r\n"
                             b"Host: 127.0.0.1\r\n"
                             + b"Cookie: " + self.cookie.encode() + b"\r\n"
                             + b"Content-Type: application/json\r\n"
                             b"Content-Length: 500\r\n\r\nabcd")
                sock.settimeout(15)
                data = sock.recv(4096)
            finally:
                sock.close()
            waited = time.monotonic() - started
            self.assertTrue(data, "the server never answered and never hung up")
            self.assertLess(waited, 12, "no deadline on a stalled request")
        finally:
            gui_app.Handler.timeout = old
        self.assertEqual([c for c in FakeWalletOps.calls if c[0] == "pay"], [])

    def test_one_connection_serves_two_requests(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        for _ in range(2):
            conn.request("GET", "/api/mint/status", None,
                         {"Accept": "application/json",
                          "Cookie": self.cookie})
            response = conn.getresponse()
            payload = json.loads(response.read())
            self.assertEqual(response.status, 200)
            self.assertIn("running", payload)
        conn.close()


class TestDegradedComponents(unittest.TestCase):
    """app.py must survive the two files it does not own being absent."""

    def test_missing_component_is_a_503_naming_the_file(self):
        workdir = tempfile.mkdtemp(prefix="guiapp-missing-")
        saved = sys.modules.pop("mintctl")
        gui_dir = os.path.join(REPO, "gui")
        hidden = [p for p in sys.path if os.path.abspath(p) == gui_dir]
        for p in hidden:
            sys.path.remove(p)          # as if mintctl.py were not written yet
        try:
            api = gui_app.Api(workdir)
            with self.assertRaises(gui_app.GuiError) as caught:
                api.mint_status()
            self.assertEqual(caught.exception.status, 503)
            self.assertIn("mintctl.py", caught.exception.detail)
        finally:
            sys.path[:0] = hidden
            sys.modules["mintctl"] = saved
            shutil.rmtree(workdir, ignore_errors=True)

    def test_a_component_that_returns_the_wrong_shape_is_a_502(self):
        class Wrong(FakeMintControl):
            def status(self):
                return ["not", "a", "dict"]
        workdir = tempfile.mkdtemp(prefix="guiapp-wrong-")
        saved = sys.modules["mintctl"]
        module = types.ModuleType("mintctl")
        module.MintControl = Wrong
        module.MintControlError = FakeMintControlError
        sys.modules["mintctl"] = module
        try:
            api = gui_app.Api(workdir)
            with self.assertRaises(gui_app.GuiError) as caught:
                api.mint_status()
            self.assertEqual(caught.exception.status, 502)
        finally:
            sys.modules["mintctl"] = saved
            shutil.rmtree(workdir, ignore_errors=True)


class TestBindRules(unittest.TestCase):
    def test_a_routable_address_is_refused_with_the_right_port(self):
        with self.assertRaises(SystemExit) as caught:
            gui_app.require_loopback("0.0.0.0", 8860)
        message = str(caught.exception)
        self.assertIn("not a loopback", message)
        self.assertIn("ssh -L 8860:127.0.0.1:8860", message)

    def test_ipv6_loopback_binds_instead_of_failing_as_a_busy_port(self):
        try:
            family = gui_app.require_loopback("::1", 0)
        except SystemExit as exc:
            self.skipTest("no ::1 on this machine: %s" % exc)
        self.assertEqual(family, socket.AF_INET6)
        workdir = tempfile.mkdtemp(prefix="guiapp-v6-")
        try:
            httpd = gui_app.serve(0, workdir, "::1")
        except OSError as exc:
            # No ::1 configured is a fact about the machine; anything else
            # (wrong address family, say) is this file's bug and must fail.
            if exc.errno in (errno.EADDRNOTAVAIL, errno.ENETUNREACH):
                self.skipTest("::1 is not configured on this machine")
            raise
        try:
            self.assertEqual(httpd.address_family, socket.AF_INET6)
            thread = threading.Thread(target=httpd.serve_forever,
                                      kwargs={"poll_interval": 0.05},
                                      daemon=True)
            thread.start()
            cookie = exchange_cookie(httpd, host="::1")
            conn = http.client.HTTPConnection("::1", httpd.server_address[1],
                                              timeout=10)
            conn.request("GET", "/api/mint/status", None,
                         {"Host": "[::1]:%d" % httpd.server_address[1],
                          "Cookie": cookie})
            self.assertEqual(conn.getresponse().status, 200)
            conn.close()
            httpd.shutdown()
            thread.join(timeout=5)
        finally:
            httpd.server_close()
            shutil.rmtree(workdir, ignore_errors=True)


class TestStartupCredential(unittest.TestCase):
    """app.py started the way an operator starts it, as a real process.

    Everything else in this file drives a GuiServer inside the test
    process, which cannot see what main() prints, cannot see stderr, and
    cannot prove what the default is when no flags are passed. These two
    tests can, so they are the ones that pin points 1 and 6: the key is
    printed once and only to the terminal, and authentication is ON unless
    --no-auth is asked for out loud.
    """

    def setUp(self):
        self.workdir = tempfile.mkdtemp(prefix="guiauth-")
        self.proc = None
        self.readers = []
        self.out = []
        self.err = []

    def tearDown(self):
        self._stop()
        shutil.rmtree(self.workdir, ignore_errors=True)

    def _stop(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=15)
        for thread in self.readers:
            thread.join(timeout=5)
        if self.proc is not None:
            for stream in (self.proc.stdout, self.proc.stderr):
                try:
                    stream.close()
                except Exception:
                    pass

    def _spawn(self, *flags):
        """Run gui/app.py for real and wait until it says it is listening."""
        port = free_port()
        self.proc = subprocess.Popen(
            [sys.executable, os.path.join(REPO, "gui", "app.py"),
             "--port", str(port), "--workdir", self.workdir] + list(flags),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for stream, sink in ((self.proc.stdout, self.out),
                             (self.proc.stderr, self.err)):
            thread = threading.Thread(
                target=lambda s=stream, k=sink: [k.append(line) for line in s],
                daemon=True)
            thread.start()
            self.readers.append(thread)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if any("OPEN" in line for line in list(self.out)):
                return port
            if self.proc.poll() is not None:
                self.fail("app.py exited %s:\n%s%s"
                          % (self.proc.returncode, "".join(self.out),
                             "".join(self.err)))
            time.sleep(0.05)
        self.fail("app.py never printed a URL:\n%s%s"
                  % ("".join(self.out), "".join(self.err)))

    def url_line(self):
        return [line for line in self.out if "OPEN" in line][0]

    # -- 6. auth is the default, --no-auth is the exception -------------
    def test_running_with_no_flags_is_authenticated(self):
        port = self._spawn()
        line = self.url_line()
        self.assertIn("?k=", line, "the startup URL carries no key")
        key = line.split("?k=")[1].split()[0]
        self.assertGreaterEqual(len(key), 32)
        self.assertNotIn("no-auth", "".join(self.err).lower(),
                         "the unauthenticated warning was printed anyway")

        # no credential at all: shut, and with this GUI's error envelope
        status, _headers, raw = http_call(port, "GET", "/api/wallet/list")
        self.assertEqual(status, 401, raw[:200])
        self.assertEqual(json.loads(raw)["error"]["reason"], "unauthorized")
        status, _headers, raw = http_call(
            port, "POST", "/api/mint/issue", {"amount_mc": 1000, "count": 1})
        self.assertEqual(status, 401, raw[:200])

        # the key alone does not open the API either
        status, _headers, raw = http_call(port, "GET",
                                          "/api/wallet/list?k=" + key)
        self.assertEqual(status, 401, raw[:200])

        # the printed URL opens the page, once, for a cookie; the cookie
        # opens the API
        status, headers, raw = http_call(port, "GET", "/?k=" + key)
        self.assertEqual(status, 200, raw[:200])
        cookie = headers["set-cookie"].split(";")[0]
        session = cookie.split("=", 1)[1]
        status, _headers, raw = http_call(port, "GET", "/api/wallet/list",
                                          headers={"Cookie": cookie})
        self.assertEqual(status, 200, raw[:200])
        self.assertNotIn(key.encode(), raw)
        self.assertNotIn(session.encode(), raw)

        # the rebinding defence survives a real process too
        status, _headers, raw = http_call(port, "GET", "/api/wallet/list",
                                          headers={"Cookie": cookie,
                                                   "Host": "evil.example.com"})
        self.assertEqual(status, 403, raw[:200])

        # grep the live instance: neither secret is in any file it wrote
        files = 0
        for root, _dirs, names in os.walk(self.workdir):
            for name in names:
                full = os.path.join(root, name)
                self.assertNotIn(key, full)
                self.assertNotIn(session, full)
                with open(full, "rb") as handle:
                    blob = handle.read()
                self.assertNotIn(key.encode(), blob, full)
                self.assertNotIn(session.encode(), blob, full)
                files += 1

        # ...nor in anything it logged. The key is printed exactly once,
        # in the URL; the session is never printed at all.
        self._stop()
        stdout, stderr = "".join(self.out), "".join(self.err)
        self.assertEqual(stdout.count(key), 1,
                         "the key reached the terminal more than the one "
                         "time it is meant to")
        self.assertNotIn(key, stderr)
        self.assertNotIn(session, stdout)
        self.assertNotIn(session, stderr)
        # and the requests above left no request log at all to carry them
        self.assertNotIn("/api/wallet/list", stdout)
        self.assertNotIn("/api/wallet/list", stderr)

    def test_no_auth_opens_the_api_and_shouts_about_it(self):
        port = self._spawn("--no-auth")
        self.assertNotIn("?k=", self.url_line(),
                         "--no-auth printed a key it does not use")

        status, headers, raw = http_call(port, "GET", "/api/wallet/list")
        self.assertEqual(status, 200, raw[:200])
        self.assertNotIn("set-cookie", headers)
        status, _headers, raw = http_call(port, "GET", "/")
        self.assertEqual(status, 200, raw[:200])

        warning = "".join(self.err)
        self.assertGreaterEqual(len(warning.strip().splitlines()), 5,
                                "the warning is not the loud multi-line one")
        self.assertIn("no-auth", warning.lower())
        self.assertIn("NO PASSWORD", warning)
        self.assertIn("mint money", warning)
        self.assertIn(self.workdir, warning)

        # --no-auth removes the credential. It does not remove the two
        # controls that stop a web page in the operator's browser.
        status, _headers, raw = http_call(port, "GET", "/api/wallet/list",
                                          headers={"Host": "evil.example.com"})
        self.assertEqual(status, 403, raw[:200])
        status, _headers, raw = http_call(
            port, "GET", "/api/wallet/list",
            headers={"Origin": "http://evil.example.com"})
        self.assertEqual(status, 403, raw[:200])


# The DOM shim and fake API that page.html runs against. It lives here
# rather than in its own file so this test module is self-contained.
PAGE_HARNESS = r'''/* Drives gui/page.html's real JavaScript under a minimal DOM, against a
   fake GUI server, and prints what the page did as JSON.
   usage: node harness.js <page.html> <burn-table.json> */
"use strict";
const fs = require("fs");

/* ---------- a DOM small enough to read, big enough to run the page ---- */
function makeDom() {
  const nodes = new Map();
  function el(id) {
    return {
      id: id, textContent: "", innerHTML: "", value: "", disabled: false,
      hidden: false, className: "", open: false, scrollTop: 0,
      scrollHeight: 0, dataset: {}, style: {},
      listeners: {},
      addEventListener(ev, fn) { (this.listeners[ev] = this.listeners[ev] || []).push(fn); },
      fire(ev, arg) { for (const fn of (this.listeners[ev] || [])) fn(arg || {}); },
      querySelectorAll() { return []; },
      select() {}
    };
  }
  const document = {
    getElementById(id) {
      if (!nodes.has(id)) nodes.set(id, el(id));
      return nodes.get(id);
    }
  };
  return {document: document, nodes: nodes};
}

/* ---------- a fake GUI server: the API app.py promises ---------------- */
function makeServer(opts) {
  const P = () => state.policy;
  const state = {
    running: true,
    policy: {rate_ppm: 10000, cap_mc: 1000, exempt_below_mc: 10},
    balances: {alice: 20000, bob: 0},
    last_start: null,
    calls: []
  };
  function burn(sum) {
    if (sum <= P().exempt_below_mc) return 0;
    return Math.min(P().cap_mc, Math.floor((sum * P().rate_ppm) / 1000000));
  }
  function wallets() {
    return Object.keys(state.balances).map(n => ({
      name: n, balance_mc: state.balances[n], coin_count: 1,
      mint_id: "crit-mint", connected: state.running, error: null}));
  }
  function handle(path, body) {
    state.calls.push({path: path, body: body || null});
    const p = path.split("?")[0];
    if (p === "/api/mint/status") {
      return {status: 200, data: {
        running: state.running, pid: state.running ? 4242 : null,
        port: 8852, mint_id: "crit-mint",
        base_url: "http://127.0.0.1:8852",
        started_at_ms: state.running ? Date.now() : null,
        last_error: null, last_start: state.last_start}};
    }
    if (p === "/api/mint/descriptor") {
      if (!state.running) return {status: 409, data: {error: {reason: "mint_stopped", detail: "stopped"}}};
      return {status: 200, data: {
        mint_id: "crit-mint", baseline_model_class: "baseline-v1",
        mint_time: 1700000000000, denominations_mc: [1, 10, 100, 1000],
        burn_policy: P(), burn_policy_next: null}};
    }
    if (p === "/api/mint/logs") return {status: 200, data: {lines: ["x"]}};
    if (p === "/api/wallet/list") return {status: 200, data: {wallets: wallets(), dir: "/var/wallets"}};
    if (p === "/api/wallet/history") {
      // app.py emits the machine reason under `cause`, never `reason`. The
      // rows are supplied in the SERVER'S OWN SHAPE on purpose: a test that
      // fed a `reason` key would pass against a page that never reads one.
      return {status: 200, data: {name: "alice",
              history: (opts && opts.history) || []}};
    }
    if (p === "/api/wallet/outstanding") {
      if (opts && opts.outstandingFails)
        return {status: 404, data: {error: {reason: "wallet_not_found",
                detail: "There is no wallet called that.", cause: "unknown"}}};
      return {status: 200, data: {name: "alice", checked: true,
              mint_id: "crit-mint",
              payments: (opts && opts.outstanding) || []}};
    }
    // §7.3 fixed point, as aicash.channels._gross_for_net does it: the
    // wallet must hand over G with G - burn(G) == amount.
    function gross(a) { let g = a; for (let i = 0; i < 40; i++) { const n = a + burn(g); if (n === g) break; g = n; } return g; }
    if (p === "/api/wallet/quote") {
      if (opts && opts.quoteError) return {status: 400, data: {error: opts.quoteError}};
      const a = body.amount_mc, g = gross(a);
      return {status: 200, data: {name: body.name, amount_mc: a,
              burn_mc: burn(g), change_mc: 0, inputs_mc: g}};
    }
    if (p === "/api/wallet/pay") {
      const a = body.amount_mc, g = gross(a);
      state.balances[body.name] -= g;
      state.lastPaid = a;
      return {status: 200, data: {name: body.name, tokens: ["aicash:v3:crit-mint:" + a + ":zz"],
              amount_mc: a, burn_mc: burn(g), balance_mc: state.balances[body.name]}};
    }
    if (p === "/api/wallet/receive") {
      const toks = body.tokens || [];
      if (opts && opts.rejectAll) {
        return {status: 200, data: {name: body.name, accepted: 0, accepted_mc: 0,
                rejected: toks.map(t => ({token: t, reason: "malformed_token", detail: "not a token"})),
                balance_mc: state.balances[body.name] || 0}};
      }
      let sum = 0;
      for (const t of toks) sum += parseInt(String(t).split(":")[3], 10) || 0;
      const b = burn(sum);
      state.balances[body.name] = (state.balances[body.name] || 0) + sum - b;
      return {status: 200, data: {name: body.name, accepted: toks.length,
              accepted_mc: sum - b, rejected: [],
              balance_mc: state.balances[body.name]}};
    }
    if (p === "/api/mint/stop") { state.running = false; return handle("/api/mint/status"); }
    if (p === "/api/mint/start") {
      state.running = true;
      state.policy = {rate_ppm: body.rate_ppm, cap_mc: body.cap_mc,
                      exempt_below_mc: body.exempt_below_mc};
      state.last_start = {mint_id: body.mint_id,
                          baseline_model_class: body.baseline_model_class,
                          port: body.port, rate_ppm: body.rate_ppm,
                          cap_mc: body.cap_mc, exempt_below_mc: body.exempt_below_mc};
      return handle("/api/mint/status");
    }
    return {status: 404, data: {error: {reason: "not_found", detail: p}}};
  }
  return {state: state, handle: handle, burn: burn};
}

/* ---------- load the page's own script ------------------------------- */
function loadPage(src, server) {
  const dom = makeDom();
  const g = globalThis;
  g.document = dom.document;
  g.window = {};
  g.navigator = {};
  g.localStorage = {getItem() { return null; }, setItem() {}};
  g.setInterval = () => 0;          // no background polling inside a test
  g.fetch = async (path, init) => {
    if (server.state.dead) throw new TypeError("fetch failed: ECONNREFUSED");
    const body = init && init.body ? JSON.parse(init.body) : null;
    const r = server.handle(path, body);
    return {ok: r.status >= 200 && r.status < 300, status: r.status,
            json: async () => r.data};
  };
  const exported = ["refreshAll", "refreshMint", "refreshQuote", "scheduleQuote",
    "payNow", "receiveNow", "startMint", "stopMint", "renderMint",
    "applyDescriptor", "setActive", "burnFor", "payCost", "costSentence",
    "refreshDescriptor", "issueInto", "refreshHistory", "refreshWallets",
    "savedCopyNote", "renderWallets"];
  const body = src + "\nreturn {" + exported.map(n => n + ":" + n).join(",") +
    ", peek: () => ({lastQuote: lastQuote, policy: policy, mint: mint, " +
    "active: active, settingsEdited: settingsEdited})};";
  const api = new Function(body)();
  return {dom: dom, page: api, $: id => dom.document.getElementById(id)};
}

function pageScript(path) {
  const html = fs.readFileSync(path, "utf8");
  const m = html.match(/<script>\n([\s\S]*)<\/script>/);
  if (!m) throw new Error("no inline <script> in " + path);
  return m[1];
}

const settle = () => new Promise(r => setTimeout(r, 0));

/* ---------- scenarios ------------------------------------------------- */
async function main() {
  const src = pageScript(process.argv[2]);
  const table = JSON.parse(fs.readFileSync(process.argv[3], "utf8"));
  const out = {};

  /* S1 — the cost line must predict what actually happens. */
  {
    const server = makeServer({});
    const h = loadPage(src, server);
    await h.page.refreshAll(); await settle();
    h.$("p-amount").value = "300";
    h.$("p-to").value = "bob";
    await h.page.refreshQuote(); await settle();
    const quoteText = h.$("p-quote").innerHTML;
    const button = h.$("p-go").textContent;
    const predicted = h.page.peek().lastQuote.cost;
    await h.page.payNow(); await settle();
    out.s1 = {quote: quoteText, button: button, predicted: predicted,
              bob_balance: server.state.balances.bob,
              paid: server.state.lastPaid,
              result: h.$("p-out").innerHTML};
  }

  /* S2 — the amount changes after the quote; a click inside the debounce
     window must not pay the new amount. */
  {
    const server = makeServer({});
    const h = loadPage(src, server);
    await h.page.refreshAll(); await settle();
    h.$("p-amount").value = "100";
    h.$("p-to").value = "bob";
    await h.page.refreshQuote(); await settle();
    const before = {label: h.$("p-go").textContent, disabled: h.$("p-go").disabled};
    h.$("p-amount").value = "4000";
    h.$("p-amount").fire("input");           // the real listener, not a copy
    const afterType = {disabled: h.$("p-go").disabled};
    await h.page.payNow(); await settle();   // the click, inside the debounce
    out.s2 = {before: before, afterType: afterType,
              pays: server.state.calls.filter(c => c.path === "/api/wallet/pay"),
              bob_balance: server.state.balances.bob,
              message: h.$("p-out").innerHTML};
  }

  /* S2b — the box changed but no event fired (a script, an autofill, a
     click that landed between the keystroke and the debounce). payNow must
     still refuse: the quote, not the box, is what was agreed to. */
  {
    const server = makeServer({});
    const h = loadPage(src, server);
    await h.page.refreshAll(); await settle();
    h.$("p-amount").value = "100";
    h.$("p-to").value = "bob";
    await h.page.refreshQuote(); await settle();
    h.$("p-amount").value = "4000";          // no "input" event at all
    await h.page.payNow(); await settle();
    out.s2b = {pays: server.state.calls.filter(c => c.path === "/api/wallet/pay"),
               bob_balance: server.state.balances.bob,
               message: h.$("p-out").innerHTML};
  }

  /* S2c — a quote still in flight when the operator changes the amount
     must not land and re-arm the button behind them. */
  {
    const server = makeServer({});
    const h = loadPage(src, server);
    await h.page.refreshAll(); await settle();
    h.$("p-amount").value = "100";
    h.$("p-to").value = "bob";
    const inFlight = h.page.refreshQuote();   // not awaited: still asking
    h.$("p-amount").value = "4000";
    h.$("p-amount").fire("input");            // voids it mid-flight
    await inFlight; await settle();
    out.s2c = {quote: h.page.peek().lastQuote,
               disabled: h.$("p-go").disabled,
               label: h.$("p-go").textContent};
  }

  /* S3 — the settings panel must stay where the operator put it. */
  {
    const server = makeServer({});
    const h = loadPage(src, server);
    await h.page.refreshAll(); await settle();
    h.$("m-settings").open = true;           // the operator's click
    h.page.renderMint();                     // one poll tick
    h.page.renderMint();                     // another
    out.s3 = {open_after_renders: h.$("m-settings").open};
  }

  /* S4 — Stop then Start must not rewrite the mint's economics. */
  {
    const server = makeServer({});
    const h = loadPage(src, server);
    await h.page.refreshAll(); await settle();
    const policyBefore = Object.assign({}, server.state.policy);
    await h.page.stopMint(); await settle();
    await h.page.startMint(); await settle();
    out.s4 = {before: policyBefore, after: Object.assign({}, server.state.policy),
              form: {rate: h.$("m-rate").value, cap: h.$("m-cap").value,
                     exempt: h.$("m-exempt").value}};
  }

  /* S5 — a paste where every token is rejected is not a success. */
  {
    const server = makeServer({rejectAll: true});
    const h = loadPage(src, server);
    await h.page.refreshAll(); await settle();
    h.$("r-tokens").value = "garbage-one\ngarbage-two";
    await h.page.receiveNow(); await settle();
    out.s5 = {html: h.$("r-out").innerHTML};
  }

  /* S6 — the page's burn arithmetic against the mint's own. */
  {
    const server = makeServer({});
    const h = loadPage(src, server);
    out.s6 = table.map(row => h.page.burnFor(row.sum, row.policy));
  }

  /* S7 - a quote refusal must not reach the screen raw. The server sentence
     carries a section citation and already names the amount; the page used
     to prefix "Cannot pay X: " and print the citation. */
  {
    const server = makeServer({quoteError: {
      reason: "insufficient_funds",
      detail: "cannot pay 5000 mc: the wallet holds 990 mc and the burn is " +
              "charged on top of the amount (§7.3) — nothing was " +
              "sent to the mint: need 5009 mc, only 990 mc selectable",
      cause: "insufficient_funds"}});
    const h = loadPage(src, server);
    await h.page.refreshAll(); await settle();
    h.$("p-amount").value = "5000";
    h.$("p-to").value = "bob";
    await h.page.refreshQuote(); await settle();
    out.s7 = {html: h.$("p-quote").innerHTML};
  }

  /* S8 - history rows: the machine cause arrives under `cause`, and each of
     the three shapes must render as itself. */
  {
    const server = makeServer({history: [
      {ts_ms: 0, kind: "receive_failed", amount_mc: 0,
       detail: "redeeming 1 token (1000 mc face) did not commit",
       cause: "already_spent"},
      {ts_ms: 0, kind: "pay_failed", amount_mc: 0,
       detail: "nothing was recorded about this attempt",
       cause: "unknown"},
      {ts_ms: 0, kind: "receive", amount_mc: 1000,
       detail: "redeemed 1 token worth 1000 mc face", cause: ""},
      {ts_ms: 0, kind: "pay_failed", amount_mc: 0,
       detail: "the mint did not answer and refused nothing; whether it " +
               "ever saw this request is undetermined, so run recover()",
       cause: "mint_unreachable"}]});
    const h = loadPage(src, server);
    await h.page.refreshAll(); await settle();
    h.page.setActive("alice");
    await h.page.refreshHistory(); await settle();
    const rows = h.$("h-body").innerHTML.split("<tr").slice(1);
    out.s8 = {html: h.$("h-body").innerHTML, rows: rows};
  }

  /* S9 - an envelope whose `reason` app.py has English for must lead with
     that, NOT with the `unknown` cause app.py defaults local faults to.
     "unknown" means no money cause was determined; it is not a finding
     that the cause is undetermined. */
  {
    const server = makeServer({quoteError: {
      reason: "bad_name",
      detail: "A wallet name is 1-32 characters: letters, digits, hyphen " +
              "and underscore, starting with a letter or digit.",
      cause: "unknown"}});
    const h = loadPage(src, server);
    await h.page.refreshAll(); await settle();
    h.$("p-amount").value = "300";
    h.$("p-to").value = "bob";
    await h.page.refreshQuote(); await settle();
    out.s9 = {html: h.$("p-quote").innerHTML};
  }

  /* S10 - app.py unreachable: balances must be marked stale everywhere they
     appear, the section-3 header included, and nothing may be reported
     about the MINT, which is a different process and may well be up. */
  {
    const server = makeServer({});
    const h = loadPage(src, server);
    await h.page.refreshAll(); await settle();
    const beforeHidden = h.$("active-stale").hidden;
    h.page.setActive("alice"); await settle();
    server.state.dead = true;
    await h.page.refreshWallets(); await settle();
    out.s10 = {beforeHidden: beforeHidden,
               staleHidden: h.$("active-stale").hidden,
               banner: h.$("auth-banner").innerHTML,
               list: h.$("w-list").innerHTML,
               header: h.$("hdr-state").textContent};
  }

  /* S11 - the payment strings are NOT the only copy, and the page must
     establish that by reading them back rather than by asserting it. */
  {
    const tok = "aicash:v3:crit-mint:300:zz";
    const server = makeServer({outstanding: [
      {op_id: "op-1", amount_mc: 300, live_mc: 300,
       tokens: [{token: tok, amount_mc: 300, state: "unspent"}]}]});
    const h = loadPage(src, server);
    await h.page.refreshAll(); await settle();
    h.page.setActive("alice"); await settle();
    // Through the REAL payment path, not by calling the helper: a helper
    // that exists but is never wired into payNow leaves the false sentence
    // on screen, which is exactly the defect.
    h.$("p-amount").value = "300";
    h.$("p-to").value = "";              // no recipient: strings to the screen
    await h.page.refreshQuote(); await settle();
    await h.page.payNow(); await settle(); await settle();
    out.s11paid = {html: h.$("p-out").innerHTML};
    const confirmed = await h.page.savedCopyNote("alice", [tok]);
    const partial = await h.page.savedCopyNote("alice", [tok, "aicash:v3:crit-mint:1:qq"]);
    const server2 = makeServer({outstandingFails: true});
    const h2 = loadPage(src, server2);
    await h2.page.refreshAll(); await settle();
    h2.page.setActive("alice"); await settle();
    const cannotCheck = await h2.page.savedCopyNote("alice", [tok]);
    out.s11 = {confirmed: confirmed, partial: partial,
               cannotCheck: cannotCheck,
               asked: server.state.calls.filter(
                 c => c.path.indexOf("/api/wallet/outstanding") === 0).length};
  }

  process.stdout.write(JSON.stringify(out, null, 1));
}
main().then(() => process.exit(0), e => {
  process.stderr.write("HARNESS ERROR: " + (e && e.stack || e) + "\n");
  process.exit(1);
});
'''


# ======================================================================
# WHY A FAILURE FAILED, from the layer that knows, unchanged on the way out
# ======================================================================
class TestFailureCauses(ServerCase):
    """One closed vocabulary, carried through, never re-guessed here.

    The component that determined the cause is the only thing that could:
    it saw the exception type and the mint's own answer. This server adds
    exactly one fact of its own (the mint process is not running) and
    otherwise passes the cause along untouched.
    """

    def error_of(self, *call_args, **kw):
        status, obj, raw = self.call(*call_args, **kw)
        self.assertGreaterEqual(status, 400, raw[:200])
        self.assertIsInstance(obj, dict, raw[:200])
        return obj["error"]

    def test_a_components_cause_reaches_the_page_unchanged(self):
        for cause in ("mint_rejected", "already_spent", "malformed_token",
                      "wrong_mint", "insufficient_funds", "unknown"):
            with self.subTest(cause=cause):
                FakeWalletOps.fail_with = ("rejected by mint", "nope", cause)
                error = self.error_of("POST", "/api/wallet/pay",
                                      {"name": "alice", "amount_mc": 5})
                self.assertEqual(error["cause"], cause)

    def test_a_component_that_names_no_cause_is_undetermined(self):
        """An older walletops.py, or one that forgot: unknown, not a story."""
        FakeWalletOps.fail_with = ("wallet store error", "sqlite said no")
        error = self.error_of("POST", "/api/wallet/pay",
                              {"name": "alice", "amount_mc": 5})
        self.assertEqual(error["cause"], "unknown")

    def test_an_invented_cause_cannot_widen_the_vocabulary(self):
        FakeWalletOps.fail_with = ("rejected by mint", "nope", "cosmic_rays")
        error = self.error_of("POST", "/api/wallet/pay",
                              {"name": "alice", "amount_mc": 5})
        self.assertEqual(error["cause"], "unknown")

    def test_unreachable_is_sharpened_to_stopped_only_when_it_is_known(self):
        """The one thing this file knows that walletops.py cannot.

        Running: a socket that did not answer is all anybody saw, and the
        cause stays the weaker claim. Not running: this process supervises
        the mint, so it can say so.
        """
        FakeWalletOps.fail_with = ("mint unreachable", "no answer",
                                   "mint_unreachable")
        self.control.running = True
        error = self.error_of("POST", "/api/wallet/pay",
                              {"name": "alice", "amount_mc": 5})
        self.assertEqual(error["cause"], "mint_unreachable")

        # Not running, and the route still reaches the component because
        # the wallet read does not require a live mint.
        self.control.running = False
        error = self.error_of("GET", "/api/wallet/history?name=alice")
        self.assertEqual(error["cause"], "mint_stopped")

    def test_a_rejection_cause_is_never_upgraded_by_a_stopped_mint(self):
        """The reverse must never happen: an answer the mint gave stands."""
        self.control.running = False
        FakeWalletOps.fail_with = ("already spent", "the mint said so",
                                   "already_spent")
        error = self.error_of("GET", "/api/wallet/history?name=alice")
        self.assertEqual(error["cause"], "already_spent")

    def test_a_stopped_mint_on_a_route_that_needs_one_says_stopped(self):
        self.control.running = False
        error = self.error_of("POST", "/api/wallet/pay",
                              {"name": "alice", "amount_mc": 5})
        self.assertEqual(error["cause"], "mint_stopped")
        self.assertNotIn("reject", error["detail"].lower())
        self.assertEqual(FakeWalletOps.calls, [],
                         "the wallet was touched for a mint that is stopped")

    def test_every_error_this_server_raises_alone_carries_a_cause(self):
        for method, path, body in (
                ("GET", "/api/nope", None),
                ("POST", "/api/wallet/pay", {"name": "../x", "amount_mc": 1}),
                ("POST", "/api/wallet/pay", {"name": "ghost", "amount_mc": 1}),
                ("POST", "/api/wallet/quote", {"name": "alice",
                                               "amount_mc": 0}),
                ("POST", "/api/mint/issue", {"amount_mc": -1}),
                ("GET", "/api/wallet/history", None),
                ("PUT", "/api/mint/status", None)):
            with self.subTest(path=path):
                error = self.error_of(method, path, body)
                self.assertIn(error["cause"], gui_app.CAUSES)

    # -- history rows ---------------------------------------------------
    def test_a_history_rows_cause_is_carried_through_verbatim(self):
        FakeWalletOps.history_rows = [
            {"ts_ms": 0, "kind": "pay_failed", "amount_mc": 0,
             "detail": "did not commit (the mint did not answer)",
             "cause": "mint_unreachable"},
            {"ts_ms": 0, "kind": "receive_failed", "amount_mc": 0,
             "detail": "did not commit (already spent)",
             "cause": "already_spent"},
            {"ts_ms": 0, "kind": "pay", "amount_mc": 5, "detail": "paid",
             "cause": ""},
        ]
        status, obj, raw = self.call("GET", "/api/wallet/history?name=alice")
        self.assertEqual(status, 200, raw[:200])
        self.assertEqual([r["cause"] for r in obj["history"]],
                         ["mint_unreachable", "already_spent", ""])

    def test_a_history_row_with_a_nonsense_cause_reads_as_unknown(self):
        FakeWalletOps.history_rows = [
            {"ts_ms": 0, "kind": "pay_failed", "amount_mc": 0,
             "detail": "x", "cause": "the gremlins"},
            {"ts_ms": 0, "kind": "pay_failed", "amount_mc": 0, "detail": "x"},
        ]
        status, obj, _raw = self.call("GET", "/api/wallet/history?name=alice")
        self.assertEqual(status, 200)
        self.assertEqual([r["cause"] for r in obj["history"]],
                         ["unknown", ""])

    def test_a_history_row_never_leaves_a_closed_field_outside_its_set(self):
        """THE SWEEP AT THIS LAYER, over both kinds of non-answer.

        A ``receive`` row has no delivery, so all five record fields are
        "" -- the question does not arise. A recovered payment DID happen
        and reads real words in every one of them. A component that
        answers a word this build cannot read is undetermined, not blank.
        Those are three different rows and this route must not merge any
        two of them.
        """
        FakeWalletOps.history_rows = [
            {"ts_ms": 0, "kind": "receive", "amount_mc": 5, "detail": "x",
             "cause": "", "recipient": "", "recipient_kind": "",
             "delivery": "", "delivery_cause": "", "delivery_attempt": ""},
            {"ts_ms": 0, "kind": "pay", "amount_mc": 5, "detail": "x",
             "cause": "", "recipient": "bob", "recipient_kind": "wallet",
             "delivery": "undelivered", "delivery_cause": "",
             "delivery_attempt": "not_attempted"},
            {"ts_ms": 0, "kind": "pay", "amount_mc": 5, "detail": "x",
             "cause": "", "recipient": "", "recipient_kind": "unknown",
             "delivery": "unknown", "delivery_cause": "",
             "delivery_attempt": "unknown"},
            {"ts_ms": 0, "kind": "pay", "amount_mc": 5, "detail": "x",
             "cause": "", "recipient": "eve",
             "recipient_kind": "sky-writing", "delivery": "probably fine",
             "delivery_cause": "", "delivery_attempt": "sort of"},
        ]
        status, obj, raw = self.call("GET", "/api/wallet/history?name=alice")
        self.assertEqual(status, 200, raw[:200])
        rows = obj["history"]
        self.assertEqual([r["recipient_kind"] for r in rows],
                         ["", "wallet", "unknown", "unknown"])
        self.assertEqual([r["delivery_attempt"] for r in rows],
                         ["", "not_attempted", "unknown", "unknown"])
        self.assertEqual([r["delivery"] for r in rows],
                         ["", "undelivered", "unknown", "unknown"])
        for row in rows:
            self.assertIn(row["recipient_kind"],
                          gui_app.RECIPIENT_KINDS + (gui_app.NOT_APPLICABLE,))
            self.assertIn(row["delivery_attempt"],
                          gui_app.DELIVERY_ATTEMPTS
                          + (gui_app.NOT_APPLICABLE,))

    def test_a_recovered_payment_row_survives_the_history_route(self):
        """The recovered row, end to end through the wire it is read on."""
        FakeWalletOps.history_rows = [
            {"ts_ms": 0, "kind": "pay", "amount_mc": 5000,
             "detail": "payment of 5000 mc was stranded in flight, burn 0 mc"
                       " \u2014 nothing was handed over: it was meant for bob",
             "cause": "", "recipient": "bob", "recipient_kind": "wallet",
             "delivery": "undelivered", "delivery_cause": "",
             "delivery_attempt": "not_attempted"},
        ]
        status, obj, _raw = self.call("GET", "/api/wallet/history?name=alice")
        self.assertEqual(status, 200)
        row = obj["history"][0]
        self.assertEqual(row["recipient"], "bob")
        self.assertEqual(row["recipient_kind"], "wallet")
        self.assertEqual(row["delivery"], "undelivered")
        self.assertEqual(row["delivery_attempt"], "not_attempted")
        self.assertIn("nothing was handed over", row["detail"])

    def test_the_two_non_answers_are_not_the_same_string(self):
        """Unit, so the rule is pinned where it is written.

        ABSENT is the caller's business -- a history page has rows where
        the question does not arise, an endpoint that lists only payments
        does not. PRESENT-but-unreadable is always undetermined.
        """
        for clean, good in ((gui_app.clean_attempt, "attempted"),
                            (gui_app.clean_recipient_kind, "wallet")):
            with self.subTest(fn=clean.__name__):
                self.assertEqual(clean(good), good)
                self.assertEqual(clean(None), "")
                self.assertEqual(clean(""), "")
                self.assertEqual(clean("   "), "")
                self.assertEqual(clean(None, "unknown"), "unknown")
                # present and unreadable: it answered, we cannot read it
                self.assertEqual(clean("sky-writing"), "unknown")
                self.assertEqual(clean(7), "unknown")
                self.assertEqual(clean("sky-writing", ""), "unknown")

    def test_a_rejected_paste_carries_its_cause(self):
        FakeWalletOps.rejected = [
            {"token": "aicash:v3:x:1:zz", "reason": "malformed token",
             "detail": "not a token", "cause": "malformed_token"}]
        status, obj, raw = self.call("POST", "/api/wallet/receive",
                                     {"name": "alice", "tokens": ["junk"]})
        self.assertEqual(status, 200, raw[:200])
        self.assertEqual(obj["rejected"][0]["cause"], "malformed_token")


# ======================================================================
# a mint that answers badly is not a mint that did not answer
# ======================================================================
class TestTheMintAnsweredBadly(ServerCase):
    """The cause this server raises on its OWN account, checked per path.

    ``mint_unreachable`` is the cause for "the mint did not answer at all;
    it never saw the request", and page.html renders it as "the mint did
    not answer, so it never saw this request". Every path in this class
    has an ANSWER in hand -- a status line, a body -- so emitting that
    cause would put that headline on screen directly above a detail
    saying what the mint answered. The only honest cause for "it
    answered, and this server cannot tell what it did with the request"
    is ``unknown``, and the page prints unknown as undetermined.
    """

    def answering(self, code=500, body=b'{"error": "no"}', mint_id=None):
        """Point the GUI at a REAL socket that answers, badly."""
        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def respond(self):
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = do_POST = respond

            def log_message(self, *args):
                pass

        httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=httpd.serve_forever,
                                  kwargs={"poll_interval": 0.05},
                                  daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)
        port = httpd.server_address[1]
        real = self.control.status

        def status_here():
            out = dict(real())
            out["base_url"] = "http://127.0.0.1:%d" % port
            out["port"] = port
            if mint_id is not None:
                out["mint_id"] = mint_id
            return out

        self.control.status = status_here
        self.addCleanup(self.control.__dict__.pop, "status", None)
        return port

    def silent(self):
        """Point the GUI at a REAL port with nothing listening on it.

        The other half of this class: every test above has an answer in
        hand, and this one has none -- a refused connection, which is the
        one shape that really is mint_unreachable.
        """
        port = free_port()
        real = self.control.status

        def status_here():
            out = dict(real())
            out["base_url"] = "http://127.0.0.1:%d" % port
            out["port"] = port
            return out

        self.control.status = status_here
        self.addCleanup(self.control.__dict__.pop, "status", None)
        return port

    def error_of(self, method, path, body=None):
        status, obj, raw = self.call(method, path, body)
        self.assert_envelope(status, obj, raw)
        return obj["error"]

    def test_issuance_nobody_answered_says_the_outcome_is_undetermined(self):
        """ADJACENCY: the one money route that used to imply too much.

        Every other failure in the issue route happens after the mint
        ANSWERED. This one is the mint not answering -- and "could not
        reach the mint" on its own reads as "nothing was created", which
        this server cannot know. The secrets exist only inside that
        request, so if the ledger did issue against them, that money is
        unspendable by anyone and the operator has to be told, not left
        to retry into a doubled supply.
        """
        self.silent()
        error = self.error_of("POST", "/api/mint/issue",
                              {"amount_mc": 500, "count": 2})
        self.assertEqual(error["cause"], "mint_unreachable")
        self.assertIn("UNDETERMINED", error["detail"])
        self.assertIn("1000 mc", error["detail"])
        self.assertIn("unspendable", error["detail"])
        self.assertNotIn("Nothing was issued", error["detail"])

    def test_a_stopped_mint_means_nothing_was_issued_not_undetermined(self):
        """The neighbour on the other side, and the easy thing to get wrong.

        A stopped mint is refused before the request is built, so nothing
        reached any ledger. Calling THAT undetermined would be the same
        defect as calling an unanswered request a refusal, only pointing
        the other way.
        """
        self.control.running = False
        try:
            error = self.error_of("POST", "/api/mint/issue",
                                  {"amount_mc": 500, "count": 2})
        finally:
            self.control.running = True
        self.assertEqual(error["cause"], "mint_stopped")
        self.assertIn("nothing was sent to it", error["detail"])
        self.assertNotIn("UNDETERMINED", error["detail"])
        self.assertNotIn("unspendable", error["detail"])

    def test_an_issue_the_mint_refused_says_nothing_was_issued(self):
        """...and the neighbour: an ANSWER may be called a rejection."""
        self.answering(500)
        error = self.error_of("POST", "/api/mint/issue",
                              {"amount_mc": 500, "count": 2})
        self.assertEqual(error["cause"], "mint_rejected")
        self.assertIn("Nothing was issued", error["detail"])
        self.assertNotIn("UNDETERMINED", error["detail"])

    def test_an_http_error_to_the_status_lookup_is_not_unreachable(self):
        self.answering(500)
        error = self.error_of("GET", "/api/token/status?token=abc123")
        self.assertEqual(error["cause"], "unknown")
        self.assertIn("answered", error["detail"])
        self.assertIn("undetermined", error["detail"])

    def test_a_descriptor_that_is_not_a_descriptor_is_not_unreachable(self):
        self.answering(503)
        error = self.error_of("GET", "/api/mint/descriptor")
        self.assertEqual(error["cause"], "unknown")
        self.assertIn("answered", error["detail"])

    def test_an_answer_that_is_not_json_is_not_unreachable(self):
        self.answering(200, b"<html>I am a captive portal</html>")
        error = self.error_of("GET", "/api/mint/descriptor")
        self.assertEqual(error["cause"], "unknown")
        self.assertIn("not JSON", error["detail"])

    def test_issue_refuses_rather_than_blaming_a_mint_that_answered(self):
        """The mint answers a descriptor with no usable id: nothing issued."""
        self.answering(200, b'{"mint_id": ""}', mint_id="")
        error = self.error_of("POST", "/api/mint/issue",
                              {"amount_mc": 5, "count": 1})
        self.assertEqual(error["cause"], "unknown")
        self.assertIn("answered", error["detail"])
        self.assertIn("nothing was issued", error["detail"])

    def test_nothing_answering_at_all_still_says_unreachable(self):
        """The other half: the one shape that IS mint_unreachable.

        Without this the fix could have been "never say unreachable", and
        a cause nobody ever emits explains nothing either.
        """
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        dead = sock.getsockname()[1]
        sock.close()                      # bound, then closed: nothing there
        real = self.control.status

        def status_dead():
            out = dict(real())
            out["base_url"] = "http://127.0.0.1:%d" % dead
            out["port"] = dead
            return out

        self.control.status = status_dead
        self.addCleanup(self.control.__dict__.pop, "status", None)
        error = self.error_of("GET", "/api/mint/descriptor")
        self.assertEqual(error["cause"], "mint_unreachable")

    def test_no_route_ever_pairs_that_cause_with_that_detail(self):
        """The invariant, swept: cause mint_unreachable never says answered.

        A future raise site that copies the wrong neighbour is what this
        catches; the causes above are only the cases known today.
        """
        self.answering(500)
        for method, path, body in (
                ("GET", "/api/mint/descriptor", None),
                ("GET", "/api/token/status?token=abc123", None),
                ("POST", "/api/mint/issue", {"amount_mc": 5, "count": 1})):
            with self.subTest(path=path):
                error = self.error_of(method, path, body)
                if error["cause"] == "mint_unreachable":
                    self.assertNotIn("answered", error["detail"],
                                     "cause says the mint never answered, "
                                     "detail says it did: %r" % (error,))


# ======================================================================
# the money a failed delivery leaves behind
# ======================================================================
class TestOutstandingRoute(ServerCase):

    def test_the_route_reads_the_payments_back(self):
        status, obj, raw = self.call("GET",
                                     "/api/wallet/outstanding?name=alice")
        self.assertEqual(status, 200, raw[:200])
        self.assertTrue(obj["checked"])
        self.assertEqual(obj["payments"][0]["tokens"][0]["token"],
                         "aicash:v3:fake-mint:7:zz")
        self.assertEqual(obj["payments"][0]["tokens"][0]["state"], "unspent")
        self.assertIn(("outstanding", "alice", 20), FakeWalletOps.calls)

    def test_an_unchecked_string_is_not_claimed_to_be_anything(self):
        """Mint down: the strings still come back, the claims do not."""
        FakeWalletOps.outstanding = {
            "checked": False, "mint_id": None,
            "payments": [{"op_id": "op-2", "amount_mc": 9, "live_mc": None,
                          "tokens": [{"token": "t", "amount_mc": 9,
                                      "state": None}]}]}
        status, obj, _raw = self.call("GET",
                                      "/api/wallet/outstanding?name=alice")
        self.assertEqual(status, 200)
        self.assertFalse(obj["checked"])
        self.assertIsNone(obj["payments"][0]["live_mc"])
        self.assertIsNone(obj["payments"][0]["tokens"][0]["state"])

    def test_an_invented_token_state_is_dropped_not_relayed(self):
        FakeWalletOps.outstanding = {
            "checked": True, "mint_id": "fake-mint",
            "payments": [{"op_id": "op-3", "amount_mc": 1, "live_mc": 1,
                          "tokens": [{"token": "t", "amount_mc": 1,
                                      "state": "probably fine"}]}]}
        status, obj, _raw = self.call("GET",
                                      "/api/wallet/outstanding?name=alice")
        self.assertEqual(status, 200)
        self.assertIsNone(obj["payments"][0]["tokens"][0]["state"])

    def test_a_component_without_the_method_says_so_and_does_not_crash(self):
        """Neither spelling present. (The method has two names now: the
        question it answers was renamed to unredeemed_payments, and the
        old name still works, so "without the method" means without both.)
        """
        saved = (FakeWalletOps.outstanding_payments,
                 FakeWalletOps.unredeemed_payments)
        del FakeWalletOps.outstanding_payments
        del FakeWalletOps.unredeemed_payments
        try:
            status, obj, raw = self.call(
                "GET", "/api/wallet/outstanding?name=alice")
            self.assertEqual(status, 503, raw[:200])
            self.assert_envelope(status, obj, raw)
            self.assertIn("walletops.py", obj["error"]["detail"])
        finally:
            (FakeWalletOps.outstanding_payments,
             FakeWalletOps.unredeemed_payments) = saved

    def test_either_spelling_of_the_method_is_answered(self):
        """A component from either side of the rename still answers.

        The rename is a vocabulary fix, not a compatibility break: the
        word "outstanding" reads as "needs recovering", which is the OTHER
        question. A build that only has the old name must keep working.
        """
        saved = FakeWalletOps.unredeemed_payments
        del FakeWalletOps.unredeemed_payments
        try:
            status, obj, raw = self.call(
                "GET", "/api/wallet/outstanding?name=alice")
            self.assertEqual(status, 200, raw[:200])
            self.assertIn(("outstanding", "alice", 20), FakeWalletOps.calls)
        finally:
            FakeWalletOps.unredeemed_payments = saved

    def test_the_response_names_the_question_it_answered(self):
        """The reviewer's complaint was that nothing on the wire did."""
        status, obj, raw = self.call("GET",
                                     "/api/wallet/outstanding?name=alice")
        self.assertEqual(status, 200, raw[:200])
        self.assertIn("recover", obj["scope"])
        self.assertIn("redeem", obj["scope"])
        self.assertEqual(obj["unredeemed_mc"], 7)

        status, obj, raw = self.call("POST", "/api/wallet/recover",
                                     {"name": "alice"})
        self.assertEqual(status, 200, raw[:200])
        self.assertIn("outstanding", obj["scope"])
        self.assertIn("never got an answer", obj["scope"])

    def test_an_unchecked_report_gives_no_total_rather_than_zero(self):
        FakeWalletOps.outstanding = {
            "checked": False, "mint_id": None,
            "payments": [{"op_id": "op-9", "amount_mc": 9, "live_mc": None,
                          "tokens": [{"token": "t", "amount_mc": 9,
                                      "state": None}]}]}
        status, obj, _raw = self.call("GET",
                                      "/api/wallet/outstanding?name=alice")
        self.assertEqual(status, 200)
        self.assertIsNone(obj["unredeemed_mc"])

    def test_the_delivery_record_is_relayed_and_never_widened(self):
        FakeWalletOps.outstanding = {
            "checked": True, "mint_id": "fake-mint",
            "payments": [
                {"op_id": "op-a", "amount_mc": 1, "live_mc": 1,
                 "recipient": "bob", "recipient_kind": "wallet",
                 "delivery": "undelivered", "delivery_cause": "mint_stopped",
                 "tokens": []},
                {"op_id": "op-b", "amount_mc": 1, "live_mc": 1,
                 "recipient": "eve", "recipient_kind": "sky-writing",
                 "delivery": "probably fine", "delivery_cause": "vibes",
                 "tokens": []}]}
        status, obj, _raw = self.call("GET",
                                      "/api/wallet/outstanding?name=alice")
        self.assertEqual(status, 200)
        first, second = obj["payments"]
        self.assertEqual((first["recipient"], first["recipient_kind"],
                          first["delivery"], first["delivery_cause"]),
                         ("bob", "wallet", "undelivered", "mint_stopped"))
        # Invented vocabulary does not pass through: it becomes the
        # honest "we do not know", never a new word on the operator's
        # screen. AND "we do not know" is not "" -- "" is what this wire
        # says when there was no payment for the question to be about,
        # and a component that answered "sky-writing" HAS answered about
        # a payment that exists. All three fields take the same reading.
        self.assertEqual(second["recipient_kind"], "unknown")
        self.assertEqual(second["delivery"], "unknown")
        self.assertEqual(second["delivery_cause"], "unknown")

    def test_a_recovered_payment_keeps_every_field_across_the_wire(self):
        """The row this round exists for, relayed rather than blanked.

        walletops.py reports a payment that was stranded in flight and
        settled by recover() under ``recovered_ops``: nothing was handed
        over, so it is not outstanding value, and the five record fields
        say who it was meant for and that it reached nobody. Until this
        round this route relayed two of its seven fields, so the same
        payment that reads "meant for bob, nothing handed over" in the
        history panel carried no recipient at all in this one.
        """
        FakeWalletOps.outstanding = {
            "checked": True, "mint_id": "fake-mint", "payments": [],
            "recovered_mc": 5000,
            "recovered_ops": [{"op_id": "op-r", "amount_mc": 5000,
                               "recipient": "bob",
                               "recipient_kind": "wallet",
                               "delivery": "undelivered",
                               "delivery_cause": "",
                               "delivery_attempt": "not_attempted"}]}
        status, obj, raw = self.call("GET",
                                     "/api/wallet/outstanding?name=alice")
        self.assertEqual(status, 200, raw[:200])
        self.assertEqual(obj["recovered_mc"], 5000)
        got = obj["recovered_ops"][0]
        self.assertEqual(got, {"op_id": "op-r", "amount_mc": 5000,
                               "recipient": "bob",
                               "recipient_kind": "wallet",
                               "delivery": "undelivered",
                               "delivery_cause": "",
                               "delivery_attempt": "not_attempted"})

    def test_a_recovered_op_that_says_nothing_reads_undetermined(self):
        """...and a component that carries none of it does not read "".

        Every item on this endpoint is a payment, so "who was this for"
        always arises. A component build that does not answer it leaves
        the question undetermined, which is a word; "" here would say
        "this row has no recipient field to fill", which is false of
        every payment.
        """
        FakeWalletOps.outstanding = {
            "checked": True, "mint_id": "fake-mint", "payments": [],
            "recovered_mc": 7, "recovered_ops": [{"op_id": "op-s",
                                                  "amount_mc": 7}]}
        status, obj, _raw = self.call("GET",
                                      "/api/wallet/outstanding?name=alice")
        self.assertEqual(status, 200)
        got = obj["recovered_ops"][0]
        self.assertEqual(got["recipient_kind"], "unknown")
        self.assertEqual(got["delivery_attempt"], "unknown")
        self.assertEqual(got["delivery"], "unknown")
        self.assertNotEqual(got["recipient_kind"], "")
        self.assertNotEqual(got["delivery_attempt"], "")

    def test_a_payment_with_no_record_reads_unknown_not_delivered(self):
        FakeWalletOps.outstanding = {
            "checked": True, "mint_id": "fake-mint",
            "payments": [{"op_id": "op-c", "amount_mc": 1, "live_mc": 1,
                          "tokens": []}]}
        status, obj, _raw = self.call("GET",
                                      "/api/wallet/outstanding?name=alice")
        self.assertEqual(status, 200)
        self.assertEqual(obj["payments"][0]["delivery"], "unknown")
        self.assertEqual(obj["payments"][0]["recipient"], "")
        # The component said nothing at all about the kind. Every item
        # THIS endpoint lists is a payment, so the question arises and the
        # answer is undetermined -- not "", which is what this wire says
        # about a row that has no recipient field to fill at all.
        self.assertEqual(obj["payments"][0]["recipient_kind"], "unknown")
        self.assertEqual(obj["payments"][0]["delivery_attempt"], "unknown")

    def test_it_needs_a_wallet_that_exists(self):
        status, obj, raw = self.call("GET",
                                     "/api/wallet/outstanding?name=ghost")
        self.assertEqual(status, 404, raw[:200])
        self.assert_envelope(status, obj, raw)

    # -- the window's own account of itself, relayed rather than rebuilt --
    #
    # The component decides how much of a wallet's payments it can list
    # and says so; this route used to throw all of that away and rebuild
    # the headline by summing the rows it happened to receive. Measured
    # through the real HTTP API against a wallet with 106 payments, 105 of
    # them live: the wire answered a confident unredeemed_mc 3000 where
    # the component, reading the same store at the same instant, answered
    # None with unlisted_outstanding_mc 200 and a true total of 3200.

    def _windowed(self, **over):
        """A component answer that says the window cut something off."""
        base = {
            "checked": True, "mint_id": "fake-mint",
            "handed_over_mc": 3200, "payment_count": 106,
            "listed_mc": 3000, "unlisted_mc": 200,
            "unlisted_outstanding_mc": 200, "truncated": True,
            "unaccounted_mc": 0, "recovered_mc": 0, "recovered_ops": [],
            "unredeemed_mc": None,
            "payments": [{"op_id": "op-w", "amount_mc": 3000, "live_mc": 3000,
                          "tokens": [{"token": "t", "amount_mc": 3000,
                                      "state": "unspent"}]}]}
        base.update(over)
        return base

    def test_a_truncated_report_gives_no_total_rather_than_a_short_one(self):
        FakeWalletOps.outstanding = self._windowed()
        status, obj, raw = self.call("GET",
                                     "/api/wallet/outstanding?name=alice")
        self.assertEqual(status, 200, raw[:200])
        # Every string it listed carries a definite state, so the old rule
        # would have published 3000 here. It is short by the 200 the
        # window could not reach, and short by a figure the component
        # handed over in as many words.
        self.assertIsNone(
            obj["unredeemed_mc"],
            "a headline was published over %r of outstanding value the "
            "window did not cover" % (obj["unlisted_outstanding_mc"],))
        self.assertEqual(obj["unspent_mc"], 3000)
        self.assertTrue(obj["truncated"])
        self.assertEqual(obj["unlisted_outstanding_mc"], 200)
        self.assertEqual(obj["payment_count"], 106)
        self.assertEqual(obj["handed_over_mc"], 3200)

    def test_the_two_identities_close_on_the_wire(self):
        FakeWalletOps.outstanding = self._windowed()
        _status, obj, _raw = self.call("GET",
                                       "/api/wallet/outstanding?name=alice")
        self.assertEqual(obj["handed_over_mc"],
                         obj["listed_mc"] + obj["unlisted_mc"])
        self.assertEqual(obj["listed_mc"],
                         obj["unspent_mc"] + obj["spent_mc"] +
                         obj["unstated_mc"] + obj["unchecked_mc"] +
                         obj["unaccounted_mc"])

    def test_an_untruncated_report_still_gives_its_total(self):
        """The refusal is about the window, not about caution in general."""
        FakeWalletOps.outstanding = self._windowed(
            truncated=False, unlisted_mc=0, unlisted_outstanding_mc=0,
            listed_mc=3000, handed_over_mc=3000, payment_count=1)
        _status, obj, _raw = self.call("GET",
                                       "/api/wallet/outstanding?name=alice")
        self.assertEqual(obj["unredeemed_mc"], 3000)
        self.assertFalse(obj["truncated"])

    def test_recovered_value_is_relayed_and_added_to_nothing(self):
        """It is already inside balance_mc. Counting it here counts it twice."""
        FakeWalletOps.outstanding = self._windowed(
            truncated=False, unlisted_mc=0, unlisted_outstanding_mc=0,
            listed_mc=3000, handed_over_mc=3000, payment_count=1,
            recovered_mc=5000,
            recovered_ops=[{"op_id": "op-r", "amount_mc": 5000}])
        _status, obj, _raw = self.call("GET",
                                       "/api/wallet/outstanding?name=alice")
        self.assertEqual(obj["recovered_mc"], 5000)
        # The five record fields ride along, and a component that carries
        # none of them leaves them undetermined -- every item here is a
        # payment, so the questions arise whether or not it answered.
        self.assertEqual(obj["recovered_ops"],
                         [{"op_id": "op-r", "amount_mc": 5000,
                           "recipient": "", "recipient_kind": "unknown",
                           "delivery": "unknown", "delivery_cause": "",
                           "delivery_attempt": "unknown"}])
        self.assertEqual(obj["unredeemed_mc"], 3000)
        self.assertEqual(obj["handed_over_mc"], 3000)

    def test_a_component_that_says_nothing_about_its_window_is_not_trusted(self):
        """No flag and a full page: the answer must get LESS confident.

        A build of walletops that publishes none of these leaves the route
        with one piece of evidence -- a page as long as the limit -- and
        the fallback has to read that as "maybe not all of it", never as
        "all of it".
        """
        rows = [{"op_id": "op-%d" % i, "amount_mc": 1, "live_mc": 1,
                 "tokens": [{"token": "t%d" % i, "amount_mc": 1,
                             "state": "unspent"}]} for i in range(20)]
        FakeWalletOps.outstanding = {"checked": True, "mint_id": "fake-mint",
                                     "payments": rows}
        _status, obj, _raw = self.call("GET",
                                       "/api/wallet/outstanding?name=alice")
        self.assertTrue(obj["truncated"])
        self.assertIsNone(obj["unredeemed_mc"])
        self.assertEqual(obj["unspent_mc"], 20)
        self.assertIsNone(obj["unlisted_outstanding_mc"])

    def test_the_scope_sentence_states_the_rule_for_the_next_caller(self):
        FakeWalletOps.outstanding = self._windowed()
        _status, obj, _raw = self.call("GET",
                                       "/api/wallet/outstanding?name=alice")
        self.assertIn("truncated", obj["scope"])
        self.assertIn("unlisted_outstanding_mc", obj["scope"])


class TestNoFabricatedZero(ServerCase):
    """A number this server did not learn must not be printed as 0.

    walletops.py's own rule -- "balance 0 must mean this wallet holds
    nothing, never something went wrong" -- has to hold on the wire too.
    Every money figure here is either a figure the component gave, or
    null, or an error; never a default that reads as a fact.
    """

    def test_a_receive_that_reports_no_counters_is_an_error_not_a_zero(self):
        saved = FakeWalletOps.receive

        def mute(self, tokens):
            FakeWalletOps.calls.append(("receive", self.name, list(tokens)))
            return {"rejected": []}

        FakeWalletOps.receive = mute
        try:
            status, obj, raw = self.call("POST", "/api/wallet/receive",
                                         {"name": "alice", "tokens": ["t"]})
            self.assertEqual(status, 502, raw[:200])
            self.assert_envelope(status, obj, raw)
            self.assertIn("accepted", obj["error"]["detail"])
        finally:
            FakeWalletOps.receive = saved

    def test_a_receive_that_answers_null_counters_is_an_error_not_a_zero(self):
        """One step to the side of the case above, and it used to pass.

        expect_dict only checks that a key is PRESENT. A component
        answering {"accepted": null, "accepted_mc": null} satisfied it,
        and _as_int(..., 0) then supplied the zero -- so the route printed
        "nothing arrived" about a receive it had been told nothing about.
        A fabricated zero is a fabricated zero whether the key is missing
        or empty.
        """
        saved = FakeWalletOps.receive
        for label, answer in (
                ("null", {"accepted": None, "accepted_mc": None,
                          "rejected": []}),
                ("a string", {"accepted": "lots", "accepted_mc": "some",
                              "rejected": []}),
                ("a dict", {"accepted": {}, "accepted_mc": {},
                            "rejected": []}),
                ("one of each", {"accepted": 1, "accepted_mc": None,
                                 "rejected": []})):
            def mute(self, tokens, answer=answer):
                FakeWalletOps.calls.append(
                    ("receive", self.name, list(tokens)))
                return dict(answer)

            FakeWalletOps.receive = mute
            try:
                with self.subTest(answered=label):
                    status, obj, raw = self.call(
                        "POST", "/api/wallet/receive",
                        {"name": "alice", "tokens": ["t"]})
                    self.assertEqual(status, 502, raw[:200])
                    self.assert_envelope(status, obj, raw)
                    self.assertIn("accepted", obj["error"]["detail"])
            finally:
                FakeWalletOps.receive = saved

    def test_a_pay_that_reports_no_amount_is_an_error_not_the_one_asked_for(self):
        """The same fabrication as receive's zero, one route over.

        amount_mc used to fall back to the amount REQUESTED, so a
        component that said nothing about what left the wallet had the
        request echoed back at the operator as a fact about their money --
        beside a burn_mc and change_mc that correctly said null.
        """
        saved = FakeWalletOps.pay

        def mute(self, amount_mc, *, to=None, deliver=None):
            FakeWalletOps.calls.append(("pay", self.name, amount_mc))
            return {"tokens": ["aicash:v3:fake-mint:1:zz"], "burn_mc": 1}

        FakeWalletOps.pay = mute
        try:
            status, obj, raw = self.call("POST", "/api/wallet/pay",
                                         {"name": "alice", "amount_mc": 30})
            self.assertEqual(status, 502, raw[:200])
            self.assert_envelope(status, obj, raw)
            self.assertIn("amount_mc", obj["error"]["detail"])
        finally:
            FakeWalletOps.pay = saved

    def test_a_pay_reporting_a_different_amount_reports_that_amount(self):
        """Relayed, not corrected to what was asked for."""
        saved = FakeWalletOps.pay

        def short(self, amount_mc, *, to=None, deliver=None):
            FakeWalletOps.calls.append(("pay", self.name, amount_mc))
            return {"tokens": ["aicash:v3:fake-mint:1:zz"],
                    "amount_mc": amount_mc - 1, "burn_mc": 1,
                    "change_mc": 0, "op_id": "op-pay"}

        FakeWalletOps.pay = short
        try:
            status, obj, raw = self.call("POST", "/api/wallet/pay",
                                         {"name": "alice", "amount_mc": 30})
            self.assertEqual(status, 200, raw[:200])
            self.assertEqual(obj["amount_mc"], 29)
        finally:
            FakeWalletOps.pay = saved

    def test_a_receive_that_answers_properly_still_reports_a_real_zero(self):
        """0 accepted is a fact when the component said so."""
        saved = FakeWalletOps.receive

        def none_taken(self, tokens):
            FakeWalletOps.calls.append(("receive", self.name, list(tokens)))
            return {"accepted": 0, "accepted_mc": 0,
                    "rejected": [{"token": "t", "reason": "already spent",
                                  "detail": "d", "cause": "already_spent"}]}

        FakeWalletOps.receive = none_taken
        try:
            status, obj, raw = self.call("POST", "/api/wallet/receive",
                                         {"name": "alice", "tokens": ["t"]})
            self.assertEqual(status, 200, raw[:200])
            self.assertEqual(obj["accepted"], 0)
            self.assertEqual(obj["accepted_mc"], 0)
        finally:
            FakeWalletOps.receive = saved

    def test_a_quote_the_component_left_blank_is_null_not_zero(self):
        saved = FakeWalletOps.quote

        def mute(self, amount_mc):
            FakeWalletOps.calls.append(("quote", self.name, amount_mc))
            return {"amount_mc": amount_mc}

        FakeWalletOps.quote = mute
        try:
            status, obj, raw = self.call("POST", "/api/wallet/quote",
                                         {"name": "alice", "amount_mc": 10})
            self.assertEqual(status, 200, raw[:200])
            self.assertIsNone(obj["burn_mc"])
            self.assertIsNone(obj["change_mc"])
        finally:
            FakeWalletOps.quote = saved


# ======================================================================
# paying somebody: the recipient the server never used to learn
# ======================================================================
class TestPayDelivery(ServerCase):
    """The plumbing, over real HTTP, against a component that records.

    The money arithmetic is walletops.py's test file; what is under test
    here is that this server learns the recipient, hands the delivery to
    the component that can watch it, and relays the record without
    widening a word of it.
    """

    def pay(self, body):
        return self.call("POST", "/api/wallet/pay", body)

    def test_a_payment_with_no_recipient_is_recorded_as_bearer(self):
        status, obj, raw = self.pay({"name": "alice", "amount_mc": 30})
        self.assertEqual(status, 200, raw[:200])
        self.assertEqual(obj["recipient"], "")
        self.assertEqual(obj["recipient_kind"], "bearer")
        self.assertEqual(obj["delivery"], "unknown")
        self.assertEqual([c for c in FakeWalletOps.calls if c[0] == "deliver"],
                         [])

    def test_a_named_recipient_is_delivered_to_and_recorded(self):
        status, obj, raw = self.pay({"name": "alice", "amount_mc": 30,
                                     "to": "bob"})
        self.assertEqual(status, 200, raw[:200])
        self.assertEqual(obj["recipient"], "bob")
        self.assertEqual(obj["recipient_kind"], "wallet")
        self.assertEqual(obj["delivery"], "delivered")
        self.assertEqual(obj["delivery_cause"], "")
        self.assertIn(("deliver", "alice", "bob"), FakeWalletOps.calls)
        # the delivery really went through the recipient's own wallet
        self.assertIn(("receive", "bob", ["aicash:v3:fake-mint:30:zz"]),
                      FakeWalletOps.calls)

    def test_a_failed_delivery_is_reported_not_raised(self):
        """The money left. Answering 4xx would say it had not."""
        FakeWalletOps.rejected = [{"token": "t", "reason": "already spent",
                                   "detail": "d", "cause": "already_spent"}]
        status, obj, raw = self.pay({"name": "alice", "amount_mc": 30,
                                     "to": "bob"})
        self.assertEqual(status, 200, raw[:200])
        self.assertEqual(obj["delivery"], "undelivered")
        self.assertEqual(obj["delivery_cause"], "already_spent")
        self.assertEqual(obj["tokens"], ["aicash:v3:fake-mint:30:zz"])

    def test_an_invented_outcome_never_reaches_the_operator(self):
        class Creative(FakeWalletOps):
            def pay(self, amount_mc, *, to=None, deliver=None):
                FakeWalletOps.calls.append(("pay", self.name, amount_mc))
                return {"tokens": [], "amount_mc": amount_mc, "burn_mc": 0,
                        "recipient": "bob", "recipient_kind": "carrier pigeon",
                        "delivery": "probably arrived",
                        "delivery_cause": "the vibes"}

        saved = FakeWalletOps.pay
        FakeWalletOps.pay = Creative.pay
        try:
            status, obj, raw = self.pay({"name": "alice", "amount_mc": 30,
                                         "to": "bob"})
            self.assertEqual(status, 200, raw[:200])
            self.assertEqual(obj["delivery"], "unknown")
            self.assertEqual(obj["delivery_cause"], "unknown")
            # "carrier pigeon" is an ANSWER this build cannot read, which
            # is undetermined -- the same reading the two fields above
            # take. "" would say this response is not about a payment.
            self.assertEqual(obj["recipient_kind"], "unknown")
        finally:
            FakeWalletOps.pay = saved

    def test_an_unknown_recipient_costs_no_money(self):
        """Validated BEFORE the payment, because a 404 after it is theft."""
        status, obj, raw = self.pay({"name": "alice", "amount_mc": 30,
                                     "to": "ghost"})
        self.assertEqual(status, 404, raw[:200])
        self.assert_envelope(status, obj, raw)
        self.assertEqual([c for c in FakeWalletOps.calls if c[0] == "pay"], [])

    def test_a_wallet_cannot_pay_itself(self):
        status, obj, raw = self.pay({"name": "alice", "amount_mc": 30,
                                     "to": "alice"})
        self.assertEqual(status, 400, raw[:200])
        self.assert_envelope(status, obj, raw)
        self.assertEqual([c for c in FakeWalletOps.calls if c[0] == "pay"], [])

    def test_a_component_that_cannot_record_refuses_rather_than_pretends(self):
        """No recipient recorded is a worse outcome than no payment.

        A build whose pay() has never heard of a recipient would pay
        happily and record nothing, and the operator would be told the
        payment was delivered to bob by a screen that had no way to know.
        """
        saved = FakeWalletOps.pay

        def old_build(self, amount_mc):
            FakeWalletOps.calls.append(("pay", self.name, amount_mc))
            return {"tokens": [], "amount_mc": amount_mc, "burn_mc": 0}

        FakeWalletOps.pay = old_build
        try:
            status, obj, raw = self.pay({"name": "alice", "amount_mc": 30,
                                         "to": "bob"})
            self.assertEqual(status, 503, raw[:200])
            self.assert_envelope(status, obj, raw)
            self.assertIn("walletops.py", obj["error"]["detail"])
            self.assertEqual(
                [c for c in FakeWalletOps.calls if c[0] == "pay"], [])
            # ...and a bearer payment still works on that same build
            status, _obj, raw = self.pay({"name": "alice", "amount_mc": 30})
            self.assertEqual(status, 200, raw[:200])
        finally:
            FakeWalletOps.pay = saved

    def test_history_relays_the_record_without_widening_it(self):
        FakeWalletOps.history_rows = [
            {"ts_ms": 0, "op_id": "op-1", "kind": "pay", "amount_mc": 5,
             "detail": "paid", "cause": "", "recipient": "bob",
             "recipient_kind": "wallet", "delivery": "undelivered",
             "delivery_cause": "mint_stopped"},
            {"ts_ms": 0, "op_id": "op-2", "kind": "pay", "amount_mc": 5,
             "detail": "paid", "cause": "", "recipient": "eve",
             "recipient_kind": "telepathy", "delivery": "arrived, probably",
             "delivery_cause": "a hunch"},
            {"ts_ms": 0, "op_id": "op-3", "kind": "receive", "amount_mc": 5,
             "detail": "took", "cause": ""},
        ]
        status, obj, raw = self.call("GET", "/api/wallet/history?name=alice")
        self.assertEqual(status, 200, raw[:200])
        first, second, third = obj["history"]
        self.assertEqual((first["op_id"], first["recipient"],
                          first["delivery"], first["delivery_cause"]),
                         ("op-1", "bob", "undelivered", "mint_stopped"))
        # It ANSWERED, in a word this file cannot read: unknown, not "".
        # ALL THREE FIELDS, which is the fix: `delivery` has read that way
        # since round 4 while `recipient_kind` beside it read "", the same
        # string the row below uses for "the question does not arise".
        self.assertEqual(second["recipient_kind"], "unknown")
        self.assertEqual(second["delivery"], "unknown")
        self.assertEqual(second["delivery_cause"], "unknown")
        # A row that says nothing about delivery keeps saying nothing: ""
        # is "the question does not arise", and must not become "unknown".
        self.assertEqual(third["delivery"], "")
        self.assertEqual(third["recipient"], "")
        self.assertEqual(third["recipient_kind"], "")
        self.assertEqual(third["delivery_attempt"], "")


# ======================================================================
# the capability key, and the one message that did not name the problem
# ======================================================================
class TestUnredeemedTotals(ServerCase):
    """The one number this round added, and the one that guessed.

    ``checked`` means THE MINT ANSWERED. It does not mean every string
    carries a state: a wallet holding a payment against mint-a, read while
    mint-b answers on that address, comes back checked with every token
    state "unknown". Folding those into a single total printed 0 about
    money whose state the very next line called unknown.
    """

    def outstanding(self):
        return self.call("GET", "/api/wallet/outstanding?name=alice")

    def test_unknown_states_are_never_rounded_down_into_the_total(self):
        FakeWalletOps.outstanding = {
            "checked": True, "mint_id": "other-mint",
            "payments": [{"op_id": "op-x", "amount_mc": 5000,
                          "live_mc": 0,
                          "tokens": [{"token": "t1", "amount_mc": 5000,
                                      "state": "unknown"}]}]}
        status, obj, raw = self.outstanding()
        self.assertEqual(status, 200, raw[:200])
        self.assertTrue(obj["checked"])
        # NOT 0. There is no single number that answers the question.
        self.assertIsNone(obj["unredeemed_mc"])
        # ...and the parts say exactly what is known.
        self.assertEqual(obj["unstated_mc"], 5000)
        self.assertEqual(obj["unspent_mc"], 0)
        self.assertEqual(obj["spent_mc"], 0)
        self.assertEqual(obj["unchecked_mc"], 0)

    def test_a_mixture_still_reports_every_part_it_knows(self):
        FakeWalletOps.outstanding = {
            "checked": True, "mint_id": "fake-mint",
            "payments": [{"op_id": "op-x", "amount_mc": 60, "live_mc": 10,
                          "tokens": [
                              {"token": "a", "amount_mc": 10,
                               "state": "unspent"},
                              {"token": "b", "amount_mc": 20,
                               "state": "spent"},
                              {"token": "c", "amount_mc": 30,
                               "state": "unknown"}]}]}
        status, obj, _raw = self.outstanding()
        self.assertEqual(status, 200)
        self.assertIsNone(obj["unredeemed_mc"])
        self.assertEqual((obj["unspent_mc"], obj["spent_mc"],
                          obj["unstated_mc"], obj["unchecked_mc"]),
                         (10, 20, 30, 0))
        # the parts account for every millicredit handed over
        self.assertEqual(obj["unspent_mc"] + obj["spent_mc"] +
                         obj["unstated_mc"] + obj["unchecked_mc"], 60)

    def test_a_complete_answer_is_still_one_number(self):
        """Hedging about everything would be as useless as asserting."""
        FakeWalletOps.outstanding = {
            "checked": True, "mint_id": "fake-mint",
            "payments": [{"op_id": "op-x", "amount_mc": 60, "live_mc": 40,
                          "tokens": [
                              {"token": "a", "amount_mc": 40,
                               "state": "unspent"},
                              {"token": "b", "amount_mc": 20,
                               "state": "spent"}]}]}
        status, obj, _raw = self.outstanding()
        self.assertEqual(status, 200)
        self.assertEqual(obj["unredeemed_mc"], 40)
        self.assertEqual(obj["unstated_mc"], 0)

    def test_a_real_zero_is_printed_when_the_mint_said_so_about_all_of_it(self):
        FakeWalletOps.outstanding = {
            "checked": True, "mint_id": "fake-mint",
            "payments": [{"op_id": "op-x", "amount_mc": 60, "live_mc": 0,
                          "tokens": [{"token": "b", "amount_mc": 60,
                                      "state": "spent"}]}]}
        status, obj, _raw = self.outstanding()
        self.assertEqual(obj["unredeemed_mc"], 0)
        self.assertEqual(obj["spent_mc"], 60)

    def test_a_partly_answered_report_gives_no_total_either(self):
        FakeWalletOps.outstanding = {
            "checked": True, "mint_id": "fake-mint",
            "payments": [{"op_id": "op-x", "amount_mc": 60, "live_mc": 40,
                          "tokens": [
                              {"token": "a", "amount_mc": 40,
                               "state": "unspent"},
                              {"token": "b", "amount_mc": 20,
                               "state": "who knows"}]}]}
        status, obj, _raw = self.outstanding()
        self.assertIsNone(obj["unredeemed_mc"])
        self.assertEqual(obj["unchecked_mc"], 20)


# ======================================================================
# an EXTERNAL payee: the record aicash actually needs
# ======================================================================
class TestExternalPayee(ServerCase):
    """A payee that is not a wallet in this workdir.

    Requiring one made the record possible exactly where it is least
    interesting -- two wallets in one directory -- while aicash's actual
    payee, an agent somewhere else, 404'd and could never be recorded by
    anybody. "bearer / unknown forever" was the state this round was set
    to remove, and for every real payment it was still the only state
    reachable.
    """

    def pay(self, body):
        return self.call("POST", "/api/wallet/pay", body)

    def test_an_external_payee_is_recorded_when_delivery_is_not_claimed(self):
        status, obj, raw = self.pay({"name": "alice", "amount_mc": 30,
                                     "to": "acme-agent-42",
                                     "deliver": False})
        self.assertEqual(status, 200, raw[:200])
        self.assertEqual(obj["recipient"], "acme-agent-42")
        self.assertEqual(obj["recipient_kind"], "wallet")
        # named, and honestly undelivered-from-here
        self.assertEqual(obj["delivery"], "unknown")
        self.assertEqual(obj["delivery_attempt"], "not_attempted")
        self.assertEqual([c for c in FakeWalletOps.calls if c[0] == "deliver"],
                         [])
        self.assertEqual(obj["tokens"], ["aicash:v3:fake-mint:30:zz"])

    def test_a_payee_that_is_not_here_is_still_refused_without_that_flag(self):
        """A typo must not silently become "recorded but not delivered"."""
        status, obj, raw = self.pay({"name": "alice", "amount_mc": 30,
                                     "to": "acme-agent-42"})
        self.assertEqual(status, 404, raw[:200])
        self.assert_envelope(status, obj, raw)
        self.assertIn("deliver:false", obj["error"]["detail"])
        self.assertEqual([c for c in FakeWalletOps.calls if c[0] == "pay"], [])

    def test_a_local_wallet_named_with_that_flag_is_not_delivered_to(self):
        """The flag says what this server did, not who the payee is."""
        status, obj, raw = self.pay({"name": "alice", "amount_mc": 30,
                                     "to": "bob", "deliver": False})
        self.assertEqual(status, 200, raw[:200])
        self.assertEqual(obj["recipient"], "bob")
        self.assertEqual(obj["delivery_attempt"], "not_attempted")
        self.assertEqual([c for c in FakeWalletOps.calls if c[0] == "deliver"],
                         [])

    def test_a_payee_label_is_bounded_and_one_line(self):
        for label, to in (("too long", "x" * 65),
                          ("a newline", "acme\nagent"),
                          ("a nul", "acme\x00agent"),
                          ("blank", "   "),
                          ("not a string", 7)):
            with self.subTest(payee=label):
                status, obj, raw = self.pay({"name": "alice",
                                             "amount_mc": 30, "to": to,
                                             "deliver": False})
                self.assertEqual(status, 400, raw[:200])
                self.assert_envelope(status, obj, raw)
                self.assertEqual(
                    [c for c in FakeWalletOps.calls if c[0] == "pay"], [])

    def test_deliver_must_be_a_boolean(self):
        status, obj, raw = self.pay({"name": "alice", "amount_mc": 30,
                                     "to": "bob", "deliver": "maybe"})
        self.assertEqual(status, 400, raw[:200])
        self.assert_envelope(status, obj, raw)
        self.assertEqual([c for c in FakeWalletOps.calls if c[0] == "pay"], [])

    def test_a_wallet_still_cannot_pay_itself_by_label(self):
        status, _obj, raw = self.pay({"name": "alice", "amount_mc": 30,
                                      "to": "alice", "deliver": False})
        self.assertEqual(status, 400, raw[:200])


# ======================================================================
# the OTHER way this product delivers a payment
# ======================================================================
class TestReceiveRecordsTheDelivery(ServerCase):
    """POST /api/wallet/receive watched an outcome and threw it away.

    Two ways to deliver one payment: pay with ``to``, which records
    "delivered"; or pay and then paste the strings into Receive, which
    recorded nothing at all. Same outcome, two routes, opposite kinds of
    truth -- the exact defect this round exists to stop.
    """

    def receive(self, body):
        return self.call("POST", "/api/wallet/receive", body)

    def test_a_receive_that_names_the_payment_records_it(self):
        status, obj, raw = self.receive({"name": "bob", "tokens": ["t"],
                                         "payer": "alice",
                                         "op_id": "op-pay"})
        self.assertEqual(status, 200, raw[:200])
        self.assertEqual(obj["recorded"]["recorded"], True)
        self.assertEqual(obj["recorded"]["delivery"], "delivered")
        self.assertEqual(obj["recorded"]["op_id"], "op-pay")
        self.assertIn(("settle", "alice", "op-pay", "bob", "result"),
                      FakeWalletOps.calls)

    def test_a_refused_receive_records_the_refusal_and_still_reports_it(self):
        FakeWalletOps.rejected = [{"token": "t", "reason": "already spent",
                                   "detail": "d", "cause": "already_spent"}]
        status, obj, raw = self.receive({"name": "bob", "tokens": ["t"],
                                         "payer": "alice",
                                         "op_id": "op-pay"})
        self.assertEqual(status, 200, raw[:200])
        self.assertEqual(obj["recorded"]["delivery"], "undelivered")
        self.assertEqual(obj["recorded"]["delivery_cause"], "already_spent")

    def test_a_receive_that_raised_records_the_cause_and_re_raises(self):
        """The failure IS the outcome the payer's record was waiting for."""
        FakeWalletOps.fail_with = ("mint stopped", "the mint is not running",
                                   "mint_stopped")
        status, obj, raw = self.receive({"name": "bob", "tokens": ["t"],
                                         "payer": "alice",
                                         "op_id": "op-pay"})
        self.assertEqual(status, 400, raw[:200])
        self.assert_envelope(status, obj, raw)
        settles = [c for c in FakeWalletOps.calls if c[0] == "settle"]
        self.assertEqual(settles, [("settle", "alice", "op-pay", "bob",
                                    "error")])

    def test_a_plain_receive_records_nothing_and_says_so(self):
        status, obj, raw = self.receive({"name": "bob", "tokens": ["t"]})
        self.assertEqual(status, 200, raw[:200])
        self.assertIsNone(obj["recorded"])
        self.assertEqual([c for c in FakeWalletOps.calls if c[0] == "settle"],
                         [])

    def test_half_a_pair_names_no_payment_and_is_refused(self):
        for label, body in (
                ("payer only", {"name": "bob", "tokens": ["t"],
                                "payer": "alice"}),
                ("op_id only", {"name": "bob", "tokens": ["t"],
                                "op_id": "op-pay"})):
            with self.subTest(sent=label):
                status, obj, raw = self.receive(body)
                self.assertEqual(status, 400, raw[:200])
                self.assert_envelope(status, obj, raw)
                self.assertEqual(
                    [c for c in FakeWalletOps.calls if c[0] == "receive"], [])

    def test_a_payer_that_is_not_a_wallet_here_is_a_404_before_any_money(self):
        status, _obj, raw = self.receive({"name": "bob", "tokens": ["t"],
                                          "payer": "ghost",
                                          "op_id": "op-pay"})
        self.assertEqual(status, 404, raw[:200])
        self.assertEqual([c for c in FakeWalletOps.calls if c[0] == "receive"],
                         [])

    def test_a_wallet_cannot_be_the_payer_of_its_own_receive(self):
        status, _obj, raw = self.receive({"name": "bob", "tokens": ["t"],
                                          "payer": "bob", "op_id": "op-pay"})
        self.assertEqual(status, 400, raw[:200])

    def test_a_record_that_cannot_be_written_never_fails_the_receive(self):
        """The money moved. A record is not the money path."""
        saved = FakeWalletOps.settle_delivery

        def broken(self, op_id, *, result=None, error=None, recipient=""):
            FakeWalletOps.calls.append(("settle", self.name, op_id,
                                        recipient, "boom"))
            raise RuntimeError("the record file is a directory")

        FakeWalletOps.settle_delivery = broken
        try:
            status, obj, raw = self.receive({"name": "bob", "tokens": ["t"],
                                             "payer": "alice",
                                             "op_id": "op-pay"})
            self.assertEqual(status, 200, raw[:200])
            self.assertEqual(obj["accepted_mc"], 10)
            self.assertFalse(obj["recorded"]["recorded"])
            self.assertEqual(obj["recorded"]["delivery"], "unknown")
        finally:
            FakeWalletOps.settle_delivery = saved

    def test_a_build_with_no_settle_delivery_says_so_rather_than_pretending(self):
        saved = FakeWalletOps.settle_delivery
        del FakeWalletOps.settle_delivery
        try:
            status, obj, raw = self.receive({"name": "bob", "tokens": ["t"],
                                             "payer": "alice",
                                             "op_id": "op-pay"})
            self.assertEqual(status, 200, raw[:200])
            self.assertFalse(obj["recorded"]["recorded"])
            self.assertIn("settle_delivery",
                          obj["recorded"]["delivery_detail"])
        finally:
            FakeWalletOps.settle_delivery = saved

    def test_an_invented_record_outcome_never_reaches_the_operator(self):
        FakeWalletOps.settled = {"op_id": "op-pay", "recorded": True,
                                 "delivery": "probably arrived",
                                 "delivery_cause": "the vibes",
                                 "delivery_detail": "trust me"}
        status, obj, raw = self.receive({"name": "bob", "tokens": ["t"],
                                         "payer": "alice",
                                         "op_id": "op-pay"})
        self.assertEqual(status, 200, raw[:200])
        self.assertEqual(obj["recorded"]["delivery"], "unknown")
        self.assertEqual(obj["recorded"]["delivery_cause"], "unknown")


class TestKeyWhitespace(ServerCase):
    """A terminal copy that picks up whitespace used to be a bare 401.

    Nothing here loosens the comparison: the key alphabet (token_urlsafe:
    A-Za-z0-9-_) contains no whitespace at any position, so trimming cannot
    turn one key into another, and every wrong-for-any-other-reason key
    below is still refused.
    """

    def key(self):
        return self.httpd.auth.key

    def open_with(self, raw_key):
        return self.fetch("GET", "/?k=" + urllib.parse.quote(raw_key),
                          cookie=False)

    def test_a_key_with_a_trailing_space_opens_the_page(self):
        # The labels describe the damage rather than quoting the key: a
        # failure report is somewhere a credential must not turn up either.
        for label, damaged in (("trailing space", self.key() + " "),
                               ("leading space", " " + self.key()),
                               ("trailing newline", self.key() + "\n"),
                               ("both ends", "\t" + self.key() + " \r\n")):
            with self.subTest(damage=label):
                status, headers, raw = self.open_with(damaged)
                self.assertEqual(status, 200, raw[:200])
                self.assertIn("set-cookie", headers,
                              "a key that is right but for whitespace at the "
                              "ends was refused")

    def test_the_session_it_hands_out_actually_works(self):
        status, headers, _raw = self.open_with(self.key() + " ")
        cookie = headers["set-cookie"].split(";")[0]
        status, _obj, raw = self.call("GET", "/api/mint/status", None,
                                      {"Cookie": cookie}, cookie=False)
        self.assertEqual(status, 200, raw[:200])

    def test_whitespace_through_the_middle_names_the_actual_problem(self):
        """The specific message: it IS the key, with a break in it."""
        key = self.key()
        broken = key[:20] + " " + key[20:]
        status, headers, raw = self.open_with(broken)
        self.assertEqual(status, 401, raw[:200])
        self.assertNotIn("set-cookie", headers,
                         "a session was issued for a key with a break in it")
        self.assertIn(b"whitespace", raw.lower())
        self.assertIn(b"terminal", raw)
        # and it still never quotes the credential back
        self.assertNotIn(key.encode(), raw)

    def test_a_newline_through_the_middle_gets_the_same_message(self):
        key = self.key()
        status, _headers, raw = self.open_with(key[:10] + "\n" + key[10:])
        self.assertEqual(status, 401)
        self.assertIn(b"whitespace", raw.lower())

    def test_a_key_wrong_for_any_other_reason_is_refused_as_before(self):
        """No hint, no whitespace story, no cookie: just the locked page.

        ``other`` is a character GUARANTEED to differ from the one it
        replaces. A fixed "x" was a 1-in-64 flake: token_urlsafe's
        alphabet contains "x", so one run in sixty-four the "damaged" key
        WAS the key, the server answered 200 with a cookie, and a
        publish-blocking suite failed for a reason with nothing to do with
        the product. Same for the upper-cased spelling, which is only a
        different key while the key has a letter in it.
        """
        key = self.key()
        other = "x" if key[20] != "x" else "y"
        cased = key.upper() if key.upper() != key else key.lower()
        if cased == key:                # all digits and punctuation
            cased = other + key[1:]
        for label, damaged in (("truncated", key[:-1]),
                               ("one character added", key + "x"),
                               ("upper-cased", cased),
                               ("empty", ""),
                               ("not the key at all", "wrong"),
                               ("one character wrong",
                                key[:20] + other + key[21:]),
                               ("wrong AND whitespace",
                                key[:20] + other + " " + key[20:])):
            with self.subTest(damage=label):
                status, headers, raw = self.open_with(damaged)
                self.assertEqual(status, 401, raw[:200])
                self.assertNotIn("set-cookie", headers)
                self.assertNotIn(b"whitespace", raw.lower(),
                                 "a merely wrong key was excused as a typo")
                self.assertIn(b"terminal", raw)

    def test_the_api_still_refuses_the_key_however_it_is_spelled(self):
        key = self.key()
        for label, spelling in (("exact", key), ("trailing space", key + " "),
                                ("broken", key[:10] + " " + key[10:])):
            with self.subTest(spelling=label):
                status, obj, raw = self.call(
                    "GET", "/api/wallet/list?k=" + urllib.parse.quote(spelling),
                    None, cookie=False)
                self.assertEqual(status, 401, raw[:200])
                self.assertEqual(obj["error"]["reason"], "unauthorized")

    def test_the_accepted_whitespace_is_exactly_the_documented_set(self):
        """Decided, bounded, and pinned -- not whatever str.strip() does.

        str.strip() with no argument removes every character Python calls
        whitespace, in any quantity, from both ends: U+00A0, U+2028, the
        vertical tab, two hundred spaces. That tolerance was never chosen,
        only inherited, and an undocumented tolerance on a credential is a
        tolerance nobody has measured.
        """
        self.assertEqual(gui_app.KEY_EDGE_WHITESPACE, " \t\r\n")
        self.assertEqual(gui_app.KEY_EDGE_WHITESPACE_MAX, 8)
        key = self.key()
        for label, damaged in (
                ("space", key + " "),
                ("tab", "\t" + key),
                ("crlf", key + "\r\n"),
                ("both ends, at the bound", " " * 8 + key + "\n" * 8)):
            with self.subTest(accepted=label):
                status, headers, raw = self.open_with(damaged)
                self.assertEqual(status, 200, raw[:200])
                self.assertIn("set-cookie", headers)

    def test_whitespace_a_terminal_copy_does_not_produce_is_refused(self):
        """A non-breaking space comes off a rendered page, not a terminal."""
        key = self.key()
        for label, damaged in (
                ("non-breaking space", key + "\u00a0"),
                ("line separator", key + "\u2028"),
                ("vertical tab", key + "\v"),
                ("form feed", "\f" + key),
                ("ideographic space", key + "\u3000"),
                ("nine spaces, past the bound", key + " " * 9),
                ("nine leading spaces", " " * 9 + key)):
            with self.subTest(refused=label):
                status, headers, raw = self.open_with(damaged)
                self.assertEqual(status, 401, raw[:200])
                self.assertNotIn("set-cookie", headers)
                # ...and it still names the problem rather than going
                # blank: it IS the key, wearing whitespace we do not take.
                self.assertIn(b"whitespace", raw.lower())
                self.assertNotIn(key.encode(), raw)
                # THE PAGE MUST NOT SEND THEM HUNTING THE WRONG THING.
                # Every shape here is EDGE whitespace that was refused,
                # and this page used to tell the operator that a space at
                # either end was fine and the break must be in the middle.
                self.assertNotIn(b"A space at either end is fine", raw)
                self.assertIn(b"at each END", raw)

    def test_the_401_page_describes_the_shape_that_is_actually_accepted(self):
        """The diagnosis was widened; the sentence next door was not.

        key_is_whitespace_damaged serves this page for the key wearing
        whitespace key_ok REFUSES -- a non-breaking space, nine trailing
        spaces -- and the page still described the middle-of-the-key case
        as the only one. A message widened out of step with its diagnosis
        points at the wrong component.
        """
        page = gui_app.LOCKED_PAGE_WHITESPACE.encode()
        self.assertIn(b"at each END", page)
        self.assertIn(str(gui_app.KEY_EDGE_WHITESPACE_MAX).encode(), page)
        for named in (b"non-breaking", b"ideographic", b"vertical tab",
                      b"line separator"):
            self.assertIn(named, page)
        self.assertNotIn(b"A space at either end is fine", page)
        # and it still quotes no credential of any kind
        self.assertNotIn(self.key().encode(), page)

    def test_a_trailing_plus_is_a_trailing_space_and_is_accepted(self):
        """The shape the reviewer hit: a URL ending in the key plus '+'.

        A query string decodes '+' to a space before anything here sees
        it, so this is the trailing-space case arriving by another road --
        and it is sent RAW, unencoded, because that is how it arrives from
        a terminal that wrapped the line.
        """
        status, headers, raw = self.fetch(
            "GET", "/?k=" + self.key() + "+", cookie=False)
        self.assertEqual(status, 200, raw[:200])
        self.assertIn("set-cookie", headers)

    def test_trimming_never_turns_a_wrong_key_into_a_right_one(self):
        """The safety argument, exercised rather than asserted.

        token_urlsafe's alphabet has no whitespace in it, so no amount of
        edge whitespace can make one valid key into another. What is
        checked here is the converse that matters: every near-miss stays a
        miss however it is padded.
        """
        key = self.key()
        other = "x" if key[20] != "x" else "y"
        for label, wrong in (("truncated", key[:-1]),
                             ("one character wrong",
                              key[:20] + other + key[21:]),
                             ("one character added", key + other)):
            for pad in ("", " ", "\n", "\t\r\n", " " * 8):
                with self.subTest(wrong=label, pad=repr(pad)):
                    status, headers, raw = self.open_with(pad + wrong + pad)
                    self.assertEqual(status, 401, raw[:200])
                    self.assertNotIn("set-cookie", headers)

    def test_the_trimmer_itself_is_total_and_bounded(self):
        """Unit-level, because the policy is a function and has edges."""
        trim = gui_app._trimmed
        self.assertEqual(trim("abc"), "abc")
        self.assertEqual(trim(" \t abc \r\n"), "abc")
        self.assertEqual(trim(" " * 8 + "abc" + " " * 8), "abc")
        for untouched in (" " * 9 + "abc", "abc" + " " * 9, "abc\u00a0",
                          "\u00a0abc", "abc\v"):
            self.assertEqual(trim(untouched), untouched)
        # not a str: decided by the comparison, not by this
        for passthrough in (None, 7, b"abc", ["abc"]):
            self.assertIs(trim(passthrough), passthrough)
        # all-whitespace does not become the key by accident
        self.assertEqual(trim(" " * 4), "")
        self.assertFalse(gui_app._secret_eq("k", trim(" " * 4)))

    def test_the_comparison_is_still_constant_time(self):
        """Trimming happens BEFORE the compare, and the compare is unchanged.

        _secret_eq is the only place either credential is compared, and it
        is hmac.compare_digest on bytes. A trim that turned into a `==`
        would pass every test above and fail this one.
        """
        source = inspect.getsource(gui_app._Auth.key_ok)
        self.assertIn("_secret_eq", source)
        self.assertNotIn("==", source)
        self.assertIn("compare_digest",
                      inspect.getsource(gui_app._secret_eq))


# ======================================================================
# THE PAGE — page.html's own JavaScript, executed
# ======================================================================
NODE = shutil.which("node")


def free_port():
    sock = socket.socket()
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


class TestPage(unittest.TestCase):
    """The page's behaviour, not its source text.

    page.html is loaded exactly as shipped, its inline script is executed
    under a small DOM, and a fake GUI API answers it with §7.3 arithmetic.
    Every assertion below is about what the operator would see and what
    would move as a result.
    """

    out = None

    @classmethod
    def setUpClass(cls):
        if not NODE:
            raise unittest.SkipTest(
                "node is not installed; page.html's JavaScript cannot be "
                "executed here. The server tests still run.")
        from aicash.burncalc import BurnPolicy, compute_burn
        cls.table = []
        cls.expected = []
        policies = [(10000, 1000, 10), (0, 0, 10), (10000, 0, 10),
                    (5000, 25, 10), (1, 1000000, 10)]
        for rate, cap, exempt in policies:
            for amount in (0, 1, 10, 11, 300, 5000, 4000, 999999, 10 ** 9):
                policy = {"rate_ppm": rate, "cap_mc": cap,
                          "exempt_below_mc": exempt}
                cls.table.append({"sum": amount, "policy": policy})
                cls.expected.append(compute_burn(
                    amount, BurnPolicy(rate, cap, exempt)))
        cls.tmp = tempfile.mkdtemp(prefix="guipage-")
        harness = os.path.join(cls.tmp, "harness.js")
        with open(harness, "w") as handle:
            handle.write(PAGE_HARNESS)
        table = os.path.join(cls.tmp, "table.json")
        with open(table, "w") as handle:
            json.dump(cls.table, handle)
        page = os.path.join(REPO, "gui", "page.html")
        proc = subprocess.run([NODE, harness, page, table],
                              capture_output=True, text=True, timeout=120)
        if proc.returncode != 0:
            raise AssertionError("page.html would not run:\n" + proc.stderr)
        cls.out = json.loads(proc.stdout)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(getattr(cls, "tmp", ""), ignore_errors=True)

    def test_the_cost_line_predicts_what_the_payment_actually_does(self):
        """The finding: the quote named a recipient figure that never
        happened, because the burn is charged twice — once on the split and
        again when the recipient redeems."""
        s = self.out["s1"]
        self.assertEqual(s["paid"], 300)
        self.assertEqual(s["predicted"]["recipient_mc"], s["bob_balance"],
                         "the cost line promised a figure the payment did "
                         "not deliver")
        self.assertEqual(s["predicted"]["recipient_mc"], 297)
        self.assertEqual(s["predicted"]["out_mc"], 303)
        self.assertEqual(s["predicted"]["total_burn_mc"], 6)
        for text in ("303 mc", "297 mc", "6 mc"):
            self.assertIn(text, s["quote"])
        self.assertIn("297 mc", s["button"],
                      "the button must name what the recipient really gets")
        self.assertIn("297 mc", s["result"])

    def test_a_stale_quote_cannot_be_paid(self):
        """The finding: change the amount, click Pay inside the 350 ms
        debounce, and the page paid an amount it never quoted."""
        s = self.out["s2"]
        self.assertEqual(s["pays"], [], "money moved on a stale quote")
        self.assertEqual(s["bob_balance"], 0)
        self.assertTrue(s["afterType"]["disabled"],
                        "Pay stayed live after the amount changed")
        self.assertIn("Nothing was paid", s["message"])

    def test_pay_uses_the_quote_and_not_the_input_box(self):
        """Belt and braces on the same finding: even if the box changes
        without an event to invalidate the quote, the click must refuse
        rather than pay an amount nobody was shown."""
        s = self.out["s2b"]
        self.assertEqual(s["pays"], [], "the box was paid, not the quote")
        self.assertEqual(s["bob_balance"], 0)
        self.assertIn("Nothing was paid", s["message"])

    def test_a_quote_that_lands_late_does_not_re_arm_the_button(self):
        s = self.out["s2c"]
        self.assertIsNone(s["quote"], "a retired quote landed anyway")
        self.assertTrue(s["disabled"])
        self.assertEqual(s["label"], "Pay")

    def test_the_settings_panel_stays_where_the_operator_put_it(self):
        """The finding: renderMint() forced it shut on every 4-second poll
        once any mint had run, hiding the burn policy."""
        self.assertTrue(self.out["s3"]["open_after_renders"])

    def test_stop_then_start_keeps_the_mints_economics(self):
        """The finding: Stop then Start re-sent the form defaults and
        silently set rate_ppm 0 / cap_mc 0 on a mint that burned 1%."""
        s = self.out["s4"]
        self.assertEqual(s["after"], s["before"])
        self.assertEqual(int(s["form"]["rate"]), 10000)
        self.assertEqual(int(s["form"]["cap"]), 1000)

    def test_a_paste_where_nothing_was_taken_is_not_green(self):
        s = self.out["s5"]["html"]
        headline = s.split("</div>")[0]
        self.assertNotIn("note ok", headline)
        self.assertIn("warn bad", headline)
        self.assertIn("NONE", headline)

    def test_the_pages_burn_arithmetic_is_the_mints(self):
        """page.html computes the recipient's burn itself. If that drifts
        from impl/aicash/burncalc.compute_burn, the cost line lies again."""
        self.assertEqual(self.out["s6"], self.expected)

    # -- the round's honesty properties, at the screen ------------------

    def test_a_refused_quote_is_not_printed_raw(self):
        """The finding: the server's sentence went to the screen with its
        section citation intact and the amount printed twice, because the
        page prefixed its own "Cannot pay X: " to a sentence that already
        said it."""
        html = self.out["s7"]["html"]
        self.assertNotIn("\u00a7", html)
        self.assertNotIn("§", html)
        self.assertNotRegex(html, r"(?i)cannot pay .*cannot pay")
        self.assertIn("does not hold enough", html)
        self.assertIn("insufficient_funds", html)

    def test_a_history_row_speaks_the_cause_it_was_written_with(self):
        """app.py emits the machine reason under `cause`. A page that read
        `reason` found nothing on every real row, so the English headline
        was dead code. Asserting on the server's own key is the point."""
        html = self.out["s8"]["html"]
        self.assertIn("had already been spent", html)

    def test_an_undetermined_history_row_reads_as_undetermined(self):
        """`unknown` must never be dressed as a specific cause."""
        html = self.out["s8"]["html"]
        self.assertIn("undetermined", html)
        for invented in ("already been spent", "did not answer",
                         "not running", "does not hold enough"):
            self.assertNotIn(
                invented, html.split("undetermined")[0].split("<tr")[-1],
                "an undetermined row was given a specific cause")

    def test_a_committed_history_row_gets_no_failure_headline(self):
        rows = self.out["s8"]["rows"]
        self.assertEqual(len(rows), 4, rows)
        # Order as supplied: receive_failed, pay_failed(unknown), receive
        # (committed), pay_failed(mint_unreachable). Only the committed row
        # has no cause, so only it carries no <b> headline.
        self.assertNotIn("<b>", rows[2])
        for i in (0, 1, 3):
            self.assertIn("<b>", rows[i], "row %d lost its headline" % i)

    def test_nothing_claims_the_mint_never_saw_a_request_it_may_have(self):
        """A dead socket establishes that no ANSWER came back. It does not
        establish that the request never landed -- §5.1 persist-before-send
        and recover() exist precisely because it may have. The headline used
        to say "so it never saw this request" and was printed directly above
        a detail from walletops that said the opposite."""
        html = self.out["s8"]["html"]
        self.assertIn("mint did not answer", html)
        self.assertIn("undetermined", html)
        self.assertNotIn("never saw", html,
                         "the page asserted the mint never received a "
                         "request it has no way of knowing about")
        self.assertNotIn("never answered", html)

    def test_a_local_fault_leads_with_its_own_sentence_not_undetermined(self):
        """app.py defaults every local fault it raises to cause="unknown".
        That is the ABSENCE of a money cause, not a finding that the cause
        is undetermined, so the page must not print "undetermined" over a
        detail that plainly says what is wrong."""
        html = self.out["s9"]["html"]
        self.assertIn("bad_name", html)
        self.assertIn("1-32 characters", html)
        self.assertNotIn("undetermined", html)

    def test_an_unreachable_server_marks_every_balance_on_screen_stale(self):
        """The finding: the section-3 header kept showing a balance with no
        caveat while the rows under it were tagged "last known"."""
        s = self.out["s10"]
        self.assertTrue(s["beforeHidden"],
                        "the stale marker was showing while app.py answered")
        self.assertFalse(s["staleHidden"],
                         "the active-wallet header showed a figure as current "
                         "while the page could not reach app.py")
        self.assertIn("last known", s["list"])
        self.assertIn("not current", s["list"])

    def test_an_unreachable_server_is_not_reported_as_a_stopped_mint(self):
        """The whole class: a page that cannot reach app.py knows nothing
        about the mint, which is a separate process on its own port."""
        s = self.out["s10"]
        self.assertIn("cannot reach", s["banner"].lower())
        self.assertIn("not a report about the mint", s["banner"].lower())
        self.assertNotRegex(s["banner"], r"(?i)the mint (is|was) (stopped|not running)")
        self.assertNotRegex(s["header"], r"(?i)mint (is )?stopped")

    def test_payment_strings_are_not_claimed_to_be_the_only_copy(self):
        """The wallet writes every payment string to its own file before
        the exchange is sent, so "this is the only copy" was false on the
        two most alarming paths the page has. The page must ESTABLISH the
        other copy by reading it back, not assert it either way."""
        s = self.out["s11"]
        self.assertGreaterEqual(s["asked"], 1,
                                "the page never asked for the read-back")
        self.assertIn("not</b> the only copy", s["confirmed"])
        self.assertIn("read every one of them back", s["confirmed"])

    def test_the_payment_panel_itself_stops_saying_only_copy(self):
        """Pins the WIRING, not just the helper: a savedCopyNote that
        exists but is never called from payNow leaves the false sentence on
        screen, and that is the whole defect."""
        html = self.out["s11paid"]["html"]
        self.assertNotIn("only copy of it", html)
        self.assertNotRegex(html, r"this is the only copy")
        self.assertIn("not</b> the only copy", html)

    def test_a_read_back_that_is_incomplete_is_not_reported_as_complete(self):
        s = self.out["s11"]
        self.assertNotIn("not</b> the only copy", s["partial"])
        self.assertIn("1 of these 2", s["partial"])
        self.assertIn("will not tell you", s["partial"])

    def test_a_read_back_that_failed_promises_nothing(self):
        s = self.out["s11"]
        self.assertIn("could not check", s["cannotCheck"])
        self.assertIn("will not guess", s["cannotCheck"])
        self.assertNotIn("not</b> the only copy", s["cannotCheck"])


# ======================================================================
# THE MONEY — one end-to-end run against a real mint
# ======================================================================
class TestMoneyEndToEnd(unittest.TestCase):
    """What the page promises, against what the mint does.

    Real run_mint.py, real wallets, the real mintctl.py and walletops.py,
    driven through app.py's own HTTP API. This is the test that pins the
    numbers: nothing else here proves that the burn the page predicts is
    the burn the mint charges.
    """

    @classmethod
    def setUpClass(cls):
        import importlib
        try:
            cls.real = (importlib.import_module("gui.mintctl"),
                        importlib.import_module("gui.walletops"))
        except Exception as exc:       # a sibling component is mid-rewrite
            raise unittest.SkipTest("gui components not importable: %s" % exc)
        try:
            import cryptography  # noqa: F401
        except ImportError:
            raise unittest.SkipTest("the mint needs the cryptography package")
        sys.modules["mintctl"], sys.modules["walletops"] = cls.real
        cls.workdir = tempfile.mkdtemp(prefix="guimoney-")
        cls.httpd = gui_app.serve(0, cls.workdir, "127.0.0.1")
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever,
                                      kwargs={"poll_interval": 0.05},
                                      daemon=True)
        cls.thread.start()
        cls.cookie = exchange_cookie(cls.httpd)
        cls.policy = {"rate_ppm": 10000, "cap_mc": 1000, "exempt_below_mc": 10}
        cls.mint_port = free_port()
        status, obj = cls.post("/api/mint/start",
                               dict(mint_id="e2e-mint",
                                    baseline_model_class="baseline-v1",
                                    port=cls.mint_port, **cls.policy))
        if status != 200:
            cls.tearDownClass()
            raise unittest.SkipTest("could not start a real mint: %s" % obj)
        for name in ("alice", "bob"):
            status, obj = cls.post("/api/wallet/create", {"name": name})
            assert status == 200, obj

    @classmethod
    def tearDownClass(cls):
        try:
            cls.post("/api/mint/stop", {"drain_seconds": 2})
        except Exception:
            pass
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=10)
        install_fakes()
        shutil.rmtree(cls.workdir, ignore_errors=True)

    @classmethod
    def _call(cls, method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", cls.port, timeout=120)
        payload = None if body is None else json.dumps(body)
        head = {"Cookie": cls.cookie}
        if payload:
            head["Content-Type"] = "application/json"
        conn.request(method, path, payload, head)
        response = conn.getresponse()
        raw = response.read()
        conn.close()
        return response.status, json.loads(raw or b"{}")

    @classmethod
    def post(cls, path, body):
        return cls._call("POST", path, body)

    @classmethod
    def get(cls, path):
        return cls._call("GET", path)

    def ok(self, result, what):
        status, obj = result
        self.assertEqual(status, 200, "%s -> %s" % (what, obj))
        return obj

    def test_the_whole_flow_and_every_number_in_it(self):
        from aicash.burncalc import BurnPolicy, compute_burn
        policy = BurnPolicy(**self.policy)

        descriptor = self.ok(self.get("/api/mint/descriptor"), "descriptor")
        self.assertEqual(descriptor["burn_policy"], self.policy,
                         "the mint is not running the policy we asked for")
        burned_before = descriptor["supply"]["cumulative_burned_mc"]

        issued = self.ok(self.post("/api/mint/issue",
                                   {"amount_mc": 20000, "count": 1}), "issue")
        self.assertEqual(len(issued["tokens"]), 1)
        credited = self.ok(self.post("/api/wallet/receive",
                                     {"name": "alice",
                                      "tokens": issued["tokens"]}), "fund")
        # Funding is an exchange like any other: alice is credited NET.
        self.assertEqual(credited["accepted_mc"],
                         20000 - compute_burn(20000, policy))

        amount = 5000
        quote = self.ok(self.post("/api/wallet/quote",
                                  {"name": "alice", "amount_mc": amount}),
                        "quote")
        self.assertEqual(quote["burn_mc"], compute_burn(quote["inputs_mc"],
                                                        policy))
        self.assertEqual(quote["inputs_mc"],
                         amount + quote["burn_mc"] + quote["change_mc"])

        # Exactly what page.html's payCost() puts on screen before the click.
        predicted_recipient = amount - compute_burn(amount, policy)
        predicted_out = quote["inputs_mc"]
        predicted_total_burn = quote["burn_mc"] + compute_burn(amount, policy)

        before = self.ok(self.get("/api/wallet/summary?name=alice"),
                         "alice before")["balance_mc"]
        paid = self.ok(self.post("/api/wallet/pay",
                                 {"name": "alice", "amount_mc": amount}),
                       "pay")
        self.assertEqual(paid["amount_mc"], amount)
        after = self.ok(self.get("/api/wallet/summary?name=alice"),
                        "alice after")["balance_mc"]
        self.assertEqual(before - after, amount + quote["burn_mc"],
                         "the wallet lost something other than the quote")
        self.assertEqual(predicted_out - quote["change_mc"],
                         amount + quote["burn_mc"])

        got = self.ok(self.post("/api/wallet/receive",
                                {"name": "bob", "tokens": paid["tokens"]}),
                      "deliver")
        self.assertEqual(got["accepted_mc"], predicted_recipient,
                         "the recipient did not get what the cost line said")
        self.assertEqual(got["rejected"], [])

        # And the mint agrees about how much money was destroyed on the way.
        descriptor = self.ok(self.get("/api/mint/descriptor"), "descriptor")
        burned = descriptor["supply"]["cumulative_burned_mc"]
        self.assertEqual(
            burned - burned_before,
            compute_burn(20000, policy) + predicted_total_burn,
            "the mint burned a different total than the page accounted for")

    # -- the payment record, against the real mint ----------------------

    def fund(self, name, amount_mc=20000):
        """Real operator issuance into a real wallet (§7.1)."""
        issued = self.ok(self.post("/api/mint/issue",
                                   {"amount_mc": amount_mc, "count": 1}),
                         "issue")
        self.ok(self.post("/api/wallet/receive",
                          {"name": name, "tokens": issued["tokens"]}), "fund")

    def history_of(self, name):
        return self.ok(self.get("/api/wallet/history?name=" + name),
                       "history")["history"]

    def row_for(self, name, op_id):
        rows = [r for r in self.history_of(name) if r["op_id"] == op_id]
        self.assertEqual(len(rows), 1, "no history row for op %s" % op_id)
        return rows[0]

    def entry_for(self, name, op_id):
        out = self.ok(self.get("/api/wallet/outstanding?name=" + name),
                      "outstanding")
        return out, [p for p in out["payments"] if p["op_id"] == op_id]

    def second_gui(self):
        """A SECOND GUI process-equivalent over the same workdir.

        What "durable" has to mean for a record: not "the object that
        wrote it can still read it", but "a GUI started later, knowing
        only the workdir, can". The mint keeps running underneath, exactly
        as it would across a restart of the operator's browser tab and of
        the GUI itself.
        """
        httpd = gui_app.serve(0, self.workdir, "127.0.0.1")
        thread = threading.Thread(target=httpd.serve_forever,
                                  kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()
        cookie = exchange_cookie(httpd)
        port = httpd.server_address[1]

        def get(path):
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
            conn.request("GET", path, None, {"Cookie": cookie})
            response = conn.getresponse()
            raw = response.read()
            conn.close()
            return response.status, json.loads(raw or b"{}")

        def shutdown():
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=10)

        self.addCleanup(shutdown)
        return get

    def test_both_ways_of_delivering_one_payment_record_the_same_thing(self):
        """TWO ROUTES, ONE TRUTH -- against the real mint, over real HTTP.

        pay with ``to`` delivers server-side and records "delivered". Pay
        and then paste the strings into Receive is the same delivery by a
        different road, and it used to record nothing at all: the same
        server watched bob take the money and served a history row saying
        recipient "", delivery "unknown". One payment, two panels a second
        apart, opposite kinds of truth -- and the blind one was the flow
        the product shipped.
        """
        self.fund("alice")
        served = self.ok(self.post("/api/wallet/pay",
                                   {"name": "alice", "amount_mc": 2000,
                                    "to": "bob"}), "pay+deliver")
        pasted = self.ok(self.post("/api/wallet/pay",
                                   {"name": "alice", "amount_mc": 2000,
                                    "to": "bob", "deliver": False}),
                         "pay only")
        # ...before the delivery, the second one is honestly unknown
        self.assertEqual(pasted["delivery"], "unknown")
        self.assertEqual(pasted["delivery_attempt"], "not_attempted")

        got = self.ok(self.post("/api/wallet/receive",
                                {"name": "bob", "tokens": pasted["tokens"],
                                 "payer": "alice",
                                 "op_id": pasted["op_id"]}), "receive")
        self.assertEqual(got["rejected"], [])
        self.assertTrue(got["recorded"]["recorded"])
        self.assertEqual(got["recorded"]["delivery"], "delivered")

        rows = {op: self.row_for("alice", op)
                for op in (served["op_id"], pasted["op_id"])}
        # ONE TRUTH about the OUTCOME: who it was for and whether it
        # arrived are the same through both roads.
        for op, row in rows.items():
            self.assertEqual(row["recipient"], "bob", op)
            self.assertEqual(row["recipient_kind"], "wallet", op)
            self.assertEqual(row["delivery"], "delivered", op)
            self.assertEqual(row["delivery_cause"], "", op)
        # ...AND ONE FIELD THAT MUST DIFFER, because it asks a different
        # question: "did THIS WALLET ever try?". alice's wallet performed
        # the first delivery and performed nothing at all for the second
        # -- the strings were pasted, and the recipient's side of this
        # server watched them land. This line used to assert "attempted"
        # for both, which meant the paste route overwrote the answer
        # `pay()` had recorded seven lines above (asserted there as
        # `not_attempted`): the product knew, wrote it down, and then
        # replaced it with the opposite. "never sent" and "sent and lost"
        # send an operator to different components, and this is the only
        # field that tells them apart.
        self.assertEqual(rows[served["op_id"]]["delivery_attempt"],
                         "attempted", "the server did deliver this one")
        self.assertEqual(rows[pasted["op_id"]]["delivery_attempt"],
                         "not_attempted",
                         "this wallet never attempted the pasted delivery")
        self.assertEqual(rows[pasted["op_id"]]["delivery_attempt"],
                         pasted["delivery_attempt"],
                         "the recorded answer must survive the observation")
        # and it is durable: a GUI that never saw either payment reads it
        get = self.second_gui()
        status, obj = get("/api/wallet/history?name=alice")
        self.assertEqual(status, 200, obj)
        later = {r["op_id"]: r for r in obj["history"]}
        for op in rows:
            self.assertEqual(later[op]["delivery"], "delivered")
            self.assertEqual(later[op]["recipient"], "bob")

    def test_a_refused_paste_records_the_refusal_against_the_payment(self):
        """The same road, with the money already gone."""
        self.fund("alice")
        paid = self.ok(self.post("/api/wallet/pay",
                                 {"name": "alice", "amount_mc": 1500,
                                  "to": "bob", "deliver": False}), "pay")
        self.ok(self.post("/api/wallet/receive",
                          {"name": "bob", "tokens": paid["tokens"]}),
                "bob takes it")
        # ...and now somebody pastes the same strings again, naming the
        # payment. They are spent; the record must say so and must not
        # claim the value is recoverable.
        again = self.ok(self.post("/api/wallet/receive",
                                  {"name": "bob", "tokens": paid["tokens"],
                                   "payer": "alice",
                                   "op_id": paid["op_id"]}), "paste again")
        self.assertTrue(again["rejected"])
        self.assertEqual(again["recorded"]["delivery"], "undelivered")
        self.assertEqual(again["recorded"]["delivery_cause"], "already_spent")
        row = self.row_for("alice", paid["op_id"])
        self.assertEqual(row["delivery"], "undelivered")
        self.assertEqual(row["delivery_cause"], "already_spent")
        self.assertIn("ALREADY BEEN REDEEMED", row["detail"])
        self.assertNotIn("still this wallet's money", row["detail"])

    def test_an_external_payee_is_recorded_by_name_over_the_wire(self):
        """aicash's actual payee: an agent that is not a wallet here."""
        self.fund("alice")
        status, obj = self.post("/api/wallet/pay",
                                {"name": "alice", "amount_mc": 1000,
                                 "to": "acme-agent-42"})
        self.assertEqual(status, 404, obj)
        self.assertIn("deliver:false", obj["error"]["detail"])

        paid = self.ok(self.post("/api/wallet/pay",
                                 {"name": "alice", "amount_mc": 1000,
                                  "to": "acme-agent-42", "deliver": False}),
                       "external pay")
        row = self.row_for("alice", paid["op_id"])
        self.assertEqual(row["recipient"], "acme-agent-42")
        self.assertEqual(row["recipient_kind"], "wallet")
        self.assertEqual(row["delivery"], "unknown")
        self.assertEqual(row["delivery_attempt"], "not_attempted")
        # NOT "bearer": somebody was named, and the row says who.
        self.assertNotEqual(row["recipient_kind"], "bearer")

    def test_a_delivered_payment_records_its_recipient_and_its_outcome(self):
        """The server learns who the money was for, and writes it down."""
        self.fund("alice")
        before = self.ok(self.get("/api/wallet/summary?name=bob"),
                         "bob before")["balance_mc"]
        paid = self.ok(self.post("/api/wallet/pay",
                                 {"name": "alice", "amount_mc": 2000,
                                  "to": "bob"}), "pay")
        self.assertEqual(paid["recipient"], "bob")
        self.assertEqual(paid["recipient_kind"], "wallet")
        self.assertEqual(paid["delivery"], "delivered")
        self.assertEqual(paid["delivery_cause"], "")
        after = self.ok(self.get("/api/wallet/summary?name=bob"),
                        "bob after")["balance_mc"]
        self.assertGreater(after, before, "the delivery moved no money")

        row = self.row_for("alice", paid["op_id"])
        self.assertEqual(row["kind"], "pay")
        self.assertEqual(row["recipient"], "bob")
        self.assertEqual(row["delivery"], "delivered")
        self.assertEqual(row["delivery_cause"], "")
        self.assertIn("bob", row["detail"])

        # the read-back view of the same payment says the same thing
        _out, entry = self.entry_for("alice", paid["op_id"])
        self.assertEqual(len(entry), 1)
        self.assertEqual(entry[0]["recipient"], "bob")
        self.assertEqual(entry[0]["delivery"], "delivered")
        # ...and bob really redeemed it, so none of it is still live
        self.assertEqual(entry[0]["live_mc"], 0)

    def test_a_delivery_that_died_is_not_the_row_a_delivered_one_leaves(self):
        """REAL failure: the recipient's store is destroyed mid-flight.

        Not a mocked exception -- bob's wallet file is replaced with
        rubbish between the payment committing and the delivery being
        attempted, which is what a disk fault looks like from here. The
        money left alice either way; the record is the only thing that can
        ever tell the two payments apart again.
        """
        self.fund("alice")
        good = self.ok(self.post("/api/wallet/pay",
                                 {"name": "alice", "amount_mc": 1500,
                                  "to": "bob"}), "pay delivered")
        self.assertEqual(good["delivery"], "delivered")

        bobs = os.path.join(self.workdir, "wallets", "bob.db")
        with open(bobs, "rb") as fh:
            saved = fh.read()

        def restore():
            with open(bobs, "wb") as fh:
                fh.write(saved)
        self.addCleanup(restore)
        with open(bobs, "wb") as fh:
            fh.write(b"this is not a database\n" * 200)

        dead = self.ok(self.post("/api/wallet/pay",
                                 {"name": "alice", "amount_mc": 1500,
                                  "to": "bob"}), "pay undelivered")
        # The payment SUCCEEDED; the delivery did not. Answering 4xx here
        # would tell the operator nothing moved, which is false.
        self.assertEqual(dead["recipient"], "bob")
        self.assertIn(dead["delivery"], ("undelivered", "unknown"))
        self.assertNotEqual(dead["delivery"], "delivered")

        good_row = self.row_for("alice", good["op_id"])
        dead_row = self.row_for("alice", dead["op_id"])
        self.assertNotEqual(good_row["delivery"], dead_row["delivery"])
        self.assertNotEqual(good_row["detail"], dead_row["detail"])
        self.assertEqual(good_row["amount_mc"], dead_row["amount_mc"])

        # ...and the money of the failed one is still findable and live.
        restore()
        _out, entry = self.entry_for("alice", dead["op_id"])
        self.assertEqual(len(entry), 1)
        self.assertEqual(entry[0]["live_mc"], 1500)
        self.assertEqual(entry[0]["delivery"], dead["delivery"])
        self.assertEqual([t["state"] for t in entry[0]["tokens"]],
                         ["unspent"] * len(entry[0]["tokens"]))

    def test_the_record_and_the_value_survive_the_gui_restarting(self):
        """A second GUI over the same workdir sees all of it."""
        self.fund("alice")
        delivered = self.ok(self.post("/api/wallet/pay",
                                      {"name": "alice", "amount_mc": 1200,
                                       "to": "bob"}), "delivered")
        bearer = self.ok(self.post("/api/wallet/pay",
                                   {"name": "alice", "amount_mc": 900}),
                         "bearer")
        get = self.second_gui()

        status, obj = get("/api/wallet/history?name=alice")
        self.assertEqual(status, 200, obj)
        rows = {r["op_id"]: r for r in obj["history"]}
        self.assertEqual(rows[delivered["op_id"]]["recipient"], "bob")
        self.assertEqual(rows[delivered["op_id"]]["delivery"], "delivered")
        self.assertEqual(rows[bearer["op_id"]]["recipient_kind"], "bearer")
        self.assertEqual(rows[bearer["op_id"]]["delivery"], "unknown")

        status, obj = get("/api/wallet/outstanding?name=alice")
        self.assertEqual(status, 200, obj)
        self.assertTrue(obj["checked"])
        entry = [p for p in obj["payments"] if p["op_id"] == bearer["op_id"]]
        self.assertEqual(len(entry), 1)
        self.assertEqual(entry[0]["live_mc"], 900)
        self.assertEqual(entry[0]["recipient_kind"], "bearer")
        # the strings themselves came back, from the file, in a process
        # that never saw the payment happen
        self.assertEqual(sorted(t["token"] for t in entry[0]["tokens"]),
                         sorted(bearer["tokens"]))
        self.assertGreaterEqual(obj["unredeemed_mc"], 900)

    def test_the_two_questions_say_on_the_wire_which_is_which(self):
        """The reviewer's pair of numbers, with the distinction legible."""
        self.fund("alice")
        bearer = self.ok(self.post("/api/wallet/pay",
                                   {"name": "alice", "amount_mc": 220}),
                         "bearer")
        out = self.ok(self.get("/api/wallet/outstanding?name=alice"),
                      "outstanding")
        self.assertTrue(out["checked"])
        self.assertGreaterEqual(out["unredeemed_mc"], 220)
        self.assertIn(bearer["op_id"], [p["op_id"] for p in out["payments"]])
        self.assertIn("recover", out["scope"])

        settled = self.ok(self.post("/api/wallet/recover", {"name": "alice"}),
                          "recover")
        self.assertEqual(
            [v for v in settled["result"].values()
             if isinstance(v, int) and v], [],
            "recover() claimed work over payments that committed: %s"
            % settled["result"])
        self.assertIn("outstanding", settled["scope"])

        # ...and the money is still there afterwards: recover() reporting
        # nothing is not recover() having lost anything.
        again = self.ok(self.get("/api/wallet/outstanding?name=alice"),
                        "outstanding again")
        self.assertEqual(again["unredeemed_mc"], out["unredeemed_mc"])

    # -- the cause vocabulary, against the real mint --------------------

    def start_mint(self):
        return self.post("/api/mint/start",
                         dict(mint_id="e2e-mint",
                              baseline_model_class="baseline-v1",
                              port=self.mint_port, **self.policy))

    def test_a_stopped_mint_is_never_reported_as_a_rejection(self):
        """Stop the real mint, try to move real money, read the words.

        This is the shape of the row the reviewer found: a delivery that
        failed with the mint DOWN, described as a refusal the mint never
        made. Here it is the live API, the real supervisor and the real
        wallet — nothing is simulated except the operator pressing stop.
        """
        self.addCleanup(self.start_mint)
        self.ok(self.post("/api/mint/stop", {"drain_seconds": 1}), "stop")

        status, obj = self.post("/api/wallet/pay",
                                {"name": "alice", "amount_mc": 100})
        self.assertGreaterEqual(status, 400, obj)
        error = obj["error"]
        self.assertEqual(error["cause"], "mint_stopped")
        self.assertIn(error["cause"], gui_app.CAUSES)
        self.assertNotIn("reject", error["detail"].lower())
        self.assertNotIn("spent", error["detail"].lower())

        # A wallet read still works with the mint down, and the history it
        # returns still says nothing the mint did not do.
        history = self.ok(self.get("/api/wallet/history?name=alice"),
                          "history")["history"]
        for row in history:
            self.assertIn(row["cause"], ("",) + tuple(gui_app.CAUSES))
            if "reject" in row["detail"].lower():
                self.assertIn(row["cause"], ("mint_rejected", "already_spent"),
                              "a permanent row blamed the mint for a refusal "
                              "it never made: %r" % (row,))

    def test_a_spent_token_is_a_rejection_and_says_which_one(self):
        """The other half: when the mint DID answer, say so, precisely."""
        issued = self.ok(self.post("/api/mint/issue",
                                   {"amount_mc": 300, "count": 1}), "issue")
        self.ok(self.post("/api/wallet/receive",
                          {"name": "bob", "tokens": issued["tokens"]}), "once")
        again = self.ok(self.post("/api/wallet/receive",
                                  {"name": "bob", "tokens": issued["tokens"]}),
                        "twice")
        self.assertEqual(again["accepted"], 0)
        self.assertEqual(again["rejected"][0]["cause"], "already_spent")

        history = self.ok(self.get("/api/wallet/history?name=bob"),
                          "history")["history"]
        failed = [r for r in history if r["kind"] == "receive_failed"]
        self.assertTrue(failed, "the rejected redemption left no row")
        self.assertEqual(failed[0]["cause"], "already_spent")

    def test_a_malformed_paste_is_not_the_mints_fault(self):
        result = self.ok(self.post("/api/wallet/receive",
                                   {"name": "bob", "tokens": ["not-a-token"]}),
                         "junk")
        self.assertEqual(result["rejected"][0]["cause"], "malformed_token")
        self.assertNotIn("mint rejected", result["rejected"][0]["detail"])

    def test_a_token_from_another_mint_reads_as_wrong_mint(self):
        """A well-formed token this mint never issued: not a bad paste."""
        from aicash.tokencodec import format_token, new_secret
        stranger = format_token("some-other-mint", 500, new_secret())
        result = self.ok(self.post("/api/wallet/receive",
                                   {"name": "bob", "tokens": [stranger]}),
                         "stranger")
        self.assertEqual(result["rejected"][0]["cause"], "wrong_mint")

    def test_paying_more_than_the_wallet_holds_is_insufficient_funds(self):
        status, obj = self.post("/api/wallet/pay",
                                {"name": "bob", "amount_mc": 10 ** 9})
        self.assertGreaterEqual(status, 400, obj)
        self.assertEqual(obj["error"]["cause"], "insufficient_funds")
        self.assertNotIn("reject", obj["error"]["detail"].lower())

    # -- money the browser was the only copy of -------------------------

    def test_money_stranded_by_a_lost_result_panel_is_recoverable(self):
        """Pay, throw the tokens away as a closed tab would, get them back.

        The page calls the strings in its result panel "the only copy". If
        that were true this test could not exist: it drops them on the
        floor and then redeems the same money from what the server can read
        back out of the wallet file.
        """
        funding = self.ok(self.post("/api/mint/issue",
                                    {"amount_mc": 9000, "count": 1}), "issue")
        self.ok(self.post("/api/wallet/receive",
                          {"name": "alice", "tokens": funding["tokens"]}),
                "fund")
        paid = self.ok(self.post("/api/wallet/pay",
                                 {"name": "alice", "amount_mc": 2000}), "pay")
        lost = list(paid["tokens"])
        del paid                      # the tab is closed; the DOM is gone

        out = self.ok(self.get("/api/wallet/outstanding?name=alice"),
                      "outstanding")
        self.assertTrue(out["checked"], "the mint is up; it should be asked")
        live = [t["token"] for p in out["payments"] for t in p["tokens"]
                if t["state"] == "unspent"]
        for token in lost:
            self.assertIn(token, live,
                          "a payment string was not recoverable from the "
                          "wallet file")

        before = self.ok(self.get("/api/wallet/summary?name=bob"),
                         "bob")["balance_mc"]
        got = self.ok(self.post("/api/wallet/receive",
                                {"name": "bob", "tokens": lost}), "deliver")
        self.assertEqual(got["rejected"], [])
        self.assertGreater(got["accepted_mc"], 0)
        after = self.ok(self.get("/api/wallet/summary?name=bob"),
                        "bob after")["balance_mc"]
        self.assertEqual(after - before, got["accepted_mc"])

        # ...and once redeemed, they are reported as spent rather than as
        # money still sitting there.
        out = self.ok(self.get("/api/wallet/outstanding?name=alice"),
                      "outstanding after")
        states = {t["token"]: t["state"] for p in out["payments"]
                  for t in p["tokens"]}
        for token in lost:
            self.assertEqual(states.get(token), "spent")

    def test_nothing_but_the_wallet_file_is_written_for_that(self):
        """No sidecar of bearer strings: the store already IS the copy.

        The payment record beside alice's store is not that sidecar and
        this proves it rather than trusting the name: the file is opened
        and searched for every string the payments produced. What the
        layout rule protects -- no second copy of live money on disk --
        is asserted directly, and the listing is still exact, so a cache,
        a lock file or a stray temp file fails this as it always did.
        """
        wallets = os.path.join(self.workdir, "wallets")
        out = self.ok(self.get("/api/wallet/outstanding?name=alice"),
                      "outstanding")
        self.assertEqual(sorted(os.listdir(wallets)),
                         ["alice.db", "alice.payments.db", "bob.db"])
        with open(os.path.join(wallets, "alice.payments.db"), "rb") as fh:
            blob = fh.read()
        self.assertNotIn(b"aicash:", blob)
        seen = 0
        for payment in out["payments"]:
            for token in payment["tokens"]:
                if token["token"]:
                    seen += 1
                    self.assertNotIn(token["token"].encode(), blob)
                    self.assertNotIn(
                        token["token"].split(":")[-1].encode(), blob)
        self.assertGreater(seen, 0, "no payment strings to check against")

    def test_a_bad_token_in_a_batch_never_loses_the_good_one(self):
        issued = self.ok(self.post("/api/mint/issue",
                                   {"amount_mc": 400, "count": 1}), "issue")
        result = self.ok(self.post("/api/wallet/receive",
                                   {"name": "bob",
                                    "tokens": ["not-a-token"] + issued["tokens"]}),
                         "receive")
        self.assertEqual(result["accepted"], 1)
        self.assertEqual(len(result["rejected"]), 1)
        self.assertGreater(result["accepted_mc"], 0)


if __name__ == "__main__":
    unittest.main()


# ======================================================================
# ROUND 5 — the two states next door
# ======================================================================
class TestAliveIsNotTheSameAsAnswering(unittest.TestCase):
    """``running`` and ``responding`` are two questions, and this server
    used to relay only the first.

    MintControl.status() probes the descriptor and reports ``responding``.
    app.py built its status dict field by field and simply left that one
    out, so a mint that was alive and answering nothing reached the page
    as an ordinary running mint -- the healthy indicator, the word
    "running" and a climbing uptime, on something that refused every
    payment. The whole difference was left in the English of
    ``last_error``, which page.html renders only when the mint is STOPPED.

    The rule these pin: RELAYED, never inferred, and ``None`` when the
    component did not say -- "we were not told" is a third answer, and
    neither of the other two may be guessed from ``last_error`` or from
    ``running``.
    """

    def _status(self, raw_extra):
        class Control(FakeMintControl):
            def status(self):
                out = FakeMintControl.status(self)
                out.update(raw_extra)
                return out
        workdir = tempfile.mkdtemp(prefix="guiapp-responding-")
        saved = sys.modules["mintctl"]
        module = types.ModuleType("mintctl")
        module.MintControl = Control
        module.MintControlError = FakeMintControlError
        sys.modules["mintctl"] = module
        try:
            return gui_app.Api(workdir).mint_status()
        finally:
            sys.modules["mintctl"] = saved
            shutil.rmtree(workdir, ignore_errors=True)

    def test_a_mint_that_is_answering_says_so(self):
        self.assertIs(self._status({"responding": True})["responding"], True)

    def test_a_mint_that_is_alive_and_not_answering_says_so(self):
        status = self._status({
            "responding": False,
            "last_error": "the mint process (pid 4242) is running but is not"
                          " answering on port 8787 yet",
        })
        self.assertIs(status["responding"], False)
        # and it is still running: the two fields answer different questions
        self.assertIs(status["running"], True)

    def test_a_control_that_does_not_say_leaves_it_unknown(self):
        """None, not False. FakeMintControl predates the field."""
        self.assertIsNone(self._status({})["responding"])

    def test_it_is_not_inferred_from_last_error(self):
        """A last_error on a mint that IS answering does not make it deaf.

        The obvious wrong implementation reads the English of last_error,
        or treats "there is an error" as "not answering". Both would flip
        this case, which is an ordinary running mint carrying the note
        from its previous failed start.
        """
        status = self._status({"responding": True,
                               "last_error": "a previous start failed"})
        self.assertIs(status["responding"], True)

    def test_a_non_bool_is_not_quietly_believed(self):
        """A component answering "yes" as a string said nothing usable."""
        for junk in ("true", 1, 0, [], {}, "no"):
            with self.subTest(junk=junk):
                self.assertIsNone(self._status({"responding": junk})["responding"])


class TestTheRecordVocabulariesDoNotDrift(unittest.TestCase):
    """Three closed sets, two files, one meaning each.

    walletops.py produces these values and app.py validates them again on
    the way out -- deliberately, because a component this server does not
    own must not be able to widen a set by answering a new word. That
    means the tuples are written twice, and the next person to add a
    member will add it to one file: a word walletops starts writing would
    then be scrubbed to "unknown" by the relay, silently, with the
    operator reading a downgraded record and nothing failing.

    It also pins the thing this round was about: each set carries a word
    for UNDETERMINED, and the empty string is reserved for exactly one
    other meaning -- the question does not arise.
    """

    def test_the_three_sets_are_the_same_in_both_files(self):
        self.assertEqual(set(walletops.RECIPIENT_KINDS),
                         set(gui_app.RECIPIENT_KINDS))
        self.assertEqual(set(walletops.DELIVERY_ATTEMPTS),
                         set(gui_app.DELIVERY_ATTEMPTS))
        self.assertEqual(set(walletops.DELIVERY_OUTCOMES),
                         set(gui_app.DELIVERIES))

    def test_every_set_can_say_undetermined(self):
        """...in a word, so it never has to say it with a blank."""
        for name, values in (("RECIPIENT_KINDS", walletops.RECIPIENT_KINDS),
                             ("DELIVERY_ATTEMPTS",
                              walletops.DELIVERY_ATTEMPTS),
                             ("DELIVERY_OUTCOMES",
                              walletops.DELIVERY_OUTCOMES),
                             ("STORE_STATES",
                              walletops.STORE_STATE_VALUES)):
            with self.subTest(vocabulary=name):
                self.assertIn(walletops.UNDETERMINED, values)

    def test_not_applicable_is_declared_and_is_in_no_vocabulary(self):
        """The blank is a MEMBER of each value set and of no vocabulary.

        The vocabularies are the real answers; NOT_APPLICABLE is the
        declared way of saying there was no question. Both files agree on
        it, and neither writes it as an answer.
        """
        self.assertEqual(walletops.NOT_APPLICABLE, gui_app.NOT_APPLICABLE)
        self.assertEqual(walletops.UNDETERMINED, gui_app.UNDETERMINED)
        for vocabulary in (walletops.RECIPIENT_KINDS,
                           walletops.DELIVERY_ATTEMPTS,
                           walletops.DELIVERY_OUTCOMES,
                           walletops.STORE_STATES):
            self.assertNotIn(walletops.NOT_APPLICABLE, vocabulary)
        for values in (walletops.RECIPIENT_KIND_VALUES,
                       walletops.DELIVERY_ATTEMPT_VALUES,
                       walletops.DELIVERY_VALUES):
            self.assertIn(walletops.NOT_APPLICABLE, values)
        # A token row always HAS a store state, so there is no
        # not-applicable for it and the set says so.
        self.assertNotIn(walletops.NOT_APPLICABLE,
                         walletops.STORE_STATE_VALUES)


class TestTheRefusedValueListsDoNotDrift(unittest.TestCase):
    """One question, two files, and they must not answer it differently.

    "Is the refused value still this wallet's money?" has three answers,
    chosen by the delivery cause. walletops decides it in
    ``_refused_value_clause()`` and writes the answer into the permanent
    record; page.html decides it again in ``refusedValueClause()`` to put
    a sentence on the pay panel. For a long time the page did not decide
    at all -- it printed "The money is NOT lost: it is in the strings
    below" for EVERY cause, including ``already_spent``, and then printed
    the record's own contradicting sentence two lines underneath, above a
    textarea with a Copy button on it.

    The two lists are now the same lists. This is what keeps them that
    way, because the next person to add a cause will add it to one file.
    """

    @staticmethod
    def _js_list(name):
        with io.open(os.path.join(REPO, "gui", "page.html"),
                     encoding="utf-8") as handle:
            src = handle.read()
        match = re.search(r"const %s = \[(.*?)\];" % name, src, re.S)
        assert match, "page.html no longer defines %s" % name
        return tuple(re.findall(r'"([^"]+)"', match.group(1)))

    def test_the_gone_set_is_the_same_in_both_files(self):
        self.assertEqual(self._js_list("REFUSED_VALUE_GONE"),
                         walletops._REFUSED_VALUE_GONE)

    def test_the_live_set_is_the_same_in_both_files(self):
        self.assertEqual(self._js_list("REFUSED_VALUE_LIVE"),
                         walletops._REFUSED_VALUE_LIVE)

    def test_already_spent_is_the_one_cause_whose_value_is_gone(self):
        """Stated on its own, because it is the whole point.

        A §3.8 rejection is atomic and consumes nothing, so every other
        refusal leaves the value live. already_spent is the one where
        somebody else already took the money, and it is the one the page
        was getting wrong.
        """
        self.assertEqual(walletops._REFUSED_VALUE_GONE, ("already_spent",))
        self.assertNotIn("already_spent", walletops._REFUSED_VALUE_LIVE)

    def test_every_cause_lands_in_exactly_one_list_or_neither(self):
        gone = set(walletops._REFUSED_VALUE_GONE)
        live = set(walletops._REFUSED_VALUE_LIVE)
        self.assertEqual(gone & live, set())
        # mint_unreachable and unknown are deliberately in NEITHER: nothing
        # answered, so what became of the value was not established, and
        # the third clause is the honest one for them.
        for cause in ("mint_unreachable", "unknown"):
            self.assertNotIn(cause, gone | live)
        # and nothing outside the pinned vocabulary has crept in
        for cause in gone | live:
            self.assertIn(cause, walletops.CAUSES)


# The second page harness. Deliberately NOT folded into PAGE_HARNESS: that
# one drives a whole session through S1-S11 and its scenarios share one
# fake server, while these two need to plant a specific SERVER ANSWER and
# read one panel back. Keeping them apart means a change to either cannot
# quietly alter what the other proves.
PAGE_STATES_HARNESS = r'''/* Drives gui/page.html's real script under a small DOM and prints, as
   JSON, the two panels round 5 was about.
   usage: node states.js <page.html> <record.json> */
"use strict";
const fs = require("fs");
const REC = JSON.parse(fs.readFileSync(process.argv[3], "utf8"));
function el(id) {
  return {id: id, textContent: "", innerHTML: "", value: "", disabled: false,
    hidden: false, className: "", open: false, scrollTop: 0, scrollHeight: 0,
    dataset: {}, style: {}, listeners: {},
    addEventListener(e, f) { (this.listeners[e] = this.listeners[e] || []).push(f); },
    fire(e, a) { for (const f of (this.listeners[e] || [])) f(a || {}); },
    querySelectorAll() { return []; }, select() {}};
}
const nodes = new Map();
globalThis.document = {getElementById(id) {
  if (!nodes.has(id)) nodes.set(id, el(id));
  return nodes.get(id); }};
globalThis.window = {}; globalThis.navigator = {};
globalThis.localStorage = {getItem: () => null, setItem() {}};
globalThis.setInterval = () => 0;
const POL = {rate_ppm: 10000, cap_mc: 500, exempt_below_mc: 10};
let RESPONDING = true;
globalThis.fetch = async (path, init) => {
  const p = path.split("?")[0];
  const D = {
    "/api/mint/status": {running: true, pid: 4242, port: 8932,
      mint_id: "t-mint", base_url: "http://127.0.0.1:8932",
      started_at_ms: 1700000000000, responding: RESPONDING,
      last_error: RESPONDING ? null :
        "the mint process (pid 4242) is running but is not answering on port 8932 yet",
      last_start: null},
    "/api/mint/descriptor": {mint_id: "t-mint", baseline_model_class: "baseline-v1",
      mint_time: 1, denominations_mc: [1, 10, 100, 1000],
      burn_policy: POL, burn_policy_next: null},
    "/api/wallet/list": {wallets: [
      {name: "alice", balance_mc: 3438, coin_count: 5, mint_id: "t-mint", connected: true, error: null},
      {name: "bob", balance_mc: 0, coin_count: 0, mint_id: "t-mint", connected: true, error: null}], dir: "/w"},
    "/api/wallet/history": {name: "alice", history: []},
    "/api/wallet/outstanding": {name: "alice", checked: true, mint_id: "t-mint",
      unredeemed_mc: 0, unspent_mc: 0, spent_mc: 300, unstated_mc: 0, unchecked_mc: 0,
      scope: "s", payments: [{op_id: REC.op_id, amount_mc: 300, live_mc: 0,
        recipient: "bob", recipient_kind: "wallet", delivery: "undelivered",
        delivery_cause: REC.delivery_cause, delivery_attempt: "attempted",
        tokens: REC.tokens.map(t => ({token: t, amount_mc: 100, state: "spent"}))}]},
    "/api/wallet/quote": {name: "alice", amount_mc: 300, burn_mc: 3, change_mc: 0, inputs_mc: 303},
    "/api/wallet/pay": Object.assign({name: "alice", balance_mc: 3438}, REC)
  }[p];
  return {ok: !!D, status: D ? 200 : 404,
          json: async () => D || {error: {reason: "not_found", detail: p}}};
};
const html = fs.readFileSync(process.argv[2], "utf8");
new Function(html.match(/<script>\n([\s\S]*)<\/script>/)[1])();
const $ = id => document.getElementById(id);
const settle = ms => new Promise(r => setTimeout(r, ms || 300));
const flat = s => String(s || "").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
(async () => {
  const out = {};
  await settle(500);
  /* A — a delivery refused because somebody had already redeemed it. */
  $("p-amount").value = "300"; $("p-to").value = "bob"; $("p-to").fire("change");
  await settle(400);
  $("p-go").fire("click");
  await settle(600);
  out.payPanel = flat($("p-out").innerHTML);
  /* B — the mint alive and answering nothing. */
  RESPONDING = false;
  await window.refreshMint ? 0 : 0;
  $("m-refresh").fire("click");
  await settle(800);
  out.deaf = {dot: $("hdr-dot").className, header: flat($("hdr-state").textContent),
              stats: flat($("m-stats").innerHTML), quote: flat($("p-quote").innerHTML),
              payDisabled: $("p-go").disabled, issueDisabled: $("f-go").disabled,
              stopDisabled: $("m-stop").disabled, refreshDisabled: $("m-refresh").disabled,
              stoppedBanner: $("stopped-banner").hidden};
  console.log(JSON.stringify(out));
  process.exit(0);
})().catch(e => { console.error("HARNESS ERROR", e && e.stack || e); process.exit(1); });
'''


# The third page harness, and the smallest: it plants ONE server answer
# and reads back the three pure functions the reconciliation panel is
# built out of. No fake session, no clicks -- the whole point is that
# these are pure, so the rule they encode can be pinned without a page
# lifecycle around it.
PAGE_WINDOW_HARNESS = r'''/* usage: node window.js <page.html> <answer.json> */
"use strict";
const fs = require("fs");
const ANSWER = JSON.parse(fs.readFileSync(process.argv[3], "utf8"));
function el(id) {
  return {id: id, textContent: "", innerHTML: "", value: "", disabled: false,
    hidden: false, className: "", open: false, dataset: {}, style: {},
    listeners: {}, addEventListener() {}, querySelectorAll() { return []; }};
}
const nodes = new Map();
globalThis.document = {getElementById(id) {
  if (!nodes.has(id)) nodes.set(id, el(id));
  return nodes.get(id); }};
globalThis.window = {}; globalThis.navigator = {};
globalThis.localStorage = {getItem: () => null, setItem() {}};
globalThis.setInterval = () => 0;
globalThis.fetch = async () => ({ok: false, status: 599,
  json: async () => ({error: {reason: "not_found", detail: "x"}})});
const html = fs.readFileSync(process.argv[2], "utf8");
new Function(html.match(/<script>\n([\s\S]*)<\/script>/)[1])();
const flat = s => String(s || "").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
const rec = window.summariseUnredeemed(ANSWER.wire);
const r = window.reconcileSupply(ANSWER.supply, ANSWER.wallets,
                                 {alice: rec}, ANSWER.supply.mint_id, true);
const now = 1700000000000;
const lines = window.supplyLines(r, now, now, "", {canRecover: true, mintLive: true});
console.log(JSON.stringify({
  rec: {truncated: rec.truncated, payment_count: rec.payment_count,
        unlisted_outstanding_mc: rec.unlisted_outstanding_mc,
        unspent_mc: rec.unspent_mc},
  reconciled: {unredeemed_mc: r.unredeemed_mc, accounted: r.accounted,
               residual: r.residual, floor: r.floor,
               unredeemed_capped: r.unredeemed_capped,
               unredeemed_unlisted_mc: r.unredeemed_unlisted_mc},
  panel: lines.map(l => flat(l[1])).join(" || "),
  tag: window.unredeemedTag(rec),
  ceiling: flat(window.unredeemedSentence
    ? window.unredeemedSentence(rec, "alice").text : "")}));
process.exit(0);
'''


class TestTheBurnNoteAndTheMintAgree(unittest.TestCase):
    """The Mint-settings note must name what §7.3 actually charges on.

    MEASURED DEFECT: the note read "The burn is min(cap, amount x rate /
    1,000,000)". §7.3 charges on sum(inputs) of the /v3/exchange call, and
    a wallet almost never holds exact change. Against a live mint under
    rate_ppm 10000 / cap_mc 1000 / exempt_below_mc 10, POST
    /api/wallet/quote for 7,000 mc answered burn_mc 71 out of inputs_mc
    7,100. The note's formula predicts 70. It was the note that was wrong;
    page.html's own burnFor(sum, p) helper always took the sum, and so
    does the cost line the operator actually commits to.
    """

    NOTE = None

    @classmethod
    def setUpClass(cls):
        page = os.path.join(REPO, "gui", "page.html")
        with io.open(page, encoding="utf-8") as handle:
            text = handle.read()
        start = text.index("The burn is")
        cls.NOTE = text[start:start + 1200]

    def test_the_note_names_the_sum_of_the_inputs_not_the_amount(self):
        self.assertIn("sum", self.NOTE)
        self.assertNotIn("min(cap, amount", self.NOTE.replace("&nbsp;", " "))

    def test_the_example_in_the_note_is_what_burncalc_computes(self):
        """The worked figure on screen, checked against the implementation."""
        sys.path.insert(0, os.path.join(REPO, "impl"))
        try:
            from aicash.burncalc import BurnPolicy, compute_burn
        finally:
            sys.path.pop(0)
        policy = BurnPolicy(rate_ppm=10000, cap_mc=1000, exempt_below_mc=10)
        # The note says: paying 7,000 out of coins worth 7,100 burns 71,
        # not 70. Both halves of that sentence, checked.
        self.assertEqual(compute_burn(7100, policy), 71)
        self.assertNotEqual(compute_burn(7100, policy),
                            min(1000, 7000 * 10000 // 1000000))
        self.assertIn("7,100", self.NOTE.replace("&nbsp;", " "))
        self.assertIn("71", self.NOTE)


class TestTheWindowIsSaidOutLoud(unittest.TestCase):
    """A read-back that did not cover the wallet must say so, by value.

    THE DEFECT THIS PINS, measured through the real HTTP API before it was
    fixed: a wallet with 106 payments, 105 of them live 30 mc bearer
    payments nobody had redeemed, answered GET /api/wallet/outstanding
    ?limit=100 with a confident ``unredeemed_mc: 3000``. The component
    behind it, reading the same store at the same instant, answered
    ``None`` with ``truncated: true`` and ``unlisted_outstanding_mc: 200``.
    The true total was 3,200. The route rebuilt the headline from the rows
    it happened to receive and dropped every field that described the
    window, and the page then inferred truncation from a full page of rows
    and told the operator the read "covered only the 100 most recent
    payments" -- which is not how the window is spent either: live money
    is taken first, so the payments that fall off the end are the ones the
    wallet has already retired.

    AND THE SECOND HALF, which is the one that reads as an arithmetic
    contradiction on screen: the figure named in the gaps clause must not
    be presented as value to ADD. Handed-out value a wallet here has since
    redeemed sits in the balances AND in that figure, because the paying
    wallet's file never learned what became of its strings. On the wallet
    measured while this was written the gaps came to 15,380 mc beside a
    residual of 12,200 mc -- adding them exceeds the mint's whole supply.
    """

    out = None

    @classmethod
    def setUpClass(cls):
        if not NODE:
            raise unittest.SkipTest(
                "node is not installed; page.html's JavaScript cannot be "
                "executed here. The server tests still run.")
        cls.tmp = tempfile.mkdtemp(prefix="guiwindow-")
        harness = os.path.join(cls.tmp, "window.js")
        with io.open(harness, "w", encoding="utf-8") as handle:
            handle.write(PAGE_WINDOW_HARNESS)
        answer = {
            # The wire, in the shape route_wallet_outstanding now sends:
            # the window's own account of itself, and no headline over the
            # value it could not reach.
            "wire": {
                "name": "alice", "checked": True, "mint_id": "t-mint",
                "unredeemed_mc": None, "unspent_mc": 3000, "spent_mc": 0,
                "unstated_mc": 0, "unchecked_mc": 0, "unaccounted_mc": 0,
                "handed_over_mc": 3200, "payment_count": 106,
                "listed_mc": 3000, "unlisted_mc": 200,
                "unlisted_outstanding_mc": 200, "truncated": True,
                "recovered_mc": 0, "recovered_ops": [], "scope": "s",
                "payments": [{"op_id": "op-w", "amount_mc": 3000,
                              "live_mc": 3000, "recipient": "",
                              "recipient_kind": "", "delivery": "unknown",
                              "delivery_cause": "",
                              "delivery_attempt": "not_attempted",
                              "tokens": [{"token": "t", "amount_mc": 3000,
                                          "state": "unspent"}]}]},
            "supply": {"mint_id": "t-mint", "outstanding_mc": 20000,
                       "cumulative_issued_mc": 21000,
                       "cumulative_burned_mc": 1000},
            "wallets": [{"name": "alice", "balance_mc": 10000,
                         "mint_id": "t-mint", "coin_count": 3,
                         "connected": True, "error": None}]}
        path = os.path.join(cls.tmp, "answer.json")
        with io.open(path, "w", encoding="utf-8") as handle:
            json.dump(answer, handle)
        page = os.path.join(REPO, "gui", "page.html")
        proc = subprocess.run([NODE, harness, page, path],
                              capture_output=True, text=True, timeout=120)
        if proc.returncode != 0:
            raise AssertionError("page.html would not run:\n" + proc.stderr)
        cls.out = json.loads(proc.stdout)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(getattr(cls, "tmp", ""), ignore_errors=True)

    def test_truncation_comes_off_the_wire_not_off_the_row_count(self):
        """One row, and the record still knows the read was short.

        The row-count rule would have said "not truncated" here: the
        answer carries a single payment, nothing like the 100-row page it
        was watching for. The server said so instead.
        """
        self.assertTrue(self.out["rec"]["truncated"])
        self.assertEqual(self.out["rec"]["payment_count"], 106)
        self.assertEqual(self.out["rec"]["unlisted_outstanding_mc"], 200)

    def test_the_panel_names_the_value_the_read_missed(self):
        panel = self.out["panel"]
        self.assertIn("200 mc", panel)
        self.assertIn("floor", panel)
        self.assertIn("ceiling", panel)

    def test_the_panel_never_calls_the_window_the_newest_payments(self):
        """It is not. Live money is taken first; retired payments fall off.

        Saying "only the 100 most recent were checked" pointed the reader
        at old payments, which is exactly where the gap is NOT.
        """
        for text in (self.out["panel"], self.out["tag"], self.out["ceiling"]):
            self.assertNotIn("most recent", text)
            self.assertNotIn("newest", text)

    def test_the_gap_figure_is_not_offered_as_value_to_add(self):
        panel = self.out["panel"]
        self.assertIn("NOT VALUE TO ADD", panel)
        # ...and the arithmetic it is protecting: accounted + the gap
        # figure exceeds what the mint says exists, so a reader who added
        # them would get a number the signed snapshot contradicts.
        rec = self.out["reconciled"]
        self.assertEqual(rec["accounted"], 13000)
        self.assertEqual(rec["residual"], 7000)
        self.assertEqual(rec["unredeemed_unlisted_mc"], 200)
        self.assertTrue(rec["floor"])

    def test_the_missed_value_is_not_counted_as_money_the_page_can_point_to(self):
        """A ceiling stays a ceiling: nothing unverified joins `accounted`."""
        rec = self.out["reconciled"]
        self.assertEqual(rec["unredeemed_mc"], 3000)
        self.assertEqual(rec["accounted"], 10000 + 3000)


class TestTheStatesNextDoor(unittest.TestCase):
    """The two neighbours round 5 found, driven through the real page.

    Both are the same shape of defect: a state that inherits the
    presentation of the state beside it, and so tells the operator the
    other one's truth.
    """

    out = None

    @classmethod
    def setUpClass(cls):
        if not NODE:
            raise unittest.SkipTest(
                "node is not installed; page.html's JavaScript cannot be "
                "executed here. The server tests still run.")
        cls.tmp = tempfile.mkdtemp(prefix="guistates-")
        harness = os.path.join(cls.tmp, "states.js")
        with io.open(harness, "w", encoding="utf-8") as handle:
            handle.write(PAGE_STATES_HARNESS)
        # A record in the shape walletops really writes for the race where a
        # third party redeems the strings before the recipient sees them.
        record = {
            "tokens": ["aicash:v3:t-mint:100:" + "A" * 43,
                       "aicash:v3:t-mint:100:" + "B" * 43,
                       "aicash:v3:t-mint:100:" + "C" * 43],
            "amount_mc": 300, "burn_mc": 3, "change_mc": 0,
            "op_id": "11111111-2222-3333-4444-555555555555",
            "recipient": "bob", "recipient_kind": "wallet",
            "delivery": "undelivered", "delivery_cause": "already_spent",
            "delivery_attempt": "attempted",
            "delivery_detail": (
                "the recipient 'bob' refused 3 of 3 string(s) in this payment"
                " — those strings had ALREADY BEEN REDEEMED, so that"
                " value is not this wallet's money and cannot be paid again"
                " (op 11111111-2222-3333-4444-555555555555)"),
        }
        path = os.path.join(cls.tmp, "record.json")
        with io.open(path, "w", encoding="utf-8") as handle:
            json.dump(record, handle)
        page = os.path.join(REPO, "gui", "page.html")
        proc = subprocess.run([NODE, harness, page, path],
                              capture_output=True, text=True, timeout=120)
        if proc.returncode != 0:
            raise AssertionError("page.html would not run:\n" + proc.stderr)
        cls.out = json.loads(proc.stdout)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(getattr(cls, "tmp", ""), ignore_errors=True)

    # -- A: money that is gone must not be called money -----------------
    def test_already_spent_is_not_called_recoverable(self):
        """The sentence that was wrong, and the record's that was right.

        The page printed "The money is NOT lost: it is in the strings
        below" for every cause, then printed the record's own "those
        strings had ALREADY BEEN REDEEMED" two lines under it.
        """
        panel = self.out["payPanel"]
        self.assertIn("NOT recoverable", panel)
        self.assertNotIn("The money is NOT lost", panel)

    def test_the_panel_does_not_contradict_the_record_it_prints(self):
        panel = self.out["payPanel"]
        # the record's sentence is still printed verbatim ...
        self.assertIn("ALREADY BEEN REDEEMED", panel)
        # ... and nothing above it offers the strings as a way to re-send
        self.assertNotIn("save these strings and paste them", panel)
        self.assertNotIn("losing this screen is not losing the money", panel)

    def test_the_token_block_says_what_the_strings_are(self):
        """A token block is the most dangerous thing this page prints."""
        self.assertIn("These strings are spent", self.out["payPanel"])

    def test_the_mint_rejected_it_is_not_said_for_already_spent(self):
        self.assertNotIn("the mint answered and refused", self.out["payPanel"])

    # -- B: alive is not the same as answering --------------------------
    def test_a_mint_that_answers_nothing_does_not_get_the_healthy_light(self):
        deaf = self.out["deaf"]
        self.assertIn("unk", deaf["dot"])
        self.assertNotEqual(deaf["dot"].strip(), "dot")

    def test_the_header_says_it_rather_than_showing_an_uptime(self):
        deaf = self.out["deaf"]
        self.assertIn("RUNNING BUT NOT ANSWERING", deaf["header"])
        self.assertNotIn("up ", deaf["header"])
        # the reason was in last_error all along and was never rendered
        self.assertIn("not answering on port", deaf["header"])

    def test_the_state_cell_does_not_say_running(self):
        stats = self.out["deaf"]["stats"]
        self.assertIn("not answering", stats)
        self.assertNotIn("running State", stats)

    def test_nothing_that_needs_the_mint_is_left_armed(self):
        deaf = self.out["deaf"]
        self.assertTrue(deaf["payDisabled"])
        self.assertTrue(deaf["issueDisabled"])

    def test_the_way_out_is_left_live(self):
        """Stop and Refresh are how an operator clears this state."""
        deaf = self.out["deaf"]
        self.assertFalse(deaf["stopDisabled"])
        self.assertFalse(deaf["refreshDisabled"])

    def test_it_is_not_presented_as_a_stopped_mint(self):
        """mint_stopped means nothing was sent. This is not that."""
        deaf = self.out["deaf"]
        self.assertTrue(deaf["stoppedBanner"])          # banner stays hidden
        self.assertNotIn("The mint is stopped", deaf["quote"])
        self.assertIn("running but is not answering", deaf["quote"])


# ======================================================================
# TWO VIEWS OF ONE MINT MUST NOT DISAGREE
#
# Everything below runs against a real run_mint.py, the real gui/mintctl.py
# and the real gui/walletops.py, driven through app.py's own HTTP API. The
# conditions are caused, not simulated: a mint really SIGSTOPped at the OS
# level, a workdir that really has never been touched, a supervision file
# really left behind by a mint this GUI never started.
# ======================================================================
def page_timeouts_ms() -> dict:
    """EVERY fetch deadline page.html declares, not only the default.

    The round that sized this server's read budget argued it from "the
    page aborts at 20s", which is true of nineteen of the twenty-one
    routes and false of two: page.html declares
    ``{default: 20000, start: 90000, stop: 70000}`` and gives
    /api/mint/start and /api/mint/stop their own longer patience because a
    supervised process transition is slow to ANSWER. The premise a budget
    is argued from has to be the whole object, so this reads the whole
    object and the pin below takes the SMALLEST of them.
    """
    with open(os.path.join(REPO, "gui", "page.html")) as handle:
        source = handle.read()
    match = re.search(r"TIMEOUTS\s*=\s*\{([^}]*)\}", source)
    assert match, "page.html no longer declares TIMEOUTS"
    found = dict((name, int(value)) for name, value
                 in re.findall(r"(\w+)\s*:\s*(\d+)", match.group(1)))
    assert found, "page.html's TIMEOUTS declares no numbers"
    return found


def page_abort_ms() -> int:
    """page.html's OWN default fetch deadline, read out of page.html.

    Not a constant repeated here: the number that matters is the one the
    shipped page actually aborts on, and a copy of it in this file would
    keep agreeing with itself after the page changed.
    """
    with open(os.path.join(REPO, "gui", "page.html")) as handle:
        source = handle.read()
    match = re.search(r"TIMEOUTS\s*=\s*\{[^}]*?default\s*:\s*(\d+)", source)
    assert match, "page.html no longer declares TIMEOUTS.default"
    return int(match.group(1))


class RealMintCase(unittest.TestCase):
    """A GUI server, a real mint, and a cookie -- per test CLASS."""

    policy = {"rate_ppm": 10000, "cap_mc": 1000, "exempt_below_mc": 10}
    mint_id = "adjacency-mint"

    @classmethod
    def setUpClass(cls):
        import importlib
        try:
            cls.real = (importlib.import_module("gui.mintctl"),
                        importlib.import_module("gui.walletops"))
        except Exception as exc:       # a sibling component is mid-rewrite
            raise unittest.SkipTest("gui components not importable: %s" % exc)
        try:
            import cryptography  # noqa: F401
        except ImportError:
            raise unittest.SkipTest("the mint needs the cryptography package")
        sys.modules["mintctl"], sys.modules["walletops"] = cls.real
        cls.workdir = tempfile.mkdtemp(prefix="guiadj-")
        cls.httpd = gui_app.serve(0, cls.workdir, "127.0.0.1")
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever,
                                      kwargs={"poll_interval": 0.05},
                                      daemon=True)
        cls.thread.start()
        cls.cookie = exchange_cookie(cls.httpd)
        cls.mint_port = free_port()
        status, obj = cls.post("/api/mint/start",
                               dict(mint_id=cls.mint_id,
                                    baseline_model_class="baseline-v1",
                                    port=cls.mint_port, **cls.policy))
        if status != 200:
            cls.tearDownClass()
            raise unittest.SkipTest("could not start a real mint: %s" % obj)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.post("/api/mint/stop", {"drain_seconds": 2})
        except Exception:
            pass
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=10)
        install_fakes()
        shutil.rmtree(cls.workdir, ignore_errors=True)

    @classmethod
    def _call(cls, method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", cls.port, timeout=120)
        payload = None if body is None else json.dumps(body)
        head = {"Cookie": cls.cookie}
        if payload:
            head["Content-Type"] = "application/json"
        conn.request(method, path, payload, head)
        response = conn.getresponse()
        raw = response.read()
        conn.close()
        return response.status, json.loads(raw or b"{}")

    @classmethod
    def post(cls, path, body):
        return cls._call("POST", path, body)

    @classmethod
    def get(cls, path):
        return cls._call("GET", path)

    def ok(self, result, what):
        status, obj = result
        self.assertEqual(status, 200, "%s -> %s" % (what, obj))
        return obj

    def lookup(self, token):
        return self.get("/api/token/status?token="
                        + urllib.parse.quote(token, safe=""))


class TestTokenLookupIsAReading(RealMintCase):
    """A lookup is a photograph of a ledger key, and says so.

    The defect: the panel printed ``state: unspent, spent_at: null`` and
    went on printing it while the page re-rendered around it, with nothing
    on screen saying when that was read. Another wallet redeemed the same
    string; the wallet's own figures moved; the lookup did not, and the
    mint asked in the same second disagreed with it.
    """

    def issued_token(self, amount_mc=5000):
        issued = self.ok(self.post("/api/mint/issue",
                                   {"amount_mc": amount_mc, "count": 1}),
                         "issue")
        return issued["tokens"][0]

    def wallet(self, name):
        status, obj = self.post("/api/wallet/create", {"name": name})
        self.assertIn(status, (200, 409), obj)
        return name

    def test_a_reading_carries_the_moment_it_was_taken(self):
        token = self.issued_token()
        before = int(time.time() * 1000)
        body = self.ok(self.lookup(token), "lookup")
        after = int(time.time() * 1000)
        self.assertEqual(body["result"]["state"], "unspent")
        # in the object the panel actually prints, not only beside it
        stamp = body["result"]["observed_at_ms"]
        self.assertIsInstance(stamp, int)
        self.assertTrue(before <= stamp <= after,
                        "%r is not when this reading was taken" % stamp)
        self.assertEqual(body["observed_at_ms"], stamp)
        self.assertIn("reading", body["result"]["as_of"].lower())
        self.assertIn("not a live view", body["result"]["as_of"].lower())
        self.assertEqual(body["result"]["mint_id"], self.mint_id)
        self.assertIsInstance(body["result"]["mint_time"], int)

    def test_the_stamp_is_on_the_same_clock_as_the_rest_of_the_page(self):
        """ONE CLOCK. The stamp is the whole remedy; it has to be readable.

        page.html prints every other moment on the screen -- history rows,
        the supply read time, the wallets read time -- through when(), which
        is toLocaleString() on the viewer's own clock, and prefers this
        server's ``as_of`` words over its own when they are there. A UTC
        stamp therefore put 14:01:55Z on the same screen as 7:01:55 AM for
        the same instant, and the age of the reading -- the one thing the
        stamp exists to let an operator see -- could not be read off it.

        Pinned against a machine deliberately NOT on UTC, so a UTC stamp
        cannot pass by coincidence.
        """
        token = self.issued_token()
        was = os.environ.get("TZ")
        os.environ["TZ"] = "America/Los_Angeles"
        time.tzset()
        try:
            body = self.ok(self.lookup(token), "lookup")
            observed = body["result"]["observed_at_ms"] / 1000.0
            local = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(observed))
            utc = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(observed))
            self.assertNotEqual(local, utc, "this test needs a non-UTC zone")
            for where in (body["result"]["as_of"], body["as_of"]):
                self.assertIn(local, where)
                self.assertNotIn(utc, where)
                self.assertNotIn("Z -", where)
        finally:
            if was is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = was
            time.tzset()

    def test_the_reading_moves_when_the_money_does(self):
        """The reviewer's sequence, run for real."""
        token = self.issued_token()
        self.wallet("taker")
        first = self.ok(self.lookup(token), "lookup before")
        self.assertEqual(first["result"]["state"], "unspent")
        self.assertIsNone(first["result"]["spent_at"])
        self.ok(self.post("/api/wallet/receive",
                          {"name": "taker", "tokens": [token]}), "redeem")
        second = self.ok(self.lookup(token), "lookup after")
        self.assertEqual(second["result"]["state"], "spent")
        self.assertIsInstance(second["result"]["spent_at"], int)
        # ...and the mint, asked directly in the same breath, agrees
        conn = http.client.HTTPConnection("127.0.0.1", self.mint_port,
                                          timeout=10)
        conn.request("POST", "/v3/status",
                     json.dumps({"hashes": [second["ledger_key"]]}),
                     {"Content-Type": "application/json"})
        response = conn.getresponse()
        direct = json.loads(response.read())
        conn.close()
        self.assertEqual(direct["results"][0]["state"],
                         second["result"]["state"])
        # the stale reading is still identifiable AS stale: it is dated,
        # and its date is older than the one that replaced it
        self.assertLess(first["observed_at_ms"], second["observed_at_ms"] + 1)
        self.assertNotEqual(first["result"]["state"], second["result"]["state"])

    def test_two_readings_are_two_moments(self):
        """Two lookups of one key are two datable readings, not one fact.

        Polled on a MONOTONIC deadline rather than slept through. The old
        form was ``time.sleep(1.1)`` against a stamp with one-second
        granularity -- a hundred milliseconds of margin, on a wall clock
        that this test does not own. Any backward step of that size (an
        ntp correction, a suspended laptop, a VM clock resync) made the
        second reading land in the same second as the first and failed the
        last assertion. It failed once in a full run and passed
        twenty-five times in isolation, which is what a hundred
        milliseconds of margin looks like from the outside.

        Nothing here is weakened: all three assertions below are the
        original ones. What changed is that the test waits for the
        property it is about -- a reading taken in a later second -- and
        gives up on a monotonic clock, which no wall-clock step can move.
        On an ordinary run it finishes sooner than the old sleep did.
        """
        token = self.issued_token()
        one = self.ok(self.lookup(token), "first")
        deadline = time.monotonic() + 30.0
        two = one
        while time.monotonic() < deadline:
            time.sleep(0.2)
            two = self.ok(self.lookup(token), "second")
            if (two["observed_at_ms"] > one["observed_at_ms"]
                    and two["result"]["as_of"] != one["result"]["as_of"]):
                break
        self.assertEqual(one["result"]["state"], two["result"]["state"])
        self.assertLess(one["observed_at_ms"], two["observed_at_ms"])
        self.assertNotEqual(one["result"]["as_of"], two["result"]["as_of"])

    def test_another_mints_silence_is_not_this_tokens_state(self):
        """A token from a mint this GUI does not supervise.

        This mint answers ``unknown`` for the key, truthfully -- it has
        never seen it. Printing that as the token's state tells the
        operator the token does not exist, when what happened is that the
        question went to a ledger that was never asked to hold it.
        """
        from aicash.tokencodec import format_token, new_secret
        foreign = format_token("some-other-mint", 5000, new_secret())
        status, obj = self.lookup(foreign)
        self.assertEqual(status, 409, obj)
        self.assertEqual(obj["error"]["cause"], "wrong_mint")
        self.assertIn("some-other-mint", obj["error"]["detail"])
        self.assertIn(self.mint_id, obj["error"]["detail"])
        self.assertIn("undetermined", obj["error"]["detail"])
        # and a bare ledger key, which names no mint, is still answerable
        token = self.issued_token()
        key = self.ok(self.lookup(token), "lookup")["ledger_key"]
        again = self.ok(self.get("/api/token/status?token="
                                 + urllib.parse.quote(key, safe="")), "by key")
        self.assertIsNone(again["token_mint_id"])
        self.assertEqual(again["result"]["state"], "unspent")


class TestEveryAnswerALookupCanGive(RealMintCase):
    """The neighbours of the token panel, enumerated and checked.

    A stamped ``unspent`` next to an unstamped ``unknown`` would put the
    defect back one state to the left, so every answer that IS a reading
    carries its moment, and every answer that is NOT a reading says why in
    the closed cause vocabulary instead.
    """

    def test_a_live_key_a_spent_key_and_a_key_nobody_issued(self):
        from aicash.tokencodec import ledger_key, new_secret
        issued = self.ok(self.post("/api/mint/issue",
                                   {"amount_mc": 3000, "count": 2}), "issue")
        live, doomed = issued["tokens"]
        self.post("/api/wallet/create", {"name": "sink"})
        self.ok(self.post("/api/wallet/receive",
                          {"name": "sink", "tokens": [doomed]}), "redeem")
        never = ledger_key(new_secret())
        expected = {"unspent": live, "spent": doomed, "unknown": never}
        for state, query in expected.items():
            with self.subTest(state=state):
                body = self.ok(self.lookup(query), state)
                self.assertEqual(body["result"]["state"], state)
                # every one of them is a reading, and says so
                self.assertIsInstance(body["result"]["observed_at_ms"], int)
                self.assertIn("not a live view",
                              body["result"]["as_of"].lower())
                self.assertEqual(body["result"]["mint_id"], self.mint_id)
                self.assertEqual(body["observed_at_ms"],
                                 body["result"]["observed_at_ms"])

    def test_the_answers_that_are_not_readings_say_why_instead(self):
        from aicash.tokencodec import format_token, new_secret
        cases = [
            ("", 400, None),
            ("aicash:v3:" + self.mint_id + ":5000", 400, None),
            ("aicash:v3:" + self.mint_id + ":5000:not-base64url!!", 400, None),
            (format_token("elsewhere-mint", 10, new_secret()), 409,
             "wrong_mint"),
        ]
        for query, expect, cause in cases:
            with self.subTest(query=query[:40]):
                code, obj = self.get("/api/token/status?token="
                                     + urllib.parse.quote(query, safe=""))
                self.assertEqual(code, expect, obj)
                self.assertIn("error", obj)
                self.assertNotIn("result", obj)
                self.assertIn(obj["error"]["cause"], walletops.CAUSES)
                if cause:
                    self.assertEqual(obj["error"]["cause"], cause)


class TestAWedgedMintAgreesWithItself(RealMintCase):
    """The mint is SIGSTOPped: alive, holding the port, answering nothing.

    Two adjacent answers to "is the mint working" used to disagree for
    about a second -- ``responding: true`` from the status route while a
    request in the same second failed with ``mint_unreachable`` -- and the
    optimistic one was the one the panel drew.

    It is also the state every deadline in this server is sized for: a
    socket that connects and then never answers is what makes a route
    spend its whole timeout instead of failing at once.
    """

    #: EVERY route this server has, and which side of the page's abort it
    #: is on. The two lists together have to be the whole routing table --
    #: a route in neither is a route nobody measured, which is how
    #: /api/wallet/list (64s) and /api/wallet/outstanding (62s), the two
    #: slowest in the product, were left out of a "budget" the summary
    #: called universal.
    BOUND = (
        ("GET", "/api/mint/status", None, 200),
        ("GET", "/api/mint/logs", None, 200),
        ("GET", "/api/mint/descriptor", None, 502),
        ("POST", "/api/mint/issue", {"amount_mc": 10, "count": 1}, 502),
        ("GET", "/api/token/status?token=" + "A" * 43, None, 502),
        ("GET", "/api/wallet/list", None, 200),
        ("GET", "/api/wallet/summary?name=alice", None, 504),
        ("GET", "/api/wallet/history?name=alice", None, 200),
        ("GET", "/api/wallet/outstanding?name=alice", None, 504),
    )
    #: Outside it, each for a reason app.py states: they move money (so
    #: they cannot be answered by abandoning the worker that is moving it),
    #: they create a file, or they are a supervised start/stop that
    #: legitimately takes as long as the mint takes.
    UNBOUND = {"/api/wallet/quote", "/api/wallet/pay", "/api/wallet/receive",
               "/api/wallet/recover", "/api/wallet/create",
               "/api/mint/start", "/api/mint/stop"}

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # TWO wallets, with money, created while the mint still answers.
        # /api/wallet/list costs one mint timeout PER WALLET, so measuring
        # it against one wallet would not show the shape of the defect;
        # and a quote needs a wallet that can actually fund it, or it is
        # refused locally and the slow path is never entered.
        for name in ("alice", "bob"):
            status, obj = cls.post("/api/wallet/create", {"name": name})
            assert status == 200, obj
        status, issued = cls.post("/api/mint/issue",
                                  {"amount_mc": 1000, "count": 1})
        assert status == 200, issued
        status, obj = cls.post("/api/wallet/receive",
                               {"name": "alice", "tokens": issued["tokens"]})
        assert status == 200, obj
        # ...and a real payment handed out as bearer strings, so that
        # /api/wallet/outstanding has strings it must ASK THE MINT about.
        # With nothing handed over that route answers out of the wallet
        # file alone and never touches the mint, which would have measured
        # the deadline of a route that does not need one.
        status, obj = cls.post("/api/wallet/pay",
                               {"name": "alice", "amount_mc": 100})
        assert status == 200, obj

    def setUp(self):
        status = self.ok(self.get("/api/mint/status"), "status")
        self.assertTrue(status["running"])
        self.pid = status["pid"]
        os.kill(self.pid, signal.SIGSTOP)
        self.addCleanup(self._resume)

    def _resume(self):
        try:
            os.kill(self.pid, signal.SIGCONT)
        except OSError:                              # pragma: no cover
            pass
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            status, obj = self.get("/api/mint/status")
            if status == 200 and obj.get("responding") is True:
                return
            time.sleep(0.1)

    def test_the_status_route_and_a_real_request_agree(self):
        status = self.ok(self.get("/api/mint/status"), "status")
        self.assertTrue(status["running"], "wedged is not stopped")
        self.assertIs(status["responding"], False,
                      "the panel would draw this mint healthy")
        code, obj = self.get("/api/mint/descriptor")
        self.assertEqual(code, 502, obj)
        self.assertEqual(obj["error"]["cause"], "mint_unreachable")
        # ...and the status route still says the same thing afterwards
        again = self.ok(self.get("/api/mint/status"), "status again")
        self.assertIs(again["responding"], False)

    def test_no_reading_in_the_first_second_says_healthy(self):
        started = time.monotonic()
        seen = []
        while time.monotonic() - started < 3.0:
            status = self.ok(self.get("/api/mint/status"), "status")
            seen.append(status["responding"])
            self.assertIs(status["responding"], False,
                          "responding=%r at t=%.2fs; readings: %r"
                          % (status["responding"],
                             time.monotonic() - started, seen))
        self.assertTrue(seen)

    def test_every_route_is_on_one_of_the_two_lists(self):
        """A route in neither list is a route nobody measured.

        This is the check the old sweep did not have: its name claimed
        every cause this server determines, its body iterated three
        hand-picked routes, and the two slowest routes in the product --
        the one every balance on the screen comes from and the one the
        handed-over figure comes from -- were in neither the test, the
        README's timing table nor the limitations list.
        """
        measured = {path.split("?")[0] for _m, path, _b, _e in self.BOUND}
        table = {path for _method, path in gui_app.ROUTES}
        self.assertEqual(measured | self.UNBOUND, table,
                         "a route on neither list: %r"
                         % sorted(table - (measured | self.UNBOUND)))
        self.assertEqual(measured & self.UNBOUND, set())

    def test_every_bound_route_answers_inside_the_pages_abort(self):
        """gui/README tells the operator to read ``cause``. It has to arrive.

        page.html aborts a fetch at TIMEOUTS.default and shows its own
        message instead; a cause computed after that is a documented
        answer nobody can reach. Measured against a really wedged mint,
        for every route this server claims to bind -- not a sample of
        them.
        """
        budget = page_abort_ms() / 1000.0
        for method, path, body, expect in self.BOUND:
            with self.subTest(path=path):
                started = time.monotonic()
                code, obj = self._call(method, path, body)
                elapsed = time.monotonic() - started
                self.assertEqual(code, expect, obj)
                self.assertLess(
                    elapsed, budget,
                    "%s %s took %.1fs; the page stops listening at %.1fs"
                    % (method, path, elapsed, budget))
                if code >= 400:
                    self.assertIn(obj["error"]["cause"],
                                  ("mint_unreachable", "unknown"), obj)
                    self.assertTrue(obj["error"]["detail"])

    def test_the_balances_on_the_screen_are_marked_incomplete_not_padded(self):
        """What the bound wallet list actually says when it gives up.

        The deadline is only worth having if the answer under it is
        honest: a wallet that was not read may not come back as a zero,
        and the list may not present itself as the whole list. page.html's
        reconcileSupply() counts a wallet whose balance is not a number as
        unread and turns every total it feeds into a floor -- which is
        the rendering this shape is chosen to get.
        """
        code, obj = self.get("/api/wallet/list")
        self.assertEqual(code, 200, obj)
        self.assertFalse(obj["complete"],
                         "a partial list presented as the whole list")
        self.assertEqual(sorted(obj["unread"]), ["alice", "bob"])
        for row in obj["wallets"]:
            self.assertIsNone(row["balance_mc"], row)
            self.assertIsNone(row["coin_count"], row)
            self.assertFalse(row["connected"], row)
            self.assertTrue(row["error"], row)
            self.assertIn("not read", row["error"].lower())

    def test_the_money_routes_are_still_outside_the_budget_and_say_so(self):
        """The disclosure, measured rather than asserted.

        /api/wallet/quote goes through walletops.py into
        aicash.wallet.MintClient, whose 30s deadline this server does not
        set; it cannot be bound the way a read is, because answering by
        abandoning the worker would mean reporting an outcome for an
        operation still in flight. So it really does finish after the page
        has stopped listening, and that is stated in app.py rather than
        left for an operator to discover. Measured here so the statement
        cannot rot in either direction: if someone shortens it, this fails
        and the route moves onto the bound list with the comment.
        """
        budget = page_abort_ms() / 1000.0
        started = time.monotonic()
        code, obj = self.post("/api/wallet/quote",
                              {"name": "alice", "amount_mc": 10})
        elapsed = time.monotonic() - started
        self.assertIn("/api/wallet/quote", self.UNBOUND)
        self.assertGreater(
            elapsed, budget,
            "quote answered in %.1fs, inside the page's %.1fs abort: it is "
            "bound after all, and app.py still says it is not" % (elapsed, budget))
        self.assertGreaterEqual(code, 400, obj)
        # ...and it is named in the source as unbound, with the reason
        with open(os.path.join(REPO, "gui", "app.py")) as handle:
            source = handle.read()
        head = source[:source.index("PAGE_ABORT_S = ")]
        self.assertIn("NOT BOUND", head)
        for path in sorted(self.UNBOUND):
            self.assertIn(path, head, "%s is unbound and unnamed" % path)

    def test_the_budget_is_arithmetic_not_a_hope(self):
        """Probe + request has to fit, with the probe now uncached."""
        control = self.real[0]
        probe = control.MintControl.probe_timeout_s
        abort = page_abort_ms() / 1000.0
        self.assertLess(probe + gui_app.MINT_HTTP_TIMEOUT_S, abort,
                        "one probe plus one mint request does not fit inside "
                        "the page's own abort")
        # ...and the same arithmetic for the routes that do not go through
        # _mint_http at all, which is where the 64s and 62s reads were.
        self.assertLess(probe + gui_app.READ_DEADLINE_S, abort,
                        "one probe plus one whole wallet read does not fit "
                        "inside the page's own abort")

    def test_this_server_and_the_page_mean_the_same_deadline(self):
        """app.py sizes its budget from a number page.html owns. It has to
        be the number page.html actually uses, not a remembered one."""
        self.assertEqual(gui_app.PAGE_ABORT_S, page_abort_ms() / 1000.0)


class TestALiveMintWithNoRecordedPortSaysOneThing(RealMintCase):
    """The state the last fix opened: alive, and nobody knows where.

    Caused for real, through this server's own HTTP API, against a real
    mint that was answering normally a second earlier: the supervision
    record loses its port -- a hand-edited file, a partial restore, a
    record written by an older release.

    Two defects lived here at once and they pointed in opposite
    directions. GET /api/mint/status answered {running: true, port: null,
    responding: null} and page.html draws exactly that as the FULLY
    HEALTHY mint (its `deaf` test is `responding === false`), green dot,
    climbing uptime, every money button live, and `last_error` -- the one
    sentence saying the health is undetermined -- rendered only when the
    mint is down or deaf, so it never reached the screen. And the very
    next request, POST /api/wallet/quote, answered 409 mint_stopped, "The
    mint is not running, so nothing was sent to it": the closed
    vocabulary's promise about a PROCESS, made about a process this
    server had just called running, because base_url() tested
    `running AND base_url` and then reported the failure in the words of
    `running` alone.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        status, obj = cls.post("/api/wallet/create", {"name": "alice"})
        assert status == 200, obj

    def setUp(self):
        self.state_path = os.path.join(self.workdir, "mint-control.json")
        with open(self.state_path) as handle:
            self.intact = json.load(handle)
        self.assertTrue(self.intact.get("port"))
        self.addCleanup(self._put_the_port_back)
        damaged = dict(self.intact)
        damaged.pop("port", None)
        with open(self.state_path, "w") as handle:
            json.dump(damaged, handle)

    def _put_the_port_back(self):
        with open(self.state_path, "w") as handle:
            json.dump(self.intact, handle)

    def test_the_status_route_and_the_next_request_agree(self):
        status = self.ok(self.get("/api/mint/status"), "status")
        self.assertTrue(status["running"], "the process really is alive")
        self.assertIsNone(status["port"])
        self.assertIsNone(status["base_url"])
        code, obj = self.post("/api/wallet/quote",
                              {"name": "alice", "amount_mc": 10})
        self.assertGreaterEqual(code, 400, obj)
        error = obj["error"]
        # mint_stopped is the claim "the mint is down, so nothing was sent
        # and nothing can be half-done". Not available about a live pid.
        self.assertNotEqual(error["cause"], "mint_stopped",
                            "said the mint is not running about a mint this "
                            "server had just reported running")
        self.assertEqual(error["cause"], "mint_unreachable", error)
        self.assertNotIn("the mint is not running", error["detail"].lower())
        # ...and it says what is actually wrong, which is more than the
        # cause promises: nothing was sent at all.
        self.assertIn("nothing was sent", error["detail"].lower())
        self.assertIn("port", error["detail"].lower())
        # the status route has not changed its mind either
        again = self.ok(self.get("/api/mint/status"), "status again")
        self.assertTrue(again["running"])

    def test_the_page_cannot_draw_this_mint_healthy(self):
        """page.html's own predicate, computed off the shipped response."""
        status = self.ok(self.get("/api/mint/status"), "status")
        running = bool(status["running"])
        deaf = running and status["responding"] is False
        self.assertTrue(deaf,
                        "page.html would draw the healthy state: %r" % status)
        # the amber state is the one in which the page prints last_error,
        # so there has to be something to print
        self.assertTrue(status["last_error"])
        self.assertIn("port", status["last_error"].lower())
        self.assertIn("nothing was sent", status["last_error"].lower())

    def test_every_route_that_needs_the_mint_says_the_same_thing(self):
        """One state, one story, across the whole panel."""
        for method, path, body in (
                ("GET", "/api/mint/descriptor", None),
                ("POST", "/api/mint/issue", {"amount_mc": 10, "count": 1}),
                ("GET", "/api/token/status?token=" + "A" * 43, None),
                ("POST", "/api/wallet/quote",
                 {"name": "alice", "amount_mc": 10})):
            with self.subTest(path=path):
                code, obj = self._call(method, path, body)
                self.assertGreaterEqual(code, 400, obj)
                self.assertEqual(obj["error"]["cause"], "mint_unreachable",
                                 obj)


class TestTheFormAndTheSupervisorAgree(unittest.TestCase):
    """Booting against a workdir some other run left behind.

    mint-control.json is the supervisor's record and is what /api/mint/status
    is derived from. gui-state.json is this server's own note and only
    exists if a start went through this server. A workdir can hold the
    first without the second -- and then the status line named one mint
    while the Start form beside it defaulted to another.
    """

    @classmethod
    def setUpClass(cls):
        import importlib
        try:
            cls.mintctl = importlib.import_module("gui.mintctl")
            cls.walletops = importlib.import_module("gui.walletops")
        except Exception as exc:
            raise unittest.SkipTest("gui components not importable: %s" % exc)
        try:
            import cryptography  # noqa: F401
        except ImportError:
            raise unittest.SkipTest("the mint needs the cryptography package")

    @classmethod
    def tearDownClass(cls):
        install_fakes()

    def setUp(self):
        sys.modules["mintctl"] = self.mintctl
        sys.modules["walletops"] = self.walletops
        self.addCleanup(install_fakes)
        self.workdir = tempfile.mkdtemp(prefix="guileftover-")
        self.addCleanup(shutil.rmtree, self.workdir, True)

    def _leave_state_behind(self, **settings):
        """Really run a mint here, really stop it, leave its record.

        Started through MintControl directly, exactly as a mint started
        from a terminal would be: the supervision file is written, and no
        gui-state.json is ever created because no request came through
        app.py.
        """
        control = self.mintctl.MintControl(self.workdir)
        control.start_timeout_s = 20.0
        self.addCleanup(self._make_sure_it_is_stopped, control)
        control.start(**settings)
        control.stop(drain_seconds=3)
        self.assertTrue(os.path.exists(
            os.path.join(self.workdir, "mint-control.json")))
        self.assertFalse(os.path.exists(
            os.path.join(self.workdir, "gui-state.json")),
            "this test is only meaningful without this server's own note")

    @staticmethod
    def _make_sure_it_is_stopped(control):
        try:
            control.stop(drain_seconds=2)
        except Exception:
            pass

    def test_the_form_shows_the_mint_the_workdir_actually_holds(self):
        settings = dict(mint_id="leftover-mint",
                        baseline_model_class="baseline-v1",
                        port=free_port(), rate_ppm=4200, cap_mc=777,
                        exempt_below_mc=11)
        self._leave_state_behind(**settings)
        api = gui_app.Api(self.workdir)
        status = api.mint_status()
        self.assertFalse(status["running"])
        self.assertEqual(status["mint_id"], "leftover-mint")
        last = status["last_start"]
        self.assertIsNotNone(
            last, "the form was left to fall back on its own defaults")
        # page.html fills the Start form from last_start when the mint is
        # not running. It must not name a different mint than the line
        # above it, and it must not name the page's built-in defaults.
        self.assertEqual(last["mint_id"], status["mint_id"])
        self.assertEqual(last["port"], status["port"])
        self.assertNotEqual(last["mint_id"], "local-test-mint")
        self.assertNotEqual(last["port"], 8787)
        # and the economics are the mint's own, not the form's defaults
        self.assertEqual(last["rate_ppm"], 4200)
        self.assertEqual(last["cap_mc"], 777)
        self.assertEqual(last["exempt_below_mc"], 11)
        self.assertEqual(last["baseline_model_class"], "baseline-v1")

    def test_a_virgin_workdir_still_says_it_knows_nothing(self):
        """No record is not a licence to invent one."""
        api = gui_app.Api(self.workdir)
        status = api.mint_status()
        self.assertFalse(status["running"])
        self.assertIsNone(status["mint_id"])
        self.assertIsNone(status["last_start"])
        self.assertIsNone(status["responding"])
        # ...and nothing invented beside it either
        self.assertIsNone(status["last_start_sources"])
        self.assertIsNone(status["last_start_ignored_note"])

    def _a_real_note_from_a_real_start(self, **settings):
        """A gui-state.json written the only way one is ever written.

        A real mint, started through THIS server's own start route in a
        workdir of its own, then stopped. Returns the path of the note.
        Nothing here is hand-written: the note is whatever route_mint_start
        actually records.
        """
        other = tempfile.mkdtemp(prefix="guinote-")
        self.addCleanup(shutil.rmtree, other, True)
        api = gui_app.Api(other)
        control = self.mintctl.MintControl(other)
        control.start_timeout_s = 20.0
        self.addCleanup(self._make_sure_it_is_stopped, control)
        api.route_mint_start(None, dict(settings))
        api.route_mint_stop(None, {"drain_seconds": 3})
        path = os.path.join(other, "gui-state.json")
        self.assertTrue(os.path.exists(path), "no note was written")
        with open(path) as handle:
            self.assertEqual(json.load(handle)["last_start"]["mint_id"],
                             settings["mint_id"])
        return path

    def test_a_note_about_another_mint_does_not_fill_this_ones_form(self):
        """The composite that named two mints at once, caused for real.

        Both records here are produced by real runs. A real mint is started
        through this server in ANOTHER workdir, which is what writes a real
        gui-state.json note; a real, different mint is started and stopped
        in THIS one, which is what writes mint-control.json. The note is
        then copied across -- a gui-state.json carried along without the
        ledger beside it, which is one of the two ways this file's own
        docstring says the records come apart.

        The form may not be completed out of the other mint's note. Its
        rate_ppm/cap_mc/exempt_below_mc are that mint's economics, the page
        prints them as the burn policy "this GUI last started it with" and
        fills the Start form from them, so pressing Start would create THIS
        mint with THAT mint's burn policy.
        """
        note_settings = dict(mint_id="note-mint",
                             baseline_model_class="baseline-v1",
                             port=free_port(), rate_ppm=3300, cap_mc=21,
                             exempt_below_mc=12)
        note_path = self._a_real_note_from_a_real_start(**note_settings)
        held = dict(mint_id="legacy-mint", baseline_model_class="baseline-v1",
                    port=free_port(), rate_ppm=4200, cap_mc=777,
                    exempt_below_mc=11)
        self._leave_state_behind(**held)
        shutil.copyfile(note_path,
                        os.path.join(self.workdir, "gui-state.json"))

        api = gui_app.Api(self.workdir)
        status = api.mint_status()
        last = status["last_start"]
        self.assertEqual(last["mint_id"], "legacy-mint")
        self.assertEqual(last["mint_id"], status["mint_id"])
        self.assertEqual(last["port"], held["port"])
        self.assertEqual(last["port"], status["port"])
        # THIS mint's economics, out of its own record -- never the note's.
        self.assertEqual(last["rate_ppm"], 4200)
        self.assertEqual(last["cap_mc"], 777)
        self.assertEqual(last["exempt_below_mc"], 11)
        for field in ("rate_ppm", "cap_mc", "exempt_below_mc"):
            self.assertNotEqual(last[field], note_settings[field], field)
        # ...and the note that was dropped is reported, not silently gone
        dropped = status["last_start_ignored_note"]
        self.assertIsNotNone(dropped, "the note vanished without a word")
        self.assertEqual(dropped["mint_id"], "note-mint")
        self.assertIn("legacy-mint", dropped["why"])
        self.assertIn("note-mint", dropped["why"])
        # every field says which record it came out of
        sources = status["last_start_sources"]
        self.assertEqual(sorted(sources), sorted(last))
        for field, where in sources.items():
            self.assertNotIn("note", where.lower(), (field, where))

    def test_this_servers_own_note_still_fills_a_gap(self):
        """A record that predates the economics is completed, not replaced.

        The supervisor's record here is the shape an OLDER release of
        mintctl wrote: identity, no argv, so no economics. There is no way
        to produce a file written by code that no longer exists except to
        write one, and that is all this test writes -- the note beside it
        is a real note from a real start, and it is about the SAME mint, so
        it is the one thing that can honestly complete the form.
        """
        port = free_port()
        note_path = self._a_real_note_from_a_real_start(
            mint_id="gap-mint", baseline_model_class="baseline-v1",
            port=port, rate_ppm=3300, cap_mc=21, exempt_below_mc=12)
        control = self.mintctl.MintControl(self.workdir)
        with open(control.state_path, "w") as handle:
            json.dump({"pid": None, "port": port, "mint_id": "gap-mint",
                       "baseline_model_class": "baseline-v1",
                       "proc_start_ticks": None, "started_at_ms": 1,
                       "last_error": None}, handle)
        shutil.copyfile(note_path,
                        os.path.join(self.workdir, "gui-state.json"))
        api = gui_app.Api(self.workdir)
        status = api.mint_status()
        last = status["last_start"]
        # the supervisor knows the identity; the note only fills the rest
        self.assertEqual(last["mint_id"], "gap-mint")
        self.assertEqual(last["port"], port)
        self.assertEqual(last["rate_ppm"], 3300)
        self.assertEqual(last["cap_mc"], 21)
        self.assertEqual(last["exempt_below_mc"], 12)
        self.assertEqual(last["mint_id"], status["mint_id"])
        self.assertIsNone(status["last_start_ignored_note"])
        # ...and the object says which half came from where, which is what
        # makes "the note filled a gap" checkable instead of asserted.
        sources = status["last_start_sources"]
        self.assertEqual(sorted(sources), sorted(last))
        for field in ("mint_id", "port", "baseline_model_class"):
            self.assertNotIn("note", sources[field].lower(), field)
        for field in ("rate_ppm", "cap_mc", "exempt_below_mc"):
            self.assertIn("note", sources[field].lower(), field)

    def test_the_form_and_the_stats_block_cannot_name_two_mints(self):
        """The guarantee gui/README.md makes, asserted where it is made.

        page.html prints ``mint.mint_id``/``mint.port`` from status() in the
        stats block and fills the Start form from ``last_start`` -- both are
        on the screen together, so if the two records ever disagree the
        operator is looking at two mints. A component whose two answers
        disagree is not papered over: the status line wins, because that is
        the one the stats block shows, and ``last_start_sources`` says so
        in words for that field.
        """
        held = dict(mint_id="pinned-mint", baseline_model_class="baseline-v1",
                    port=free_port(), rate_ppm=4200, cap_mc=777,
                    exempt_below_mc=11)
        self._leave_state_behind(**held)

        class TwoAnswers:
            """A supervisor that contradicts itself, which is the only way
            these two fields can differ for a real MintControl -- it derives
            both from mint-control.json under one lock."""

            def __init__(self, inner):
                self._inner = inner

            def __getattr__(self, name):
                return getattr(self._inner, name)

            def recorded_start(self):
                out = dict(self._inner.recorded_start())
                out["mint_id"] = "some-other-mint"
                out["port"] = 65001
                return out

        api = gui_app.Api(self.workdir)
        api.components._mint = TwoAnswers(
            self.mintctl.MintControl(self.workdir))
        status = api.mint_status()
        last = status["last_start"]
        self.assertEqual(status["mint_id"], "pinned-mint")
        self.assertEqual(last["mint_id"], status["mint_id"])
        self.assertEqual(last["port"], status["port"])
        for field in ("mint_id", "port"):
            self.assertIn("status line", status["last_start_sources"][field])
            self.assertIn("disagreement",
                          status["last_start_sources"][field])
        self.assertIn("some-other-mint",
                      status["last_start_sources"]["mint_id"])


# ======================================================================
# ROUND 6 -- the row a recovered payment leaves, on the wire
# ======================================================================
class TestARecoveredPaymentOnTheWire(RealMintCase):
    """Real mint, real walletops, real HTTP: the fields an operator reads.

    The component tests drive this too, but the wire is where it is read
    and where a relay can quietly blank a field the component filled in.
    """

    mint_id = "recovered-mint"

    def strand_a_payment(self, name, amount_mc=5000, to="bob"):
        """Interrupt a payment the way the transport interrupts one.

        The exchange goes out, the MINT COMMITS IT, and the response is
        dropped: §5.1's crash-in-flight. walletops.pay() raises without
        returning a single string, the op is left `planned`, and
        POST /api/wallet/recover settles it against the ledger into a
        committed `pay` that handed nothing to anybody.

        Driven against the wallet FILE the server manages, because there
        is no way to make a socket die mid-request from the client side
        of this API -- and it is the same file the routes below read.
        """
        from aicash.wallet import MintClient
        walletops = sys.modules["walletops"]

        class DropTheAnswer(MintClient):
            def _transport(self, method, path, body, extra_headers=None):
                out = super()._transport(method, path, body, extra_headers)
                if path == "/v3/exchange":
                    raise OSError("simulated response loss after delivery")
                return out

        path = os.path.join(self.workdir, "wallets", name + ".db")
        base = "http://127.0.0.1:%d" % self.mint_port
        ops = walletops.WalletOps(path, base)
        try:
            ops._open()
            ops._wallet.client = DropTheAnswer(base)
            with self.assertRaises(walletops.WalletOpsError) as cm:
                ops.pay(amount_mc, to=to)
            self.assertEqual(cm.exception.cause, "mint_unreachable")
        finally:
            ops.close()

    def test_the_wire_says_what_the_record_knows(self):
        self.ok(self.post("/api/wallet/create", {"name": "alice"}), "create")
        issued = self.ok(self.post("/api/mint/issue",
                                   {"amount_mc": 50000, "count": 1}), "issue")
        self.ok(self.post("/api/wallet/receive",
                          {"name": "alice", "tokens": issued["tokens"]}),
                "fund")
        before = self.ok(self.get("/api/wallet/summary?name=alice"),
                         "summary")["balance_mc"]

        self.strand_a_payment("alice", 5000, to="bob")
        summary = self.ok(self.post("/api/wallet/recover", {"name": "alice"}),
                          "recover")
        self.assertEqual(summary["result"]["ops_confirmed"], 1)

        rows = self.ok(self.get("/api/wallet/history?name=alice"),
                       "history")["history"]
        pays = [r for r in rows if r["kind"] == "pay"]
        self.assertEqual(len(pays), 1, rows)
        row = pays[0]
        # Every closed field carries a value from its set, and neither of
        # the two this round gave a word to is blank.
        self.assertIn(row["recipient_kind"],
                      gui_app.RECIPIENT_KINDS + (gui_app.NOT_APPLICABLE,))
        self.assertIn(row["delivery_attempt"],
                      gui_app.DELIVERY_ATTEMPTS + (gui_app.NOT_APPLICABLE,))
        self.assertNotEqual(row["recipient_kind"], "")
        self.assertNotEqual(row["delivery_attempt"], "")
        # ...and they say what the product actually knows
        self.assertEqual(row["recipient"], "bob")
        self.assertEqual(row["recipient_kind"], "wallet")
        self.assertEqual(row["delivery"], "undelivered")
        self.assertEqual(row["delivery_attempt"], "not_attempted")
        self.assertIn("nothing was handed over", row["detail"])

        # The value is in the balance, not in anybody else's hands, and
        # the two panels say the same thing about the same op_id.
        out = self.ok(self.get("/api/wallet/outstanding?name=alice"),
                      "outstanding")
        self.assertEqual(out["payments"], [])
        self.assertEqual(out["recovered_mc"], 5000)
        recovered = [r for r in out["recovered_ops"]
                     if r["op_id"] == row["op_id"]]
        self.assertEqual(len(recovered), 1)
        for field in ("recipient", "recipient_kind", "delivery",
                      "delivery_cause", "delivery_attempt"):
            self.assertEqual(recovered[0][field], row[field], field)
        after = self.ok(self.get("/api/wallet/summary?name=alice"),
                        "summary after")["balance_mc"]
        # the burn is real -- the mint committed the exchange -- and the
        # rest of the payment came back into the spendable balance
        self.assertLess(before - after, 5000)

    def test_the_wire_names_a_stranded_payment_before_recover_runs(self):
        """THE ROW AN OPERATOR ACTUALLY STARES AT DURING AN OUTAGE.

        Every other test in this class reads the row AFTER
        POST /api/wallet/recover has turned the stranded op into a
        committed payment.  That is the easy half.  The hours before
        recover() can run -- with the mint down, which is exactly when a
        payment gets stranded -- are when the operator has to decide
        whether to send it again, and that decision needs the name.

        It was on disk the whole time, in this module's own intent table,
        and the wire said ``recipient: ""`` until recover() ran.
        """
        self.ok(self.post("/api/wallet/create", {"name": "carl"}), "create")
        issued = self.ok(self.post("/api/mint/issue",
                                   {"amount_mc": 50000, "count": 1}), "issue")
        self.ok(self.post("/api/wallet/receive",
                          {"name": "carl", "tokens": issued["tokens"]}),
                "fund")
        self.strand_a_payment("carl", 5000, to="dana")

        rows = self.ok(self.get("/api/wallet/history?name=carl"),
                       "history")["history"]
        pending = [r for r in rows if r["kind"] == "pay_pending"]
        self.assertEqual(len(pending), 1, rows)
        row = pending[0]
        # WHO IT WAS FOR -- known, durable, and now printed.
        self.assertEqual(row["recipient"], "dana")
        self.assertEqual(row["recipient_kind"], "wallet")
        self.assertNotEqual(row["recipient_kind"], gui_app.NOT_APPLICABLE)
        self.assertIn(row["recipient_kind"], gui_app.RECIPIENT_KINDS)
        self.assertIn("meant for dana", row["detail"])
        # ...and NOT a claim that anything was delivered: no money moved,
        # so all three delivery fields say the question does not arise.
        self.assertEqual(row["delivery"], gui_app.NOT_APPLICABLE)
        self.assertEqual(row["delivery_cause"], gui_app.NOT_APPLICABLE)
        self.assertEqual(row["delivery_attempt"], gui_app.NOT_APPLICABLE)
        self.assertIn("no value left the wallet", row["detail"])

        # AND THE SAME ANSWER AFTERWARDS.  One durable fact, one op_id:
        # the product must not forget a name and then remember it.
        self.ok(self.post("/api/wallet/recover", {"name": "carl"}), "recover")
        after = [r for r in self.ok(
            self.get("/api/wallet/history?name=carl"), "history again"
        )["history"] if r["op_id"] == row["op_id"]]
        self.assertEqual(len(after), 1)
        self.assertEqual(after[0]["kind"], "pay")
        self.assertEqual((after[0]["recipient"], after[0]["recipient_kind"]),
                         (row["recipient"], row["recipient_kind"]))

    def test_the_receive_route_does_not_rewrite_a_bearer_payment(self):
        """THE FLOW gui/README.md DOCUMENTS, END TO END OVER HTTP.

        Pay with no ``to``, paste the strings into another wallet, and let
        POST /api/wallet/receive route the observation back to the payer's
        record -- the walkthrough the README ships.  That route always
        knows the name of the wallet it credited, so it always passes one,
        and the payer's row used to come back claiming the operator had
        named that wallet (``recipient_kind: "wallet"``) and that the
        paying wallet had attempted a delivery (``attempted``).  Neither
        happened.  Both values are inside their closed sets, which is why
        a membership sweep could not see it.
        """
        for name in ("erin", "frank"):
            self.ok(self.post("/api/wallet/create", {"name": name}), "create")
        issued = self.ok(self.post("/api/mint/issue",
                                   {"amount_mc": 50000, "count": 1}), "issue")
        self.ok(self.post("/api/wallet/receive",
                          {"name": "erin", "tokens": issued["tokens"]}),
                "fund")
        paid = self.ok(self.post("/api/wallet/pay",
                                 {"name": "erin", "amount_mc": 5000}), "pay")
        self.assertEqual(paid["recipient_kind"], "bearer")
        self.assertEqual(paid["recipient"], "")
        got = self.ok(self.post("/api/wallet/receive",
                                {"name": "frank", "tokens": paid["tokens"],
                                 "payer": "erin", "op_id": paid["op_id"]}),
                      "receive")
        self.assertTrue(got["recorded"]["recorded"], got["recorded"])
        self.assertEqual(got["recorded"]["delivery"], "delivered")

        rows = [r for r in self.ok(self.get("/api/wallet/history?name=erin"),
                                   "history")["history"]
                if r["op_id"] == paid["op_id"]]
        self.assertEqual(len(rows), 1, rows)
        row = rows[0]
        self.assertEqual(row["delivery"], "delivered")      # the new fact
        self.assertEqual(row["recipient_kind"], "bearer")   # the old ones
        self.assertEqual(row["recipient"], "")
        self.assertEqual(row["delivery_attempt"], "not_attempted")
        # ...and the wallet that took the strings is still said out loud
        self.assertIn("frank", row["detail"])


# The pointer a recovery panel makes at the History table under it.
# MEASURED DEFECT, against a live app.py and page.html's real JavaScript:
# `recovered_ops` is a WHOLE-WALLET figure and the History table asks
# limit=50, so on a wallet with 50 operations newer than the recovery the
# panel said "It is marked recovered in the History table." over a table of
# 50 rows containing no such row -- 69 rows, op 2442f039 in recovered_ops,
# `/recovered/` false over the whole rendered table. The product had the
# op id in hand and sent the operator to look for a row instead.
PAGE_POINTER_HARNESS = r'''/* usage: node pointer.js <page.html> */
"use strict";
const fs = require("fs");
function el(id) {
  return {id: id, textContent: "", innerHTML: "", value: "", disabled: false,
    hidden: false, className: "", open: false, dataset: {}, style: {},
    listeners: {}, addEventListener() {}, querySelectorAll() { return []; }};
}
const nodes = new Map();
globalThis.document = {getElementById(id) {
  if (!nodes.has(id)) nodes.set(id, el(id));
  return nodes.get(id); }};
globalThis.window = {}; globalThis.navigator = {};
globalThis.localStorage = {getItem: () => null, setItem() {}};
globalThis.setInterval = () => 0;
globalThis.fetch = async () => ({ok: false, status: 599,
  json: async () => ({error: {reason: "not_found", detail: "x"}})});
const html = fs.readFileSync(process.argv[2], "utf8");
new Function(html.match(/<script>\n([\s\S]*)<\/script>/)[1])();
const one = {state: "known", recovered_mc: 6000,
             recovered_ops: [{op_id: "aaaa1111", amount_mc: 6000}]};
const two = {state: "known", recovered_mc: 9000,
             recovered_ops: [{op_id: "aaaa1111", amount_mc: 6000},
                             {op_id: "bbbb2222", amount_mc: 3000}]};
const none = {state: "known", recovered_mc: 6000, recovered_ops: []};
const S = (...ids) => new Set(ids);
console.log(JSON.stringify({
  one_in:      window.recoveredClause(one, "alice", S("aaaa1111")),
  one_out:     window.recoveredClause(one, "alice", S("zzzz")),
  two_in:      window.recoveredClause(two, "alice", S("aaaa1111", "bbbb2222")),
  two_partial: window.recoveredClause(two, "alice", S("aaaa1111")),
  two_out:     window.recoveredClause(two, "alice", S()),
  unread:      window.recoveredClause(one, "alice", null),
  unnamed:     window.recoveredClause(none, "alice", S())}));
process.exit(0);
'''


class TestTheRecoveryPanelDoesNotPointAtARowThatIsNotThere(unittest.TestCase):
    """A pointer at the History table is a claim, and it can be false.

    The panel and the table are two windows chosen on different rules --
    whole-wallet against newest-50 -- so "wider" is not "contains". The
    sentence is now made only for the ops the table is actually showing;
    the ones it is not showing are named by op id, which is the thing an
    operator can search the wallet's own record on.
    """

    @classmethod
    def setUpClass(cls):
        if not NODE:
            raise unittest.SkipTest(
                "node is not installed; page.html's JavaScript cannot be "
                "executed here. The server tests still run.")
        cls.tmp = tempfile.mkdtemp(prefix="guipointer-")
        harness = os.path.join(cls.tmp, "pointer.js")
        with io.open(harness, "w", encoding="utf-8") as handle:
            handle.write(PAGE_POINTER_HARNESS)
        page = os.path.join(REPO, "gui", "page.html")
        proc = subprocess.run([NODE, harness, page],
                              capture_output=True, text=True, timeout=120)
        if proc.returncode != 0:
            raise AssertionError("page.html would not run:\n" + proc.stderr)
        cls.out = json.loads(proc.stdout)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(getattr(cls, "tmp", ""), ignore_errors=True)

    def test_the_ordinary_case_still_points_at_the_table(self):
        """The row IS there, so saying so is true -- and stays word for word.

        gui/README.md quotes this sentence verbatim; a reworded version
        would leave the manual quoting something the product never says.
        """
        self.assertTrue(
            self.out["one_in"].endswith(
                " It is marked recovered in the History table."),
            self.out["one_in"])
        self.assertTrue(
            self.out["two_in"].endswith(
                " Each one is marked recovered in the History table."),
            self.out["two_in"])

    def test_an_op_outside_the_window_is_not_claimed_to_be_in_it(self):
        """The defect, pinned: no pointer at a row the table is not showing."""
        for key in ("one_out", "two_out"):
            said = self.out[key]
            self.assertNotIn("marked recovered in the History table", said)
            self.assertIn("NOT in the History table below", said)
            self.assertIn("newest 50 operations only", said)

    def test_the_op_id_is_printed_instead_of_the_missing_pointer(self):
        """Having the answer and not printing it is the whole defect class."""
        self.assertIn("aaaa1111", self.out["one_out"])
        for op in ("aaaa1111", "bbbb2222"):
            self.assertIn(op, self.out["two_out"])

    def test_a_partly_visible_set_names_only_the_ones_that_are_missing(self):
        """Neither half of a mixed answer may be spoken for by the other."""
        said = self.out["two_partial"]
        self.assertIn("bbbb2222", said)
        self.assertNotIn("aaaa1111", said)
        self.assertIn("NO row in the History table below", said)
        self.assertIn("The rest are marked recovered in the table.", said)

    def test_rows_that_were_never_read_are_not_spoken_for_either(self):
        """`shown` is null when this page has not read the rows in this pass.

        Absent rows and rows known to be absent are different findings, and
        the weaker one must not borrow the stronger one's sentence.
        """
        said = self.out["unread"]
        self.assertIn("have not been read in this pass", said)
        self.assertNotIn("marked recovered in the History table", said)
        self.assertNotIn("NOT in the History table below", said)

    def test_a_server_that_named_no_operation_is_unchanged(self):
        """The pre-existing branch keeps its own sentence."""
        self.assertIn("names no operation", self.out["unnamed"])


# ======================================================================
# ONE FRAMING RULE, FOR EVERY SERVER IN THIS REPOSITORY
#
# The history this section exists because of: a request-framing defect was
# reported against the mint by an outside reviewer, fixed there, found to
# have been fixed for ONE SPELLING of one header name, and fixed again
# properly -- and then an independent verifier pointed the same
# twenty-five spellings at THIS server, which nobody had swept, and found
# nineteen of them still working on every POST route and all twenty-five
# on every GET route. The GET routes were worse than the POST ones because
# they had no guard of any kind: a GET carrying a declared Content-Length
# and a body was answered, its body was never read, and the octets left
# behind were framed as the NEXT request line -- two responses out of one
# request, on a socket this server then went on reusing.
#
# What closed it is not a third copy of the fix. gui/app.py imports
# aicash.mintapi.framing_verdict, the single rule every server in this
# repository asks, and applies it to every request of every method before
# any route runs. These tests drive raw sockets because a phantom response
# is invisible to http.client: the library reads one response and hands
# back the first one, and the whole defect is what is on the wire after
# it.
# ======================================================================
#: A whole, valid request, sent as the BODY of the request above it. If
#: this server leaves it on the wire, a keep-alive peer or a pipelining
#: proxy frames it as the next request line and this server answers it --
#: which is the entire defect, and the only way to see it is to count what
#: comes back off a raw socket. It asks for a route no target below asks
#: for, so its answer is unmistakable if it ever appears.
SMUGGLED = b"GET /api/mint/logs HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"

#: What the fake MintControl's log route says, and nothing else does.
SMUGGLED_MARK = b"mint line 0"

FRAMING_SPELLINGS = tuple(
    line % {"n": len(SMUGGLED)} for line in (
        # The transfer coding, spelled every way a hop rewrites a name.
        "Transfer-Encoding: chunked",
        "transfer-encoding: chunked",
        "TRANSFER-ENCODING: chunked",
        "Transfer_Encoding: chunked",
        "Transfer.Encoding: chunked",
        "TransferEncoding: chunked",
        "Transfer--Encoding: chunked",
        "Transfer__Encoding: chunked",
        "Transfer0Encoding: chunked",
        "Transfer|Encoding: chunked",
        "Transfer-Encoding : chunked",        # space before the colon
        "Transfer-Encoding\t: chunked",       # tab before the colon
        "transfer-encoding: CHUNKED",
        "Transfer-Encoding: CHUNKED, identity",
        # The length, spelled every way two parties compute differently.
        "Content-Length: 5\r\nContent-Length: %(n)d",   # the CL.CL pair
        "Content-Length: +%(n)d",             # int() takes a sign, HTTP does not
        "Content-Length: %(n)d_0",            # PEP 515, not 1*DIGIT
        "Content-Length:  %(n)d ",            # surrounding OWS int() eats
        "Content-Length: %(n)d\x0b",          # Python whitespace, not HTTP's
        "Content-Length: 0%(n)d",             # a leading zero
        "Content_Length: %(n)d",
        "Content.Length: %(n)d",
        "ContentLength: %(n)d",
        "Content-Length : %(n)d",             # space before the colon
        "Content-Length: %(n)d, 5",           # a list, not a number
    )
)


def framing_verdict_for(spelling, cookie, body_expected):
    """What the SHARED rule says about the header block a test just sent.

    Tests assert this server's wire behaviour against the rule's verdict
    rather than against a list of spellings the test author thinks are
    bad. A list of bad spellings is what was wrong the last two times; a
    test carrying its own copy of one would be the same mistake in the
    test file.
    """
    block = ("Host: 127.0.0.1\r\nCookie: %s\r\n"
             "Content-Type: application/json\r\n%s\r\n\r\n"
             % (cookie, spelling))
    parsed = email.parser.Parser().parsestr(block, headersonly=True)
    return gui_app.framing_verdict(parsed, body_expected=body_expected)


def code_only(path):
    """A Python file with its comments and docstrings removed.

    So a test about what the CODE does is not answered by prose. This
    file's own explanation of the defect necessarily quotes the
    expression the defect was made of, and a naive substring search over
    the whole source finds the explanation and calls it a relapse.
    """
    with open(path, "rb") as handle:
        tokens = list(tokenize.tokenize(handle.readline))
    kept = []
    statement_start = True
    for tok in tokens:
        if tok.type == tokenize.COMMENT:
            continue
        if tok.type in (tokenize.NL, tokenize.NEWLINE, tokenize.INDENT,
                        tokenize.DEDENT, tokenize.ENCODING):
            if tok.type in (tokenize.NEWLINE, tokenize.NL):
                statement_start = True
            continue
        if tok.type == tokenize.STRING and statement_start:
            continue                      # a docstring, or a bare string
        statement_start = False
        kept.append(tok.string)
    return " ".join(kept)


def framing_header_lookups(path):
    """Every place a file ASKS a header block for a framing header name.

    An ``ast`` walk rather than a substring search, because the one thing
    that must not come back is a lookup -- ``headers.get("X")`` or
    ``headers["X"]`` -- while WRITING a Content-Length onto a response is
    exactly what a correct server does. The name is folded before it is
    compared, so a lookup that comes back wearing an underscore or no
    separator at all is found too.
    """
    with open(path, encoding="utf-8") as handle:
        tree = ast.parse(handle.read())

    def mentions_headers(node):
        return "headers" in ast.dump(node)

    def is_framing_name(node):
        if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
            return False
        folded = re.sub(r"[^a-z0-9]+", "", node.value.lower())
        return folded in ("contentlength", "transferencoding")

    found = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in ("get", "get_all", "__getitem__")
                and mentions_headers(node.func.value)):
            for arg in node.args:
                if is_framing_name(arg):
                    found.append((node.lineno, arg.value))
        if isinstance(node, ast.Subscript) and mentions_headers(node.value):
            if is_framing_name(node.slice):
                found.append((node.lineno, node.slice.value))
    return found


def raw_exchange(port, payload, wait=8.0):
    """Send bytes, read until the server hangs up or stops talking.

    Returns ``(data, closed)``: everything that came back, and whether the
    server closed the connection itself. Both halves matter -- a phantom
    response is extra DATA, and a connection kept open after a request
    this server refused to frame is the socket the next one arrives on.
    """
    sock = socket.create_connection(("127.0.0.1", port), timeout=wait)
    try:
        sock.sendall(payload)
        sock.settimeout(wait)
        data = b""
        closed = False
        deadline = time.monotonic() + wait
        while time.monotonic() < deadline:
            try:
                chunk = sock.recv(65536)
            except (socket.timeout, TimeoutError):
                break
            if not chunk:
                closed = True
                break
            data += chunk
        return data, closed
    finally:
        sock.close()


def split_all_responses(raw, head_request=False):
    """Split a socket dump into complete responses, BY THEIR OWN FRAMING.

    Returns ``(responses, trailing)``. Anything that is not a status line
    where a status line must be is not a response: it is the trailing
    octets this round exists to make impossible, and it comes back in
    ``trailing`` rather than being counted as an answer. That is what
    caught the other half of this round's work -- a JSON error body
    written with no status line and no headers, appended straight past the
    previous response's declared Content-Length.
    """
    responses = []
    rest = raw
    while rest:
        if not rest.startswith(b"HTTP/1."):
            break
        head, sep, body = rest.partition(b"\r\n\r\n")
        if not sep:
            break
        length = None
        for line in head.split(b"\r\n")[1:]:
            name, _, value = line.partition(b":")
            if name.strip().lower() == b"content-length":
                try:
                    length = int(value.strip())
                except ValueError:                       # pragma: no cover
                    length = None
        if head_request:
            length = 0
        if length is None or len(body) < length:
            responses.append(rest)
            rest = b""
            break
        responses.append(head + sep + body[:length])
        rest = body[length:]
    return responses, rest


def complete_responses(raw, head_request=False):
    """How many responses on the wire are FULLY framed, not merely begun.

    split_all_responses above counts a response whose body is shorter than
    its own Content-Length as a response, because its job is to report
    what arrived. This one is stricter on purpose: it is what the watching
    helper below polls on, and a half-arrived response must not stop the
    read early.
    """
    seen = 0
    rest = raw
    while rest.startswith(b"HTTP/1."):
        head, sep, body = rest.partition(b"\r\n\r\n")
        if not sep:
            break
        length = None
        for line in head.split(b"\r\n")[1:]:
            name, _, value = line.partition(b":")
            if name.strip().lower() == b"content-length":
                try:
                    length = int(value.strip())
                except ValueError:                       # pragma: no cover
                    length = None
        if head_request:
            length = 0
        if length is None or len(body) < length:
            break
        seen += 1
        rest = body[length:]
    return seen


def exchange_and_watch(port, payload, expect=1, wait=8.0, linger=1.0,
                       head_request=False, half_close=False):
    """Send bytes, read until ``expect`` responses are COMPLETE, then watch.

    Returns ``(responses, trailing, closed, data)`` like raw_exchange +
    split_all_responses, but it does not spend the whole timeout on every
    cell: the answers are read as fast as they arrive and the socket is
    then watched for ``linger`` seconds more, which is what distinguishes
    "this server kept the connection" from "this server had not hung up
    yet". A test that asserts a socket LIVES has to wait for something
    that never happens, so waiting less, deliberately, is the difference
    between a four-cell sweep that costs one second and one that costs
    half a minute.
    """
    sock = socket.create_connection(("127.0.0.1", port), timeout=wait)
    try:
        sock.sendall(payload)
        if half_close:
            # "I have finished sending." The only way to produce a body
            # that stops short of its declared length without waiting out
            # the server's body-read timeout: the read returns what it has
            # instead of blocking for octets that are never coming.
            sock.shutdown(socket.SHUT_WR)
        data = b""
        closed = False
        deadline = time.monotonic() + wait
        while complete_responses(data, head_request) < expect:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                chunk = sock.recv(65536)
            except (socket.timeout, TimeoutError):
                break
            if not chunk:
                closed = True
                break
            data += chunk
        end = time.monotonic() + linger
        while not closed and time.monotonic() < end:
            sock.settimeout(max(0.01, end - time.monotonic()))
            try:
                chunk = sock.recv(65536)
            except (socket.timeout, TimeoutError):
                break
            if not chunk:
                closed = True
                break
            data += chunk
        responses, trailing = split_all_responses(data, head_request)
        return responses, trailing, closed, data
    finally:
        sock.close()


class TestFramingIsOneSharedRule(ServerCase):
    """Twenty-five spellings, every method, every route, one rule."""

    # Method, path, and whether a body is a smuggled request or filler.
    TARGETS = (
        ("GET", "/"),
        ("GET", "/api/mint/status"),
        ("GET", "/api/wallet/list"),
        ("HEAD", "/"),
        ("POST", "/api/wallet/create"),
        ("POST", "/api/mint/issue"),
        ("OPTIONS", "/api/mint/status"),
        ("PUT", "/api/wallet/pay"),
        ("DELETE", "/api/wallet/list"),
    )

    def build(self, method, path, spelling):
        return ("%s %s HTTP/1.1\r\n"
                "Host: 127.0.0.1\r\n"
                "Cookie: %s\r\n"
                "Content-Type: application/json\r\n"
                "%s\r\n\r\n" % (method, path, self.cookie, spelling)
                ).encode() + SMUGGLED

    def test_the_framing_rule_is_imported_and_not_copied_here(self):
        """A local copy is how this defect survived three fixes.

        The rule lives in one module and every server in this repository
        asks that module. If somebody ever "restores" a private copy to
        gui/app.py -- the duplication note in the console's docstring was
        written about the AUTHENTICATION design and does not cover
        framing -- this fails before any of the wire tests do.
        """
        self.assertEqual(gui_app.framing_verdict.__module__, "aicash.mintapi")
        # Comments and docstrings stripped: the explanation of this defect
        # has to quote the expression the defect was made of.
        path = os.path.join(REPO, "gui", "app.py")
        code = code_only(path)
        self.assertNotIn("def framing_verdict", code,
                         "gui/app.py has grown its own copy of the rule")
        self.assertNotIn("_FRAMING_CONFUSABLE", code)
        # THE ONE QUESTION THE RULE EXISTS TO STOP ANYBODY ASKING: is this
        # header spelled thus? It is not the question this server needs an
        # answer to, and asking it is what left nineteen spellings working.
        # Writing a Content-Length onto a RESPONSE is a different act and
        # is not what this looks for; see framing_header_lookups.
        self.assertEqual(
            framing_header_lookups(path), [],
            "gui/app.py asks a header block for a framing header by name "
            "again -- that question has been wrong twice")
        # The check has to be able to fail, so prove it on a file that
        # really does ask.
        probe = os.path.join(self.workdir, "asks.py")
        with open(probe, "w", encoding="utf-8") as handle:
            handle.write("def f(self):\n"
                         "    return self.headers.get('Transfer_Encoding')\n")
        self.assertEqual([name for _line, name in framing_header_lookups(probe)],
                         ["Transfer_Encoding"])

    def test_no_spelling_on_any_method_leaves_a_phantom_response(self):
        """The verifier's sweep, run against every route of every method.

        One request in, exactly one response out, and nothing on the wire
        after it. Before the shared rule was applied here this failed 142
        times across these nine targets.
        """
        for method, path in self.TARGETS:
            for spelling in FRAMING_SPELLINGS:
                with self.subTest(method=method, path=path,
                                  spelling=spelling):
                    data, closed = raw_exchange(
                        self.port, self.build(method, path, spelling))
                    responses, trailing = split_all_responses(
                        data, head_request=(method == "HEAD"))
                    self.assertEqual(
                        len(responses), 1,
                        "%d responses for one request: %r"
                        % (len(responses), data[:400]))
                    self.assertEqual(
                        trailing, b"",
                        "octets after the response: %r" % trailing[:200])
                    self.assertNotIn(
                        SMUGGLED_MARK, data,
                        "the smuggled request in the body was answered")
                    verdict = framing_verdict_for(
                        spelling, self.cookie, method == "POST")
                    if verdict.must_close:
                        self.assertTrue(
                            closed,
                            "the rule said close and the socket stayed up: "
                            "%r" % (verdict,))
                    if not verdict.framed:
                        status, _headers, body = split_response(responses[0])
                        self.assertEqual(status, 400)
                        if method != "HEAD":   # a HEAD answer carries no body
                            self.assertEqual(
                                json.loads(body)["error"]["reason"],
                                "unframable_request")

    def test_a_get_that_declares_a_body_does_not_answer_what_is_in_it(self):
        """The headline finding, on its own, in the plainest form.

        A GET for the page, carrying a Content-Length and a whole second
        request as its body. It used to return the page and then answer
        the smuggled request out of the body, leaving two responses and
        hundreds of bytes on one socket.
        """
        payload = ("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                   "Cookie: %s\r\n"
                   "Content-Length: %d\r\n\r\n"
                   % (self.cookie, len(SMUGGLED))).encode() + SMUGGLED
        data, closed = raw_exchange(self.port, payload)
        responses, trailing = split_all_responses(data)
        self.assertEqual(len(responses), 1, "the smuggled request was answered")
        self.assertEqual(trailing, b"")
        self.assertTrue(closed)
        self.assertIn(b"<!doctype html", responses[0].lower())
        self.assertNotIn(SMUGGLED_MARK, data)
        # And it SAYS it is closing, rather than hanging up silently on a
        # peer that just read a complete Content-Length and is entitled to
        # send another request.
        status, headers, _body = split_response(responses[0])
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("connection"), "close")

    def test_the_refusal_names_a_reason_from_the_shared_set(self):
        """This server's envelope, the shared rule's machine reason.

        The verdict carries no status code and no error shape -- its four
        callers use three different vocabularies -- so the 400 and the
        sentence are this file's. The slug is not, and a slug this server
        prints that the rule does not define would mean the two have
        drifted.
        """
        seen = set()
        for spelling in FRAMING_SPELLINGS:
            verdict = framing_verdict_for(spelling, self.cookie, True)
            data, _closed = raw_exchange(
                self.port, self.build("POST", "/api/wallet/create", spelling))
            responses, trailing = split_all_responses(data)
            self.assertEqual(trailing, b"")
            self.assertEqual(len(responses), 1)
            status, _headers, body = split_response(responses[0])
            obj = json.loads(body)
            if verdict.framed:
                # The rule framed it, so this server read the body and
                # refused it on its CONTENT, not on its framing. Nothing
                # here is entitled to an opinion about that.
                self.assertNotEqual(obj["error"]["reason"],
                                    "unframable_request", spelling)
                continue
            self.assertEqual(status, 400, spelling)
            self.assertEqual(obj["error"]["reason"], "unframable_request")
            self.assertIn(obj["error"]["cause"], gui_app.CAUSES)
            slug = obj["error"]["detail"].rsplit("(framing: ", 1)[1].rstrip(")")
            self.assertEqual(slug, verdict.reason, spelling)
            seen.add(slug)
        self.assertGreaterEqual(len(seen), 3, "the sweep proved almost nothing")
        self.assertTrue(
            seen <= set(gui_app.FRAMING_REASONS),
            "reasons this server prints that the shared rule does not "
            "define: %s" % sorted(seen - set(gui_app.FRAMING_REASONS)))

    def test_the_gui_and_the_mint_decide_identical_bytes_identically(self):
        """One socket, one rule: the verdict, and what this server did.

        Every spelling above is put through the shared rule directly and
        through this server's wire behaviour, and the two must agree. This
        is the property the round is for -- not "the GUI is fixed" but
        "the GUI has no framing opinion of its own to be wrong about".
        """
        for method, path in (("GET", "/api/mint/status"),
                             ("POST", "/api/wallet/create")):
            for spelling in FRAMING_SPELLINGS:
                with self.subTest(method=method, spelling=spelling):
                    verdict = framing_verdict_for(
                        spelling, self.cookie, method == "POST")
                    data, closed = raw_exchange(
                        self.port, self.build(method, path, spelling))
                    responses, trailing = split_all_responses(data)
                    self.assertEqual(trailing, b"")
                    self.assertEqual(len(responses), 1)
                    status, headers, body = split_response(responses[0])
                    if not verdict.framed:
                        self.assertEqual(status, 400)
                        self.assertEqual(json.loads(body)["error"]["reason"],
                                         "unframable_request")
                        self.assertEqual(
                            headers.get("connection"), "close",
                            "an unframable request answered without saying "
                            "the connection is going")
                    else:
                        # Framed: refused on its CONTENT if at all, never on
                        # its framing. This server has no second opinion.
                        if status >= 400:
                            self.assertNotEqual(
                                json.loads(body)["error"]["reason"],
                                "unframable_request")
                    # must_close is the RULE's decision, not this server's.
                    if verdict.must_close:
                        self.assertTrue(
                            closed,
                            "the rule said close and the socket stayed up: "
                            "%r" % (verdict,))

    def test_a_well_framed_request_still_keeps_its_connection(self):
        """The fix must not be "close everything", on GET or on POST.

        A page poll every four seconds over one socket is the reason this
        server speaks HTTP/1.1 at all.
        """
        payload = (
            "GET /api/mint/status HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            "Cookie: %s\r\n\r\n"
            "POST /api/wallet/create HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            "Cookie: %s\r\nContent-Type: application/json\r\n"
            "Content-Length: 17\r\n\r\n{\"name\": \"carol\"}"
            "GET /api/mint/status HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            "Cookie: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            % (self.cookie, self.cookie, self.cookie)).encode()
        data, closed = raw_exchange(self.port, payload)
        responses, trailing = split_all_responses(data)
        self.assertEqual(trailing, b"")
        self.assertEqual(len(responses), 3,
                         "three pipelined requests, %d answers: %r"
                         % (len(responses), data[:300]))
        for response in responses:
            status, _headers, _body = split_response(response)
            self.assertEqual(status, 200)
        self.assertTrue(closed)

    def test_a_body_that_stops_short_of_its_length_is_not_used(self):
        """A truncated body is a desynchronised stream, not a short call."""
        payload = ("POST /api/wallet/create HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                   "Cookie: %s\r\nContent-Type: application/json\r\n"
                   "Content-Length: 400\r\n\r\n{\"name\": \"dave\"}"
                   % self.cookie).encode()
        old = gui_app.Handler.timeout
        gui_app.Handler.timeout = 2
        try:
            data, closed = raw_exchange(self.port, payload, wait=12.0)
        finally:
            gui_app.Handler.timeout = old
        responses, trailing = split_all_responses(data)
        self.assertEqual(trailing, b"")
        self.assertEqual(len(responses), 1)
        status, _headers, _body = split_response(responses[0])
        self.assertGreaterEqual(status, 400)
        self.assertTrue(closed)
        self.assertNotIn("dave", [c[1] for c in FakeWalletOps.calls
                                  if c and len(c) > 1])


class TestNoResponseWithoutAStatusLine(ServerCase):
    """A refusal is a response, or it is trailing octets. Nothing between.

    CPython sets ``request_version`` to HTTP/0.9 before it tries to parse a
    request line, and in HTTP/0.9 ``send_response``, ``send_header`` and
    ``end_headers`` are all no-ops. This server's overridden ``send_error``
    then wrote its JSON body raw -- no status line, no headers -- appended
    past the previous response's declared Content-Length on a pipelined
    connection. A client reading by Content-Length is handed a complete
    response and then a tail of bytes that belong to nothing.
    """

    def test_an_unparseable_pipelined_request_line_gets_a_status_line(self):
        payload = (b"GET /api/mint/status HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                   b"Cookie: " + self.cookie.encode() + b"\r\n\r\n"
                   b"\x16\x03\x01garbage\r\n\r\n")
        data, closed = raw_exchange(self.port, payload)
        responses, trailing = split_all_responses(data)
        self.assertEqual(
            trailing, b"",
            "a body with no status line, appended past a Content-Length: %r"
            % trailing[:200])
        self.assertEqual(len(responses), 2,
                         "expected an answer and a refusal, got %d: %r"
                         % (len(responses), data[:300]))
        first_status, _h, _b = split_response(responses[0])
        self.assertEqual(first_status, 200)
        status, headers, body = split_response(responses[1])
        self.assertEqual(status, 400)
        self.assertEqual(headers.get("connection"), "close")
        obj = json.loads(body)
        self.assertIn("error", obj)
        self.assertIn(obj["error"]["cause"], gui_app.CAUSES)
        self.assertTrue(closed)

    def test_an_unparseable_first_request_line_is_also_a_response(self):
        data, closed = raw_exchange(self.port, b"\x16\x03\x01garbage\r\n\r\n")
        responses, trailing = split_all_responses(data)
        self.assertEqual(trailing, b"", "raw bytes with no status line")
        self.assertEqual(len(responses), 1)
        status, _headers, body = split_response(responses[0])
        self.assertEqual(status, 400)
        self.assertIn("error", json.loads(body))
        self.assertTrue(closed)

    def test_an_http_0_9_request_is_refused_in_a_protocol_with_framing(self):
        """The same shape as the send_error defect, one door along.

        A request line with no version on it is HTTP/0.9, where
        send_response, send_header and end_headers are all no-ops -- so
        every answer this server composed for such a request, error
        envelopes included, went out as a naked body with no status line
        and no length. Nothing that speaks to this GUI speaks 0.9.
        """
        for payload in (b"GET /\r\nHost: 127.0.0.1\r\n\r\n",
                        b"GET /api/mint/status\r\n\r\n"):
            with self.subTest(payload=payload):
                data, closed = raw_exchange(self.port, payload)
                responses, trailing = split_all_responses(data)
                self.assertEqual(trailing, b"",
                                 "a naked body with no status line: %r"
                                 % trailing[:120])
                self.assertEqual(len(responses), 1, repr(data[:200]))
                status, headers, body = split_response(responses[0])
                self.assertEqual(status, 400)
                self.assertIn("content-length", headers)
                self.assertIn("error", json.loads(body))
                self.assertTrue(closed)

    def test_a_refusal_does_not_echo_a_kilobyte_of_the_request_line(self):
        """The base class quotes the request line; a request line is 64 KiB."""
        payload = b"GET /" + b"A" * 20000 + b" NOTHTTP\r\n\r\n"
        data, _closed = raw_exchange(self.port, payload)
        responses, trailing = split_all_responses(data)
        self.assertEqual(trailing, b"")
        self.assertEqual(len(responses), 1)
        _status, _headers, body = split_response(responses[0])
        self.assertLess(len(body), 1024,
                        "the caller's own bytes reflected at length")


class TestNumbersAreBoundedNotJustShaped(ServerCase):
    """A guard that bounds SHAPE and not LENGTH is not a guard.

    ``[+-]?[0-9]+`` accepts five thousand digits, and ``int()`` on five
    thousand digits raises CPython's int/str conversion ValueError -- out
    of the route, onto the blanket handler, and into a 500 whose body
    carried the interpreter's own message and the digit count the caller
    chose. Live on /api/mint/issue for both its numeric fields and on
    /api/mint/start for four of its own.
    """

    HUGE = "9" * 5000

    def setUp(self):
        super().setUp()
        # The fake controller is per CLASS, so its record of what it was
        # asked to do outlives one test. These tests are about what did
        # NOT happen, so they start from an empty record.
        self.control.started = []
        self.control.stopped = []

    def test_a_five_thousand_digit_number_is_a_sentence_not_a_500(self):
        cases = (
            ("/api/mint/issue", {"amount_mc": self.HUGE, "count": 1}),
            ("/api/mint/issue", {"amount_mc": 10, "count": self.HUGE}),
            ("/api/wallet/pay", {"name": "alice", "amount_mc": self.HUGE}),
            ("/api/wallet/quote", {"name": "alice", "amount_mc": self.HUGE}),
            ("/api/mint/stop", {"drain_seconds": self.HUGE}),
        )
        for field in ("port", "rate_ppm", "cap_mc", "exempt_below_mc"):
            body = {"mint_id": "m", "baseline_model_class": "baseline-v1",
                    "port": 9999, "rate_ppm": 0, "cap_mc": 0,
                    "exempt_below_mc": 10}
            body[field] = self.HUGE
            cases += (("/api/mint/start", body),)
        for path, body in cases:
            with self.subTest(path=path, body=sorted(body)):
                status, obj, raw = self.call("POST", path, body)
                self.assertEqual(status, 400, raw[:300])
                self.assert_envelope(status, obj, raw)
                self.assertNotIn("digits", obj["error"]["detail"])
                self.assertNotIn("ValueError", obj["error"]["detail"])
        self.assertEqual(self.control.started, [])
        self.assertEqual(self.control.stopped, [])

    def test_a_giant_lines_query_is_refused_rather_than_defaulted(self):
        status, obj, raw = self.call("GET", "/api/mint/logs?lines=" + self.HUGE)
        self.assertEqual(status, 400, raw[:200])
        self.assert_envelope(status, obj, raw)

    def test_a_default_is_for_an_absent_field_not_a_nonsense_one(self):
        """``count: "abc"`` used to issue ONE token instead of saying no.

        On a route that creates money, substituting the route's own
        default for a value the caller actually sent is the wrong way
        round: absent is a request to use the default, nonsense is not.
        """
        for body, why in (({"amount_mc": 10, "count": "abc"}, "count"),
                          ({"amount_mc": 10, "count": True}, "count"),
                          ({"amount_mc": 10, "count": 2.5}, "count")):
            with self.subTest(why=why, body=body):
                status, obj, raw = self.call("POST", "/api/mint/issue", body)
                self.assertEqual(status, 400, raw[:200])
                self.assert_envelope(status, obj, raw)
        status, obj, raw = self.call("POST", "/api/mint/stop",
                                     {"drain_seconds": "abc"})
        self.assertEqual(status, 400, raw[:200])
        self.assertEqual(self.control.stopped, [])
        # ...and an ABSENT field still gets the route's default.
        status, _obj, raw = self.call("POST", "/api/mint/stop", {})
        self.assertEqual(status, 200, raw[:200])
        self.assertEqual(self.control.stopped, [10])

    def test_a_relayed_message_cannot_amplify_what_the_caller_sent(self):
        """A component's sentence may quote the caller; this file bounds it.

        Not the same defect as the blanket handler, and found looking for
        the same shape: a message this server did not compose, relayed
        into a response body at whatever length it arrived.
        """
        FakeWalletOps.fail_with = FakeWalletOpsError(
            "wallet_error", "x" * 40000, "unknown")
        try:
            status, obj, raw = self.call("POST", "/api/wallet/pay",
                                         {"name": "alice", "amount_mc": 5})
        finally:
            FakeWalletOps.fail_with = None
        self.assertEqual(status, 400, raw[:200])
        self.assert_envelope(status, obj, raw)
        self.assertLessEqual(len(obj["error"]["detail"]),
                             gui_app._RELAYED_DETAIL_MAX + 20)
        self.assertIn("truncated", obj["error"]["detail"])

    def test_no_route_puts_an_interpreter_exception_into_a_body(self):
        """The blanket handler is the last place a message can leak.

        Any exception that reaches it is by definition one this server did
        not plan for, so its text is the interpreter's -- and the
        interpreter quotes whatever the caller sent.
        """
        marker = "SECRET-INTERPRETER-TEXT-9134"

        class Boom(Exception):
            pass

        original = gui_app.Api.route_mint_status

        def explode(self, _query, _body):
            raise Boom(marker)

        gui_app.Api.route_mint_status = explode
        noise = io.StringIO()
        saved = sys.stderr
        sys.stderr = noise          # the handler thread prints here
        try:
            status, obj, raw = self.call("GET", "/api/mint/status")
        finally:
            sys.stderr = saved
            gui_app.Api.route_mint_status = original
        self.assertEqual(status, 500)
        self.assert_envelope(status, obj, raw)
        text = raw.decode("utf-8", "replace")
        self.assertNotIn(marker, text, "the exception's text reached the page")
        self.assertNotIn("Boom", text, "the exception's TYPE reached the page")
        self.assertIn("terminal running app.py", obj["error"]["detail"])
        # ...and it is not lost: it goes where the operator can read it.
        self.assertIn(marker, noise.getvalue())
        self.assertIn("Traceback", noise.getvalue())


class TestTheModelClassGoesOnACommandLine(ServerCase):
    """/api/mint/start spawns a mint with this string in its argv.

    It also becomes, under §4.1, the permanent definition of what one
    millicredit means for that mint_id. A five-thousand-character one was
    accepted and really spawned.
    """

    def setUp(self):
        super().setUp()
        self.control.started = []
        self.control.stopped = []

    def start_body(self, baseline):
        return {"mint_id": "bounded-mint", "baseline_model_class": baseline,
                "port": 9911, "rate_ppm": 0, "cap_mc": 0,
                "exempt_below_mc": 10}

    def test_a_five_thousand_character_class_never_reaches_a_subprocess(self):
        status, obj, raw = self.call("POST", "/api/mint/start",
                                     self.start_body("b" * 5000))
        self.assertEqual(status, 400, raw[:200])
        self.assert_envelope(status, obj, raw)
        self.assertEqual(self.control.started, [],
                         "a mint was spawned with a 5,000-character argv")

    def test_control_characters_never_reach_a_command_line(self):
        for baseline in ("base\nline-v1", "base\tline", "base\x00line",
                         "base\rline", "\x1b[2Jbaseline"):
            with self.subTest(baseline=baseline):
                status, obj, raw = self.call("POST", "/api/mint/start",
                                             self.start_body(baseline))
                self.assertEqual(status, 400, raw[:200])
                self.assert_envelope(status, obj, raw)
        self.assertEqual(self.control.started, [])

    def test_the_ordinary_value_still_starts_a_mint(self):
        status, _obj, raw = self.call("POST", "/api/mint/start",
                                      self.start_body("baseline-v1"))
        self.assertEqual(status, 200, raw[:300])
        self.assertEqual([s["baseline_model_class"]
                          for s in self.control.started], ["baseline-v1"])
        longest = "b" * gui_app.BASELINE_MAX
        status, _obj, raw = self.call("POST", "/api/mint/start",
                                      self.start_body(longest))
        self.assertEqual(status, 200, raw[:300])
        self.assertEqual(self.control.started[-1]["baseline_model_class"],
                         longest)


# ======================================================================
# A BODY THIS SERVER CANNOT PARSE IS NOT THIS SERVER FAILING
#
# The reader was wrapped in a handler for ValueError alone. json.loads
# says "no" in more ways than that, and the one it was missing --
# RecursionError, out of the C scanner, on a document nested deep enough
# to blow its stack -- is not a ValueError at all. It escaped to the
# blanket handler in _handle, so every POST route on this server answered
# a 200 KB array of brackets with 500 "internal_error" and printed a
# traceback on the operator's terminal: a malformed request reported as a
# failure of the money server that received it.
#
# The mint (aicash/mintapi.py), the supervision server and the operator
# console widened this exact clause in earlier rounds. Nobody asked
# whether THIS reader had the same gap. These tests are the question,
# asked of every POST route and of every field of the widest body.
#
# Raw sockets, not http.client: half of what is being asserted is what is
# on the wire AFTER the response -- one well-formed answer, nothing
# trailing it, and never no answer at all.
# ======================================================================
#: Deep enough that CPython's C scanner gives up (measured at ~9,997 on
#: this interpreter), small enough to sit well inside MAX_BODY_BYTES: at
#: 40,000 levels this is 80 KB against a 1 MiB cap. That combination is
#: the whole point -- the body is not refused for its size, it is refused
#: for its shape, and the refusal has to be a sentence rather than a
#: crash.
NEST_DEPTH = 40_000


def nested_array(depth: int = NEST_DEPTH) -> bytes:
    return (b"[" * depth) + (b"]" * depth)


#: Every route on this server that reads a body, which is every route
#: that calls _read_body, which is every POST route in ROUTES. Derived
#: from the table rather than typed out, so a POST route added tomorrow
#: is covered by these tests on the day it is added.
POST_ROUTES = tuple(sorted(p for (m, p) in gui_app.ROUTES if m == "POST"))

#: The six fields /api/mint/start reads. A body can be a well-formed JSON
#: object and still carry the hostile document one level down, which is
#: the shape a real caller would send: the sweep that found this counted
#: each field separately for exactly that reason.
MINT_START_FIELDS = ("mint_id", "baseline_model_class", "port",
                     "rate_ppm", "cap_mc", "exempt_below_mc")


class TestADeeplyNestedBodyIsNotAnInternalError(ServerCase):
    """Thirteen cells: eight POST routes, six fields of the widest one.

    EVERY CELL HERE SENDS ``Connection: close``, so none of them can see
    what this server does with the socket -- which is how a round spent on
    framing left a deep body's connection decision unmeasured. That half
    is TestABadBodyDoesNotCostTheConnection below, which sends the same
    document with no Connection header and a valid request pipelined
    behind it.
    """

    def post_raw(self, path, body: bytes, cookie=True):
        """One POST over a raw socket. Returns (responses, trailing, raw)."""
        head = ("POST %s HTTP/1.1\r\n"
                "Host: 127.0.0.1:%d\r\n"
                "Content-Type: application/json\r\n"
                "Content-Length: %d\r\n"
                "Connection: close\r\n" % (path, self.port, len(body)))
        if cookie:
            head += "Cookie: %s\r\n" % self.cookie
        data, _closed = raw_exchange(self.port, head.encode() + b"\r\n" + body,
                                     wait=20.0)
        responses, trailing = split_all_responses(data)
        return responses, trailing, data

    def assert_bad_json_not_internal(self, path, body, note=""):
        responses, trailing, data = self.post_raw(path, body)
        self.assertEqual(len(responses), 1,
                         "%s%s answered %d times, not once: %r"
                         % (path, note, len(responses), data[:300]))
        self.assertEqual(trailing, b"",
                         "%s%s left octets past its own framing: %r"
                         % (path, note, trailing[:200]))
        status, _headers, payload = split_response(responses[0])
        self.assertEqual(
            status, 400,
            "%s%s answered %d, not 400: %r" % (path, note, status,
                                               payload[:300]))
        obj = json.loads(payload)
        self.assert_envelope(status, obj, payload)
        self.assertEqual(obj["error"]["reason"], "bad_json",
                         "%s%s: %r" % (path, note, obj))

    def test_every_post_route_calls_a_deep_body_bad_json(self):
        """The finding itself, on every route that reads a body."""
        self.assertEqual(len(POST_ROUTES), 8, POST_ROUTES)
        for path in POST_ROUTES:
            with self.subTest(path=path):
                self.assert_bad_json_not_internal(path, nested_array())

    def test_every_field_of_mint_start_is_covered_too(self):
        """A well-formed object carrying the document one level down.

        This is the shape a caller actually sends, and it is the one that
        proves the refusal is the READER's and not some route's own
        validation: the route never runs.
        """
        for field in MINT_START_FIELDS:
            with self.subTest(field=field):
                body = (b'{"mint_id": "m", "baseline_model_class": "b", '
                        b'"port": 9911, "rate_ppm": 0, "cap_mc": 0, '
                        b'"exempt_below_mc": 0, "%s": %s}'
                        % (field.encode(), nested_array()))
                self.assert_bad_json_not_internal(
                    "/api/mint/start", body, note=" (field %s)" % field)

    def test_a_nested_object_is_refused_the_same_way(self):
        """Braces, not brackets: the same C scanner, the same stack."""
        depth = NEST_DEPTH
        body = (b'{"a":' * depth) + b"1" + (b"}" * depth)
        self.assert_bad_json_not_internal("/api/wallet/pay", body)

    def test_the_answer_carries_no_interpreter_vocabulary(self):
        """No traceback, no exception name, no parser file path.

        The blanket handler's sentence is not acceptable here either: it
        says something inside this GUI failed, and nothing did.
        """
        _responses, _trailing, data = self.post_raw("/api/wallet/quote",
                                                    nested_array())
        text = data.decode("utf-8", "replace")
        for forbidden in ("Traceback", "RecursionError", "maximum recursion",
                          "json/decoder.py", "scan_once", "internal_error",
                          "Something inside this GUI failed"):
            self.assertNotIn(forbidden, text,
                             "the answer quoted the interpreter: %r" % text[:400])

    def test_nothing_is_printed_on_the_operators_terminal(self):
        """A malformed request is not an incident.

        The blanket handler prints a traceback to stderr on purpose --
        that is where an internal failure belongs. A body that is simply
        bad JSON must not produce one, or the terminal fills with stack
        traces every time somebody fat-fingers a paste.
        """
        noise = io.StringIO()
        saved = sys.stderr
        sys.stderr = noise              # the handler thread prints here
        try:
            self.post_raw("/api/wallet/receive", nested_array())
        finally:
            sys.stderr = saved
        self.assertNotIn("Traceback", noise.getvalue(), noise.getvalue()[:500])
        self.assertNotIn("RecursionError", noise.getvalue())

    def test_an_unauthenticated_deep_body_is_still_refused_for_the_credential(self):
        """The gate is still in front of the reader.

        Worth pinning: a fix applied in the wrong place -- parsing before
        authorising, so the refusal can name the parse -- would hand an
        unauthenticated caller a different answer than 401, and that is a
        way to probe a server without a credential.
        """
        responses, trailing, data = self.post_raw("/api/wallet/pay",
                                                  nested_array(), cookie=False)
        self.assertEqual(len(responses), 1, data[:300])
        self.assertEqual(trailing, b"")
        status, _headers, payload = split_response(responses[0])
        self.assertEqual(status, 401, payload[:300])

    def test_an_ordinary_body_still_routes(self):
        """The widened clause did not widen what counts as bad JSON."""
        body = json.dumps({"name": "alice", "amount_mc": 11}).encode()
        responses, trailing, data = self.post_raw("/api/wallet/pay", body)
        self.assertEqual(len(responses), 1, data[:300])
        self.assertEqual(trailing, b"")
        status, _headers, payload = split_response(responses[0])
        self.assertEqual(status, 200, payload[:300])

    def test_shallow_nesting_is_not_collateral(self):
        """A hundred levels is legal JSON and stays legal.

        The refusal is the parser's limit, not a depth rule this server
        invented, and a test that only sent forty thousand levels would
        not notice if somebody replaced it with one.
        """
        body = b'{"name": "alice", "amount_mc": 11, "note": %s}' % (
            nested_array(100),)
        responses, _trailing, data = self.post_raw("/api/wallet/pay", body)
        status, _headers, payload = split_response(responses[0])
        self.assertEqual(status, 200, payload[:300])


class TestEveryJsonReaderNamesTheSameFamily(unittest.TestCase):
    """The drift detector, across all four servers rather than this one.

    The defect it exists against was repo-wide: the narrow
    ``except ValueError`` around json.loads was in four files, three were
    widened in earlier rounds and the fourth was not, because each fix was
    made where its defect was reported instead of everywhere the shape
    lived. A detector that walks ONE of the four repeats that mistake in
    the place meant to prevent it -- it is the same "fix it where it was
    found" one level up -- so it walks all four, from this file, because
    reading a sibling's source costs nothing and importing it is already
    done by the acceptance test in impl/tests/test_c06_mintapi.py.

    IN SCOPE is a reader that parses what another process sent: one whose
    enclosing class (or function, for a reader outside a class) also takes
    bytes off a socket. That rule is mechanical and it is the rule the
    defect follows -- a stack overflow or a five-thousand-digit integer is
    something a PEER sends. A parser reading this process's own durable
    state is not in scope and must not be: aicash/supervision.py's
    _SupCore re-reads a details_json column it wrote itself, inside a
    class that touches no socket at all, and demanding a network guard
    there would be a test asserting a thing nobody found a reason for.
    """

    #: Every HTTP server in this repository. The list is the claim: a
    #: fifth server added tomorrow is not covered until it is added here,
    #: and the per-file assertion below fails loudly if one of these stops
    #: containing a reader, rather than passing quietly.
    SERVER_SOURCES = ("gui/app.py", "mint_console.py",
                      "impl/aicash/mintapi.py", "impl/aicash/supervision.py")

    #: What "this scope takes bytes off a socket" looks like in source.
    #: rfile for a request handler, urlopen/getresponse for a client, recv
    #: and makefile for the raw layer underneath both.
    NETWORK_MARKERS = ("rfile", "urlopen", "getresponse", "recv", "makefile")

    def handled_names(self, node):
        """Every exception name an except clause names, however spelled."""
        if node is None:
            return {"BARE"}
        if isinstance(node, ast.Name):
            return {node.id}
        if isinstance(node, ast.Attribute):
            return {node.attr}
        if isinstance(node, ast.Tuple):
            out = set()
            for elt in node.elts:
                out |= self.handled_names(elt)
            return out
        return set()                                     # pragma: no cover

    def json_readers(self, relpath):
        """[(lineno, {handled}, in_scope)] for every json.loads in a file."""
        path = os.path.join(REPO, relpath)
        with open(path, encoding="utf-8") as handle:
            source = handle.read()
        tree = ast.parse(source)

        def scope_of(lineno):
            """The enclosing class, or the enclosing function if none."""
            best = None
            for node in ast.walk(tree):
                if not isinstance(node, (ast.ClassDef, ast.FunctionDef)):
                    continue
                if not node.lineno <= lineno <= (node.end_lineno or node.lineno):
                    continue
                if isinstance(node, ast.ClassDef):
                    if best is None or not isinstance(best, ast.ClassDef):
                        best = node
                    elif node.lineno > best.lineno:
                        best = node
                elif best is None:
                    best = node
            return best

        handlers = {}
        for outer in ast.walk(tree):
            if not isinstance(outer, ast.Try):
                continue
            handled = set()
            for handler in outer.handlers:
                handled |= self.handled_names(handler.type)
            for node in outer.body:
                for call in ast.walk(node):
                    if self.is_json_loads(call):
                        handlers[call.lineno] = handled

        found = []
        for call in ast.walk(tree):
            if not self.is_json_loads(call):
                continue
            scope = scope_of(call.lineno)
            text = ast.get_source_segment(source, scope) if scope else source
            in_scope = any(marker in (text or "")
                           for marker in self.NETWORK_MARKERS)
            found.append((call.lineno, handlers.get(call.lineno, set()),
                          in_scope))
        return found

    @staticmethod
    def is_json_loads(node):
        return (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "loads"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "json")

    def test_every_server_still_has_a_reader_to_check(self):
        """A walk that finds nothing must fail, not pass quietly.

        Per file, not in total: four files summing to six readers still
        passes if one file has none and another has three, and "this
        server no longer parses anything a peer sent" is exactly the
        change that should be looked at rather than assumed.
        """
        for relpath in self.SERVER_SOURCES:
            with self.subTest(source=relpath):
                in_scope = [r for r in self.json_readers(relpath) if r[2]]
                self.assertTrue(
                    in_scope,
                    "%s parses nothing that came off a socket any more, so "
                    "the assertions below no longer check it" % relpath)

    def test_every_json_loads_of_network_bytes_handles_recursionerror(self):
        """The rule, in all four files, spelled with the name itself.

        RecursionError BY NAME. A blanket ``except Exception`` catches it
        and was accepted here a round ago, which is a hole in a drift
        detector rather than a convenience: a reader wrapped in a blanket
        handler passes while producing exactly the 500 this exists to
        prevent, because the blanket is the thing that turns a malformed
        document into "something inside this server failed".
        """
        for relpath in self.SERVER_SOURCES:
            for lineno, handled, in_scope in self.json_readers(relpath):
                if not in_scope:
                    continue
                with self.subTest(source=relpath, line=lineno):
                    self.assertIn(
                        "RecursionError", handled,
                        "%s:%d parses bytes from another process under a "
                        "handler that does not name RecursionError (%s). A "
                        "nested document raises it, it is not a ValueError, "
                        "and uncaught it becomes a 500 or no answer at all."
                        % (relpath, lineno, sorted(handled) or "nothing"))

    def test_the_family_is_named_in_full(self):
        """ValueError too, where bytes off a socket are parsed.

        The other two of the three ways json.loads says no: a syntax
        error and CPython's int/str digit limit are both ValueErrors, and
        UnicodeDecodeError is a ValueError as well, so naming ValueError
        covers all three. Named separately from the test above because a
        reader that named only RecursionError would pass that one and
        still fail on the five-thousand-digit amount_mc that started this.
        """
        for relpath in self.SERVER_SOURCES:
            for lineno, handled, in_scope in self.json_readers(relpath):
                if not in_scope:
                    continue
                with self.subTest(source=relpath, line=lineno):
                    self.assertIn("ValueError", handled,
                                  "%s:%d does not name ValueError (%s)"
                                  % (relpath, lineno, sorted(handled)))

    def test_the_encoder_is_covered_too(self):
        """json.dumps recurses as well, and it is the LAST reporter.

        _json is what the blanket handler calls to say anything at all.
        An exception raised there has nowhere left to be reported, and the
        request ends with no response on the wire -- the one outcome this
        round's bar names explicitly.
        """
        source = textwrap.dedent(inspect.getsource(gui_app.Handler._json))
        handled = set()
        dumps_seen = 0
        for outer in ast.walk(ast.parse(source)):
            if not isinstance(outer, ast.Try):
                continue
            for node in outer.body:
                for call in ast.walk(node):
                    if (isinstance(call, ast.Call)
                            and isinstance(call.func, ast.Attribute)
                            and call.func.attr == "dumps"):
                        dumps_seen += 1
                        for handler in outer.handlers:
                            names = handler.type
                            if isinstance(names, ast.Tuple):
                                handled |= {e.id for e in names.elts
                                            if isinstance(e, ast.Name)}
                            elif isinstance(names, ast.Name):
                                handled.add(names.id)
        # The AST and not the source text: this method's own comment says
        # the word, and a test a comment can satisfy is a test of prose.
        self.assertTrue(dumps_seen, "no guarded json.dumps in Handler._json")
        self.assertIn("RecursionError", handled,
                      "Handler._json encodes under a handler that does not "
                      "name RecursionError (%s)" % sorted(handled))


# ======================================================================
# THE THREE FRAMING CELLS THE VERIFIER RECORDED AS DISAGREEMENTS
#
# THE MATRIX WAS RIGHT AND THE LAST ROUND'S COUNTER-MEASUREMENT WAS NOT.
# The claim recorded here a round ago -- that the verifier's closes were
# all its "Host: h" probes being refused 403 before framing was ever the
# question -- is true of the absolute-form cell and FALSE of the short
# declared length. Addressed to a loopback Host, a short Content-Length
# over a longer body closed this socket too, for a different reason
# nobody looked for: the body WAS read, but the parse that followed
# raised before _handle reached its own `drained = True`, so the finally
# clause hung up on a stream that was perfectly well framed. The cell
# passed only because "Content-Length: 2" over "{}EXTRAEXTRA" truncates
# to "{}", which is valid JSON; raising the length by ONE octet flipped
# the answer.
#
# Measured since, with the four-server harness that already exists
# (impl/tests/test_c06_mintapi.py, FourServersOneFramingRuleTest.
# start_four), byte-identical requests, loopback Host, no Connection
# header:
#
#   cell                          mint  supervision  GUI (was)  console
#   bad JSON, exact length        keep     keep        CLOSE     keep*
#   short declared length         keep     keep        CLOSE     keep*
#   a plain well-formed GET       keep     keep        keep      close*
#
#   * the console never sets protocol_version, so it answers HTTP/1.0 and
#     BaseHTTPRequestHandler leaves close_connection True on every request
#     -- its own docstring says so. It closes on the third row too, where
#     there is nothing to decide. Its closes are not framing decisions and
#     cannot be counted as agreement or disagreement with anything.
#
# So this server was the only one of the four that hung up on a malformed
# body, in the one path where its comment claimed it did not. That is
# fixed in app.py (the parse moved out of the reader and behind the
# drain), and these tests are the measurement, per spelling, so a single
# lucky payload cannot carry the claim again.
# ======================================================================
class TestWhatThisServerActuallyDoesWithTheSocket(ServerCase):

    def probe(self, payload, expect=1, wait=8.0):
        return exchange_and_watch(self.port, payload, expect=expect,
                                  wait=wait)

    def good_headers(self):
        return ("Host: 127.0.0.1:%d\r\nCookie: %s\r\n"
                % (self.port, self.cookie))

    #: Four spellings of ONE cell: the peer declares fewer octets than it
    #: sends. They differ only in whether the truncated prefix happens to
    #: be valid JSON, which is not a property of the framing and must not
    #: change the socket decision. The first is the spelling the last
    #: round tested, and it is the ONLY one of the four that passed: "{}"
    #: parses, the route runs, and the answer says nothing about what a
    #: malformed prefix would have done. The other three are the same cell
    #: with one octet more.
    SHORT_LENGTHS = (
        (2, b"{}EXTRAEXTRA", "bad_name"),        # prefix "{}" -- valid JSON
        (3, b"{}EXTRAEXTRA", "bad_json"),        # prefix "{}E"
        (10, b'{"name":"alice","mint_id":"m"}XXXX', "bad_json"),
        (20, b'{"name":"alice","mint_id":"m"}XXXX', "bad_json"),
    )

    def test_a_short_declared_length_is_honoured_and_the_socket_lives(self):
        """CL declares fewer octets than arrive. The declaration is the frame.

        The extra octets are not this message -- they are whatever the
        peer sends next, and this server does not have to hang up to be
        safe from them. It answers the request it was framed, once, and
        leaves the socket up: the same call the mint and the supervision
        server make, measured, on byte-identical requests.

        EVERY SPELLING, because the one-spelling version of this test was
        the round's own weakened check: it sent the single payload whose
        truncation is still valid JSON, and one more octet of declared
        length turned the answer from keep into close.
        """
        for length, body, reason in self.SHORT_LENGTHS:
            with self.subTest(content_length=length):
                head = ("POST /api/wallet/create HTTP/1.1\r\n"
                        + self.good_headers()
                        + "Content-Type: application/json\r\n"
                          "Content-Length: %d\r\n\r\n" % length)
                payload = head.encode() + body
                responses, trailing, closed, data = self.probe(payload)
                self.assertEqual(len(responses), 1, data[:400])
                self.assertEqual(trailing, b"")
                status, headers, payload_bytes = split_response(responses[0])
                self.assertEqual(status, 400, payload_bytes[:300])
                self.assertEqual(json.loads(payload_bytes)["error"]["reason"],
                                 reason, payload_bytes[:300])
                self.assertIsNone(headers.get("connection"),
                                  "announced a close it did not have to make")
                self.assertFalse(
                    closed,
                    "this server closed on a short declared length (CL=%d); "
                    "the mint and the supervision server answer the "
                    "pipelined request behind it on the same connection"
                    % length)

    def test_no_declared_length_with_octets_is_refused_and_closed(self):
        """The one of the three that is a real framing decision.

        No trustworthy statement of length, and octets on the wire: this
        server cannot know where the message ends, so it does not guess
        and the socket does not survive. All four servers close here.
        """
        payload = ("POST /api/wallet/create HTTP/1.1\r\n" + self.good_headers()
                   + "Content-Type: application/json\r\n\r\n{}").encode()
        responses, trailing, closed, data = self.probe(payload)
        self.assertEqual(len(responses), 1, data[:400])
        self.assertEqual(trailing, b"")
        self.assertTrue(closed, "an unframable request kept the socket")
        status, headers, payload_bytes = split_response(responses[0])
        self.assertEqual(status, 400, payload_bytes[:300])
        self.assertEqual(headers.get("connection"), "close",
                         "closed without saying so, which a peer cannot act on")
        self.assertEqual(json.loads(payload_bytes)["error"]["reason"],
                         "unframable_request")

    def test_an_absolute_form_target_is_answered_once_and_the_socket_goes(self):
        """THIS TEST USED TO ASSERT THE OPPOSITE, AND IT WAS WRONG.

        What stood here was
        ``test_an_absolute_form_target_keeps_the_socket``, asserting
        ``assertFalse(closed)`` with the message "the mint and the
        supervision server do not [close]". That claim was false when it
        was written and it certified the one cell where this server was
        alone among the four. Re-measured with the four-server harness,
        byte-identical requests, loopback Host, valid credential:

            server        GET http://127.0.0.1:P/<route>
            mint          400 bad_request_target, CLOSED
            supervision   400 bad_request_target, CLOSED
            console       answers, CLOSED
            GUI (was)     404 not_found,          KEPT

        Three to one, and the odd one out is the server an operator sits
        in front of. app.py's parse_request now refuses it, for the reason
        written there: this server routes on ``self.path`` verbatim, so an
        absolute-form target has never matched a route and never could,
        and RFC 7230 §5.3.2 says a server that accepts one must ignore
        ``Host`` and route on the target's own authority -- which this
        server does not do, so the request's two statements of "which
        server is this for" leave this hop unresolved.
        """
        payload = ("GET http://127.0.0.1:%d/api/wallet/list HTTP/1.1\r\n"
                   % self.port + self.good_headers() + "\r\n").encode()
        responses, trailing, closed, data = self.probe(payload)
        self.assertEqual(len(responses), 1, data[:400])
        self.assertEqual(trailing, b"")
        status, headers, payload_bytes = split_response(responses[0])
        self.assertEqual(status, 400, payload_bytes[:300])
        self.assertEqual(json.loads(payload_bytes)["error"]["reason"],
                         "bad_request_target", payload_bytes[:300])
        self.assertEqual(headers.get("connection"), "close",
                         "hung up without saying so, which a peer and an "
                         "intermediary both have to guess at")
        self.assertTrue(closed,
                        "this server answered an absolute-form target and "
                        "then invited another request on the same socket; "
                        "the other three answer once and hang up")

    def test_a_bad_host_closes_and_it_is_a_separate_cause(self):
        """The Host refusal is real, and it is NOT what cell A measured.

        A Host that is not a loopback literal is refused 403 and hung up
        on, before framing is the question. That much the last round had
        right. What it then did with it was the error: it read the same
        close on the short-length probe as "the verifier measured the Host
        refusal", when with a loopback Host that probe ALSO closed, by a
        different rule entirely. A close that two causes both produce
        cannot be attributed to either by observing it.

        So this test does what the old one could not: it drives both
        probes with BOTH hosts and asserts the four outcomes differ. The
        bad Host closes either way; the loopback Host closes on neither,
        which is what makes the 403 the only cause left standing for the
        cells that do close.
        """
        bad = "Host: h\r\nCookie: %s\r\n" % self.cookie
        good = self.good_headers()
        cells = {
            ("short length", "bad host"): (
                ("POST /api/wallet/create HTTP/1.1\r\n" + bad +
                 "Content-Length: 10\r\n\r\n"
                 '{"name":"alice","mint_id":"m"}XXXX'), 403, True),
            ("short length", "loopback host"): (
                ("POST /api/wallet/create HTTP/1.1\r\n" + good +
                 "Content-Length: 10\r\n\r\n"
                 '{"name":"alice","mint_id":"m"}XXXX'), 400, False),
            # AN ORIGIN-FORM GET WHERE THE ABSOLUTE-FORM ONE USED TO BE.
            # The absolute-form probe cannot carry this half of the claim
            # any more: parse_request now refuses that target BEFORE
            # _handle runs the Host check at all, so it answers 400
            # bad_request_target and closes whatever the Host says, and a
            # cell whose two rows are identical separates nothing. Its own
            # behaviour is asserted in full by
            # test_an_absolute_form_target_is_answered_once_and_the_socket_goes.
            #
            # A plain GET is the right substitute and is strictly stronger
            # here: it is a request with NOTHING wrong with it except the
            # Host, so the 403-and-close it gets is attributable to the
            # Host refusal and to nothing else, and the same bytes with a
            # loopback Host are answered 200 on a live socket. That is the
            # cleanest possible statement of "the Host refusal is real and
            # it is a separate cause", which is what this test is for.
            ("plain get", "bad host"): (
                ("GET /api/wallet/list HTTP/1.1\r\n"
                 + bad + "\r\n"), 403, True),
            ("plain get", "loopback host"): (
                ("GET /api/wallet/list HTTP/1.1\r\n"
                 + good + "\r\n"), 200, False),
        }
        for (probe, host), (text, expect_status, expect_closed) in cells.items():
            with self.subTest(probe=probe, host=host):
                responses, trailing, closed, data = self.probe(text.encode())
                self.assertEqual(len(responses), 1, data[:400])
                self.assertEqual(trailing, b"")
                status, _headers, payload = split_response(responses[0])
                self.assertEqual(status, expect_status, payload[:300])
                if expect_status == 403:
                    self.assertEqual(json.loads(payload)["error"]["reason"],
                                     "not_loopback")
                self.assertEqual(
                    closed, expect_closed,
                    "%s with a %s: closed=%s, which is not what makes the "
                    "two causes tellable apart" % (probe, host, closed))


# ======================================================================
# THE MINT PORT IS NOT NECESSARILY THE MINT
#
# The round's own finding shape, one layer down and in the function the
# round touched. _mint_http widened its json.loads clause to catch
# RecursionError -- copied out of the console's tuple at
# mint_console.py:1252, which is
#
#     (OSError, ValueError, RecursionError, http.client.HTTPException)
#
# -- and left the fourth member behind. http.client.HTTPException is a
# plain Exception, not an OSError, so the urlopen/read above the parse
# caught none of it and four shapes of reply walked out of the Api and
# into the blanket handler: HTTP/1.1 500 internal_error, with a traceback
# on the operator's terminal, on /api/mint/descriptor, /api/token/status
# and /api/mint/issue. The money route is the one that matters: a 500
# there leaves it undetermined whether tokens were created and says
# nothing about it.
#
# These tests put a real socket on the mint port and answer real garbage.
# ======================================================================
class TestTheMintPortAnsweredSomethingThatIsNotHttp(ServerCase):

    #: Every http.client.HTTPException the stdlib client raises for a
    #: reply that is not HTTP, with the class it raises named so a reader
    #: can check the tuple against the exception hierarchy rather than
    #: against this comment.
    REPLIES = {
        "BadStatusLine": b"GARBAGE\r\n\r\n",
        "HTTPException (more than 100 headers)":
            b"HTTP/1.1 200 OK\r\n"
            + b"".join(b"X-Pad-%d: v\r\n" % i for i in range(200))
            + b"\r\n",
        "IncompleteRead":
            b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort",
        "LineTooLong":
            b"HTTP/1.1 200 OK\r\nX-Big: " + b"a" * 200_000 + b"\r\n\r\n",
    }

    #: The three routes that reach _mint_http, derived from the call sites
    #: rather than typed from memory: descriptor, token status, issue.
    ROUTES = (
        ("GET", "/api/mint/descriptor", None),
        ("GET", "/api/token/status?token=abc", None),
        ("POST", "/api/mint/issue", {"amount_mc": 500, "count": 2}),
    )

    def rogue(self, reply: bytes) -> int:
        """A real listener on a real port that answers ``reply``, verbatim.

        Not an http.server: the whole point is a reply the stdlib's own
        server could not produce. It reads the request first, so the GUI's
        request is genuinely sent and the outcome genuinely undetermined.
        """
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(8)
        stop = threading.Event()

        def serve():
            listener.settimeout(0.2)
            while not stop.is_set():
                try:
                    conn, _ = listener.accept()
                except (socket.timeout, TimeoutError, OSError):
                    continue
                try:
                    conn.recv(65536)
                    conn.sendall(reply)
                    # EOF, not a reset. Closing outright races the reader:
                    # a peer that is still mid-read gets ECONNRESET, which
                    # is an OSError and lands on the mint_unreachable
                    # clause instead of the one under test. Half-closing
                    # and then waiting for the client to hang up gives the
                    # deterministic end-of-message every one of these
                    # replies needs to be the exception it is named for.
                    conn.shutdown(socket.SHUT_WR)
                    conn.settimeout(5)
                    while conn.recv(65536):
                        pass
                except OSError:                          # pragma: no cover
                    pass
                finally:
                    conn.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        port = listener.getsockname()[1]
        self.addCleanup(listener.close)
        self.addCleanup(thread.join, 5)
        self.addCleanup(stop.set)

        real = self.control.status

        def status_here():
            out = dict(real())
            out["base_url"] = "http://127.0.0.1:%d" % port
            out["port"] = port
            return out

        self.control.status = status_here
        self.addCleanup(self.control.__dict__.pop, "status", None)
        return port

    def drive(self, reply):
        """Every route against one rogue reply, with stderr captured."""
        self.rogue(reply)
        noise = io.StringIO()
        saved = sys.stderr
        sys.stderr = noise                  # the handler thread prints here
        try:
            out = [(method, path) + self.call(method, path, body)
                   for method, path, body in self.ROUTES]
        finally:
            sys.stderr = saved
        return out, noise.getvalue()

    def test_a_reply_that_is_not_http_is_not_an_internal_error(self):
        """The finding itself: four replies, three routes, twelve cells."""
        for label, reply in self.REPLIES.items():
            results, noise = self.drive(reply)
            for method, path, status, obj, raw in results:
                with self.subTest(reply=label, route="%s %s" % (method, path)):
                    self.assert_envelope(status, obj, raw)
                    self.assertEqual(
                        status, 502,
                        "%s %s answered %d for a %s reply: %r"
                        % (method, path, status, label, raw[:300]))
                    self.assertEqual(obj["error"]["reason"],
                                     "bad_mint_response", raw[:300])
                    self.assertEqual(obj["error"]["cause"], "unknown",
                                     raw[:300])
            with self.subTest(reply=label, check="terminal"):
                self.assertNotIn("Traceback", noise, noise[:600])

    def test_it_does_not_say_the_mint_did_not_answer(self):
        """The cause vocabulary, which is the whole reason for the split.

        mint_unreachable means "nothing answered; it never saw the
        request" and page.html renders it as exactly that. Octets came
        back here. Saying unreachable would put that headline above a
        detail describing what arrived -- and on the issue route it would
        do it about money.
        """
        for label, reply in self.REPLIES.items():
            results, _noise = self.drive(reply)
            for method, path, _status, obj, raw in results:
                with self.subTest(reply=label, route="%s %s" % (method, path)):
                    self.assertNotEqual(obj["error"]["cause"],
                                        "mint_unreachable", raw[:300])
                    self.assertNotIn("did not answer", obj["error"]["detail"])

    def test_the_issue_route_says_the_outcome_is_undetermined(self):
        """The money route, and the reason a 500 there is not acceptable.

        The request went out. Whatever is on that port may have created
        tokens against secrets that existed only inside that call. The
        answer has to say so -- which it does, because the cause is
        unknown and route_mint_issue appends the undetermined sentence to
        exactly that cause.
        """
        for label, reply in self.REPLIES.items():
            with self.subTest(reply=label):
                self.rogue(reply)
                noise, saved = io.StringIO(), sys.stderr
                sys.stderr = noise
                try:
                    status, obj, raw = self.call(
                        "POST", "/api/mint/issue",
                        {"amount_mc": 500, "count": 2})
                finally:
                    sys.stderr = saved
                self.assertEqual(status, 502, raw[:300])
                detail = obj["error"]["detail"]
                self.assertIn("UNDETERMINED", detail)
                self.assertIn("1000 mc", detail)
                self.assertNotIn("Nothing was issued", detail)

    def test_the_answer_quotes_no_traceback_to_the_browser(self):
        """A rogue process on that port must not get to write the page."""
        for label, reply in self.REPLIES.items():
            results, _noise = self.drive(reply)
            for method, path, _status, _obj, raw in results:
                with self.subTest(reply=label, route="%s %s" % (method, path)):
                    text = raw.decode("utf-8", "replace")
                    for forbidden in ("Traceback", "internal_error",
                                      "Something inside this GUI failed",
                                      "urllib", "http/client.py"):
                        self.assertNotIn(forbidden, text, text[:400])

    def test_a_refused_connection_is_still_mint_unreachable(self):
        """The neighbour, so the widened clause did not swallow it.

        Nothing listening is the one shape that really is "the mint did
        not answer", and it must keep saying so: connection refused is a
        ConnectionRefusedError, an OSError, and it is caught ABOVE the new
        clause. http.client.RemoteDisconnected is the same story spelled
        differently -- it inherits from ConnectionResetError AND from
        BadStatusLine, and the order of the except clauses is what keeps
        it on the mint_unreachable side.
        """
        port = free_port()
        real = self.control.status

        def status_here():
            out = dict(real())
            out["base_url"] = "http://127.0.0.1:%d" % port
            out["port"] = port
            return out

        self.control.status = status_here
        self.addCleanup(self.control.__dict__.pop, "status", None)
        status, obj, raw = self.call("GET", "/api/mint/descriptor")
        self.assertEqual(status, 502, raw[:300])
        self.assertEqual(obj["error"]["cause"], "mint_unreachable", raw[:300])

    def test_the_client_call_is_guarded_where_the_parse_is(self):
        """The drift question, asked of the CALL and not only the parse.

        The enumeration that missed this asked what every json.loads can
        raise and stopped there. The call that FEEDS the parse raises its
        own family, and it is a family no clause above it named. This
        walks the source instead of trusting that it was thought about:
        every urlopen/getresponse in this file must sit under a handler
        that names HTTPException.
        """
        with open(gui_app.__file__, encoding="utf-8") as handle:
            tree = ast.parse(handle.read())
        checked = 0
        for outer in ast.walk(tree):
            if not isinstance(outer, ast.Try):
                continue
            handled = set()
            for handler in outer.handlers:
                node = handler.type
                if node is None:
                    handled.add("BARE")
                elif isinstance(node, ast.Tuple):
                    for elt in node.elts:
                        handled.add(getattr(elt, "attr", None)
                                    or getattr(elt, "id", ""))
                else:
                    handled.add(getattr(node, "attr", None)
                                or getattr(node, "id", ""))
            for node in outer.body:
                for call in ast.walk(node):
                    if (isinstance(call, ast.Call)
                            and isinstance(call.func, ast.Attribute)
                            and call.func.attr in ("urlopen", "getresponse")):
                        checked += 1
                        self.assertIn(
                            "HTTPException", handled,
                            "gui/app.py:%d speaks to another process under a "
                            "handler that does not name HTTPException (%s). "
                            "BadStatusLine, IncompleteRead and LineTooLong "
                            "are not OSErrors and become a bare 500."
                            % (call.lineno, sorted(handled)))
        self.assertTrue(checked, "the walk found no client call to check; "
                                 "the assertion above is vacuous")


# ======================================================================
# A MALFORMED BODY IS NOT A FRAMING FAILURE
#
# The connection decision, which this server got wrong in the one path
# its own comment said it got right. Every cell here sends a body the
# reader refuses and a COMPLETE valid request pipelined behind it: if the
# socket survives, the second request is answered on it, and that is the
# assertion. The mint and the supervision server answer both, measured.
# ======================================================================
class TestABadBodyDoesNotCostTheConnection(ServerCase):

    #: One class of bad body per spelling of "no".
    BODIES = {
        "unterminated object": b"{",
        "not an object": b"[]",
        "invalid utf-8": b'{"name": "\xff\xfe"}',
        "five thousand digits": b'{"amount_mc": ' + b"9" * 5000 + b"}",
        "ten thousand levels deep": (b"[" * 10_000) + (b"]" * 10_000),
    }

    def two_requests(self, path, body, headers=None):
        """A POST with ``body``, then a valid GET, on one connection."""
        head = ("POST %s HTTP/1.1\r\n"
                "Host: 127.0.0.1:%d\r\n"
                "Cookie: %s\r\n"
                "Content-Type: application/json\r\n"
                "Content-Length: %d\r\n"
                % (path, self.port, self.cookie, len(body)))
        second = ("GET /api/wallet/list HTTP/1.1\r\n"
                  "Host: 127.0.0.1:%d\r\n"
                  "Cookie: %s\r\n\r\n" % (self.port, self.cookie))
        payload = ((head + (headers or "") + "\r\n").encode() + body
                   + second.encode())
        return exchange_and_watch(self.port, payload, expect=2)

    def test_the_pipelined_request_behind_a_bad_body_is_answered(self):
        """Two requests in, two responses out, on one socket."""
        for label, body in self.BODIES.items():
            with self.subTest(body=label):
                responses, trailing, closed, data = self.two_requests(
                    "/api/wallet/pay", body)
                self.assertEqual(
                    len(responses), 2,
                    "%s: %d response(s), so the request behind it was "
                    "discarded: %r" % (label, len(responses), data[:400]))
                self.assertEqual(trailing, b"")
                first, second = (split_response(r) for r in responses)
                self.assertEqual(first[0], 400, first[2][:300])
                self.assertEqual(json.loads(first[2])["error"]["reason"],
                                 "bad_json", first[2][:300])
                self.assertIsNone(
                    first[1].get("connection"),
                    "%s: announced a close for a body that was read whole"
                    % label)
                self.assertEqual(second[0], 200, second[2][:300])

    def test_every_post_route_keeps_the_socket(self):
        """Not one route: the reader is shared, so the claim is shared."""
        for path in POST_ROUTES:
            with self.subTest(path=path):
                responses, trailing, closed, data = self.two_requests(
                    path, b"{")
                self.assertEqual(len(responses), 2, data[:400])
                self.assertEqual(trailing, b"")
                self.assertEqual(split_response(responses[1])[0], 200,
                                 data[:400])

    def test_an_unframable_body_still_costs_the_connection(self):
        """The other side of the line, and why this is not "never close".

        No trustworthy statement of length means the octets on the wire
        cannot be told from the next request line. Nothing was read, the
        stream is not framed, and the socket does not survive -- so the
        request behind it is NOT answered, and must not be.
        """
        head = ("POST /api/wallet/pay HTTP/1.1\r\n"
                "Host: 127.0.0.1:%d\r\n"
                "Cookie: %s\r\n"
                "Content-Type: application/json\r\n"
                "Transfer-Encoding: chunked\r\n\r\n" % (self.port, self.cookie))
        second = ("GET /api/wallet/list HTTP/1.1\r\n"
                  "Host: 127.0.0.1:%d\r\n"
                  "Cookie: %s\r\n\r\n" % (self.port, self.cookie))
        responses, trailing, closed, data = exchange_and_watch(
            self.port, (head + second).encode(), expect=1)
        self.assertEqual(len(responses), 1, data[:400])
        self.assertEqual(trailing, b"")
        self.assertTrue(closed, "an unframable request kept the socket")
        status, headers, payload = split_response(responses[0])
        self.assertEqual(status, 400, payload[:300])
        self.assertEqual(json.loads(payload)["error"]["reason"],
                         "unframable_request")
        self.assertEqual(headers.get("connection"), "close")

    def test_a_short_body_still_costs_the_connection(self):
        """A body that stopped before its own declared length.

        The peer said more octets were coming and then did not send them.
        Whatever arrives next cannot be told from the rest of this body,
        so this one closes too -- the distinction being drawn is "were the
        octets read", not "did the parse like them".
        """
        body = b'{"name": "alice"}'
        head = ("POST /api/wallet/create HTTP/1.1\r\n"
                "Host: 127.0.0.1:%d\r\n"
                "Cookie: %s\r\n"
                "Content-Type: application/json\r\n"
                "Content-Length: %d\r\n\r\n" % (self.port, self.cookie,
                                                len(body) + 40))
        responses, trailing, closed, data = exchange_and_watch(
            self.port, head.encode() + body, expect=1, half_close=True)
        self.assertEqual(len(responses), 1, data[:400])
        self.assertEqual(trailing, b"")
        self.assertTrue(closed, "a truncated body kept the socket")
        status, headers, payload = split_response(responses[0])
        self.assertEqual(status, 400, payload[:300])
        self.assertEqual(json.loads(payload)["error"]["reason"], "bad_request")
        self.assertEqual(headers.get("connection"), "close")

    def test_a_peer_that_asked_to_close_is_still_obeyed(self):
        """Keeping the socket is not overriding the client.

        Connection: close is the peer's decision, not this server's, and
        the drain does not undo it.
        """
        body = b"{"
        payload = ("POST /api/wallet/pay HTTP/1.1\r\n"
                   "Host: 127.0.0.1:%d\r\n"
                   "Cookie: %s\r\n"
                   "Content-Type: application/json\r\n"
                   "Connection: close\r\n"
                   "Content-Length: %d\r\n\r\n"
                   % (self.port, self.cookie, len(body))).encode() + body
        responses, trailing, closed, data = exchange_and_watch(
            self.port, payload, expect=1)
        self.assertEqual(len(responses), 1, data[:400])
        self.assertTrue(closed, "the peer asked to close and was not obeyed")
        status, headers, payload_bytes = split_response(responses[0])
        self.assertEqual(status, 400, payload_bytes[:300])
        self.assertEqual(headers.get("connection"), "close")


# ======================================================================
# THE BAND EITHER SIDE OF THE PARSER'S DEPTH LIMIT
#
# The nesting tests pin 100 levels (accepted) and 40,000 (refused). On
# this interpreter json.loads gives up at about 9,980, so nothing in the
# suite sat anywhere near the boundary and a change that moved it -- a
# depth rule invented locally, a different parser, a thread with a
# smaller stack -- would have been invisible in both directions.
#
# This does not pin the boundary, which is the interpreter's business and
# moves between builds. It sweeps ACROSS it and asserts the only two
# things that are this server's business: every depth is answered exactly
# once, and every answer is either the route's or a bad_json -- never a
# 500, never silence, never octets past the framing.
# ======================================================================
class TestTheNestingBoundaryBand(ServerCase):

    DEPTHS = tuple(range(8_000, 11_001, 250))

    def ask(self, depth):
        body = (b'{"name": "alice", "amount_mc": 11, "note": %s}'
                % ((b"[" * depth) + (b"]" * depth)))
        payload = ("POST /api/wallet/pay HTTP/1.1\r\n"
                   "Host: 127.0.0.1:%d\r\n"
                   "Cookie: %s\r\n"
                   "Content-Type: application/json\r\n"
                   "Connection: close\r\n"
                   "Content-Length: %d\r\n\r\n"
                   % (self.port, self.cookie, len(body))).encode() + body
        responses, trailing, closed, data = exchange_and_watch(
            self.port, payload, expect=1, wait=20.0, linger=0.2)
        self.assertEqual(len(responses), 1,
                         "depth %d: %d response(s): %r"
                         % (depth, len(responses), data[:300]))
        self.assertEqual(trailing, b"", "depth %d left octets" % depth)
        return split_response(responses[0])

    def test_every_depth_across_the_boundary_is_answered_the_same_two_ways(self):
        outcomes = set()
        for depth in self.DEPTHS:
            with self.subTest(depth=depth):
                status, _headers, payload = self.ask(depth)
                if status == 200:
                    outcomes.add("accepted")
                    continue
                self.assertEqual(status, 400, "depth %d answered %d: %r"
                                 % (depth, status, payload[:300]))
                self.assertEqual(json.loads(payload)["error"]["reason"],
                                 "bad_json", payload[:300])
                outcomes.add("bad_json")
        self.assertEqual(
            outcomes, {"accepted", "bad_json"},
            "the sweep did not straddle the parser's limit (%s); it is "
            "measuring one side of a boundary it was written to cross"
            % sorted(outcomes))

    def test_the_deepest_accepted_document_reaches_the_route(self):
        """The half a "refuse everything deep" rule would break.

        Just under the limit is a legal JSON document and the route runs
        on it. Without this, a local depth cap -- the thing the refusal
        must NOT become -- would pass the whole class.
        """
        status, _headers, payload = self.ask(9_000)
        self.assertEqual(status, 200, payload[:300])


# ======================================================================
# THE ONE PATH THAT COULD ANSWER BEFORE THE FRAMING GATE
# ======================================================================
class TestAnInterimAnswerIsNotEmittedBeforeTheGate(ServerCase):
    """Expect: 100-continue, which is live on three of the four servers.

    protocol_version = HTTP/1.1 makes BaseHTTPRequestHandler.
    handle_expect_100 reachable, and it fires inside parse_request --
    before _handle, and therefore before the framing gate everything in
    this round is built around. The console considered this exact hook,
    neutralised it and has a test for it, even though its own
    protocol_version leaves it unreachable; nothing carried that across to
    the servers where it was reachable, and neither the 58-spelling sweep
    nor the round's new tests ever sent the header.

    MEASURED AT ALL FOUR, byte-identical requests, through the harness in
    impl/tests/test_c06_mintapi.py: POST with Expect: 100-continue and a
    chunked body drew a bare "HTTP/1.1 100 Continue" out of the mint and
    out of the supervision profile as well, ahead of their own framing
    refusal. Those two files are not this round's to edit and the finding
    is reported rather than fixed there; these tests are this server's
    half, and they are what the other two would inherit.
    """

    def probe(self, extra, path="/api/wallet/pay", body=b""):
        payload = ("POST %s HTTP/1.1\r\n"
                   "Host: 127.0.0.1:%d\r\n"
                   "Cookie: %s\r\n"
                   "Content-Type: application/json\r\n"
                   "Expect: 100-continue\r\n"
                   "%s\r\n" % (path, self.port, self.cookie, extra)).encode()
        return exchange_and_watch(self.port, payload + body, expect=1)

    def test_no_continue_before_a_framing_refusal(self):
        """The finding: a bare 100 promising to read an unframable body."""
        for label, extra in (("chunked", "Transfer-Encoding: chunked\r\n"),
                             ("two lengths",
                              "Content-Length: 5\r\nContent-Length: 6\r\n"),
                             ("no length at all", "")):
            with self.subTest(spelling=label):
                responses, trailing, closed, data = self.probe(extra)
                self.assertNotIn(
                    b"100 Continue", data,
                    "%s: this server invited a body it had already decided "
                    "not to frame: %r" % (label, data[:200]))
                self.assertEqual(len(responses), 1, data[:300])
                self.assertEqual(trailing, b"")
                self.assertTrue(closed)
                status, headers, payload = split_response(responses[0])
                self.assertEqual(status, 400, payload[:300])
                self.assertEqual(json.loads(payload)["error"]["reason"],
                                 "unframable_request", payload[:300])
                self.assertEqual(headers.get("connection"), "close")

    def test_no_continue_before_a_body_too_large_to_read(self):
        """The same promise, one refusal along."""
        responses, trailing, closed, data = self.probe(
            "Content-Length: %d\r\n" % (gui_app.MAX_BODY_BYTES + 1))
        self.assertNotIn(b"100 Continue", data, data[:200])
        self.assertEqual(len(responses), 1, data[:300])
        status, _headers, payload = split_response(responses[0])
        self.assertEqual(status, 413, payload[:300])
        self.assertEqual(json.loads(payload)["error"]["reason"], "too_large")
        self.assertTrue(closed)

    def test_a_framable_body_still_gets_its_continue(self):
        """And the hook is not simply switched off.

        A client that waits for the interim answer before sending its body
        has to get one, or every such request pays the body-read timeout.
        The override refuses the requests the gate would refuse and hands
        the rest to the stdlib.
        """
        body = json.dumps({"name": "alice", "amount_mc": 11}).encode()
        responses, trailing, closed, data = self.probe(
            "Content-Length: %d\r\n" % len(body), body=body)
        self.assertIn(b"HTTP/1.1 100 Continue", data, data[:200])
        self.assertEqual(trailing, b"")
        # The interim line is not a response: split_all_responses counts it
        # as one, so the tail is what matters here.
        self.assertTrue(data.rstrip().endswith(b"}"), data[-200:])
        self.assertIn(b"200 OK", data)

    def test_the_interim_answer_does_not_suppress_the_real_one(self):
        """A 1xx is not an answer, and must not be recorded as one.

        The console's note on this hook: counting the 100 as "a response
        has begun" is what made its own last-resort handler suppressible,
        and a failing request would then get silence -- the defect class
        re-entering through the fix for it. _send only records a status of
        200 or more, and this is the test of that.
        """
        body = json.dumps({"name": "alice", "amount_mc": 11}).encode()
        broken = RuntimeError("after the continue, before the answer")
        original = gui_app.Handler._handle

        def explode(self, method):
            raise broken

        gui_app.Handler._handle = explode
        self.addCleanup(setattr, gui_app.Handler, "_handle", original)
        noise, saved = io.StringIO(), sys.stderr
        sys.stderr = noise
        try:
            responses, trailing, closed, data = self.probe(
                "Content-Length: %d\r\n" % len(body), body=body)
        finally:
            sys.stderr = saved
        self.assertIn(b"HTTP/1.1 100 Continue", data, data[:200])
        self.assertIn(b"500", data, data[:300])
        self.assertIn("internal_error", data.decode("utf-8", "replace"))


# ======================================================================
# NOTHING LEAVES THIS SERVER WITH NO ANSWER AT ALL
#
# The coverage boundary of the blanket handler, which the enumeration
# never asked about. _handle's try starts after the HTTP/0.9 refusal,
# after the framing verdict and after the path parsing, and a try does
# not cover its own except and finally clauses -- where _error -> _json
# -> _send is what writes to the socket. Both sibling servers have a
# handle_one_request last resort for exactly this; this one did not.
# ======================================================================
class TestNothingLeavesThisServerUnanswered(ServerCase):

    def request(self, path="/api/wallet/list", method="GET"):
        payload = ("%s %s HTTP/1.1\r\n"
                   "Host: 127.0.0.1:%d\r\n"
                   "Cookie: %s\r\n"
                   "Connection: close\r\n\r\n"
                   % (method, path, self.port, self.cookie)).encode()
        noise, saved = io.StringIO(), sys.stderr
        sys.stderr = noise
        try:
            out = exchange_and_watch(self.port, payload, expect=1)
        finally:
            sys.stderr = saved
        return out + (noise.getvalue(),)

    def break_it(self, name, boom=None):
        """Make one module-level name raise, for one test."""
        original = getattr(gui_app, name)

        def explode(*args, **kwargs):
            raise boom or RuntimeError("%s failed" % name)

        setattr(gui_app, name, explode)
        self.addCleanup(setattr, gui_app, name, original)

    def test_a_failure_before_the_blanket_handler_is_still_answered(self):
        """framing_fields runs OUTSIDE _handle's try, on every request."""
        self.break_it("framing_fields")
        responses, trailing, closed, data, noise = self.request()
        self.assertEqual(len(responses), 1,
                         "zero bytes back, which is the bar's own words: %r"
                         % data[:200])
        self.assertEqual(trailing, b"")
        status, headers, payload = split_response(responses[0])
        self.assertEqual(status, 500, payload[:300])
        obj = json.loads(payload)
        self.assert_envelope(status, obj, payload)
        self.assertEqual(obj["error"]["reason"], "internal_error")
        self.assertEqual(headers.get("connection"), "close")
        self.assertIn("Traceback", noise,
                      "the operator got no trace of a failure that is a bug "
                      "in this file")

    def test_the_verdict_itself_failing_is_answered_too(self):
        self.break_it("framing_verdict")
        responses, _trailing, _closed, data, _noise = self.request()
        self.assertEqual(len(responses), 1, data[:200])
        status, _headers, payload = split_response(responses[0])
        self.assertEqual(status, 500, payload[:300])

    def test_the_backstop_does_not_write_a_second_response(self):
        """A failure AFTER the answer is on the wire is not answered twice.

        That is the desync this whole round exists to prevent, and it is
        the shape a naive last resort introduces: _handle answers, the
        finally clause raises, and the backstop appends a second status
        line to a socket that already carries one.
        """
        original = gui_app.Handler._handle

        def answer_then_fail(self, method):
            original(self, method)
            raise RuntimeError("in the finally, after the answer")

        gui_app.Handler._handle = answer_then_fail
        self.addCleanup(setattr, gui_app.Handler, "_handle", original)
        responses, trailing, _closed, data, noise = self.request()
        self.assertEqual(len(responses), 1,
                         "two responses on one request: %r" % data[:400])
        self.assertEqual(trailing, b"",
                         "octets past the framing: %r" % trailing[:200])
        status, _headers, payload = split_response(responses[0])
        self.assertEqual(status, 200, payload[:300])
        self.assertIn("Traceback", noise)

    def test_the_answer_is_a_sentence_and_not_a_stack_trace(self):
        self.break_it("framing_fields", RuntimeError("secret-looking text"))
        responses, _trailing, _closed, data, _noise = self.request()
        text = data.decode("utf-8", "replace")
        self.assertNotIn("Traceback", text)
        self.assertNotIn("secret-looking text", text)
        self.assertNotIn("RuntimeError", text)

    def test_it_does_not_claim_nothing_happened(self):
        """The honesty rule the console's version of this is written to.

        A backstop cannot know whether the request took effect -- POST
        /api/mint/issue creates money and then formats tokens locally --
        so the sentence must not assert that it did not.
        """
        self.break_it("framing_fields")
        responses, _trailing, _closed, data, _noise = self.request()
        self.assertEqual(len(responses), 1, data[:200])
        _status, _headers, payload = split_response(responses[0])
        detail = json.loads(payload)["error"]["detail"]
        self.assertIn("cannot tell whether the request took effect", detail)


# ======================================================================
# THE THREE HARDENINGS THE MINT HAD AND THIS SERVER DID NOT
#
# All three findings below are the same shape, and it is the shape that
# has cost this project four rounds: a transport bound was reported once,
# fixed in the server it was reported against, and never carried to the
# three siblings. The coverage that let each one survive here is the part
# worth naming, because a green suite over the wrong shape reads as
# coverage and is worse than none:
#
#   * the drip: this file's socket tests all send a COMPLETE request in
#     one sendall(), so nothing in 8,000 lines ever exercised a request
#     that arrives slowly, and the class attribute that was supposed to
#     bound one was an idle timeout wearing the word "deadline" in its
#     comment.
#   * the leading empty line: every raw payload in this file starts at
#     the method token. The one shape RFC 7230 §3.5 says a server SHOULD
#     tolerate was never sent.
#   * the unroutable target: it WAS covered, by a test that asserted the
#     defect. See
#     test_an_absolute_form_target_is_answered_once_and_the_socket_goes.
#
# Every test here drives raw sockets and every one of them fails against
# the app.py that preceded it.
# ======================================================================
class TestTheDripIsBoundedByAWallClock(ServerCase):
    """An idle timeout is not a request budget, and this one was not one.

    MEASURED BEFORE THE FIX, against this server, with no credential and
    no valid route needed: a connection that sent
    ``GET /api/mint/status HTTP/1.1\\r\\nHost: 127.0.0.1\\r\\n`` and then
    ONE BYTE EVERY TWO SECONDS into the header block held a handler thread
    and a file descriptor for as long as it kept dripping -- 41 seconds in
    the run that produced this class, past 100 seconds in the verifier's.
    ``Handler.timeout`` is applied per recv, so every one of those bytes
    reset it, and GuiServer is a ThreadingHTTPServer, which caps neither
    connections nor threads: N such sockets are N parked threads, and the
    cost to mount it is one byte every two seconds per socket.

    The fix is the mint's, imported and not rewritten: ``_DeadlineRaw``
    under ``io.BufferedReader``, which is the only position that covers
    the HEADER phase as well as the body.
    """

    #: Clamped for the test, so watching a drip die costs a second instead
    #: of ten. The SHIPPED value is asserted separately below, because a
    #: test that only ever sets its own is a test of nothing.
    CLAMP = 1.0

    def drip(self, head, step=0.15, limit=8.0):
        """Send `head`, then one byte at a time. Returns (held, closed).

        The drip is deliberately far faster than the idle timeout: if
        ``Handler.timeout`` were what ended this connection the test would
        prove nothing.
        """
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=20.0)
        self.addCleanup(sock.close)
        sock.sendall(head)
        started = time.monotonic()
        closed = False
        while time.monotonic() - started < limit:
            time.sleep(step)
            try:
                sock.sendall(b"X")
            except OSError:
                closed = True           # the server hung up mid-drip
                break
            sock.settimeout(0.05)
            try:
                if sock.recv(65536) == b"":
                    closed = True
                    break
                while sock.recv(65536):   # an answer arrived; drain to EOF
                    pass
                closed = True
                break
            except (socket.timeout, TimeoutError):
                pass
        return time.monotonic() - started, closed

    def clamp(self):
        original = gui_app.Handler.request_timeout
        self.assertIsNotNone(original)
        gui_app.Handler.request_timeout = self.CLAMP
        self.addCleanup(setattr, gui_app.Handler, "request_timeout", original)
        # The idle timeout keeps its shipped value on purpose.
        self.assertGreaterEqual(gui_app.Handler.timeout, 5)

    def test_a_drip_into_the_header_block_is_ended_by_the_deadline(self):
        """The measured finding, with no credential anywhere in it.

        The header phase is the half an idle timeout cannot reach and the
        half no authentication runs in front of: this connection never
        completes a request line, so ``_authorize`` never runs and the
        peer never has to be anybody.
        """
        self.clamp()
        held, closed = self.drip(b"GET /api/mint/status HTTP/1.1\r\n"
                                 b"Host: 127.0.0.1\r\n")
        self.assertTrue(closed,
                        "a header-block drip held the connection, and its "
                        "thread, for %.1fs and counting" % held)
        self.assertLess(held, 5.0,
                        "the request outlived its deadline: %.1fs" % held)

    def test_a_drip_into_the_body_is_ended_too(self):
        """The same bound, one phase down, on an authenticated POST.

        ``Content-Length`` is exactly MAX_BODY_BYTES, so the byte cap
        never fires and only a wall clock can end this.
        """
        self.clamp()
        head = ("POST /api/wallet/create HTTP/1.1\r\n"
                "Host: 127.0.0.1:%d\r\nCookie: %s\r\n"
                "Content-Type: application/json\r\n"
                "Content-Length: %d\r\n\r\n"
                % (self.port, self.cookie, gui_app.MAX_BODY_BYTES)).encode()
        held, closed = self.drip(head)
        self.assertTrue(closed,
                        "a dripped body held the connection for %.1fs" % held)
        self.assertLess(held, 5.0,
                        "the body outlived its deadline: %.1fs" % held)

    def test_the_deadline_is_the_shipped_default_and_it_is_finite(self):
        """Not something only a test sets, and not something only a
        deployment sets either."""
        self.assertEqual(gui_app.Handler.request_timeout,
                         gui_app.REQUEST_DEADLINE_S)
        self.assertGreater(gui_app.REQUEST_DEADLINE_S, 0)
        self.assertLessEqual(gui_app.REQUEST_DEADLINE_S, 120)

    def test_the_budget_is_sized_against_the_page_and_the_body_cap(self):
        """Why TEN and not the mint's thirty, asserted rather than argued.

        Two bounds, both of them properties of THIS server:

          * page.html aborts its own fetch and shows its own message
            instead of whatever this server determined, so a request whose
            READ alone can outlast that is a request whose answer nothing
            will read. Each budget is at most half of the page's patience,
            leaving the other half to the other direction.
          * require_loopback() refuses to bind anything the world can
            reach, so every request this server will ever read is written
            by a process on this machine. The floor the budget implies
            against a full MAX_BODY_BYTES body is asserted to be modest --
            far below loopback, far above any drip.

        AND THE PAGE'S PATIENCE IS NOT ONE NUMBER, which is what the
        version of this test that stood here got wrong: it pinned against
        PAGE_ABORT_S alone, and PAGE_ABORT_S is ``TIMEOUTS.default``,
        which covers nineteen of the twenty-one routes. /api/mint/start
        waits 90s and /api/mint/stop 70s. The premise a budget is argued
        from has to be the whole object, so this reads the whole object
        and pins against the SMALLEST of the three -- which is the default
        today, so the number is unchanged and the ARGUMENT is now true.
        A page that shortens any of the three fails here.
        """
        declared = page_timeouts_ms()
        self.assertIn("default", declared)
        self.assertEqual(gui_app.PAGE_ABORT_S, declared["default"] / 1000.0,
                         "app.py's PAGE_ABORT_S is not page.html's default")
        shortest = min(declared.values()) / 1000.0
        for name, budget in (("read", gui_app.REQUEST_DEADLINE_S),
                             ("write", gui_app.RESPONSE_BUDGET_S)):
            self.assertLessEqual(
                budget, shortest / 2,
                "the %s budget (%.1fs) is more than half the page's "
                "shortest patience (%.1fs, from TIMEOUTS %r)"
                % (name, budget, shortest, declared))
        # Both halves together must still fit inside it, or a request that
        # spends its whole read budget has no answering time left at all.
        self.assertLessEqual(
            gui_app.REQUEST_DEADLINE_S + gui_app.RESPONSE_BUDGET_S, shortest,
            "read budget + write budget outlasts the page's own abort")
        floor_bytes_per_second = (gui_app.MAX_BODY_BYTES
                                  / gui_app.REQUEST_DEADLINE_S)
        self.assertLess(floor_bytes_per_second, 1 << 20,
                        "the budget demands more than a megabyte a second "
                        "of a local client")
        self.assertGreater(floor_bytes_per_second, 1 << 10,
                           "the budget is so loose a drip fits inside it")

    def test_the_idle_timeout_is_a_ceiling_over_both_budgets(self):
        """The ordering, pinned so an edit cannot invert it.

        WHAT THIS TEST USED TO BE CALLED, because the rename is the
        finding. It was
        ``test_the_read_side_is_the_deadline_and_the_write_side_is_the_idle``
        and its docstring asserted that ``timeout`` "remains the bound on
        a blocked WRITE". It opened no socket and drove no write, and the
        claim in its name was FALSE: ``timeout`` is applied per sendall,
        so a peer that queues responses and drains them slowly gets a
        fresh window for each one -- measured at 200 seconds and still
        running on a 2000-deep pipeline. A green test whose NAME asserts a
        bound nobody measured is the exact defect this round was convened
        to remove, reproduced inside the fix for it.

        So the write-side claim is gone from here and lives in
        TestTheWriteSideIsABudgetAndNotAWindow, which drives it on live
        sockets. What is left here is the arithmetic that has to hold
        between the three numbers, and only that:

        ``timeout`` is the ceiling on ONE syscall and must be the largest,
        so it never pre-empts either budget; each budget is the operative
        bound on its own side. If someone later raises the read deadline
        above the idle timeout, the header phase goes back to being
        covered by an idle timeout for the window between them -- which is
        the original defect. This fails first.
        """
        self.assertLess(gui_app.Handler.request_timeout,
                        gui_app.Handler.timeout,
                        "the read budget no longer beats the idle timeout: "
                        "the header phase is back under an idle bound")
        self.assertLess(gui_app.Handler.write_budget,
                        gui_app.Handler.timeout,
                        "the write budget no longer beats the idle timeout")
        # And the read budget must still clear the page's own poll
        # interval, or an idle keep-alive socket is torn down under a page
        # that is about to use it. page.html's fastest poll is four
        # seconds.
        self.assertGreater(gui_app.Handler.request_timeout, 4.0)

    def test_the_deadline_is_disarmed_between_requests(self):
        """Each request on a kept connection gets a WHOLE budget, and the
        one it was armed for is the one that spends it.

        WHAT THIS TEST USED TO BE, because it is the second of the two
        this round shipped that certified nothing. It sent two requests
        back to back down one socket and asserted both were answered --
        with a docstring claiming "a pause between them longer than a
        clamped budget" and NO SLEEP ANYWHERE IN THE LOOP. It was verified
        to pass with the ``self.request_deadline = None`` disarm deleted,
        because handle_one_request re-arms at the top of every iteration
        and whether the finally disarms is unobservable from a socket.

        So both halves are driven here, each by the thing that can see it:

          * THE RE-ARM, from outside. Four requests down one connection
            with a real one-second pause before each, against a budget
            clamped to two seconds. Every wait and every read is inside
            one budget; the RUN is not. A deadline armed once per
            connection instead of once per request expires during the
            third wait and answers 408 instead of 200, and a budget that
            is never re-armed at all does the same.
          * THE DISARM, from inside, because that is where it is visible
            at all. handle_one_request is wrapped and the deadline is read
            back the instant it returns: it must be None every time. Delete
            the disarm and this half fails; nothing driven over a socket
            can fail for it.
        """
        original = gui_app.Handler.request_timeout
        gui_app.Handler.request_timeout = 2.0
        self.addCleanup(setattr, gui_app.Handler, "request_timeout", original)

        left_armed = []
        unwrapped = gui_app.Handler.handle_one_request

        def watch(handler):
            try:
                return unwrapped(handler)
            finally:
                left_armed.append(handler.request_deadline)

        gui_app.Handler.handle_one_request = watch
        self.addCleanup(setattr, gui_app.Handler, "handle_one_request",
                        unwrapped)

        head = ("GET /api/mint/status HTTP/1.1\r\n"
                "Host: 127.0.0.1:%d\r\nCookie: %s\r\n\r\n"
                % (self.port, self.cookie)).encode()
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=20.0)
        self.addCleanup(sock.close)
        data = b""
        for turn in range(4):
            # A REAL pause, which the version of this test that stood here
            # only claimed. One second against a two-second budget: fine
            # per request, and three seconds of it across the run.
            time.sleep(1.0)
            sock.sendall(head)
            deadline = time.monotonic() + 5.0
            want = complete_responses(data) + 1
            while complete_responses(data) < want:
                if time.monotonic() > deadline:
                    break
                sock.settimeout(max(0.05, deadline - time.monotonic()))
                try:
                    chunk = sock.recv(65536)
                except (socket.timeout, TimeoutError):
                    break
                if not chunk:
                    break
                data += chunk
        responses, trailing = split_all_responses(data)
        self.assertEqual(len(responses), 4,
                         "a kept connection lost a request whose own budget "
                         "was never spent: %r" % data[:400])
        self.assertEqual(trailing, b"")
        for response in responses:
            status, _headers, payload = split_response(response)
            self.assertEqual(
                status, 200,
                "a request inside its own budget was refused (%d): %r"
                % (status, payload[:200]))
        # The inside half. Four requests were answered, so at least four
        # turns through handle_one_request have finished.
        self.assertGreaterEqual(len(left_armed), 4, left_armed)
        self.assertEqual(
            [seen for seen in left_armed if seen is not None], [],
            "handle_one_request returned with a deadline still armed: %r "
            "-- state from a finished request, left where the next one "
            "reads it" % (left_armed,))

    def test_the_deadline_reader_is_the_mints_and_there_is_no_second_copy(self):
        """One implementation, imported, and a check that it stays one.

        The whole cause of this round is a transport hardening carried by
        hand from one server to the next, with each hand-carry leaving one
        server behind. app.py imports aicash.mintapi._DeadlineRaw rather
        than reproducing it, so there is one wall clock in this repository
        and not four.

        The second half of this test is what keeps that true: an AST walk
        over app.py for a class of its own that reads from the socket. A
        comment cannot satisfy it and a docstring cannot either.

        AND IT LOOKS FOR MORE THAN ONE METHOD NAME, because the version
        that shipped looked for a class defining literally ``readinto``
        and nothing else -- so a re-implementation spelled any other way
        walked past it: a shim over ``read``, a ``recv_into`` wrapper
        around the socket, or a subclass of the mint's own class that
        overrode the clock. The whole read surface is named here, and so
        is inheritance.

        THE WRITE SIDE IS DELIBERATELY NOT COVERED BY THIS GUARD, and the
        distinction is the point rather than an exemption. ``_DeadlineRaw``
        bounds one request's reads against an absolute instant and there
        is exactly one of those in this repository. ``_BudgetedWriter``
        bounds a connection's writes against an accumulated total, which
        is a different quantity the mint does not have -- so it is a local
        class on purpose, and the guard below insists it stay a WRITER by
        failing if it ever grows a read method.
        """
        from aicash import mintapi as real_mintapi
        self.assertIs(gui_app._DeadlineRaw, real_mintapi._DeadlineRaw,
                      "app.py is not using the mint's deadline reader")
        #: Everything a class would have to define to sit under (or
        #: around, or instead of) the buffered reader and hold a clock of
        #: its own. Any one of them in a class in app.py is a second
        #: implementation of the bound the mint already owns.
        reading = {"readinto", "readinto1", "read", "read1", "readline",
                   "readlines", "recv", "recv_into", "peek"}
        with open(gui_app.__file__, encoding="utf-8") as handle:
            source = ast.parse(handle.read())
        homegrown, inherited = [], []
        for node in ast.walk(source):
            if not isinstance(node, ast.ClassDef):
                continue
            methods = {body.name for body in node.body
                       if isinstance(body, (ast.FunctionDef,
                                            ast.AsyncFunctionDef))}
            overlap = sorted(methods & reading)
            if overlap:
                homegrown.append("%s (%s)" % (node.name, ", ".join(overlap)))
            for base in node.bases:
                # `class X(_DeadlineRaw)` and `class X(mintapi._DeadlineRaw)`
                name = getattr(base, "id", None) or getattr(base, "attr", None)
                if name == "_DeadlineRaw":
                    inherited.append(node.name)
        self.assertEqual(homegrown, [],
                         "app.py grew its own socket reader (%s); there is "
                         "one in aicash.mintapi and a second copy is how "
                         "this defect class survived four rounds"
                         % "; ".join(homegrown))
        self.assertEqual(inherited, [],
                         "app.py subclasses the mint's deadline reader (%s); "
                         "an override of readinto there is a second clock "
                         "wearing the first one's name"
                         % ", ".join(inherited))

    def test_the_reader_is_actually_plugged_in(self):
        """The import and the class attribute prove nothing on their own.

        setup() is what puts the deadline layer under the buffered
        reader, and a handler whose rfile is the stock one has a comment
        and no bound. Asserted on a live connection's own handler.
        """
        seen = {}
        original = gui_app.Handler._handle

        def capture(handler, method):
            seen["rfile"] = handler.rfile
            seen["raw"] = getattr(handler.rfile, "raw", None)
            seen["deadline"] = handler.request_deadline
            return original(handler, method)

        gui_app.Handler._handle = capture
        self.addCleanup(setattr, gui_app.Handler, "_handle", original)
        status, _obj, _raw = self.call("GET", "/api/mint/status")
        self.assertEqual(status, 200)
        self.assertIsInstance(seen["rfile"], io.BufferedReader)
        self.assertIsInstance(seen["raw"], gui_app._DeadlineRaw)
        self.assertIsNotNone(seen["deadline"],
                             "the deadline was not armed for a live request")


class TestTheWriteSideIsABudgetAndNotAWindow(ServerCase):
    """A timeout that resets is not a budget -- one direction over.

    THE FINDING, MEASURED AGAINST A LIVE ``gui.app.serve()``. The round
    before this one put a wall clock under the READ side and left a
    comment saying ``Handler.timeout`` was "the bound on a blocked WRITE".
    It was not. socketserver applies ``timeout`` to the socket, so it is
    the ceiling on ONE ``sendall``, and a peer that accepts a few
    kilobytes inside every window gets a fresh window for every response
    it queued:

        one socket, 2000 pipelined `GET /` with a valid session cookie
        (226 KB of request), peer draining ~10 KB/s -- handler thread and
        fd STILL HELD at 200.0 seconds and 2,006,461 bytes delivered when
        the measurement was capped.

    And when a write finally did time out, ``_handle``'s blanket
    ``except Exception`` printed a traceback on the operator's terminal
    and composed a 500 onto a socket that already carried a partial
    response -- a second response after a first, buying the peer another
    whole window: 65.0 seconds of hold on a 400-deep pipeline.

    GuiServer is a ThreadingHTTPServer with no connection or thread cap,
    so N such sockets are N parked threads, and the cost to mount it is
    one socket and a slow reader. This is the server that is on by default
    with an operator in front of it.

    THE FIX IS A CUMULATIVE BUDGET THAT BELONGS TO THE CONNECTION
    (``_BudgetedWriter`` + ``Handler.write_budget``), because that is the
    only scope a pipeline cannot multiply: the peer chooses how many
    responses it queues, so any per-response bound is multiplied by a
    number the peer picks. AFTER, same harness, same rate: 11.5 seconds
    and 65,213 bytes, thread and fd back. With the budget removed from the
    same tree: 55.5 seconds and 401,213 bytes.

    Every test below drives a real socket. None of them asserts the bound
    by comparing two constants, which is how the claim this class replaces
    came to be green and false at the same time.
    """

    #: Clamped so watching a slow drain die costs a second instead of ten.
    #: The SHIPPED value is asserted separately below.
    CLAMP = 1.0

    def clamp(self, budget=CLAMP):
        original = gui_app.Handler.write_budget
        gui_app.Handler.write_budget = budget
        self.addCleanup(setattr, gui_app.Handler, "write_budget", original)
        # The idle timeout keeps its shipped value: if `timeout` were what
        # ended these connections the tests would prove nothing.
        self.assertGreaterEqual(gui_app.Handler.timeout, 5)

    def watch_handlers(self):
        """When each connection's handler thread LET GO, by client port.

        THE THING BEING BOUNDED IS A SERVER-SIDE RESOURCE, and measuring
        it from the client would measure the wrong end. A slow peer still
        has megabytes of already-queued response sitting in the kernel
        when the server hangs up -- the socket buffer autotunes into the
        megabytes on loopback -- so the client goes on receiving for
        minutes after the handler thread and the fd are gone. The finding
        was "handler thread and fd STILL HELD at 200.0s"; this watches
        exactly that, through ``finish()``, which socketserver calls in a
        finally when the handler is done with the connection.
        """
        released = {}
        original = gui_app.Handler.finish

        def watch(handler):
            try:
                return original(handler)
            finally:
                released[handler.client_address[1]] = time.monotonic()

        gui_app.Handler.finish = watch
        self.addCleanup(setattr, gui_app.Handler, "finish", original)
        return released

    def drain(self, depth, rate=8192, cap=12.0, cookie=True):
        """`depth` pipelined ``GET /``, read at about `rate` bytes/second.

        Returns ``(held, released, got, sock)``: how long the handler
        thread lived, whether it let go at all inside `cap`, how many
        bytes the slow peer had taken by then, and the socket, still open,
        for a test that wants to drain the rest.

        The peer always makes progress -- it reads a slice every quarter
        second, far inside the idle timeout -- which is the whole point: a
        bound that only fires when a peer stops reading ENTIRELY is not a
        bound on this shape. ``/`` is the operator page, ~261 KiB, so one
        response alone is half a minute at this rate.
        """
        released = self.watch_handlers()
        head = "GET / HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n" % self.port
        if cookie:
            head += "Cookie: %s\r\n" % self.cookie
        payload = (head + "\r\n").encode() * depth
        sock = socket.create_connection(("127.0.0.1", self.port),
                                        timeout=cap + 5.0)
        self.addCleanup(sock.close)
        # A small receive buffer so this peer really is slow rather than
        # merely polite.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8192)
        mine = sock.getsockname()[1]
        sock.sendall(payload)
        started = time.monotonic()
        step, got = 0.25, 0
        want = max(1, int(rate * step))
        nxt = started + step
        while time.monotonic() - started < cap:
            if mine in released:
                break
            now = time.monotonic()
            if now < nxt:
                time.sleep(min(0.05, nxt - now))
                continue
            nxt += step
            read = 0
            while read < want:
                sock.settimeout(0.05)
                try:
                    part = sock.recv(min(4096, want - read))
                except (socket.timeout, TimeoutError):
                    break
                except OSError:             # the server reset us
                    break
                if not part:
                    break
                got += len(part)
                read += len(part)
        letgo = released.get(mine)
        held = (letgo - started) if letgo else (time.monotonic() - started)
        return held, letgo is not None, got, sock

    def rest_of_it(self, sock, cap=20.0):
        """Everything still on the wire after the handler let go, read as
        fast as the kernel will give it up."""
        data = b""
        deadline = time.monotonic() + cap
        while time.monotonic() < deadline:
            sock.settimeout(max(0.05, deadline - time.monotonic()))
            try:
                part = sock.recv(1 << 20)
            except (socket.timeout, TimeoutError):
                break
            except OSError:
                break
            if not part:
                break
            data += part
        return data

    def test_a_slow_drain_is_ended_by_the_budget(self):
        """The measured finding, on an authenticated pipeline.

        Forty queued responses, a peer reading steadily but slowly, and a
        socket the server must let go of. Before the budget this shape ran
        past 200 seconds; the assertion here is against a clamp, so it
        fails in seconds rather than in minutes.
        """
        self.clamp()
        held, released, got, _sock = self.drain(depth=60)
        self.assertTrue(
            released,
            "a slow-drain pipeline held the handler thread, and its fd, for "
            "%.1fs and counting (%d bytes taken by the peer)" % (held, got))
        self.assertLess(
            held, 6.0,
            "the write side outlived its budget: %.1fs against a %.1fs "
            "budget" % (held, self.CLAMP))

    def test_the_budget_is_what_ends_it_and_nothing_else(self):
        """THE NEGATIVE CONTROL, which is the half that makes the test
        above mean something.

        Same peer, same rate, same depth, with only ``write_budget``
        removed -- which is the fix reverted in place. The connection must
        still be alive at a point where the budgeted one was long gone.
        Without this, "the socket closed" could be the idle timeout, a
        full send buffer, or the peer's own bookkeeping.
        """
        self.clamp(budget=None)
        held, released, got, _sock = self.drain(depth=60, cap=5.0)
        self.assertFalse(
            released,
            "with the budget removed the handler let go anyway after %.1fs "
            "(%d bytes) -- then the test above is not measuring the budget"
            % (held, got))

    def test_the_hold_does_not_scale_with_the_depth_of_the_pipeline(self):
        """The reason the budget belongs to the CONNECTION.

        A per-response bound would be multiplied by a number the PEER
        picks: forty responses, forty windows. Ten deep and four hundred
        deep must cost the same wall clock, because the budget is one
        total and not one per answer.
        """
        self.clamp()
        shallow, shallow_released, _g, _s = self.drain(depth=60)
        deep, deep_released, _g2, _s2 = self.drain(depth=2000)
        self.assertTrue(shallow_released, "60-deep held %.1fs" % shallow)
        self.assertTrue(deep_released, "2000-deep held %.1fs" % deep)
        self.assertLess(
            deep, shallow + 4.0,
            "a thirty-fold deeper pipeline bought %.1fs more hold (%.1fs vs "
            "%.1fs): the bound is per response, not per connection"
            % (deep - shallow, deep, shallow))

    def test_a_write_that_runs_out_does_not_answer_twice(self):
        """The recovery shape, which doubled the hold and desynced the
        socket at the same time.

        MEASURED: the first write timed out inside ``_send`` ->
        ``end_headers``; ``_handle``'s blanket ``except`` then printed a
        traceback and called ``_error(500, ...)``, writing a SECOND,
        complete response onto a socket that already carried a partial
        one, and burning another full window doing it -- 65.0s total on a
        400-deep pipeline. ``_answered`` was already True and that clause
        never read it.

        So: no 500 anywhere on the wire, no ``internal_error`` envelope
        behind a partial response, nothing on the operator's terminal for
        what is a peer-side condition, and no second window.
        """
        self.clamp(budget=0.5)
        noise, saved = io.StringIO(), sys.stderr
        sys.stderr = noise
        try:
            held, released, _got, sock = self.drain(depth=60, cap=10.0)
            data = self.rest_of_it(sock)
            time.sleep(0.3)
        finally:
            sys.stderr = saved
        self.assertTrue(released,
                        "the handler was still held at %.1fs" % held)
        self.assertLess(held, 4.0,
                        "the recovery bought a second window: %.1fs" % held)
        self.assertNotIn(b"HTTP/1.1 500", data,
                         "a 500 was written onto a socket that already "
                         "carried a response")
        # The ENVELOPE, not the bare word: page.html's own JavaScript
        # mentions `internal_error` by name, and the page is what these
        # sixty responses are made of.
        self.assertNotIn(b'"reason": "internal_error"', data,
                         "a peer that stopped reading was reported to "
                         "itself as this server failing")
        self.assertNotIn("Traceback", noise.getvalue(),
                         "a peer-side condition printed a traceback on the "
                         "operator's terminal: %s" % noise.getvalue()[:400])
        responses, _trailing = split_all_responses(data)
        for response in responses:
            status, _headers, _body = split_response(response)
            self.assertEqual(status, 200, response[:120])

    def test_the_writer_is_actually_plugged_in(self):
        """The class and the constant prove nothing on their own.

        setup() is what puts the budget layer over the socket, and a
        handler whose wfile is the stock ``_SocketWriter`` has a comment
        and no bound. Asserted on a live connection's own handler.
        """
        seen = {}
        original = gui_app.Handler._handle

        def capture(handler, method):
            seen["wfile"] = handler.wfile
            seen["budget"] = handler.write_budget
            return original(handler, method)

        gui_app.Handler._handle = capture
        self.addCleanup(setattr, gui_app.Handler, "_handle", original)
        status, _obj, _raw = self.call("GET", "/api/mint/status")
        self.assertEqual(status, 200)
        self.assertIsInstance(seen["wfile"], gui_app._BudgetedWriter,
                              "the response stream is not under a budget")
        self.assertIsNotNone(seen["budget"],
                             "the budget was disabled for a live request")

    def test_the_budget_belongs_to_the_connection_not_to_the_request(self):
        """Where ``write_spent`` is reset is the whole of the fix.

        Reset per REQUEST -- in handle_one_request, which is where a
        reader reaching for symmetry with ``request_deadline`` would put
        it -- and the peer gets the multiplier back: every queued response
        starts the budget again. It is reset in setup(), which runs once
        per CONNECTION, and this is what says so: across three requests on
        one kept socket the spend only ever goes up, and a fresh
        connection starts at zero.
        """
        seen = []
        original = gui_app.Handler._handle

        def capture(handler, method):
            seen.append((id(handler), handler.write_spent))
            return original(handler, method)

        gui_app.Handler._handle = capture
        self.addCleanup(setattr, gui_app.Handler, "_handle", original)

        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        self.addCleanup(conn.close)
        for _ in range(3):
            conn.request("GET", "/api/mint/status",
                         headers={"Cookie": self.cookie})
            response = conn.getresponse()
            self.assertEqual(response.status, 200)
            response.read()
        kept = [spent for handler, spent in seen
                if handler == seen[0][0]]
        self.assertEqual(len(kept), 3,
                         "the three requests did not share one connection: "
                         "%r" % (seen,))
        self.assertEqual(kept[0], 0.0,
                         "a new connection did not start with a whole "
                         "budget: %r" % (kept,))
        self.assertEqual(sorted(kept), kept,
                         "the write spend went DOWN between two requests on "
                         "one connection -- the budget is being reset per "
                         "request, which is the scope a pipeline multiplies: "
                         "%r" % (kept,))
        self.assertGreater(kept[-1], 0.0,
                           "two answered requests spent no measurable write "
                           "time at all; nothing is being charged: %r"
                           % (kept,))
        # ...and a second connection is a second budget, not a continuation
        # of the first.
        before = len(seen)
        status, _obj, _raw = self.call("GET", "/api/mint/status")
        self.assertEqual(status, 200)
        self.assertEqual(seen[before][1], 0.0,
                         "a fresh connection inherited another connection's "
                         "spend: %r" % (seen[before],))

    def test_the_budget_is_the_shipped_default_and_it_is_finite(self):
        """Not something only a test sets, and not something only a
        deployment sets either."""
        self.assertEqual(gui_app.Handler.write_budget,
                         gui_app.RESPONSE_BUDGET_S)
        self.assertGreater(gui_app.RESPONSE_BUDGET_S, 0)
        self.assertLessEqual(gui_app.RESPONSE_BUDGET_S, 120)


class TestEveryTransportRefusalGoesThroughOneDoor(ServerCase):
    """One funnel, because the mint wrote one down as the countermeasure.

    impl/aicash/mintapi.py routes every refusal of a request that never
    became a call through ``_Handler._refuse_transport(code, reason)``,
    with the reason spelled out in its docstring: "One place, so the three
    refusals below cannot drift into three spellings of 'close and answer
    400' -- which is the shape this round exists to remove."

    THE MINT'S CHECK WAS CARRIED HERE LAST ROUND AND THE MINT'S FUNNEL WAS
    NOT. This file had two hand-written sites in two different methods,
    each spelling ``self.close_connection = True`` and then
    ``self._error(400, <reason>, <prose>)``, plus a third in
    ``send_error`` that also had to remember to move ``request_version``
    off HTTP/0.9 -- and this round was about to add a fourth and a fifth.
    Three things have to happen together on every one of them (close the
    connection, get off a version with no status line, fill in the two
    fields ``send_response`` reads) and every hand-written site is a site
    that can forget one. Forgetting the version one emits a NAKED BODY,
    which is the precise defect this round is closing.

    So the assertions below are structural, over app.py's own AST: the
    door exists, every transport reason word goes through it, and nothing
    goes around it.
    """

    #: The reason words that mean "this never became a call". Each one is
    #: answered by a refusal that must close the connection.
    TRANSPORT_REASONS = {"bad_version", "bad_request_target",
                         "bad_request_line", "request_timeout"}

    def app_source(self):
        with open(gui_app.__file__, encoding="utf-8") as handle:
            return ast.parse(handle.read())

    def calls_to(self, tree, attribute):
        """Every ``self.<attribute>(...)`` call in app.py, with its args."""
        found = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if (isinstance(func, ast.Attribute) and func.attr == attribute
                    and isinstance(func.value, ast.Name)
                    and func.value.id == "self"):
                found.append(node)
        return found

    def test_the_door_exists_and_does_all_three_things(self):
        """A funnel that only closes the connection is not the funnel."""
        self.assertTrue(hasattr(gui_app.Handler, "_refuse_transport"),
                        "app.py has no transport-refusal funnel at all")
        source = inspect.getsource(gui_app.Handler._refuse_transport)
        self.assertIn("close_connection", source)
        self.assertIn("request_version", source,
                      "the funnel does not move a 0.9 request off a version "
                      "where send_response is a no-op -- which is how a "
                      "refusal goes out as a naked body")
        self.assertIn("command", source,
                      "the funnel does not fill in the field _send reads to "
                      "ask whether this was a HEAD")

    def test_every_transport_reason_is_answered_through_it(self):
        """Each of the four words reaches the wire through the funnel."""
        tree = self.app_source()
        through = set()
        for call in self.calls_to(tree, "_refuse_transport"):
            for arg in call.args:
                if isinstance(arg, ast.Constant) and arg.value in \
                        self.TRANSPORT_REASONS:
                    through.add(arg.value)
        self.assertEqual(
            through, self.TRANSPORT_REASONS,
            "these transport refusals do not go through the funnel: %s"
            % ", ".join(sorted(self.TRANSPORT_REASONS - through)))

    def test_nothing_goes_around_it(self):
        """The half that keeps the test above from rotting.

        A future edit that adds a fifth refusal by hand -- ``_error(400,
        "bad_version", ...)`` next to a ``close_connection`` of its own --
        passes the test above (the word still appears at the funnel too)
        and fails here.
        """
        tree = self.app_source()
        around = []
        for call in self.calls_to(tree, "_error"):
            for arg in call.args:
                if isinstance(arg, ast.Constant) and arg.value in \
                        self.TRANSPORT_REASONS:
                    around.append((arg.value, call.lineno))
        self.assertEqual(
            around, [],
            "a transport refusal is spelled out by hand instead of going "
            "through _refuse_transport: %s"
            % ", ".join("%s at app.py:%d" % pair for pair in around))

    def test_the_refusals_agree_on_the_wire(self):
        """Structure is not behaviour, so the four are also driven.

        Each shape below is a request that never became a call. All four
        must come back as ONE framed response with a length, with the
        hang-up announced, carrying this server's envelope and a cause
        from the closed set -- and the socket must go. A refusal that
        forgot one of the funnel's three jobs shows up here as a naked
        body, a kept socket, or no answer at all.
        """
        original = gui_app.Handler.request_timeout
        gui_app.Handler.request_timeout = 1.0
        self.addCleanup(setattr, gui_app.Handler, "request_timeout", original)
        host = "Host: 127.0.0.1:%d\r\n" % self.port
        cases = (
            ("bad_version", 400, b"GET /api/mint/status\r\n\r\n"),
            ("bad_request_target", 400,
             ("GET http://127.0.0.1:%d/api/mint/status HTTP/1.1\r\n%s\r\n"
              % (self.port, host)).encode()),
            ("bad_request_line", 400,
             ("\r\n\r\nGET /api/mint/status HTTP/1.1\r\n%s\r\n"
              % host).encode()),
            # No terminator at all: answered when the clock runs out.
            ("request_timeout", 408, b"GET /api/mint/status HTTP/1.1"),
        )
        for reason, code, payload in cases:
            with self.subTest(reason=reason):
                data, closed = raw_exchange(self.port, payload, wait=6.0)
                self.assertNotEqual(data, b"",
                                    "%s got no answer at all" % reason)
                responses, trailing = split_all_responses(data)
                self.assertEqual(len(responses), 1,
                                 "%s: %r" % (reason, data[:200]))
                self.assertEqual(trailing, b"",
                                 "%s left trailing octets: %r"
                                 % (reason, trailing[:120]))
                status, headers, body = split_response(responses[0])
                self.assertEqual(status, code, "%s: %r" % (reason, body[:200]))
                self.assertIn("content-length", headers, reason)
                self.assertEqual(headers.get("connection"), "close",
                                 "%s hung up without saying so: %r"
                                 % (reason, headers))
                obj = json.loads(body)
                self.assertEqual(obj["error"]["reason"], reason, body[:200])
                self.assertIn(obj["error"]["cause"], gui_app.CAUSES, reason)
                self.assertTrue(closed, "%s kept the socket" % reason)


class TestARequestThatRanOutOfClockIsStillAnswered(ServerCase):
    """The last two shapes on this server that got NO STATUS LINE.

    MEASURED BEFORE THIS, on all twenty-one routes, with a valid session
    cookie:

        GET <route> HTTP/1.1                      (request line never
                                                   terminated)
        GET <route> HTTP/1.1\\r\\nHost: x\\r\\n        (header block never
                                                   terminated)

    ZERO BYTES in both cases, socket dropped at the deadline. The read
    budget was doing its job -- the thread and the fd came back at ten
    seconds -- but the caller was told nothing, and "nothing" is the one
    outcome this round's bar names outright: a caller cannot tell it from
    a crash, a wrong port, or a server that never existed.

    ``BaseHTTPRequestHandler`` wraps its whole request in
    ``except TimeoutError: close and return``, silently, so the answer
    cannot come from the base class; ``_answer_an_unfinished_request`` is
    where it comes from. 408 is what RFC 7231 6.5.7 defines for exactly
    this, and it says to send ``Connection: close`` with it.

    A DELIBERATE DIVERGENCE FROM THE MINT, written down rather than
    discovered later: impl/aicash/mintapi.py drops these two shapes, and
    this file does not own that. The GUI is the server an operator sits in
    front of and the one that is on by default, and answering is strictly
    more than dropping -- but it is a transport decision this server now
    makes alone, and the honest place for that sentence is here, next to
    the tests that prove it.
    """

    #: Clamped so watching a request run out of clock costs a second
    #: instead of ten. The SHIPPED value is pinned in
    #: TestTheDripIsBoundedByAWallClock.
    CLAMP = 1.0

    def clamp(self):
        original = gui_app.Handler.request_timeout
        gui_app.Handler.request_timeout = self.CLAMP
        self.addCleanup(setattr, gui_app.Handler, "request_timeout", original)
        self.assertGreaterEqual(gui_app.Handler.timeout, 5)

    def routes(self):
        api = sorted(gui_app.ROUTES)
        return ([("GET", "/"), ("HEAD", "/"), ("GET", "/index.html"),
                 ("GET", "/favicon.ico")] + api)

    def stall(self, payload, cap=6.0):
        """Send a partial request and then say nothing. (held, data, closed)."""
        sock = socket.create_connection(("127.0.0.1", self.port),
                                        timeout=cap + 2.0)
        self.addCleanup(sock.close)
        started = time.monotonic()
        data, closed = b"", False
        try:
            sock.sendall(payload)
            while time.monotonic() - started < cap:
                sock.settimeout(max(0.05, cap - (time.monotonic() - started)))
                try:
                    part = sock.recv(65536)
                except (socket.timeout, TimeoutError):
                    break
                if not part:
                    closed = True
                    break
                data += part
        except OSError:
            closed = True
        return time.monotonic() - started, data, closed

    def assert_framed_408(self, data, label, head_request=False):
        """One framed 408, a length on it, and the hang-up announced.

        ``head_request`` is about WHEN the clock ran out, not about what
        the caller typed. A request line that never terminated leaves this
        server with no method at all -- it never read one -- so its
        refusal carries a body even if the caller meant HEAD. A header
        block that never terminated leaves the method parsed, so a HEAD is
        answered the way a HEAD must be: headers, a Content-Length, and no
        octets after them.
        """
        responses, trailing = split_all_responses(data, head_request)
        self.assertEqual(len(responses), 1,
                         "%s got %d responses, not one: %r"
                         % (label, len(responses), data[:200]))
        self.assertEqual(trailing, b"", "%s: %r" % (label, trailing[:120]))
        status, headers, body = split_response(responses[0])
        self.assertEqual(status, 408, "%s: %r" % (label, body[:200]))
        self.assertEqual(headers.get("connection"), "close",
                         "%s did not announce the hang-up: %r"
                         % (label, headers))
        self.assertIn("content-length", headers, label)
        if head_request:
            self.assertEqual(body, b"", "%s: a HEAD was answered with a "
                                        "body: %r" % (label, body[:120]))
            return
        obj = json.loads(body)
        self.assertEqual(obj["error"]["reason"], "request_timeout", label)
        self.assertIn(obj["error"]["cause"], gui_app.CAUSES, label)
        self.assertNotIn(b"Traceback", body)

    def test_a_request_line_that_never_ends_is_answered_on_every_route(self):
        """No CRLF, ever. Twenty-one routes, one answer each.

        Every route, not one: a fix proven on a single route is how this
        project's signature defect keeps surviving, and the shape is
        refused before any route runs, so a route-dependent answer here
        would itself be the finding.
        """
        self.clamp()
        for method, path in self.routes():
            with self.subTest(method=method, path=path):
                held, data, closed = self.stall(
                    ("%s %s HTTP/1.1" % (method, path)).encode())
                self.assertNotEqual(
                    data, b"",
                    "%s %s: zero bytes and a dropped socket after %.1fs"
                    % (method, path, held))
                self.assert_framed_408(data, "%s %s" % (method, path))
                self.assertTrue(closed, "%s %s kept the socket" % (method, path))

    def test_a_header_block_that_never_ends_is_answered_on_every_route(self):
        """A complete request line, a header, and then silence."""
        self.clamp()
        for method, path in self.routes():
            with self.subTest(method=method, path=path):
                held, data, closed = self.stall(
                    ("%s %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                     % (method, path, self.port)).encode())
                self.assertNotEqual(
                    data, b"",
                    "%s %s: zero bytes and a dropped socket after %.1fs"
                    % (method, path, held))
                self.assert_framed_408(data, "%s %s" % (method, path),
                                       head_request=method == "HEAD")
                self.assertTrue(closed, "%s %s kept the socket" % (method, path))

    def test_a_drip_that_never_completes_a_request_is_answered_too(self):
        """Not only silence: a peer that keeps the socket warm a byte at a
        time and never finishes the header block gets the same answer,
        because the bound is a wall clock and not idleness."""
        self.clamp()
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=8.0)
        self.addCleanup(sock.close)
        sock.sendall(b"GET /api/mint/status HTTP/1.1\r\nHost: 127.0.0.1\r\n")
        started, data = time.monotonic(), b""
        while time.monotonic() - started < 6.0:
            try:
                sock.sendall(b"X")
            except OSError:
                break
            time.sleep(0.2)
            sock.settimeout(0.05)
            try:
                part = sock.recv(65536)
            except (socket.timeout, TimeoutError):
                continue
            if not part:
                break
            data += part
        self.assertNotEqual(data, b"", "a drip was dropped without an answer")
        self.assert_framed_408(data, "header drip")

    def test_an_idle_keep_alive_socket_is_answered_and_closed(self):
        """A kept connection that goes quiet past the budget.

        This is the shape two comments in app.py used to describe wrongly
        -- they said `timeout` governed idle keep-alive time, and the
        deadline does, because handle_one_request arms it BEFORE the
        blocking read that waits for the next request line. Measured at
        the shipped values: closed at 10.0s, not 30. page.html polls every
        four seconds, so its own connection never reaches this.
        """
        self.clamp()
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=8.0)
        self.addCleanup(sock.close)
        sock.sendall(("GET /api/mint/status HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                      "Cookie: %s\r\n\r\n"
                      % (self.port, self.cookie)).encode())
        first = b""
        sock.settimeout(6.0)
        while complete_responses(first) < 1:
            part = sock.recv(65536)
            if not part:
                break
            first += part
        status, _headers, _body = split_response(first)
        self.assertEqual(status, 200, first[:200])
        # ...and now say nothing at all.
        started, tail = time.monotonic(), b""
        while time.monotonic() - started < 6.0:
            try:
                part = sock.recv(65536)
            except (socket.timeout, TimeoutError):
                break
            if not part:
                break
            tail += part
        self.assertNotEqual(tail, b"",
                            "an idle kept socket was dropped with no answer")
        self.assert_framed_408(tail, "idle keep-alive")
        self.assertLess(time.monotonic() - started, 5.0)

    def test_with_the_answer_removed_these_shapes_return_zero_bytes(self):
        """THE NEGATIVE CONTROL, and it is the fix reverted in place.

        ``_answer_an_unfinished_request`` neutered, same clamp, same
        bytes: the base class's silent ``except TimeoutError`` is what is
        left, and it writes nothing. That is what these three shapes did
        before this class existed, and it is what the tests above would be
        accepting if they were written to tolerate an empty answer.
        """
        self.clamp()
        original = gui_app.Handler._answer_an_unfinished_request
        gui_app.Handler._answer_an_unfinished_request = lambda handler: None
        self.addCleanup(setattr, gui_app.Handler,
                        "_answer_an_unfinished_request", original)
        for label, payload in (
                ("request line", b"GET /api/mint/status HTTP/1.1"),
                ("header block",
                 b"GET /api/mint/status HTTP/1.1\r\nHost: 127.0.0.1\r\n")):
            with self.subTest(label=label):
                held, data, closed = self.stall(payload)
                self.assertEqual(
                    data, b"",
                    "%s answered without the hook -- then the tests above "
                    "are not measuring it: %r" % (label, data[:120]))
                self.assertTrue(closed,
                                "%s was neither answered nor released after "
                                "%.1fs" % (label, held))

    def test_a_peer_that_says_nothing_and_leaves_is_not_answered(self):
        """The other negative control: 408 is for a clock that ran out,
        not for every connection that ends.

        A peer that opens a socket and closes it without asking anything
        -- which is every speculative connection a browser opens and never
        uses -- has not timed out. There is no request, there is nobody
        waiting, and a status line written into that would mean answering
        every dropped connection on the machine. The EOF arrives long
        before the clamped budget, so the clock never expires and the hook
        never fires.
        """
        self.clamp()
        noise, saved = io.StringIO(), sys.stderr
        sys.stderr = noise
        try:
            sock = socket.create_connection(("127.0.0.1", self.port),
                                            timeout=5.0)
            try:
                sock.shutdown(socket.SHUT_WR)
                sock.settimeout(3.0)
                got = sock.recv(65536)
            finally:
                sock.close()
            time.sleep(0.2)
        finally:
            sys.stderr = saved
        self.assertEqual(got, b"", "an EOF was answered as a timeout")
        self.assertNotIn("Traceback", noise.getvalue())

    def test_nothing_is_printed_on_the_operators_terminal(self):
        """A peer that ran out of clock is a fact about the peer. The
        operator's terminal is for this server's own failures."""
        self.clamp()
        noise, saved = io.StringIO(), sys.stderr
        sys.stderr = noise
        try:
            _held, data, _closed = self.stall(
                b"GET /api/mint/status HTTP/1.1\r\nHost: 127.0.0.1\r\n")
            time.sleep(0.3)
        finally:
            sys.stderr = saved
        self.assert_framed_408(data, "header block")
        self.assertNotIn("Traceback", noise.getvalue(),
                         "a timed-out request printed a traceback: %s"
                         % noise.getvalue()[:400])


class TestOneEmptyLineBeforeTheRequestIsTolerated(ServerCase):
    """RFC 7230 §3.5: a server SHOULD ignore at least one empty line
    received before the request line.

    MEASURED BEFORE THE FIX, on every route, with a valid session cookie:
    ``\\r\\n`` followed by a perfectly well-formed request came back as
    ZERO BYTES and a dropped socket. That is the "no answer at all" class,
    on a shape the standard blesses and that a client which terminated its
    last body with an extra CRLF really emits -- and it was one of three
    cells where the four servers here disagreed about identical bytes:

        server        \\r\\nGET <route> HTTP/1.1 ...
        mint          200, socket kept
        supervision   200, socket kept
        GUI (was)     NOTHING, socket dropped
        console (was) NOTHING, socket dropped

    The fix is the mint's parse_request, carried here.

    THE CONSOLE ROW IS NOW STALE AND IS CORRECTED RATHER THAN LEFT, which
    is the point of writing tables like this down at all. mint_console.py
    landed the same block later on 2026-09-17; a report from earlier in
    this round still says the console drops this shape, and it does not.
    All four servers answer one leading empty line today:

        server        \\r\\n + request      \\r\\n\\r\\n + request
        mint          200, socket kept    NOTHING, socket dropped
        supervision   200, socket kept    NOTHING, socket dropped
        console       200, then closes    200 up to its own cap, then a
                                          framed 400 past it
        this server   200, socket kept    framed 400, socket goes

    The second column is a cell the four do NOT agree on, and it is
    asserted here as a divergence rather than glossed: see
    test_it_is_one_line_and_not_a_loop_and_it_says_so, and app.py's
    parse_request docstring for why this file takes the strictest of the
    three answers.
    """

    #: Every route this server answers, plus the page and the favicon.
    #: The finding was reported against all of them and it is asserted
    #: against all of them: a fix proven on one route is how the framing
    #: rule came to be fixed for a single spelling twice.
    def routes(self):
        api = sorted(gui_app.ROUTES)
        return ([("GET", "/"), ("HEAD", "/"), ("GET", "/index.html"),
                 ("GET", "/favicon.ico")] + api)

    def probe(self, lead, method, path, body=b"", head_request=None):
        """``head_request`` overrides how the answer is FRAMED on the way
        back, which matters on exactly one shape: a refusal taken before
        the request line was ever parsed. The server has no method then --
        it never read one -- so it frames its refusal with a body, and a
        reader told to expect a bodiless answer mis-splits it."""
        head = ("%s %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nCookie: %s\r\n"
                % (method, path, self.port, self.cookie))
        if method == "POST":
            head += ("Content-Type: application/json\r\n"
                     "Content-Length: %d\r\n" % len(body))
        payload = lead + (head + "\r\n").encode() + body
        if head_request is None:
            head_request = method == "HEAD"
        return exchange_and_watch(self.port, payload, expect=1, wait=6.0,
                                  linger=0.4, head_request=head_request)

    def test_every_route_answers_behind_one_leading_crlf(self):
        """DIFFERENTIAL, not a status whitelist: the same bytes with and
        without the empty line must produce the same answer.

        A whitelist ("< 500", "not a 400") would pass a server that turned
        every request behind a CRLF into some other refusal, and most of
        these routes refuse an empty ``{}`` body on their own merits
        anyway. Asserting EQUALITY with the un-prefixed request is the
        claim the RFC actually makes -- one leading empty line changes
        nothing -- and it is checkable on every route without the test
        having to know what any of them do.
        """
        for method, path in self.routes():
            with self.subTest(method=method, path=path):
                plain = self.probe(b"", method, path, b"{}")
                behind = self.probe(b"\r\n", method, path, b"{}")
                for label, (responses, trailing, closed, data) in (
                        ("plain", plain), ("behind one CRLF", behind)):
                    self.assertEqual(
                        len(responses), 1,
                        "%s %s %s got %d responses (%r)"
                        % (method, path, label, len(responses), data[:200]))
                    self.assertEqual(trailing, b"", "%s %s %s: %r"
                                     % (method, path, label, trailing[:120]))
                self.assertEqual(
                    split_response(behind[0][0])[0],
                    split_response(plain[0][0])[0],
                    "%s %s answered differently behind one empty line: %r"
                    % (method, path, behind[0][0][:200]))
                self.assertEqual(
                    split_response(behind[0][0])[2],
                    split_response(plain[0][0])[2],
                    "%s %s: the body changed behind one empty line"
                    % (method, path))
                self.assertEqual(
                    behind[2], plain[2],
                    "%s %s: one leading empty line changed the connection "
                    "decision (closed=%s, plain closed=%s)"
                    % (method, path, behind[2], plain[2]))
                self.assertFalse(
                    behind[2],
                    "%s %s behind one CRLF cost the connection; the mint and "
                    "the supervision profile keep it" % (method, path))

    def test_the_bare_lf_and_bare_cr_spellings_too(self):
        """A stray empty line is not always spelled CRLF.

        A client that terminated a body with a bare LF leaves one, and the
        mint tolerates all three spellings. A fix that covered only the
        one spelling the author happened to send is this project's
        signature defect.
        """
        for lead in (b"\n", b"\r"):
            with self.subTest(lead=lead):
                responses, trailing, closed, data = self.probe(
                    lead, "GET", "/api/mint/status")
                self.assertEqual(len(responses), 1, data[:300])
                self.assertEqual(trailing, b"")
                status, _headers, payload = split_response(responses[0])
                self.assertEqual(status, 200, payload[:200])
                self.assertFalse(closed)

    def test_the_request_behind_it_is_really_read_and_really_routed(self):
        """Not merely "something came back": the right route ran, with the
        right query, and the component saw it.

        A parse_request that swallowed the empty line and then answered
        from a stale request line -- or that answered without dispatching
        at all -- would pass a test that only counted responses.
        """
        FakeWalletOps.calls = []
        payload = (b"\r\n" + ("GET /api/wallet/history?name=alice&limit=7"
                              " HTTP/1.1\r\n"
                              "Host: 127.0.0.1:%d\r\nCookie: %s\r\n\r\n"
                              % (self.port, self.cookie)).encode())
        responses, trailing, _closed, data = exchange_and_watch(
            self.port, payload, expect=1, wait=6.0, linger=0.4)
        self.assertEqual(len(responses), 1, data[:300])
        self.assertEqual(trailing, b"")
        status, _headers, body = split_response(responses[0])
        self.assertEqual(status, 200, body[:300])
        self.assertIn(("history", "alice", 7), FakeWalletOps.calls,
                      "the route behind the empty line never ran, or ran "
                      "with the wrong query: %r" % (FakeWalletOps.calls,))

    def test_it_is_one_line_and_not_a_loop_and_it_says_so(self):
        """"At least one" is what the RFC asks for, and a loop would let a
        peer hold a thread by trickling CRLFs. Stopping at one is right.
        SAYING SO is the part that was missing.

        WHAT THIS TEST USED TO ACCEPT, which is why it is rewritten rather
        than renamed. It asserted "no route ran and the socket went" and
        then walked ``for response in responses`` -- a loop over an EMPTY
        LIST, because two leading empty lines returned ZERO BYTES. It
        blessed "nothing at all" as the right answer to a request shape,
        which is the one outcome this round's bar names outright, and it
        did so in the file whose job is to catch exactly that.

        A second empty line is now refused with a framed 400 carrying a
        length and ``Connection: close``, on every route, in both
        spellings and at three lines deep as well as two. The count still
        stops at one: no route runs, and the socket still goes.
        """
        for lead in (b"\r\n\r\n", b"\n\n", b"\r\n\r\n\r\n"):
            for method, path in self.routes():
                with self.subTest(lead=lead, method=method, path=path):
                    FakeWalletOps.calls = []
                    # head_request=False even for HEAD, deliberately: this
                    # refusal is taken before super().parse_request() has
                    # read a request line, so the server does not know the
                    # method and frames a body. That is the right answer --
                    # the alternative is a refusal whose reason nobody can
                    # read -- and the socket goes immediately, so nothing
                    # can desync behind it.
                    responses, trailing, closed, data = self.probe(
                        lead, method, path, b"{}", head_request=False)
                    self.assertEqual(
                        len(responses), 1,
                        "%d leading empty lines before %s %s got %d "
                        "responses (%r)"
                        % (lead.count(b"\n"), method, path,
                           len(responses), data[:200]))
                    self.assertEqual(trailing, b"", repr(trailing[:120]))
                    status, headers, body = split_response(responses[0])
                    self.assertEqual(status, 400, body[:200])
                    self.assertEqual(headers.get("connection"), "close",
                                     "the hang-up was not announced: %r"
                                     % headers)
                    self.assertIn("content-length", headers)
                    obj = json.loads(body)
                    self.assertEqual(obj["error"]["reason"],
                                     "bad_request_line", body[:200])
                    self.assertIn(obj["error"]["cause"], gui_app.CAUSES)
                    self.assertTrue(closed,
                                    "a second empty line kept the socket")
                    self.assertEqual(
                        [c for c in FakeWalletOps.calls if c[0] == "list"],
                        [], "a route ran behind two leading empty lines")

    def test_an_empty_line_and_then_nothing_is_not_an_internal_error(self):
        """EOF after the empty line. There is nothing to answer, and
        nothing to print a traceback about either."""
        noise, saved = io.StringIO(), sys.stderr
        sys.stderr = noise
        try:
            sock = socket.create_connection(("127.0.0.1", self.port),
                                            timeout=5.0)
            try:
                sock.sendall(b"\r\n")
                sock.shutdown(socket.SHUT_WR)
                sock.settimeout(3.0)
                got = sock.recv(65536)
            finally:
                sock.close()
            time.sleep(0.2)
        finally:
            sys.stderr = saved
        self.assertEqual(got, b"")
        self.assertNotIn("Traceback", noise.getvalue())

    def test_an_absurd_request_line_behind_it_is_still_framed(self):
        """The 414 guard on the line parse_request reads itself.

        handle_one_request bounds the request line at 64 KiB; the line
        read after an empty one is read by this file, so it carries the
        same guard -- and the refusal has to be a framed HTTP message, not
        the naked body this server used to emit for an unparseable one.
        """
        payload = b"\r\nGET /" + b"a" * 70000 + b" HTTP/1.1\r\n\r\n"
        responses, trailing, closed, data = exchange_and_watch(
            self.port, payload, expect=1, wait=6.0, linger=0.4)
        self.assertEqual(len(responses), 1, data[:200])
        self.assertEqual(trailing, b"")
        self.assertTrue(closed)
        status, headers, body = split_response(responses[0])
        self.assertEqual(status, 414, body[:200])
        self.assertEqual(headers.get("connection"), "close")
        self.assertIn("content-length", headers)
        json.loads(body)          # this server's envelope, not an HTML page


class TestARequestTargetThisServerCannotRoute(ServerCase):
    """Absolute-form, asterisk-form and a bare relative path.

    MEASURED BEFORE THE FIX: 404, and then the connection KEPT, on all
    three -- the third of the three cells where the four servers here
    disagreed on identical bytes and the only one where this server was
    alone. The mint and the supervision profile answer 400
    bad_request_target and hang up; the console answers and hangs up.

    No body is involved, so this was not a smuggling hole by itself. It is
    a server that answered a request it could not route and then invited
    another one down the same socket, while three siblings did not.
    """

    TARGETS = (
        ("absolute form", "http://127.0.0.1:%(port)d/api/wallet/list"),
        ("absolute form, no port", "http://127.0.0.1/api/wallet/list"),
        ("absolute form, elsewhere", "http://example.invalid/api/wallet/list"),
        ("asterisk", "*"),
        ("relative path", "api/wallet/list"),
        ("relative path, page", "index.html"),
        ("authority form", "127.0.0.1:%(port)d"),
    )

    def probe(self, method, target, extra=""):
        payload = ("%s %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nCookie: %s\r\n%s"
                   "\r\n" % (method, target % {"port": self.port}, self.port,
                             self.cookie, extra)).encode()
        return exchange_and_watch(self.port, payload, expect=1, wait=6.0,
                                  linger=0.5,
                                  head_request=method == "HEAD")

    def test_every_form_is_answered_once_and_hung_up_on(self):
        for name, target in self.TARGETS:
            with self.subTest(target=name):
                responses, trailing, closed, data = self.probe("GET", target)
                self.assertEqual(len(responses), 1, data[:300])
                self.assertEqual(trailing, b"",
                                 "octets past the framing: %r" % trailing[:120])
                status, headers, body = split_response(responses[0])
                self.assertEqual(status, 400, body[:300])
                obj = json.loads(body)
                self.assert_envelope(status, obj, body)
                self.assertEqual(obj["error"]["reason"], "bad_request_target")
                self.assertEqual(
                    headers.get("connection"), "close",
                    "%s: hung up without announcing it" % name)
                self.assertTrue(
                    closed,
                    "%s: answered and then invited another request on the "
                    "same socket; the other three servers answer once and "
                    "hang up" % name)

    def test_it_covers_the_methods_with_no_handler_of_their_own(self):
        """parse_request and not the top of _handle, which is why.

        A method this file implements no ``do_*`` for is answered 501 from
        inside handle_one_request without any of _handle running. Putting
        the target check in _handle would have left those uncovered, which
        is the mint's own reason for the hook it chose.
        """
        for method in ("GET", "HEAD", "POST", "OPTIONS", "PUT", "DELETE",
                       "PATCH", "TRACE", "PROPFIND"):
            with self.subTest(method=method):
                extra = ("Content-Type: application/json\r\n"
                         "Content-Length: 0\r\n" if method == "POST" else "")
                responses, trailing, closed, data = self.probe(
                    method, "*", extra)
                self.assertEqual(len(responses), 1, data[:300])
                self.assertEqual(trailing, b"")
                status, _headers, body = split_response(responses[0])
                self.assertEqual(status, 400, body[:200])
                self.assertTrue(closed, "%s kept the socket" % method)

    def test_no_route_ran_and_no_credential_was_needed_to_find_that_out(self):
        """The refusal is a transport decision, so it is taken before
        dispatch -- and it must not have run a route on the way."""
        FakeWalletOps.calls = []
        payload = ("GET http://127.0.0.1:%d/api/wallet/list HTTP/1.1\r\n"
                   "Host: 127.0.0.1:%d\r\n\r\n"
                   % (self.port, self.port)).encode()
        responses, _trailing, closed, data = exchange_and_watch(
            self.port, payload, expect=1, wait=6.0, linger=0.5)
        self.assertEqual(len(responses), 1, data[:300])
        self.assertTrue(closed)
        status, _headers, body = split_response(responses[0])
        self.assertEqual(status, 400, body[:200])
        self.assertEqual(FakeWalletOps.calls, [])

    def test_the_refusal_does_not_quote_the_target_back(self):
        """A request target can carry the capability key (``/?k=...``),
        and an error body is the cheapest place to hand it to whatever can
        read a response. The console's 400 on a bad target is written to
        the same rule."""
        secret = self.httpd.auth.key
        payload = ("GET http://127.0.0.1:%d/?k=%s HTTP/1.1\r\n"
                   "Host: 127.0.0.1:%d\r\n\r\n"
                   % (self.port, secret, self.port)).encode()
        responses, _trailing, _closed, data = exchange_and_watch(
            self.port, payload, expect=1, wait=6.0, linger=0.5)
        self.assertEqual(len(responses), 1, data[:300])
        self.assertNotIn(secret.encode(), data,
                         "the refusal handed the capability key back")

    def test_a_bodiless_protocol_request_line_is_still_bad_version(self):
        """PRECEDENCE, and it is not decoration.

        A two-word request line is HTTP/0.9, where send_response,
        send_header and end_headers are ALL no-ops -- so a target refusal
        composed for one would go out as a naked body with no status line,
        which is the exact defect the 0.9 guard exists against. The target
        check therefore steps aside for 0.9 and _handle refuses it as
        bad_version, which is also the mint's order on the same bytes.
        """
        for target in ("http://127.0.0.1/api/wallet/list", "*",
                       "api/wallet/list"):
            with self.subTest(target=target):
                payload = ("GET %s\r\nHost: 127.0.0.1\r\n\r\n"
                           % target).encode()
                responses, trailing, closed, data = exchange_and_watch(
                    self.port, payload, expect=1, wait=6.0, linger=0.5)
                self.assertEqual(len(responses), 1, data[:300])
                self.assertEqual(
                    trailing, b"",
                    "a response with no status line went out: %r"
                    % trailing[:200])
                self.assertTrue(data.startswith(b"HTTP/1."), data[:120])
                status, headers, body = split_response(responses[0])
                self.assertEqual(status, 400, body[:200])
                self.assertEqual(json.loads(body)["error"]["reason"],
                                 "bad_version", body[:200])
                self.assertEqual(headers.get("connection"), "close")
                self.assertTrue(closed)

    def test_the_zero_nine_guard_depends_on_the_library_default(self):
        """Found by the mint-versus-this-server sweep, and pinned here.

        The mint carries THREE pieces against a naked answer:
        ``default_request_version = "HTTP/1.1"``, a ``send_error``
        override, and a check in parse_request that refuses both
        spellings of 0.9 -- a WORD COUNT for a two-word request line and a
        VERSION test for an explicit ``HTTP/0.9``. This file carries two
        of the three: the ``send_error`` override, and ``_handle``'s
        version test. It has no ``default_request_version``, and measured
        across all seven doors (an unparseable request line, a one-word
        line, a two-word line, ``HTTP/9.9``, an explicit ``HTTP/0.9``, a
        64 KiB request line, a bad method) every answer comes back framed,
        so there is no open door here today.

        But the two pieces are load-bearing TOGETHER with the library
        default staying where it is. ``_handle`` refuses a two-word
        request line only because the stdlib default puts ``HTTP/0.9`` in
        ``request_version`` when it cannot read one off the wire. Setting
        ``default_request_version`` here without ALSO adding the mint's
        word count would make a two-word request line read as HTTP/1.1
        and be ROUTED -- a request with no version on it answered on its
        merits, which is the door the mint's word count exists for. That
        is why this file was left with two pieces rather than given the
        third, and this test is what makes the coupling visible to the
        next person instead of leaving it in a comment.
        """
        self.assertEqual(gui_app.Handler.default_request_version, "HTTP/0.9",
                         "this server's 0.9 refusal reads request_version, "
                         "which is only HTTP/0.9 for a version-less request "
                         "line while the library default says so; raising it "
                         "needs the mint's word count added at the same time")
        payload = ("GET /api/wallet/list\r\nHost: 127.0.0.1:%d\r\n"
                   "Cookie: %s\r\n\r\n" % (self.port, self.cookie)).encode()
        responses, trailing, closed, data = exchange_and_watch(
            self.port, payload, expect=1, wait=6.0, linger=0.5)
        self.assertEqual(len(responses), 1, data[:300])
        self.assertEqual(trailing, b"", "a naked answer: %r" % trailing[:200])
        status, _headers, body = split_response(responses[0])
        self.assertEqual(status, 400, body[:200])
        self.assertEqual(json.loads(body)["error"]["reason"], "bad_version")
        self.assertTrue(closed)

    def test_an_origin_form_target_is_untouched(self):
        """"Refuse everything" would pass every test above.

        The ordinary shape still routes, still answers 200, and still
        keeps the connection -- which is the cell all four servers agree
        on and the one a target check is most likely to break.
        """
        payload = ("GET /api/wallet/list HTTP/1.1\r\n"
                   "Host: 127.0.0.1:%d\r\nCookie: %s\r\n\r\n"
                   % (self.port, self.cookie)).encode()
        responses, trailing, closed, data = exchange_and_watch(
            self.port, payload, expect=1, wait=6.0, linger=0.5)
        self.assertEqual(len(responses), 1, data[:300])
        self.assertEqual(trailing, b"")
        status, headers, body = split_response(responses[0])
        self.assertEqual(status, 200, body[:200])
        self.assertIsNone(headers.get("connection"))
        self.assertFalse(closed, "an origin-form GET lost its connection")
