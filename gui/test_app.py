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
import errno
import http.client
import http.server
import inspect
import io
import json
import os
import re
import shutil
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
    """Enough of the pinned MintControl contract to exercise the server."""

    def __init__(self, workdir):
        self.workdir = workdir
        self.running = True
        self.started = []
        self.stopped = []

    def status(self):
        return {"running": self.running,
                "pid": 4242 if self.running else None,
                "port": 8787,
                "mint_id": "fake-mint",
                "base_url": "http://127.0.0.1:8787",
                "started_at_ms": 1700000000000 if self.running else None,
                "last_error": None}

    def start(self, *, mint_id, baseline_model_class, port, rate_ppm,
              cap_mc, exempt_below_mc):
        self.started.append(dict(mint_id=mint_id,
                                 baseline_model_class=baseline_model_class,
                                 port=port, rate_ppm=rate_ppm, cap_mc=cap_mc,
                                 exempt_below_mc=exempt_below_mc))
        self.running = True
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
        # screen.
        self.assertEqual(second["recipient_kind"], "")
        self.assertEqual(second["delivery"], "unknown")
        self.assertEqual(second["delivery_cause"], "unknown")

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
        self.assertEqual(obj["payments"][0]["recipient_kind"], "")

    def test_it_needs_a_wallet_that_exists(self):
        status, obj, raw = self.call("GET",
                                     "/api/wallet/outstanding?name=ghost")
        self.assertEqual(status, 404, raw[:200])
        self.assert_envelope(status, obj, raw)


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
            self.assertEqual(obj["recipient_kind"], "")
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
        self.assertEqual(second["recipient_kind"], "")
        # It ANSWERED, in a word this file cannot read: unknown, not "".
        self.assertEqual(second["delivery"], "unknown")
        self.assertEqual(second["delivery_cause"], "unknown")
        # A row that says nothing about delivery keeps saying nothing: ""
        # is "the question does not arise", and must not become "unknown".
        self.assertEqual(third["delivery"], "")
        self.assertEqual(third["recipient"], "")


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
        for op, row in rows.items():
            self.assertEqual(row["recipient"], "bob", op)
            self.assertEqual(row["recipient_kind"], "wallet", op)
            self.assertEqual(row["delivery"], "delivered", op)
            self.assertEqual(row["delivery_cause"], "", op)
            self.assertEqual(row["delivery_attempt"], "attempted", op)
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
