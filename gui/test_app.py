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
import inspect
import io
import json
import os
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
    def __init__(self, reason, detail):
        super().__init__("%s: %s" % (reason, detail))
        self.reason = reason
        self.detail = detail


class FakeWalletOps:
    """Records every call, so a test can assert that money did NOT move."""

    calls = []
    fail_with = None          # (reason, detail) | Exception | None

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

    def pay(self, amount_mc):
        FakeWalletOps.calls.append(("pay", self.name, amount_mc))
        self._maybe_fail()
        return {"tokens": ["aicash:v3:fake-mint:%d:zz" % amount_mc],
                "amount_mc": amount_mc, "burn_mc": 1}

    def receive(self, tokens):
        FakeWalletOps.calls.append(("receive", self.name, list(tokens)))
        self._maybe_fail()
        return {"accepted_mc": 10, "accepted": len(tokens), "rejected": []}

    def recover(self):
        FakeWalletOps.calls.append(("recover", self.name))
        self._maybe_fail()
        return {"recovered": 0}

    def history(self, *, limit=50):
        FakeWalletOps.calls.append(("history", self.name, limit))
        self._maybe_fail()
        return [{"ts_ms": 1, "kind": "pay", "amount_mc": 5, "detail": "x"}]

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
    if (p === "/api/wallet/history") return {status: 200, data: {name: "alice", history: []}};
    // §7.3 fixed point, as aicash.channels._gross_for_net does it: the
    // wallet must hand over G with G - burn(G) == amount.
    function gross(a) { let g = a; for (let i = 0; i < 40; i++) { const n = a + burn(g); if (n === g) break; g = n; } return g; }
    if (p === "/api/wallet/quote") {
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
    const body = init && init.body ? JSON.parse(init.body) : null;
    const r = server.handle(path, body);
    return {ok: r.status >= 200 && r.status < 300, status: r.status,
            json: async () => r.data};
  };
  const exported = ["refreshAll", "refreshMint", "refreshQuote", "scheduleQuote",
    "payNow", "receiveNow", "startMint", "stopMint", "renderMint",
    "applyDescriptor", "setActive", "burnFor", "payCost", "costSentence",
    "refreshDescriptor", "issueInto"];
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

  process.stdout.write(JSON.stringify(out, null, 1));
}
main().then(() => process.exit(0), e => {
  process.stderr.write("HARNESS ERROR: " + (e && e.stack || e) + "\n");
  process.exit(1);
});
'''


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
