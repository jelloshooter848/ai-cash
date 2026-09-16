#!/usr/bin/env python3
"""Tests for gui/app.py and gui/page.html.

Three kinds of test, because this component has three kinds of claim.

  * THE SERVER. A real GuiServer on a real loopback port, driven with raw
    sockets so the tests can send the headers a browser sends and the ones
    an attacker sends. The two components app.py talks to are faked here
    ON PURPOSE (mintctl.py and walletops.py have their own test files):
    what is under test is the HTTP skin — the origin controls, the error
    envelope, input validation, credential redaction.

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
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
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
    def call(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        payload = None if body is None else json.dumps(body)
        head = {"Accept": "application/json"}
        if payload is not None:
            head["Content-Type"] = "application/json"
        head.update(headers or {})
        conn.request(method, path, payload, head)
        response = conn.getresponse()
        raw = response.read()
        conn.close()
        try:
            return response.status, json.loads(raw or b"{}"), raw
        except ValueError:
            return response.status, None, raw

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
        raw = raw_request(self.port,
                          "GET /api/mint/status HTTP/1.0\r\n\r\n")
        status, _headers, body = split_response(raw)
        self.assertEqual(status, 421, body[:200])
        self.assertEqual(json.loads(body)["error"]["reason"], "not_loopback")

    def test_foreign_host_header_is_refused(self):
        raw = raw_request(
            self.port,
            "GET /api/mint/status HTTP/1.1\r\nHost: mint.evil.example\r\n"
            "Connection: close\r\n\r\n")
        status, _headers, body = split_response(raw)
        self.assertEqual(status, 421, body[:200])


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
                             {"Content-Type": "application/json"})
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
                             b"Host: 127.0.0.1\r\nContent-Type: application/json\r\n"
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
                         {"Accept": "application/json"})
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
            conn = http.client.HTTPConnection("::1", httpd.server_address[1],
                                              timeout=10)
            conn.request("GET", "/api/mint/status", None,
                         {"Host": "[::1]:%d" % httpd.server_address[1]})
            self.assertEqual(conn.getresponse().status, 200)
            conn.close()
            httpd.shutdown()
            thread.join(timeout=5)
        finally:
            httpd.server_close()
            shutil.rmtree(workdir, ignore_errors=True)


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
        head = {"Content-Type": "application/json"} if payload else {}
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
