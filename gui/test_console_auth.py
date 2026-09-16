#!/usr/bin/env python3
"""Tests for the operator console's authentication (mint_console.py).

The console is the artifact the 2026-09-08 review was actually about: it
holds the mint's admin credential and exposes token issuance, and for most
of its life a loopback bind was its only protection. These tests pin the
four controls that replaced that single lock, and they do it the only way
worth doing it — a REAL console process, started the way an operator
starts it, in front of a REAL mint that really issues money.

Nothing here is faked. Every assertion below is about bytes that crossed a
socket. Requests are built on a raw socket rather than with a client
library so a test can send the headers an attacker sends: a Host that is
not loopback, an Origin from another site, a stolen capability key on an
API route.

The authenticated console is the fixture for almost everything, because
the authenticated path is the shipped path. --no-auth appears in exactly
one place: the test that proves the flag warns loudly and that it is NOT
what you get by default.

Run:  cd <repo> && python3 -m unittest gui.test_console_auth -v
"""
import ast
import http.client
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
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

CONSOLE = os.path.join(REPO, "mint_console.py")
RUN_MINT = os.path.join(REPO, "run_mint.py")
MINT_ID = "console-auth-test-mint"
COOKIE_NAME = "aicash_console"          # pinned: page.html and the server agree

# Every response this module receives, as text, so one test can sweep the
# lot for the credential instead of trusting each test to have looked.
TRANSCRIPT = []
STATE = {}


# ----------------------------------------------------------------------
# plumbing
# ----------------------------------------------------------------------
def free_port():
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


class Reader(threading.Thread):
    """Drain a child's pipe into a list, so it cannot block on a full buffer
    and so the tests can read what the operator would have seen."""

    def __init__(self, stream):
        super().__init__(daemon=True)
        self.stream, self.lines = stream, []

    def run(self):
        for line in self.stream:
            self.lines.append(line)

    @property
    def text(self):
        return "".join(self.lines)


def raw_request(port, method, path, headers=None, body=None, host=None,
                record=True):
    """One request over a fresh connection, with full control of the headers.

    Returns (status, headers-dict-ish, body-bytes). The Host header defaults
    to the real loopback authority; pass host= to forge it.
    """
    payload = b"" if body is None else (
        body if isinstance(body, bytes) else json.dumps(body).encode())
    head = {"Host": host if host is not None else "127.0.0.1:%d" % port,
            "Connection": "close", "Accept": "*/*"}
    if body is not None:
        head["Content-Type"] = "application/json"
        head["Content-Length"] = str(len(payload))
    for key, value in (headers or {}).items():
        if value is None:
            head.pop(key, None)
        else:
            head[key] = value
    raw = ("%s %s HTTP/1.1\r\n" % (method, path)).encode()
    raw += "".join("%s: %s\r\n" % kv for kv in head.items()).encode()
    raw += b"\r\n" + payload

    sock = socket.create_connection(("127.0.0.1", port), timeout=30)
    try:
        sock.sendall(raw)
        response = http.client.HTTPResponse(sock, method=method)
        response.begin()
        content = response.read()
        status, hdrs = response.status, response.headers
    finally:
        sock.close()
    if record:
        TRANSCRIPT.append("%s %s -> %d\n%s\n%s" % (
            method, path, status, hdrs.as_string(),
            content.decode("utf-8", "replace")))
    return status, hdrs, content


class NotReady(AssertionError):
    """A fixture did not come up. Deliberately NOT unittest.SkipTest.

    This used to raise SkipTest, and that was the one real hole in this
    module: setUpModule waits for the console's capability URL, so a console
    that printed no capability URL — i.e. a console shipping with auth off,
    the exact regression these tests exist to catch — skipped the module and
    unittest printed `OK (skipped=1)` and exited 0. Thirty-odd security
    tests vanished and the run still looked green.

    A fixture failing to start is a failure of this suite, not a reason to
    stop testing. AssertionError, so it reads as a failure rather than an
    infrastructure error, and so it can never be mistaken for a skip.
    """


def wait_for(predicate, what, timeout=45.0):
    end = time.monotonic() + timeout
    last = None
    while time.monotonic() < end:
        try:
            value = predicate()
            if value:
                return value
        except Exception as exc:       # not up yet
            last = exc
        time.sleep(0.1)
    raise NotReady("%s did not become ready within %.0fs: %s"
                   % (what, timeout, last))


def start_console(port, extra=(), workdir=None):
    """A real `python3 mint_console.py` process, as an operator runs it."""
    proc = subprocess.Popen(
        [sys.executable, CONSOLE, "--port", str(port),
         "--mint-port", str(STATE["mint_port"]), "--mint-id", MINT_ID,
         "--admin-token-file", STATE["token_file"]] + list(extra),
        cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = Reader(proc.stdout), Reader(proc.stderr)
    proc.readers = (out, err)
    out.start()
    err.start()
    wait_for(lambda: socket.create_connection(("127.0.0.1", port), 0.2).close()
             or True, "console on port %d" % port)
    return proc, out, err


def stop(proc, timeout=10):
    """Terminate a child and close its pipes. Nothing is left running."""
    if proc is None:
        return
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=timeout)
    for reader in getattr(proc, "readers", ()):
        reader.join(timeout=timeout)
    for pipe in (proc.stdout, proc.stderr):
        try:
            if pipe is not None:
                pipe.close()
        except OSError:
            pass


def read_admin_token():
    with open(STATE["token_file"]) as fh:
        return json.load(fh)["admin_token"]


# ----------------------------------------------------------------------
# in-process fixtures: a console with no real mint behind it
#
# These need neither the cryptography package nor a mint subprocess, so the
# checks built on them hold even on a machine where the real fixture cannot
# start. That is the point: the module's most important assertion — auth is
# ON when nobody asked for anything — must not depend on a fixture that can
# fail to come up.
# ----------------------------------------------------------------------
class RecordingMint:
    """A stand-in mint that remembers the headers the console sent it.

    Needed because the interesting property of the X-Admin-Token fix is the
    absence of a header on the wire, and neither the console's responses nor
    the real mint's access log record request headers at all.
    """

    def __init__(self):
        self.requests = []              # (method, path, headers)
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _serve(self):
                n = int(self.headers.get("Content-Length") or 0)
                if n:
                    self.rfile.read(n)
                outer.requests.append(
                    (self.command, self.path, dict(self.headers)))
                body = json.dumps(outer.reply(self.path)).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = _serve
            do_POST = _serve

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(
            target=self.httpd.serve_forever, kwargs={"poll_interval": 0.05},
            daemon=True)
        self.thread.start()

    @staticmethod
    def reply(path):
        if path == "/v3/mints":
            return {"mint_id": MINT_ID, "denominations_mc": [1000],
                    "supply": {"outstanding_mc": 0, "cumulative_issued_mc": 0,
                               "cumulative_burned_mc": 0, "snapshot_seq": 1}}
        return {}

    def headers_for(self, path):
        return [h for m, p, h in self.requests if p == path]

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=10)


class InProcessConsole:
    """mint_console.serve() in this process, on an ephemeral port.

    Started through serve() rather than by poking at Console directly, so
    the defaults under test are the defaults an operator gets.
    """

    def __init__(self, mint_port, admin_token=None, **kw):
        import mint_console
        self.stream = io.StringIO()
        self.httpd = mint_console.serve(0, mint_port, MINT_ID, admin_token,
                                        stream=self.stream, **kw)
        self.port = self.httpd.server_address[1]
        self.url = self.httpd.console_url
        self.thread = threading.Thread(
            target=self.httpd.serve_forever, kwargs={"poll_interval": 0.05},
            daemon=True)
        self.thread.start()

    @property
    def key(self):
        return self.httpd.auth.key

    def cookie(self):
        _s, hdrs, _b = raw_request(self.port, "GET", "/?k=%s" % self.key,
                                   record=False)
        return {"Cookie": hdrs.get("Set-Cookie").split(";")[0]}

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=10)


def prove_the_default_console_is_authenticated():
    """Auth is ON with no flags. Raises rather than returning a verdict.

    This is called from the top of setUpModule, BEFORE anything that can
    skip, and again from a normal test so it is visible in the count. It
    deliberately uses neither the mint nor a subprocess: the console 401s a
    stranger whether or not there is a mint behind it, so nothing about the
    environment can turn this check off.
    """
    console = InProcessConsole(mint_port=1)      # nothing is on port 1
    try:
        auth = console.httpd.auth
        assert auth.enabled, "serve() defaulted to auth OFF"
        assert auth.key and len(auth.key) >= 32, "no capability key: %r" % auth.key
        assert "?k=" in console.url, "no capability URL: %r" % console.url

        status, hdrs, _b = raw_request(console.port, "GET", "/", record=False)
        assert status == 401, "GET / with no key answered %d" % status
        assert hdrs.get("Set-Cookie") is None, "an unauthenticated GET / got a session"

        status, _h, body = raw_request(console.port, "GET", "/api/descriptor",
                                       record=False)
        assert status == 401, "GET /api/descriptor with no cookie answered %d" % status
        assert json.loads(body)["error"]["reason"] == "unauthorized", body

        status, hdrs, _b = raw_request(console.port, "GET",
                                       "/?k=%s" % auth.key, record=False)
        assert status == 200, "the capability URL answered %d" % status
        assert hdrs.get("Set-Cookie"), "the capability URL handed out no cookie"
    finally:
        console.stop()


def setUpModule():
    # First, and outside every try: a console that ships unlocked must break
    # this module loudly, on any machine, whatever else is missing.
    prove_the_default_console_is_authenticated()

    try:
        import cryptography  # noqa: F401
    except ImportError:
        raise unittest.SkipTest("the mint needs the cryptography package")

    STATE["workdir"] = tempfile.mkdtemp(prefix="console-auth-")
    STATE["mint_port"] = free_port()
    STATE["token_file"] = os.path.join(STATE["workdir"], "admin-keys.json")
    STATE["access_log"] = os.path.join(STATE["workdir"], "access.log")
    STATE["mint"] = STATE["console"] = None

    # --console-port 0 disables run_mint's own console: this module starts
    # the console itself so it owns its stdout and can read the one-time URL.
    STATE["mint"] = subprocess.Popen(
        [sys.executable, RUN_MINT,
         "--port", str(STATE["mint_port"]), "--console-port", "0",
         "--db", os.path.join(STATE["workdir"], "mint.db"),
         "--keys", os.path.join(STATE["workdir"], "mint-keys.json"),
         "--admin-token-file", STATE["token_file"],
         "--access-log", STATE["access_log"],
         "--mint-id", MINT_ID, "--prune-interval-hours", "0"],
        cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    STATE["mint_out"] = Reader(STATE["mint"].stdout)
    STATE["mint_err"] = Reader(STATE["mint"].stderr)
    STATE["mint"].readers = (STATE["mint_out"], STATE["mint_err"])
    STATE["mint_out"].start()
    STATE["mint_err"].start()
    try:
        wait_for(lambda: raw_request(STATE["mint_port"], "GET", "/v3/mints",
                                     record=False)[0] == 200, "the mint")
        STATE["admin_token"] = wait_for(read_admin_token,
                                        "the mint's admin token file")

        STATE["port"] = free_port()
        proc, out, err = start_console(STATE["port"])
        STATE["console"], STATE["out"], STATE["err"] = proc, out, err
        url = wait_for(
            lambda: re.search(r"http://127\.0\.0\.1:\d+/\?k=([A-Za-z0-9_-]+)",
                              out.text), "the console's capability URL")
        STATE["url"], STATE["key"] = url.group(0), url.group(1)
    except BaseException:
        tearDownModule()
        raise


def tearDownModule():
    stop(STATE.get("console"))
    stop(STATE.get("mint"))
    if STATE.get("workdir"):
        shutil.rmtree(STATE["workdir"], ignore_errors=True)


# ----------------------------------------------------------------------
class ConsoleCase(unittest.TestCase):
    """Shared helpers. Every request goes to the real authenticated console."""

    @property
    def port(self):
        return STATE["port"]

    @property
    def key(self):
        return STATE["key"]

    def get(self, path, **kw):
        return raw_request(self.port, "GET", path, **kw)

    def post(self, path, body, **kw):
        return raw_request(self.port, "POST", path, body=body, **kw)

    def open_session(self):
        """Do what a browser does with the printed URL: exchange the key."""
        status, hdrs, _ = self.get("/?k=%s" % self.key)
        self.assertEqual(status, 200)
        cookie = hdrs.get("Set-Cookie")
        self.assertIsNotNone(cookie, "the capability URL handed out no cookie")
        value = cookie.split(";")[0].split("=", 1)[1]
        return {"Cookie": "%s=%s" % (COOKIE_NAME, value)}, cookie

    def cookie(self):
        return self.open_session()[0]

    def assertUnauthorized(self, status, body, where):
        self.assertEqual(status, 401, "%s answered %d, not 401" % (where, status))
        obj = json.loads(body)
        self.assertEqual(obj["error"]["reason"], "unauthorized",
                         "%s: wrong error envelope: %r" % (where, obj))
        self.assertTrue(obj["error"]["detail"],
                        "%s: 401 with no detail to act on" % where)


# every /api/* route the console exposes, as (method, path, body)
API_ROUTES = [
    ("GET", "/api/descriptor", None),
    ("POST", "/api/issue", {"amount_mc": 1000, "count": 1}),
    ("POST", "/api/status", {"q": "deadbeef"}),
]


class TestCapabilityUrl(ConsoleCase):
    """1. The key exists once, in memory, and is printed to the terminal."""

    def test_the_url_is_printed_with_a_long_random_key(self):
        self.assertIn("?k=", STATE["url"])
        self.assertGreaterEqual(len(self.key), 32,
                                "a guessable key is not a capability")
        self.assertIn("http://127.0.0.1:%d/" % self.port, STATE["url"])

    def test_the_key_is_not_written_to_any_file(self):
        """It may live in this process's stdout — that is the terminal. It
        must not reach disk anywhere the console controls."""
        hits = []
        for root, _dirs, names in os.walk(STATE["workdir"]):
            for name in names:
                path = os.path.join(root, name)
                try:
                    with open(path, "rb") as fh:
                        if self.key.encode() in fh.read():
                            hits.append(path)
                except OSError:
                    pass
        self.assertEqual(hits, [], "the capability key reached disk")

    def test_the_key_is_not_in_the_consoles_stderr_or_the_mints_logs(self):
        for name, text in (("console stderr", STATE["err"].text),
                           ("mint stdout", STATE["mint_out"].text),
                           ("mint stderr", STATE["mint_err"].text)):
            self.assertNotIn(self.key, text, "the key leaked to %s" % name)

    def test_the_printed_warning_does_not_pretend_this_is_safe(self):
        text = STATE["out"].text.lower()
        self.assertIn("loopback", text)
        self.assertIn("401", text, "the operator is not told the bare URL fails")


class TestCookieExchange(ConsoleCase):
    """2. The key buys a cookie at GET /, and nothing else."""

    def test_the_right_key_serves_the_page_and_a_hardened_cookie(self):
        headers, cookie = self.open_session()
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        self.assertIn("Path=/", cookie)
        value = headers["Cookie"].split("=", 1)[1]
        self.assertNotEqual(value, self.key,
                            "the session IS the key: leaking one leaks both")
        self.assertGreaterEqual(len(value), 32)

    def test_the_page_comes_back_and_carries_no_credential(self):
        headers, _ = self.open_session()
        status, hdrs, body = self.get("/", headers=headers)
        self.assertEqual(status, 200)
        self.assertIn("text/html", hdrs.get("Content-Type", ""))
        text = body.decode()
        self.assertIn("aicash mint console", text)
        self.assertNotIn(self.key, text)
        self.assertNotIn(STATE["admin_token"], text)

    def test_no_key_and_no_cookie_is_401_with_no_cookie_handed_out(self):
        status, hdrs, body = self.get("/")
        self.assertEqual(status, 401)
        self.assertIsNone(hdrs.get("Set-Cookie"),
                          "an unauthenticated GET / was given a session")
        self.assertIn("text/html", hdrs.get("Content-Type", ""))
        self.assertIn("terminal", body.decode().lower(),
                      "the 401 page does not say where the URL comes from")

    def test_a_wrong_key_gets_no_cookie(self):
        for attempt in ("wrong", self.key[:-1], self.key + "x", ""):
            status, hdrs, _ = self.get("/?k=%s" % attempt)
            self.assertEqual(status, 401, "key %r was accepted" % attempt)
            self.assertIsNone(hdrs.get("Set-Cookie"),
                              "key %r was given a session" % attempt)

    def test_a_forged_cookie_is_refused(self):
        status, _hdrs, body = self.get(
            "/api/descriptor",
            headers={"Cookie": "%s=%s" % (COOKIE_NAME, "f" * 43)})
        self.assertUnauthorized(status, body, "a forged cookie")

    def test_the_401_page_never_echoes_what_was_sent(self):
        """Reflecting the query string would put the key straight back into
        a page an attacker can read."""
        status, _hdrs, body = self.get("/?k=NEEDLE-abc123")
        self.assertEqual(status, 401)
        self.assertNotIn("NEEDLE-abc123", body.decode())


class TestEveryApiRouteNeedsTheCookie(ConsoleCase):
    """3. Cookie-gated means all of them, GET included."""

    def test_no_cookie_is_401_on_every_api_route(self):
        for method, path, body in API_ROUTES:
            status, _hdrs, content = raw_request(self.port, method, path,
                                                 body=body)
            self.assertUnauthorized(status, content, "%s %s" % (method, path))

    def test_the_capability_key_does_not_work_on_an_api_route(self):
        """The whole point of the exchange: a URL that leaks cannot be
        replayed against an API route."""
        for method, path, body in API_ROUTES:
            status, _hdrs, content = raw_request(
                self.port, method, "%s?k=%s" % (path, self.key), body=body)
            self.assertUnauthorized(status, content,
                                    "%s %s with the key" % (method, path))

    def test_an_api_401_never_hands_back_a_cookie(self):
        for method, path, body in API_ROUTES:
            _s, hdrs, _c = raw_request(self.port, method, path, body=body)
            self.assertIsNone(hdrs.get("Set-Cookie"),
                              "%s %s issued a session" % (method, path))

    def test_with_the_cookie_every_route_actually_works(self):
        """The lock must not be the reason the tool stops working: this is
        the same console, same process, doing real work against a real
        mint — including minting real money."""
        headers = self.cookie()

        status, _hdrs, body = self.get("/api/descriptor", headers=headers)
        self.assertEqual(status, 200, body)
        descriptor = json.loads(body)
        self.assertEqual(descriptor["mint_id"], MINT_ID)
        before = descriptor["supply"]["cumulative_issued_mc"]

        status, _hdrs, body = self.post("/api/issue",
                                        {"amount_mc": 2500, "count": 2},
                                        headers=headers)
        self.assertEqual(status, 200, body)
        tokens = json.loads(body)["tokens"]
        self.assertEqual(len(tokens), 2)
        self.assertTrue(all(t.startswith("aicash:v3:%s:" % MINT_ID)
                            for t in tokens), tokens)

        status, _hdrs, body = self.post("/api/status", {"q": tokens[0]},
                                        headers=headers)
        self.assertEqual(status, 200, body)

        status, _hdrs, body = self.get("/api/descriptor", headers=headers)
        self.assertEqual(json.loads(body)["supply"]["cumulative_issued_mc"],
                         before + 5000,
                         "the authenticated path did not really mint")

    def test_an_unknown_api_route_is_still_gated(self):
        status, _hdrs, body = self.get("/api/there-is-no-such-thing")
        self.assertUnauthorized(status, body, "an unknown /api/ route")


class TestHostHeader(ConsoleCase):
    """4. DNS rebinding: the bind cannot see it, the Host check can."""

    def test_a_foreign_host_is_403_even_with_a_valid_cookie(self):
        headers = self.cookie()
        for host in ("evil.example", "evil.example:%d" % self.port,
                     "127.0.0.1.evil.example:%d" % self.port,
                     "localhost.evil.example", "0.0.0.0:%d" % self.port,
                     "10.0.0.7:%d" % self.port):
            for method, path, body in API_ROUTES:
                status, _hdrs, content = raw_request(
                    self.port, method, path, body=body, headers=headers,
                    host=host)
                self.assertEqual(status, 403,
                                 "Host %r reached %s %s (%d)"
                                 % (host, method, path, status))
                self.assertEqual(json.loads(content)["error"]["reason"],
                                 "bad_host")

    def test_the_hosts_that_got_past_the_old_splitter_are_403(self):
        """The three that were a LIVE bypass, plus the rest of the family.

        Before this was fixed the Host check split the header by hand and
        validated only the part before the separator. Everything after the
        closing bracket was discarded, so "[::1]evil.example" and
        "[::1].evil.example" were compared as a clean "[::1]"; and
        "127.0.0.1:" produced an empty port string, which is falsy, so the
        port branch was skipped entirely. All three were answered 200 on
        POST /api/issue against a running mint -- the request reached POST
        /admin/issue with the operator credential and money was minted.

        The previous test here sampled only hosts shaped like a domain
        name, which is why the whole bracket family survived it. This one
        drives every API route under every host in the family and requires
        403 from the gate, so the route body is never reached at all.
        """
        headers = self.cookie()
        for host in ("[::1]evil.example", "[::1].evil.example", "127.0.0.1:",
                     "[::1]:", "[::1]:%d@evil.example" % self.port,
                     "[::1]:%d.evil.example" % self.port,
                     "127.0.0.1:%d.evil.example" % self.port,
                     "localhost:evil.example", "127.0.0.1:not-a-port",
                     "localhost:%d:9" % self.port, "::1:%d" % self.port,
                     "::1.evil.example", "localhost:80/../x",
                     "2130706433:%d" % self.port):
            for method, path, body in API_ROUTES:
                with self.subTest(host=host, route=path):
                    status, _hdrs, content = raw_request(
                        self.port, method, path, body=body, headers=headers,
                        host=host)
                    self.assertEqual(
                        status, 403,
                        "Host %r reached %s %s (%d) -- this host is not a "
                        "loopback literal and the Host check is the only "
                        "thing standing between a rebinding attack and a "
                        "mint" % (host, method, path, status))
                    self.assertEqual(
                        json.loads(content)["error"]["reason"], "bad_host")

    def test_a_foreign_host_cannot_even_fetch_the_page(self):
        status, _hdrs, _b = self.get("/?k=%s" % self.key, host="evil.example")
        self.assertEqual(status, 403)

    def test_the_real_loopback_names_are_accepted(self):
        headers = self.cookie()
        for host in ("127.0.0.1:%d" % self.port, "localhost:%d" % self.port,
                     "[::1]:%d" % self.port, "localhost"):
            status, _hdrs, body = self.get("/api/descriptor", headers=headers,
                                           host=host)
            self.assertEqual(status, 200, "Host %r was refused: %s"
                             % (host, body))

    def test_a_missing_host_is_refused(self):
        headers = dict(self.cookie())
        headers["Host"] = None          # raw_request drops it
        status, _hdrs, _b = self.get("/api/descriptor", headers=headers)
        self.assertEqual(status, 403)


class TestCrossSite(ConsoleCase):
    """5. The tab the operator already had open."""

    def test_a_foreign_origin_is_403(self):
        headers = self.cookie()
        for origin in ("http://evil.example", "https://evil.example",
                       "http://127.0.0.1:1", "null",
                       "http://localhost.evil.example"):
            for method, path, body in API_ROUTES:
                status, _hdrs, content = raw_request(
                    self.port, method, path, body=body,
                    headers=dict(headers, Origin=origin))
                self.assertEqual(status, 403,
                                 "Origin %r reached %s %s" % (origin, method, path))
                self.assertEqual(json.loads(content)["error"]["reason"],
                                 "cross_site")

    def test_a_foreign_referer_is_403(self):
        headers = self.cookie()
        status, _hdrs, content = self.get(
            "/api/descriptor",
            headers=dict(headers, Referer="http://evil.example/x"))
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(content)["error"]["reason"], "cross_site")

    def test_a_cross_site_fetch_is_403(self):
        headers = self.cookie()
        for site in ("cross-site", "same-site"):
            status, _hdrs, _c = self.post(
                "/api/issue", {"amount_mc": 1000, "count": 1},
                headers=dict(headers, **{"Sec-Fetch-Site": site}))
            self.assertEqual(status, 403, "Sec-Fetch-Site: %s got through" % site)

    def test_our_own_origin_and_referer_are_allowed(self):
        headers = self.cookie()
        mine = "http://127.0.0.1:%d" % self.port
        status, _hdrs, body = self.get(
            "/api/descriptor",
            headers=dict(headers, Origin=mine, Referer=mine + "/",
                         **{"Sec-Fetch-Site": "same-origin"}))
        self.assertEqual(status, 200, body)

    def test_absent_origin_and_referer_are_allowed(self):
        """curl and same-origin fetches send neither, and neither can be
        conscripted by a web page."""
        status, _hdrs, body = self.get("/api/descriptor", headers=self.cookie())
        self.assertEqual(status, 200, body)


class TestCredentialContainment(ConsoleCase):
    """6. The admin token stays server-side, in every direction."""

    def test_the_admin_token_never_appears_in_any_response(self):
        token = STATE["admin_token"]
        self.assertTrue(token and len(token) >= 16)
        # Touch every route, authenticated and not, then sweep everything
        # this module has received so far.
        headers = self.cookie()
        for method, path, body in API_ROUTES:
            raw_request(self.port, method, path, body=body, headers=headers)
            raw_request(self.port, method, path, body=body)
        self.get("/?k=%s" % self.key)
        self.get("/")
        self.assertGreater(len(TRANSCRIPT), 10)
        leaked = [t for t in TRANSCRIPT if token in t]
        self.assertEqual(leaked, [],
                         "the operator credential came back over HTTP")

    def test_the_admin_token_never_reaches_the_consoles_own_output(self):
        token = STATE["admin_token"]
        self.assertNotIn(token, STATE["out"].text)
        self.assertNotIn(token, STATE["err"].text)

    def test_the_admin_token_is_not_in_the_mints_access_log(self):
        """The console used to attach X-Admin-Token to public mint routes
        too. Nothing that does not need the credential should carry it."""
        with open(STATE["access_log"], "rb") as fh:
            log = fh.read()
        self.assertNotIn(STATE["admin_token"].encode(), log)
        self.assertIn(b"/admin/issue", log,
                      "the fixture never exercised the credentialled route")

    def test_a_bad_admin_token_does_not_come_back_through_the_proxy(self):
        """Start a console pointed at the real mint with the WRONG
        credential: the mint's 401 must pass through without the console
        echoing what it presented."""
        port = free_port()
        proc, out, err = start_console(
            port, extra=["--admin-token", "WRONG-CREDENTIAL-abcdefghijklmnop",
                         "--admin-token-file", ""])
        self.addCleanup(stop, proc)
        url = wait_for(
            lambda: re.search(r"/\?k=([A-Za-z0-9_-]+)", out.text),
            "the second console's URL")
        status, hdrs, _b = raw_request(port, "GET", "/?k=%s" % url.group(1))
        self.assertEqual(status, 200)
        cookie = hdrs.get("Set-Cookie").split(";")[0]
        status, _hdrs, body = raw_request(
            port, "POST", "/api/issue", body={"amount_mc": 1000, "count": 1},
            headers={"Cookie": cookie})
        self.assertEqual(status, 401, body)
        text = body.decode()
        self.assertNotIn("WRONG-CREDENTIAL-abcdefghijklmnop", text)
        self.assertNotIn("WRONG-CREDENTIAL-abcdefghijklmnop", out.text + err.text)


class TestDefaultsAndTheEscapeHatch(ConsoleCase):
    """7. Auth is on by default; --no-auth is loud."""

    def test_the_default_console_is_authenticated(self):
        """The fixture console was started with no auth flags at all."""
        self.assertIn("?k=", STATE["url"])
        status, _hdrs, body = self.get("/api/descriptor")
        self.assertUnauthorized(status, body, "the default console")

    def test_no_auth_opens_the_door_and_says_so_on_stderr(self):
        port = free_port()
        proc, out, err = start_console(port, extra=["--no-auth"])
        self.addCleanup(stop, proc)
        warning = wait_for(lambda: "--no-auth" in err.text and err.text,
                           "the --no-auth warning")
        self.assertGreaterEqual(len(warning.strip().splitlines()), 3,
                                "the warning is not multi-line: %r" % warning)
        self.assertIn("MINT MONEY", warning)
        self.assertNotIn("?k=", out.text,
                         "--no-auth still printed a capability URL")
        status, _hdrs, body = raw_request(port, "GET", "/api/descriptor")
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["mint_id"], MINT_ID)

    def test_no_auth_still_refuses_a_foreign_host(self):
        """The flag drops the key, not the origin controls: an unlocked test
        console must still not be drivable by a web page."""
        port = free_port()
        proc, _out, _err = start_console(port, extra=["--no-auth"])
        self.addCleanup(stop, proc)
        status, _hdrs, _b = raw_request(port, "GET", "/api/descriptor",
                                        host="evil.example")
        self.assertEqual(status, 403)
        status, _hdrs, _b = raw_request(
            port, "POST", "/api/issue", body={"amount_mc": 1000, "count": 1},
            headers={"Origin": "http://evil.example"})
        self.assertEqual(status, 403)


class TestAuthUnit(unittest.TestCase):
    """The in-memory half, imported directly: cheap, and it pins the
    properties the HTTP tests can only observe indirectly."""

    def setUp(self):
        import mint_console
        self.mod = mint_console

    def test_a_fresh_key_every_construction(self):
        keys = {self.mod.Auth().key for _ in range(20)}
        self.assertEqual(len(keys), 20)
        self.assertTrue(all(len(k) >= 32 for k in keys))

    def test_sessions_are_independent_of_the_key(self):
        auth = self.mod.Auth()
        session = auth.new_session()
        self.assertNotEqual(session, auth.key)
        self.assertTrue(auth.session_ok(session))
        self.assertFalse(auth.session_ok(auth.key))
        self.assertFalse(auth.key_ok(session))

    def test_sessions_are_bounded(self):
        auth = self.mod.Auth()
        first = auth.new_session()
        for _ in range(self.mod.MAX_SESSIONS + 5):
            auth.new_session()
        self.assertFalse(auth.session_ok(first),
                         "sessions grow without limit")

    def test_empty_and_wrong_types_never_authorise(self):
        auth = self.mod.Auth()
        auth.new_session()          # something to compare against
        # The last four are the ones that used to raise rather than return:
        # hmac.compare_digest refuses a str holding any non-ASCII character,
        # and both of these take their argument straight off the wire.
        for bad in ("", None, 0, b"x", [], "\u00e9", "k\u00e9y", "\U0001f600",
                    "\u00e9" * 200):
            self.assertFalse(auth.key_ok(bad), repr(bad))
            self.assertFalse(auth.session_ok(bad), repr(bad))

    def test_a_non_ascii_credential_returns_false_instead_of_raising(self):
        """Not just falsey — it must not raise, because the caller is an
        unauthenticated request handler and an exception there is a dropped
        connection plus a traceback in the operator's log."""
        auth = self.mod.Auth()
        session = auth.new_session()
        for bad in ("\u00e9", auth.key[:-1] + "\u00e9", session[:-1] + "\u00e9",
                    "\ud800"):
            self.assertIs(auth.key_ok(bad), False, repr(bad))
            self.assertIs(auth.session_ok(bad), False, repr(bad))
        # and the real ones still work afterwards
        self.assertTrue(auth.key_ok(auth.key))
        self.assertTrue(auth.session_ok(session))

    def test_disabled_auth_is_explicitly_open(self):
        auth = self.mod.Auth(enabled=False)
        self.assertIsNone(auth.key)
        self.assertTrue(auth.session_ok(""))

    def test_host_matching_handles_ipv6_and_ports(self):
        """The Host header is matched end to end, port included.

        This replaces a test of a hand-rolled _split_hostport helper. That
        helper validated the part before the separator and discarded the
        rest, so "[::1]evil.example", "[::1].evil.example" and "127.0.0.1:"
        were all accepted as loopback and reached POST /admin/issue on a
        live mint with the operator credential. The helper is gone; one
        anchored pattern that has to match the whole header replaced it,
        because a splitter decides what gets compared and therefore quietly
        stops the name set from being the whitelist it looks like.

        The same five cases the old test covered are still covered, now
        stated as the question that actually matters -- is this header
        accepted -- rather than as how it happens to be cut up.
        """
        accepted = ("127.0.0.1:8080", "localhost", "[::1]:8080", "[::1]",
                    "127.0.0.1", "localhost:8080", "::1",
                    "127.0.0.1:8080".upper())
        for value in accepted:
            with self.subTest(host=value):
                self.assertIsNotNone(
                    self.mod._HOST_RE.match(value.strip().lower()),
                    "%r is a loopback literal and must be accepted" % value)

        refused = ("evil.example:80", "evil.example",
                   # the three that were live bypasses
                   "[::1]evil.example", "[::1].evil.example", "127.0.0.1:",
                   # and the rest of the family the splitter also blurred
                   "127.0.0.1:8080.evil.example", "localhost:evil.example",
                   "127.0.0.1:not-a-port", "[::1]:8080@evil.example",
                   "[::1]:", "localhost:8080:9", "::1:8080",
                   "::1.evil.example", "127.0.0.1.evil.example",
                   "127.0.0.2", "0.0.0.0", "2130706433", "")
        for value in refused:
            with self.subTest(host=value):
                self.assertIsNone(
                    self.mod._HOST_RE.match(value.strip().lower()),
                    "%r is not a loopback literal and must be refused; a "
                    "Host check that accepts it is not a DNS-rebinding "
                    "defence" % value)


class TestAuthenticatedByDefault(unittest.TestCase):
    """8. The regression this module exists to catch, checked without the
    fixture — no mint, no subprocess, nothing that can fail to start and
    take the check with it."""

    def test_serve_with_no_flags_is_authenticated(self):
        prove_the_default_console_is_authenticated()

    def test_the_suites_own_waits_fail_rather_than_skip(self):
        """A fixture that never comes up must break the run. The previous
        version of wait_for raised SkipTest here, which is how a console
        with auth switched off produced `OK (skipped=1)` and exit 0."""
        with self.assertRaises(AssertionError):
            wait_for(lambda: False, "something that never happens",
                     timeout=0.3)
        self.assertFalse(issubclass(NotReady, unittest.SkipTest))


class TestEverythingButThePageIsGated(unittest.TestCase):
    """9. The gate is 'everything except GET /', not 'everything under
    /api/'. A route added tomorrow is locked before it is written."""

    NOT_THE_PAGE = ["/favicon.ico", "/nope", "/v3/mints", "/admin/issue",
                    "/api/../v3/mints", "/static/app.js", "/index.htm",
                    "/api", "/.well-known/x", "/api/descriptor/"]

    @classmethod
    def setUpClass(cls):
        cls.mint = RecordingMint()
        cls.console = InProcessConsole(cls.mint.port,
                                       admin_token="UNUSED-TOKEN-0123456789")

    @classmethod
    def tearDownClass(cls):
        cls.console.stop()
        cls.mint.stop()

    def test_no_route_but_the_page_answers_without_the_cookie(self):
        for path in self.NOT_THE_PAGE:
            for method in ("GET", "POST"):
                status, _h, body = raw_request(
                    self.console.port, method, path,
                    body={} if method == "POST" else None, record=False)
                self.assertEqual(status, 401,
                                 "%s %s answered %d unauthenticated"
                                 % (method, path, status))
                self.assertEqual(json.loads(body)["error"]["reason"],
                                 "unauthorized", path)
        self.assertEqual(self.mint.requests, [],
                         "an unauthenticated request was proxied to the mint: "
                         "%r" % (self.mint.requests,))

    def test_a_smuggled_path_does_not_slip_the_gate(self):
        """urlsplit('//api/x') parses 'api' as a netloc, which would have
        made a prefix-based gate see a non-API route. The gate is not
        prefix-based any more, and CPython collapses the leading // before
        the handler sees it — both, checked."""
        for path in ("//api/descriptor", "/./api/descriptor",
                     "/x/../api/descriptor", "/api//descriptor",
                     "/api%2fdescriptor", "/API/descriptor",
                     "/api/descriptor%00", "/api/descriptor?k=x"):
            status, _h, body = raw_request(self.console.port, "GET", path,
                                           record=False)
            self.assertEqual(status, 401, "%s answered %d" % (path, status))
            self.assertEqual(json.loads(body)["error"]["reason"],
                             "unauthorized", path)
        self.assertEqual(self.mint.requests, [],
                         "a smuggled path reached the mint: %r"
                         % (self.mint.requests,))

    def test_posting_to_the_page_route_is_gated_too(self):
        """GET / is the exemption. POST / is not."""
        status, _h, body = raw_request(self.console.port, "POST", "/",
                                       body={}, record=False)
        self.assertEqual(status, 401, body)

    def test_with_the_cookie_those_paths_are_an_honest_404(self):
        """The gate must be a gate, not a blanket 401 hiding a broken
        dispatch: authenticated, the same paths 404 and the page serves."""
        headers = self.console.cookie()
        for path in self.NOT_THE_PAGE:
            status, _h, _b = raw_request(self.console.port, "GET", path,
                                         headers=headers, record=False)
            self.assertEqual(status, 404, "%s answered %d with a cookie"
                             % (path, status))
        status, _h, body = raw_request(self.console.port, "GET", "/",
                                       headers=headers, record=False)
        self.assertEqual(status, 200)
        self.assertIn(b"aicash mint console", body)


class TestMalformedCredentialsAreAnAnswer(ConsoleCase):
    """10. The authentication path must not raise on attacker input.

    `GET /?k=%C3%A9` reached hmac.compare_digest with a non-ASCII str, which
    raises TypeError: the handler thread died, the connection was dropped
    with no response at all, and a traceback was appended to the console's
    stderr — the same stderr the startup banner warns a service manager may
    be capturing to a file.
    """

    BAD_KEYS = ["%C3%A9", "%F0%9F%98%80", "k%C3%A9y", "%C3%A9%C3%A9%C3%A9",
                "%ED%A0%80", "%FF%FE"]

    def test_a_non_ascii_key_gets_a_401_not_a_dropped_connection(self):
        before = len(STATE["err"].text)
        for bad in self.BAD_KEYS:
            status, hdrs, body = self.get("/?k=" + bad, record=False)
            self.assertEqual(status, 401, "?k=%s answered %d" % (bad, status))
            self.assertIsNone(hdrs.get("Set-Cookie"),
                              "?k=%s was handed a session" % bad)
            self.assertIn(b"Not authorised", body)
        time.sleep(0.3)
        self.assertNotIn("Traceback", STATE["err"].text[before:],
                         "the auth path raised on unauthenticated input")

    def test_a_non_ascii_key_on_an_api_route_is_a_normal_401(self):
        before = len(STATE["err"].text)
        for method, path, body in API_ROUTES:
            status, _h, content = raw_request(
                self.port, method, "%s?k=%%C3%%A9" % path, body=body,
                record=False)
            self.assertUnauthorized(status, content, "%s %s ?k=non-ascii"
                                    % (method, path))
        time.sleep(0.3)
        self.assertNotIn("Traceback", STATE["err"].text[before:])

    def test_a_non_ascii_cookie_is_a_normal_401(self):
        before = len(STATE["err"].text)
        for value in ("\u00e9" * 8, "caf\u00e9", "\U0001f600"):
            status, _h, content = raw_request(
                self.port, "GET", "/api/descriptor", record=False,
                headers={"Cookie": "%s=%s" % (COOKIE_NAME, value)})
            self.assertEqual(status, 401, "a non-ASCII cookie answered %d"
                             % status)
        time.sleep(0.3)
        self.assertNotIn("Traceback", STATE["err"].text[before:])

    def test_the_real_key_still_works_after_all_that(self):
        status, hdrs, _b = self.get("/?k=%s" % self.key, record=False)
        self.assertEqual(status, 200)
        self.assertIsNotNone(hdrs.get("Set-Cookie"))


class TestNo401BranchEchoesTheRequest(ConsoleCase):
    """11. The capability URL is the credential, so no error body may
    reflect it — and there are two 401 branches, HTML and JSON."""

    NEEDLE = "NEEDLE-9f3a1c"

    def test_the_html_401_does_not_reflect_the_query(self):
        status, _h, body = self.get("/?k=%s" % self.NEEDLE, record=False)
        self.assertEqual(status, 401)
        self.assertNotIn(self.NEEDLE, body.decode())

    def test_the_json_401_does_not_reflect_the_query_or_the_path(self):
        for method, path, payload in API_ROUTES:
            status, _h, body = raw_request(
                self.port, method, "%s?k=%s&q=%s" % (path, self.NEEDLE,
                                                     self.NEEDLE),
                body=payload, record=False)
            text = body.decode()
            self.assertEqual(status, 401, text)
            self.assertNotIn(self.NEEDLE, text,
                             "%s %s echoed the query into its 401" % (method, path))
            self.assertNotIn(path, text,
                             "%s %s echoed the path into its 401" % (method, path))

    def test_an_unknown_route_401_does_not_reflect_the_path(self):
        status, _h, body = raw_request(
            self.port, "GET", "/%s?k=%s" % (self.NEEDLE, self.NEEDLE),
            record=False)
        self.assertEqual(status, 401)
        self.assertNotIn(self.NEEDLE, body.decode())

    def test_the_403_bodies_do_not_reflect_the_request_either(self):
        for host, origin in ((self.NEEDLE + ".example", None),
                             (None, "http://%s.example" % self.NEEDLE)):
            headers = {"Origin": origin} if origin else {}
            status, _h, body = raw_request(
                self.port, "GET", "/api/descriptor?k=%s" % self.NEEDLE,
                headers=headers, host=host, record=False)
            self.assertEqual(status, 403, body)
            self.assertNotIn(self.NEEDLE, body.decode())


class TestAdminTokenOnlyRidesAdminRoutes(unittest.TestCase):
    """12. The credential goes on POST /admin/issue and nowhere else.

    The console used to attach X-Admin-Token to every proxied request,
    including the descriptor poll the page fires every five seconds. The
    mint's access log records method, route and status only, so no log
    assertion can see this: it takes a mint that records its headers.
    """

    TOKEN = "RECORDED-ADMIN-TOKEN-abcdefghijklmnop"

    @classmethod
    def setUpClass(cls):
        cls.mint = RecordingMint()
        cls.console = InProcessConsole(cls.mint.port, admin_token=cls.TOKEN)
        cls.headers = cls.console.cookie()

    @classmethod
    def tearDownClass(cls):
        cls.console.stop()
        cls.mint.stop()

    @staticmethod
    def token_header(headers):
        for name, value in headers.items():
            if name.lower() == "x-admin-token":
                return value
        return None

    def sent(self, path):
        seen = self.mint.headers_for(path)
        self.assertTrue(seen, "the console never called %s" % path)
        return seen

    def test_the_descriptor_poll_carries_no_credential(self):
        status, _h, body = raw_request(self.console.port, "GET",
                                       "/api/descriptor",
                                       headers=self.headers, record=False)
        self.assertEqual(status, 200, body)
        for headers in self.sent("/v3/mints"):
            self.assertIsNone(self.token_header(headers),
                              "X-Admin-Token rode the 5-second poll")
            self.assertNotIn(self.TOKEN, "".join(headers.values()))

    def test_the_status_lookup_carries_no_credential(self):
        status, _h, body = raw_request(
            self.console.port, "POST", "/api/status", body={"q": "deadbeef"},
            headers=self.headers, record=False)
        self.assertEqual(status, 200, body)
        for headers in self.sent("/v3/status"):
            self.assertIsNone(self.token_header(headers),
                              "X-Admin-Token rode a public status lookup")

    def test_issuance_does_carry_it(self):
        """The narrowing must not have narrowed it to nothing: the one
        route that needs the credential still gets it, unaltered."""
        status, _h, body = raw_request(
            self.console.port, "POST", "/api/issue",
            body={"amount_mc": 1000, "count": 1}, headers=self.headers,
            record=False)
        self.assertEqual(status, 200, body)
        self.assertEqual(len(json.loads(body)["tokens"]), 1)
        sent = [self.token_header(h) for h in self.sent("/admin/issue")]
        self.assertTrue(sent and all(v == self.TOKEN for v in sent),
                        "the credentialled route did not present the token: %r"
                        % (sent,))

    def test_across_every_route_only_admin_issue_ever_saw_it(self):
        for method, path, payload in API_ROUTES:
            raw_request(self.console.port, method, path, body=payload,
                        headers=self.headers, record=False)
        carried = {path for _m, path, headers in self.mint.requests
                   if self.token_header(headers) is not None}
        self.assertEqual(carried, {"/admin/issue"},
                         "the credential reached %r" % (carried,))


class TestTheConsoleAnswersWhenTheMintIsGone(unittest.TestCase):
    """13. An authenticated request to a dead mint is an error envelope,
    not a dropped connection and a traceback."""

    @classmethod
    def setUpClass(cls):
        dead = free_port()              # bound, then closed: nothing listens
        cls.console = InProcessConsole(dead, admin_token="TOKEN-0123456789ab")
        cls.headers = cls.console.cookie()

    @classmethod
    def tearDownClass(cls):
        cls.console.stop()

    def test_a_dead_mint_is_a_502_with_a_reason(self):
        for method, path, payload in API_ROUTES:
            status, _h, body = raw_request(self.console.port, method, path,
                                           body=payload, headers=self.headers,
                                           record=False)
            self.assertEqual(status, 502, "%s %s answered %d" % (method, path, status))
            obj = json.loads(body)
            self.assertEqual(obj["error"]["reason"], "mint_unreachable")
            self.assertNotIn("TOKEN-0123456789ab", body.decode())

    def test_the_gate_still_comes_first(self):
        """A dead mint must not become a way to learn anything without the
        cookie: unauthenticated is still 401, not 502."""
        status, _h, body = raw_request(self.console.port, "GET",
                                       "/api/descriptor", record=False)
        self.assertEqual(status, 401, body)


class TestReloadingThePageKeepsTheSession(ConsoleCase):
    """14. A new session per page load let a browser evict its own tabs."""

    def test_a_valid_cookie_is_not_replaced_on_every_load(self):
        headers, _cookie = self.open_session()
        status, hdrs, body = self.get("/", headers=headers, record=False)
        self.assertEqual(status, 200)
        self.assertIsNone(hdrs.get("Set-Cookie"),
                          "a page load with a valid cookie minted a session")
        self.assertIn(b"aicash mint console", body)

    def test_many_reloads_do_not_evict_the_tab_doing_them(self):
        import mint_console
        headers, _cookie = self.open_session()
        for _ in range(mint_console.MAX_SESSIONS + 8):
            status, _h, _b = self.get("/", headers=headers, record=False)
            self.assertEqual(status, 200)
        status, _h, body = self.get("/api/descriptor", headers=headers,
                                    record=False)
        self.assertEqual(status, 200,
                         "reloading the page logged the page out: %s" % body)


class TestSourceLevelInvariants(unittest.TestCase):
    """15. Two properties no black-box test can see.

    Swapping hmac.compare_digest for == leaves every HTTP test green, and
    so does re-introducing a raw compare_digest on a str. Both are cheap to
    pin by reading the source, so they are pinned by reading the source.
    """

    @classmethod
    def setUpClass(cls):
        import mint_console
        cls.mod = mint_console
        with open(mint_console.__file__) as fh:
            cls.source = fh.read()
        cls.tree = ast.parse(cls.source)

    def _segments(self, node, kinds):
        out = []
        for child in ast.walk(node):
            if isinstance(child, ast.Compare) and any(
                    isinstance(op, kinds) for op in child.ops):
                out.append(ast.get_source_segment(self.source, child) or "")
        return out

    def test_no_secret_is_compared_with_equals(self):
        bad = [seg for seg in self._segments(self.tree, (ast.Eq, ast.NotEq))
               if re.search(r"key|session|secret|token|digest", seg, re.I)]
        self.assertEqual(bad, [],
                         "a secret is compared with ==/!=: %r" % bad)

    def test_the_comparison_helper_uses_compare_digest_on_bytes(self):
        func = next(n for n in self.tree.body
                    if isinstance(n, ast.FunctionDef) and n.name == "_secret_eq")
        body = ast.get_source_segment(self.source, func)
        self.assertIn("hmac.compare_digest", body)
        self.assertIn(".encode(", body,
                      "compare_digest is called on str again; it raises on "
                      "non-ASCII, which is attacker-reachable input")
        self.assertEqual(self._segments(func, (ast.Eq, ast.NotEq)), [])

    def test_every_credential_comparison_goes_through_it(self):
        calls = [ast.get_source_segment(self.source, n)
                 for n in ast.walk(self.tree)
                 if isinstance(n, ast.Call)
                 and ast.get_source_segment(self.source, n.func)
                 == "hmac.compare_digest"]
        self.assertEqual(len(calls), 1,
                         "compare_digest is called in %d places; the guarded "
                         "helper should be the only one" % len(calls))

    def test_the_gate_is_not_a_prefix_test(self):
        """'everything except the page' rather than 'everything under
        /api/': the shape that makes the next route born locked."""
        self.assertNotIn('startswith("/api/")', self.source)
        self.assertIn("_session_authorized", self.source)

    def test_the_docs_do_not_promise_this_is_safe_to_expose(self):
        doc = textwrap.dedent(self.mod.__doc__ or "").lower()
        self.assertIn("loopback", doc)
        self.assertTrue("not safe to expose" in doc or "safe to expose" in doc,
                        "the module docstring stopped saying this is not safe "
                        "to expose")


if __name__ == "__main__":
    unittest.main()
