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

Since 2026-09-17 they also pin REQUEST FRAMING, which is the other half of
what this file is for. The console had no framing rule at all -- not a
stale copy of the mint's, no copy -- and the two defect classes met here:
six Content-Length spellings took the handler out with NO RESPONSE ON THE
WIRE AT ALL, and every Transfer-Encoding spelling the mint refuses was
answered as though the request had no body. The rule is now imported from
aicash.mintapi, shared with the mint's two handlers and the operator GUI,
and the tests below drive it over raw sockets the same way the
authentication tests drive the four gates. `raw_bytes` exists for them:
it sends exactly the octets given, tolerates a server that answers before
reading the body, and returns EVERY response on the connection, so a test
can tell one answer from two.

Since 2026-09-17 they also pin the OTHER member of "it answers nothing at
all", which the first sweep could not see. Every hostile shape that sweep
built said HTTP/1.1, and the only protocol version this console was silent
on was HTTP/0.9: a request line with two words, on which the stdlib makes
every status line and header a no-op, so the composed answer -- the framing
refusal included -- went out as a naked body with no length and no
Connection: close. A sweep is only as wide as its shapes, so the shapes now
include that one. And ``declared_body_unread``, the one verdict branch whose
only effect is must_close, is driven at last: with keep-alive turned on in
its own fixture, so the two cases are observably different rather than both
satisfied by the HTTP/1.0 accident.

Since 2026-09-17 they also pin THE OTHER SPELLING OF THAT SAME PROTOCOL,
and the reason this paragraph exists is worth more than the tests under it.
The coverage described above was green, and it certified an open door: every
HTTP/0.9 shape it sent was the TWO-WORD one, which the console already
refused, while a THREE-WORD request line whose version token is literally
``HTTP/0.9`` walked straight past the word count -- the stdlib can read that
version, so it sets ``request_version`` from the wire and every
header-composing call in the file goes back to being a no-op. Measured over
raw sockets, on the real console, before the fix: the signed descriptor, the
console page, the unauthenticated 401, the framing refusal and the
bad-target refusal all came back with NO STATUS LINE, and ``POST /api/issue
HTTP/0.9`` MINTED THE MONEY and handed the bearer token back as 82 naked
octets. A suite that is green over the wrong shape is worse than no suite,
because it reads as coverage; these tests send both spellings, on every
route, and one of them asserts that the mint was never asked to mint.

And two more shapes that got nothing back at all. A peer sending ONE OCTET
EVERY TWO SECONDS into the header block held a thread and an fd past 76
seconds, because ``Console.timeout`` is an IDLE bound and every byte re-arms
it; the whole-request deadline is driven here with the budget turned down.
A well-formed request preceded by ONE EMPTY LINE -- what a client that ended
its last body with a stray CRLF emits, and which RFC 7230 3.5 says to
tolerate -- was silently discarded, zero bytes back. Both are driven over
raw sockets, and both failed against the file as it shipped that morning.

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


def parsed_headers(text):
    """The header object a server actually gets, built from real bytes.

    ``framing_verdict`` is asked about ``self.headers``, which is what
    ``http.client.parse_headers`` produced from the wire -- not a hand-built
    ``email.message.Message``, whose payload is None rather than the empty
    string and which therefore is not the shape the rule reasons about.
    """
    return http.client.parse_headers(io.BytesIO(text.encode("latin-1")))


class RawExchange:
    """Every byte a server sent back on one connection, and whether it hung
    up. Deliberately not parsed by http.client: the interesting failures
    here are "nothing came back", "two responses came back for one request"
    and "the socket stayed open", and a client library turns all three into
    either an exception or a single tidy response object."""

    def __init__(self, raw, still_open):
        self.raw = raw
        self.still_open = still_open

    @property
    def statuses(self):
        return [int(code) for code in
                re.findall(rb"HTTP/1\.[01] (\d{3})", self.raw)]

    @property
    def status(self):
        return self.statuses[0] if self.statuses else None

    @property
    def body(self):
        parts = self.raw.split(b"\r\n\r\n", 1)
        return parts[1] if len(parts) > 1 else b""

    def json(self):
        return json.loads(self.body)

    def describe(self):
        if not self.raw:
            return "NO RESPONSE AT ALL (socket dropped)"
        return "%r%s%s" % (self.raw.split(b"\r\n", 1)[0],
                           " [%d responses]" % len(self.statuses)
                           if len(self.statuses) != 1 else "",
                           " [socket still open]" if self.still_open else "")


def raw_bytes(port, request, timeout=12.0, record=True):
    """Send exactly ``request`` and read until the server hangs up.

    The send runs on its own thread because a correct server may refuse a
    declared body BEFORE reading it -- 413 on an oversized Content-Length
    does exactly that -- and a single-threaded sendall of two megabytes
    into a socket nobody is draining deadlocks the test, not the server.
    """
    sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    sock.settimeout(timeout)

    def push():
        try:
            sock.sendall(request)
        except OSError:
            pass                       # refused before we finished; fine

    sender = threading.Thread(target=push, daemon=True)
    sender.start()
    chunks, still_open = [], False
    try:
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    except (socket.timeout, TimeoutError):
        still_open = True
    except OSError:
        pass
    finally:
        try:
            sock.close()
        except OSError:
            pass
        sender.join(timeout=2)
    exchange = RawExchange(b"".join(chunks), still_open)
    if record:
        TRANSCRIPT.append("raw %r -> %s\n%s" % (
            request[:60], exchange.describe(),
            exchange.raw.decode("utf-8", "replace")))
    return exchange


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


def start_console(port, extra=(), workdir=None, token_file=True):
    """A real `python3 mint_console.py` process, as an operator runs it.

    ``token_file=False`` omits --admin-token-file entirely, which is what a
    --no-admin-token console has to be started as: naming a credential file
    and asking for no credential is refused as contradictory.
    """
    cred = (["--admin-token-file", STATE["token_file"]] if token_file else [])
    proc = subprocess.Popen(
        [sys.executable, CONSOLE, "--port", str(port),
         "--mint-port", str(STATE["mint_port"]), "--mint-id", MINT_ID]
        + cred + list(extra),
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

    def test_two_host_headers_are_refused_whichever_one_is_the_good_one(self):
        """A header stated twice is a header two hops may resolve
        differently -- which is the exact reason the shared framing rule
        refuses a duplicated Content-Length, one field over.

        ``headers.get("Host")`` reads the FIRST, so
        ``Host: 127.0.0.1:<port>`` followed by ``Host: evil.example``
        passed this gate and reached a live mint with the operator
        credential on it, while an intermediary reading the last one
        believes it forwarded the request to evil.example. Loopback-only,
        so a small hole; the same class all the same.
        """
        cookie = ("Cookie: %s\r\n" % self.cookie()["Cookie"]).encode()
        good = b"Host: 127.0.0.1:%d\r\n" % self.port
        evil = b"Host: evil.example\r\n"
        for name, block in (("good first", good + evil),
                            ("evil first", evil + good),
                            ("the same good host twice", good + good)):
            with self.subTest(name):
                exchange = raw_bytes(self.port, (
                    b"GET /api/descriptor HTTP/1.1\r\n" + block + cookie
                    + b"\r\n"), record=False)
                self.assertEqual(exchange.status, 403,
                                 "%s: %s" % (name, exchange.describe()))
                self.assertEqual(self.console_reason_of(exchange), "bad_host",
                                 "%s: %s" % (name, exchange.describe()))

    @staticmethod
    def console_reason_of(exchange):
        try:
            envelope = exchange.json().get("error")
        except ValueError:
            return None
        return envelope.get("reason") if isinstance(envelope, dict) else None


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


class TestStartupCredential(unittest.TestCase):
    """8. The absence of an operator credential is REFUSED, not assumed.

    Same shape as the library's L19 change, at the console: a console with
    no credential cannot issue, so it must say so at startup rather than at
    the first click of Issue. And "no credential" has to include the forms
    an absent credential actually arrives in -- a missing file, a null
    field, an empty string, a variable that expanded to whitespace -- not
    just the ones that are falsy in Python.
    """

    def run_console(self, extra, timeout=30):
        """Start a console that is expected to REFUSE, and collect it."""
        proc = subprocess.Popen(
            [sys.executable, CONSOLE, "--port", "0",
             "--mint-port", str(STATE["mint_port"]), "--mint-id", MINT_ID]
            + list(extra),
            cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True)
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, err = proc.communicate()
            self.fail("the console STARTED on a credential it should have "
                      "refused; it did not exit. stdout=%r" % out[:400])
        return proc.returncode, out, err

    def token_file(self, contents):
        d = tempfile.mkdtemp(prefix="consoletok-")
        self.addCleanup(shutil.rmtree, d, True)
        path = os.path.join(d, "mint-admin-keys.json")
        with open(path, "w") as fh:
            fh.write(contents)
        return path

    def test_no_credential_flag_at_all_refuses_to_start(self):
        code, _out, err = self.run_console(
            ["--admin-token-file", self.token_file('{}')])
        self.assertEqual(code, 1, err)
        self.assertIn("will not start without one", err)
        # It must name all three ways out, or the refusal is a dead end.
        for flag in ("--admin-token-file", "--admin-token", "--no-admin-token"):
            self.assertIn(flag, err)

    def test_a_missing_token_file_refuses_to_start(self):
        d = tempfile.mkdtemp(prefix="consoletok-")
        self.addCleanup(shutil.rmtree, d, True)
        code, _out, err = self.run_console(
            ["--admin-token-file", os.path.join(d, "nope.json")])
        self.assertEqual(code, 1, err)
        self.assertIn("does not exist", err)

    def test_every_shape_of_an_absent_credential_refuses_to_start(self):
        """The forms an empty credential really arrives in. A whitespace
        token is the one that used to get through: it is truthy, so the
        console started "credentialled", promised issuance and collected a
        401 at the first click."""
        cases = {
            "null field": '{"admin_token": null}',
            "empty string": '{"admin_token": ""}',
            "one space": '{"admin_token": " "}',
            "a newline": '{"admin_token": "\\n"}',
            "tabs and spaces": '{"admin_token": " \\t "}',
            "wrong type": '{"admin_token": 12345}',
            "no field": '{"something_else": "x"}',
        }
        for label, blob in cases.items():
            with self.subTest(credential=label):
                code, out, err = self.run_console(
                    ["--admin-token-file", self.token_file(blob)])
                self.assertEqual(code, 1, "%s: %r" % (label, err))
                self.assertIn("no operator credential", err)
                self.assertNotIn("?k=", out,
                                 "%s: a capability URL was printed by a "
                                 "console that should not have started"
                                 % label)

    def test_an_empty_or_whitespace_admin_token_flag_refuses_to_start(self):
        for bad in ("", " ", "   ", "\t"):
            with self.subTest(token=repr(bad)):
                code, _out, err = self.run_console(["--admin-token", bad])
                self.assertEqual(code, 1, err)
                self.assertIn("no operator credential", err)

    def test_the_refusal_never_echoes_the_credential_it_read(self):
        """A console that fails to start writes to somebody's terminal and
        very often to a log. The value it rejected was meant to be secret
        even when it is junk."""
        secret = "not-a-real-token-but-still-a-secret-9f3a"
        code, out, err = self.run_console(
            ["--admin-token-file", self.token_file(
                '{"admin_token": %d}' % 4242)])
        self.assertEqual(code, 1)
        self.assertNotIn("4242", err)
        self.assertNotIn("4242", out)
        # And a badly-formed file's CONTENTS never reach the message either.
        code, out, err = self.run_console(
            ["--admin-token-file", self.token_file(secret)])
        self.assertEqual(code, 1)
        self.assertNotIn(secret, err, "the file's contents were echoed")
        self.assertNotIn(secret, out)

    def test_no_admin_token_starts_read_only_and_issuance_answers_503(self):
        """The deliberate opt-out. It must work, it must say what it is,
        and its 503 must not claim the mint refused anything."""
        port = free_port()
        proc, out, _err = start_console(port, extra=["--no-admin-token"],
                                        token_file=False)
        self.addCleanup(stop, proc)
        banner = wait_for(lambda: "?k=" in out.text and out.text,
                          "the read-only console banner")
        self.assertIn("cannot issue", banner)
        self.assertIn("read-only", banner.lower())
        self.assertNotIn("minting credential", banner,
                         "a console with NO credential said its captured "
                         "stdout holds a minting credential")
        key = re.search(r"\?k=([A-Za-z0-9_\-]+)", banner).group(1)
        status, hdrs, _b = raw_request(port, "GET", "/?k=" + key)
        self.assertEqual(status, 200)
        cookie = hdrs.get("Set-Cookie").split(";")[0]
        # Read-only really is read-only, and really does still read.
        status, _h, body = raw_request(port, "GET", "/api/descriptor",
                                       headers={"Cookie": cookie})
        self.assertEqual(status, 200, body)
        status, _h, body = raw_request(
            port, "POST", "/api/issue", body={"amount_mc": 1000, "count": 1},
            headers={"Cookie": cookie})
        self.assertEqual(status, 503, body)
        err = json.loads(body)["error"]
        self.assertEqual(err["reason"], "no_admin_credential")
        # The pinned vocabulary: the mint never saw this request, so nothing
        # here may report it as something the mint refused. The detail is
        # allowed to say the mint did NOT refuse it -- that is the point --
        # so this looks for the CLAIM, not for the word.
        detail = err["detail"].lower()
        self.assertIn("did not send", detail)
        self.assertIn("never saw it", detail)
        self.assertIn("did not refuse it", detail)
        for claim in ("the mint refused", "the mint rejected",
                      "rejected by the mint", "refused by the mint",
                      "the mint answered"):
            self.assertNotIn(claim, detail,
                             "a request the mint never received was reported "
                             "as something the mint did")

    def test_asking_for_no_credential_is_not_overridden_by_one(self):
        """--no-admin-token used to be checked only AFTER the credential
        lookup, so on any machine where the default mint-admin-keys.json
        existed the flag was silently ignored and the console came up
        holding a live minting credential. Naming a credential alongside it
        is now refused as the contradiction it is."""
        for extra in (["--no-admin-token", "--admin-token", "some-secret"],
                      ["--no-admin-token", "--admin-token-file",
                       STATE["token_file"]]):
            with self.subTest(argv=extra):
                code, out, err = self.run_console(extra)
                self.assertEqual(code, 2, err)
                self.assertIn("contradictory", err)
                self.assertNotIn("?k=", out)

    def test_a_read_only_console_still_needs_its_session_cookie(self):
        """--no-admin-token drops the operator credential, not the lock on
        the console's own door."""
        port = free_port()
        proc, _out, _err = start_console(port, extra=["--no-admin-token"],
                                         token_file=False)
        self.addCleanup(stop, proc)
        status, _h, body = raw_request(
            port, "POST", "/api/issue", body={"amount_mc": 1, "count": 1})
        self.assertEqual(status, 401, body)


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


# ----------------------------------------------------------------------
# request framing
#
# The tables below are not a list of bad header spellings to keep up to
# date -- a list is what was wrong the first two times this defect was
# fixed. They are a sample of one CLASS, kept here so a regression in the
# shared rule is visible from the console's own suite: the separator in a
# field name is the part other software rewrites (nginx's
# underscores_in_headers, Apache and IIS folding `_` to `-`), and
# whitespace before a colon makes Python's email parser drop the field
# entirely, so no lookup by name can ever see it. The verdict that must
# hold for every row is the same one: this console cannot be certain where
# the body ends, so it does not read one, it answers, and it hangs up.
# ----------------------------------------------------------------------
TRANSFER_CODING_SPELLINGS = {
    # Registered under the canonical name.
    "canonical": b"Transfer-Encoding: chunked\r\n",
    "lowercase": b"transfer-encoding: chunked\r\n",
    "mixed case": b"TrAnSfEr-EnCoDiNg: chunked\r\n",
    "tab-separated value": b"Transfer-Encoding:\tchunked\r\n",
    "identity then chunked": b"Transfer-Encoding: identity, chunked\r\n",
    "chunked beside a zero length":
        b"Transfer-Encoding: chunked\r\nContent-Length: 0\r\n",
    "chunked beside an honest length":
        b"Transfer-Encoding: chunked\r\nContent-Length: 32\r\n",
    # Not registered AT ALL: RFC 7230 3.2.4 forbids whitespace before the
    # colon, and Python's parser answers by not producing a field.
    "one space before the colon": b"Transfer-Encoding : chunked\r\n",
    "two spaces before the colon": b"Transfer-Encoding  : chunked\r\n",
    "a tab before the colon": b"Transfer-Encoding\t: chunked\r\n",
    "no colon at all": b"Transfer-Encoding chunked\r\n",
    # Obsolete line folding: the continuation is swallowed into the value
    # of whatever preceded it, so the transfer coding vanishes silently.
    "obsolete line folding": b"Transfer-Encoding: \r\n chunked\r\n",
    "folded onto the Host header": b"Host: 127.0.0.1\r\n Transfer-Encoding: chunked\r\n",
    # Registered, but under a name no lookup asks for -- and a front end
    # that normalises the separator has ALREADY dechunked the body.
    "underscore": b"Transfer_Encoding: chunked\r\n",
    "dot": b"Transfer.Encoding: chunked\r\n",
    "pipe": b"Transfer|Encoding: chunked\r\n",
    "double underscore": b"Transfer__Encoding: chunked\r\n",
    "no separator at all": b"TransferEncoding: chunked\r\n",
    "a digit where the hyphen goes": b"Transfer0Encoding: chunked\r\n",
    # The neighbouring field, same class.
    "Content-Length spaced before the colon": b"Content-Length : 32\r\n",
    "Content_Length": b"Content_Length: 32\r\n",
    "Content-Length with a tab before the colon": b"Content-Length\t: 32\r\n",
    "ContentLength": b"ContentLength: 32\r\n",
    # Two lengths: RFC 7230 3.3.3 says reject, and the danger is precisely
    # that an intermediary may pick the other one.
    "duplicated Content-Length": b"Content-Length: 2\r\nContent-Length: 32\r\n",
    "duplicated Content-Length that agrees":
        b"Content-Length: 32\r\nContent-Length: 32\r\n",
}

# Content-Length VALUES. The first group is the one that took the handler
# out with no response at all; the second is the one int() read as a length
# that a spec-strict hop reads as no length.
# Every value below is sent with TestContentLengthValuesAreAnAnswer.BODY,
# which is exactly 32 octets -- so the ones int() accepts really do frame
# the whole body, and the test is measuring the console's rule rather than
# an accidental short read. Measured against the pre-round file: eight of
# these answered NOTHING AT ALL, four were read as a 32-octet body a
# spec-strict hop rejects outright, and `-1` parked a worker thread.
CONTENT_LENGTH_VALUES = {
    # Answered nothing at all: ValueError or OverflowError out of the
    # handler, socket dropped, traceback on the operator's terminal.
    "five thousand digits": b"1" * 5000,       # the reported shape
    "twenty digits": b"9" * 20,
    "not a number": b"abc",
    "the comma form": b"2, 32",
    "hex": b"0x20",
    "a float": b"32.0",
    "a space inside": b"3 2",
    # int() reads fullwidth digits as 32 in a Python source file; off the
    # wire the value arrives latin-1-decoded, so it raised instead. Either
    # way it is not `1*DIGIT` and there is no length here to trust.
    "unicode digits": "３２".encode("utf-8"),
    # Read as a 32-octet body by int()'s looser grammar, while any parser
    # using HTTP's own reads an invalid length and must not recover.
    "leading plus": b"+32",
    "PEP 515 underscores": b"3_2",
    "a vertical tab suffix": b"32\x0b",
    "a non-breaking space suffix": b"32\xa0",
    # Negative: `read(-1)` reads to EOF and parked a thread forever;
    # `read(-32)` raised ValueError, which the old reader reported to the
    # caller as "bad_json" -- a framing failure blamed on their payload.
    "leading minus": b"-32",
    "minus one": b"-1",
    # Not a length at all.
    "empty": b"",
}


# One 32-octet body, sent chunked. 0x20 = 32, the same length every
# CONTENT_LENGTH_VALUES row declares, so a spelling that is NOT refused
# really would have framed a whole request off the wire.
CHUNKED_BODY = b"20\r\n{\"q\": \"deadbeefdeadbeefdeadbee\"}\r\n0\r\n\r\n"


class FramingCase(ConsoleCase):
    """Raw-socket framing tests against the real authenticated console."""

    # A complete, well-formed, authenticated request appended after the
    # request under test. If the console frames the body wrongly, these
    # octets become the next request line and this one gets ANSWERED --
    # two responses for one request, which is the whole of the attack.
    def smuggled_tail(self, cookie):
        return (b"GET /api/descriptor HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                % self.port) + cookie + b"\r\n"

    def cookie_header(self):
        if getattr(self, "_cookie_header", None) is None:
            self._cookie_header = ("Cookie: %s\r\n"
                                   % self.cookie()["Cookie"]).encode()
        return self._cookie_header

    def build(self, method, path, header_lines, body=b"", cookie=None,
              tail=True):
        cookie = self.cookie_header() if cookie is None else cookie
        request = (b"%s %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                   % (method, path, self.port)) + cookie
        request += b"Content-Type: application/json\r\n"
        request += header_lines + b"\r\n" + body
        if tail:
            request += self.smuggled_tail(cookie)
        return request

    @staticmethod
    def console_reason(exchange):
        """The console's own refusal word, or None if it did not send one.

        Never indexes blindly: the console's older route-level errors are
        ``{"error": "<a string>"}``, and a test that did
        ``json()["error"]["reason"]`` on one reported a TypeError instead of
        the answer the console actually gave.
        """
        try:
            envelope = exchange.json().get("error")
        except ValueError:
            return None
        return envelope.get("reason") if isinstance(envelope, dict) else None

    def assertHadAStatusLine(self, exchange, what):
        """One framed answer, and the socket said it was going.

        On FramingCase rather than on one 0.9 class because BOTH spellings
        of HTTP/0.9 assert exactly this, and a second copy of it was how
        the first spelling came to be the only one anyone checked.
        """
        self.assertTrue(exchange.raw,
                        "%s: NO RESPONSE AT ALL" % what)
        self.assertIsNotNone(
            exchange.status,
            "%s: the console answered with NO STATUS LINE -- %r. That is a "
            "naked HTTP/0.9 body: an intermediary cannot read it as a "
            "refusal, it carries no length, and it cannot say the "
            "connection is going" % (what, exchange.raw[:120]))
        self.assertEqual(len(exchange.statuses), 1,
                         "%s: %s" % (what, exchange.describe()))
        self.assertFalse(exchange.still_open,
                         "%s: the socket survived a request this server "
                         "will not answer in kind" % what)
        self.assertIn(b"connection: close",
                      exchange.raw.split(b"\r\n\r\n", 1)[0].lower(),
                      "%s: hung up without saying so: %s"
                      % (what, exchange.describe()))

    def assertRefusedAndHungUp(self, exchange, what):
        self.assertTrue(exchange.raw,
                        "%s: NO RESPONSE AT ALL -- the console dropped the "
                        "socket without a status line" % what)
        self.assertEqual(
            len(exchange.statuses), 1,
            "%s: %d responses came back for one request, so octets the "
            "console never read were framed as another request: %s"
            % (what, len(exchange.statuses), exchange.describe()))
        self.assertEqual(exchange.status, 400,
                         "%s answered %s, not 400: %s"
                         % (what, exchange.status, exchange.describe()))
        self.assertFalse(exchange.still_open,
                         "%s: the connection survived a request whose body "
                         "could not be framed" % what)
        self.assertIn(b"connection: close",
                      exchange.raw.split(b"\r\n\r\n", 1)[0].lower(),
                      "%s: the console hung up without SAYING so. Dropping "
                      "the socket is enough for a peer talking to us "
                      "directly and is not enough for anything in between "
                      "-- the original report against the mint turned on a "
                      "400 answered without Connection: close, after which "
                      "the octets it never read were framed as the next "
                      "request line: %s" % (what, exchange.describe()))
        try:
            obj = exchange.json()
        except ValueError:
            self.fail("%s: the refusal was not JSON: %r"
                      % (what, exchange.body[:200]))
        envelope = obj.get("error")
        self.assertIsInstance(
            envelope, dict,
            "%s: the console answered %r, not its framing envelope -- a 400 "
            "that says 'bad_json' is a body it READ, which means it framed "
            "one it should not have" % (what, obj))
        self.assertEqual(envelope.get("reason"), "bad_framing",
                         "%s: %r" % (what, obj))
        self.assertTrue(envelope.get("detail"),
                        "%s: a refusal with nothing to act on" % what)


class TestEveryFramingSpellingIsRefused(FramingCase):
    """16. The console reaches the mint's verdict on the mint's bytes.

    Before this round it reached none of them: it had no framing rule, so
    a chunked POST read as an empty one and every spelling below either
    proxied a body the console had mis-measured or killed the handler.
    """

    def test_every_spelling_is_refused_and_the_connection_closes(self):
        for name, header_line in TRANSFER_CODING_SPELLINGS.items():
            with self.subTest(name):
                exchange = raw_bytes(self.port, self.build(
                    b"POST", b"/api/status", header_line, CHUNKED_BODY),
                    record=False)
                self.assertRefusedAndHungUp(exchange, name)

    def test_the_same_spellings_are_refused_on_every_post_route(self):
        """Framing is a property of the bytes, not of the route. /api/issue
        frames its body off the same socket /api/status does."""
        for path in (b"/api/issue", b"/api/status", b"/api/nonexistent",
                     b"/"):
            for name in ("one space before the colon", "underscore",
                         "duplicated Content-Length"):
                with self.subTest(path=path, spelling=name):
                    exchange = raw_bytes(self.port, self.build(
                        b"POST", path, TRANSFER_CODING_SPELLINGS[name],
                        CHUNKED_BODY), record=False)
                    self.assertRefusedAndHungUp(
                        exchange, "POST %s / %s" % (path.decode(), name))

    def test_the_get_routes_are_framed_too(self):
        """The GUI's sweep found its GET routes as bad as its POST routes.
        A GET body is never read by this layer either, so an unframable one
        is the same desync -- and GET / is the capability-URL route, the
        one place this console answers without a cookie."""
        cookie = self.cookie_header()
        for path in (b"/api/descriptor", b"/", b"/nope"):
            for name in ("canonical", "one space before the colon",
                         "underscore", "duplicated Content-Length"):
                with self.subTest(path=path, spelling=name):
                    exchange = raw_bytes(self.port, self.build(
                        b"GET", path, TRANSFER_CODING_SPELLINGS[name],
                        CHUNKED_BODY, cookie=cookie), record=False)
                    self.assertRefusedAndHungUp(
                        exchange, "GET %s / %s" % (path.decode(), name))

    def test_a_method_the_console_does_not_implement_is_framed_too(self):
        """PUT and DELETE reach no do_* method of this file at all -- the
        stdlib answers them 501 -- so a framing guard written at the top of
        do_GET and do_POST would miss them, and their unread chunk octets
        are exactly as smuggleable. This is why the guard sits in
        parse_request."""
        for method in (b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH",
                       b"TRACE"):
            with self.subTest(method=method):
                exchange = raw_bytes(self.port, self.build(
                    method, b"/api/status",
                    TRANSFER_CODING_SPELLINGS["one space before the colon"],
                    CHUNKED_BODY), record=False)
                self.assertRefusedAndHungUp(exchange, method.decode())

    def test_framing_is_decided_before_the_cookie_is_looked_at(self):
        """An unframable request is refused whether or not it is
        authenticated: where the body ends is a fact about the octets, and
        it has to be settled before any code path can read one."""
        for name in ("one space before the colon", "underscore"):
            with self.subTest(name):
                exchange = raw_bytes(self.port, self.build(
                    b"POST", b"/api/issue", TRANSFER_CODING_SPELLINGS[name],
                    CHUNKED_BODY, cookie=b""), record=False)
                self.assertRefusedAndHungUp(exchange, "no cookie / " + name)

    def test_a_well_formed_request_is_not_taxed(self):
        """The guard must refuse the CLASS and nothing else. Optional
        whitespace after the colon and leading zeros are both `1*DIGIT`
        with OWS (RFC 7230 3.3.2) and are perfectly legal lengths -- a
        framing rule that refused them would be a keep-alive tax dressed
        up as a security control."""
        body = json.dumps({"q": "deadbeef"}).encode()
        for name, line in (
                ("plain", b"Content-Length: %d\r\n" % len(body)),
                ("extra OWS", b"Content-Length:   %d\r\n" % len(body)),
                ("a tab after the colon",
                 b"Content-Length:\t%d\r\n" % len(body)),
                ("leading zeros", b"Content-Length: 00%d\r\n" % len(body))):
            with self.subTest(name):
                exchange = raw_bytes(self.port, self.build(
                    b"POST", b"/api/status", line, body, tail=False),
                    record=False)
                self.assertEqual(exchange.status, 200,
                                 "%s is a legal message and was answered "
                                 "%s: %s" % (name, exchange.status,
                                             exchange.describe()))

    def test_a_request_with_no_body_at_all_is_not_refused_as_unframable(self):
        """Absent is not unreadable. GET / carries no length and is the
        route the capability URL opens."""
        exchange = raw_bytes(self.port, self.build(
            b"GET", b"/api/descriptor", b"", b"", tail=False), record=False)
        self.assertEqual(exchange.status, 200, exchange.describe())


class TestContentLengthValuesAreAnAnswer(FramingCase):
    """17. THE FINDING: it answered nothing at all.

    ``int(self.headers.get("Content-Length") or 0)`` with no guard. A
    five-thousand-digit length raised ValueError out of do_POST, the
    console sent zero bytes, the socket was dropped, and socketserver
    printed a traceback. EIGHT of the values below did that; FOUR more were
    read as a 32-octet body by int()'s looser grammar while a spec-strict
    hop sees an invalid length and must not recover; one parked a worker
    thread forever; and one reported a framing failure as bad JSON.
    """

    BODY = json.dumps({"q": "deadbeefdeadbeefdeadbee"}).encode()   # 32

    def test_no_content_length_value_leaves_the_caller_with_nothing(self):
        for name, value in CONTENT_LENGTH_VALUES.items():
            with self.subTest(name):
                exchange = raw_bytes(self.port, self.build(
                    b"POST", b"/api/status",
                    b"Content-Length: " + value + b"\r\n", self.BODY),
                    record=False)
                self.assertTrue(
                    exchange.raw,
                    "Content-Length %r: NO RESPONSE AT ALL. The handler "
                    "died and the socket was dropped." % name)
                self.assertRefusedAndHungUp(exchange, "Content-Length " + name)

    def test_the_reported_shape_specifically(self):
        """Five thousand digits, the exact input the outside reviewer
        pointed at the mint. Pinned on its own so the row cannot be quietly
        dropped from the table above."""
        exchange = raw_bytes(self.port, self.build(
            b"POST", b"/api/issue", b"Content-Length: " + b"9" * 5000 +
            b"\r\n", b'{"amount_mc": 1000, "count": 1}'), record=False)
        self.assertEqual(exchange.status, 400, exchange.describe())
        self.assertEqual(exchange.json()["error"]["reason"], "bad_framing")

    def test_a_declared_body_larger_than_the_cap_is_refused_unread(self):
        """`Content-Length: 4294967296` used to become
        `rfile.read(4294967296)`: a one-line memory request. Nothing is
        read now, which is why this answers instantly with no body sent."""
        exchange = raw_bytes(self.port, self.build(
            b"POST", b"/api/status",
            b"Content-Length: 4294967296\r\n", b"", tail=False),
            record=False)
        self.assertEqual(exchange.status, 413, exchange.describe())
        self.assertEqual(exchange.json()["error"]["reason"], "body_too_large")
        self.assertFalse(exchange.still_open)

    def test_an_oversized_body_actually_sent_is_refused_too(self):
        big = b'{"q": "' + b"A" * (2 * 1024 * 1024) + b'"}'
        exchange = raw_bytes(self.port, self.build(
            b"POST", b"/api/status",
            b"Content-Length: %d\r\n" % len(big), big, tail=False),
            record=False)
        self.assertEqual(exchange.status, 413, exchange.describe())


class TestNothingAnswersWithNothing(FramingCase):
    """18. The class, swept: no shape gets silence, and no shape puts an
    interpreter traceback in front of the operator.

    The console's stderr is the second assertion and the more important
    one. ``NO RESPONSE AT ALL`` is what the CALLER saw; a traceback
    through socketserver's handle_error is what the OPERATOR saw, and the
    startup banner warns that a service manager may be capturing it.

    A SWEEP IS ONLY AS WIDE AS ITS SHAPES, and this one had a hole of
    exactly that kind until 2026-09-17: every shape it built said
    ``HTTP/1.1``, and the one protocol version this console was silent on
    was HTTP/0.9 -- a request line with two words, on which the stdlib
    makes every status line and header a no-op, so the composed body went
    out naked on every route including the framing refusal. The class whose
    job is "no shape gets silence" could not see the silence because it
    never sent that shape. It sends it now; the assertions with names on
    them are in ``TestAVersionlessRequestLineIsAnswered``.
    """

    def hostile_shapes(self):
        cookie = self.cookie_header()
        shapes = []
        for name, line in TRANSFER_CODING_SPELLINGS.items():
            shapes.append(("TE " + name,
                           self.build(b"POST", b"/api/status", line,
                                      b"20\r\n{\"q\": \"deadbeefdeadbeefdeadbee\"}"
                                      b"\r\n0\r\n\r\n", cookie=cookie)))
        for name, value in CONTENT_LENGTH_VALUES.items():
            shapes.append(("CL " + name,
                           self.build(b"POST", b"/api/status",
                                      b"Content-Length: " + value + b"\r\n",
                                      b'{"q": "deadbeefdeadbeefdeadbee"}',
                                      cookie=cookie)))
        for name, body in (
                ("q is a number", b'{"q": 5}'),
                ("q is true", b'{"q": true}'),
                ("q is an object", b'{"q": {"a": 1}}'),
                ("q is a list", b'{"q": [1]}'),
                ("amount_mc is true", b'{"amount_mc": true, "count": 1}'),
                ("count is true", b'{"amount_mc": 1000, "count": true}'),
                ("amount_mc past the token ceiling",
                 b'{"amount_mc": 10000000000000000000000000000000, '
                 b'"count": 1}'),
                ("amount_mc past the interpreter's digit limit",
                 b'{"amount_mc": ' + b"9" * 5000 + b', "count": 1}'),
                ("a hundred thousand open brackets", b"[" * 100000),
                ("not json at all", b"<html>"),
                ("json that is not an object", b'"just a string"'),
                ("an unterminated string", b'{"q": "abc')):
            path = (b"/api/issue" if b"amount_mc" in body
                    else b"/api/status")
            shapes.append((name, self.build(
                b"POST", path, b"Content-Length: %d\r\n" % len(body), body,
                cookie=cookie, tail=False)))
        for target in (b"http://[", b"http://[v1.x]", b"http://[::1",
                       b"http://[]:99999999999999999999", b"//[v1.x",
                       b"http://[1:2:3", b"*"):
            shapes.append(("target " + target.decode("latin-1"),
                           b"GET " + target + b" HTTP/1.1\r\n"
                           b"Host: 127.0.0.1:%d\r\n" % self.port
                           + cookie + b"\r\n"))
        # HTTP/0.9: A REQUEST LINE WITH NO VERSION ON IT. Every row above
        # says HTTP/1.1, and for a long time that was the whole hole in this
        # class -- the one protocol version on which this console answered
        # with no status line at all was the one version no shape used, so a
        # sweep that exists to prove "nothing gets silence" could not see the
        # silence. `self.build()` cannot make these; they are written out.
        # TestAVersionlessRequestLineIsAnswered drives the same family with
        # the full set of assertions; these rows are here so the SWEEP sees
        # it too, which is the part that was missing.
        for name, line in list(TRANSFER_CODING_SPELLINGS.items())[:6]:
            shapes.append(("0.9 TE " + name,
                           b"GET /\r\n" + line + b"\r\n"))
        for name, value in list(CONTENT_LENGTH_VALUES.items())[:6]:
            shapes.append(("0.9 CL " + name,
                           b"GET /\r\nContent-Length: " + value + b"\r\n\r\n"))
        for name, raw in (
                ("0.9 the page route", b"GET /\r\n\r\n"),
                ("0.9 the capability URL",
                 b"GET /?k=" + self.key.encode() + b"\r\n\r\n"),
                ("0.9 an api route",
                 b"GET /api/descriptor\r\n" + cookie + b"\r\n"),
                ("0.9 an unknown route", b"GET /zzz\r\n" + cookie + b"\r\n"),
                ("0.9 an unsplittable target", b"GET http://[\r\n\r\n"),
                ("0.9 POST, which 0.9 has no word for", b"POST /\r\n\r\n"),
                ("a one-word request line", b"GET\r\n\r\n")):
            shapes.append((name, raw))
        # AND THE SPELLED-OUT VERSION OF THE SAME PROTOCOL. Every 0.9 row
        # above is the two-word spelling, which this console already
        # refused; the three-word one -- a version token the stdlib CAN
        # read, so ``request_version`` comes off the wire -- went naked on
        # every route while this class was green. A sweep is only as wide
        # as its shapes, twice over.
        for name, raw in (
                ("0.9 spelled out, the page route", b"GET / HTTP/0.9\r\n\r\n"),
                ("0.9 spelled out, the capability URL",
                 b"GET /?k=" + self.key.encode() + b" HTTP/0.9\r\n\r\n"),
                ("0.9 spelled out, an api route",
                 b"GET /api/descriptor HTTP/0.9\r\nHost: 127.0.0.1:%d\r\n"
                 % self.port + cookie + b"\r\n"),
                ("0.9 spelled out, unauthenticated",
                 b"GET /api/descriptor HTTP/0.9\r\n\r\n"),
                ("0.9 spelled out, an unknown route",
                 b"GET /zzz HTTP/0.9\r\n" + cookie + b"\r\n"),
                ("0.9 spelled out, an unsplittable target",
                 b"GET http://[ HTTP/0.9\r\n\r\n"),
                ("0.9 spelled out, a framing refusal",
                 b"GET / HTTP/0.9\r\nTransfer-Encoding: chunked\r\n\r\n"
                 b"0\r\n\r\n"),
                ("0.9 spelled out, POST issuance",
                 b"POST /api/issue HTTP/0.9\r\nHost: 127.0.0.1:%d\r\n"
                 % self.port + cookie
                 + b"Content-Type: application/json\r\n"
                   b"Content-Length: 30\r\n\r\n"
                   b'{"amount_mc": 1000, "count": 1}'),
                ("0.9 spelled out, a header block the stdlib refuses",
                 b"GET / HTTP/0.9\r\n"
                 + b"".join(b"X-%d: y\r\n" % i for i in range(200))
                 + b"\r\n"),
                ("one empty line, then a well-formed request",
                 b"\r\nGET /api/descriptor HTTP/1.1\r\n"
                 b"Host: 127.0.0.1:%d\r\n" % self.port + cookie + b"\r\n")):
            shapes.append((name, raw))
        return shapes

    def test_every_hostile_shape_gets_a_status_line(self):
        silent = []
        for name, request in self.hostile_shapes():
            exchange = raw_bytes(self.port, request, record=False)
            if not exchange.raw or exchange.status is None:
                silent.append(name)
            elif exchange.status >= 500:
                silent.append("%s (answered %d)" % (name, exchange.status))
        self.assertEqual(silent, [],
                         "these requests got no answer, or a 5xx, from the "
                         "console: %r" % (silent,))

    def test_a_request_target_the_console_cannot_split_is_a_400(self):
        """`_route()` splits self.path with urllib, and urlsplit RAISES on
        an unparseable authority. `GET http://[ HTTP/1.1` is absolute-form
        -- which RFC 7230 5.3.2 says a server must accept -- with a
        malformed IPv6 host, and it used to come out of do_GET as a
        ValueError with no response on the wire at all. Same class as the
        Content-Length finding, one field over."""
        cookie = self.cookie_header()
        # Only targets urlsplit really refuses: `http://[v1.x]` PARSES
        # (an IPvFuture literal is well formed) and is an honest 404, and a
        # test that demanded 400 for it would be pinning a bug.
        for target in (b"http://[", b"http://[::1", b"http://[:",
                       b"http://[1:2:3",
                       b"http://[]:99999999999999999999"):
            with self.subTest(target=target):
                request = (b"GET " + target + b" HTTP/1.1\r\n"
                           b"Host: 127.0.0.1:%d\r\n" % self.port
                           + cookie + b"\r\n")
                exchange = raw_bytes(self.port, request, record=False)
                self.assertIsNotNone(
                    exchange.status,
                    "%r got no answer at all" % target)
                self.assertEqual(exchange.status, 400, exchange.describe())
                self.assertEqual(exchange.json()["error"]["reason"],
                                 "bad_request_target", exchange.describe())

    def test_the_one_remaining_int_on_caller_text_cannot_raise(self):
        """SWEPT, not fixed: `_host_ok` still calls int() on a port, and
        that one is safe -- `_HOST_RE` matches `[0-9]{1,5}` end to end, so
        a value past five digits never reaches int() at all. The safety
        lives in the regex and not at the call site, which is exactly the
        coupling a later widening of the pattern would break silently, so
        it is pinned by BEHAVIOUR rather than by reading the pattern: every
        one of these must be an answer, and 403 is the right one."""
        for port in (b"9" * 5000, b"9" * 20, b"0", b"99999", b"65536",
                     b"+80", b"8_0", b"0x50", b""):
            with self.subTest(port=port):
                request = (b"GET /api/descriptor HTTP/1.1\r\n"
                           b"Host: 127.0.0.1:" + port + b"\r\n\r\n")
                exchange = raw_bytes(self.port, request, record=False)
                self.assertIsNotNone(
                    exchange.status,
                    "Host port %r got no answer at all -- int() raised out "
                    "of the host gate" % port[:20])
                self.assertEqual(exchange.status, 403, exchange.describe())
                self.assertEqual(exchange.json()["error"]["reason"],
                                 "bad_host", exchange.describe())

    def test_no_refusal_body_echoes_the_request_target(self):
        """The page route's target IS the capability key. None of the new
        refusals may hand it back, the way none of the 401 branches do."""
        secret = "CAPABILITY-LOOKING-VALUE-abcdef0123456789"
        for request in (
                b"GET /?k=" + secret.encode() + b" HTTP/1.1\r\n"
                b"Host: 127.0.0.1:%d\r\n"
                b"Transfer-Encoding : chunked\r\n\r\n" % self.port,
                b"GET http://[?k=" + secret.encode() + b" HTTP/1.1\r\n"
                b"Host: 127.0.0.1:%d\r\n\r\n" % self.port,
                b"POST /api/status?k=" + secret.encode() + b" HTTP/1.1\r\n"
                b"Host: 127.0.0.1:%d\r\n"
                b"Content-Length: abc\r\n\r\n" % self.port):
            exchange = raw_bytes(self.port, request, record=False)
            self.assertNotIn(secret.encode(), exchange.raw,
                             "a refusal echoed the request target: %s"
                             % exchange.describe())

    def test_no_traceback_reached_the_operators_terminal(self):
        for _name, request in self.hostile_shapes():
            raw_bytes(self.port, request, record=False)
        # The reader thread drains the pipe; give it a moment to catch up.
        deadline = time.monotonic() + 5.0
        text = ""
        while time.monotonic() < deadline:
            text = STATE["err"].text + STATE["out"].text
            if "Traceback" in text:
                break
            time.sleep(0.2)
        self.assertNotIn("Traceback", text,
                         "a request printed a stack trace through the "
                         "server machinery")
        self.assertNotIn("Exception occurred during processing", text)


class TestAVersionlessRequestLineIsAnswered(FramingCase):
    """18a. THE SECOND MEMBER OF "it answers nothing at all", and the one
    the sweep in class 18 was structurally unable to see.

    The first member is an exception that kills the handler before anything
    is written. This one needs no exception at all:
    ``BaseHTTPRequestHandler`` makes ``send_response_only()``,
    ``send_header()`` and ``end_headers()`` NO-OPS while
    ``request_version == "HTTP/0.9"``, so every answer the console composed
    for a two-word request line went out as a NAKED BODY -- no status line,
    no Content-Length, no ``Connection: close``. Measured before the fix, on
    a console started exactly as an operator starts it: all thirteen shapes
    below produced zero status lines, and the framing refusal itself was one
    of them. Feeding those bytes to http.client raises BadStatusLine, which
    is the reported defect verbatim: a refusal delivered in a form no
    intermediary can read as a refusal, with no length and no close.

    Why class 18 could not find it: ``hostile_shapes()`` builds every shape
    with ``HTTP/1.1``, and the only protocol version this console was silent
    on is the one version no shape used. Those rows are added there too; this
    class exists so the property has a name of its own.

    gui/app.py closed this exact member on 2026-09-15 (app.py, ``bad_version``,
    "THE OTHER WAY TO EMIT A RESPONSE WITH NO STATUS LINE") -- the answer was
    twenty feet away in this repository while the console was silent on every
    route.
    """

    def versionless_shapes(self):
        cookie = self.cookie_header()
        key = self.key.encode()
        return [
            # The framing refusals: the answer the shared rule earned,
            # delivered with nothing around it.
            ("TE chunked",
             b"GET /\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"),
            ("TE underscore",
             b"GET /\r\nTransfer_Encoding: chunked\r\n\r\n0\r\n\r\n"),
            ("TE space before the colon",
             b"GET /\r\nTransfer-Encoding : chunked\r\n\r\n0\r\n\r\n"),
            ("duplicated Content-Length",
             b"GET /\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n"),
            ("Content-Length abc", b"GET /\r\nContent-Length: abc\r\n\r\n"),
            ("Content-Length, five thousand digits",
             b"GET /\r\nContent-Length: " + b"9" * 5000 + b"\r\n\r\n"),
            # The other refusal this file composes.
            ("a target urlsplit refuses", b"GET http://[\r\n\r\n"),
            # And the ordinary answers, which were just as naked.
            ("the page route", b"GET /\r\n\r\n"),
            ("the capability URL", b"GET /?k=" + key + b"\r\n\r\n"),
            ("an api route", b"GET /api/descriptor\r\n" + cookie + b"\r\n"),
            ("an unknown route", b"GET /zzz\r\n" + cookie + b"\r\n"),
        ]

    def stdlib_shapes(self):
        """Request lines the BASE CLASS answers, before any code of ours
        runs. They were naked for the same reason and cannot be fixed in
        ``parse_request`` -- only by what the base class reads for a request
        line with no version on it, which is ``default_request_version``."""
        return [
            ("POST, which HTTP/0.9 has no word for", b"POST /\r\n\r\n"),
            ("a one-word request line", b"GET\r\n\r\n"),
        ]

    def test_every_versionless_request_gets_a_real_status_line(self):
        for name, request in self.versionless_shapes():
            with self.subTest(name):
                exchange = raw_bytes(self.port, request, record=False)
                self.assertHadAStatusLine(exchange, name)
                self.assertEqual(exchange.status, 400,
                                 "%s: %s" % (name, exchange.describe()))
                self.assertEqual(
                    self.console_reason(exchange), "bad_version",
                    "%s: a versionless request line has to be refused as "
                    "one, before anything composes an answer it cannot "
                    "frame: %s" % (name, exchange.describe()))

    def test_the_stdlibs_own_errors_are_framed_too(self):
        """The base class answers these itself and cannot be intercepted,
        so the fix has to be the default it reads, not a guard of ours."""
        for name, request in self.stdlib_shapes():
            with self.subTest(name):
                exchange = raw_bytes(self.port, request, record=False)
                self.assertHadAStatusLine(exchange, name)
                self.assertEqual(exchange.status, 400,
                                 "%s: %s" % (name, exchange.describe()))

    def test_the_refusal_is_readable_by_a_client_library(self):
        """The property stated the way a caller sees it: http.client raises
        BadStatusLine on a naked body, and that is precisely the report."""
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=12)
        try:
            sock.sendall(b"GET /\r\nTransfer-Encoding: chunked\r\n\r\n")
            response = http.client.HTTPResponse(sock)
            response.begin()            # raises BadStatusLine if naked
            self.assertEqual(response.status, 400)
            body = json.loads(response.read())
            self.assertEqual(body["error"]["reason"], "bad_version")
        finally:
            sock.close()

    def test_no_versionless_refusal_echoes_the_capability_key(self):
        """The page route's target IS the capability. The 0.9 refusals are
        answered before any route is looked at, and must not hand it back
        any more than the 401 branches do."""
        exchange = raw_bytes(self.port,
                             b"GET /?k=" + self.key.encode() + b"\r\n\r\n",
                             record=False)
        self.assertNotIn(self.key.encode(), exchange.raw,
                         "a versionless refusal echoed the capability URL")

    def test_a_real_http_1_0_request_is_still_answered_normally(self):
        """The negative control. Raising ``default_request_version`` must
        not make this server refuse HTTP/1.0, which is what it speaks."""
        cookie = self.cookie_header()
        exchange = raw_bytes(self.port, (
            b"GET /api/descriptor HTTP/1.0\r\nHost: 127.0.0.1:%d\r\n"
            % self.port) + cookie + b"\r\n", record=False)
        self.assertEqual(exchange.status, 200, exchange.describe())


class TestTheSpelledOutVersionIsRefusedToo(FramingCase):
    """22. THE OTHER SPELLING OF HTTP/0.9, and the door this suite's own
    coverage certified as closed while it stood open.

    ``TestAVersionlessRequestLineIsAnswered`` above drives HTTP/0.9 BY
    OMISSION -- a two-word request line, which the console refuses by
    counting the words. This class drives HTTP/0.9 BY STATEMENT: three
    words, the third of them literally ``HTTP/0.9``. The word count cannot
    see it. The stdlib CAN read that version token, so
    ``super().parse_request()`` returns True with ``request_version`` set
    FROM THE WIRE, and from that instant ``send_response_only``,
    ``send_header`` and ``end_headers`` are no-ops again -- on every route,
    including the refusals that exist to be readable.

    Measured on the real console over raw sockets, 2026-09-17, before the
    fix: seven routes, zero status lines. The signed descriptor came back
    as 1,126 naked octets. The console page came back naked. The
    unauthenticated 401 came back naked. And ``POST /api/issue HTTP/0.9``
    ASKED THE MINT TO CREATE MONEY and returned the bearer token as 82
    naked octets -- a credential handed to a caller in a form no
    intermediary can frame, log or truncate correctly.

    The fix is the mint's, not a third one: ``aicash.mintapi._Handler``
    keeps the word count ALONGSIDE a test of ``request_version``, because
    with ``default_request_version = "HTTP/1.1"`` a two-word line no longer
    presents as 0.9 and a version check alone would start serving it; it
    forces the field back to a real version so its own refusal is framed;
    and it refuses with a framed 400. All three, in that order, are what
    ``mint_console.Console.parse_request`` now does.

    THE LESSON THIS CLASS IS REALLY FOR: the suite was green before it
    existed, and its greenness was a claim about a door that was open. The
    0.9 coverage was entirely the spelling that was already handled. A
    suite that is green over the wrong shape is worse than no suite,
    because a reader stops looking.
    """

    def spelled_shapes(self):
        """Every route, spelled ``HTTP/0.9``, with the gates SATISFIED.

        The Host header is on almost every row on purpose. Without it the
        console answers 403 ``bad_host`` before the route runs, and a
        refusal is not what this class is about -- the finding is that
        these requests RAN, produced the real answer, and delivered it with
        nothing around it. A shape that never reaches the route proves the
        version check no more than a closed door proves a lock. The one row
        with no Host is there to say so.
        """
        cookie = self.cookie_header()
        key = self.key.encode()
        host = b"Host: 127.0.0.1:%d\r\n" % self.port
        body = b'{"amount_mc": 1000, "count": 1}'
        return [
            ("the signed descriptor",
             b"GET /api/descriptor HTTP/0.9\r\n" + host + cookie + b"\r\n"),
            ("the console page",
             b"GET /?k=" + key + b" HTTP/0.9\r\n" + host + b"\r\n"),
            ("the page route with no key",
             b"GET / HTTP/0.9\r\n" + host + b"\r\n"),
            ("the unauthenticated refusal",
             b"GET /api/descriptor HTTP/0.9\r\n" + host + b"\r\n"),
            ("a forged Host, refused before the route",
             b"GET /api/descriptor HTTP/0.9\r\nHost: evil.example\r\n"
             + cookie + b"\r\n"),
            ("an unknown route",
             b"GET /zzz HTTP/0.9\r\n" + host + cookie + b"\r\n"),
            ("the framing refusal",
             b"GET / HTTP/0.9\r\n" + host
             + b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n"),
            ("a target urlsplit refuses",
             b"GET http://[ HTTP/0.9\r\n" + host + b"\r\n"),
            ("POST /api/status",
             b"POST /api/status HTTP/0.9\r\n" + host + cookie
             + b"Content-Type: application/json\r\n"
               b"Content-Length: 18\r\n\r\n" + b'{"q": "deadbeef"}\n'),
            ("POST /api/issue -- THE ONE THAT MINTED",
             b"POST /api/issue HTTP/0.9\r\n" + host + cookie
             + b"Content-Type: application/json\r\n"
               b"Content-Length: %d\r\n\r\n" % len(body) + body),
            ("a method with no handler here",
             b"PUT /api/issue HTTP/0.9\r\n" + host + cookie + b"\r\n"),
        ]

    def test_every_spelled_out_09_request_gets_a_framed_400(self):
        for name, request in self.spelled_shapes():
            with self.subTest(name):
                exchange = raw_bytes(self.port, request, record=False)
                self.assertHadAStatusLine(exchange, name)
                self.assertEqual(exchange.status, 400,
                                 "%s: %s" % (name, exchange.describe()))
                self.assertEqual(
                    self.console_reason(exchange), "bad_version",
                    "%s: a request line that SPELLS OUT HTTP/0.9 has to be "
                    "refused as one. The word count cannot see it and the "
                    "route ran: %s" % (name, exchange.describe()))

    def test_the_stdlibs_own_error_is_framed_on_this_spelling_too(self):
        """The door ``parse_request`` cannot reach.

        An over-long header block is answered by the stdlib from INSIDE
        ``super().parse_request()``, after it has already set
        ``request_version`` from the wire and before our check runs. On
        ``GET / HTTP/0.9`` that came back as 333 octets of the stdlib's
        HTML error page with no status line at all, while the identical
        request in HTTP/1.1 got a framed 431. Only ``send_error`` can close
        it, which is the half of this fix that is the mint's
        ``send_error`` override.
        """
        block = b"".join(b"X-%d: y\r\n" % i for i in range(200))
        naked = raw_bytes(self.port, b"GET / HTTP/0.9\r\n" + block + b"\r\n",
                          record=False)
        self.assertIsNotNone(
            naked.status,
            "a 431 for a spelled-out 0.9 request came back with NO STATUS "
            "LINE: %r" % naked.raw[:160])
        framed = raw_bytes(self.port, b"GET / HTTP/1.1\r\nHost: 127.0.0.1:%d"
                           b"\r\n" % self.port + block + b"\r\n", record=False)
        self.assertEqual(
            naked.status, framed.status,
            "the same over-long header block is answered %s in HTTP/0.9 and "
            "%s in HTTP/1.1" % (naked.status, framed.status))

    def test_the_issuance_route_hands_back_no_token(self):
        """The worst single byte-sequence in the finding: a bearer token,
        naked. Nothing in the answer may look like one."""
        body = b'{"amount_mc": 1000, "count": 1}'
        exchange = raw_bytes(self.port, (
            b"POST /api/issue HTTP/0.9\r\nHost: 127.0.0.1:%d\r\n" % self.port
            + self.cookie_header()
            + b"Content-Type: application/json\r\n"
              b"Content-Length: %d\r\n\r\n" % len(body) + body),
            record=False)
        self.assertEqual(exchange.status, 400, exchange.describe())
        self.assertNotIn(b"aicash:", exchange.raw,
                         "a refused 0.9 issuance still handed back a token")
        self.assertNotIn(b"tokens", exchange.raw, exchange.describe())

    def test_no_money_was_created_by_any_of_it(self):
        """The mint's own books, before and after.

        ``bad_version`` in the body would be satisfied by a console that
        minted and THEN refused. This asks the mint what it did:
        ``cumulative_issued_mc`` is monotonic, it is the mint's number and
        not the console's, and it must not move.
        """
        def issued():
            status, _h, payload = raw_request(
                self.port, "GET", "/api/descriptor",
                headers=self.cookie(), record=False)
            self.assertEqual(status, 200, payload)
            return json.loads(payload)["supply"]["cumulative_issued_mc"]

        before = issued()
        for name, request in self.spelled_shapes():
            raw_bytes(self.port, request, record=False)
        self.assertEqual(
            issued(), before,
            "a request line spelling HTTP/0.9 reached the issuance route "
            "and the mint created money for it -- which is what happened "
            "before this class existed, with the token handed back as 82 "
            "octets with no framing at all")

    def test_a_client_library_can_read_the_refusal(self):
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=12)
        try:
            sock.sendall(b"GET /api/descriptor HTTP/0.9\r\n\r\n")
            response = http.client.HTTPResponse(sock)
            response.begin()            # BadStatusLine if naked
            self.assertEqual(response.status, 400)
            self.assertEqual(json.loads(response.read())["error"]["reason"],
                             "bad_version")
        finally:
            sock.close()

    def test_the_capability_url_spelled_09_is_refused_and_not_echoed(self):
        """The one route where the REQUEST LINE IS THE SECRET.

        Rewritten because the old assertion certified nothing about this
        class's subject. It asserted only that the key was absent from the
        bytes -- and that held BEFORE the fix too: the pre-fix console
        answered this request nakedly with the console page, and the page
        does not contain the key either, so the method passed against an
        open door. (Verified by reverting the version test: ok.)

        What was actually broken on these bytes is that the capability URL,
        spelled HTTP/0.9, OPENED A SESSION and got the page back with no
        status line on it. So the refusal is what is asserted now -- framed,
        400, ``bad_version``, one response, socket going -- AND the key
        still absent, which is the cheap half kept because a refusal body
        is the cheapest place to hand a secret back.
        """
        exchange = raw_bytes(
            self.port,
            b"GET /?k=" + self.key.encode() + b" HTTP/0.9\r\n\r\n",
            record=False)
        self.assertHadAStatusLine(exchange, "the capability URL at 0.9")
        self.assertEqual(exchange.status, 400, exchange.describe())
        self.assertEqual(
            self.console_reason(exchange), "bad_version",
            "the capability URL spelled HTTP/0.9 was not refused as a bad "
            "version: %s" % exchange.describe())
        self.assertNotIn(b"Set-Cookie", exchange.raw,
                         "the 0.9 capability URL opened a session: %s"
                         % exchange.describe())
        self.assertNotIn(self.key.encode(), exchange.raw,
                         "a 0.9 refusal echoed the capability URL")

    def test_the_word_count_is_still_there(self):
        """The two checks are not alternatives and neither is redundant.

        With ``default_request_version = "HTTP/1.1"`` a TWO-word line lands
        on ``request_version == "HTTP/1.1"`` and sails past a version test;
        a THREE-word line spelling 0.9 sails past a word count. Dropping
        either one starts serving one of the two spellings, which is
        exactly the mistake the mint made once and wrote down.

        READ OFF THE SYNTAX TREE, NOT THE SOURCE TEXT, and that is the
        whole point of this rewrite. The old version took
        ``ast.get_source_segment`` of the entire function and asserted the
        two strings appeared SOMEWHERE in it -- and
        ``get_source_segment`` returns COMMENTS. The string
        ``request_version == "HTTP/0.9"`` appears in the explanatory
        comment sitting inside the very branch it was guarding, so the
        assertion was satisfied by prose: reverting mint_console.py to the
        pre-fix ``if zero_nine:`` made eleven sibling subtests, the money
        test and the token test fail while THIS method reported ok. It was
        the only guard on the half of the fix that closes the reported
        defect and it guarded nothing.

        So: find the ``if`` that calls ``_refuse_bad_version``, and assert
        against its OWN test expression -- an ``or`` of exactly two
        operands, one of them a comparison of ``request_version`` against
        the literal ``"HTTP/0.9"``, the other a name bound in this same
        function to a count of the words on ``raw_requestline``. A comment
        cannot satisfy any of that, and neither can an assignment that is
        never read: the word-count half must be reachable FROM THE
        CONDITION.
        """
        with open(CONSOLE, encoding="utf-8") as fh:
            source = fh.read()
        func = next(n for n in ast.walk(ast.parse(source))
                    if isinstance(n, ast.FunctionDef)
                    and n.name == "parse_request")

        def calls(node, name):
            return any(isinstance(c, ast.Call)
                       and isinstance(c.func, ast.Attribute)
                       and c.func.attr == name
                       for c in ast.walk(node))

        guards = [n for n in ast.walk(func)
                  if isinstance(n, ast.If) and calls(n, "_refuse_bad_version")]
        self.assertEqual(
            len(guards), 1,
            "parse_request has %d branches that refuse a bad version; this "
            "guard reads exactly one" % len(guards))
        test = guards[0].test
        self.assertIsInstance(
            test, ast.BoolOp,
            "the 0.9 refusal is guarded by a SINGLE condition (%s). Both "
            "spellings need both checks: a TWO-word line presents as "
            "HTTP/1.1 and sails past a version test, a THREE-word line "
            "spelling HTTP/0.9 sails past a word count, and whichever one "
            "is left is now served naked on every route"
            % ast.dump(test)[:120])
        self.assertIsInstance(test.op, ast.Or,
                              "the two 0.9 checks are ANDed: a request has "
                              "to be both spellings at once to be refused")

        def is_version_test(node):
            return (isinstance(node, ast.Compare)
                    and isinstance(node.left, ast.Attribute)
                    and node.left.attr == "request_version"
                    and len(node.ops) == 1
                    and isinstance(node.ops[0], ast.Eq)
                    and isinstance(node.comparators[0], ast.Constant)
                    and node.comparators[0].value == "HTTP/0.9")

        def counts_the_words(node):
            """The operand, or -- if it is a name -- what it is bound to."""
            sources = [node]
            if isinstance(node, ast.Name):
                sources = [a.value for a in ast.walk(func)
                           if isinstance(a, ast.Assign)
                           and any(isinstance(t, ast.Name) and t.id == node.id
                                   for t in a.targets)]
            for expr in sources:
                split = any(
                    isinstance(c, ast.Call)
                    and isinstance(c.func, ast.Attribute)
                    and c.func.attr == "split"
                    and isinstance(c.func.value, ast.Attribute)
                    and c.func.value.attr == "raw_requestline"
                    for c in ast.walk(expr))
                counted = any(isinstance(c, ast.Call)
                              and isinstance(c.func, ast.Name)
                              and c.func.id == "len"
                              for c in ast.walk(expr))
                if split and counted:
                    return True
            return False

        self.assertTrue(
            any(is_version_test(v) for v in test.values),
            "no operand of the 0.9 guard compares request_version against "
            '"HTTP/0.9", so a THREE-word request line whose version token '
            "is literally HTTP/0.9 is read by the stdlib, sets "
            "request_version FROM THE WIRE, and is served naked again -- "
            "the critical finding of this round, reopened")
        self.assertTrue(
            any(counts_the_words(v) for v in test.values),
            "no operand of the 0.9 guard counts the words on "
            "raw_requestline (an assignment that nothing in the condition "
            "reads does not count), so a TWO-word request line presents as "
            "HTTP/1.1 and is served")


class TestLeadingEmptyLinesAreTolerated(FramingCase):
    """23. A well-formed request with stray CRLFs in front of it, which got
    NOTHING BACK.

    RFC 7230 3.5: a server SHOULD ignore at least one empty line received
    before the request line. The stdlib does not -- an empty request line
    makes ``words`` empty, ``parse_request`` returns False with nothing
    written, and the socket is dropped. So
    ``\\r\\nGET /api/descriptor HTTP/1.1 ...``, which is what a client that
    terminated its last body with an extra CRLF emits, was UNIFORM REQUEST
    LOSS on a shape the standard blesses: zero bytes back, measured on the
    real console 2026-09-17.

    ONE LINE OF TOLERANCE WAS NOT ENOUGH, and that is what this class was
    extended for. "At least one" is a FLOOR the RFC sets, not a ceiling,
    and tolerating exactly one put the shape one octet over straight back
    into the silent-discard path: two leading empty lines in front of the
    same well-formed authenticated request came back with ZERO BYTES and a
    dropped socket, measured here and on the mint's own port. So the
    console now steps over a BOUNDED RUN --
    ``mint_console.MAX_LEADING_EMPTY_LINES`` -- and answers a framed 400
    past it. The cap is what keeps this from being a thread a CRLF trickle
    can hold; the framed 400 past the cap is what keeps the cap from being
    one more way to get silence.

    THIS IS A DIVERGENCE FROM THE MINT as of 2026-09-17 and it is asserted
    as one, not hidden: aicash.mintapi tolerates exactly one line and
    discards the rest in silence. The rule belongs in the library so all
    four servers move together, impl/ was not this round's to edit, and the
    console is the one of the four that holds the issuing credential.
    """

    @staticmethod
    def cap():
        import mint_console
        return mint_console.MAX_LEADING_EMPTY_LINES

    def test_one_leading_crlf_is_answered(self):
        cookie = self.cookie_header()
        for name, lead in (("CRLF", b"\r\n"), ("bare LF", b"\n")):
            with self.subTest(name):
                exchange = raw_bytes(self.port, lead + (
                    b"GET /api/descriptor HTTP/1.1\r\n"
                    b"Host: 127.0.0.1:%d\r\n" % self.port) + cookie
                    + b"Connection: close\r\n\r\n", record=False)
                self.assertTrue(
                    exchange.raw,
                    "%s: a well-formed request preceded by one empty line "
                    "got NOTHING BACK and the socket was dropped" % name)
                self.assertEqual(exchange.status, 200, exchange.describe())
                self.assertIn(b"mint_id", exchange.raw, exchange.describe())

    def test_the_leading_line_does_not_disable_any_gate(self):
        """Tolerating the empty line re-reads the request line ourselves,
        which is a second door into ``parse_request``. Everything after it
        must be unchanged: the same 401 with no cookie, the same framing
        refusal, the same 0.9 refusal."""
        for name, rest, status, reason in (
                ("unauthenticated",
                 b"GET /api/descriptor HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n"
                 % self.port, 401, "unauthorized"),
                ("unframable",
                 b"GET / HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                 b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n" % self.port,
                 400, "bad_framing"),
                ("0.9 by omission", b"GET /\r\n\r\n", 400, "bad_version"),
                ("0.9 spelled out", b"GET / HTTP/0.9\r\n\r\n", 400,
                 "bad_version")):
            with self.subTest(name):
                exchange = raw_bytes(self.port, b"\r\n" + rest, record=False)
                self.assertEqual(exchange.status, status,
                                 "%s: %s" % (name, exchange.describe()))
                self.assertEqual(self.console_reason(exchange), reason,
                                 "%s: %s" % (name, exchange.describe()))

    def test_a_run_of_empty_lines_up_to_the_cap_is_answered(self):
        """The shape the single-line tolerance still lost.

        TWO leading empty lines in front of a well-formed AUTHENTICATED
        request used to come back with zero bytes and a dropped socket --
        the request was read off the wire, understood by nobody, and thrown
        away. Every count up to the cap is now answered on its merits.
        """
        cookie = self.cookie_header()
        for count in (2, 3, self.cap()):
            with self.subTest("%d leading empty lines" % count):
                exchange = raw_bytes(self.port, b"\r\n" * count + (
                    b"GET /api/descriptor HTTP/1.1\r\n"
                    b"Host: 127.0.0.1:%d\r\n" % self.port) + cookie
                    + b"Connection: close\r\n\r\n", record=False)
                self.assertTrue(
                    exchange.raw,
                    "%d leading empty lines in front of a well-formed "
                    "authenticated request got NOTHING BACK and the socket "
                    "was dropped" % count)
                self.assertEqual(exchange.status, 200, exchange.describe())
                self.assertIn(b"mint_id", exchange.raw, exchange.describe())

    def test_past_the_cap_the_run_is_refused_in_a_framed_400(self):
        """A cap, and not one more way to get silence.

        The run has to be bounded -- an unbounded loop is a handler thread
        an anonymous peer holds with a CRLF trickle -- and the bound has to
        ANSWER, because "the stdlib returns False having written nothing"
        is the defect this whole round is about. One framed 400, a length
        on it, ``Connection: close``, and the socket goes.
        """
        exchange = raw_bytes(self.port, b"\r\n" * (self.cap() + 1),
                             timeout=12.0, record=False)
        self.assertTrue(
            exchange.raw,
            "a run of %d empty lines past the cap got NOTHING BACK"
            % (self.cap() + 1))
        self.assertEqual(exchange.status, 400, exchange.describe())
        self.assertEqual(self.console_reason(exchange), "too_many_empty_lines",
                         exchange.describe())
        self.assertIn(b"connection: close",
                      exchange.raw.split(b"\r\n\r\n", 1)[0].lower(),
                      "hung up without saying so: %s" % exchange.describe())
        self.assertFalse(exchange.still_open,
                         "a run past the cap left the connection open: %s"
                         % exchange.describe())

    def test_empty_lines_then_a_hangup_are_answered_not_dropped(self):
        """The peer sent empty lines and closed its sending half.

        No request is coming, and the WRITE half is still open, so it gets
        an answer rather than a dropped socket. "There was nothing worth
        answering" is the reasoning behind every silence this round
        removed.
        """
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=12)
        try:
            sock.sendall(b"\r\n\r\n")
            sock.shutdown(socket.SHUT_WR)
            chunks = []
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
        finally:
            sock.close()
        exchange = RawExchange(b"".join(chunks), False)
        self.assertTrue(exchange.raw,
                        "empty lines followed by a hang-up got NOTHING BACK")
        self.assertEqual(exchange.status, 400, exchange.describe())
        self.assertEqual(self.console_reason(exchange), "empty_request_line",
                         exchange.describe())

    def test_a_whitespace_request_line_is_answered_too(self):
        """THE ASSERTION IN THIS METHOD IS INVERTED FROM WHAT IT WAS, and
        that is the finding it exists for.

        It used to assert ``assertIsNone(exchange.status)`` -- it pinned NO
        RESPONSE AT ALL as the correct answer to these bytes, in the file
        that spent the round closing exactly that class, and it would have
        gone red on the day someone fixed the defect its own docstring
        named. A test that certifies silence is a test that defends the
        defect.

        A request line of SPACES or of a TAB is not the empty line, so it
        is not stepped over above; the stdlib splits it, gets no words, and
        returns False from ``parse_request`` HAVING WRITTEN NOTHING. Zero
        bytes back, socket dropped -- measured here and on the mint, both,
        2026-09-17. The console now answers it: one framed 400,
        ``bad_request_line``, a length on it, and the socket goes.

        It is closed GENERALLY and not by naming these two byte strings:
        the console answers whenever ``super().parse_request()`` refused
        with no status line out, so a future stdlib that adds another
        silent False lands on the 400 rather than reopening the defect.
        The bare CR, LF and CRLF are still the empty line and are still
        stepped over -- asserted above, so "answer everything" has not
        quietly swallowed the tolerance.

        DIVERGENCE FROM THE MINT, asserted deliberately: aicash.mintapi
        still discards these bytes in silence. Moving it there moves all
        four servers together and is the right shape; impl/ was not this
        round's to edit, and a console holding the issuing credential does
        not get to keep a silence until the library catches up.
        """
        for name, request in (("spaces", b"   \r\n\r\n"),
                              ("a tab", b"\t\r\n\r\n"),
                              ("spaces and a tab", b" \t \r\n\r\n")):
            with self.subTest(name):
                exchange = raw_bytes(self.port, request, timeout=12.0,
                                     record=False)
                self.assertTrue(
                    exchange.raw,
                    "%s: NO RESPONSE AT ALL. A request line this console "
                    "cannot read is still a request it was asked, and the "
                    "peer cannot tell silence from a crash or a firewall"
                    % name)
                self.assertEqual(exchange.status, 400, exchange.describe())
                self.assertEqual(
                    self.console_reason(exchange), "bad_request_line",
                    "%s: %s" % (name, exchange.describe()))
                self.assertEqual(len(exchange.statuses), 1,
                                 "%s: %s" % (name, exchange.describe()))
                self.assertIn(
                    b"connection: close",
                    exchange.raw.split(b"\r\n\r\n", 1)[0].lower(),
                    "%s: hung up without saying so: %s"
                    % (name, exchange.describe()))
                self.assertFalse(
                    exchange.still_open,
                    "%s left the connection open: a peer can hold a "
                    "handler thread with it" % name)


class TestTheRequestDeadlineEndsASlowDrip(unittest.TestCase):
    """24. An IDLE timeout is not a budget, and this console only had one.

    ``Console.timeout`` is applied to the socket by socketserver, so it is
    re-armed by every recv that returns a byte. An UNAUTHENTICATED peer
    sending one octet every two seconds into the header block therefore
    holds a daemon thread and a file descriptor for as long as it likes:
    measured on the real console 2026-09-17, still held at 76 seconds with
    nothing sent back, against a timeout of 30. ThreadingHTTPServer caps
    neither, and none of the four authentication gates is any defence --
    the request never reaches them, because it never finishes arriving.

    The mint solved this with a whole-request wall-clock deadline enforced
    BENEATH the buffered reader, which is the only place that bounds the
    header phase as well as the body. That class is imported here, not
    copied: see ``test_the_deadline_layer_is_the_mints_own``.

    Its own console with the budget turned down, the way
    ``TestABodyThatNeverArrivesIsAnswered`` turns the timeout down: the
    shipped thirty seconds is the right number on loopback and the wrong
    number in a suite. The IDLE timeout is deliberately left alone, so the
    drip below really is re-arming it and the deadline really is what ends
    the request.
    """

    DRIP = 0.4          # seconds between octets; must be < Console.timeout
    BUDGET = 2.0        # the whole-request deadline, for this console only

    @classmethod
    def setUpClass(cls):
        import mint_console
        cls.mod = mint_console
        cls.shipped_budget = getattr(mint_console.Console,
                                     "request_timeout", None)
        cls.shipped_idle = mint_console.Console.timeout
        mint_console.Console.request_timeout = cls.BUDGET
        cls.console = InProcessConsole(mint_port=1)   # nothing is on port 1

    @classmethod
    def tearDownClass(cls):
        cls.console.stop()
        if cls.shipped_budget is None:
            try:
                del cls.mod.Console.request_timeout
            except AttributeError:
                pass
        else:
            cls.mod.Console.request_timeout = cls.shipped_budget

    def test_the_shipped_budget_is_finite_and_is_the_mints_number(self):
        from aicash.mintapi import MAX_REQUEST_SECONDS
        self.assertIsNotNone(
            self.shipped_budget,
            "Console has no request_timeout: the only bound on a request "
            "is the IDLE timeout, which one octet every two seconds "
            "re-arms forever")
        self.assertEqual(
            self.shipped_budget, MAX_REQUEST_SECONDS,
            "the console's whole-request budget is no longer the mint's "
            "constant, so a drip can outlive the mint on the port next to "
            "it")
        self.assertGreater(self.shipped_idle, self.DRIP,
                           "this test's drip interval is longer than the "
                           "idle timeout, so it would prove nothing")

    def test_the_deadline_layer_is_the_mints_own(self):
        """Imported, not re-implemented. A second "bound the whole request"
        is the local-copy shape this file already refuses for framing."""
        from aicash.mintapi import _DeadlineRaw
        self.assertIs(self.mod._DeadlineRaw, _DeadlineRaw,
                      "mint_console has its own deadline layer now; there "
                      "is one implementation of this and the mint owns it")

    def test_the_deadline_is_under_the_buffered_reader(self):
        """Above it would set one timeout for one blocking read and bound
        nothing -- which is the mistake the idle timeout already makes. The
        header block is refilled by ``readline`` and each refill has to
        re-check the clock."""
        with open(CONSOLE, encoding="utf-8") as fh:
            source = fh.read()
        func = next(n for n in ast.walk(ast.parse(source))
                    if isinstance(n, ast.FunctionDef) and n.name == "setup")
        seg = ast.get_source_segment(source, func)
        self.assertIn("io.BufferedReader", seg)
        self.assertIn("_DeadlineRaw(self.connection, self)", seg,
                      "the deadline layer is not the raw side of the "
                      "reader any more")

    def test_a_one_byte_drip_into_the_header_block_is_ended(self):
        port = self.console.port
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        started = time.monotonic()
        sent = 0
        closed = None
        try:
            sock.sendall(b"GET /api/descriptor HTTP/1.1\r\n")
            sock.settimeout(0.05)
            while time.monotonic() - started < self.BUDGET * 6:
                try:
                    sock.sendall(b"X")
                    sent += 1
                except OSError:
                    closed = time.monotonic() - started
                    break
                try:
                    if sock.recv(4096) == b"":
                        closed = time.monotonic() - started
                        break
                except (socket.timeout, TimeoutError, BlockingIOError):
                    pass
                except OSError:
                    closed = time.monotonic() - started
                    break
                time.sleep(self.DRIP)
        finally:
            sock.close()
        self.assertIsNotNone(
            closed,
            "an unauthenticated peer dripping one octet every %.1fs held a "
            "handler thread and a file descriptor for %.1fs against a "
            "whole-request budget of %.1fs (%d octets sent). The idle "
            "timeout cannot end this: every octet re-arms it."
            % (self.DRIP, time.monotonic() - started, self.BUDGET, sent))
        self.assertLess(
            closed, self.BUDGET * 5,
            "the drip outlived the deadline by too much to call it enforced "
            "(%.1fs against %.1fs)" % (closed, self.BUDGET))

    def test_a_prompt_request_is_not_cut_short(self):
        """The negative control, LABELLED AS ONE.

        It passes under every mutation of the deadline, and that is
        correct: its job is to fail if a budget starts refusing ordinary
        traffic. Nobody should count it as coverage of the deadline -- the
        drip test above and the three 408 tests below are that.
        """
        exchange = raw_bytes(self.console.port, (
            b"GET / HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
            b"Connection: close\r\n\r\n" % self.console.port), record=False)
        self.assertEqual(exchange.status, 401, exchange.describe())

    # -- the budget ANSWERS now, and these are the shapes it used to drop --

    def timed_out(self, prologue, what):
        """Send ``prologue``, then say nothing, and read what comes back.

        Deliberately not ``raw_bytes``: that helper's sender closes nothing
        and its reader cannot tell "the budget expired and the console
        answered" from "the budget expired and the console dropped the
        socket", which is the whole distinction under test here.
        """
        sock = socket.create_connection(("127.0.0.1", self.console.port),
                                        timeout=self.BUDGET * 8)
        started = time.monotonic()
        chunks = []
        try:
            if prologue:
                sock.sendall(prologue)
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
        except (socket.timeout, TimeoutError):
            self.fail("%s: the console was still holding the connection "
                      "%.1fs after a budget of %.1fs"
                      % (what, time.monotonic() - started, self.BUDGET))
        except OSError:
            pass
        finally:
            sock.close()
        return RawExchange(b"".join(chunks), False), time.monotonic() - started

    def test_a_request_that_never_finishes_arriving_is_answered_408(self):
        """THE BOUND WORKED AND THE PEER COULD NOT TELL.

        Every shape here ended inside the budget before this test existed
        -- and ended with ZERO BYTES and an EOF, which a peer cannot
        distinguish from a crash, a firewall or a hang. Measured on the
        shipped console 2026-09-17: 29.5s, nothing back, on all three.
        408 is HTTP's own status for exactly this, it costs one write on a
        socket the handler is closing anyway, and it is framed like every
        other answer this console gives.

        The silent connection is in the list on purpose: it is the shape
        with the best excuse for silence (the peer said nothing at all) and
        it is still a peer that opened a connection to this console and is
        owed an answer before its socket goes.
        """
        for what, prologue in (
                ("a connection that says nothing at all", b""),
                ("an empty line, then silence", b"\r\n"),
                ("an unterminated request line", b"GET /api/desc"),
                ("a half-sent header block",
                 b"GET /api/descriptor HTTP/1.1\r\nHost: 127.0.0.1\r\n"),
                ("empty lines, then silence", b"\r\n\r\n")):
            with self.subTest(what):
                exchange, took = self.timed_out(prologue, what)
                self.assertTrue(
                    exchange.raw,
                    "%s: NO RESPONSE AT ALL after %.1fs. The budget ended "
                    "it, which is not the same as answering it" %
                    (what, took))
                self.assertEqual(exchange.status, 408, exchange.describe())
                self.assertEqual(
                    self.console_reason_of(exchange), "request_timeout",
                    "%s: %s" % (what, exchange.describe()))
                self.assertEqual(len(exchange.statuses), 1,
                                 "%s: %s" % (what, exchange.describe()))
                self.assertIn(
                    b"connection: close",
                    exchange.raw.split(b"\r\n\r\n", 1)[0].lower(),
                    "%s: hung up without saying so" % what)
                self.assertLess(
                    took, self.BUDGET * 5,
                    "%s: answered, but %.1fs after a budget of %.1fs"
                    % (what, took, self.BUDGET))

    def test_the_408_is_the_budget_and_not_a_route(self):
        """The negative control for the 408: an ordinary unauthenticated
        request against the same console answers 401 immediately, so the
        408 above is the clock and not a handler that answers 408 to
        everything."""
        exchange = raw_bytes(self.console.port, (
            b"GET /api/descriptor HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
            b"Connection: close\r\n\r\n" % self.console.port),
            record=False)
        self.assertEqual(exchange.status, 401, exchange.describe())

    @staticmethod
    def console_reason_of(exchange):
        try:
            envelope = exchange.json().get("error")
        except ValueError:
            return None
        return envelope.get("reason") if isinstance(envelope, dict) else None


class TestTheShippedBudgetIsDrivenToExpiry(ConsoleCase):
    """25. THE SUITE NEVER DROVE THE NUMBER THAT SHIPS.

    ``TestTheRequestDeadlineEndsASlowDrip`` turns ``request_timeout`` down
    to two seconds for a console of its own -- the right call for a suite
    -- so what it proves is that the MECHANISM fires and that the shipped
    constant is ``MAX_REQUEST_SECONDS``. Those two facts do not add up to
    "the shipped console ends a stalled request", and the gap was closed by
    hand with a stopwatch on a console nobody kept. A measurement nobody
    kept is a measurement the next round has to take again.

    So this drives the real thing: the module's own console, started the
    way an operator starts it, with the shipped thirty-second budget and
    the shipped thirty-second idle bound, and nothing turned down. It costs
    about thirty seconds of wall clock and it is the only test here that
    does. That is the price of the suite carrying the measurement instead
    of a report carrying it.
    """

    def test_a_silent_peer_is_answered_at_the_shipped_budget(self):
        from aicash.mintapi import MAX_REQUEST_SECONDS
        import mint_console
        self.assertEqual(mint_console.Console.request_timeout,
                         MAX_REQUEST_SECONDS,
                         "this test measures the shipped budget; the "
                         "console's is no longer the mint's constant")
        budget = MAX_REQUEST_SECONDS
        sock = socket.create_connection(("127.0.0.1", self.port),
                                        timeout=budget * 3)
        started = time.monotonic()
        chunks = []
        try:
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
        except (socket.timeout, TimeoutError):
            self.fail("the shipped console was still holding a silent "
                      "connection %.1fs after a budget of %.1fs"
                      % (time.monotonic() - started, budget))
        except OSError:
            pass
        finally:
            sock.close()
        took = time.monotonic() - started
        exchange = RawExchange(b"".join(chunks), False)
        self.assertTrue(
            exchange.raw,
            "the shipped console ended a silent connection after %.1fs "
            "with NO RESPONSE AT ALL" % took)
        self.assertEqual(exchange.status, 408, exchange.describe())
        self.assertEqual(len(exchange.statuses), 1, exchange.describe())
        self.assertIn(b"content-length",
                      exchange.raw.split(b"\r\n\r\n", 1)[0].lower(),
                      "the 408 carried no length: %s" % exchange.describe())
        self.assertLess(
            took, budget + 15,
            "the shipped budget did not end this within %.1fs (%.1fs)"
            % (budget, took))
        self.assertGreater(
            took, budget / 3,
            "this ended after %.1fs against a budget of %.1fs -- far too "
            "early for the shipped number, so whatever ended it, it was "
            "not the budget this test claims to have measured"
            % (took, budget))


class TestTheWriteSideHasABudgetToo(unittest.TestCase):
    """26. ``_DeadlineRaw`` bounds every READ of a request. Nothing bounded
    the writes.

    The imported deadline layer restores the idle timeout on its way out --
    deliberately, so the response is never left running on whatever sliver
    of the read budget remained -- and the consequence was that the
    response ran on the IDLE timeout ALONE. An idle timeout is re-armed by
    every write that makes progress, which is the same sentence
    ``request_timeout`` was added to this file for, one direction over: a
    reader that accepts one octet just inside ``Console.timeout`` seconds,
    forever, holds the handler forever.

    IT WAS NOT REACHABLE ON THE SHIPPED CONSOLE and it is bounded anyway.
    The console sets no ``protocol_version``, so it grants no keep-alive,
    and its largest single response is the page at about 8 KB, which fits
    the kernel send buffer and returns from ``sendall`` before any reader
    has read a byte. "Unreachable" is exactly how a naked framing refusal
    survived a round in this same file, and it is one attribute away from
    reachable -- ``TestTheDaySomeoneSetsProtocolVersion`` exists for that
    day and did not cover the write side.

    Driven against ``_DeadlineWrite`` and ``Console.response_budget``
    directly, over a real socket pair, with the budget turned down the way
    the drip test turns the request budget down. The point being proved is
    that it is a BUDGET and not an idle bound: every individual write below
    succeeds promptly, and the clock still runs out.
    """

    BUDGET = 0.3
    IDLE = 5.0          # much larger, so the idle bound cannot be what fires

    def setUp(self):
        import mint_console
        self.mod = mint_console

        class Stub:
            timeout = TestTheWriteSideHasABudgetToo.IDLE
            response_timeout = TestTheWriteSideHasABudgetToo.BUDGET
            response_deadline = None
            response_budget = mint_console.Console.response_budget

        self.stub = Stub()
        self.left, self.right = socket.socketpair()
        self.addCleanup(self.left.close)
        self.addCleanup(self.right.close)
        self.writer = mint_console._DeadlineWrite(
            self.left.makefile("wb", 0), self.left, self.stub)

    def drip_out(self, seconds):
        """Write one octet at a time, draining the far end, until the write
        side refuses. Returns how long that took, or None."""
        started = time.monotonic()
        while time.monotonic() - started < seconds:
            try:
                self.writer.write(b"x")
            except TimeoutError:
                return time.monotonic() - started
            self.right.recv(4096)          # a reader that IS keeping up
            time.sleep(0.02)
        return None

    def test_the_budget_is_cumulative_and_not_re_armed_by_progress(self):
        took = self.drip_out(self.BUDGET * 10)
        self.assertIsNotNone(
            took,
            "a response that kept making progress wrote for %.1fs against "
            "a response budget of %.1fs and was never cut off. Every write "
            "succeeded promptly, so the IDLE bound (%.1fs) can never fire: "
            "a reader that accepts one octet per idle window holds this "
            "handler for as long as it likes"
            % (self.BUDGET * 10, self.BUDGET, self.IDLE))
        self.assertLess(took, self.BUDGET * 5,
                        "the write side outlived its budget by too much to "
                        "call it enforced (%.2fs against %.2fs)"
                        % (took, self.BUDGET))
        self.assertGreater(took, self.BUDGET / 3,
                           "the write side was cut off after %.2fs against "
                           "a budget of %.2fs, so something other than the "
                           "budget stopped it" % (took, self.BUDGET))

    def test_a_response_inside_the_budget_is_not_cut_short(self):
        """The negative control. A budget that refuses ordinary responses
        is not a fix."""
        self.stub.response_timeout = 30.0
        self.assertIsNone(self.drip_out(0.5),
                          "an ordinary response was cut off by the write "
                          "budget")

    def test_the_shipped_write_budget_is_the_mints_number(self):
        from aicash.mintapi import MAX_REQUEST_SECONDS
        self.assertEqual(
            getattr(self.mod.Console, "response_timeout", None),
            MAX_REQUEST_SECONDS,
            "the console's response budget is not the mint's constant, so "
            "a slow reader can outlive the mint on the port next to it")

    def test_the_write_side_is_wrapped_where_the_stdlib_writes_too(self):
        """In ``setup``, not in ``_send``: the stdlib writes responses of
        its own (``send_error``'s 414 and 501, every header block) and a
        budget that only covers this file's own writes is a budget with the
        library's writes outside it -- the same reason the framing check
        lives in ``parse_request`` and not at the top of ``do_GET``."""
        with open(CONSOLE, encoding="utf-8") as fh:
            source = fh.read()
        func = next(n for n in ast.walk(ast.parse(source))
                    if isinstance(n, ast.FunctionDef) and n.name == "setup")
        seg = ast.get_source_segment(source, func)
        self.assertIn("_DeadlineWrite(self.wfile", seg,
                      "the write side is no longer wrapped in setup(), so "
                      "the response runs on the idle timeout alone")


class TestTheConsoleIsOffByDefault(unittest.TestCase):
    """25. The posture question, answered in the launcher rather than in a
    guide.

    ``run_mint.py`` started the console on a fixed port unless told
    otherwise, and DEPLOYMENT.md asked the operator to remember
    ``--console-port 0`` in production. That is the wrong way round for the
    one process in this repository that holds the ISSUING CREDENTIAL and
    puts a button on it: an operator who followed the guide loosely was
    running it without having chosen to, and every other dangerous power in
    that launcher (--open-issuance, --open-registration, --supervision) is
    already opt-in. The console is now opt-in too, and it is one flag away.

    Driven as behaviour and not only as a default value, because "the
    default is 0" and "no console listens" are different sentences.
    """

    def setUp(self):
        self.workdir = tempfile.mkdtemp(prefix="console-default-")
        self.procs = []

    def tearDown(self):
        for proc in self.procs:
            stop(proc)
        shutil.rmtree(self.workdir, ignore_errors=True)

    def run_mint(self, extra):
        port = free_port()
        proc = subprocess.Popen(
            [sys.executable, RUN_MINT, "--port", str(port),
             "--db", os.path.join(self.workdir, "mint.db"),
             "--keys", os.path.join(self.workdir, "mint-keys.json"),
             "--admin-token-file", os.path.join(self.workdir, "admin.json"),
             "--access-log", os.path.join(self.workdir, "access.log"),
             "--mint-id", MINT_ID, "--prune-interval-hours", "0"] + extra,
            cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True)
        out, err = Reader(proc.stdout), Reader(proc.stderr)
        proc.readers = (out, err)
        out.start()
        err.start()
        self.procs.append(proc)
        wait_for(lambda: "mint is up" in out.text, "the mint's startup banner")
        return proc, out, err, port

    def test_no_console_starts_when_nobody_asked_for_one(self):
        try:
            import cryptography  # noqa: F401
        except ImportError:
            raise unittest.SkipTest("the mint needs the cryptography package")
        _proc, out, err, _port = self.run_mint([])
        text = out.text + err.text
        self.assertIsNone(
            re.search(r"http://127\.0\.0\.1:\d+/\?k=", text),
            "run_mint.py printed a console capability URL with no "
            "--console-port asked for, so a console holding the issuing "
            "credential is listening on this machine right now:\n%s" % text)
        self.assertIn("console", text.lower(),
                      "the banner says nothing about the console at all; an "
                      "operator who expected one is left guessing")
        self.assertIn("not started", text.lower())

    def test_the_flag_still_starts_one(self):
        """Off by default is not off. The console is one flag away, and it
        still prints the one URL that works."""
        try:
            import cryptography  # noqa: F401
        except ImportError:
            raise unittest.SkipTest("the mint needs the cryptography package")
        console_port = free_port()
        _proc, out, err, _port = self.run_mint(
            ["--console-port", str(console_port)])
        url = wait_for(
            lambda: re.search(r"http://127\.0\.0\.1:\d+/\?k=[A-Za-z0-9_-]+",
                              out.text + err.text),
            "the console's capability URL")
        self.assertIn(str(console_port), url.group(0))
        status, _h, _b = raw_request(console_port, "GET", "/", record=False)
        self.assertEqual(status, 401)

    def test_the_default_in_the_parser_is_off(self):
        """The value itself, so a reader of the source sees the decision
        without running anything."""
        with open(RUN_MINT, encoding="utf-8") as fh:
            source = fh.read()
        found = []
        for node in ast.walk(ast.parse(source)):
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "add_argument"
                    and node.args
                    and getattr(node.args[0], "value", None)
                    == "--console-port"):
                found = [kw.value.value for kw in node.keywords
                         if kw.arg == "default"]
        self.assertEqual(found, [0],
                         "run_mint.py's --console-port default is %r. A "
                         "console that holds the issuing credential must be "
                         "asked for, not remembered against." % (found,))


class TestAFramedBodyNobodyReadsClosesTheConnection(FramingCase):
    """18c. ``declared_body_unread``: the half of the shared contract this
    console CONSUMES and nothing proved.

    The rule has one branch whose only observable effect is ``must_close``.
    A GET with a legal, single, decimal ``Content-Length`` is framed and
    legal -- there is nothing to refuse -- but no GET route here reads a
    body, so the declared octets stay on the wire and the connection cannot
    carry another request. The rule says so (``framed=True``,
    ``must_close=True``, ``reason="declared_body_unread"``) and
    ``parse_request`` obeys it in one line.

    Before this class existed, ``grep -rn declared_body_unread`` over gui/,
    impl/ and mint_console.py found only the library's own definition:
    nothing anywhere drove a request that reaches that branch. Deleting
    ``if verdict.must_close: self.close_connection = True`` left every test
    green -- and it hid a real gap, because the page route composed its own
    200 and was the ONE response path that never read
    ``self.close_connection``. That is the route a browser loads, and it is
    the only 200 that can be required to close.
    """

    BODY = b"HELLO"

    def framed_but_unread(self, target, cookie=None):
        cookie = self.cookie_header() if cookie is None else cookie
        return ((b"GET %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                 % (target, self.port)) + cookie
                + b"Content-Length: %d\r\n\r\n" % len(self.BODY)
                + self.BODY + self.smuggled_tail(self.cookie_header()))

    def assertAnsweredAndHungUp(self, exchange, what, expected):
        self.assertTrue(exchange.raw, "%s: NO RESPONSE AT ALL" % what)
        self.assertEqual(exchange.status, expected,
                         "%s answered %s: %s"
                         % (what, exchange.status, exchange.describe()))
        self.assertEqual(
            len(exchange.statuses), 1,
            "%s: %d responses for one request -- the declared octets this "
            "server never read were framed as the next request line: %s"
            % (what, len(exchange.statuses), exchange.describe()))
        self.assertFalse(exchange.still_open,
                         "%s: the connection survived a request whose "
                         "declared body nobody read" % what)
        self.assertIn(
            b"connection: close",
            exchange.raw.split(b"\r\n\r\n", 1)[0].lower(),
            "%s: this response MUST close and did not SAY so. Dropping the "
            "socket is enough for a peer talking to us directly and is not "
            "enough for anything in between -- and the 200 on the page "
            "route is exactly where that was missing: %s"
            % (what, exchange.describe()))

    def test_the_rule_names_this_branch_and_only_this_branch(self):
        """Anchored to the library's own word, so a test that stopped
        reaching the branch would stop matching it too."""
        from aicash.mintapi import framing_verdict
        verdict = framing_verdict(parsed_headers("Content-Length: 5\r\n\r\n"),
                                  body_expected=False)
        self.assertIs(verdict.framed, True)
        self.assertIs(verdict.must_close, True)
        self.assertEqual(verdict.length, 5)
        self.assertEqual(verdict.reason, "declared_body_unread")
        # The negative control: the same header on a caller that WILL read
        # the body is an ordinary framed request that keeps its connection.
        reader = framing_verdict(parsed_headers("Content-Length: 5\r\n\r\n"),
                                 body_expected=True)
        self.assertIs(reader.must_close, False)
        self.assertEqual(reader.reason, "ok")

    def test_every_get_route_that_answers_200_says_connection_close(self):
        """Including the page, which is the one a browser loads and the one
        that used to compose its own 200 outside ``_send``."""
        for target in (b"/", b"/index.html", b"/api/descriptor"):
            with self.subTest(target=target):
                exchange = raw_bytes(self.port,
                                     self.framed_but_unread(target),
                                     record=False)
                self.assertAnsweredAndHungUp(
                    exchange, "GET %s" % target.decode(), 200)

    def test_the_key_exchange_page_load_says_it_too(self):
        """The one page load that also mints a session cookie -- a
        different branch of the same route, and the one an operator
        actually takes from the terminal."""
        target = b"/?k=" + self.key.encode()
        exchange = raw_bytes(self.port,
                             self.framed_but_unread(target, cookie=b""),
                             record=False)
        self.assertAnsweredAndHungUp(exchange, "GET /?k=<key>", 200)
        head = exchange.raw.split(b"\r\n\r\n", 1)[0]
        self.assertIn(b"Set-Cookie", head,
                      "routing the page through _send dropped the session "
                      "cookie: %s" % exchange.describe())
        self.assertIn(b"Cache-Control", head,
                      "routing the page through _send dropped no-store")

    def test_the_other_status_codes_close_too(self):
        for target, expected in ((b"/nope", 404), (b"/api/nonexistent", 404)):
            with self.subTest(target=target):
                exchange = raw_bytes(self.port,
                                     self.framed_but_unread(target),
                                     record=False)
                self.assertAnsweredAndHungUp(
                    exchange, "GET %s" % target.decode(), expected)

    def test_an_unauthenticated_one_closes_too(self):
        """A 401 is still an answer to a request that left octets on the
        wire. It is ``_deny``'s path, not ``_refuse_unframable``'s."""
        exchange = raw_bytes(self.port,
                             self.framed_but_unread(b"/api/descriptor",
                                                    cookie=b""),
                             record=False)
        self.assertAnsweredAndHungUp(exchange, "GET /api/descriptor (no "
                                     "cookie)", 401)

    def test_this_console_never_grants_keep_alive_today(self):
        """WHAT THE ASSERTIONS ABOVE DO AND DO NOT PROVE, stated here so
        nobody reads them as more than they are.

        This class leaves ``protocol_version`` at HTTP/1.0, where
        ``BaseHTTPRequestHandler`` leaves ``close_connection`` True on every
        request -- so ``_send`` emits ``Connection: close`` on EVERY
        response and the smuggled tail is never answered on any of them.
        Every clause above is therefore satisfiable today without the
        console obeying ``must_close`` at all. That is exactly why
        ``TestTheDaySomeoneSetsProtocolVersion`` below exists: it turns
        keep-alive on and makes the two cases observably different. The
        pair is the test; this half alone is not.
        """
        cookie = self.cookie_header()
        exchange = raw_bytes(self.port, (
            b"GET /api/descriptor HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
            % self.port) + cookie + b"\r\n", record=False)
        self.assertEqual(exchange.status, 200, exchange.describe())
        self.assertIn(b"connection: close",
                      exchange.raw.split(b"\r\n\r\n", 1)[0].lower(),
                      "the HTTP/1.0 accident this class's limits rest on is "
                      "gone; re-read the paragraph in parse_request")


class TestTheDaySomeoneSetsProtocolVersion(unittest.TestCase):
    """18d. The accident removed, so ``must_close`` has to be doing the work.

    ``mint_console`` never sets ``protocol_version``, so it answers HTTP/1.0
    and keep-alive is never granted at all -- which means every assertion
    about ``Connection: close`` and about "only one response came back" in
    the classes above is satisfied by the accident rather than by the code.
    The stated reason for obeying ``must_close`` and for sending the header
    at all is the day someone adds the one line the mint and the GUI both
    have. This class is that day.

    It sets ``Console.protocol_version`` on its own console and puts it
    back, the same way ``TestABodyThatNeverArrivesIsAnswered`` turns the
    timeout down. With keep-alive live the two cases separate:

      * a plain GET is framed, ``must_close`` is False, the connection is
        reusable, and a pipelined second request IS answered -- two
        responses, which is the proof the stream was genuinely re-framable;
      * a GET that declares octets nobody reads is ``declared_body_unread``,
        and the same pipelined request must NOT be answered, on any route,
        including the page a browser loads.
    """

    @classmethod
    def setUpClass(cls):
        import mint_console
        cls.mod = mint_console
        cls.shipped = mint_console.Console.protocol_version
        mint_console.Console.protocol_version = "HTTP/1.1"
        cls.mint = RecordingMint()
        cls.console = InProcessConsole(cls.mint.port,
                                       admin_token="UNUSED-TOKEN-0123456789")
        cls.port = cls.console.port
        cls.cookie = ("Cookie: %s\r\n"
                      % cls.console.cookie()["Cookie"]).encode()

    @classmethod
    def tearDownClass(cls):
        cls.console.stop()
        cls.mint.stop()
        cls.mod.Console.protocol_version = cls.shipped

    def test_the_shipped_class_still_answers_http_1_0(self):
        """The accident is an accident and stays written down as one."""
        self.assertEqual(self.shipped, "HTTP/1.0",
                         "mint_console.Console now sets protocol_version; "
                         "the paragraph in parse_request that calls "
                         "keep-alive an accident is out of date")

    def tail(self):
        return (b"GET /api/descriptor HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                % self.port) + self.cookie + b"\r\n"

    def fire(self, target, extra=b"", body=b"", cookie=None):
        cookie = self.cookie if cookie is None else cookie
        return raw_bytes(self.port, (
            b"GET %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n" % (target, self.port))
            + cookie + extra + b"\r\n" + body + self.tail(), record=False)

    def test_keep_alive_really_is_granted_now(self):
        """The control that makes every assertion below mean something: on
        a request with nothing to close for, the pipelined tail IS
        answered. Without this row, "one response" proves nothing."""
        exchange = self.fire(b"/api/descriptor")
        self.assertEqual(
            len(exchange.statuses), 2,
            "the console did not re-frame its stream after a plain GET, so "
            "this class is not measuring what it claims: %s"
            % exchange.describe())
        self.assertNotIn(b"connection: close",
                         exchange.raw.split(b"\r\n\r\n", 1)[0].lower(),
                         "a request that requires no hang-up announced one")

    def test_a_declared_body_nobody_reads_closes_on_every_route(self):
        for target in (b"/", b"/index.html", b"/api/descriptor", b"/nope"):
            with self.subTest(target=target):
                exchange = self.fire(target, b"Content-Length: 5\r\n",
                                     b"HELLO")
                self.assertEqual(
                    len(exchange.statuses), 1,
                    "GET %s: the five octets this console never read were "
                    "framed as the next request line and ANSWERED: %s"
                    % (target.decode(), exchange.describe()))
                self.assertIn(
                    b"connection: close",
                    exchange.raw.split(b"\r\n\r\n", 1)[0].lower(),
                    "GET %s: must_close, and the response does not say so "
                    "-- this is the route a browser loads and it was the "
                    "one response path that never read close_connection: %s"
                    % (target.decode(), exchange.describe()))
                self.assertFalse(exchange.still_open,
                                 "GET %s kept the connection"
                                 % target.decode())

    def test_the_key_exchange_page_load_closes_too(self):
        exchange = self.fire(b"/?k=" + self.console.key.encode(),
                             b"Content-Length: 5\r\n", b"HELLO", cookie=b"")
        self.assertEqual(exchange.status, 200, exchange.describe())
        self.assertEqual(len(exchange.statuses), 1, exchange.describe())
        head = exchange.raw.split(b"\r\n\r\n", 1)[0]
        self.assertIn(b"connection: close", head.lower(), exchange.describe())
        self.assertIn(b"Set-Cookie", head, exchange.describe())

    def test_an_unframable_request_still_cannot_smuggle(self):
        """The framing refusal, with the accident removed."""
        for line in (b"Transfer-Encoding : chunked\r\n",
                     b"Transfer_Encoding: chunked\r\n",
                     b"Content-Length: 1\r\nContent-Length: 2\r\n",
                     b"Content-Length: abc\r\n"):
            with self.subTest(line=line):
                exchange = self.fire(b"/api/descriptor", line, CHUNKED_BODY)
                self.assertEqual(exchange.status, 400, exchange.describe())
                self.assertEqual(len(exchange.statuses), 1,
                                 exchange.describe())
                self.assertFalse(exchange.still_open, exchange.describe())

    def test_an_expect_100_continue_does_not_disarm_the_backstop(self):
        """``handle_expect_100`` becomes REACHABLE the moment anyone sets
        ``protocol_version``, and it sends a bare 100 Continue through
        ``send_response_only``. If that counted as "a response has begun",
        ``_last_resort`` would suppress its own 500 and a later failure on
        the same request would be answered with SILENCE -- the exact class
        this file was swept for, re-entering through the fix for it.

        1xx does not set ``_answered``. Asserted on the real server (the
        100 really is sent and the final response really does follow it)
        and on the flag itself, because the flag is what the backstop
        reads and no black-box request can show it while the branch that
        would need it is a bug nobody has written yet.
        """
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=12)
        try:
            sock.sendall(b"POST /api/status HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
                         % self.port + self.cookie
                         + b"Content-Type: application/json\r\n"
                           b"Expect: 100-continue\r\n"
                           b"Content-Length: 18\r\n\r\n")
            time.sleep(0.4)
            sock.sendall(b'{"q": "deadbeef"}\n')
            raw = b""
            sock.settimeout(8)
            try:
                while True:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    raw += chunk
            except (socket.timeout, TimeoutError):
                pass
        finally:
            sock.close()
        statuses = [int(c) for c in re.findall(rb"HTTP/1\.[01] (\d{3})", raw)]
        self.assertIn(100, statuses,
                      "handle_expect_100 is reachable at HTTP/1.1 and no "
                      "100 Continue was sent: %r" % raw[:200])
        self.assertTrue([s for s in statuses if s >= 200],
                        "the 100 Continue was the ONLY thing sent; the "
                        "request itself got no final answer: %r" % raw[:200])

        # And the flag directly, which is what _last_resort reads.
        probe = self.mod.Console.__new__(self.mod.Console)
        probe.request_version = "HTTP/1.1"
        probe.protocol_version = "HTTP/1.1"
        probe._answered = False
        probe.log_request = lambda *a, **k: None
        self.mod.Console.send_response_only(probe, 100)
        self.assertFalse(probe._answered,
                         "a 100 Continue marked the request answered, so a "
                         "later failure on it would be silent -- which is "
                         "the whole defect class, re-entering through its "
                         "own fix")
        self.mod.Console.send_response_only(probe, 500)
        self.assertTrue(probe._answered,
                        "a real status line no longer marks the request "
                        "answered, so the backstop could write a SECOND "
                        "response on top of a first")

    def test_a_versionless_request_is_still_refused_with_a_status_line(self):
        """BOTH spellings, and with ``protocol_version`` set this is the
        case that matters most: at HTTP/1.1 keep-alive is really granted,
        so a 0.9 answer that went out naked would be followed on the same
        connection by whatever came next -- octets past a declared length,
        which is response splitting rather than untidiness."""
        for name, request in (("two words", b"GET /\r\n\r\n"),
                              ("spelled out", b"GET / HTTP/0.9\r\n\r\n")):
            with self.subTest(name):
                exchange = raw_bytes(self.port, request, record=False)
                self.assertIsNotNone(exchange.status, exchange.describe())
                self.assertEqual(exchange.status, 400, exchange.describe())
                self.assertEqual(len(exchange.statuses), 1,
                                 exchange.describe())
                self.assertFalse(exchange.still_open, exchange.describe())
                self.assertEqual(json.loads(exchange.body)["error"]["reason"],
                                 "bad_version")


class TestABodyThatNeverArrivesIsAnswered(unittest.TestCase):
    """18b. Declared five hundred octets, sent five, then silence.

    With no socket timeout this parked a worker thread FOR GOOD: no
    response, no log line, no traceback, and the thread never came back --
    the quietest member of the "answers nothing at all" family and the only
    one that costs something on every repetition. ``Console.timeout`` makes
    it answerable, so it is answered.

    Its own console, with the timeout turned down, because the shipped
    thirty seconds is the right number on loopback and the wrong number in
    a test suite. The timeout is set on ``Console`` itself, which
    ``serve()``'s handler subclass inherits, and put back afterwards.
    """

    @classmethod
    def setUpClass(cls):
        import mint_console
        cls.mod = mint_console
        cls.shipped = mint_console.Console.timeout
        cls.assertion_about_the_default = cls.shipped
        mint_console.Console.timeout = 2
        cls.mint = RecordingMint()
        cls.console = InProcessConsole(cls.mint.port,
                                       admin_token="UNUSED-TOKEN-0123456789")

    @classmethod
    def tearDownClass(cls):
        cls.console.stop()
        cls.mint.stop()
        cls.mod.Console.timeout = cls.shipped

    def test_the_shipped_timeout_is_finite(self):
        self.assertIsNotNone(self.shipped,
                             "Console.timeout is None again: a half-sent "
                             "body parks a worker thread forever")
        self.assertLessEqual(self.shipped, 120)

    def test_a_half_sent_body_is_answered_408_and_hung_up(self):
        cookie = self.console.cookie()["Cookie"]
        request = (b"POST /api/status HTTP/1.1\r\n"
                   b"Host: 127.0.0.1:%d\r\n" % self.console.port
                   + ("Cookie: %s\r\n" % cookie).encode()
                   + b"Content-Type: application/json\r\n"
                     b"Content-Length: 500\r\n\r\nshort")
        started = time.monotonic()
        exchange = raw_bytes(self.console.port, request, timeout=20,
                             record=False)
        elapsed = time.monotonic() - started
        self.assertIsNotNone(exchange.status,
                             "a stalled body got no answer at all after "
                             "%.1fs" % elapsed)
        self.assertEqual(exchange.status, 408, exchange.describe())
        self.assertEqual(exchange.json()["error"]["reason"], "body_timeout")
        self.assertLess(elapsed, 15,
                        "the console waited past its own timeout (%.1fs)"
                        % elapsed)


class TestBodyValuesReachTheMintOrDoNot(unittest.TestCase):
    """19. A value the console will not use must be refused BEFORE the mint
    is asked, not after.

    ``{"amount_mc": true}`` passed ``isinstance(amount, int)`` -- True is
    an int in Python -- and ``{"amount_mc": 10**31}`` passed ``amount > 0``.
    Both reached POST /admin/issue, the mint MINTED, and the console then
    raised TokenError out of format_token with no response on the wire: the
    money existed, its secrets died with the handler, and the operator got
    a dropped socket to interpret. RecordingMint is the fixture because the
    assertion is about a request that must NOT have been sent.
    """

    @classmethod
    def setUpClass(cls):
        cls.mint = RecordingMint()
        cls.console = InProcessConsole(cls.mint.port,
                                       admin_token="UNUSED-TOKEN-0123456789")

    @classmethod
    def tearDownClass(cls):
        cls.console.stop()
        cls.mint.stop()

    def post(self, path, body):
        return raw_request(self.console.port, "POST", path, body=body,
                           headers=self.console.cookie(), record=False)

    def test_a_bad_amount_never_reaches_the_mint(self):
        before = len(self.mint.headers_for("/admin/issue"))
        for body in ({"amount_mc": True, "count": 1},
                     {"amount_mc": 10 ** 31, "count": 1},
                     {"amount_mc": (1 << 63), "count": 1},
                     {"amount_mc": 0, "count": 1},
                     {"amount_mc": -1, "count": 1},
                     {"amount_mc": 1.5, "count": 1},
                     {"amount_mc": "1000", "count": 1},
                     {"amount_mc": None, "count": 1},
                     {"amount_mc": 1000, "count": True},
                     {"amount_mc": 1000, "count": 0},
                     {"amount_mc": 1000, "count": 101}):
            with self.subTest(body=body):
                status, _h, payload = self.post("/api/issue", body)
                self.assertEqual(status, 400, payload)
        self.assertEqual(len(self.mint.headers_for("/admin/issue")), before,
                         "a refused issuance still asked the mint to mint")

    def test_the_largest_legal_amount_is_still_legal(self):
        """The bound is tokencodec's, imported, not a number retyped here:
        a check that drifts BELOW format_token's ceiling turns a legal
        request into a 400."""
        import mint_console
        from aicash.tokencodec import MAX_AMOUNT_MC
        self.assertTrue(mint_console._bounded_int(MAX_AMOUNT_MC, 1,
                                                  MAX_AMOUNT_MC))
        self.assertFalse(mint_console._bounded_int(MAX_AMOUNT_MC + 1, 1,
                                                   MAX_AMOUNT_MC))
        self.assertFalse(mint_console._bounded_int(True, 1, MAX_AMOUNT_MC))
        self.assertFalse(mint_console._bounded_int(False, 0, 10))

    def test_a_non_string_lookup_is_an_answer(self):
        """``(body.get("q") or "").strip()`` called .strip() on whatever
        arrived. Three JSON types raised AttributeError out of the handler
        and answered nothing."""
        for value in (5, True, {"a": 1}, [1, 2], 1.5):
            with self.subTest(value=value):
                status, _h, payload = self.post("/api/status", {"q": value})
                self.assertEqual(status, 400, payload)
                self.assertIn(b"string", payload)
        for value in (None, "", "   "):
            with self.subTest(value=value):
                status, _h, payload = self.post("/api/status", {"q": value})
                self.assertEqual(status, 400, payload)

    def test_an_absurdly_long_lookup_is_not_forwarded(self):
        before = len(self.mint.headers_for("/v3/status"))
        status, _h, payload = self.post("/api/status", {"q": "a" * 5000})
        self.assertEqual(status, 400, payload)
        self.assertEqual(len(self.mint.headers_for("/v3/status")), before,
                         "a 5,000-character lookup was proxied to the mint")

    def test_a_legal_lookup_still_works(self):
        status, _h, payload = self.post("/api/status", {"q": "deadbeef"})
        self.assertEqual(status, 200, payload)


class TestTheMintAndTheConsoleAgreeOnIdenticalBytes(FramingCase):
    """21. Two of the four servers, the same octets, one verdict.

    The point of the round is not three more fixes; it is that there is ONE
    rule and a test that drives the servers with identical bytes and
    asserts they reach identical framing decisions. This module can reach
    two of the four -- it already runs a real mint subprocess in front of
    the real console -- so it drives those two here and says so. The other
    two (gui/app.py and the Supervision Profile) are driven from their own
    suites; what makes the set coherent is that all four now CALL
    ``aicash.mintapi.framing_verdict``, which the tests above pin from this
    side.

    What "identical decision" can mean across servers with three different
    error vocabularies is worth being exact about, because it is the part a
    careless test gets wrong:

      * it is NOT the status code (the mint answers 3.8 ``bad_format``,
        this console answers its own ``bad_framing``);
      * it is NOT the reason string, for the same reason;
      * it is NOT "the connection closed" either -- the console never
        grants keep-alive at all, because it never sets
        ``protocol_version`` and so answers HTTP/1.0. That is an accident,
        not a decision, and a test that compared connection reuse would be
        pinning the accident.

    It is: is the shared rule's verdict on those exact header bytes the
    same one, and does each server ACT on that verdict -- answer once, and
    leave no reusable connection carrying octets it did not read?

    ON A POST, acting on it means refusing, in each server's own words, and
    that is what the first two methods assert: each row three times, against
    the function, against the mint (3.8 ``bad_format``, kind "call", index
    null, which is what that server calls a body it declines to read), and
    against the console (400 ``bad_framing``).

    ON A GET IT DOES NOT MEAN REFUSING, and this class said otherwise for a
    round while testing only the method on which it happens to be true. A
    real mint answers `GET /v3/mints` + `Transfer-Encoding: chunked` with
    **200** and then hangs up (mintapi ``_close_if_body_goes_unread``);
    this console and gui/app.py answer **400**. The framing verdict is
    identical -- which is all the pinned contract requires -- and the
    response is not. ``test_the_rule_agrees_on_get_too...`` below drives
    that method and asserts the property at its real size, including the
    mint's 200, so a future change on either side names itself instead of
    passing quietly.

    The vocabulary has to be part of it, and the first draft of this class
    left it out and was WORTHLESS: it asserted only "4xx, one response,
    socket closed", and the PRE-ROUND console satisfied every clause. With
    no framing rule at all it read a chunked POST as a zero-length body,
    dispatched it, and answered 400 "nothing to look up" from inside the
    route -- a refusal of the wrong thing, with the chunk octets still on
    the wire, that looks identical from outside unless you read what it
    said. Checked: this class as written fails on that binary, and the
    version that compared only status codes passed.
    """

    MINT_BODY = json.dumps({"hashes": ["00" * 32]}).encode()

    def mint_port(self):
        return STATE["mint_port"]

    def framing_rule(self):
        import mint_console       # puts impl/ on sys.path
        from aicash.mintapi import framing_verdict
        del mint_console
        return framing_verdict

    def header_block(self, header_line):
        return ("Host: 127.0.0.1\r\nContent-Type: application/json\r\n"
                + header_line.decode("latin-1") + "\r\n")

    def test_the_rule_and_both_servers_refuse_the_same_spellings(self):
        framing_verdict = self.framing_rule()
        cookie = self.cookie_header()
        for name, header_line in TRANSFER_CODING_SPELLINGS.items():
            with self.subTest(name):
                verdict = framing_verdict(
                    parsed_headers(self.header_block(header_line)),
                    body_expected=True)
                self.assertFalse(
                    verdict.framed,
                    "the shared rule frames %r; the servers below are then "
                    "agreeing about the wrong thing" % name)

                console = raw_bytes(self.port, self.build(
                    b"POST", b"/api/status", header_line, CHUNKED_BODY,
                    cookie=cookie), record=False)
                mint = raw_bytes(self.mint_port(), (
                    b"POST /v3/status HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                    b"Content-Type: application/json\r\n" + header_line +
                    b"\r\n" + CHUNKED_BODY
                    + b"GET /v3/mints HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"),
                    record=False)

                for label, exchange in (("console", console), ("mint", mint)):
                    self.assertIsNotNone(
                        exchange.status,
                        "%s: %s got no answer at all" % (label, name))
                    self.assertEqual(
                        exchange.status, 400,
                        "%s answered %s for %s: %s"
                        % (label, exchange.status, name,
                           exchange.describe()))
                    self.assertEqual(
                        len(exchange.statuses), 1,
                        "%s framed the pipelined request off %s and answered "
                        "it: %s" % (label, name, exchange.describe()))
                    self.assertFalse(
                        exchange.still_open,
                        "%s kept a connection it cannot frame (%s)"
                        % (label, name))

                # Each in its own words, which is the half that is MEANT to
                # differ -- and the half that distinguishes "refused as
                # unframable" from "read a zero-length body and then
                # complained about it", which is what the console used to
                # do and what a status-code-only comparison cannot see.
                self.assertEqual(
                    self.console_reason(console), "bad_framing",
                    "the console answered %r for %s: that is a route-level "
                    "refusal, so it FRAMED a body it should not have"
                    % (console.body[:200], name))
                self.assertEqual(
                    mint.json().get("errors"),
                    [{"index": None, "kind": "call", "reason": "bad_format"}],
                    "the mint answered %r for %s" % (mint.body[:200], name))

    def test_the_rule_agrees_on_get_too_and_both_servers_obey_must_close(self):
        """THE SAME BYTES ON THE METHOD THE ROWS ABOVE NEVER SEND, and the
        property stated at the size it actually is.

        The rows above drive the mint only at POST /v3/status. Pointed at a
        GET route the word "refuse" stops being shared: `GET /v3/mints` with
        `Transfer-Encoding: chunked` is answered **200** by a real mint and
        **400** by this console, and neither is wrong. The mint answers the
        GET (§3.7 says anyone may make it) and then hangs up --
        mintapi `_close_if_body_goes_unread` -- while the console and
        gui/app.py refuse it outright. What the pinned contract requires is
        that the FRAMING DECISION is identical, not that the response is,
        and those are different sentences; this class's own docstring used
        to say the stronger one and test only the method on which it
        happens to be true.

        So this is what agreement means on a GET, and all three clauses are
        asserted: the shared rule reaches the same verdict on the same
        bytes; each server answers EXACTLY ONCE; and each server's socket
        is gone afterwards, so the octets neither of them read cannot be
        framed as anybody's next request line. The vocabularies are then
        allowed to differ, and they do.
        """
        framing_verdict = self.framing_rule()
        cookie = self.cookie_header()
        for name, header_line in TRANSFER_CODING_SPELLINGS.items():
            with self.subTest(name):
                # body_expected=False: neither server reads a GET body.
                # This is the input both of them derive for this method.
                verdict = framing_verdict(
                    parsed_headers(self.header_block(header_line)),
                    body_expected=False)
                self.assertFalse(
                    verdict.framed,
                    "the shared rule frames %r on a GET; the servers below "
                    "are then agreeing about the wrong thing" % name)
                self.assertTrue(
                    verdict.must_close,
                    "an unframable request that does not require a close is "
                    "a contradiction: %r" % name)

                console = raw_bytes(self.port, self.build(
                    b"GET", b"/api/descriptor", header_line, CHUNKED_BODY,
                    cookie=cookie), record=False)
                mint = raw_bytes(self.mint_port(), (
                    b"GET /v3/mints HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                    + header_line + b"\r\n" + CHUNKED_BODY
                    + b"GET /v3/mints HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"),
                    record=False)

                for label, exchange in (("console", console), ("mint", mint)):
                    self.assertIsNotNone(
                        exchange.status,
                        "%s: %s got no answer at all" % (label, name))
                    self.assertEqual(
                        len(exchange.statuses), 1,
                        "%s framed the pipelined request off an unframable "
                        "GET (%s) and answered it: %s"
                        % (label, name, exchange.describe()))
                    self.assertFalse(
                        exchange.still_open,
                        "%s kept a connection it cannot frame (%s): %s"
                        % (label, name, exchange.describe()))

                # And now the half that is MEANT to differ, pinned so that a
                # future change to either makes this test say which one
                # moved rather than going quietly green.
                self.assertEqual(
                    self.console_reason(console), "bad_framing",
                    "the console answered %r for %s"
                    % (console.body[:200], name))
                self.assertEqual(console.status, 400, console.describe())
                self.assertEqual(
                    mint.status, 200,
                    "the mint no longer answers an unframable GET with the "
                    "descriptor and a hang-up (%s). That may be an "
                    "improvement, but it is a change in mintapi's do_GET and "
                    "it belongs in mintapi's own tests and in this "
                    "docstring: %s" % (name, mint.describe()))

    def test_the_rule_and_both_servers_accept_the_same_legal_lengths(self):
        """The negative control. A guard that refused everything would pass
        the test above and be useless, so the same three parties have to
        agree on a legal message too."""
        framing_verdict = self.framing_rule()
        cookie = self.cookie_header()
        console_body = json.dumps({"q": "deadbeef"}).encode()
        for name, template in (("plain", b"Content-Length: %d\r\n"),
                               ("extra OWS", b"Content-Length:   %d\r\n"),
                               ("a tab after the colon",
                                b"Content-Length:\t%d\r\n"),
                               ("leading zeros", b"Content-Length: 0%d\r\n")):
            with self.subTest(name):
                verdict = framing_verdict(
                    parsed_headers(self.header_block(
                        template % len(self.MINT_BODY))),
                    body_expected=True)
                self.assertTrue(verdict.framed, name)
                self.assertEqual(verdict.length, len(self.MINT_BODY), name)
                self.assertFalse(verdict.must_close, name)

                console = raw_bytes(self.port, self.build(
                    b"POST", b"/api/status", template % len(console_body),
                    console_body, cookie=cookie, tail=False), record=False)
                self.assertEqual(console.status, 200,
                                 "%s: %s" % (name, console.describe()))

                # The mint DOES grant keep-alive (it sets
                # protocol_version), so on a message it framed correctly the
                # pipelined request that follows is answered -- two
                # responses, which is the observable proof that the stream
                # was re-framable. The console cannot show it that way and
                # is not asked to; see this class's docstring.
                mint = raw_bytes(self.mint_port(), (
                    b"POST /v3/status HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                    b"Content-Type: application/json\r\n"
                    + template % len(self.MINT_BODY) + b"\r\n"
                    + self.MINT_BODY
                    + b"GET /v3/mints HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                      b"Connection: close\r\n\r\n"), record=False)
                self.assertEqual(
                    len(mint.statuses), 2,
                    "the mint did not re-frame its stream after a legal "
                    "%s: %s" % (name, mint.describe()))


class TestAnUnusableMintIdIsRefusedAtStartup(unittest.TestCase):
    """22. The money-losing member of the "answers nothing" family.

    ``--mint-id`` is operator-supplied and reached ``format_token`` only
    AFTER POST /admin/issue had returned 200. An id with a colon, a space,
    an underscore, an empty one, or one past the length limit therefore
    minted real money and THEN raised TokenError out of do_POST with no
    response on the wire -- every click, silently, and the mint stores
    hashes and never secrets, so each of those tokens is money that exists
    and can never be spent. Refused at startup now, like the credential.
    """

    def test_a_usable_id_starts_and_an_unusable_one_does_not(self):
        import mint_console
        self.assertTrue(mint_console._mint_id_is_usable("local-test-mint"))
        for bad in ("a:b", "", "sp ace", "ok_id-1", "x" * 300, None, 5):
            with self.subTest(bad=bad):
                self.assertFalse(mint_console._mint_id_is_usable(bad),
                                 "%r would mint and then fail to format"
                                 % (bad,))

    def test_serve_refuses_rather_than_binding_a_port(self):
        import mint_console
        with self.assertRaises(ValueError) as caught:
            mint_console.serve(0, 1, "a:b", "UNUSED-TOKEN-0123456789",
                               stream=io.StringIO())
        self.assertIn("mint_id", str(caught.exception))

    def test_the_cli_refuses_with_something_to_act_on(self):
        proc = subprocess.run(
            [sys.executable, CONSOLE, "--port", "0", "--mint-port", "1",
             "--mint-id", "a:b", "--no-admin-token"],
            cwd=REPO, capture_output=True, text=True, timeout=60)
        self.assertNotEqual(proc.returncode, 0, proc.stdout)
        message = proc.stdout + proc.stderr
        self.assertIn("--mint-id", message)
        self.assertIn("/v3/mints", message,
                      "the refusal does not say where to get a usable id")

    def test_the_real_fixtures_id_is_usable(self):
        """Not a tautology: it is the id every other test in this module
        issues real tokens under."""
        import mint_console
        self.assertTrue(mint_console._mint_id_is_usable(MINT_ID))


class TestTheFramingRuleIsTheSharedOne(unittest.TestCase):
    """20. ONE RULE, IN ONE PLACE. The point of the round.

    Three servers fixed this defect separately and reached three different
    states of correctness; the fourth -- this one -- never wrote a rule at
    all. These assertions exist so that "the console has its own copy
    again" fails here rather than being found by a fifth reviewer.
    """

    @classmethod
    def setUpClass(cls):
        import mint_console
        cls.mod = mint_console
        with open(mint_console.__file__) as fh:
            cls.source = fh.read()
        cls.tree = ast.parse(cls.source)

    def test_the_console_uses_the_librarys_function_itself(self):
        from aicash.mintapi import framing_verdict
        self.assertIs(self.mod.framing_verdict, framing_verdict,
                      "mint_console.framing_verdict is not the library's; a "
                      "local copy has been reintroduced")

    def test_the_verdict_carries_the_four_fields_the_contract_pins(self):
        """The console reads `length`, `framed`, `must_close` and `reason`
        and never the concrete type. If the library changes the type, this
        still has to hold -- which is why it is read through the file's own
        adapter and not off the library's object; see
        ``test_this_file_does_not_pin_the_librarys_return_type``."""
        verdict = self.mod._framing_fields(self.mod.framing_verdict(
            parsed_headers("Content-Length: 26\r\n\r\n")))
        for field in ("length", "framed", "must_close", "reason"):
            self.assertTrue(hasattr(verdict, field),
                            "the framing verdict has no %r" % field)
        self.assertEqual(verdict.length, 26)
        self.assertIs(verdict.framed, True)
        self.assertIsInstance(verdict.reason, str)

    def test_this_file_does_not_pin_the_librarys_return_type(self):
        """The contract leaves the concrete type to the rule's owner -- "an
        object or tuple carrying at least length, framed, must_close,
        reason" -- so a caller that reaches for attributes has quietly made
        that untrue, and a caller whose TESTS reach for attributes has made
        it untrue twice.

        gui/app.py reads the verdict through a tolerant ``framing_fields``
        adapter and this file used to read attributes off the object, so one
        contract had two readings and a change to the library's type would
        have broken one caller and not the other. Both read it the same way
        now. Every shape the contract allows has to come out the same four
        values in the same order.
        """
        fields = self.mod._framing_fields
        object_form = self.mod.framing_verdict(
            parsed_headers("Content-Length: 26\r\n\r\n"))
        dict_form = {"length": 26, "framed": True, "must_close": False,
                     "reason": "ok"}
        tuple_form = (26, True, False, "ok")
        seen = [tuple(fields(shape))
                for shape in (object_form, dict_form, tuple_form)]
        self.assertEqual(seen[0], (26, True, False, "ok"),
                         "the adapter does not read the library's own "
                         "return type: %r" % (seen[0],))
        self.assertEqual(seen[0], seen[1],
                         "a dict-shaped verdict reads differently from the "
                         "object: %r vs %r" % (seen[0], seen[1]))
        self.assertEqual(seen[1], seen[2],
                         "a tuple-shaped verdict reads differently: %r vs "
                         "%r" % (seen[1], seen[2]))

    def test_the_adapter_decides_nothing_about_framing(self):
        """It unpacks; it must never judge. A framing decision that grows in
        here is a local framing rule with a different name, and it would be
        the third one in this repository."""
        func = next(n for n in self.tree.body
                    if isinstance(n, ast.FunctionDef)
                    and n.name == "_framing_fields")
        # The CODE, not the docstring: the docstring's whole job is to name
        # the rule it is not.
        stmts = func.body[1:] if (isinstance(func.body[0], ast.Expr)
                                  and isinstance(func.body[0].value,
                                                 ast.Constant)) else func.body
        body = "\n".join(ast.get_source_segment(self.source, s) or ""
                         for s in stmts)
        self.assertTrue(body.strip(), "the adapter has no body to check")
        for word in ("Content-Length", "Transfer-Encoding", "chunked",
                     "framing_verdict", "headers"):
            self.assertNotIn(word, body,
                             "_framing_fields mentions %r; it is an "
                             "unpacker, not a rule" % word)

    def test_the_body_reading_methods_are_derived_from_the_dispatch(self):
        """``body_expected`` is the shared rule's ONE caller input, and the
        rule uses it for the clause the library calls THE clause that closes
        the class: what an ABSENT Content-Length means.

        Spelled inline as ``self.command == "POST"`` it is silently wrong
        the day someone adds a body-reading ``do_PUT``: that handler is
        asked about with ``body_expected=False``, so a PUT with no
        Content-Length comes back "framed, length 0" instead of unframable,
        and every test in this module stays green. So the set is declared
        once, next to the rule, and checked here against what the ``do_*``
        methods actually do.
        """
        reads = set()
        for node in ast.walk(self.tree):
            if (isinstance(node, ast.FunctionDef)
                    and node.name.startswith("do_")):
                body = ast.get_source_segment(self.source, node) or ""
                if "_read_json" in body:
                    reads.add(node.name[len("do_"):])
        self.assertTrue(reads,
                        "no do_* method reads a body any more, so this "
                        "check is vacuous -- re-derive it")
        self.assertEqual(
            reads, set(self.mod.BODY_READING_METHODS),
            "BODY_READING_METHODS is %r but the handlers that call "
            "_read_json are %r. The set is the framing rule's only input; "
            "a handler missing from it reads a body the rule was told "
            "nobody would read."
            % (sorted(self.mod.BODY_READING_METHODS), sorted(reads)))

    def test_the_caller_fact_is_not_spelled_inline(self):
        func = next(n for n in ast.walk(self.tree)
                    if isinstance(n, ast.FunctionDef)
                    and n.name == "parse_request")
        seg = ast.get_source_segment(self.source, func)
        self.assertIn("BODY_READING_METHODS", seg)
        self.assertNotIn('self.command == "POST"', seg,
                         "the one caller input is derived inline again; see "
                         "BODY_READING_METHODS")

    def test_the_framing_refusal_is_built_in_exactly_one_place(self):
        """``_read_json`` carried a SECOND 400 ``bad_framing`` envelope for
        the same condition, without the ``framing`` field that
        ``_refuse_unframable`` includes -- two spellings of one refusal in
        one file, documented as unreachable and therefore never compared
        against each other. Unreachable is exactly when a divergence
        survives."""
        sites = [n for n in ast.walk(self.tree)
                 if isinstance(n, ast.Constant) and n.value == "bad_framing"]
        self.assertEqual(len(sites), 1,
                         "this file builds %d bad_framing envelopes; a "
                         "caller and a log correlation can only learn one"
                         % len(sites))

    def test_the_unreachable_backstop_answers_that_same_envelope(self):
        """"Unreachable" is a claim about another method, so the branch is
        driven directly rather than trusted. ``_read_json`` re-checks for a
        missing or lengthless verdict and must answer through the one
        refusal, including when there is no verdict object to read a reason
        off."""
        mod = self.mod

        class Fake:
            close_connection = False

            def __init__(self):
                self.sent = []
                self.refused = []

            def _send(self, code, obj, *a, **kw):
                self.sent.append((code, obj))

            def _refuse_unframable(self, verdict):
                self.refused.append(verdict)

        # the re-check itself: it delegates, it does not compose
        fake = Fake()
        fake._framing = None
        body, ok = mod.Console._read_json(fake)
        self.assertIsNone(body)
        self.assertFalse(ok)
        self.assertEqual(fake.refused, [None],
                         "_read_json answered a missing verdict itself "
                         "instead of through the one refusal")

        # and the one refusal, on a verdict that is not there at all
        naked = Fake()
        mod.Console._refuse_unframable(naked, None)
        self.assertTrue(naked.close_connection)
        code, obj = naked.sent[0]
        self.assertEqual(code, 400)
        self.assertEqual(obj["error"]["reason"], "bad_framing")
        self.assertEqual(obj["error"]["framing"], "no_verdict",
                         "the backstop must be tellable from the rule: "
                         "%r" % (obj,))
        self.assertTrue(obj["error"]["detail"])
        from aicash.mintapi import FRAMING_REASONS
        self.assertNotIn("no_verdict", FRAMING_REASONS,
                         "no_verdict is now one of the library's own "
                         "reasons, so the backstop can no longer be told "
                         "apart from a real verdict")

    def test_the_versionless_guard_is_in_the_same_one_hook(self):
        """The other way this server could answer with no status line, and
        it is guarded in ``parse_request`` for the same reason framing is:
        the base class dispatches nothing of ours for a PUT or a 501."""
        func = next(n for n in ast.walk(self.tree)
                    if isinstance(n, ast.FunctionDef)
                    and n.name == "parse_request")
        seg = ast.get_source_segment(self.source, func)
        self.assertIn("_refuse_bad_version", seg)
        self.assertEqual(
            self.mod.Console.default_request_version, "HTTP/1.1",
            "default_request_version is back to HTTP/0.9, so the stdlib's "
            "own errors -- a one-word request line, POST with no version, "
            "a 431 header block -- go out as naked bodies again")

    def test_it_carries_no_status_code_and_no_error_envelope(self):
        """Its four callers speak three different error vocabularies, so
        the shared rule must decide framing ONLY. This console's own 400
        `bad_framing` envelope is built here, from the verdict."""
        verdict = self.mod.framing_verdict(
            parsed_headers("Content-Length: abc\r\n\r\n"))
        self.assertIs(verdict.framed, False)
        for field in ("status", "code", "http_status", "error", "envelope"):
            self.assertFalse(hasattr(verdict, field),
                             "the shared framing rule grew a %r; it decides "
                             "framing only" % field)

    def test_no_framing_header_is_looked_up_by_name_in_this_file(self):
        """`headers.get("Content-Length")` asks "is there a header spelled
        exactly this", and the answer to that question is not the answer a
        server needs -- `Transfer-Encoding : chunked` is registered under no
        name at all. Every such lookup here was a defect and there are none
        left."""
        bad = []
        for node in ast.walk(self.tree):
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "get"
                    and isinstance(node.func.value, ast.Attribute)
                    and node.func.value.attr == "headers"
                    and node.args
                    and isinstance(node.args[0], ast.Constant)):
                flat = str(node.args[0].value).lower().replace("_", "")
                flat = flat.replace("-", "").replace(".", "")
                if "contentlength" in flat or "transferencoding" in flat:
                    bad.append(ast.get_source_segment(self.source, node))
        self.assertEqual(bad, [],
                         "a framing header is looked up by name again: %r"
                         % (bad,))

    def test_no_header_value_is_handed_to_int(self):
        """int() accepts a sign, PEP 515 underscores and surrounding
        whitespace, so it is a LOOSER parser than HTTP's `1*DIGIT` -- and
        it raises past the interpreter's digit limit, which is how this
        file came to answer nothing at all."""
        bad = []
        for node in ast.walk(self.tree):
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "int"):
                seg = ast.get_source_segment(self.source, node) or ""
                if "headers" in seg:
                    bad.append(seg)
        self.assertEqual(bad, [],
                         "a header value is converted with int() again: %r"
                         % (bad,))

    def test_the_rule_is_asked_in_exactly_one_place(self):
        calls = [ast.get_source_segment(self.source, n)
                 for n in ast.walk(self.tree)
                 if isinstance(n, ast.Call)
                 and isinstance(n.func, ast.Name)
                 and n.func.id == "framing_verdict"]
        self.assertEqual(len(calls), 1,
                         "framing_verdict is asked in %d places; one hook "
                         "that every method passes through is the point"
                         % len(calls))

    def test_the_hook_covers_methods_this_file_does_not_implement(self):
        """It is in parse_request, not at the top of do_GET/do_POST: PUT
        reaches no do_* of ours and its unread body is just as smuggleable.
        """
        func = next(n for n in ast.walk(self.tree)
                    if isinstance(n, ast.FunctionDef)
                    and n.name == "parse_request")
        self.assertIn("framing_verdict",
                      ast.get_source_segment(self.source, func))

    def test_the_docstring_records_that_framing_is_shared_and_why(self):
        """The console's considered note on DELIBERATE DUPLICATION was
        written about the four-gate authentication design and is sound for
        it. It is wrong for framing, and the next reader must not
        'restore' a local copy on the strength of it."""
        doc = (self.mod.__doc__ or "")
        lower = doc.lower()
        self.assertIn("framing_verdict", doc)
        self.assertIn("aicash.mintapi", lower)
        self.assertIn("restore", lower,
                      "the docstring no longer tells the next reader not to "
                      "restore a local framing copy")
        self.assertIn("a control nobody re-reads", lower,
                      "the authentication duplication argument was deleted "
                      "instead of being kept and carved out")
        self.assertTrue("four gates" in lower or "same four gates" in lower,
                        "the duplication note no longer says which design it "
                        "is about")

    def test_the_docstring_still_says_the_console_is_not_safe_to_expose(self):
        self.assertIn("safe to expose", (self.mod.__doc__ or "").lower())


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
