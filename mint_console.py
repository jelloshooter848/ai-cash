#!/usr/bin/env python3
"""Operator console for a running aicash mint.

A separate HTTP server, deliberately: the protocol implementation in
impl/aicash stays untouched, and nothing here is normative. The console
proxies to the mint so the browser talks to one origin, and it holds the
admin token server-side so the credential never reaches the page.

WHY THIS FILE HAS AUTHENTICATION OF ITS OWN
-------------------------------------------
This console holds the mint's admin credential and exposes issuance. For
most of its life its only protection was the loopback bind, and that is a
much weaker boundary than it sounds:

  * it does not separate users on a shared machine;
  * it does not stop any other local process, including something the
    operator installed for an unrelated reason;
  * it does not stop a web page open in the operator's own browser from
    issuing requests to 127.0.0.1 — a routinely exploited class of attack.

So the port is now gated four ways:

  1. CAPABILITY URL. Startup generates a fresh key (secrets.token_urlsafe)
     that lives only in this process's memory and is printed once, to the
     terminal. It is never written to a file we control, never logged, and
     never appears in a response body.
  2. COOKIE EXCHANGE. GET / with the right ?k= gets the page plus an
     HttpOnly, SameSite=Strict session cookie whose value is a *different*
     random string. EVERY OTHER ROUTE, of every method, requires that
     cookie and accepts no key in the query string, so a URL that leaks
     (shoulder, history, a screenshot) cannot be replayed against an API
     route by a page that cannot read cookies. The gate is written as
     "everything except GET /" rather than "everything under /api/": a
     route added later is then locked before anyone writes it.
  3. HOST HEADER MUST BE A LOOPBACK LITERAL. This is the DNS-rebinding
     defence, and it is exactly why the loopback bind is not sufficient on
     its own: a hostile site can point its own domain at 127.0.0.1 and the
     browser will happily connect here — only the Host check catches it.
  4. ORIGIN / REFERER / SEC-FETCH-SITE. Present-and-foreign is refused;
     absent is allowed, because curl and same-origin fetches omit them and
     neither can be conscripted by a web page.

NONE OF THIS MAKES THE CONSOLE SAFE TO EXPOSE. It is a second lock on a
door that should still not face the street: keep the bind on 127.0.0.1,
do not port-forward it, do not put it behind a reverse proxy. The auth is
insurance against the local attacker and the hostile tab, not a licence to
widen the bind.

DELIBERATE DUPLICATION: the operator GUI implements the same design in
gui/app.py (page at gui/page.html), and this file does NOT import it. Two
reasons: the console must stay runnable on its own with nothing but the
stdlib and impl/, and a security control that a second tool silently
inherits is a control nobody re-reads. A later round may unify them; until
then, a change here is a change to make there too.

WHERE THE TWO ACTUALLY DIVERGE, for whoever unifies them (an earlier note
claimed gui/app.py answers a foreign Host with 421; it does not, and never
did — `grep -c 421 gui/app.py` is 0. Both tools answer 403. The real list):

  * error reason strings: this file says "bad_host" and "cross_site",
    gui/app.py says "not_loopback" and "not_authorized";
  * cookie names: "aicash_console" here, "aicash_gui_session" there —
    which is deliberate, so one tool's session is not the other's;
  * (settled) gui/app.py used to compare secrets with hmac.compare_digest
    on str, which raises TypeError on non-ASCII input. It now has its own
    _secret_eq with the same encode-first contract as this file's, so both
    tools answer a non-ASCII credential with 401 instead of raising inside
    the gate. Neither file imports the other's; see DELIBERATE DUPLICATION.
  * (settled) this file's Host check used a hand-rolled splitter while
    gui/app.py used an anchored regex, and the splitter accepted three
    forged hosts that reached a live mint. Both now use the same anchored
    pattern; this one keeps a capture group because it also pins the port.

The status codes already agree; do not "reconcile" one to a code it never
returned.

Loopback only. Anyone who reaches this port AND holds the capability URL
can mint.
"""
import argparse
import base64
import hmac
import http.client
import http.cookies
import json
import os
import re
import secrets
import sys
import threading
import urllib.parse
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "impl"))
from aicash.tokencodec import format_token, ledger_key, new_secret

COOKIE_NAME = "aicash_console"
# A handful of open tabs / re-opens of the capability URL, no more. Bounded
# so that a stream of GET /?k=<key> cannot grow this process without limit.
MAX_SESSIONS = 32
# What a browser may put in Host, and what an Origin/Referer may name. A
# literal only: "127.0.0.1.attacker.example" resolving to 127.0.0.1 is the
# whole rebinding attack, and it fails this set.
LOOPBACK_NAMES = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})

NO_AUTH_BANNER = """\
********************************************************************
*  aicash mint console is running with --no-auth.                  *
*                                                                  *
*  There is NO capability key and NO session cookie. Every local   *
*  process, and every web page open in this machine's browser,     *
*  can reach this port and MINT MONEY with the operator            *
*  credential this console holds.                                  *
*                                                                  *
*  This flag exists for automated tests. If you did not mean to    *
*  pass it, stop this process now and restart without it.          *
********************************************************************"""

PAGE = r"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>aicash mint console</title><style>
:root{--bg:#f7f7f5;--card:#fff;--ink:#1a1a18;--dim:#6b6b66;--line:#e2e2dd;
--accent:#2f6f4f;--warn:#8a4b2a;--mono:ui-monospace,SFMono-Regular,Menlo,monospace}
@media(prefers-color-scheme:dark){:root{--bg:#16161a;--card:#1e1e23;--ink:#e8e8e4;
--dim:#9a9a94;--line:#30303a;--accent:#6bbf90;--warn:#d89a6a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
.wrap{max-width:940px;margin:0 auto;padding:24px 18px 60px}
h1{font-size:20px;margin:0 0 2px}h2{font-size:14px;text-transform:uppercase;
letter-spacing:.07em;color:var(--dim);margin:0 0 12px}
.sub{color:var(--dim);font-size:13px;margin-bottom:22px;font-family:var(--mono)}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;
padding:18px;margin-bottom:16px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
.stat .n{font-size:24px;font-family:var(--mono);font-weight:600}
.stat .l{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--dim)}
label{display:block;font-size:12px;color:var(--dim);margin:10px 0 4px}
input,textarea{width:100%;padding:9px 10px;border:1px solid var(--line);border-radius:7px;
background:var(--bg);color:var(--ink);font-family:var(--mono);font-size:13px}
textarea{min-height:70px;resize:vertical}
button{background:var(--accent);color:#fff;border:0;border-radius:7px;padding:9px 16px;
font-size:14px;cursor:pointer;margin-top:12px}button:hover{opacity:.9}
button.sec{background:transparent;color:var(--ink);border:1px solid var(--line)}
.row{display:flex;gap:12px;flex-wrap:wrap}.row>div{flex:1;min-width:130px}
pre{background:var(--bg);border:1px solid var(--line);border-radius:7px;padding:12px;
overflow-x:auto;font-size:12px;margin:12px 0 0;white-space:pre-wrap;word-break:break-all}
.tok{font-family:var(--mono);font-size:12px;background:var(--bg);border:1px solid var(--line);
border-radius:6px;padding:9px;margin-top:8px;word-break:break-all;cursor:pointer}
.tok:hover{border-color:var(--accent)}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--accent);
margin-right:6px;vertical-align:middle}.dot.off{background:var(--warn)}
.warn{color:var(--warn);font-size:12px;margin-top:8px}
details summary{cursor:pointer;color:var(--dim);font-size:13px}
.ok{color:var(--accent)}.bad{color:var(--warn)}
#lost{display:none;background:var(--card);border:1px solid var(--warn);border-radius:10px;
padding:14px;margin-bottom:16px;color:var(--warn);font-size:13px}
</style></head><body><div class="wrap">
<h1><span class="dot" id="dot"></span>aicash mint console</h1>
<div class="sub" id="hdr">connecting...</div>

<div id="lost">This session is no longer authorised. The console was
restarted, or this tab was opened without the one-time URL. Re-open the
console using the address printed in the terminal that started it — it
carries a key that is generated fresh on every start and is not stored
anywhere.</div>

<div class="grid" id="stats"></div>

<div class="card"><h2>Issue tokens</h2>
<div class="row">
<div><label>Amount each (millicredits)</label><input id="amt" value="1000"></div>
<div><label>How many</label><input id="qty" value="1"></div>
</div>
<button onclick="issue()">Issue</button>
<div class="warn">Issuing creates new money. It is signed into the supply snapshot and cannot be undone.</div>
<div id="issued"></div></div>

<div class="card"><h2>Check a token</h2>
<label>Paste a token string or a ledger key</label>
<textarea id="q" placeholder="aicash:v3:..."></textarea>
<button class="sec" onclick="check()">Check status</button>
<div id="status"></div></div>

<div class="card"><h2>Mint descriptor</h2>
<details><summary>Show raw JSON</summary><pre id="raw">...</pre></details></div>
</div><script>
const $=id=>document.getElementById(id);
// credentials:'same-origin' is the default, and it is spelled out because
// the session cookie IS the authorisation on every /api/* route: drop it
// and the whole page 401s.
async function api(p,b){const r=await fetch(p,b?{method:'POST',credentials:'same-origin',
 headers:{'Content-Type':'application/json'},body:JSON.stringify(b)}:{credentials:'same-origin'});
 let data={};try{data=await r.json();}catch(e){data={error:{reason:'bad_response'}};}
 if(r.status===401){$('lost').style.display='block';}
 return {ok:r.ok,status:r.status,data:data};}
function fmt(n){return (n===undefined||n===null)?'-':n.toLocaleString();}
async function refresh(){
 const r=await api('/api/descriptor');
 if(!r.ok){$('dot').className='dot off';
  $('hdr').textContent=(r.status===401)?'not authorised':'mint unreachable';return;}
 const d=r.data,s=d.supply||{};
 $('dot').className='dot';$('lost').style.display='none';
 $('hdr').textContent=d.mint_id+'  ·  '+(d.denominations_mc||[]).join(', ')+' mc denominations';
 $('stats').innerHTML=[['Outstanding',s.outstanding_mc],['Issued',s.cumulative_issued_mc],
  ['Burned',s.cumulative_burned_mc],['Snapshot',s.snapshot_seq]]
  .map(([l,v])=>`<div class="stat"><div class="n">${fmt(v)}</div><div class="l">${l}</div></div>`).join('');
 $('raw').textContent=JSON.stringify(d,null,2);}
async function issue(){
 const amount=parseInt($('amt').value,10),count=parseInt($('qty').value,10);
 $('issued').innerHTML='<div class="warn">issuing...</div>';
 const r=await api('/api/issue',{amount_mc:amount,count:count});
 if(!r.ok){$('issued').innerHTML='<pre class="bad">'+JSON.stringify(r.data,null,2)+'</pre>';return;}
 $('issued').innerHTML='<div class="warn ok">'+r.data.tokens.length+
  ' token(s) issued. Click to copy — these are bearer tokens, anyone holding one can spend it.</div>'+
  r.data.tokens.map(t=>`<div class="tok" onclick="navigator.clipboard.writeText('${t}');this.textContent='copied — '+this.dataset.t" data-t="${t}">${t}</div>`).join('');
 refresh();}
async function check(){
 const r=await api('/api/status',{q:$('q').value.trim()});
 $('status').innerHTML='<pre>'+JSON.stringify(r.data,null,2)+'</pre>';}
refresh();setInterval(refresh,5000);
</script></body></html>"""

DENIED_PAGE = """<!doctype html><meta charset="utf-8">
<title>aicash mint console - not authorised</title>
<style>body{font:15px/1.6 system-ui,sans-serif;margin:0;background:#16161a;color:#e8e8e4}
.w{max-width:620px;margin:12vh auto;padding:0 20px}code{background:#26262c;padding:2px 5px;
border-radius:4px}h1{font-size:19px}p{color:#b9b9b3}</style>
<div class="w"><h1>Not authorised</h1>
<p>This console can mint money, so it does not answer an address that was
merely guessed. Open it with the one-time URL printed by the process that
started it — the line beginning <code>http://127.0.0.1:</code> and ending
in <code>?k=&hellip;</code>.</p>
<p>That key is generated fresh on every start and is held only in the
console's memory: it is not in a file, not in a log, and not recoverable.
If the terminal is gone, restart the console to get a new one.</p></div>"""


def _secret_eq(known, presented) -> bool:
    """Constant-time compare that cannot be made to raise.

    hmac.compare_digest, never ==: an ordinary string comparison returns
    early on the first wrong byte and leaks the prefix by timing.

    It is called on bytes, not on str, and that is the whole point of this
    wrapper. compare_digest raises TypeError on a str holding any non-ASCII
    character, and every value passed here is attacker-supplied: the ?k= of
    an unauthenticated GET, or a cookie. `GET /?k=%C3%A9` used to kill the
    handler thread, drop the connection with no response, and append a
    traceback to stderr — which the startup banner warns may be captured to
    a file by a service manager. Encoding first makes the comparison total:
    every input is either unequal or malformed, and both answer False.

    Length still leaks, as it does for compare_digest on bytes; the secrets
    compared here are fixed-length, so there is nothing in that to learn.
    """
    if not isinstance(known, str) or not isinstance(presented, str):
        return False
    if not known or not presented:
        return False
    try:
        return hmac.compare_digest(known.encode("utf-8", "surrogatepass"),
                                   presented.encode("utf-8", "surrogatepass"))
    except (UnicodeError, TypeError, ValueError):
        return False


class Auth:
    """The capability key and the sessions it has handed out. Memory only.

    Nothing here is ever persisted or logged. A restart invalidates every
    outstanding session, which is the intended behaviour: the credential
    the console holds should not outlive the terminal that launched it.
    """

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        # token_urlsafe(32) is 32 bytes of os.urandom, ~43 url-safe chars.
        self.key = secrets.token_urlsafe(32) if enabled else None
        self._sessions = OrderedDict()
        self._lock = threading.Lock()

    def key_ok(self, presented) -> bool:
        if not self.enabled:
            return True
        return _secret_eq(self.key, presented)

    def new_session(self) -> str:
        """An independent secret, not the key: the cookie must not be able
        to reconstruct the capability URL, and vice versa."""
        session = secrets.token_urlsafe(32)
        with self._lock:
            self._sessions[session] = None
            while len(self._sessions) > MAX_SESSIONS:
                self._sessions.popitem(last=False)
        return session

    def session_ok(self, presented) -> bool:
        if not self.enabled:
            return True
        with self._lock:
            known = list(self._sessions)
        found = False
        for session in known:
            # No early break: every candidate is compared, so the time
            # taken does not depend on which slot matched.
            if _secret_eq(session, presented):
                found = True
        return found


# One anchored whitelist for the whole Host header, port included. It
# replaced a hand-rolled splitter that validated the part before the
# separator and threw the rest away, which let three forged hosts through
# to a live mint: "[::1]evil.example" and "[::1].evil.example" (everything
# after "]" was discarded, so the name checked was a clean "[::1]") and
# "127.0.0.1:" (an empty port is falsy, so the port branch was skipped
# entirely). All three were answered 200 on POST /api/issue, which reached
# POST /admin/issue on the mint with the operator credential and minted.
#
# A set of names plus a splitter is exactly how the accepted host space
# widens: the splitter decides what gets compared, so the set stops being
# the whitelist it looks like. One regex that has to match end to end
# cannot be talked into ignoring a suffix. gui/app.py's _HOST_RE is the
# same pattern for the same reason; the only difference here is the
# capture group, because this file additionally pins the port to its own.
#
# Bare "::1" carries no port: an unbracketed IPv6 address followed by
# ":<port>" is not something HTTP can express, so "::1:8893" is not a
# loopback host with a port and is refused.
_HOST_RE = re.compile(
    r"^(?:(?:127\.0\.0\.1|localhost|\[::1\])(?::([0-9]{1,5}))?|::1)$")


class Console(BaseHTTPRequestHandler):
    mint_port = 0
    mint_id = ""
    admin_token = None
    auth = None

    def log_message(self, *a):
        # Silence is load-bearing, not laziness: the default handler writes
        # the request line to stderr, and the request line of the capability
        # URL is the capability. Nothing in this file writes self.path, a
        # query string or a cookie anywhere.
        pass

    # ---------------- request-shape guards ----------------

    def _route(self) -> str:
        return urllib.parse.urlsplit(self.path).path

    def _query_key(self) -> str:
        query = urllib.parse.urlsplit(self.path).query
        values = urllib.parse.parse_qs(query).get("k") or []
        return values[0] if values else ""

    def _cookie_session(self) -> str:
        raw = self.headers.get("Cookie")
        if not raw:
            return ""
        try:
            jar = http.cookies.SimpleCookie()
            jar.load(raw)
        except http.cookies.CookieError:
            return ""
        morsel = jar.get(COOKIE_NAME)
        return morsel.value if morsel else ""

    def _my_port(self):
        try:
            return self.server.server_address[1]
        except Exception:
            return None

    def _host_ok(self) -> bool:
        """Host must be a loopback literal. The DNS-rebinding defence.

        A hostile page cannot change the Host header the browser sends, so
        a request that arrives here claiming any other name came through a
        name that resolved to 127.0.0.1 — which is the attack. A missing
        Host is refused too: no browser omits it, so allowing it bought
        nothing and left the control open to a hand-rolled client.
        """
        host = self.headers.get("Host")
        if not host:
            return False
        match = _HOST_RE.match(host.strip().lower())
        if match is None:
            return False
        # The whole header matched a loopback literal. Additionally pin the
        # port to the one actually bound, so a literal aimed at some other
        # local service is not accepted merely for being loopback.
        port = match.group(1)
        mine = self._my_port()
        if port and mine is not None and int(port) != mine:
            return False
        return True

    def _same_origin(self, value: str) -> bool:
        if value.lower() == "null":       # sandboxed iframe, file://, data:
            return False
        try:
            parts = urllib.parse.urlsplit(value)
            port = parts.port
        except ValueError:
            return False
        if parts.scheme != "http":
            return False
        if (parts.hostname or "").lower() not in LOOPBACK_NAMES:
            return False
        mine = self._my_port()
        return port is not None and mine is not None and port == mine

    def _origin_ok(self) -> bool:
        """Refuse a request another site told the browser to make.

        SameSite=Strict on the session cookie already means a cross-site
        request arrives without it and 401s. This is the belt to that
        braces, and it also covers the --no-auth path. Absent headers are
        allowed: curl and same-origin fetches omit them, and neither can be
        conscripted by a web page.
        """
        site = (self.headers.get("Sec-Fetch-Site") or "").strip().lower()
        if site and site not in ("same-origin", "none"):
            return False
        for header in ("Origin", "Referer"):
            value = (self.headers.get(header) or "").strip()
            if value and not self._same_origin(value):
                return False
        return True

    # ---------------- responses ----------------

    def _send(self, code, obj, ctype="application/json"):
        payload = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _deny(self, code, reason, detail, api):
        # close_connection because a denied POST may have an unread body on
        # the socket; reusing that connection would desynchronise it. The
        # body never echoes self.path — it holds the key on the page route.
        self.close_connection = True
        if api:
            return self._send(code, {"error": {"reason": reason,
                                               "detail": detail}})
        return self._send(code, DENIED_PAGE.encode(),
                          "text/html; charset=utf-8")

    def _guard(self, api) -> bool:
        if not self._host_ok():
            self._deny(403, "bad_host",
                       "This console only answers requests addressed to "
                       "127.0.0.1 or localhost. It is a local operator "
                       "tool, not a hosted service.", api)
            return False
        if not self._origin_ok():
            self._deny(403, "cross_site",
                       "That request came from another web page. This "
                       "console holds the mint's operator credential, so "
                       "it answers only its own page.", api)
            return False
        return True

    def _is_page(self, route) -> bool:
        """The ONE route the capability key may open, and only by GET.

        The gate below is written as "everything except this", not as
        "everything under /api/". The difference is which way a route added
        tomorrow is born: under a prefix test it is born open and its author
        has to remember the lock, and this is the tool that already shipped
        unlocked once. gui/app.py gates the same way, deliberately.
        """
        return route in ("/", "/index.html")

    def _session_authorized(self) -> bool:
        """The cookie, and only the cookie.

        A key in the query string is deliberately NOT accepted here. The
        capability URL can end up in shell history, a screenshot or a
        shoulder; the cookie is HttpOnly and SameSite=Strict, so a page
        that steals the URL still cannot drive a non-page route with it.
        """
        return self.auth.session_ok(self._cookie_session())

    def _deny_no_session(self):
        # The detail is a fixed string. It never interpolates self.path or
        # the query: on this route the query IS the capability, and a 401
        # body is the cheapest place to hand it back to whatever can read
        # the response.
        return self._deny(401, "unauthorized",
                          "this route needs the console session cookie; "
                          "open the console at the URL printed in the "
                          "terminal", True)

    # ---------------- mint proxy ----------------

    def _mint(self, method, path, body=None, admin=False):
        """Proxy one request to the mint. Never raises.

        The mint is a separate process an operator can stop, and with it
        stopped an authenticated request used to get a dropped connection
        and a traceback on stderr instead of an answer. A 502 in the error
        envelope is what the page is already written to render, and the
        detail names only an exception class — never the mint's response
        text, which could carry back something we did not intend to show.
        """
        headers = {"Content-Type": "application/json"}
        # Only /admin/* needs the credential. The public routes used to get
        # it too, which put the operator token into requests that did not
        # need it (and into whatever the mint chooses to log about them).
        if admin and self.admin_token:
            headers["X-Admin-Token"] = self.admin_token
        c = None
        try:
            c = http.client.HTTPConnection("127.0.0.1", self.mint_port,
                                           timeout=10)
            c.request(method, path,
                      json.dumps(body) if body is not None else None, headers)
            r = c.getresponse()
            return r.status, json.loads(r.read() or b"{}")
        except (OSError, ValueError, http.client.HTTPException) as exc:
            return 502, {"error": {
                "reason": "mint_unreachable",
                "detail": "the console could not complete a request to the "
                          "mint on 127.0.0.1:%d (%s). Is it still running?"
                          % (self.mint_port, type(exc).__name__)}}
        finally:
            if c is not None:
                try:
                    c.close()
                except OSError:
                    pass

    # ---------------- routes ----------------

    def do_GET(self):
        route = self._route()
        page = self._is_page(route)
        if not self._guard(not page):
            return

        if page:
            has_session = self._session_authorized()
            if self.auth.enabled and not (
                    has_session or self.auth.key_ok(self._query_key())):
                return self._deny(401, "unauthorized",
                                  "open the URL printed in the terminal",
                                  False)
            payload = PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            if self.auth.enabled and not has_session:
                # Only on the key exchange. Minting a session on every page
                # load would let a browser sitting on the page evict its own
                # other tabs (MAX_SESSIONS of them) just by reloading.
                # HttpOnly: script cannot read it, so an XSS or a hostile
                # extension page cannot exfiltrate the session. Strict: the
                # browser withholds it on anything another site initiates.
                self.send_header(
                    "Set-Cookie",
                    "%s=%s; HttpOnly; SameSite=Strict; Path=/"
                    % (COOKIE_NAME, self.auth.new_session()))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            return self.wfile.write(payload)

        # Everything that is not the page: the cookie, before dispatch, so
        # an unknown route and a future route are both already locked.
        if not self._session_authorized():
            return self._deny_no_session()

        if route == "/api/descriptor":
            code, obj = self._mint("GET", "/v3/mints")
            return self._send(code, obj)
        self._send(404, {"error": {"reason": "not_found", "detail": ""}})

    def do_POST(self):
        route = self._route()
        if not self._guard(True):
            return
        # No POST route is the page, so there is no exemption here at all.
        if not self._session_authorized():
            return self._deny_no_session()

        n = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return self._send(400, {"error": "bad_json"})
        if not isinstance(body, dict):
            return self._send(400, {"error": "bad_json"})

        if route == "/api/issue":
            amount, count = body.get("amount_mc"), body.get("count", 1)
            if not isinstance(amount, int) or amount <= 0 or not isinstance(count, int) \
                    or not 1 <= count <= 100:
                return self._send(400, {"error": "amount_mc must be a positive int, "
                                                 "count between 1 and 100"})
            secret_bytes = [new_secret() for _ in range(count)]
            outputs = [{"amount_mc": amount,
                        "secret": base64.urlsafe_b64encode(s).decode().rstrip("=")}
                       for s in secret_bytes]
            code, obj = self._mint("POST", "/admin/issue", {"outputs": outputs},
                                   admin=True)
            if code != 200:
                return self._send(code, obj)
            # The token string only exists here: the mint stores hashes, never
            # secrets, so an unshown token is unrecoverable money.
            return self._send(200, {"tokens": [format_token(self.mint_id, amount, s)
                                               for s in secret_bytes]})

        if route == "/api/status":
            q = (body.get("q") or "").strip()
            if not q:
                return self._send(400, {"error": "nothing to look up"})
            key = q
            if q.startswith("aicash:"):
                parts = q.split(":")
                if len(parts) != 5:
                    return self._send(400, {"error": "malformed token string"})
                pad = "=" * (-len(parts[4]) % 4)
                try:
                    key = ledger_key(base64.urlsafe_b64decode(parts[4] + pad))
                except Exception:
                    return self._send(400, {"error": "malformed token secret"})
            code, obj = self._mint("POST", "/v3/status", {"hashes": [key]})
            return self._send(code, obj)

        self._send(404, {"error": {"reason": "not_found", "detail": ""}})


def serve(port, mint_port, mint_id, admin_token, auth=True, announce=True,
          stream=None):
    """Bind the console. Authenticated unless auth=False.

    Returns a ThreadingHTTPServer with ``.auth`` and ``.console_url`` on it.
    The capability URL is printed here, once, and nowhere else: callers get
    it back on the server object rather than by re-deriving the key.
    """
    out = stream if stream is not None else sys.stdout
    state = Auth(enabled=bool(auth))
    handler = type("ConsoleHandler", (Console,), {
        "mint_port": mint_port, "mint_id": mint_id,
        "admin_token": admin_token, "auth": state})
    httpd = ThreadingHTTPServer(("127.0.0.1", port), handler)
    httpd.daemon_threads = True
    httpd.auth = state
    bound = httpd.server_address[1]
    httpd.console_url = ("http://127.0.0.1:%d/?k=%s" % (bound, state.key)
                         if state.enabled else "http://127.0.0.1:%d/" % bound)
    if not state.enabled:
        # Loud, multi-line, on stderr, every single startup.
        print(NO_AUTH_BANNER, file=sys.stderr, flush=True)
    if announce:
        if state.enabled:
            print("\n  CONSOLE  open this exact URL — it carries a one-time key:"
                  "\n\n      %s\n"
                  "\n  The plain http://127.0.0.1:%d/ answers 401. The key is"
                  "\n  held in memory only, is never written to a file or a log"
                  "\n  by this console, and dies with this process."
                  "\n  (If this process's stdout is captured to a file by a"
                  "\n  service manager, that file now holds a minting"
                  "\n  credential — restart to rotate it.)"
                  "\n  Auth does not make this safe to expose: keep it on"
                  "\n  loopback, do not proxy it, do not port-forward it."
                  % (httpd.console_url, bound), file=out, flush=True)
        else:
            print("\n  CONSOLE  %s   (UNAUTHENTICATED)" % httpd.console_url,
                  file=out, flush=True)
    return httpd


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Operator console for a running aicash mint. Loopback "
                    "only; prints a one-time capability URL on startup.")
    ap.add_argument("--port", type=int, default=8080,
                    help="console port; 0 picks an ephemeral one")
    ap.add_argument("--mint-port", type=int, default=8787,
                    help="port the mint is listening on")
    ap.add_argument("--mint-id", default="local-test-mint")
    ap.add_argument("--admin-token-file", default="mint-admin-keys.json",
                    help='JSON file with an "admin_token" field, as written '
                         "by run_mint.py. Preferred: a token passed on the "
                         "command line is visible to every process on the "
                         "machine via /proc and ps.")
    ap.add_argument("--admin-token",
                    help="operator credential (visible in ps; prefer "
                         "--admin-token-file)")
    ap.add_argument("--no-auth", action="store_true",
                    help="FOR AUTOMATED TESTS ONLY: serve with no capability "
                         "key and no session cookie. Prints a loud warning.")
    args = ap.parse_args(argv)

    token = args.admin_token
    if token is None and args.admin_token_file:
        try:
            with open(args.admin_token_file) as fh:
                token = json.load(fh).get("admin_token")
        except FileNotFoundError:
            token = None
        except (OSError, ValueError) as exc:
            # Never interpolate the file's contents into the message.
            sys.exit("could not read %s: %s"
                     % (args.admin_token_file, type(exc).__name__))

    httpd = serve(args.port, args.mint_port, args.mint_id, token,
                  auth=not args.no_auth)
    try:
        httpd.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()
        httpd.server_close()


if __name__ == "__main__":
    main()
