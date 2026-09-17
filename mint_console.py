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

THE CLASS OF DEFECT THIS AUTHENTICATION EXISTS AGAINST
------------------------------------------------------
The same defect has now been found three times in this repository, on three
different artifacts, and underneath it is one shape: a credential-shaped
thing whose ABSENCE was read as permission rather than as refusal. None of
the three failed a check. Each had no check, and no check reads as fine
because nothing gets reported.

  1. this console (2026-09-08): it holds the mint's admin credential and
     exposes issuance, and its only protection was the loopback bind. The
     four gates above are that fix.
  2. the operator GUI, gui/app.py with gui/page.html (2026-09-15):
     specified the same way at a larger surface, because it also holds
     every wallet in its workdir and can spend them. Same four gates, same
     reasons: its module docstring states them from that side, and
     gui/README.md's security section points back here by name (app.py
     itself does not mention this file — the README is the link that
     exists). Whoever unifies the two starts from the divergence list
     below.
  3. the library itself (2026-09-15): ``MintConfig.admin_token`` defaulted
     to ``None`` and ``admin_authorized()`` answered True for ``None``, so
     any program that built a mint from a default config served POST
     /admin/issue to whoever could reach the port. That is the worst of the
     three, because the other two are tools an operator chooses to run and
     this one is what you get by not thinking about it. The field now has
     no default at all: a secret string, ADMIN_ISSUANCE_DISABLED, or
     ADMIN_ISSUANCE_OPEN, and anything else — unset, None, "" — raises out
     of MintConfig before a port is bound. Open issuance still exists and
     is opted into by name, so `grep -rn ADMIN_ISSUANCE_OPEN` finds every
     open mint; what is gone is reaching it by saying nothing. Breaking
     change from the v0.4 build, deliberately, recorded in
     LOCKED-DESIGN-DECISIONS.md (L19) rather than left to prose.

This file follows (3) rather than depending on it. It refuses to start with
no credential — ``--no-admin-token`` is the explicit, read-only opt-out, so
the absence is something an operator asked for and never something that
happened — and POST /api/issue answers 503 ``no_admin_credential`` instead
of sending a credential-less /admin/issue and finding out how generous the
mint on the other end happens to be. See ``main()`` and ``_mint()``.

DELIBERATE DUPLICATION -- OF THE AUTHENTICATION, AND ONLY OF IT: the
operator GUI implements the same four gates in gui/app.py (page at
gui/page.html), and this file does NOT import them. Two reasons: the
console must stay startable on its own out of impl/ with no third-party
package but the one the mint itself needs, and a security control that a
second tool silently inherits is a control nobody re-reads. A later round
may unify them; until then, a change to a GATE here is a change to make
there too. That argument is unchanged and it still holds for the four
gates above.

REQUEST FRAMING IS SHARED, DELIBERATELY, AND MUST NOT BE COPIED BACK HERE.
``framing_verdict`` is imported from ``aicash.mintapi`` and asked about
EVERY request this file answers, of every method, in ``parse_request``.
That is the exact opposite of the rule above, on purpose. The rule above is
an argument about a control an operator RE-READS and can decide differently
for two tools; framing is not that kind of control, and this round is the
evidence:

  * the defect was reported once, by an outside reviewer, against the mint,
    and fixed there;
  * it was then found to have been fixed for ONE SPELLING of one header
    name, and fixed a second time against the class;
  * an independent verifier then pointed the same twenty-five spellings at
    the servers nobody had swept. Nineteen still worked on the GUI, on its
    POST routes and its GET routes alike. THIS FILE had no framing rule at
    all -- not a stale copy, no copy -- and was worse than either. Measured
    against it, on sixteen Content-Length values -- the fifteen in
    ``CONTENT_LENGTH_VALUES`` plus an honest control -- for one 32-octet
    body:

      - EIGHT sent NO STATUS LINE AT ALL, dropped the socket, and printed a
        traceback through the server machinery -- ``abc``, ``3 2``,
        ``2, 32``, ``0x20``, ``32.0``, twenty digits, five thousand digits
        (the shape the outside reviewer reported against the mint), and
        fullwidth ``３２``, which ``int()`` would accept as 32 in a Python
        source file and which arrives here latin-1-decoded off the wire;
      - FOUR were READ as a 32-octet body that a spec-strict hop reads as
        an invalid length and must not recover from -- ``+32`` and ``3_2``
        (``int()`` takes a sign and PEP 515 separators), ``32\x0b`` and
        ``32\xa0`` (Python's whitespace set is wider than HTTP's OWS).
        That is a length two parties compute differently, which is the
        definition of a smuggling primitive;
      - ONE, ``-1``, parked a worker thread on ``read(-1)`` until the peer
        went away. No response, no log line, no traceback, and the thread
        never came back;
      - ``-32`` answered ``bad_json`` -- a framing failure reported to the
        caller as a problem with their JSON, which was fine.

Four copies of one wire-format rule produced four different states of
correctness, and the copy a reader would have called "deliberately
duplicated" was the one that had never been written. Re-reading cannot keep
four copies of THIS in step, because what has to agree is not a policy an
operator picks per tool -- it is where the request body ends, and every hop
on the socket computes that or the request is smuggleable. So it is one
function, in the library all four servers import.

What this file's own suite checks, precisely, so nobody credits it with
more: ``gui/test_console_auth.py`` pins that
``mint_console.framing_verdict IS aicash.mintapi.framing_verdict`` (not a
copy of it), that it is asked in exactly ONE place here, that no framing
header is looked up by name and no header value reaches ``int()`` any
more, and -- in ``TestTheMintAndTheConsoleAgreeOnIdenticalBytes`` -- it
drives the REAL mint and the REAL console with the same twenty-five
spellings. What that class asserts, stated exactly, because an earlier
version of this paragraph claimed more than it measures: on POST, the rule
refuses and BOTH servers refuse, each in its own vocabulary. On GET they do
NOT both refuse and are not asked to -- the rule reaches the identical
verdict on the identical bytes, and the mint then answers 200 and closes
(mintapi ``_close_if_body_goes_unread``) where this console answers 400.
"Identical framing decisions" is the property; "identical responses" is not,
and the two are different sentences. The GET rows assert the first: same
verdict, one response each, socket closed by each. It reaches two of the
four servers because those are the two it already starts; the other two are
driven from their own suites, and what makes the set coherent is the single
function all four call.

THE OTHER DEFECT CLASS THIS FILE WAS SWEPT FOR -- "it answers nothing at
all" -- HAS TWO MEMBERS, not one, and the second was open until 2026-09-17.
The first is an exception that kills the handler before anything is
written; ``parse_request``, the value guards in ``do_POST``,
``Console.timeout`` and ``handle_one_request``'s backstop close that one.
The second needs no exception: ``BaseHTTPRequestHandler`` makes every
status line and header a NO-OP while ``request_version`` is ``HTTP/0.9``,
so such a request got the composed body with nothing around it -- on every
route, and on the framing refusal itself, which is the original report's
own shape.

AND IT HAS TWO SPELLINGS, WHICH IS WHY IT WAS CLOSED TWICE. A two-word
request line is HTTP/0.9 BY OMISSION; a three-word one whose version token
is literally ``HTTP/0.9`` is HTTP/0.9 BY STATEMENT. The first fix here
counted the words in the request line, and the second spelling walked
straight past it: the stdlib CAN read that version, so it sets
``request_version`` from the wire, and every route went naked again.
Measured over raw sockets on 2026-09-17, on a console started the way an
operator starts it: the signed descriptor, the console page, the
unauthenticated 401 and the framing refusal all came back with no status
line at all, and ``POST /api/issue HTTP/0.9`` MINTED THE MONEY and returned
the bearer token as 82 naked octets. ``default_request_version``, the
version test in ``parse_request`` and ``send_error`` close all of it, and
all three are the mint's (aicash.mintapi._Handler), taken rather than
rewritten -- the mint had closed the second spelling days earlier, and this
file was the last one in the repository without it.

The suite could not see any of it, and that is the part worth remembering:
its 0.9 coverage was entirely the spelling that was already handled, so it
was GREEN OVER AN OPEN DOOR, which reads as coverage and is worse than no
coverage. The sweep class could not see it either, because every shape it
built said HTTP/1.1; it now builds both 0.9 spellings.

TWO MORE TRANSPORT HOLES CLOSED THE SAME DAY, both by taking the mint's
answer rather than writing one. ``Console.timeout`` is an IDLE bound: a
peer sending one octet every two seconds into the header block reset it
forever and held a thread and an fd past 76 seconds with nothing sent
back. ``request_timeout`` and ``_DeadlineRaw`` (imported from the mint, not
copied) put a wall-clock ceiling on one whole request, enforced BENEATH the
buffered reader, which is the only place that bounds the header phase as
well as the body. And a well-formed request preceded by one empty line --
what a client that ended its last body with a stray CRLF emits -- was
silently discarded, zero bytes back; RFC 7230 3.5 says tolerate at least
one, the mint does, and now so does ``parse_request``.

EVERY REMAINING SHAPE THAT ANSWERED NOTHING AT ALL WAS CLOSED ON
2026-09-17, after an independent sweep found that "at least one" and "the
stdlib refuses it" were still leaving peers with zero bytes:

  * TWO OR MORE leading empty lines in front of a well-formed
    authenticated request. One line of tolerance is a floor, not a
    ceiling, and the second line put the request straight back into the
    silent-discard path. ``MAX_LEADING_EMPTY_LINES`` steps over a bounded
    run and answers a framed 400 past it -- a cap, because an unbounded
    loop is a thread a CRLF trickle can hold.
  * A REQUEST LINE OF WHITESPACE (``"   \r\n"``, ``"\t\r\n"``). Not the
    empty line, so not re-read; the stdlib splits it, finds no words and
    returns False having written nothing. Closed generally rather than by
    naming the bytes: if ``super().parse_request()`` refused without a
    status line going out, this file answers 400.
  * THE REQUEST DEADLINE AND THE IDLE BOUND EXPIRING IN THE HEADER PHASE.
    The bound worked and the peer could not tell it from a crash: zero
    bytes at 29.5 seconds, then EOF. ``handle_one_request`` answers a
    framed 408 now -- HTTP's own status for "the client did not produce a
    request in time" -- on the socket it was about to drop anyway.
  * THE WRITE SIDE HAD NO BUDGET, only the idle timeout, which a reader
    that accepts one octet per timeout window re-arms forever.
    ``_DeadlineWrite`` is the read side's missing half; see that class for
    why "unreachable on the shipped console" was not a reason to leave it.

Two of those (the whitespace request line, and the run of empty lines past
one) are DIVERGENCES FROM THE MINT as of this round: aicash.mintapi
discards both in silence, measured on its own port the same day. That is
the opposite of what the paragraph below asks for and it is recorded, in
the tests and here, as work owed to impl/ rather than as a local rule with
a reason. The console is the one of the four an operator points a browser
at, it holds the issuing credential, and it is the one that shipped a
default that is now off.

gui/app.py closed the first member on 2026-09-15 and wrote down why -- the
information was twenty feet away in this repository, which is the pattern
this round exists to end, so it is recorded here rather than only fixed.

DO NOT "RESTORE" A LOCAL COPY. If the framing rule needs to change it
changes in impl/aicash/mintapi.py and all four servers move together; a
copy here is the defect, not the insurance. Sharing it costs nothing this
file cares about: ``framing_verdict`` carries NO status code and NO error
envelope, precisely because its callers speak three different error
vocabularies, so this console keeps its own (400 ``bad_framing``, its own
JSON envelope, connection closed) exactly as the mint keeps its §3.8
reasons and the GUI keeps its own.

The one thing it does cost, stated so the next reader is not surprised:
``aicash.mintapi`` imports ``aicash.signing``, which imports
``cryptography``, so this file now needs that package at import time where
before it needed only ``aicash.tokencodec``, which is stdlib-only. Nothing
is lost operationally -- a console with no mint to talk to has no purpose,
and the mint cannot start without ``cryptography`` either -- but the
console can no longer be imported on a machine that has only the stdlib.
The clean fix belongs to the library, not here: lift the framing rule into
a stdlib-only ``aicash.framing`` and re-export ``framing_verdict`` from
``aicash.mintapi``, so the import line in this file never changes. Reported
this round rather than done, because impl/ is not this file's to edit.

WHERE THE TWO ACTUALLY DIVERGE, for whoever unifies them (an earlier note
claimed gui/app.py answers a foreign Host with 421; it does not, and never
did — `grep -c 421 gui/app.py` is 0. Both tools answer 403. The real list):

  * error reason strings on the HOST gate: this file says "bad_host",
    gui/app.py says "not_loopback". The CROSS-SITE gate does not diverge —
    both tools answer it 403 "cross_site", and an earlier version of this
    row claimed gui/app.py says "not_authorized" there. It does not:
    `grep -n cross_site mint_console.py gui/app.py` shows the same string
    on both sides of that gate. gui/app.py's "not_authorized" is real but
    belongs to an unrelated gate — the 401 the MINT returns when it
    refuses the operator credential during an issue, which gui/app.py
    (app.py:1379) translates into its own 403 "not_authorized" naming
    mint-admin-keys.json. This file does not translate that case at all:
    POST /api/issue forwards the mint's status and body through unchanged.
    So it is a third difference, not the same one: unify the host-gate
    string, and decide separately whether the console should also name a
    refused operator credential instead of passing the mint's 401 along;
  * cookie names: "aicash_console" here, "aicash_gui_session" there —
    which is deliberate, so one tool's session is not the other's;
  * (open, and the next thing to share) "HAS A RESPONSE ALREADY BEGUN".
    This file answers it privately with ``_answered``, the
    ``send_response_only`` override and ``_last_resort``; gui/app.py
    carries its own equivalent for the same reason. It is not the framing
    rule, but it is the SECOND wire-level fact each server now answers on
    its own, and the shape that produced four framing rules was exactly
    this one. It is not shared this round for a reason that is about
    ownership and not about design: the natural home is a stdlib-only
    module under impl/aicash, alongside the framing rule, and impl/ is not
    this file's to edit. Reported rather than done, in the same paragraph
    as the ``aicash.framing`` split above, because whoever does one should
    do both. The HTTP/0.9 hole this round closed is what that fact looks
    like when two servers answer it separately: gui/app.py had closed it
    and this file had not.
  * (settled) gui/app.py used to compare secrets with hmac.compare_digest
    on str, which raises TypeError on non-ASCII input. It now has its own
    _secret_eq with the same encode-first contract as this file's, so both
    tools answer a non-ASCII credential with 401 instead of raising inside
    the gate. Neither file imports the other's; see DELIBERATE DUPLICATION.
  * (settled, and now shared rather than reconciled) REQUEST FRAMING used
    to be a divergence nobody had written down, because this file had no
    framing rule to diverge FROM. Both files now ask
    ``aicash.mintapi.framing_verdict`` and reach the same verdict on the
    same bytes; only the envelope around the refusal differs, which is the
    part that is meant to. See the framing section above before writing a
    local one.
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
import io
import json
import os
import re
import secrets
import sys
import threading
import time
import urllib.parse
from collections import OrderedDict, namedtuple
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "impl"))
from aicash.mintapi import MAX_REQUEST_SECONDS, framing_verdict
# Imported, underscore and all, rather than copied. ``_DeadlineRaw`` is the
# mint's whole-request deadline -- the only layer that bounds the HEADER
# phase as well as the body -- and the console needs exactly it, not
# something like it. A second implementation of "bound the whole request"
# is the local-copy shape the framing rule above already refuses in this
# file: two spellings of one transport rule, drifting apart in the dark.
# The leading underscore says the mint owns it and this file must not
# change its meaning; it does not say "write your own". See
# ``Console.setup``.
from aicash.mintapi import _DeadlineRaw
from aicash.tokencodec import (
    MAX_AMOUNT_MC, TokenError, format_token, ledger_key, new_secret,
)

COOKIE_NAME = "aicash_console"
# The largest request body this console will read. Every body it has a use
# for is tiny -- ``{"amount_mc": N, "count": N}`` and one token string -- so
# the number is not a measurement of anything here; it is the number the
# mint (mintapi.MAX_BODY_BYTES) and the GUI (gui/app.py MAX_BODY_BYTES)
# already use, and a third number would be one more thing to reconcile. The
# point is that a cap is CHECKED BEFORE ALLOCATING: `Content-Length:
# 4294967296` used to become `rfile.read(4294967296)`.
MAX_BODY_BYTES = 1 << 20
# Longest string POST /api/status will look up. A v3 token is about 100
# characters and a ledger key is 64; 1 KiB is slack, not a measurement.
MAX_QUERY_LEN = 1024
# A handful of open tabs / re-opens of the capability URL, no more. Bounded
# so that a stream of GET /?k=<key> cannot grow this process without limit.
MAX_SESSIONS = 32
# How many empty lines this console will step over before the request line.
# RFC 7230 3.5 says a server SHOULD ignore AT LEAST ONE, which is a floor and
# not a ceiling: tolerating exactly one left two leading CRLFs in front of a
# well-formed authenticated request getting zero bytes back and a dropped
# socket, which is the same uniform request loss the tolerance existed to
# remove. A cap rather than a loop, because an unbounded run is a handler
# thread an anonymous peer can hold with a CRLF trickle -- and past the cap
# the answer is a framed 400, not the silence that made this a defect in the
# first place. Eight is slack over the one or two a real client emits; it is
# not a measurement.
MAX_LEADING_EMPTY_LINES = 8
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
// The closed set of failures this page can NAME, keyed by the reason string
// the console itself put in the error envelope. Nothing is inferred from the
// status code alone beyond the 401 fallback below.
const HDR_WHY={
 mint_unreachable:'mint unreachable - it did not answer this console',
 no_admin_credential:'read-only: this console holds no operator credential',
 unauthorized:'not authorised',
 bad_host:'refused here: the Host header is not a loopback literal',
 cross_site:'refused here: cross-site request',
 not_found:'this console has no such route',
 bad_response:'the console answered something that is not JSON'};
async function refresh(){
 const r=await api('/api/descriptor');
 if(!r.ok){$('dot').className='dot off';
  // Say why, from the reason the server actually sent, and nothing else.
  // "mint unreachable" is reserved for the ONE case this console
  // determined it: its own proxy could not complete a request to the mint
  // (_mint()'s 502). A 403 out of this console's own Host/Origin gate, or
  // a 500 raised in this process, never reached the mint at all -- calling
  // either of those "mint unreachable" asserts a cause nothing here knows.
  // Anything unrecognised reads as undetermined, and says so.
  const why=(r.data&&r.data.error&&r.data.error.reason)||'';
  $('hdr').textContent=(r.status===401)?HDR_WHY.unauthorized:(HDR_WHY[why]||
   'descriptor unreadable - http '+r.status+(why?' '+why:'')+
   '; why is undetermined, and this console will not guess');
  return;}
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


def _bounded_int(value, low: int, high: int) -> bool:
    """Is ``value`` a caller-supplied integer that is really in range?

    THREE checks, and the middle one is the one that was missing.
    ``isinstance(True, int)`` is True in Python, so the old
    ``isinstance(amount, int) and amount > 0`` accepted
    ``{"amount_mc": true}``: it passed validation, reached
    ``format_token``, which refuses a bool by design, and TokenError came
    out of ``do_POST`` with no response on the wire at all -- AFTER the
    mint had already been asked to issue. A bool is not a number a caller
    typed; it is a number the language lends it.

    The upper bound is the other half. ``amount_mc`` had none, so
    ``{"amount_mc": 10000000000000000000000000000000}`` -- ordinary JSON,
    well inside the interpreter's digit limit, so it parsed -- was minted
    and THEN raised TokenError out of the handler on the way to being
    formatted. Bounding it here refuses the request before the mint is
    asked, which is the difference between a 400 and money that exists and
    can never be spent.
    """
    return (isinstance(value, int) and not isinstance(value, bool)
            and low <= value <= high)


def _mint_id_is_usable(mint_id) -> bool:
    """Can this console actually FORMAT a token for this mint id?

    Asked by CAUSING it, not by re-deriving the rule: tokencodec's own
    ``MINT_ID_RE`` is private, and a second copy of a validity rule in this
    file is the mistake the framing half of this round exists to undo. One
    throwaway ``format_token`` with a fixed amount and a fixed zero secret
    exercises the exact call POST /api/issue will make later.

    Why it is worth asking at STARTUP. ``--mint-id`` is operator-supplied
    and was never checked anywhere: an id with a colon, a space, an
    underscore, an empty one, or one over the length limit reaches
    ``format_token`` only AFTER ``/admin/issue`` has returned 200, so the
    console minted real money and then raised TokenError out of the handler
    with no response on the wire -- every single click, silently, with the
    secrets dying in the traceback. That is the same shape as the credential
    refusal in ``main()`` and it gets the same answer: refuse to start,
    rather than discover it at the first click of Issue.
    """
    try:
        format_token(mint_id, 1, b"\x00" * 32)
    except TokenError:
        return False
    return True


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


#: The four fields ``framing_verdict``'s contract pins, in order, as this
#: file holds them. A named shape of OUR OWN, not the library's type: the
#: contract says the rule returns "an object or tuple carrying at least
#: length, framed, must_close, reason" and leaves the concrete type to its
#: owner, so this file must not pin that type -- neither in its code nor,
#: which is the subtler half, in its tests.
_Framing = namedtuple("_Framing", "length framed must_close reason")


def _framing_fields(verdict):
    """The four contract fields, off whatever ``framing_verdict`` returns.

    AN ADAPTER, NOT A RULE. It decides nothing about framing; it unpacks an
    answer someone else computed, and every branch below reads the same
    four names in the same order. Compare ``framing_fields`` in gui/app.py,
    which is the same three-branch unpacker for the same reason: before
    this existed the two servers read one contract two different ways --
    the GUI through a tolerant adapter, this file by reaching for
    attributes on the object -- so a change to the library's return type
    would have broken one caller and not the other, and this file's tests
    pinned the object form, which quietly made "the return type is the
    owner's choice" untrue. It is duplicated here rather than imported
    because a console must not import the wallet-holding GUI to start; the
    thing that must not be duplicated is the RULE, and the rule is one
    function in one place.
    """
    if hasattr(verdict, "framed"):       # an object, dataclass or NamedTuple
        return _Framing(verdict.length, bool(verdict.framed),
                        bool(verdict.must_close), str(verdict.reason))
    if isinstance(verdict, dict):
        return _Framing(verdict["length"], bool(verdict["framed"]),
                        bool(verdict["must_close"]), str(verdict["reason"]))
    length, framed, must_close, reason = verdict   # a plain tuple, in order
    return _Framing(length, bool(framed), bool(must_close), str(reason))


#: EVERY METHOD WHOSE HANDLER IN THIS FILE READS A REQUEST BODY, and the
#: only input the shared framing rule takes from its caller.
#:
#: Not a guess about which HTTP methods MAY carry a body -- that guess is
#: what left the GUI's GET routes smuggleable. A fact about the dispatch
#: below: ``_read_json`` is called from ``do_POST`` and from nowhere else.
#: The rule uses it only to decide what an ABSENT Content-Length means. On
#: a body about to be read, "no Content-Length" is "no statement", which is
#: what every mangled or front-end-rewritten framing header degrades into;
#: on a method that reads nothing it is the ordinary case for every
#: conforming client and means zero octets.
#:
#: Spelled as a set next to the rule rather than inline as
#: ``self.command == "POST"`` because the inline form is silently wrong the
#: day someone adds a body-reading ``do_PUT``: that handler would be asked
#: about with ``body_expected=False``, so an absent Content-Length on it
#: would come back "framed, length 0" instead of unframable -- the one
#: clause the library calls THE clause that closes the class. The set is
#: checked against the actual ``do_*`` methods by
#: ``TestTheFramingRuleIsTheSharedOne``, so adding that handler without
#: adding it here fails a test instead of reopening the defect. (The other
#: three servers each derive this fact their own way; a shared derivation
#: would have to live in the library, which is not this file's to edit --
#: reported, not done.)
BODY_READING_METHODS = frozenset({"POST"})


class _NoticesTheBound(io.RawIOBase):
    """Remembers that a read hit a bound, because the stdlib forgets.

    ``BaseHTTPRequestHandler.handle_one_request`` reads the request line
    and the header block inside its own ``except socket.timeout`` clause,
    and that clause LOGS AND RETURNS: it sets ``close_connection`` and the
    peer gets nothing. So the ``TimeoutError`` ``_DeadlineRaw`` raises in
    the header phase never reaches this file's ``handle_one_request`` at
    all, and every attempt to answer it from there answered nothing --
    measured while writing this, 2026-09-17: five request shapes, five
    silences, against a handler that believed it was sending a 408.

    One flag, set on the way past, read after ``super().handle_one_request()``
    returns. Sitting BETWEEN ``io.BufferedReader`` and ``_DeadlineRaw``
    rather than replacing either: the mint owns the deadline and this file
    must not re-spell it (see the module docstring), and the buffered
    reader is what makes the deadline whole-request. This layer decides
    nothing -- it re-raises the identical exception -- it only leaves a
    note that a bound, and not a peer, ended the read.
    """

    def __init__(self, raw, handler):
        self._raw = raw
        self._handler = handler

    def readable(self) -> bool:
        return True

    def readinto(self, buf) -> int:
        try:
            return self._raw.readinto(buf)
        except TimeoutError:
            self._handler.timed_out = True
            raise


class _DeadlineWrite:
    """The handler's write side, under a wall-clock RESPONSE budget.

    THE OTHER HALF OF ``_DeadlineRaw``, and the half nobody had. That class
    is imported from the mint and bounds every READ of a request -- request
    line, headers and body -- against ``handler.request_deadline``. It
    restores the idle timeout on its way out, deliberately, so the write
    side is never left running on a sliver of the read budget; the
    consequence was that the write side ran on the IDLE timeout alone, and
    an idle timeout is re-armed by every write that makes progress. A
    reader that accepts one octet just inside ``timeout`` seconds, forever,
    held this handler forever. That is the same defect ``request_timeout``
    was added for, one direction over.

    It was not reachable on the shipped console -- no ``protocol_version``,
    so no keep-alive, and the largest single response is the console page
    at about 8 KB, which fits the kernel's send buffer and returns from
    ``sendall`` before any reader has read a byte. "Not reachable" is
    exactly how the naked framing refusal survived unnoticed in this file
    for a round, so it is bounded rather than written down, and the bound
    is the one the read side already uses: a wall clock, checked before
    every write, smaller of it and the idle timeout.

    ITS OWN DEADLINE AND NOT ``request_deadline``: a request that used most
    of its budget arriving must still be ANSWERED, and the answer a
    timed-out body gets is a 408 written after the read budget is gone (see
    ``_read_json``). Sharing one deadline would silence exactly the
    refusals this round added. The response budget is armed on the first
    write of each response and cleared with the request in
    ``handle_one_request``.

    Delegation rather than inheritance from ``io.BufferedIOBase``:
    socketserver's ``finish`` reads ``closed``, calls ``flush`` and calls
    ``close``, ``handle_one_request`` calls ``flush``, and nothing else in
    this file touches ``wfile``. Those four, explicitly, so a fifth
    attribute that appears in some future stdlib is an AttributeError in a
    test run rather than a silently unbounded path.
    """

    def __init__(self, wfile, sock, handler):
        self._wfile = wfile
        self._sock = sock
        self._handler = handler

    def write(self, data):
        budget = self._handler.response_budget()
        self._sock.settimeout(budget)
        try:
            return self._wfile.write(data)
        finally:
            # Symmetrical with ``_DeadlineRaw.readinto``: the socket goes
            # back to the plain idle bound, so no other caller inherits
            # whatever was left of this response's budget.
            self._sock.settimeout(self._handler.timeout)

    def flush(self):
        return self._wfile.flush()

    def close(self):
        return self._wfile.close()

    @property
    def closed(self):
        return self._wfile.closed


class Console(BaseHTTPRequestHandler):
    #: Whole-connection budget, in seconds. socketserver puts it on the
    #: socket, so every read in this handler can time out instead of
    #: blocking forever.
    #:
    #: Found by sweeping the "answers nothing at all" class rather than by
    #: re-reading the report: with no timeout, ``Content-Length: 500``
    #: followed by five octets and then silence parked a worker thread on
    #: ``rfile.read`` FOREVER. No response, no traceback, no log line, and
    #: a thread gone for good -- the quietest member of the family, and the
    #: only one that costs something on every repetition. A handful of such
    #: sockets is the console, permanently. Thirty seconds is enormous on
    #: loopback (the mint proxy's own budget is ten) and still finite.
    #:
    #: AND IT IS AN IDLE BOUND, WHICH IS NOT A BUDGET. socketserver puts it
    #: on the socket, so it is re-armed by every recv that returns a byte: a
    #: peer that sends ONE OCTET EVERY TWO SECONDS into the header block
    #: resets it forever. Measured on this console, 2026-09-17: an
    #: unauthenticated `GET /api/descriptor HTTP/1.1` followed by one `X`
    #: every two seconds held a daemon thread and a file descriptor for 76
    #: seconds with nothing sent back, and was still holding both when the
    #: measurement stopped. ThreadingHTTPServer caps neither, and the four
    #: gates above are no defence at all here -- the request never reaches
    #: them, because it never finishes arriving. ``request_timeout`` below
    #: is what ends it.
    timeout = 30

    #: Wall-clock ceiling on ONE WHOLE REQUEST, armed in
    #: ``handle_one_request`` and enforced by ``_DeadlineRaw`` beneath the
    #: buffered reader. The mint's number, from the mint's constant, because
    #: a console that outlived the mint it fronts would just move the drip
    #: one port over. A class attribute for the same reason ``timeout`` is:
    #: a test overrides it by subclassing, without reaching into module
    #: state.
    request_timeout = MAX_REQUEST_SECONDS

    #: Absolute monotonic instant this request must be read by; None
    #: between requests, when only the idle timeout applies.
    request_deadline = None

    #: True once a read on this request hit either bound. Set by
    #: ``_NoticesTheBound`` because the stdlib swallows the exception
    #: before ``handle_one_request`` below can see it; read there to decide
    #: whether the peer is owed a 408.
    timed_out = False

    #: Wall-clock ceiling on WRITING one whole response, enforced by
    #: ``_DeadlineWrite`` above. Same number as the read budget and for the
    #: same reason -- a console that let a slow reader outlive the mint it
    #: fronts would just move the drip one direction over -- but a separate
    #: deadline, because a request that spent its read budget must still be
    #: able to send the 408 that says so.
    response_timeout = MAX_REQUEST_SECONDS

    #: Absolute monotonic instant the response in flight must be written
    #: by; None until the first write of a response, and cleared with the
    #: request. Armed lazily so the clock starts when this console starts
    #: answering, not when the peer started asking.
    response_deadline = None

    #: WHAT THIS HANDLER ASSUMES A REQUEST LINE WITH NO VERSION ON IT IS,
    #: and the second way this file could answer with no status line at all.
    #:
    #: ``BaseHTTPRequestHandler`` makes ``send_response_only()``,
    #: ``send_header()`` and ``end_headers()`` NO-OPS while
    #: ``request_version == "HTTP/0.9"`` -- 0.9 has no status line and no
    #: headers -- so every answer this file composes for a two-word request
    #: line used to go out as a naked body: no status line, no
    #: Content-Length, no ``Connection: close``. That included the framing
    #: refusal itself, which is the original report verbatim: a refusal
    #: delivered in a form no intermediary can read as a refusal. Feeding
    #: those bytes to http.client raises BadStatusLine.
    #:
    #: The stdlib decides that BEFORE ``parse_request`` below can refuse
    #: anything -- ``POST /`` with no version, a one-word request line and a
    #: 431 header block are all answered from inside the base class -- so
    #: the only place to close it for every one of them is the default it
    #: reads. Raising the default does not make this server speak 0.9; it
    #: makes every ANSWER it sends a well-framed HTTP/1.x message, and
    #: ``parse_request`` then refuses the 0.9 request outright with a real
    #: 400. gui/app.py does the same, one layer higher, and wrote down the
    #: same reason; the console needs it one layer lower because the
    #: stdlib's own errors are the ones its sweep never saw.
    default_request_version = "HTTP/1.1"

    mint_port = 0
    mint_id = ""
    admin_token = None
    auth = None

    def setup(self):
        """Put the request deadline under the reader, not around it.

        socketserver has just made ``rfile = connection.makefile('rb',
        rbufsize)``. Swap in the SAME buffered reader over a
        deadline-checking raw layer, exactly as the mint does: every refill
        of the buffer -- ``readline`` over the request line and the header
        block, ``read(n)`` over the body -- comes back through
        ``_DeadlineRaw.readinto`` and re-checks the clock there.

        Wrapping the BufferedReader from ABOVE instead would set one
        timeout for one whole blocking read and bound nothing, which is the
        mistake the idle timeout already makes. The header phase is the
        half that matters here: ``_read_json``'s ``TimeoutError`` guard
        only ever sees a request that finished arriving.

        Closing the original only drops its socket refcount -- it does not
        close the fd -- so ``connection.close()`` stays honest.
        """
        super().setup()
        original = self.rfile
        self.rfile = io.BufferedReader(
            _NoticesTheBound(_DeadlineRaw(self.connection, self), self),
            io.DEFAULT_BUFFER_SIZE if self.rbufsize <= 0 else self.rbufsize,
        )
        original.close()
        # And the write side, which the mint's class deliberately does not
        # cover: see ``_DeadlineWrite``. Wrapping here rather than in
        # ``_send`` catches the stdlib's own writes too -- ``send_error``'s
        # 414 and 501, and every header block -- which is the same reason
        # the framing check lives in ``parse_request`` and not at the top
        # of ``do_GET``.
        self.wfile = _DeadlineWrite(self.wfile, self.connection, self)

    def response_budget(self) -> float:
        """Seconds the write in hand may take, arming the budget if needed.

        Raises ``TimeoutError`` -- what ``_DeadlineRaw`` raises, and what
        ``handle_one_request`` already answers 408 for -- when the response
        has run out of clock. The smaller of the idle bound and the budget
        remaining, so neither is weakened by the other.
        """
        if self.response_deadline is None:
            self.response_deadline = time.monotonic() + self.response_timeout
        left = self.response_deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("response deadline exceeded")
        idle = self.timeout
        return left if idle is None else min(idle, left)

    def log_message(self, *a):
        # Silence is load-bearing, not laziness: the default handler writes
        # the request line to stderr, and the request line of the capability
        # URL is the capability. Nothing in this file writes self.path, a
        # query string or a cookie anywhere.
        pass

    #: The framing verdict for the request now being answered, set by
    #: ``parse_request`` below. It is ``_framing_fields`` applied to what
    #: ``aicash.mintapi.framing_verdict`` returned, so this file holds the
    #: four fields that function's contract pins -- ``length``, ``framed``,
    #: ``must_close``, ``reason`` -- in a shape of its own, and never the
    #: library's concrete type, which belongs to the library.
    _framing = None
    #: True once a status line has gone out, so the last-resort handler
    #: below cannot write a second response on top of a first.
    _answered = False

    # ---------------- framing: one rule, shared, every method ----------

    def parse_request(self) -> bool:
        """Decide where this request's body ends, before anything reads it.

        THE FRAMING RULE IS NOT IN THIS FILE, deliberately; see the module
        docstring. ``framing_verdict`` lives in aicash.mintapi and the
        mint's two handlers and the operator GUI ask that same function.
        This method is only where the console ASKS.

        Why ``parse_request`` and not the top of ``do_GET``/``do_POST``:
        this is the one hook that every request passes through after the
        headers are parsed and before anything dispatches, so it covers the
        methods this file does not implement too. ``PUT /api/issue`` with a
        chunked body is answered 501 by the stdlib handler without any
        ``do_*`` of ours running at all, and the chunk octets it leaves
        behind are as unframed as a POST's. "Every request this server
        answers, of every method" has to be a place, not a habit, or the
        fifth route added here is born unframed the way this whole file
        was.

        Returning False is the stdlib's own "stop, do not dispatch" signal
        (``handle_one_request`` returns immediately), so the refusal below
        is the complete answer to that request.

        ``body_expected`` is the ONE caller fact the shared rule takes, and
        it is exactly "is this handler about to read a body": POST does
        (``_read_json``, on every route, before dispatch), and no other
        method this file implements ever does. Getting it right is what
        makes the rest free -- an absent Content-Length is "no body" for a
        GET and "no trustworthy length" for a POST, and a GET that DECLARES
        octets nobody will read comes back ``must_close`` without this file
        having to reason about it. There is no second clause here, and
        there must not be: a local "and also close when..." is a local
        framing rule with a different name.

        THE OTHER HALF OF THIS METHOD IS A VERSION CHECK, and it is here
        for the same reason the framing check is: it is the one hook every
        request passes through. A request line with two words is HTTP/0.9,
        which has no status line and no headers, and while
        ``request_version`` says so every ``send_response_only``,
        ``send_header`` and ``end_headers`` in this file is a NO-OP -- so
        every answer composed for such a request, the framing refusal
        included, went out as a naked body with no status line, no length
        and no ``Connection: close``. That is the reported defect verbatim,
        one protocol version over, and the sweep class could not see it
        because every shape it builds says HTTP/1.1. ``default_request_version``
        above makes the stdlib's OWN errors well framed; this refuses the
        request itself, in HTTP/1.1, with a length, and hangs up.

        EVERYTHING THAT CHANGES IF SOMEONE SETS ``protocol_version``, in one
        paragraph, because nothing here may quietly depend on its absence:

          * That the console survives an unclosed poisoned stream today is
            an ACCIDENT. It never sets ``protocol_version``, so it answers
            HTTP/1.0, ``BaseHTTPRequestHandler`` leaves ``close_connection``
            True on every request, and keep-alive is never granted at all --
            which is why the smuggled second request the mint's tests fire
            never got answered here even before this round. Nothing in this
            file decided that, and obeying ``must_close`` does not depend on
            it: every response goes through ``_send``, which SAYS
            ``Connection: close`` whenever this handler is about to hang up,
            and the page route goes through it too (it did not, and was the
            one 200 that can carry ``must_close`` -- a GET that declares
            octets nobody will read).
          * ``handle_expect_100`` becomes reachable, and it sends a bare
            100 Continue through ``send_response_only``. That used to set
            ``_answered``, after which ``_last_resort`` would suppress its
            own 500 and a failing request would get silence again -- this
            file's own defect class, re-entering through the fix for it.
            Closed rather than written down: 1xx does not set the flag. See
            that override.
        """
        self._framing = None
        skipped = 0
        while self.raw_requestline in (b"\r\n", b"\n", b"\r"):
            # RFC 7230 3.5: a server SHOULD ignore at least one empty line
            # received before the request line. The stdlib does not: an
            # empty request line makes ``words`` empty and
            # ``parse_request`` return False with NOTHING WRITTEN and the
            # socket closed, so
            # ``\r\nGET /api/descriptor HTTP/1.1\r\nHost: ...\r\n\r\n``
            # -- a perfectly well-formed authenticated request with one
            # stray CRLF in front of it, which is exactly what a client
            # that terminated its last body with an extra CRLF emits -- was
            # SILENTLY DISCARDED. Measured on this console, 2026-09-17:
            # zero bytes back, socket dropped. That is the "no answer at
            # all" class one door over from the naked-body one.
            #
            # A BOUNDED RUN, NOT ONE LINE, and not an unbounded loop
            # either. "At least one" is the floor the RFC sets, not a
            # ceiling, and one line alone left the shape one octet over
            # STILL SILENT: two leading empty lines in front of a
            # well-formed authenticated request came back with zero bytes
            # and the socket dropped (measured here 2026-09-17, and on the
            # mint's own port, identically). That is the same uniform
            # request loss the single-line tolerance was added to remove,
            # so the run is tolerated to ``MAX_LEADING_EMPTY_LINES`` and
            # the request behind it is answered.
            #
            # The cap is what keeps this from becoming a thread an
            # anonymous peer can hold with a CRLF trickle, and past the cap
            # the peer gets a FRAMED 400 rather than the silence an
            # unbounded loop's victim used to get. ``request_timeout``
            # bounds the whole request underneath it as well; two bounds,
            # because a budget that ends a drip is not a reason to let one
            # start.
            if skipped >= MAX_LEADING_EMPTY_LINES:
                self._refuse_leading_empty_lines()
                return False
            skipped += 1
            self.raw_requestline = self.rfile.readline(65537)
            if len(self.raw_requestline) > 65536:
                # ``handle_one_request``'s own guard, repeated because this
                # read is ours. ``_name_the_unparsed_request`` is what sets
                # the three fields ``send_error`` and the log read before
                # any of them is read -- the stdlib blanks
                # ``request_version`` here and this file cannot, because a
                # blank one is not ``HTTP/1.1`` and the status line would
                # go out as a no-op.
                self._name_the_unparsed_request()
                self.send_error(414)
                return False
            if not self.raw_requestline:
                # EOF after the empty line, so the peer is done sending.
                # It is still owed an answer: it addressed this console,
                # this console read octets off the socket, and the write
                # half is still open. Answering 400 here rather than
                # dropping the socket is the same rule as everywhere else
                # in this file -- no request shape leaves with no answer at
                # all -- and if the peer has gone, ``_send`` raises OSError
                # into ``handle_one_request``, which is where a dead socket
                # is already handled.
                self._refuse_empty_request_line()
                return False
        # BEFORE the base class parses, because the base class ANSWERS some
        # request lines itself (`POST /` with no version, a one-word line)
        # and those answers are the naked ones. Reading the raw line is the
        # only way to know afterwards what shape it was.
        zero_nine = len(self.raw_requestline.split()) == 2
        if not super().parse_request():
            # Malformed request line, unsupported version, too many or too
            # long headers: the stdlib has already sent its own error --
            # with a status line on it now, which is what
            # ``default_request_version`` and ``send_error`` below are for.
            #
            # EXCEPT FOR ONE SHAPE, WHICH IT REFUSES IN SILENCE. A request
            # line of nothing but whitespace -- ``"   \r\n"``, ``"\t\r\n"``
            # -- is not the empty line, so it is not re-read above; the
            # stdlib splits it, gets NO WORDS, and returns False having
            # written nothing at all. Measured here and on the mint,
            # 2026-09-17: zero bytes back on both. That is the last member
            # of the "no answer at all" family this file was swept for, and
            # it is closed the general way rather than by naming those two
            # byte strings: if the stdlib refused without answering, THIS
            # file answers. ``_answered`` is set by ``send_response_only``,
            # so it is exactly "a status line has gone out", and the
            # stdlib's own refusals (400, 414, 431, 505) all set it on
            # their way past.
            #
            # DELIBERATE DIVERGENCE FROM THE MINT, recorded rather than
            # hidden: aicash.mintapi discards these bytes in silence today,
            # so this console now answers a shape the mint does not. The
            # rule belongs in the library with the rest of them -- see the
            # module docstring on where transport rules live -- and impl/
            # is not this file's to edit this round. Reported, with the
            # test that pins it here pointing at the same sentence.
            if not self._answered:
                self._refuse_bad_request_line()
            return False
        if zero_nine or self.request_version == "HTTP/0.9":
            # ``request_version`` is the test that matters and the word
            # count is NOT a substitute for it: a THREE-word request line
            # whose version token is literally ``HTTP/0.9`` is one the
            # stdlib CAN read, so ``super().parse_request()`` above returns
            # True with ``request_version == "HTTP/0.9"`` SET FROM THE
            # WIRE -- and every answer composed after that goes out naked
            # again, because ``send_response_only``, ``send_header`` and
            # ``end_headers`` are no-ops in 0.9. ``default_request_version``
            # cannot help there (it is consulted only when the stdlib
            # CANNOT read a version) and neither can ``send_error``, which
            # guards its own path only.
            #
            # Measured on this console before this line existed, over raw
            # sockets, 2026-09-17: the signed descriptor, the console page,
            # the unauthenticated refusal, the framing refusal and the
            # bad-target refusal all came back with NO STATUS LINE -- and
            # ``POST /api/issue HTTP/0.9`` MINTED THE MONEY and handed the
            # bearer token back as 82 naked octets. The word count walked
            # straight past all of it.
            #
            # Nor is the version test a substitute for the word count: with
            # ``default_request_version = "HTTP/1.1"`` a two-word line
            # lands on ``request_version == "HTTP/1.1"`` and would sail
            # past a version check alone. BOTH, or one of the two 0.9
            # spellings is served.
            #
            # Forcing the field to HTTP/1.1 before answering is what makes
            # THIS refusal itself framed. All three pieces are the mint's
            # (aicash.mintapi._Handler.parse_request), in the mint's order,
            # for the reason the mint wrote down; nothing new is invented
            # here.
            self.request_version = "HTTP/1.1"
            self._refuse_bad_version()
            return False
        try:
            urllib.parse.urlsplit(self.path)
        except ValueError:
            # Found by sweeping the "answers nothing at all" class across
            # the rest of this file rather than by re-reading the report,
            # and it is the same shape one field over: `_route()` splits
            # `self.path` with no guard, and urlsplit RAISES on an
            # unparseable authority. `GET http://[ HTTP/1.1` is
            # absolute-form, which RFC 7230 5.3.2 says a server must
            # accept, with a malformed IPv6 host -- ValueError straight out
            # of do_GET, before any gate, so the console sent nothing and
            # printed a traceback. Refused here, once, for every method, so
            # `_route()` is total by construction rather than by three
            # callers each remembering to wrap it.
            self._refuse_bad_target()
            return False
        verdict = _framing_fields(framing_verdict(
            self.headers,
            body_expected=self.command in BODY_READING_METHODS))
        self._framing = verdict
        if not verdict.framed:
            self._refuse_unframable(verdict)
            return False
        if verdict.must_close:
            self.close_connection = True
        return True

    def _refuse_bad_version(self) -> None:
        """400 on either spelling of HTTP/0.9.

        BY OMISSION (a two-word request line) and BY STATEMENT (a
        three-word one whose version token is ``HTTP/0.9``). Both have no
        status line and no headers, both make every header-composing call
        in this file a no-op, and a check that catches only one of them
        leaves the other serving naked bodies on every route.

        Answered in HTTP/1.1 -- ``default_request_version`` -- so the
        refusal has a status line, a length and a ``Connection: close`` on
        it. Nothing that speaks to this console speaks 0.9 (it is a page, a
        browser and curl), and a tool that holds a mint's operator
        credential must not answer in a protocol whose answers cannot be
        told from trailing octets. gui/app.py refuses the same shape with
        the same reason word.
        """
        self.close_connection = True
        self._send(400, {"error": {
            "reason": "bad_version",
            "detail": "this console answers HTTP/1.0 and HTTP/1.1. A "
                      "request line that names HTTP/0.9, and a request "
                      "line that names no version at all (which is "
                      "HTTP/0.9), both describe a protocol with no status "
                      "line, no headers and no way to state how long an "
                      "answer is -- so there is no honest way to answer "
                      "one here. Send the same request as HTTP/1.1."}})

    def _name_the_unparsed_request(self) -> None:
        """The three fields every response path reads, before any of them.

        ``send_response`` reaches ``log_request`` (which interpolates
        ``self.requestline``) and ``send_response_only`` (which reads
        ``self.request_version``), and NEITHER IS SET until
        ``super().parse_request()`` has run. Answering before that point --
        which the two refusals above do, deliberately, because the request
        line never arrived -- therefore raised AttributeError out of the
        error path, which ``handle_one_request``'s backstop then tried to
        answer through the same three fields and raised again: a traceback
        on stderr and ZERO BYTES to the peer. The silent-discard defect,
        re-entering through its own fix, which is why this is a method and
        not three lines copied into two callers.

        ``HTTP/1.1`` and not the empty string: ``send_response_only`` makes
        the status line a NO-OP while ``request_version`` is ``HTTP/0.9``,
        and the class default is exactly that. Same reason
        ``default_request_version`` is set at the top of this class.
        """
        self.requestline = ""
        self.request_version = "HTTP/1.1"
        self.command = ""

    def _refuse_bad_request_line(self) -> None:
        """400 on a request line the stdlib refused without answering.

        One shape reaches this today: a request line of nothing but
        whitespace. ``"   \\r\\n"`` is not the empty line, so the tolerance
        above does not re-read it; the stdlib splits it, gets no words, and
        returns False from ``parse_request`` HAVING WRITTEN NOTHING. Zero
        bytes back and a dropped socket -- the last member of the family
        this round exists to close, and the reason this is a general
        backstop on "refused without answering" rather than a test for two
        byte strings: the next stdlib version that adds a silent False
        lands here instead of reopening the defect.

        The detail never quotes the request line. On the page route the
        request line carries the capability key, and this method is
        reachable for any shape at all -- same rule as ``_refuse_bad_target``
        and the 401 branches.
        """
        self.close_connection = True
        self._send(400, {"error": {
            "reason": "bad_request_line",
            "detail": "this console could not read a method, a target and "
                      "a version off that request line"}})

    def _refuse_empty_request_line(self) -> None:
        """400 when the peer sent empty lines and then stopped.

        The read half is at EOF, so no request is coming; the WRITE half is
        still open, and a peer that addressed this console and sent octets
        to it gets an answer rather than a dropped socket. That is this
        file's rule, and "there was nothing worth answering" was the
        reasoning behind every silence this round removed.

        If the peer really has gone, ``_send`` raises OSError and
        ``handle_one_request`` absorbs it -- the one place in this file
        that already knows a socket can be dead.
        """
        self._name_the_unparsed_request()
        self.close_connection = True
        self._send(400, {"error": {
            "reason": "empty_request_line",
            "detail": "the connection ended after an empty line with no "
                      "request line on it"}})

    def _refuse_leading_empty_lines(self) -> None:
        """400 on a run of empty lines past ``MAX_LEADING_EMPTY_LINES``.

        The cap is the thing that keeps the tolerance from being a loop an
        anonymous peer can hold a thread with. Answering here rather than
        falling through to the stdlib's silent False is the difference
        between a bound and a defect: the peer is told the run was too
        long, with a length on the answer, and the socket goes.
        """
        self._name_the_unparsed_request()
        self.close_connection = True
        self._send(400, {"error": {
            "reason": "too_many_empty_lines",
            "detail": "this console steps over at most %d empty lines "
                      "before a request line" % MAX_LEADING_EMPTY_LINES}})

    def _refuse_bad_target(self) -> None:
        """400 on a request target this server cannot even split.

        The detail never quotes the target: on the page route the target
        carries the capability key, and a 400 body is the cheapest place to
        hand it back to whatever can read the response. Same rule as the
        401 branches -- see ``_deny_no_session``.
        """
        self.close_connection = True
        self._send(400, {"error": {
            "reason": "bad_request_target",
            "detail": "this console could not parse the request target"}})

    def _refuse_unframable(self, verdict) -> None:
        """400 and hang up on a request whose body cannot be located.

        Its own envelope, and deliberately not ``_deny``'s: ``_deny``
        serves DENIED_PAGE on the page route, whose whole text is about
        authorisation, and this is not an authorisation decision. It is
        also answered the same way on every route including GET /, because
        a client that sent an unframable request is not a browser that
        mistyped a URL.

        ``verdict.reason`` is the library's machine word for WHY the body
        could not be located; it is passed through as ``framing`` rather
        than being remapped, so a reader can match it against the mint's
        and the GUI's logs for the same request. No status code and no
        envelope comes from the library -- that is this file's, exactly as
        the contract says.

        THE ONLY PLACE THIS FILE BUILDS A ``bad_framing`` BODY. ``_read_json``
        used to build a second one for the same condition, without the
        ``framing`` field, guarded by a comment saying it was unreachable --
        and it is unreachable, which is exactly why nothing would have
        noticed that the console answered one condition with two different
        bodies. Two spellings of one refusal in one file is the local-copy
        shape at envelope scale, so there is one, and the backstop calls it.
        ``verdict`` may be ``None`` there (that is what the backstop is
        checking for), so the reason word is read defensively; ``no_verdict``
        is deliberately NOT one of the library's ``FRAMING_REASONS``, so a
        reader who ever sees it knows it came from this file's backstop and
        not from the rule.
        """
        self.close_connection = True
        self._send(400, {"error": {
            "reason": "bad_framing",
            "framing": getattr(verdict, "reason", None) or "no_verdict",
            "detail": "this console could not determine where this "
                      "request's body ends, so it did not read one and did "
                      "not answer the route. Send a single, plain "
                      "Content-Length of decimal digits and no transfer "
                      "coding."}})

    def send_error(self, code, message=None, explain=None):
        """The stdlib's own failures, with a status line on them.

        ``default_request_version`` covers every request line the stdlib
        cannot read a version off. It does not cover the one it CAN:
        ``GET / HTTP/0.9`` is three words and a version the stdlib parses,
        so ``request_version`` is set from the wire inside
        ``super().parse_request()`` BEFORE the header block is read -- and
        an over-long header block on that request is answered by the stdlib
        itself, from inside ``parse_request``, with every header call a
        no-op. Measured here 2026-09-17: ``GET / HTTP/0.9`` plus two
        hundred header lines came back as 333 octets of the stdlib's HTML
        error page with NO STATUS LINE, no length and no close, while the
        same request in HTTP/1.1 got a framed 431.

        ``parse_request`` below cannot close that one -- the stdlib answers
        and returns False before our check runs -- so the version is forced
        here too. This is the mint's ``send_error`` override
        (aicash.mintapi._Handler.send_error) with its JSON envelope left
        out: the envelope is the mint's transport vocabulary, and this
        console's stdlib-level errors have always been the stdlib's page.
        What is taken is the half that matters -- nothing leaves here in a
        protocol with no way to say how long it is.

        Written to be safe on a handler where ``request_version`` does not
        exist yet: an AttributeError inside an error path is a request
        answered with nothing at all, which is the class this whole round
        is about.
        """
        if getattr(self, "request_version", "HTTP/0.9") == "HTTP/0.9":
            self.request_version = "HTTP/1.1"
        super().send_error(code, message, explain)

    def handle_one_request(self):
        """No request ever leaves this server with no answer at all.

        The finding this exists against: ``int(self.headers.get(
        "Content-Length") or 0)`` on a five-thousand-digit length raised
        ValueError out of ``do_POST``, socketserver's ``handle_error``
        printed a traceback, and the client got ZERO bytes -- no status
        line, socket dropped. An operator got a stack trace and a caller
        got silence, which is strictly worse than the 500 the mint used to
        answer for the same input: a 500 is an answer you can act on.

        ``parse_request`` above now removes the whole framing family before
        dispatch, and the value checks in ``do_POST`` remove the ones that
        were reached through the body. This is the backstop for the ones
        nobody has found yet, and it is a backstop and not a licence: an
        exception reaching here is a bug in this file, and the 500 says so
        rather than pretending the request was refused on its merits.

        What it does NOT claim is that nothing happened. POST /api/issue
        asks the mint to create money and then formats tokens locally, so
        an exception on the second half is money that exists and is
        unrecoverable; a 500 body asserting "nothing changed" would be a
        sentence this process cannot know to be true. It names the
        exception class, like ``_mint`` does, and says the console cannot
        tell -- the same honesty rule the rest of this file is written to.
        """
        self._answered = False
        self.timed_out = False
        # Arm the wall-clock deadline for this request. Keep-alive idle time
        # BETWEEN requests stays covered by ``timeout`` alone, which is the
        # shorter of the two, so nothing legitimate is cut short by arming
        # here. ``_DeadlineRaw`` reads it on every refill.
        self.request_deadline = time.monotonic() + self.request_timeout
        try:
            super().handle_one_request()
        except TimeoutError:
            # A bound that the stdlib did NOT swallow -- today that is the
            # write side (``_DeadlineWrite``), which arrives here with a
            # status line already on the wire. ``timed_out`` is set so the
            # answer below runs exactly one check, and ``_answered`` is
            # what stops a second response going out on top of a first.
            self.timed_out = True
            self.close_connection = True
        except OSError:
            # A reset peer, a broken pipe: the socket is gone, so there is
            # nowhere to answer. Not an error of ours.
            self.close_connection = True
        except Exception as exc:               # noqa: BLE001 -- see above
            self._last_resort(exc)
        finally:
            # THE DEADLINE, OR THE IDLE BOUND, EXPIRING BEFORE THE REQUEST
            # LINE OR INSIDE THE HEADER BLOCK -- and it is ANSWERED now.
            #
            # It used to end in silence, on the reasoning that "a request
            # that never finished arriving has no route and no framing".
            # That is true and it is not a reason to send nothing: measured
            # 2026-09-17, a peer that opened a connection and went quiet, a
            # peer that sent ``\r\n`` and went quiet, a peer that sent half
            # a request line and went quiet each got ZERO BYTES at 29.5
            # seconds and then EOF. The bound worked and the peer could not
            # tell it from a crash, a firewall or a hang. 408 is HTTP's own
            # status for this exact case, it is framed like everything else
            # this file sends, and it costs one write on a socket the
            # handler is closing anyway.
            #
            # AFTER ``super()`` RATHER THAN AROUND IT, and that is not a
            # style choice: ``BaseHTTPRequestHandler.handle_one_request``
            # reads the request line and the header block inside its own
            # ``except socket.timeout``, which logs, sets
            # ``close_connection`` and RETURNS -- so the exception never
            # propagates here at all. ``_NoticesTheBound`` leaves the flag
            # on its way past instead. An ``except`` clause here looked
            # right and sent nothing.
            #
            # ``_answered`` is the guard: the body phase answers its own
            # 408 in ``_read_json`` and a write-side timeout has a status
            # line out already, and a second response is the desync
            # everything in this file exists to prevent.
            if self.timed_out and not self._answered:
                self.close_connection = True
                # The request may have stopped arriving BEFORE the stdlib
                # set ``requestline``, ``command`` and ``request_version``
                # at all -- a connection that said nothing, or an empty
                # line and then silence. ``send_response`` reads all three
                # on its way out, so answering without them raised
                # AttributeError inside the answer and the peer got the
                # silence again. Measured while writing this: four of the
                # five shapes below, answered by a handler that believed it
                # had sent a 408.
                self._name_the_unparsed_request()
                try:
                    self._send(408, {"error": {
                        "reason": "request_timeout",
                        "detail": "the request did not arrive in time: "
                                  "this console allows %gs between reads "
                                  "and %gs for one whole request"
                                  % (self.timeout or 0,
                                     self.request_timeout)}})
                except OSError:
                    # The peer really has gone. Nothing to answer to.
                    pass
            self.request_deadline = None
            self.response_deadline = None

    def _last_resort(self, exc) -> None:
        self.close_connection = True
        if self._answered:
            # A status line is already on the wire; a second response would
            # be exactly the desync everything above exists to prevent.
            return
        try:
            self._send(500, {"error": {
                "reason": "internal_error",
                "detail": "the console failed while handling this request "
                          "(%s). It cannot say whether the mint was asked "
                          "to do anything before the failure; check the "
                          "mint's own state before retrying."
                          % type(exc).__name__}})
        except OSError:
            pass

    def send_response_only(self, code, message=None):
        # Every response in this file goes through the stdlib here --
        # `_send`, `_deny`, the page, and BaseHTTPRequestHandler's own
        # `send_error` for 501/414 -- so this is the one place that can
        # know an answer has begun. `_last_resort` reads it.
        #
        # AN INTERIM STATUS IS NOT AN ANSWER. `handle_expect_100` sends a
        # bare 100 Continue through here, and counting that as "a response
        # has begun" is how the backstop below came to be suppressible: a
        # genuine failure on that same request would then be answered with
        # SILENCE again -- the exact class this file was swept for -- while
        # HTTP allows any number of 1xx before the one final response. So
        # 1xx does not set it. That is a real fix rather than a note: the
        # branch is unreachable today (`parse_request` honours
        # `Expect: 100-continue` only when `protocol_version >= HTTP/1.1`,
        # and this class leaves it at HTTP/1.0), and "unreachable" was
        # already how a second framing envelope came to survive unnoticed
        # in this same file. One line, on the day someone sets
        # `protocol_version`, otherwise breaks two things instead of one.
        #
        # `request_version` is NOT what gates this file's status lines any
        # more: `default_request_version` is HTTP/1.1, so the base class
        # emits one even for a request line that carried no version. That
        # is the second way a response here could have had no status line,
        # and it was open on every route until this round.
        if not 100 <= code < 200:
            self._answered = True
        super().send_response_only(code, message)

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

        TWO Host headers is refused as well, for the reason the shared
        framing rule refuses two Content-Lengths: a header a request states
        twice is a header two hops may resolve differently, and this one
        decides whether the request reaches a live mint with an operator
        credential on it. `.get()` reads the FIRST, so
        `Host: 127.0.0.1:<port>` followed by `Host: evil.example` passed
        this gate while an intermediary that reads the last one thinks it
        forwarded a request to evil.example. Loopback-only, so it is a
        small hole; it is also one line to close and the same class as the
        rule this round exists to share.
        """
        stated = self.headers.get_all("Host") or []
        if len(stated) != 1:
            return False
        host = stated[0]
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

    def _send(self, code, obj, ctype="application/json", extra=()):
        """THE one place this file writes a response.

        ``extra`` is for headers only one route has (the page's
        ``Set-Cookie`` and ``Cache-Control``). It exists so that route can
        come through here instead of composing its own 200 with
        send_response/send_header/end_headers, which is what it used to do
        -- and that made it the ONE response path that never read
        ``self.close_connection``, on the one 200 that can be required to
        close: a GET that is framed but declares octets nobody will read
        (``declared_body_unread``). Every other path announced the hang-up
        and the route a browser actually loads did not.
        """
        payload = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        for name, value in extra:
            self.send_header(name, value)
        if self.close_connection:
            # SAY it, do not merely do it. Every caller that decides to hang
            # up -- the framing refusal, the body cap, the timeout, the
            # short read, every `_deny` -- has already set close_connection
            # by the time it gets here, and each of those is a request whose
            # remaining octets this server did not read. Dropping the socket
            # silently is enough for a peer that is talking to us directly,
            # and it is NOT enough for anything in between: the original
            # report against the mint turned on a 400 answered WITHOUT
            # Connection: close, after which the unread octets were framed
            # as the next request line. The console is loopback-only and
            # answers HTTP/1.0, where close is already the default, so this
            # header changes nothing today -- which is exactly when it is
            # cheap to add, and it stops being free the day someone sets
            # protocol_version.
            self.send_header("Connection", "close")
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
        if admin:
            if not self.admin_token:
                # A missing credential is refused HERE. The old spelling was
                # `if admin and self.admin_token`, which sent the admin
                # request with no header at all and left the mint to decide
                # how generous to be about it — and the mint's answer used to
                # be "allow everyone". That is defect (3) in this file's
                # docstring, seen from the calling side.
                #
                # The reason string is picked with care: the mint did not
                # reject this request, because the mint never saw it. Saying
                # "the mint refused" here would be asserting a cause this
                # process cannot know.
                return 503, {"error": {
                    "reason": "no_admin_credential",
                    "detail": "this console holds no operator credential, so "
                              "it did not send the issuance request. The mint "
                              "never saw it and did not refuse it. Restart "
                              "the console with --admin-token-file pointed at "
                              "the file run_mint.py wrote, or with "
                              "--admin-token. (A mint started deliberately "
                              "open — run_mint.py --open-issuance, i.e. "
                              "ADMIN_ISSUANCE_OPEN — hands this console no "
                              "credential either; issue against the mint's "
                              "own port, not through here.)"}}
            headers["X-Admin-Token"] = self.admin_token
        c = None
        try:
            c = http.client.HTTPConnection("127.0.0.1", self.mint_port,
                                           timeout=10)
            c.request(method, path,
                      json.dumps(body) if body is not None else None, headers)
            r = c.getresponse()
            # Bounded and RecursionError-caught for the same two reasons
            # everything the network hands this file is: whatever is
            # listening on the mint port is not necessarily the mint, and
            # `read()` with no argument plus a json parser with no depth
            # limit is an unbounded allocation and a stack overflow reached
            # from another process. Over the cap the parse fails and the
            # caller gets the same 502 as an unreachable mint, which is the
            # honest answer: the console did not get a usable reply.
            return r.status, json.loads(r.read(MAX_BODY_BYTES + 1) or b"{}")
        except (OSError, ValueError, RecursionError,
                http.client.HTTPException) as exc:
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

    # ---------------- request body ----------------

    def _read_json(self):
        """Returns (object, True), or answers the caller and returns
        (None, False). Never raises, and never answers with nothing.

        The line this replaced was::

            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(n) or b"{}")

        and every part of it was a way to lose the request:

        * ``int()`` is a LOOSER parser than HTTP's, and an unguarded one.
          Of sixteen values measured against the pre-round file, EIGHT took
          the handler out with no response at all -- ``abc``, ``3 2``,
          ``2, 32``, ``0x20``, ``32.0`` and fullwidth ``３２``
          (ValueError), twenty digits (OverflowError inside ``read``), five
          thousand digits (the interpreter's int/str conversion limit,
          which is the shape the outside reviewer reported against the
          mint). FOUR more were read as a body a strict hop reads
          differently: ``+32`` and ``3_2`` (int() accepts a sign and PEP
          515 separators), ``32\x0b`` and ``32\xa0`` (Python's whitespace
          set is wider than HTTP's OWS). ``-1`` pinned a worker thread on
          ``read(-1)`` until the peer went away, and ``-32`` answered
          "bad_json" for a request whose JSON was fine.
        * no length was computed by anything that had looked at
          ``Transfer-Encoding``, under any spelling, so a chunked POST read
          as an empty one and the chunk octets stayed on the wire.
        * ``rfile.read(n)`` allocated whatever the caller asked for, so
          ``Content-Length: 4294967296`` was a one-line memory request.

        None of that is decided here now. ``parse_request`` has already
        asked ``framing_verdict`` -- the shared rule -- and refused the
        request outright unless a length can be TRUSTED, so the number used
        below is that verdict's and nothing re-parses the header. What is
        left for this method is the part that is genuinely this console's:
        its cap, its short-read rule, and its own error envelope.
        """
        verdict = self._framing
        if verdict is None or verdict.length is None:
            # Unreachable: parse_request answers and stops dispatch for
            # exactly this case. Kept because "unreachable" is a claim
            # about another method, and the cost of being wrong about it is
            # reading a body off an unframed socket. It answers through
            # `_refuse_unframable` and NOT with an envelope of its own: the
            # day this fires, the body a caller gets and the word a log
            # correlates on must be the ones every other refusal uses, or
            # the only time it ever happens is the one time nothing
            # recognises it.
            self._refuse_unframable(verdict)
            return None, False
        length = verdict.length
        if length > MAX_BODY_BYTES:
            # Refused BEFORE allocating, which is the whole point: the old
            # reader trusted the header and called read() with it.
            self.close_connection = True
            self._send(413, {"error": {
                "reason": "body_too_large",
                "detail": "this console reads at most %d bytes of request "
                          "body; it did not read this one." % MAX_BODY_BYTES}})
            return None, False
        try:
            raw = self.rfile.read(length) if length else b""
        except TimeoutError:
            # The caller declared octets it never sent. Answerable, unlike a
            # reset, so it is answered -- the point of this whole round is
            # that a request does not get silence.
            #
            # EITHER bound can raise this now: ``timeout`` if the peer went
            # quiet, or the whole-request deadline (``_DeadlineRaw`` raises
            # ``TimeoutError`` too) if it kept dripping. The detail names
            # both rather than quoting the idle number alone, which was the
            # only bound when this line was written and stopped being the
            # only one the day the deadline arrived -- a message that says
            # "within 30s of the request" on a console whose budget has been
            # turned down is a sentence this process no longer knows to be
            # true.
            self.close_connection = True
            self._send(408, {"error": {
                "reason": "body_timeout",
                "detail": "the body did not arrive in time: this console "
                          "allows %gs between reads and %gs for one whole "
                          "request" % (self.timeout or 0,
                                       self.request_timeout)}})
            return None, False
        except OSError:
            # Reset peer or a dead socket mid-body. Nothing to answer to.
            self.close_connection = True
            return None, False
        if len(raw) != length:
            # Short read: the peer half-closed or died. The stream cannot
            # be framed any more, so it does not survive -- and a truncated
            # body must not be allowed to parse as a shorter valid one.
            self.close_connection = True
            self._send(400, {"error": {
                "reason": "short_body",
                "detail": "the body ended before the declared "
                          "Content-Length"}})
            return None, False
        try:
            body = json.loads(raw or b"{}")
        except (UnicodeDecodeError, ValueError, RecursionError):
            # json.loads says "no" in three ways and only ONE was caught.
            # ValueError is the documented one (JSONDecodeError, and the
            # bare ValueError CPython raises past its int/str digit limit,
            # so `{"amount_mc": <5000 digits>}` lands here). RecursionError
            # is the one that was not: `[[[[...` two hundred thousand deep
            # is a 200 KB body, well inside the cap, that blew the C
            # parser's stack and took the handler out with NO RESPONSE AT
            # ALL. All three are permanently bad bytes. The body was fully
            # read, so unlike the refusals above the stream is still framed.
            self._send(400, {"error": "bad_json"})
            return None, False
        if not isinstance(body, dict):
            self._send(400, {"error": "bad_json"})
            return None, False
        return body, True

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
            # Through `_send`, like every other response in this file, so
            # that a page load which must close SAYS so. See `_send`.
            extra = []
            if self.auth.enabled and not has_session:
                # Only on the key exchange. Minting a session on every page
                # load would let a browser sitting on the page evict its own
                # other tabs (MAX_SESSIONS of them) just by reloading.
                # HttpOnly: script cannot read it, so an XSS or a hostile
                # extension page cannot exfiltrate the session. Strict: the
                # browser withholds it on anything another site initiates.
                extra.append((
                    "Set-Cookie",
                    "%s=%s; HttpOnly; SameSite=Strict; Path=/"
                    % (COOKIE_NAME, self.auth.new_session())))
            extra.append(("Cache-Control", "no-store"))
            return self._send(200, payload, "text/html; charset=utf-8",
                              extra)

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

        body, ok = self._read_json()
        if not ok:
            return

        if route == "/api/issue":
            amount, count = body.get("amount_mc"), body.get("count", 1)
            # Bounded and bool-refused BEFORE the mint is asked. Both halves
            # were missing and both ended the same way -- TokenError out of
            # format_token, no response on the wire, and for `amount_mc`
            # that happened AFTER /admin/issue had already minted, so the
            # money existed and the only copy of its secret died with the
            # handler. MAX_AMOUNT_MC is tokencodec's own ceiling, imported
            # rather than restated so this check cannot drift below the one
            # format_token applies.
            if not _bounded_int(amount, 1, MAX_AMOUNT_MC):
                return self._send(400, {"error": "amount_mc must be a whole "
                                                 "number between 1 and %d "
                                                 "(true is not a number)"
                                                 % MAX_AMOUNT_MC})
            if not _bounded_int(count, 1, 100):
                return self._send(400, {"error": "count must be a whole "
                                                 "number between 1 and 100 "
                                                 "(true is not a number)"})
            secret_bytes = [new_secret() for _ in range(count)]
            outputs = [{"amount_mc": amount,
                        "secret": base64.urlsafe_b64encode(s).decode().rstrip("=")}
                       for s in secret_bytes]
            code, obj = self._mint("POST", "/admin/issue", {"outputs": outputs},
                                   admin=True)
            if code != 200:
                return self._send(code, obj)
            # The token string only exists here: the mint stores hashes, never
            # secrets, so an unshown token is unrecoverable money. Which is
            # why this is the one call in the file wrapped for its own sake:
            # the checks above make TokenError unreachable, and if it ever
            # became reachable again the operator must be TOLD that money was
            # minted and lost, not handed a dropped socket to interpret.
            try:
                tokens = [format_token(self.mint_id, amount, s)
                          for s in secret_bytes]
            except TokenError as exc:
                return self._send(500, {"error": {
                    "reason": "token_unformattable",
                    "detail": "the mint issued, but this console could not "
                              "format the token(s) (%s). That money exists "
                              "and its secrets are gone. Reconcile against "
                              "the mint's supply snapshot."
                              % type(exc).__name__}})
            return self._send(200, {"tokens": tokens})

        if route == "/api/status":
            q = body.get("q")
            if q is None:
                q = ""
            if not isinstance(q, str):
                # `(body.get("q") or "").strip()` called .strip() on
                # whatever the caller put there: `{"q": 5}`, `{"q": true}`
                # and `{"q": {}}` each raised AttributeError out of the
                # handler and answered NOTHING. A number is not a token.
                return self._send(400, {"error": "q must be a string"})
            if len(q) > MAX_QUERY_LEN:
                # The only two things this field can legitimately hold are
                # a token string and a ledger key, both around a hundred
                # characters. Bounded so a megabyte of it is not forwarded
                # to the mint as a hash to look up.
                return self._send(400, {"error": "q is too long to be a "
                                                 "token or a ledger key"})
            q = q.strip()
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
    if not _mint_id_is_usable(mint_id):
        # In serve() and not only in main(), because serve() is the one door
        # every console comes through -- run_mint.py starts one this way too
        # -- and a console that cannot format a token cannot do the only
        # thing it holds a credential for. ValueError here, ap.error() in
        # main(): one rule, each caller's own way of saying no.
        raise ValueError(
            "mint_id %r cannot appear in a token, so this console could "
            "issue money it is then unable to show anyone. Use the id the "
            "mint itself reports at GET /v3/mints." % (mint_id,))
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
    if announce and not admin_token:
        # Reachable through serve() from run_mint.py --open-issuance, which
        # is the one supported way to get here with no credential. Say it on
        # startup rather than at the first click of Issue.
        print("\n  CONSOLE  no operator credential was given, so this console"
              "\n  cannot issue: POST /api/issue answers 503"
              " no_admin_credential."
              "\n  Everything read-only (descriptor, status) still works.",
              file=out, flush=True)
    if announce:
        if state.enabled:
            # What a captured stdout is worth depends on what this console
            # can DO, and with no operator credential the answer is: read.
            # The key opens the page and the read-only routes; it cannot
            # reach issuance, because there is nothing here to issue with.
            # Saying "a minting credential" in that mode would overstate
            # the leak, which is the same class of error as understating
            # one: a sentence asserting more than the process knows.
            captured = ("that file now holds a minting credential"
                        "\n  — restart to rotate it.)"
                        if admin_token else
                        "that file now holds this console's"
                        "\n  session key. It opens a READ-ONLY console — no"
                        "\n  operator credential was given, so the key cannot"
                        "\n  reach issuance. Restart to rotate it.)")
            print("\n  CONSOLE  open this exact URL — it carries a one-time key:"
                  "\n\n      %s\n"
                  "\n  The plain http://127.0.0.1:%d/ answers 401. The key is"
                  "\n  held in memory only, is never written to a file or a log"
                  "\n  by this console, and dies with this process."
                  "\n  (If this process's stdout is captured to a file by a"
                  "\n  service manager, %s"
                  "\n  Auth does not make this safe to expose: keep it on"
                  "\n  loopback, do not proxy it, do not port-forward it."
                  % (httpd.console_url, bound, captured), file=out, flush=True)
        else:
            print("\n  CONSOLE  %s   (UNAUTHENTICATED)" % httpd.console_url,
                  file=out, flush=True)
    return httpd


#: Where run_mint.py writes the generated operator credential. Named
#: rather than inlined so the help text, the refusal messages and the
#: lookup cannot drift apart.
DEFAULT_ADMIN_TOKEN_FILE = "mint-admin-keys.json"


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Operator console for a running aicash mint. Loopback "
                    "only; prints a one-time capability URL on startup.")
    ap.add_argument("--port", type=int, default=8080,
                    help="console port; 0 picks an ephemeral one")
    ap.add_argument("--mint-port", type=int, default=8787,
                    help="port the mint is listening on")
    ap.add_argument("--mint-id", default="local-test-mint")
    # default=None so that "the operator asked for this file" and "nobody
    # said anything, so we looked in the usual place" are distinguishable
    # below. They have to be: --no-admin-token is an explicit request to hold
    # NO credential, and it used to be silently overridden by whatever
    # happened to be sitting in the default file.
    ap.add_argument("--admin-token-file", default=None,
                    help='JSON file with an "admin_token" field, as written '
                         "by run_mint.py (default: %s). Preferred: a token "
                         "passed on the command line is visible to every "
                         "process on the machine via /proc and ps."
                         % DEFAULT_ADMIN_TOKEN_FILE)
    ap.add_argument("--admin-token",
                    help="operator credential (visible in ps; prefer "
                         "--admin-token-file)")
    ap.add_argument("--no-admin-token", action="store_true",
                    help="start with NO operator credential: descriptor and "
                         "status still work and POST /api/issue answers 503. "
                         "Without this flag a console that found no "
                         "credential refuses to start, because an absent "
                         "credential must be something you asked for.")
    ap.add_argument("--no-auth", action="store_true",
                    help="FOR AUTOMATED TESTS ONLY: serve with no capability "
                         "key and no session cookie. Prints a loud warning.")
    args = ap.parse_args(argv)

    # --no-admin-token is an explicit instruction to hold no credential, so
    # pairing it with a credential is a contradiction, not a preference
    # order. It used to be neither: the flag was checked only AFTER the
    # lookup, so a console started with --no-admin-token on a machine where
    # the default mint-admin-keys.json existed came up holding a live
    # minting credential and said nothing about having ignored the flag.
    # An operator who asks for a read-only console and silently gets a
    # minting one is the same defect this round is about, pointing the other
    # way: the presence of a credential nobody asked for.
    if not _mint_id_is_usable(args.mint_id):
        ap.error("--mint-id %r cannot appear in a token string. This console "
                 "would mint successfully and then be unable to format what "
                 "it minted, which loses the money: the mint stores hashes, "
                 "never secrets, so a token that is never shown is gone. Use "
                 "the id the mint reports at GET /v3/mints."
                 % (args.mint_id,))
    if args.no_admin_token and args.admin_token is not None:
        ap.error("--admin-token with --no-admin-token is contradictory: one "
                 "supplies an operator credential and the other says to run "
                 "without one. Pick one.")
    if args.no_admin_token and args.admin_token_file is not None:
        ap.error("--admin-token-file with --no-admin-token is contradictory: "
                 "one names a file to read an operator credential from and "
                 "the other says to run without a credential. Pick one. "
                 "(--no-admin-token on its own does not read %s either.)"
                 % DEFAULT_ADMIN_TOKEN_FILE)
    if args.admin_token_file is None and not args.no_admin_token:
        args.admin_token_file = DEFAULT_ADMIN_TOKEN_FILE

    token = args.admin_token
    # `not token` rather than `token == ""`: a credential is never compared
    # with ==/!= in this file, not even against the empty string, and a
    # source-level test pins that (test_no_secret_is_compared_with_equals).
    why = ("--admin-token was given but is empty or only whitespace"
           if isinstance(token, str) and not token.strip() else
           "neither --admin-token nor --admin-token-file was given")
    if token is None and args.admin_token_file:
        try:
            with open(args.admin_token_file) as fh:
                token = json.load(fh).get("admin_token")
        except FileNotFoundError:
            token, why = None, "%s does not exist" % args.admin_token_file
        except (OSError, ValueError) as exc:
            # Never interpolate the file's contents into the message.
            sys.exit("could not read %s: %s"
                     % (args.admin_token_file, type(exc).__name__))
        else:
            why = ('%s has no usable "admin_token" field'
                   % args.admin_token_file)
    if not isinstance(token, str) or not token.strip():
        # Anything that is not a non-whitespace string is no credential: an
        # empty --admin-token, a JSON file whose field is null, 0, a list.
        # It used to become a console that quietly proxied issuance with no
        # header.
        #
        # `.strip()` and not just `not token`: a token file holding only a
        # newline, or an environment variable that expanded to nothing, is
        # truthy and used to sail through here. The console then started
        # "credentialled", promised issuance, and got a 401 at the first
        # click -- which is exactly what the startup refusal below exists to
        # prevent. The library refuses to BUILD a mint on such a token
        # (MintConfig.__post_init__), so no mint is ever gated on one; a
        # console holding one holds nothing. It is tested, never trimmed:
        # nothing here sends a credential the operator did not supply.
        token = None

    if token is None and not args.no_admin_token:
        # The absence of a credential is refused at startup, not discovered
        # at the first click of Issue — the same move the library made when
        # it stopped letting an unset admin_token build a mint at all (see
        # the docstring, and L19).
        sys.exit(
            "no operator credential (%s).\n"
            "This console will not start without one. It would not be able "
            "to issue — it refuses to send an uncredentialled "
            "/admin/issue, and a mint gated on X-Admin-Token would answer "
            "401 anyway — so starting would only postpone finding that out "
            "until the first click of Issue.\n"
            "  --admin-token-file PATH  the file run_mint.py writes "
            "(default mint-admin-keys.json, JSON field \"admin_token\")\n"
            "  --admin-token TOKEN      visible in ps to every process on "
            "this machine; prefer the file\n"
            "  --no-admin-token         start read-only on purpose: "
            "descriptor and status work, Issue answers 503" % why)

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
