#!/usr/bin/env python3
"""Local operator GUI for an aicash mint: one command, one browser tab.

Run it, open the printed URL, and you can start a mint, create wallets,
fund one and pay another without a terminal and without reading the spec.

Nothing here is protocol. This process starts ``run_mint.py`` as a child
(via gui/mintctl.py) and drives ``aicash.wallet.Wallet`` (via
gui/walletops.py); it never reimplements either, and it changes no mint
behaviour. The pieces it does own are the ones a browser forces on you:

  * ONE ORIGIN. The page and every API route are served by this server, so
    the page never makes a cross-origin request and no CORS header is ever
    needed. Anything that must reach the mint is proxied here.
  * THE CREDENTIAL STAYS HERE. The mint's /admin/issue token is read from
    the workdir, used as an ``X-Admin-Token`` header on the server side,
    and scrubbed out of every response body and log line on the way out.
    It is never in page.html and never in a JSON response.
  * A CAPABILITY URL, THEN A COOKIE. Loopback is a weaker boundary than
    it sounds: it does not separate two users of one machine, it does not
    stop any other local process, and it does not stop a web page in the
    operator's own browser from issuing requests to 127.0.0.1. So this
    server also authenticates. At startup it mints a key that exists only
    in memory and prints it once, in the URL on the terminal. That URL
    opens the page and nothing else; the page is handed an HttpOnly,
    SameSite=Strict session cookie, and from then on the cookie is the
    only credential any /api/ route accepts. The key is never written to a
    file, never logged, and never in a response body.
  * LOOPBACK ONLY, AND SAME-ORIGIN ONLY. The listener refuses any
    non-loopback bind address, and refuses a request whose Host header is
    not a loopback literal, so a page on the internet cannot rebind DNS and
    drive your mint. It also refuses any request a browser marks as coming
    from another site (Sec-Fetch-Site / Origin / Referer), because a
    cross-site POST to 127.0.0.1 needs no rebinding and no CORS permission
    to fire.
  * NONE OF THAT MAKES THIS SAFE TO EXPOSE. The cookie is a second lock on
    a door that should still not face the street. It is not a reason to
    relax the loopback bind, and there is no flag that relaxes it.
  * NO TRACEBACK EVER REACHES THE PAGE. Every route returns JSON; failures
    return ``{"error": {"reason", "detail", "cause"}}`` with a detail a
    non-expert can act on.
  * A FAILURE SAYS WHY IT FAILED, AND ONLY WHAT IS KNOWN. ``cause`` is a
    machine reason from ONE closed set, shared verbatim with walletops.py
    and page.html (see CAUSES below). It is carried through from the layer
    that determined it, never re-guessed here: a wallet error keeps the
    cause walletops recorded, and this file only ever ADDS the one thing it
    alone can know -- that the mint PROCESS is not running -- which is the
    difference between ``mint_unreachable`` and ``mint_stopped``. Anything
    undetermined is ``unknown`` and says so in words. The failures this
    file raises on its own obey the same rule: ``mint_unreachable`` is
    named at the two raise sites where nothing answered (a URLError or an
    OSError on the socket) and NOWHERE else, so a mint that answers http
    500, or non-JSON, or a descriptor with no mint id, is reported as
    ``bad_mint_response`` / ``unknown`` -- it answered, and what it did
    with the request is undetermined.

gui/mintctl.py and gui/walletops.py are written against a pinned contract
and may be missing or newer than this file. Every use of them goes through
_Components, which turns "not importable", "wrong attributes" and "returned
a shape I did not expect" into a plain 503/502 naming the file at fault,
rather than a 500 with a stack trace.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import errno
import hmac
import inspect
import ipaddress
import json
import os
import re
import secrets
import socket
import sys
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
for _p in (HERE, os.path.join(REPO, "impl")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

DEFAULT_PORT = 8799
DEFAULT_WORKDIR = os.path.join(HERE, "var")

# THE DEADLINE BUDGET, WHICH ROUTES IT BINDS, AND WHICH IT DOES NOT.
#
# The page gives up on its own: page.html's TIMEOUTS.default is 20s, after
# which it aborts the fetch and shows ITS message -- "nothing answered
# before this page gave up waiting" -- instead of the error body this
# server determined. gui/README.md tells the operator to read ``cause``
# rather than the status line, so a cause this server computes AFTER the
# page has stopped listening is a documented answer that cannot be reached.
#
# So the budget is sized from the page inwards, not from the socket
# outwards. The cost of asking the mint anything, once: MintControl's
# descriptor probe (mintctl.probe_timeout_s, 2s, one per mint_status()
# call -- and there is no probe cache any more, so it is paid every time)
# plus the deadline of the call itself.
#
# BOUND, measured against a real SIGSTOPped mint:
#
#   * every route that goes through _mint_http (mint descriptor, mint
#     supply, token lookup, issue): 2 + MINT_HTTP_TIMEOUT_S = 10s.
#   * /api/wallet/list, /api/wallet/summary, /api/wallet/outstanding:
#     2 + READ_DEADLINE_S = 14s, enforced by Api._read_within() below.
#     These do not go through _mint_http at all -- they go through
#     gui/walletops.py into aicash.wallet.MintClient, whose own 30s
#     deadline this file does not set and cannot shorten from here -- so
#     before that deadline existed they ran 32s (one wallet), 62s (two
#     mint calls) and 64s (two wallets, read one after another) against a
#     wedged mint: the three slowest routes in the product, all of them
#     unreachable from the page at exactly the moment they matter, and
#     /api/wallet/list is the one every balance on the screen comes from.
#
# NOT BOUND, and deliberately. Every route in this list can outlast the
# page's abort against a wedged mint, and all of them are named here
# because an operator watching a panel hang is owed the reason:
#
#   * /api/wallet/quote (~31-38s), /api/wallet/pay (~31-38s),
#     /api/wallet/receive and /api/wallet/recover (~36s) MOVE MONEY.
#     _read_within() answers by ABANDONING its worker, which is safe for a
#     read and is not safe here: this server would be reporting an outcome
#     for an operation still in flight inside the worker it walked away
#     from, which is the one thing this GUI must never do. They wait for
#     walletops.py to finish and report what it determined, even when that
#     lands after the page has stopped listening -- in which case the
#     operator sees page.html's own "gave up waiting" message, the
#     wallet's history row is still written by walletops.py, and
#     /api/wallet/recover (itself slow, for the same reason) is how an
#     operation left in flight is settled. Shortening them means giving
#     aicash.wallet.MintClient a timeout, which is a change to a file this
#     one does not own.
#   * /api/wallet/create makes a wallet file. Abandoning it would let this
#     server answer "not created" while the worker it abandoned was still
#     creating it.
#   * /api/mint/start and /api/mint/stop are supervised process
#     transitions with their own timeouts (MintControl.start_timeout_s and
#     the stop drain). A start that takes 25s has not failed -- it is
#     starting -- and page.html gives exactly these two their own longer
#     deadlines (TIMEOUTS.start 90s, TIMEOUTS.stop 70s), so the 20s abort
#     is not their budget in the first place.
#
# PAGE_ABORT_S is what all of that is sized against. Nothing in this file
# reads it at runtime -- it is the page's number, not this server's -- and
# the tests are what keep the arithmetic honest: they assert it against
# the value page.html actually uses, and they measure each bound route
# against a really wedged mint.
PAGE_ABORT_S = 20.0
MINT_HTTP_TIMEOUT_S = 8.0
# How long a whole READ may take before it answers with what it has. Only
# ever applied to routes that move no money; see _read_within().
READ_DEADLINE_S = 12.0
MAX_BODY_BYTES = 1 << 20
# A whole-second deadline on one connection. Without it a client that sends
# "Content-Length: 500" and then four bytes pins a handler thread forever.
REQUEST_TIMEOUT_S = 30
# JSON numbers above 2**53 stop being exact in a browser, and the mint has
# its own bounds anyway; refuse them here with a sentence instead of
# relaying the mint's 500.
MAX_AMOUNT_MC = (1 << 53) - 1
WALLET_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$")
# A PAYEE is not a wallet name. Mirrors gui/walletops.py's own bound, so a
# label this server accepts is one that component will accept too.
RECIPIENT_NAME_MAX = 64
# Mirrors aicash.tokencodec.MINT_ID_RE. Checked here only to give a better
# message than a component exception would; MintControl re-checks it, and the
# mint itself is the authority.
MINT_ID_RE = re.compile(r"^[a-z0-9-]{1,64}$")


#: THE closed failure-cause vocabulary, identical in gui/walletops.py.
#: Every error body carries exactly one of these in ``error.cause``, and
#: every history row for an operation that did not commit carries one too.
#: The rule that matters: "the mint rejected it" belongs to mint_rejected
#: (and already_spent) ALONE -- a request the mint never received was not
#: refused by it -- and ``unknown`` is rendered as undetermined, never
#: dressed up as the likeliest story.
CAUSES = (
    "mint_unreachable",
    "mint_stopped",
    "mint_rejected",
    "already_spent",
    "malformed_token",
    "wrong_mint",
    "insufficient_funds",
    "unknown",
)

#: This file's OWN reasons that are also causes. Everything else this
#: server raises is a local fault (a bad name, a bad amount, a broken
#: component) with no determined cause in the money vocabulary, and says
#: ``unknown`` rather than borrowing a story from the mint.
#:
#: ``mint_unreachable`` is deliberately NOT here. The reason slug says
#: "this server could not use the mint"; the CAUSE says "the mint never
#: answered at all", and those are not the same finding -- a mint that
#: answers http 500, or answers with something that is not JSON, or
#: answers a descriptor with no mint_id in it, has plainly answered.
#: Mapping the slug to the cause asserted the stronger claim on every one
#: of those paths, directly above a detail that said the mint answered.
#: So the two transport failures that really are unreachable name the
#: cause explicitly at the raise site (see ``_mint_http``), every other
#: path says ``unknown`` and spells out in its detail what the mint
#: actually did.
_REASON_CAUSE = {
    "mint_stopped": "mint_stopped",
    "wallet_error": "unknown",
}


#: What became of a payment's delivery, relayed from walletops.py and
#: never re-derived here. "unknown" is a real answer -- an interrupted
#: delivery leaves exactly that -- and "" means the question does not
#: arise (nothing moved, so nothing was delivered).
DELIVERIES = ("delivered", "undelivered", "unknown")

#: What the recipient field of a payment record means. "" is the fourth
#: state: nothing was recorded, which is not the same as "no recipient".
RECIPIENT_KINDS = ("wallet", "bearer")

#: DID THE PAYING WALLET EVER TRY? Relayed from walletops.py, never
#: re-derived here. It is what tells apart the situations that all read
#: ``delivery: "unknown"`` -- a payment never delivered from one that was
#: attempted and lost -- and those send an operator to different places.
#: "" is the third value and means nothing was recorded.
DELIVERY_ATTEMPTS = ("not_attempted", "attempted")


def clean_attempt(value) -> str:
    """Coerce into DELIVERY_ATTEMPTS, or "" for nothing recorded."""
    text = str(value or "").strip()
    return text if text in DELIVERY_ATTEMPTS else ""


def clean_delivery(value, default: str = "") -> str:
    """Coerce a delivery outcome into DELIVERIES, or into ``default``.

    Same discipline as clean_cause: a component that answers something
    outside the closed set does not get to widen it through this server.
    """
    text = str(value or "").strip()
    return text if text in DELIVERIES else default


def clean_cause(value) -> str:
    """Any cause, coerced into the closed set. Never widens it."""
    text = str(value or "")
    return text if text in CAUSES else "unknown"


SESSION_COOKIE = "aicash_gui_session"
# One browser is one session. A handful covers a second tab, a reopened
# window and a re-exchange after a restart; the oldest is dropped rather
# than letting a long-running process accumulate credentials forever.
MAX_SESSIONS = 32


class GuiError(Exception):
    """An HTTP status, a machine reason, a human detail and a cause.

    ``cause`` defaults to whatever this file's own reason vocabulary maps
    to -- which is ``unknown`` for everything except the two failures this
    server determines itself -- so a raise site that has not thought about
    the cause says "undetermined" rather than inheriting a story.
    """

    def __init__(self, status: int, reason: str, detail: str, cause=None):
        super().__init__(f"{reason}: {detail}")
        self.status = status
        self.reason = reason
        self.detail = detail
        self.cause = clean_cause(
            cause if cause is not None else _REASON_CAUSE.get(reason))


def _cookie_values(header, name: str) -> list:
    """Every value sent for ``name`` in one Cookie header.

    Every, not the first: a hostile page that cannot read our cookie can
    still try to *shadow* it by setting a second one with the same name
    from a sibling origin, and whether the browser sends theirs first is
    not something to depend on. Checking all of them means an extra cookie
    cannot displace the real one.
    """
    out = []
    for part in (header or "").split(";"):
        key, sep, value = part.partition("=")
        if sep and key.strip() == name:
            out.append(value.strip().strip('"'))
    return out


#: THE EXACT WHITESPACE A PASTED KEY MAY CARRY, decided rather than
#: inherited. ``str.strip()`` with no argument removes every character
#: Python calls whitespace -- including U+00A0, U+2028, the Unicode space
#: family and the vertical tab -- from both ends, in any quantity. That
#: was never the intent: the intent is the one or two characters a
#: TERMINAL COPY carries, which is this set and no more.
#:
#: space and tab       a selection that ran past the end of the URL
#: CR and LF           the line break a copied terminal line ends with
#:
#: ``+`` needs no entry: a query string decodes ``+`` to a space before
#: this sees it, so a trailing plus IS a trailing space here.
#:
#: Everything else is refused, and deliberately: a non-breaking space or
#: a zero-width character does not come off a terminal, it comes off a
#: rendered page or a crafted URL, and quietly accepting it would widen
#: the set of strings that open this GUI for a case nobody has.
KEY_EDGE_WHITESPACE = " \t\r\n"

#: ...and at most this many of them at EACH end. A paste carries one or
#: two; a hundred is not a copy accident, and an unbounded tolerance is a
#: tolerance nobody has measured. Refusing past the bound costs a real
#: operator nothing and keeps the accepted shape something a test can
#: state exhaustively.
KEY_EDGE_WHITESPACE_MAX = 8


def _trimmed(value):
    """A pasted credential with the whitespace a terminal copy adds removed.

    Exactly ``KEY_EDGE_WHITESPACE``, at most ``KEY_EDGE_WHITESPACE_MAX``
    characters at each end, and nothing else -- see those constants for
    why each part of that is deliberate. A string carrying more, or
    carrying whitespace of another kind, is returned UNCHANGED and is
    then refused by the comparison like any other wrong key.

    Why trimming at all is safe rather than a loosened comparison: the key
    is ``secrets.token_urlsafe``, whose alphabet is ``A-Za-z0-9-_`` -- it
    contains no whitespace at any position, so removing whitespace can
    never turn one valid key into another, and cannot turn a wrong key into
    a right one. What it removes is the trailing space or newline a
    terminal copy picks up, which used to produce a bare 401 whose message
    described none of it: the one place in this flow where the error did
    not name the actual problem.

    It does no comparison itself and never looks at the secret, so it is
    not on the constant-time path: `_secret_eq` still decides, on bytes,
    with hmac.compare_digest.

    Non-str values pass through untouched, so the comparison below still
    decides them.
    """
    if not isinstance(value, str):
        return value
    start, end = 0, len(value)
    while (start < end and value[start] in KEY_EDGE_WHITESPACE
           and start < KEY_EDGE_WHITESPACE_MAX):
        start += 1
    stop = 0
    while (end > start and value[end - 1] in KEY_EDGE_WHITESPACE
           and stop < KEY_EDGE_WHITESPACE_MAX):
        end -= 1
        stop += 1
    # More than the bound at either end: not a paste artefact. Hand back
    # what was presented and let it be refused on its merits.
    if start >= KEY_EDGE_WHITESPACE_MAX and start < len(value) and \
            value[start] in KEY_EDGE_WHITESPACE:
        return value
    if stop >= KEY_EDGE_WHITESPACE_MAX and end > start and \
            value[end - 1] in KEY_EDGE_WHITESPACE:
        return value
    return value[start:end]


def _secret_eq(known, presented) -> bool:
    """Constant-time compare of two secrets that cannot be made to raise.

    hmac.compare_digest, never ``==``: an ordinary string comparison
    returns early on the first wrong byte, so a nearly-right guess answers
    measurably slower than a wrong one and the secret can be walked out one
    character at a time.

    It is called on BYTES, not on str, and that is the whole reason this
    wrapper exists rather than a bare compare_digest at each site.
    compare_digest raises TypeError on a str holding any non-ASCII
    character, and every value reaching here is attacker-supplied: the
    ``?k=`` of an unauthenticated GET, or a Cookie header. ``GET
    /?k=%C3%A9`` used to raise inside _authorize, which fell through to the
    handler's catch-all and answered 500 with a traceback on stderr -- a
    crash in the gate, on an unauthenticated request, that any local
    process could produce at will. Encoding first makes the comparison
    total: every input is either equal, unequal, or malformed, and the last
    two both answer False.

    surrogatepass, so a lone surrogate smuggled through the URL decoder
    encodes to bytes and compares unequal instead of raising on the way in.

    Length still leaks, exactly as it does for compare_digest on bytes. The
    secrets compared here are fixed-length, so there is nothing in that to
    learn.

    This is the only hmac.compare_digest call site in this module, which is
    what makes "secrets are compared in constant time" a property of one
    function a test can pin rather than a habit every future caller has to
    remember.
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


class _Auth:
    """The capability key, the sessions exchanged for it, and nothing else.

    Both values are generated here, live only in this process's memory, and
    leave it in exactly two places: the key in the URL printed once on the
    terminal, a session in one Set-Cookie header. They are never written to
    the workdir, never logged (Handler.log_message is silent), and scrubbed
    out of every response body on the way past Handler._redact.

    ``enabled=False`` is --no-auth: for automated tests, never for a
    machine anyone cares about.
    """

    def __init__(self, enabled: bool = True):
        self.enabled = bool(enabled)
        # token_urlsafe(32) is 32 bytes of os.urandom, ~43 characters. Not
        # guessable at any rate an attacker can drive a local socket at.
        self.key = secrets.token_urlsafe(32) if self.enabled else ""
        self._sessions = []
        self._lock = threading.Lock()

    def new_session(self) -> str:
        """A session value independent of the key.

        Independent on purpose: holding one must prove nothing about the
        other, so a session that leaks (a screenshot of devtools, a copied
        curl command) cannot be walked back to the key, and vice versa.
        """
        session = secrets.token_urlsafe(32)
        with self._lock:
            self._sessions.append(session)
            del self._sessions[:-MAX_SESSIONS]
        return session

    def sessions(self) -> list:
        with self._lock:
            return list(self._sessions)

    def key_ok(self, presented) -> bool:
        # _secret_eq, not compare_digest directly: `presented` is whatever
        # was in the query string, including non-ASCII, and a bare
        # compare_digest on str raises TypeError on it. See _secret_eq.
        if not self.enabled:
            return True
        return _secret_eq(self.key, _trimmed(presented))

    def key_is_whitespace_damaged(self, presented) -> bool:
        """True when what was pasted IS this key, with whitespace inside it.

        The diagnosis, not a second door: this is only ever used to choose
        a 401 page that names the actual problem. A key that fails for any
        other reason -- one character off, a different key, an empty one --
        answers False here and gets the ordinary refusal.

        It is the internal-whitespace case, because the surrounding kind is
        already accepted by key_ok. A terminal that wrapped the URL, or a
        copy that took the line break with it, produces exactly this: the
        right secret with a space or a newline through the middle of it.
        Still compare_digest, still on bytes, still constant-time.

        This diagnosis is deliberately WIDER than what key_ok accepts: it
        also recognises the key wearing whitespace key_ok refuses (a
        non-breaking space, or more edge whitespace than the bound), and
        names that as the problem. Widening a message is not widening a
        door -- nothing here issues a session -- and telling an operator
        "that is your key with whitespace in it" beats a blank refusal for
        exactly the case this method exists for.

        AND THE PAGE SAYS SO. LOCKED_PAGE_WHITESPACE spells out the shape
        _trimmed actually accepts -- up to KEY_EDGE_WHITESPACE_MAX of
        KEY_EDGE_WHITESPACE at each end, nothing else -- because this
        widening once left the page still telling the operator that edge
        whitespace was fine while being served for a trailing non-breaking
        space. A diagnosis and the sentence it is shown with have to be
        widened together or the message points at the wrong thing.
        """
        if not self.enabled or not isinstance(presented, str):
            return False
        squeezed = "".join(presented.split())
        if squeezed == _trimmed(presented):
            return False        # nothing internal to blame; it is just wrong
        return _secret_eq(self.key, squeezed)

    def session_ok(self, cookie_header) -> bool:
        if not self.enabled:
            return True
        found = False
        for value in _cookie_values(cookie_header, SESSION_COOKIE):
            for session in self.sessions():
                # _secret_eq, and no early return: a plain `==` on a secret,
                # or a break on the first match, both answer faster for a
                # nearly right guess than for a wrong one. _secret_eq also
                # absorbs a non-ASCII cookie, which compare_digest on str
                # would raise on -- inside the gate, before any route.
                if _secret_eq(session, value):
                    found = True
        return found

    def secrets_in(self, text: str) -> list:
        """Whichever of our credentials appear in ``text``. See _redact."""
        candidates = ([self.key] if self.key else []) + self.sessions()
        return [value for value in candidates if value and value in text]


# ----------------------------------------------------------------------
# the two modules this file does not own
# ----------------------------------------------------------------------
class _Components:
    """Import and call gui/mintctl.py and gui/walletops.py defensively.

    They are built in parallel with this file against the same written
    contract. Coding against the contract is right; *assuming* the contract
    held is not, because the failure mode of a wrong assumption here is a
    500 with a traceback on the operator's screen. So: import lazily (the
    GUI still starts and still explains itself when one file is absent),
    check the attributes the contract names, and validate the shape of
    every return value before the page ever sees it.
    """

    def __init__(self, workdir: str):
        self.workdir = workdir
        self._lock = threading.RLock()
        self._mintctl_mod = None
        self._mint = None
        self._walletops_mod = None

    # -- module loading -------------------------------------------------
    @staticmethod
    def _load(module_name: str, needed: tuple) -> object:
        try:
            module = __import__(module_name)
        except ImportError as exc:
            raise GuiError(
                503, "gui_incomplete",
                f"gui/{module_name}.py could not be imported ({exc}). It is "
                f"part of this GUI and must sit next to app.py. Everything "
                f"that needs it is unavailable until it does; the rest of "
                f"the page still works.")
        except Exception as exc:  # the module itself raised at import time
            raise GuiError(
                500, "component_error",
                f"gui/{module_name}.py failed while being imported "
                f"({type(exc).__name__}: {exc}). Fix that file; this GUI "
                f"cannot work around it.")
        missing = [n for n in needed if not hasattr(module, n)]
        if missing:
            raise GuiError(
                503, "gui_incomplete",
                f"gui/{module_name}.py does not define {', '.join(missing)}. "
                f"It does not match the contract this page was built "
                f"against.")
        return module

    def mint(self):
        """The shared MintControl instance."""
        with self._lock:
            if self._mint is None:
                module = self._load("mintctl", ("MintControl", "MintControlError"))
                try:
                    self._mint = module.MintControl(self.workdir)
                except Exception as exc:
                    raise GuiError(
                        500, "component_error",
                        f"MintControl({self.workdir!r}) raised "
                        f"{type(exc).__name__}: {exc}")
                self._mintctl_mod = module
            return self._mint

    def mint_running(self):
        """Is the mint PROCESS up? True/False, or None when unknowable.

        The one fact this file knows and walletops.py cannot: it supervises
        the mint, walletops only has a socket. Handing it over is what lets
        a stranded wallet operation record ``mint_stopped`` instead of the
        weaker ``mint_unreachable`` -- and never the reverse, because None
        (mintctl broken, absent, or lying) leaves the weaker claim standing.
        """
        try:
            control = self.mint()
            status = control.status()
            if isinstance(status, dict) and "running" in status:
                return bool(status["running"])
        except Exception:               # noqa: BLE001 - a supervisor that
            return None                 # cannot answer knows nothing
        return None

    def walletops(self):
        """The walletops module itself, loaded and contract-checked once.

        Exposed because this file has to ASK what that build can do (does
        its pay() take a recipient?) before handing it a call it might
        raise on. Loading is the same lazy, checked load every other use
        goes through.
        """
        with self._lock:
            if self._walletops_mod is None:
                self._walletops_mod = self._load(
                    "walletops", ("WalletOps", "WalletOpsError"))
            return self._walletops_mod

    def wallet(self, store_path: str, base_url: str):
        """A fresh WalletOps for one wallet file.

        Fresh per call on purpose: aicash.wallet.Wallet holds an sqlite
        connection, and sqlite connections belong to the thread that made
        them. This is a ThreadingHTTPServer.
        """
        module = self.walletops()
        try:
            ops = module.WalletOps(store_path, base_url)
        except Exception as exc:
            raise self._translate(exc, f"WalletOps({os.path.basename(store_path)})")
        # Set, not passed to the constructor: the pinned contract fixes
        # WalletOps(store_path, base_url), and a component build that has
        # never heard of this attribute must keep working. One that has
        # uses it to tell "the mint did not answer" from "the mint is not
        # running" when it records why an operation failed.
        try:
            ops.mint_running = self.mint_running
        except Exception:               # noqa: BLE001 - it is an extra, not
            pass                        # a requirement
        return ops

    # -- calling --------------------------------------------------------
    @staticmethod
    def _reason(text) -> str:
        """One machine vocabulary for `error.reason`, whatever the source.

        The components phrase their reasons for a human ("insufficient
        funds"); this file phrases its own for a machine ("bad_request").
        A client cannot switch on a mixture, so every reason that leaves
        here is snake_case. The human sentence is `detail`, which is
        passed through untouched.
        """
        slug = re.sub(r"[^a-z0-9]+", "_", str(text).strip().lower()).strip("_")
        return slug[:60] or "error"

    def _translate(self, exc: BaseException, what: str) -> GuiError:
        """Turn a component exception into a GuiError, keeping its message.

        And its CAUSE. walletops.py determined it at the moment of failure
        with facts this file no longer has; the only thing added here is
        the one fact this file has and it did not -- a mint process that is
        not running -- and only to sharpen ``mint_unreachable``. Nothing is
        ever re-guessed, and a component that reports no cause is
        ``unknown``, not "probably a rejection".
        """
        if isinstance(exc, GuiError):
            return exc
        ops_err = getattr(self._walletops_mod, "WalletOpsError", None)
        if ops_err is not None and isinstance(exc, ops_err):
            reason = getattr(exc, "reason", None) or "wallet_error"
            detail = getattr(exc, "detail", None) or str(exc)
            cause = clean_cause(getattr(exc, "cause", None))
            if cause == "mint_unreachable" and self.mint_running() is False:
                cause = "mint_stopped"
            return GuiError(400, self._reason(reason), str(detail) or str(exc),
                            cause)
        mint_err = getattr(self._mintctl_mod, "MintControlError", None)
        if mint_err is not None and isinstance(exc, mint_err):
            return GuiError(400, "mint_control", str(exc) or type(exc).__name__)
        return GuiError(
            500, "component_error",
            f"{what} raised {type(exc).__name__}: {exc}")

    def call(self, what: str, fn, *args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except BaseException as exc:
            raise self._translate(exc, what) from None

    # -- shape checking -------------------------------------------------
    @staticmethod
    def expect_dict(value, what: str, required=()) -> dict:
        if not isinstance(value, dict):
            raise GuiError(
                502, "bad_component_response",
                f"{what} returned {type(value).__name__}, not a dict. That "
                f"file does not match the contract this page expects.")
        missing = [k for k in required if k not in value]
        if missing:
            raise GuiError(
                502, "bad_component_response",
                f"{what} returned a dict without {', '.join(missing)}. That "
                f"file does not match the contract this page expects.")
        return value

    @staticmethod
    def expect_list(value, what: str) -> list:
        if not isinstance(value, list):
            raise GuiError(
                502, "bad_component_response",
                f"{what} returned {type(value).__name__}, not a list. That "
                f"file does not match the contract this page expects.")
        return value


def _local_stamp(ms: int) -> str:
    """An ms epoch as a readable instant on THIS MACHINE'S clock.

    For operators, not machines: every stamp this file prints is also
    carried as the raw integer beside it.

    Local, not UTC, and that is the whole point of it. page.html renders
    every other moment on the screen -- history rows, the supply read time,
    the wallets read time -- with toLocaleString(), under a comment that
    says ONE CLOCK, not two. A stamp printed as 14:01:55Z beside a supply
    line reading 7:01:55 AM is two clocks seven hours apart on one screen,
    and the age of the reading -- which is the entire reason the stamp is
    there -- cannot be read off it at all. The server and the browser are
    the same machine here: app.py binds loopback only and refuses a Host
    header that is not a loopback literal.
    """
    try:
        local = time.localtime(ms / 1000.0)
        zone = time.strftime("%Z", local).strip()
        stamp = time.strftime("%Y-%m-%d %H:%M:%S", local)
        return stamp + (" " + zone if zone else "")
    except (OSError, OverflowError, ValueError):  # pragma: no cover
        return "unknown time"


def _as_int(value, default=None):
    """Lenient int for COMPONENT OUTPUT. Never raises: an unexpected shape
    renders as '-' in the UI rather than failing a whole request."""
    if isinstance(value, bool) or value is None:
        return default
    if isinstance(value, int):
        return value
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


_DIGITS_RE = re.compile(r"[+-]?[0-9]+")


def _strict_int(value, default=None):
    """Strict int for CALLER INPUT. Anything that is not exactly a whole
    number is ``default`` (which the callers turn into a 400), never a
    truncation: an amount of 12.7 is a mistake, not twelve."""
    if isinstance(value, bool) or value is None:
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if value.is_integer() else default
    if isinstance(value, str) and _DIGITS_RE.fullmatch(value.strip()):
        return int(value.strip())
    return default


# ----------------------------------------------------------------------
# the API
# ----------------------------------------------------------------------
class Api:
    """Every route's body, independent of HTTP. Raises GuiError; returns JSON-able."""

    def __init__(self, workdir: str):
        self.workdir = os.path.abspath(workdir)
        self.wallets_dir = os.path.join(self.workdir, "wallets")
        os.makedirs(self.wallets_dir, exist_ok=True)
        self.components = _Components(self.workdir)
        self._mint_lock = threading.Lock()
        self._wallet_locks: dict = {}
        self._wallet_locks_guard = threading.Lock()
        self._state_path = os.path.join(self.workdir, "gui-state.json")

    # -- helpers --------------------------------------------------------
    @contextlib.contextmanager
    def _wallet(self, name: str, path: str, base: str):
        """A WalletOps for the length of one request, then released.

        WalletOps owns an sqlite connection. One per request is deliberate
        (sqlite connections belong to the thread that opened them, and this
        is a ThreadingHTTPServer), which makes closing it deliberate too:
        without this, every poll of the wallet list would leak a handle.
        """
        ops = self.components.wallet(path, base)
        try:
            yield ops
        finally:
            closer = getattr(ops, "close", None)
            if callable(closer):
                try:
                    closer()
                except Exception:
                    pass

    def _wallet_lock(self, name: str) -> threading.Lock:
        with self._wallet_locks_guard:
            return self._wallet_locks.setdefault(name, threading.Lock())

    def _remember(self, key: str, value) -> None:
        """Best-effort note-to-self in the workdir. Never fails a request."""
        try:
            try:
                with open(self._state_path) as handle:
                    state = json.load(handle)
            except (OSError, ValueError):
                state = {}
            if not isinstance(state, dict):
                state = {}
            state[key] = value
            tmp = self._state_path + ".tmp"
            with open(tmp, "w") as handle:
                json.dump(state, handle)
            os.replace(tmp, self._state_path)
        except OSError:
            pass

    def _recall(self, key: str, default=None):
        try:
            with open(self._state_path) as handle:
                state = json.load(handle)
            if isinstance(state, dict):
                return state.get(key, default)
        except (OSError, ValueError):
            pass
        return default

    def admin_token(self):
        """The /admin/issue credential. Server-side only; never serialised."""
        control = self.components.mint()
        if not hasattr(control, "admin_token"):
            return None
        token = self.components.call("MintControl.admin_token", control.admin_token)
        return token if isinstance(token, str) and token else None

    def mint_status(self) -> dict:
        control = self.components.mint()
        raw = self.components.call("MintControl.status", control.status)
        raw = self.components.expect_dict(raw, "MintControl.status", ("running",))
        status = {
            "running": bool(raw.get("running")),
            "pid": _as_int(raw.get("pid")),
            "port": _as_int(raw.get("port")),
            "mint_id": raw.get("mint_id") if isinstance(raw.get("mint_id"), str) else None,
            "base_url": raw.get("base_url") if isinstance(raw.get("base_url"), str) else None,
            "started_at_ms": _as_int(raw.get("started_at_ms")),
            "last_error": raw.get("last_error") if isinstance(raw.get("last_error"), str) else None,
            # IS IT ANSWERING -- which is not the same question as "is the
            # process alive", and dropping it was this GUI flattening two
            # states into one. MintControl.status() probes the descriptor
            # and reports the answer; a mint that is alive but not
            # answering (starting up, shutting down, SIGSTOPped, wedged)
            # came through here as an ordinary running mint, so the page
            # lit the healthy indicator and showed an uptime for something
            # that refuses every payment. The whole difference was left in
            # the English of last_error, which the page renders only when
            # the mint is STOPPED -- so on screen there was no difference
            # at all.
            #
            # None, not False, and it now reaches here for TWO reasons,
            # both of them "nobody said no": the component did not report
            # the field at all, or it reported None because there was no
            # mint process to ask -- a workdir holding no running mint has
            # nothing that could have failed to answer, and False there
            # describes a failure that never happened. Either way "we were
            # not told no" is a third answer and the page must be able to
            # tell it from "it told us no". Nothing here infers it from
            # last_error or from running, and nothing here turns it back
            # into a boolean.
            "responding": (bool(raw["responding"])
                           if isinstance(raw.get("responding"), bool)
                           else None),
        }
        # No _remember() here on purpose: /api/mint/status is a GET, and a
        # GET does not write to the workdir. MintControl.status() keeps the
        # last known port/base_url across a stop by itself, and start()
        # records what a GUI restart would otherwise forget.
        last, sources, ignored = self._last_start(status)
        status["last_start"] = last
        # WHERE EACH FIELD CAME FROM, beside the fields themselves. Two
        # records answer "which mint does this workdir hold" and they can
        # be about different mints; a merged object with no provenance
        # presents somebody else's economics as this mint's settings.
        status["last_start_sources"] = sources
        status["last_start_ignored_note"] = ignored
        return status

    #: Everything the Start form asks for, in the order it asks.
    _START_FIELDS = ("mint_id", "baseline_model_class", "port",
                     "rate_ppm", "cap_mc", "exempt_below_mc")

    #: Where a field of ``last_start`` came from, in words a panel can print.
    _FROM_SUPERVISOR = "the mint supervisor's record for this workdir"
    _FROM_NOTE = "this GUI's own note of the last mint it started here"
    _FROM_STATUS = "the status line's own record, on this same call"

    def _last_start(self, status: dict):
        """What the Start form should show, and where each field came from.

        Returns ``(fields, sources, ignored_note)``: the merged settings,
        a field -> English-sentence map saying which record each one came
        out of, and the note that was NOT used (with why), if any.

        Two records answer "which mint does this workdir hold", and they
        are written by different things at different times:

          * mint-control.json, the SUPERVISOR's, written by MintControl on
            every start and updated when it adopts a mint it did not
            spawn. status() above is derived from this file.
          * ``last_start`` in gui-state.json, THIS server's note, written
            only by a start that went through route_mint_start here.

        A workdir can easily hold the first and not the second -- a mint
        started from the command line, a gui-state.json that was never
        copied along with the ledger, a GUI restarted against somebody
        else's workdir. When that happened, this route used to answer with
        the supervisor's mint_id and port while handing the page nothing
        for the form, so the form fell back to its own built-in defaults
        (local-test-mint, port 8787) and the two halves of the same panel
        named two different mints. Then Stop/Start would have rewritten
        the mint's identity and economics to the defaults nobody typed.

        Filling the gaps fixed that and opened the next one: the two
        records can be about DIFFERENT MINTS. A note saying mint 'note-mint'
        on port 9999 with rate 3300 was used to complete a supervisor
        record for 'legacy-mint' on port 61234, and the page rendered the
        composite as one mint's settings -- burn-policy sentence, issue
        cost line and all -- then started legacy-mint with note-mint's
        economics. So there are three rules here, and all three are about
        one screen not showing two mints:

          1. The note fills a gap only when it is about the SAME mint. A
             note that names another mint_id is dropped WHOLE -- its
             economics belong to that mint, not to this one -- and comes
             back as ``ignored_note`` rather than silently vanishing.
          2. ``mint_id`` and ``port`` are then pinned to whatever status()
             reported ON THIS CALL, because those two are also printed in
             the stats block beside the form, from status(), while the
             form is filled from here. Pinning is normally a no-op: for
             MintControl both answers are derived from mint-control.json
             under one lock. Where it is not a no-op it is a component
             disagreeing with itself, and rule 3 keeps that visible.
          3. Nothing is papered over: when the pin overrides a value,
             ``sources`` says so in the sentence for that field, so the
             disagreement is reported rather than hidden.

        Returns (None, None, ignored) only when NEITHER record knows
        anything -- a genuinely virgin workdir, where the form's own
        defaults are the honest thing to show.
        """
        recorded = None
        try:
            control = self.components.mint()
            fn = getattr(control, "recorded_start", None)
            if callable(fn):
                raw = self.components.call("MintControl.recorded_start", fn)
                if isinstance(raw, dict):
                    recorded = raw
        except GuiError:
            # A supervisor that cannot answer is not a reason to fail a
            # status read; the note below still covers a GUI restart.
            recorded = None
        note = self._recall("last_start")
        note = note if isinstance(note, dict) else None

        def named(source):
            value = (source or {}).get("mint_id")
            return value if isinstance(value, str) and value else None

        # Which mint this workdir holds, most authoritative first. status()
        # and the supervisor's record come from the same file; the note is
        # the last resort and is the one that can be about anywhere.
        held = status.get("mint_id") if isinstance(status.get("mint_id"), str) else None
        held = held or named(recorded) or named(note)
        ignored = None
        note_id = named(note)
        if note is not None and held and note_id and note_id != held:
            ignored = {
                "mint_id": note_id,
                "port": _as_int(note.get("port")),
                "why": ("this GUI last started mint %r from here, but this "
                        "workdir holds %r. Another mint's burn policy is not "
                        "this mint's, so nothing from that note was used to "
                        "fill this form." % (note_id, held)),
            }
            note = None

        merged: dict = {}
        sources: dict = {}
        for field in self._START_FIELDS:
            for source, label in ((recorded, self._FROM_SUPERVISOR),
                                  (note, self._FROM_NOTE)):
                if source is None:
                    continue
                value = source.get(field)
                if value is None or isinstance(value, bool):
                    continue
                merged[field] = value
                sources[field] = label
                break
        for field in ("mint_id", "port"):
            live = status.get(field)
            if live is None:
                continue
            if field in merged and merged[field] != live:
                sources[field] = (
                    "%s -- and %s says %r for this field. Both cannot be on "
                    "one screen at once (the stats block prints the status "
                    "line's value and the form prints this one), so the "
                    "status line wins and the disagreement is reported here "
                    "rather than hidden."
                    % (self._FROM_STATUS, sources[field], merged[field]))
            elif field not in merged:
                sources[field] = self._FROM_STATUS
            merged[field] = live
        if not merged:
            return None, None, ignored
        return merged, sources, ignored

    def base_url(self, *, required: bool, status: dict | None = None) -> str:
        """Where the mint is. Falls back to the last one we saw.

        A stopped mint is not an error for reads: a wallet must still be
        able to show its last known balance, which is what the fallback is
        for. It is an error for anything that needs the mint to answer.

        The refusal it raises when the mint cannot be addressed names the
        state this server is actually in, because the neighbouring route
        will be asked the same question in the next second: ``mint_stopped``
        only when the process is down, ``mint_unreachable`` when a live
        process has no usable address here.

        ``status`` lets a caller that has ALREADY asked mint_status() hand
        the answer over instead of paying for a second descriptor probe.
        That is a deadline question, not a style one: every probe costs up
        to MintControl.probe_timeout_s against a wedged mint, and the whole
        route has to answer inside the page's own abort.
        """
        try:
            if status is None:
                status = self.mint_status()
        except GuiError:
            # mintctl itself is broken or absent. A read that only wants the
            # last known state should still work — the wallet files are right
            # there and do not need the supervisor to be healthy.
            if required:
                raise
            return self._recall("last_base_url") or "http://127.0.0.1:8787"
        if status["running"] and status["base_url"]:
            return status["base_url"]
        if required and status["running"]:
            # A LIVE mint with no address. This branch exists because the
            # test above is a conjunction and the refusal below is not:
            # saying "the mint is not running" here contradicted
            # /api/mint/status, which had just said running: true about the
            # same pid, in the same second.
            #
            # ``mint_stopped`` is not available for it. That cause is the
            # closed vocabulary's claim about a PROCESS -- it promises the
            # operator the mint was down, which is how walletops.py records
            # it in a wallet's permanent history -- and there is a live
            # process here. ``mint_unreachable`` is the weaker claim ("no
            # answer; what the mint did or did not see is undetermined")
            # and weaker is the only safe direction to be wrong in. The
            # sentence then narrows it to what is actually known, which is
            # more than the cause promises: nothing was sent at all.
            detail = ("The mint process (pid %s) is running, but this "
                      "workdir's record does not say which port it is on, so "
                      "there was nowhere to send this request and nothing "
                      "was sent. Stop the mint in the MINT panel and start "
                      "it again to re-establish its address."
                      % (status.get("pid"),))
            if status["last_error"]:
                detail += f" Last error: {status['last_error']}"
            raise GuiError(502, "mint_unreachable", detail, "mint_unreachable")
        if required:
            detail = ("The mint is not running, so nothing was sent to it "
                      "and nothing was refused by it. Start it in the MINT "
                      "panel first.")
            if status["last_error"]:
                detail += f" Last error: {status['last_error']}"
            raise GuiError(409, "mint_stopped", detail, "mint_stopped")
        # Stopped: MintControl keeps the last known base_url, and the note
        # written by the last successful start covers a GUI restart with a
        # component that does not.
        return (status["base_url"]
                or self._recall("last_base_url")
                or "http://127.0.0.1:8787")

    def _mint_http(self, method: str, path: str, body=None, *, admin=False,
                   base: str | None = None):
        """One request to the running mint, from this process.

        ``base`` is the same saving as base_url()'s ``status``: a caller
        that already resolved where the mint is does not pay for a second
        descriptor probe inside the deadline budget.
        """
        if base is None:
            base = self.base_url(required=True)
        data = None if body is None else json.dumps(body).encode()
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if admin:
            token = self.admin_token()
            if token:
                headers["X-Admin-Token"] = token
        request = urllib.request.Request(
            base.rstrip("/") + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=MINT_HTTP_TIMEOUT_S) as response:
                payload = response.read()
                status = response.status
        except urllib.error.HTTPError as exc:  # a real answer, just not 2xx
            payload = exc.read()
            status = exc.code
        except urllib.error.URLError as exc:
            # Nothing answered: the one shape that IS mint_unreachable.
            raise GuiError(
                502, "mint_unreachable",
                f"The mint says it is running but did not answer at {base} "
                f"({exc.reason}). Try stopping and starting it.",
                "mint_unreachable") from None
        except OSError as exc:
            raise GuiError(
                502, "mint_unreachable",
                f"Could not reach the mint at {base}: {exc}",
                "mint_unreachable") from None
        try:
            obj = json.loads(payload or b"{}")
        except ValueError:
            # It ANSWERED -- badly. Saying "the mint did not answer" here
            # would contradict this very sentence, and this server has no
            # idea what the mint did with the request, so: undetermined.
            raise GuiError(
                502, "bad_mint_response",
                f"The mint answered http {status} with something that is "
                f"not JSON, so what it did with the request is "
                f"undetermined.", "unknown") from None
        return status, obj

    # -- mint routes ----------------------------------------------------
    def route_mint_status(self, _query, _body) -> dict:
        return self.mint_status()

    def route_mint_start(self, _query, body) -> dict:
        mint_id = str(body.get("mint_id") or "").strip()
        baseline = str(body.get("baseline_model_class") or "").strip()
        if not MINT_ID_RE.fullmatch(mint_id):
            raise GuiError(
                400, "bad_request",
                "Mint id must be 1-64 characters of lowercase letters, "
                "digits and hyphens, e.g. local-test-mint.")
        if not baseline:
            raise GuiError(
                400, "bad_request",
                "Baseline model class cannot be empty. baseline-v1 is the "
                "usual value.")
        port = _strict_int(body.get("port"))
        if port is None or not 1 <= port <= 65535:
            raise GuiError(400, "bad_request",
                           "Port must be a whole number from 1 to 65535.")
        numbers = {}
        for field, low in (("rate_ppm", 0), ("cap_mc", 0), ("exempt_below_mc", 0)):
            value = _strict_int(body.get(field))
            if value is None or value < low:
                raise GuiError(
                    400, "bad_request",
                    f"{field} must be a whole number of at least {low}.")
            numbers[field] = value
        if not self._mint_lock.acquire(blocking=False):
            raise GuiError(409, "busy",
                           "Another start or stop is already in progress.")
        try:
            control = self.components.mint()
            result = self.components.call(
                "MintControl.start", control.start, mint_id=mint_id,
                baseline_model_class=baseline, port=port, **numbers)
            self.components.expect_dict(result, "MintControl.start", ("running",))
        finally:
            self._mint_lock.release()
        status = self.mint_status()
        # What this mint was actually started with. The page reads it back
        # into the form, so a later Stop/Start cannot quietly re-send the
        # form's defaults and rewrite the mint's economics; and it survives
        # a GUI or browser restart, when the form would otherwise reset.
        started = {"mint_id": mint_id, "baseline_model_class": baseline,
                   "port": port, **numbers}
        self._remember("last_start", started)
        if status.get("base_url"):
            self._remember("last_base_url", status["base_url"])
        status["last_start"] = started
        return status

    def route_mint_stop(self, _query, body) -> dict:
        drain = _strict_int(body.get("drain_seconds"), 10)
        if drain is None or not 0 <= drain <= 120:
            raise GuiError(400, "bad_request",
                           "drain_seconds must be a whole number from 0 to 120.")
        if not self._mint_lock.acquire(blocking=False):
            raise GuiError(409, "busy",
                           "Another start or stop is already in progress.")
        try:
            control = self.components.mint()
            self.components.call("MintControl.stop", control.stop,
                                 drain_seconds=drain)
        finally:
            self._mint_lock.release()
        return self.mint_status()

    def route_mint_logs(self, query, _body) -> dict:
        lines = _strict_int(query.get("lines"), 200) or 200
        lines = max(1, min(lines, 2000))
        control = self.components.mint()
        raw = self.components.call("MintControl.logs", control.logs, lines=lines)
        raw = self.components.expect_list(raw, "MintControl.logs")
        return {"lines": [str(line).rstrip("\n") for line in raw]}

    def route_mint_descriptor(self, _query, _body) -> dict:
        status, obj = self._mint_http("GET", "/v3/mints")
        if status != 200 or not isinstance(obj, dict) or "mint_id" not in obj:
            # Reaching here means _mint_http got an answer: a mint that
            # answers badly is not a mint that did not answer.
            raise GuiError(
                502, "bad_mint_response",
                f"The mint answered http {status} but not with a descriptor, "
                f"so which mint is running is undetermined.", "unknown")
        return obj

    def route_mint_issue(self, _query, body) -> dict:
        """§7.1 operator funding. The only place new money is created.

        The token strings exist ONLY in this response: the mint stores
        hashes, never secrets, so a token that is issued and not shown is
        money nobody can ever spend. Hence issue-then-return, and the page
        credits a wallet as a separate step it can retry.
        """
        amount = _strict_int(body.get("amount_mc"))
        count = _strict_int(body.get("count"), 1)
        if amount is None or amount <= 0:
            raise GuiError(400, "bad_request",
                           "Amount must be a whole number of millicredits "
                           "greater than zero.")
        if amount > MAX_AMOUNT_MC:
            raise GuiError(400, "bad_request",
                           f"Amount must be at most {MAX_AMOUNT_MC} "
                           f"millicredits.")
        if count is None or not 1 <= count <= 100:
            raise GuiError(400, "bad_request",
                           "Count must be a whole number from 1 to 100.")
        try:
            from aicash.tokencodec import format_token, ledger_key, new_secret
        except Exception as exc:
            raise GuiError(
                500, "component_error",
                f"Could not load the aicash token codec from impl/ "
                f"({exc}).") from None
        # One mint_status() for both the id and the address: each one
        # costs a live descriptor probe, and this route has to produce its
        # answer -- including its failure cause -- inside the page's abort.
        status_now = self.mint_status()
        base = self.base_url(required=True, status=status_now)
        mint_id = status_now["mint_id"]
        if not mint_id:
            descriptor = self.route_mint_descriptor(None, None)
            mint_id = descriptor.get("mint_id")
        if not isinstance(mint_id, str) or not mint_id:
            # Only reachable after the descriptor call succeeded, i.e.
            # after the mint answered. Nothing was issued, and why the
            # answer carried no usable mint_id is undetermined.
            raise GuiError(502, "bad_mint_response",
                           "The mint answered, but not with a mint id this "
                           "GUI can use, so nothing was issued.", "unknown")
        secrets = [new_secret() for _ in range(count)]
        outputs = [{"amount_mc": amount, "secret_hash": ledger_key(s)}
                   for s in secrets]
        try:
            status, obj = self._mint_http("POST", "/admin/issue",
                                          {"outputs": outputs}, admin=True,
                                          base=base)
        except GuiError as exc:
            # ADJACENCY, and a money claim: every other failure in this
            # route happens after the mint ANSWERED. This one is the mint
            # not answering, and "could not reach the mint" on its own
            # implies nothing was created -- which this server cannot
            # know. The secrets live only in this function, so if the mint
            # did issue against them they are unspendable from this
            # moment on, and the operator has to be told that rather than
            # left to retry into a silently doubled supply.
            # mint_stopped is deliberately NOT in this set: that one is
            # raised by base_url() BEFORE anything is sent, so nothing
            # reached the ledger and its own sentence already says so.
            # Rewriting it into "undetermined" would be this round's
            # defect committed in the other direction.
            if exc.cause in ("mint_unreachable", "unknown"):
                raise GuiError(
                    exc.status, exc.reason,
                    f"{exc.detail} Whether {amount * count} mc was issued "
                    f"is UNDETERMINED: the request may have reached the "
                    f"ledger. The secrets for it existed only in this "
                    f"request and are now gone, so if it did, that money "
                    f"is unspendable by anyone. Check the mint's supply "
                    f"in the descriptor before issuing again.",
                    exc.cause) from None
            raise
        if status == 401:
            raise GuiError(
                403, "not_authorized",
                "The mint refused the operator credential. It is read from "
                f"{os.path.join(self.workdir, 'mint-admin-keys.json')}; that "
                "file belongs to the mint that is running now.")
        if status != 200:
            # It answered, and refused. That IS a rejection and is the one
            # place in this route entitled to the word.
            raise GuiError(
                502, "issue_rejected",
                f"The mint rejected the issue request (http {status}): "
                f"{json.dumps(obj)[:400]}. Nothing was issued.",
                "mint_rejected")
        return {"amount_mc": amount,
                "count": count,
                "total_mc": amount * count,
                "tokens": [format_token(mint_id, amount, s) for s in secrets]}

    def route_token_status(self, query, _body) -> dict:
        """One reading of one ledger key, stamped with when it was taken.

        A LOOKUP IS A READING, NOT A SUBSCRIPTION. Bearer value is
        one-shot: the instant somebody redeems the string, ``unspent``
        becomes ``spent`` and the answer on screen stops being true. This
        route always asks the mint fresh -- there is no cache here and
        there must not be one -- but the answer it hands back is still a
        photograph, and a photograph left on a panel while the page
        re-renders around it reads exactly like a live view. That is how
        an operator ends up looking at ``state: unspent`` for a token the
        mint, asked in the same second, calls spent.

        So the reading carries the moment it was taken, in the object the
        panel actually prints: ``as_of`` in words, ``observed_at_ms`` and
        the mint's own ``mint_time`` for anything that does arithmetic,
        and the ``mint_id`` that answered. Nothing here decides how long a
        reading stays interesting -- it only refuses to present one
        undated.
        """
        text = (query.get("token") or "").strip()
        if not text:
            raise GuiError(400, "bad_request",
                           "Paste a token string or a ledger key to look up.")
        key = text
        token_mint_id = None
        if text.startswith("aicash:"):
            parts = text.split(":")
            if len(parts) != 5:
                raise GuiError(400, "bad_token",
                               "That is not a whole token string. A token "
                               "looks like aicash:v3:<mint>:<amount>:<secret>.")
            try:
                from aicash.tokencodec import ledger_key
                pad = "=" * (-len(parts[4]) % 4)
                key = ledger_key(base64.urlsafe_b64decode(parts[4] + pad))
            except Exception:
                raise GuiError(400, "bad_token",
                               "The secret part of that token is not valid "
                               "base64url.") from None
            token_mint_id = parts[2]
        status_now = self.mint_status()
        base = self.base_url(required=True, status=status_now)
        answering = status_now["mint_id"]
        if (token_mint_id and isinstance(answering, str) and answering
                and token_mint_id != answering):
            # ADJACENCY, and the same defect in its other direction: this
            # mint would answer "unknown" for this key, truthfully, and
            # that word renders as "no such token" -- when what actually
            # happened is that the question went to a ledger that was
            # never asked to hold it. One mint's silence is not another
            # mint's word, and passing it off as this token's state is a
            # reading presented with more confidence than its source.
            raise GuiError(
                409, "wrong_mint",
                f"That token says it was issued by mint {token_mint_id!r}, "
                f"and the mint running here is {answering!r}. This GUI can "
                f"only ask the mint it supervises, and that mint has no "
                f"word about another mint's tokens -- so this token's state "
                f"is undetermined from here.",
                "wrong_mint")
        status, obj = self._mint_http("POST", "/v3/status", {"hashes": [key]},
                                      base=base)
        observed_at_ms = int(time.time() * 1000)
        if status != 200:
            # The mint answered; it just did not answer 200. That is not
            # "the mint did not answer", and it is not a refusal of a
            # money operation either -- a lookup moves nothing.
            raise GuiError(502, "bad_mint_response",
                           f"The mint answered http {status} to the status "
                           f"lookup, so this token's state is undetermined.",
                           "unknown")
        results = obj.get("results") if isinstance(obj, dict) else None
        first = results[0] if isinstance(results, list) and results else None
        mint_time = obj.get("mint_time") if isinstance(obj, dict) else None
        mint_time = _as_int(mint_time)
        stamp = {
            "as_of": _local_stamp(observed_at_ms) + " - what the mint said "
                     "at that moment, by this machine's clock, which is the "
                     "one every other time on this page is shown in. A "
                     "reading, not a live view: look it up again to see the "
                     "state now.",
            "observed_at_ms": observed_at_ms,
            "mint_time": mint_time,
            "mint_id": answering,
        }
        if isinstance(first, dict):
            # Stamped INSIDE the entry, because the entry is what a panel
            # prints. A timestamp the renderer has to opt into is a
            # timestamp an undated reading still gets to skip.
            first = dict(first)
            first.update(stamp)
        return {"query": text, "ledger_key": key, "result": first,
                "raw": obj, "base_url": base,
                "token_mint_id": token_mint_id, **stamp}

    # -- wallet routes --------------------------------------------------
    def _store_path(self, name: str) -> str:
        if not isinstance(name, str) or not WALLET_NAME_RE.fullmatch(name):
            raise GuiError(
                400, "bad_name",
                "A wallet name is 1-32 characters: letters, digits, "
                "hyphen and underscore, starting with a letter or digit.")
        path = os.path.join(self.wallets_dir, name + ".db")
        # Belt and braces over the regex: the name becomes a filename.
        if os.path.dirname(os.path.abspath(path)) != self.wallets_dir:
            raise GuiError(400, "bad_name", "That wallet name is not allowed.")
        return path

    def wallet_names(self) -> list:
        try:
            entries = sorted(os.listdir(self.wallets_dir))
        except OSError as exc:
            raise GuiError(500, "workdir_unreadable",
                           f"Could not read {self.wallets_dir}: {exc}") from None
        return [e[:-3] for e in entries
                if e.endswith(".db") and WALLET_NAME_RE.fullmatch(e[:-3])]

    def _read_within(self, what: str, seconds: float, fn, *args, **kwargs):
        """Run a READ with a wall-clock deadline. Returns (finished, value).

        ``(False, None)`` means the deadline passed and the worker was
        ABANDONED -- it is still running, and whatever it eventually
        returns is dropped. That is why this is for reads only: a payment
        abandoned this way would leave this server describing an outcome
        while the operation that decides it is still in flight, and every
        route that moves money is excluded from it by hand (see the
        deadline budget at the top of this file). Reads move nothing, so
        the worst an abandoned one costs is one wasted socket.

        The work runs in the worker, not here, so the sqlite connection a
        WalletOps opens is opened, used and closed on one thread -- which
        is the same rule _wallet() is built on.

        An exception from the worker is re-raised in the caller, with its
        own traceback, exactly as if the call had been made here.
        """
        box: dict = {}

        def run():
            try:
                box["value"] = fn(*args, **kwargs)
            except BaseException as exc:     # noqa: BLE001 - re-raised below
                box["error"] = exc

        worker = threading.Thread(target=run, name="read:%s" % what,
                                  daemon=True)
        worker.start()
        worker.join(max(0.0, float(seconds)))
        if worker.is_alive():
            return False, None
        if "error" in box:
            raise box["error"]
        return True, box.get("value")

    def _unread_wallet(self, name: str, why: str) -> dict:
        """The shape of a wallet that was NOT read, in the same fields.

        ``balance_mc`` is None, never 0: page.html counts a wallet whose
        balance is not a number as unread and marks every total it feeds
        as a floor, which is the honest rendering. A zero here would be
        added up as money that is not there.
        """
        return {"name": name, "balance_mc": None, "coin_count": None,
                "mint_id": None, "connected": False, "error": why}

    def _summary(self, name: str, base: str) -> dict:
        """One wallet's summary, degraded rather than fatal."""
        try:
            with self._wallet(name, self._store_path(name), base) as ops:
                raw = self.components.call(
                    f"WalletOps({name}).summary", ops.summary)
                raw = self.components.expect_dict(
                    raw, f"WalletOps({name}).summary")
            return {"name": name,
                    "balance_mc": _as_int(raw.get("balance_mc")),
                    "coin_count": _as_int(raw.get("coin_count")),
                    "mint_id": raw.get("mint_id"),
                    "connected": bool(raw.get("connected")),
                    "error": None}
        except GuiError as exc:
            return {"name": name, "balance_mc": None, "coin_count": None,
                    "mint_id": None, "connected": False, "error": exc.detail}

    def route_wallet_list(self, _query, _body) -> dict:
        """Every wallet's balance -- inside one deadline, whatever happens.

        This is the route every balance on the screen comes from, and it
        reads the wallets one after another, so against a mint that is
        alive and answering nothing it used to cost one MintClient timeout
        PER WALLET: 32s for one wallet, 64s for two, growing with the
        list, all of it long after page.html stopped listening at 20s. The
        screen showed no balances at all in exactly the situation an
        operator most wants to see them.

        So the whole fan-out shares one budget. A wallet that is not read
        inside it comes back in the same shape as any other wallet that
        could not be read -- balance None, with the reason in ``error`` --
        which page.html already counts as unread and already marks the
        totals it feeds as a floor. The answer is never padded with a
        fabricated zero, and ``complete`` says outright whether this list
        is the whole list.
        """
        base = self.base_url(required=False)
        names = self.wallet_names()
        deadline = time.monotonic() + READ_DEADLINE_S
        wallets, unread = [], []
        for name in names:
            left = deadline - time.monotonic()
            finished, row = (False, None)
            if left > 0:
                finished, row = self._read_within(
                    "wallet/list:%s" % name, left, self._summary, name, base)
            if not finished:
                unread.append(name)
                row = self._unread_wallet(
                    name,
                    "Not read. This list has %g seconds to answer before the "
                    "page stops waiting, and they ran out here -- most often "
                    "because the mint is alive but answering nothing, which "
                    "costs every wallet read its own timeout. Nothing was "
                    "read from this wallet, so no figure here is its balance."
                    % READ_DEADLINE_S)
            wallets.append(row)
        return {"wallets": wallets, "dir": self.wallets_dir,
                # Is this the whole list? Said in the response rather than
                # left to be worked out from the rows, because a total
                # summed off a partial list is this round's whole subject.
                "complete": not unread,
                "unread": unread,
                "deadline_s": READ_DEADLINE_S}

    def route_wallet_create(self, _query, body) -> dict:
        name = str(body.get("name") or "").strip()
        path = self._store_path(name)
        if os.path.exists(path):
            raise GuiError(409, "wallet_exists",
                           f"A wallet called {name} already exists.")
        # A new wallet binds to the running mint's id, so it needs the mint.
        base = self.base_url(required=True)
        with self._wallet_lock(name):
            if os.path.exists(path):
                raise GuiError(409, "wallet_exists",
                               f"A wallet called {name} already exists.")
            summary = self._summary(name, base)
        if summary["error"]:
            # Do not leave a half-made store lying around under a name the
            # operator will try again with.
            if os.path.exists(path) and summary["balance_mc"] in (None, 0):
                try:
                    os.unlink(path)
                except OSError:
                    pass
            raise GuiError(500, "wallet_create_failed", summary["error"])
        return summary

    def _wallet_ops(self, query_or_body) -> tuple:
        name = str(query_or_body.get("name") or "").strip()
        path = self._store_path(name)
        if not os.path.exists(path):
            raise GuiError(404, "wallet_not_found",
                           f"There is no wallet called {name} in "
                           f"{self.wallets_dir}.")
        return name, path

    def route_wallet_summary(self, query, _body) -> dict:
        name, _path = self._wallet_ops(query)
        base = self.base_url(required=False)
        finished, summary = self._read_within(
            "wallet/summary:%s" % name, READ_DEADLINE_S, self._summary,
            name, base)
        if not finished:
            raise GuiError(
                504, "wallet_not_read",
                "This wallet's balance was not read within %g seconds, so "
                "this server gave up rather than answer after the page had "
                "stopped waiting. Nothing was read and nothing was changed; "
                "a mint that is alive but not answering is the usual reason."
                % READ_DEADLINE_S,
                # Not mint_unreachable: nobody established that the mint is
                # what ran out the clock. "unknown" is the honest cause.
                "unknown")
        if summary["error"] and summary["balance_mc"] is None:
            raise GuiError(502, "wallet_error", summary["error"])
        return summary

    def route_wallet_history(self, query, _body) -> dict:
        name, path = self._wallet_ops(query)
        limit = _strict_int(query.get("limit"), 50) or 50
        limit = max(1, min(limit, 500))
        with self._wallet(name, path, self.base_url(required=False)) as ops:
            rows = self.components.call(f"WalletOps({name}).history",
                                        ops.history, limit=limit)
        rows = self.components.expect_list(rows, f"WalletOps({name}).history")
        out = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            # cause is carried through EXACTLY as the component recorded it
            # (coerced into the closed set, never re-derived here): it is
            # the permanent record of why an operation did not commit, and
            # this layer knows nothing about that moment that the component
            # did not. A row with no cause is an op that committed ("") or
            # one whose cause was never recorded ("unknown") -- and the
            # component's own detail says which.
            cause = row.get("cause")
            delivery_cause = row.get("delivery_cause")
            out.append({"ts_ms": _as_int(row.get("ts_ms")),
                        "op_id": str(row.get("op_id", "")),
                        "kind": str(row.get("kind", "")),
                        "amount_mc": _as_int(row.get("amount_mc")),
                        "detail": str(row.get("detail", "")),
                        "cause": "" if cause in (None, "") else
                                 clean_cause(cause),
                        # The payment record, relayed exactly as recorded.
                        # "" means the question does not arise (nothing
                        # moved); "unknown" means it arose and nobody
                        # knows the answer. Those are different rows and
                        # this layer must not merge them.
                        "recipient": str(row.get("recipient", "")),
                        "recipient_kind": (row.get("recipient_kind")
                                           if row.get("recipient_kind")
                                           in RECIPIENT_KINDS else ""),
                        # Absent means the component said nothing about
                        # delivery, which is "" -- the question does not
                        # arise. Present but unrecognised means it DID
                        # answer and this file cannot read the answer,
                        # which is "unknown". Merging those two would be
                        # the same conflation this round is about.
                        "delivery": ("" if row.get("delivery") in (None, "")
                                     else clean_delivery(row.get("delivery"),
                                                         "unknown")),
                        "delivery_cause": ("" if not delivery_cause else
                                           clean_cause(delivery_cause)),
                        # Did the paying wallet ever try? Four situations
                        # read "unknown" and this is one of the two fields
                        # that tell them apart -- see DELIVERY_ATTEMPTS.
                        # Relayed, never inferred from the other fields.
                        "delivery_attempt": clean_attempt(
                            row.get("delivery_attempt"))})
        return {"name": name, "history": out}

    def route_wallet_receive(self, _query, body) -> dict:
        """Credit a wallet with pasted strings -- and, when the caller says
        which payment they came from, RECORD the outcome against it.

        The recording half exists because this route is the other way this
        product delivers a payment. ``POST /api/wallet/pay`` with ``to``
        performs the delivery itself and the payer's record gets
        "delivered"; a caller that pays and then pastes the strings here
        produced exactly the same outcome and, until now, this server
        watched it land and threw the observation away -- so one payment
        read "delivered to bob" through one route and "unknown" through
        the other, which is two panels on one screen disagreeing about one
        payment.

        Optional ``payer`` (a wallet in this workdir) and ``op_id`` are
        what let it be recorded. Both or neither; with neither, this is
        the plain Receive it always was, because strings pasted out of an
        email genuinely have no payment this server can name. The write
        goes through walletops, is made ONCE (a settled outcome is never
        rewritten), and never fails the request: the money moved either
        way, and a record that could not be written reads "unknown",
        which is then what is true.
        """
        name, path = self._wallet_ops(body)
        tokens = body.get("tokens")
        if isinstance(tokens, str):
            tokens = [tokens]
        if not isinstance(tokens, list) or not tokens:
            raise GuiError(400, "bad_request",
                           "Paste at least one token string, one per line.")
        tokens = [str(t).strip() for t in tokens if str(t).strip()]
        if not tokens:
            raise GuiError(400, "bad_request",
                           "Paste at least one token string, one per line.")
        if len(tokens) > 100:
            raise GuiError(400, "bad_request",
                           "Receive at most 100 tokens at a time.")
        payer, payer_path, op_id = self._settles(body, name)
        base = self.base_url(required=True)
        # Both wallets, in NAME ORDER, exactly as route_wallet_pay takes
        # them: this route can now touch the payer's record while holding
        # the receiver's lock, and two calls in opposite directions taking
        # them in call order would deadlock.
        with contextlib.ExitStack() as stack:
            for who in sorted({name} | ({payer} if payer else set())):
                stack.enter_context(self._wallet_lock(who))
            failed = None
            with self._wallet(name, path, base) as ops:
                try:
                    raw = self.components.call(f"WalletOps({name}).receive",
                                               ops.receive, tokens)
                except GuiError as exc:
                    # The delivery is still an OUTCOME, and it is the one
                    # the payer's record is waiting for. Recorded below,
                    # then re-raised unchanged.
                    failed, raw = exc, None
                if raw is not None:
                    # The counters are REQUIRED, and required to be
                    # NUMBERS. A key that is present and null is not an
                    # answer; _as_int(..., 0) supplying a zero for it is
                    # the same fabricated zero as a missing key, one step
                    # to the side. Either way this server has not been
                    # told what happened and says so with a 502.
                    raw = self.components.expect_dict(
                        raw, f"WalletOps({name}).receive",
                        ("accepted", "accepted_mc"))
                    accepted = _as_int(raw.get("accepted"))
                    accepted_mc = _as_int(raw.get("accepted_mc"))
                    if accepted is None or accepted_mc is None:
                        raise GuiError(
                            502, "bad_component_response",
                            f"WalletOps({name}).receive returned accepted / "
                            f"accepted_mc that are not whole numbers. That "
                            f"file does not match the contract this page "
                            f"expects, and this server will not print a zero "
                            f"it was not told.")
            recorded = None
            if payer:
                recorded = self._record_delivery(
                    payer, payer_path, base, op_id, name, raw, failed)
            if failed is not None:
                raise failed
            summary = self._summary(name, base)
        rejected = []
        for item in (raw.get("rejected") or []):
            if isinstance(item, dict):
                rejected.append({"token": str(item.get("token", ""))[:120],
                                 "reason": str(item.get("reason", "rejected")),
                                 "detail": str(item.get("detail", "")),
                                 "cause": clean_cause(item.get("cause"))})
        return {"name": name,
                "accepted": accepted,
                "accepted_mc": accepted_mc,
                "rejected": rejected,
                "balance_mc": summary["balance_mc"],
                # None when the caller named no payment. Otherwise what
                # was written down, in the record's own vocabulary --
                # ``recorded: false`` means there was no unsettled record
                # for that op_id, which is a fact, not a failure.
                "recorded": recorded}

    def _settles(self, body, name: str) -> tuple:
        """(payer, payer_path, op_id) for a receive that names a payment."""
        payer = body.get("payer")
        op_id = str(body.get("op_id") or "").strip()
        if payer in (None, "") and not op_id:
            return "", "", ""
        if payer in (None, "") or not op_id:
            raise GuiError(
                400, "bad_request",
                "To record this delivery against a payment, send BOTH payer "
                "(the wallet that paid) and op_id (from that payment's "
                "response or its history row). One without the other names "
                "no payment.")
        if len(op_id) > 128:
            raise GuiError(400, "bad_request", "That op_id is not an op_id.")
        payer, payer_path = self._wallet_ops({"name": payer})
        if payer == name:
            raise GuiError(
                400, "bad_request",
                f"{name} cannot be the payer of a payment it is receiving.")
        return payer, payer_path, op_id

    def _record_delivery(self, payer: str, payer_path: str, base: str,
                         op_id: str, recipient: str, raw, failed) -> dict:
        """Hand the outcome this route just watched to the payer's record.

        Best effort in the strict sense: it never fails the receive and
        never changes what the receive returns. A walletops build with no
        settle_delivery says so rather than pretending it recorded
        something.
        """
        with self._wallet(payer, payer_path, base) as payer_ops:
            settle = getattr(payer_ops, "settle_delivery", None)
            if not callable(settle):
                return {"recorded": False, "op_id": op_id,
                        "delivery": "unknown", "delivery_cause": "",
                        "delivery_detail": (
                            "gui/walletops.py here has no settle_delivery, so "
                            "this delivery was not written into " + payer +
                            "'s payment record")}
            try:
                # GuiError carries .reason/.detail/.cause -- the exact
                # three attributes walletops reads off a WalletOpsError,
                # and _translate already put the component's own cause in
                # them (sharpened to mint_stopped where this server knows
                # the process is down). So the refusal is classified from
                # what actually failed, not from "a delivery failed".
                out = settle(op_id, result=raw, error=failed,
                             recipient=recipient)
            except Exception:           # noqa: BLE001 - a record is not the
                out = None              # money path; see walletops.py
        if not isinstance(out, dict):
            return {"recorded": False, "op_id": op_id, "delivery": "unknown",
                    "delivery_cause": "", "delivery_detail": (
                        "the payment record could not be written, so " +
                        payer + "'s row for this payment still reads "
                        "unknown")}
        return {"recorded": bool(out.get("recorded")),
                "op_id": str(out.get("op_id", op_id)),
                "delivery": clean_delivery(out.get("delivery"), "unknown"),
                "delivery_cause": ("" if not out.get("delivery_cause")
                                   else clean_cause(out.get("delivery_cause"))),
                "delivery_detail": str(out.get("delivery_detail", ""))}

    def _amount(self, body) -> int:
        amount = _strict_int(body.get("amount_mc"))
        if amount is None or amount <= 0:
            raise GuiError(400, "bad_request",
                           "Amount must be a whole number of millicredits "
                           "greater than zero.")
        if amount > MAX_AMOUNT_MC:
            raise GuiError(400, "bad_request",
                           f"Amount must be at most {MAX_AMOUNT_MC} "
                           f"millicredits.")
        return amount

    def route_wallet_quote(self, _query, body) -> dict:
        name, path = self._wallet_ops(body)
        amount = self._amount(body)
        base = self.base_url(required=True)
        with self._wallet(name, path, base) as ops:
            raw = self.components.call(f"WalletOps({name}).quote",
                                       ops.quote, amount)
        raw = self.components.expect_dict(raw, f"WalletOps({name}).quote")
        return {"name": name, "amount_mc": amount,
                "burn_mc": _as_int(raw.get("burn_mc")),
                "change_mc": _as_int(raw.get("change_mc")),
                "inputs_mc": _as_int(raw.get("inputs_mc"))}

    def route_wallet_pay(self, _query, body) -> dict:
        """Pay, and -- when a recipient is named -- deliver and RECORD it.

        ``to`` is optional and is the whole of this round's fix at this
        layer. Without it the money leaves as bearer strings and the
        record says exactly that. With it, this server performs the
        delivery itself, which is what lets walletops.py watch the
        delivery and write down whether it landed: a browser that pays and
        then separately calls /api/wallet/receive keeps that knowledge in
        a DOM node, where a reload destroys it and no history row can ever
        recover it.

        AND ``to`` IS NOT ONLY A LOCAL WALLET. Requiring one made the
        record possible exactly where it is least interesting -- money
        moving between two wallets in one workdir -- while aicash's actual
        payee, an agent somewhere else, could never be recorded by anyone:
        the request 404'd. So ``to`` is any recipient LABEL, and
        ``deliver: false`` says this server is not the one handing the
        strings over. The payment is then recorded with the recipient's
        name, ``delivery: "unknown"`` and
        ``delivery_attempt: "not_attempted"``, which is exactly what is
        true: somebody was named, nothing was delivered from here, and the
        row says both instead of saying "bearer" about a payment that had
        a payee. A ``to`` that names no local wallet WITHOUT
        ``deliver: false`` is still refused -- silently recording instead
        of delivering would be this server deciding, on a typo, not to do
        what it was asked.

        A delivery that FAILS does not fail this request: the money left
        the wallet, the strings are in the response and in the wallet
        file, and ``delivery`` says what became of them. Failing here
        would tell the operator nothing moved, which is false.
        """
        name, path = self._wallet_ops(body)
        amount = self._amount(body)
        to = body.get("to")
        base = self.base_url(required=True)
        deliver_here = body.get("deliver", True)
        if deliver_here not in (None, True, False):
            raise GuiError(400, "bad_request",
                           "deliver must be true (this server hands the "
                           "strings to a wallet it holds) or false (it does "
                           "not, and only the recipient's name is recorded).")
        recipient = None            # a local wallet this server delivers into
        recipient_path = ""
        record_for = ""             # the name written into the record
        if to not in (None, ""):
            record_for = self._recipient_name(to)
            if record_for == name:
                raise GuiError(
                    400, "bad_request",
                    f"{name} cannot pay itself: pick a different recipient, "
                    f"or leave the recipient empty to take the token "
                    f"strings away as bearer money.")
            if not self._pay_can_record():
                raise GuiError(
                    503, "gui_incomplete",
                    "gui/walletops.py does not accept a recipient for a "
                    "payment, so this GUI cannot record who a payment was "
                    "meant for or whether it arrived. Leave the recipient "
                    "empty and deliver the strings with Receive; the "
                    "money is unaffected.")
            if deliver_here is not False:
                local = (WALLET_NAME_RE.fullmatch(record_for) and
                         os.path.exists(self._store_path(record_for)))
                if not local:
                    raise GuiError(
                        404, "wallet_not_found",
                        f"There is no wallet called {record_for} in "
                        f"{self.wallets_dir}, so this server cannot deliver "
                        f"to it. To pay a payee it does not hold and still "
                        f"record who the money was for, send deliver:false: "
                        f"the strings come back in the response and the "
                        f"record says the delivery was not attempted from "
                        f"here.")
                recipient, recipient_path = self._wallet_ops(
                    {"name": record_for})
        # BOTH wallets are locked for the whole payment, in NAME ORDER:
        # a delivery writes to the recipient's store, and two payments in
        # opposite directions taking their locks in call order would
        # deadlock. Taken once, here, because these locks are not
        # reentrant.
        with contextlib.ExitStack() as stack:
            for who in sorted({name} | ({recipient} if recipient else set())):
                stack.enter_context(self._wallet_lock(who))
            with self._wallet(name, path, base) as ops:
                if recipient is None and not record_for:
                    raw = self.components.call(f"WalletOps({name}).pay",
                                               ops.pay, amount)
                elif recipient is None:
                    # Named, not delivered from here. The record carries
                    # the payee; delivery stays unknown and the attempt
                    # says it was never made, which is the honest pair.
                    raw = self.components.call(f"WalletOps({name}).pay",
                                               ops.pay, amount,
                                               to=record_for)
                else:
                    # The recipient's wallet is opened for the length of
                    # the delivery only. Handing its receive() to the
                    # payer is what lets the component watch the delivery
                    # and record the outcome.
                    with self._wallet(recipient, recipient_path,
                                      base) as payee:
                        raw = self.components.call(
                            f"WalletOps({name}).pay", ops.pay, amount,
                            to=recipient, deliver=payee.receive)
                raw = self.components.expect_dict(
                    raw, f"WalletOps({name}).pay", ("tokens", "amount_mc"))
                tokens = self.components.expect_list(
                    raw.get("tokens"), f"WalletOps({name}).pay tokens")
                # WHAT ACTUALLY LEFT, from the component that watched it.
                # It used to fall back to the amount REQUESTED, which is
                # the same shape of fabrication as receive's zero: a
                # number this server was not told, printed as a fact about
                # money. burn_mc and change_mc are already null when the
                # component gave none, and this is now the same rule.
                paid_mc = _as_int(raw.get("amount_mc"))
                if paid_mc is None:
                    raise GuiError(
                        502, "bad_component_response",
                        f"WalletOps({name}).pay returned an amount_mc that "
                        f"is not a whole number. This server will not print "
                        f"the amount it asked for as the amount that left.")
            summary = self._summary(name, base)
        return {"name": name,
                "tokens": [str(t) for t in tokens],
                "amount_mc": paid_mc,
                "burn_mc": _as_int(raw.get("burn_mc")),
                "change_mc": _as_int(raw.get("change_mc")),
                "balance_mc": summary["balance_mc"],
                "op_id": str(raw.get("op_id", "")),
                # Relayed exactly as recorded. "unknown" stays unknown
                # here: this server watched nothing walletops did not.
                "recipient": str(raw.get("recipient", "")),
                "recipient_kind": (raw.get("recipient_kind")
                                   if raw.get("recipient_kind")
                                   in RECIPIENT_KINDS else ""),
                "delivery": clean_delivery(raw.get("delivery"), "unknown"),
                "delivery_cause": (
                    "" if not raw.get("delivery_cause")
                    else clean_cause(raw.get("delivery_cause"))),
                "delivery_attempt": clean_attempt(
                    raw.get("delivery_attempt")),
                "delivery_detail": str(raw.get("delivery_detail", ""))}

    def _recipient_name(self, to) -> str:
        """A recipient LABEL, bounded the way walletops.py bounds it.

        Not a wallet name: a payee is whoever the operator says it is, and
        restricting the label to the local wallet alphabet is what made
        every external payment unrecordable. It is a label and nothing
        else -- it never becomes a path, a header or a query -- so what it
        has to be is short, printable and one line, because it ends up in
        a permanent record and in sentences shown to humans.
        """
        if not isinstance(to, str) or not to.strip():
            raise GuiError(400, "bad_request",
                           "A recipient must be a non-empty name, or left "
                           "out entirely for bearer strings.")
        label = to.strip()
        if len(label) > RECIPIENT_NAME_MAX:
            raise GuiError(400, "bad_request",
                           f"A recipient name is at most "
                           f"{RECIPIENT_NAME_MAX} characters.")
        if any(ch < " " or ch == "\x7f" for ch in label):
            raise GuiError(400, "bad_request",
                           "A recipient name cannot contain control "
                           "characters.")
        return label

    def _pay_can_record(self) -> bool:
        """Does the walletops build here take a recipient at all?

        The same defensiveness as every other component call in this file:
        a build that predates the payment record must not be handed a
        keyword it will raise on, and must not be allowed to pay while
        this server believes a record is being written. Absent the
        capability the route refuses the recipient and says why, rather
        than paying and recording nothing.
        """
        # Loaded outside the guard: a walletops.py that is absent or
        # broken is its own error with its own message, not "this build
        # cannot record a recipient".
        module = self.components.walletops()
        try:
            params = inspect.signature(module.WalletOps.pay).parameters
            return "to" in params and "deliver" in params
        except Exception:               # noqa: BLE001 - an unreadable
            return False                # signature is not a capability

    def route_wallet_outstanding(self, query, _body) -> dict:
        """THE HANDED-OVER QUESTION: what has nobody redeemed yet?

        Of the value this wallet has ALREADY PAID OUT, which strings does
        the mint still call unspent -- plus, per payment, who it was meant
        for and whether the delivery landed.

        THIS IS NOT /api/wallet/recover's QUESTION, and the two answering
        differently at the same instant is normal rather than a bug. This
        route can report 220 mc across four strings while recover()
        reports nothing to settle, both correct: a payment that committed
        is not an operation in flight, and an operation in flight is not
        handed-over value. The reviewer who found those two numbers side
        by side had nothing on the wire telling them which question each
        was answering, so both responses now carry a ``scope`` sentence
        that says it in words, and the component method behind this one
        was renamed ``unredeemed_payments`` -- "outstanding" is exactly
        the word that reads as "needs recovering".

        The path keeps its old spelling because page.html calls it and
        page.html is not this file's to change.

        Why this route exists: page.html tells the operator that the token
        strings in its result panel are "the only copy" of the money, and
        it is not -- every one of them was written into the wallet file
        before the exchange was sent and is still there. Without a way to
        read them back, that sentence was true in practice: a reload, a
        closed tab or a delivery that failed halfway really did destroy the
        only accessible copy of real value.

        No copy of the MONEY is persisted to make this work (see
        walletops.py: a sidecar of bearer strings would be a second
        complete copy of live money on disk, bought for durability the
        store already has). The strings here are rebuilt from the wallet
        file; this is a READ. The recipient and delivery outcome beside
        each payment come from the payment record, which holds amounts and
        an op_id and never a secret.

        WHAT IT DOES NOT REACH, because the claim is about money and a
        half-true recovery story is worse than none:

          * what the SCREEN does with it is page.html's, not this
            file's. This route exists and answers; a claim here about
            whether some other file calls it is a claim about a file this
            one does not own and cannot keep true. (As this was written,
            page.html calls it on every pay result and prints "These are
            not the only copy" -- but the read-back would be worth having
            either way.)
          * it recovers PAYMENTS, not issuance. /api/mint/issue returns
            freshly issued strings and persists nothing anywhere -- the
            mint keeps ledger-key hashes, never secrets -- so for those
            strings "the only copy" is simply TRUE until a wallet takes
            them. That is exactly why crediting them is a separate,
            retryable step, and it is the reason the issue panel must not
            be dismissed before the credit succeeds.

        It returns live bearer secrets, so it is behind the same session
        cookie as every other route, and it is a GET only in the sense that
        it changes nothing -- it is not cacheable and the response carries
        no-store like all of them.

        What it does widen, stated rather than glossed: a session that
        could already spend every wallet here can now also read back the
        strings of payments ALREADY HANDED OVER -- money that is morally
        the payee's until they redeem it. That is a real difference, and it
        is accepted because the same secrets are sitting in plaintext in
        the wallet file two directories away (0600, same user), because
        this API is loopback-only and cookie-gated, and because the
        alternative is a GUI that really does destroy the operator's own
        money on a reload. Anyone who can reach this route can already
        empty every wallet it serves.
        """
        name, path = self._wallet_ops(query)
        limit = _strict_int(query.get("limit"), 20) or 20
        limit = max(1, min(limit, 100))
        base = self.base_url(required=False)

        def read():
            with self._wallet(name, path, base) as ops:
                # The new name first, the old one after it: a component
                # build from either side of the rename answers the same
                # question, and neither spelling is required to exist.
                method = "unredeemed_payments"
                fn = getattr(ops, method, None)
                if not callable(fn):
                    method = "outstanding_payments"
                    fn = getattr(ops, method, None)
                if not callable(fn):
                    raise GuiError(
                        503, "gui_incomplete",
                        "gui/walletops.py defines neither unredeemed_payments "
                        "nor outstanding_payments. Payment strings can still "
                        "be copied from the result panel when a payment is "
                        "made, but this GUI cannot read them back out of the "
                        "wallet file.")
                label = f"WalletOps({name}).{method}"
                return label, self.components.call(label, fn, limit=limit)

        # THE HANDED-OVER FIGURE, INSIDE THE PAGE'S OWN DEADLINE. This one
        # asks the mint twice (open the wallet, then ask about every string
        # it handed out), so against a wedged mint it took 62s -- and the
        # figure it produces is the one the reconciliation on screen
        # subtracts. A read; abandoning it moves nothing.
        finished, got = self._read_within(
            "wallet/outstanding:%s" % name, READ_DEADLINE_S, read)
        if not finished:
            raise GuiError(
                504, "wallet_not_read",
                "The handed-over value for %s was not read within %g "
                "seconds, so this server gave up rather than answer after "
                "the page had stopped waiting. Nothing was read and nothing "
                "was changed; a mint that is alive but not answering is the "
                "usual reason, and this figure needs the mint twice."
                % (name, READ_DEADLINE_S),
                "unknown")
        what, raw = got
        raw = self.components.expect_dict(raw, what, ("payments",))
        payments = []
        for item in self.components.expect_list(raw.get("payments"), what):
            if not isinstance(item, dict):
                continue
            tokens = []
            for token in (item.get("tokens") or []):
                if not isinstance(token, dict):
                    continue
                state = token.get("state")
                tokens.append({
                    "token": str(token.get("token", "")),
                    "amount_mc": _as_int(token.get("amount_mc")),
                    # unspent | spent | unknown | None. None is "the mint
                    # was not asked", which is not the same as "unknown to
                    # the ledger", and the two must not merge.
                    "state": state if state in ("unspent", "spent", "unknown")
                             else None})
            delivery_cause = item.get("delivery_cause")
            payments.append({"op_id": str(item.get("op_id", "")),
                             "amount_mc": _as_int(item.get("amount_mc")),
                             "live_mc": _as_int(item.get("live_mc")),
                             # Same record, same words, as history(): one
                             # payment must not read "delivered" in one
                             # view and "unknown" in the other.
                             "recipient": str(item.get("recipient", "")),
                             "recipient_kind": (item.get("recipient_kind")
                                                if item.get("recipient_kind")
                                                in RECIPIENT_KINDS else ""),
                             "delivery": clean_delivery(item.get("delivery"),
                                                        "unknown"),
                             "delivery_cause": (
                                 "" if not delivery_cause
                                 else clean_cause(delivery_cause)),
                             "delivery_attempt": clean_attempt(
                                 item.get("delivery_attempt")),
                             "tokens": tokens})
        checked = bool(raw.get("checked"))
        # THE TOTALS, DECOMPOSED BY WHAT THE MINT ACTUALLY SAID. Summed
        # from the per-token states in this very response, so the headline
        # number and the lines under it cannot answer the same question
        # differently.
        #
        # ``checked`` means THE MINT ANSWERED. It does not mean every
        # string carries a state: a wallet holding a payment against
        # mint-a, read while mint-b answers on that address, comes back
        # checked with every state "unknown" -- the ledger has no entry,
        # so whether anybody redeemed those strings is not known. Folding
        # that into a single total made it read 0, which is the fabricated
        # zero this file refuses everywhere else and is worse here because
        # the money is real.
        by_state = {"unspent": 0, "spent": 0, "unknown": 0, None: 0}
        for payment in payments:
            for token in payment["tokens"]:
                by_state[token["state"]] += (token["amount_mc"] or 0)
        complete = checked and not by_state["unknown"] and not by_state[None]
        # THE WHOLE-WALLET FIGURES, RELAYED AND NOT RECOMPUTED. The four
        # buckets above decompose the payments THIS RESPONSE LISTS, and
        # ``limit`` windows that list. Until this round the response said
        # nothing about the window at all, so a wallet with more payments
        # than the window published a confident ``unredeemed_mc`` that was
        # short by whatever fell off the end -- measured on a wallet with
        # 106 payments: the wire answered 3,000 where the component,
        # reading the same store at the same instant, answered None with
        # ``unlisted_outstanding_mc`` 200 and a true total of 3,200. The
        # component's own docstring states the rule for a re-serialising
        # caller, and this is that caller: relay the window's own account
        # of itself, or drop the headline.
        #
        # Relayed, never derived here. A component build that publishes
        # none of them leaves them null, and the fallbacks below are
        # written so that missing information can only make this response
        # LESS confident, never more.
        handed_over_mc = _as_int(raw.get("handed_over_mc"))
        listed_mc = _as_int(raw.get("listed_mc"))
        unlisted_mc = _as_int(raw.get("unlisted_mc"))
        unlisted_outstanding_mc = _as_int(raw.get("unlisted_outstanding_mc"))
        payment_count = _as_int(raw.get("payment_count"))
        recovered_mc = _as_int(raw.get("recovered_mc"))
        unaccounted_mc = _as_int(raw.get("unaccounted_mc"))
        recovered_ops = []
        for item in (raw.get("recovered_ops") or []):
            if isinstance(item, dict):
                recovered_ops.append({"op_id": str(item.get("op_id", "")),
                                      "amount_mc": _as_int(
                                          item.get("amount_mc"))})
        truncated = raw.get("truncated")
        if not isinstance(truncated, bool):
            # The component did not say. A full page is the only evidence
            # left, and it is the same evidence page.html was reduced to
            # inferring for itself.
            truncated = (payment_count > len(payments)
                         if payment_count is not None
                         else len(payments) >= limit)
        # Did every payment that still has value outstanding fit in the
        # window? A number answers it outright; with no number, a full
        # page has to be taken as "maybe not".
        fits = (unlisted_outstanding_mc == 0
                if unlisted_outstanding_mc is not None else not truncated)
        return {"name": name,
                "checked": checked,
                # How much this wallet has handed to other people over its
                # whole life, how many payments that was, and how much of
                # it this response actually lists. The identity the
                # component asserts and this route relays unchanged:
                #   handed_over_mc == listed_mc + unlisted_mc
                #   listed_mc == unspent + spent + unstated + unchecked
                #                + unaccounted
                "handed_over_mc": handed_over_mc,
                "payment_count": payment_count,
                "listed_mc": listed_mc,
                "unlisted_mc": unlisted_mc,
                # Of the value the window left out, how much the wallet's
                # own file still shows as handed over rather than retired.
                # Non-zero here is the one thing that turns an otherwise
                # complete report's headline into null, and it is
                # published so a reader can say WHY instead of guessing
                # from the row count.
                "unlisted_outstanding_mc": unlisted_outstanding_mc,
                # Is this the whole of this wallet's payments? Said in the
                # response rather than left to be worked out from
                # len(payments), which is what page.html was doing.
                "truncated": truncated,
                # Handed over and in none of the four buckets: 0 on every
                # path the component can reach, and a non-zero is its own
                # bug said out loud rather than absorbed.
                "unaccounted_mc": unaccounted_mc,
                # NOT handed over at all: pay operations that returned no
                # string to anybody and that recover() put back in the
                # spendable pool. This value is already inside the
                # wallet's balance_mc, so it is reported under its own
                # name and added to nothing above -- counting it twice is
                # exactly what an operator reading both screens must not
                # be made to do.
                "recovered_mc": recovered_mc,
                "recovered_ops": recovered_ops,
                "mint_id": raw.get("mint_id") if isinstance(
                    raw.get("mint_id"), str) else None,
                # The one number that answers "how much of what this
                # wallet paid out is still unredeemed" -- and it is None
                # unless every string in the report carries the mint's own
                # word for it AND every payment with outstanding value
                # fitted in the window. Any "0" here is 0 because the mint
                # said so about every string, never because some of them
                # went unanswered; any integer here is a whole-wallet
                # total, never a windowed one.
                "unredeemed_mc": (by_state["unspent"]
                                  if complete and fits else None),
                # ...and the parts, always, so a report that cannot give
                # the total still says exactly what it does know. These
                # four plus unaccounted_mc sum to listed_mc -- the value
                # handed over in the payments THIS RESPONSE LISTS, not in
                # the wallet's whole life. Nothing is rounded into
                # another, and handed_over_mc above is the whole-life
                # figure they are a window on.
                "unspent_mc": by_state["unspent"],
                "spent_mc": by_state["spent"],
                # The mint answered and has NO LEDGER ENTRY for these --
                # a different mint's database, most often. Not zero, not
                # spent, not unspent.
                "unstated_mc": by_state["unknown"],
                # The mint was not asked, or answered about only some.
                "unchecked_mc": by_state[None],
                "scope": ("value this wallet has already paid out that "
                          "nobody has redeemed yet; it says nothing about "
                          "operations left in flight -- POST "
                          "/api/wallet/recover is the one that settles "
                          "those, and it can correctly report nothing to "
                          "do while this reports money. unredeemed_mc and "
                          "the four buckets describe the payments listed "
                          "here; handed_over_mc, payment_count and "
                          "truncated describe the whole wallet, and a "
                          "caller re-serialising any of this must carry "
                          "truncated and unlisted_outstanding_mc with it "
                          "or drop its own headline to null"),
                "payments": payments}

    def route_wallet_recover(self, _query, body) -> dict:
        """THE IN-FLIGHT QUESTION: did an operation never get an answer?

        Settles operations this wallet started and got no answer for,
        against the ledger (§5.1). It does NOT look at value already
        handed over, so "nothing recovered" here is not a statement that
        the wallet has no unredeemed payments -- GET /api/wallet/outstanding
        answers that, and the two disagreeing at the same instant is
        normal. Both responses carry a ``scope`` sentence saying which
        question they answered, because a number on its own did not.
        """
        name, path = self._wallet_ops(body)
        base = self.base_url(required=True)
        with self._wallet_lock(name):
            with self._wallet(name, path, base) as ops:
                raw = self.components.call(f"WalletOps({name}).recover",
                                           ops.recover)
                raw = self.components.expect_dict(
                    raw, f"WalletOps({name}).recover")
            summary = self._summary(name, base)
        return {"name": name, "result": raw,
                "balance_mc": summary["balance_mc"],
                "scope": ("operations this wallet started and never got an "
                          "answer for; it does not look at payments that "
                          "committed, so nothing to recover here does not "
                          "mean nothing is unredeemed -- GET "
                          "/api/wallet/outstanding answers that")}


# ----------------------------------------------------------------------
# HTTP
# ----------------------------------------------------------------------
ROUTES = {
    ("GET", "/api/mint/status"): "route_mint_status",
    ("POST", "/api/mint/start"): "route_mint_start",
    ("POST", "/api/mint/stop"): "route_mint_stop",
    ("GET", "/api/mint/logs"): "route_mint_logs",
    ("GET", "/api/mint/descriptor"): "route_mint_descriptor",
    ("POST", "/api/mint/issue"): "route_mint_issue",
    ("GET", "/api/wallet/list"): "route_wallet_list",
    ("POST", "/api/wallet/create"): "route_wallet_create",
    ("GET", "/api/wallet/summary"): "route_wallet_summary",
    ("GET", "/api/wallet/history"): "route_wallet_history",
    ("POST", "/api/wallet/receive"): "route_wallet_receive",
    ("POST", "/api/wallet/pay"): "route_wallet_pay",
    ("POST", "/api/wallet/quote"): "route_wallet_quote",
    ("POST", "/api/wallet/recover"): "route_wallet_recover",
    ("GET", "/api/wallet/outstanding"): "route_wallet_outstanding",
    ("GET", "/api/token/status"): "route_token_status",
}

_ALLOWED_ORIGIN_HOSTS = {"127.0.0.1", "localhost", "::1"}
# The WHOLE Host header, not a prefix of it: 127.0.0.1, localhost, [::1] or
# ::1, then either nothing or a colon and a decimal port. There is no set of
# allowed names beside this pattern, because a set plus a hand-rolled
# splitter is how the accepted host space widens by accident: the pattern is
# the whitelist, and it is anchored at both ends because the obvious
# hand-rolled version -- split on the last colon, or cut at the "]" --
# validates the part before the separator and accepts whatever follows it,
# so "127.0.0.1:8799.evil.example", "localhost:not-a-port" and
# "[::1]evil.example" all sail through a check that looks right. An
# "optional :port" that accepts arbitrary text is not an optional port; it
# is an optional anything.
#
# Bare "::1" carries no port: an unbracketed IPv6 address followed by
# ":<port>" is not something HTTP can express, so "::1:8799" is not a
# loopback host with a port and is refused.
_HOST_RE = re.compile(
    r"^(?:(?:127\.0\.0\.1|localhost|\[::1\])(?::[0-9]{1,5})?|::1)$")

# The 401 for a key that IS this GUI's key with whitespace through the
# middle of it -- a terminal that wrapped the URL, a copy that took the line
# break with it. Says what is wrong, because a bare "wrong key" for a key
# that is character-for-character right is the one message in this flow that
# sent the operator looking in the wrong place. It quotes nothing back:
# no key, no session, not even the length of what was pasted.
LOCKED_PAGE_WHITESPACE = """<!doctype html><meta charset=utf-8>
<title>aicash operator - locked</title>
<body style="font:15px/1.5 system-ui;padding:40px;max-width:44em">
<h1>That key has whitespace in it</h1>
<p>What you opened is this GUI's key wearing whitespace the key itself does
not contain &mdash; which is what happens when the terminal wraps the address
over two lines and only part of it is selected, or when a copy takes the line
break along, or when something on the way substituted a fancy space
character.</p>
<p>Go back to the terminal window running <code>app.py</code>, copy the whole
address as ONE unbroken line, and open it again.</p>
<p>What is forgiven, exactly: up to eight ordinary spaces, tabs, carriage
returns or newlines at each END of the key. Everything else is refused and
this page is what you get for it &mdash; whitespace in the MIDDLE, a longer
run than that at either end, or any other kind of space character (a
non-breaking space, an ideographic space, a vertical tab, a line separator).
So do not go hunting only for a break in the middle: an invisible character
at the end will land you here too.</p>
</body>
"""

# Deliberately says nothing an attacker could use: no key, no session, no
# port list, no hint about what the routes are. Just where the operator's
# own URL came from.
LOCKED_PAGE = """<!doctype html><meta charset=utf-8>
<title>aicash operator - locked</title>
<body style="font:15px/1.5 system-ui;padding:40px;max-width:44em">
<h1>This page needs the URL from your terminal</h1>
<p>The aicash operator GUI prints one address when it starts, with a key
in it, like <code>http://127.0.0.1:8799/?k=&hellip;</code>. That address is
the password: open it, and this browser is let in for as long as the GUI
keeps running.</p>
<p>Look in the terminal window where you ran <code>app.py</code>. If you
have lost it, stop the GUI and start it again; the key is generated fresh
each time and is never written down anywhere.</p>
</body>
"""


class Handler(BaseHTTPRequestHandler):
    api: Api = None            # set by serve()
    auth: _Auth = None         # set by serve(); None fails every request shut
    page_path: str = ""
    # One request's pending Set-Cookie. Set in exactly one place
    # (_authorize, on a good key) and emitted by _send. A class-level
    # default matters: send_error() can answer before _handle() runs.
    _set_cookie = None
    server_version = "aicash-gui"
    sys_version = ""
    # A deadline on one connection. Without it, a client that announces
    # "Content-Length: 500" and then sends four bytes holds a handler
    # thread for as long as it likes, and enough of those exhaust the
    # server with no request ever completing.
    timeout = REQUEST_TIMEOUT_S
    # HTTP/1.1 so the page's 4-second poll reuses one connection instead of
    # opening three. Every response here carries an exact Content-Length,
    # and any path that answers without draining a request body closes the
    # connection rather than leave the next read misaligned.
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        """Silent by design: a request line can carry a token in a query
        string, and this server's log would be the one place it landed."""

    # -- plumbing -------------------------------------------------------
    def _redact(self, text: str) -> str:
        """Last line of defence for the operator credential.

        Nothing here deliberately serialises the admin token, but component
        error messages are pasted through verbatim and one of them could
        quote a command line. Strip it on the way out rather than trust
        that none of them ever will.
        """
        try:
            token = self.api.admin_token()
        except Exception:
            token = None
        if token and len(token) >= 8 and token in text:
            text = text.replace(token, "[admin token redacted]")
        # The capability key and the session belong in exactly two places:
        # the URL on the terminal and one Set-Cookie header. Nothing here
        # serialises either -- but a route that echoed its own query string,
        # or a component quoting a command line, would, and either would
        # hand the whole GUI to a page that can only read a response body.
        # Strip them on the way out rather than trust that none ever will.
        try:
            leaked = self.auth.secrets_in(text) if self.auth else []
        except Exception:
            leaked = []
        for value in leaked:
            text = text.replace(value, "[credential redacted]")
        return text

    def _send(self, code: int, payload: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        if code != 204:  # a 204 has no body by definition
            self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        if self._set_cookie:
            self.send_header("Set-Cookie", self._set_cookie)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        # Self-contained page, no CDN: say so in a header the browser enforces.
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; connect-src 'self'; "
            "img-src 'self' data:; base-uri 'none'; form-action 'none'")
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def _json(self, code: int, obj):
        try:
            text = json.dumps(obj, default=str)
        except (TypeError, ValueError):
            code, text = 500, json.dumps(
                {"error": {"reason": "bad_component_response",
                           "cause": "unknown",
                           "detail": "A component returned something that "
                                     "cannot be sent as JSON."}})
        self._send(code, self._redact(text).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _error(self, code: int, reason: str, detail: str, cause=None):
        """One error envelope, and it always carries a cause.

        ``cause`` defaults through the reason vocabulary, which maps
        everything this file raises on its own to ``unknown`` except the
        two it actually determines. A caller that has a better cause --
        every GuiError does -- passes it.
        """
        self._json(code, {"error": {
            "reason": reason,
            "detail": detail,
            "cause": clean_cause(
                cause if cause is not None else _REASON_CAUSE.get(reason)),
        }})

    def _host_ok(self) -> bool:
        """Refuse a Host header that is not a loopback LITERAL.

        This is the DNS-rebinding defence, and it is the reason binding to
        127.0.0.1 is not sufficient on its own. A page on the public
        internet can point its own hostname at 127.0.0.1 and then drive
        this API from the victim's browser: the packets are loopback
        packets, the bind address stops nothing, and the only thing the
        attacker cannot change is that the browser puts *their* hostname in
        the Host header. So the name is checked, not the address, and only
        the four literals a person can actually type are accepted -- no
        resolution, because "does this name resolve to 127.0.0.1" is the
        question the attacker gets to answer.

        A missing Host is refused too. No browser omits it, so allowing it
        bought nothing and left a hole in the outer defence.

        The whole header has to match, port included. Validating the name
        and shrugging at the rest is the classic way to get this wrong:
        "127.0.0.1:8799.evil.example" has a loopback literal in front of it
        and is not a loopback host.
        """
        host = (self.headers.get("Host") or "").strip().lower()
        return _HOST_RE.match(host) is not None

    def _origin_ok(self) -> bool:
        """Refuse a request that another site told the browser to make.

        The Host check above stops DNS rebinding. It does NOT stop the
        simpler attack: any page the operator has open in another tab can
        POST straight to http://127.0.0.1:<port> with a simple content
        type, which the browser sends with our own Host header and with no
        preflight to veto. The attacker cannot read the reply, but it does
        not need to — the request alone mints money, pays every wallet out
        to token strings only it will ever see, or stops the mint.

        Two headers close it, and a browser sends at least one of them on
        any request that came from a page:

          * ``Sec-Fetch-Site``: ``same-origin`` and ``none`` (typed in the
            address bar) are ours; ``cross-site`` and ``same-site`` are
            another page driving us.
          * ``Origin``: when present it must be exactly this server.

          * ``Referer``: same rule. A browser that suppressed Origin may
            still send this, and a page that sends a forged one is not a
            browser.

        A request carrying none of them is not a browser request — curl, a
        script, the examples in the README — and is allowed, because those
        cannot be conscripted by a web page in the first place.
        """
        site = (self.headers.get("Sec-Fetch-Site") or "").strip().lower()
        if site and site not in ("same-origin", "none"):
            return False
        for header in ("Origin", "Referer"):
            value = (self.headers.get(header) or "").strip()
            if not value:
                continue          # absent is allowed; present must be us
            if not self._same_origin(value):
                return False
        return True

    def _same_origin(self, value: str) -> bool:
        """Is this Origin (or Referer URL) exactly this server?

        Scheme, host and port all have to match. "Starts with
        http://127.0.0.1" is not a check: http://127.0.0.1.evil.example
        starts with it too, and so does another local port belonging to
        some other program the operator is running.
        """
        if value.lower() == "null":   # sandboxed iframe, file://, data:
            return False
        try:
            parsed = urllib.parse.urlsplit(value)
            port = parsed.port
        except ValueError:
            return False
        if parsed.scheme != "http":
            return False
        if (parsed.hostname or "").lower() not in _ALLOWED_ORIGIN_HOSTS:
            return False
        try:
            mine = self.server.server_address[1]
        except Exception:
            mine = None
        return port is not None and mine is not None and port == mine

    # -- THE ACCESS POLICY, all of it, in one place ---------------------
    def _authorize(self, method: str, path: str, query: dict) -> bool:
        """The only gate. Every request passes through here, before
        dispatch, before the body is read, before any route name is even
        looked up. A route added to ROUTES tomorrow inherits all of it
        without its author doing anything, because dispatch happens after
        this function returns True.

          1. HOST is a loopback literal, or 403. DNS rebinding; see
             _host_ok. This is the check most likely to be written wrong,
             and the one that stops an attack the bind address does not.
          2. ORIGIN and REFERER, when present, are this server, or 403.
             Absent is fine: a same-origin fetch and curl both omit them.
             Together with SameSite=Strict on the cookie, this is what
             stops a page in another tab from POSTing here.
          3. GET / is the ONE route the capability key opens. A correct
             ?k= is exchanged for an HttpOnly, SameSite=Strict session
             cookie, once, and the key is never needed again. A wrong or
             missing key, with no valid cookie, is 401 and NO Set-Cookie.
          4. EVERYTHING ELSE requires that cookie and accepts nothing
             else. GET as much as POST: /api/wallet/list names every
             wallet, /api/mint/logs is the mint's log. ?k= is deliberately
             NOT accepted here -- a URL ends up in history files, proxy
             logs, Referer headers and shoulder-surfing range, which is
             exactly why it is spent once on a cookie and then retired.

        None of this makes the GUI safe to expose. It is a second lock on
        a door that should still not face the street: it does not turn the
        loopback bind into an optional extra, and nothing here should ever
        be read as permission to relax it.
        """
        if self.auth is None:
            # serve() always installs one. Fail closed if something built a
            # Handler subclass without it, rather than serve money openly.
            self.close_connection = True
            self._error(500, "misconfigured",
                        "This server was started without an access policy "
                        "and will not answer anything.")
            return False
        if not self._host_ok():
            self.close_connection = True
            self._error(
                403, "not_loopback",
                "This GUI only answers requests addressed to 127.0.0.1, "
                "[::1] or localhost. It is a local operator tool, not a "
                "hosted service, and a request that arrived under any other "
                "name is a browser being pointed here by someone else.")
            return False
        if not self._origin_ok():
            self.close_connection = True
            self._error(
                403, "cross_site",
                "That request came from another web page. This GUI can mint "
                "money and spend every wallet in its workdir, so it answers "
                "only its own page, opened directly at this address.")
            return False
        if not self.auth.enabled:
            return True           # --no-auth; main() has already shouted
        has_cookie = self.auth.session_ok(self.headers.get("Cookie"))
        if method in ("GET", "HEAD") and path in ("/", "/index.html"):
            if has_cookie:
                return True
            presented = query.get("k")
            if self.auth.key_ok(presented):
                self._set_cookie = (
                    "%s=%s; HttpOnly; SameSite=Strict; Path=/"
                    % (SESSION_COOKIE, self.auth.new_session()))
                return True
            self.close_connection = True
            # A key that is right but for whitespace THROUGH it gets a page
            # that names that, instead of the generic refusal: it is the one
            # failure here whose cause the server can see and the operator
            # cannot. Every other wrong key -- a character off, a stale one,
            # an empty one -- is refused exactly as before, with no hint.
            page = (LOCKED_PAGE_WHITESPACE
                    if self.auth.key_is_whitespace_damaged(presented)
                    else LOCKED_PAGE)
            self._send(401, page.encode("utf-8"),
                       "text/html; charset=utf-8")
            return False
        if not has_cookie:
            self.close_connection = True
            self._error(
                401, "unauthorized",
                "This request carried no session for this GUI. Open the "
                "address printed in the terminal that is running app.py — "
                "it contains a key, and opening it is what hands this "
                "browser the cookie every API route requires. The key "
                "itself is not accepted here.", "unknown")
            return False
        return True

    def _read_body(self) -> dict:
        length = _as_int(self.headers.get("Content-Length"), 0) or 0
        if length > MAX_BODY_BYTES:
            raise GuiError(413, "too_large",
                           "That request body is too large for this GUI.")
        if length <= 0:
            return {}
        try:
            raw = self.rfile.read(length)
        except OSError as exc:
            raise GuiError(400, "bad_request",
                           f"The request body did not arrive ({exc}).") from None
        try:
            obj = json.loads(raw or b"{}")
        except ValueError:
            raise GuiError(400, "bad_json",
                           "The request body was not valid JSON.") from None
        if not isinstance(obj, dict):
            raise GuiError(400, "bad_json",
                           "The request body must be a JSON object.")
        return obj

    # -- dispatch -------------------------------------------------------
    def _handle(self, method: str):
        # A body we never read would leave the next request on a reused
        # connection misaligned, so any path that skips it closes instead.
        drained = False
        # One connection can carry many requests; nothing from the last one
        # may survive into this one.
        self._set_cookie = None
        raw_path, _, raw_query = self.path.partition("?")
        path = urllib.parse.unquote(raw_path).rstrip("/") or "/"
        query = {k: v[-1] for k, v in urllib.parse.parse_qs(raw_query).items()}
        try:
            # THE gate. Nothing below this line runs for a request that did
            # not pass it, which is the whole point of dispatching after it
            # rather than checking inside each route.
            if not self._authorize(method, path, query):
                return
            if method not in ("GET", "HEAD", "POST"):
                # No route uses these. BaseHTTPRequestHandler would answer
                # with a 501 HTML page, and would answer before the gate;
                # this is JSON, and it is behind the gate.
                return self._error(
                    405, "method_not_allowed",
                    f"This GUI answers GET and POST only; no route uses "
                    f"{method}.")
            if path in ("/", "/index.html") and method in ("GET", "HEAD"):
                return self._serve_page()
            if path == "/favicon.ico":
                return self._send(204, b"", "image/x-icon")
            if not path.startswith("/api/"):
                return self._error(404, "not_found",
                                   f"No page at {path}. The GUI is at /.")
            name = ROUTES.get((method, path))
            if name is None:
                other = [m for (m, p) in ROUTES if p == path]
                if other:
                    return self._error(
                        405, "method_not_allowed",
                        f"{path} answers {', '.join(sorted(other))}, not "
                        f"{method}.")
                return self._error(404, "not_found", f"No API route {path}.")
            if method == "POST":
                body = self._read_body()
                drained = True
            else:
                body = {}
            result = getattr(self.api, name)(query, body)
            return self._json(200, result)
        except GuiError as exc:
            return self._error(exc.status, exc.reason, exc.detail, exc.cause)
        except Exception as exc:
            # The whole point of this clause: the operator gets one sentence,
            # never a stack trace, and the trace goes to this process's stderr
            # where it belongs.
            traceback.print_exc()
            return self._error(
                500, "internal_error",
                f"{type(exc).__name__}: {exc}. The full detail is in the "
                f"terminal running app.py.")
        finally:
            if method not in ("GET", "HEAD") and not drained:
                self.close_connection = True

    def _serve_page(self):
        try:
            with open(self.page_path, "rb") as handle:
                payload = handle.read()
        except OSError as exc:
            message = (f"<!doctype html><meta charset=utf-8>"
                       f"<title>aicash operator</title>"
                       f"<body style='font:15px system-ui;padding:40px'>"
                       f"<h1>page.html is missing</h1><p>app.py could not read"
                       f" <code>{self.page_path}</code>: {exc}</p>"
                       f"<p>The API is still running; the interface is not.</p>")
            return self._send(500, message.encode("utf-8"),
                              "text/html; charset=utf-8")
        return self._send(200, payload, "text/html; charset=utf-8")

    def do_GET(self):
        self._handle("GET")

    def do_HEAD(self):
        self._handle("HEAD")

    def do_POST(self):
        self._handle("POST")

    # Every method this class answers goes through _handle, and therefore
    # through _authorize. There is deliberately no second entry point: a
    # do_* that did its own thing would be a route with no access policy.
    def do_PUT(self):
        self._handle("PUT")

    def do_PATCH(self):
        self._handle("PATCH")

    def do_DELETE(self):
        self._handle("DELETE")

    def do_OPTIONS(self):
        # Deliberately no CORS headers: the page is served by this same
        # server, so nothing it does is cross-origin, and an Access-Control
        # answer here would invite precisely the cross-site request
        # _origin_ok() exists to refuse.
        self._handle("OPTIONS")

    def send_error(self, code, message=None, explain=None):
        """The base class's own failures, in this GUI's error envelope.

        handle_one_request() calls this directly for a request line it
        cannot parse, a method with no handler, an over-long header block.
        Its default body is HTML; the contract here says every failure is
        {"error": {"reason", "detail"}}.
        """
        self.close_connection = True
        short, long = self.responses.get(
            code, ("error", "The request could not be handled."))
        detail = explain or long
        if message and message != short:
            detail = f"{message}. {detail}"
        try:
            self._error(int(code), _Components._reason(message or short),
                        str(detail))
        except Exception:  # the socket is already gone; nothing to report to
            pass



class GuiServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class GuiServer6(GuiServer):
    """The same server on an IPv6 loopback (``--host ::1``).

    socketserver takes the address family from the class, so binding ::1
    needs its own class rather than the same one: with AF_INET it fails
    with "Address family for hostname not supported", which main() would
    then report as a busy port.
    """
    address_family = socket.AF_INET6


def require_loopback(host: str, port: int = DEFAULT_PORT) -> int:
    """Resolve ``host`` and refuse anything the world could reach.

    This process can create money and can spend every wallet in the
    workdir. It authenticates now, and that changes nothing here: a
    capability cookie is a second lock on a door that should still not
    face the street. Binding to a routable address would put every one of
    these routes, and the mint's operator credential behind them, one
    guessable-or-stolen cookie away from everyone who can route a packet
    to this machine. There is no flag to relax this.
    """
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise SystemExit(f"cannot resolve --host {host!r}: {exc}")
    families = set()
    for info in infos:
        address = info[4][0].split("%")[0]
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            raise SystemExit(f"--host {host!r} resolved to something that is "
                             f"not an IP address ({address!r}).")
        if not parsed.is_loopback:
            raise SystemExit(
                f"refusing to bind {host!r} ({address}): it is not a loopback "
                f"address.\n"
                f"This GUI can mint money and spend every wallet in the "
                f"workdir. Its session cookie is a second lock, not a reason "
                f"to face the network, so it binds 127.0.0.1 only.\n"
                f"To reach it from another machine, forward the port over "
                f"ssh:  ssh -L {port}:127.0.0.1:{port} user@this-host")
        families.add(info[0])
    # IPv4 when the name offers it (localhost usually offers both), IPv6
    # only when that is all there is — ::1 asked for explicitly, say.
    return (socket.AF_INET if socket.AF_INET in families
            else socket.AF_INET6 if socket.AF_INET6 in families
            else socket.AF_INET)


def serve(port: int, workdir: str, host: str = "127.0.0.1", *,
          auth: bool = True) -> GuiServer:
    """One bound, authenticated server. ``auth=False`` is --no-auth."""
    family = require_loopback(host, port)
    # One handler class per server, so the workdir and the credentials
    # belong to the server rather than to the module: two GuiServers in one
    # process (the tests do exactly that) must not share an Api, a workdir,
    # or a key.
    bound = type("BoundHandler", (Handler,),
                 {"api": Api(workdir),
                  "auth": _Auth(enabled=auth),
                  "page_path": os.path.join(HERE, "page.html")})
    server_class = GuiServer6 if family == socket.AF_INET6 else GuiServer
    server = server_class((host, port), bound)
    server.auth = bound.auth
    return server


NO_AUTH_WARNING = """
  ############################################################
  ##                                                        ##
  ##   --no-auth:  THIS GUI IS SERVING WITH NO PASSWORD     ##
  ##                                                        ##
  ############################################################

  Every route is open to anything that can open a socket to this port:
  any other process running as any user on this machine, including
  something installed for an unrelated reason. Those routes mint money
  and spend every wallet in

      {workdir}

  This flag exists so automated tests can drive the server. It is not a
  convenience, and it is not a fix for a lost URL -- stop the GUI and
  start it again for a fresh one. Do not leave this process running.

  ############################################################
"""


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Local operator GUI for an aicash mint.")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help=f"port for this GUI (default {DEFAULT_PORT})")
    parser.add_argument("--host", default="127.0.0.1",
                        help="loopback address to bind; anything else is "
                             "refused with an explanation")
    parser.add_argument("--workdir", default=DEFAULT_WORKDIR,
                        help="where the mint database, keys, log and wallets "
                             f"live (default {DEFAULT_WORKDIR})")
    parser.add_argument("--no-auth", action="store_true",
                        help="serve with NO key and NO session cookie. For "
                             "automated tests only: it opens every route, "
                             "including the ones that mint money and spend "
                             "wallets, to every process on this machine.")
    args = parser.parse_args(argv)

    workdir = os.path.abspath(args.workdir)
    os.makedirs(os.path.join(workdir, "wallets"), exist_ok=True)
    try:
        httpd = serve(args.port, workdir, args.host, auth=not args.no_auth)
    except OSError as exc:
        if exc.errno in (errno.EADDRINUSE, errno.EACCES):
            why = ("something else is already listening there. Stop it, or "
                   "pass --port with a different number."
                   if exc.errno == errno.EADDRINUSE else
                   "this user is not allowed to bind that port. Pass --port "
                   "with a number above 1024.")
        else:
            why = ("that address could not be bound at all. 127.0.0.1 is the "
                   "default and always works; --host takes a loopback "
                   "address, not a hostname of this machine.")
        print(f"cannot bind {args.host}:{args.port}: {exc}\n{why}",
              file=sys.stderr)
        return 2

    if args.no_auth:
        # Loud, multi-line, on stderr, on every single startup. Nobody gets
        # to run this by accident and not notice.
        sys.stderr.write(NO_AUTH_WARNING.format(workdir=workdir))
        sys.stderr.flush()

    shown = args.host if ":" not in args.host else f"[{args.host}]"
    base = f"http://{shown}:{httpd.server_address[1]}/"
    # The key is printed here and nowhere else: not to a file, not to a log
    # line (log_message is silent), not into any response body. Losing it
    # means restarting the GUI, which is the intended cost.
    url = base if args.no_auth else base + "?k=" + httpd.auth.key
    print(f"\n  aicash operator GUI")
    print(f"  workdir   {workdir}")
    print(f"  wallets   {os.path.join(workdir, 'wallets')}")
    print(f"\n  OPEN      {url}   <- open this in a browser\n")
    if args.no_auth:
        print(f"  NO AUTHENTICATION (--no-auth). See the warning above. "
              f"Ctrl-C to stop.\n", flush=True)
    else:
        print(f"  That whole URL is the password: the key in it is generated "
              f"fresh each\n  start, kept only in memory, and exchanged once "
              f"for a session cookie. Do\n  not paste it into anything.\n")
        print(f"  It is still loopback only, and that still matters. The "
              f"cookie is a second\n  lock on a door that should not face "
              f"the street: these routes mint money\n  and spend every "
              f"wallet in the workdir. Ctrl-C to stop.\n", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping the GUI. A mint started from here keeps running; "
              "stop it from the page, or start the GUI again and press Stop.")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
