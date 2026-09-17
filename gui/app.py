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
  * ONE FRAMING RULE, AND IT IS NOT WRITTEN HERE. Where a request body
    ends -- and therefore whether the connection can carry another request
    afterwards -- is decided by ``aicash.mintapi.framing_verdict``, the
    single rule every HTTP server in this repository imports. This file
    applies it to EVERY request of EVERY method before any route runs, and
    keeps only its own status codes and error envelope. See the import
    below for why there is no local copy and why its absence is fatal.
  * NO TRACEBACK EVER REACHES THE PAGE. Every route returns JSON; failures
    return ``{"error": {"reason", "detail", "cause"}}`` with a detail a
    non-expert can act on. Not the exception's text either: an interpreter
    message is a trace by another name, and one of them carried the digit
    count of a number a caller chose.
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
import http.client
import inspect
import io
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

# ----------------------------------------------------------------------
# THE ONE FRAMING RULE, IMPORTED, NEVER COPIED
# ----------------------------------------------------------------------
# How long a request body is, and whether the connection can carry another
# request afterwards, is decided by ONE function for every HTTP server in
# this repository: aicash.mintapi.framing_verdict. This file does not own
# that question and does not answer it locally.
#
# Why it is imported instead of implemented here. The defect it closes was
# reported once against the mint, fixed there, found to have been fixed for
# a single SPELLING of one header name, and fixed again properly -- and
# then an independent verifier pointed the same twenty-five spellings at
# THIS server and found nineteen of them still working, on every POST route
# and on every GET route, because the fix lived twenty feet away and this
# file had no counterpart to it. A local copy is how that happens: two
# rules on one protocol drift, and the half that drifts is the smuggleable
# half. There is now one rule, one place, and a test that drives every
# server in the repository with identical bytes and asserts they reach
# identical framing decisions.
#
# THE IMPORT IS DELIBERATELY FATAL. There is no local fallback and no
# "degraded framing" mode: a server that cannot tell where a request body
# ends must not answer HTTP at all. Every other impl/ import in this file
# is wrapped (see _Components) because gui/mintctl.py and gui/walletops.py
# are separately-owned components whose absence is a 503 naming the file;
# the framing rule is not a component, it is the protocol, and a 503 is
# itself an HTTP response that would have to be framed.
# FRAMING_REASONS is re-exported deliberately, not imported by accident:
# it is the closed set of machine slugs a verdict can carry, and this
# server prints one of them in its refusal. A caller (or a test) mapping
# those exhaustively should read the set from here rather than grow a
# second list of its own -- a second list is how this defect started.
# ``_DeadlineRaw`` comes from the same module and for the same reason: it
# is the mint's whole-request wall-clock deadline, the transport hardening
# that stops a peer from resetting an IDLE timeout forever a byte at a
# time. It is IMPORTED, not re-implemented, because a second copy of a
# transport bound is exactly the shape of defect the paragraph above
# describes -- four rounds of this project were spent carrying one
# server's hardening to the next by hand, and each hand-carry left one
# server behind. It is private to aicash.mintapi (a leading underscore)
# and this file reads it anyway, deliberately: a private name shared by
# one import is one implementation, and a public name copied into four
# files is four. See Handler.setup below for what it is plugged into, and
# TestTheDripIsBoundedByAWallClock for the test that asserts this file
# defines no second copy of it.
try:
    from aicash.mintapi import (FRAMING_REASONS, _DeadlineRaw,
                                framing_verdict)
except Exception as _framing_import_error:   # pragma: no cover - see above
    raise ImportError(
        "gui/app.py cannot start: it needs aicash.mintapi.framing_verdict, "
        "the single request-framing rule shared by every HTTP server in "
        "this repository (the mint, the supervision profile, this GUI and "
        "the operator console). It was not importable from "
        + os.path.join(REPO, "impl") + " (" + repr(_framing_import_error)
        + "). This file deliberately keeps NO local copy of that rule: a "
        "second copy is exactly how the same smuggling defect came to be "
        "fixed in one server and left open in three. Restore the export, "
        "do not reimplement it here."
    ) from _framing_import_error


def framing_fields(verdict):
    """The four contract fields, off whatever ``framing_verdict`` returns.

    The shared rule's return TYPE is its owner's choice -- the pinned
    contract says "an object or tuple carrying at least length, framed,
    must_close, reason" -- so this reads the four fields without pinning
    the shape, and nothing else in this file touches the verdict object.
    It is an adapter, not a rule: it decides nothing about framing, it
    only unpacks an answer someone else computed.

      * ``length``     -- int | None; octets of body that can be trusted.
                          ``None`` means no trustworthy statement of length
                          exists, which is NOT the same as zero.
      * ``framed``     -- False when the body cannot be framed at all.
      * ``must_close`` -- True when the connection MUST be closed after
                          answering, whatever the answer is. That covers
                          both an unframable request and a framed one whose
                          declared octets this caller has already said it
                          will not read.
      * ``reason``     -- short machine slug from FRAMING_REASONS, for THIS
                          server's own vocabulary. It carries no HTTP
                          status and no error envelope, because the rule's
                          four callers use three different ones.
    """
    if hasattr(verdict, "framed"):       # an object, dataclass or NamedTuple
        return (verdict.length, bool(verdict.framed),
                bool(verdict.must_close), str(verdict.reason))
    if isinstance(verdict, dict):
        return (verdict["length"], bool(verdict["framed"]),
                bool(verdict["must_close"]), str(verdict["reason"]))
    length, framed, must_close, reason = verdict   # a plain tuple, in order
    return length, bool(framed), bool(must_close), str(reason)


#: What this server SAYS when the shared rule refuses to frame a request.
#: The rule returns a machine slug and no HTTP vocabulary at all; the
#: status code, the reason word and this sentence are this server's, and
#: the mint and the console each write their own from the same slug.
UNFRAMABLE_DETAIL = (
    "This GUI could not determine where that request's body ends, so it "
    "read none of it and closed the connection instead of guessing. The "
    "usual cause is a chunked body: send the body with a Content-Length "
    "header instead -- this server reads bodies by length and does not "
    "decode chunked transfer encoding. A duplicated, misspelled or "
    "unparseable Content-Length does the same thing. No field of this "
    "request was looked at, so nothing this route would have wanted is "
    "missing; the body was never read."
)

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
# THE IDLE BOUND ON ONE SOCKET CALL, and it is only that. socketserver
# applies it to the accepted socket, so it is a per-syscall timeout: a
# peer that sends -- or accepts -- one byte inside every window resets it
# forever, and the comment that used to sit here ("without it a client
# that sends Content-Length: 500 and then four bytes pins a handler thread
# forever") was wrong in the one way that mattered: a client that sends
# four bytes and then one more every two seconds pinned a handler thread
# anyway.
#
# WHAT IT DOES NOT BOUND, said plainly here because two comments in this
# file used to claim it did:
#   * It does not bound a READ. REQUEST_DEADLINE_S does, through
#     _DeadlineRaw, and it is the SMALLER of the two, so it is the
#     operative bound on every read this server performs.
#   * It does not bound an IDLE KEEP-ALIVE SOCKET between requests either.
#     handle_one_request arms the deadline BEFORE the blocking read of the
#     next request line, so a kept socket that goes quiet is closed at
#     REQUEST_DEADLINE_S. MEASURED: a socket that took a 200 and then said
#     nothing was answered 408 and closed at 10.0s, not at 30.
#   * It does not bound a WRITE either, and that was the live hole. It is
#     per sendall, so N pipelined responses drained slowly are N fresh
#     windows: MEASURED at 200 seconds and still running on one socket
#     carrying 2000 pipelined `GET /` with a peer reading ~10 KB/s.
#     RESPONSE_BUDGET_S below is what bounds that, cumulatively, per
#     CONNECTION -- which is the only scope a pipeline cannot multiply.
#
# What is left for it is the floor under both budgets: no single syscall
# blocks longer than this even when a budget has more room than that left.
REQUEST_TIMEOUT_S = 30
# THE WALL-CLOCK BOUND ON ONE WHOLE REQUEST -- request line, headers and
# body together -- enforced under the buffered reader by the mint's
# _DeadlineRaw (see Handler.setup).
#
# WHY TEN SECONDS HERE WHERE THE MINT CHOSE THIRTY. The mint's budget is
# sized against the ~77 KiB of a full max_batch exchange arriving over
# whatever link a mint is reachable on, which is a real network. This
# server has no network in its read phase at all: require_loopback()
# refuses to bind anything the world can reach, so every request it will
# ever read is written by a process on this same machine, and the largest
# body it will read is MAX_BODY_BYTES. Ten seconds against a megabyte is a
# floor of ~100 KiB/s, which loopback beats by three or four orders of
# magnitude and which no drip comes close to.
#
# And the ceiling is not the socket's, it is the PAGE's. page.html aborts
# its own fetch and shows its own message instead of whatever this server
# determined, so a request whose READ alone outlasts that is a request
# whose answer nothing will ever read. Half the page's patience for
# getting the question in, half for answering it, is the split that keeps
# every bound route below reachable.
#
# AND THE PAGE'S PATIENCE IS NOT ONE NUMBER, which the sentence that used
# to stand here got wrong. page.html declares
# `TIMEOUTS = {default: 20000, start: 90000, stop: 70000}`: nineteen of
# the twenty-one routes abort at PAGE_ABORT_S, and /api/mint/start and
# /api/mint/stop wait 90s and 70s because a supervised process transition
# is slow to ANSWER, not slow to ASK -- their request bodies are a few
# dozen bytes over loopback. So the budget is sized against the SHORTEST
# of the three, which is the default, and the two longer ones are covered
# a fortiori. The test reads all three out of page.html and pins the
# budget against the minimum, so a page that shortens any of them fails
# here rather than drifting.
#
# It is also what now bounds an idle keep-alive connection: the deadline is
# armed in handle_one_request BEFORE the request line is read, so a peer
# that connects and says nothing is closed at ten seconds rather than at
# REQUEST_TIMEOUT_S. Ten is comfortably above the page's 4s poll interval,
# which is the only legitimate thing that waits on an idle socket here.
REQUEST_DEADLINE_S = 10.0
# THE WALL-CLOCK BOUND ON THE WRITE SIDE OF ONE CONNECTION -- cumulative
# seconds spent inside socket writes, across every response this
# connection sends, enforced by _BudgetedWriter.
#
# WHY CUMULATIVE AND WHY PER CONNECTION, because both halves are the
# finding. `timeout` above is per sendall, so it is a window and not a
# budget, and a pipeline multiplies windows: MEASURED against a live
# serve(), one socket carrying 2000 pipelined `GET /` with a valid session
# cookie (226 KB of request) and a peer draining ~10 KB/s -- inside the
# 30s window, so every sendall made progress -- held its handler thread
# and its fd past 200 SECONDS and 2,006,461 delivered bytes before the
# measurement was capped. Unauthenticated, 4000 pipelined 401s held 20.0s.
# GuiServer is a ThreadingHTTPServer with no connection or thread cap, so
# N such sockets are N parked threads, and the cost to mount it is one
# socket and a slow reader.
#
# A per-RESPONSE budget would not have closed it: the peer chooses how
# many responses it queues, so any per-response bound is multiplied by a
# number the peer picks. The budget therefore belongs to the connection,
# and it counts time spent IN a write rather than wall time since the
# connection opened -- because the page's own connection is long-lived on
# purpose (a 4-second poll reusing one socket) and must never be torn down
# for being old. A connection that is answering normally spends
# microseconds here: the writes go into the loopback socket buffer.
#
# TEN SECONDS for the same reason the read side gets ten: half the page's
# shortest patience for getting the answer out, the other half having been
# spent getting the question in. The operator page is ~261 KiB, so ten
# seconds is a floor of ~26 KiB/s against a browser on this same machine,
# which loopback beats by orders of magnitude.
#
# WHAT A PEER SEES WHEN IT RUNS OUT: nothing more. The budget expires
# inside a write, `_send` turns that into a closed connection rather than
# an exception, and no second response is composed onto a socket that
# already carries a partial one. There is no way to report it -- the
# report would be another write, on the socket that just proved it cannot
# take one.
RESPONSE_BUDGET_S = 10.0
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
# THE BASELINE GOES ON A COMMAND LINE. /api/mint/start passes this value
# to MintControl.start, which spawns run_mint.py with `--model-class
# <value>` in its argv -- so an unbounded string here is an unbounded
# argv entry in a child process, and a five-thousand-character one was
# accepted and really spawned. §4.1 makes this field the DEFINITION of
# the unit and immutable for the life of a mint_id, which is a strong
# argument for a short, deliberate, printable name and none at all for a
# kilobyte of anything. 128 is far above every real value (`baseline-v1`
# is eleven characters) and far below anything that can strain an argv.
# Control characters are refused outright: they cannot be meant, they
# cannot be read back off a terminal, and they would ride into the
# child's command line and into the descriptor this mint serves forever.
BASELINE_MAX = 128
BASELINE_RE = re.compile(
    r"^[\x21-\x7e][\x20-\x7e]{0,%d}$" % (BASELINE_MAX - 1))


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

#: TWO STATES THAT ARE NOT ANSWERS, and they are not the same state.
#: ``NOT_APPLICABLE`` is "the question does not arise" -- a ``receive``
#: row has no delivery, so it has no recipient and no attempt either.
#: ``UNDETERMINED`` is "it does arise and nothing here answers it" -- a
#: payment WAS made and this server has no row saying who for. Writing
#: one string for both is what made a recovered payment and a row that
#: never had a delivery identical on the wire; ``delivery`` has told them
#: apart since round 4 and the other two fields now do it the same way.
#:
#: WHICH QUESTION ARISES DEPENDS ON THE FIELD, not only on the row. A
#: ``pay`` that did NOT commit moved no money, so it has no delivery and
#: all three delivery fields are NOT_APPLICABLE -- but somebody asked for
#: that payment and named somebody or deliberately named nobody, so
#: ``recipient_kind`` is never NOT_APPLICABLE on it. walletops.py fills
#: it from the row it wrote when the payment was interrupted; this file
#: relays it and does not re-derive it.
#: See gui/walletops.py, which declares the same two and is where these
#: values are produced.
NOT_APPLICABLE = ""
UNDETERMINED = "unknown"

#: What the recipient field of a payment record means. "unknown" is a
#: real member: nothing was recorded, which is not the same as "no
#: recipient" (that is ``bearer``) and not the same as NOT_APPLICABLE
#: (no payment, so no recipient field to fill).
RECIPIENT_KINDS = ("wallet", "bearer", "unknown")

#: DID THE PAYING WALLET EVER TRY? Relayed from walletops.py, never
#: re-derived here. It is what tells apart the situations that all read
#: ``delivery: "unknown"`` -- a payment never delivered from one that was
#: attempted and lost -- and those send an operator to different places.
#: "unknown" is the third value and means nothing was recorded.
DELIVERY_ATTEMPTS = ("not_attempted", "attempted", "unknown")


def clean_attempt(value, default: str = NOT_APPLICABLE) -> str:
    """Coerce into DELIVERY_ATTEMPTS, relaying which KIND of non-answer.

    Two non-answers, and they are not interchangeable:

    * PRESENT but unreadable -- the component DID answer and this build
      cannot read the word. The payment exists and had an attempt or did
      not; nothing here says which, so UNDETERMINED.
    * ABSENT or blank -- the component said nothing at all, and what that
      means depends on the endpoint, so the CALLER says. On a history
      page a row may be a receive, where the question does not arise, so
      the default is NOT_APPLICABLE; on an endpoint that lists nothing
      but payments the question always arises and the caller passes
      UNDETERMINED.

    Both used to collapse into "", which told an operator a payment had
    no delivery to speak of because a newer walletops.py used a word this
    build has not learnt.
    """
    text = "" if value is None else str(value).strip()
    if text in DELIVERY_ATTEMPTS:
        return text
    return default if not text else UNDETERMINED


def clean_recipient_kind(value, default: str = NOT_APPLICABLE) -> str:
    """Coerce into RECIPIENT_KINDS, by the same rule as clean_attempt.

    A component that answers "sky-writing" HAS answered: the payment had
    a recipient of some kind and this server cannot read which. That is
    undetermined, and reporting it as "" -- the string this wire uses for
    "there was no payment here" -- is the one reading that is certainly
    wrong.
    """
    text = "" if value is None else str(value).strip()
    if text in RECIPIENT_KINDS:
        return text
    return default if not text else UNDETERMINED


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


#: The longest a message this file did NOT write may be when it leaves in
#: a response body. Everything this server composes itself is a sentence
#: and fits; what does not fit is a message from somewhere else with a
#: caller's own input quoted inside it -- an exception's text, a
#: component's relayed complaint, the base class's echo of a 64 KiB
#: request line. A money server should not reflect a kilobyte of whatever
#: it was sent back out of an error body, so a relayed message is cut and
#: says that it was cut. 1000 is far above every real message here (the
#: longest this file composes is under 500) and far below an amplifier.
_RELAYED_DETAIL_MAX = 1000


def _bounded(text: str, limit: int = _RELAYED_DETAIL_MAX) -> str:
    """Cut a message this file did not compose. See _RELAYED_DETAIL_MAX."""
    text = str(text)
    if len(text) <= limit:
        return text
    return text[:limit] + " (truncated)"


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
            # _bounded: the component's sentence may quote what the caller
            # sent it (a token string, a payee label), and a relayed
            # message is not this file's to vouch for the length of.
            return GuiError(400, self._reason(reason),
                            _bounded(str(detail) or str(exc)), cause)
        mint_err = getattr(self._mintctl_mod, "MintControlError", None)
        if mint_err is not None and isinstance(exc, mint_err):
            return GuiError(400, "mint_control",
                            _bounded(str(exc) or type(exc).__name__))
        return GuiError(
            500, "component_error",
            _bounded(f"{what} raised {type(exc).__name__}: {exc}"))

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


#: A whole number a caller may state as a STRING, bounded in both shape
#: and LENGTH. The length half is the fix: the old pattern was
#: ``[+-]?[0-9]+``, which bounds the shape and nothing else, so a caller
#: could send five thousand digits and ``int()`` raised CPython's
#: int/str conversion ValueError (4300 digits) straight out of the route
#: and onto the blanket handler -- a 500 whose body carried the
#: interpreter's own message, including the digit count the caller chose,
#: and a traceback on this process's stderr. Live on /api/mint/issue for
#: both of its numeric fields and on /api/mint/start for four of its own.
#: Nineteen digits is above every bound any route here enforces
#: (MAX_AMOUNT_MC is sixteen, a port is five, a count is three), so
#: nothing a caller can legitimately mean is refused by the length cap;
#: what it refuses is a number that was never going to be accepted and
#: only ever chose how expensively it would be rejected.
_DIGITS_RE = re.compile(r"[+-]?[0-9]{1,19}")


def _strict_int(value, default=None):
    """Strict int for CALLER INPUT. Never raises, for any input.

    ``default`` is the answer when the field is ABSENT and nothing else.
    Anything a caller actually sent that is not exactly a whole number is
    ``None``, which every caller turns into a 400 -- never a truncation
    (an amount of 12.7 is a mistake, not twelve) and never a silent
    substitution of the route's default. Those are different answers and
    this used to give the same one to both: ``{"count": "9" * 5000}``
    would have issued ONE token rather than saying no, which on a route
    that creates money is the wrong way round.

    The string branch is bounded in length as well as in shape; see
    _DIGITS_RE. A Python ``int`` that arrived already parsed (JSON
    numbers become ints before this is called) is returned whatever its
    magnitude -- the routes' own range checks refuse it with a sentence,
    and no conversion happens here that could raise. A 5,000-DIGIT JSON
    number literal never reaches this function at all: json.loads raises
    ValueError on it and _parse_body answers ``bad_json``.
    """
    if value is None:
        return default
    if isinstance(value, bool):
        # Present, and not a number. `True` is an int to Python and is not
        # one to anybody sending JSON.
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if value.is_integer() else None
    if isinstance(value, str) and _DIGITS_RE.fullmatch(value.strip()):
        return int(value.strip())
    return None


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
        except http.client.HTTPException as exc:
            # THE OTHER HALF OF THE CONSOLE'S EXCEPT TUPLE, and it was left
            # behind when RecursionError was copied out of it. The tuple at
            # mint_console.py:1252 is (OSError, ValueError, RecursionError,
            # http.client.HTTPException) and every member is there for ONE
            # stated reason: whatever is listening on the mint port is not
            # necessarily the mint. http.client.HTTPException is NOT an
            # OSError -- it is a plain Exception -- so with only the three
            # clauses above, four shapes of reply from a rogue process on
            # that port walked out of here into the blanket handler in
            # _handle and became a bare 500 with a traceback on the
            # operator's terminal, on /api/mint/descriptor,
            # /api/token/status and /api/mint/issue:
            #
            #   * BadStatusLine      -- `GARBAGE\r\n\r\n` on the socket;
            #   * LineTooLong        -- a 200 KB header line;
            #   * HTTPException      -- "got more than 100 headers";
            #   * IncompleteRead     -- raised by `response.read()` INSIDE
            #     the with-block above, which is why the read is in this
            #     try and not after it: a declared length the peer never
            #     finished sending.
            #
            # bad_mint_response and not mint_unreachable: octets came back.
            # Something on that port took the request and answered it with
            # bytes this server cannot read as HTTP, and on the issue route
            # that difference is money -- "could not reach the mint" reads
            # as "nothing was created", which this process cannot know.
            #
            # ORDER MATTERS AND IS DELIBERATE. http.client.RemoteDisconnected
            # inherits from BOTH ConnectionResetError and BadStatusLine, so
            # it is caught by the OSError clause ABOVE this one and keeps
            # the mint_unreachable it has always had. That is the honest
            # word for it: the peer closed with no answer at all.
            raise GuiError(
                502, "bad_mint_response",
                f"The mint port at {base} answered with something this GUI "
                f"could not read as an HTTP response "
                f"({type(exc).__name__}), so what it did with the request "
                f"is undetermined.", "unknown") from None
        try:
            obj = json.loads(payload or b"{}")
        except (UnicodeDecodeError, ValueError, RecursionError):
            # It ANSWERED -- badly. Saying "the mint did not answer" here
            # would contradict this very sentence, and this server has no
            # idea what the mint did with the request, so: undetermined.
            #
            # RecursionError for the same reason the console catches it on
            # its own client socket: whatever is listening on the mint port
            # is not necessarily the mint, and a nested-array reply deep
            # enough to blow the C parser's stack is a stack overflow
            # reached from another process. Uncaught it is not a
            # bad_mint_response at all -- it is a bare 500 out of the
            # blanket handler, blaming this GUI for what the thing on the
            # mint port sent.
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
        if not BASELINE_RE.fullmatch(baseline):
            # This string becomes an argv entry in a spawned mint (see
            # BASELINE_MAX) and, under §4.1, the permanent definition of
            # what one millicredit means for that mint_id. Both of those
            # are reasons to know its shape before the subprocess exists,
            # not after.
            raise GuiError(
                400, "bad_request",
                f"Baseline model class must be 1 to {BASELINE_MAX} printable "
                f"characters with no control characters and no leading "
                f"space; it is passed to the mint on its command line and, "
                f"once that mint has issued a token, it can never be "
                f"changed. baseline-v1 is the usual value.")
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
        # `or 200` used to stand here, which meant an unusable ?lines=
        # silently became the default -- including a five-thousand-digit
        # one, whose only other outcome was an interpreter ValueError out
        # of _strict_int. A number nobody can honour is refused in a
        # sentence; an ABSENT ?lines= is still the default, because not
        # asking is not the same as asking for nonsense.
        lines = _strict_int(query.get("lines"), 200)
        if lines is None:
            raise GuiError(400, "bad_request",
                           "lines must be a whole number; 1 to 2000 are "
                           "honoured and anything outside that is clamped.")
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
                        # "" means the question does not arise; "unknown"
                        # means it arose and nobody knows the answer.
                        # Those are different rows and this layer must not
                        # merge them. On a `pay_pending` / `pay_failed`
                        # row the two RECIPIENT fields are answered and
                        # the three DELIVERY fields are "": no money
                        # moved, so there was no delivery -- but it was
                        # still a payment and it was still for somebody.
                        "recipient": str(row.get("recipient", "")),
                        "recipient_kind": clean_recipient_kind(
                            row.get("recipient_kind")),
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
                "recipient_kind": clean_recipient_kind(
                    raw.get("recipient_kind"), UNDETERMINED),
                "delivery": clean_delivery(raw.get("delivery"), "unknown"),
                "delivery_cause": (
                    "" if not raw.get("delivery_cause")
                    else clean_cause(raw.get("delivery_cause"))),
                "delivery_attempt": clean_attempt(
                    raw.get("delivery_attempt"), UNDETERMINED),
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
                             "recipient_kind": clean_recipient_kind(
                                 item.get("recipient_kind"), UNDETERMINED),
                             "delivery": clean_delivery(item.get("delivery"),
                                                        "unknown"),
                             "delivery_cause": (
                                 "" if not delivery_cause
                                 else clean_cause(delivery_cause)),
                             "delivery_attempt": clean_attempt(
                                 item.get("delivery_attempt"), UNDETERMINED),
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
                # THE SAME FIVE RECORD FIELDS the payments above carry,
                # relayed by the same rules. history() prints a row for
                # each of these op_ids and a reader matches the two by
                # op_id; a recovered payment that reads "meant for bob,
                # nothing handed over" there and carries no recipient at
                # all here is one payment answering differently in two
                # panels, which is the defect this whole endpoint exists
                # to have stopped.
                cause = item.get("delivery_cause")
                recovered_ops.append({
                    "op_id": str(item.get("op_id", "")),
                    "amount_mc": _as_int(item.get("amount_mc")),
                    "recipient": str(item.get("recipient", "")),
                    "recipient_kind": clean_recipient_kind(
                        item.get("recipient_kind"), UNDETERMINED),
                    # Defaulted to "unknown", exactly as the payments
                    # list two blocks up defaults it: every item on this
                    # endpoint is a payment, so "" -- the question does
                    # not arise -- is true of none of them.
                    "delivery": clean_delivery(item.get("delivery"),
                                               "unknown"),
                    "delivery_cause": ("" if not cause
                                       else clean_cause(cause)),
                    "delivery_attempt": clean_attempt(
                        item.get("delivery_attempt"), UNDETERMINED)})
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


class _BudgetedWriter(io.BufferedIOBase):
    """The handler's write side, under a CUMULATIVE wall-clock budget.

    THE MIRROR OF ``_DeadlineRaw``, ONE DIRECTION OVER, and it exists
    because the round that installed the read-side deadline left the write
    side with the exact defect it had just closed. ``Handler.timeout`` is
    applied by socketserver to the whole socket, so it bounds one
    ``sendall`` -- and a peer that accepts a few kilobytes inside every
    window gets a fresh window for every response. MEASURED against a live
    ``serve()``: one socket, 2000 pipelined ``GET /`` with a valid session
    cookie, peer draining ~10 KB/s, handler thread and fd still held at
    200 seconds and 2,006,461 bytes when the measurement was capped.

    WHY THIS IS NOT THE MINT'S CLASS, and it is a real difference rather
    than a second copy of the same thing. ``_DeadlineRaw`` bounds ONE
    REQUEST's reads against an absolute instant, and it is imported from
    ``aicash.mintapi`` precisely so this file grows no second wall clock
    for that. This bounds a CONNECTION's writes against an accumulated
    total, which is a different quantity for a different reason: the peer
    chooses how many responses it queues, so any per-response bound is
    multiplied by a number the peer picks, while the page's own connection
    is long-lived on purpose and must not be torn down for being old. What
    the two share is the rule that a window is not a budget, and nothing
    else. It defines no read method at all, which is the property the
    no-second-copy test asserts.

    Time spent is charged whether the write succeeded or failed, and the
    idle timeout is restored afterwards so the read side is never left
    running under whatever sliver of the write budget remained.

    ``time.monotonic`` here is transport bookkeeping and nothing else: no
    value computed in this class is ever served, signed or persisted.
    """

    def __init__(self, sock, handler):
        self._sock = sock
        self._handler = handler

    def writable(self) -> bool:
        return True

    def fileno(self) -> int:
        # socketserver's own _SocketWriter offers this; wsgiref and
        # anything else that asks the response stream for a descriptor
        # would get an UnsupportedOperation without it.
        return self._sock.fileno()

    def write(self, payload):
        handler = self._handler
        idle = handler.timeout
        budget = handler.write_budget
        if budget is None:
            window = idle
        else:
            left = budget - handler.write_spent
            if left <= 0:
                # Raised BEFORE the syscall, so an exhausted budget cannot
                # buy one more window by trying. TimeoutError is an
                # OSError, which is what _send turns into a closed
                # connection rather than a second response.
                raise TimeoutError("response budget exhausted")
            window = left if idle is None else min(idle, left)
        self._sock.settimeout(window)
        started = time.monotonic()
        try:
            self._sock.sendall(payload)
        finally:
            handler.write_spent += time.monotonic() - started
            self._sock.settimeout(idle)
        with memoryview(payload) as view:
            return view.nbytes


class Handler(BaseHTTPRequestHandler):
    api: Api = None            # set by serve()
    auth: _Auth = None         # set by serve(); None fails every request shut
    page_path: str = ""
    # One request's pending Set-Cookie. Set in exactly one place
    # (_authorize, on a good key) and emitted by _send. A class-level
    # default matters: send_error() can answer before _handle() runs.
    _set_cookie = None
    #: Whether a FINAL response (>= 200) has already gone out for the
    #: request being handled. Read by the handle_one_request backstop,
    #: which must never write a second response onto a socket that already
    #: carries one -- that is the desync everything in this file exists to
    #: prevent. A 1xx does NOT set it: an interim status is not an answer,
    #: and counting it as one is how the console's own backstop became
    #: suppressible (mint_console.py, `_send`). Class-level default because
    #: send_error() can answer before handle_one_request assigns it.
    _answered = False
    server_version = "aicash-gui"
    sys_version = ""
    # THE IDLE BOUND ON ONE RECV, and nothing more. socketserver's
    # StreamRequestHandler.setup() applies it to the accepted socket, so
    # every recv gets its own fresh window and a peer that sends ONE BYTE
    # inside every window resets it forever. Measured on this server
    # before request_timeout below existed: one byte every two seconds
    # into the header block, no credential, no complete request line, held
    # a handler thread and a file descriptor past 100 seconds and would
    # have held it indefinitely -- and GuiServer is a ThreadingHTTPServer,
    # which caps neither connections nor threads, so N such sockets are N
    # parked threads.
    #
    # WHAT IT STILL DOES, now that a budget stands on either side of it.
    # It is the ceiling on ONE syscall and nothing else: no single recv and
    # no single sendall blocks longer than this, even when the budget
    # governing that side has more room than that left. It is the
    # pre-existing value and it is deliberately the LARGEST of the three,
    # so it never pre-empts a budget.
    #
    # IT IS NOT THE BOUND ON A WRITE. That sentence stood here, and on a
    # blocked write it was false in exactly the way this round was convened
    # to remove: per sendall is a window, and a pipeline of responses
    # drained slowly is as many fresh windows as the peer cares to queue --
    # measured at 200 seconds and still running. write_budget below is the
    # bound, it is cumulative, and it belongs to the connection.
    #
    # IT IS NOT THE BOUND ON ANY READ EITHER, and the ordering is the
    # opposite of the mint's on purpose: the mint's deadline is LONGER than
    # its idle timeout, so both bind, whereas here the deadline is shorter
    # and is always the operative one on the read side, including the wait
    # for the next request line on an idle keep-alive socket. That is the
    # intended division of labour and TestTheDripIsBoundedByAWallClock
    # asserts it on live sockets, so a later edit cannot quietly invert it
    # and leave the header phase covered by an idle timeout again.
    timeout = REQUEST_TIMEOUT_S
    # THE WALL-CLOCK BOUND ON ONE WHOLE REQUEST. Armed in
    # handle_one_request, enforced by _DeadlineRaw on every recv. A class
    # attribute rather than module state so a deployment -- or a test that
    # has to watch a drip die -- overrides it by subclassing.
    request_timeout = REQUEST_DEADLINE_S
    #: Absolute monotonic instant this request must be read by. None
    #: between requests, and a class-level default because setup() runs
    #: before handle_one_request assigns it.
    request_deadline: float | None = None
    #: THE WRITE-SIDE BUDGET, in cumulative seconds spent inside socket
    #: writes for the whole CONNECTION. A class attribute for the same
    #: reason request_timeout is one: a deployment -- or a test that has to
    #: watch a slow drain die -- overrides it by subclassing rather than by
    #: reaching into module state. None disables it, which nothing shipped
    #: does; it exists so a test can prove the budget is what ends the
    #: connection by removing it and watching the hold return.
    write_budget: float | None = RESPONSE_BUDGET_S
    #: Seconds this connection has already spent inside socket writes.
    #: Reset in setup(), which runs once per connection and not once per
    #: request -- per request is the scope a pipeline multiplies.
    write_spent = 0.0
    # HTTP/1.1 so the page's 4-second poll reuses one connection instead of
    # opening three. Every response here carries an exact Content-Length,
    # and any path that answers without draining a request body closes the
    # connection rather than leave the next read misaligned.
    protocol_version = "HTTP/1.1"

    def setup(self):
        """Put a wall clock under BOTH sides of this connection.

        The read side gets the mint's deadline; the write side gets this
        file's cumulative budget. Neither side of a socket is bounded by a
        per-syscall timeout, and this round found that out twice: once on
        the read side, and once, after the read side was fixed, on the
        write side that a comment claimed ``timeout`` covered.

        socketserver has just made ``rfile = connection.makefile('rb',
        rbufsize)``. This swaps in the same buffered reader over
        ``_DeadlineRaw``, which gives every recv the SMALLER of the idle
        timeout and the time left on ``request_deadline`` and raises
        before the syscall once that is gone.

        UNDER the BufferedReader and not around it, which is the whole
        trick and the reason this is imported rather than re-derived:
        BufferedReader's own loops -- ``readline`` over the header block,
        ``read(n)`` over a body -- come back through ``readinto`` for
        every refill, so each refill re-checks the clock. Wrapping the
        BufferedReader instead would have set one timeout for one
        blocking read and bounded nothing. It is also the only position
        that covers the HEADER phase as well as the body, and the header
        phase is where the measured drip lived: no credential, no route,
        no framing decision yet, and a thread held past 100 seconds.

        Closing the original reader only drops its socket refcount -- it
        does not close the fd -- so connection.close() stays honest.

        A TimeoutError raised from down there is a socket.timeout, which
        BaseHTTPRequestHandler.handle_one_request already turns into a
        silent close for the header phase, and which _read_body_bytes
        already catches (it catches OSError, and TimeoutError is one) and
        turns into this server's own framed 400 for the body phase. So
        nothing new has to be caught for this to be answered properly.
        """
        super().setup()
        original = self.rfile
        self.rfile = io.BufferedReader(
            _DeadlineRaw(self.connection, self),
            io.DEFAULT_BUFFER_SIZE if self.rbufsize <= 0 else self.rbufsize)
        original.close()
        # AND THE SAME TREATMENT ON THE WAY OUT. socketserver has also just
        # made the write side (a _SocketWriter, whose write() is one
        # sendall under the socket's own timeout). _BudgetedWriter charges
        # every write against one cumulative per-connection budget, which
        # is the only scope a pipeline of responses cannot multiply. Here
        # and not in handle_one_request BECAUSE the budget is the
        # connection's: setup() runs once per connection, and resetting
        # write_spent per request would hand the peer the multiplier back.
        outgoing = self.wfile
        self.wfile = _BudgetedWriter(self.connection, self)
        self.write_spent = 0.0
        try:
            outgoing.close()
        except OSError:                 # pragma: no cover - already gone
            pass

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
        # A RESPONSE THIS SERVER WILL NOT FRAME MUST SAY SO ON THE WIRE.
        # protocol_version is HTTP/1.1, so a peer that reads a complete
        # Content-Length and sees no Connection header is entitled to send
        # another request down the same socket -- and every path here that
        # answers a request whose body it declined to read has already set
        # close_connection. Announcing it turns a silent EOF into the one
        # thing an intermediary can act on, which is the whole difference
        # between hanging up and desynchronising.
        will_close = bool(self.close_connection)
        if code >= 200:
            # A final response. See _answered: 1xx is deliberately not one,
            # and nothing in this file sends 1xx through here anyway.
            self._answered = True
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        if code != 204:  # a 204 has no body by definition
            self.send_header("Content-Length", str(len(payload)))
        if will_close:
            # send_header("Connection", "close") also sets close_connection,
            # which it already is; this is the announcement, not the switch.
            self.send_header("Connection", "close")
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
        # EVERY OCTET THIS SERVER PUTS ON THE SOCKET GOES THROUGH HERE, and
        # a failure putting it there is a fact about the PEER, not a bug in
        # this file. end_headers() is where the header block is flushed and
        # the line below is where the body goes, so both are inside the
        # same clause.
        #
        # WHAT THIS REPLACED, and it was measured. The two-exception clause
        # that used to sit on the body write alone let a write TIMEOUT --
        # a peer that stopped reading -- escape into _handle's blanket
        # `except Exception`, which printed a traceback on the operator's
        # terminal and then composed a 500 onto a socket that already
        # carried a partial response. That is a second response after a
        # first, which is the desync everything in this file exists to
        # prevent, and it bought the peer a second full window: 65.0
        # seconds of hold on a 400-deep pipeline where the first write had
        # already spent one.
        #
        # _answered is already True (set above, before send_response), so
        # the backstops upstream will not try to answer either. There is
        # nothing to report to and nothing to report: the report would be
        # another write, on the socket that just proved it cannot take one.
        try:
            self.end_headers()
            if getattr(self, "command", None) != "HEAD":
                # getattr: send_error() can reach here before parse_request
                # has set `command`, and an AttributeError between
                # end_headers() and the write is a declared Content-Length
                # with no body after it -- a client reading by length then
                # waits for octets that are never coming.
                self.wfile.write(payload)
        except OSError:
            # BrokenPipeError, ConnectionResetError and TimeoutError (the
            # exhausted write budget) are all OSError, and all three mean
            # the same thing here: this socket will not carry the rest of
            # this response, so it carries nothing further at all.
            self.close_connection = True

    def _refuse_transport(self, code: int, reason: str, detail: str) -> None:
        """Answer a request that never became a call, and hang up.

        ONE PLACE, so the refusals below cannot drift into four spellings
        of "close and answer 400". This is the mint's funnel
        (impl/aicash/mintapi.py, ``_Handler._refuse_transport``), carried
        here for the reason the mint wrote down when it added it: three
        hand-written refusal sites in two methods is the shape this round
        exists to remove, and this file had exactly that -- two sites, each
        spelling ``close_connection = True`` and then ``_error`` by hand,
        with a third and a fourth about to be added by this round.

        THE THREE THINGS EVERY TRANSPORT REFUSAL NEEDS, and the reason they
        belong together rather than at each site:

        * ``close_connection``. Nothing here was dispatched, so nothing
          here knows where the next request line would start.
        * A version that can carry a status line. ``parse_request`` sets
          ``request_version`` to HTTP/0.9 before it reads anything, and in
          0.9 ``send_response``, ``send_header`` and ``end_headers`` are
          all no-ops -- so a refusal composed while that is still the
          version goes out as a NAKED BODY with no status line at all,
          which is the precise defect this round is closing. Every refusal
          that reaches here is a refusal this server could not attribute to
          a version, so all of them are answered in HTTP/1.1.
        * ``requestline`` and ``command``, which ``send_response`` ->
          ``log_request`` and ``_send`` read. A refusal that fires before
          ``parse_request`` set them would raise AttributeError inside the
          error path, and an AttributeError inside an error path is
          answered with nothing at all.
        """
        self.close_connection = True
        if getattr(self, "requestline", None) is None:
            self.requestline = ""
        if not getattr(self, "command", None):
            # _send asks whether this was a HEAD. "Not HEAD" is the answer
            # that emits the body about to be framed.
            self.command = ""
        if getattr(self, "request_version", "HTTP/0.9") == "HTTP/0.9":
            self.request_version = "HTTP/1.1"
        self._error(code, reason, detail)

    def _json(self, code: int, obj):
        try:
            text = json.dumps(obj, default=str)
        except (TypeError, ValueError, RecursionError):
            # RecursionError is the third member of the family, here for
            # the same reason it is on the two readers: the encoder
            # recurses too. This is the last place in the file that could
            # turn a bad document into NO RESPONSE AT ALL -- _json is what
            # the blanket handler in _handle calls to report a failure, so
            # an exception raised HERE has nowhere left to be reported and
            # leaves the handler with the request unanswered. The fallback
            # below encodes a fixed, flat dict, which cannot raise.
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

    def _read_body_bytes(self, length) -> bytes:
        """Read exactly the octets the SHARED framing rule vouched for.

        ``length`` comes from ``framing_verdict`` in ``_handle`` and from
        nowhere else. This method does not look at a header, does not ask
        whether one is spelled ``Transfer-Encoding``, and does not compute
        a length of its own -- it did all three, and that is precisely the
        defect: ``headers.get("Transfer-Encoding")`` is a question about
        ONE SPELLING, and nineteen other spellings walked past it (a
        space before the colon, an underscore, a dot, no separator at all,
        a second Content-Length, a ``+`` sign) and were read as a body of
        zero octets by ``_as_int(self.headers.get("Content-Length"), 0)``.
        The unread octets then stayed on a keep-alive socket and were
        framed as the next request line: one request in, two responses
        out. The mint met the same defect first and closed it by deriving
        the verdict from the length it can COMPUTE rather than from a
        header it can NAME; this server now imports that rule instead of
        having an opinion.

        ``length is None`` is "there is no trustworthy statement of how
        long this body is", which is NOT "the body is empty". That
        distinction is the one the old reader collapsed, and collapsing it
        is how a dropped or rewritten framing header became a silent zero.

        THIS METHOD STOPS AT THE OCTETS, and the split is the point.
        Everything it can refuse is a statement about the WIRE -- no
        trustworthy length, more octets than this server will read, fewer
        octets than the peer declared -- and every one of those leaves the
        stream unframed, so every one of them costs the connection. What
        the octets MEAN is _parse_body's question, it is asked after the
        body is off the wire and the socket is framed again, and it costs
        nothing. Reading and parsing in one method is what made a
        malformed document close a connection that had nothing wrong with
        it: the caller never reached its own ``drained = True``.
        """
        if length is None:
            # A body-bearing request with no length this server can trust.
            # Nothing is read -- _handle has already marked the connection
            # to close, so the octets that were never read cannot frame
            # anything.
            raise GuiError(400, "unframable_request", UNFRAMABLE_DETAIL)
        if length > MAX_BODY_BYTES:
            raise GuiError(413, "too_large",
                           "That request body is too large for this GUI.")
        if length <= 0:
            return b""
        try:
            raw = self.rfile.read(length)
        except OSError as exc:
            raise GuiError(400, "bad_request",
                           f"The request body did not arrive ({exc}).") from None
        if len(raw) != length:
            # Short read: the peer half-closed or died mid-body. Without
            # this the truncated bytes either parsed as a shorter valid
            # document -- accepting a call the caller never finished
            # sending -- or surfaced as a confusing bad_json. Either way
            # the stream is desynchronised and the connection does not
            # survive it; _handle leaves close_connection set because the
            # body never came off the wire.
            raise GuiError(400, "bad_request",
                           "The request body stopped short of the length it "
                           "declared, so none of it was used.")
        return raw

    def _parse_body(self, raw: bytes) -> dict:
        """What the octets MEAN. Called only after they are off the wire.

        Nothing this method refuses is a framing failure, and nothing it
        refuses closes the connection: by the time it runs, _handle has
        already marked the stream drained and handed the socket back. That
        is not a local opinion -- it is the call the mint
        (impl/aicash/mintapi.py, "the connection survives"), the
        supervision profile and the operator console all make for this
        exact input, and this server used to be the one that disagreed
        while its comment claimed it did not.
        """
        try:
            obj = json.loads(raw or b"{}")
        except (UnicodeDecodeError, ValueError, RecursionError):
            # json.loads says "no" in three ways and only ONE was caught.
            # ValueError is the documented one (JSONDecodeError, and the
            # bare ValueError CPython raises past its int/str digit limit,
            # so `{"amount_mc": <5000 digits>}` lands here);
            # UnicodeDecodeError is a ValueError and is named for the
            # reader. RecursionError is the one that was not caught, and
            # it is not a ValueError at all: `[[[[...` about ten thousand
            # deep is a body well inside MAX_BODY_BYTES that blows the C
            # parser's stack, and it escaped this clause to the blanket
            # handler in _handle -- a 500 "internal_error" on every POST
            # route of this server for a body that is simply malformed.
            # The mint (aicash/mintapi.py), the supervision server and the
            # operator console all widened this exact clause; nobody asked
            # whether this reader had the same gap, and it did.
            #
            # All three are permanently bad bytes and none of them is
            # this server failing. The body was fully read, so unlike the
            # refusals in _read_body_bytes the stream is still framed and
            # the connection does not have to die for it -- and now it does
            # not. This sentence was here a round before the code did it:
            # the parse lived inside the reader, so it raised BEFORE
            # _handle's `drained = True`, and the finally clause closed the
            # socket on every bad_json, including a body with an exact
            # Content-Length and nothing left on the wire. A pipelined
            # request behind it was discarded unanswered. Measured against
            # all four servers, the mint and the supervision profile answer
            # both requests on one connection; the console keeps the
            # decision too (it hangs up regardless, because it never sets
            # protocol_version and so answers HTTP/1.0). This server was
            # alone, and the comment was the only place that said so.
            raise GuiError(400, "bad_json",
                           "The request body was not valid JSON.") from None
        if not isinstance(obj, dict):
            raise GuiError(400, "bad_json",
                           "The request body must be a JSON object.")
        return obj

    # -- lifecycle ------------------------------------------------------
    def handle_one_request(self):
        """No request leaves this server with no answer at all.

        THE COVERAGE BOUNDARY OF THE BLANKET HANDLER, which is the thing
        the last round enumerated around rather than through. _handle's
        `try` starts AFTER the HTTP/0.9 refusal, AFTER
        framing_fields(framing_verdict(...)) and AFTER the path and query
        parsing, and -- being a try -- it does not cover its own `except`
        and `finally` clauses either, where _error -> _json -> _send is
        what writes to the socket. An exception in any of those places
        leaves socketserver's handle_error to print a traceback and the
        caller reading ZERO bytes: no status line, socket dropped. That is
        the one outcome this round's bar names outright, and it is worse
        than a 500, which is at least an answer a caller can act on.

        Both sibling servers already have this hook for exactly that
        reason (mint_console.py, impl/aicash/mintapi.py); this one did not,
        and nothing in the enumeration asked why. It is a backstop and not
        a licence: an exception arriving here is a bug in this file, and
        the 500 says so rather than pretending the request was refused on
        its merits.

        What it does NOT claim is that nothing happened. /api/mint/issue
        asks the mint to create money; an exception on the way back is
        money that may exist. The sentence says the outcome is
        undetermined, which is the same honesty rule the rest of this file
        is written to.
        """
        self._answered = False
        # Armed BEFORE the request line is read, which is what makes this
        # whole-request rather than body-only, and what bounds a peer that
        # connects and then says nothing at all.
        #
        # AND IT IS WHAT BOUNDS AN IDLE KEEP-ALIVE SOCKET TOO. The comment
        # that used to stand here said the opposite -- that idle time
        # between requests was governed by `timeout` alone -- and it was
        # false, because `handle()` re-enters this method and the line
        # below arms the deadline BEFORE the blocking read that waits for
        # the next request line. MEASURED: a socket that took a 200 and
        # then went silent was answered and closed at 10.0s, not 30. Ten
        # seconds is comfortably above page.html's fastest poll (four
        # seconds), which is the only legitimate thing that waits on an
        # idle socket here. The disarm in the finally is still right -- a
        # deadline left armed is state from a finished request -- but it is
        # not what makes the next request's budget whole; the re-arm above
        # is.
        self.request_deadline = time.monotonic() + self.request_timeout
        try:
            super().handle_one_request()
            self._answer_an_unfinished_request()
        except OSError:
            # A reset peer, a broken pipe, a timeout: the socket is gone,
            # so there is nowhere to answer and nothing failed here.
            self.close_connection = True
        except Exception:                       # noqa: BLE001 -- see above
            traceback.print_exc()
            self.close_connection = True
            if self._answered:
                # A status line is already on the wire. A second response
                # behind it is the desync, not the cure.
                return
            try:
                self._error(
                    500, "internal_error",
                    "Something inside this GUI failed while answering that "
                    "request, and it failed outside the part of it that "
                    "knows how to describe a failure. Nothing was retried "
                    "and nothing was assumed, and this server cannot tell "
                    "whether the request took effect. The full detail, "
                    "including which line failed, is on the terminal "
                    "running app.py.")
            except Exception:                   # noqa: BLE001
                # The last resort failed too (a dead socket, most likely).
                # There is nothing further to try and nothing to report to:
                # swallowing it here at least keeps socketserver from
                # printing a second traceback for the same request.
                traceback.print_exc()
        finally:
            # Disarmed however this request ended. A deadline left armed
            # would be spent by the NEXT request on a keep-alive socket,
            # which would cut short a perfectly good one.
            self.request_deadline = None

    def _answer_an_unfinished_request(self) -> None:
        """A request that ran out of clock is still answered.

        THE LAST TWO SHAPES ON THIS SERVER THAT GOT NO STATUS LINE, and
        both of them are a peer that began a request and never finished
        it. MEASURED before this method existed, on all twenty-one routes:

            GET /api/mint/status HTTP/1.1            (no CRLF, ever)
            GET /api/mint/status HTTP/1.1\r\nHost: x\r\n  (no blank line)

        ZERO BYTES in both cases, socket dropped at the deadline. The
        read side was doing its job -- the thread and the fd came back at
        ten seconds -- but the caller was told nothing, and "nothing" is
        the one outcome this round's bar names outright. It is the same
        answer whether that caller is a broken script, a proxy that died
        mid-request, or a drip.

        WHY THE BASE CLASS CANNOT DO IT. ``BaseHTTPRequestHandler``
        wraps its whole request in ``except TimeoutError: close and
        return`` -- silently, by design, because in the general case a
        timed-out socket may be gone. Here it is usually not gone: a peer
        dripping a header block is a peer still connected and still
        reading, and 408 is the status RFC 7231 §6.5.7 defines for
        precisely this ("the server did not receive a complete request
        message within the time that it was prepared to wait") and which
        it says to send with ``Connection: close``.

        WHY IT IS SAFE TO ANSWER AN IDLE KEEP-ALIVE SOCKET THIS WAY, which
        is the other thing that lands here. The deadline is armed before
        the wait for the next request line, so a kept socket that goes
        quiet for ten seconds gets this 408 instead of a silent close. A
        408 with ``Connection: close`` on an idle persistent connection is
        the ordinary, specified thing for a server to send, and it is
        strictly more than the silent close it replaces: a client learns
        that the connection is finished instead of inferring it from an
        EOF. page.html polls every four seconds, so its own connection
        never reaches this.

        AND IF THE PEER REALLY IS GONE, the write fails and ``_send``
        turns that into a closed connection with no traceback. Trying
        costs one failed syscall; not trying costs every caller that was
        still there an answer.
        """
        if self._answered:
            return
        deadline = self.request_deadline
        if deadline is None or time.monotonic() < deadline:
            # Not the clock: an EOF, a refusal already sent, a request
            # answered on its merits. Nothing to add.
            return
        self._refuse_transport(
            408, "request_timeout",
            "This GUI reads one whole request -- request line, headers and "
            "body together -- inside a fixed wall-clock budget, and that "
            "budget ran out before the request was complete. Nothing was "
            "dispatched, nothing took effect, and the connection is "
            "closed. Send the request again in one piece.")

    def parse_request(self) -> bool:
        """Two transport decisions this server was making alone, taken here.

        ``parse_request`` and not the top of ``_handle`` because this is
        the one hook every request passes through -- including the methods
        this file implements no ``do_*`` for, which the base class answers
        501 from inside ``handle_one_request`` without any of this file
        running at all. Returning False is the base class's own "stop, do
        not dispatch" signal, so a refusal below is the complete answer to
        that request. It is the mint's hook, for the mint's reason
        (impl/aicash/mintapi.py, ``_Handler.parse_request``), and the
        console's too.

        ONE EMPTY LINE IN FRONT OF THE REQUEST. RFC 7230 §3.5 says a
        server SHOULD ignore at least one empty line received before the
        request line. The base class does not: an empty request line makes
        ``words`` empty and ``parse_request`` return False with NOTHING
        WRITTEN and the socket dropped. Measured on this server, on all
        twenty-one routes, with a valid session cookie:
        ``\r\nGET /api/mint/status HTTP/1.1\r\nHost: ...\r\n\r\n``
        -- a perfectly well-formed request with one stray CRLF in front of
        it, which is exactly what a client that terminated its last body
        with an extra CRLF emits -- came back as ZERO BYTES and a closed
        socket. The mint and the supervision profile answer it 200; this
        server and the console silently discarded it. That is the "no
        answer at all" class, on a shape the standard blesses, and it is
        one of the three cells where four servers disagreed on identical
        bytes.

        THE CONSOLE'S HALF OF THAT CELL IS CLOSED TOO, as of 2026-09-17,
        and a report written earlier in this round saying it was not is
        stale: mint_console.py carries this block with its own 414 guard.
        All four servers now answer one leading empty line. They do NOT
        all answer the SECOND one the same way, and the paragraph below
        says what each does, because a cross-server table nobody re-reads
        is how the stale claim happened in the first place.

        One line, not a loop: "at least one" is what the RFC asks for, and
        a loop would let a peer hold a thread by trickling CRLFs -- though
        now only until ``request_deadline`` expires, because this read
        happens under the same wall clock as every other.

        AND THE SECOND EMPTY LINE IS ANSWERED, not dropped, which is where
        this file now goes past the mint on the same bytes and does so
        deliberately. Two or three leading empty lines used to fall through
        to the base class, whose ``parse_request`` finds no words in an
        empty request line and returns False with NOTHING WRITTEN and the
        socket dropped: measured at zero bytes on all twenty-one routes.
        Declining to tolerate a second empty line is the right decision;
        declining to SAY SO is the "no answer at all" class again, one
        shape over. So the count stays at one and the refusal is a framed
        400 with a length and ``Connection: close``.

        WHERE THE FOUR SERVERS STAND ON THE SECOND EMPTY LINE, measured
        2026-09-17, because this is now a cell they do not agree on and a
        reader is owed the table rather than the half of it this file
        implements:

            mint / supervision   tolerate one, then silently discard
            operator console     tolerate a bounded RUN
                                 (MAX_LEADING_EMPTY_LINES), framed 400
                                 past the cap
            this server          tolerate one, framed 400 past it

        All three of those ANSWER the shape the RFC blesses and none of
        them can be held by a CRLF trickle. They differ only in how many
        stray lines they forgive before refusing, and this file takes the
        strictest of the three: it is never more permissive than a sibling,
        so nothing reaches a route here that would not reach one there. The
        rule belongs in aicash.mintapi so all four move together, and impl/
        was not this round's to edit -- that is a real piece of unfinished
        work and it is written here rather than left to be rediscovered.

        A REQUEST TARGET THIS SERVER COULD NEVER ROUTE. RFC 7230 §5.3
        gives a request target four forms. This server routes on
        ``self.path`` verbatim, so only origin-form (``/api/...``) has
        ever matched a route: absolute-form
        (``http://127.0.0.1:8799/api/wallet/list``), asterisk-form
        (``*``) and a bare relative path (``api/wallet/list``) never have
        and never could. Being unroutable was never the problem. Answering
        404 and then INVITING ANOTHER REQUEST on the same connection is
        the part that was wrong, and this server was the only one of the
        four that did it -- the mint and the supervision profile answer
        400 and hang up, the console answers and hangs up. Measured, on
        all three target forms, with a valid session cookie.

        §5.3.2 says an origin server that accepts absolute-form must
        ignore ``Host`` and route on the target's own authority; this
        server does neither, so a request still addressed the way it would
        be addressed to a proxy is a request whose two statements of
        "which server is this for" this hop has not resolved -- and
        ``_host_ok`` reads the one it is not routing on. That is the
        framing disagreement one field over, so it is answered once and
        the socket goes. Asterisk-form is refused with the rest rather
        than exempted: it is defined for ``OPTIONS`` alone, no route here
        answers ``OPTIONS``, and it was answered 404 on a REUSED
        connection like the others.

        THE VERSION CHECK IS DELIBERATELY NOT MOVED UP HERE, and the order
        matters. ``_handle`` refuses HTTP/0.9 -- where ``send_response``,
        ``send_header`` and ``end_headers`` are all no-ops and any answer
        composed goes out as a naked body. If the target check below ran
        for a 0.9 request line it would compose its own refusal into those
        no-ops and emit exactly the naked body the 0.9 guard exists
        against. So a 0.9 request line falls through untouched and is
        refused as ``bad_version`` by ``_handle`` -- which is the mint's
        precedence too (it takes the version first and the target second)
        and therefore the same answer from both servers on the same bytes.
        """
        if self.raw_requestline in (b"\r\n", b"\n", b"\r"):
            self.raw_requestline = self.rfile.readline(65537)
            if len(self.raw_requestline) > 65536:
                # ``handle_one_request``'s own guard, repeated because this
                # read is ours. The fields set first are the ones
                # ``send_error`` reads to frame its answer.
                self.requestline = ""
                self.request_version = ""
                self.command = ""
                self.send_error(414)
                return False
            if not self.raw_requestline:
                # EOF after the empty line. Nothing to answer, and nobody
                # left to answer it to.
                self.close_connection = True
                return False
            if self.raw_requestline in (b"\r\n", b"\n", b"\r"):
                # A SECOND empty line, and the count stops at one. The
                # base class would answer this with nothing at all -- see
                # the docstring -- so it is answered here instead.
                self._refuse_transport(
                    400, "bad_request_line",
                    "This GUI ignores one empty line before a request "
                    "line, which is what RFC 7230 3.5 asks of it, and "
                    "stops there: a server that skips empty lines in a "
                    "loop can be held by a peer that sends nothing else. "
                    "The second empty line is where a request line was "
                    "expected. Nothing was dispatched and the connection "
                    "is closed.")
                return False
        if not super().parse_request():
            # Malformed request line, unsupported version, too many or too
            # long headers: the base class has already answered, through
            # this file's ``send_error`` override, which is what puts a
            # status line and a length on it.
            return False
        if self.request_version == "HTTP/0.9":
            # See the docstring: ``_handle`` owns this one, and answering
            # anything here would answer it nakedly.
            return True
        if not self.path.startswith("/"):
            self._refuse_transport(
                400, "bad_request_target",
                "This GUI answers origin-form request targets only -- a "
                "path beginning with '/'. An absolute-form target "
                "(http://host/path), an asterisk target (*) or a bare "
                "relative path names no route here and never could, and "
                "an absolute-form target states a destination host that "
                "this server does not route on, which is a question about "
                "where the request was going that this hop cannot answer. "
                "Nothing was dispatched and the connection is closed.")
            return False
        return True

    def handle_expect_100(self):
        """An interim 100 is a PROMISE to read a body. Do not make one
        this server has already decided to refuse.

        THE ONE PATH THAT ANSWERS BEFORE THE FRAMING GATE.
        `handle_expect_100` is called from
        BaseHTTPRequestHandler.parse_request, and only when
        protocol_version is at least HTTP/1.1. MEASURED, not assumed: this
        server sets it, and so do impl/aicash/mintapi.py and the
        supervision profile that inherits its handler, so the hook is live
        on three of the four servers here; only the console leaves
        protocol_version alone, answers HTTP/1.0, and never reaches it.
        The console neutralised its copy anyway and has a test for it --
        against the day someone sets protocol_version -- and nothing
        carried that across to the two servers where it was already live.
        Measured before this override, a `POST /api/wallet/pay` carrying
        `Expect: 100-continue` together with `Transfer-Encoding: chunked`
        (or a duplicated Content-Length) got

            HTTP/1.1 100 Continue\r\n\r\n

        -- a bare status line with no headers, inviting the peer to send a
        body this server had already decided it would not frame -- and only
        then the 400 and the hang-up. No desync followed, because the
        refusal and the close follow immediately. It is still a response
        emitted by a path that bypasses the gate the rest of this file is
        built around -- and a live hook nobody sends the header to is
        exactly how it survived two rounds of framing work here: 58
        spellings at 55 routes, 3,190 cells, and not one of them carried
        an Expect header.

        So the gate is asked FIRST, from the same shared rule and with the
        same caller fact _handle passes it, and the interim answer is sent
        only for a request this server will actually read a body for.
        Refusing here returns False, which makes parse_request return False
        and handle_one_request stop: one response, then the close.
        """
        length, framed, _must_close, reason = framing_fields(
            framing_verdict(self.headers,
                            body_expected=self.command == "POST"))
        if not framed:
            self.close_connection = True
            self._error(400, "unframable_request",
                        f"{UNFRAMABLE_DETAIL} (framing: {reason})",
                        "unknown")
            return False
        if length is not None and length > MAX_BODY_BYTES:
            # The same refusal _read_body_bytes would give, given a
            # hundred-continue earlier. Saying it now costs the caller one
            # round trip instead of a megabyte of body nobody will read.
            self.close_connection = True
            self._error(413, "too_large",
                        "That request body is too large for this GUI.")
            return False
        return super().handle_expect_100()

    # -- dispatch -------------------------------------------------------
    def _handle(self, method: str):
        """Every request this server answers, of every method, starts here.

        THE FRAMING GATE IS THE FIRST THING AND IT IS NOT METHOD-SPECIFIC.
        An independent verifier found the GET routes of this server
        smuggleable precisely because the previous author assumed only a
        POST can carry a body: a GET with a declared Content-Length and a
        second request in its body was answered, the body was never read,
        and the octets left behind were framed as the next request line --
        two responses out of one request, on a socket the server then
        went on reusing. So the verdict is taken here, once, before
        authorisation, before dispatch, before any route name is looked
        up, and it is taken for GET and HEAD and OPTIONS and PUT exactly
        as for POST. A method this file answers tomorrow inherits it by
        existing.

        The rule itself is not here and must not be: see framing_verdict.
        """
        # A body we never read would leave the next request on a reused
        # connection misaligned, so any path that skips it closes instead.
        drained = False
        # One connection can carry many requests; nothing from the last one
        # may survive into this one.
        self._set_cookie = None
        # What the BASE CLASS decided about reuse from the request line and
        # the Connection header, before this method touched anything. A
        # body read off the wire re-frames the socket, but it does not undo
        # a `Connection: close` the client asked for.
        peer_keeps_alive = not self.close_connection

        if self.request_version == "HTTP/0.9":
            # THE OTHER WAY TO EMIT A RESPONSE WITH NO STATUS LINE, found
            # sweeping for the shape of the one in send_error(). HTTP/0.9
            # has no status line and no headers, so send_response(),
            # send_header() and end_headers() are all no-ops -- every
            # answer this server composed for a 0.9 request went out as a
            # naked body, JSON error envelopes included. Nothing that
            # speaks to this GUI speaks 0.9 (it is a page, a browser and
            # an fetch()), and a money server that answers in a protocol
            # with no framing is a money server whose answers cannot be
            # told from trailing octets. So it is refused, in HTTP/1.1,
            # with a length, and the socket goes.
            return self._refuse_transport(
                400, "bad_version",
                "This GUI answers HTTP/1.0 and HTTP/1.1. A request line "
                "with no version on it is HTTP/0.9, which has no status "
                "line, no headers and no way to state how long an answer "
                "is -- so there is no honest way to answer one here.")

        # WHETHER THIS FILE IS ABOUT TO READ A BODY -- the one caller fact
        # the shared rule needs. It is NOT a guess about which HTTP methods
        # may carry a body; that guess is exactly what left the GET routes
        # smuggleable. It is a fact about the dispatch below:
        # `_read_body_bytes` is called on the POST branch and on no
        # other. The rule uses it only to decide what an ABSENT
        # Content-Length means. On a body
        # about to be read, "no Content-Length" is not "no body", it is "no
        # statement" -- and no statement is what every mangled, dropped or
        # front-end-rewritten framing header degrades into by the time this
        # parser sees it. On every other method the routes read nothing, so
        # an absent length is the ordinary case for every conforming client
        # and means zero octets; refusing there would cost keep-alive on
        # every well-formed GET and buy nothing. A GET that DECLARES a body
        # is a different thing entirely, and the rule closes on it.
        body_expected = method == "POST"
        length, framed, must_close, reason = framing_fields(
            framing_verdict(self.headers, body_expected=body_expected))
        if must_close or length:
            # must_close: unframable, or framed octets this caller has
            # already said it will not read. `length`: octets on the wire
            # that nothing has read YET -- a POST that goes on to read its
            # body whole puts the connection back a few lines down. Set
            # NOW, not in a `finally` that runs after the response headers
            # are already on the socket: that is what made the old teardown
            # a silent hang-up with no `Connection: close` for a peer to
            # act on.
            self.close_connection = True
        if not framed:
            # THE ONE VERDICT THAT IS SAFE WHICHEVER WAY ANOTHER HOP
            # RESOLVES IT. The rule returns no status code and no envelope
            # -- its four callers use three different vocabularies -- so
            # the 400, the reason word and the sentence are this server's
            # own; only the machine slug is the rule's, and it is passed
            # through so a caller driving the API directly can tell a
            # chunked body from a duplicated length.
            return self._error(400, "unframable_request",
                               f"{UNFRAMABLE_DETAIL} (framing: {reason})",
                               "unknown")

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
                raw = self._read_body_bytes(length)
                drained = True
                if peer_keeps_alive and not must_close:
                    # The body is off the wire in its entirety, so the
                    # stream is framed again and the socket is reusable --
                    # unless the peer asked to close, or the shared rule
                    # said this request's connection must not be reused
                    # whatever else happens.
                    self.close_connection = False
                # AND THE PARSE COMES AFTER THAT, deliberately. Whether the
                # octets are JSON, whether they are an object, whether a
                # route likes them: none of that is a fact about the
                # stream, so none of it may take the connection down. Doing
                # the parse inside the reader put it BEFORE these two
                # lines, which is how `bad_json` -- and only bad_json,
                # never a route's own refusal of a valid document -- hung
                # up on a socket that was perfectly well framed.
                body = self._parse_body(raw)
            else:
                body = {}
            result = getattr(self.api, name)(query, body)
            return self._json(200, result)
        except GuiError as exc:
            return self._error(exc.status, exc.reason, exc.detail, exc.cause)
        except Exception:
            # The whole point of this clause: the operator gets one
            # sentence, never a stack trace, and the trace goes to this
            # process's stderr where it belongs.
            #
            # AND NOT THE EXCEPTION'S OWN TEXT EITHER. An interpreter
            # message is a traceback by another name and it quotes
            # whatever the caller sent: a five-thousand-digit amount_mc
            # landed here as
            # "Exceeds the limit (4300 digits) for integer string
            # conversion: value has 5000 digits; use
            # sys.set_int_max_str_digits()...", which told the operator
            # nothing, told an attacker the interpreter's configuration,
            # and echoed the caller's own input back out of a money
            # server. The trace goes to this process's stderr, where it
            # belongs and where the operator can read it; the page gets one
            # sentence and no interpreter vocabulary at all.
            traceback.print_exc()
            if self._answered:
                # A STATUS LINE IS ALREADY ON THE WIRE, so a 500 behind it
                # is not a cure, it is the desync. This clause used to
                # answer unconditionally and never read this flag -- only
                # the outer backstop in handle_one_request did -- so a
                # response that failed PART WAY THROUGH ITS OWN WRITE got a
                # second, complete response appended to the partial one,
                # and the attempt bought the peer another whole write
                # window on a socket that had just proved it would not take
                # one (measured: 65.0s of hold on a 400-deep pipeline where
                # 30 of it was this recovery). _send now turns a failed
                # write into a closed connection by itself, so this is the
                # second lock and not the first.
                self.close_connection = True
                return None
            return self._error(
                500, "internal_error",
                "Something inside this GUI failed while answering that "
                "request, and it was not a failure this server knows how "
                "to describe. Nothing was retried and nothing was assumed. "
                "The full detail, including which line failed, is on the "
                "terminal running app.py.")
        finally:
            if not drained and (length or must_close):
                # A declared body nothing read. Already set above; repeated
                # here because the POST path CLEARS it on a whole read and
                # an exception can land between that read and this line.
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

        AND IT STILL GETS A STATUS LINE. ``parse_request`` sets
        ``request_version`` to HTTP/0.9 BEFORE it tries to read the request
        line, and in HTTP/0.9 ``send_response``, ``send_header`` and
        ``end_headers`` are all no-ops -- so for an unparseable request
        line this override used to write its JSON body to the socket RAW,
        with no status line and no headers of any kind. On a pipelined
        connection that landed appended past the previous response's
        declared Content-Length: on the wire, a bodiless-protocol response
        glued onto the end of a well-formed one, which is the same
        trailing-octet primitive the framing rule exists to close, arriving
        from the other direction. A client reading by Content-Length is
        handed the first response and then a tail of bytes that are not
        part of it.

        So a failure this server cannot attribute to a version is answered
        in HTTP/1.1: a status line, a Content-Length, ``Connection: close``,
        and then the socket goes. A peer that really did speak HTTP/0.9
        gets a response it may not parse -- but it has just been refused
        and hung up on, and every other server on the internet answers it
        the same way. The alternative, which is what was here, is bytes
        with no framing at all.
        """
        # The close, the version and the two fields send_response reads
        # are _refuse_transport's, not this method's: this is the base
        # class's transport refusal arriving through the library's own
        # hook, and it is the same kind of answer as the four below it.
        # Spelling them here as well is how a fifth spelling of "close and
        # answer" gets into a file that is removing exactly that.
        short, long = self.responses.get(
            code, ("error", "The request could not be handled."))
        detail = explain or long
        if message and message != short:
            detail = f"{message}. {detail}"
        # The base class's message for an unparseable request line is
        # "Bad request syntax (%r)" % the request line, and a request line
        # is allowed to be 64 KiB. Unbounded, that is 64 KiB of the
        # caller's own bytes reflected out of a money server's error body.
        # The first 200 characters say which request failed; the rest only
        # says it at greater length.
        detail = _bounded(detail, 200)
        try:
            self._refuse_transport(
                int(code), _Components._reason(message or short), detail)
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
