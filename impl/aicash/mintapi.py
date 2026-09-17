"""C06 — mintapi: the HTTP surface of a mint.

Spec: aicash-spec-v0.4.md §3.3 (exchange wire forms), §3.5 (status),
§3.6 (descriptor), §3.7 (anonymous bearer access), §3.8 (error semantics).
Locked: L2 (no auth on Layer 0), L11 (performance self-attested/nullable),
L17 (Ed25519 static key, rate limits published-not-enforced, plain HTTP,
injected clock). Depends: C04 (ledgerstore), C05 (signing), and through
them C01–C03.

JSON in/out over stdlib ``ThreadingHTTPServer``. The server holds no
money logic of its own: it parses §3.3 wire forms into C04's typed forms,
lets the ledger's single atomic transaction decide, and serializes results
with C01's canonical JSON so response bytes are stable (byte-identical
idempotency replays, reproducible client-side digests).

Time discipline (L17): C06 never reads wall time. The mint clock is
whatever clock the injected Ledger was built with, observed through the
public ``Ledger.status`` return value.

Snapshot integrity (§3.6): ``snapshot_seq`` is persisted in the same
sqlite database as the ledger (C06-owned tables, never touching C04's),
as the HIGH-WATER MARK of a reserved block that the server hands out from
memory. A restarted mint therefore resumes strictly above every seq it
could have signed — it can never sign two snapshots that violate §3.6
monotonicity ("portable proof of nonconformance") merely by restarting —
while a descriptor fetch stays a read, so an anonymous poller cannot take
the payment database's write lock (see ``_Core.descriptor``). Because the
ordering of a snapshot's supply read against its seq is now held by an
in-process mutex rather than by sqlite's write lock, one ledger file may
be served by exactly ONE mint process: ``_Core._claim_single_writer``
takes an advisory ``flock`` on the ledger and a second server refuses to
start or to serve a descriptor (§3.6's proof-of-nonconformance is not
something an honest mint may leave to a deployment convention). Activity
counters live in the same store: windowed to the current mint-clock day
and counted at most once per idempotency key, so §3.3 replays never
double-count and "daily" figures never accumulate process-lifetime
totals.

Resource bounds (deployment, not §3.7 rate limiting — L17 scopes
enforcement out): ``MAX_BODY_BYTES`` caps what one request may make the
server allocate, ``MAX_IDEMPOTENCY_KEY_LEN`` caps what one caller may
write into the §8 recovery window, ``_Handler.timeout`` caps how long one
recv may block, and ``MAX_REQUEST_SECONDS`` caps the WALL-CLOCK life of a
whole request so a peer that drips a byte at a time — resetting the idle
timeout on every recv — still cannot hold a thread (see
``_DeadlineRaw``). All four bound a SINGLE request; none of them counts
requests per caller. None is published in §3.6's ``limits``: that object
is the pinned home of the protocol limit (``max_batch``) and its scope
guard is explicit, so a body the mint declines to read is reported with
the §3.8 reason for an envelope it cannot parse — ``bad_format``, which
is permanent — and never with ``over_batch_limit``, which §9.5 classifies
as retryable with backoff and which would send a payer into a retry loop
over bytes that can never succeed.

Secret hygiene (§3.1, requirement 5): request bodies are never logged.
The access log (logger ``aicash.mintapi``) carries route pattern + status
code only — even the path is normalized to a fixed route pattern so a
confused client that puts a token in a URL still cannot make the server
log secret material. Never a stack trace in a response body.
"""

from __future__ import annotations

import hmac
import io
import json
import logging
import os
import re
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:  # POSIX only; the reference build targets Linux (see DEPLOYMENT).
    import fcntl
except ImportError:  # pragma: no cover - no advisory locking available
    fcntl = None

from aicash.burncalc import (
    BurnPolicy,
    is_increase,
    validate_notice,
    validate_policy,
)
from aicash.clock import system_clock
from aicash.ledgerstore import (
    ExchangeRejected,
    Ledger,
    OutputSpec,
    parse_output_wire,
)
from aicash.lockeval import InputForm
from aicash.signing import attach_sig, pubkey_b64u
from aicash.tokencodec import (
    MINT_ID_RE,
    TokenError,
    b64u_decode,
    body_digest,
    canonical_json,
    parse_token,
)

__all__ = [
    "MintConfig",
    "MintServer",
    "make_mint",
    "ADMIN_ISSUANCE_OPEN",
    "ADMIN_ISSUANCE_DISABLED",
    # The request-framing rule, public because it is SHARED. Every HTTP
    # server in this repository -- this mint, the Supervision Profile, the
    # operator GUI and the operator console -- decides how long a request
    # body is by calling `framing_verdict`, and nothing else. It is on the
    # integrator surface for the same reason: anyone embedding a handler of
    # their own beside a mint needs the same rule, and the alternative to
    # exporting it is what already happened three times here -- a private
    # copy that was right on the day it was written.
    "FramingVerdict",
    "framing_verdict",
    "FRAMING_REASONS",
]

logger = logging.getLogger("aicash.mintapi")

_DAY_MS = 86_400_000

# Largest request body the server will read, in bytes (§3.3/§3.6 limits).
# Sized from the ONE published limit that bounds a legal call: max_batch
# (default 256) entries. The fattest legal entry is a claim input
# ``{"token": "...", "witness": "..."}`` or an output carrying a §3.4 lock:
# a token is "v3:<mint_id<=64>:<amount>:<secret b64u 43>" and every hash or
# witness is a 43-character b64u of 32 bytes, so ~300 bytes of JSON per
# entry is already generous. 256 entries then need ~77 KiB; 1 MiB leaves
# better than 13x headroom AT THAT DEFAULT for whitespace, a long mint_id and
# the envelope, while still refusing the unbounded ``Content-Length`` a single
# client used to be able to make the server allocate. That headroom is a
# property of the default max_batch, not of this cap: max_batch is
# configurable, and at the largest value this cap admits (_max_batch_ceiling)
# the cap is only ~1.5x a maximal call, not 13x it (677 KB canonical, 707 KB
# as json.dumps writes it, against 1 MiB). Not a
# rate limit (L17 scopes those out) — a per-request allocation bound. A
# deployment that raises max_batch past what this cap can carry is refused at
# construction rather than left to publish an impossible limit: see
# _max_batch_ceiling and MintConfig.
MAX_BODY_BYTES = 1_048_576

# -- /admin/issue: what the ABSENCE of a credential means ---------------
#
# It used to mean "allow everyone". ``MintConfig.admin_token`` defaulted to
# None and ``admin_authorized()`` returned True for None, so a mint built
# from a default config served POST /admin/issue -- unlimited issuance, the
# only endpoint in this codebase that creates money from nothing -- to
# anybody who could reach the port. Nothing failed a check; there was no
# check, and no check reads as fine because nothing gets reported. Every
# embedder who did not think about it got an open mint.
#
# So openness is no longer a state you can reach by saying nothing. There
# are exactly three states, all of them named, and none of them is the
# default:
#
#   admin_token="<secret>"      gated: X-Admin-Token must match (constant time)
#   ADMIN_ISSUANCE_DISABLED     /admin/issue answers 401 to everyone, always
#   ADMIN_ISSUANCE_OPEN         /admin/issue answers everyone -- opt in BY NAME
#
# WHY THE REFUSAL IS AT CONSTRUCTION TIME, NOT AT REQUEST TIME.
# Failing closed at request time (mint runs, issuance always 401) would also
# shut the hole, and it is the gentler change: nothing that never issues
# would break. It was rejected anyway, for three reasons.
#   1. The defect is a DECISION THAT WAS NEVER MADE, not a check that failed.
#      A mint that boots and serves happily has, once again, recorded no
#      decision anywhere; the operator learns what their mint does only when
#      they first reach for issuance, which for a real deployment is under
#      load, in production, months later. Refusing to build puts the
#      discovery before the port is ever bound.
#   2. The requirement is that openness be GREPPABLE. ``grep -rn
#      ADMIN_ISSUANCE_OPEN`` must enumerate every open mint in a tree. That
#      only holds if silence cannot produce one, which means silence has to
#      be an error, not a quiet default -- at request time, silence still
#      produces a running mint whose config file says nothing at all.
#   3. It converts a security property into a type error, which is the one
#      class of bug this project's tooling catches for free. Every call site
#      that was relying on open issuance raises on the line that built the
#      config, with the three choices in the message.
# The cost is real and is paid deliberately: existing callers break loudly,
# including ones that never issue. That is the point -- each break is a
# place where nobody had decided.
#
# Note what is NOT here: there is no silent fallback anywhere below. If the
# field is unset, or None, or anything that is not one of the three states
# above, MintConfig raises. Layer 0 (/v3/exchange, /v3/status) is untouched
# by all of this and stays anonymous for everyone, per L2 and §3.7 -- this
# gate is only ever on the non-normative §7.1 operator-funding path.


class _AdminIssuanceMode:
    """A named, identity-compared /admin/issue policy. Not a token."""

    __slots__ = ("_name", "_global_name")

    def __init__(self, name: str, global_name: str | None = None):
        self._name = name
        # The module-global this instance is bound to. It is what makes the
        # object survive pickling BY REFERENCE (see __reduce__) instead of
        # being rebuilt as a look-alike, and it is separate from _name only
        # because _ADMIN_TOKEN_UNSET reprs as "<unset>", which is not a
        # legal identifier.
        self._global_name = global_name or name

    def __repr__(self) -> str:
        return self._name

    # ------------------------------------------------------------------
    # Identity survives copying. Everything downstream of these sentinels
    # compares them with `is` -- MintConfig.__post_init__ validates that
    # way and admin_authorized() authorizes that way -- so a copy that is
    # merely EQUAL is not good enough; it has to be the same object.
    #
    # This is not hypothetical. dataclasses.replace() on a MintConfig is on
    # the live path (SupervisionServer.__init__ rebuilds every supervision
    # mint's config with it), and a caller who hands it a deep-copied config
    # used to get either a silently-shut ADMIN_ISSUANCE_OPEN mint -- the
    # non-str fallthrough in admin_authorized() fails closed, so the mint ran
    # but refused everyone with nothing said anywhere -- or, for
    # ADMIN_ISSUANCE_DISABLED, a ValueError complaining about "a
    # _AdminIssuanceMode, which is not ... one of the named issuance modes"
    # about a value whose own repr() printed ADMIN_ISSUANCE_DISABLED.
    #
    # Failing closed was the right direction; failing SILENTLY was not, and
    # an error message that denies the value it is printing is worse than
    # either. Preserving identity removes the whole class of problem: after
    # any copy, pickle or dataclasses.replace round trip the config still
    # holds the exact object the author named in source.
    # ------------------------------------------------------------------
    def __copy__(self) -> "_AdminIssuanceMode":
        return self

    def __deepcopy__(self, memo) -> "_AdminIssuanceMode":
        return self

    def __reduce__(self) -> str:
        # A plain string return tells pickle "this is the module global of
        # that name" -- it stores a reference, and unpickling re-resolves
        # aicash.mintapi.<global_name>, which IS this object. The alternative
        # (reconstructing from __slots__) would produce an equal-looking mode
        # that no `is` test in this module would ever match.
        return self._global_name


# Opt in to an unauthenticated /admin/issue, by name, in source a reader can
# grep. Anyone who can reach the port can mint without limit. Legitimate for
# a throwaway demo or an in-process test harness on a loopback port; never
# for anything reachable by anything you did not start yourself.
ADMIN_ISSUANCE_OPEN = _AdminIssuanceMode("ADMIN_ISSUANCE_OPEN")

# No HTTP issuance at all: /admin/issue answers 401 to every caller,
# including the operator. This is the safe choice for any mint whose
# issuance happens in-process through ``Ledger.issue``, and it is a real
# third state, not "no credential" -- it says the endpoint is shut, rather
# than leaving a reader to infer that from a missing field.
ADMIN_ISSUANCE_DISABLED = _AdminIssuanceMode("ADMIN_ISSUANCE_DISABLED")

# Distinct from both, and from None: "nobody said". Only ever a default.
_ADMIN_TOKEN_UNSET = _AdminIssuanceMode("<unset>", "_ADMIN_TOKEN_UNSET")

_ADMIN_TOKEN_GUIDANCE = (
    "MintConfig.admin_token must be set explicitly, because POST"
    " /admin/issue creates credits from nothing and an unset credential"
    " used to mean 'allow everyone'. Choose one, by name:\n"
    "  admin_token=\"<secret>\"                 gate it on X-Admin-Token\n"
    "  admin_token=ADMIN_ISSUANCE_DISABLED     no HTTP issuance at all"
    " (safe default for embedders)\n"
    "  admin_token=ADMIN_ISSUANCE_OPEN         unauthenticated issuance --"
    " anyone who reaches the port mints without limit\n"
    "Both names import from this module:\n"
    "  from aicash.mintapi import ADMIN_ISSUANCE_DISABLED,"
    " ADMIN_ISSUANCE_OPEN\n"
    "Layer 0 (/v3/exchange, /v3/status) is unaffected either way: it is"
    " anonymous for everyone, per L2 and §3.7."
)


# §3.3 idempotency keys are caller-chosen and are PERSISTED by C04 for the
# whole §8 recovery window (90 days by default), so an unbounded key is
# unbounded storage a caller writes into the mint for free. 128 characters
# fits every sane construction with room to spare: a UUID is 36, a b64u
# SHA-256 is 43, a "<caller>:<uuid>" namespaced pair well under 100.
MAX_IDEMPOTENCY_KEY_LEN = 128

# Per-entry byte ALLOWANCE for the max_batch cross-check against
# MAX_BODY_BYTES (see MintConfig.__post_init__), so a mint can never publish
# in limits.max_batch a batch size whose maximal call its own body cap always
# refuses. MEASURED against the fattest entry a CONFORMING caller sends: an
# output carrying a §3.4 lock,
#   {"amount_mc":<19 digits>,"secret_hash":"<43>","lock":{"preimage_hash":
#    "<43>","expiry":<13 digits>,"refund_hash":"<43>"}}
# at 247 bytes with no insignificant whitespace and 257 the way json.dumps
# writes it by default; the fattest input, a claim {"token","witness"} whose
# token carries a 64-character mint_id, is 206 / 209. 384 keeps better than
# 50% headroom over the worst of those, for the whitespace a client is free
# to send and for any future field that grows an entry.
#
# NOT an upper bound over every entry the mint will parse, and deliberately
# not claimed as one. §3.1 pins an amount's FORM (^[1-9][0-9]*$) but not its
# LENGTH, so {"amount_mc": <1000 digits>, "secret_hash": "<43>"} is an entry
# the mint reads and answers `amount_mismatch` — not `bad_format` — at ~1074
# bytes, 2.8x this allowance. A caller sending max_batch entries of that
# shape can still put a body over MAX_BODY_BYTES. The ceiling below NARROWS
# that hole (it closes max_batch=8000, where every maximal call of the
# ordinary shape was refused) rather than closing it; closing it needs a
# length bound on amounts in C01, which is a protocol question and not a
# deployment-config one. test_c06 pins both halves of this.
_CONTENT_LENGTH_RE = re.compile(r"[0-9]{1,19}")
"""RFC 7230 §3.3.2 ``Content-Length = 1*DIGIT``, and nothing else.

Used instead of handing the header value straight to ``int()``, which is
a LOOSER parser than HTTP's: it accepts a leading sign, PEP 515 underscore
separators and surrounding whitespace, so ``+53`` and ``5_3`` both read as
53 here while an intermediary reads them as malformed or as zero — a
length two parties compute differently, which is the definition of a
smuggling primitive. The 19-digit cap is the other half: it keeps ``int()``
below CPython's int/str conversion limit, so a 5,000-digit Content-Length
cannot raise a bare ValueError out of a framing decision."""

_FRAMING_FIELD_NAMES = ("content-length", "transfer-encoding")
"""The only two field names that can change how long a request body is.

Named ONCE, and then only ever used to build the confusion rule below —
never looked up by name in a header block. ``headers.get("X")`` asks
"is there a header spelled exactly X", and the answer to that question is
not the answer this server needs.
"""

_FRAMING_NAME_SEPARATOR = r"(?:[^a-z0-9]*|.)"
"""What may stand where a framing header name has its hyphen.

Either a run of any length of non-alphanumeric characters (including none
at all), or any single character. Those are the two ways a separator is
rewritten in practice: punctuation-to-punctuation substitution and
collapsing (``Transfer_Encoding``, ``Transfer.Encoding``,
``Transfer__Encoding``, ``TransferEncoding``), and one-character confusion
(``Transfer0Encoding``). Written as a shape rather than as a character
class so that neither half needs a list."""

_FRAMING_CONFUSABLE_RE = re.compile(
    "|".join(
        name.replace("-", _FRAMING_NAME_SEPARATOR)
        for name in _FRAMING_FIELD_NAMES
    )
)
"""Field names another hop could read as one of the framing headers.

DERIVED from ``_FRAMING_FIELD_NAMES``, not written out, because a list of
bad spellings is the thing that was wrong the last two times: each hyphen
becomes ``_FRAMING_NAME_SEPARATOR``, so ``transfer-encoding``,
``Transfer_Encoding``, ``Transfer.Encoding``, ``Transfer|Encoding``,
``Transfer__Encoding``, ``TransferaEncoding`` and ``transferencoding`` are
one rule and so is the spelling nobody has written down yet. Adding a
framing header to the tuple above extends the rule to every confusion of
THAT name too, with no second edit and no second list to keep in step.

Why punctuation is the axis: a field name's separator is the part of it
that other software rewrites. nginx has ``underscores_in_headers``,
Apache and IIS historically folded ``_`` to ``-``, and a gateway that
normalises ``Transfer_Encoding`` into ``Transfer-Encoding`` has DECHUNKED
a body this server then reads as zero octets long — the two parties
disagree about where the request ends, which is the whole of request
smuggling. The rule does not try to guess which rewrites are live in any
particular deployment (that is a fact about someone else's config, not
about this request); it declines to reuse the connection whenever the
question can be asked at all.

A name matching this is never READ as framing — a mint that honoured
``Transfer_Encoding`` would be inventing its own dialect. It is read as
"this server cannot be certain how long the body is", which is the one
verdict that is safe whichever way the other hop resolves it."""

_TCHAR = frozenset("!#$%&'*+-.^_`|~0123456789"
                   "abcdefghijklmnopqrstuvwxyz"
                   "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
"""RFC 7230 §3.2.6 ``tchar`` — every character a header NAME may contain.

A parsed name carrying anything else (``;``, ``"``, ``(``, a control byte)
is a name no two parsers have to agree on, whatever it turns out to mean,
so a request carrying one cannot be framed. This is a property of the
grammar, not a list of bad spellings — which is the whole reason it is
here: the confusable-name regex below can only express confusion AT a
separator position, so ``Content-Length;`` and ``Transfer-Encoding.``
walked straight past it while the Supervision Profile's own rule refused
them. Four hundred and thirty-five names sat in that gap, and three of
them reproduced the original report's access-log symptom verbatim."""


def _fold_header_name(name: str) -> str:
    """A header name reduced to what survives any hop's renaming.

    Lowercase, and every non-alphanumeric character dropped. ``-`` and
    ``_`` are the pair that matters — CGI, WSGI, and every front end that
    round-trips a header through an environment variable map one to the
    other, so ``Transfer_Encoding`` is ``Transfer-Encoding`` to them and a
    header of no consequence to ``email.parser``. ``.``, doubled
    separators, and a leading or trailing one go the same way, because the
    fold is not an enumeration of the separators seen so far: it keeps only
    the characters that carry the NAME and discards everything that merely
    punctuates it.

    THIS IS THE WIDER OF THE TWO RULES THIS REPOSITORY HAD. It lived in
    C10 while ``_FRAMING_CONFUSABLE_RE`` lived here, and the promotion
    round exported the NARROWER one to the other three servers. Both are
    asked now, and a name refused by either is refused: the regex reaches
    one-character confusions the fold keeps (``Transfer0Encoding`` folds to
    itself), the fold reaches every extra or misplaced separator the regex
    cannot express (``Con-tent-Length``, ``Content-Length-``,
    ``_Transfer-Encoding``). Neither is a superset of the other, so the
    union is the rule and there is exactly one union.
    """
    return "".join(c for c in name.lower() if c.isascii() and c.isalnum())


#: ``_FRAMING_FIELD_NAMES`` under that fold. Precomputed so the hot path
#: compares against a set rather than rebuilding it per header, and DERIVED
#: from the same tuple the regex is derived from, so adding a third framing
#: header extends both halves of the rule with no second edit.
_FOLDED_FRAMING_NAMES = frozenset(
    _fold_header_name(n) for n in _FRAMING_FIELD_NAMES
)


@dataclass(frozen=True)
class FramingVerdict:
    """What ``framing_verdict`` decided about ONE request's framing.

    Four fields and nothing else:

    * ``length`` — the body length this server can be CERTAIN of, or
      ``None`` when no length can be trusted. Never negative, never
      non-numeric: a caller may hand it straight to ``rfile.read``.
    * ``framed`` — ``False`` exactly when ``length`` is ``None``, i.e.
      when this request's body cannot be framed at all. Carried as its
      own field so a caller reads an intent rather than re-deriving one
      from a sentinel.
    * ``must_close`` — ``True`` when the connection MUST be closed after
      answering, whatever the answer is. That is every unframable
      request, and also a request that IS framed but declares octets the
      caller has already said it will not read (``body_expected=False``
      with a non-zero length): those octets stay on the wire and a
      keep-alive peer frames them as the next request line.
    * ``reason`` — a short machine string from ``FRAMING_REASONS``, for
      the caller's logs and its own error vocabulary.

    DELIBERATELY NOT HERE: HTTP status codes and error envelopes. This
    object is consumed by four servers in this repository with three
    different error vocabularies — the mint answers §3.8 ``bad_format``
    at call level, the Supervision Profile answers its own ``rejected``
    shape, and the two operator consoles answer theirs — so a verdict
    that carried a status would be a verdict only one of them could use,
    and the other three would go back to writing their own rule. Framing
    is the part they must agree on; how they say no is not.
    """

    length: int | None
    framed: bool
    must_close: bool
    reason: str


#: Every value ``FramingVerdict.reason`` can carry, so a caller can map the
#: set exhaustively and a new one cannot appear unnoticed.
FRAMING_REASONS = (
    "ok",
    "header_block_defective",
    "header_block_unparsed",
    "header_shape_unreadable",
    "header_line_folded",
    "header_name_not_token",
    "framing_name_confusable",
    "framing_name_folded",
    "content_length_duplicated",
    "content_length_absent",
    "content_length_malformed",
    "declared_body_unread",
)

_FRAMED_OK = FramingVerdict(length=0, framed=True, must_close=False, reason="ok")


def _unframable(reason: str) -> FramingVerdict:
    """The one verdict that is safe whichever way another hop reads this
    request: no trusted length, and do not reuse the socket."""
    return FramingVerdict(
        length=None, framed=False, must_close=True, reason=reason
    )


def framing_verdict(headers, *, body_expected: bool = True) -> FramingVerdict:
    """THE request-framing rule, for every HTTP server in this repository.

    ``headers`` is the parsed message object an ``http.server`` handler
    holds as ``self.headers`` (an ``email.message.Message``). Nothing else
    about the handler is read, which is the point: the rule is a function
    of the parsed header block and of one caller fact — whether this
    caller is about to read a body — so four servers can ask it about
    identical wire bytes and get identical answers.

    WHY THIS IS SHARED AND NOT COPIED. It was copied. The mint was fixed
    for one spelling of one header, then fixed properly against the class,
    and the two other servers in the same repository kept the version that
    was wrong — nineteen of twenty-five spellings still worked against
    them. A framing rule that each server re-derives is a framing rule
    that drifts, and the half that drifts is the smuggleable half.
    Everything below is the mint's rule, unchanged in behaviour, with its
    only caller-specific input (``body_expected``) taken as an argument
    instead of read off a handler.

    The question it answers is the only one that has a safe answer: how
    many octets of this request belong to its body? A number means the
    stream can be re-framed after the answer and the connection may be
    reused. ``None`` means it cannot, whatever the reason, and the caller
    must hang up.

    Derived from what is definitely known, never from what a header
    happens to be called:

    * A header block this parser could not read whole — a defect, an
      unread remainder left in the message payload, or a name or value
      carrying an obsolete folded continuation. See the code: this is
      the precondition, not a separate rule.
    * More than one ``Content-Length`` — the CL.CL smuggling pair. Two
      stated lengths are not a length; an intermediary may believe the
      other one. Any duplicate, not only a disagreeing one, because
      "identical" is a judgement about whitespace and leading zeros
      that we would have to make the same way as every proxy in the
      path.
    * A field name that is not an RFC 7230 ``token`` — ``_TCHAR``. A
      name carrying ``;``, ``"``, ``(`` or a control byte is a name no
      two parsers have to agree on, and agreement is the only thing
      framing rests on.
    * Any field name that could carry framing meaning to ANY hop, asked
      TWO ways whose union is the rule: ``_fold_header_name`` (lowercase,
      every non-alphanumeric character dropped) landing on a framing name
      without BEING that name, and ``_FRAMING_CONFUSABLE_RE``, derived
      from the two framing header
      names by letting each hyphen be any single character or any run
      of punctuation, including none at all. Neither reaches everything
      the other does — the regex can only express confusion at the one
      separator position, so ``Con-tent-Length``, ``Content-Length-`` and
      ``_Transfer-Encoding`` fell out of it entirely and were IGNORED
      rather than refused, while the fold cannot see a one-character
      substitution like ``Transfer0Encoding``. Both halves lived in this
      repository already, in two different files; the round that promoted
      one of them to the shared rule promoted the narrower, and 435 names
      that the Supervision Profile refused were framed by the mint, the
      GUI and the console. Asking both is what makes "one rule" true
      rather than merely single-sourced. This
      clause exists because a stated length can be a LIE: this stack
      does not dechunk, so ``Transfer-Encoding: chunked`` beside
      ``Content-Length: 0`` makes the length rule below believe a body
      that is not there, and the clause that caught it was for one
      round a lookup of one exact spelling. Sixteen other spellings of
      the same field name walked past it beside a truthful
      ``Content-Length: 0`` — and a truthful length is precisely where
      no other clause can help, because there is nothing wrong with it.
      The rule is now a property of the NAME rather than a list of
      names: a field this server cannot be sure is inert is a field it
      declines to frame a connection around. It is never obeyed, only
      refused — honouring ``Transfer_Encoding`` would be inventing a
      dialect, and the safe answer does not require guessing which
      rewrites are live upstream.
    * A ``Content-Length`` that is not a bare run of ASCII digits of a
      plausible size. RFC 7230 §3.3.2 says ``1*DIGIT`` and nothing
      else, while ``int()`` also accepts a leading ``+``, PEP 515
      underscore separators and surrounding whitespace: ``+53`` and
      ``5_3`` both became 53 here and are rejected or read as zero by
      other parsers, which is a desync with a mint-side body attached.
      The digit run is length-capped as well, so ``int()`` can never
      meet CPython's int/str conversion limit and raise out of a
      framing decision — the D2 defect, met on the D1 path.
    * No ``Content-Length`` at all, on a request whose body the caller
      was about to read (``body_expected``). THIS is the clause
      that closes the class. An absent length on a body-bearing method
      is not "no body": it is "no statement", and no statement is
      exactly what every mangled, misspelled or front-end-rewritten
      framing header degrades into by the time it reaches this parser.
      The server cannot tell "the peer sent nothing" from "the peer
      sent something this parser dropped", so it does not try; it
      declines to reuse the connection either way. The cost is one
      keep-alive round trip on a request that has no readable JSON
      body and therefore fails anyway; the benefit is that no spelling
      of a body-framing header, present or future, can leave octets on
      a pooled socket.

      ``body_expected`` is False only for a GET-shaped guard, where an
      absent Content-Length is the ordinary case for every conforming
      client and means a body length of zero. Closing there would cost
      keep-alive on every well-formed GET and buy nothing: a route that
      reads no body has nothing for a dropped header to mis-size. What
      it buys instead is ``must_close``: a GET that DECLARES octets
      nobody will read still cannot keep its connection, because the
      octets are still on the wire.
    """
    if headers.defects:
        # A header block the parser could not read WHOLE. The email
        # parser drops `Transfer-Encoding : chunked` (one space before
        # the colon) entirely and records a defect instead, so a length
        # computed from what survived is a length computed from part of
        # the request -- and "part of the request" is exactly what an
        # intermediary and this server then disagree about. This is the
        # PRECONDITION on everything below rather than a second rule:
        # "no computable length" only means anything if the header block
        # was fully computed. Proved necessary by adversarial sweep, not
        # by argument: `Content-Length: 57` beside a SPACED
        # Transfer-Encoding survives every clause below (the length is
        # single, parseable and honest, and the transfer coding is
        # invisible), frames cleanly, and keeps the connection -- the
        # CL.TE half of the same smuggling pair, still open after the
        # length rule alone. RFC 7230 §3.2.4 requires rejecting
        # whitespace before the colon for precisely this reason.
        return _unframable("header_block_defective")
    payload = headers.get_payload()
    if not isinstance(payload, str) or payload:
        # The precondition has to be the property it claims, not a
        # paraphrase of it, because everything below rests on it.
        # `defects` alone is not "the parser read the whole block":
        # email's feedparser has a SILENT stop, where a final header
        # line beginning with `From ` is unread-lined into the message
        # payload and header parsing simply RETURNS, with no defect
        # recorded. What is left in the payload is header-block bytes
        # this server never interpreted, and "bytes we did not read"
        # is the same situation as a defect however quietly the parser
        # reached it. C10's own framing rule already checked this while
        # Layer 0 did not, and Layer 0 asking a weaker question than the
        # profile layered on top of it is the drift that makes two rules
        # on one socket disagree. There is no C10 rule now: this clause,
        # its token check and its hard fold all live here, so the drift
        # has nowhere to happen.
        return _unframable("header_block_unparsed")
    lengths = []
    for name, value in headers.items():
        if not isinstance(name, str) or not isinstance(value, str):
            # A shape this rule does not read. email can hand back a
            # non-str for a defective line; "cannot read it" is the
            # answer, not "it is not a framing header".
            return _unframable("header_shape_unreadable")
        if "\r" in name or "\n" in name or "\r" in value or "\n" in value:
            # Obsolete line folding (RFC 7230 §3.2.4, which lets a
            # server reject it outright). A folded line is the OTHER way
            # a framing header disappears without a defect: a
            # continuation line beginning with a space is swallowed into
            # the value of whatever preceded it, so
            # `Host: h` + ` Transfer-Encoding: chunked` registers as one
            # Host header and no transfer coding at all, with nothing
            # flagged. Refusing every folded name or value covers that
            # without naming the header that got swallowed.
            return _unframable("header_line_folded")
        if not name or not _TCHAR.issuperset(name):
            # Not an RFC 7230 token. `Content-Length;`, `Transfer-Encoding.`
            # and `Content-Length"` parse cleanly here, carry no defect and
            # no fold, and are read as framing by anything that tokenises
            # more forgivingly than this parser. A name two parsers need
            # not agree on cannot frame a connection, whatever it means.
            return _unframable("header_name_not_token")
        key = name.strip().lower()
        if _fold_header_name(name) in _FOLDED_FRAMING_NAMES and (
            key not in _FRAMING_FIELD_NAMES
        ):
            # A framing header wearing a separator we fold and somebody
            # else folds differently: `Con-tent-Length`, `Content-Length-`,
            # `_Transfer-Encoding`, `Content__Length`. Refuse ON the fold
            # rather than deciding which reading is right. See
            # `_fold_header_name`: this clause and the regex below reach
            # different names, and the union is the rule.
            return _unframable("framing_name_folded")
        if key == "content-length":
            lengths.append(value)
        elif _FRAMING_CONFUSABLE_RE.fullmatch(key):
            # Either a transfer coding (which this stack cannot consume
            # whatever it says) or a name some other hop may read as one
            # of the two framing headers. See _FRAMING_CONFUSABLE_RE:
            # the verdict is "no certain length", never "obey it".
            return _unframable("framing_name_confusable")
    if len(lengths) > 1:
        return _unframable("content_length_duplicated")
    if not lengths:
        if body_expected:
            return _unframable("content_length_absent")
        return _FRAMED_OK
    # OWS is SP and HTAB (RFC 7230 §3.2.3) and nothing else. Bare
    # `str.strip()` is PYTHON's whitespace set, which also eats
    # \x0b \x0c \x1c \x1d \x1e \x1f \x85 and \xa0 — so
    # `Content-Length: 5\x0b` was stripped to "5", matched the digit
    # pattern and framed five octets, while any parser using HTTP's
    # own definition sees an invalid length and (RFC 7230 §3.3.3 rule
    # 4) must not recover. \xa0 is legal obs-text, so that header line
    # is WELL FORMED and only its value is invalid: nothing upstream
    # rejects the message for us. Handing a spec-strict pattern the
    # output of a Python-defined strip put the looseness straight back
    # that the pattern had just removed from int().
    value = lengths[0].strip(" \t")
    if not _CONTENT_LENGTH_RE.fullmatch(value):
        return _unframable("content_length_malformed")
    length = int(value)
    if not body_expected and length != 0:
        # Framed, stated, and about to go unread: the octets are still on
        # the wire, so the connection cannot carry another request. The
        # length is still trustworthy and is still reported -- this is a
        # statement about the CALLER (it said it would not read a body),
        # not about the request, which is perfectly well formed.
        return FramingVerdict(
            length=length,
            framed=True,
            must_close=True,
            reason="declared_body_unread",
        )
    return FramingVerdict(
        length=length, framed=True, must_close=False, reason="ok"
    )

_FAT_ENTRY_BYTES = 384

# Allowance for everything outside the two entry arrays: the idempotency_key
# (bounded by MAX_IDEMPOTENCY_KEY_LEN above), the three envelope keys, the
# brackets and the separators — under 300 bytes in the worst case. 1024 is
# deliberate slack, not a measurement.
_ENVELOPE_BYTES = 1024


def _max_batch_ceiling(body_cap: int | None = None) -> int:
    """Largest ``max_batch`` a body cap of ``body_cap`` bytes can carry.

    ``body_cap`` defaults to the LIVE value of MAX_BODY_BYTES, read at call
    time. Spelling that default as ``body_cap: int = MAX_BODY_BYTES`` binds
    it at IMPORT instead, which is the same cap-versus-cap drift this
    arithmetic exists to prevent: ``_Handler._read_json`` reads the global
    per request, so a deployment that retunes MAX_BODY_BYTES would have had
    its config validated against the old number while the reader enforced
    the new one — and the refusal it printed quoted the new one while
    refusing on the old, making its own remedy inert.

    At least 1: a mint that cannot carry one entry is broken in a way this
    arithmetic is not the place to report.
    """
    if body_cap is None:
        body_cap = MAX_BODY_BYTES
    return max(1, (body_cap - _ENVELOPE_BYTES) // _FAT_ENTRY_BYTES)


# Wall-clock life of ONE request: request line, headers and body together.
# ``_Handler.timeout`` is a per-recv IDLE timeout and nothing more — a peer
# that sends one byte every few seconds resets it on every recv, so
# ``Content-Length: 1048576`` (exactly at MAX_BODY_BYTES, so the byte cap
# never fires) plus a drip holds a daemon thread and a file descriptor for
# as long as the attacker keeps dripping; ThreadingHTTPServer caps neither
# connections nor threads, so N such sockets are N parked threads. That is
# the same exhaustion the idle timeout was added for, only cheaper to mount,
# so the deadline is enforced in wall clock, not idleness (``_DeadlineRaw``).
# 30s against the ~77 KiB of a full max_batch call is a floor of ~2.5 KiB/s,
# far below any link a mint is reachable on and far above what a drip is.
MAX_REQUEST_SECONDS = 30.0

# §3.6 snapshot_seq allocation block. See _Core._next_snapshot_seq: the seq
# is handed out from a reserved in-memory block so a descriptor fetch is a
# read, not a write, amortizing one sqlite write over this many snapshots.
_SEQ_BLOCK = 1024

_PERFORMANCE_FIELDS = frozenset(
    {"p99_exchange_ms", "sustained_qps", "window_days", "measured_at"}
)


def _require_plain_int(name: str, value: object, minimum: int | None = None):
    if type(value) is not int:
        raise ValueError(f"{name} must be a plain int")
    if minimum is not None and value < minimum:
        raise ValueError(f"{name} must be >= {minimum}")
    return value


def _default_rate() -> dict:
    # §3.6 pinned schema: per_caller_rps, burst, scope. OPEN-QUESTIONS R15
    # closed the old Open #3 and pinned scope as mandatory; this function was
    # still emitting the pre-resolution shape. Found 2026-09-08 by an outside
    # implementation reading the descriptor against §3.6.
    return {"per_caller_rps": 50, "burst": 200, "scope": "ip"}


RATE_SCOPES = ("ip", "connection", "global")


def _validate_rate(name: str, r: object) -> None:
    """Enforce the §3.6 pinned rate schema.

    Nothing checked this, which is how the descriptor shipped without `scope`
    against a decision (OPEN-QUESTIONS R15) that had already closed pinning it
    as mandatory. A published descriptor is a conformance claim; an unvalidated
    one is a claim nobody checked.
    """
    if not isinstance(r, dict):
        raise ValueError(f"{name} must be a dict")
    missing = {"per_caller_rps", "burst", "scope"} - set(r)
    if missing:
        raise ValueError(f"{name} missing §3.6 pinned field(s): "
                         f"{', '.join(sorted(missing))}")
    if isinstance(r["per_caller_rps"], bool) or not isinstance(
            r["per_caller_rps"], (int, float)):
        raise ValueError(f"{name}.per_caller_rps must be a number")
    _require_plain_int(f"{name}.burst", r["burst"], 0)
    if r["scope"] not in RATE_SCOPES:
        raise ValueError(f"{name}.scope must be one of {', '.join(RATE_SCOPES)}")


def _policy_dict(p: BurnPolicy) -> dict:
    return {
        "rate_ppm": p.rate_ppm,
        "cap_mc": p.cap_mc,
        "exempt_below_mc": p.exempt_below_mc,
    }


@dataclass(frozen=True)
class MintConfig:
    """Everything a mint advertises and enforces at the HTTP surface.

    ``burn_policy_next`` is ``None`` or ``(BurnPolicy, effective_at_ms)``
    (§7.3 change notice, rendered as the §3.6 descriptor field).
    ``burn_policy_announced_at`` is the mint-clock instant that notice was
    PUBLISHED, and it is mandatory whenever ``burn_policy_next`` raises the
    burn for any sum: §7.3 requires such an increase to be announced at
    least seven days (or ``max_lock_expiry_ms``, whichever is longer)
    before it takes effect, and that interval is unmeasurable without the
    announcement time. It is config, not a clock read (L17), and it is not
    a §3.6 descriptor field — a restarted mint must be able to re-state a
    notice it gave a week ago without its notice period restarting. A
    decrease needs none (decreases may be immediate).
    ``performance`` is ``None`` or the §3.6 self-attested dict (rendered
    ``null`` when stale — L11).

    ``admin_token`` is MANDATORY and has no default: it is one of a
    non-empty secret string (``/admin/issue`` is gated on a constant-time
    ``X-Admin-Token`` match), ``ADMIN_ISSUANCE_DISABLED`` (the endpoint
    answers 401 to everyone), or ``ADMIN_ISSUANCE_OPEN`` (unauthenticated
    issuance, opted into by name). Leaving it out — or passing ``None``,
    which is what used to mean "allow everyone" — raises. See the
    ADMIN_ISSUANCE_* block above for why the refusal is here and not at
    request time. Layer 0 endpoints never require any of it (L2/§3.7).
    """

    mint_id: str
    baseline_model_class: str
    burn_policy: BurnPolicy
    signing_private: bytes
    signing_public: bytes
    denominations_mc: tuple[int, ...] = (1, 10, 100, 1_000, 10_000, 100_000)
    burn_policy_next: tuple[BurnPolicy, int] | None = None
    burn_policy_announced_at: int | None = None
    max_batch: int = 256
    anonymous_rate: dict = field(default_factory=_default_rate)
    registered_rate: dict = field(default_factory=_default_rate)
    grace_ms: int = 5_000
    timestamp_precision_ms: int = 1
    max_lock_expiry_ms: int | None = 30 * _DAY_MS
    recovery_window_ms: int = 90 * _DAY_MS
    prunes_spent_records: bool = False
    policy_url: str = "about:blank"
    performance: dict | None = None
    profiles: tuple[str, ...] = ()
    # No default that grants anything: _ADMIN_TOKEN_UNSET is rejected
    # by __post_init__. Keyword-only would also work; a sentinel is
    # used so the refusal can carry _ADMIN_TOKEN_GUIDANCE rather than
    # Python's bare "missing required argument".
    admin_token: str | _AdminIssuanceMode = _ADMIN_TOKEN_UNSET

    def __post_init__(self):
        if not isinstance(self.mint_id, str) or not self.mint_id:
            raise ValueError("mint_id must be a non-empty string")
        if not MINT_ID_RE.fullmatch(self.mint_id):
            # The exact §3.1 rule C01 pins for token strings — a config
            # that violates it would mint tokens no parser accepts.
            raise ValueError(
                "invalid mint_id %r: a mint_id must be 1-64 characters of"
                " lowercase ASCII letters, digits, or hyphen"
                " (regex ^[a-z0-9-]{1,64}$; tokencodec.MINT_ID_RE)"
                % (self.mint_id,)
            )
        if not isinstance(self.baseline_model_class, str):
            raise ValueError("baseline_model_class must be a string")
        validate_policy(self.burn_policy)
        if self.burn_policy_next is not None:
            next_policy, effective_at = self.burn_policy_next
            validate_policy(next_policy)
            _require_plain_int("burn_policy_next effective_at", effective_at, 0)
        if self.burn_policy_announced_at is not None:
            _require_plain_int(
                "burn_policy_announced_at", self.burn_policy_announced_at, 0
            )
            if self.burn_policy_next is None:
                raise ValueError(
                    "burn_policy_announced_at is set but burn_policy_next is"
                    " None: an announcement time with nothing announced is a"
                    " notice the operator believes they gave and this mint"
                    " publishes nowhere. Set burn_policy_next, or drop the"
                    " announcement time."
                )
        _validate_rate("anonymous_rate", self.anonymous_rate)
        _validate_rate("registered_rate", self.registered_rate)
        for kb in ("signing_private", "signing_public"):
            v = getattr(self, kb)
            if not isinstance(v, bytes) or len(v) != 32:
                raise ValueError(f"{kb} must be 32 raw bytes")
        for d in self.denominations_mc:
            _require_plain_int("denomination", d, 1)
        _require_plain_int("max_batch", self.max_batch, 1)
        # max_batch is PUBLISHED (§3.6 limits.max_batch) and MAX_BODY_BYTES
        # is not, so a config whose published limit the byte cap cannot carry
        # makes the mint advertise a batch size whose maximal call it
        # always refuses — and refuses with `bad_format`, which §9.5 pins as
        # PERMANENT, so a payer aiming at the published limit with entries of
        # ordinary size has no conforming recovery. (Smaller entries still
        # get through at such a max_batch, which is what made this silent:
        # the limit is not unusable, only unreachable at the size it
        # promises.)
        # The two numbers were never cross-checked: max_batch=8000 was
        # accepted silently. Refused at construction instead, because the
        # alternative is a descriptor that lies.
        ceiling = _max_batch_ceiling(MAX_BODY_BYTES)
        if self.max_batch > ceiling:
            # The BUDGET, not a measurement: _FAT_ENTRY_BYTES is an
            # allowance over the fattest conforming entry (see its comment),
            # so this number is what the mint sizes against, which is what
            # an operator has to move to get past this refusal. Raising
            # MAX_BODY_BYTES to exactly this figure admits exactly this
            # max_batch — the arithmetic below is the same one, inverted.
            budget = _ENVELOPE_BYTES + self.max_batch * _FAT_ENTRY_BYTES
            raise ValueError(
                "max_batch=%d exceeds what this mint's request body cap can"
                " carry: at an allowance of %d bytes per entry plus %d for"
                " the envelope, a call at that published limit is budgeted"
                " at about %d bytes against a MAX_BODY_BYTES of %d, so the"
                " mint would advertise in limits.max_batch a batch size its"
                " own body cap refuses with a permanent bad_format. Lower"
                " max_batch to %d or below, or raise MAX_BODY_BYTES to at"
                " least %d."
                % (self.max_batch, _FAT_ENTRY_BYTES, _ENVELOPE_BYTES,
                   budget, MAX_BODY_BYTES, ceiling, budget)
            )
        _require_plain_int("grace_ms", self.grace_ms, 0)
        _require_plain_int(
            "timestamp_precision_ms", self.timestamp_precision_ms, 1
        )
        if self.max_lock_expiry_ms is not None:
            _require_plain_int("max_lock_expiry_ms", self.max_lock_expiry_ms, 1)
        _require_plain_int("recovery_window_ms", self.recovery_window_ms, 0)
        # §7.3 change notice. Placed after max_lock_expiry_ms is known to
        # be a valid int, because the required notice is
        # `max(7 days, max_lock_expiry_ms)` — the lock horizon is half the
        # rule, not a decoration on it: funds locked mid-flight must not be
        # repriced by surprise, so a mint that lets locks run longer than a
        # week owes correspondingly longer notice.
        #
        # This ran nowhere before. burncalc has carried validate_notice
        # since C03 and no configuration path called it, so a burn INCREASE
        # with a hundred SECONDS of notice was accepted at construction and
        # published in the descriptor as a conforming §7.3 notice. Refused
        # here, with the other refusals, for the reason the admin-token
        # block states at length: an operator finds out when they build the
        # config, not when counterparties' locked funds reprice under them.
        if self.burn_policy_next is not None:
            next_policy, effective_at = self.burn_policy_next
            if is_increase(self.burn_policy, next_policy):
                if self.burn_policy_announced_at is None:
                    raise ValueError(
                        "burn_policy_next %r raises the burn over the current"
                        " policy %r, and §7.3 requires such an increase to be"
                        " announced at least 7 days (or max_lock_expiry_ms,"
                        " whichever is longer) before effective_at. That"
                        " interval cannot be checked without knowing WHEN the"
                        " notice was published, so set"
                        " burn_policy_announced_at to the mint-clock"
                        " millisecond at which this burn_policy_next was first"
                        " published. (A burn DECREASE may be immediate and"
                        " needs no announcement time.)"
                        % (next_policy, self.burn_policy)
                    )
                # Raises burncalc.PolicyError (a ValueError) naming the
                # notice actually given and the notice required.
                validate_notice(
                    self.burn_policy,
                    next_policy,
                    self.burn_policy_announced_at,
                    effective_at,
                    self.max_lock_expiry_ms,
                )
        if self.prunes_spent_records and self.max_lock_expiry_ms is None:
            # §8(b): prunes_spent_records: true REQUIRES a finite lock horizon.
            raise ValueError(
                "prunes_spent_records requires a finite max_lock_expiry_ms"
            )
        # (rate schemas validated above by _validate_rate against the §3.6
        # pinned shape. The loop that stood here required every value to be a
        # plain int, which did not merely omit the mandatory `scope` field —
        # it made adding it raise. The descriptor could not have conformed.)
        if self.performance is not None:
            perf = self.performance
            if not isinstance(perf, dict) or set(perf) != _PERFORMANCE_FIELDS:
                raise ValueError(
                    "performance must be None or have exactly the fields "
                    f"{sorted(_PERFORMANCE_FIELDS)}"
                )
            for k in _PERFORMANCE_FIELDS:
                _require_plain_int(f"performance.{k}", perf[k], 0)
            _require_plain_int("performance.window_days", perf["window_days"], 1)
        # The publish blocker (see the ADMIN_ISSUANCE_* block above): the
        # absence of a credential is REFUSAL, not permission, and it is
        # refused here — at construction — so no mint ever binds a port
        # without someone having said which of the three states it is in.
        tok = self.admin_token
        if tok is _ADMIN_TOKEN_UNSET:
            raise ValueError(
                "admin_token was not set.\n" + _ADMIN_TOKEN_GUIDANCE
            )
        if tok is None:
            # Called out separately from "not set": None was the old spelling
            # of ADMIN_ISSUANCE_OPEN, so code carrying it forward is code that
            # asked for an open mint in the old vocabulary. It must not be
            # read as ADMIN_ISSUANCE_DISABLED by accident (that would silently
            # break a deliberate demo) nor honored as open (that would keep
            # the hole). It is an error, naming both replacements.
            raise ValueError(
                "admin_token=None no longer means anything. It used to mean"
                " 'allow everyone', which is how /admin/issue came to be open"
                " by default.\n" + _ADMIN_TOKEN_GUIDANCE
            )
        if tok is ADMIN_ISSUANCE_OPEN or tok is ADMIN_ISSUANCE_DISABLED:
            pass
        elif isinstance(tok, str):
            if not tok:
                raise ValueError(
                    "admin_token must be a NON-EMPTY string. An empty string"
                    " is not a credential: it would gate /admin/issue on an"
                    " empty X-Admin-Token header, which every caller can"
                    " send.\n" + _ADMIN_TOKEN_GUIDANCE
                )
            if not tok.strip():
                # Same hole as the empty string, reached the way it actually
                # happens: a credential read from a file or an environment
                # variable that turned out to hold only a newline or a run of
                # spaces. `if not tok` lets those through -- they are truthy --
                # so the mint would come up gated on whitespace, which every
                # caller can send just as easily as an empty header. It is
                # refused rather than stripped, because stripping would
                # silently serve a DIFFERENT credential than the one supplied.
                # Whitespace INSIDE an otherwise real token is left alone.
                raise ValueError(
                    "admin_token is %d character(s) of whitespace and nothing"
                    " else, which is not a credential: /admin/issue would be"
                    " gated on a header any caller can send. This is what an"
                    " empty token file or an unset environment variable looks"
                    " like by the time it gets here. It is refused rather than"
                    " trimmed, because trimming would gate the mint on a"
                    " credential you did not supply.\n"
                    % (len(tok),) + _ADMIN_TOKEN_GUIDANCE
                )
        elif isinstance(tok, _AdminIssuanceMode):
            # An issuance mode that is not one of the two public ones. The
            # sentinels preserve identity across copy/pickle now (see
            # _AdminIssuanceMode), so the only way to get here is to have
            # constructed a mode of your own -- and this message must not
            # claim the value "is not one of the named issuance modes" when
            # its own repr() may well print one of those names. Say what is
            # actually wrong: it is not THE object.
            raise ValueError(
                "admin_token was given an issuance mode (%r) that is not the"
                " ADMIN_ISSUANCE_OPEN or ADMIN_ISSUANCE_DISABLED object from"
                " aicash.mintapi. These are compared by identity, so a"
                " look-alike built elsewhere is not accepted; import the"
                " names rather than reconstructing them.\n" % (tok,)
                + _ADMIN_TOKEN_GUIDANCE
            )
        else:
            # The TYPE, never the value: whatever was passed was meant to be
            # a credential, and §3.1 requirement 5's rule about not putting
            # secret material into log streams applies to exception text just
            # as much (a ValueError from a mint that fails to start is going
            # straight into somebody's log).
            raise ValueError(
                "admin_token was given a %s, which is not a credential and is"
                " not one of the named issuance modes. (The value is not"
                " echoed here: it was meant to be a secret.)\n"
                % (type(tok).__name__,) + _ADMIN_TOKEN_GUIDANCE
            )


def _call_rejection(reason: str) -> tuple[int, dict]:
    """§3.8 call-level rejection body (same shape C04 uses for call errors)."""
    return 400, {
        "status": "rejected",
        "errors": [{"index": None, "kind": "call", "reason": reason}],
    }


#: THE STATUS WORD FOR A STATUS CODE, SPELLED HERE.
#:
#: These used to be derived from ``BaseHTTPRequestHandler.responses[code]``'s
#: reason phrase, which handed this mint's MACHINE-READABLE vocabulary to
#: CPython: python3.12 spells ``HTTPStatus(414).phrase`` "Request-URI Too
#: Long" and derived ``request_uri_too_long``, and CPython has already
#: renamed several of these members for RFC 9110 (413, 414, 416, 422), so
#: the same mint on a different interpreter answered a DIFFERENT word for
#: the same request. A field a client matches on cannot move with the
#: interpreter. HTTP does not define these slugs — a table does — so the
#: table is here, next to the only server that sends them, the way the
#: operator GUI and the operator console hand-write theirs.
_TRANSPORT_STATUS = {
    400: "bad_request",
    401: "unauthorized",
    404: "not_found",
    405: "method_not_allowed",
    408: "request_timeout",
    411: "length_required",
    413: "payload_too_large",
    414: "uri_too_long",
    431: "header_fields_too_large",
    500: "internal_error",
    501: "not_implemented",
    505: "http_version_not_supported",
}

#: WHY, per code, for the refusals the standard library raises itself
#: through ``send_error`` — a request line it cannot parse (400), one past
#: 64 KiB (414), a header block past its limits (431), a method with no
#: handler (501), a version it will not speak (505).
#:
#: A separate word from the status, on purpose: ``send_error`` used to pass
#: the status word in as the reason as well, so ``@@@@`` answered
#: ``{"reason": "bad_request", "status": "bad_request"}`` — a tautology that
#: LOOKS parseable, which is worse than no field at all, next to a
#: ``_refuse_transport`` path that answers a real word (``bad_version``,
#: ``bad_request_target``) in the same field of the same envelope.
_TRANSPORT_WHY = {
    400: "bad_request_line",
    414: "request_line_too_long",
    431: "header_block_too_large",
    501: "unsupported_method",
    505: "bad_version",
}


def _transport_status(code: int) -> str:
    """This mint's status word for a status code, never the interpreter's.

    Unknown codes get ``http_<code>``, which is derived from the CODE and
    so cannot drift either. Nothing here reads ``self.responses``.
    """
    return _TRANSPORT_STATUS.get(code, "http_%d" % code)


def _transport_why(code: int) -> str:
    """The reason word for a refusal the library raised on its own."""
    return _TRANSPORT_WHY.get(code, "transport_refused")


def _transport_rejection(code: int, reason: str) -> dict:
    """A refusal that never reached a route, in this mint's ``status`` shape.

    NOT §3.8. §3.8 rejections are decisions about a CALL — an envelope this
    mint parsed and declined — and every one of them carries ``errors`` with
    a ``kind`` and an ``index``. The bodies here answer requests that never
    became a call at all: a request line the standard library cannot version,
    a target this mint does not route, a header block past the parser's
    limits. Giving those a §3.8 body would tell a payer that its CALL was
    rejected for a reason §9.5 classifies, when in fact nothing this mint
    could classify was ever read.

    So they get the shape the mint's other transport answers already use —
    ``{"status": ...}``, as in ``{"status": "not_found"}`` and
    ``{"status": "unauthorized"}``, whose words are in the table above and
    are literally what this function produces for 404 and 401.

    ``reason`` is the second field and the only added one: the machine word
    for WHY, so ``bad_version`` and ``bad_request_target`` can be told apart
    inside the one status word ``bad_request``. It is ALWAYS a different
    word from the status — see ``_TRANSPORT_WHY`` — so a caller that
    matches on ``reason`` never gets a restatement of the code it already
    has. It is the same field, with the same words, that the operator GUI
    and the operator console put in their own envelopes for the same two
    refusals — three vocabularies, one decision, as ``framing_verdict``'s
    contract has it.

    TWO ENVELOPES IN THIS SERVER, NOT THREE, AND THE LINE IS THE ONE ABOVE.
    This one answers requests that never reached dispatch, and every one of
    them carries both fields. The other is a ROUTE's answer —
    ``{"status": "not_found"}`` for a path no route matches,
    ``{"status": "unauthorized"}`` for a credential a route refused — where
    the method dispatched, the target was read, and the status word IS the
    whole reason; those two are consistent with each other and a ``reason``
    on one of them and not the other is the drift, not the fix.

    THE CALLER'S OWN BYTES ARE NEVER IN HERE. ``BaseHTTPRequestHandler``
    builds its message for an unparseable request line as
    ``"Bad request syntax (%r)" % requestline`` and a request line may be
    64 KiB, so the library's message is up to 64 KiB of the caller's octets
    reflected out of a money server's error body. Neither the library's
    ``message`` nor its reason phrase is read at all.
    """
    return {"status": _transport_status(code), "reason": reason}


_STATE_SCHEMA = """
CREATE TABLE IF NOT EXISTS mintapi_state (
  id                 INTEGER PRIMARY KEY CHECK (id = 1),
  snapshot_seq       INTEGER NOT NULL,
  activity_day       INTEGER NOT NULL,
  activity_count     INTEGER NOT NULL,
  activity_volume_mc INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS mintapi_counted (
  idempotency_key TEXT PRIMARY KEY
);
"""


class _Core:
    """Route logic, shared by all handler threads. Wire in/out only.

    Durable C06 state (``snapshot_seq`` high-water mark, day-windowed
    activity) lives in C06-owned tables inside the ledger's sqlite file,
    via a dedicated connection. All access is serialized by ``self._lock``.
    Writes (activity counting, seq-block reservation) run under ``BEGIN
    IMMEDIATE``; a descriptor serve does not, because it is a read —
    ``self._lock`` alone orders the supply read against seq allocation, so
    (seq, cumulatives) stay jointly monotone (§3.6). See
    ``_next_snapshot_seq`` for why that also holds across restarts.
    """

    def __init__(self, config: MintConfig, ledger: Ledger):
        self.config = config
        self.ledger = ledger
        self._lock = threading.Lock()
        # The Ledger does not expose its db path publicly; the reference
        # implementation reads the private attribute rather than widening
        # C04's API from outside (recorded in the build notes).
        self._state = sqlite3.connect(
            ledger._db_path,
            timeout=30.0,
            isolation_level=None,  # manual txn control, like C04
            check_same_thread=False,  # guarded by self._lock
        )
        # Reserved §3.6 snapshot_seq block, [_seq_next, _seq_limit).
        # Empty at boot; the first descriptor fetch reserves one.
        self._seq_next = 0
        self._seq_limit = 0
        # Single-writer claim over the ledger file; see _claim_single_writer.
        self._lock_path = ledger._db_path
        self._lock_fd: int | None = None
        self._state.executescript(_STATE_SCHEMA)
        self._state.execute(
            "INSERT OR IGNORE INTO mintapi_state (id, snapshot_seq,"
            " activity_day, activity_count, activity_volume_mc)"
            " VALUES (1, 0, -1, 0, 0)"
        )
        self._state.commit()

    # -- single-writer claim over the ledger (§3.6 monotonicity) ---------

    def _claim_single_writer(self) -> None:
        """Take the advisory single-writer lock on this ledger file.

        §3.6 makes "any two signed snapshots violating monotonicity"
        PORTABLE PROOF OF NONCONFORMANCE — it is a property of the mint_id
        and its signing key, not of a process. Snapshot ordering used to be
        held by sqlite: the supply read and the seq bump ran inside one
        ``BEGIN IMMEDIATE`` on the shared file, so any number of processes
        serving one ledger were still jointly monotone. Making the
        descriptor a read moved that ordering onto ``self._lock``, a
        ``threading.Lock`` that exists once per process. Two mints on one
        db file then draw disjoint seq blocks (the reservation is still
        atomic) but order their supply READS independently, so the process
        holding the higher block can sign a higher seq over an older
        supply — an honest mint framed by its own signatures.

        The precondition is therefore enforced, not documented: exactly one
        process may serve a given ledger. ``flock`` is advisory but
        whole-file and released by the kernel on exit, so a crashed mint
        does not wedge its own restart, and it conflicts between two open
        file descriptions even inside one process — two MintServers on one
        db in one interpreter have the same ordering bug and are refused
        the same way. Idempotent: a re-claim by the holder is a no-op.

        Held on the LEDGER FILE itself rather than on a sidecar: nothing
        to leave behind next to a deployment's mint.db, and the claim
        cannot drift from the thing it claims. ``flock`` is safe to put
        there because sqlite's unix VFS locks with POSIX record locks
        (``fcntl(F_SETLK)``), an independent mechanism on Linux — this
        lock neither blocks nor is blocked by any sqlite connection,
        including C04's.

        Raises RuntimeError when another mint holds the ledger.
        """
        if self._lock_fd is not None:
            return
        if fcntl is None:  # pragma: no cover - POSIX-only build target
            return
        fd = os.open(self._lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            raise RuntimeError(
                "another mint process already serves this ledger (%s). One"
                " ledger file is served by exactly one mint: §3.6 snapshot"
                " monotonicity is ordered per process, so a second server"
                " could sign snapshots that are portable proof of"
                " nonconformance against this mint_id. Stop the other"
                " process, or give this mint its own ledger."
                % self._lock_path
            ) from None
        self._lock_fd = fd

    def _release_single_writer(self) -> None:
        fd, self._lock_fd = self._lock_fd, None
        if fd is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    # -- clock (via the Ledger's injected clock; L17 — never wall time) --

    def _mint_time(self) -> int:
        return self.ledger.status([])[0]

    # -- §3.3 wire form parsing ------------------------------------------
    #
    # Anything that fails to parse is passed through raw: C04 reports any
    # non-typed value as `bad_format` at its index (§3.8), which keeps
    # index attribution exact without duplicating the error plumbing.

    def _parse_input(self, val: object):
        if isinstance(val, str):
            try:
                tok = parse_token(val)
            except TokenError:
                return val
            if tok.mint_id != self.config.mint_id:
                return val  # foreign-mint token → bad_format at this index
            return InputForm(kind="plain", token=tok)
        if isinstance(val, dict):
            keys = set(val.keys())
            if keys == {"token", "witness"}:
                try:
                    tok = parse_token(val["token"])
                    witness = b64u_decode(val["witness"])
                except TokenError:
                    return val
                if tok.mint_id != self.config.mint_id:
                    return val
                return InputForm(kind="claim", token=tok, witness=witness)
            if keys == {"hash", "witness"}:
                if not isinstance(val["hash"], str):
                    return val
                try:
                    witness = b64u_decode(val["witness"])
                except TokenError:
                    return val
                return InputForm(
                    kind="refund", hash=val["hash"], witness=witness
                )
        return val

    def _parse_output(self, val: object):
        # C04's parse_output_wire IS the wire parser (shared, never
        # duplicated): Ledger.issue accepts wire dicts through the same
        # code path this HTTP layer uses.
        return parse_output_wire(val)

    # -- POST /v3/exchange ------------------------------------------------

    def exchange(self, body: object) -> tuple[int, dict]:
        if not isinstance(body, dict):
            return _call_rejection("bad_format")
        key = body.get("idempotency_key")
        inputs = body.get("inputs")
        outputs = body.get("outputs")
        if (
            not isinstance(key, str)
            or not key
            # An over-length idempotency key is a malformed envelope, not a
            # property of any one item: §3.8 `bad_format`, kind "call",
            # index null. (The §3.8 vocabulary has no length-specific
            # reason, and §3.8's own example of a call-level rejection is
            # exactly "a malformed envelope".) Enforced HERE rather than in
            # C04 because the cost being bounded is C06's: the key is what
            # a caller writes into the ledger's 90-day recovery window.
            or len(key) > MAX_IDEMPOTENCY_KEY_LEN
            or not isinstance(inputs, list)
            or not isinstance(outputs, list)
        ):
            return _call_rejection("bad_format")
        if len(inputs) + len(outputs) > self.config.max_batch:
            return _call_rejection("over_batch_limit")
        try:
            digest = body_digest(body)  # §3.3: digest over canonical body
        except TokenError:
            return _call_rejection("bad_format")  # e.g. floats — never legal
        parsed_inputs = [self._parse_input(v) for v in inputs]
        parsed_outputs = [self._parse_output(v) for v in outputs]
        try:
            result = self.ledger.exchange(
                key, digest, parsed_inputs, outputs=parsed_outputs
            )
        except ExchangeRejected as exc:
            return 400, {"status": "rejected", "errors": exc.errors}
        volume = result["burn_mc"] + sum(
            spec.amount_mc
            for spec in parsed_outputs
            if isinstance(spec, OutputSpec)
        )
        self._record_activity(key, volume)
        return 200, result

    def _record_activity(self, idempotency_key: str, volume_mc: int) -> None:
        """Count one successful exchange toward the §3.6 activity figures.

        At most once per idempotency key, ever (the ``mintapi_counted``
        primary key persists), so §3.3 replays of an already-executed call
        never double-count. Counters are windowed to the current mint-clock
        day: the first counted exchange of a new day resets them, so
        ``daily_*`` never accumulates a process- or ledger-lifetime total.
        """
        with self._lock:
            self._state.execute("BEGIN IMMEDIATE")
            try:
                cur = self._state.execute(
                    "INSERT OR IGNORE INTO mintapi_counted"
                    " (idempotency_key) VALUES (?)",
                    (idempotency_key,),
                )
                if cur.rowcount == 1:  # first time this call is counted
                    day = self._mint_time() // _DAY_MS
                    row = self._state.execute(
                        "SELECT activity_day, activity_count,"
                        " activity_volume_mc FROM mintapi_state WHERE id = 1"
                    ).fetchone()
                    if row[0] == day:
                        count, vol = row[1] + 1, row[2] + volume_mc
                    else:  # mint-clock day rolled over: fresh window
                        count, vol = 1, volume_mc
                    self._state.execute(
                        "UPDATE mintapi_state SET activity_day = ?,"
                        " activity_count = ?, activity_volume_mc = ?"
                        " WHERE id = 1",
                        (day, count, vol),
                    )
                self._state.execute("COMMIT")
            except BaseException:
                self._state.execute("ROLLBACK")
                raise

    # -- §3.5 status ------------------------------------------------------

    @staticmethod
    def _wire_entry(entry: dict) -> dict:
        """§3.5 pinned per-hash schema: unknown entries carry explicit
        ``lock/spent_at/claim_witness: null`` and no ``amount_mc``."""
        if entry.get("state") == "unknown":
            return {
                "state": "unknown",
                "lock": None,
                "spent_at": None,
                "claim_witness": None,
            }
        return entry

    def status_single(self, h: str) -> tuple[int, dict]:
        mint_time, results = self.ledger.status([h])
        return 200, {"mint_time": mint_time, "result": self._wire_entry(results[0])}

    def status_batch(self, body: object) -> tuple[int, dict]:
        if not isinstance(body, dict):
            return _call_rejection("bad_format")
        hashes = body.get("hashes")
        if not isinstance(hashes, list):
            return _call_rejection("bad_format")
        if len(hashes) > self.config.max_batch:
            return _call_rejection("over_batch_limit")
        mint_time, results = self.ledger.status(hashes)
        return 200, {
            "mint_time": mint_time,
            "results": [self._wire_entry(r) for r in results],
        }

    # -- §3.6 descriptor --------------------------------------------------

    def _next_snapshot_seq(self) -> int:
        """Allocate the next §3.6 ``snapshot_seq``. Caller holds ``_lock``.

        Numbers come from a block reserved with ONE sqlite write per
        ``_SEQ_BLOCK`` snapshots, instead of a write per serve. The value
        PERSISTED at reservation time is the block's high-water mark — the
        largest seq this process may hand out — so any restart, crash
        included, resumes strictly above every seq that could already have
        been signed. §3.6 requires ``snapshot_seq`` to increase, not to be
        contiguous, so the gap an unused block tail leaves is conformant;
        what would be nonconformant (a repeated or regressing seq across a
        restart, §3.6's "portable proof of nonconformance") is exactly what
        persisting the high-water mark rules out.
        """
        if self._seq_next >= self._seq_limit:
            self._state.execute("BEGIN IMMEDIATE")
            try:
                self._state.execute(
                    "UPDATE mintapi_state SET snapshot_seq ="
                    " snapshot_seq + ? WHERE id = 1",
                    (_SEQ_BLOCK,),
                )
                high = self._state.execute(
                    "SELECT snapshot_seq FROM mintapi_state WHERE id = 1"
                ).fetchone()[0]
                self._state.execute("COMMIT")
            except BaseException:
                self._state.execute("ROLLBACK")
                raise
            # Reserved: (high - _SEQ_BLOCK, high]. BEGIN IMMEDIATE makes the
            # bump atomic, so two mints sharing one ledger file get disjoint
            # blocks and neither can reuse the other's numbers.
            self._seq_next = high - _SEQ_BLOCK + 1
            self._seq_limit = high + 1
        seq = self._seq_next
        self._seq_next += 1
        return seq

    def descriptor(self) -> tuple[int, dict]:
        c = self.config
        # Snapshot construction (§3.6). This used to run BEGIN IMMEDIATE and
        # UPDATE snapshot_seq on EVERY fetch, which made an unauthenticated
        # GET /v3/mints take sqlite's write lock on the payment database: a
        # descriptor poller serialized against real exchanges and could stall
        # them for free. A descriptor serve is now a READ — reservation
        # aside, which is one write per _SEQ_BLOCK serves.
        #
        # Monotonicity is preserved by ``self._lock`` instead of by sqlite's
        # write lock. Every snapshot is built while holding it, and the
        # supply read happens BEFORE the seq is allocated, so snapshots
        # ordered by snapshot_seq are also ordered by the instant their
        # supply was read; C04 commits exchanges atomically, so a later read
        # can only see equal-or-greater cumulatives. (seq, cumulatives)
        # therefore stay jointly monotone, and each snapshot still satisfies
        # ``outstanding == issued − burned`` because Ledger.supply() reads
        # all three in a single statement. Nothing is cached: the counters
        # served are read fresh per fetch, never stale behind a completed
        # exchange.
        #
        # That argument holds only for ONE process per ledger, so the claim
        # is re-checked here rather than trusted to whoever started the
        # server: a mint that cannot hold the single-writer lock refuses to
        # sign a snapshot at all (RuntimeError → 500) instead of signing one
        # that might be §3.6 proof of nonconformance against its own key.
        with self._lock:
            self._claim_single_writer()
            mint_time = self._mint_time()
            supply = self.ledger.supply()  # one atomic read (C04)
            snapshot_seq = self._next_snapshot_seq()
            row = self._state.execute(
                "SELECT activity_day, activity_count, activity_volume_mc"
                " FROM mintapi_state WHERE id = 1"
            ).fetchone()
        if row[0] == mint_time // _DAY_MS:
            activity_count, activity_volume = row[1], row[2]
        else:  # counters belong to an earlier mint-clock day: none today
            activity_count, activity_volume = 0, 0
        # mint_id and baseline_model_class ride INSIDE the signed body. §4.1
        # calls a contradicting descriptor portable proof of nonconformance,
        # and that proof is only constructible if a signature covers the
        # field: the supply invariant is portable precisely because each
        # snapshot is signed. Carrying them here also means the archiver
        # network already diffing signed snapshots sees a baseline change with
        # no new code. Found 2026-09-08 by outside review of the fix that
        # introduced the §4.1 claim.
        snapshot = dict(
            supply,
            mint_id=c.mint_id,
            baseline_model_class=c.baseline_model_class,
            snapshot_seq=snapshot_seq,
            snapshot_time=mint_time,
        )
        snapshot = attach_sig(snapshot, c.signing_private)  # C05

        performance = c.performance
        if performance is not None:
            # L11 honesty: stale measurements MUST render null, never zeros.
            age_ms = mint_time - performance["measured_at"]
            if age_ms > performance["window_days"] * _DAY_MS:
                performance = None

        if c.burn_policy_next is None:
            burn_policy_next = None
        else:
            next_policy, effective_at = c.burn_policy_next
            burn_policy_next = {
                "policy": _policy_dict(next_policy),
                "effective_at": effective_at,
            }

        return 200, {
            "mint_id": c.mint_id,
            "baseline_model_class": c.baseline_model_class,
            "mint_time": mint_time,
            "denominations_mc": list(c.denominations_mc),
            "burn_policy": _policy_dict(c.burn_policy),
            "burn_policy_next": burn_policy_next,
            "supply": snapshot,
            "performance": performance,
            "limits": {
                "max_batch": c.max_batch,
                "anonymous_rate": dict(c.anonymous_rate),
                "registered_rate": dict(c.registered_rate),
            },
            "lock_params": {
                "grace_ms": c.grace_ms,
                "timestamp_precision_ms": c.timestamp_precision_ms,
                "max_lock_expiry_ms": c.max_lock_expiry_ms,
            },
            "retention": {
                "recovery_window_ms": c.recovery_window_ms,
                "prunes_spent_records": c.prunes_spent_records,
                "policy_url": c.policy_url,
            },
            "profiles": list(c.profiles),
            "activity": {
                "daily_exchange_count": activity_count,
                "daily_volume_mc": activity_volume,
                "as_of": mint_time,
            },
            "signing_pubkey": pubkey_b64u(c.signing_public),
            # §3.6: "All fields mandatory unless marked profile-scoped", and
            # signing_pubkey_next is typed `null | {...}` and carries no
            # profile marking — so an explicit null IS the conforming way to
            # say "no rotation announced", while omitting the key leaves a
            # client reading §3.6 unable to tell a mint with nothing to
            # announce from an older revision that predates the field.
            # Hard-coded null: rotation itself is out of scope per L17, and
            # nothing in this file may ever set it without the cross-signature
            # §3.6 requires (a new key with no cross-signature from its
            # predecessor is a DIFFERENT SIGNER, and monotonicity proofs do
            # not span the break).
            "signing_pubkey_next": None,
        }

    # -- POST /admin/issue (non-normative §7.1 operator funding) ----------

    def admin_authorized(self, presented_token: str | None) -> bool:
        """Constant-time admin-token check (credential-comparison hygiene).

        True only when the mint was explicitly built ADMIN_ISSUANCE_OPEN, or
        when a configured secret matches the presented header. There is no
        longer a "no token configured" branch that returns True: MintConfig
        will not build without one of the three named states, so by the time
        any request reaches here somebody has decided. ``hmac.compare_digest``
        over utf-8 bytes avoids the timing side channel of ordinary string
        inequality — unchanged, and the reason the match arm is written this
        way rather than with ``==``.
        """
        configured = self.config.admin_token
        if configured is ADMIN_ISSUANCE_OPEN:
            # Opted into by name at construction; see ADMIN_ISSUANCE_OPEN.
            return True
        if not isinstance(configured, str):
            # ADMIN_ISSUANCE_DISABLED, and the fallthrough for anything else
            # that somehow got past validation: refuse. Never "allow".
            return False
        presented = presented_token if isinstance(presented_token, str) else ""
        return hmac.compare_digest(
            configured.encode("utf-8", "surrogateescape"),
            presented.encode("utf-8", "surrogateescape"),
        )

    def admin_issue(self, body: object, presented_token: str | None):
        if not self.admin_authorized(presented_token):
            return 401, {"status": "unauthorized"}
        if not isinstance(body, dict):
            return _call_rejection("bad_format")
        outputs = body.get("outputs")
        if not isinstance(outputs, list):
            return _call_rejection("bad_format")
        parsed = [self._parse_output(v) for v in outputs]
        try:
            self.ledger.issue(parsed)
        except ExchangeRejected as exc:
            return 400, {"status": "rejected", "errors": exc.errors}
        return 200, {"status": "ok", "outputs_confirmed": len(parsed)}


class _MintHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    core: _Core  # set by MintServer.start

    def handle_error(self, request, client_address):
        # Never print tracebacks (default behavior) — log route-free notice.
        logger.info("connection error")


class _DeadlineRaw(io.RawIOBase):
    """The handler's raw read side, under a WALL-CLOCK request deadline.

    An idle timeout alone does not bound a request. ``_Handler.timeout``
    is applied per recv, so a peer that sends one byte every few seconds
    resets it forever: a declared body at exactly MAX_BODY_BYTES (the cap
    never fires) dripped one byte at a time parks a daemon thread and an
    fd indefinitely, and ThreadingHTTPServer caps neither. So every recv
    of a request — request line, headers and body alike — gets the SMALLER
    of the idle timeout and the time left on ``handler.request_deadline``,
    and an expired deadline raises before the syscall.

    Sitting under ``io.BufferedReader`` rather than replacing it is what
    makes this whole-request: BufferedReader's own loops (``readline``
    over headers, ``read(n)`` over a body) come back through ``readinto``
    for every refill, so each refill re-checks the clock. Wrapping the
    BufferedReader instead would have set one timeout for an entire
    blocking read and bounded nothing.

    The exception raised is ``TimeoutError`` — ``socket.timeout`` since
    3.10 — which BaseHTTPRequestHandler.handle_one_request already turns
    into a silent close for the header phase, and which
    ``_Handler._read_json`` catches for the body phase.

    ``time.monotonic`` here is transport bookkeeping, not the mint clock:
    L17 keeps C06 off wall time because mint_time is a SERVED value, and
    no value computed here is ever served, signed or persisted.
    """

    def __init__(self, sock, handler):
        self._sock = sock
        self._handler = handler

    def readable(self) -> bool:
        return True

    def readinto(self, buf) -> int:
        idle = self._handler.timeout
        deadline = self._handler.request_deadline
        if deadline is None:
            budget = idle
        else:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError("request deadline exceeded")
            budget = left if idle is None else min(idle, left)
        self._sock.settimeout(budget)
        try:
            return self._sock.recv_into(buf)
        finally:
            # Restored so the response write side is never left running
            # under whatever sliver of the read budget happened to remain.
            self._sock.settimeout(idle)


class _Handler(BaseHTTPRequestHandler):
    server_version = "AICashMint/0.4"
    protocol_version = "HTTP/1.1"

    # WHAT THIS HANDLER ASSUMES A REQUEST LINE WITH NO VERSION ON IT IS, and
    # the reason this mint used to answer some requests with NO STATUS LINE
    # AT ALL.
    #
    # ``BaseHTTPRequestHandler`` makes ``send_response_only()``,
    # ``send_header()`` and ``end_headers()`` NO-OPS while
    # ``request_version == "HTTP/0.9"`` — 0.9 has no status line and no
    # headers — and the class default for ``default_request_version`` is
    # exactly ``"HTTP/0.9"``. Setting ``protocol_version`` does not touch
    # it: that field says what this server ANSWERS IN, this one says what it
    # assumes it was ASKED IN, and the library reads the second when it
    # cannot read a version off the wire. Measured consequence, on every one
    # of this mint's seven routes and every one of the supervision profile's
    # twenty-one:
    #
    #   * ``@@@@`` — a request line the library cannot parse — produced the
    #     library's own HTML error page, naked: no status line, no
    #     Content-Length, no ``Connection: close``.
    #   * ``GET /v3/mints`` — a two-word request line — produced this mint's
    #     OWN SIGNED DESCRIPTOR, about a kilobyte, naked, because the route
    #     ran and every header it composed was a no-op.
    #   * ``GET /v3/mints HTTP/9.9`` — a version the library refuses — the
    #     same naked error page.
    #
    # And the consequence that makes it critical rather than untidy: on a
    # keep-alive connection, a well-formed request followed by a two-word one
    # was answered with a correct response declaring a Content-Length and
    # then, past that length, the whole descriptor again — octets that are
    # not part of that response and carry no framing of their own. That is response splitting, and behind the reverse proxy
    # DEPLOYMENT.md makes mandatory it is the whole mechanism: the proxy reads
    # the declared length and the client reads what follows, and the two
    # disagree about where the response ended.
    #
    # The library decides this BEFORE ``parse_request`` below can refuse
    # anything — a one-word request line and an over-long header block are
    # both answered from inside ``handle_one_request`` — so the only place to
    # close it for every one of them is the default it reads. Raising the
    # default does not make this mint speak 0.9; it makes every ANSWER it
    # sends a well-framed HTTP/1.x message, and ``parse_request`` below then
    # refuses the 0.9 REQUEST outright with a real 400.
    #
    # This is the operator console's fix, verbatim and for the same reason;
    # ``send_error`` below is HALF of the operator GUI's, and the GUI's
    # OTHER half — refusing on ``request_version == "HTTP/0.9"`` in
    # ``parse_request`` below — is the third piece. All three, because each
    # covers a door the others do not:
    #
    #   * without the default, the GUI's override still composes its JSON
    #     into no-ops for an unparseable request line;
    #   * without the override, the library's HTML error page is framed but
    #     is not this mint's error vocabulary;
    #   * without the VERSION check, a request line that spells the version
    #     out — ``GET /v3/mints HTTP/0.9``, three words, a version the
    #     library can read — sets ``request_version`` from the wire and every
    #     no-op comes back. The first version of this fix took the console's
    #     word count and the GUI's ``send_error`` and called it the union of
    #     the two; it was not, and the descriptor went on the wire naked
    #     through the door the word count cannot see.
    default_request_version = "HTTP/1.1"

    _route = "<unknown>"  # normalized route pattern, for the access log

    # socketserver.StreamRequestHandler.setup() applies this to the accepted
    # socket; the class default is None, i.e. NO timeout. With HTTP/1.1
    # keep-alive that meant one anonymous client (§3.7 — anyone) could open
    # a connection, send nothing or half a request, and park a daemon thread
    # and a file descriptor for the life of the process. 10s is far longer
    # than any Layer 0 call needs (they are single sqlite transactions) and
    # short enough that a stalled peer cannot accumulate. A timeout fires as
    # socket.timeout inside BaseHTTPRequestHandler.handle_one_request, which
    # routes it to self.log_error (silenced below) and closes — no traceback
    # on stdout; _MintHTTPServer.handle_error covers anything that escapes.
    #
    # It is an IDLE bound and only that: `request_timeout` below is what
    # stops a peer from resetting it forever a byte at a time.
    timeout = 10

    # Wall-clock ceiling on one whole request, armed in handle_one_request
    # and enforced by _DeadlineRaw on every recv. A class attribute for the
    # same reason `timeout` is: a deployment (or a test) overrides it by
    # subclassing, without reaching into module state.
    request_timeout = MAX_REQUEST_SECONDS

    #: Absolute monotonic instant this request must be read by; None
    #: between requests, when only the idle timeout applies.
    request_deadline: float | None = None

    def setup(self):
        super().setup()
        # socketserver made rfile = connection.makefile('rb', rbufsize).
        # Swap in the same buffered reader over a deadline-checking raw
        # layer; closing the original only drops its socket refcount (it
        # does not close the fd), which keeps connection.close() honest.
        original = self.rfile
        self.rfile = io.BufferedReader(
            _DeadlineRaw(self.connection, self),
            io.DEFAULT_BUFFER_SIZE if self.rbufsize <= 0 else self.rbufsize,
        )
        original.close()

    def handle_one_request(self):
        # Arm the deadline for this request. Keep-alive idle time between
        # requests is covered by `timeout` alone, which is the shorter of
        # the two, so nothing legitimate is cut short by arming here.
        self.request_deadline = time.monotonic() + self.request_timeout
        try:
            super().handle_one_request()
        finally:
            self.request_deadline = None

    # ---- logging: route pattern + status only (requirement 5) ----------

    def log_request(self, code="-", size="-"):
        if hasattr(code, "value"):  # HTTPStatus from send_error paths
            code = code.value
        logger.info("%s %s %s", self.command, self._route, code)

    def log_error(self, format, *args):  # noqa: A002 - stdlib signature
        pass  # default would log free text; the access log above is enough

    def log_message(self, format, *args):  # noqa: A002 - stdlib signature
        pass

    # ---- plumbing -------------------------------------------------------

    def _send(self, code: int, obj: object) -> None:
        body = canonical_json(obj)  # C01 canonical JSON: stable bytes (req 6)
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if self.close_connection:
            # Announce the close AND (via BaseHTTPRequestHandler.send_header)
            # set self.close_connection. Mandatory whenever we answer without
            # having consumed the declared body: leftover octets would be
            # parsed as the next request on a keep-alive connection.
            self.send_header("Connection", "close")
        self.end_headers()
        if getattr(self, "command", None) != "HEAD":
            # getattr, not attribute access: ``send_error`` below can reach
            # here for an over-long request line before ``parse_request`` has
            # set ``command`` at all, and an AttributeError between
            # ``end_headers()`` and this write is a declared Content-Length
            # with no body after it — a peer reading by length then waits for
            # octets that are never coming, which is the same desync one
            # direction over.
            #
            # No route here answers HEAD (the library refuses it 501 before
            # dispatch), so the only response this guard suppresses a body on
            # is that refusal — and a 501 that carried a body after a HEAD
            # would be a framing violation in a server whose whole subject is
            # framing. The operator GUI guards its one write the same way.
            self.wfile.write(body)

    # ---- request-line refusals: no shape answers without a status line ---

    def _refuse_transport(self, code: int, reason: str) -> None:
        """Answer a request that never became a call, and hang up.

        One place, so the three refusals below cannot drift into three
        spellings of "close and answer 400" — which is the shape this round
        exists to remove. The status word comes from this module's own
        table, never from ``self.responses``: the library's reason phrases
        move between interpreter versions and this mint's machine words must
        not. The library's ``message`` is never read either, because that
        message quotes the caller's request line back at it.
        """
        self.close_connection = True
        self._send(code, _transport_rejection(code, reason))

    def parse_request(self) -> bool:
        """Refuse the request lines this mint cannot answer honestly.

        The one hook every request passes through after the request line is
        read and before anything dispatches — which is why the checks are
        here and not at the top of ``do_GET``/``do_POST``. ``PUT
        /v3/exchange`` never runs a ``do_*`` of ours at all, and it is as
        entitled to a framed answer as a GET is. Returning False is the
        library's own "stop, do not dispatch" signal, so the refusal is the
        complete answer to that request.

        THE 0.9 REFUSAL, AND IT HAS TWO SPELLINGS. A request line with two
        words is HTTP/0.9 by omission; a request line whose version token is
        literally ``HTTP/0.9`` is HTTP/0.9 by statement. Both have no status
        line and no headers, both make ``send_response_only``,
        ``send_header`` and ``end_headers`` no-ops, and a check that catches
        only one of them leaves the other serving naked bodies — which is
        precisely what a word count alone did. ``default_request_version``
        above makes the ANSWER well framed for the lines the library cannot
        version; this refuses the REQUEST in both spellings, because a mint
        that answers in a protocol whose responses cannot be told from
        trailing octets is a mint whose answers an intermediary cannot
        frame. Nothing that speaks to this mint speaks 0.9 — the reference
        wallet, the operator console and the operator GUI all send HTTP/1.1
        — and the operator GUI refuses both spellings with the same reason
        word, ``bad_version``.

        The word count is read off ``raw_requestline`` BEFORE
        ``super().parse_request()`` because the library ANSWERS some request
        lines itself and then reports only True/False; after the call there
        is no way left to tell what shape the line was. The version is read
        AFTER, because only the library's own parse puts the wire's version
        in ``request_version``.

        THE TARGET CHECK. RFC 7230 §5.3 gives a request target four forms.
        This mint routes on ``self.path`` verbatim, so only origin-form
        (``/v3/mints``) ever matches a route: absolute-form
        (``http://host/v3/mints``) has never reached one and never could,
        and authority-form and asterisk-form name no route either. Being
        unroutable was never the problem; answering 404 and then INVITING
        another request on the same connection is the part that is wrong.

        §5.3.2 says an origin server that takes
        absolute-form must ignore ``Host`` and route on the target's own
        authority; this mint does neither, so a request that arrives still
        addressed the way it would be addressed to a proxy is a request whose
        two statements of "which server is this for" this hop has not
        resolved — and DEPLOYMENT.md puts a reverse proxy in front of every
        deployed mint, so there is always a second hop that may resolve them
        the other way. That is the framing disagreement one field over, so the
        request is answered once and the socket goes. The operator GUI and the
        operator console both close on the same bytes; this is the change that
        makes all four servers reach one decision on them.

        Asterisk-form is refused with the rest rather than exempted: it is
        defined for ``OPTIONS`` alone, this mint implements no ``OPTIONS``
        route, and ``GET *`` was answered 404 ON A REUSED CONNECTION, which
        is the same "answered, then invited another" as the rest of them.
        """
        if self.raw_requestline in (b"\r\n", b"\n", b"\r"):
            # RFC 7230 §3.5: a server SHOULD ignore at least one empty line
            # received before the request line. The library does not: an
            # empty request line makes ``words`` empty and ``parse_request``
            # return False with NOTHING WRITTEN and the socket closed, so
            # ``\r\nGET /v3/mints HTTP/1.1\r\nHost: h\r\n\r\n`` — a
            # perfectly well-formed request with one stray CRLF in front of
            # it, which is exactly what a client that terminated its last
            # body with an extra CRLF emits — is silently DISCARDED. That is
            # the "no answer at all" class one door over from the naked-body
            # one, and behind the reverse proxy DEPLOYMENT.md mandates it is
            # uniform request loss on a shape the RFC blesses.
            #
            # One line, not a loop: "at least one" is what the RFC asks for,
            # and a loop would let an anonymous peer hold a thread by
            # trickling CRLFs inside the request deadline.
            self.raw_requestline = self.rfile.readline(65537)
            if len(self.raw_requestline) > 65536:
                # ``handle_one_request``'s own guard, repeated because this
                # read is ours: the fields it sets first are the ones
                # ``send_error`` and ``log_request`` read.
                self.requestline = ""
                self.request_version = ""
                self.command = ""
                self.send_error(414)
                return False
            if not self.raw_requestline:
                # EOF after the empty line. Nothing to answer.
                self.close_connection = True
                return False
        zero_nine = len(self.raw_requestline.split()) == 2
        if not super().parse_request():
            # Malformed request line, unsupported version, too many or too
            # long headers: the library has already answered — with a status
            # line on it now, which is what ``default_request_version`` and
            # ``send_error`` below are for.
            return False
        if zero_nine or self.request_version == "HTTP/0.9":
            # ``request_version`` is the test that matters and the word count
            # is NOT a substitute for it: a THREE-word request line whose
            # version token is literally ``HTTP/0.9`` is one the library CAN
            # read, so ``super().parse_request()`` above returns True with
            # ``request_version == "HTTP/0.9"`` set FROM THE WIRE — and every
            # answer composed after that goes out naked again, because
            # ``send_response_only``, ``send_header`` and ``end_headers`` are
            # no-ops in 0.9. ``default_request_version`` cannot help there
            # (it is only consulted when the library CANNOT read a version)
            # and neither can ``send_error`` (it guards its own path only).
            #
            # Nor is the version test a substitute for the word count: with
            # ``default_request_version = "HTTP/1.1"`` a two-word line lands
            # on ``request_version == "HTTP/1.1"`` and would sail past a
            # version check alone. Both, or one of the two 0.9 spellings is
            # served.
            #
            # Forcing the field to HTTP/1.1 before answering is what makes
            # THIS refusal itself framed; it is the operator GUI's guard, in
            # the GUI's own order, for the reason the GUI wrote down.
            self.request_version = "HTTP/1.1"
            self._refuse_transport(400, "bad_version")
            return False
        if not self.path.startswith("/"):
            self._refuse_transport(400, "bad_request_target")
            return False
        return True

    def send_error(self, code, message=None, explain=None):
        """The library's own failures, in this mint's transport envelope.

        ``handle_one_request`` calls this directly for a request line it
        cannot parse, a request line past 64 KiB, a method with no handler
        and a version it will not speak. Its default body is an HTML page;
        every other answer this mint sends is JSON.

        AND IT STILL GETS A STATUS LINE, which is the half that matters.
        ``parse_request`` sets ``request_version`` to the default BEFORE it
        tries to read the request line, and for an over-long request line
        ``handle_one_request`` sets it to ``""`` without going through
        ``parse_request`` at all — so this override is written to be safe on
        a handler where neither ``request_version`` nor ``command`` exists
        yet, and an AttributeError inside an error path is a request answered
        with nothing at all.

        A failure this mint cannot attribute to a version is answered in
        HTTP/1.1: a status line, a Content-Length, ``Connection: close``, and
        then the socket goes. A peer that really did speak HTTP/0.9 gets a
        response it may not parse — but it has just been refused and hung up
        on, and the alternative, which is what was here, is octets with no
        framing at all. This is the operator GUI's override, for the reason
        the GUI wrote down.
        """
        self.close_connection = True
        if getattr(self, "request_version", "HTTP/0.9") == "HTTP/0.9":
            self.request_version = "HTTP/1.1"
        if not getattr(self, "command", None):
            # ``parse_request`` clears it before reading the request line,
            # and ``_send`` asks whether this was a HEAD. "Not HEAD" is the
            # answer that emits the body we are about to frame.
            self.command = ""
        try:
            code = int(code)
        except (TypeError, ValueError):     # pragma: no cover - defensive
            code = 500
        try:
            self._send(code, _transport_rejection(code, _transport_why(code)))
        except Exception:                   # pragma: no cover - socket gone
            # There is nowhere left to answer. Never let an error path raise
            # into ``handle_error``: that is how a request ends up with no
            # response at all, which is the defect this override exists
            # against.
            pass

    def _body_rejection(self):
        """Refuse this request's body and hang up.

        Every refusal answers with ONE §3.8 reason, ``bad_format``, so the
        reason is a property of the route rather than of handler state a
        body reader happened to leave behind. An earlier version carried it
        out of band on the handler, which quietly extended the contract of
        an OVERRIDABLE method: a subclass that replaces ``_read_json``
        (C10's Supervision Profile handler is the live example) cannot know
        to set a private attribute, and the inherited Layer 0 routes would
        then answer from a stale class default — the same wire request
        getting two different §3.8 reasons depending on profile, which
        L13/B9 forbid. Nothing to leave behind, nothing to go stale.
        """
        self.close_connection = True
        return None, False

    def _framing_verdict(self, *, body_expected: bool) -> FramingVerdict:
        """THIS handler's framing verdict — the whole object, one call.

        The single point at which anything in this process turns a parsed
        header block into a framing decision. ``_framed_body_length`` reads
        ``.length`` off it and ``_close_if_body_goes_unread`` reads
        ``.must_close`` off it; neither re-derives the other's field, which
        is what they used to do. ``must_close`` in particular had NO
        executing consumer in this package while the GET guard hand-wrote
        the same decision one method down — a contract field whose own
        owner re-implements it is a contract field free to drift from its
        definition on the next change, and it is the field the GUI and the
        console use to decide whether to hang up.

        Subclasses that need to narrow framing override THIS, and nothing
        else: every reader in this class reaches the rule through here, so
        one override reaches the POST reader, the GET guard and the
        inherited Layer 0 routes together. (C10 no longer needs to —
        its rule was folded into ``framing_verdict``.)
        """
        return framing_verdict(self.headers, body_expected=body_expected)

    def _framed_body_length(self, *, body_expected: bool) -> int | None:
        """Octets of request body this server is CERTAIN of, or None.

        A DELEGATION, deliberately: the rule itself is the module-level
        ``framing_verdict``, which is public and which the Supervision
        Profile, the operator GUI and the operator console all import and
        call. It used to live here as a private method, and that is the
        whole reason the other three servers had a copy of a rule that was
        wrong — nineteen of twenty-five spellings still framed a body on
        them after this class was closed here. One rule, one place, four
        callers; anything that grows a second copy fails
        ``TheFramingRuleIsOneSharedFunctionTest`` in test_c06.

        The verdict's ``length`` IS this method's answer, by construction:
        ``framing_verdict`` returns ``length=None`` exactly when it returns
        ``framed=False``, so "no trusted length" and "unframable" are the
        same fact seen from two sides and cannot disagree. ``must_close``
        adds the one thing a bare length cannot say — that a GET which
        DECLARED octets nobody will read must still hang up — and
        ``_close_if_body_goes_unread`` below READS that field off the same
        verdict rather than deriving it a second way.

        Subclasses narrow framing by overriding ``_framing_verdict``, not
        this method: the whole verdict is the override point, so a
        narrowing reaches ``must_close`` as well as ``length`` and the GET
        guard cannot end up applying a different rule from the POST reader.
        """
        return self._framing_verdict(body_expected=body_expected).length

    def _body_framing_is_unreadable(self, *, body_expected: bool = True) -> bool:
        """True when this request's body cannot be read off the socket.

        THE framing rule, in one place, because both directions need the
        same answer. ``BaseHTTPRequestHandler`` does not dechunk, so a
        request carrying ``Transfer-Encoding`` has a body this layer cannot
        consume no matter which method it arrives on: the GET guard has
        always said so (``_close_if_body_goes_unread``), while the POST
        reader sized the body from ``Content-Length`` alone and read a
        chunked POST as an EMPTY one. It then answered without hanging up,
        so the unread chunk octets stayed on a keep-alive socket and were
        framed as the next request line — the mint's own access log showed
        three entries for two requests, the middle one a phantom with
        method None. Found by outside review 2026-09-16; the guard it needed
        already existed, one method down.

        A CONFLICTING ``Content-Length`` is the second door into the same
        desync, and Layer 0 still had it open after C10 closed its own:
        ``headers.get`` silently returns the FIRST of a duplicated header,
        so ``Content-Length: 2`` followed by ``Content-Length: 46`` read
        two octets off ``/v3/exchange`` and left forty-four on the wire to
        be framed as the next request line — one request in, two responses
        out, connection still pooled. That is the classic CL.CL smuggling
        pair, and the danger is exactly that an intermediary (the proxy
        DEPLOYMENT.md makes mandatory) may pick the OTHER value. RFC 7230
        §3.3.3 requires rejecting such a message. Any duplicate is refused,
        not only a disagreeing one: "identical" is a judgement about
        whitespace and leading zeros that we would then have to make the
        same way as every intermediary in the path, and the safe answer
        does not depend on getting that right. The single-header spelling
        ``Content-Length: 2, 46`` needs no clause of its own: it is not a
        run of digits, so ``_framed_body_length`` has no length for it, and
        having no length closes.

        C10's ``_read_sup_json`` asks THIS method too, so the two servers
        reach the identical framing verdict on identical wire bytes while
        keeping their different §3.8 envelopes. One server, one socket:
        a rule Layer 0 and the profile computed separately is a rule that
        drifts, and the half that drifts is smuggleable.

        WHICH REQUESTS ARE UNFRAMABLE IS NO LONGER A LIST OF BAD HEADERS.
        It was, for one round, and the list was wrong the way every such
        list is wrong. ``Transfer-Encoding : chunked`` — one space before
        the colon — is not registered by Python's email parser AT ALL, so
        ``headers.get("Transfer-Encoding")`` returned None, the framing
        check saw no transfer coding and no Content-Length, defaulted the
        length to zero, never read the chunk octets, answered 400 WITHOUT
        ``Connection: close``, and the chunk octets were then framed as the
        next request line: two responses on the socket for one request, the
        second one method-less, which is precisely the access-log symptom
        the first report described. ``Transfer_Encoding: chunked`` does the
        same by a different road (the parser registers it under a name that
        is not the one asked for, and front ends that normalise ``_`` to
        ``-`` will have dechunked it), and so would a third spelling nobody
        has written down yet. See ``_framed_body_length``: the verdict is
        now derived from the length this server can COMPUTE, not from a
        header it can NAME.
        """
        return self._framed_body_length(body_expected=body_expected) is None

    def _read_json(self):
        """Returns (parsed, ok). Any trouble with the body → (None, False).

        The caller answers (None, False) with §3.8 ``bad_format``, kind
        "call", index null — §3.8's own example of a call-level rejection
        is "a malformed envelope", and a body this layer declines to read
        is exactly that. Deliberately NOT ``over_batch_limit``, even for a
        body past MAX_BODY_BYTES: §9.5 pins that reason as "retryable with
        backoff", but identical bytes over the cap fail identically
        forever, so a spec-conforming payer would retry a call that can
        never succeed instead of splitting it or giving up. MAX_BODY_BYTES
        is also not a §3.6 published limit and cannot become one (that
        object's scope guard is explicit), so no client can be expected to
        aim at it — which is precisely what makes a permanent reason the
        honest one. It is NOT, however, out of a published limit's reach:
        at the largest max_batch MintConfig admits (_max_batch_ceiling) this
        cap is only ~1.5x a maximal call, and an entry the mint
        parses can exceed the per-entry allowance that ceiling is derived
        from (see _FAT_ENTRY_BYTES), so a caller aiming at a published limit
        CAN land here. The permanent reason still holds on its own ground:
        identical bytes over the cap fail identically forever, so "retryable
        with backoff" would be advice that can never work, while the
        recovery that does work — split the call — is exactly what a
        permanent reason tells a payer to go find.
        """
        if self._body_framing_is_unreadable():
            # Nothing is read, and the octets that were never read cannot be
            # left to frame the next request: `_body_rejection` closes the
            # connection, exactly as the GET guard does, and the route
            # answers `bad_format` at call level like any other envelope
            # this layer declines to read.
            return self._body_rejection()
        # Not None: the guard above IS `_framed_body_length(...) is None`,
        # and it is the only source of a length in this reader. Nothing is
        # re-parsed here, so the number read off the socket and the verdict
        # that the socket is re-framable cannot disagree. (A negative or
        # non-numeric length no longer needs its own clause: the framing
        # rule only ever returns a non-negative int.)
        length = self._framed_body_length(body_expected=True)
        if length > MAX_BODY_BYTES:
            # Refuse BEFORE allocating: the old code trusted the header and
            # called rfile.read(length), so `Content-Length: 4294967296` was
            # a one-line memory-exhaustion request from any anonymous caller
            # (§3.7). Nothing is read, so the connection cannot be reused.
            return self._body_rejection()
        try:
            raw = self.rfile.read(length) if length > 0 else b""
        except OSError:
            # A reset peer, the idle `timeout`, or the whole-request
            # deadline (_DeadlineRaw raises TimeoutError, an OSError, when
            # a driblet of a body outlasts request_timeout). The socket is
            # unusable either way; hang up rather than let the exception
            # reach handle_error.
            return self._body_rejection()
        if len(raw) != length:
            # Short read: the peer half-closed or died mid-body. Without this
            # a truncated body either parsed as a shorter valid document
            # (silently accepting a call the client never finished sending)
            # or surfaced as a confusing JSONDecodeError. Either way the
            # stream is desynchronized, so the connection does not survive.
            return self._body_rejection()
        try:
            return json.loads(raw.decode("utf-8")), True
        except (UnicodeDecodeError, ValueError, RecursionError):
            # A malformed envelope is a malformed envelope however the
            # parser says so, and json.loads says so in three ways, only one
            # of which was handled here:
            #   * json.JSONDecodeError — a ValueError subclass, syntax;
            #   * a bare ValueError — CPython's int-string digit limit, so
            #     an `amount_mc` of 5,000 digits is VALID JSON that raises
            #     out of int(); it reached the 500 handler, and §3.8 owes an
            #     enumerated reason, never a bare 500;
            #   * RecursionError — the same shape one nesting level up:
            #     `[[[[...` a hundred thousand deep is a 200 KB body, well
            #     inside MAX_BODY_BYTES, that blew the C parser's stack and
            #     also answered 500.
            # All three are permanently bad bytes, which is what bad_format
            # means (§9.5). The body WAS fully read, so unlike the refusals
            # above the stream is still framed and the connection survives.
            # Found by outside review 2026-09-16 (the literal; the nesting
            # sibling was found looking for the same shape).
            return None, False

    # ---- routes ---------------------------------------------------------

    def _close_if_body_goes_unread(self) -> None:
        """Hang up after answering a GET that declared a body.

        A GET body is never read by this layer, so a declared one leaves
        octets on the wire that a keep-alive peer or a pipelining proxy
        frames as the NEXT request line — the same desync the POST path
        closes by hanging up on a body it refuses. There is nothing here
        to reject (the GET itself is well formed and §3.7 says anyone may
        make it), so the request is answered and THEN the connection is
        dropped, rather than reusing a stream that can no longer be
        framed. Transfer-Encoding counts too: the stdlib handler does not
        dechunk, so a chunked body is equally unconsumed — that half of the
        rule lives in ``_body_framing_is_unreadable`` and the POST reader
        applies the same one.

        Shared rather than duplicated because C10's ``_SupHandler``
        answers its own GET routes without reaching this class's
        ``do_GET`` (it returns before ``super().do_GET()`` for a
        supervision route), and a framing guard that only covers Layer 0
        leaves the profile's routes smuggleable — one server, one socket,
        so it has to be one rule.
        """
        # ONE field, READ, not re-derived. This used to be two clauses —
        # "unframable?" and "a declared length that is not zero?" — which
        # is precisely `FramingVerdict.must_close`'s definition, hand-copied
        # into the file that defines it while the field itself had no
        # executing consumer anywhere in the package. The two other servers
        # act on `must_close`; so does this one now, so there is one
        # definition of "hang up" and the mint is bound by it.
        if self._framing_verdict(body_expected=False).must_close:
            self.close_connection = True

    def do_GET(self):
        core: _Core = self.server.core
        try:
            self._close_if_body_goes_unread()
            path = self.path.split("?", 1)[0]
            if path == "/v3/mints":
                self._route = "/v3/mints"
                code, obj = core.descriptor()
            elif path.startswith("/v3/status/") and len(path) > len("/v3/status/"):
                self._route = "/v3/status/<hash>"
                code, obj = core.status_single(path[len("/v3/status/"):])
            else:
                self._route = "<unknown>"
                code, obj = 404, {"status": "not_found"}
            self._send(code, obj)
        except Exception as exc:
            self._safe_500(exc)

    def do_POST(self):
        core: _Core = self.server.core
        try:
            path = self.path.split("?", 1)[0]
            body, ok = self._read_json()
            # A body this layer would not read is a malformed envelope:
            # §3.8 bad_format, kind "call", index null. Computed here from
            # `ok` alone, never from state the reader left on the handler —
            # `_read_json` is overridable and a subclass cannot be asked to
            # maintain a private attribute (see _body_rejection).
            if path == "/v3/exchange":
                self._route = "/v3/exchange"
                code, obj = (
                    core.exchange(body) if ok else _call_rejection("bad_format")
                )
            elif path == "/v3/status":
                self._route = "/v3/status"
                code, obj = (
                    core.status_batch(body)
                    if ok
                    else _call_rejection("bad_format")
                )
            elif path == "/admin/issue":
                self._route = "/admin/issue"
                token = self.headers.get("X-Admin-Token")
                if not core.admin_authorized(token):
                    code, obj = 401, {"status": "unauthorized"}
                elif ok:
                    code, obj = core.admin_issue(body, token)
                else:
                    code, obj = _call_rejection("bad_format")
            else:
                self._route = "<unknown>"
                code, obj = 404, {"status": "not_found"}
            self._send(code, obj)
        except Exception as exc:
            self._safe_500(exc)

    def _safe_500(self, exc: BaseException | None = None):
        # Requirement 4: never a stack trace in a response body.
        #
        # A write that failed because the PEER went away is not an internal
        # error, and there is nobody left to tell. Attempting the 500 anyway
        # writes a second access-log line for a request that was already
        # answered, or already correctly refused, before the socket died --
        # so the log claims a 500 no client ever received. That is a lie in
        # the one record an operator debugs from, and the reviewers reading
        # this repository would reasonably read those lines as real faults.
        # A transport failure therefore closes quietly; only a genuine fault
        # gets the 500.
        if isinstance(exc, OSError):
            self.close_connection = True
            return
        try:
            self._send(500, {"status": "error"})
        except Exception:
            pass


class MintServer:
    """A real mint over HTTP, and the in-process test harness for one."""

    def __init__(self, config: MintConfig, ledger: Ledger):
        if not isinstance(config, MintConfig):
            raise TypeError("config must be a MintConfig")
        if not isinstance(ledger, Ledger):
            raise TypeError("ledger must be a C04 Ledger")
        # Shared-parameter consistency (fail fast at boot, not at payment
        # time): the descriptor advertises the config's burn_policy /
        # retention / lock horizon, but the LEDGER enforces its own — a
        # hand-wired mismatch would make the mint publish one policy and
        # charge another. ``make_mint`` builds the pair from one source of
        # truth; this check catches everyone who wires by hand.
        #
        # ``burn_policy_next`` is on this list for the same reason as
        # ``burn_policy``, and it is the half that was missing: the
        # descriptor publishes the change notice and every reference client
        # switches policy the instant ``mint_time`` reaches ``effective_at``,
        # so a ledger that does not carry the same notice charges the
        # superseded policy and rejects every client-built exchange with
        # ``amount_mismatch`` — a plain receive included, fleet-wide, from
        # the moment an honest operator's scheduled change lands. Checking
        # only ``burn_policy`` meant this check passed while the two views
        # disagreed about every future instant.
        for name in (
            "burn_policy",
            "burn_policy_next",
            "recovery_window_ms",
            "max_lock_expiry_ms",
        ):
            cfg_v, led_v = getattr(config, name), getattr(ledger, name)
            if cfg_v == led_v:
                continue
            if name == "burn_policy_next" and led_v is None:
                # The one disagreement that is not drift: a Ledger built
                # before the notice existed has no opinion to contradict the
                # config with, and the config is the source of truth for
                # what the mint publishes. Adopt rather than refuse — a
                # ledger silently left behind is the defect; a hand-wired
                # mint refusing to boot over a constructor argument that did
                # not exist until now is not the fix for it. Every other
                # combination, including a Ledger carrying a notice the
                # config does NOT publish (the mint would charge a policy it
                # never announced — worse than the reverse), still raises.
                ledger.adopt_burn_policy_next(cfg_v)
                logger.warning(
                    "mint %s: the Ledger was built without the §7.3 change"
                    " notice this MintConfig publishes (%r); adopting it so"
                    " the mint charges what it advertises. Pass"
                    " burn_policy_next to Ledger(...), or build both with"
                    " make_mint(config, db_path).",
                    config.mint_id, cfg_v,
                )
                continue
            raise ValueError(
                "config/ledger mismatch on %s: MintConfig has %r but the"
                " Ledger was built with %r — the mint would advertise one"
                " value and enforce another. Build both from the config"
                " via make_mint(config, db_path), or construct the Ledger"
                " with the config's values." % (name, cfg_v, led_v)
            )
        if config.admin_token is ADMIN_ISSUANCE_OPEN:
            # Explicitly chosen, so it is allowed — but never silent. The
            # whole defect class was "no check reads as fine because nothing
            # gets reported", and an open mint is exactly the state an
            # operator should be told about every single time one starts.
            logger.warning(
                "mint %s: /admin/issue is UNAUTHENTICATED"
                " (ADMIN_ISSUANCE_OPEN) — anyone who can reach this port can"
                " mint without limit", config.mint_id,
            )
        self._core = _Core(config, ledger)
        self._httpd: _MintHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self, port: int = 0, host: str = "127.0.0.1") -> int:
        """Bind and serve on background threads; return the bound port.

        Defaults to 127.0.0.1:0 — an ephemeral port on loopback, which is
        what the tests want. A deployed mint needs a FIXED port instead: its
        URL is published in the descriptor and held by counterparties, so an
        address that moves on every restart is not addressable. Pass one.

        `host` stays loopback by default. Transport is plain HTTP (L17), so
        binding a routable interface publishes an unencrypted mint; put TLS
        in front before widening this.
        """
        if self._httpd is not None:
            raise RuntimeError("server already started")
        # Before binding: exactly one mint process may serve a ledger, or
        # §3.6 snapshot monotonicity is no longer a property of the mint_id
        # (see _Core._claim_single_writer). Fail here, loudly, rather than
        # at the first descriptor a second process signs.
        self._core._claim_single_writer()
        self._httpd = _MintHTTPServer((host, port), _Handler)
        self._httpd.core = self._core
        self._thread = threading.Thread(
            target=self._httpd.serve_forever,
            name="aicash-mintapi",
            daemon=True,
        )
        self._thread.start()
        return self._httpd.server_address[1]

    def stop(self) -> None:
        if self._httpd is None:
            self._core._release_single_writer()
            return
        self._httpd.shutdown()
        self._httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=10)
        self._httpd = None
        self._thread = None
        # Released last: while a serving thread could still be building a
        # snapshot, this mint is still the single writer.
        self._core._release_single_writer()


def make_mint(
    config: MintConfig, db_path: str, clock=system_clock
) -> tuple[MintServer, Ledger]:
    """Build a Ledger and a MintServer from ONE source of truth.

    The Ledger is constructed from the config's ``burn_policy``,
    ``burn_policy_next``, ``recovery_window_ms`` and ``max_lock_expiry_ms``,
    so the values the descriptor advertises are, by construction, the values
    the ledger enforces — no hand-wired duplication to drift.
    ``burn_policy_next`` is part of that list because the descriptor
    publishes it and every reference client acts on it the instant
    ``mint_time`` reaches ``effective_at``: a ledger that never received it
    would keep charging the superseded policy and fail every client-built
    exchange with ``amount_mismatch``. ``clock`` defaults to
    the wall-clock ``aicash.clock.system_clock``; tests inject a
    ``FakeClock`` (L17). Returns ``(server, ledger)``; call
    ``server.start()`` to bind a port. The ledger is returned too so
    callers can drive it directly (issuance, pruning, tests).
    """
    if not isinstance(config, MintConfig):
        raise TypeError("config must be a MintConfig")
    ledger = Ledger(
        db_path,
        clock,
        config.burn_policy,
        recovery_window_ms=config.recovery_window_ms,
        max_lock_expiry_ms=config.max_lock_expiry_ms,
        burn_policy_next=config.burn_policy_next,
    )
    return MintServer(config, ledger), ledger
