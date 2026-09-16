"""GUI wallet operations — a thin, honest wrapper over ``aicash.wallet.Wallet``.

This module is NOT protocol.  It adds no rules, changes no mint behaviour and
writes nothing into ``impl/aicash``.  It exists so a local operator GUI can
drive a wallet without catching six different library exceptions and without
ever showing a traceback to a human who pasted a bad token string.

What it adds over ``Wallet``
----------------------------
* every failure raised out of this module is a ``WalletOpsError`` carrying a
  short ``.reason`` (fits on a button: "already spent") and a long
  ``.detail`` (an engineer can debug from it).  Concretely: every sqlite
  call this module makes, directly or through ``Wallet``, is inside a
  ``_store_errors`` guard, so a closed handle, a corrupt file, a locked db
  or cross-thread misuse surfaces as ``WalletOpsError`` and never as a raw
  ``sqlite3.Error``;
* ``summary()`` never raises merely because the MINT is down — it reports
  the wallet's last known held balance with ``connected=False``.  It does
  raise when the STORE itself cannot be read, and when the store's coins
  belong to a different mint than the one now answering: see "failures are
  never collapsed" below;
* ``receive()`` takes a LIST and uses ``Wallet.receive_batch``, so a batch
  pays ONE burn on the input sum (§3.3 burn-once / §7.3) instead of one burn
  per token, and a single spent or malformed token is dropped without
  discarding the good tokens sent with it;
* ``history()`` reconstructs a transaction log from the wallet's own sqlite,
  READ-ONLY, over ONE connection and ONE snapshot.  See the limitations
  below — they are real.

WHY A FAILURE FAILED: THE PINNED CAUSE VOCABULARY
-------------------------------------------------
Every ``WalletOpsError`` carries ``.cause``, a machine reason from a CLOSED
set, beside the human ``.reason`` / ``.detail``.  Every ``history()`` row
for an operation that did not commit carries the same ``cause`` field, and
the cause is recorded AT THE MOMENT THE FAILURE HAPPENS, PER OPERATION —
the only moment, and the only granularity, at which anything in this
process knows it::

    mint_unreachable    the mint did not answer; whether the request ever
                        landed is undetermined (§5.1, recover())
    mint_stopped        the GUI knows the mint process is not running
    mint_rejected       the mint answered and refused; its own §3.8 reasons
                        are in the sentence
    already_spent       this specific token was already spent
    malformed_token     the string is not a token
    wrong_mint          a token (or a store) belonging to a different mint_id
    insufficient_funds  the wallet does not hold enough
    unknown             genuinely undetermined — and the sentence says so

The rule that is the point: **"the mint rejected it" may be said only for
mint_rejected** (and its refinement already_spent, which is also an answer
the mint gave).  A request the mint never received was not rejected by it.
``unknown`` must read as unknown; it is never dressed as a likelier story.

This matters because the store CANNOT reconstruct the cause afterwards.
``wallet_ops.state`` is ``failed`` for two unrelated histories: the mint
answered and refused (``MintRejected``), and the mint never answered at all
so the op was left ``planned`` and a later ``recover()`` marked it
``failed``.  A history row that guesses picks one of those and is wrong
half the time — which is exactly the defect this section exists to close:
a row reading "did not commit (the mint rejected it)" for a delivery that
failed with the mint DOWN sends an operator to debug the wrong component.

So this module writes the cause down.  One extra table in the wallet store
(still ONE file — see containment below)::

    walletops_op_causes(op_id, cause, sentence, op)

written INSERT-OR-IGNORE, best effort, only for ops that did not reach
state ``done``, and never overwritten: **a history row keeps the reason it
was written with, permanently.**  It is the record an operator debugs from
months later, and a second attempt's cause is a different op's story.
A failed op with no row — one written by a wallet_cli, an older build, or
a process that died before it could record — reads ``unknown`` and says
the cause is undetermined.  Recording is best effort in the strict sense:
if the store refuses the write, the operation's own error is still raised
unchanged, and the history row degrades to ``unknown``.  Nothing about the
money depends on it.

One call can leave behind ops with DIFFERENT causes, so the cause is
decided per op and never stamped across the call.  ``receive()`` is the
case that proves it: ``Wallet.receive_batch`` resolves the op the mint
refused and re-sends the good remainder under a fresh op, so a batch whose
first round the mint enumerated and refused and whose retry then hit a
dead socket ends with one op the mint answered about and one it never
did.  Each op's own ``wallet_ops.state`` at the end of the call is the
evidence — ``failed`` is written by the wallet only inside its
``except MintRejected`` handlers, ``planned`` is what nothing resolved —
and ``_cause_for_state`` writes only what that op's state supports.  Where
the call-level error cannot be true of an op, that op gets what IS known,
down to ``unknown`` in so many words.

``mint_stopped`` is the one cause this module cannot determine alone: it
knows a socket did not answer, not whether a process exists.  The GUI does,
so ``mint_running`` (an optional callable, set by ``gui/app.py``) may be
supplied; when it returns exactly ``False`` an unreachable mint is reported
as ``mint_stopped``.  Absent, or raising, or returning anything else, the
cause stays ``mint_unreachable`` — the weaker claim, which is always true
when the socket did not answer.

FAILURES ARE NEVER COLLAPSED
----------------------------
"Balance 0" must mean "this wallet holds nothing", never "something went
wrong".  Three unrelated conditions are therefore reported three ways:

=========================  =====================================
the MINT is not answering  ``connected=False`` plus the real, locally
                           readable balance and the mint_id the held
                           coins were issued by.  No exception.
the STORE cannot be read   ``WalletOpsError("wallet store error" /
                           "wallet file unusable")``.  Never a
                           fabricated zero.
the store's coins belong   ``WalletOpsError("wrong mint")`` from
to another mint            ``summary`` / ``pay`` / ``quote``, naming
                           both mint ids.  Never a balance presented
                           as spendable against a mint that will not
                           honour it.
=========================  =====================================

FILES, SIDE EFFECTS AND CONTAINMENT
-----------------------------------
This module writes exactly ONE file: the wallet store itself, at the
``store_path`` it was constructed with.  There is no sidecar, no cache
file and no second artefact of any kind, so the pinned workdir layout
(``var/wallets/<name>.db``, one sqlite file per named wallet) holds
exactly.  It never creates a directory either: if the parent directory of
``store_path`` does not exist the call fails with a clear error rather
than materialising a tree somewhere on the filesystem.

MONEY STRANDED BY A FAILED DELIVERY (a durability claim, examined)
------------------------------------------------------------------
``pay()`` returns bearer token strings.  The GUI shows them in a result
panel and says they are "the only copy" — so a reload, a closed tab or a
stray navigation would destroy real value.  For a PAYMENT that sentence is
false — the wallet file already holds every one of those strings — and
this module is where it is disproved rather than patched over.  Three
things it does NOT do, stated plainly because the claim is about money:

* it does not make the sentence stop being printed.  ``gui/page.html``
  still says "these strings are the only copy of it" after a failed
  delivery, and nothing on that page calls
  ``GET /api/wallet/outstanding``: today the read-back is reachable from
  Python, from the HTTP API, and not from the screen.  The page and
  ``gui/README.md`` are not this module's to change; until they are
  changed the operator is still told, at the moment of loss, something
  this file can disprove.
* it does not cover money that never reached a wallet.  ``/api/mint/issue``
  hands back freshly issued strings and persists NOTHING (the mint stores
  ledger-key hashes, never secrets), so for THOSE strings the "only copy"
  sentence is simply TRUE, and losing the panel loses the money.  Nothing
  here recovers them; crediting them to a wallet is what makes them
  recoverable, which is why that is a separate, retryable step.
* it does not recover a payment the payee has already redeemed — that
  money is theirs, not stranded.

Every payment output was persisted, secret and all, BEFORE the exchange
was sent (§5.1 persist-before-send) and is still in ``wallet_tokens`` in
state ``handed_over`` after it committed.  The money is already durable,
at 0600, in the file that IS the wallet.  What was missing was a way to
read it back, so ``outstanding_payments()`` reconstructs the exact token
strings of past payments from the store, byte for byte the same strings
``pay()`` returned.

The deliberate decision, therefore: **this layer persists NO new copy and
writes NO new file.**  A sidecar of payment strings would be a second
complete copy of live bearer money on disk — a larger blast radius, a
second thing to leak, back up by accident, or leave behind — bought for a
durability property the store already has.  A read-back costs nothing and
is strictly safer.  What it cannot do alone is tell a payment that was
delivered and redeemed from one that is stranded: ``handed_over`` means
"this left the wallet", not "nobody took it".  The MINT knows, so when it
is reachable each string is checked against ``/v3/status`` and reported as
``unspent`` (still live money), ``spent`` (the payee took it — not
stranded) or ``unknown``; with the mint down the strings still come back,
honestly marked ``checked: False``.

``summary()`` DOES create the store file when the mint is reachable and
the file does not exist yet.  That is deliberate and is the mechanism
``POST /api/wallet/create`` uses to materialise a new wallet.  It is the
only write ``summary()`` performs; reads of an existing wallet touch
nothing.

THREADING
---------
A ``WalletOps`` instance is thread-affine, because the sqlite connection
inside ``Wallet`` is: the thread that first opens the store owns it.
Every public method takes an instance lock, and use from a second thread
raises ``WalletOpsError("wallet busy elsewhere")`` rather than sqlite's
"SQLite objects created in a thread can only be used in that same
thread".  A threaded server should build one ``WalletOps`` per request
(which is what ``gui/app.py`` does) rather than share one.

HISTORY: WHAT THE EXISTING SCHEMA CAN AND CANNOT TELL US
--------------------------------------------------------
The wallet store has exactly two tables and neither has a clock column::

    wallet_tokens(key, secret, amount_mc, state, role, op_id, reserved_by)
    wallet_ops(op_id, kind, state, request_json)

``op_id`` is a random uuid4, so it sorts by nothing.  Therefore:

* **There are no timestamps.  None.**  ``ts_ms`` is ``TS_UNKNOWN`` on
  every row — a value that IS the integer ``0`` (it is an ``int``
  subclass, so ``== 0``, ``isinstance(x, int)`` and ``json.dumps`` all
  behave exactly as they always did) but that says what it means when it
  is printed: ``str()`` gives ``"unknown"`` and ``repr()`` gives
  ``TS_UNKNOWN(0 — the wallet store records no clock)``.  **Zero here
  means UNKNOWN, not 1970-01-01.**  A consumer that wants to branch on it
  should test ``row["ts_ms"] is TS_UNKNOWN`` (it is a singleton) or just
  ``not row["ts_ms"]``, and must not render it as a date: every wallet
  ever written by this build would render as the epoch.  Ordering comes
  from the sqlite ``rowid`` of ``wallet_ops``, which is insertion order —
  the order the operations were *planned*, which for this single-threaded
  wallet is also the order they were attempted.  It is not wall-clock
  time and it cannot be compared against anything outside this one store.
  Producing a real ``ts_ms`` would need a clock column in the wallet
  schema or a second file beside the store; both are ruled out here, so
  the field is honestly inert rather than quietly invented.
  A JSON consumer sees a plain ``0`` (the wire shape is unchanged, and
  that is enforced at import — see ``TS_UNKNOWN`` below), so an HTTP
  layer that re-serialises these rows has to carry the "no clock"
  disclosure itself: ``gui/app.py`` passes the ``0`` through and
  ``page.html`` is where it is explained.  It does not leave the When
  column empty: each such cell reads the words ``not recorded``, and one
  note above the table says how many cells that is and why the wallet's
  database has no time to give.
* ``pay`` and ``pay_many`` are both recorded as kind ``pay``.  A fan-out to
  three recipients is indistinguishable from one payment of the total, and
  the per-recipient split is not recoverable.
* There is **no counterparty information anywhere** — not who paid us, not
  who we paid.  ``detail`` can only describe amounts.
* A payment that was handed over is terminal in the store.  Whether the
  payee actually redeemed it is not knowable locally; a refusal appears
  only as a separate later ``refused`` op.
* Operator issuance (``/admin/issue``) is not a wallet operation, so money
  arriving from the mint operator shows up only as the ``receive`` that
  redeemed it.
* Tokens retired by ``_mark_dead_if_ours`` (a copy we held that was
  consumed elsewhere) generate no op row and so no history row.
* For an op that did NOT commit (``failed`` / still ``planned``) the amount
  is reported as ``0``, because no value moved; the attempted amount is put
  in ``detail`` instead.  The kind is suffixed ``_failed`` / ``_pending``.

What IS honest and is therefore what ``history()`` returns: per committed
op, the direction (receive / pay / refused), the value that actually moved,
and the burn the mint actually charged — burn is derived as
``sum(input face amounts) - sum(output amounts)`` from the stored plan,
which is the arithmetic the mint itself enforced (§3.3 conservation).

DECLARED RETURN SHAPES (the contract fixes some of these loosely; these
are the exact shapes a caller may rely on)
-----------------------------------------------------------------------
``summary()``  -> ``{"balance_mc": int, "mint_id": str, "coin_count": int,
                  "connected": bool}`` — exactly these four keys.
                  ``mint_id`` is ``""`` only when it is genuinely unknown
                  (a store with no recorded operation, mint down).  When
                  ``connected`` is True the ``mint_id`` is the live mint's
                  AND every held coin has been checked to belong to it.
``receive()``  -> ``{"accepted_mc": int, "accepted": int,
                  "rejected": [{"token": str, "reason": str,
                  "detail": str}]}``
``quote()``    -> ``{"amount_mc": int, "burn_mc": int, "change_mc": int,
                  "inputs_mc": int}`` — a superset of the contract's
                  unspecified ``dict``; ``inputs_mc == amount_mc +
                  burn_mc + change_mc`` always.
``pay()``      -> ``{"tokens": [str], "amount_mc": int, "burn_mc": int}``
``recover()``  -> ``Wallet.recover``'s counters, passed through unchanged.
``outstanding_payments()``
               -> ``{"checked": bool, "mint_id": str, "payments":
                  [{"op_id": str, "amount_mc": int, "live_mc": int|None,
                  "tokens": [{"token": str, "amount_mc": int, "key": str,
                  "state": "unspent"|"spent"|"unknown"|None}]}]}``,
                  newest first.  FOUR keys per token, ``key`` included:
                  it is the ledger key (a hash, not a secret), it is what
                  identifies a row whose ``token`` could not be rendered,
                  and it is what was sent to ``/v3/status``.  The HTTP
                  route in ``gui/app.py`` drops it — a browser has no use
                  for it — so the wire shape there is the three-key one;
                  a Python caller gets four.  ``state`` is ``None`` and
                  ``live_mc`` is ``None`` when the mint could not be
                  asked.  ``checked`` is True when every token listed
                  carries the mint's own word for it, which is vacuously
                  the case when there are no payments: it answers "is
                  this report verified", not "is the mint up" —
                  ``summary()["connected"]`` is the field for that.
                  THESE ARE LIVE BEARER STRINGS: the only method here
                  that returns secrets, and it exists so a browser tab is
                  not the only place a payment survives.
``history()``  -> ``[{"ts_ms": TS_UNKNOWN, "kind": str, "amount_mc": int,
                  "detail": str}]``, newest first.  ``ts_ms`` is ALWAYS
                  ``TS_UNKNOWN`` — an ``int`` equal to ``0`` meaning "this
                  store records no clock", never a real time and never the
                  epoch; see the history section above.  ``kind`` is drawn from
                  a CLOSED set — a caller may switch on it exhaustively::

                      receive   receive_failed   receive_pending
                      pay       pay_failed       pay_pending
                      refused   refused_failed   refused_pending

                  plus, only if a NEWER wallet build writes an op kind
                  this one does not know, that kind verbatim with the same
                  three suffixes.  Treat an unrecognised ``kind`` as
                  "some operation", read ``detail``, and do not crash.
                  ``amount_mc`` is ALWAYS a non-negative magnitude: there
                  is no sign convention, the direction lives in ``kind``
                  (``receive``/``refused`` in, ``pay`` out), and it is
                  ``0`` for any op that did not commit.
                  ``cause`` is ``""`` for an op that committed and one of
                  the CAUSES above for one that did not — ``unknown``
                  whenever the cause was never recorded, never a guess.
"""

from __future__ import annotations

import contextlib
import json
import os
import sqlite3
import sys
import threading
import urllib.request

_IMPL = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "impl"
)
if _IMPL not in sys.path:
    sys.path.insert(0, _IMPL)

from aicash.tokencodec import (  # noqa: E402
    TokenError,
    b64u_decode,
    format_token,
    parse_token,
)
from aicash.wallet import (  # noqa: E402
    InsufficientFunds,
    MintClient,
    MintRejected,
    MintUnavailable,
    PaymentInvalid,
    Wallet,
)

__all__ = ["CAUSES", "TS_UNKNOWN", "WalletOps", "WalletOpsError"]


# ---------------------------------------------------------------------------
# the closed cause vocabulary (see "WHY A FAILURE FAILED" above)
# ---------------------------------------------------------------------------

#: THE closed set.  ``WalletOpsError.cause`` and every ``history()`` row's
#: ``cause`` is one of these and nothing else — a caller may switch on it
#: exhaustively, and anything unrecognised becomes ``unknown`` rather than
#: widening the vocabulary by accident.
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

#: The sentence a cause gets when the recorded one is missing or unusable.
#: ``unknown`` says it is undetermined, in those words, because that is the
#: whole discipline: a cause nobody recorded must not be dressed up as the
#: likeliest story.
_CAUSE_FALLBACK = {
    "mint_unreachable": "the mint did not answer, so whether it ever saw"
                        " this request is undetermined",
    "mint_stopped": "the mint process was not running when this failed, so"
                    " it did not answer",
    "mint_rejected": "the mint answered and rejected it",
    "already_spent": "the mint answered and rejected it: the token had"
                     " already been spent",
    "malformed_token": "the string was not a token; nothing was sent to the"
                       " mint",
    "wrong_mint": "the token belongs to a different mint, which this mint"
                  " cannot redeem",
    "insufficient_funds": "the wallet does not hold enough",
    "unknown": "the cause was not recorded, so why this failed is"
               " undetermined — nothing here can say the mint refused it",
}

#: Longest sentence stored or rendered.  A cause is a sentence, not a log.
_SENTENCE_MAX = 400


def _clean_cause(cause) -> str:
    """Any cause, coerced into the closed set.  Never widens it."""
    text = str(cause or "")
    return text if text in CAUSES else "unknown"


def _sentence(text, cause: str) -> str:
    """One human sentence for a cause, trimmed, never empty."""
    out = " ".join(str(text or "").split())[:_SENTENCE_MAX]
    return out or _CAUSE_FALLBACK.get(cause, _CAUSE_FALLBACK["unknown"])


# ---------------------------------------------------------------------------
# "no clock in this schema" sentinel
# ---------------------------------------------------------------------------


class _UnknownTime(int):
    """``0``, and loud about the fact that it is not a time.

    The wallet store has no clock column (see the module docstring), so
    every ``history()`` row would otherwise carry a bare ``ts_ms`` of
    ``0`` — which the next consumer of this API can read as midnight on
    1 January 1970 and render as a date.  This is still the integer
    ``0``: it compares equal to ``0``, ``isinstance(x, int)`` is True,
    arithmetic works, and ``json.dumps`` writes ``0``, so nothing that
    already handles the field changes behaviour.  What changes is what it
    says when a human or a log sees it: ``str()`` is ``"unknown"`` and
    ``repr()`` names itself and the reason.
    """

    __slots__ = ()

    def __repr__(self) -> str:
        return "TS_UNKNOWN(0 — the wallet store records no clock)"

    def __str__(self) -> str:
        return "unknown"


#: The only value ``history()`` ever puts in ``ts_ms``.  A singleton, so
#: ``row["ts_ms"] is TS_UNKNOWN`` is an exact test; ``== 0`` and
#: ``not row["ts_ms"]`` work too.  It means "this wallet's sqlite records
#: no time for this operation", NOT "this happened at the epoch".
TS_UNKNOWN = _UnknownTime(0)

# The WIRE shape is the contract here; the pretty printing is only a
# convenience.  ``GET /api/wallet/history`` must always put a bare ``0`` in
# ``ts_ms``: a consumer that suddenly read ``"TS_UNKNOWN(0 - ...)"`` out of
# that field would be parsing corrupt JSON, which is very much worse than an
# unlabelled zero.  Both of json's encoders serialise an ``int`` subclass by
# value on CPython 3.12 -- the C encoder, and the pure-Python one that any
# ``indent=`` forces -- but that is an implementation detail of the encoder,
# not a documented promise, and this module has no test that would catch it
# changing.  So check it once, at import, against BOTH encoders, and give up
# the sentinel rather than the API if it ever stops holding.
if (json.dumps({"ts_ms": TS_UNKNOWN}) != '{"ts_ms": 0}'
        or json.dumps([TS_UNKNOWN], indent=1) != "[\n 0\n]"):  # pragma: no cover
    # Fall back to the plain integer.  Everything a caller is told to rely on
    # still holds: ``row["ts_ms"] is TS_UNKNOWN`` (history() puts this very
    # object in the row), ``== 0``, ``isinstance(x, int)``, ``not x``.  Only
    # ``str()``/``repr()`` lose the word "unknown" -- the cosmetic half -- and
    # the field goes back to being a bare zero that this docstring, gui/app.py
    # and gui/README.md each explain in words.
    TS_UNKNOWN = 0


# ---------------------------------------------------------------------------
# errors
# ---------------------------------------------------------------------------


class WalletOpsError(Exception):
    """One error type for the whole GUI surface.

    ``.reason`` is a short human phrase safe to put on a button or a toast.
    ``.detail`` is the long form: the underlying exception type, the §3.8
    reasons the mint enumerated, the store path — whatever an engineer
    needs.  Neither field ever contains a secret or a token string.
    """

    def __init__(self, reason: str, detail: str = "", cause: str = "unknown"):
        self.reason = str(reason)
        self.detail = str(detail)
        #: The machine reason, from CAUSES.  ``unknown`` is the honest
        #: default: a site that has not thought about the cause says it does
        #: not know, rather than inheriting somebody else's story.
        self.cause = _clean_cause(cause)
        super().__init__(self.reason if not self.detail
                         else f"{self.reason}: {self.detail}")


#: §3.8 / lock-evaluation reasons -> short phrase, long explanation.
_REASONS: dict[str, tuple[str, str]] = {
    "spent": (
        "already spent",
        "the mint has already retired this token's ledger entry — bearer"
        " value is one-shot (§3.8 spent); somebody redeemed it first",
    ),
    "unknown": (
        "not from this mint",
        "the mint has no ledger entry for this token (§3.8 unknown): it was"
        " issued by a different mint, or the mint's database was replaced",
    ),
    "bad_format": (
        "malformed token",
        "the string is not a well-formed aicash token for this mint (§3.8"
        " bad_format): a truncated paste, or not a token at all",
    ),
    "lock_preimage_invalid": (
        "wrong lock secret",
        "the token is locked and the preimage presented does not open it",
    ),
    "bad_witness_length": (
        "bad lock witness",
        "the token is locked and the witness supplied is the wrong length",
    ),
    "lock_expired": (
        "lock expired",
        "the token's lock deadline has passed; only the refund path applies",
    ),
    "lock_not_expired": (
        "refund too early",
        "the token's lock has not expired yet, so a refund claim is invalid",
    ),
    "refund_invalid": (
        "not refundable",
        "this token has no refund path the mint will honour",
    ),
    "amount_mismatch": (
        "amount mismatch",
        "inputs did not equal outputs plus the mint's burn (§3.3"
        " conservation); the wallet built an unbalanced exchange",
    ),
    "idempotency_conflict": (
        "duplicate request",
        "an exchange was replayed under the same idempotency key with"
        " different contents (§3.3)",
    ),
}

#: ``bad_format`` means two very different things depending on where it
#: came from.  On ``receive`` the operator pasted the string, so "check
#: your paste" is actionable.  On ``pay`` / ``recover`` the operator typed
#: a number and pasted nothing: the offending strings are the wallet's OWN
#: stored coins, so the real fault is a store bound to the wrong mint, and
#: telling the operator their paste is malformed would be nonsense.
_OWN_COINS_BAD_FORMAT = (
    "coins not from this mint",
    "the mint rejected this wallet's own stored coins as not its own (§3.8"
    " bad_format).  Nothing you typed is wrong: the store is bound to a"
    " different mint than the one answering on this address — check the"
    " mint_id the mint was started with",
)


def _explain(reason, where: str = "receive") -> tuple[str, str]:
    key = str(reason)
    if key == "bad_format" and where not in ("receive", "paste"):
        return _OWN_COINS_BAD_FORMAT
    if key in _REASONS:
        return _REASONS[key]
    return (key or "rejected", f"mint rejection reason {key!r} (§3.8)")


def _cause_of_rejection(reasons: list) -> str:
    """The cause for a rejection the MINT actually answered with.

    Only two values are reachable here, and both mean the mint saw the
    request and said no: ``already_spent`` when every §3.8 reason it gave
    was ``spent`` (the one refinement worth making — it tells the operator
    the token is gone rather than that something is broken), and plain
    ``mint_rejected`` otherwise.  §3.8 ``unknown`` is deliberately NOT
    mapped to ``wrong_mint``: "this ledger has no entry" is consistent with
    a foreign mint AND with a fabricated token, and only a local parse can
    tell those apart (see ``_explain_paste``).
    """
    distinct = set(reasons or ())
    if distinct == {"spent"}:
        return "already_spent"
    return "mint_rejected"


#: The causes that mean THE MINT ANSWERED and refused.  Only one of these
#: may ever be written against an op the mint actually answered about, and
#: only one of them licenses the words "the mint rejected it".
_ANSWERED_CAUSES = ("mint_rejected", "already_spent")

#: What is known about an op the WALLET resolved as failed in a call that
#: ended some OTHER way (the multi-round receive: round one refused, round
#: two never answered).  The mint answered and refused this exchange —
#: that is the only way wallet.py writes ``failed`` — but the §3.8 reasons
#: it gave went out with an exception this call then replaced, so they are
#: not recorded and are not invented here.
_ANSWERED_ELSEWHERE = (
    "the mint answered and rejected this exchange; the operation then"
    " failed for a different reason, so the reasons the mint gave for this"
    " one were not recorded"
)

#: The mirror: an op nothing resolved, in a call whose error was an answer
#: about a DIFFERENT exchange.  That answer says nothing about this one.
_ANSWER_WAS_ELSEWHERE = (
    "nothing recorded what happened to this request: the refusal in this"
    " operation was of a different exchange, so why this one did not"
    " commit is undetermined — run recover() to settle it against the"
    " ledger"
)


def _cause_for_state(state, cause: str, text: str) -> tuple[str, str]:
    """(cause, sentence) for ONE op, from the wallet's record of THAT op.

    ``state`` is the op's own ``wallet_ops`` row at the end of the call,
    written by the wallet when the op ended, and it is the only per-op
    evidence that exists.  ``failed`` means the mint answered and refused
    it; anything else means nothing resolved it, which is what a transport
    failure leaves behind.  See ``WalletOps._settle_cause`` for why that
    reading of ``failed`` holds.

    So the call-level cause is used for an op only when it can be true of
    that op: an answer-cause for an op the mint answered about, a
    no-answer cause for an op nothing answered about.  Where they do not
    line up, this says what IS known and nothing more — never the other
    op's story, and never ``mint_unreachable`` for an exchange the mint
    enumerated.
    """
    answered = cause in _ANSWERED_CAUSES
    if state == "failed":
        return (cause, text) if answered else ("mint_rejected",
                                               _ANSWERED_ELSEWHERE)
    if answered:
        return "unknown", _ANSWER_WAS_ELSEWHERE
    return cause, text


def _reasons_of(errors) -> list[str]:
    out = []
    for e in errors or ():
        if isinstance(e, dict) and e.get("reason") is not None:
            out.append(str(e["reason"]))
    return out


def _from_rejection(errors, where: str) -> WalletOpsError:
    reasons = _reasons_of(errors)
    if not reasons:
        return WalletOpsError(
            "rejected by mint", f"{where}: the mint answered and rejected the"
            " exchange without naming a reason",
            "mint_rejected",
        )
    short, long = _explain(reasons[0], where)
    if len(set(reasons)) > 1:
        short = "rejected by mint"
    return WalletOpsError(
        short,
        f"{where}: the mint answered and rejected the exchange, §3.8 reasons "
        + ", ".join(sorted(set(reasons)))
        + f" — {long}",
        _cause_of_rejection(reasons),
    )


def _unavailable(exc: Exception, base_url: str,
                 stopped: bool = False) -> WalletOpsError:
    """The mint did not answer.  ``stopped`` only when something KNOWS it.

    Two causes, and the difference is whether anybody can see the process:
    this module can only observe a socket that did not answer, which is
    ``mint_unreachable`` — always true when the connection failed.
    ``mint_stopped`` is the stronger claim and is made only when a
    ``mint_running`` hook (gui/app.py has one) reports the process gone.
    Neither ever says the mint rejected anything: it did not answer, so it
    refused nothing.

    What neither sentence says is that the mint never RECEIVED the
    request, because a transport failure cannot establish that: §5.1
    persist-before-send and ``Wallet.recover()`` exist precisely because a
    request can land, commit on the ledger and still lose its answer.  The
    cause name is the pinned vocabulary's; the sentence claims only what a
    dead socket proves, and points at recover() for the rest.
    """
    if stopped:
        return WalletOpsError(
            "mint stopped",
            f"the mint process is not running, so it did not answer"
            f" {base_url} and refused nothing ({type(exc).__name__}:"
            f" {exc}); if anything was already in flight when it stopped,"
            f" run recover() to settle it against the ledger",
            "mint_stopped",
        )
    return WalletOpsError(
        "mint unreachable",
        f"could not talk to the mint at {base_url}: {type(exc).__name__}:"
        f" {exc} — the mint did not answer and refused nothing; whether it"
        f" ever saw this request is undetermined, so run recover() to"
        f" settle it. Is it running on that port?",
        "mint_unreachable",
    )


# ---------------------------------------------------------------------------
# WalletOps
# ---------------------------------------------------------------------------

_HELD = "confirmed"  # the only spendable state in wallet.py

#: sqlite has a bound on host parameters per statement; chunk IN () lists.
_SQL_CHUNK = 200

#: Hashes per /v3/status call when checking handed-over payments.  The
#: mint's own §3.6 ``limits.max_batch`` lowers it when it is smaller; this
#: is only the ceiling, so a mint that publishes nothing readable still
#: gets a request it is likely to accept.
_STATUS_BATCH = 64

#: WHERE a failure's cause is written down.  In the wallet store itself —
#: the module still writes exactly one file — beside wallet_ops, keyed by
#: the same op_id, and never read or written by aicash.wallet: a wallet
#: opened by any other tool ignores it, and this module treats its absence
#: as "no cause was recorded", which is exactly what it means.
_CAUSES_TABLE = "walletops_op_causes"
_CAUSES_DDL = (
    f"CREATE TABLE IF NOT EXISTS {_CAUSES_TABLE} ("
    " op_id    TEXT PRIMARY KEY,"   # the wallet_ops row this explains
    " cause    TEXT NOT NULL,"      # one of CAUSES
    " sentence TEXT NOT NULL,"      # what to show a human, as recorded
    " op       TEXT NOT NULL)"      # which call recorded it
)


class WalletOps:
    """Operations on ONE named wallet store against ONE mint base_url.

    Construction touches nothing: no file is created and no HTTP call is
    made, so building a ``WalletOps`` for a stopped mint is safe.  The
    underlying ``Wallet`` is opened lazily on the first operation that
    genuinely needs the mint (the ``Wallet`` constructor needs the
    descriptor's ``mint_id``).

    Thread-affine — see the module docstring.  One instance per request.
    """

    def __init__(self, store_path: str, base_url: str, *,
                 mint_running=None) -> None:
        self._store_path = os.path.abspath(str(store_path))
        self._base_url = str(base_url).rstrip("/")
        self._wallet: Wallet | None = None
        self._owner: int | None = None
        self._lock = threading.RLock()
        #: Optional ``() -> bool`` telling this module whether the mint
        #: PROCESS is running.  Only gui/app.py can know that; supplying it
        #: is what turns "the socket did not answer" (mint_unreachable) into
        #: the stronger, more useful "the mint is not running"
        #: (mint_stopped).  Settable after construction, which is how
        #: app.py installs it without the constructor signature being part
        #: of the component contract.
        self.mint_running = mint_running
        #: op_ids planned by the call currently running, filled by the
        #: wallet's own persist_fsync event, so a failure can be recorded
        #: against the exact ops it left behind.  None between calls.
        self._planned: list | None = None
        self._chained_hook = None

    # -- paths ----------------------------------------------------------

    @property
    def store_path(self) -> str:
        return self._store_path

    @property
    def base_url(self) -> str:
        return self._base_url

    # -- threading ------------------------------------------------------

    @contextlib.contextmanager
    def _entered(self):
        """Serialise one public call and refuse cross-thread reuse.

        sqlite connections belong to the thread that opened them.  Rather
        than let that surface as a raw ``sqlite3.ProgrammingError``, an
        instance that already owns an open store refuses a second thread
        by name.
        """
        if not self._lock.acquire(timeout=30.0):
            raise WalletOpsError(
                "wallet busy elsewhere",
                f"another operation on {self._store_path} is still running"
                " after 30s; a WalletOps instance serves one caller at a"
                " time — build one per request",
                "unknown",
            )
        try:
            me = threading.get_ident()
            if self._wallet is not None and self._owner not in (None, me):
                raise WalletOpsError(
                    "wallet busy elsewhere",
                    f"{self._store_path} was opened on thread"
                    f" {self._owner} and sqlite handles cannot cross"
                    " threads; build one WalletOps per thread/request"
                    " instead of sharing this one",
                    "unknown",
                )
            yield
        finally:
            self._lock.release()

    # -- why did it fail? -----------------------------------------------

    def _mint_is_stopped(self) -> bool:
        """True only when something that can SEE the process says it is gone.

        Deliberately asymmetric: anything other than an explicit ``False``
        from the hook — no hook, a hook that raises, a hook that answers
        None — leaves the weaker claim (mint_unreachable) in place.  An
        unreachable mint is a fact about a socket; a stopped mint is a fact
        about a process, and this module cannot see processes.
        """
        hook = self.mint_running
        if not callable(hook):
            return False
        try:
            return hook() is False
        except Exception:               # noqa: BLE001 - a broken hook is not
            return False                # a reason to mis-report the cause

    def _unreachable(self, exc: Exception) -> WalletOpsError:
        return _unavailable(exc, self._base_url, self._mint_is_stopped())

    def _on_wallet_event(self, event, op_id) -> None:
        """``Wallet.event_hook``: remember every op plan that hits the disk.

        The wallet fires this immediately after the plan COMMIT and before
        the exchange is sent, which is precisely the set of ops a failure
        can strand.  Any hook that was already installed (impl's own tests
        instrument with one) is chained, not replaced.
        """
        try:
            if event == "persist_fsync" and self._planned is not None:
                self._planned.append(op_id)
        finally:
            hook = self._chained_hook
            if callable(hook):
                hook(event, op_id)

    def _watch_ops(self) -> None:
        """Start collecting the op_ids of the call about to run."""
        self._planned = []

    def _settle_cause(self, cause: str, sentence, where: str) -> None:
        """Write WHY against every op this call left short of ``done``.

        PER OP — never one blanket story for the whole call.  ONE
        ``receive()`` can plan SEVERAL ops: ``Wallet.receive_batch``
        resolves the op the mint refused and retries the good remainder
        under a fresh op (impl/aicash/wallet.py), so a single call can end
        with an op the mint ANSWERED and refused beside an op the mint
        never answered about at all.  Applying the last exception's cause
        to both wrote "the mint never answered" onto the permanent record
        of an exchange the mint had enumerated and refused — the exact
        inversion of the defect this module exists to close.

        The per-op evidence is the wallet's OWN record, written by the
        wallet at the moment each op ended.  ``aicash.wallet`` moves an op
        to state ``failed`` in exactly five places and every one of them is
        inside an ``except MintRejected`` handler (``_resolve_failed`` from
        ``receive``, ``receive_batch``, ``pay``, ``pay_many``, ``refuse``):
        a ``failed`` op is one the mint answered about.  An op a transport
        failure stranded is still ``planned`` — nothing resolved it.  Each
        op's state at the end of the call therefore says which of the two
        happened to IT, and ``_cause_for_state`` turns that into the pair
        actually written.  (``recover()`` also writes ``failed``, but it
        plans no ops, so nothing it settles is ever in ``ops`` here.)

        Best effort by design: this is a record for a human reading history
        months later, not a step in the money path, so every failure here is
        swallowed.  ``INSERT OR IGNORE`` — a row keeps the cause it was
        written with, permanently; a later attempt is a different op.
        """
        ops, self._planned = self._planned, None
        if not ops:
            return
        cause = _clean_cause(cause)
        text = _sentence(sentence, cause)
        conn, borrowed = None, False
        try:
            if self._wallet is not None:
                conn, borrowed = self._wallet._db, True
            else:
                conn = sqlite3.connect(self._store_path, isolation_level=None)
            marks = ",".join("?" * len(ops))
            rows = conn.execute(
                "SELECT op_id, state FROM wallet_ops"
                f" WHERE op_id IN ({marks})",
                tuple(ops),
            ).fetchall()
            writes = []
            for op_id, state in rows:
                if state == "done":
                    continue
                op_cause, op_text = _cause_for_state(state, cause, text)
                writes.append((op_id, op_cause, op_text, str(where)))
            if not writes:
                return
            conn.execute(_CAUSES_DDL)
            conn.executemany(
                f"INSERT OR IGNORE INTO {_CAUSES_TABLE}"
                " (op_id, cause, sentence, op) VALUES (?, ?, ?, ?)",
                writes,
            )
        except Exception:               # noqa: BLE001 - see docstring
            pass
        finally:
            if conn is not None and not borrowed:
                try:
                    conn.close()
                except Exception:       # noqa: BLE001
                    pass

    # -- error guards ---------------------------------------------------

    @contextlib.contextmanager
    def _store_errors(self, where: str):
        """Every sqlite failure inside becomes exactly one WalletOpsError.

        This is the guard that makes the module docstring's promise true:
        corruption, permission denied, a locked database, a closed handle
        and cross-thread misuse all come out as ``wallet store error``
        with the underlying sqlite type and message in ``.detail``.
        """
        try:
            yield
        except sqlite3.Error as exc:
            raise WalletOpsError(
                "wallet store error",
                f"{where}: sqlite failure on {self._store_path}:"
                f" {type(exc).__name__}: {exc} — this is the wallet FILE, not"
                f" the mint; whether the mint saw anything is undetermined",
                "unknown",
            ) from exc

    # -- mint plumbing --------------------------------------------------

    def _client(self) -> MintClient:
        try:
            return MintClient(self._base_url)
        except ValueError as exc:
            raise WalletOpsError(
                "bad mint address",
                f"{self._base_url!r} is not a usable mint base url"
                f" (expected http://host:port): {exc}",
                "unknown",
            ) from exc

    def descriptor(self) -> dict:
        """The mint's §3.6 descriptor.  Raises WalletOpsError if it is down."""
        client = self._client()
        try:
            return client.descriptor()
        except MintUnavailable as exc:
            raise self._unreachable(exc) from exc
        except (KeyError, TypeError, ValueError) as exc:
            raise WalletOpsError(
                "bad mint response",
                f"the mint at {self._base_url} returned a descriptor this"
                f" build cannot read: {type(exc).__name__}: {exc}",
                "unknown",
            ) from exc

    def _live_mint_id(self) -> str | None:
        """The answering mint's id, or None when it is simply not there.

        Only DOWNTIME returns None.  A base_url that is not a usable mint
        address, or a mint answering with an unreadable descriptor, is a
        misconfiguration and still raises — collapsing those into "mint is
        down" would tell the operator to start a mint that is already
        running.
        """
        desc = None
        try:
            desc = self.descriptor()
        except WalletOpsError as exc:
            # The cause, not the phrase: "mint unreachable" and "mint
            # stopped" are the same fact about this call (nothing answered)
            # said with different confidence about why.
            if exc.cause in ("mint_unreachable", "mint_stopped"):
                return None
            raise
        mint_id = desc.get("mint_id")
        if not isinstance(mint_id, str) or not mint_id:
            raise WalletOpsError(
                "bad mint response",
                f"the descriptor from {self._base_url} carries no mint_id",
                "unknown",
            )
        return mint_id

    def _open(self, mint_id: str | None = None) -> Wallet:
        """Open (creating if needed) the wallet store.  Needs the mint up.

        Re-checks the binding on every call: if the mint answering on this
        address now calls itself something else (the operator restarted it
        under a new mint_id — one click in this GUI), the cached ``Wallet``
        is dropped and rebound, so we never send a stale mint's tokens or
        report a stale mint's id.
        """
        if mint_id is None:
            mint_id = self._live_mint_id()
            if mint_id is None:
                raise self._unreachable(MintUnavailable("no descriptor"))
        if self._wallet is not None:
            if self._wallet.mint_id == mint_id:
                self._arm_hook(self._wallet)
                return self._wallet
            self._close_locked()  # identity changed under us: rebind
        parent = os.path.dirname(self._store_path) or "."
        if not os.path.isdir(parent):
            raise WalletOpsError(
                "wallet folder missing",
                f"{parent} does not exist, and this module never creates"
                f" directories; create the wallets folder first",
                "unknown",
            )
        try:
            self._wallet = Wallet(self._store_path, self._client(), mint_id)
        except sqlite3.Error as exc:
            raise WalletOpsError(
                "wallet file unusable",
                f"sqlite could not open {self._store_path}:"
                f" {type(exc).__name__}: {exc}",
                "unknown",
            ) from exc
        except OSError as exc:
            raise WalletOpsError(
                "wallet file unusable",
                f"could not create {self._store_path}:"
                f" {type(exc).__name__}: {exc}",
                "unknown",
            ) from exc
        self._owner = threading.get_ident()
        self._arm_hook(self._wallet)
        return self._wallet

    def _arm_hook(self, wallet: Wallet) -> None:
        """Install _on_wallet_event, chaining whatever was there before.

        Identity is checked on the underlying FUNCTION and instance, not on
        the bound method: ``wallet.event_hook is self._on_wallet_event`` is
        always False (attribute access builds a fresh bound method each
        time), and a version of this that believed otherwise chained the
        hook to itself on every call and recursed until the stack ran out.
        """
        hook = getattr(wallet, "event_hook", None)
        if (getattr(hook, "__func__", None) is WalletOps._on_wallet_event
                and getattr(hook, "__self__", None) is self):
            return                      # already ours
        self._chained_hook = hook
        wallet.event_hook = self._on_wallet_event

    def _close_locked(self) -> None:
        w, self._wallet, self._owner = self._wallet, None, None
        if w is not None:
            # Wallet exposes no close(); the handle is private and this is
            # the one place this module reaches for it.  app.py relies on
            # close() to avoid leaking a handle per polled request.
            try:
                w._db.close()
            except sqlite3.Error:
                pass

    def close(self) -> None:
        """Release the sqlite handle.  Idempotent; never raises.

        Beyond the pinned contract, and deliberately so: ``gui/app.py``
        builds one WalletOps per HTTP request and calls this in a finally
        block, without which a polled wallet list leaks a handle per poll.
        """
        with self._lock:
            self._close_locked()

    # -- read-only store access ----------------------------------------

    def _connect_ro(self) -> sqlite3.Connection | None:
        """A READ-ONLY connection to the store, or None if it does not exist.

        ``mode=ro`` means this can never create the file and never mutates
        a byte of it.  sqlite failures are NOT swallowed: they propagate
        to the caller's ``_store_errors`` guard, because "this file cannot
        be read" and "this wallet is empty" must not look alike.
        """
        if not os.path.exists(self._store_path):
            return None
        uri = "file:" + urllib.request.pathname2url(self._store_path) + "?mode=ro"
        return sqlite3.connect(uri, uri=True)

    def _read(self, sql: str, params: tuple, where: str) -> list[tuple] | None:
        """One read-only query.  None ONLY when the store does not exist."""
        with self._store_errors(where):
            conn = self._connect_ro()
            if conn is None:
                return None
            try:
                return conn.execute(sql, params).fetchall()
            finally:
                conn.close()

    def _held(self) -> tuple[int, int]:
        """(balance_mc, coin_count) of spendable coins, without the mint."""
        if self._wallet is not None:
            with self._store_errors("balance"):
                rows = self._wallet._db.execute(
                    "SELECT COALESCE(SUM(amount_mc), 0), COUNT(*)"
                    " FROM wallet_tokens WHERE state = ?",
                    (_HELD,),
                ).fetchall()
        else:
            rows = self._read(
                "SELECT COALESCE(SUM(amount_mc), 0), COUNT(*)"
                " FROM wallet_tokens WHERE state = ?",
                (_HELD,),
                "balance",
            )
        if not rows:
            return 0, 0
        return int(rows[0][0] or 0), int(rows[0][1] or 0)

    def _balance(self, wallet: Wallet, where: str) -> int:
        with self._store_errors(where):
            return int(wallet.balance())

    # -- which mint does this store's money belong to? ------------------

    def _held_by_mint(self) -> list[tuple[str, int, int]]:
        """[(mint_id, held_mc, coin_count)] over CURRENTLY HELD value.

        A held coin was created as an output of some op; that op's stored
        plan lists the input token strings it was exchanged from, and a
        token string carries its mint_id.  So the mint a coin is worth
        money at is recoverable exactly, without a schema change and
        without trusting any cache.  ``mint_id`` is ``""`` for an op whose
        inputs could not be parsed.  Newest op first.
        """
        rows = self._read(
            "SELECT o.request_json, COALESCE(SUM(t.amount_mc), 0), COUNT(*)"
            " FROM wallet_tokens t JOIN wallet_ops o ON o.op_id = t.op_id"
            " WHERE t.state = ? GROUP BY o.op_id ORDER BY o.rowid DESC",
            (_HELD,),
            "mint binding",
        )
        merged: dict[str, list[int]] = {}
        order: list[str] = []
        for request_json, total, count in rows or ():
            mint_id = _plan_mint_id(request_json)
            if mint_id not in merged:
                merged[mint_id] = [0, 0]
                order.append(mint_id)
            merged[mint_id][0] += int(total or 0)
            merged[mint_id][1] += int(count or 0)
        return [(m, merged[m][0], merged[m][1]) for m in order]

    def _known_mint_id(self) -> str:
        """Best effort mint_id while the mint is DOWN.

        Preferred source: the mint the currently held coins were issued
        by.  Fallback for a wallet that holds nothing right now: the most
        recent operation's inputs.  Returns "" when the store has never
        recorded an operation at all — honestly unknown, not invented.
        """
        for mint_id, _mc, _n in self._held_by_mint():
            if mint_id:
                return mint_id
        rows = self._read(
            "SELECT request_json FROM wallet_ops ORDER BY rowid DESC LIMIT 20",
            (),
            "mint binding",
        )
        for (request_json,) in rows or ():
            mint_id = _plan_mint_id(request_json)
            if mint_id:
                return mint_id
        return ""

    def _assert_binding(self, live_mint_id: str, where: str) -> None:
        """Refuse to treat another mint's coins as money at this mint.

        Restarting the mint under a different mint_id on the same port is
        one click in this GUI.  The held coins are then worthless here —
        the ledger has no entry for them — and presenting their total as a
        balance, or trying to spend it, is the one confidently-wrong
        number a money UI must never show.
        """
        for mint_id, mc, count in self._held_by_mint():
            if mint_id and mint_id != live_mint_id:
                raise WalletOpsError(
                    "wrong mint",
                    f"this wallet holds {mc} mc ({count} coin"
                    f"{'' if count == 1 else 's'}) issued by mint"
                    f" {mint_id!r}, but the mint answering at"
                    f" {self._base_url} calls itself {live_mint_id!r}."
                    f" {live_mint_id!r} has no ledger entry for those"
                    f" coins, so they cannot be spent or counted here"
                    f" ({where}).  Restart the mint with mint_id"
                    f" {mint_id!r} to reach this money again.",
                    "wrong_mint",
                )

    # -- the contract ---------------------------------------------------

    def summary(self) -> dict:
        """{"balance_mc", "mint_id", "coin_count", "connected"}.

        Never raises for a mint that is merely down: ``connected`` is
        False and the balance is the last known held value read straight
        off the local store, which is the truth about what this wallet
        holds regardless of whether the mint is answering.  ``mint_id`` is
        then the mint that money belongs to, read out of the store — never
        a live id that would contradict ``connected=False``.

        It DOES raise, rather than report a fabricated zero, when the
        store cannot be read at all, and when the held coins belong to a
        different mint than the one now answering.

        Side effect: when the mint is reachable and the store file does
        not exist yet, it is created (this is how a new wallet is
        materialised).  Nothing else is ever written.
        """
        with self._entered():
            live = self._live_mint_id()
            if live is None:
                balance, count = self._held()
                return {
                    "balance_mc": balance,
                    "mint_id": self._known_mint_id(),
                    "coin_count": count,
                    "connected": False,
                }
            self._assert_binding(live, "summary")
            self._open(live)
            balance, count = self._held()
            return {
                "balance_mc": balance,
                "mint_id": live,
                "coin_count": count,
                "connected": True,
            }

    def receive(self, tokens: list[str]) -> dict:
        """Redeem a batch of pasted token strings.

        ONE ``/v3/exchange`` for the whole batch, so ONE burn on the input
        sum rather than a burn per token (§3.3, §7.3, §9.2).  A token that
        is spent, unknown or malformed is reported in ``rejected`` and the
        remaining good tokens are re-sent under a fresh idempotency key —
        one bad paste never costs the caller the good tokens beside it.

        Returns {"accepted_mc", "accepted", "rejected": [{token, reason,
        detail, cause}]}.  ``accepted_mc`` is NET of the burn, and each
        rejection's ``cause`` is from CAUSES — ``malformed_token`` and
        ``wrong_mint`` are decided HERE, locally, without the mint having
        been asked, and are never reported as the mint refusing anything.
        """
        if not isinstance(tokens, list) or not all(
            isinstance(t, str) for t in tokens
        ):
            raise WalletOpsError(
                "bad request",
                "receive() takes a list of token strings; got"
                f" {type(tokens).__name__}; nothing was sent to the mint",
                "unknown",
            )
        if not tokens:
            return {"accepted_mc": 0, "accepted": 0, "rejected": []}
        with self._entered():
            wallet = self._open()
            self._watch_ops()
            try:
                try:
                    with self._store_errors("receive"):
                        result = wallet.receive_batch(tokens)
                except PaymentInvalid as exc:
                    raise _from_rejection(exc.errors, "receive") from exc
                except MintRejected as exc:
                    raise _from_rejection(exc.errors, "receive") from exc
                except MintUnavailable as exc:
                    raise self._unreachable(exc) from exc
                except ValueError as exc:
                    raise WalletOpsError(
                        "bad request", f"receive: {exc}; nothing was sent to"
                        f" the mint", "unknown") from exc
            except WalletOpsError as exc:
                # Record WHY against whatever this call left unfinished,
                # while the reason is still known.  Nothing downstream can
                # work it out later: a failed op looks identical whether the
                # mint refused it or never heard of it.  A batch can leave
                # BOTH behind (the mint refuses round one, the retry never
                # lands), so _settle_cause decides per op rather than
                # stamping this error's cause on all of them.
                self._settle_cause(exc.cause, exc.detail, "receive")
                raise
            rejected = []
            for dead in result.get("dead", []):
                i = dead.get("index")
                token = tokens[i] if isinstance(i, int) and 0 <= i < len(
                    tokens) else ""
                short, long, cause = self._explain_paste(
                    dead.get("reason"), token, wallet.mint_id)
                rejected.append(
                    {"token": token, "reason": short, "detail": long,
                     "cause": cause}
                )
            # A partially-rejected batch SUCCEEDS (the good tokens are
            # credited) while still leaving failed ops behind: those the
            # mint answered and refused.  They get their cause too, from the
            # answer the mint actually gave.
            accepted_mc = int(result.get("credited_mc", 0))
            accepted = len(tokens) - len(rejected)
            # ONLY the rejections the mint itself answered with count
            # here, and only those are named in the sentence: a token this
            # module dropped locally (malformed, or from another mint) was
            # never sent, so listing it as something the mint refused would
            # blame the mint for a refusal it never made.
            answered = {r["cause"] for r in rejected
                        if r["cause"] in _ANSWERED_CAUSES}
            if answered:
                named = ", ".join(sorted(
                    {r["reason"] for r in rejected
                     if r["cause"] in _ANSWERED_CAUSES}))
                one = accepted == 1
                rest = (f" the other {accepted} token{'' if one else 's'}"
                        f" in the batch {'was' if one else 'were'} re-sent"
                        f" under a fresh key and credited {accepted_mc} mc"
                        if accepted else " nothing in this batch was credited")
                self._settle_cause(
                    "already_spent" if answered == {"already_spent"}
                    else "mint_rejected",
                    f"the mint answered and rejected this exchange ({named});"
                    + rest,
                    "receive",
                )
            else:
                # Nothing the mint refused.  Any op still short of `done`
                # here (there should be none) is not explained by anything
                # this call saw, and saying so is the whole discipline.
                self._settle_cause(
                    "unknown",
                    "this batch committed; nothing recorded why any"
                    " remaining op did not, so it is undetermined",
                    "receive",
                )
            return {
                "accepted_mc": accepted_mc,
                "accepted": accepted,
                "rejected": rejected,
            }

    @staticmethod
    def _explain_paste(reason, token: str,
                       mint_id: str) -> tuple[str, str, str]:
        """(short, long, cause) for ONE rejected pasted token, refined locally.

        ``Wallet.receive_batch`` maps a perfectly well-formed token from
        ANOTHER mint to ``bad_format`` before any HTTP call, so the §3.8
        table alone would tell the operator to re-copy a paste that is in
        fact intact.  Re-parsing the string here recovers the distinction:
        parses fine but names a different mint -> "not from this mint",
        with both ids in the detail.
        """
        short, long = _explain(reason, "paste")
        if str(reason) != "bad_format":
            # Only the mint produces these, and only by answering.
            return short, long, _cause_of_rejection([str(reason)])
        if not token:
            # bad_format with no string to look at: this could be the local
            # pre-flight or the mint's own answer and there is no way to
            # tell from here, so it is undetermined and says so.
            return short, long, "unknown"
        try:
            tok = parse_token(token)
        except TokenError:
            # Rejected by the local pre-flight, before any HTTP call: the
            # mint was never shown this string and refused nothing.
            return short, long, "malformed_token"
        if tok.mint_id != mint_id:
            return (
                "not from this mint",
                f"this is a well-formed token — nothing is wrong"
                f" with the paste — but it was issued by mint"
                f" {tok.mint_id!r} and this wallet is connected to"
                f" {mint_id!r}.  Only {mint_id!r} can redeem it, and it was"
                f" never sent: this mint was not asked about it.",
                "wrong_mint",
            )
        # Parses, names this mint, and was still called bad_format: that
        # verdict can only have come from the mint answering.
        return short, long, "mint_rejected"

    def quote(self, amount_mc: int) -> dict:
        """Dry run of ``pay(amount_mc)``: what it would cost, no mutation.

        {"amount_mc", "burn_mc", "change_mc", "inputs_mc"} where
        ``inputs_mc == amount_mc + burn_mc + change_mc``.  The burn is a
        function of the INPUT sum, not of the amount (§7.3), so overshoot
        and the anti-fragmentation sweep can raise it — that is exactly
        what this exposes.
        """
        amount_mc = _amount(amount_mc, "quote")
        with self._entered():
            live = self._live_mint_id()
            if live is None:
                raise self._unreachable(MintUnavailable("no descriptor"))
            self._assert_binding(live, "quote")
            wallet = self._open(live)
            try:
                with self._store_errors("quote"):
                    q = wallet.quote(amount_mc)
            except InsufficientFunds as exc:
                raise _insufficient(exc, self._held()[0], amount_mc) from exc
            except MintUnavailable as exc:
                raise self._unreachable(exc) from exc
            except ValueError as exc:
                raise WalletOpsError(
                    "bad amount",
                    f"quote: {exc}; nothing was sent to the mint",
                    "unknown") from exc
            return {
                "amount_mc": amount_mc,
                "burn_mc": int(q["burn_mc"]),
                "change_mc": int(q["change_mc"]),
                "inputs_mc": int(q["inputs_mc"]),
            }

    def pay(self, amount_mc: int) -> dict:
        """Produce bearer token strings totalling ``amount_mc``.

        {"tokens", "amount_mc", "burn_mc"}.  ``burn_mc`` is measured, not
        predicted: it is the drop in held balance minus the amount paid,
        which is precisely what the mint burned on this exchange.
        """
        amount_mc = _amount(amount_mc, "pay")
        with self._entered():
            live = self._live_mint_id()
            if live is None:
                raise self._unreachable(MintUnavailable("no descriptor"))
            self._assert_binding(live, "pay")
            wallet = self._open(live)
            before = self._balance(wallet, "pay")
            self._watch_ops()
            try:
                try:
                    with self._store_errors("pay"):
                        tokens = wallet.pay(amount_mc)
                except InsufficientFunds as exc:
                    raise _insufficient(exc, before, amount_mc) from exc
                except MintRejected as exc:
                    raise _from_rejection(exc.errors, "pay") from exc
                except PaymentInvalid as exc:
                    raise _from_rejection(exc.errors, "pay") from exc
                except MintUnavailable as exc:
                    raise self._unreachable(exc) from exc
                except ValueError as exc:
                    raise WalletOpsError(
                        "bad amount",
                        f"pay: {exc}; nothing was sent to the mint",
                        "unknown") from exc
            except WalletOpsError as exc:
                # The op this call planned (if it got that far) is stranded
                # in the store.  Write down what stranded it NOW: after this
                # returns, "the mint said no" and "the mint never heard of
                # it" are the same row.
                self._settle_cause(exc.cause, exc.detail, "pay")
                raise
            # Committed: every op this call planned is `done`, so there is
            # nothing to explain — just stop watching.
            self._planned = None
            after = self._balance(wallet, "pay")
            return {
                "tokens": list(tokens),
                "amount_mc": amount_mc,
                "burn_mc": max(0, (before - after) - amount_mc),
            }

    def recover(self) -> dict:
        """Resolve operations left in flight by a crash, against the mint.

        Passes through ``Wallet.recover``'s summary counters unchanged.
        Deliberately NOT gated on the mint-binding check: resolving an
        in-flight op against whatever mint is there is exactly what a
        stranded operator needs, and recover() moves no new value.
        """
        with self._entered():
            wallet = self._open()
            self._watch_ops()
            try:
                try:
                    with self._store_errors("recover"):
                        return dict(wallet.recover())
                except MintUnavailable as exc:
                    raise self._unreachable(exc) from exc
                except MintRejected as exc:
                    raise _from_rejection(exc.errors, "recover") from exc
            except WalletOpsError as exc:
                self._settle_cause(exc.cause, exc.detail, "recover")
                raise
            finally:
                # recover() plans nothing of its own; this only releases the
                # watch.  The ops it resolves already carry the cause that
                # was recorded when they were stranded, and INSERT OR IGNORE
                # means resolving them never rewrites that history.
                self._planned = None

    def outstanding_payments(self, *, limit: int = 20) -> dict:
        """The bearer strings of past payments, rebuilt from the store.

        THE ANSWER TO "the only copy is in a DOM node".  It is not: every
        payment output was written to this wallet file, secret included,
        before the exchange was sent (§5.1), and is still there in state
        ``handed_over``.  This rebuilds the exact strings ``pay()``
        returned, so a reload, a closed tab or a delivery that failed
        halfway does not destroy money — see the module docstring for why
        no new file is written to achieve that.

        ``handed_over`` means "this left the wallet", NOT "nobody redeemed
        it".  Only the mint knows which, so when it answers, every string
        is checked against §3.4 ``/v3/status`` and reported ``unspent``
        (still live), ``spent`` (the payee took it) or ``unknown`` (no
        ledger entry — a different mint's database).  With the mint down
        the strings still come back with ``checked: False`` and ``state:
        None``: an unchecked string is not claimed to be money, and it is
        not claimed to be dead either.

        ``limit`` is a number of PAYMENT OPERATIONS, newest first.

        It hands out live secrets — the only method here that does — so a
        caller must treat the result as money, not as a report.  What that
        widens is stated in ``gui/app.py``'s route: a payment already
        delivered but not yet redeemed can be read back and re-spent by
        whoever can call this, which is anyone who could already spend the
        whole wallet.
        """
        if type(limit) is not int or limit <= 0:
            raise WalletOpsError(
                "bad request", f"limit must be a positive int, got {limit!r}",
                "unknown")
        with self._entered():
            rows = self._read(
                "SELECT t.op_id, t.secret, t.amount_mc, t.key, o.request_json"
                " FROM wallet_tokens t JOIN wallet_ops o ON o.op_id = t.op_id"
                " WHERE t.state = 'handed_over' AND t.role = 'payment'"
                " ORDER BY o.rowid DESC, t.key",
                (),
                "outstanding",
            )
            payments: list[dict] = []
            by_op: dict = {}
            fallback_mint_id = None     # read from the store at most once
            for op_id, secret, amount_mc, key, request_json in rows or ():
                if op_id not in by_op:
                    if len(by_op) >= limit:
                        continue
                    by_op[op_id] = {"op_id": op_id, "amount_mc": 0,
                                    "live_mc": None, "tokens": [],
                                    "_mint_id": _plan_mint_id(request_json)}
                    payments.append(by_op[op_id])
                entry = by_op[op_id]
                if not entry["_mint_id"] and fallback_mint_id is None:
                    fallback_mint_id = self._known_mint_id()
                mint_id = entry["_mint_id"] or fallback_mint_id
                try:
                    token = format_token(
                        mint_id, int(amount_mc),
                        b64u_decode(str(secret), expect_len=32))
                except (TokenError, ValueError, TypeError):
                    # A row this build cannot render is reported as a row it
                    # cannot render, not silently dropped: money the operator
                    # cannot see is worse than a gap they can.
                    entry["tokens"].append(
                        {"token": "", "amount_mc": int(amount_mc or 0),
                         "key": str(key), "state": None})
                    entry["amount_mc"] += int(amount_mc or 0)
                    continue
                entry["tokens"].append(
                    {"token": token, "amount_mc": int(amount_mc or 0),
                     "key": str(key), "state": None})
                entry["amount_mc"] += int(amount_mc or 0)
            checked = self._check_spent(payments)
            for entry in payments:
                entry.pop("_mint_id", None)
                if checked:
                    entry["live_mc"] = sum(
                        t["amount_mc"] for t in entry["tokens"]
                        if t["state"] == "unspent")
            return {
                "checked": checked,
                "mint_id": self._known_mint_id(),
                "payments": payments,
            }

    def _check_spent(self, payments: list) -> bool:
        """Ask the mint which of these strings are still money.  Best effort.

        Returns whether the answer is trustworthy: True when every string
        below carries a state the mint gave for it, False when the mint
        could not be asked.  A mint that is down, or that fails the query,
        leaves every ``state`` at None and returns False — the strings are
        still returned, because they are still the operator's money; what
        is withheld is any CLAIM about them.

        With NOTHING to check the answer is True, and vacuously so: every
        string listed (there are none) carries the mint's word for it, so
        nothing in the report is unverified.  Returning False there would
        say "the mint could not be asked" about a mint that was never
        asked because there was nothing to ask — the same conflation of
        "nothing" with "broken" this module exists to refuse.  A caller
        that wants to know whether the mint is reachable reads
        ``summary()["connected"]``, which is the field for that question.
        """
        keys = [t["key"] for p in payments for t in p["tokens"] if t["key"]]
        if not keys:
            return True
        # Chunked against the mint's published §3.6 limits.max_batch, not
        # sent as one unbounded list: a wallet with many handed-over
        # payments would otherwise be refused wholesale and read as
        # "could not check" when the mint was perfectly willing to answer.
        results: list = []
        try:
            client = self._client()
            step = _STATUS_BATCH
            try:
                limit = int(self.descriptor()["limits"]["max_batch"])
                step = max(1, min(step, limit))
            except (WalletOpsError, KeyError, TypeError, ValueError):
                pass                    # the conservative default stands
            for start in range(0, len(keys), step):
                _mint_time, part = client.status(keys[start:start + step])
                if not isinstance(part, list):
                    return False
                results.extend(part)
        except (WalletOpsError, MintUnavailable, MintRejected, OSError,
                ValueError, KeyError, TypeError):
            return False
        if len(results) != len(keys):
            return False
        states = {}
        for key, result in zip(keys, results):
            state = result.get("state") if isinstance(result, dict) else None
            states[key] = state if state in ("unspent", "spent",
                                             "unknown") else None
        for payment in payments:
            for token in payment["tokens"]:
                token["state"] = states.get(token["key"])
        return True

    def history(self, *, limit: int = 50) -> list[dict]:
        """Reconstructed transaction log, newest first.

        Rows are ``{"ts_ms", "kind", "amount_mc", "detail", "cause"}``.
        ``cause`` is ``""`` for an op that committed and otherwise one of
        CAUSES, read back from what was recorded AT THE TIME OF FAILURE —
        never inferred from the state column, which cannot tell a refusal
        from a request the mint never received.  A row with no recorded
        cause reads ``unknown`` and its detail says the cause is
        undetermined.  READ THE
        MODULE DOCSTRING before trusting a field: the store has no clock,
        so ``ts_ms`` is always ``TS_UNKNOWN`` and "newest first" means
        newest by sqlite insertion order, not by time.  ``TS_UNKNOWN``
        *is* the integer ``0``, but it means UNKNOWN, never 1970 — it
        prints as ``unknown`` and ``row["ts_ms"] is TS_UNKNOWN`` is the
        exact test.  Do not render it as a date.  ``kind`` is drawn from
        the closed set listed in the module docstring; ``amount_mc`` is
        always a non-negative magnitude, direction lives in ``kind``.

        Reads the store READ-ONLY over ONE connection, so the page a
        caller gets is one consistent snapshot even if the wallet is being
        written to at the same time.  Raises rather than returning ``[]``
        when the store cannot be read: "no activity" and "unreadable" are
        not the same answer.
        """
        if type(limit) is not int or limit <= 0:
            raise WalletOpsError(
                "bad request",
                f"limit must be a positive int, got {limit!r}",
                "unknown",
            )
        with self._entered():
            with self._store_errors("history"):
                conn = self._connect_ro()
                if conn is None:
                    return []
                try:
                    ops = conn.execute(
                        "SELECT op_id, kind, state, request_json FROM"
                        " wallet_ops ORDER BY rowid DESC LIMIT ?",
                        (limit,),
                    ).fetchall()
                    if not ops:
                        return []
                    op_ids = [o[0] for o in ops]
                    out_by_op = _outputs_by_op(conn, op_ids)
                    causes = _causes_by_op(conn, op_ids)
                finally:
                    conn.close()
        return [
            _history_row(op_id, kind, state, request_json,
                         out_by_op.get(op_id, {}), causes.get(op_id))
            for op_id, kind, state, request_json in ops
        ]


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _outputs_by_op(conn, op_ids: list) -> dict:
    """{op_id: {role: total_mc}} for many ops in ONE grouped query.

    Deliberately not one query per row: ``history()`` is polled, and a
    per-row query is both an N+1 and a different snapshot per row.
    """
    out: dict = {}
    for start in range(0, len(op_ids), _SQL_CHUNK):
        chunk = op_ids[start:start + _SQL_CHUNK]
        marks = ",".join("?" * len(chunk))
        rows = conn.execute(
            "SELECT op_id, role, COALESCE(SUM(amount_mc), 0) FROM"
            f" wallet_tokens WHERE op_id IN ({marks}) GROUP BY op_id, role",
            tuple(chunk),
        ).fetchall()
        for op_id, role, total in rows:
            out.setdefault(op_id, {})[str(role)] = int(total or 0)
    return out


def _causes_by_op(conn, op_ids: list) -> dict:
    """{op_id: (cause, sentence)} for the ops in this page of history.

    ONE grouped query on the SAME connection and the same snapshot as the
    rest of history, for the same reason ``_outputs_by_op`` is: a per-row
    query is an N+1 and reads each row under a different snapshot.

    A store that has never recorded a cause has no table, which is not an
    error — it is the answer "nothing was recorded", and every row it
    covers reads ``unknown``.  Only that one sqlite complaint is absorbed;
    any other failure is a real store failure and propagates to the
    caller's ``_store_errors`` guard.
    """
    out: dict = {}
    for start in range(0, len(op_ids), _SQL_CHUNK):
        chunk = op_ids[start:start + _SQL_CHUNK]
        marks = ",".join("?" * len(chunk))
        try:
            rows = conn.execute(
                f"SELECT op_id, cause, sentence FROM {_CAUSES_TABLE}"
                f" WHERE op_id IN ({marks})",
                tuple(chunk),
            ).fetchall()
        except sqlite3.OperationalError as exc:
            if "no such table" not in str(exc).lower():
                raise
            return out
        for op_id, cause, sentence in rows:
            out[op_id] = (str(cause), str(sentence))
    return out


def _history_row(op_id, kind, state, request_json, out_by_role: dict,
                 cause_row=None) -> dict:
    inputs = _plan_inputs(request_json)
    face_in, unparsed = 0, 0
    for tok in inputs:
        try:
            face_in += parse_token(tok).amount_mc
        except TokenError:
            unparsed += 1
    out_total = sum(out_by_role.values())
    # The mint's conservation rule is sum(in) == sum(out) + burn (§3.3),
    # so the burn charged is recoverable exactly — provided every input
    # token string parsed.
    burn = face_in - out_total if not unparsed else None
    burn_txt = f"burn {burn} mc" if burn is not None and burn >= 0 else \
        "burn not reconstructible"

    committed = state == "done"
    suffix = "" if committed else (
        "_failed" if state == "failed" else "_pending"
    )
    cause, note = _cause_note(state, cause_row)
    if kind == "pay":
        paid = out_by_role.get("payment", 0)
        change = out_by_role.get("change", 0)
        if committed:
            amount, detail = paid, (
                f"paid out {paid} mc, {burn_txt}, {change} mc change"
                " returned to the wallet"
            )
        else:
            amount, detail = 0, (
                f"payment of {paid} mc did not commit"
                f" ({note}); no value left the wallet"
            )
    elif kind == "receive":
        n = len(inputs)
        if committed:
            amount, detail = out_total, (
                f"redeemed {n} token{'' if n == 1 else 's'}"
                f" worth {face_in} mc face, {burn_txt},"
                f" {out_total} mc credited"
            )
        else:
            amount, detail = 0, (
                f"redeeming {n} token{'' if n == 1 else 's'}"
                f" ({face_in} mc face) did not commit"
                f" ({note})"
            )
    elif kind == "refused":
        if committed:
            amount, detail = out_total, (
                f"reclaimed {len(inputs)} refused payment token(s),"
                f" {face_in} mc face, {burn_txt},"
                f" {out_total} mc back in the wallet"
            )
        else:
            amount, detail = 0, (
                f"reclaiming {len(inputs)} refused token(s) did not"
                f" commit ({note})"
            )
    else:  # a kind this build does not know — report, do not invent
        amount = out_total if committed else 0
        detail = (
            f"operation kind {str(kind)!r} recorded by a newer wallet"
            f" build; {out_total} mc of outputs, state {state}"
            + ("" if committed else f" ({note})")
        )
    if unparsed:
        detail += (
            f" — {unparsed} input token string(s) in the stored plan"
            " could not be parsed, so the face total is incomplete"
        )
    return {
        # The store keeps no timestamps; TS_UNKNOWN is 0 and says so when
        # printed, so "unknown" cannot be mistaken for the epoch.
        "ts_ms": TS_UNKNOWN,
        "kind": f"{kind}{suffix}",
        "amount_mc": int(amount),
        "detail": detail,
        # Recorded when it failed, never reconstructed afterwards.
        "cause": cause,
    }


def _cause_note(state, cause_row) -> tuple[str, str]:
    """(cause, one clause for the detail) for an op that did not commit.

    THE FIX THIS ROUND EXISTS FOR.  This used to return the fixed string
    "the mint rejected it" for every op in state ``failed`` — including a
    delivery that failed because the mint was DOWN, which the mint never
    saw and therefore never refused.  That row is permanent and is what an
    operator debugs from months later, so it sent them at the wrong
    component with full confidence.

    There is nothing in ``wallet_ops`` to derive the cause from: ``failed``
    is written both by a §3.8 rejection and by ``recover()`` settling an op
    the mint never answered about.  So the only honest sources are the row
    this module wrote at the time of failure, and — when there is none —
    the word ``unknown``, said plainly.
    """
    if state == "done":
        return "", ""
    cause = _clean_cause(cause_row[0]) if cause_row else "unknown"
    recorded = _sentence(cause_row[1], cause) if cause_row else ""
    if not recorded:
        # Nothing was written down for this op.  Say that, in those words.
        recorded = _CAUSE_FALLBACK["unknown"] if state == "failed" else (
            "this wallet does not know whether the mint received it, and"
            " nothing recorded why — run recover() to settle it against the"
            " ledger"
        )
        return "unknown", recorded
    if state == "planned":
        return cause, f"{recorded} — still unresolved; run recover() to settle"
    return cause, recorded


def _plan_inputs(request_json) -> list[str]:
    """The plain token strings of a stored plan's inputs.

    Used only to read their FACE AMOUNTS and their mint_id.  These strings
    carry live secrets: they are never returned, logged, or put in a
    detail string.
    """
    try:
        body = json.loads(request_json)
    except (TypeError, ValueError):
        return []
    if not isinstance(body, dict):
        return []
    return [i for i in body.get("inputs", []) if isinstance(i, str)]


def _plan_mint_id(request_json) -> str:
    """The mint_id the inputs of a stored plan were issued by, or ""."""
    for tok in _plan_inputs(request_json):
        try:
            return parse_token(tok).mint_id
        except TokenError:
            continue
    return ""


def _amount(amount_mc, where: str) -> int:
    """Validate an amount BEFORE anything is opened or dialled.

    ``type(x) is not int`` already rejects ``bool`` (``type(True) is
    bool``), so no separate bool clause is needed.  The point of checking
    here rather than leaving it to ``Wallet``'s identical check is that a
    typo must not need a running mint and an open store to be reported:
    ``pay("100")`` says "bad amount" even with the mint stopped.
    """
    if type(amount_mc) is not int:
        raise WalletOpsError(
            "bad amount",
            f"{where}: amount_mc must be a whole number of millicents,"
            f" got {type(amount_mc).__name__} — nothing was sent to the mint",
            "unknown",
        )
    if amount_mc <= 0:
        raise WalletOpsError(
            "bad amount",
            f"{where}: amount_mc must be greater than zero, got {amount_mc}"
            f" — nothing was sent to the mint",
            "unknown",
        )
    return amount_mc


def _insufficient(exc: Exception, held_mc: int, amount_mc: int) -> WalletOpsError:
    return WalletOpsError(
        "insufficient funds",
        f"cannot pay {amount_mc} mc: the wallet holds {held_mc} mc and the"
        f" burn is charged on top of the amount (§7.3) — nothing was sent to"
        f" the mint: {exc}",
        "insufficient_funds",
    )
