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

So this module writes the cause down.  One extra table in the wallet
store, alongside the two the protocol defines — see containment below for
why THIS one lives in the store while the payment record does not::

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

WHAT A PAYMENT RECORD CARRIES
-----------------------------
A history row is read months later, by someone deciding which component
to go and look at.  Until this round a ``pay`` row recorded the amount
and nothing else, so a payment that ARRIVED and a payment whose delivery
DIED were identical in every field, forever — and the row that cannot
tell them apart sends its reader to the wrong place with no way to know
it.  So every payment now records, durably, in the GUI-owned file beside
the store::

    op_id            the handle that finds the value again
    amount_mc        what left the wallet as payment
    burn_mc          what the mint took on the split
    change_mc        what came back into the wallet
    recipient        the name it was meant for, when there was one
    recipient_kind   "wallet" (a named recipient) | "bearer" (strings
                     handed back to the caller, no recipient named)
    delivery         "delivered" | "undelivered" | "unknown"
    delivery_cause   one of CAUSES, unchanged, for a delivery that ended
                     in something OBSERVED — including an ``unknown``
                     one, where ``mint_unreachable`` is the exact word
                     for "nobody answered"; "" when nothing was observed
    delivery_attempt "attempted" | "not_attempted" — did this wallet ever
                     try?  A narrower question than ``delivery``
    note             the sentence, as recorded at the time

``delivery`` is a CLOSED set of three and ``unknown`` is a REAL member of
it, not a placeholder to be tidied away later.  It is what an interrupted
delivery leaves behind and it must render as unknown: the record is
written BEFORE the delivery is attempted, in state ``unknown``, and is
settled to ``delivered`` or ``undelivered`` only when this process
actually sees the answer.  Kill the GUI between those two moments and the
row says ``unknown`` — which is precisely true, because the recipient may
or may not have been credited, and nothing in this machine knows which.

AND ``unknown`` IS NOT ONE STATE.  Most payments this product makes land
in it, so collapsing everything inside it into one pair of fields
reproduces, one level down, the very defect the record was added to fix.
Four situations are told apart in MACHINE-READABLE fields — see
``DELIVERY_ATTEMPTS`` for the table — because "never sent", "sent and
lost", "nobody answered" and "handed over as bearer strings" send an
operator to four different places.

The mapping from a failed delivery to an outcome is the round-4 cause
vocabulary applied without softening::

    mint_stopped, mint_rejected, already_spent, malformed_token,
    wrong_mint, insufficient_funds      -> undelivered   (something
        answered, or was known to be down; the value did not land)

    mint_unreachable, unknown           -> unknown       (§5.1: whether
        the exchange landed is undetermined, and a wallet that guessed
        here would be guessing about the recipient's money)

The OUTCOME is weakened there; the CAUSE is not.  An ``unknown`` delivery
still records ``mint_unreachable`` when that is what happened, because
"nobody answered" is a precise, pinned word and discarding it made a
delivery that was attempted and lost identical to one never attempted.

AND WHAT BECAME OF THE VALUE IS A THIRD QUESTION, answered per cause and
never across all of them.  ``already_spent`` means another party redeemed
those strings: the value is not the payer's, and the note says so.
``mint_stopped``, ``mint_rejected``, ``wrong_mint``, ``malformed_token``
consumed nothing, so the value was still the payer's when the row was
written — which is what the note claims, in those words, with a pointer
at ``unredeemed_payments()`` for what is live NOW.  See
``_refused_value_clause``.

An undelivered or unknown row always names the way back to the value:
the op_id, which is what ``unredeemed_payments()`` groups by, and the
strings themselves are still in the store in state ``handed_over``.

TWO QUESTIONS ABOUT MONEY THAT IS NOT WHERE YOU LEFT IT
-------------------------------------------------------
These are different questions with different answers, and a wallet can
answer "220 mc across four strings" to one and "nothing to settle" to the
other IN THE SAME INSTANT without either being wrong::

    THE HANDED-OVER QUESTION — unredeemed_payments()
        "Of the value this wallet has already paid out, what has nobody
        redeemed yet?"  Looks at COMMITTED payments (every output in role
        ``payment`` of a ``wallet_ops`` row in state ``done``, whatever
        the output's own state is now) and asks the mint which strings
        are still unspent.  It does NOT look at operations that never
        finished, and finding value here is NOT a sign that anything is
        broken: a payment that was made ten seconds ago and not yet
        redeemed is listed, and so is one that was delivered and simply
        not spent.

        IT REPORTS TWO NUMBERS, NOT ONE, and the distinction is the whole
        point: ``amount_mc`` is what the payment handed over and is fixed
        for good at the instant it committed; ``live_mc`` / ``retired_mc``
        / the per-string states are how much of that is still unredeemed,
        and those move.  Reporting the second under the first's name made
        an old payment's amount shrink whenever a later operation touched
        one of its strings, while ``history()`` went on printing the
        original figure — one payment, two amounts, and the moving one
        wearing the permanent one's name.

    THE IN-FLIGHT QUESTION — recover()
        "Did this wallet start an operation that never got an answer?"
        Looks at ops still in state ``planned`` and settles each against
        the ledger (§5.1).  It does NOT look at handed-over value at all,
        so it correctly reports nothing to do while a wallet has hundreds
        of millicredits of unredeemed payments sitting in it.

The old name for the first of those was ``outstanding_payments()``, and
"outstanding" is exactly the word that blurs them — it reads as "needs
recovering", which is the OTHER question.  The old name still works and
forwards to the new one; it is documented as the ambiguous spelling so
that nobody re-derives the confusion from a call site.

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
This module writes exactly TWO files, both under the pinned workdir and
both named from the ``store_path`` it was constructed with::

    var/wallets/<name>.db            the wallet store — THE MONEY (0600)
    var/wallets/<name>.payments.db   the payment record — NO MONEY IN IT,
                                     and also 0600: no secret, but the
                                     whole payment graph

The second is new.  It holds NO SECRET — no token string, no key, no way
to spend anything: amounts, an op_id, a recipient name and a delivery
outcome, every one a fact ABOUT money rather than a way to move it.  The
second copy of live value a sidecar of token strings WOULD be is still
refused, and still for the reason given under "money stranded" below.

"It holds no money" is NOT the same claim as "it is harmless to leave
readable", and only the first was ever true.  It holds this wallet's
entire payment graph: who was paid, how much, when relative to what
else.  So it is created ``0600``, like the store beside it, rather than
at whatever the ambient umask gives (0644 on a default 022) — chmod'd on
every write, so a file an earlier build created wrong is repaired the
next time this one touches it.  See ``_JOURNAL_MODE``.
Why beside the store rather than in it: the wallet's own schema
(``wallet_tokens``, ``wallet_ops``, owned by ``impl/aicash/wallet.py``)
must stay exactly what the protocol defines — ``wallet_cli``, a newer
build, and the reference tests all open that file — and the recipient of
a payment is not a protocol concept at all.  It is something the GUI
knows and the wallet cannot: the wallet hands over bearer strings and has
no opinion about who is supposed to take them.  A GUI-owned fact belongs
in a GUI-owned file, named so that a human deleting it knows what they
are deleting (a record, not value) and so that a wallet moved without it
degrades to "not recorded" rather than to a wrong answer.

Neither file is ever created by a READ, and no directory is ever created
at all: if the parent directory of ``store_path`` does not exist the call
fails with a clear error rather than materialising a tree somewhere on
the filesystem.  A missing, unreadable or corrupt record file is not an
error — it is the answer "nothing was recorded", which reads as
``unknown`` everywhere it surfaces.  It never fails an operation: the
money path does not depend on it.

MONEY STRANDED BY A FAILED DELIVERY (a durability claim, examined)
------------------------------------------------------------------
``pay()`` returns bearer token strings.  The GUI shows them in a result
panel and says they are "the only copy" — so a reload, a closed tab or a
stray navigation would destroy real value.  For a PAYMENT that sentence is
false — the wallet file already holds every one of those strings — and
this module is where it is disproved rather than patched over.  Three
things it does NOT do, stated plainly because the claim is about money:

* it does not print anything itself.  What the SCREEN says is
  ``gui/page.html``'s, and that file is not this module's to change; a
  claim here about what it currently prints is a claim about a file this
  module does not own and cannot keep true.  (As this was written it
  calls ``GET /api/wallet/outstanding`` on every pay result and prints
  "These are not the only copy" — but the sentence that matters is the
  one below, which does not depend on that: the read-back exists, it is
  reachable from Python and from the HTTP API, and whether a given
  screen uses it is that screen's business.)
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

The deliberate decision, therefore: **this layer persists NO SECOND COPY
OF THE MONEY.**  A sidecar of payment strings would be a second complete
copy of live bearer money on disk — a larger blast radius, a second thing
to leak, back up by accident, or leave behind — bought for a durability
property the store already has.  A read-back costs nothing and is
strictly safer.  That decision is unchanged by the payment record added
beside the store: it carries an op_id and amounts, never a secret, and
``unredeemed_payments()`` still reconstructs the strings from the wallet
file itself.  The record says WHERE A PAYMENT WAS MEANT TO GO and WHAT
BECAME OF IT; the money it describes never leaves the store.

What the read-back cannot do alone is tell a payment that was
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
* Whether the payee actually redeemed a payment is not knowable locally;
  a refusal appears only as a separate later ``refused`` op.  Nor is a
  payment output's store row terminal: ``handed_over`` becomes
  ``spent_out`` the moment this wallet pastes a copy back and the mint
  declines to credit it, and ``Wallet.recover()`` settles a pay op the
  transport stranded by putting its outputs in the SPENDABLE pool
  (``confirmed``) -- strings ``pay()`` never returned to anybody.
  ``unredeemed_payments()`` is where those two are untangled; a state
  filter over these rows is not, and was the round-6 defect.
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
``pay()``      -> ``{"tokens": [str], "amount_mc": int, "burn_mc": int,
                  "change_mc": int, "op_id": str, "recipient": str,
                  "recipient_kind": str, "delivery": str,
                  "delivery_cause": str, "delivery_attempt": str,
                  "delivery_detail": str}``.
                  The last seven are the payment record, returned as well
                  as written: ``delivery`` is from DELIVERY_OUTCOMES,
                  ``delivery_attempt`` from DELIVERY_ATTEMPTS,
                  ``delivery_cause`` is "" when nothing was observed and
                  otherwise one of CAUSES (an ``unknown`` delivery that
                  was attempted and got no answer carries
                  ``mint_unreachable``), and ``op_id`` is "" only when the
                  wallet told this module nothing to key a record by.
``recover()``  -> ``Wallet.recover``'s counters, passed through unchanged.
                  Answers THE IN-FLIGHT QUESTION and not the other one —
                  see "two questions" above.
``unredeemed_payments()`` (``outstanding_payments()`` is the old name)
               -> ``{"checked": bool, "mint_id": str,
                  "handed_over_mc": int, "unspent_mc": int,
                  "spent_mc": int, "unstated_mc": int,
                  "unchecked_mc": int, "unaccounted_mc": int,
                  "unredeemed_mc": int|None, "payments":
                  [{"op_id": str, "amount_mc": int, "live_mc": int|None,
                  "retired_mc": int, "unaccounted_mc": int,
                  "recipient": str, "recipient_kind": str,
                  "delivery": str, "delivery_cause": str,
                  "delivery_attempt": str,
                  "tokens": [{"token": str, "amount_mc": int, "key": str,
                  "state": "unspent"|"spent"|"unknown"|None,
                  "store_state": str}]}]}``,
                  newest first.  ``amount_mc`` is what that payment handed
                  over — fixed when it committed, identical to the figure
                  ``history()`` prints for the same op_id, and it never
                  moves again.  The TOTALS are over the payments listed
                  and they add up::

                      handed_over_mc == unspent_mc + spent_mc
                                        + unstated_mc + unchecked_mc
                                        + unaccounted_mc

                  ``unaccounted_mc`` is the named residual — handed-over
                  value this module could put in none of the four boxes.
                  It is 0 on every path; it is a field rather than an
                  assumption so that a scan which ever drops value shows a
                  gap instead of a smaller total.  ``unredeemed_mc`` is
                  ``unspent_mc`` when every string in the report carries
                  the mint's own word and ``None`` otherwise.  The five
                  record fields are read from the
                  payment record beside the store and are ``""`` /
                  ``"unknown"`` for a payment nothing was recorded for.
                  FIVE keys per token, ``key`` and ``store_state``
                  included.  ``store_state`` is from STORE_STATES and is
                  THIS WALLET's word about the string (``handed_over`` /
                  ``spent_out`` / ``confirmed``), never the mint's;
                  ``retired_mc`` sums the ``spent_out`` ones, which is the
                  part of a payment this wallet knows is dead WITHOUT
                  asking the mint.  ``key``:
                  it is the ledger key (a hash, not a secret), it is what
                  identifies a row whose ``token`` could not be rendered,
                  and it is what was sent to ``/v3/status``.  The HTTP
                  route in ``gui/app.py`` drops it, and ``store_state``
                  with it — a browser has no use for either — so the wire
                  shape there is the three-key one; a Python caller gets
                  five.  ``state`` is ``None`` when
                  the mint could not be asked.  ``live_mc`` is an int only
                  when EVERY string in that payment carries ``unspent`` or
                  ``spent``; it is ``None`` whenever any is ``unknown``
                  (the mint answered and has no ledger entry for it) or
                  ``None``, because there is then no total that is not
                  part guess.
                  ``checked`` is True when every token listed
                  carries the mint's own word for it, which is vacuously
                  the case when there are no payments: it answers "is
                  this report verified", not "is the mint up" —
                  ``summary()["connected"]`` is the field for that.
                  THESE ARE LIVE BEARER STRINGS: the only method here
                  that returns secrets, and it exists so a browser tab is
                  not the only place a payment survives.
``history()``  -> ``[{"ts_ms": TS_UNKNOWN, "op_id": str, "kind": str,
                  "amount_mc": int, "detail": str, "cause": str,
                  "recipient": str, "recipient_kind": str,
                  "delivery": str, "delivery_cause": str,
                  "delivery_attempt": str}]``, newest
                  first.  The five record fields are ``""`` on every row
                  that is not a COMMITTED payment (nothing was delivered,
                  so there is no outcome to state); on one that is, they
                  are what the payment record holds, and ``unknown``
                  whenever no record was written.  ``ts_ms`` is ALWAYS
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
                  ``cause`` and ``delivery_cause`` are disjoint by
                  construction and never both set: ``cause`` explains an
                  op that did NOT commit (no money moved), while
                  ``delivery_cause`` explains a delivery of money that
                  DID move.
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

__all__ = ["CAUSES", "DELIVERY_ATTEMPTS", "DELIVERY_OUTCOMES",
           "RECIPIENT_KINDS", "TS_UNKNOWN", "WalletOps", "WalletOpsError"]


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
# the payment record (see "WHAT A PAYMENT RECORD CARRIES" above)
# ---------------------------------------------------------------------------

#: THE closed set of delivery outcomes.  ``unknown`` is a real member: it
#: is what an interrupted delivery leaves behind, and it renders as
#: unknown rather than as the likelier-sounding story.
DELIVERY_OUTCOMES = ("delivered", "undelivered", "unknown")

#: What a recipient field means.  ``""`` is the fourth state and means
#: NOTHING WAS RECORDED, which is not the same as "no recipient".
RECIPIENT_KINDS = ("wallet", "bearer")

#: DID THIS WALLET EVER TRY?  A separate, narrower question from
#: ``delivery``, and the one that splits the four situations that used to
#: be byte-identical inside ``unknown``::
#:
#:     recipient_kind  delivery  delivery_attempt  delivery_cause
#:     bearer          unknown   not_attempted     ""     strings handed
#:                                                        to the caller
#:     wallet          unknown   not_attempted     ""     named, but no
#:                                                        deliver= given
#:     wallet          unknown   attempted         ""     started and
#:                                                        never answered
#:                                                        (killed, ^C)
#:     wallet          unknown   attempted         mint_unreachable
#:                                                        tried, nobody
#:                                                        answered
#:
#: "Never sent" and "sent and lost" send an operator to different
#: components, so they are different rows in machine-readable fields and
#: not merely different free text.  ``""`` is the fourth value and means
#: NOTHING WAS RECORDED, exactly as it does for ``recipient_kind``.
DELIVERY_ATTEMPTS = ("not_attempted", "attempted")

#: WHAT BECAME OF THE VALUE A RECIPIENT REFUSED — decided per cause, never
#: asserted across all of them.  The record used to say "the refused value
#: is still this wallet's money" for EVERY undelivered cause, which is
#: false for the one that matters most: ``already_spent`` means somebody
#: else redeemed those strings, and a row claiming otherwise sends its
#: reader hunting money another party has spent.  Three answers, because
#: there are three situations:
#:
#: * GONE — the mint answered that the strings were already spent.  The
#:   value is not this wallet's and never will be again.
#: * LIVE — the refusal consumed nothing: the mint was down or not
#:   running (nothing was submitted), the mint answered and refused the
#:   exchange (§3.8 rejections are atomic and consume no input), the
#:   recipient is bound to another mint, or the string never parsed.  The
#:   value was still this wallet's AT THE MOMENT THIS WAS WRITTEN — the
#:   note says that, and points at the live read-back for now.
#: * neither — the refusal established nothing either way, so the record
#:   says so rather than picking the friendlier half.
_REFUSED_VALUE_GONE = ("already_spent",)
_REFUSED_VALUE_LIVE = ("mint_stopped", "mint_rejected", "wrong_mint",
                       "malformed_token", "insufficient_funds")

#: A quoted sentence from somebody else's component goes into a permanent
#: record with a bound on it.  Bounded HERE rather than by the
#: ``_SENTENCE_MAX`` trim at the end, because that trim cuts from the
#: RIGHT — it would drop the clause about whether the money still exists
#: and keep the other wallet's stack-shaped prose.
_QUOTED_MAX = 170

#: Causes under which a failed delivery leaves the outcome GENUINELY
#: undetermined.  ``mint_unreachable`` is the §5.1 case: the recipient's
#: wallet persisted its plan and sent an exchange that nothing answered,
#: so the tokens may or may not have been redeemed into it.  Calling that
#: "undelivered" would be a guess about somebody else's money.
_UNDETERMINED_DELIVERY = ("mint_unreachable", "unknown")

#: A recipient name is a label that ends up in a record and in sentences
#: shown to humans.  Bounded and free of control characters, so it cannot
#: smuggle a newline into a log line or 8 KB into a database row.
_RECIPIENT_MAX = 64

#: WHERE a payment record is written: a GUI-owned sqlite file beside the
#: store, never inside it.  ``impl/aicash/wallet.py`` owns the schema of
#: the store and this module does not add to it; the recipient of a
#: payment is not a protocol fact at all.
_JOURNAL_SUFFIX = ".payments.db"
_JOURNAL_TABLE = "walletops_payments"
_JOURNAL_DDL = (
    f"CREATE TABLE IF NOT EXISTS {_JOURNAL_TABLE} ("
    " op_id          TEXT PRIMARY KEY,"   # the wallet_ops row this describes
    " mint_id        TEXT NOT NULL,"
    " amount_mc      INTEGER NOT NULL,"   # what left as payment
    " burn_mc        INTEGER NOT NULL,"   # what the mint took
    " change_mc      INTEGER NOT NULL,"   # what came back
    " token_count    INTEGER NOT NULL,"   # how many strings to find again
    " recipient      TEXT NOT NULL,"      # "" when none was named
    " recipient_kind TEXT NOT NULL,"      # wallet | bearer
    " delivery       TEXT NOT NULL,"      # one of DELIVERY_OUTCOMES
    " delivery_cause TEXT NOT NULL,"      # "" or one of CAUSES
    " note           TEXT NOT NULL,"      # the sentence, as recorded
    " delivery_attempt TEXT NOT NULL DEFAULT '')"  # DELIVERY_ATTEMPTS
)

#: Columns added after the table first shipped.  A record file written by
#: an earlier build has the table already, so ``CREATE TABLE IF NOT
#: EXISTS`` does nothing to it and an INSERT naming a new column would
#: fail — silently, because every write here is best effort, which would
#: turn "we added a field" into "this wallet records nothing any more".
#: Each is added with a DEFAULT so the existing rows read as "not
#: recorded" rather than as a value nobody wrote.
_JOURNAL_ADDED = (
    (f"ALTER TABLE {_JOURNAL_TABLE} ADD COLUMN delivery_attempt"
     " TEXT NOT NULL DEFAULT ''"),
)

#: The record is named after the store and sits in the same directory, so
#: it inherits that directory's exposure and nothing else: it is created
#: 0600 like the store, not at whatever the ambient umask happens to be.
#: It carries no secret — no token string, no key — but it does carry the
#: wallet's whole payment graph: every recipient name, every amount, every
#: op_id.  "It holds no money" is not the same claim as "it is fine for
#: anyone on this machine to read", and only the first was ever true.
_JOURNAL_MODE = 0o600

#: The five record fields as they read when there is NO record: not a
#: recipient, not a delivery anybody watched, and said in those words.
_NO_RECORD = {
    "recipient": "",
    "recipient_kind": "",
    "delivery": "unknown",
    "delivery_cause": "",
    "delivery_attempt": "",
    "note": "no delivery record was written for this payment, so where it"
            " went is not known here",
}

#: The same five fields for a row where the question does not arise: an
#: operation that moved no money has no delivery to have an outcome.
_NO_DELIVERY = {"recipient": "", "recipient_kind": "", "delivery": "",
                "delivery_cause": "", "delivery_attempt": "", "note": ""}

#: What a payment's record says before anything has been delivered.  Each
#: is a complete sentence about a KNOWN situation — "bearer strings were
#: handed to the caller" is not the same claim as "nobody watched", and
#: neither is dressed up as delivery.
_DELIVERY_NOTE = {
    "bearer": "paid out as bearer strings with no recipient named; where"
              " they went after that is not knowable from this wallet",
    "named": "meant for {recipient}, but this wallet was not asked to"
             " deliver it, so whether it arrived is not knowable here",
    "pending": "meant for {recipient}; the delivery had been started and"
               " not yet answered when this was written",
}


def _as_mc(value):
    """An int amount out of a component result, or None when it is not one."""
    if type(value) is int:
        return value
    return None


def _clean_delivery(value) -> str:
    """Coerce into DELIVERY_OUTCOMES.  Anything unrecognised is unknown."""
    text = str(value or "").strip()
    return text if text in DELIVERY_OUTCOMES else "unknown"


def _outcome_for(cause: str) -> str:
    """Delivery outcome implied by the cause a delivery failed with.

    The one judgement call in the payment record, and it is made in the
    direction of claiming less: a cause that means "something answered"
    supports ``undelivered``, and the two causes that mean "nobody
    answered" support nothing stronger than ``unknown``.  See
    ``_UNDETERMINED_DELIVERY``.
    """
    return "unknown" if _clean_cause(cause) in _UNDETERMINED_DELIVERY \
        else "undelivered"


#: What a payment output's own row in the wallet store may say about it.
#: The STORE's word, never the mint's -- see ``unredeemed_payments()``.
#: ``handed_over`` it left and nothing local contradicts that;
#: ``spent_out`` this wallet has RETIRED its copy -- ``_mark_dead_if_ours``
#: fires when the mint consumed the string AND when the mint answered
#: ``unknown`` ("no entry on the ledger I am keeping"), so it means "this
#: wallet will not offer this again", never "this value is dead";
#: ``confirmed`` ``Wallet.recover()`` settled a stranded pay op and put
#: the output back in the spendable pool -- strings ``pay()`` never
#: returned, so that payment handed nothing over and is reported under
#: ``recovered_mc`` rather than as money somebody else is holding.  A
#: state this build does not know reads ``""`` -- unrecognised, not
#: reinterpreted.
STORE_STATES = ("handed_over", "spent_out", "confirmed", "pending", "orphan")


def _clean_store_state(value) -> str:
    """Coerce into STORE_STATES.  Anything else is ``""`` (unrecognised)."""
    text = str(value or "").strip()
    return text if text in STORE_STATES else ""


def _clean_attempt(value) -> str:
    """Coerce into DELIVERY_ATTEMPTS.  Anything else is ``""`` — which
    means NOTHING WAS RECORDED, not "it was not attempted"."""
    text = str(value or "").strip()
    return text if text in DELIVERY_ATTEMPTS else ""


def _refused_value_clause(cause: str) -> str:
    """What is honestly sayable about value a recipient refused.

    Conditional on the cause, and never on the general shape "a delivery
    failed".  See ``_REFUSED_VALUE_GONE`` / ``_REFUSED_VALUE_LIVE`` for
    why each cause lands where it does.  The LIVE sentence is explicitly
    dated ("when this was recorded"), because the record is permanent and
    a third party can redeem a handed-over string a second after it is
    written: the row states what was true then and names the call that
    answers for now.
    """
    cause = _clean_cause(cause)
    if cause in _REFUSED_VALUE_GONE:
        return ("those strings had ALREADY BEEN REDEEMED, so that value is"
                " not this wallet's money and cannot be paid again")
    if cause in _REFUSED_VALUE_LIVE:
        return ("nothing consumed those strings, so the refused value was"
                " still this wallet's money when this was recorded")
    return ("whether the refused value is still this wallet's money was"
            " not established")


def _quoted(text) -> str:
    """Somebody else's sentence, bounded, with no bearer string in it."""
    out = " ".join(_no_secrets(text).split())
    return out if len(out) <= _QUOTED_MAX else out[:_QUOTED_MAX - 1] + "\u2026"


def _note_with_quote(head: str, said) -> str:
    """``head``, then as much of ``said`` as fits inside _SENTENCE_MAX.

    The head carries the money: whether the refused value still exists,
    and the op_id that finds it again.  Writing the two together and
    letting the trim at the end of ``settle`` cut from the RIGHT would
    drop exactly that and keep the other component's prose — and would
    also leave the caller holding a 500-character sentence while the
    permanent record held a clipped one.  So the budget is spent here,
    once, and the record and the returned ``delivery_detail`` are the
    same sentence.
    """
    head = " ".join(str(head).split())[:_SENTENCE_MAX]
    said = _quoted(said)
    room = _SENTENCE_MAX - len(head) - len(" It said: ")
    if not said or room < 12:
        return head
    if len(said) > room:
        said = said[:room - 1] + "\u2026"
    return f"{head} It said: {said}"


def _no_secrets(text) -> str:
    """A sentence with any token string in it replaced by a description.

    A delivery note quotes whatever the recipient's wallet said went
    wrong, and that sentence is written to a file and shown in history.
    Nothing this module records may contain a live bearer string, so the
    one shape that could carry one is removed here rather than trusted not
    to appear.
    """
    out = str(text or "")
    while "aicash:" in out:
        start = out.index("aicash:")
        end = start
        while end < len(out) and not out[end].isspace():
            end += 1
        out = out[:start] + "<a token string, not recorded>" + out[end:]
    return out


def _journal_path(store_path: str) -> str:
    """``var/wallets/<name>.db`` -> ``var/wallets/<name>.payments.db``.

    Derived, never configured: the record must be found by anything that
    can find the store, including a later process that was handed only the
    store path.  A wallet name cannot contain a dot (``gui/app.py`` pins
    the alphabet), so this name can never collide with a wallet's own.
    """
    base = str(store_path)
    if base.lower().endswith(".db"):
        base = base[:-3]
    return base + _JOURNAL_SUFFIX


class _PaymentJournal:
    """The GUI-owned record of what became of each payment.

    Separate from the wallet store on purpose (see the module docstring):
    the store is the money and its schema belongs to the protocol; this is
    a record ABOUT money, holds no secret, and is the GUI's to shape.

    Every WRITE is best effort in the strict sense — the money path never
    depends on it, and a failure to record leaves the row reading
    ``unknown``, which is exactly what is then true.  Every READ degrades
    to "nothing recorded" for the same reason: a missing file is a wallet
    that was paid from by an older build or another tool, and a wallet
    that cannot say where a payment went must say so rather than guess.
    """

    def __init__(self, store_path: str) -> None:
        self.path = _journal_path(store_path)

    # -- writes ---------------------------------------------------------

    def begin(self, record: dict) -> None:
        """Record the payment BEFORE its delivery is attempted.

        The ordering is the whole point.  Written here the row exists in
        state ``unknown`` from the instant the money leaves; settled after
        the attempt it becomes ``delivered`` or ``undelivered``.  A GUI
        that dies in between therefore leaves ``unknown`` on disk, which
        is the truth — the recipient may or may not have been credited —
        rather than a confident answer nobody checked.

        INSERT OR REPLACE, not OR IGNORE: an op_id is a fresh uuid4 per
        operation, so there is nothing to overwrite; if a store somehow
        reuses one, the newer payment is the one being described.
        """
        if not record.get("op_id"):
            return                      # nothing to key it by; stays unknown
        self._write(
            f"INSERT OR REPLACE INTO {_JOURNAL_TABLE}"
            " (op_id, mint_id, amount_mc, burn_mc, change_mc, token_count,"
            "  recipient, recipient_kind, delivery, delivery_cause, note,"
            "  delivery_attempt)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (str(record["op_id"]), str(record.get("mint_id", "")),
             int(record.get("amount_mc", 0)), int(record.get("burn_mc", 0)),
             int(record.get("change_mc", 0)),
             int(record.get("token_count", 0)),
             str(record.get("recipient", "")),
             str(record.get("recipient_kind", "")),
             _clean_delivery(record.get("delivery")),
             _clean_cause(record.get("delivery_cause"))
             if record.get("delivery_cause") else "",
             _no_secrets(record.get("note", ""))[:_SENTENCE_MAX],
             _clean_attempt(record.get("delivery_attempt"))),
        )

    def settle(self, op_id: str, delivery: str, cause: str, note,
               recipient: str = "", recipient_kind: str = "") -> bool:
        """Write down what a delivery attempt actually showed.  ONCE.

        ``WHERE ... AND delivery = 'unknown'`` is not an optimisation: a
        settled outcome is NEVER rewritten.  The row is the permanent
        record an operator debugs from, a second observer's later opinion
        about the same op is a different observation, and "delivered" that
        can be overwritten by a later "undelivered" is exactly the screen
        that is right only sometimes.  A row nobody settled keeps the
        ``unknown`` ``begin`` gave it.

        ``recipient`` is filled in only where NOTHING was named — the
        bearer case, where this GUI later watched the strings credited to
        a wallet it knows the name of.  It never overwrites a name that
        was recorded at payment time.

        Returns whether a row was actually updated, so a caller can say
        "recorded" or "there was no record to settle" instead of guessing.
        """
        if not op_id:
            return False
        return self._write(
            f"UPDATE {_JOURNAL_TABLE} SET delivery = ?, delivery_cause = ?,"
            " note = ?, delivery_attempt = 'attempted',"
            " recipient = CASE WHEN recipient = '' THEN ? ELSE recipient END,"
            " recipient_kind = CASE WHEN recipient = ''"
            "                      THEN ? ELSE recipient_kind END"
            " WHERE op_id = ? AND delivery = 'unknown'",
            (_clean_delivery(delivery),
             _clean_cause(cause) if cause else "",
             _no_secrets(note)[:_SENTENCE_MAX],
             str(recipient or ""),
             str(recipient_kind or "") if recipient else "",
             str(op_id)),
        )

    def _write(self, sql: str, params: tuple) -> bool:
        """Run one statement, creating and migrating the file if needed.

        Returns whether it changed a row.  Best effort throughout: a
        failure here leaves the record reading ``unknown``, which is then
        exactly what is known, and never disturbs the money path.
        """
        conn = None
        try:
            fresh = not os.path.exists(self.path)
            conn = sqlite3.connect(self.path, isolation_level=None,
                                   timeout=10.0)
            # BEFORE anything is written into it. sqlite3.connect creates
            # the file under the ambient umask, which on a default 022 is
            # 0644 -- world-readable, beside a store the protocol layer
            # took care to make 0600, and holding every recipient name and
            # amount this wallet ever paid. chmod unconditionally rather
            # than only when fresh, so a file an earlier build already
            # created wrong is repaired the next time it is written.
            try:
                os.chmod(self.path, _JOURNAL_MODE)
            except OSError:
                pass                    # a filesystem with no modes; the
                                        # write below still stands or fails
                                        # on its own merits
            conn.execute(_JOURNAL_DDL)
            if not fresh:
                for statement in _JOURNAL_ADDED:
                    try:
                        conn.execute(statement)
                    except sqlite3.Error:
                        pass            # already there: the normal case
            return bool(conn.execute(sql, params).rowcount)
        except Exception:               # noqa: BLE001 - see class docstring
            return False
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:       # noqa: BLE001
                    pass

    # -- reads ----------------------------------------------------------

    def records(self, op_ids: list) -> dict:
        """{op_id: record dict} for the ops asked about.  Never creates.

        READ-ONLY (``mode=ro``), so a history poll cannot bring the file
        into existence and cannot touch a byte of it.  An absent or
        unreadable record file yields ``{}`` and every row it would have
        covered reads ``unknown``.
        """
        if not op_ids or not os.path.exists(self.path):
            return {}
        out: dict = {}
        conn = None
        try:
            uri = "file:" + urllib.request.pathname2url(self.path) + "?mode=ro"
            conn = sqlite3.connect(uri, uri=True, timeout=10.0)
            cols = ("op_id, mint_id, amount_mc, burn_mc, change_mc,"
                    " token_count, recipient, recipient_kind, delivery,"
                    " delivery_cause, note")
            # Asked for, and dropped only if this file predates it. NOT
            # probed with a PRAGMA first: history() is polled and its
            # query count is bounded on purpose, so the ordinary path must
            # not pay a round trip to discover a column that is there.
            extra = ", delivery_attempt"
            for start in range(0, len(op_ids), _SQL_CHUNK):
                chunk = op_ids[start:start + _SQL_CHUNK]
                marks = ",".join("?" * len(chunk))
                sql = (f"SELECT {cols}{extra} FROM {_JOURNAL_TABLE}"
                       f" WHERE op_id IN ({marks})")
                try:
                    rows = conn.execute(sql, tuple(chunk)).fetchall()
                except sqlite3.OperationalError:
                    extra = ""
                    rows = conn.execute(
                        f"SELECT {cols} FROM {_JOURNAL_TABLE}"
                        f" WHERE op_id IN ({marks})", tuple(chunk)).fetchall()
                for row in rows:
                    out[str(row[0])] = {
                        "op_id": str(row[0]), "mint_id": str(row[1]),
                        "amount_mc": int(row[2] or 0),
                        "burn_mc": int(row[3] or 0),
                        "change_mc": int(row[4] or 0),
                        "token_count": int(row[5] or 0),
                        "recipient": str(row[6] or ""),
                        "recipient_kind": str(row[7] or ""),
                        "delivery": _clean_delivery(row[8]),
                        "delivery_cause": (_clean_cause(row[9])
                                           if row[9] else ""),
                        "note": str(row[10] or ""),
                        # A file written before this column existed is
                        # read here, not refused: the field reads "" --
                        # nothing recorded -- and every other fact in the
                        # row survives. A SELECT naming a missing column
                        # raises, and every row in the file would then
                        # read "unknown".
                        "delivery_attempt": (_clean_attempt(row[11])
                                             if len(row) > 11 else ""),
                    }
        except Exception:               # noqa: BLE001 - see class docstring
            return out
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:       # noqa: BLE001
                    pass
        return out


def _recipient(to, where: str) -> tuple[str, str]:
    """(recipient, recipient_kind) for a ``to=`` argument.

    ``None`` is not "unknown" here — it is the operator asking for bearer
    strings, which is a thing that HAPPENED and is recorded as such.  The
    empty ``recipient_kind`` is reserved for a payment nothing was
    recorded about at all, and only a reader can produce that.
    """
    if to is None:
        return "", "bearer"
    if not isinstance(to, str) or not to.strip():
        raise WalletOpsError(
            "bad request",
            f"{where}: to= must be a non-empty recipient name or None for"
            f" bearer strings, got {type(to).__name__}; nothing was sent to"
            f" the mint",
            "unknown",
        )
    name = to.strip()
    if len(name) > _RECIPIENT_MAX or any(ch < " " or ch == "\x7f"
                                         for ch in name):
        raise WalletOpsError(
            "bad request",
            f"{where}: a recipient name is at most {_RECIPIENT_MAX}"
            f" characters and cannot contain control characters; nothing"
            f" was sent to the mint",
            "unknown",
        )
    return name, "wallet"


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

#: WHERE a failure's cause is written down.  In the wallet store itself,
#: beside wallet_ops, keyed by the same op_id, and never read or written
#: by aicash.wallet: a wallet opened by any other tool ignores it, and
#: this module treats its absence as "no cause was recorded", which is
#: exactly what it means.  It stays here rather than moving out to the
#: payment record beside the store because it is keyed to, and only
#: meaningful with, a wallet_ops row: a cause without its op is not a
#: fact about anything.  The two records are disjoint by construction —
#: this one covers ops that did NOT commit, the payment record covers
#: payments that DID — so no operation is ever described by both.
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
        #: The GUI-owned record of what became of each payment, beside the
        #: store.  Constructing it opens nothing and creates nothing.
        self._journal = _PaymentJournal(self._store_path)

    # -- paths ----------------------------------------------------------

    @property
    def store_path(self) -> str:
        return self._store_path

    @property
    def record_path(self) -> str:
        """The payment record beside the store.  May not exist yet."""
        return self._journal.path

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

    def pay(self, amount_mc: int, *, to=None, deliver=None) -> dict:
        """Produce bearer token strings totalling ``amount_mc``, and RECORD
        where they were meant to go and what became of them.

        {"tokens", "amount_mc", "burn_mc", "change_mc", "op_id",
        "recipient", "recipient_kind", "delivery", "delivery_cause",
        "delivery_detail"}.  ``burn_mc`` is measured, not predicted: it is
        the drop in held balance minus the amount paid, which is precisely
        what the mint burned on this exchange.

        ``to`` is the INTENDED RECIPIENT as a name — a GUI concept the
        wallet itself has no room for, which is why it is recorded beside
        the store rather than in it.  ``None`` means bearer strings: the
        caller is taking them away and this wallet will never know who got
        them.  Both are recorded; neither is inferred.

        ``deliver`` is an optional ``callable(list[str]) -> dict`` that
        hands the strings to the recipient — in this GUI, the recipient
        wallet's own ``receive()``.  Supplying it is what lets this module
        WATCH the delivery and therefore record its outcome; without it
        the payment is recorded as ``unknown`` forever, because from here
        it genuinely is.

        THE ORDERING IS THE CONTRACT.  The record is written, committed
        and only then is the delivery attempted:

        * kill the process in between and the row says ``unknown`` — true,
          because the recipient may or may not have been credited;
        * a delivery that comes back refused records ``undelivered`` with
          the cause the recipient's wallet gave, unchanged;
        * a delivery that comes back with nobody having answered records
          ``unknown``, never ``undelivered`` — see ``_outcome_for``.

        A failed delivery is not a failed payment and does not raise: the
        money left the wallet, the strings are in ``tokens`` and in the
        store, and the caller is told exactly what happened in
        ``delivery``.  The one exception is a BaseException out of
        ``deliver`` (an interrupt, a SystemExit): that is not an outcome
        this module observed, so it propagates and the row keeps the
        ``unknown`` it was written with.
        """
        amount_mc = _amount(amount_mc, "pay")
        recipient, kind = _recipient(to, "pay")
        if deliver is not None and not callable(deliver):
            raise WalletOpsError(
                "bad request",
                f"pay: deliver= must be callable(list[str]), got"
                f" {type(deliver).__name__}; nothing was sent to the mint",
                "unknown",
            )
        if deliver is not None and kind == "bearer":
            # Delivering somewhere this module cannot NAME would record
            # "delivered" against a payment whose row could never tell an
            # operator where it went — a confident field over a blank one,
            # which is the shape of defect this record exists to remove.
            raise WalletOpsError(
                "bad request",
                "pay: deliver= needs to= — a delivery with no recipient"
                " name would be recorded as delivered to nobody in"
                " particular; nothing was sent to the mint",
                "unknown",
            )
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
                # it" are the same row.  Nothing is written to the payment
                # record: no money moved, so there is no payment to record.
                self._settle_cause(exc.cause, exc.detail, "pay")
                raise
            # Committed: every op this call planned is `done`, so there is
            # nothing to explain — just stop watching.
            planned = self._planned or []
            self._planned = None
            after = self._balance(wallet, "pay")
            burn_mc = max(0, (before - after) - amount_mc)
            facts = self._payment_facts(wallet, planned)
            op_id = facts["op_id"]
            note = _DELIVERY_NOTE["bearer" if kind == "bearer" else
                                  ("named" if deliver is None else "pending")]
            if kind != "bearer":
                note = note.format(recipient=recipient)
            # DID THIS WALLET EVER TRY?  Written NOW, with the record,
            # because after this line nothing can reconstruct it: a
            # process killed inside deliver() and a process that was never
            # given a deliver() both leave a row reading "unknown", and
            # they send an operator to different components.
            attempt = "attempted" if deliver is not None else "not_attempted"
            self._journal.begin({
                "op_id": op_id, "mint_id": live,
                "amount_mc": facts["paid_mc"] or amount_mc,
                "burn_mc": facts["burn_mc"] if facts["burn_mc"] is not None
                else burn_mc,
                "change_mc": facts["change_mc"],
                "token_count": facts["token_count"] or len(tokens),
                "recipient": recipient, "recipient_kind": kind,
                "delivery": "unknown", "delivery_cause": "", "note": note,
                "delivery_attempt": attempt,
            })
            result = {
                "tokens": list(tokens),
                "amount_mc": amount_mc,
                "burn_mc": burn_mc,
                "change_mc": facts["change_mc"],
                "op_id": op_id,
                "recipient": recipient,
                "recipient_kind": kind,
                "delivery": "unknown",
                "delivery_cause": "",
                "delivery_attempt": attempt,
                "delivery_detail": note,
            }
            if deliver is None:
                return result
            delivery, cause, note = self._deliver(
                tokens, deliver, recipient, op_id)
            self._journal.settle(op_id, delivery, cause, note)
            result.update(delivery=delivery, delivery_cause=cause,
                          delivery_detail=note)
            return result

    def _payment_facts(self, wallet, op_ids: list) -> dict:
        """The arithmetic of the payment this call just committed.

        Which op: the one whose outputs carry role ``payment`` — the same
        op ``unredeemed_payments()`` groups by and the same op_id history
        keys on, so the three views of one payment cannot drift apart.
        The burn is reconstructed the way ``history()`` reconstructs it
        (§3.3 conservation: inputs less outputs), which makes the recorded
        figure the mint's own arithmetic rather than a second estimate.

        Best effort: a store that will not answer leaves ``op_id`` empty,
        no record is written, and the payment reads ``unknown`` — which is
        then exactly what is known about it.
        """
        blank = {"op_id": "", "paid_mc": 0, "change_mc": 0, "burn_mc": None,
                 "token_count": 0}
        if not op_ids:
            return blank
        try:
            marks = ",".join("?" * len(op_ids))
            rows = wallet._db.execute(
                "SELECT t.op_id, t.role, COUNT(*), COALESCE(SUM(t.amount_mc),"
                f" 0) FROM wallet_tokens t WHERE t.op_id IN ({marks})"
                " GROUP BY t.op_id, t.role",
                tuple(op_ids),
            ).fetchall()
            found = blank
            for op_id, role, count, total in rows:
                if str(role) != "payment":
                    continue
                if found["op_id"] and found["op_id"] != op_id:
                    continue        # one pay() plans one payment op
                found = dict(found, op_id=str(op_id),
                             paid_mc=int(total or 0),
                             token_count=int(count or 0))
            if not found["op_id"]:
                return blank
            for op_id, role, _count, total in rows:
                if str(op_id) == found["op_id"] and str(role) == "change":
                    found["change_mc"] = int(total or 0)
            plan = wallet._db.execute(
                "SELECT request_json FROM wallet_ops WHERE op_id = ?",
                (found["op_id"],)).fetchone()
            outputs = sum(int(t or 0) for o, _r, _c, t in rows
                          if str(o) == found["op_id"])
            face_in, unparsed = 0, 0
            for token in _plan_inputs(plan[0] if plan else None):
                try:
                    face_in += parse_token(token).amount_mc
                except TokenError:
                    unparsed += 1
            if not unparsed and face_in >= outputs:
                found["burn_mc"] = face_in - outputs
            return found
        except Exception:               # noqa: BLE001 - a record is not the
            return blank                # money path; see _PaymentJournal

    def _deliver(self, tokens, deliver, recipient: str,
                 op_id: str) -> tuple[str, str, str]:
        """Hand the strings over and say what is now KNOWN about them.

        Returns (delivery, delivery_cause, note) and NEVER raises for a
        delivery that failed — a refused delivery is a fact to record, not
        an error to throw over a payment that already committed.

        The shapes it distinguishes:

        * the recipient took everything            -> delivered
        * the recipient answered, refusing         -> undelivered, with
          its own cause; or, when the cause means nobody answered at all
          (``mint_unreachable``), -> unknown WITH THAT CAUSE, because §5.1
          says the exchange may still have landed but "nobody answered"
          is still the most precise thing known about it
        * anything else — an exception that is not a WalletOpsError, a
          return value that is not a result -> unknown with cause
          ``unknown``: something was observed and it established nothing,
          which is a different row from the empty cause an interrupted
          delivery leaves (nothing was ever observed at all)

        BaseException is deliberately NOT caught.  An interrupt is not an
        observation; letting it through leaves the ``unknown`` the record
        was written with — and, because ``begin`` wrote
        ``delivery_attempt="attempted"``, an interrupted delivery is still
        distinguishable from one that was never tried.

        The classification itself lives in two module functions so that
        ``settle_delivery()`` — the same observation arriving from the
        recipient's side of this GUI — cannot describe it differently.
        """
        who = f"the recipient {recipient!r}" if recipient else "the recipient"
        try:
            result = deliver(list(tokens))
        except WalletOpsError as exc:
            return _delivery_from_error(exc, who, op_id)
        except Exception as exc:        # noqa: BLE001 - see docstring
            return "unknown", "unknown", _note_with_quote(
                f"delivery to {who} raised {type(exc).__name__} — whether the"
                f" payment was credited there is undetermined (op {op_id}).",
                exc)
        return _delivery_from_result(result, who, op_id)

    def settle_delivery(self, op_id: str, *, result=None, error=None,
                        recipient: str = "") -> dict:
        """Record an outcome THIS GUI watched from the recipient's side.

        The payer's ``pay(to=..., deliver=...)`` is not the only way this
        product delivers a payment: ``gui/app.py``'s POST
        /api/wallet/receive credits a wallet with strings someone pasted,
        and when the caller can say which payment they came from, that
        route has watched the very outcome the payer's record was left
        guessing at.  Dropping it left two ways to deliver one payment
        telling opposite kinds of truth — the recorded one and the blind
        one — so the observation is routed back here and classified by
        the SAME two functions ``_deliver`` uses.

        ``result`` is a ``receive()``-shaped dict; ``error`` is a
        ``WalletOpsError`` from one that raised.  Exactly one is expected;
        neither is a caller that observed nothing, and that records
        nothing.

        Writes ONCE, into a row still reading ``unknown``: a settled
        outcome is never rewritten (see ``_PaymentJournal.settle``).  The
        return value says what was concluded and whether a row took it::

            {"op_id", "recorded": bool, "delivery", "delivery_cause",
             "delivery_detail"}

        ``recorded`` False means there was no unsettled record for that
        op_id — an op this wallet never paid, a payment already settled,
        or no record file at all.  It is not an error and never raises
        over an outcome: the money moved either way.
        """
        op_id = str(op_id or "")
        name = str(recipient or "").strip()
        who = f"the recipient {name!r}" if name else "the recipient"
        if error is not None:
            delivery, cause, note = _delivery_from_error(error, who, op_id)
        elif result is not None:
            delivery, cause, note = _delivery_from_result(result, who, op_id)
        else:
            return {"op_id": op_id, "recorded": False, "delivery": "unknown",
                    "delivery_cause": "", "delivery_detail": (
                        "nothing was observed about this delivery, so"
                        " nothing was recorded about it")}
        with self._entered():
            recorded = self._journal.settle(
                op_id, delivery, cause, note,
                recipient=name, recipient_kind="wallet" if name else "")
        return {"op_id": op_id, "recorded": bool(recorded),
                "delivery": delivery, "delivery_cause": cause,
                "delivery_detail": note}

    def recover(self) -> dict:
        """THE IN-FLIGHT QUESTION: did an operation never get an answer?

        Resolves operations this wallet left in state ``planned`` — the
        plan hit the disk, the exchange went out, and nothing came back —
        by asking the ledger what actually happened to each (§5.1).
        Passes through ``Wallet.recover``'s summary counters unchanged.

        WHAT IT DOES NOT ANSWER, because the two were being confused:
        it says NOTHING about value this wallet successfully paid out and
        nobody has redeemed.  Those payments committed; there is no
        in-flight operation to settle, and ``recover()`` correctly reports
        nothing to do while the wallet holds hundreds of millicredits of
        handed-over strings.  ``unredeemed_payments()`` is the method for
        that question, and the two answering differently at the same
        instant is normal rather than a contradiction — see "two
        questions" in the module docstring.

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

    def unredeemed_payments(self, *, limit: int = 20) -> dict:
        """THE HANDED-OVER QUESTION: what has nobody redeemed yet?

        TWO DIFFERENT QUESTIONS, AND THE ONE THAT USED TO OVERWRITE THE
        OTHER.  "How much did this payment hand over" is a fact fixed at
        the instant the exchange committed and it never changes again.
        "How much of that is still unredeemed" changes every time somebody
        redeems a string.  This report answers BOTH, in separate fields,
        because a build that answered the second under the first's name
        made an earlier payment's amount shrink when a LATER, unrelated
        operation touched one of its strings::

            alice.pay(300)                     # three 100 mc strings
            bob.receive(two of them)           # the payee redeems two
            alice.receive(those same two)      # pasted back by mistake

        The last line rejects both strings (already spent) and, on the way
        through, ``Wallet._mark_dead_if_ours`` retires this wallet's own
        copies from ``handed_over`` to ``spent_out``.  A report that
        listed only ``handed_over`` rows then said this payment was 100 mc
        while ``history()`` -- reading the same table without the state
        filter -- still said 300 mc.  Same payment, same op_id, same
        instant, two amounts, and the one that moved was the one
        ``gui/README.md`` calls the permanent record of where the money
        went.  ``amount_mc`` here is that permanent figure, read the way
        ``history()`` reads it, so the two views cannot disagree.

        WHAT IS LISTED: payments that ACTUALLY HANDED STRINGS OVER --
        every ``wallet_ops`` row in state ``done`` whose role ``payment``
        outputs were returned by ``pay()`` -- with EVERY string that
        payment produced whatever the store now says about each one.
        Order is the ones the store still calls outstanding and then the
        ones it has retired in full, each half newest first; that is the
        window rule below, and it is reading order too.  Not only the unredeemed ones: a payment whose every
        string the mint calls ``spent`` is still here with ``live_mc: 0``,
        and so is one this wallet took back in through ``receive()``.

        AND WHAT IS DELIBERATELY NOT LISTED, because it is not handed-over
        money at all: a pay op the transport stranded and ``recover()``
        later settled.  ``WalletOps.pay()`` re-raises in that case without
        returning a single string and without writing a payment record --
        nobody outside this wallet file ever saw those secrets -- and
        ``Wallet.recover()`` then puts the outputs back in the SPENDABLE
        pool (``state='confirmed'``, impl/aicash/wallet.py).  They are in
        ``summary()["balance_mc"]``, and counting them here as well told
        an operator that 5,000 mc was in somebody else's hands AND in
        their own balance, against a mint whose signed supply snapshot
        only ever knew about one of them.  Their value is reported under
        its own name instead -- ``recovered_mc``, with ``recovered_ops``
        naming the op_ids, which is what lets a reader match the ``pay``
        rows ``history()`` prints for them against a report that hands
        over nothing.  TWO independent marks identify such an op and
        either is enough: this module's own cause row, written against the
        op at the instant ``pay()`` raised (``walletops_op_causes``), and
        a role ``payment`` output sitting in ``confirmed``, a state
        ``_resolve_success`` can never produce for a payment output.

        WHERE THAT IS IMPRECISE, stated rather than left to be found: the
        cause row is written by THIS module, so a pay stranded by some
        other tool driving the same wallet file leaves none.  While such
        an op's recovered coins are still in the pool the ``confirmed``
        mark still catches it; once they have been spent again every trace
        is gone and this reports the op as a payment that handed its value
        over.  The error is bounded to that: those outputs are then
        ``spent_out``, the mint calls them ``spent``, so they inflate the
        historical ``handed_over_mc`` and can never inflate
        ``unspent_mc``, ``unredeemed_mc`` or the reconciliation against
        the mint's supply.  The direction is deliberate -- exclusion
        requires positive evidence, because a total that hides money the
        wallet really did hand over is the worse failure and was the
        round-5 defect.

        THE DECOMPOSITION ADDS UP, AND SAYS SO, IN TWO STEPS.  Over the
        WHOLE wallet::

            handed_over_mc == listed_mc + unlisted_mc

        and over the payments actually LISTED::

            listed_mc == unspent_mc + spent_mc + unstated_mc
                         + unchecked_mc + unaccounted_mc

        ``handed_over_mc`` is the whole-life total: it is the value this
        wallet handed to other people, it is not windowed by ``limit``,
        and it never shrinks.  ``unaccounted_mc`` is the residual: value
        this module knows was handed over and could not put in any of the
        four boxes.  It is 0 in every path here, and it exists NAMED so
        that a future change which drops strings from the per-string scan
        shows up as a gap an operator can see rather than as a smaller
        total they cannot.  The same identity holds per payment, where the
        residual is that payment's ``unaccounted_mc``.

        ``limit`` WINDOWS THE LIST AND THE WINDOW IS DECLARED.  ``limit``
        is a number of PAYMENT OPERATIONS; ``payment_count`` is how many
        this wallet has, ``truncated`` says the list is short of that, and
        ``unlisted_mc`` is the handed-over value that did not fit.  An
        earlier build published the windowed total under the name
        ``handed_over_mc`` with no truncation marker at all, so a wallet
        that had paid 101 times answered "nothing unredeemed" over money
        the mint called unspent.  Two things stop that here.  First, the
        window is spent on money that can still be live: payments with at
        least one string still in ``handed_over`` are taken FIRST, newest
        first, and only then is the rest of the window filled with the
        newest payments the store has already retired in full -- a
        hundred dead payments can no longer push a live one out.  Second,
        ``unredeemed_mc`` is ``None`` -- never a confident 0 -- whenever
        outstanding value did not fit (``unlisted_outstanding_mc``).

        Retired value that did not fit cannot be unredeemed, and that is
        an argument rather than an assumption: every path that writes
        ``spent_out`` (``Wallet._mark_dead_if_ours``, and ``recover()``'s
        settlement) runs only after THIS mint has consumed the string or
        refused it, and no path anywhere returns a string from
        ``spent_out`` to ``handed_over``.

        PER-TOKEN THERE ARE TWO WORDS FOR TWO WITNESSES.  ``state`` is the
        MINT's, from §3.4 ``/v3/status``, and is ``None`` when the mint
        could not be asked.  ``store_state`` is THIS WALLET's own row --
        ``handed_over`` (it left, nothing local says otherwise) or
        ``spent_out`` (this wallet has RETIRED its copy).  They are kept
        apart because they fail differently: the mint's word is
        authoritative and unavailable when it is down, the store's word is
        always readable and only ever second-hand.

        ``retired_mc`` sums the ``spent_out`` ones, and it is a fact about
        THIS STORE, not a verdict on the money.  ``Wallet``'s retirement
        rule is "the mint would not credit this wallet with the string" --
        it fires when the mint consumed it AND when the mint answered
        ``unknown``, which means "no entry on the ledger I am keeping",
        not "consumed".  Point a wallet at a mint whose database has been
        replaced and its own strings are retired while remaining perfectly
        alive on the original ledger; the report says so in the same
        breath, because those strings then read ``state: "unknown"`` and
        land in ``unstated_mc`` with ``unredeemed_mc`` ``None``.  So:
        ``retired_mc`` is "this wallet will not offer these again", it is
        NOT "this value is dead", and it is deliberately outside the
        mint's four-way decomposition rather than a fifth box in it.

        WHAT IT DOES NOT ANSWER: whether any operation is in flight.  An
        op the mint never answered about is ``recover()``'s business, is
        not listed here, and a wallet can have four unredeemed payments
        and nothing whatever to recover at the same instant.  Both numbers
        are then correct; they are answers to different questions.  (The
        old name for this method was ``outstanding_payments()``, and
        "outstanding" is precisely the word that blurred the two.)

        THE ANSWER TO "the only copy is in a DOM node".  It is not: every
        payment output was written to this wallet file, secret included,
        before the exchange was sent (§5.1), and is still there.  This
        rebuilds the exact strings ``pay()`` returned, so a reload, a
        closed tab or a delivery that failed halfway does not destroy
        money -- see the module docstring for why no new file is written
        to achieve that.

        AND ``checked`` IS NOT "every state is known": it says the mint
        ANSWERED.  A payment read while a DIFFERENT mint answers on that
        address comes back checked with every string ``unknown``, so
        ``live_mc`` is ``None`` there rather than ``0`` -- 0 would be a
        confident claim about money this same report calls undetermined
        one field away.  ``unredeemed_mc`` obeys the same rule one level
        up: an int only when every string in the whole report carries the
        mint's own word AND no outstanding payment was left out of the
        window, ``None`` otherwise, with ``unspent_mc`` and the other
        three always present so a report that cannot give the total still
        says exactly what it does know.

        WHAT A RE-SERIALISING CALLER MUST CARRY.  ``gui/app.py`` rebuilds
        the four mint figures by summing the per-token states of the
        payments it forwards, which is the right rule for the payments it
        can see and is NOT the rule for a windowed report: a caller that
        totals the rows must publish ``truncated`` and
        ``unlisted_outstanding_mc`` beside them, or drop its own headline
        to ``None`` when they are set, exactly as this does.  The window
        is only ever short of the whole wallet when more payments than
        ``limit`` still have strings in ``handed_over``.

        It hands out live secrets -- the only method here that does -- so a
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
            scan = self._payment_rows(limit)
            payments: list[dict] = []
            fallback_mint_id = None     # read from the store at most once
            for op_id in scan["order"]:
                plan_mint_id = _plan_mint_id(scan["plan_by_op"].get(op_id))
                if not plan_mint_id and fallback_mint_id is None:
                    fallback_mint_id = self._known_mint_id()
                mint_id = plan_mint_id or fallback_mint_id
                entry = {"op_id": op_id,
                         # THE PERMANENT FIGURE: what this payment handed
                         # over, summed over every output it created
                         # whatever became of it since.  Exactly what
                         # history() prints for the same op_id.
                         "amount_mc": scan["paid_by_op"].get(op_id, 0),
                         # ...and how much of it the store still believes
                         # is in somebody else's hands.  This one moves.
                         "outstanding_mc": scan["out_by_op"].get(op_id, 0),
                         "live_mc": None, "retired_mc": 0,
                         "unaccounted_mc": 0, "tokens": []}
                for secret, amount_mc, key, store_state in scan[
                        "rows_by_op"].get(op_id, ()):
                    amount = int(amount_mc or 0)
                    store_state = _clean_store_state(store_state)
                    try:
                        token = format_token(
                            mint_id, amount,
                            b64u_decode(str(secret), expect_len=32))
                    except (TokenError, ValueError, TypeError):
                        # A row this build cannot render is reported as a
                        # row it cannot render, not silently dropped: money
                        # the operator cannot see is worse than a gap they
                        # can.  Its VALUE still counts, so the
                        # decomposition below stays whole.
                        token = ""
                    entry["tokens"].append(
                        {"token": token, "amount_mc": amount,
                         "key": str(key), "state": None,
                         "store_state": store_state})
                    if store_state == "spent_out":
                        entry["retired_mc"] += amount
                # The residual, per payment: value the grouped sum says
                # this payment handed over that the per-string scan did
                # not produce a row for.  Structurally 0 -- both come off
                # ONE read transaction over the same table (see
                # _payment_rows) -- and named anyway, because the defect
                # this method was rewritten for was exactly a total that
                # shrank without a field to say so.  What it can really
                # catch is this module dropping rows, which is how the
                # defect happened; it is not a guard against a concurrent
                # writer, because the snapshot already excludes one.
                # NOT clamped at 0: a scan that produced MORE than the
                # grouped sum is as much a defect as one that produced
                # less, and folding either direction away is the move
                # this method was rewritten to stop.
                entry["unaccounted_mc"] = (
                    entry["amount_mc"]
                    - sum(t["amount_mc"] for t in entry["tokens"]))
                payments.append(entry)
            checked = self._check_spent(payments)
            # WHO each payment was for and what became of the delivery,
            # from the record beside the store and keyed by the same op_id
            # this groups by.  A payment with no record reads "unknown" in
            # the same words history() uses for it: the two views of one
            # payment must not be able to say different things.
            records = self._journal.records([p["op_id"] for p in payments])
            by_state = {"unspent": 0, "spent": 0, "unknown": 0, None: 0}
            listed_mc = 0
            listed_outstanding_mc = 0
            unaccounted_mc = 0
            for entry in payments:
                record = records.get(entry["op_id"]) or _NO_RECORD
                entry["recipient"] = record["recipient"]
                entry["recipient_kind"] = record["recipient_kind"]
                entry["delivery"] = record["delivery"]
                entry["delivery_cause"] = record["delivery_cause"]
                entry["delivery_attempt"] = record.get("delivery_attempt", "")
                # HOW MUCH OF THIS PAYMENT IS STILL LIVE -- a number only
                # when every string in it carries a state the mint gave.
                # ``checked`` says the mint ANSWERED; it does not say the
                # mint knew. A payment against another mint's ledger comes
                # back answered, with every string "unknown", and summing
                # only the unspent ones there produces a confident 0 about
                # money the very next field calls undetermined. None is
                # the honest answer, and the per-token states are where a
                # caller reads what IS known.
                states = {t["state"] for t in entry["tokens"]}
                if checked and not (states & {"unknown", None}):
                    entry["live_mc"] = sum(
                        t["amount_mc"] for t in entry["tokens"]
                        if t["state"] == "unspent")
                listed_mc += entry["amount_mc"]
                listed_outstanding_mc += entry["outstanding_mc"]
                unaccounted_mc += entry["unaccounted_mc"]
                for token in entry["tokens"]:
                    by_state[token["state"]] += token["amount_mc"]
            # ``complete`` is the same rule ``live_mc`` uses, one level up:
            # every string in the whole report carries the mint's own word.
            complete = (checked and not by_state["unknown"]
                        and not by_state[None])
            # Value the window left out, split so that the half which
            # could still be live is visible on its own.  A non-zero
            # ``unlisted_outstanding_mc`` is the only thing that can turn
            # a complete report's ``unredeemed_mc`` into None, and it is
            # published so a caller can say WHY rather than guess from
            # len(payments).
            unlisted_mc = scan["handed_over_mc"] - listed_mc
            unlisted_outstanding_mc = (scan["outstanding_mc"]
                                       - listed_outstanding_mc)
            return {
                "checked": checked,
                "mint_id": self._known_mint_id(),
                # The identity, and it is asserted by test_walletops.py
                # over a randomised sequence of payments, redemptions and
                # re-pastes:
                #   handed_over_mc == listed_mc + unlisted_mc
                #   listed_mc      == unspent + spent + unstated
                #                     + unchecked + unaccounted
                # WHOLE-LIFE, never windowed: what this wallet has handed
                # to other people, all of it.
                "handed_over_mc": scan["handed_over_mc"],
                # How many payments that is, and how much of it this
                # report actually lists.
                "payment_count": scan["payment_count"],
                "listed_mc": listed_mc,
                "unlisted_mc": unlisted_mc,
                "unlisted_outstanding_mc": unlisted_outstanding_mc,
                "truncated": len(payments) < scan["payment_count"],
                "unspent_mc": by_state["unspent"],
                "spent_mc": by_state["spent"],
                # The mint answered and has NO LEDGER ENTRY for these --
                # a different mint's database, most often.
                "unstated_mc": by_state["unknown"],
                # The mint was not asked, or answered about only some.
                "unchecked_mc": by_state[None],
                # Handed over and in none of the four boxes above.  0
                # everywhere this module can reach; a non-zero here is a
                # bug in this method, said out loud rather than absorbed.
                "unaccounted_mc": unaccounted_mc,
                # The one number that answers "how much of what this
                # wallet paid out is still unredeemed", and None unless
                # every string carries a definite state AND every
                # outstanding payment fitted in the window.
                "unredeemed_mc": (by_state["unspent"]
                                  if complete and not unlisted_outstanding_mc
                                  else None),
                # NOT handed over and NOT in the four boxes: pay ops that
                # returned no string to anybody and that recover() put
                # back in the spendable pool.  This value is inside
                # summary()["balance_mc"]; adding it to the figures above
                # would count the same coins twice, which is precisely
                # what an operator reading both screens must not be made
                # to do.
                "recovered_mc": scan["recovered_mc"],
                "recovered_ops": scan["recovered_ops"],
                "payments": payments,
            }

    def _payment_rows(self, limit: int) -> dict:
        """What the STORE says about this wallet's payments, in one read.

        TWO queries inside ONE explicit read transaction (``BEGIN`` ...
        ``COMMIT`` around both, see ``_ro_snapshot``), and deliberately
        two rather than one: the first is the GROUPED sum per payment op
        -- the identical arithmetic ``history()`` runs through
        ``_outputs_by_op`` -- and the second is the per-string scan the
        report's token list is built from.  The transaction is what makes
        that "one snapshot" rather than two: a plain sqlite3 connection
        opens NO transaction for a SELECT, so without the ``BEGIN`` each
        statement reads whatever is committed at the moment it runs and a
        writer between them would shift the parts out from under the
        total.  Reading the total and the parts from one snapshot by two
        different routes is what makes ``unaccounted_mc`` a cross-check on
        this module's own scan instead of noise.

        Selection is ``wallet_ops.state = 'done'`` and role ``payment``,
        with NO filter on the token's own state -- that filter was the
        original defect -- MINUS the ops that handed nothing over (see
        ``unredeemed_payments``).  The whole-wallet totals are computed
        over every such op; ``limit`` windows only the list, and spends
        the window on payments that still have a string in
        ``handed_over`` before it spends it on payments the store has
        already retired in full.  A store that does not exist yields the
        empty scan, which is "this wallet has never paid anybody" and not
        an error.
        """
        scan = {"order": [], "paid_by_op": {}, "plan_by_op": {},
                "out_by_op": {}, "rows_by_op": {},
                "handed_over_mc": 0, "outstanding_mc": 0,
                "payment_count": 0, "recovered_mc": 0, "recovered_ops": []}
        with self._store_errors("outstanding"):
            conn = self._connect_ro()
            if conn is None:
                return scan
            try:
                with _ro_snapshot(conn):
                    # Ops this module recorded a failure against: pay()
                    # raised, so no string was returned to any caller.
                    # Read first, inside the same snapshot as the sums.
                    stranded = _stranded_ops(conn)
                    handed: list = []
                    for (op_id, paid, outstanding, any_confirmed,
                         request_json) in conn.execute(
                        "SELECT t.op_id, COALESCE(SUM(t.amount_mc), 0),"
                        " COALESCE(SUM(CASE WHEN t.state = 'handed_over'"
                        "  THEN t.amount_mc END), 0),"
                        " MAX(CASE WHEN t.state = 'confirmed'"
                        "  THEN 1 ELSE 0 END),"
                        " o.request_json FROM wallet_tokens t"
                        " JOIN wallet_ops o ON o.op_id = t.op_id"
                        " WHERE t.role = 'payment' AND o.state = 'done'"
                        " GROUP BY t.op_id ORDER BY o.rowid DESC",
                    ).fetchall():
                        op_id = str(op_id)
                        paid = int(paid or 0)
                        if any_confirmed or op_id in stranded:
                            # Never handed over: recover() settled a pay
                            # op whose strings pay() never returned.  Its
                            # value is in the balance, so it is reported
                            # under its own name and nowhere else.
                            scan["recovered_mc"] += paid
                            scan["recovered_ops"].append(
                                {"op_id": op_id, "amount_mc": paid})
                            continue
                        handed.append((op_id, paid, int(outstanding or 0),
                                       request_json))
                    scan["payment_count"] = len(handed)
                    scan["handed_over_mc"] = sum(h[1] for h in handed)
                    scan["outstanding_mc"] = sum(h[2] for h in handed)
                    # The window, live money first.  Both halves stay
                    # newest-first; what changes is that a payment the
                    # store has fully retired can no longer displace one
                    # the mint may still call unspent.
                    chosen = ([h for h in handed if h[2] > 0]
                              + [h for h in handed if h[2] == 0])[:limit]
                    for op_id, paid, outstanding, request_json in chosen:
                        scan["order"].append(op_id)
                        scan["paid_by_op"][op_id] = paid
                        scan["out_by_op"][op_id] = outstanding
                        scan["plan_by_op"][op_id] = request_json
                    order = scan["order"]
                    for start in range(0, len(order), _SQL_CHUNK):
                        chunk = order[start:start + _SQL_CHUNK]
                        marks = ",".join("?" * len(chunk))
                        for (op_id, secret, amount_mc, key,
                             state) in conn.execute(
                            "SELECT op_id, secret, amount_mc, key, state FROM"
                            f" wallet_tokens WHERE role = 'payment' AND op_id"
                            f" IN ({marks}) ORDER BY key",
                            tuple(chunk),
                        ).fetchall():
                            scan["rows_by_op"].setdefault(
                                str(op_id), []).append(
                                    (secret, amount_mc, key, state))
            finally:
                conn.close()
        return scan

    def outstanding_payments(self, *, limit: int = 20) -> dict:
        """The OLD NAME for ``unredeemed_payments()``.  Same answer.

        Kept because it is the name ``gui/app.py``'s route and any earlier
        caller were written against, and removing it would turn a
        vocabulary correction into a broken GUI.  It is documented here
        rather than quietly aliased because the word itself was the
        defect: "outstanding" reads as "needs recovering", which is
        ``recover()``'s question and not this one.  New callers should use
        ``unredeemed_payments``.
        """
        return self.unredeemed_payments(limit=limit)

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

        Rows are ``{"ts_ms", "op_id", "kind", "amount_mc", "detail",
        "cause", "recipient", "recipient_kind", "delivery",
        "delivery_cause", "delivery_attempt"}``.

        A COMMITTED PAYMENT carries the payment record: who it was meant
        for, whether it was delivered, and — for one that was not — the
        cause, so that a row read three months later says which component
        to go and look at.  A payment with no record reads ``unknown``,
        never ``delivered``.  Every other row carries ``""`` in those five
        fields: an operation that moved no money has no delivery whose
        outcome could be stated, and stating one would be inventing it.

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

        Reads the store READ-ONLY inside ONE explicit read transaction
        (``_ro_snapshot``), so the page a caller gets is one consistent
        snapshot even if the wallet is being written to at the same time.
        The transaction is what buys that: a plain sqlite3 connection
        opens none of its own for a SELECT, so "one connection" alone
        would be several snapshots.  Raises rather than returning ``[]``
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
                    # THREE queries, ONE read transaction -- see
                    # _ro_snapshot for why the transaction is what makes
                    # "one snapshot" true of a sqlite3 connection.
                    with _ro_snapshot(conn):
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
            # A second file, so a second read — deliberately AFTER the
            # store's snapshot is closed rather than inside it.  The record
            # describes payments that already committed, so it cannot
            # disagree with the snapshot about whether they did; what it
            # can be is absent, which reads as "not recorded" and never as
            # "delivered".
            records = self._journal.records(op_ids)
        return [
            _history_row(op_id, kind, state, request_json,
                         out_by_op.get(op_id, {}), causes.get(op_id),
                         records.get(op_id))
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


@contextlib.contextmanager
def _ro_snapshot(conn):
    """Hold ONE read transaction across several statements on ``conn``.

    A plain ``sqlite3.Connection`` opens NO transaction for a SELECT, so
    two SELECTs on one connection are two independent reads: demonstrated
    by committing from another connection between them and watching the
    second answer change.  Every method here that reads a total by one
    route and its parts by another depends on both seeing the same bytes,
    so the transaction is opened explicitly and closed again immediately.

    ``BEGIN`` is DEFERRED: it takes no lock until the first read and holds
    a SHARED lock only until ``COMMIT``.  THE COST, stated because it is
    real: this store is in rollback-journal mode, where a held read lock
    turns a concurrent writer away (``database is locked``) rather than
    letting it commit underneath -- which is exactly what makes the reads
    one snapshot.  So the transaction spans two or three quick queries on
    a local file and NEVER an HTTP call: every mint request in this module
    is made after the connection is closed.  The connection is read-only,
    so there is nothing to roll back and the close is best effort.
    """
    conn.execute("BEGIN")
    try:
        yield conn
    finally:
        try:
            conn.execute("COMMIT")
        except sqlite3.Error:
            pass


def _stranded_ops(conn) -> set:
    """op_ids this module recorded a FAILURE cause against.

    A cause row exists only for an op that was NOT ``done`` when the call
    that planned it raised (``_settle_cause`` skips ``done`` ops), and
    ``WalletOps.pay`` raises without returning a single string.  So for a
    pay op the row means, permanently: nothing from this payment was ever
    handed to anybody, whatever ``recover()`` did to the op afterwards.

    A store that has never recorded a cause has no table, which is not an
    error -- it is the answer "nothing was recorded".  Only that one
    sqlite complaint is absorbed; any other failure is a real store
    failure and propagates to the caller's ``_store_errors`` guard.
    """
    try:
        rows = conn.execute(
            f"SELECT op_id FROM {_CAUSES_TABLE}").fetchall()
    except sqlite3.OperationalError as exc:
        if "no such table" not in str(exc).lower():
            raise
        return set()
    return {str(r[0]) for r in rows}


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
                 cause_row=None, record=None) -> dict:
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
    delivery = dict(_NO_DELIVERY)
    if kind == "pay":
        paid = out_by_role.get("payment", 0)
        change = out_by_role.get("change", 0)
        if committed:
            delivery = _delivery_note(record)
            amount, detail = paid, (
                f"paid out {paid} mc, {burn_txt}, {change} mc change"
                f" returned to the wallet — {delivery['note']}"
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
        # The handle that finds this operation again: it is what
        # unredeemed_payments() groups by and what the payment record is
        # keyed on, so a row and the money it describes can be joined.
        "op_id": str(op_id),
        "kind": f"{kind}{suffix}",
        "amount_mc": int(amount),
        "detail": detail,
        # Recorded when it failed, never reconstructed afterwards.
        "cause": cause,
        # Recorded when the payment was made and when its delivery was
        # answered; "" on any row where no money moved.
        "recipient": delivery["recipient"],
        "recipient_kind": delivery["recipient_kind"],
        "delivery": delivery["delivery"],
        "delivery_cause": delivery["delivery_cause"],
        "delivery_attempt": delivery["delivery_attempt"],
    }


def _delivery_from_error(exc, who: str, op_id: str) -> tuple[str, str, str]:
    """(delivery, cause, note) for a delivery that RAISED a WalletOpsError.

    The money clause is chosen by ``_refused_value_clause`` and is placed
    BEFORE the quoted sentence on purpose: the note is trimmed to
    ``_SENTENCE_MAX`` from the right, and what must survive that trim is
    whether the value still exists, not the other component's prose.
    """
    cause = _clean_cause(getattr(exc, "cause", None))
    said = getattr(exc, "detail", "") or getattr(exc, "reason", "") or exc
    if _outcome_for(cause) == "unknown":
        # Nobody answered.  The OUTCOME is undetermined (§5.1) but the
        # cause is not: "nobody answered" is the most precise word there
        # is for it, it is in the pinned vocabulary, and throwing it away
        # made this row byte-identical to a payment never attempted.
        return "unknown", cause, _note_with_quote(
            f"{who} was sent this payment and nothing answered — whether it"
            f" was credited there is undetermined; check with the mint"
            f" before paying again (op {op_id}).", said)
    return "undelivered", cause, _note_with_quote(
        f"{who} did not take this payment — {_refused_value_clause(cause)}"
        f" (op {op_id}; unredeemed_payments() says which of its strings are"
        f" live now).", said)


def _delivery_from_result(result, who: str, op_id: str) -> tuple[str, str, str]:
    """(delivery, cause, note) for a delivery that RETURNED something."""
    if not isinstance(result, dict):
        return "unknown", "unknown", (
            f"delivery to {who} returned {type(result).__name__}, which says"
            f" nothing about whether the payment landed (op {op_id})")
    rejected = result.get("rejected")
    rejected = rejected if isinstance(rejected, list) else []
    if not rejected:
        credited = _as_mc(result.get("accepted_mc"))
        return "delivered", "", (
            f"delivered to {who}"
            + (f", credited {credited} mc there" if credited is not None
               else "")
            + f" (op {op_id})")
    causes = {_clean_cause(r.get("cause")) for r in rejected
              if isinstance(r, dict)}
    cause = causes.pop() if len(causes) == 1 else "unknown"
    took = _as_mc(result.get("accepted")) or 0
    # The vocabulary has no "partly", and inventing one would widen a
    # closed set.  The row says undelivered — the payment did not arrive
    # as sent — and the sentence says exactly how much did, and what
    # became of the part that did not.  That last clause is decided per
    # cause: a payment refused because the strings were ALREADY SPENT is
    # not value this wallet can pay again, and a row saying it is sends
    # its reader hunting money somebody else has.
    return "undelivered", cause, _note_with_quote(
        f"{who} refused {len(rejected)} of"
        f" {len(rejected) + took} string(s) in this payment"
        f"{'' if not took else f'; the other {took} were taken'}"
        f" — {_refused_value_clause(cause)}"
        f" (op {op_id}; unredeemed_payments() says which of its strings are"
        f" live now)", "")


def _delivery_note(record) -> dict:
    """The five record fields plus a clause, for ONE committed payment.

    THE OTHER HALF OF THE ROUND-4 FIX.  A row that said only "paid out
    5000 mc" described a payment that arrived and a payment whose delivery
    died in identical words; an operator reading it three months later had
    nothing to act on.  These fields are read back from what was recorded
    at the time, exactly like ``cause`` — never re-derived, because
    nothing in the store afterwards can tell the two apart.

    A payment with NO record reads ``unknown`` and says so.  That is the
    honest state for a payment made by an older build, by ``wallet_cli``,
    or by a process that died before it could write: the money left, and
    where it went is not recorded here.
    """
    if not record:
        return dict(_NO_RECORD)
    out = {
        "recipient": str(record.get("recipient", "")),
        "recipient_kind": str(record.get("recipient_kind", "")),
        "delivery": _clean_delivery(record.get("delivery")),
        "delivery_cause": (_clean_cause(record.get("delivery_cause"))
                           if record.get("delivery_cause") else ""),
        # Whether a delivery was ever attempted is a DIFFERENT question
        # from what became of one, and the four situations that all read
        # "unknown" are told apart by it.  See DELIVERY_ATTEMPTS.
        "delivery_attempt": _clean_attempt(record.get("delivery_attempt")),
        "note": str(record.get("note") or ""),
    }
    if not out["note"]:
        out["note"] = _NO_RECORD["note"]
    return out


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
