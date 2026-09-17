"""C10 — supervision: the optional Supervision Profile (§6.1).

Spec: aicash-spec-v0.4.md §5.2, §5.3, §6.1, §7.3 (custodial rules), §8(c).
Locked: L13 (controls bind only operator-registered custodial agents; Layer 0
stays authless and un-capped), L17 (per-principal random bearer API keys,
injected clock, Ed25519 statement signatures). Depends: C04 (ledgerstore),
C05 (signing), C06 (mintapi — this module mounts routes onto a C06 server).

Design notes
------------
* All supervision state lives in the mint's sqlite database (C10-owned
  ``sup_*`` tables, never touching C04's or C06's), via a dedicated
  connection guarded by one lock — the same shared-file discipline C06 uses.
* The custodial/ledger bridge (§5.3): a deposit is a REAL C04 exchange
  spending the presented bearer tokens into a mint-custody entry (a by-hash
  output whose secret the mint itself generated and holds in ``sup_custody``);
  a withdrawal is a C04 exchange spending mint-custody entries into the
  CALLER-specified by-hash outputs (the mint never sees the new secrets) plus
  a change output back into custody. Invariant maintained by construction:
  ``sum(unspent custody) == sum(agent balances) - sup_mint.absorbed_mc``
  (the ledger-level burn the mint has absorbed under §7.3/R17).
* Custodial transfers and pulls never touch C04 and never burn (§7.3).
  Deposits/withdrawals burn exactly as the exchange calls they are; the
  withdrawal's full gross debit (amount + burn) counts against caps.
* Withdrawal burn attribution (§7.3, pinned by resolution R17 in
  OPEN-QUESTIONS.md): the agent is charged ``compute_burn(amount_withdrawn)``
  on the REQUESTED amount, never on the mint's internally selected custody
  inputs. The exchange itself still burns per L12 on its actual inputs; the
  difference (>= 0, since the selected inputs always cover the request and
  ``compute_burn`` is monotone) comes out of the mint's custody pool and is
  tracked in ``sup_mint.absorbed_mc``. Deposits are symmetric and unchanged:
  the agent is charged the burn on the deposited tokens' sum, which it
  controls.
* Persist-before-send (§5.1, mandatory; §5.3 "no exceptions" for
  withdrawals): the supervision core IS the wallet for custody money, so
  every secret it generates (deposit custody secret, withdrawal change
  secret) is committed to ``sup_custody`` in a ``pending`` state — together
  with a ``sup_pending_ops`` staging record describing the follow-up work —
  BEFORE ``ledger.exchange`` is called. On success the staged op is
  finalized (activate pending outputs, mark inputs spent, adjust balance,
  journal lines); on ``ExchangeRejected`` it is discarded. A crash between
  the exchange commit and the finalize commit is reconciled at startup by
  probing ``/v3/status`` for whether the staged exchange committed, then
  rolling the op forward or back. Custody inputs selected for an in-flight
  withdrawal are marked ``reserved`` so a crashed withdrawal can never
  wedge the selector on ledger-spent rows.
* No-bearer-withdrawal (§6.1(4)) is enforced as the BOUND IT CLAIMS, not
  as its literal wording. §6.1(4) says withdrawals from a flagged account
  fail, and that alone is bypassable in two hops: transfer the balance to
  an agent of another operator and withdraw there. So the flag also
  refuses a flagged agent's custodial moves that leave its operator —
  ``/v3/agent/transfer`` to another operator's agent, and
  ``/v3/agent/authorize_pull`` of a grant whose payee is another
  operator's agent — with ``external_transfer_disabled``. ``/v3/pull`` on
  such a grant is refused too (re-checked there, since a grant may predate
  the flag) but answers ``authorization_revoked``: §6.1(6) pins a CLOSED
  enumeration of pull errors and a ratified spec does not get an eighth
  reason bolted on, so the refusal is expressed with the member of that
  list that is true here — the grant no longer confers a debit right. See
  ``agent_pull`` for why that member and not ``account_frozen``. Moves to a
  SIBLING agent of the same operator stay legal: the receiver is under the
  same operator's caps, freeze, flags and fleet statement, so the value has
  not left the supervised perimeter. The perimeter is the operator, never
  the single agent; what bounds total exfiltration inside it is the cap
  schedule and the freeze.
* Operator registration is credential-gated, on a credential of its OWN.
  ``/v3/operator/register`` mints an operator identity — and therefore a
  fleet the flag above measures itself against — so leaving it authless
  made every per-agent control optional: anyone who could reach the port
  could stand up a second operator and be outside the first one's
  perimeter. The first fix for that gated it on C06's issuance check, and
  that conflated two different powers: creating credits from nothing, and
  creating an operator account. On a mint built ``ADMIN_ISSUANCE_DISABLED``
  the issuance check is unconditionally false, so registration answered 401
  to everyone; with no operator there are no agents, no deposits, no pulls,
  no withdrawals and no statements, and the profile mounted, advertised
  itself in the descriptor and could do nothing at all — in the
  configuration the rest of this work pushes operators toward. Both this
  file and the component document told such a mint to provision operators
  "out of band"; no out-of-band mechanism existed.
  So the gate now has its own secret, ``SupervisionServer(...,
  registration_token=...)``, with C06's three-named-state discipline
  (``REGISTRATION_OPEN`` / ``REGISTRATION_DISABLED`` / a secret string) and
  its own header ``X-Registration-Token``. The default keeps one answer to
  "who administers this mint" wherever one exists: a string ``admin_token``
  becomes the registration credential too (so ``X-Admin-Token`` still
  works, unchanged); ``ADMIN_ISSUANCE_OPEN`` opens registration too;
  ``ADMIN_ISSUANCE_DISABLED`` GENERATES a registration credential instead
  of killing the route, readable at ``SupervisionServer.registration_token``
  and never logged. ``SupervisionServer.provision_operator`` is the
  in-process bootstrap the documentation used to promise, and
  ``run_mint.py --supervision`` exposes all of it. Which state applies is
  announced once at mount — the unauthenticated one loudly.
* Caps (§6.1(2)): trailing 3_600s / 86_400s rolling windows over the
  debit-like statement lines, evaluated at debit commit with the injected
  mint clock; ``absolute`` is the lifetime debit total. A line aged exactly
  window ms no longer counts (strict ``t > now - window``).
* Body framing is decided from a header block this layer parsed WHOLE, not
  by asking ``self.headers`` for a name. ``self.headers`` is what
  ``email.parser`` made of the wire, and the two differ on inputs an
  intermediary reads perfectly well — a single space before a colon makes
  the parser drop that line and every line after it into the message
  payload, so ``Transfer-Encoding : chunked`` read as "no framing headers
  at all", the body read as empty, and the chunk octets stayed on a
  keep-alive socket to be framed as the next request.
  The rule refuses on the VIEW rather than on any spelling, and asks one
  question: can this layer prove the header block means, to every other
  hop, what it means here? A parser defect, a non-empty payload and a
  CR/LF in a name or value all say no. So does a NAME this layer cannot
  vouch for, and that clause is a normalisation rather than a list of
  spellings, because a list is what the first attempt was and one step off
  it (``Transfer_Encoding: chunked`` beside ``Content-Length: 0``, which
  parses perfectly and which every CGI/WSGI front end folds back to a
  transfer coding) walked straight through it. Every parsed name must be a
  bare RFC 7230 token, and a name that FOLDS onto a framing header
  (lowercase, separators dropped) without being its canonical spelling is
  refused on the fold.
* THAT RULE IS NOT THIS MODULE'S ANY MORE. It was, and being this
  module's alone was the defect: when framing was lifted into one shared
  function for all four HTTP servers in this repository, the function that
  got lifted was C06's confusable-NAME regex — which can only express
  confusion at the single separator position — while the token check and
  the hard fold stayed here. 435 header names (``Content-Length;``,
  ``Transfer-Encoding.``, ``Con-tent-Length``, ``Content-Length-``,
  ``_Transfer-Encoding`` …) were refused by the supervision profile and
  FRAMED by the plain mint, the operator GUI and the operator console, on
  every POST route and every anonymous GET route. Both halves now live in
  ``aicash.mintapi.framing_verdict`` and their UNION is the rule, so
  ``_SupHandler`` overrides nothing and names nothing: there is no
  ``_sup_framing_is_unreadable`` and no ``_framed_body_length`` override,
  and the C10 POST reader, the C10 GET guard and the inherited Layer 0
  routes on the same socket all reach the identical verdict because they
  reach the identical function.
* Serving limits (deployment hardening, not protocol): the supervision
  routes run on a SECOND stdlib ThreadingHTTPServer, so an unbounded
  request body or an untimed socket costs the mint memory or a parked
  thread. ``_MAX_BODY_BYTES`` is checked against Content-Length before
  anything is read, and ``_SupHandler.timeout`` bounds how long one
  connection may stall or idle. Both are enforced by C10's own code, but
  the byte cap is no longer a second number: it is DERIVED at import from
  C06's ``MAX_BODY_BYTES``, since two hand-written copies were equal only
  by coincidence and nothing kept them that way (L17 leaves rate limiting
  and TLS out of the reference build, so these two caps are all there
  is). An over-size body is refused with the existing ``bad_format``
  rejection — no new error vocabulary. The cap lives on a C10-private
  reader (``_read_sup_json``), never as an
  override of C06's ``_read_json``: the inherited Layer 0 routes must
  keep answering exactly as a plain C06 mint does (L13/B9), including
  C06's own choice of §3.8 reason for a body it refuses.
* Statement (§6.1(7)): built from the ``sup_lines`` journal, pinned schema,
  signed with the mint key over canonical JSON (C05). Generation enforces
  the balance invariant: the journal-derived balance must equal both the
  stored balance and ``closing - opening``; a mismatch is a 500, never a
  silently wrong statement.
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import json
import logging
import os
import sqlite3
import threading
import urllib.parse

from aicash.burncalc import compute_burn
from aicash.clock import system_clock
from aicash.ledgerstore import ExchangeRejected, Ledger, OutputSpec
from aicash.lockeval import InputForm
from aicash.mintapi import (
    ADMIN_ISSUANCE_DISABLED,
    ADMIN_ISSUANCE_OPEN,
    MAX_BODY_BYTES,
    MintConfig,
    MintServer,
    _Handler,
    _MintHTTPServer,
    _fold_header_name,
    framing_verdict,
)
from aicash.signing import attach_sig
from aicash.tokencodec import (
    Token,
    TokenError,
    b64u_decode,
    b64u_encode,
    ledger_key,
    new_secret,
    parse_token,
)

#: Deliberately just the server. ``aicash/__init__.py`` mirrors this
#: module's ``__all__`` whole (pinned by a C06 test), and that file is not
#: this component's to edit; the registration vocabulary
#: (``REGISTRATION_OPEN``, ``REGISTRATION_DISABLED``,
#: ``REGISTRATION_INHERITS_ISSUANCE``, ``make_supervision_mint``) is
#: imported from ``aicash.supervision`` by name instead — which is how
#: run_mint.py takes it.
__all__ = ["SupervisionServer"]

#: C10's own logger. It carries exactly one kind of message — how this
#: mint gates operator registration, emitted once at mount — and never a
#: request, a header, a body or a key (see the standing guard in
#: test_c10_supervision.py).
logger = logging.getLogger("aicash.supervision")


class _RegistrationMode:
    """A named state for ``SupervisionServer(registration_token=...)``.

    Same shape and the same reason as C06's ``_AdminIssuanceMode``: a
    policy that is not a credential must not be able to arrive as one. A
    bare string is a secret to compare; these two objects are decisions,
    they compare equal to nothing, and their repr says which one it is in
    a traceback or a log line.
    """

    __slots__ = ("_name",)

    def __init__(self, name: str):
        self._name = name

    def __repr__(self) -> str:
        return self._name

    __str__ = __repr__


#: Operator registration takes no credential. Anyone who can reach the
#: port can create an operator — and an agent under a new operator is
#: outside every existing operator's caps, freeze and flags. Opted into by
#: name, announced at mount as a WARNING.
REGISTRATION_OPEN = _RegistrationMode("REGISTRATION_OPEN")

#: ``POST /v3/operator/register`` answers 401 to everyone. The mint is
#: still usable: operators are provisioned through
#: ``SupervisionServer.provision_operator``, which is the out-of-band
#: mechanism this profile's documentation used to promise and not have.
REGISTRATION_DISABLED = _RegistrationMode("REGISTRATION_DISABLED")

#: The default. Registration follows whatever the mint already decided
#: about ``/admin/issue``, EXCEPT that a mint which disabled issuance gets
#: a generated registration credential rather than a dead route — see
#: ``_resolve_registration_credential`` for why that exception is the
#: whole point.
REGISTRATION_INHERITS_ISSUANCE = _RegistrationMode(
    "REGISTRATION_INHERITS_ISSUANCE"
)

_REGISTRATION_GUIDANCE = (
    "registration_token must be a non-empty secret string, or one of the"
    " named states:\n"
    "  registration_token=\"<secret>\"              gate it on"
    " X-Registration-Token\n"
    "  registration_token=REGISTRATION_DISABLED   no HTTP registration;"
    " use SupervisionServer.provision_operator()\n"
    "  registration_token=REGISTRATION_OPEN       unauthenticated"
    " registration -- opt in by name\n"
    "  (omit it)                                  follow the mint's"
    " admin_token, generating a credential when issuance is disabled\n"
    "  from aicash.supervision import REGISTRATION_DISABLED,"
    " REGISTRATION_OPEN"
)


def _resolve_registration_credential(config: MintConfig, requested):
    """Decide what ``POST /v3/operator/register`` requires.

    Returns ``(credential, source)``. ``credential`` is a secret string,
    ``REGISTRATION_OPEN`` or ``REGISTRATION_DISABLED``; ``source`` is the
    one word the mount-time log line is built from.

    WHY THIS IS NOT ``admin_authorized`` ANY MORE. Gating registration on
    the mint's issuance credential closed a real hole (an authless way to
    mint an operator identity is an authless way out of every per-agent
    control the profile has) but it conflated two different powers:
    creating credits from nothing, and creating an operator account. A
    mint built ``ADMIN_ISSUANCE_DISABLED`` has deliberately given up the
    first; the issuance check is then unconditionally false, so the second
    went with it and registration answered 401 to no credential, an empty
    one, a wrong one and the literal name of the mode alike. With no
    operator there are no agents, no deposits, no pulls, no withdrawals
    and no statements: the profile mounted, advertised itself in the
    descriptor and could do nothing at all — in exactly the configuration
    the rest of this work pushes operators toward, which is the safe one.
    The component document and this module both said such a mint
    "provisions operators out of band"; no out-of-band mechanism existed
    anywhere in the repository.

    So registration has its own credential, with its own header and its
    own named states, and the default still gives a deployment ONE answer
    to "who administers this mint" wherever that answer exists:

    * ``admin_token`` is a secret string -> registration takes the SAME
      secret. Unchanged behaviour, unchanged header (``X-Admin-Token`` is
      still accepted), unchanged tests.
    * ``ADMIN_ISSUANCE_OPEN`` -> registration is open too. An
      unauthenticated minting endpoint is already the larger power; a
      gated registration route next to it would be security theatre.
    * ``ADMIN_ISSUANCE_DISABLED`` -> a random registration credential is
      GENERATED. This is the fix. The mint is bootstrappable, the route is
      still gated, and the credential is never logged: read it from
      ``SupervisionServer.registration_token`` (the launcher writes it to
      a 0600 file, exactly as it does the issuance credential).

    An explicit ``registration_token=`` overrides all of that in either
    direction, so an operator who wants the two powers held by two
    different people can have that, and one who wants no HTTP route at all
    can say ``REGISTRATION_DISABLED`` and use ``provision_operator``.
    """
    if requested is REGISTRATION_INHERITS_ISSUANCE:
        admin = config.admin_token
        if admin is ADMIN_ISSUANCE_OPEN:
            return REGISTRATION_OPEN, "inherited-open"
        if isinstance(admin, str) and admin.strip():
            return admin, "inherited"
        # ADMIN_ISSUANCE_DISABLED, and any state that is not a usable
        # secret: generate rather than strand the profile.
        return _new_key(), "generated"
    if requested is REGISTRATION_OPEN or requested is REGISTRATION_DISABLED:
        return requested, "explicit-mode"
    if isinstance(requested, _RegistrationMode):
        raise ValueError(
            "registration_token was given a mode (%r) that is not"
            " REGISTRATION_OPEN, REGISTRATION_DISABLED or"
            " REGISTRATION_INHERITS_ISSUANCE.\n" % (requested,)
            + _REGISTRATION_GUIDANCE
        )
    if isinstance(requested, str):
        if not requested.strip():
            # An empty or all-whitespace string is what an unset shell
            # variable looks like after expansion, and it is a credential
            # every caller can send. Refuse at construction: the mint that
            # comes up is the one that will run for a week.
            raise ValueError(
                "registration_token must be a NON-EMPTY string. %d"
                " character(s) of whitespace is a credential anyone can"
                " present.\n" % (len(requested),)
                + _REGISTRATION_GUIDANCE
            )
        return requested, "explicit-token"
    raise ValueError(
        "registration_token was given a %s, which is neither a credential"
        " nor one of the named states.\n" % (type(requested).__name__,)
        + _REGISTRATION_GUIDANCE
    )


HOUR_MS = 3_600_000
DAY_MS = 86_400_000

#: §6.1(7) pinned kind partition. freeze/unfreeze are amount-0 events,
#: excluded from both sums (and from cap windows, which sum debit-like only).
DEBIT_KINDS = ("debit", "pull_out", "withdrawal", "burn")
CREDIT_KINDS = ("credit", "pull_in", "deposit", "issuance")

_DEBIT_SQL = "('debit','pull_out','withdrawal','burn')"
_CREDIT_SQL = "('credit','pull_in','deposit','issuance')"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sup_operators (
  operator_id TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  key_sha256  TEXT NOT NULL UNIQUE,
  created_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sup_agents (
  agent_id             TEXT PRIMARY KEY,
  operator_id          TEXT NOT NULL,
  name                 TEXT NOT NULL,
  key_sha256           TEXT NOT NULL UNIQUE,
  balance_mc           INTEGER NOT NULL DEFAULT 0,
  frozen               INTEGER NOT NULL DEFAULT 0,
  no_bearer_withdrawal INTEGER NOT NULL DEFAULT 0,
  cap_per_hour_mc      INTEGER,
  cap_per_day_mc       INTEGER,
  cap_absolute_mc      INTEGER,
  created_at           INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sup_lines (
  seq                  INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_id             TEXT NOT NULL,
  t                    INTEGER NOT NULL,
  kind                 TEXT NOT NULL,
  amount_mc            INTEGER NOT NULL,
  counterparty_account TEXT,
  ref                  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS sup_lines_agent_t ON sup_lines (agent_id, t);
CREATE TABLE IF NOT EXISTS sup_pull_auths (
  auth_id           TEXT PRIMARY KEY,
  granting_agent_id TEXT NOT NULL,
  payee_account     TEXT NOT NULL,
  cap_mc_per_day    INTEGER NOT NULL,
  expires_at        INTEGER NOT NULL,
  revoked           INTEGER NOT NULL DEFAULT 0,
  created_at        INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sup_pull_uses (
  seq       INTEGER PRIMARY KEY AUTOINCREMENT,
  auth_id   TEXT NOT NULL,
  t         INTEGER NOT NULL,
  amount_mc INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sup_custody (
  hash        TEXT PRIMARY KEY,
  secret_b64u TEXT NOT NULL,
  amount_mc   INTEGER NOT NULL,
  -- 'pending'  : secret persisted, creating exchange not yet known committed
  -- 'unspent'  : active custody money
  -- 'reserved' : selected as input by an in-flight withdrawal
  -- 'spent'    : consumed by a committed withdrawal exchange
  state       TEXT NOT NULL DEFAULT 'unspent'
);
CREATE TABLE IF NOT EXISTS sup_pending_ops (
  op_id        TEXT PRIMARY KEY,
  kind         TEXT NOT NULL,   -- 'deposit' | 'withdraw'
  agent_id     TEXT NOT NULL,
  probe_hash   TEXT NOT NULL,   -- ledger hash whose state reveals commit
  details_json TEXT NOT NULL    -- everything the finalize/unwind needs
);
-- §7.3/R17 mint-side accounting: cumulative ledger-level withdrawal burn
-- the mint has absorbed (ledger burn on custody inputs minus the
-- agent-charged burn on the requested amount). One row, id = 1.
-- Invariant: sum(unspent custody) == sum(agent balances) - absorbed_mc.
CREATE TABLE IF NOT EXISTS sup_mint (
  id          INTEGER PRIMARY KEY CHECK (id = 1),
  absorbed_mc INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO sup_mint (id, absorbed_mc) VALUES (1, 0);
"""

_AGENT_COLS = (
    "agent_id",
    "operator_id",
    "name",
    "balance_mc",
    "frozen",
    "no_bearer_withdrawal",
    "cap_per_hour_mc",
    "cap_per_day_mc",
    "cap_absolute_mc",
)
_AGENT_SELECT = "SELECT %s FROM sup_agents" % ", ".join(_AGENT_COLS)


def _rejected(reason: str) -> tuple[int, dict]:
    return 400, {"status": "rejected", "reason": reason}


def _unknown_agent() -> tuple[int, dict]:
    # A missing agent and another operator's agent answer identically
    # (no cross-operator existence oracle).
    return 404, {"status": "rejected", "reason": "unknown_agent"}


#: Inclusive bounds of SQLite's INTEGER storage class (a signed 64-bit
#: value). Every integer this module accepts from a request body ends up in
#: one of those columns, so this is the range in which "an integer" is a
#: thing the mint can actually hold.
_SQLITE_INT_MIN = -(2 ** 63)
_SQLITE_INT_MAX = 2 ** 63 - 1


def _plain_int(v: object) -> bool:
    """True for a JSON integer this mint can accept, store and return.

    The single chokepoint every integer-valued field goes through
    (``per_hour_mc``, ``per_day_mc``, ``absolute_mc``, ``cap_mc_per_day``,
    ``expires_at``, ``amount_mc`` on pull/transfer/withdraw), which is why
    the range lives HERE and not in six route bodies.

    It used to check the TYPE and nothing else, and a type check is not a
    validity check: Python's ``int`` is unbounded and SQLite's is not, so
    ``{"per_hour_mc": 9223372036854775808}`` — valid JSON, correct type,
    non-negative — passed every guard on the route, reached
    ``conn.execute`` and raised ``OverflowError`` out of the driver. The
    route's ``except BaseException: rollback; raise`` re-raised it into
    ``_dispatch_sup``'s blanket handler and the caller got a bare 500.
    ``10 ** 600`` did the same. §3.8 owes an enumerated reason for a value
    the mint refuses, and "an integer larger than the mint can store" is a
    malformed field, not an internal fault — so it is ``bad_format``, which
    is what every caller of this predicate already answers.

    Stated as a bound on the VALUE rather than as a guard on the five
    fields the report happened to name: any field that reaches SQL through
    this predicate is covered, including ones added later.
    """
    # bool is excluded: type(True) is bool, not int.
    return type(v) is int and _SQLITE_INT_MIN <= v <= _SQLITE_INT_MAX


#: Longest caller-supplied string this mint will accept into a supervision
#: column or echo back in a response — ``operator_name``, ``agent_name``,
#: the journal ``ref``, and every identifier a caller names.
#:
#: There is no storage reason for a bound (SQLite TEXT is effectively
#: unlimited) and that is exactly why there was none: a five-thousand
#: character operator name returned 200 and created a real operator, and a
#: ``ref`` of the same size was written to TWO journal lines per transfer
#: and re-rendered inside every signed statement that covers them, where
#: it is paid for again on every read, forever. A field with no bound is a
#: field whose cost is set by whoever calls it.
#:
#: 256 is deliberately generous for what these fields ARE — human labels
#: and payment references, not documents — and deliberately a single
#: number rather than one per field: six bounds are six things to keep in
#: step, and the last round of this defect was six checks that had each
#: been written separately. C06 bounds its own caller-chosen string,
#: ``idempotency_key``, at 128 for the same reason (MAX_IDEMPOTENCY_KEY_LEN).
MAX_TEXT_LEN = 256


def _plain_text(v: object, *, max_len: int = MAX_TEXT_LEN) -> bool:
    r"""True for a JSON string this mint can store, render AND return.

    The string counterpart of ``_plain_int``, and the same lesson: a type
    check is not a validity check. ``op_register`` checked
    ``isinstance(name, str) and name`` and stopped there, so both of these
    reached the database:

    * an operator name containing an UNPAIRED SURROGATE (``"op\ud800"``,
      which ``json.loads`` produces happily — JSON's ``\uXXXX`` escape
      has no pairing rule). Python holds it, SQLite's binding cannot
      encode it, and ``json.dumps(...).encode("utf-8")`` on the way back
      out cannot either. Whichever of those fires first, the caller gets a
      bare 500 and §3.8 owes an enumerated reason. The reviewer's report
      describes the failure surfacing from the RESPONSE encoder, with the
      operator already created — there is nothing correct for an encoder
      to do at that point, which is precisely why the fix has to be INPUT
      validation: by the time anything downstream can object, the mint has
      already done the thing it cannot describe;
    * a five-thousand character name, which simply worked: 200 OK and a
      real operator, with the cost of the field set by its caller.

    Both are the same defect — a route accepting what it cannot render —
    so they get the same predicate, applied to every caller-supplied
    string this module stores or echoes rather than to the one field each
    was reported on. Layer 0 closed its half of this class (C01's
    canonical JSON refuses an unpaired surrogate with ``TokenError``, and
    ``idempotency_key`` is length-bounded); this is C10's.

    "Can render" is asked by DOING it, not by pattern-matching what a
    surrogate looks like: ``str.encode("utf-8")`` is the exact operation
    that fails downstream — in the sqlite binding and in the response
    encoder — so a string that survives it here survives them there. A
    predicate that tried to enumerate the unencodable code points would
    be the same list-shaped mistake this repository has now made three
    times about header names.

    THE ENCODE CLAUSE WAS NOT THE WHOLE OF "CAN RENDER", and the gap was
    reported as one value on two routes: an ``operator_name`` and an
    ``agent_name`` carrying a NUL. ``"acme\x00evil"`` encodes to UTF-8
    without complaint, is under the bound, and answered 200 with a real
    operator and a live key. So did BEL, backspace, ESC, CR, LF, DEL,
    the C1 controls, U+2028, the bidi overrides and the zero-width
    spaces — one class, every family of it driven over raw sockets on
    both routes, every one accepted. Encodability is about bytes;
    what these fields need is a question about a STRING, and this
    predicate is named for the second.

    Ask what the validation is FOR, and a caller-supplied label that this
    mint stores, echoes, or re-renders inside a signed document has three
    requirements. They are what the clauses below are, in order:

    1. **It must be bounded.** ``max_len``, above. A field with no bound
       is a field whose cost is set by whoever calls it.
    2. **It must be encodable.** ``str.encode("utf-8")`` — the operation
       the sqlite binding and the response encoder both perform, asked
       here so it cannot fail there with the row already written.
    3. **It must render, and must forge no structure in anything that
       embeds it.** ``str.isprintable()``. False for exactly the
       characters that have no rendering of their own (the C0 and C1
       controls, DEL, the surrogates, private-use and unassigned code
       points) and for the ones whose rendering is an instruction to the
       thing displaying them rather than a glyph: the line and paragraph
       separators, the non-ASCII spaces, and the format characters —
       which is where the bidi overrides and the zero-width spaces live,
       the characters that make two different stored strings display
       identically.

    (3) is the clause that matters most for ``ref``, because ``ref`` is
    the one caller-supplied string here that is re-rendered inside a
    SIGNED statement, twice per transfer, for as long as the journal is
    retained — and its author is the agent the statement audits. A
    signature over a document whose text the audited party chose is worth
    less if that text can carry an ESC sequence into the operator's
    terminal, a line separator into a line-oriented export, or an
    override that makes the rendered ``ref`` read as something other than
    what was signed. C01's canonical JSON escapes the C0 controls on the
    way out, so JSON structure itself was never forgeable; it does not
    escape DEL, the C1 range, U+2028/9 or the format characters, and it
    is in any case only the one embedding of many. The fix belongs on the
    way IN, where the answer is still "no", for the same reason the
    surrogate fix did.

    Three clauses, and (3) subsumes (2): every string UTF-8 cannot encode
    is a lone surrogate, and every lone surrogate is in a category
    ``isprintable`` already refuses. (2) is kept anyway, and kept first,
    because it is the only clause that IS the downstream operation rather
    than a description of it — ``isprintable`` reads the Unicode category
    table of whichever Python is running, and the encode is invariant.
    The clause that names the real failure should be the clause that
    refuses it.

    Deliberately NOT relaxed for interior whitespace beyond the ASCII
    space: a tab or a newline in a human label is a line in somebody's
    report, and none of these fields is a document.
    """
    if type(v) is not str or len(v) > max_len:
        return False
    try:
        v.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return v.isprintable()


def _new_id(prefix: str) -> str:
    return prefix + "-" + b64u_encode(os.urandom(9))


def _new_key() -> str:
    # Per-principal random bearer API key (L17 / OPEN-QUESTIONS #5).
    return b64u_encode(os.urandom(32))


def _key_digest(key: str) -> str:
    """sha256 of a bearer API key. Keys are stored and looked up ONLY by
    digest: the database never holds a raw key, and the B-tree equality
    probe compares digests — matching-prefix timing on the digest reveals
    nothing about the key itself."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


#: (method, path) -> (required role, handler method name).
#: Roles: "register" = the mint's OPERATOR-REGISTRATION credential,
#: presented in ``X-Registration-Token`` (or, because the default derives
#: it from the issuance secret, in ``X-Admin-Token``) — see
#: ``_resolve_registration_credential`` for why this is no longer the
#: issuance check itself; "operator"/"agent" = a supervision bearer key of
#: that kind; "either" = agent or operator.
#: No supervision route is authless: /v3/operator/register used to be, and
#: an authless way to mint a NEW operator identity is an authless way out of
#: every per-agent control the profile has (a flagged agent transfers to an
#: agent of the operator you just registered and withdraws there).
_ROUTES = {
    ("POST", "/v3/operator/register"): ("register", "op_register"),
    ("POST", "/v3/operator/agents"): ("operator", "op_agents"),
    ("POST", "/v3/operator/caps"): ("operator", "op_caps"),
    ("POST", "/v3/operator/freeze"): ("operator", "op_freeze"),
    ("POST", "/v3/operator/unfreeze"): ("operator", "op_unfreeze"),
    ("POST", "/v3/operator/flags"): ("operator", "op_flags"),
    ("GET", "/v3/operator/statement"): ("operator", "op_statement"),
    ("GET", "/v3/agent/balance"): ("either", "agent_balance"),
    ("POST", "/v3/agent/authorize_pull"): ("agent", "agent_authorize_pull"),
    ("POST", "/v3/agent/revoke_pull"): ("agent", "agent_revoke_pull"),
    ("POST", "/v3/pull"): ("agent", "agent_pull"),
    ("POST", "/v3/agent/transfer"): ("agent", "agent_transfer"),
    ("POST", "/v3/agent/deposit"): ("agent", "agent_deposit"),
    ("POST", "/v3/agent/withdraw"): ("agent", "agent_withdraw"),
}


class _SupCore:
    """Supervision Profile state + route logic on the mint's sqlite."""

    def __init__(self, config: MintConfig, ledger: Ledger, mint_core,
                 registration_credential=REGISTRATION_DISABLED):
        self.config = config
        self.ledger = ledger
        # C06's core. Registration used to be gated by calling its
        # ``admin_authorized`` directly; it is not any more, because that
        # check is unconditionally false on a mint built
        # ADMIN_ISSUANCE_DISABLED and took the whole profile down with
        # issuance (see _resolve_registration_credential). Kept for the
        # descriptor/single-writer plumbing C10 shares with C06.
        self._mint_core = mint_core
        #: A secret string, REGISTRATION_OPEN or REGISTRATION_DISABLED.
        #: Resolved by SupervisionServer; the default here is the refusing
        #: one, so a _SupCore built by hand without a decision cannot be
        #: the permissive accident.
        self._registration_credential = registration_credential
        self._lock = threading.RLock()
        # Same shared-database discipline as C06's _Core (private-attribute
        # access recorded in C06's build notes; C10 follows it).
        self._conn = sqlite3.connect(
            ledger._db_path,
            timeout=30.0,
            isolation_level=None,  # manual txn control
            check_same_thread=False,  # guarded by self._lock
        )
        self._conn.executescript(_SCHEMA)
        with self._lock:
            self._recover_pending()

    # -- plumbing ---------------------------------------------------------

    def _now(self) -> int:
        # The injected mint clock, observed through C04's public API (L17).
        return self.ledger.status([])[0]

    def _txn(self):
        self._conn.execute("BEGIN IMMEDIATE")

    def _commit(self):
        self._conn.execute("COMMIT")

    def _rollback(self):
        self._conn.execute("ROLLBACK")

    def _principal(self, auth_header: object):
        """Resolve a bearer API key to ('operator'|'agent', id) or None."""
        if not isinstance(auth_header, str) or not auth_header.startswith(
            "Bearer "
        ):
            return None
        digest = _key_digest(auth_header[len("Bearer "):])
        row = self._conn.execute(
            "SELECT operator_id FROM sup_operators WHERE key_sha256 = ?",
            (digest,),
        ).fetchone()
        if row is not None:
            return ("operator", row[0])
        row = self._conn.execute(
            "SELECT agent_id FROM sup_agents WHERE key_sha256 = ?", (digest,)
        ).fetchone()
        if row is not None:
            return ("agent", row[0])
        return None

    def registration_authorized(self, presented_token) -> bool:
        """Constant-time check of the OPERATOR-REGISTRATION credential.

        Deliberately not ``_mint_core.admin_authorized``: registering an
        operator and issuing credits are two different powers, and the
        round that conflated them made a mint with issuance disabled unable
        to register anything at all. Same comparison discipline as C06's —
        ``hmac.compare_digest`` over utf-8 bytes, never ``==`` — and the
        same shape of three named states, so there is one credential
        vocabulary in this codebase rather than two.

        True only for REGISTRATION_OPEN (opted into by name) or an exact
        match against the configured secret. REGISTRATION_DISABLED, and
        anything that is not a string, are False and never "allow".
        """
        configured = self._registration_credential
        if configured is REGISTRATION_OPEN:
            return True
        if not isinstance(configured, str):
            return False
        presented = presented_token if isinstance(presented_token, str) else ""
        return hmac.compare_digest(
            configured.encode("utf-8", "surrogateescape"),
            presented.encode("utf-8", "surrogateescape"),
        )

    def provision_operator(self, operator_name: str):
        """Create an operator WITHOUT an HTTP request. Returns (id, key).

        The out-of-band mechanism. Both this module and
        components/C10-supervision.md used to tell an operator running a
        mint with issuance disabled to "provision operators out of band",
        and no such mechanism existed: the only writer of ``sup_operators``
        was the gated HTTP route, and the launcher had no supervision flag
        at all. That sentence is now true.

        It is in-process by construction — a caller already holding the
        SupervisionServer object holds the mint — so it takes no credential
        and answers to no header. That is the whole distinction between
        this and the route: the route has to prove who is asking because
        anyone can reach the port.

        It does NOT get a weaker name rule than the route, though. The
        two doors write the same column, and the reason a name has to be
        bounded, encodable and renderable is a property of the column and
        of everything downstream of it — a signed statement, an operator's
        terminal, an export — not of who was trusted to fill it. The check
        was ``isinstance(str) and non-empty`` while the route ran
        ``_plain_text``, so ``--provision-operator`` on the launcher was a
        way in for exactly the values the route refuses. Same predicate,
        raised rather than answered because this is a Python call.
        """
        if not isinstance(operator_name, str) or not operator_name:
            raise ValueError("operator_name must be a non-empty string")
        if not _plain_text(operator_name):
            raise ValueError(
                "operator_name must be at most %d characters and printable"
                " (no control, format, separator or unpaired-surrogate code"
                " points): it is stored, and rendered by things this mint"
                " does not control" % MAX_TEXT_LEN
            )
        with self._lock:
            return self._insert_operator(operator_name)

    def _insert_operator(self, name: str):
        """The single writer of ``sup_operators``; caller holds the lock."""
        operator_id, key = _new_id("op"), _new_key()
        self._txn()
        try:
            self._conn.execute(
                "INSERT INTO sup_operators (operator_id, name, key_sha256,"
                " created_at) VALUES (?, ?, ?, ?)",
                (operator_id, name, _key_digest(key), self._now()),
            )
            self._commit()
        except BaseException:
            self._rollback()
            raise
        return operator_id, key

    def dispatch(
        self, method, path, body, body_ok, auth_header, params,
        admin_header=None, registration_header=None,
    ):
        """Auth (§6.1(1)) then route. 401 = no/unknown key on an authed
        route; 403 = a valid key of the wrong role. Auth is decided before
        body validation so the B8 matrix is exact.

        The "register" role is the mint's operator-registration credential.
        It is read from ``X-Registration-Token``, falling back to
        ``X-Admin-Token`` when that header is absent — ONE secret, two
        accepted spellings, because the default resolution makes the
        registration credential literally the issuance secret on the mints
        that have one, and every existing bootstrap script sends it under
        the older name. A mint whose registration credential is distinct
        (generated, or configured explicitly) simply does not match the
        issuance secret in either header, which is the separation the whole
        change is for. A supervision bearer key — operator or agent — is
        not that credential and gets the same 401 as no key at all: it is
        not the wrong role for the route so much as the wrong kind of
        secret, and answering 403 would tell an agent key holder that its
        key was recognised.
        """
        role_req, fn_name = _ROUTES[(method, path)]
        with self._lock:
            principal = self._principal(auth_header)
            if role_req == "register":
                presented = (
                    registration_header
                    if registration_header is not None
                    else admin_header
                )
                if not self.registration_authorized(presented):
                    return 401, {"status": "unauthorized"}
            elif role_req != "none":
                if principal is None:
                    return 401, {"status": "unauthorized"}
                if role_req in ("operator", "agent") and principal[0] != role_req:
                    return 403, {"status": "forbidden"}
            if method == "POST" and (not body_ok or not isinstance(body, dict)):
                return _rejected("bad_format")
            return getattr(self, fn_name)(principal, body, params)

    # -- row helpers ------------------------------------------------------

    def _agent(self, agent_id: object) -> dict | None:
        if not _plain_text(agent_id):
            # `isinstance(agent_id, str)` was the whole guard, and an id
            # is a caller-supplied string like any other: `{"agent_id":
            # "ag\ud800"}` was bound straight into the SELECT below and
            # raised UnicodeEncodeError out of the driver — a bare 500 on
            # /v3/operator/caps, /freeze, /unfreeze, /flags,
            # /agent/authorize_pull, /agent/transfer, /agent/balance and
            # /operator/statement, all from one unguarded lookup. Refusing
            # HERE covers every route that names an agent, including ones
            # added later: an id this mint cannot render is an id it
            # cannot be holding, so "not found" is the true answer and the
            # callers' existing `unknown_agent` handling says it.
            return None
        row = self._conn.execute(
            _AGENT_SELECT + " WHERE agent_id = ?", (agent_id,)
        ).fetchone()
        if row is None:
            return None
        return dict(zip(_AGENT_COLS, row))

    def _add_line(self, agent_id, t, kind, amount_mc, counterparty, ref):
        self._conn.execute(
            "INSERT INTO sup_lines (agent_id, t, kind, amount_mc,"
            " counterparty_account, ref) VALUES (?, ?, ?, ?, ?, ?)",
            (agent_id, t, kind, amount_mc, counterparty, ref),
        )

    def _debits_since(self, agent_id: str, since: int) -> int:
        """Sum of debit-like lines strictly newer than ``since`` (trailing
        window: a line aged exactly the window no longer counts)."""
        return self._conn.execute(
            "SELECT COALESCE(SUM(amount_mc), 0) FROM sup_lines"
            f" WHERE agent_id = ? AND t > ? AND kind IN {_DEBIT_SQL}",
            (agent_id, since),
        ).fetchone()[0]

    def _debits_lifetime(self, agent_id: str) -> int:
        return self._conn.execute(
            "SELECT COALESCE(SUM(amount_mc), 0) FROM sup_lines"
            f" WHERE agent_id = ? AND kind IN {_DEBIT_SQL}",
            (agent_id,),
        ).fetchone()[0]

    def _leaves_the_operator(self, sender: dict, target: dict) -> bool:
        """True iff ``sender`` is flagged no-bearer-withdrawal and the move
        would put value in an account OUTSIDE its operator (§6.1(4), read
        as the bound it is claimed to be rather than as its literal list
        of one operation).

        The flag's stated job is that this agent cannot turn its allowance
        into bearer tokens. Refusing only ``/v3/agent/withdraw`` does not
        do that job: a custodial transfer (or a pull grant, which is a
        transfer the payee triggers) to an agent under another operator
        hands the whole balance to a principal this operator does not
        supervise, and that principal withdraws it. Same act, one hop.

        The line is drawn at the OPERATOR, not the agent, because an agent
        of the same operator is inside the same perimeter: same caps, same
        freeze, same flags, same fleet statement, same key holder. Drawing
        it at the agent would refuse ordinary intra-fleet accounting (a
        worker settling to its own operator's treasury agent) and buy
        nothing — the operator can flag the sibling too.
        """
        return bool(sender["no_bearer_withdrawal"]) and (
            sender["operator_id"] != target["operator_id"]
        )

    def _cap_violation(self, agent: dict, gross_mc: int, now: int) -> bool:
        """True iff adding a gross debit of ``gross_mc`` at ``now`` would
        exceed any configured cap (§6.1(2): trailing 3600s/86400s windows,
        absolute = lifetime)."""
        aid = agent["agent_id"]
        for cap, window in (
            (agent["cap_per_hour_mc"], HOUR_MS),
            (agent["cap_per_day_mc"], DAY_MS),
        ):
            if cap is not None and self._debits_since(aid, now - window) + gross_mc > cap:
                return True
        cap = agent["cap_absolute_mc"]
        if cap is not None and self._debits_lifetime(aid) + gross_mc > cap:
            return True
        return False

    def _balance_from_lines(self, agent_ids, t_before=None, t_through=None):
        """Journal-derived balance: sum(credit-like) - sum(debit-like) over
        the given agents, restricted to t < t_before or t <= t_through."""
        marks = ",".join("?" for _ in agent_ids)
        cond, args = "", list(agent_ids)
        if t_before is not None:
            cond, args = " AND t < ?", args + [t_before]
        elif t_through is not None:
            cond, args = " AND t <= ?", args + [t_through]
        row = self._conn.execute(
            f"SELECT COALESCE(SUM(CASE WHEN kind IN {_CREDIT_SQL} THEN amount_mc"
            f" WHEN kind IN {_DEBIT_SQL} THEN -amount_mc ELSE 0 END), 0)"
            f" FROM sup_lines WHERE agent_id IN ({marks})" + cond,
            args,
        ).fetchone()
        return row[0]

    # -- operator routes --------------------------------------------------

    def op_register(self, principal, body, params):
        """POST /v3/operator/register — operator bootstrap (C10 API).

        Gated on the mint's operator-registration credential (see
        ``dispatch`` and ``registration_authorized``). It used to be
        authless and labelled a test bootstrap, which made it the hole
        under the no-bearer-withdrawal flag: a flagged agent's holder
        registered an operator of its own, registered an agent there, and
        had a perimeter the first operator's controls said nothing about.
        The gate stays; what changed is which secret it is: registering an
        operator is not the power to create credits from nothing, and
        hanging it off the issuance check left the route dead on every mint
        that had deliberately turned issuance off.
        """
        name = body.get("operator_name")
        if not _plain_text(name) or not name:
            # The reported route. A name that cannot be rendered is
            # refused BEFORE an operator exists, because after it exists
            # there is no correct answer left: the encoder that finally
            # notices is downstream of the row, the key and the identity.
            return _rejected("bad_format")
        operator_id, key = self._insert_operator(name)
        return 200, {
            "status": "ok",
            "operator_id": operator_id,
            "operator_key": key,
        }

    def op_agents(self, principal, body, params):
        name = body.get("agent_name")
        if not _plain_text(name) or not name:
            # Not reported, found by sweeping: the same field, the same
            # table, the same two failures, one route across.
            return _rejected("bad_format")
        agent_id, key = _new_id("ag"), _new_key()
        self._txn()
        try:
            self._conn.execute(
                "INSERT INTO sup_agents (agent_id, operator_id, name,"
                " key_sha256, created_at) VALUES (?, ?, ?, ?, ?)",
                (agent_id, principal[1], name, _key_digest(key), self._now()),
            )
            self._commit()
        except BaseException:
            self._rollback()
            raise
        return 200, {"status": "ok", "agent_id": agent_id, "agent_key": key}

    def _operator_agent(self, principal, agent_id):
        agent = self._agent(agent_id)
        if agent is None or agent["operator_id"] != principal[1]:
            return None
        return agent

    def op_caps(self, principal, body, params):
        agent = self._operator_agent(principal, body.get("agent_id"))
        if agent is None:
            return _unknown_agent()
        caps = {}
        for field in ("per_hour_mc", "per_day_mc", "absolute_mc"):
            v = body.get(field)  # absent and explicit null both mean no cap
            if v is not None and (not _plain_int(v) or v < 0):
                return _rejected("bad_format")
            caps[field] = v
        self._txn()
        try:
            self._conn.execute(
                "UPDATE sup_agents SET cap_per_hour_mc = ?, cap_per_day_mc = ?,"
                " cap_absolute_mc = ? WHERE agent_id = ?",
                (
                    caps["per_hour_mc"],
                    caps["per_day_mc"],
                    caps["absolute_mc"],
                    agent["agent_id"],
                ),
            )
            self._commit()
        except BaseException:
            self._rollback()
            raise
        return 200, {"status": "ok", "agent_id": agent["agent_id"], "caps": caps}

    def _set_frozen(self, principal, body, frozen: bool):
        target = body.get("agent_id")
        if target == "ALL":
            rows = self._conn.execute(
                "SELECT agent_id, frozen FROM sup_agents WHERE operator_id = ?"
                " ORDER BY agent_id",
                (principal[1],),
            ).fetchall()
        else:
            agent = self._operator_agent(principal, target)
            if agent is None:
                return _unknown_agent()
            rows = [(agent["agent_id"], agent["frozen"])]
        now = self._now()
        kind = "freeze" if frozen else "unfreeze"
        # Response field: 'frozen' / 'unfrozen' (pre-1.0 wire fix: the
        # field was originally misspelled 'freezed'/'unfreezed'; renamed
        # before any external caller could depend on it — see
        # components/C10-supervision.md). The journal *kind* strings
        # ('freeze'/'unfreeze') are §6.1(7)-pinned and unchanged.
        field = "frozen" if frozen else "unfrozen"
        changed = []
        self._txn()
        try:
            for agent_id, was in rows:
                if bool(was) == frozen:
                    continue  # idempotent: no duplicate journal events
                self._conn.execute(
                    "UPDATE sup_agents SET frozen = ? WHERE agent_id = ?",
                    (1 if frozen else 0, agent_id),
                )
                # §6.1(7): freeze/unfreeze are amount-0 non-monetary lines.
                self._add_line(agent_id, now, kind, 0, None, "")
                changed.append(agent_id)
            self._commit()
        except BaseException:
            self._rollback()
            raise
        return 200, {"status": "ok", field: changed}

    def op_freeze(self, principal, body, params):
        return self._set_frozen(principal, body, True)

    def op_unfreeze(self, principal, body, params):
        return self._set_frozen(principal, body, False)

    def op_flags(self, principal, body, params):
        agent = self._operator_agent(principal, body.get("agent_id"))
        if agent is None:
            return _unknown_agent()
        flag = body.get("no_bearer_withdrawal")
        if not isinstance(flag, bool):
            return _rejected("bad_format")
        self._txn()
        try:
            self._conn.execute(
                "UPDATE sup_agents SET no_bearer_withdrawal = ?"
                " WHERE agent_id = ?",
                (1 if flag else 0, agent["agent_id"]),
            )
            self._commit()
        except BaseException:
            self._rollback()
            raise
        return 200, {
            "status": "ok",
            "agent_id": agent["agent_id"],
            "no_bearer_withdrawal": flag,
        }

    def op_statement(self, principal, body, params):
        """GET /v3/operator/statement — §6.1(7)/§8(c) signed statement,
        producible on demand for any in-retention period (this reference
        implementation retains the custodial journal indefinitely)."""
        try:
            t_from = int(params["from"])
            t_to = int(params["to"])
        except (KeyError, ValueError, TypeError):
            return _rejected("bad_format")
        if not _plain_int(t_from) or not _plain_int(t_to):
            # A try/except around int() catches a non-numeric string; it
            # does NOT bound the value, and these two go straight into a
            # sqlite binding. `?to=9223372036854775808` — one past the
            # column's range, valid JSON, correct type, non-negative —
            # raised OverflowError out of the driver in
            # `_balance_from_lines` and answered a bare 500 with no
            # enumerated reason, which is the exact error-model violation
            # the round that wrote `_plain_int` was convened to eliminate.
            # It survived here because this route converts its integers by
            # hand instead of through the module's stated single
            # chokepoint, and a larger value (`"9" * 25`) was caught by
            # accident — CPython's int/str conversion limit fires first —
            # which is how a route with a hole in it looks swept.
            return _rejected("bad_format")
        if t_from < 0 or t_to < t_from:
            return _rejected("bad_format")
        agent_param = params.get("agent_id")
        if agent_param is None or agent_param == "fleet":
            scope_agent = "fleet"
            rows = self._conn.execute(
                "SELECT agent_id, balance_mc FROM sup_agents"
                " WHERE operator_id = ?",
                (principal[1],),
            ).fetchall()
            agent_ids = [r[0] for r in rows]
            stored_balance = sum(r[1] for r in rows)
        else:
            agent = self._operator_agent(principal, agent_param)
            if agent is None:
                return _unknown_agent()
            scope_agent = agent["agent_id"]
            agent_ids = [scope_agent]
            stored_balance = agent["balance_mc"]

        if agent_ids:
            opening = self._balance_from_lines(agent_ids, t_before=t_from)
            closing = self._balance_from_lines(agent_ids, t_through=t_to)
            current = self._balance_from_lines(agent_ids)
            marks = ",".join("?" for _ in agent_ids)
            line_rows = self._conn.execute(
                "SELECT t, kind, amount_mc, counterparty_account, ref"
                f" FROM sup_lines WHERE agent_id IN ({marks})"
                " AND t >= ? AND t <= ? ORDER BY seq",
                agent_ids + [t_from, t_to],
            ).fetchall()
        else:
            opening = closing = current = 0
            line_rows = []

        lines = [
            {
                "t": t,
                "kind": kind,
                "amount_mc": amount,
                "counterparty_account": counterparty,
                "ref": ref,
            }
            for (t, kind, amount, counterparty, ref) in line_rows
        ]
        credit_sum = sum(
            ln["amount_mc"] for ln in lines if ln["kind"] in CREDIT_KINDS
        )
        debit_sum = sum(
            ln["amount_mc"] for ln in lines if ln["kind"] in DEBIT_KINDS
        )
        # Balance invariant, enforced at generation (§6.1(7)): the pinned
        # partition must reproduce closing - opening, AND the journal must
        # agree with the stored balances. A violation is an internal error
        # (500 via the handler), never a silently wrong signed statement.
        if credit_sum - debit_sum != closing - opening:
            raise RuntimeError("statement invariant violated (partition)")
        if current != stored_balance:
            raise RuntimeError("statement invariant violated (balance)")

        statement = {
            "v": 4,
            "mint_id": self.config.mint_id,
            "scope": {"operator_id": principal[1], "agent_id": scope_agent},
            "period": {"from": t_from, "to": t_to},
            "opening_balance_mc": opening,
            "closing_balance_mc": closing,
            "lines": lines,
        }
        # Signed over canonical JSON with the mint's published key (C05).
        return 200, attach_sig(statement, self.config.signing_private)

    # -- balance / spend-rate --------------------------------------------

    def agent_balance(self, principal, body, params):
        """GET /v3/agent/balance — §6.1(5) balance and spend-rate, no
        counterparty identities. Agents see themselves; operators any of
        their own agents (?agent_id required)."""
        role, pid = principal
        agent_param = params.get("agent_id")
        if role == "agent":
            if agent_param is not None and agent_param != pid:
                return 403, {"status": "forbidden"}
            agent = self._agent(pid)
        else:
            if agent_param is None:
                return _rejected("bad_format")
            agent = self._operator_agent(principal, agent_param)
            if agent is None:
                return _unknown_agent()
        now = self._now()
        return 200, {
            "status": "ok",
            "agent_id": agent["agent_id"],
            "balance_mc": agent["balance_mc"],
            "frozen": bool(agent["frozen"]),
            "no_bearer_withdrawal": bool(agent["no_bearer_withdrawal"]),
            "caps": {
                "per_hour_mc": agent["cap_per_hour_mc"],
                "per_day_mc": agent["cap_per_day_mc"],
                "absolute_mc": agent["cap_absolute_mc"],
            },
            "spend_rate": {
                "trailing_hour_mc": self._debits_since(
                    agent["agent_id"], now - HOUR_MS
                ),
                "trailing_day_mc": self._debits_since(
                    agent["agent_id"], now - DAY_MS
                ),
                "lifetime_mc": self._debits_lifetime(agent["agent_id"]),
            },
        }

    # -- pull authorizations (§6.1(6)) ------------------------------------

    def agent_authorize_pull(self, principal, body, params):
        payee = body.get("payee_account")
        cap = body.get("cap_mc_per_day")
        expires_at = body.get("expires_at")
        if not _plain_int(cap) or cap <= 0 or not _plain_int(expires_at) or expires_at < 0:
            return _rejected("bad_format")
        payee_agent = self._agent(payee)
        if payee_agent is None:
            # §6.1(6): the payee must hold a custodial account at this mint.
            return _rejected("unknown_account")
        granter = self._agent(principal[1])
        if self._leaves_the_operator(granter, payee_agent):
            # A grant is a transfer the payee triggers later; a flagged
            # agent may not open one that points out of its operator.
            # /v3/pull re-checks, because a grant may predate the flag.
            return _rejected("external_transfer_disabled")
        auth_id = _new_id("auth")
        self._txn()
        try:
            self._conn.execute(
                "INSERT INTO sup_pull_auths (auth_id, granting_agent_id,"
                " payee_account, cap_mc_per_day, expires_at, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                # THE RESOLVED ROW'S ID, NOT THE CALLER'S BYTES. `payee`
                # reached this line having only been used to LOOK A ROW UP
                # (`self._agent(payee)` above, which runs `_plain_text` and
                # answers `unknown_account` when it fails), so storing it
                # was safe — but safe because SQLite TEXT equality is
                # byte-exact, which is a fact about the storage engine and
                # not about this code. Change the collation on that column,
                # or resolve the payee through any lookup that normalises,
                # and the string in this column stops being the id it was
                # matched against while every test still passes. The row
                # the SELECT actually found carries the mint-generated id;
                # write that one, and the claim "every string in this
                # column is a mint-generated agent id" is a property of the
                # INSERT rather than of the engine underneath it.
                (auth_id, principal[1], payee_agent["agent_id"], cap,
                 expires_at, self._now()),
            )
            self._commit()
        except BaseException:
            self._rollback()
            raise
        return 200, {"status": "ok", "auth_id": auth_id}

    def agent_revoke_pull(self, principal, body, params):
        auth_id = body.get("auth_id")
        if not _plain_text(auth_id):
            return _rejected("bad_format")
        row = self._conn.execute(
            "SELECT granting_agent_id FROM sup_pull_auths WHERE auth_id = ?",
            (auth_id,),
        ).fetchone()
        if row is None or row[0] != principal[1]:
            return _rejected("authorization_missing")
        self._txn()
        try:
            # Revocation is immediate (§6.1(6)); revoking twice is a no-op.
            self._conn.execute(
                "UPDATE sup_pull_auths SET revoked = 1 WHERE auth_id = ?",
                (auth_id,),
            )
            self._commit()
        except BaseException:
            self._rollback()
            raise
        return 200, {"status": "ok", "auth_id": auth_id}

    def agent_pull(self, principal, body, params):
        """POST /v3/pull — payee-initiated, mint-executed atomic debit of
        the granting account and credit of the payee (§6.1(6))."""
        auth_id = body.get("auth_id")
        amount = body.get("amount_mc")
        ref = body.get("ref")
        if not _plain_text(auth_id) or not _plain_int(amount) or amount <= 0:
            return _rejected("bad_format")
        if ref is None:
            ref = ""
        if not _plain_text(ref):
            # A `ref` is stored on BOTH journal lines and re-rendered in
            # every signed statement that covers them, so an unrenderable
            # one poisons a read path the caller never touches again and
            # an unbounded one is paid for on every statement, forever.
            return _rejected("bad_format")
        now = self._now()
        self._txn()
        try:
            auth = self._conn.execute(
                "SELECT granting_agent_id, payee_account, cap_mc_per_day,"
                " expires_at, revoked FROM sup_pull_auths WHERE auth_id = ?",
                (auth_id,),
            ).fetchone()
            # An auth granted to a different payee answers exactly like a
            # missing one (no authorization-existence oracle).
            if auth is None or auth[1] != principal[1]:
                self._rollback()
                return _rejected("authorization_missing")
            granter_id, payee_id, day_cap, expires_at, revoked = auth
            if revoked:
                self._rollback()
                return _rejected("authorization_revoked")
            if now >= expires_at:  # expiry boundary: at/after -> expired
                self._rollback()
                return _rejected("authorization_expired")
            granter = self._agent(granter_id)
            payee = self._agent(payee_id)
            if granter["frozen"]:
                # L13/§6.1(3): freeze suspends pulls; nothing queues.
                self._rollback()
                return _rejected("account_frozen")
            if self._leaves_the_operator(granter, payee):
                # Checked HERE and not only at authorize time: the grant
                # may have been opened before the operator set the flag,
                # and the flag has to bind the money, not the paperwork.
                #
                # The reason is `authorization_revoked`, NOT the
                # `external_transfer_disabled` the two agent-initiated
                # routes use, because §6.1(6) pins a CLOSED enumeration
                # for pull errors —
                #   authorization_missing | authorization_revoked |
                #   authorization_expired | pull_cap_exceeded |
                #   agent_cap_exceeded | account_frozen |
                #   insufficient_balance
                # — and the spec is ratified. /v3/agent/transfer and
                # /v3/agent/authorize_pull have no pinned enumeration, so
                # they may name the flag; this route may not invent an
                # eighth reason, and a conformant client switch-casing
                # the seven would fall through on one.
                # `authorization_revoked` is the honest member of that
                # set: the grant no longer confers a debit right, and the
                # client behaviour it asks for — stop pulling, go ask the
                # granter for a new authorization — is exactly right
                # here, since a fresh grant is what the granter would
                # have to obtain (and would be refused at authorize time
                # with the flag named). Nothing in the API contradicts
                # it: no route reports an authorization's revoked bit, so
                # the row staying revoked = 0 is unobservable, and the
                # row is left alone deliberately — clearing the flag must
                # restore the grant, and a real revoke is the granting
                # agent's act (§6.1(6), "revocable-at-will"), not the
                # mint's. `account_frozen` was rejected as the mapping:
                # /v3/agent/balance publishes `frozen` and this account
                # is not frozen, so that reason WOULD contradict an
                # observable field.
                # Side benefit: the payee is told nothing about the
                # granter's operator or flags, which the old reason
                # leaked to a third party.
                self._rollback()
                return _rejected("authorization_revoked")
            used = self._conn.execute(
                "SELECT COALESCE(SUM(amount_mc), 0) FROM sup_pull_uses"
                " WHERE auth_id = ? AND t > ?",
                (auth_id, now - DAY_MS),
            ).fetchone()[0]
            if used + amount > day_cap:
                self._rollback()
                return _rejected("pull_cap_exceeded")
            if self._cap_violation(granter, amount, now):
                # Pulls count against the granting agent's caps (L13).
                self._rollback()
                return _rejected("agent_cap_exceeded")
            if granter["balance_mc"] < amount:
                self._rollback()
                return _rejected("insufficient_balance")
            self._conn.execute(
                "UPDATE sup_agents SET balance_mc = balance_mc - ?"
                " WHERE agent_id = ?",
                (amount, granter_id),
            )
            self._conn.execute(
                "UPDATE sup_agents SET balance_mc = balance_mc + ?"
                " WHERE agent_id = ?",
                (amount, payee_id),
            )
            self._add_line(granter_id, now, "pull_out", amount, payee_id, ref)
            self._add_line(payee_id, now, "pull_in", amount, granter_id, ref)
            self._conn.execute(
                "INSERT INTO sup_pull_uses (auth_id, t, amount_mc)"
                " VALUES (?, ?, ?)",
                (auth_id, now, amount),
            )
            self._commit()
        except BaseException:
            self._rollback()
            raise
        return 200, {
            "status": "ok",
            "amount_mc": amount,
            "balance_mc": payee["balance_mc"] + amount,
        }

    # -- custodial transfer (never touches C04, never burns — §7.3) -------

    def agent_transfer(self, principal, body, params):
        to_account = body.get("to_account")
        amount = body.get("amount_mc")
        ref = body.get("ref")
        if not _plain_int(amount) or amount <= 0:
            return _rejected("bad_format")
        if ref is None:
            ref = ""
        if not _plain_text(ref):
            return _rejected("bad_format")
        if to_account == principal[1]:
            # A self-transfer nets to zero yet would consume cap headroom
            # and journal a spurious debit/credit pair; refuse it outright.
            return _rejected("bad_format")
        now = self._now()
        self._txn()
        try:
            sender = self._agent(principal[1])
            target = self._agent(to_account)
            if target is None:
                self._rollback()
                return _rejected("unknown_account")
            if sender["frozen"]:
                self._rollback()
                return _rejected("account_frozen")
            if self._leaves_the_operator(sender, target):
                # §6.1(4) as the threat model states it: a flagged agent
                # cannot reach bearer value, including through an agent of
                # an operator this operator does not control.
                self._rollback()
                return _rejected("external_transfer_disabled")
            if self._cap_violation(sender, amount, now):
                self._rollback()
                return _rejected("agent_cap_exceeded")
            if sender["balance_mc"] < amount:
                self._rollback()
                return _rejected("insufficient_balance")
            self._conn.execute(
                "UPDATE sup_agents SET balance_mc = balance_mc - ?"
                " WHERE agent_id = ?",
                (amount, sender["agent_id"]),
            )
            self._conn.execute(
                "UPDATE sup_agents SET balance_mc = balance_mc + ?"
                " WHERE agent_id = ?",
                (amount, target["agent_id"]),
            )
            self._add_line(
                sender["agent_id"], now, "debit", amount, target["agent_id"], ref
            )
            self._add_line(
                target["agent_id"], now, "credit", amount, sender["agent_id"], ref
            )
            self._commit()
        except BaseException:
            self._rollback()
            raise
        return 200, {
            "status": "ok",
            "balance_mc": sender["balance_mc"] - amount,
        }

    # -- deposit: bearer -> balance via a real C04 exchange (§5.3) --------

    def agent_deposit(self, principal, body, params):
        tokens = body.get("tokens")
        ref = body.get("ref")
        if not isinstance(tokens, list) or not tokens:
            return _rejected("bad_format")
        if ref is None:
            ref = ""
        if not _plain_text(ref):
            return _rejected("bad_format")
        parsed = []
        for t in tokens:
            try:
                tok = parse_token(t)
            except TokenError:
                return _rejected("bad_format")
            if tok.mint_id != self.config.mint_id:
                return _rejected("bad_format")
            parsed.append(tok)
        total = sum(tok.amount_mc for tok in parsed)
        # §7.3: capture the instant ONCE for the whole call and price the
        # burn through the ledger's own selection rule, so a scheduled
        # change flips for this pre-computation at the same moment it flips
        # inside `exchange`. (`now` used to be read further down, after the
        # burn; reading the ledger's frozen configured policy here made the
        # supervision profile disagree with its own ledger from
        # `effective_at` onwards — every deposit `amount_mismatch`.)
        now = self._now()
        burn = compute_burn(total, self.ledger.effective_burn_policy(now))
        net = total - burn
        # Mint-custody output: the mint generates and holds this secret;
        # it is custody money, not a client secret (§5.3 bridge).
        custody_secret = new_secret()
        custody_hash = ledger_key(custody_secret)
        inputs = [InputForm(kind="plain", token=tok) for tok in parsed]
        outputs = [OutputSpec(amount_mc=net, secret_hash=custody_hash)]
        idem = "sup-deposit-" + b64u_encode(os.urandom(18))
        op_id = _new_id("pend")
        details = {"custody_hash": custody_hash, "net_mc": net, "t": now,
                   "ref": ref}
        # Persist-before-send (§5.1, mandatory client ordering; §5.3): the
        # custody secret and the staged follow-up are durably committed
        # BEFORE the exchange that creates the entry can commit. A crash
        # anywhere after this point is reconciled by _recover_pending.
        self._txn()
        try:
            self._conn.execute(
                "INSERT INTO sup_custody (hash, secret_b64u, amount_mc,"
                " state) VALUES (?, ?, ?, 'pending')",
                (custody_hash, b64u_encode(custody_secret), net),
            )
            self._conn.execute(
                "INSERT INTO sup_pending_ops (op_id, kind, agent_id,"
                " probe_hash, details_json) VALUES (?, 'deposit', ?, ?, ?)",
                (op_id, principal[1], custody_hash,
                 json.dumps(details, sort_keys=True)),
            )
            self._commit()
        except BaseException:
            self._rollback()
            raise
        try:
            result = self.ledger.exchange(idem, idem, inputs, outputs=outputs)
        except ExchangeRejected as exc:
            # The exchange rolled back atomically: the custody entry was
            # never created, so the staged secret is discarded.
            self._txn()
            try:
                self._conn.execute(
                    "DELETE FROM sup_custody WHERE hash = ?"
                    " AND state = 'pending'",
                    (custody_hash,),
                )
                self._conn.execute(
                    "DELETE FROM sup_pending_ops WHERE op_id = ?", (op_id,)
                )
                self._commit()
            except BaseException:
                self._rollback()
                raise
            return 400, {"status": "rejected", "errors": exc.errors}
        self._finalize_deposit(op_id, principal[1], details)
        agent = self._agent(principal[1])
        return 200, {
            "status": "ok",
            "deposited_mc": net,
            "burn_mc": result["burn_mc"],
            "balance_mc": agent["balance_mc"],
        }

    def _finalize_deposit(self, op_id, agent_id, details):
        """Post-exchange half of a deposit: activate the custody entry,
        credit the balance, journal the line, clear the staged op. Called
        on the request path and by startup recovery (idempotent-safe: the
        staged op row exists exactly until this commits)."""
        self._txn()
        try:
            self._conn.execute(
                "UPDATE sup_custody SET state = 'unspent' WHERE hash = ?"
                " AND state = 'pending'",
                (details["custody_hash"],),
            )
            self._conn.execute(
                "UPDATE sup_agents SET balance_mc = balance_mc + ?"
                " WHERE agent_id = ?",
                (details["net_mc"], agent_id),
            )
            # §6.1(7): the deposit line is the net amount credited. The
            # deposit's burn is an exchange-side event, not an agent debit,
            # so it neither appears as a debit line nor counts against caps
            # (§6.1(2) lists transfer/pull/withdrawal-gross only).
            self._add_line(
                agent_id, details["t"], "deposit", details["net_mc"], None,
                details["ref"],
            )
            self._conn.execute(
                "DELETE FROM sup_pending_ops WHERE op_id = ?", (op_id,)
            )
            self._commit()
        except BaseException:
            self._rollback()
            raise

    # -- withdraw: balance -> bearer via a C04 exchange from custody ------

    def agent_withdraw(self, principal, body, params):
        outputs = body.get("outputs")
        if not isinstance(outputs, list) or not outputs:
            return _rejected("bad_format")
        specs = []
        total_out = 0
        for o in outputs:
            if not isinstance(o, dict) or set(o) != {"amount_mc", "secret_hash"}:
                return _rejected("bad_format")
            amount, secret_hash = o["amount_mc"], o["secret_hash"]
            if not _plain_int(amount) or amount <= 0:
                return _rejected("bad_format")
            try:
                b64u_decode(secret_hash, expect_len=32)
            except TokenError:
                return _rejected("bad_format")
            # By-hash only (§5.3): the mint never sees the new secrets.
            specs.append(OutputSpec(amount_mc=amount, secret_hash=secret_hash))
            total_out += amount
        now = self._now()
        agent = self._agent(principal[1])
        if agent["frozen"]:
            return _rejected("account_frozen")
        if agent["no_bearer_withdrawal"]:
            # §6.1(4): while the flag is set, withdrawals fail.
            return _rejected("withdrawal_disabled")

        # §7.3/R17: the agent-charged burn is computed on the REQUESTED
        # amount, never on the mint's internally selected custody inputs
        # (custody fragmentation is the mint's own operational artifact).
        # One policy for the whole call, selected at the `now` captured
        # above (§7.3): the agent-charged burn, the custody selection and
        # the ledger burn it must cover are all priced under it, so a
        # scheduled change can never split a single withdrawal.
        policy = self.ledger.effective_burn_policy(now)
        burn = compute_burn(total_out, policy)
        gross = total_out + burn  # §7.3: full debit including burn
        if self._cap_violation(agent, gross, now):
            return _rejected("agent_cap_exceeded")
        if agent["balance_mc"] < gross:
            return _rejected("insufficient_balance")

        # Select custody inputs, smallest first (minimizes the ledger-level
        # burn the mint must absorb); accumulate until inputs cover the
        # outputs + the exchange's own L12 burn. Only 'unspent' rows are
        # eligible: rows reserved by an in-flight (or crashed,
        # not-yet-reconciled) withdrawal are never re-picked.
        custody = self._conn.execute(
            "SELECT hash, secret_b64u, amount_mc FROM sup_custody"
            " WHERE state = 'unspent' ORDER BY amount_mc ASC, hash ASC"
        ).fetchall()
        selected, in_sum = [], 0
        for row in custody:
            selected.append(row)
            in_sum += row[2]
            if in_sum - compute_burn(in_sum, policy) >= total_out:
                break
        ledger_burn = compute_burn(in_sum, policy)
        if in_sum - ledger_burn < total_out:
            # Custody can only fall short of a within-balance request in a
            # degenerate burn corner; report it as insufficient funds.
            return _rejected("insufficient_balance")
        # The exchange still burns per L12 on its actual inputs; the
        # difference vs the agent-charged burn is absorbed by the mint's
        # custody pool (§7.3/R17). >= 0: in_sum >= total_out and
        # compute_burn is monotone.
        absorbed = ledger_burn - burn

        change = in_sum - total_out - ledger_burn
        change_secret = change_hash = None
        exchange_outputs = list(specs)
        if change > 0:
            change_secret = new_secret()
            change_hash = ledger_key(change_secret)
            exchange_outputs.append(
                OutputSpec(amount_mc=change, secret_hash=change_hash)
            )
        inputs = [
            InputForm(
                kind="plain",
                token=Token(
                    mint_id=self.config.mint_id,
                    amount_mc=amt,
                    secret=b64u_decode(secret_b64u, expect_len=32),
                ),
            )
            for (_h, secret_b64u, amt) in selected
        ]
        idem = "sup-withdraw-" + b64u_encode(os.urandom(18))
        op_id = _new_id("pend")
        details = {
            "input_hashes": [h for (h, _s, _a) in selected],
            "change_hash": change_hash,  # None when no change output
            "total_out_mc": total_out,
            "burn_mc": burn,  # agent-charged: compute_burn(total_out)
            "ledger_burn_mc": ledger_burn,  # L12 burn on the actual inputs
            "absorbed_mc": absorbed,  # mint-absorbed difference (§7.3/R17)
            "gross_mc": gross,
            "t": now,
        }
        # Persist-before-send with no exceptions (§5.3): the change secret
        # is durable, the selected inputs are reserved (so a crash can
        # never wedge the selector on ledger-spent rows), and the staged
        # follow-up is committed BEFORE the exchange runs.
        self._txn()
        try:
            for h in details["input_hashes"]:
                self._conn.execute(
                    "UPDATE sup_custody SET state = 'reserved'"
                    " WHERE hash = ? AND state = 'unspent'",
                    (h,),
                )
            if change > 0:
                self._conn.execute(
                    "INSERT INTO sup_custody (hash, secret_b64u, amount_mc,"
                    " state) VALUES (?, ?, ?, 'pending')",
                    (change_hash, b64u_encode(change_secret), change),
                )
            self._conn.execute(
                "INSERT INTO sup_pending_ops (op_id, kind, agent_id,"
                " probe_hash, details_json) VALUES (?, 'withdraw', ?, ?, ?)",
                (op_id, principal[1], details["input_hashes"][0],
                 json.dumps(details, sort_keys=True)),
            )
            self._commit()
        except BaseException:
            self._rollback()
            raise
        try:
            self.ledger.exchange(idem, idem, inputs, outputs=exchange_outputs)
        except ExchangeRejected as exc:
            # Atomic rollback inside C04 — release the staged state too.
            self._unwind_withdraw(op_id, details)
            return 400, {"status": "rejected", "errors": exc.errors}
        self._finalize_withdraw(op_id, principal[1], details)
        return 200, {
            "status": "ok",
            "withdrawn_mc": total_out,
            "burn_mc": burn,
            "balance_mc": agent["balance_mc"] - gross,
        }

    def _finalize_withdraw(self, op_id, agent_id, details):
        """Post-exchange half of a withdrawal: consume the reserved inputs,
        activate the change entry, debit the gross, journal the pinned
        lines, clear the staged op. Called on the request path and by
        startup recovery."""
        self._txn()
        try:
            for h in details["input_hashes"]:
                self._conn.execute(
                    "UPDATE sup_custody SET state = 'spent'"
                    " WHERE hash = ? AND state = 'reserved'",
                    (h,),
                )
            if details["change_hash"] is not None:
                self._conn.execute(
                    "UPDATE sup_custody SET state = 'unspent'"
                    " WHERE hash = ? AND state = 'pending'",
                    (details["change_hash"],),
                )
            self._conn.execute(
                "UPDATE sup_agents SET balance_mc = balance_mc - ?"
                " WHERE agent_id = ?",
                (details["gross_mc"], agent_id),
            )
            # §7.3/R17: the ledger burned on the actual custody inputs but
            # the agent was only charged compute_burn(amount); the custody
            # pool absorbed the difference — record it so the invariant
            # custody == balances - absorbed stays auditable.
            self._conn.execute(
                "UPDATE sup_mint SET absorbed_mc = absorbed_mc + ?"
                " WHERE id = 1",
                (details.get("absorbed_mc", 0),),
            )
            # §6.1(7) pinned: withdrawal net of burn + burn as its own line;
            # both are debit-like, so the gross counts against caps. The
            # burn line is the agent-charged burn (§7.3/R17), not the
            # ledger-level burn on the mint-selected inputs.
            self._add_line(
                agent_id, details["t"], "withdrawal",
                details["total_out_mc"], None, "",
            )
            if details["burn_mc"] > 0:
                self._add_line(
                    agent_id, details["t"], "burn", details["burn_mc"],
                    None, "",
                )
            self._conn.execute(
                "DELETE FROM sup_pending_ops WHERE op_id = ?", (op_id,)
            )
            self._commit()
        except BaseException:
            self._rollback()
            raise

    def _unwind_withdraw(self, op_id, details):
        """Discard a staged withdrawal whose exchange did NOT commit:
        release the reserved inputs, drop the pending change secret,
        clear the staged op. No balance was touched."""
        self._txn()
        try:
            for h in details["input_hashes"]:
                self._conn.execute(
                    "UPDATE sup_custody SET state = 'unspent'"
                    " WHERE hash = ? AND state = 'reserved'",
                    (h,),
                )
            if details["change_hash"] is not None:
                self._conn.execute(
                    "DELETE FROM sup_custody WHERE hash = ?"
                    " AND state = 'pending'",
                    (details["change_hash"],),
                )
            self._conn.execute(
                "DELETE FROM sup_pending_ops WHERE op_id = ?", (op_id,)
            )
            self._commit()
        except BaseException:
            self._rollback()
            raise

    # -- startup reconciliation of the §5.3 bridge ------------------------

    def _recover_pending(self):
        """Reconcile staged deposit/withdraw ops left by a crash between
        the C04 exchange commit and the supervision follow-up commit.

        For each staged op, /v3/status of its probe hash tells whether the
        exchange committed: a deposit's custody output exists iff it did;
        a withdrawal's first custody input is spent iff it did. Committed
        ops roll FORWARD via the same finalize used on the request path;
        uncommitted ops roll BACK (discard staged secrets, release
        reservations). Either way no money is lost: every secret was
        durable before its exchange could commit (§5.1/§5.3)."""
        ops = self._conn.execute(
            "SELECT op_id, kind, agent_id, probe_hash, details_json"
            " FROM sup_pending_ops ORDER BY op_id"
        ).fetchall()
        for op_id, kind, agent_id, probe_hash, details_json in ops:
            details = json.loads(details_json)
            _t, results = self.ledger.status([probe_hash])
            probe_state = results[0]["state"]
            if kind == "deposit":
                if probe_state == "unknown":
                    # The exchange never committed; the depositor's tokens
                    # are untouched. Discard the staged custody secret.
                    self._txn()
                    try:
                        self._conn.execute(
                            "DELETE FROM sup_custody WHERE hash = ?"
                            " AND state = 'pending'",
                            (details["custody_hash"],),
                        )
                        self._conn.execute(
                            "DELETE FROM sup_pending_ops WHERE op_id = ?",
                            (op_id,),
                        )
                        self._commit()
                    except BaseException:
                        self._rollback()
                        raise
                else:
                    self._finalize_deposit(op_id, agent_id, details)
            elif kind == "withdraw":
                if probe_state == "spent":
                    self._finalize_withdraw(op_id, agent_id, details)
                else:
                    self._unwind_withdraw(op_id, details)
            else:  # pragma: no cover — unreachable by construction
                raise RuntimeError("unknown staged op kind: %r" % (kind,))


# ---------------------------------------------------------------------------
# HTTP mounting: supervision routes in front of the unchanged C06 handler.
# ---------------------------------------------------------------------------


class _SupHTTPServer(_MintHTTPServer):
    sup: _SupCore  # set by SupervisionServer.start


#: Largest request body these routes will read, in bytes. Content-Length
#: is attacker-controlled, so reading it before checking it IS the denial
#: of service: one request would otherwise make the mint allocate an
#: arbitrary amount of memory. The largest legitimate supervision body is
#: a deposit's token list (a few hundred bytes per token), so 1 MiB is
#: orders of magnitude of headroom. Enforced by C10's own reader on C10's
#: own routes; L17 keeps rate limiting out of the reference build, so this
#: cap is the only bound on what a single supervision request can ask the
#: mint to allocate. It bounds C10's routes only — Layer 0 keeps C06's
#: bound and C06's refusal, byte for byte (L13/B9).
#:
#: DERIVED from C06's ``MAX_BODY_BYTES`` rather than written out again: the
#: two were equal only by coincidence (``1 << 20`` here, ``1_048_576``
#: there) and nothing made them stay equal, so retuning one would have moved
#: the supervision routes' cap away from Layer 0's without a single test
#: noticing. Binding the value at IMPORT time is the point — this is one
#: constant with one source, not a live alias: the readers stay separate
#: (``_read_sup_json`` vs ``_Handler._read_json``) because C06 and C10
#: answer a refused body with different error envelopes by design, and the
#: C10 tests that prove C10 enforces its own bound do so by raising
#: ``mintapi.MAX_BODY_BYTES`` at runtime, which must not drag this value up
#: with it.
_MAX_BODY_BYTES = MAX_BODY_BYTES

#: THE FOLD, RE-EXPORTED, NOT RE-DEFINED. This module wrote it, and for one
#: round it was the only server that had it: the promotion that made framing
#: a shared function exported the mint's confusable-NAME regex and left this
#: fold behind, so 435 header names that ``_SupHandler`` refused were framed
#: by the mint, the operator GUI and the operator console — three servers
#: made LAXER by a round whose whole point was one rule. The fold now lives
#: in ``aicash.mintapi`` beside the regex, both halves are asked by
#: ``framing_verdict``, and this name is an alias so that
#: ``supervision._fold_header_name is mintapi._fold_header_name`` is a fact
#: a test can assert rather than a convention a reader must keep. It is
#: imported at the top of this module and used nowhere else here; what it
#: is doing in the import list is holding that assertion up.

#: Per-connection socket timeout, in seconds. socketserver applies a
#: handler's ``timeout`` in setup(); the stdlib default is None, i.e. no
#: timeout at all. Without one, a client that connects and then sends
#: nothing — or that finishes a request and holds the HTTP/1.1 keep-alive
#: connection idle — parks one ThreadingHTTPServer thread forever, so a
#: handful of sockets exhaust the server. Generous for any real request
#: against a local mint, short enough that stalled peers cannot pile up.
_HANDLER_TIMEOUT_S = 10.0


class _SupHandler(_Handler):
    """C06's handler + the Supervision Profile routes.

    Unmatched paths fall through to the parent, so every Layer 0 route
    stays authless and byte-identical to a plain C06 mint (L13/B9).
    """

    #: Applied by socketserver.StreamRequestHandler.setup() to the
    #: connection; a stalled or idle client is dropped, not hosted.
    timeout = _HANDLER_TIMEOUT_S

    # NO REQUEST-LINE RULE EITHER, AND ONE SHAPE IS STILL OPEN BENEATH IT.
    #
    # `parse_request`, `send_error` and `default_request_version` are the
    # parent's, untouched, and `test_the_profile_holds_no_request_line_
    # rule_of_its_own` asserts that by identity. That is the same "one
    # rule, one place" the framing note below records the cost of
    # breaking — three servers made laxer by a round that lifted the
    # narrower of two rules — so it is written down here rather than
    # discovered again.
    #
    # THE OPEN SHAPE, measured on this profile on 2026-09-17 and NOT
    # closed here on purpose: the wire spelling of HTTP/0.9 is a request
    # line and NOTHING ELSE — `GET /v3/mints\r\n`, no header block, no
    # blank line, because 0.9 has none. The parent computes its two-word
    # verdict off `raw_requestline` BEFORE `super().parse_request()` and
    # acts on it AFTER, and `super().parse_request()` reads the header
    # block — so a real 0.9 client blocks inside `parse_headers` until
    # this class's `timeout` fires and the socket is closed with ZERO
    # bytes written. Measured against a live supervision mint, in
    # parallel, one socket each: `GET /v3/mints\r\n` 10.02s / 0 bytes,
    # `GET /v3/agent/balance\r\n` 10.02s / 0 bytes, the bare-LF spelling
    # identical; `\r\n\r\n` before a well-formed request 0.01s / 0 bytes
    # (the parent tolerates ONE empty line, and the second one is a
    # request line it cannot parse). The terminated spellings the suites
    # drive — `GET /v3/mints\r\n\r\n` and `GET /v3/mints HTTP/0.9\r\n\r\n`
    # — are framed 400s in 0.01s, and they are the ones a client never
    # sends. `GET /v3/mints\r` (CR alone) measures the same but is NOT
    # this defect: a lone CR is not a line terminator, so no complete
    # request line has been asked yet and there is nothing to answer;
    # the only thing owed there is the bound, and the bound fires.
    #
    # THE FIX IS AN ORDERING CHANGE IN `mintapi._Handler.parse_request`
    # (act on the two-word verdict before calling `super()`; force
    # `request_version` to HTTP/1.1, `_refuse_transport(400,
    # "bad_version")`, close) plus a BOUNDED loop over leading empty
    # lines instead of the single one, still inside the existing
    # wall-clock deadline. Both belong there because all four servers in
    # this repository reach that class or copy it, and a `parse_request`
    # here would close the door on the ONE server that already inherits
    # every other transport refusal while the plain mint, the operator
    # console and the operator GUI stayed open — the exact drift shape
    # this file has paid for three times. `TheProfileInheritsTheRequest
    # LineRefusalsTest` drives the open spellings anyway and pins what IS
    # true of them here today: never a naked body, never a leak, and the
    # thread released at this class's budget. That ordering was patched
    # into the parent AT RUNTIME (no file edited) to check both halves of
    # this note: the 0.9 cells become framed 400s in 0.01-0.02s, the
    # requests behind leading empty lines are answered in 0.01s, and the
    # C10 request-line block passes unchanged in both worlds.

    # NO FRAMING RULE, AND NO NAME FOR ONE.
    #
    # `_sup_framing_is_unreadable` stood here: the VIEW preconditions (a
    # parser defect, an unread payload, an obs-fold), an RFC 7230 `token`
    # check on every parsed name, and a HARD FOLD of each name (lowercased,
    # every non-alphanumeric character dropped) refusing anything that
    # lands on `content-length` or `transfer-encoding` without being it.
    #
    # It was the WIDER of the two framing rules this repository contained,
    # and the round that lifted framing into one shared function lifted the
    # OTHER one — C06's confusable-name regex, which can only express
    # confusion at the single separator position. The measured consequence
    # was 435 header names (`Content-Length;`, `Transfer-Encoding.`,
    # `Con-tent-Length`, `Content-Length-`, `_Transfer-Encoding` …) that
    # this server refused and that the plain mint, the operator GUI and the
    # operator console all FRAMED, on every POST route and every anonymous
    # GET route. "One rule everywhere" had been achieved by exporting the
    # weaker answer to three servers that previously had no answer at all.
    #
    # So the token check and the fold moved INTO
    # `aicash.mintapi.framing_verdict`, asked there beside the regex, and
    # their union is what all four servers get. Then the method was left
    # behind as a one-line delegation with no caller — and a named method
    # with no caller, on the class that used to own the rule, is an
    # invitation to put the rule back. There is nothing here now. The
    # residual is unchanged and still honest: a header spelled as a clean
    # token, folding onto nothing HTTP calls framing today, that some
    # future hop nevertheless treats as framing. Nothing at any layer of
    # this process can see that one.

    # NO `_framed_body_length` OVERRIDE, AND THAT IS THE DELIVERABLE.
    #
    # One stood here. It read "if self._sup_framing_is_unreadable():
    # return None; return super()._framed_body_length(...)" and it was the
    # narrowing that made this server stricter than the three that import
    # the shared rule. It is gone because the narrowing is gone: C10's
    # token check and C10's hard fold are inside
    # ``aicash.mintapi.framing_verdict`` now, asked beside C06's
    # confusable-name regex, so the supervision profile, the plain mint,
    # the operator GUI and the operator console reach the SAME verdict on
    # the same bytes rather than four verdicts that happen to agree on the
    # inputs somebody thought to test.
    #
    # If a future C10 rule really is C10-only, override
    # ``_framing_verdict`` — the whole object, one method — so the
    # narrowing reaches ``must_close`` as well as ``length`` and the GET
    # guard cannot end up applying a different rule from the POST reader.
    # Do not re-add a second length computation anywhere in this class.

    def _read_sup_json(self):
        """Body reader for the SUPERVISION routes: C06's shape, C10's cap.

        Deliberately NOT an override of ``_Handler._read_json``. The
        inherited Layer 0 routes (``/v3/exchange``, ``/v3/status``,
        ``/admin/issue``) reach the body reader through C06's own
        ``do_POST``, and C06 answers a refused body with a §3.8 reason it
        chooses there (``bad_format`` vs ``over_batch_limit``, which carry
        different retry semantics per spec §3.8 and the retry rules at
        "Error semantics on invalid payment"). Overriding the shared name
        silently re-answered those Layer 0 calls with C10's reason, which
        breaks the invariant in this class's docstring — a supervision
        mint must be byte-identical to a plain C06 mint on Layer 0
        (L13/B9). A separate name keeps C10's cap on C10's routes and
        leaves the inherited ones untouched.

        Returns (parsed, ok). An over-size, truncated or unparseable body
        is (None, False), which ``_SupCore.dispatch`` already answers with
        this module's existing ``bad_format`` rejection (§6.1) — the cap
        introduces no new error vocabulary.

        Every refusal path sets ``close_connection``: the declared body is
        left unread, so the octets still on the wire would otherwise be
        parsed as the NEXT request on a keep-alive connection (framing
        desync — request N's body becomes request N+1's request line).
        ``_Handler._send`` turns the flag into a ``Connection: close``
        header, so the peer is told as well.

        Content-Length is not the only way a body arrives, which is the
        bug this reader had: a ``Transfer-Encoding: chunked`` POST declares
        no Content-Length, so the length defaulted to 0, the body read as
        empty, the route answered ``bad_format`` — and KEPT THE CONNECTION,
        with every octet of the chunked body still on the wire for the
        stdlib to parse as the next request line. A pipelined
        ``GET /v3/mints`` after the chunks got its own 200 on the same
        socket; behind the connection-reusing proxy DEPLOYMENT.md tells the
        operator to run, that response goes to whoever holds the pooled
        connection next. Nothing in this stack dechunks, so any
        transfer-coded body is unframable to us and the only safe answer is
        to refuse it and hang up. C06's reader carries the same rule for
        Layer 0 (and its own §3.8 reason); this one is C10's, in C10's
        vocabulary, for the same reason the byte cap is duplicated rather
        than shared — the two servers answer a refused body with different
        envelopes by design.

        A CONFLICTING Content-Length is the third door into the same
        desync and was open just as long: ``headers.get`` returns the
        first of a duplicated header, so a `2` followed by a `46` read
        two octets and left forty-four on the wire to be parsed as the
        next request line. Refused by the shared rule for the same reason
        as a chunked body — a length two parties compute differently is
        not a length.

        NOTHING IN HERE COMPUTES A LENGTH ANY MORE. Both the yes/no and
        the number come from the one shared rule, so this reader cannot
        size a body the rule would not, which is the failure mode a second
        local computation exists to have. All this method owns is C10's
        byte cap and C10's way of saying no.
        """
        if self._body_framing_is_unreadable():
            # The one shared verdict. One server, one socket: Layer 0 and
            # the profile must agree byte for byte on which requests are
            # unframable, and two separately-worded copies of that rule are
            # how they stop agreeing. Only the ANSWER is C10's — refuse in
            # C10's vocabulary and hang up — which is the same division the
            # byte cap draws.
            self.close_connection = True
            return None, False
        # THE LENGTH COMES FROM THE VERDICT TOO, and this line is the
        # reason to say so loudly: what stood here was
        # `self.headers.get_all("Content-Length")` plus a bare `int()` —
        # the exact two constructs `framing_verdict` exists to replace,
        # surviving in the reader that actually pulls bytes off the socket
        # on the profile's twelve POST routes, directly beneath a docstring
        # explaining that a second local copy is how the two halves of this
        # server drifted apart. It agreed with the shared rule; agreeing
        # today is what every copy in this file's history did. Not None:
        # the guard above IS `... is None`.
        length = self._framed_body_length(body_expected=True)
        if length > _MAX_BODY_BYTES:
            # Refuse BEFORE allocating. (A negative or non-numeric length
            # needs no clause: the shared rule only ever returns a
            # non-negative int, and has no length at all for
            # `Content-Length: 2, 46` or `+46`.)
            self.close_connection = True
            return None, False
        try:
            raw = self.rfile.read(length) if length > 0 else b""
        except OSError:
            # The socket timeout above fired mid-body (slowloris), or the
            # peer vanished. Either way the framing is gone: stop reading
            # and release the connection — the parked thread is the
            # resource being protected. TimeoutError is an OSError.
            self.close_connection = True
            return None, False
        if len(raw) != length:  # client hung up before sending it all
            self.close_connection = True
            return None, False
        try:
            return json.loads(raw.decode("utf-8")), True
        except (UnicodeDecodeError, ValueError, RecursionError):
            # json.loads says "malformed" in three ways and only one was
            # caught here:
            #   * json.JSONDecodeError — a ValueError subclass, syntax;
            #   * a bare ValueError — CPython's int-string digit limit, so
            #     an operator_name of 5,000 digits is VALID JSON that
            #     raises out of int();
            #   * RecursionError — `[[[[...` a hundred thousand deep is a
            #     200 KB body, well inside the cap, that blows the C
            #     parser's stack.
            # The last two escaped this reader, reached _dispatch_sup's
            # blanket ``except Exception`` and answered an unenumerated
            # 500 to an ANONYMOUS caller (the body is read before auth is
            # decided, so the admin gate does not shield the route). All
            # three are permanently bad bytes, which is what bad_format
            # means, and C10's doc says every POST route can answer
            # bad_format for a mis-typed body. C06's reader was fixed for
            # the identical shapes this round; this is the same fix in the
            # sibling reader, kept separate for the reason in the
            # docstring above.
            # The whole declared body WAS consumed here, so the stream is
            # still framed: this one may keep the connection alive.
            return None, False

    def _dispatch_sup(self, method: str, path: str) -> None:
        self._route = path  # fixed route pattern; never logs bodies/keys
        try:
            if method == "POST":
                body, ok = self._read_sup_json()
                params = {}
            else:
                body, ok = None, True
                query = urllib.parse.urlsplit(self.path).query
                params = {
                    k: v[-1]
                    for k, v in urllib.parse.parse_qs(query).items()
                }
            code, obj = self.server.sup.dispatch(
                method,
                path,
                body,
                ok,
                self.headers.get("Authorization"),
                params,
                self.headers.get("X-Admin-Token"),
                self.headers.get("X-Registration-Token"),
            )
        except Exception:
            # Anything raised while PRODUCING the answer is an internal
            # fault and owes the caller a 500 — TimeoutError included, so
            # a timeout inside dispatch is never mistaken for a dead peer
            # and silently dropped. Socket timeouts cannot arrive here:
            # _read_sup_json catches OSError (TimeoutError's base) itself.
            self._safe_500()
            return
        try:
            self._send(code, obj)
        except TimeoutError:
            # Our own socket timeout fired while WRITING: the peer stopped
            # reading. There is nowhere to put a 500, so drop the
            # connection — the parked thread is the resource protected.
            self.close_connection = True
        except Exception:
            self._safe_500()

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if ("GET", path) in _ROUTES:
            # Same framing rule C06's do_GET applies, applied here because
            # this branch RETURNS before reaching it: a supervision GET
            # (/v3/operator/statement, /v3/agent/balance) never reads a
            # body either, so a declared one would be left on the wire and
            # parsed as the next request line on a keep-alive connection.
            # Answering it and then hanging up is the only safe framing —
            # a guard that covered Layer 0 alone would leave the profile's
            # own routes smuggleable through the same socket.
            # ONE call, not two. A second `if self._sup_framing_is_
            # unreadable(): self.close_connection = True` stood here, and
            # it was already reached through the line above — the guard
            # asks `FramingVerdict.must_close`, which is true for every
            # unframable request. A hand-maintained duplicate of a decision
            # already on the same path is the shape this round exists to
            # remove, even when it agrees.
            self._close_if_body_goes_unread()
            self._dispatch_sup("GET", path)
            return
        super().do_GET()

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if ("POST", path) in _ROUTES:
            self._dispatch_sup("POST", path)
            return
        super().do_POST()


class SupervisionServer(MintServer):
    """A C06 mint with the Supervision Profile mounted.

    The descriptor's ``profiles`` gains ``"supervision"`` automatically
    (C10 requirement 8) — the config passed in need not list it.
    """

    def __init__(self, config: MintConfig, ledger: Ledger,
                 registration_token=REGISTRATION_INHERITS_ISSUANCE):
        if "supervision" not in config.profiles:
            config = dataclasses.replace(
                config, profiles=tuple(config.profiles) + ("supervision",)
            )
        credential, source = _resolve_registration_credential(
            config, registration_token
        )
        super().__init__(config, ledger)
        self.sup = _SupCore(config, ledger, self._core, credential)
        #: The credential ``POST /v3/operator/register`` requires, or None
        #: when the route is open or disabled. On a mint built
        #: ADMIN_ISSUANCE_DISABLED this is a freshly generated secret and
        #: this attribute is the ONLY place it exists — it is deliberately
        #: never logged, so a launcher (see run_mint.py --supervision) has
        #: to read it from here and put it somewhere the operator can find
        #: it, the same way C06's generated issuance credential is handled.
        self.registration_token = credential if isinstance(credential, str) else None
        #: "inherited" | "inherited-open" | "generated" | "explicit-token"
        #: | "explicit-mode" — how the line above was decided, for a
        #: launcher that must tell the operator where to look.
        self.registration_source = source
        # Discoverable, not silent: /v3/operator/register stopped being
        # authless, and an operator whose bootstrap script starts getting
        # 401s should be able to learn why from the mint it started rather
        # than from a diff. Same shape as C06's own issuance warning — the
        # alarming state is announced loudly, the safe ones on INFO — and
        # it never carries the credential itself.
        if credential is REGISTRATION_OPEN:
            logger.warning(
                "mint %s: POST /v3/operator/register is UNAUTHENTICATED"
                " (%s) — anyone who can reach this port can register an"
                " operator, and an agent under it is outside every other"
                " operator's caps, freeze and flags",
                config.mint_id,
                "admin_token=ADMIN_ISSUANCE_OPEN"
                if source == "inherited-open"
                else "registration_token=REGISTRATION_OPEN",
            )
        elif credential is REGISTRATION_DISABLED:
            logger.info(
                "mint %s: POST /v3/operator/register is DISABLED"
                " (registration_token=REGISTRATION_DISABLED) — provision"
                " operators in process with"
                " SupervisionServer.provision_operator()", config.mint_id,
            )
        elif source == "generated":
            logger.info(
                "mint %s: issuance is ADMIN_ISSUANCE_DISABLED, so POST"
                " /v3/operator/register is gated on a GENERATED credential"
                " instead — registering an operator is not the power to"
                " issue credits, and this route used to die with it. Read"
                " the credential from SupervisionServer.registration_token"
                " (it is never logged) and present it in"
                " X-Registration-Token", config.mint_id,
            )
        elif source == "explicit-token":
            logger.info(
                "mint %s: POST /v3/operator/register requires this mint's"
                " own registration credential in X-Registration-Token,"
                " separate from the issuance credential", config.mint_id,
            )
        else:
            logger.info(
                "mint %s: POST /v3/operator/register requires the mint's"
                " X-Admin-Token credential", config.mint_id,
            )

    def provision_operator(self, operator_name: str):
        """Create an operator out of band. Returns ``(id, key)``.

        The bootstrap path for a mint whose HTTP registration route is
        disabled — and the mechanism this profile's documentation promised
        and did not have. In process, so it takes no credential: the caller
        is holding the mint.
        """
        return self.sup.provision_operator(operator_name)

    def start(self, port: int = 0, host: str = "127.0.0.1") -> int:
        """Bind and serve; same contract and signature as MintServer.start.

        ``port``/``host`` exist because this override used to take neither,
        so a launcher could not put the profile on a fixed published
        address — it could only take the ephemeral port this class chose.
        Defaults unchanged (127.0.0.1:0), so every existing ``start()``
        call means exactly what it meant.

        Including the single-writer claim. This class binds its own socket
        instead of calling ``super().start()``, which used to mean the
        ``flock`` on the ledger was never taken before the bind; the claim
        is lazy and idempotent, so ``_Core.descriptor`` took it at the first
        fetch and a supervision mint alone on its ledger still served
        correctly. What was lost was FAIL-FAST: between this bind and the
        first descriptor, another process could take the claim, and from
        then on this mint answers every descriptor with a 500 forever —
        bound, serving Layer 0 and the profile, and unable to sign a
        snapshot — instead of having refused to start. Claimed here, in the
        same place and the same order as ``MintServer.start``.
        """
        if self._httpd is not None:
            raise RuntimeError("server already started")
        self._core._claim_single_writer()
        self._httpd = _SupHTTPServer((host, port), _SupHandler)
        self._httpd.core = self._core
        self._httpd.sup = self.sup
        self._thread = threading.Thread(
            target=self._httpd.serve_forever,
            name="aicash-supervision",
            daemon=True,
        )
        self._thread.start()
        return self._httpd.server_address[1]


def make_supervision_mint(
    config: MintConfig,
    db_path: str,
    clock=system_clock,
    registration_token=REGISTRATION_INHERITS_ISSUANCE,
):
    """C06's ``make_mint`` for a supervised mint. Returns (server, ledger).

    The Ledger is built from the config's own fields, exactly as
    ``make_mint`` builds it, so the values the descriptor advertises are
    the values the ledger enforces. That duplication is safe by
    construction rather than by care: ``MintServer.__init__`` (which this
    server's constructor runs) raises on any config/ledger disagreement
    across those same four fields, so a copy that drifts cannot start.
    """
    ledger = Ledger(
        db_path,
        clock,
        config.burn_policy,
        recovery_window_ms=config.recovery_window_ms,
        max_lock_expiry_ms=config.max_lock_expiry_ms,
        burn_policy_next=config.burn_policy_next,
    )
    server = SupervisionServer(
        config, ledger, registration_token=registration_token
    )
    return server, ledger
