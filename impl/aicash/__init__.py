"""AICash v0.4 reference implementation.

Spec: ../../aicash-spec-v0.4.md · Quickstart: ../../README.md

The integrator-facing surface is re-exported here so a first integration is
``from aicash import Wallet, make_mint, MintConfig, BurnPolicy, ...`` rather
than a scavenger hunt across modules.

What "the surface" means, precisely -- the README states it as a promise
("everything an integrator needs ... is re-exported from the package root"),
and PackageRootSurfaceTest in impl/tests/test_c06_mintapi.py enforces it:

* the WHOLE public API of every integrator-facing module: ``aicash.mintapi``
  (build a mint), ``aicash.wallet`` (pay and get paid), ``aicash.envelope``
  (the §9.5 wire object) and ``aicash.supervision``. Nothing in those
  modules' ``__all__`` is a member an embedder is meant to be kept away
  from, so the root mirrors each of them entire and the test fails on the
  next name added to any of them -- not just to mintapi;
* every type a re-exported call hands back OR demands (``parse_token`` ->
  ``Token``, ``parse_envelope`` -> ``Envelope``), so a caller can annotate a
  result, isinstance-check it, and name an argument type without importing a
  submodule;
* every exception a re-exported call can raise, so ``except`` is writable
  from the same import line as the call. That includes
  ``lockeval.LockError``: ``Ledger.exchange`` lets it out whenever a stored
  lock digest is unreadable (a damaged or hand-edited ``mint.db``), because
  ledgerstore guards ``validate_lock`` on the way in but not ``evaluate`` on
  the way out. Deliberate omissions go in
  ``PackageRootSurfaceTest.EXCEPTIONS_DELIBERATELY_OFF_ROOT``, and the
  reason on each one has to be re-caused before it is believed: the entry
  that used to sit there claimed ledgerstore caught ``LockError``
  internally, and a corrupted ``lock_preimage_hash`` row disproves it in
  four lines. ``test_lockerror_really_does_escape_to_a_root_only_caller``
  now causes it on every run.

A name that satisfies one of those and is missing is not a style nit. That
is how ``ADMIN_ISSUANCE_DISABLED`` -- the one name that exists to stop an
embedder shipping an open mint -- came to raise ImportError at the root the
docstring above points them at.

Issuance, since the root is where an embedder starts: ``MintConfig`` has NO
default for ``admin_token``. Saying nothing about it raises ValueError at
build time, and ``admin_token=None`` is rejected by name. The three ways to
build are a real credential, ``ADMIN_ISSUANCE_DISABLED``, or -- tests and
throwaway sandboxes only -- ``ADMIN_ISSUANCE_OPEN``.

Known-stale neighbours (each pinned by a test here, so the note cannot
outlive the defect, and cannot be dropped while the defect stands):

* one name is claimed by two modules with two different functions behind
  it: ``make_dispute_record`` is in ``aicash.escrow.__all__`` AND in
  ``aicash.receipts.__all__``, and their signatures differ (escrow takes
  ``evidence``, receipts takes ``evidence_hash``). The root can only bind
  one; it binds the ``receipts`` one. Escrow callers must spell it
  ``from aicash.escrow import make_dispute_record``. Renaming either is a
  change to those modules, not to this file.
"""
from aicash.burncalc import BurnPolicy, PolicyError, compute_burn
from aicash.clock import FakeClock, system_clock
from aicash.escrow import (
    Arbiter,
    CommitThenAccept,
    DeadlineError,
    EscrowError,
    EscrowPayee,
    EscrowPayer,
    FundingInfo,
    FundingInvalid,
    LateReveal,
    QuorumNotMet,
    RevealInvalid,
    compute_deadlines,
    milestone_schedule,
    rung_composition,
)
from aicash.channels import (
    CHAIN_TAG,
    ChannelError,
    ChannelInfo,
    ChannelInvalid,
    ChannelPayee,
    ChannelPayer,
    DrawInvalid,
    derive_chain,
)
from aicash.envelope import (
    ERROR_KINDS,
    ERROR_REASONS,
    ChannelDraw,
    Envelope,
    EnvelopeError,
    build_envelope,
    parse_envelope,
    payment_error,
)
from aicash.ledgerstore import ExchangeRejected, Ledger, OutputSpec
from aicash.lockeval import LockError
from aicash.mintapi import (
    ADMIN_ISSUANCE_DISABLED,
    ADMIN_ISSUANCE_OPEN,
    FRAMING_REASONS,
    FramingVerdict,
    MintConfig,
    MintServer,
    framing_verdict,
    make_mint,
)
from aicash.receipts import (
    make_dispute_record,
    make_receipt,
    verify_dispute,
    verify_receipt,
)
from aicash.signing import generate_keypair, sign_obj, verify_obj
from aicash.supervision import SupervisionServer
from aicash.swap import SwapParty, SwapResult, QuoteRefused, SwapError, compute_margin, run_swap
from aicash.tokencodec import (
    MINT_ID_RE,
    Token,
    TokenError,
    canonical_json,
    format_token,
    ledger_key,
    new_secret,
    parse_token,
)
from aicash.wallet import (
    InsufficientFunds,
    MintClient,
    MintRejected,
    MintUnavailable,
    PaymentInvalid,
    Wallet,
)

__all__ = [
    # units / policy
    "BurnPolicy", "compute_burn", "PolicyError",
    # clocks (L17)
    "FakeClock", "system_clock",
    # mint (ADMIN_ISSUANCE_* are how a mint is built at all — see MintConfig)
    "MintConfig", "MintServer", "make_mint", "Ledger", "OutputSpec",
    "ADMIN_ISSUANCE_DISABLED", "ADMIN_ISSUANCE_OPEN",
    "ExchangeRejected", "SupervisionServer",
    # the ONE request-framing rule every HTTP server in this repository
    # asks — exported because it is shared, not because a mint needs it
    # spelled from the root (see aicash.mintapi.__all__)
    "framing_verdict", "FramingVerdict", "FRAMING_REASONS",
    # Ledger.exchange raises this one out of a corrupt lock row (see docstring)
    "LockError",
    # client + its exceptions (error handling is part of the integration surface)
    "Wallet", "MintClient",
    "MintRejected", "MintUnavailable", "PaymentInvalid", "InsufficientFunds",
    # tokens / crypto
    "format_token", "parse_token", "new_secret", "ledger_key", "canonical_json",
    "Token", "TokenError", "MINT_ID_RE",
    "generate_keypair", "sign_obj", "verify_obj",
    # layer 2 — channels
    "ChannelPayer", "ChannelPayee", "ChannelInfo", "derive_chain", "CHAIN_TAG",
    "ChannelError", "ChannelInvalid", "DrawInvalid",
    # layer 2 — escrow
    "EscrowPayer", "EscrowPayee", "Arbiter", "FundingInfo",
    "CommitThenAccept", "compute_deadlines", "rung_composition",
    # `milestone_schedule` joined the surface when verify_funding started
    # REQUIRING the payee's own offer: an integrator that must pass
    # `milestones=` needs the helper that reads one without importing
    # `aicash.escrow` directly (README: "you should not need to read
    # implementation source to integrate").
    "milestone_schedule",
    "EscrowError", "DeadlineError", "FundingInvalid", "QuorumNotMet", "RevealInvalid", "LateReveal",
    # layer 2 — records / envelope
    "make_receipt", "verify_receipt", "make_dispute_record", "verify_dispute",
    "build_envelope", "parse_envelope", "payment_error",
    "Envelope", "ChannelDraw", "EnvelopeError",
    # the §3.8 vocabulary payment_error enforces — a caller validating
    # before the call, or rendering the legal set in a 402, needs these
    "ERROR_KINDS", "ERROR_REASONS",
    # layer 3 — swaps
    "SwapParty", "SwapResult", "compute_margin", "run_swap", "QuoteRefused", "SwapError",
]
