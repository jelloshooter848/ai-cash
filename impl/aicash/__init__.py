"""AICash v0.4 reference implementation.

Spec: ../../aicash-spec-v0.4.md · Quickstart: ../../README.md

The integrator-facing surface is re-exported here so a first integration is
``from aicash import Wallet, make_mint, MintConfig, BurnPolicy, ...`` rather
than a scavenger hunt across modules. The component docs (../../components/
CNN-*.md "Public API" blocks) are the per-module API reference.
"""

from aicash.burncalc import BurnPolicy, compute_burn
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
from aicash.envelope import build_envelope, parse_envelope, payment_error
from aicash.ledgerstore import ExchangeRejected, Ledger, OutputSpec
from aicash.mintapi import MintConfig, MintServer, make_mint
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
    "BurnPolicy", "compute_burn",
    # clocks (L17)
    "FakeClock", "system_clock",
    # mint
    "MintConfig", "MintServer", "make_mint", "Ledger", "OutputSpec",
    "ExchangeRejected", "SupervisionServer",
    # client + its exceptions (error handling is part of the integration surface)
    "Wallet", "MintClient",
    "MintRejected", "MintUnavailable", "PaymentInvalid", "InsufficientFunds",
    # tokens / crypto
    "format_token", "parse_token", "new_secret", "ledger_key", "canonical_json",
    "TokenError", "MINT_ID_RE",
    "generate_keypair", "sign_obj", "verify_obj",
    # layer 2 — channels
    "ChannelPayer", "ChannelPayee", "ChannelInfo", "derive_chain", "CHAIN_TAG",
    "ChannelError", "ChannelInvalid", "DrawInvalid",
    # layer 2 — escrow
    "EscrowPayer", "EscrowPayee", "Arbiter", "FundingInfo",
    "CommitThenAccept", "compute_deadlines", "rung_composition",
    "EscrowError", "DeadlineError", "FundingInvalid", "QuorumNotMet", "RevealInvalid", "LateReveal",
    # layer 2 — records / envelope
    "make_receipt", "verify_receipt", "make_dispute_record", "verify_dispute",
    "build_envelope", "parse_envelope", "payment_error",
    # layer 3 — swaps
    "SwapParty", "SwapResult", "compute_margin", "run_swap", "QuoteRefused", "SwapError",
]
