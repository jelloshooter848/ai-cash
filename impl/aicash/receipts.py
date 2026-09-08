"""C12 — receipts: Layer 2 record formats (spec §10.1, §10.2, §10.3, §9.5, §3.8).

Bilateral receipts, dispute-outcome records, delivery attestations, the
payment request envelope with its 402 error object.  Pure data + signatures;
no mint interaction, no I/O, no clock.

Schema strictness (component requirement 1, documented):
  * Every schema carries ``v: 4`` and exactly the §10 field sets.
  * ``parse_envelope`` is STRICT: unknown fields in the ``aicash`` object or
    in ``channel_draw`` are rejected.  Forward compatibility is a v0.4
    non-goal.  (An absent ``channel_draw`` key is treated as ``null`` — the
    schema marks the field nullable; see open questions.)
  * ``verify_*`` functions do not strip or reject unknown fields: whatever
    the document carries is part of the signed bytes, so any field added
    after signing breaks the signature.  Unknown fields are therefore
    "preserved on verify" — covered, never silently dropped.

Multi-signature rule (component requirement 2): documents store
``signatures: {role: sig}`` and each role's signature covers the canonical
JSON (C01, §3.3-pinned) of the document WITHOUT the ``signatures`` object
entirely.  Counter-signing therefore never invalidates an earlier
signature, and signing order is irrelevant.

Receipt refusal is legitimate (§10.1): ``receipt_status`` reports which
signatures are present in neutral vocabulary
(``unsigned/payer_only/payee_only/complete``) without judgment language.
"""

from __future__ import annotations

import re
from typing import NamedTuple

from aicash.tokencodec import (
    Token,
    TokenError,
    b64u_decode,
    b64u_encode,
    canonical_json,
    parse_token,
)
from aicash.signing import sign_raw, verify_raw

__all__ = [
    "SCHEMA_V",
    "DECISIONS",
    "ERROR_REASONS",
    "ERROR_KINDS",
    "EnvelopeError",
    "ChannelDraw",
    "Envelope",
    "make_receipt",
    "sign_receipt",
    "verify_receipt",
    "receipt_status",
    "make_dispute_record",
    "sign_dispute",
    "verify_dispute",
    "make_attestation",
    "sign_attestation",
    "verify_attestation",
    "build_envelope",
    "parse_envelope",
    "payment_error",
]

SCHEMA_V = 4

DECISIONS = frozenset({"released", "refunded", "split"})

#: §3.8 reason vocabulary, verbatim.
ERROR_REASONS = frozenset(
    {
        "unknown",
        "spent",
        "lock_preimage_invalid",
        "lock_expired",
        "lock_not_expired",
        "refund_invalid",
        "bad_witness_length",
        "amount_mismatch",
        "output_exists",
        "bad_format",
        "over_batch_limit",
    }
)

#: §3.8/§3.3 enumerate offending input indices (step 2) and output indices
#: (step 3); the worked example shows kind "input".
ERROR_KINDS = frozenset({"input", "output"})

_PARTY_ROLES = frozenset({"payer", "payee"})
_ATTEST_ROLES = frozenset({"worker", "counterparty"})

# Same mint-id shape C01 pins for token strings (§3.1).
_MINT_ID_RE = re.compile(r"^[a-z0-9-]{1,64}$")

_RECEIPT_FIELDS = frozenset(
    {
        "v",
        "payer_id",
        "payee_id",
        "amount_mc",
        "mint_id",
        "token_hashes",
        "timestamp",
        "memo",
        "purpose",
        "signatures",
    }
)
_DISPUTE_FIELDS = frozenset(
    {
        "v",
        "job_id",
        "milestone",
        "claimed_mc",
        "released_mc",
        "decision",
        "arbiter_ids",
        "evidence_hash",
        "timestamp",
        "votes",
        "signatures",
        "refusals",
    }
)
_ATTEST_FIELDS = frozenset(
    {"v", "worker_id", "counterparty_id", "tasks", "total_mc", "period", "signatures"}
)


# --- small validators ---------------------------------------------------------


def _req_str(value, name: str, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise ValueError("%s must be a string" % name)
    if not allow_empty and value == "":
        raise ValueError("%s must be non-empty" % name)
    return value


def _req_int(value, name: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("%s must be an integer" % name)
    if value < minimum:
        raise ValueError("%s must be >= %d" % (name, minimum))
    return value


def _req_b64u32(value, name: str) -> str:
    _req_str(value, name)
    try:
        b64u_decode(value, expect_len=32)
    except TokenError as exc:
        raise ValueError("%s must be base64url of 32 bytes: %s" % (name, exc))
    return value


def _req_mint_id(value, name: str = "mint_id") -> str:
    _req_str(value, name)
    if not _MINT_ID_RE.fullmatch(value):
        raise ValueError("invalid %s" % name)
    return value


# --- shared signature machinery ----------------------------------------------


def _doc_bytes(doc: dict) -> bytes:
    """Canonical JSON of the document with the ``signatures`` object
    excluded entirely (component requirement 2)."""
    if not isinstance(doc, dict):
        raise ValueError("document must be a dict")
    return canonical_json({k: v for k, v in doc.items() if k != "signatures"})


def _add_signature(doc: dict, key: bytes, role: str) -> dict:
    """Return a NEW dict with signatures[role] set; accumulates, never
    mutates the input, never disturbs other roles' signatures."""
    sig = b64u_encode(sign_raw(_doc_bytes(doc), key))
    sigs = doc.get("signatures")
    new_sigs = dict(sigs) if isinstance(sigs, dict) else {}
    new_sigs[role] = sig
    out = dict(doc)
    out["signatures"] = new_sigs
    return out


def _check_one_signature(doc: dict, role: str, public: bytes) -> bool:
    """True iff signatures[role] exists and verifies over the doc bytes."""
    sigs = doc.get("signatures")
    if not isinstance(sigs, dict):
        return False
    sig_str = sigs.get(role)
    if not isinstance(sig_str, str):
        return False
    try:
        sig = b64u_decode(sig_str, expect_len=64)
    except TokenError:
        return False
    return verify_raw(_doc_bytes(doc), sig, public)


# ==============================================================================
# §10.1 — Bilateral signed receipts
# ==============================================================================


def _validate_receipt_body(r: dict) -> None:
    """Raise ValueError unless r carries a valid §10.1 body (signatures not
    inspected here)."""
    if not isinstance(r, dict):
        raise ValueError("receipt must be a dict")
    if r.get("v") != SCHEMA_V:
        raise ValueError("receipt v must be %d" % SCHEMA_V)
    _req_str(r.get("payer_id"), "payer_id")
    _req_str(r.get("payee_id"), "payee_id")
    _req_int(r.get("amount_mc"), "amount_mc", minimum=1)
    _req_mint_id(r.get("mint_id"))
    hashes = r.get("token_hashes")
    if not isinstance(hashes, list) or not hashes:
        raise ValueError("token_hashes must be a non-empty list")
    for i, h in enumerate(hashes):
        _req_b64u32(h, "token_hashes[%d]" % i)
    _req_int(r.get("timestamp"), "timestamp", minimum=0)
    _req_str(r.get("memo"), "memo", allow_empty=True)
    _req_str(r.get("purpose"), "purpose", allow_empty=True)


def make_receipt(
    payer_id: str,
    payee_id: str,
    amount_mc: int,
    mint_id: str,
    token_hashes: list,
    timestamp: int,
    memo: str,
    purpose: str,
) -> dict:
    """Build an unsigned §10.1 receipt (signatures: {})."""
    r = {
        "v": SCHEMA_V,
        "payer_id": payer_id,
        "payee_id": payee_id,
        "amount_mc": amount_mc,
        "mint_id": mint_id,
        "token_hashes": list(token_hashes) if isinstance(token_hashes, list) else token_hashes,
        "timestamp": timestamp,
        "memo": memo,
        "purpose": purpose,
        "signatures": {},
    }
    _validate_receipt_body(r)
    return r


def sign_receipt(r: dict, key: bytes, role: str) -> dict:
    """Sign as "payer" or "payee"; counter-signing accumulates.  Returns a
    new dict; the input is never mutated."""
    _validate_receipt_body(r)
    if role not in _PARTY_ROLES:
        raise ValueError('receipt role must be "payer" or "payee"')
    return _add_signature(r, key, role)


def verify_receipt(r: dict, payer_pub: bytes, payee_pub: bytes) -> bool:
    """Total: True iff r is a well-formed v4 receipt carrying BOTH the payer
    and payee signatures, each valid over the document without its
    ``signatures`` object.  Half-signed receipts return False (use
    ``receipt_status`` for a judgment-free view).  Never raises."""
    try:
        _validate_receipt_body(r)
    except Exception:
        return False
    try:
        return _check_one_signature(r, "payer", payer_pub) and _check_one_signature(
            r, "payee", payee_pub
        )
    except Exception:
        return False


def receipt_status(r: dict) -> str:
    """Which signatures are present: "unsigned" | "payer_only" |
    "payee_only" | "complete".  Presence only — no validity judgment and no
    judgment language: refusal to sign is a first-class posture (§10.1)."""
    sigs = r.get("signatures") if isinstance(r, dict) else None
    if not isinstance(sigs, dict):
        sigs = {}
    has_payer = isinstance(sigs.get("payer"), str)
    has_payee = isinstance(sigs.get("payee"), str)
    if has_payer and has_payee:
        return "complete"
    if has_payer:
        return "payer_only"
    if has_payee:
        return "payee_only"
    return "unsigned"


# ==============================================================================
# §10.2 — Dispute-outcome record
# ==============================================================================


def _validate_dispute_body(d: dict) -> None:
    if not isinstance(d, dict):
        raise ValueError("dispute record must be a dict")
    if d.get("v") != SCHEMA_V:
        raise ValueError("dispute v must be %d" % SCHEMA_V)
    _req_str(d.get("job_id"), "job_id")
    _req_int(d.get("milestone"), "milestone", minimum=0)
    claimed = _req_int(d.get("claimed_mc"), "claimed_mc", minimum=1)
    released = _req_int(d.get("released_mc"), "released_mc", minimum=0)
    decision = d.get("decision")
    if decision not in DECISIONS:
        raise ValueError('decision must be one of "released", "refunded", "split"')
    # Requirement 3: split requires 0 < released_mc < claimed_mc.  The
    # non-split decisions are pinned to their consistent amounts (a
    # "released" record releasing less than claimed is a split in disguise).
    if decision == "split":
        if not (0 < released < claimed):
            raise ValueError("split requires 0 < released_mc < claimed_mc")
    elif decision == "released":
        if released != claimed:
            raise ValueError('decision "released" requires released_mc == claimed_mc')
    else:  # refunded
        if released != 0:
            raise ValueError('decision "refunded" requires released_mc == 0')
    arbiter_ids = d.get("arbiter_ids")
    if not isinstance(arbiter_ids, list) or not arbiter_ids:
        raise ValueError("arbiter_ids must be a non-empty list")
    seen = set()
    for i, a in enumerate(arbiter_ids):
        _req_str(a, "arbiter_ids[%d]" % i)
        if a in _PARTY_ROLES:
            raise ValueError('arbiter_ids may not use the reserved role names "payer"/"payee"')
        if a in seen:
            raise ValueError("duplicate arbiter_id %r" % a)
        seen.add(a)
    _req_b64u32(d.get("evidence_hash"), "evidence_hash")
    _req_int(d.get("timestamp"), "timestamp", minimum=0)
    votes = d.get("votes")
    if not isinstance(votes, list):
        raise ValueError("votes must be a list")
    for i, vote in enumerate(votes):
        if not isinstance(vote, dict):
            raise ValueError("votes[%d] must be a dict" % i)
    refusals = d.get("refusals")
    if not isinstance(refusals, list):
        raise ValueError("refusals must be a list")
    seen_ref = set()
    for i, party in enumerate(refusals):
        if party not in _PARTY_ROLES:
            raise ValueError('refusals entries must be "payer" or "payee"')
        if party in seen_ref:
            raise ValueError("duplicate refusal %r" % party)
        seen_ref.add(party)


def make_dispute_record(
    job_id: str,
    milestone: int,
    claimed_mc: int,
    released_mc: int,
    decision: str,
    arbiter_ids: list,
    evidence_hash: str,
    timestamp: int,
    votes: list,
    refusals: list = (),
) -> dict:
    """Build an unsigned §10.2 dispute-outcome record.

    ``votes`` is the signed-vote set the panel exchanged (L15/§9.3: signed
    vote records are mandatory panel evidence); entries are opaque dicts and
    become signed content of the record.  ``refusals`` (optional) names the
    parties who declined to counter-sign; it is part of the signed content,
    so the arbiter states the refusal when it creates and signs the record.
    """
    d = {
        "v": SCHEMA_V,
        "job_id": job_id,
        "milestone": milestone,
        "claimed_mc": claimed_mc,
        "released_mc": released_mc,
        "decision": decision,
        "arbiter_ids": list(arbiter_ids) if isinstance(arbiter_ids, list) else arbiter_ids,
        "evidence_hash": evidence_hash,
        "timestamp": timestamp,
        "votes": list(votes) if isinstance(votes, list) else votes,
        "signatures": {},
        "refusals": list(refusals),
    }
    _validate_dispute_body(d)
    # Fail fast on votes that cannot be canonicalized (they are signed content).
    try:
        canonical_json(d["votes"])
    except TokenError as exc:
        raise ValueError("votes are not canonical-JSON representable: %s" % exc)
    return d


def sign_dispute(d: dict, key: bytes, role: str) -> dict:
    """Sign as "payer", "payee", or one of the record's arbiter_ids.
    A role listed in ``refusals`` cannot sign (the record says it refused).
    Returns a new dict; accumulates like sign_receipt."""
    _validate_dispute_body(d)
    if role not in _PARTY_ROLES and role not in d["arbiter_ids"]:
        raise ValueError("role must be payer, payee, or a listed arbiter_id")
    if role in d["refusals"]:
        raise ValueError("role %r is recorded as refusing; it cannot also sign" % role)
    return _add_signature(d, key, role)


def verify_dispute(
    d: dict, arbiter_pubs: dict, payer_pub: bytes = None, payee_pub: bytes = None
) -> bool:
    """Total: True iff the record is well-formed and its signature set is
    valid per §10.2: at least ONE arbiter signature (verifying against
    ``arbiter_pubs[arbiter_id]``) suffices; party signatures are optional
    but, when present, must verify against the supplied party key; every
    present signature must verify; a refused party must not have signed.
    Zero arbiter signatures → False.  Never raises."""
    try:
        _validate_dispute_body(d)
        sigs = d.get("signatures")
        if not isinstance(sigs, dict) or not sigs:
            return False
        if not isinstance(arbiter_pubs, dict):
            return False
        arbiter_ids = set(d["arbiter_ids"])
        refusals = set(d["refusals"])
        arbiter_sig_count = 0
        for role in sigs:
            if role in refusals:
                return False  # signed AND refused is self-contradictory
            if role in _PARTY_ROLES:
                pub = payer_pub if role == "payer" else payee_pub
                if pub is None or not _check_one_signature(d, role, pub):
                    return False
            elif role in arbiter_ids:
                pub = arbiter_pubs.get(role)
                if pub is None or not _check_one_signature(d, role, pub):
                    return False
                arbiter_sig_count += 1
            else:
                return False  # signature from a role the record does not name
        return arbiter_sig_count >= 1
    except Exception:
        return False


# ==============================================================================
# §10.3 — Delivery attestation
# ==============================================================================


def _validate_attestation_body(a: dict) -> None:
    if not isinstance(a, dict):
        raise ValueError("attestation must be a dict")
    if a.get("v") != SCHEMA_V:
        raise ValueError("attestation v must be %d" % SCHEMA_V)
    _req_str(a.get("worker_id"), "worker_id")
    _req_str(a.get("counterparty_id"), "counterparty_id")
    _req_int(a.get("tasks"), "tasks", minimum=1)
    _req_int(a.get("total_mc"), "total_mc", minimum=0)
    period = a.get("period")
    if isinstance(period, str):
        if period == "":
            raise ValueError("period must be non-empty")
    elif isinstance(period, dict):
        if set(period.keys()) != {"start_ms", "end_ms"}:
            raise ValueError("period dict must have exactly start_ms and end_ms")
        start = _req_int(period.get("start_ms"), "period.start_ms", minimum=0)
        end = _req_int(period.get("end_ms"), "period.end_ms", minimum=0)
        if end < start:
            raise ValueError("period.end_ms must be >= period.start_ms")
    else:
        raise ValueError("period must be a string label or {start_ms, end_ms}")


def make_attestation(
    worker_id: str, counterparty_id: str, tasks: int, total_mc: int, period
) -> dict:
    """Build an unsigned §10.3 delivery attestation.  ``period`` is either a
    string label (e.g. "2026-08") or ``{start_ms, end_ms}`` integer ms."""
    a = {
        "v": SCHEMA_V,
        "worker_id": worker_id,
        "counterparty_id": counterparty_id,
        "tasks": tasks,
        "total_mc": total_mc,
        "period": period,
        "signatures": {},
    }
    _validate_attestation_body(a)
    return a


def sign_attestation(a: dict, key: bytes, role: str) -> dict:
    """Sign as "worker" or "counterparty"; accumulates; returns a new dict."""
    _validate_attestation_body(a)
    if role not in _ATTEST_ROLES:
        raise ValueError('attestation role must be "worker" or "counterparty"')
    return _add_signature(a, key, role)


def verify_attestation(a: dict, worker_pub: bytes, counterparty_pub: bytes) -> bool:
    """Total: True iff both-signed (§10.3) and both signatures verify."""
    try:
        _validate_attestation_body(a)
    except Exception:
        return False
    try:
        return _check_one_signature(a, "worker", worker_pub) and _check_one_signature(
            a, "counterparty", counterparty_pub
        )
    except Exception:
        return False


# ==============================================================================
# §9.5 — Payment request envelope, §3.8 — 402 error object
# ==============================================================================


class EnvelopeError(ValueError):
    """Structured complaint from parse_envelope: never a leaked C01
    exception.  ``reason`` is a stable machine-readable name; ``index`` is
    the offending token index when the failure is token-scoped (else None).
    ``payment_errors()`` renders the token-scoped complaint as §3.8 error
    entries ready for ``payment_error``."""

    def __init__(self, message: str, reason: str, index: int = None):
        super().__init__(message)
        self.reason = reason
        self.index = index

    def payment_errors(self) -> list:
        if self.index is None:
            return []
        return [{"index": self.index, "kind": "input", "reason": "bad_format"}]


class ChannelDraw(NamedTuple):
    channel_id: str
    k: int
    x_k: bytes  # raw 32 bytes


class Envelope(NamedTuple):
    request: dict  # the request fields, aicash removed
    mint_id: str
    tokens: tuple  # tuple[Token, ...] — parsed, validated
    channel_draw: ChannelDraw  # or None


_AICASH_FIELDS = frozenset({"mint_id", "tokens", "channel_draw"})
_DRAW_FIELDS = frozenset({"channel_id", "k", "x_k"})


def _validated_draw_dict(channel_draw) -> dict:
    """Validate a channel_draw mapping for build_envelope; returns the wire
    form (x_k as b64u string).  Raises ValueError."""
    if not isinstance(channel_draw, dict):
        raise ValueError("channel_draw must be a dict or None")
    if set(channel_draw.keys()) != _DRAW_FIELDS:
        raise ValueError("channel_draw must have exactly channel_id, k, x_k")
    channel_id = _req_str(channel_draw["channel_id"], "channel_id")
    k = _req_int(channel_draw["k"], "k", minimum=1)
    x_k = channel_draw["x_k"]
    if isinstance(x_k, bytes):
        if len(x_k) != 32:
            raise ValueError("x_k must be 32 bytes")
        x_k = b64u_encode(x_k)
    else:
        _req_b64u32(x_k, "x_k")
    return {"channel_id": channel_id, "k": k, "x_k": x_k}


def build_envelope(request: dict, mint_id: str, tokens: list, channel_draw=None) -> dict:
    """Attach the §9.5 ``aicash`` field to a request.  Tokens are validated
    with C01 and must belong to ``mint_id``.  Builder-side errors raise
    ValueError (this is the payer's own code path, not hostile input)."""
    if not isinstance(request, dict):
        raise ValueError("request must be a dict")
    if "aicash" in request:
        raise ValueError("request already carries an aicash field")
    _req_mint_id(mint_id)
    if not isinstance(tokens, list):
        raise ValueError("tokens must be a list of token strings")
    for i, t in enumerate(tokens):
        try:
            parsed = parse_token(t)
        except TokenError as exc:
            raise ValueError("tokens[%d] invalid: %s" % (i, exc))
        if parsed.mint_id != mint_id:
            raise ValueError("tokens[%d] belongs to mint %r, envelope says %r"
                             % (i, parsed.mint_id, mint_id))
    draw = None if channel_draw is None else _validated_draw_dict(channel_draw)
    out = dict(request)
    out["aicash"] = {"mint_id": mint_id, "tokens": list(tokens), "channel_draw": draw}
    return out


def parse_envelope(request: dict) -> Envelope:
    """Strictly validate and unpack a §9.5 envelope.  Every failure raises
    EnvelopeError with a stable named ``reason``; C01 parse errors are
    converted, never leaked (component requirement 4).

    Named reasons: bad_request, missing_aicash, bad_aicash, unknown_field,
    missing_field, bad_mint_id, bad_tokens, bad_token, mint_mismatch,
    bad_channel_draw, unknown_channel_field, missing_channel_field,
    bad_channel_id, bad_k, bad_x_k.
    """
    if not isinstance(request, dict):
        raise EnvelopeError("request must be a dict", "bad_request")
    if "aicash" not in request:
        raise EnvelopeError("no aicash field", "missing_aicash")
    aicash = request["aicash"]
    if not isinstance(aicash, dict):
        raise EnvelopeError("aicash must be an object", "bad_aicash")
    keys = set(aicash.keys())
    unknown = keys - _AICASH_FIELDS
    if unknown:
        raise EnvelopeError("unknown aicash field(s): %s" % sorted(unknown), "unknown_field")
    # channel_draw may be elided (== null); mint_id and tokens are required.
    for required in ("mint_id", "tokens"):
        if required not in keys:
            raise EnvelopeError("aicash missing %s" % required, "missing_field")
    mint_id = aicash["mint_id"]
    if not isinstance(mint_id, str) or not _MINT_ID_RE.fullmatch(mint_id):
        raise EnvelopeError("invalid mint_id", "bad_mint_id")
    raw_tokens = aicash["tokens"]
    if not isinstance(raw_tokens, list):
        raise EnvelopeError("tokens must be a list", "bad_tokens")
    parsed_tokens = []
    for i, t in enumerate(raw_tokens):
        try:
            parsed = parse_token(t)
        except TokenError as exc:
            raise EnvelopeError("tokens[%d] invalid: %s" % (i, exc), "bad_token", index=i)
        if parsed.mint_id != mint_id:
            raise EnvelopeError(
                "tokens[%d] mint %r does not match envelope mint %r"
                % (i, parsed.mint_id, mint_id),
                "mint_mismatch",
                index=i,
            )
        parsed_tokens.append(parsed)
    draw_raw = aicash.get("channel_draw")
    draw = None
    if draw_raw is not None:
        if not isinstance(draw_raw, dict):
            raise EnvelopeError("channel_draw must be an object or null", "bad_channel_draw")
        draw_keys = set(draw_raw.keys())
        unknown = draw_keys - _DRAW_FIELDS
        if unknown:
            raise EnvelopeError(
                "unknown channel_draw field(s): %s" % sorted(unknown), "unknown_channel_field"
            )
        missing = _DRAW_FIELDS - draw_keys
        if missing:
            raise EnvelopeError(
                "channel_draw missing %s" % sorted(missing), "missing_channel_field"
            )
        channel_id = draw_raw["channel_id"]
        if not isinstance(channel_id, str) or channel_id == "":
            raise EnvelopeError("channel_id must be a non-empty string", "bad_channel_id")
        k = draw_raw["k"]
        if isinstance(k, bool) or not isinstance(k, int) or k < 1:
            raise EnvelopeError("k must be an integer >= 1", "bad_k")
        x_k = draw_raw["x_k"]
        if not isinstance(x_k, str):
            raise EnvelopeError("x_k must be a base64url string", "bad_x_k")
        try:
            x_k_raw = b64u_decode(x_k, expect_len=32)
        except TokenError as exc:
            raise EnvelopeError("x_k invalid: %s" % exc, "bad_x_k")
        draw = ChannelDraw(channel_id=channel_id, k=k, x_k=x_k_raw)
    rest = {k: v for k, v in request.items() if k != "aicash"}
    return Envelope(
        request=rest, mint_id=mint_id, tokens=tuple(parsed_tokens), channel_draw=draw
    )


def payment_error(errors: list) -> dict:
    """The §3.8-shaped 402 body:
    ``{status: "rejected", errors: [{index, kind, reason}, ...]}``.
    Kinds and reasons are restricted to the §3.8 vocabulary; anything
    outside it raises ValueError (component B5)."""
    if not isinstance(errors, list) or not errors:
        raise ValueError("errors must be a non-empty list")
    out_errors = []
    for i, e in enumerate(errors):
        if not isinstance(e, dict):
            raise ValueError("errors[%d] must be a dict" % i)
        if set(e.keys()) != {"index", "kind", "reason"}:
            raise ValueError("errors[%d] must have exactly index, kind, reason" % i)
        index = e["index"]
        if isinstance(index, bool) or not isinstance(index, int) or index < 0:
            raise ValueError("errors[%d].index must be an integer >= 0" % i)
        kind = e["kind"]
        if kind not in ERROR_KINDS:
            raise ValueError("errors[%d].kind %r outside the spec vocabulary" % (i, kind))
        reason = e["reason"]
        if reason not in ERROR_REASONS:
            raise ValueError("errors[%d].reason %r outside the spec vocabulary" % (i, reason))
        out_errors.append({"index": index, "kind": kind, "reason": reason})
    return {"status": "rejected", "errors": out_errors}
