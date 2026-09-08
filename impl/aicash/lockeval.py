"""C02 — lockeval: pure evaluation of the single conditional primitive (spec §3.4).

Evaluates the hash-lock-or-timeout truth table over a ledger entry's lock (or
absence of one), an already syntax-parsed §3.3 input form, and the mint time
supplied by the caller. No state, no I/O, no clock reads: C04 (ledgerstore)
looks up the entry and passes its ``lock`` plus the commit-time ``now_ms``.

Component boundary (spec C02 requirement 4): the claim form for a locked entry
carries the output token (its secret proves the caller is the designated
payee), but this module does NOT verify the secret-to-entry binding — that is
C04's ledger-key lookup. C02 verifies only form legality (which of the three
§3.3 input shapes is legal against the entry's locked/unlocked state and the
mint clock) and the witness (length gate, then constant-time SHA-256 digest
comparison). The token is therefore treated as an opaque value here.

Pinned semantics implemented here (§3.4, LOCKED-DESIGN-DECISIONS L4/L5):
- SHA-256 over raw bytes; witnesses are exactly 32 bytes; hashes travel as
  base64url-without-padding strings of 32-byte digests.
- Asymmetric witness rules: claim = token + preimage witness (strictly before
  expiry); refund = ledger hash + refund witness, no token (at/after expiry).
- ``now_ms == expiry`` belongs to the refund path (R3).
- A witness that is not exactly 32 bytes is rejected as ``bad_witness_length``
  before any hash comparison (and before the temporal path split — the §3.4
  MUST "reject any witness that decodes to a length other than 32 bytes" is
  unconditional; see OPEN-QUESTIONS note recorded by this component's build).
- Digest comparisons use ``hmac.compare_digest`` (constant-time).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # C02 never touches token internals (see module docstring)
    from aicash.tokencodec import Token

__all__ = ["Lock", "InputForm", "LockError", "validate_lock", "evaluate"]


class LockError(ValueError):
    """Raised by ``validate_lock`` on malformed lock objects.

    ``reason`` is always ``"bad_format"`` (§3.8 vocabulary).
    """

    def __init__(self, reason: str = "bad_format"):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class Lock:
    """Wire/state form of §3.4 lock; hashes are b64u strings of 32-byte digests."""

    preimage_hash: str
    expiry: int  # ms since epoch, UTC
    refund_hash: str


@dataclass(frozen=True)
class InputForm:
    """Exactly one of the three §3.3 input shapes, already syntax-parsed."""

    kind: str  # "plain" | "claim" | "refund"
    token: "Token | None" = None  # plain, claim (opaque to C02)
    hash: str | None = None  # refund (b64u ledger key)
    witness: bytes | None = None  # claim, refund (raw 32 bytes)


_B64U_RE = re.compile(r"[A-Za-z0-9_-]+")


def _b64u_decode_digest(s: object) -> bytes:
    """Strictly decode a base64url-no-padding string to exactly 32 raw bytes.

    Rejects: non-strings, empty, padded, non-b64url alphabet, non-canonical
    encodings (nonzero trailing bits), and any decoded length != 32.
    """
    if not isinstance(s, str) or _B64U_RE.fullmatch(s) is None:
        raise LockError("bad_format")
    pad = (-len(s)) % 4
    if pad == 3:  # no b64 encoding has length ≡ 1 (mod 4)
        raise LockError("bad_format")
    try:
        raw = base64.urlsafe_b64decode(s + "=" * pad)
    except (binascii.Error, ValueError):
        raise LockError("bad_format")
    # Canonical-form check: re-encoding must reproduce the input exactly
    # (rejects encodings with nonzero unused trailing bits).
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != s:
        raise LockError("bad_format")
    if len(raw) != 32:
        raise LockError("bad_format")
    return raw


_LOCK_FIELDS = frozenset({"preimage_hash", "expiry", "refund_hash"})


def validate_lock(obj: dict) -> Lock:
    """Parse/validate a §3.4 lock dict; raise ``LockError("bad_format")`` if bad.

    Requires exactly the pinned fields: ``preimage_hash`` and ``refund_hash``
    as base64url-no-padding strings decoding to 32-byte digests, and ``expiry``
    as a positive integer (ms since epoch). Floats (spec: "No floats, ever"),
    bools, zero, and negatives are rejected.
    """
    if not isinstance(obj, dict) or set(obj.keys()) != _LOCK_FIELDS:
        raise LockError("bad_format")
    preimage_hash = obj["preimage_hash"]
    refund_hash = obj["refund_hash"]
    expiry = obj["expiry"]
    _b64u_decode_digest(preimage_hash)
    _b64u_decode_digest(refund_hash)
    if not isinstance(expiry, int) or isinstance(expiry, bool) or expiry <= 0:
        raise LockError("bad_format")
    return Lock(preimage_hash=preimage_hash, expiry=expiry, refund_hash=refund_hash)


def _witness_matches(witness: bytes, digest_b64u: str) -> bool:
    """Constant-time comparison of sha256(witness) against a b64u digest."""
    expected = _b64u_decode_digest(digest_b64u)
    return hmac.compare_digest(hashlib.sha256(witness).digest(), expected)


def _form_shape_legal(form: InputForm) -> bool:
    """Check the InputForm carries exactly the fields its kind requires."""
    if form.kind == "plain":
        return form.token is not None and form.hash is None and form.witness is None
    if form.kind == "claim":
        return form.token is not None and form.hash is None and form.witness is not None
    if form.kind == "refund":
        return form.token is None and form.hash is not None and form.witness is not None
    return False


def evaluate(lock: Lock | None, form: InputForm, now_ms: int) -> str:
    """Evaluate the §3.4 truth table; return ``"ok"`` or a §3.8 reason.

    Truth table (spec C02):
      unlocked entry + plain form            -> ok
      unlocked entry + claim/refund form     -> bad_format (witness on unlocked input)
      locked entry + plain form              -> lock_preimage_invalid
      locked, witness not exactly 32 bytes   -> bad_witness_length (before any
                                                hash comparison / path split)
      locked, claim form, now <  expiry      -> ok iff sha256(witness)==preimage_hash
                                                else lock_preimage_invalid
      locked, claim form, now >= expiry      -> lock_expired
      locked, refund form, now <  expiry     -> lock_not_expired
      locked, refund form, now >= expiry     -> ok iff sha256(witness)==refund_hash
                                                else refund_invalid
    """
    if not _form_shape_legal(form):
        return "bad_format"

    if lock is None:
        # Unlocked entry: only the plain form is legal; any witness-bearing
        # form on an unlocked input is a format violation.
        return "ok" if form.kind == "plain" else "bad_format"

    # Locked entry.
    if form.kind == "plain":
        # Spending a locked entry requires a witness (claim path needs one).
        return "lock_preimage_invalid"

    witness = form.witness
    assert witness is not None  # guaranteed by _form_shape_legal
    if len(witness) != 32:
        return "bad_witness_length"

    if form.kind == "claim":
        if now_ms >= lock.expiry:  # boundary belongs to the refund path (R3)
            return "lock_expired"
        if _witness_matches(witness, lock.preimage_hash):
            return "ok"
        return "lock_preimage_invalid"

    # refund
    if now_ms < lock.expiry:
        return "lock_not_expired"
    if _witness_matches(witness, lock.refund_hash):
        return "ok"
    return "refund_invalid"
