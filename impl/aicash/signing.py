"""C05 — signing: the one thin signing seam for every signature in AICash.

Spec: aicash-spec-v0.4.md §3.6 (snapshot signatures), §6.1(7) (statement
signatures), §10 (receipt/attestation signatures). Locked: L17 (Ed25519 via
the ``cryptography`` package, static keys).

Objects are signed over their canonical JSON (C01's ``canonical_json``,
§3.3 pinned: UTF-8, sorted keys, no insignificant whitespace, plain
integers, NFC strings) with the top-level signature field excluded from the
signed bytes, so signatures survive re-serialization and key reordering.
Nested ``signature`` keys inside sub-objects are signed content — only the
top-level field named by ``sig_field`` is excluded.

``verify_obj``/``verify_raw`` are total: any malformed input (bad b64u,
wrong-length signature, wrong key, uncanonicalizable object) returns
``False`` and never raises.
"""

from __future__ import annotations

import base64
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

__all__ = [
    "generate_keypair",
    "sign_raw",
    "verify_raw",
    "sign_obj",
    "verify_obj",
    "attach_sig",
    "pubkey_b64u",
]

# Requirement 2: canonicalization is C01's canonical_json (§3.3 pinned rules).
from aicash.tokencodec import canonical_json


# --- base64url (no padding) helpers -----------------------------------------

_B64U_ALPHABET_RE = re.compile(r"[A-Za-z0-9_-]*")


def _b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64u_decode_strict(s: str) -> bytes:
    """Strict, canonical base64url decode: unpadded alphabet [A-Za-z0-9_-]
    only, canonical trailing bits. Exactly one string encodes any given byte
    sequence; every other string raises ValueError.

    Canonicality is enforced by round-trip: after decoding, the bytes are
    re-encoded and must reproduce the input exactly. This rejects padding,
    whitespace, every non-alphabet character (which
    ``base64.urlsafe_b64decode`` would otherwise silently discard with its
    default ``validate=False``), and non-canonical unused trailing bits in
    the final character.
    """
    if not isinstance(s, str):
        raise ValueError("not a string")
    if not _B64U_ALPHABET_RE.fullmatch(s):
        raise ValueError("bad base64url")
    pad = -len(s) % 4
    if pad == 3:
        raise ValueError("bad base64url length")
    try:
        out = base64.urlsafe_b64decode(s + "=" * pad)
    except Exception as exc:  # binascii.Error and friends
        raise ValueError("bad base64url") from exc
    if _b64u_encode(out) != s:
        raise ValueError("non-canonical base64url")
    return out


# --- key handling ------------------------------------------------------------

def generate_keypair() -> tuple[bytes, bytes]:
    """Generate an Ed25519 keypair as raw 32-byte (private, public)."""
    private = ed25519.Ed25519PrivateKey.generate()
    private_raw = private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public_raw = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return private_raw, public_raw


def _load_private(private: bytes) -> ed25519.Ed25519PrivateKey:
    if not isinstance(private, (bytes, bytearray)) or len(private) != 32:
        raise ValueError("private key must be 32 raw bytes")
    return ed25519.Ed25519PrivateKey.from_private_bytes(bytes(private))


def _load_public(public: bytes) -> ed25519.Ed25519PublicKey:
    if not isinstance(public, (bytes, bytearray)) or len(public) != 32:
        raise ValueError("public key must be 32 raw bytes")
    return ed25519.Ed25519PublicKey.from_public_bytes(bytes(public))


def pubkey_b64u(public: bytes) -> str:
    """Encode a raw 32-byte public key as base64url without padding."""
    if not isinstance(public, (bytes, bytearray)) or len(public) != 32:
        raise ValueError("public key must be 32 raw bytes")
    return _b64u_encode(bytes(public))


# --- raw byte signing (RFC 8032 conformance surface) -------------------------

def sign_raw(message: bytes, private: bytes) -> bytes:
    """Sign raw bytes; returns the 64-byte Ed25519 signature."""
    return _load_private(private).sign(bytes(message))


def verify_raw(message: bytes, signature: bytes, public: bytes) -> bool:
    """Total verification of raw bytes: True iff valid, never raises."""
    try:
        if not isinstance(signature, (bytes, bytearray)) or len(signature) != 64:
            return False
        _load_public(public).verify(bytes(signature), bytes(message))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


# --- object signing ----------------------------------------------------------

def _signed_bytes(obj: dict, sig_field: str) -> bytes:
    """Canonical bytes of obj with the top-level sig_field excluded."""
    if not isinstance(obj, dict):
        raise TypeError("can only sign/verify dict objects")
    body = {k: v for k, v in obj.items() if k != sig_field}
    return canonical_json(body)


def sign_obj(obj: dict, private: bytes) -> str:
    """b64u(Ed25519.sign(canonical_json(obj without top-level 'signature')))."""
    return _b64u_encode(sign_raw(_signed_bytes(obj, "signature"), private))


def attach_sig(obj: dict, private: bytes, sig_field: str = "signature") -> dict:
    """Return a NEW dict: obj (minus any old sig_field) plus a fresh signature.

    The input dict is never mutated.
    """
    sig = _b64u_encode(sign_raw(_signed_bytes(obj, sig_field), private))
    out = {k: v for k, v in obj.items() if k != sig_field}
    out[sig_field] = sig
    return out


def verify_obj(obj: dict, public: bytes, sig_field: str = "signature") -> bool:
    """Total verification: True iff obj carries a valid signature over its
    canonical JSON (sig_field excluded). Never raises; never mutates obj."""
    try:
        if not isinstance(obj, dict) or sig_field not in obj:
            return False
        sig_str = obj[sig_field]
        if not isinstance(sig_str, str):
            return False
        signature = _b64u_decode_strict(sig_str)
        message = _signed_bytes(obj, sig_field)
        return verify_raw(message, signature, public)
    except Exception:
        return False
