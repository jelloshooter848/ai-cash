# C05 — signing

**Module:** `aicash/signing.py` · **Tests:** `tests/test_c05_signing.py` · **Spec:** §3.6 (snapshot signatures), §6.1(7) (statement signatures), §10 (receipt/attestation signatures) · **Locked:** L17 (Ed25519 via `cryptography`, static keys)

## Purpose
One thin, correct signing seam for every signature in the system. Canonical-JSON signing so signatures survive re-serialization.

## Public API
```python
generate_keypair() -> tuple[bytes, bytes]          # (private_32, public_32) raw Ed25519
sign_obj(obj: dict, private: bytes) -> str          # b64u(Ed25519.sign(canonical_json(obj_without_sig)))
verify_obj(obj: dict, public: bytes, sig_field: str = "signature") -> bool
# verify_obj pops sig_field, canonicalizes the remainder, verifies; never raises on bad sig — returns False
attach_sig(obj: dict, private: bytes, sig_field: str = "signature") -> dict   # returns new dict with sig
pubkey_b64u(public: bytes) -> str
```

## Requirements
1. Uses `cryptography.hazmat.primitives.asymmetric.ed25519`; raw 32-byte keys at the API boundary.
2. Canonicalization is C01's `canonical_json`; the signature field itself is excluded from the signed bytes; nested `signature` keys inside sub-objects are NOT excluded (only the top-level field named by `sig_field`).
3. `verify_obj` is total: malformed b64u, wrong-length sig, wrong key → `False`, never an exception.
4. RFC 8032 conformance: verify against at least two official test vectors (from RFC 8032 §7.1: TEST 1 empty message, TEST 2 one byte — adapt: sign raw bytes helper `sign_raw`/`verify_raw` exposed for this).

## Benchmark (critic checklist)
- [ ] B1 RFC 8032 TEST 1 and TEST 2 vectors pass through `sign_raw`/`verify_raw` (keys, message, signature hardcoded from the RFC).
- [ ] B2 `attach_sig` → `verify_obj` round-trip true; any single field mutation (int +1, key rename, string case) → False.
- [ ] B3 Signature is stable under dict re-ordering of the same content (sign obj built in one order, verify obj built in another).
- [ ] B4 Tampered/truncated/empty signature strings → False without exception.
- [ ] B5 A doc with a nested sub-object containing its own `signature` key round-trips (nested one is signed content).
- [ ] B6 Wrong public key → False.
