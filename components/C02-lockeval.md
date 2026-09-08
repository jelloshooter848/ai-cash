# C02 — lockeval

**Module:** `aicash/lockeval.py` · **Tests:** `tests/test_c02_lockeval.py` · **Spec:** §3.4 (pinned parameters, asymmetric witness rules, expiry-race semantics)

## Purpose
Pure evaluation of the single conditional primitive. No state, no I/O; the caller (C04) supplies the ledger entry and the mint time.

## Public API
```python
@dataclass(frozen=True)
class Lock:            # wire/state form; hashes are b64u strings of 32-byte digests
    preimage_hash: str
    expiry: int        # ms since epoch
    refund_hash: str

@dataclass(frozen=True)
class InputForm:       # exactly one of the three §3.3 input shapes, already syntax-parsed
    kind: str          # "plain" | "claim" | "refund"
    token: Token | None      # plain, claim
    hash: str | None         # refund (b64u ledger key)
    witness: bytes | None    # claim, refund (raw 32 bytes)

validate_lock(obj: dict) -> Lock       # parses/validates a lock dict; raises LockError("bad_format")
                                       # (32-byte b64u hashes, int expiry > 0)
evaluate(lock: Lock | None, form: InputForm, now_ms: int) -> str
# returns "ok" or a §3.8 reason:
#   unlocked entry + plain form            -> ok
#   unlocked entry + claim/refund form     -> bad_format  (witness on unlocked input)
#   locked entry + plain form              -> lock_preimage_invalid (claim path requires witness)
#   locked, claim form, now <  expiry      -> ok iff sha256(witness)==preimage_hash else lock_preimage_invalid
#   locked, claim form, now >= expiry      -> lock_expired
#   locked, refund form, now <  expiry     -> lock_not_expired
#   locked, refund form, now >= expiry     -> ok iff sha256(witness)==refund_hash else refund_invalid
#   witness not exactly 32 bytes           -> bad_witness_length (checked before any hash comparison)
```

## Requirements
1. `now_ms == expiry` belongs to the refund path (§3.4: "mint_time == expiry belongs to the refund path"). Strict `<` for claim.
2. Witness length check precedes hash comparison and wins the reason code.
3. All hashing is `sha256` over raw bytes; comparisons over raw 32-byte digests (decode b64u first), constant-time comparison (`hmac.compare_digest`).
4. The claim form for a locked entry carries the token (secret) — C02 does not verify the secret-to-entry binding (that is C04's key lookup); it verifies form legality + witness only. Document this boundary in the module docstring.
5. Pure: no clock reads, no I/O.

## Benchmark (critic checklist)
- [ ] B1 Truth table exercised exhaustively: {unlocked, locked} × {plain, claim, refund} × {before, at, after expiry} × {good witness, bad witness, wrong-length witness} — every §3.8 reason above is produced by at least one case, and no case returns anything not in the table.
- [ ] B2 Boundary: `now == expiry` → claim with valid preimage returns `lock_expired`; refund with valid secret returns `ok`. `now == expiry − 1` reversed.
- [ ] B3 A 31-byte and 33-byte witness → `bad_witness_length` even when its sha256 would match.
- [ ] B4 Known-vector test: hardcoded preimage/hash pair verified against `hashlib` computed in the test itself.
- [ ] B5 Refund path never accepts the claim preimage and vice versa (cross-witness cases).
- [ ] B6 `validate_lock` rejects: missing fields, non-b64u hashes, 31-byte digests, float/negative/zero expiry.
- [ ] B7 Constant-time comparison used (code inspection: `compare_digest`, not `==`, on digest comparisons).
