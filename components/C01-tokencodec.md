# C01 — tokencodec

**Module:** `aicash/tokencodec.py` · **Tests:** `tests/test_c01_tokencodec.py` · **Spec:** §3.1, §3.2, §3.3 (canonical JSON), §3.4 (encoding rules)

## Purpose
Pure encoding layer: token strings, base64url secrets/hashes, ledger keys, canonical JSON. No I/O, no state, no clock.

## Public API
```python
class TokenError(ValueError): ...          # .reason = "bad_format"
b64u_encode(b: bytes) -> str               # base64url, no padding
b64u_decode(s: str, expect_len: int | None = None) -> bytes   # raises TokenError on bad alphabet/padding/length
new_secret() -> bytes                      # 32 random bytes (os.urandom)
ledger_key(secret: bytes) -> str           # b64u(sha256(secret)) — the ledger key encoding used everywhere
format_token(mint_id: str, amount_mc: int, secret: bytes) -> str      # "aicash:v3:<mint>:<amt>:<b64u secret>"
parse_token(s: str) -> Token               # Token(mint_id, amount_mc, secret: bytes); raises TokenError
canonical_json(obj) -> bytes               # §3.3 pinned: UTF-8, sorted keys, no whitespace, plain ints, NFC strings
body_digest(obj) -> str                    # b64u(sha256(canonical_json(obj)))
```

## Requirements
1. Secrets are exactly 32 bytes; `format_token` rejects other lengths; `parse_token` rejects tokens whose secret decodes to ≠ 32 bytes (`bad_format`).
2. `amount_mc` is a positive integer; reject `0`, negatives, floats, leading `+`, non-digits, amounts with leading zeros other than exactly "0" (which is itself rejected).
3. `mint_id` is 1–64 chars of `[a-z0-9-]`; reject others (colon-safety).
4. base64url without padding, strict: reject `=`-padded, `+`/`/` alphabet, whitespace.
5. `parse_token(format_token(...))` round-trips exactly; parsing never mutates.
6. Canonical JSON (normalize-then-sort, §3.3 R21): all strings (keys and values) are NFC-normalized first, then object keys are sorted by Unicode code point on the normalized key; two distinct raw keys that collide after NFC are rejected (`TokenError`, `bad_format`); ints serialized in decimal, no floats accepted anywhere (raise on float input); output stable across calls.
7. No logging of secrets anywhere in the module (§3.1: tokens are passwords).

## Benchmark (critic checklist)
- [ ] B1 Round-trip: 100 random (mint_id, amount, secret) triples survive format→parse identically.
- [ ] B2 Malformed corpus rejected with TokenError: wrong prefix, wrong version, 4 or 6 fields, bad b64u (padding, `+`, `/`, embedded newline), 31/33-byte secrets, amount `0`, `007`, `-5`, `1.5`, `1e3`, empty/oversize/uppercase mint_id.
- [ ] B3 `ledger_key` equals independently computed `base64url(sha256(raw_secret))` for a known vector (hardcoded expected string in test).
- [ ] B4 Canonical JSON: `{"b":1,"a":[2,3]}` and `{ "a":[2,3], "b" : 1 }` (parsed) produce identical bytes; key order test with non-ASCII keys sorted on the NFC-normalized key; float input raises; NFC: `"é"` composed and decomposed inputs produce identical bytes and sort at the composed form's code-point position; distinct raw keys colliding after NFC are rejected.
- [ ] B5 `body_digest` differs on any semantic change (amount 1→2) and is stable across dict insertion orders.
- [ ] B6 `new_secret()` returns 32 bytes and 1,000 draws contain no duplicates.
- [ ] B7 Tests import only `aicash.tokencodec` + stdlib; module imports no I/O/network libs; `grep`-level check: no `print`/`logging` of secret material.
