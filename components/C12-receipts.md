# C12 — receipts

**Module:** `aicash/receipts.py` · **Tests:** `tests/test_c12_receipts.py` · **Spec:** §10.1, §10.2, §10.3, §9.5 · **Depends:** C01, C05

## Purpose
The Layer 2 record formats: bilateral receipts, dispute-outcome records, delivery attestations, and the payment request envelope with its 402 error object. Pure data + signatures; no mint interaction.

## Public API
```python
make_receipt(payer_id, payee_id, amount_mc, mint_id, token_hashes, timestamp, memo, purpose) -> dict
sign_receipt(r, key, role: "payer"|"payee") -> dict          # counter-signing accumulates
verify_receipt(r, payer_pub, payee_pub) -> bool              # both signatures over the v4 schema
make_dispute_record(job_id, milestone, claimed_mc, released_mc, decision, arbiter_ids,
                    evidence_hash, timestamp, votes: list[dict]) -> dict
sign_dispute(d, key, role) / verify_dispute(d, arbiter_pubs, payer_pub=None, payee_pub=None) -> bool
    # VALID with arbiter signature(s) alone; party refusals listed in d["refusals"] (§10.2)
make_attestation(worker_id, counterparty_id, tasks, total_mc, period) -> dict   # §10.3, both-signed
build_envelope(request: dict, mint_id, tokens, channel_draw=None) -> dict       # §9.5 aicash field
    # channel_draw (optional) is a {channel_id, k, x_k} mapping; x_k may be a b64u string OR raw 32 bytes
parse_envelope(request: dict) -> Envelope                                        # strict; raises EnvelopeError

class Envelope(NamedTuple):     # the parsed §9.5 envelope (the aicash field, unpacked)
    request: dict               # the original request with the "aicash" key removed
    mint_id: str                # the envelope's mint_id (validated §3.1 shape)
    tokens: tuple[Token, ...]   # parsed & validated C01 Token objects (NOT the raw strings); each
                                # .mint_id already checked to equal mint_id — read .amount_mc/.secret/…
    channel_draw: ChannelDraw | None    # None when absent/null (the field is nullable in §9.5)
class ChannelDraw(NamedTuple):  # the parsed §9.5 channel_draw
    channel_id: str             # the funding idempotency key — payee uses it for O(1) channel resolution
    k: int                      # the 1-based global increment index (>= 1)
    x_k: bytes                  # the witness, DECODED to raw 32 bytes (not the b64u wire string) — feeds
                                # straight into ChannelPayee.on_draw, which normalizes bytes-or-string

payment_error(errors: list[{index,kind,reason}]) -> dict     # the §3.8-shaped 402 body:
    # {"status": "rejected", "errors": [{index, kind, reason}, ...]}; index is an int >= 0.
    # kind ∈ ERROR_KINDS = {"input", "output"}  (the §3.8 offending-input/output enumeration; no
    #   "call"-level kind exists — report a call-level refusal against index 0, kind "input")
    # reason ∈ ERROR_REASONS = {"unknown", "spent", "lock_preimage_invalid", "lock_expired",
    #   "lock_not_expired", "refund_invalid", "bad_witness_length", "amount_mismatch",
    #   "output_exists", "bad_format", "over_batch_limit"}  (§3.8 verbatim)
    # anything outside either frozenset raises ValueError (kinds/reasons cannot drift)
```

## Requirements
1. Schemas carry `v: 4` and exactly the §10 field sets; unknown fields rejected on parse (strict), preserved on verify (forward-compat is a non-goal for v0.4 — strict both ways, documented).
2. Signatures via C05 over canonical JSON; multi-signature docs store `signatures: {role: sig}` — each role's signature covers the document WITHOUT the `signatures` object entirely (so signers don't depend on order).
3. Dispute records: `decision ∈ {released, refunded, split}`; `split` requires `released_mc < claimed_mc` and > 0; refusal noting per §10.2 (arbiter-only validity).
4. Envelope: token strings validated with C01 (parse errors → structured complaint, not exception leak); `channel_draw` requires all of {channel_id, k, x_k}, x_k b64u 32 bytes.
5. Receipt-refusal is legitimate (§10.1): `verify_receipt` on a half-signed receipt returns False but a dedicated `receipt_status(r)` distinguishes `unsigned/payer_only/payee_only/complete` without judgment language.

## Benchmark (critic checklist)
- [ ] B1 Receipt: build → payer signs → payee counter-signs → verify true; either signature over different content → false; signing order irrelevant (both orders produce verifying docs).
- [ ] B2 Dispute record: arbiter-only signature with `refusals:["payer"]` verifies true (the §10.2 contested case); zero arbiter signatures → false; split-decision bounds enforced.
- [ ] B3 Attestation round-trip and tamper detection.
- [ ] B4 Envelope: build→parse round-trip; corpus of malformed envelopes (bad token, missing channel_draw fields, non-b64u x_k, extra fields) each rejected with a named reason.
- [ ] B5 payment_error emits exactly the §3.8 shape; kinds/reasons restricted to the spec vocabulary.
- [ ] B6 Multi-signature exclusion rule: adding the second signature does not invalidate the first (both verify against the same signed bytes).
- [ ] B7 receipt_status covers all four states.
