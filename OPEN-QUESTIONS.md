# OPEN-QUESTIONS

Ambiguities encountered while drafting/building. Logged instead of silently guessed. Items move to "Resolved" with rationale when a spec decision is made; the spec is the authority once it speaks.

## Open

(none — all items resolved in the v0.4 rev-2 resolution pass; new items appended here as found)

## Resolved in the v0.4 rev-2 resolution pass

R13. **Descriptor signing key discovery/rotation** (was Open #1). Pinned in §3.6: `signing_pubkey` in the descriptor (TOFU + recommended out-of-band pinning); rotation via `signing_pubkey_next` cross-signed by the current key over `{mint_id, pubkey, effective_at}`; an unchained key change breaks the monotonicity-proof chain by design (that break IS the alarm).
R14. **Privacy Profile cipher suite** (was Open #2). Pinned in §6.2: BDHKE over secp256k1, domain-separated try-and-increment hash-to-curve (`sha256("aicash-h2c" || counter_le32 || secret)`), mandatory DLEQ proofs against the published keyset (anti-tagging), keyset ids as hash of denomination pubkeys, rotated keysets honored for the retention window. Implementation remains out of the v0.4 reference build (L17).
R15. **Rate-limit expression schema** (was Open #3). Pinned in §3.6: `{ per_caller_rps: number, burst: int, scope: "ip"|"connection"|"global" }` for both anonymous and registered tiers.
R16. **Supervision auth scheme** (was Open #5). §6.1(1) now states scheme-agnosticism normatively; the separation and per-operation credential class are what conform. Reference implementation's bearer keys recorded as a non-normative profile.
R17. **Custodial withdrawal burn attribution** (was Open #6). Pinned in §7.3: the agent is charged `compute_burn(amount_withdrawn)` on the requested amount; custody-fragmentation burn differences are absorbed by the mint. Deposits symmetric (agent controls those inputs). C10 updated accordingly.
R18. **Tranche capacity vs max_batch** (was Open #7). Pinned in §9.1: tranche capacity is `max_batch − 1` increments; `⌈N/(max_batch−1)⌉` tranches. Matches the C08 implementation.
R19. **Swap margin latency-slot attribution** (was Open #8). Pinned in §11: status slot = Mint 2, one redemption slot per mint; conservative max-of-both per slot is explicitly conformant (MAY). C11's max-based implementation conforms.
R20. **Swap dispute margin** (was Open #9). Pinned in §11 step 4: `recovery_window_ms >= (T − T′) + M` where `M` is the computed minimum margin. Matches the C11 implementation.
R21. **Canonical JSON key ordering vs NFC** (C01 critic's question). Pinned in §3.3: NFC-normalize first, sort by code point on the normalized key, reject post-NFC duplicate keys. C01 updated (sort-after-NFC) — cross-implementation digest agreement requires normalize-then-sort.

## Resolved during v0.4 drafting

R1. **How a locked output is spent (v0.3 ambiguity).** v0.3 said "spendable by anyone revealing x" but keyed every entry by its own secret and never defined the input format for locked spends. Resolved in §3.3/§3.4: **claim path = token secret + preimage witness; refund path = ledger hash + refund witness (no secret)**; outputs may be created **by hash** so a funder can pay a party it cannot rob. Rationale: the alternative reading (witness alone, or funder-known secrets) makes every conditional construction race-exposed to the funder, contradicting the ratified framework's channel properties ("the payer cannot claw back earned value"). This is a pinning of ambiguity, not a state-machine change: ledger state and atomicity are unchanged.
R2. **Burn formula.** Framework said "bounded fraction, capped per call, drip-exempt." Spec pins: `burn = 0 if sum(inputs) <= exempt_below_mc else min(cap_mc, floor(sum*rate_ppm/1e6))`, `rate_ppm <= 10_000`, `exempt_below_mc >= 10`, assessed once per call. (§7.3)
R3. **Expiry boundary ownership.** `mint_time == expiry` belongs to the refund path; single-path evaluation at commit time; race handling is a client-side grace convention with published `grace_ms`. (§3.4)
R4. **Timestamps.** Integer milliseconds since Unix epoch, UTC, everywhere. (§3.2)

## Resolved during the v0.4 defect sweep (second review pass)

R5. **Swap atomicity on private ledgers.** Preimage reveal is not automatic as on a public chain. Resolved: `/v3/status` MUST return `claim_witness` for locked entries spent via the claim path, for the retention window. (§3.5, §11)
R6. **Channel chain witness leak.** With an untagged chain, lock i+1's public `preimage_hash` IS lock i's claim witness (`sha256(x_{i+1}) = x_i`), letting a payee claim N−1 increments at open. Resolved: chain derivation uses `sha256("aicash-chain" || x)`, lock commitment stays plain `sha256(x)` — disjoint functions, no public value reveals a witness. Found by the spec author during review; missed by all nine review agents. (§9.1)
R7. **Idempotency replay vs. secret storage.** Store `key → {body_digest, result}`, never raw bodies; mismatched digest → `idempotency_conflict`. (§3.3)
R8. **k-of-n binding honesty.** Shares are verifiable for dealer-commitment consistency only, never against the SHA-256 lock image (that needs ZK); the lock-to-preimage binding is by signed panel attestation + mandatory payee funding verification, with panel failure provable ex post. (§9.3)
R9. **max_batch is an operational limit, not a measurement** — lives in `limits` (never null), not the nullable `performance` block. (§3.6)
R10. **Joint escrow preimages are impossible without ZK** (attesting `sha256(p_m)` requires holding `p_m`), so k-of-n panels use the rung construction: per-arbiter preimages, signed-vote quorum, defection bounded to value/n. Found by the independent verification pass. (§9.3)
R11. **Canonical JSON** pinned: UTF-8, sorted keys, no insignificant whitespace, plain integers, NFC strings. (§3.3)
R12. **Statement kind partition** pinned; freeze/unfreeze are amount 0 and excluded; withdrawals net-of-burn with burn as its own line. (§6.1(7))
