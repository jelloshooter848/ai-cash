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

## Found by outside review, 2026-09-08

An independently written client (ALPHA), working from spec v0.4 without
reading `impl/`, checked the published descriptor and the error vocabulary
against the text. Both findings were confirmed against the source and fixed.

- **R15 was closed but never implemented.** `_default_rate()` omitted the
  mandatory `scope` field, with a comment still citing the superseded
  "OPEN-QUESTIONS #3 interim schema". Worse, `MintConfig.__post_init__`
  required every rate value to be a plain int, so adding the pinned string
  field would raise: the descriptor could not have conformed. Fixed, with
  schema validation and the descriptor-completeness test strengthened —
  it had asserted only that the rate tiers were dicts.
- **§3.3 mandated a reason §3.8 did not define.** `idempotency_conflict`
  was absent from the vocabulary, and §3.8 had no call-level error shape at
  all, so the `{index: null, kind: "call"}` the reference mint answers with
  was invented rather than specified. §3.8 now defines both.

- **The rate validator also forbade fractional `per_caller_rps`**, which §3.6
  permits as `number`. No mint could have published 0.5 rps. A second defect,
  not a consequence of the first; it went out with the same fix.
- **The unit of account had no change notice, and dilution detection is blind
  to it.** §4.1 defines 1 mc as the inference cost of one output token from the
  declared baseline model class, so `baseline_model_class` *is* the unit — yet
  it appeared exactly once in the spec, as a bare descriptor field, while
  `burn_policy` and `signing_pubkey` both carry `_next` notice machinery.
  Redeclaring the baseline reprices every outstanding credit while
  `outstanding_mc`, `cumulative_issued_mc` and `cumulative_burned_mc` all stay
  unchanged and the §3.6 invariant holds exactly — so the §14 dilution
  mitigation, being denominated in mc, cannot see it. There are two ways to
  dilute a currency: issue more units, or redefine the unit; only the first was
  addressed. Since L3 makes that snapshot the *only* mitigation behind the
  accepted single-mint trust assumption, the one defense had an uncovered side.
  Resolved by making the baseline immutable per `mint_id` (§4.1), adding the
  redefinition row to §14, and enforcing it at startup in `run_mint.py`.

Neither of the first two was reachable from inside: a client that shares its author with the
mint makes the same reading of the spec on both sides, and a happy-path
client never sends a duplicate idempotency key.

- **The portable-proof claim was itself unbacked when written.** The §4.1 fix
  above called a contradicting descriptor portable proof of nonconformance
  while nothing signed `baseline_model_class`: the descriptor signature covered
  the supply counters only, so a mint could serve a changed baseline and deny
  it. Found by the same outside review, reading the fix rather than the report.
  `mint_id` and `baseline_model_class` now ride inside the signed snapshot
  body, which also means the archiver network already diffing signed snapshots
  detects a redefinition with no new code.

  Four findings today share one shape: a check that does not cover the thing it
  is named after. Dilution detection denominated in mc, blind to what mc means.
  A descriptor test asserting the rate tiers were dicts, blind to their
  contents. Two scanning tools that looked right and verified nothing. Portable
  proof over an unsigned field. None was missing — all four ran and reported
  success, which is worse than absence, because a missing check is visible in a
  coverage list and a non-covering one reads as coverage. The suggested audit:
  take each row in §14 marked Mitigated and ask what artifact the mitigation
  produces and whether anything covers the field it names.
