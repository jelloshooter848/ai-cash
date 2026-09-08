# LOCKED DESIGN DECISIONS — AICash v0.4

This document is handed to every critic/reviewer of the reference implementation. These decisions are **settled by the ratified v0.4 process** (three design reviews, eight personas, 8–0 ratification). Do not flag them as bugs, gaps, or improvements. If an implementation *violates* one, that IS a bug. If you believe a decision itself is wrong, say so explicitly as a spec-level objection and stop — do not work around it. The spec (`aicash-spec-v0.4.md`) wins over code; this file wins over reviewer intuition.

## L1. Plain bearer tokens have NO timelock, expiry, or revocation — deliberately.
A bearer token is a password: final, irreversible, unstoppable, valid until spent. There is no expiry on ordinary value and there must not be. The ONLY conditional/temporal mechanism in the entire system is the §3.4 hash-lock-or-timeout on *locked outputs*. "Tokens should expire" and "add a revocation path" are rejected designs, not missing features.

## L2. Layer 0 has no identities, no signatures, no accounts, no sender/recipient fields.
The ledger knows "these hashes in, these hashes out." Authentication is possession of secrets and witnesses, nothing else. Signature schemes exist only ABOVE Layer 0 (mint's descriptor/statement signing keys; parties' receipt keys). Do not flag missing authentication/authorization on `/v3/exchange` — its absence is the design.

## L3. Single-mint trust is accepted and disclosed.
The mint can, in principle, lie about state. Mitigation is the signed monotonic supply snapshot with the `outstanding == issued − burned` invariant (portable proof of nonconformance), not consensus, not federation (parked with trigger). Do not flag "centralized" as a bug.

## L4. The lock primitive is deliberately non-extensible.
SHA-256 only, 32-byte preimages, one preimage path + one refund path, expiry boundary owned by the refund path, evaluated against the mint clock at commit. No scripting, no second condition type, no oracles, no arithmetic. Richer conditions are Layer 2 constructions over this primitive.

## L5. Witness rules are asymmetric on purpose.
Claim path (pre-expiry) = output token secret + preimage witness. Refund path (at/after expiry) = ledger hash + refund witness, NO token secret. This is the HTLC role split with hashes instead of keys. It is not an inconsistency.

## L6. `/v3/status` disclosing `claim_witness` of a claim-spent locked output is REQUIRED.
It looks like an information leak; it is the load-bearing atomicity mechanism for cross-mint swaps on a private ledger. Do not flag it. (Refund spends disclose nothing; disclosure lasts only for the retention window.)

## L7. The channel chain MUST be domain-separated.
`x_{i-1} = sha256("aicash-chain" || x_i)` (chain), `preimage_hash_i = sha256(x_i)` (lock). An untagged chain leaks every witness through the public lock hashes. Flag any implementation that drops the tag; do not "simplify" it away.

## L8. Bearer loss is unrecoverable by design.
No seed phrases, no operator recovery for bearer tokens. Mitigations are custodial mode and client-side secret sharding. Do not flag missing recovery.

## L9. Credits are nonconvertible, permanently.
No fiat bridge, no crypto bridge, no commercial-vendor payment, ever (§0.1, §12). This is a regulatory load-bearing wall, not a missing feature.

## L10. There is no earned issuance and no attestation service, permanently.
Entry is receive-first over the anonymous bearer-access right (§3.7, §7.2). Operator funding is the only issuance. Do not propose attestors.

## L11. No normative latency/throughput SLO.
Performance is self-attested, labeled, nullable-when-stale, and routed on by the market. Do not flag missing SLOs; DO flag a mint reporting stale numbers as fresh (that violates the honesty clause).

## L12. The burn is once-per-call, capped, drip-exempt.
`burn = 0 if sum(inputs) <= exempt_below_mc else min(cap_mc, floor(sum·rate_ppm/1e6))`; `rate_ppm ≤ 10_000`; `exempt_below_mc ≥ 10`. Assessed per `/v3/exchange` call. Custodial internal transfers never burn.

## L13. Supervision controls bind ONLY operator-registered custodial agents.
No-bearer-withdrawal flags, caps, freezes never apply to bearer-mode callers or as mint-wide defaults. Freeze suspends pulls; pulls count against caps. The anonymous tier's rate limits must not be more restrictive than any other bearer class.

## L14. Serve-then-batch-redeem exposure is accepted and quantified.
A status-verified token can be double-spent until redeemed; the payee's window/M-token exposure is a disclosed fraud margin, not a bug. Redemption is the only proof of exclusivity.

## L15. Escrow panels use the rung construction — joint secrets are refused.
No shared/joint preimage ever exists (hashing a secret nobody knows requires ZK, which is refused). Each arbiter locks its own rungs to its own preimages; quorum is a signed-vote convention; any defection is bounded to value/n and provable. Do not demand ZK binding or VSS; do not flag "an arbiter could reveal without quorum" as a bug (it is the disclosed, bounded defection model); DO flag a missing payee funding-verification step or missing signed-vote records.

## L16. Drawn-but-unsettled channel value refunds to the payer at expiry.
Settlement discipline is the payee's job; the spec discloses it. Not a bug.

## L17. Reference implementation scope (v0.4 build):
- Privacy Profile: descriptor advertisement and obligations only; the blind-signature wire protocol (cipher suite now pinned in §6.2: secp256k1 BDHKE + DLEQ) is NOT implemented in the v0.4 reference build. Do not flag its absence from the build.
- Signing: mint snapshot/statement signatures use Ed25519 with a static key published in the descriptor (key rotation is OPEN-QUESTIONS #1).
- Rate limiting: everyone is served as the anonymous tier (trivially non-discriminatory); enforcement is a stub. Do not flag missing rate-limit enforcement, DO flag missing publication.
- Supervision auth: per-principal random bearer API keys (scheme-agnostic per OPEN-QUESTIONS; separation of operator vs agent credentials IS required and testable).
- Transport is plain HTTP in tests (TLS is deployment, not code).
- Timestamps: integer ms since epoch UTC everywhere; tests may inject a fake clock — lock semantics must consult the injected clock, never wall time directly.

## L18. Known-open items live in OPEN-QUESTIONS.md.
Do not fail a component for an item recorded there; verify the implementation matches the recorded interim resolution.
