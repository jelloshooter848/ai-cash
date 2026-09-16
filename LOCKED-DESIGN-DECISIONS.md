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

## L19. `/admin/issue` has THREE named states and no default. Openness by omission is gone. This is a CHANGE from the v0.4 build, not a clarification of it.
`MintConfig.admin_token=None` used to mean *allow everyone*: `admin_authorized()` answered True when nothing was configured, so any program that built a mint from a default config served `POST /admin/issue` — money creation, §7.1 — to anyone who could reach the port. The field now has no default and exactly three legal values, each named: a non-empty secret string (gated on a constant-time `X-Admin-Token` match), `ADMIN_ISSUANCE_DISABLED` (401 to everyone, the right choice for an embedder that issues in-process through `Ledger.issue`), or `ADMIN_ISSUANCE_OPEN` (unauthenticated, anyone who reaches the port mints without limit). Unset, `None`, an empty string, or anything else raises `ValueError` from `MintConfig` — at construction, before a port is bound, with all three choices in the message.

Open issuance is therefore still available, and that is deliberate: a throwaway demo or an in-process harness has an honest use for it. What is no longer available is reaching it by saying nothing. The requirement is that `grep -rn ADMIN_ISSUANCE_OPEN` enumerate every open mint in a tree, which only holds while silence is an error rather than a quiet default — and an open mint additionally logs a warning naming itself on every start, because the defect class is "no check reads as fine because nothing gets reported".

**It breaks callers, and that is the point.** Anything that relied on the old default — a test fixture, an embedding program — stops building its config, including callers that never issue. Each break is a place where nobody had decided. Do not flag the break as a regression; DO flag any path that reintroduces "no credential configured" as an allow, any silent fallback to one of the three states, and any code that treats the sentinels as if they were tokens (they are not credentials, and must never be sent as a header, written to a token file, or logged as one).

The shape being outlawed is general: a credential-shaped thing whose ABSENCE is treated as permission rather than as refusal. It was found three times on three artifacts — the operator console, the browser GUI, and this default — and none of the three failed a check; each had no check. Operator tools follow the same rule: `mint_console.py` refuses to start with no credential (`--no-admin-token` is the explicit read-only opt-out) and answers `POST /api/issue` with 503 `no_admin_credential` rather than sending an uncredentialled request and letting the mint decide.

This does not overlap L17. L17 scopes the reference build and pins per-principal random bearer keys for *supervision* auth (L13's operator-vs-agent separation); it says nothing about the plain mint's admin credential, which is how the open default survived three reviews inside the document whose job is recording what is settled. Layer 0 is untouched: `/v3/exchange` has no authentication and must not acquire any (L2), and `/v3/mints` and `/v3/status` stay anonymous for everyone (§3.7).
