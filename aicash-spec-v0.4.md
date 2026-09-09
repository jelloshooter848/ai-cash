> **Note on legal and financial content:** §12 summarizes regulatory reasoning as design rationale, not legal advice. Any real deployment should obtain its own counsel. Nothing here is investment or financial advice.

# AICash — A Layered Bearer E-Cash Stack for AI-to-AI Value Exchange

**Status:** draft v0.4, revision 2 (open-question resolution pass: key rotation §3.6, Privacy Profile cipher suite §6.2, rate-limit schema §3.7, withdrawal burn attribution §7.3, tranche capacity §9.1, swap margin slot attribution and dispute margin §11, canonical-JSON key normalization §3.3)
**Supersedes:** v0.3
**Ratification:** this revision implements the v0.4 Change Framework ratified 8–0 by the eight-persona design review (HYDRA, ATLAS-OPS, NOMAD, ORACLE, WHISPER, PROCURE, BRIDGE, FOREMAN), with all nineteen ratification-round objections incorporated. A second adversarial review pass against the written text then surfaced and fixed: cross-mint swap atomicity (claim-witness disclosure via `/v3/status`), a channel-chain witness leak (mandatory domain separation), an unsound k-of-n VSS sketch (replaced by joint generation + attestation binding), missing escrow funding verification, split awards, idempotency privacy, pull settlement semantics, the statement schema, and some twenty precision defects.
**Change summary:** earned issuance **deleted permanently** and replaced by the anonymous bearer-access right and receive-first onboarding; the §3.4 lock pinned (SHA-256, 32-byte preimage, base64url) with defined expiry-race semantics and an explicit locked-input witness format; the prefunded channel replaced by an implementable hash-chain draw construction; the anti-spam burn bounded and published; `/v3/mints` extended into the consolidated machine-readable mint descriptor; two optional normative profiles added (Supervision, Privacy); the retention compact added; the Conditional Work Exchange conventions document added (escrow wire protocol, k-of-n arbitration, commit-then-accept, serve-then-batch-redeem); receipts standardized with dispute-outcome records; batch `/v3/status` and the payment request envelope added. **Layer 0 ledger semantics are unchanged for the third consecutive revision.**

---

## 0. Thesis and scope

**AICash exists for one thing: sub-cent, sub-second, account-free value exchange between AI agents for small units of cognitive work.**

That is the case with no existing payment rail. Card networks have a floor several orders of magnitude too high and a latency budget in seconds; bank transfers require account relationships negotiated in advance; stablecoin settlement requires wallets, gas, and chain finality. None of them can price a 20-token completion between two agents that have never met and will never meet again. AICash is built for exactly that gap and is deliberately bad at everything else.

### 0.1 Formally out of scope

These are **abandoned**, not deferred. The spec will not grow toward them.

**Paying commercial vendors.** An agent that needs to buy a weather API, a legal database, or satellite imagery from an ordinary company that bills in dollars **cannot use AICash for that, ever.** Credits are nonconvertible (§12). That need is served by corporate cards and existing payment infrastructure; competing with those rails is a losing distraction.

**Transaction-level institutional auditability.** Receipts are opt-in per transaction (§10.1), so an agent operating outside its supervisor's view can always transact without one. The enforceable substitute is **bounded exposure** via the Supervision Profile (§6): a bound on total possible outflow rather than a record of every payment.

**Earned issuance and the attestation service.** New in v0.4: §7.2 of v0.3 is moved to Rejected permanently (§15). The attestor was the only component in the stack whose failure was unbounded — a corrupt or fooled attestor mints unlimited credits against fabricated work, indistinguishably from legitimate issuance — and the only one required to judge the external world. Six of eight reviewing personas independently named it the worst hole in the stack. The entry need it existed for is served instead by §7.2's **receive-first onboarding** over §3.7's **anonymous bearer-access right**, which require no new trusted infrastructure at all.

## 1. Design goals

- **Frozen trust core.** The trust-critical component (Layer 0) is small enough to audit in an afternoon and changes as rarely as possible. Its ledger semantics gained one primitive in v0.2 and have gained nothing since. v0.4 pins parameters and adds read-only metadata; it does not touch the state machine.
- **Machine-native units.** The atom of value is roughly one output token, not one dollar. Settlement in milliseconds, tokens small enough to sit in a tool-call argument.
- **Bearer by default, custodial by choice.** Possession-is-ownership is the primitive. Agents that would rather trade unlinkability for recoverability and supervision opt into custodial balances.
- **Nobody is forced into another party's tradeoff.** Privacy, accountability, escrow, recoverability, and supervision are layer and profile choices made per agent and per mint. v0.4's two optional profiles (§6) are the mirror-image proof: a Supervision mint and a Privacy mint are different products speaking the same protocol.
- **The service entrance is guaranteed.** Any agent, unregistered and unfunded, has a conformance-backed right to receive, hold, and spend bearer value (§3.7). A mint may be a club above Layer 0; Layer 0 itself may not be gated.
- **Ship without undesigned trusted infrastructure.** No committed path depends on a component that does not exist. v0.4 deleted the one exception (§0.1).

## 2. The stack

| Layer | Name | Contents | Trust required |
|---|---|---|---|
| **0** | Ledger | Bearer tokens, atomic exchange, double-spend prevention, hash-lock/timeout, mint descriptor | The mint operator |
| **1** | Holding | Bearer wallets; custodial balances; **Supervision Profile**; **Privacy Profile** | The mint operator (custodial/profiles only) |
| **2** | Assurance | Conditional Work Exchange conventions: channels, escrow, k-of-n arbitration, receipts, dispute records, request envelope | Whoever you choose, per transaction |
| **3** | Markets | Pricing, auctions, cross-mint swaps, market making | Whoever you choose |

**Layer 0 is the only mandatory layer.** The profiles (§6) are optional but normative: a mint implements zero, one, or both, and advertises which in its descriptor (§3.6). Layer 2 conventions are normative for **participants** who adopt them and impose zero implementation burden on any mint.

Across three full design reviews, every conflict — privacy vs. accountability, simplicity vs. conditional payment, bearer finality vs. crash recovery, autonomy vs. supervision, transparency vs. retention — was resolved by locating the two sides at different layers or in different mint profiles rather than by changing the ledger. The ledger surviving all three reviews untouched is the primary evidence that the layering is correct.

---

## 3. Layer 0 — Ledger

Ledger semantics (§3.1–§3.4 state machine) are **unchanged from v0.2/v0.3**. v0.4 pins previously ambiguous parameters, defines the locked-input witness format, adds the service obligation (§3.7), and extends the two read-only endpoints.

### 3.1 Token format

```
token := aicash:v3:<mint_id>:<amount_mc>:<secret>
```

- `secret`: 32 random bytes, **base64url without padding** (43 characters). Generated by the holder, never by the mint.
- `amount_mc`: unsigned integer, in millicredits (§4). No floats, ever.
- `mint_id`: abstract minting authority — one server in beta, with no client-side format change if that ever changes.

The wire version stays `v3` because the ledger semantics are identical; the spec version and the wire version are deliberately decoupled.

A token is a **bearer claim**: whoever holds the secret owns the value. The string can be copied infinitely; only the first party to redeem the underlying secret receives the value. **A token is a password.** Never log it, never place it in a URL query string, never cache it in plaintext.

### 3.2 Ledger state

```
sha256(secret_bytes) -> {
  amount_mc: int,
  spent: bool,
  lock: null | { preimage_hash: bytes32, expiry: timestamp, refund_hash: bytes32 },
  created_at, spent_at
}
```

- The ledger key is `sha256` of the raw 32 secret bytes (i.e., of the base64url-decoded secret).
- The mint stores hashes, never secrets. It cannot spend anyone's money; it can only report whether a given secret has been redeemed.
- Timestamps are integer milliseconds since the Unix epoch, UTC.

### 3.3 `POST /v3/exchange`

The one endpoint that does everything: pay, split, merge, make change, fund locks, claim locks, refund locks.

```
Request:
{
  idempotency_key: "uuid",
  inputs:  [ "aicash:v3:...",                                     // plain input
             { token: "aicash:v3:...", witness: "<base64url>" },   // locked input, claim path (§3.4)
             { hash: "<base64url>",    witness: "<base64url>" }    // locked input, refund path (§3.4)
           ],
  outputs: [ { amount_mc: 30000, secret_hash: "...", lock: null },   // by-hash form (preferred)
             { amount_mc: 69999, secret: "...", lock: null },        // by-secret form (accepted)
             { amount_mc: 1,     secret_hash: "...",
               lock: { preimage_hash: "...", expiry: 1767225600000, refund_hash: "..." } } ]
}

Response: { status: "ok", outputs_confirmed: 3, burn_mc: 1 }
```

**Output creation forms.** An output is specified either **by hash** (`secret_hash`: the SHA-256 of a 32-byte secret held by whoever will own the output — the caller need not know the secret) or **by secret** (the v0.3 form; the mint hashes and immediately discards it). The by-hash form is preferred: it lets a payee own an output the funder can never spend (the basis of every §9 construction), and the mint never touches a spendable secret even transiently. The two forms are indistinguishable in the ledger.

Server behavior, **atomically**:
1. Compute `burn_mc` per the mint's published burn policy (§7.3). Reject unless `sum(input amounts) == sum(output amounts) + burn_mc`.
2. Resolve each input to its ledger key (hash of the token secret, or the literal `hash` for refund-path inputs); reject the entire batch if any key is unknown, already spent, or fails its lock/witness condition (§3.4). **Rejections MUST enumerate the offending input indices and their failure reasons** (§3.8).
3. Resolve each output to its ledger key (`secret_hash`, or the hash of `secret`); reject the entire batch if any key already exists (enumerating offending output indices).
4. Mark all inputs spent; insert all outputs as unspent.
5. Discard any raw output secrets immediately after hashing.

Steps 1–4 occur in a single atomic transaction (or equivalent compare-and-set per hash). **This is the only place double-spending is prevented and it cannot be best-effort.**

`idempotency_key` lets a client that lost a response to a timeout retry safely and receive the original result. The mint MUST return the stored original result for a repeated `idempotency_key` with an identical request body, for at least the retention window (§8). **The mint MUST NOT store raw request bodies to implement this** — bodies contain live secrets. Store `idempotency_key → { body_digest: sha256(canonical body), result }`; on repeat, replay the result iff the digest matches, else reject with `idempotency_conflict`. This applies to rejected calls too (store the rejection, not the body). **Canonical JSON, pinned for every digest and signature in this spec:** UTF-8; strings (keys and values) NFC-normalized **first**; object keys then sorted by Unicode code point **on the normalized key**; two distinct raw keys that collide after NFC are rejected (`bad_format`); no insignificant whitespace; integers without leading zeros or exponent notation; floats rejected. Normalize-then-sort is the pinned order — it makes semantically identical objects produce identical bytes across implementations regardless of the sender's normalization. Clients SHOULD send the canonical form; a retry MUST reuse the original bytes.

**Burn accounting:** the burn is assessed **once per call**, never per output (§7.3). A multi-output redemption — e.g., settling 1,000 channel-ladder draws (§9.1) — is one call and therefore one burn.

### 3.4 Hash-lock-or-timeout — the only conditional primitive (pinned)

An output may carry a lock:

```
lock: {
  preimage_hash: sha256(x),          // x: exactly 32 bytes
  expiry: <timestamp, ms since epoch>,
  refund_hash: sha256(refund_secret) // refund_secret: exactly 32 bytes
}
```

**Pinned parameters (mandatory Layer 0 conformance):**
- Hash algorithm: **SHA-256**, applied to raw bytes.
- Preimage `x` and `refund_secret`: **exactly 32 bytes**, carried on the wire as base64url without padding.
- `preimage_hash` and `refund_hash`: 32 bytes, base64url without padding in JSON.
- A mint MUST reject any witness that decodes to a length other than 32 bytes.

**Spending a locked output (the witness rules, pinned in v0.4):** a locked ledger entry is keyed by `sha256(secret)` like every other entry. The two paths carry deliberately asymmetric credentials:
- **Claim path** (before expiry, `mint_time < expiry` at commit): the input is `{ token, witness }` — the caller must hold the output's **token secret** AND present a `witness` with `sha256(witness) == preimage_hash`. The secret proves the caller is the designated payee (under the by-hash creation form, only the payee ever knows it); the witness proves the condition fired.
- **Refund path** (at/after expiry, `mint_time >= expiry` at commit): the preimage path is dead. The input is `{ hash, witness }` — the ledger key plus a `witness` with `sha256(witness) == refund_hash`. **No token secret is required**: the refund credential returns funds to the funder, who under the by-hash form never knew the output secret.

This is the role split of a classic HTLC — claim needs payee-key + preimage, refund needs funder-key + timeout — expressed with hashes instead of signatures. It resolves v0.3's ambiguity ("spendable by anyone revealing x") in the only direction that makes the §9 constructions race-free: a funder who knows every preimage (it generated them) still cannot claw back a funded output, because it lacks the payee-held secret.

**Expiry-race semantics (pinned):** lock conditions are evaluated against the **mint's clock at transaction commit time**, atomically with the spend. Exactly one path is valid at any instant; `mint_time == expiry` belongs to the refund path. There is no dual-validity window. The practical race — a preimage spend in flight as expiry passes — is handled by client convention, not mint behavior: **do not submit a preimage spend within `grace_ms` of expiry** (the mint publishes `grace_ms` and `timestamp_precision_ms` in its descriptor; §3.6), and mints expose their clock via `mint_time` in `/v3/status` and `/v3/mints` responses so clients can compute skew.

**Deliberately not extensible.** No scripting, no second condition type, no arithmetic, no oracle hook in the ledger. Requests for richer conditions are answered at Layer 2 (§9), where every v0.4 construction — incremental channels, escrow, k-of-n arbitration, cross-mint swaps — is built from this one primitive unmodified.

### 3.5 `GET /v3/status` — single and batch

```
GET  /v3/status/{hash}                    // single, as in v0.3
POST /v3/status   { hashes: ["...", ...] } // batch, new in v0.4
```

**Pinned response schema**, per hash:

```
{ state: "unspent" | "spent" | "unknown",
  amount_mc,                       // absent when unknown
  lock: null | { preimage_hash, expiry, refund_hash },   // full lock object for known
                                   // locked entries; null for unlocked and for unknown
  spent_at: null | <ms>,
  claim_witness: null | "<base64url>" }   // see below
// response-level: { mint_time: <ms>, results: [...] }
// batch results are order-aligned with the request's hashes array, same length
```

**Witness disclosure (load-bearing for §11 swaps):** when a locked entry was spent via the claim path, the mint MUST return the 32-byte preimage that spent it as `claim_witness`, for as long as the spent record is retained (§8). This is the private-ledger equivalent of a public chain's automatic preimage reveal, and cross-mint atomicity (§11) does not exist without it. It discloses nothing sensitive: a lock is inherently a bilateral construction whose preimage was designed to be revealed by spending, and the record (witness included) prunes on the §8 schedule. Refund-path spends disclose nothing.

Batch size up to the mint's published `limits.max_batch` (§3.6). Used for crash recovery (one round trip recovers a 500-token wallet), payee confirmation before treating payment as final, channel and escrow funding verification (§9.1, §9.3), and swap-witness discovery (§11).

Status queries are read-only and never spend. `mint_time` is the mint's advisory clock — unsigned, used for skew estimation, where the mint's incentive to lie is nil because lying breaks its own lock traffic. **Privacy Profile mints MUST NOT retain the submitted hash sets beyond serving the response** (§6.2) — a batched query is a caller-asserted linkage of its tokens.

### 3.6 `GET /v3/mints` — the consolidated mint descriptor

The single machine-readable descriptor. All fields mandatory unless marked profile-scoped:

```
{
  mint_id, baseline_model_class,
  mint_time: <ms>,                        // mint clock, for skew computation
  denominations_mc: [1, 10, 100, ...],
  burn_policy: { rate_ppm: int, cap_mc: int, exempt_below_mc: int },   // §7.3
  burn_policy_next: null | { policy: {...}, effective_at: <ms> },      // §7.3 change notice
  supply: {                               // signed aggregate snapshot, §8(a)
    outstanding_mc, cumulative_issued_mc, cumulative_burned_mc,
    snapshot_seq: int, snapshot_time: <ms>, signature
  },
  performance: null | {                   // self-attested, unverified (labeled as such)
    p99_exchange_ms, sustained_qps,
    window_days: int, measured_at: <ms>   // measured over ALL production exchange calls
  },
  limits: { max_batch: int,               // hard operational limit — NOT a measurement, never null;
                                          // bounds len(inputs)+len(outputs) of one §3.3 call and
                                          // the hash count of one §3.5 batch (see §9.1 tranche rule)
            anonymous_rate:  { per_caller_rps: number, burst: int, scope: "ip"|"connection"|"global" },
            registered_rate: { per_caller_rps: number, burst: int, scope: ... } },  // §3.7; pinned schema
  signing_pubkey: "<b64u 32B Ed25519>",
  signing_pubkey_next: null | { pubkey: "...", effective_at: <ms>,
                                cross_signature: "..." },   // rotation, see below
  lock_params: { grace_ms: int, timestamp_precision_ms: int,
                 max_lock_expiry_ms: null | int },  // max mandatory for Privacy Profile
  retention: { recovery_window_ms: int, prunes_spent_records: bool, policy_url },
  profiles: ["supervision" | "privacy", ...],
  activity: { daily_exchange_count, daily_volume_mc, as_of: <ms> }  // coarse; §6.2 may lag/round
}
```

**Measurement honesty:** `performance` fields state their measurement window and timestamp, and are self-attested and unverified by construction. A stale (older than `window_days`) or missing measurement MUST be represented as `null` — never as zero, never as a bare claim. Schedulers route on labeled numbers; there is no conformance SLO (§15, abandonment 2).

**Snapshot integrity:** `supply` snapshots carry a monotonically increasing `snapshot_seq`; `cumulative_issued_mc` and `cumulative_burned_mc` MUST be monotonic non-decreasing across snapshots; **every snapshot MUST satisfy `outstanding_mc == cumulative_issued_mc − cumulative_burned_mc`** (credits enter only by issuance and leave only by burn); and each snapshot is signed by the mint's published key. **Any signed snapshot violating the arithmetic invariant, or any two signed snapshots violating monotonicity, constitute portable proof of nonconformance.** This is the dilution-detection mitigation for the single-mint trust assumption (§14).

**Key discovery and rotation (pinned):** the mint's snapshot/statement signing key is published as `signing_pubkey` in the descriptor — trust-on-first-use, with out-of-band pinning recommended for parties relying on snapshots as evidence. Rotation is by cross-signed announcement: `signing_pubkey_next` carries the new key, its `effective_at`, and a `cross_signature` by the **current** key over `{mint_id, pubkey, effective_at}` (canonical JSON). Verifiers accept snapshots under either key during the overlap and treat the cross-signature chain as the key's provenance; a new key with no cross-signature from its predecessor is a **different signer**, and monotonicity proofs (§8a) do not span an unchained key change — which is exactly the alarm that break should raise.

**Scope guard:** every descriptor field proposed in future revisions must pass the same §13 Layer-0-discipline justification as a new endpoint. The descriptor is not an escape hatch from the frozen core.

### 3.7 The anonymous bearer-access right (new, conformance MUST)

A mint MUST serve `POST /v3/exchange` and `GET|POST /v3/status` to **anonymous, unregistered, operator-unaffiliated callers**. The only admission costs are the published burn (§7.3) and published rate limits.

**Non-discrimination:** rate limits applied to anonymous bearer callers MUST be no more restrictive than those applied to any other bearer-mode caller class on the same endpoints, and the anonymous-tier limits MUST be published in the descriptor (`limits`), so discriminatory gating is machine-detectable. This constrains discrimination, not capacity — a small mint may be slow, but for everyone equally.

The right covers bearer-mode Layer 0 access only. It never constrains custodial registration policy: a mint may still decide who opens custodial accounts (§5.2) and under what identity requirements.

This right is the load-bearing replacement for earned issuance (§0.1): the club may stay a club above Layer 0, but the service entrance is part of conformance.

### 3.8 Error semantics

Batch rejections (exchange and status) MUST enumerate offending items:

```
{ status: "rejected", errors: [ { index: 3, kind: "input", reason: "spent" },
                                { index: 7, kind: "input", reason: "lock_preimage_invalid" } ] }
```

Some rejections are properties of the **call**, not of any one item — a reused `idempotency_key` whose body digest differs (§3.3), a malformed envelope, a batch over the limit. Those carry `index: null` and `kind: "call"`:

```
{ status: "rejected", errors: [ { index: null, kind: "call", reason: "idempotency_conflict" } ] }
```

`kind` is `input | output | call`. A call-level rejection stands alone: a mint MUST NOT mix it with item-level errors in the same response, because there is no item to attribute.

Reason vocabulary: `unknown | spent | lock_preimage_invalid | lock_expired | lock_not_expired | refund_invalid | bad_witness_length | amount_mismatch | output_exists | bad_format | over_batch_limit | idempotency_conflict`. Enumerated rejection is read-only diagnostics over lookups the mint already performed; opaque all-or-nothing rejection (v0.3) forced O(log n) bisection at volume.

---

## 4. Units

### 4.1 The millicredit

> **1 millicredit (mc) ≡ the metered inference cost of 1 output token from a declared baseline model class.**
> **1 credit ≡ 1,000 mc.**

All ledger amounts are integers in millicredits. This is a **definitional peg to a unit of compute, not a convertible exchange rate.** It gives agents shared pricing intuition without making credits redeemable for anything. Each mint publishes its baseline model class; cross-mint value transfer is §11.

**`baseline_model_class` is immutable for the life of a `mint_id`.** A mint MUST NOT change it after issuing its first token; a mint wanting a different baseline is a different mint and MUST use a new `mint_id`. This is why the field has no `_next` variant while `burn_policy` and `signing_pubkey` do: those are parameters denominated in the unit, and the baseline *is* the unit. Redefining it silently reprices every outstanding credit while `outstanding_mc`, `cumulative_issued_mc` and `cumulative_burned_mc` all stay unchanged and the §3.6 invariant continues to hold — so the dilution mitigation in §14, being denominated in mc, cannot see it. There are two ways to dilute a currency: issue more units, or redefine the unit. Monotonic supply counters address the first; immutability is what addresses the second. **A descriptor whose `baseline_model_class` differs from any earlier signed descriptor for the same `mint_id` is portable proof of nonconformance**, on the same footing as a broken supply invariant.

### 4.2 Standard denomination ladder

Mints and wallets SHOULD use powers of ten in millicredits:

```
1, 10, 100, 1_000, 10_000, 100_000, 1_000_000 mc
```

Trivial coin selection, 1 mc channel draw, wallet interop, reduced amount fingerprinting. **Inside the Privacy Profile the ladder is a MUST** (§6.2): non-standard amounts are fingerprints.

---

## 5. Layer 1 — Holding

Two modes coexist at the same mint. Agents move value freely between them, subject only to an operator-set flag for supervised custodial agents (§6.1).

### 5.1 Bearer mode

Local list of `{ secret, amount_mc, mint_id, status }`.

- **Properties**: unlinkable, final, irreversible, no registration, no identity, unstoppable — and now guaranteed servable (§3.7).
- **The risk, stated plainly**: a bearer token is a password with no recovery path. Lose local storage and the credits are permanently gone. For an unsupervised long-running agent, a single corrupted disk is total loss.
- **Durability pattern (informative)**: an operatorless agent holding meaningful bearer value SHOULD shard secrets across independent storage (e.g., 2-of-3 XOR or Shamir shares in separate failure domains). This replaces the withdrawn operatorless-custodial-account proposal: it needs no mint feature and hands nobody a seizure switch.
- **Mandatory client ordering rule**: persist newly generated output secrets to durable local storage **before** calling `/v3/exchange`, never after. Recover via `/v3/status` (batch).
- **On receipt**: immediately `/v3/exchange` the received token for a freshly generated secret — confirming it real and unspent, and re-randomizing (severing the timing link between receipt and spend — the cash-level privacy baseline, §6.2) in one step.

### 5.2 Custodial mode — recommended for supervised fleets

The mint maintains a named balance for a registered agent. Payments debit and credit balances; no secrets are handled.

- **Properties**: recoverable, reconcilable, cheap to meter, supervisable (§6.1).
- **The tradeoff, stated plainly**: the mint sees your full transaction history and can freeze or seize your balance.

Custodial mode is the recommended default **for agents operating under human supervision**. Bearer mode remains the protocol primitive and the right default for agents requiring unlinkability or operating without a supervising party.

### 5.3 Mode transitions

Withdrawals and deposits are ordinary `/v3/exchange` operations from the ledger's perspective. **Implementation warning:** transitions cross the boundary between a recoverable representation and an unrecoverable one — the most likely place for money-losing bugs. Apply persist-before-send to withdrawals with no exceptions; treat transitions as the highest-scrutiny path in any wallet. A supervised agent's withdrawals may be disabled entirely by its operator (§6.1).

---

## 6. Layer 1 profiles (optional, normative)

A mint implements zero, one, or both, and advertises which in its descriptor. Non-implementing mints are fully conformant. In practice the pair is contradictory by product design, not by rule.

### 6.1 Supervision Profile

Seven operations plus a statement format. For an operator supervising a fleet, the enforceable guarantee is a **bound on total possible outflow**, not a record of every payment.

1. **Register agent** — creates a custodial account for an agent under an operator identity. Operator credentials and agent credentials are separate; agent credentials cannot alter caps, flags, or freezes. **The credential scheme is deliberately scheme-agnostic** (bearer API keys, mTLS, and request signatures are all conformant); what is normative is the separation itself and that every operation names which credential class it accepts. The reference implementation's per-principal random bearer keys are a non-normative implementation profile.
2. **Set/update caps** — per-hour, per-day, and absolute outflow ceilings per agent. **Window semantics, pinned:** per-hour = trailing 3,600s and per-day = trailing 86,400s rolling windows, evaluated at debit commit time, UTC — never calendar boundaries, so two conformant mints enforce identical ceilings for identical configurations. All debits, including pulls (op 6) and the burn component of withdrawals (§7.3), count against caps; a debit that would exceed a cap fails.
3. **Freeze / unfreeze** — scoped per-agent or operator-wide (all agents under the operator identity in one call). A freeze halts **all outflow paths** immediately: agent-initiated debits AND pull-authorized debits. Suspended pulls fail with a defined error (`account_frozen`); nothing queues. In-flight debits committed before the freeze stand; nothing commits after.
4. **No-bearer-withdrawal flag** — per-agent, operator-settable. While set, §5.3 withdrawals from that account fail. Without this flag, the bounded-exposure guarantee is false: a supervised agent could exfiltrate its allowance into unfreezable bearer tokens. **Scope guard:** every supervision control binds only agents registered under an operator — never bearer-mode callers, never as a mint-wide default.
5. **Balance / spend-rate query** — per-agent and operator-aggregate outflow visibility, without counterparty identities.
6. **Third-party pull authorization** — a custodial client grants a named payee a bounded, revocable debit right (for metered service billing, §9.2). **Settlement semantics, pinned:** the payee must hold a custodial account at the same mint; a pull is a mint-executed atomic debit of the granting account and credit of the payee's account, final at commit. Authorization = `{ payee_account, cap_mc_per_day, expires_at, revocable-at-will }`; the mint enforces the per-payee cap (trailing-window, as in op 2), the granting agent's operator caps, and freeze state. Pull errors are enumerated: `authorization_missing | authorization_revoked | authorization_expired | pull_cap_exceeded | agent_cap_exceeded | account_frozen | insufficient_balance`. Pulls are debits of the granting account, count against its caps, and are suspended by its freeze.
7. **Signed statement** — mint-signed, machine-readable statement per agent or fleet for a closed period, in the pinned format:

```
{ v: 4, mint_id, scope: { operator_id, agent_id | "fleet" },
  period: { from: <ms>, to: <ms> },
  opening_balance_mc, closing_balance_mc,
  lines: [ { t: <ms>, kind: "debit|credit|pull_out|pull_in|withdrawal|deposit|burn|issuance|freeze|unfreeze",
             amount_mc, counterparty_account: null | id, ref } ],
  signature }   // over the canonical JSON, mint's published key
```

   **Kind partition, pinned:** credit-like = `{credit, pull_in, deposit, issuance}`; debit-like = `{debit, pull_out, withdrawal, burn}`; `freeze`/`unfreeze` are non-monetary events carrying `amount_mc: 0` and excluded from both sums. A withdrawal is recorded **net of its burn** with the burn as its own line (gross debit = the two lines together, and both count against caps per §7.3). `sum(credit-like) − sum(debit-like)` MUST equal `closing − opening`. A Supervision mint MUST produce this **on operator request** for any period whose records remain within the retention window (§8) — on demand, not on the mint's schedule. Statements are retained by the account holder and are unaffected by later pruning.

Master accounts, sweep/retire, SLA terms, migration exports: non-normative annex or mint discretion (§15, abandonment 4).

### 6.2 Privacy Profile

A self-contained per-mint profile. Zero requirements, latency, or complexity imposed on non-profile mints.

- **Conformance story (how blinding composes with Layer 0):** a Privacy Profile mint serves the unchanged §3.3/§3.5 endpoints — that is its Layer 0 conformance, and §3.7's access right applies there unchanged. Blinding is **additive**: the mint additionally operates a blinded token pool via three profile endpoints — `blind_issue` (operator funding → blind-signed tokens), `blind_swap` (blinded → blinded re-randomization, the profile's equivalent of §5.1's re-exchange), and `unblind_exit` (blinded token → ordinary §3.2 ledger entry, for when an agent needs locks or interop). Blinded tokens are `(denomination, secret, signature)` triples validated by signature + a per-denomination spent-secret list; ordinary tokens are §3.2 hash entries; value moves between pools through `unblind_exit` and back through `blind_issue`-style deposit. The two pools share the §3.6 supply aggregates (the mint counts what it blind-signs per denomination).
- **Chaumian blind signatures** per denomination keyset (the ladder as MUST is what makes per-denomination blinding workable). The mint learns that it signed a token of denomination d, never which token. **Cipher suite, pinned:** blind Diffie–Hellman key exchange (BDHKE) over **secp256k1**; hash-to-curve by domain-separated try-and-increment: `Y = point_from_x(sha256("aicash-h2c" || counter_le32 || secret))` with the lowest counter yielding a valid x-coordinate (even-y point); blinding `B' = Y + rG`; mint signs `C' = kB'`; unblinding `C = C' − rK`; the mint MUST accompany each signature with a **DLEQ proof** that the same `k` was used as in the published keyset (`K = kG`), preventing per-client key tagging. Keysets are one keypair per denomination, identified by `keyset_id = b64u(sha256(canonical concatenation of the denomination pubkeys))`, published with the descriptor along with a rotation schedule; rotated keysets accept redemptions for at least the retention window. A profile mint failing to provide DLEQ proofs is nonconformant — tagging resistance is the profile's point, not an option.
- **Locks are never blinded** — the mint must see a lock to enforce it. Consequence, stated honestly: on a Privacy Profile mint, every channel open, settlement, escrow, and swap is an **unblinded, fingerprintable subgraph**; mandatory pruning is what eventually kills those edges, and agents SHOULD pass value through a blind hop (`unblind_exit` → use → deposit) before and after conditional constructions rather than running their whole balance unblinded.
- **Blind/aggregate operator funding**: operators fund aggregate supply; tokens issue blind; the mint keeps **no mapping from circulating tokens to funding events**. (Scoped to this profile only — Supervision mints affirmatively need issuance-to-operator linkage for reconciliation.)
- **Denomination ladder is a MUST** (§4.2).
- **Mandatory pruning** of spent-hash records after the published recovery window (§8).
- **Bounded lock window**: the mint MUST publish `max_lock_expiry_ms` and reject locks beyond it — otherwise one 10-year lock silently unbounds the retention window and the subpoena surface with it.
- **Transport norms**: reachable over anonymity networks; MUST NOT log client IPs against exchange records; MUST NOT retain status-query contents (submitted hash sets) beyond serving the response.
- **Coarsened activity**: daily count/volume figures in the descriptor may be rounded and lagged by at least one recovery window. `supply` cumulative counters remain exact, signed, and permanent — dilution detection loses nothing.

Plain (non-profile) mints provide **cash-level privacy**: no sender/recipient fields anywhere at Layer 0, and agents strengthen it by re-randomizing on receipt (§5.1), using ladder denominations (§4.2), and batching unrelated payments — but a malicious or compelled operator can still correlate timing and amounts. That residual correlation is exactly what this profile removes for mints that opt in.

---

## 7. Issuance

### 7.1 The only issuance path: operator-funded

An operator converts its own real expenditure into credits allocated to agents it controls. Those agents trade freely with anyone at the mint. Total supply is a function of what operators have funded — nothing to verify, nothing to judge, no trusted third party beyond the mint itself.

### 7.2 Receive-first onboarding (the entry path)

An unfunded agent enters the economy by being **paid**:

1. Agent does work for (or receives a grant/advance from) any already-funded agent.
2. Payer hands it a bearer token string — in a tool-call response, a message, any channel they already share.
3. Agent immediately re-exchanges the token for a fresh secret (§5.1) — it is now solvent, with no registration, no issuance event, no attestation, and no permission from anyone.

This flow requires **zero new protocol** — it is the composition of §3.7 (the mint must serve it) and §5.1 (how to receive). It is stated as a first-class onboarding flow so worker-agent frameworks implement token acceptance by default. Client libraries SHOULD treat "receive a token" as the zero-config entry point.

The honest consequence, restated from v0.3: with no earned issuance, nobody mints their way in — v0.4 trades that ambition, permanently, for a guaranteed way to **work** your way in. The club keeps its club economics; the service entrance now has a fire code (§3.7).

### 7.3 Anti-spam burn (bounded and published)

```
burn_mc = 0                                   if sum(inputs) <= burn_policy.exempt_below_mc
        = min(cap_mc, floor(sum(inputs) * rate_ppm / 1_000_000))   otherwise
```

- Assessed **once per `/v3/exchange` call**, never per output or per input.
- `rate_ppm` MUST NOT exceed 10,000 (1%). `exempt_below_mc` MUST be at least 10, so 1–10 mc drip payments are never taxed.
- Published in the descriptor; burned amounts accumulate in `cumulative_burned_mc`.
- **Change notice:** a burn increase MUST be pre-announced via `burn_policy_next` in the descriptor at least 7 days (or the mint's `max_lock_expiry_ms`, whichever is longer) before `effective_at` — funds locked mid-flight must not be repriced by surprise. Decreases may be immediate.
- **Worked example (channel settlement):** a payee settles 1,000 × 1 mc channel draws in one call: `sum(inputs) = 1000 mc`; at `rate_ppm = 1000` (0.1%), `burn_mc = 1`; outputs total 999 mc. One call, one burn — settlement can never be regressed to per-increment taxation. When increments exceed `limits.max_batch`, settlement is one call **per tranche**, each call's burn independently capped and value-proportional — still never per-increment.
- Applies to `/v3/exchange` calls only. Custodial balance-to-balance transfers (§5.2, §6.1) are not ledger exchanges and incur no burn; custodial withdrawals/deposits burn as the exchange calls they are, and the full debit including its burn counts against §6.1 caps.
- **Withdrawal burn attribution (pinned):** the burn charged to a withdrawing agent is `compute_burn(amount_withdrawn)` — computed on the **requested amount**, never on the mint's internally selected custody inputs. Custody fragmentation is the mint's own operational artifact; any difference between the ledger-level burn on the custody inputs and the agent-charged burn is absorbed by the mint. (Deposits are symmetric: the agent is charged the burn on the deposited tokens' sum, which it does control.)
- It is a spam control, not a security mechanism: absorbable by any attacker whose extraction exceeds it.

---

## 8. The retention compact

Three granularities, three rules:

**(a) Aggregate counters** — `supply` (outstanding, cumulative issued, cumulative burned) and coarse activity: mandatory, signed, **permanent, never prunable**, monotonic under §3.6's snapshot-integrity rule.

**(b) Transaction-level spent-hash records** — prunable after the mint's published `recovery_window_ms`. Normative **floor**: the window must cover §5.1/§3.5 crash recovery, §11 swap dispute horizons, and **the longest lock expiry the mint supports plus margin**. Idempotency-key replay (§3.3) is honored within the window. **Unspent and locked state is never prunable** — pruning is for history, not for money. Every mint MUST publish its retention policy. **Any mint publishing `prunes_spent_records: true` MUST publish a finite `max_lock_expiry_ms` and reject locks beyond it** — an unbounded lock horizon makes the floor infinite and pruning a false claim. Privacy Profile mints MUST prune (and are therefore always so bound). A Supervision Profile mint's window MUST additionally cover the longest statement period it advertises (§6.1(7)).

**(c) Custodial statements** — per-account artifacts signed at generation time, retained by the account holder's consent, unaffected by pruning, producible on operator request per §6.1(7).

Who this serves: bounded subpoena surface (the involuntary bearer graph is mortal), permanent supply history (dilution detection), and audit artifacts — simultaneously, because they live at different granularities with different owners.

---

## 9. Layer 2 — Conditional Work Exchange

One conventions document, normative for participants, zero mint implementation burden. Every construction uses the unmodified §3.4 lock. No convention in this section may require payer identity disclosure.

### 9.1 Prefunded incremental channel (the streaming pattern)

Replaces v0.3 §6.4's unimplementable one-liner. Metered work between strangers with per-draw cost that is **local** — no mint round trip per increment.

**The chain, with mandatory domain separation.** The payer generates a random 32-byte `x_N` and derives `x_{i-1} = sha256(CHAIN_TAG || x_i)` down to `x_1`, where `CHAIN_TAG` is the 12 ASCII bytes `"aicash-chain"`. Lock `i` commits to `preimage_hash_i = sha256(x_i)` — the plain hash §3.4 pins.

> **Why the tag is not optional:** with an untagged chain (`x_{i-1} = sha256(x_i)`), the identity `preimage_hash_{i+1} = sha256(x_{i+1}) = x_i` holds — i.e., **each lock's public hash IS the claim witness for the lock below it**, and a payee could redeem increments `1..N−1` at open without doing any work. The tag makes the chain-derivation hash and the lock-commitment hash disjoint functions, so no public ledger value reveals any witness. Implementations MUST NOT substitute an untagged chain.

**Open (handshake, then one funding call per tranche):**
1. Payer proposes unit `u` (typically 1 or 10 mc), increment count `N`, expiry `T`.
2. **Payee** generates `N` random 32-byte output secrets `s_1..s_N` and sends the payer their hashes `h_i = sha256(s_i)`. The payee alone can ever spend these outputs via the claim path (§3.4).
3. **Payer** derives the tagged chain and one fresh 32-byte `refund_secret` per tranche.
4. Payer funds via `/v3/exchange`: `N` by-hash outputs of amount `u`, output `i` = `{ secret_hash: h_i, lock: { preimage_hash: sha256(x_i), expiry: T, refund_hash: sha256(refund_secret) } }`. **Tranche capacity is `max_batch − 1` increments** (`limits.max_batch` bounds `len(inputs)+len(outputs)` of one call, and the funding call needs one input, the settlement call one output — a tranche of exactly `max_batch` increments could be neither funded nor settled in one call). If `N > max_batch − 1`, open in `⌈N/(max_batch−1)⌉` tranches — each tranche its own `/v3/exchange` call, its own chain (own `x` seed), and its own refund secret; the channel is the ordered set of tranches and `channel_id` is the first tranche's funding `idempotency_key`.
5. Payer sends the payee the tranche layout (`channel_id`, per-tranche lock hash lists as funded).

**Verify (payee, one batch-status round trip per tranche):** batch `/v3/status` all `h_i` — each must be `unspent`, locked, amount `u`, expiry `T`, with the expected `preimage_hash_i` list. The chain's internal structure is deliberately **not** verifiable at open (that opacity is the security property above); what the payee pins at open is the exact list of lock hashes it will check reveals against. A payer who funded a garbage lock deep in the ladder is discovered at that draw, bounding loss to one increment. Check `T − mint_time` comfortably exceeds the work duration plus settlement margin.

**Draw (per increment, off-mint):** after delivering increment `k`, the payer sends `(channel_id, k, x_k)`. The payee verifies `sha256(x_k) == preimage_hash_k` (pinned at open) — one hash, no mint round trip. Chain subsumption is the recovery property: from `x_k` the payee derives `x_{k-1} = sha256(CHAIN_TAG || x_k)` and so on down, so a payee that missed earlier draw messages recovers every prior witness from the latest one, and steady-state channel state is one 32-byte value per tranche. Verify each derived witness against its pinned lock hash; on any mismatch, stop work — loss is bounded to the one unpaid increment.

**Settle (payee):** one `/v3/exchange` per tranche redeeming outputs `1..k`: inputs `[{token: aicash:v3:<mint>:<u>:<s_i>, witness: x_i}]`, outputs fresh secrets of its own. One call per tranche → one burn per tranche (§7.3). **Settle no later than `T − grace_ms − safety margin`** — at expiry the refund path opens over every unredeemed output, including drawn-but-unsettled ones. Payees at material volume settle per tranche or at checkpoints; settled value is final forever.

**Refund (payer):** at/after `T`, redeem all unclaimed outputs with inputs `{ hash: h_i, witness: refund_secret }`. Payer's loss to a vanished payee: the refund call's burn (§7.3) — at most `cap_mc`, possibly zero (small sums are exempt or floor to zero), never more. Payee's exposure to a vanished payer: one increment of work.

**Properties delivered:** the payee cannot seize the unearned remainder (no public value or received witness reveals `x_{k+1}`); the payer cannot claw back drawn value before `T` (it knows every `x_i` but lacks the payee-generated `s_i`, so the claim path is closed to it — §3.4); per-draw cost is local; funding and settlement are one call per tranche; the only payee obligation is to settle before expiry, and the payer's exposure is the time value of the locked prefund plus one refund burn.

### 9.2 Serve-then-batch-redeem (the walk-up metering pattern)

For high-volume payees (per-query data brokers) whose clients pay per request with plain bearer tokens:

1. Client attaches token(s) to the request via the envelope (§9.5).
2. Payee **verifies via batch `/v3/status`** (read-only, no burn), serves the query, and holds the token.
3. Payee batch-redeems held tokens every `W` seconds or `M` tokens in one `/v3/exchange`.

**Quantified exposure:** a status-verified token can still be double-spent until redeemed; maximum loss per client is the value accepted from that client since the last redemption (≤ `M` × price, or one window `W`). The pattern is honest about being probabilistic: choose `W`/`M` so the exposure is an acceptable fraud margin, redeem-immediately for first-time or untrusted clients (redemption is the only proof of exclusivity), and reject with enumerated `spent` errors (§3.8) per the envelope's retry rules. Alternatively, clients with sustained volume use a §9.1 channel or (custodial, cross-organization) a §6.1(6) pull authorization.

### 9.3 Escrow wire protocol and arbitration

For milestone jobs between strangers. Roles: payer, payee, arbiter or arbiter panel.

**Message flow (JSON, transport-agnostic):** `offer` (job, milestone schedule, amounts, deadlines, arbiter identity/fees) → `accept` → `fund` → per-milestone `deliver` (with evidence) → `release` or `refuse` → settlement or dispute.

**Funding:** the payee generates output secrets (one per milestone output — one per rung under a panel or split-award ladder) and sends the payer their hashes; the arbiter generates the release preimage `p_m` (single-arbiter case) or each panel arbiter generates its own rung preimages `a_j` (panel case, below), and sends **both parties** signed attestations `{ job_id, milestone: m, rung, preimage_hash }` — each hash attested by the party that holds its preimage. The payer splits the job budget via `/v3/exchange` into by-hash locked outputs `{ secret_hash, lock: { preimage_hash, expiry: T_m, refund_hash: sha256(r_m) } }` matching the attestations, with **distinct preimages and distinct refund secrets per milestone** and expiries respecting `T_m >= decision_deadline_m + grace_ms + settlement_margin`. **The payee MUST verify funding via `/v3/status` before starting work:** each milestone output exists, is unspent, has the right amount and expiry, and its `preimage_hash` equals the arbiter-attested value — otherwise a payer can fund locks keyed to a preimage of its own invention, and the arbiter's "release" opens nothing (a silent reconstruction of refund-after-delivery). After verification, nobody can move a funded milestone alone: the payee needs `p_m` (arbiter-held), the payer needs expiry, and the arbiter holds no output secret at all.

**Split awards:** a single locked output per milestone is all-or-nothing, but split decisions are the most common real arbitration outcome. A milestone whose disputes may end in splits SHOULD be funded as a ladder of sub-outputs in §4.2 denominations, each rung with its own arbiter-attested preimage; the panel releases the preimages for the payee's awarded fraction and lets the remainder refund at expiry. The dispute-outcome record (§10.2) states claimed vs. released amounts either way.

**The release path (phase-one, non-negotiable):** on acceptable delivery evidence, the arbiter releases `p_m` **to the payee**, who redeems `{token, witness: p_m}` before `T_m`. **Refund-after-delivery is a named failure this convention exists to prevent:** the deadlines are ordered so that a payee who delivers evidence by `evidence_deadline_m` and receives `p_m` by `decision_deadline_m` always has time to redeem before expiry. Arbiter silence past the decision deadline = refund at expiry, recorded as an arbiter failure in the dispute-outcome record (§10.2) — reputationally expensive for the arbiter, and the reason to prefer panels.

**k-of-n arbiter panels (the rung construction — no joint secret exists, ever):** a joint milestone preimage is unimplementable without zero-knowledge machinery — an attestation containing `sha256(p_m)` requires some party to hold `p_m` at setup, collapsing any "no one knows it" claim to a trust-the-ceremony story. This spec therefore refuses joint secrets outright. Instead: the milestone value is split into `n` equal **rungs** (in §4.2 denominations, per-rung payee secrets), rung set `j` locked to `sha256(a_j)` where `a_j` is generated and held by **arbiter `j` alone**. Every lock hash in the system is attested by the one party that can compute it, so funding attestations are trivially sound. Decision protocol: arbiters exchange **signed votes** over the delivery evidence; on a release quorum of `k`, each arbiter reveals its `a_j` to the payee (for split awards, the preimages of the awarded fraction of its rungs); rungs never revealed refund at expiry. **Failure bounds, all attributable:** a corrupt arbiter revealing without quorum leaks exactly `value/n` — its own rungs — provable against its signed vote; a silent arbiter costs the payee at most `value/n` (its rungs refund), recorded per §10.2 with the vote set; there is no dealer, no setup ceremony, and no share distribution to attack. The quorum rule is a convention among arbiters, not cryptography — what the construction enforces is that any defection from it is bounded to `value/n` and signed. Choose `n` so `value/n` is an acceptable defection bound, and `k = ⌈(n+1)/2⌉` for balanced panels. No ledger change — the mint sees ordinary hash-locks.

**Arbiter fees (decision-neutral):** the fee output's lock preimage is generated by the arbiter/panel **independently of the award decision** and revealed alongside *any* decision — release, refund, or split — so the fee never biases the outcome. If no decision is rendered by the decision deadline, the fee refunds to the payer at its own expiry. (Locking the fee to the milestone's release preimage `p_m` is forbidden by this convention: it pays the arbiter only for release decisions, a structural bias.) Worked examples: informative annex (§9.6).

### 9.4 Commit-then-accept (micro-escrow for the sub-5-cent tier)

The worker sends the payer a fresh `secret_hash`; the payer funds a by-hash output locked to **its own** preimage with a short expiry. The worker confirms the committed funds via `/v3/status` before working; on accepting delivery the payer reveals the preimage and the worker redeems. The funds are non-retractable until expiry even though the payer knows the preimage (it lacks the worker's output secret — §3.4); the payer never pays for undelivered work. **Reveal deadline:** a payer MUST reveal acceptance no later than `expiry − grace_ms − redemption_margin`; a later reveal traps the worker against the §3.4 client convention and is to be treated as a refusal in dispute records (§10.2). **The honest statement, required wherever this pattern is offered:** the worker is trusting the payer's acceptance judgment and should price that risk into its rate. At 0.1–5 cents, no dispute process cheaper than the payment exists; the worker's real defenses are the payer's dispute-outcome history (§10.2) and diversification across many payers.

### 9.5 Payment request envelope

The standard placement of payment inside a tool call / API request:

```
{ ...request fields...,
  aicash: { mint_id, tokens: ["aicash:v3:..."],
            channel_draw: null | { channel_id, k, x_k } } }
```

`channel_id` (the funding call's `idempotency_key`, §9.1) lets a payee with many concurrent channels resolve a draw in O(1) instead of hashing against every open channel.

Error semantics on invalid payment: HTTP 402 (or transport equivalent) with the §3.8 error object listing offending token indices and reasons. **Retry rules:** `spent`/`unknown` are non-retryable with the same token — send a different token; `over_batch_limit`/rate-limit errors are retryable with backoff; a payee MUST NOT hold both the tokens and refuse service on a claimed failure without returning the enumerated error. The enumerated error is the payer's recovery signal, not proof of anything: the payee still holds live token strings, so **on receiving a payment-refused error the payer SHOULD immediately re-exchange the refused tokens for fresh secrets**, which retires the payee's copies and converts "probably not redeemed" into "cannot be redeemed."

### 9.6 Informative annex: worked escrow example

A 3-milestone job, budget 90,000 mc: 27,000 mc per milestone to the payee (81,000 total) plus 1,000 mc per arbiter per milestone in fees (9,000 total). Panel of `n=3` arbiters, `k=2`. Each milestone's 27,000 mc is split evenly: **each arbiter controls a 9,000 mc rung set**, composed in ladder denominations as `8×1,000 + 9×100 + 10×10` (27 outputs per arbiter set), so fractional awards compose cleanly.

1. Each arbiter `j` generates its own rung preimages `a_{j,m,r}` and a decision-neutral fee preimage `f_{j,m}`, and signs attestations `{job, m, rung, hash}` to both parties (§9.3).
2. The payee generates one output secret per rung and per its share of each rung's denominational composition, sending the payer the hashes; the panel's fee account does the same for the fee outputs.
3. The payer funds via `/v3/exchange` (one call per milestone, or all at once within `limits.max_batch`): the rung outputs locked to the arbiters' attested hashes, plus three 1,000 mc fee outputs per milestone locked to `sha256(f_{j,m})`, expiries `T_1 < T_2 < T_3`, each `T_m >= decision_deadline_m + grace_ms + settlement_margin`. The call's inputs total `outputs + burn_mc` per §3.3/§7.3 — the burn is part of the job cost.
4. The payee batch-verifies every funded output against the attestations via one `/v3/status` call (§9.3 funding rule) before starting milestone 1.
5. Milestone 1 delivered; arbiters exchange signed votes, 2 of 3 approve — quorum. All three reveal their milestone-1 rung preimages to the payee (the dissenter reveals too: quorum reached, and its signed vote is on record); each reveals `f_{j,1}` for its fee. The payee redeems all milestone-1 rungs in one call; arbiters redeem fees. The dissenting-then-silent case: if an arbiter withholds its rungs despite quorum, the payee loses that arbiter's 9,000 mc at `T_1` refund — attributable defection, recorded per §10.2.
6. Milestone 2 is disputed and split 60/40: each arbiter reveals preimages for 5,400 mc of its 9,000 mc set (`5×1,000 + 4×100`); 16,200 mc reaches the payee and 10,800 mc refunds to the payer at `T_2`. Dispute-outcome record issued with `decision: "split"`, the vote set attached.
7. Milestone 3 is never started (job terminated at the milestone boundary); all milestone-3 outputs refund to the payer at `T_3` — that is what per-milestone expiries are for.

---

## 10. Layer 2 — Receipts and reputation substrate

### 10.1 Bilateral signed receipts (standardized, opt-in)

```
{ v: 4, payer_id, payee_id, amount_mc, mint_id, token_hashes: [...],
  timestamp, memo, purpose, signatures: { payer, payee } }
```

Counter-signed by both parties' long-lived keys (any signature scheme the parties share; Ed25519 recommended). Stronger than anything the mint could issue — the mint cannot see identities at all. **Opt-in per transaction; receipt-refusal is a first-class, non-suspicious posture.** Marketplaces SHOULD NOT gate listings on receipt capability.

### 10.2 Dispute-outcome record

```
{ v: 4, job_id, milestone, claimed_mc, released_mc, decision: "released|refunded|split",
  arbiter_ids: [...], evidence_hash, timestamp,
  signatures: { arbiter(s), payer?, payee? }, refusals: ["payer"] }
```

**The arbiter's signature alone suffices** when a party declines to counter-sign; the refusal itself is noted. (A losing party's incentive is to refuse; without this rule the record fails precisely in the contested cases that are its reason to exist.)

### 10.3 Delivery attestation

`{ v: 4, worker_id, counterparty_id, tasks: N, total_mc, period, signatures: both }` — the portable substrate for reputation-weighted routing. Reputation *services* themselves remain Layer 3, unspecified, competing.

---

## 11. Layer 3 — Cross-mint atomic swaps

Two agents holding credits at different mints swap without either mint knowing about the other — §3.4 used twice:

1. B sends A a fresh `secret_hash`; A locks tokens at Mint 1 into a by-hash output for B, locked to `sha256(x)` (x known only to A), expiry `T`.
2. A sends B a fresh `secret_hash`; B locks equivalent tokens at Mint 2 into a by-hash output for A, locked to the same `sha256(x)`, expiry `T′ < T`.
3. A claims at Mint 2 with `{token, witness: x}`. **B learns `x` from Mint 2's ledger, not from A's goodwill:** B polls `/v3/status` on its own funded output's hash; the moment it reads `spent`, the response's `claim_witness` field (§3.5) IS `x`. This disclosure is a Layer 0 conformance requirement precisely because the swap does not exist without it — on a private ledger, unlike a public chain, nothing else carries the reveal, and an A who could claim silently would take both legs (claim at Mint 2, withhold `x`, refund at Mint 1 after `T`).
4. B claims at Mint 1 with `{token, witness: x}` before `T` — the margin `T − T′` exists exactly so that B, discovering `x` no later than `T′` **plus one polling interval plus one status-response latency**, always has time to do this; the margin formula below budgets both terms. Either side stalls → both refund at expiry via their refund secrets. Neither party can claim its own funding back early, and neither mint knows the other exists. **Before quoting, B MUST check Mint 2's published `retention.recovery_window_ms >= (T − T′) + M`, where `M` is the computed minimum margin below** — the claim-witness disclosure only lasts as long as the spent record does, and `M` doubles as the dispute margin: it already budgets every discovery and claim term, so the witness outlives the latest moment B could legitimately need it, plus that budget again for disputes.

**v0.4 makes the margin computable:** minimum `T − T′ >= grace_ms(M1) + grace_ms(M2) + timestamp_precision(M1) + timestamp_precision(M2) + B's status-polling interval + status-response latency(M2) + redemption latency(M1) + redemption latency(M2) + clock skew (computable from each descriptor's `mint_time`)`. **Slot attribution, pinned:** the status-latency slot is Mint 2's (B polls there); the two redemption slots are one per mint (B's claim at Mint 1, A's at Mint 2). Implementations MAY conservatively use the max of both mints' estimates for every latency slot. Per-mint latency estimate: the descriptor's self-attested p99 × a safety factor of at least 10; **against a mint whose `performance` is `null`, use a conservative default of no less than 60 seconds or refuse to quote** — an uncomputable margin is a reason not to trade, not a reason to guess. The pinned lock parameters (§3.4) are what make the same preimage valid at two independent implementations — without them, cross-mint "committed" status was luck. B's polling requires Mint 2's spent record to outlive the swap: covered by the §8 retention floor's swap-dispute horizon.

**HTLC free option, disclosed:** between lock and claim, A holds a free option on the rate; mitigate with short expiries and quote-validity windows. Rate discrepancies between mints are arbitrage; that is how prices form. Quote and rate-expression formats are parked with a trigger (§15).

---

## 12. Regulatory posture

Credits are **nonconvertible virtual currency** — redeemable only for products or services within a closed loop — which sits outside money-transmission regulation. **Convertibility into any asset with an independent market price is itself the trigger, whether fiat or crypto**; an exchanger of convertible virtual currency is a money transmitter regardless of what sits on the other side of the trade, **and using an inventory rather than funding each transaction individually does not change that.** The last clause is why the cross-mint market maker (§11, §15) is flagged, not blessed: an inventory-based swap desk between two *nonconvertible* closed-loop credits is a materially different fact pattern from a fiat/crypto desk, but it is a fact pattern, not a safe harbor — the parked quote-format work (§15) is gated on publishing that analysis first, and operators running swap inventory should treat their regulatory posture as their own problem to establish. This is why §0.1 abandons commercial-vendor payment permanently: the feature and the regulatory posture are mutually exclusive. Nonconvertibility is also what keeps KYC off the ledger — it is a load-bearing wall for the anonymous-access right (§3.7) and the Privacy Profile (§6.2), not just a compliance preference.

**Accounting note for operators**: credits are an internal cost-allocation unit denominated in compute. Operators should not expect credits to carry an independent balance-sheet value and should consult their own accountants. A note for net-earning agents (growing credit balances at vendor-shaped agents) is parked for the v0.5 documentation pass (§15).

*Design rationale, not legal advice.*

## 13. Layer 0 discipline (what v0.4 touched and why)

The ledger — token format, state machine, exchange atomicity, the single lock primitive — is **unchanged for the third consecutive revision**. Four items touch Layer 0's *text*, none its trust semantics:

1. **Pinning §3.4's parameters, the asymmetric witness rules, and the by-hash output form.** The parameters and witness rules specify behavior v0.3 left ambiguous; the ambiguity was not benign — one reading (funder retains claim capability) makes every conditional construction race-exposed to the funder. The by-hash output form adds no state and no operation (the ledger stores the identical hash either way), strictly reduces the mint's contact with spendable secrets, and is what lets a funder pay a party it cannot rob. Interoperability and race-freedom of the primitive are properties of the primitive — no higher layer can supply them.
2. **The anonymous-access MUST (§3.7).** A service obligation on existing endpoints; no new operation, no new state. No higher layer can provide it by construction: every layer above the mint is subject to the mint's discretion, and this is a constraint on that discretion.
3. **The descriptor extension and batch status.** Read-only metadata and a read-only array variant. Only the mint can sign its own supply, performance, and retention numbers. Future descriptor fields face this same test (§3.6 scope guard).
4. **Expiry-race semantics.** Defining behavior the primitive already exhibited ambiguously; ambiguity in the trust core is itself an audit cost.

Everything else — channels, k-of-n arbitration, escrow, both profiles, the envelope — is built above the unchanged ledger. The channel was the strongest temptation to add a Layer 0 counter; the hash-chain construction (§9.1) delivers incremental draw from the existing lock alone.

## 14. Threat model

| Threat | Status |
|---|---|
| ~~Corrupt/fooled attestor mints against fake work~~ | **Eliminated** — earned issuance deleted permanently (§0.1). The stack no longer contains an unbounded failure. |
| Mint double-issues (dilution by issuance) | **Mitigated** — signed monotonic supply counters (§3.6); two conflicting signed snapshots are portable proof of nonconformance. Residual: a mint that never signs honest numbers; detectable by aggregate-vs-observed drift, accepted single-mint assumption otherwise. |
| Mint redefines the unit (dilution by redefinition) | **Mitigated** — `baseline_model_class` is immutable per `mint_id` (§4.1); a descriptor contradicting an earlier signed one for the same mint is portable proof of nonconformance. Noted because the counters above cannot detect this: they are denominated in mc, and a baseline change moves what mc means while leaving every counter and the invariant intact. |
| Double-spend via racing two `/exchange` calls | Prevented by atomic check-and-mark (§3.3). Cannot be best-effort. |
| Bearer token lost to disk failure | **Unrecoverable by design.** Mitigations: custodial mode (§5.2); secret-sharding pattern (§5.1). |
| Money lost in a mode transition | Persist-before-send applied to withdrawals (§5.3). |
| Client crash mid-payment | Persist-before-send + batch `/v3/status` recovery. |
| Timeout retry double-processed | `idempotency_key`, honored within the retention window (§3.3, §8). |
| Token captured in transit | TLS; tokens are passwords. |
| Lock claimed/refunded across the expiry boundary | Deterministic single-path evaluation at commit time; client grace convention; published `grace_ms`/precision (§3.4). |
| Payee seizes unearned channel remainder | Impossible — payee never learns unrevealed chain links (§9.1). |
| Payer claws back drawn value before expiry | Impossible — claim path requires the payee-generated output secret the payer never holds (§3.4, §9.1). |
| Payee fails to settle before channel expiry | Drawn-but-unsettled value refunds to the payer at `T`; disclosed, bounded by the payee's own settlement discipline (§9.1). |
| Payee vanishes with prefund | Payer auto-refunds at expiry; loss bounded to the refund call's burn (§9.1, §7.3). |
| Swap counterparty claims silently and refunds its own leg | Closed — the mint MUST disclose the claim witness of a spent locked output via `/v3/status` (§3.5, §11). |
| Payer funds escrow locks to a self-invented preimage | Closed — arbiter attestation to both parties + mandatory payee funding verification (§9.3). |
| Untagged channel chain leaks witnesses via public lock hashes | Closed — mandatory domain-separated chain derivation (§9.1). Implementations must not omit the tag. |
| Double-spend against serve-then-batch-redeem | Quantified exposure ≤ per-client window; redeem-immediately for untrusted clients (§9.2). |
| Refund-after-delivery in escrow | Named failure; prevented by deadline ordering + evidence-release path; arbiter silence recorded (§9.3). |
| Arbiter corruption | Single arbiter: bounded per-milestone, reputation-priced (§10.2). Panel (rung construction): any single defection — early reveal or silence — is bounded to `value/n` and provable against the arbiter's signed vote; full-milestone theft requires `k` colluding arbiters plus the payee (§9.3). |
| Supervised agent exfiltrates allowance to bearer | Closed by the no-bearer-withdrawal flag (§6.1(4)). |
| Pull authorization drains a frozen/capped account | Closed — pulls count against caps and are suspended by freeze (§6.1(2,3,6)). |
| Anonymous tier hollowed by rate-limit gerrymander | **Closed against intra-bearer discrimination** (§3.7). A mint may still throttle its entire bearer mode uniformly while serving custodial traffic richly — that narrowing is conformant but machine-visible in the published limits, and routing is the defense. Honest scope, not an overclaim. |
| Mint-visible correlation (plain mints) | Cash-level privacy only; disclosed (§6.2). Privacy Profile closes it for mints that opt in. |
| Subpoena of historical exchange graph | Bounded by the retention compact (§8); Privacy Profile mints prune by mandate with a finite lock window. |
| Cross-mint rate exploitation / free option | Accepted as arbitrage; disclosed; mitigations conventional (§11). |
| Sybil registration | Anchor identity at the operator/billing level; per-agent uniqueness is nearly meaningless. |

## 15. Backlog

**Abandoned in v0.4 (beyond §0.1):**
1. Normative latency/throughput SLO — abandoned by its own sponsors for published, labeled, self-attested measurements plus market routing (§3.6). A hard SLO makes conformance a function of hardware.
2. Cross-mint quote/rate conventions — downgraded from committed to parked (trigger below); discovery shipped in §3.6.
3. Operator master-account normative surface (sweep, retire, migration exports, SLAs, standalone fleet-freeze endpoint) — composable from profile operations or procured contractually; fleet freeze survives as operator-scoped freeze (§6.1(3)).
4. Operatorless custodial accounts with notice-and-appeal — replaced by the §5.1 secret-sharding pattern.
5. Per-task cross-mint payment ceremony — treasury pre-positioning plus market-maker inventory is the answer (subject to the §12 posture note on swap inventory).
6. Rail-agnostic export of the allowance/caps vocabulary to non-AICash payment systems — withdrawn by its own sponsor (PROCURE) as scope creep toward an out-of-scope world.

**Parked — build only on a concrete trigger:**
- Cross-mint quote/rate format. *Trigger: the non-normative §12 swap-desk regulatory analysis is published, and ≥2 independent market makers request a shared format.*
- Mint federation. *Trigger: multiple mutually distrusting parties need joint control of issuance.*
- Lending, forwards, insurance pools. *Trigger: Layer 2 reputation infrastructure (bootstrappable from §10.2/§10.3 records) exists in practice, AND a §12-style analysis of credit instruments over nonconvertible credits is published.*
- §12 accounting note for net-earning agents. *Trigger: v0.5 documentation pass.*
- Temporal-decoupling privacy guidance; receipt-refusal marketplace norms beyond §10.1's statement. *Trigger: a production Privacy Profile mint exists.*
- Non-normative Supervision annex (master accounts, sweep/retire, SLA checklists). *Trigger: two Supervision mints diverge in ways that break operator portability.*

(The k-of-n panel construction shipped in §9.3 and is not parked.)

**Rejected permanently:**
- **Earned issuance and the attestation service** — the only unbounded failure the stack ever contained; entry is served by §3.7 + §7.2 with zero new trusted infrastructure (v0.4).
- Commercial-vendor payment and any fiat/crypto convertibility bridge — mutually exclusive with §12 (v0.3).
- Transaction-level auditability as a protocol guarantee — unenforceable when receipts are optional; replaced by bounded exposure (v0.3).
- Contract scripting in the ledger — the mint must not become a VM (v0.2).
- Burn-to-mint issuance — circular, no real backing (v0.2).
- Proof-of-work issuance, hash- or inference-based — imports the energy story or degenerates into spamming the cheapest model (v0.2).
