# FEDERATION.md — The Witness Ring

**Proposed as `§6.3 Federation Profile` of aicash-spec-v0.5 (optional, normative).**
**Status:** design, post-red-team. Three adversarial reviews (malicious operator, systems critic, adoption critic) ran against the draft; §7 records every finding, its verdict, and what was adopted or declined. Several findings were fatal to claims the draft made. Those claims are retracted here rather than softened.

**Layer 0 footprint:** two nullable descriptor fields, one optional read-only flag, one amendment to where the descriptor's `supply` block comes from, one sentence in the retention compact (§8). Ledger semantics (§3.1–§3.4) are byte-identical for a fourth consecutive revision.

**One-line summary of what changed against the draft:** the draft claimed silent over-issuance was structurally caught. It is not, and cannot be within this budget. The commitment is still worth building — it converts an unbounded, invisible rug into one bounded by the operator's own parked inventory, and it is the substrate everything else stands on — but the honest claim is a *bound*, not *detection*. Everything downstream of that correction is smaller and more honest than the draft.

---

## 0. What this solves, and what it deliberately does not

### 0.1 The three harms

| | Harm | Today |
|---|---|---|
| **H1** | **Rug-pull / over-issuance.** An operator mints credits for its own agents at zero cost, swaps them out at §11, closes the mint. Victims hold its credits. | §3.6's signed monotone snapshot catches *arithmetic* lying. It does not catch a mint that increments `cumulative_issued_mc` honestly and mints a fortune (§7.1 issuance is unbounded by design), and it does not catch a mint that inserts rows and never touches the counters. `BOOTSTRAP.md:222` Loop 1 already gossips `d(cumulative_issued_mc)/dt`; `BOOTSTRAP.md:301` (P1) records the accepted residual. |
| **H2** | **Mint death.** The single sqlite ledger is permanently lost; every coin at that mint is worthless. There is no second copy anywhere. | Nothing. |
| **H3** | **Coercion / single operator.** One legal person can be compelled to cease, freeze, or gate. `BOOTSTRAP.md:174` names this the cheapest kill on the whole network. | Operator legal separability (`BOOTSTRAP.md:44`), multi-homing, and minimal operator plurality as a Phase-1 exit (`BOOTSTRAP.md:68`). This document does not improve on that ranking. |

### 0.2 The core move: split the authority bundle, not the server

A mint holds three authorities in one place because one person happens to hold all three:

| Authority | Rate | Latency budget | Where the operator can steal |
|---|---|---|---|
| **Settlement** — mark hashes spent, insert hashes unspent (§3.3) | 10²–10⁴/s | sub-second (§0 thesis) | **Nowhere.** By L2/§3.2 the mint stores hashes, never secrets. It can refuse service and lie about aggregates; it cannot spend your coin. |
| **Issuance** — create value from nothing (§7.1) | a handful/week | days would be fine | Everywhere. |
| **Identity & succession** — sign the descriptor, own `mint_id`, rotate keys (§3.6) | a handful/year | weeks would be fine | Everywhere. |

Every classic federation replicates **settlement** — the hot, latency-bound authority where all the cost lives — and gets the other two as a side effect. That is backwards. So: **federate issuance and identity; leave settlement single-writer; replicate state without agreeing on it.**

That thesis survived all three red teams intact. What did not survive is the draft's confidence about how much a commitment-plus-cosignature scheme buys against a *malicious* operator.

### 0.3 What this deliberately does not solve

Stated first, so no reader has to hunt for it.

1. **The backing rug.** An operator issues 10⁹ mc perfectly within a published policy against zero real spend, swaps out at §11, and closes. No mechanism here touches it. §7.1's "backing" is the operator's own real expenditure — an unverifiable external fact, and L10/§0.1 permanently forbid building the thing that would verify it. **A policy-conformant issuance against nothing is fully certified.** This is the rug a rational operator actually runs.
2. **Tree completeness.** A mint can commit to a set of its own choosing (§7, MO-A1 / SC-A5). This cannot be closed within the budget. The residual is a *bound*, not detection: see §4.1.
3. **Per-payment censorship.** No party in this design ever sees an individual payment. A compelled operator quietly refusing service to a named party is invisible to every mechanism here.
4. **The cheapest kill.** A lawful cessation order against one legal person. This design does not reduce its probability by one percentage point, and it **adds** new compellable parties (§8.6, §8.7).
5. **Convertible value in succession.** L9 means there is no backing to transfer. A perfect succession proof is a signed, quantified receipt for a loss unless a funded successor exists, which is a social problem no protocol solves.

### 0.4 The budget these solutions had to fit

- Layer 0's ledger semantics have been unchanged for three revisions; §1 names "small enough to audit in an afternoon" as the project's most valued property. Measured trust core today: `ledgerstore.py` 716 + `tokencodec.py` 239 + `lockeval.py` 188 + `burncalc.py` 180 = **1,323 LOC**. A federation that turns the mint into a BFT consensus system spends that entire asset — it moves the safety argument from "read 1,323 lines" to "trust a proof and a library," which is a change of *category*.
- Token format and wallet payment behavior must not change. `mint_id` already names an abstract minting authority (§3.1).
- No blockchain, no PoW, no global consensus, no mining. L9 nonconvertibility stays. L10 no attestation service.
- Sub-second settlement is the §0 thesis. Nothing multi-round on the payment path.
- A mint must stay cheap enough for one motivated operator.
- Prefer primitives that already exist: §3.4 hash-lock, §3.6 signed supply snapshots, §11 swaps, the by-hash output form, and — the largest reuse in this document — **`BOOTSTRAP.md`'s already-specified archiver network** (`:86`, `:222`), which has operators, heartbeats, a portable-proof wire format, and a wallet-side consumer.

---

## 1. The model

### 1.1 Components, in build order

| | Name | Needs | Delivers alone |
|---|---|---|---|
| **F0a** | Operator-controlled encrypted replication | nobody | Durability against disk/site/datacenter/ransomware loss |
| **F0b** | Independent custodians + split restore key | 3 custodians | Durability against operator *disappearance* |
| **F1** | The supply commitment (self-signed checkpoint) | nobody | `outstanding_mc` becomes falsifiable |
| **F1s** | Wallet-side proof sampling | nobody | A *deployed* detector population |
| **F2** | Checkpoint archiving + cross-archiver diff (extends the existing archiver) | existing archiver operators | Equivocation **detection**; the alarm gets a consumer |
| **F2v** | The verifying replica | 1–2 independent parties with storage | Raises silent-inflation cost from three lines of SQL to a maintained shadow ledger |
| **F3** | The cosigning ring (non-equivocation *binding*) | n named legal persons with stake | Binding third-party attestation; substrate for F4/F5 |
| **F4** | Issuance / policy / adjustment certificates | published policy envelope | Disclosed inflation gated below `k_iss` collusion |
| **F5** | Succession | pre-signed authority + ≥3 jurisdictions | Verifiable, capped restore |

**F1 and F1s are the highest value-per-line in this document and require no second party at all.** F2 reuses a role BOOTSTRAP already staffs. F3 onward requires named legal persons and, per §5, is gated on mint #2 existing.

### 1.2 The checkpoint header

One artifact, one cadence, one `seq` space. (The draft had a 10 s internal cadence and a 60 s witnessed cadence sharing one `seq` counter, which makes `seq == last.seq + 1` unsatisfiable for any verifier — SC-B3.)

```json
{
  "v": 1,
  "mint_id": "...",
  "seq": 8412,                                  // strictly monotone, gapless
  "prev":    "<b64u sha256(canonical(header[8411]))>",
  "genesis": "<b64u sha256(canonical(header[1]))>",   // constant, pinned at F1 start
  "mint_time": 1767225600000,

  "unspent_root": "<b64u 32B>",                 // root HASH; root SUM is supply.outstanding_mc
  "commit_seq": 44219913,                       // ledger commit counter at snapshot; monotone

  "supply": {
    "outstanding_mc":         41002133,
    "cumulative_issued_mc":  120000000,
    "cumulative_burned_mc":   78997867,
    "cumulative_adjustment_mc":       0,        // MONOTONE NON-INCREASING, always <= 0
    "snapshot_seq": 8412,
    "snapshot_time": 1767225600000
  },

  "restore": null,                              // §1.9, non-null only during a claim window
  "operator_held_mc": null,                     // optional, self-declared, UNVERIFIABLE (§1.10)

  "last_issuance_seq": 17,
  "last_adjustment_seq": 4,
  "roster_seq": 3,
  "policy_digest": "<b64u sha256(canonical issuance policy)>",
  "proof_service": "open" | "degraded" | "unavailable",

  "mint_signature": "<b64u Ed25519, §3.6 signing_pubkey>"
}
```

**The mandatory invariant** — §3.6's existing rule, with a commitment bolted on and one term added so that an honest correction does not permanently void it (SC-A3b):

```
root.sum  ==  outstanding_mc
          ==  cumulative_issued_mc − cumulative_burned_mc + cumulative_adjustment_mc
              − (restore.gap_mc − restore.claimed_mc)      // zero when restore is null
```

`cumulative_adjustment_mc` is **≤ 0 and monotone non-increasing, without exception**. There is no positive adjustment path anywhere in this design (§7, MO-D1 / SC-A3 / AC-A3). Value enters the ledger only through `cumulative_issued_mc`, which is gated by `IssuanceCertificate` under F4, and — during a bounded succession window only — through the `restore` reserve, which is capped by a number the *dead* mint published.

**Dropped from the draft header:** `unspent_count`, `unspent_sum_mc`, `locked_count`, `locked_sum_mc`, `blind_caps`. None of them is an input to any check anyone performs, and `locked_sum_mc` on a 60 s grid is a signed, permanent, non-repudiable amount oracle for individual §9.3 escrows and §11 swap legs at bootstrap traffic levels — materially more disclosure than the §3.6 `activity` field the spec deliberately coarsened (§7, MO-E1 / SC-B10).

**Cadence.** `checkpoint_interval_ms` default **300 000** (5 min), with ±20% jitter, and a mint MUST NOT publish a checkpoint covering fewer than `min_activity_floor` exchanges (default 32) unless `max_checkpoint_interval_ms` (default 86 400 000) has elapsed. Both are published in the descriptor. Rationale: 1,440 signatures/day/mint is incompatible with the hardware key the role is sold on (AC-A8), and a fine-grained delta on a low-traffic mint reconstructs individual transactions by exactly the argument §8.7 uses to refuse publishing leaf sets. The cadence enters §11's margin as a named slot (§1.8) rather than being hidden.

### 1.3 The Merkle sum tree (pinned)

Compressed **sparse** Merkle sum tree, depth 256, keyed by the §3.2 ledger key `sha256(secret_bytes)`.

```
LEAF_TAG = "aicash-ckpt-leaf"    (16 ASCII bytes)
NODE_TAG = "aicash-ckpt-node"    (16 ASCII bytes)

leaf        := ( sha256(LEAF_TAG || ledger_key || amount_be16 || lock_digest), amount_mc )
lock_digest := 32 zero bytes                    if lock is null
             | sha256(canonical_json(lock))     §3.3 canonical JSON

empty(d)    := ( sha256(NODE_TAG || 0x00 || depth_u8), 0 )      // precomputed per depth
inner       := ( sha256(NODE_TAG || L.hash || L.sum_be16 || R.hash || R.sum_be16),
                 L.sum + R.sum )
```

**Pinned requirements, in priority order:**

1. `root.sum == outstanding_mc`, where `outstanding_mc` is computed from the actual unspent set. `ledgerstore.py:655 supply()` already does this — "observable, not tautological."
2. **Sums are unbounded integers in computation and comparison.** Serialization is 16-byte big-endian and MUST **reject**, never wrap, any sum ≥ 2¹²⁸. `issue()` MUST reject any issuance taking `cumulative_issued_mc` above 2⁶⁴−1. Without this, a chosen `v = 2⁶⁴` counterfeit produces a root byte-identical to the honest one (SC-D1).
3. Sparse-by-key, not sorted-by-key, specifically so a **non-inclusion** proof discloses no neighbor's ledger key. A sorted tree's non-inclusion proof reveals two strangers' ledger keys, which are exactly the handles a prober needs to track those coins through `/v3/status`.
4. A proof exposes digests and sums only, never a raw neighbor ledger key. The leaf hash form above is load-bearing for this, not decorative.
5. **A `lock_digest` in the leaf pins lock terms.** An inclusion proof at seq N is cryptographic evidence of the lock's `expiry`, `preimage_hash` and `refund_hash` at N. Post-hoc lock mutation by an operator who controls the database — shortening a §11 leg's expiry so the counterparty misses its claim window, then refunding to itself — becomes portable proof of nonconformance. §3.2 defines no lock-mutation operation, so this closes the *careless* and the *opportunistic* version of a theft §11 has no other defense against (adopted from MO-B3, which correctly noted the draft built this and never claimed it).

**Sizing, corrected.** The draft's "2×10⁶ SHA-256 ≈ 20–40 ms at 10⁶ leaves" was off by one to two orders of magnitude (SC-A6.4). A depth-256 SMT over n leaves costs ≈ n·log₂n compressions on full rebuild: **≈ 2×10⁷ at 10⁶ leaves**, which is tens of seconds in CPython and well under a second in C. Therefore:

- Full rebuild is the default and is **mandatory below 10⁵ live outputs**, where it is comfortably sub-second and immune to the incremental path's failure mode (§1.4).
- Above 10⁵ live outputs, incremental SMT maintenance is permitted **only** under the commit-counter rule in §1.4. It is O(log n) per update.
- `checkpoint_interval_ms` MUST be derived from measured rebuild time, not fixed. A long read transaction pins the WAL against checkpointing; a cadence shorter than the rebuild grows the WAL without bound.
- Header ≈ 400 bytes. Compressed inclusion proof ≈ 700–900 bytes (≈20 non-empty siblings plus a bitmap at 10⁶ leaves).

### 1.4 The checkpointer — correctness rules (the systems critic's blocking findings)

These are normative and they take priority over every other consideration in this document.

**(a) Never watermark on a wall clock.** `ledgerstore.py:477` captures `now = self._clock()` *before* `BEGIN IMMEDIATE`, and `sqlite3.connect(..., timeout=30.0)` (`:233`) means a contended call can block up to 30 s waiting for that lock. So `created_at`/`spent_at` are **request-arrival** timestamps, not commit timestamps, and a row can be committed seconds after the timestamp it carries. A checkpointer that scans `(prev_watermark, W]` on those columns therefore silently drops rows forever: an honest holder's coin becomes permanently unprovable (`not_found` on every proof request — indistinguishable from fraud), and a **spent** coin retains a valid inclusion proof against every later checkpoint, which under a naive succession claim rule recreates it as unspent. That is a double-spend across succession caused by load, with no adversary (SC-A1).

Normative:
- The checkpointer MUST derive the unspent set from a **single consistent read snapshot**, never from a timestamp range.
- An incremental checkpointer MUST watermark on a monotone **commit counter** bumped inside the §3.3 transaction, never on `created_at`/`spent_at`.
- The reference implementation MUST move `now = self._clock()` to *after* `BEGIN IMMEDIATE` in `exchange()` and `issue()`. **This is a conformance fix independent of federation:** §3.4 pins lock evaluation "against the mint's clock at transaction commit time," and reading the clock before waiting up to 30 s for the write lock is not that. It needs a §3.4 sentence noting `now` is post-lock-wait, and a test.

**(b) WAL, and `synchronous=FULL` with it.** The reference implementation sets **no** `journal_mode` anywhere (`grep` over `impl/aicash` finds `synchronous` only at `wallet.py:281`, for the wallet DB). So it runs in rollback-journal mode, where a reader holds SHARED and `BEGIN IMMEDIATE` blocks behind it: today a checkpointer's scan serializes against the payment path, with 30-second stalls then `SQLITE_BUSY` on `/v3/exchange` as the visible symptom (SC-A6). The draft's "under WAL readers do not block writers" was a claim about a configuration that does not exist.

Normative for any mint running a checkpointer: `PRAGMA journal_mode=WAL` **and** `PRAGMA synchronous=FULL`. The second is not pedantry — WAL's commonly recommended `synchronous=NORMAL` loses the WAL tail on OS/power loss, which resurrects *spent* entries after recovery. That is a Layer 0 double-spend regression introduced by the item this document tells you to ship first.

**(c) One snapshot for the tree and the counters.** The header's invariant binds `root.sum` to `outstanding_mc`. `supply()` is one statement and internally atomic, but it is a *different* statement from the leaf scan. One exchange committing between them makes the two differ by exactly the burn, and the mint publishes a signed artifact that is, by the project's own definition, portable proof of its own nonconformance. The leaf scan and the counter read MUST occur in one explicit `BEGIN DEFERRED` read transaction.

**(d) Persist before signing.** The checkpointer is a singleton under an exclusive lock. It MUST fsync `(seq, full header bytes)` **before** signing or publishing, and MUST re-emit byte-identical bytes for a persisted `seq` on restart. Otherwise a crash between sign and publish, or any HA pair of checkpointers, deterministically produces two distinct signed headers at one `seq` — which this design defines as proof of fraud. An honest crash must not indict an honest mint (SC-B1).

**(e) Refuse to sign a broken invariant.** If the local invariant check fails, the checkpointer MUST NOT sign a header. It emits a **`PendingAdjustment`** (§1.7) and alarms the operator. A signed header is a claim; do not sign a claim you have already disproved.

**(f) The checkpointer is trust-critical and must be read.** The draft wrote *"a bug in this code cannot lose or misdirect money — it lives in a read-only process outside the atomic transaction."* That sentence is true about money and dangerously wrong about trust: it instructs every future auditor to skim the one process that is the entire trust boundary of the commitment, and a three-line `NOT IN` clause there is invisible to the "read `_exchange_locked`, confirm one transaction boundary" audit (MO-A1). **Retracted.** The correct statement: *a bug here cannot lose or misdirect money, but it can end the mint (§1.7) and it is where the supply claim lives. Audit it as trust-critical.*

### 1.5 Who stores what, who verifies what

| Party | Holds | Verifies | Cannot |
|---|---|---|---|
| **Mint** | the ledger | its own invariant before signing | — |
| **F0a custodian** (operator's own object stores) | ciphertext | nothing | read it |
| **F0b custodian** (independent) | ciphertext + one key share | nothing | read it alone |
| **Checkpoint archiver** (F2; the existing `BOOTSTRAP.md:86` archiver + ~120 LOC) | header chain, ~400 B × seq | signature, `seq == last+1`, `prev`, `genesis`, invariant, monotonicity — **and a peer archiver's head, diffed** | see leaves |
| **Verifying replica** (F2v) | live unspent set (hashes + amounts + locks), never the spend history | everything above **plus an independently recomputed `unspent_root` and `outstanding_mc`** | spend anything — L2/§3.2 means it holds hashes, never secrets |
| **Cosigner** (F3) | ~200 B/mint: `mint_id`, mint pubkey, `policy_digest`, `roster_seq`, `last` (seq, digest, issued, burned, adjustment, outstanding), `last_issuance_seq`, `first_seen_seq` | same checks, plus policy-envelope checks on certificates | see leaves; stall a payment; corrupt a payment |
| **Wallet** (F1s) | its own coins | a sampled inclusion proof against a published root | — |
| **§11 counterparty** | — | inclusion + `lock_digest` of the funded leg, against a checkpoint it fetched itself | — |

**Note what is *not* in the cosigner column.** A cosigner receives only the header. It **cannot recompute `unspent_root` and has no leaves against which to check `root.sum`.** A cosignature means: *"the mint told me these numbers, they chain, and they subtract correctly."* It does not mean the tree is complete, and completeness is the property H1 needs. That is why F2v exists and why F3 is not the anti-counterfeiting mechanism the draft implied.

### 1.6 Message flows

**Flow A — publish a checkpoint (F1, no second party).**
1. Checkpointer takes the exclusive singleton lock, opens one `BEGIN DEFERRED` read snapshot.
2. Reads `commit_seq`, the counters, and enumerates the unspent set — all in that snapshot.
3. Builds (or incrementally updates) the SMT; computes `root`.
4. Checks the §1.2 invariant locally. On failure → `PendingAdjustment`, stop.
5. Composes the header, fsyncs `(seq, bytes)`, then signs.
6. Publishes at `GET /v3/checkpoint` (latest) and `GET /v3/checkpoint/{seq}` (archive), and mirrors `checkpoint` into the descriptor.

**Flow B — archive and diff (F2, existing archiver operators).**
1. Archiver pulls `GET /v3/checkpoint` **directly from the mint**, never through an aggregator.
2. Verifies signature, `seq == last+1`, `prev`, `genesis` anchor, the invariant, and monotonicity of `issued`/`burned` (non-decreasing) and `adjustment` (non-increasing).
3. **Cross-fetches at least one peer archiver's head and diffs it.** Two distinct headers at one `seq`, or divergent `prev` chains, is a portable fork proof.
4. Publishes its own signed heartbeat and head. Silence is "archiving dark," never zero incidents (`BOOTSTRAP.md:86`).

> **This flow is where non-equivocation *detection* actually lives, and it needs no cosigning ring at all.** Two independent parties that pull directly and gossip will catch a mint serving different histories to different audiences. A cosignature adds *binding* — a signed, attributable refusal to fork, made before the fraud rather than after — but the detector is cheap and BOOTSTRAP already staffs it. This is the single largest honest downgrade of F3's marginal value in this document.

**Flow C — verifying replica (F2v).**
1. Consumes the encrypted replication stream, decrypts locally, applies inserts and spends to a local unspent set. It never retains the spend history, so §8's graph mortality is preserved on its side.
2. At `commit_seq` matching a header, rebuilds the root from **its own** set and compares root and `outstanding_mc`.
3. A mismatch is published as: the header, the recomputed root, and the aggregate delta — **never the leaf set**. A single disagreeing replica is he-said-she-said; **two verifying replicas agreeing against the mint is the evidence**. Deploy ≥2 or state the limitation.

**Flow D — cosign (F3).**
1. Mint POSTs the header to each roster member.
2. Cosigner verifies: signature; `seq == last+1`; `prev == digest(last)`; `genesis` matches its pinned anchor; issued/burned non-decreasing, adjustment non-increasing; the §1.2 invariant; `policy_digest` unchanged or covered by a `PolicyCertificate`; `roster_seq` unchanged or covered by a `RosterCertificate`; any `Δissued > 0` covered by an `IssuanceCertificate` **carrying ≥ `k_iss` valid signatures from the roster at `roster_seq`** — *not* "one this cosigner itself signed," which would make every legitimate issuance alarm from the `n − k_iss` members who did not sign it (SC-B2).
3. **Before signing, and mandatorily before signing any catch-up batch, it fetches the current head from ≥1 other cosigner's public log and refuses on divergence.** ~20 LOC. Without it, `n` cosigners are `n` independent oracles who each trust the mint for their entire view of the world, and offline catch-up — which §3 explicitly permits — is the moment a cosigner has no independent view at all (MO-A3c).
4. Fsyncs its updated `last` **before** replying.
5. Signs, replies, appends to its own public append-only log at `GET /f/log`.

> **A cosigner never signs two different digests at one `seq`.** That rule is per-cosigner and is worth exactly nothing globally unless quorums intersect — see §1.11.

**Flow E — issuance (F4).** Operator prepares a batch → submits `{outputs leaf list, amount_mc, outputs_root, policy_digest, effective_at}` to the roster → each cosigner recomputes `outputs_root`, checks `sum == amount_mc`, checks the policy envelope **against its own clock**, signs, and discards the leaf list → operator assembles the certificate → `POST /admin/issue` refuses without it. Routine issuance under a **standing drip authorization** needs no live quorum at all (§1.7).

**Flow F — proof and swap (§1.8).**

**Flow G — death and succession (§1.9).**

### 1.7 Certificates

All four are canonical JSON per §3.3, Ed25519, and live **outside** Layer 0 (§2).

**`IssuanceCertificate` — two modes.**

```json
{ "v":1, "mint_id":"...", "issuance_seq":18,        // monotonic, gapless
  "mode": "drip" | "batch",
  "prev_checkpoint": { "seq":8410, "digest":"..." },
  "amount_mc": 5000000,                              // batch mode
  "outputs_root": "<b64u>",                          // batch mode: exactly WHICH ledger keys
  "rate_mc_per_week": 250000, "term_end": <ms>,      // drip mode
  "policy_digest": "<b64u>",
  "effective_at": <ms>,                              // >= witness-clock now + policy.notice_ms
  "mint_signature": "...", "witness_signatures": [ ... ] }   // >= k_iss, from roster@roster_seq
```

`amount_mc` is not a licence to mint anything: `outputs_root` names the exact ledger keys that come into existence. An issuance batch is hundreds of coins, not millions, so the cosigner can be handed the leaf list, verify, and discard it.

**Why the drip mode exists.** `k_iss` cosignatures from unpaid humans is not an availability problem, it is the fourth-order statistic of volunteer response time — days, with a fat tail. An operator funding an internal compute market on a sprint cadence (`BOOTSTRAP.md:75`, which is the mint's *entire purpose* at Phase 1) responds rationally by issuing large batches quarterly to amortize the ceremony. That is **adverse to H1**: it converts a continuous, small, velocity-gossipable stream into a lumpy pre-authorized inventory sitting in the operator's own pocket — which is also precisely the inventory that bounds the unclosable exclusion attack (§4.1). The drip removes the incentive to batch: one certificate authorizes a published rate for a term, `Δissued` per checkpoint is checked against it arithmetically, and the exceptional path retains the veto where it matters (AC-A6). It is also the answer to the issuance-halt threshold (§8.6): a stalled quorum does not stop routine funding, only exceptional funding.

**`AdjustmentCertificate` — downward only, always.**

```json
{ "v":1, "mint_id":"...", "adjustment_seq":4,
  "prev_checkpoint": { "seq":8410, "digest":"..." },
  "delta_outstanding_mc": -1200,          // MUST be < 0. There is no positive form.
  "reason_code": "operational_correction" | "data_loss" | "restore_gap_closeout",
  "reason_url": "...",
  "mint_signature":"...", "witness_signatures":[ ... ] }   // >= k_iss
```

The draft permitted positive adjustments and gated them at the same `k_iss` as issuance while requiring **no** `outputs_root`, **no** notice window, and **no** rate ceiling. All three red teams independently found this and all three were right: it is a strictly weaker-gated issuance path that refunds everything F4 buys, with `reason_code: "data_loss"` shipped as a blessed cover story. Worse, cosigning a claimed operational correction *is* attesting to an external fact — a party holding 200 bytes has no capability to evaluate whether a claimed correction is real, and L10/§0.1 rejected the attestation service as a *concept*, not as a size (AC-A3).

Restricting `delta_outstanding_mc` to negative resolves both. A downward correction is the mint claiming *less* money exists, which no rug wants and which requires no external judgment — it is arithmetic over the mint's own numbers, exactly the cosigner's entire competence. Additionally: the policy envelope MUST carry a rolling annual adjustment budget (count and absolute mc); exceeding it is a mechanical policy violation a cosigner refuses without narrative.

**`PolicyCertificate`.** `policy_digest` sits in a descriptor the mint alone signs, so nothing in the draft stopped a mint from unilaterally rotating its issuance envelope to a laxer one — which makes every H1 "prevented" claim self-imposed (SC-B4, AC-A7). Normative: any change that **loosens** any bound requires `k_iss` signatures plus notice ≥ the issuance notice window; tightening may take effect immediately but is still cosigned so the digest chain is unbroken. A cosigner MUST refuse a header whose `policy_digest` changed without a matching certificate. The profile publishes a **default envelope with rationale**, so the first ring argues from an anchor rather than filling in a blank page the operator wrote (AC-A7).

**`RosterCertificate`.** The draft said roster changes "reuse §3.6's cross-signed rotation verbatim," but §3.6's rotation is *one key signing its successor* and never names a signer for a set-signs-set change. Under the natural reading — the mint signs it — the operator rotates its own guardians and "an unchained change IS the alarm" fires only on a change it forgot to sign (MO-C5). Under an all-`n` reading, one vanished volunteer freezes the roster permanently and `n` decays monotonically until issuance stops forever and the operator flips the config flag (AC-A5). Normative:

- Signed by ≥ `max(k_ck, k_iss, k_succ)` of the **outgoing** roster. **Never by the mint.**
- Notice window ≥ `succession_timeout_ms`, published before `effective_at`.
- **Fixed renewable terms:** membership expires after 12 months unless affirmatively renewed by a signed statement. Decay becomes the default and continuation the deliberate act — the project's own "silence is the alarm" pattern, applied to the alarm-ringers.
- Involuntary removal of a non-responsive member additionally requires a published stall predicate (no signature in D days) and a delay window; the slot is publicly marked lapsed, never silently backfilled.
- The descriptor MUST expose **`effective_n`** (members who signed within the last interval) alongside `n`. A ring of 5 with 2 alive must not read as 5 anywhere.
- It appears as a first-class row in the threshold table (§1.11).

**`PendingAdjustment` — self-signed, and the reason the alarm does not eat honest mints.** Operator key only, publishable instantly, timestamped, publicly reasoned. It is not authorization for anything; it is a declaration that the mint knows its invariant is broken and why.

Its purpose is a timing asymmetry the draft missed. `BOOTSTRAP.md:222` Loop 1 already wires the deployed archiver network to treat a verified invariant break as **mint death** — "stop accepting, orderly exit, gossip the proof." This design attaches a new ~350-LOC tree builder to that automated evacuation trigger. The alarm propagates in **seconds**; the exculpation (`AdjustmentCertificate`, `k_iss` unpaid volunteers, "days would be fine") takes a **week**. A mint can be killed by its own monitoring in minutes and cannot clear itself for days (AC-A4). Normative, shipping in the same release as any conformance rule that binds `outstanding == root.sum`:

> An invariant break accompanied by a `PendingAdjustment` published within one checkpoint interval is **Tier-1 route-away**, not Tier-2 death, for a bounded window (default 14 days), after which — absent a cosigned `AdjustmentCertificate` — it escalates to Tier-2. An operator that exceeds the policy adjustment budget loses the downgrade.

This is the C6 shape `BOOTSTRAP.md:334` already ratified for sunsets: one key alone cannot fire everyone's exit, and neither can one key alone be executed by an alarm.

**Before any of this ships: cross-implementation tree-construction conformance vectors.** Two conformant mints producing different roots for the same set is a false fraud accusation with an automated kill attached.

### 1.8 Proofs, sampling, and §11

**`POST /v3/status` gains one optional read-only flag:**

```
POST /v3/status { hashes: [...], with_proof: true }
  → per result: + "inclusion_proof": { seq, path[], sums[], bitmap } | null
              | "non_inclusion_proof": { seq, path[], sums[], bitmap }
  → response-level: + "checkpoint": <header + any cosignatures>
```

Chosen over a new `/v3/proof` endpoint deliberately (§13 precedent item 3: batch status and the descriptor extension). Callers can already probe arbitrary hashes via `/v3/status`, so this discloses no new class of information about the queried hash.

**Proof service is a right, not a courtesy.** The draft called `with_proof` "an optional read-only flag" and never said a mint publishing a checkpoint must serve it — so a mint can publish beautifully cosigned checkpoints, look excellent in every dashboard, and answer proof requests with `unavailable`, `rebuilding`, or a per-caller rate limit, making the commitment unfalsifiable while retaining every reputational benefit (MO-B1). Normative:

- If `checkpoint != null`, the mint MUST serve `with_proof` for **any** hash, to anonymous callers, and MUST answer with an explicit **non-inclusion** proof rather than an error when the key is absent from the tree.
- `not_found` (absent from the tree) and `unavailable` (mint cannot serve) MUST be distinguishable in the schema, and `proof_service` in the header is a machine-visible state, not a per-response excuse.
- **Proofs get their own published limit** in `limits.proofs`, separate from §3.7's non-discrimination rule on `/v3/status`. `with_proof: true` on a `max_batch` request is `max_batch × ~256` hash operations plus tree residency; the mint must be able to bound that amplification without throttling its entire bearer tier, which §3.7 rightly forbids (SC-B11). §3.7's right covers `with_proof: false`.
- Proofs are served against the **latest** checkpoint only. One resident tree, and it composes with the succession rule in §1.9.

**F1s — wallet sampling, the highest-leverage twenty lines in this document.** The draft's detection argument required a population of holders who request proofs and notice failures. At Phase 1–2 that population is approximately empty: one mint plus an overflow mint, ~50 swaps *total* is a Phase-3 exit criterion, and the typical holder is a drip-payment agent with a 1 mc balance and no reason to verify anything. Eighteen months is a perfectly good horizon for a rug (AC-A15). So make verification a side effect of ordinary operation — the pattern `BOOTSTRAP.md` §4.2 already ratified:

> Reference wallets SHOULD attach `with_proof: true` to a small random fraction (default 2%) of the `/v3/status` batches they **already** perform on re-exchange (§5.1) and on payee confirmation, and gossip any inclusion failure against a published root through the §9.5 error path.

Zero new volunteers, zero new daemons, and it converts a detection argument from asymptotic to deployed. Where verifying replicas exist and expose a read-only status surface, the sampler SHOULD query a randomly chosen one of {mint, replicas} and gossip disagreement — that is what binds the replica's state to the state that serves payments (§4.1).

**§11 — what proof-before-swap actually buys, restated.** The draft required a §11 counterparty to obtain an inclusion proof "before locking its own leg," and glossed the cost as "swapped coins must be ≥1 witnessed interval old." Both are wrong. The object B must evaluate is **a locked output A creates at swap time** — age zero. It cannot be in an older tree. And the counterparty is a Layer 3 agent; nothing checks a MUST binding it, and a mint publishing `checkpoint: null` is fully conformant, so a MUST the dominant Phase 1–2 case cannot satisfy trains implementers to ignore MUSTs (SC-B7, AC-A13). Restated:

- A §11 counterparty **MUST** verify an inclusion proof of the funded leg when the mint publishes a checkpoint, and MUST otherwise treat the mint as **unwitnessed** and price accordingly.
- Satisfying it means **B waits for A's funded output to appear in a checkpoint B fetched itself**, then verifies inclusion *and* pins `lock_digest`, before B locks its own leg.
- §11's margin formula gains a named slot: `checkpoint_staleness(M1) = checkpoint_interval_ms(M1) + publication_lag`. This is **not** absorbed by the existing 60 s null-`performance` default, which is a *latency* estimate against a different term that is already spent. The cost lands on **quote validity** (pre-lock) and widens A's disclosed HTLC free option, so `T` extends correspondingly. Say it in the quote-validity paragraph, not in the margin paragraph.
- **The claim is downgraded.** Not "fake coins cannot be proven" and not "a cryptographic supply guarantee." The honest claim: *this coin is a member of a set whose published sum equals the mint's published counters at seq N, and its lock terms at N are pinned.* Against the exclusion attack (§4.1) — a counterfeit *inside* the tree with the operator's own parked coin outside it — the proof succeeds and the counterparty learns nothing about counterfeiting.

### 1.9 Death, restore, and claims

**`succession_authority` — signed while the operator is healthy.** The draft's offline legitimacy test demanded "an unbroken §3.6 cross-signature chain from the pinned dead-mint key," while its `SuccessionCertificate` had no mint signature field — because a dead or compelled operator cannot produce one. Either the test never passes, or wallets accept a witness-only authority, which under §3.6's own rule is "a different signer," i.e. the alarm rather than the resolution (SC-B6). Fix: at ring formation, the **live** mint key cross-signs a dead-man delegation into the descriptor:

```json
"succession_authority": { "mint_id":"...", "roster_digest":"...", "k_succ":5,
                          "succession_timeout_ms": 1209600000,
                          "cross_signature": "<b64u by current signing_pubkey>" }
```

This reuses §3.6's cross-signature verbatim, predates any compulsion, gives a wallet's offline test a deterministic answer, and narrows the hijack surface because it names a **specific roster** rather than blessing whoever arrives with signatures.

**`SuccessionCertificate`** carries `final_checkpoint` (seq, digest, `outstanding_mc`, **and the full supply block including `cumulative_issued_mc`, `cumulative_burned_mc`, `cumulative_adjustment_mc`**), `successor_pubkey`, `stall_evidence`, and ≥ `k_succ` signatures from ≥3 jurisdictions.

**Stall evidence is third-party observable or it is nothing.** The draft's `stall_evidence` was two self-asserted timestamps, which collapses the deliberately slow timeout to zero for a coalition that forges `last_seen_at` (MO-D3, SC-D3). Normative: `last_seen_at` is defined as `max(received_at)` across the **cosigners' own signed, independently published logs**, cross-fetched per Flow D. Every clock in every policy check is the checking party's own, never the mint's `mint_time`.

**The restore rule.** The successor restores from the replica and publishes its first checkpoint chained from `final_checkpoint`. It MUST adopt `final_checkpoint`'s counters **verbatim** — otherwise an honest restore from a replica whose high-water mark precedes the final checkpoint fails the cosigners' own monotonicity check, and there is no field to roll counters back (SC-A4). Any shortfall between the restored set and the certified `outstanding_mc` is disclosed as a **claim reserve**, not an adjustment:

```json
"restore": { "succession_digest":"...", "gap_mc": 41200, "claimed_mc": 0,
             "claim_deadline": <ms> }      // default: final_checkpoint + 2 x succession_timeout_ms
```

The invariant (§1.2) carries `− (gap_mc − claimed_mc)` as a known deficit. Honoring a claim moves value from `gap_mc` into `claimed_mc`; it never touches `cumulative_issued_mc`. **The successor cannot inflate during restore by construction** — the cap is a number the dead mint published and independent parties signed. At `claim_deadline` the residual `gap_mc − claimed_mc` converts, once, into a negative `cumulative_adjustment_mc`, and `restore` goes null. Monotone, bounded, terminating.

**Claims — against the final root only, and never a secret.**

```
POST /succession/claim { ledger_hash, amount_mc, inclusion_proof, seq }
```

> **The claim endpoint accepts a ledger hash and NEVER a token secret.** The ledger key is `sha256(secret)`; a holder proves membership with the hash alone; the successor re-creates the entry at that hash as unspent; the holder later spends it normally through §3.3 with the secret it never disclosed.

This is the best single idea in the draft and it survives every red team: it **structurally** removes the secret-harvesting payload from a coerced or hostile successor. A hostile successor learns a ledger hash and an amount, which it could read out of the replica anyway. It learns nothing spendable. Keep the governance guardrails as defense in depth, but the payload is gone at the design level.

Two corrections the red teams forced:

1. **`seq` MUST equal `final_checkpoint.seq`.** The draft let a holder prove inclusion at *any* historical root, and the successor could not disprove it: producing a non-inclusion proof at the final root requires the full leaf set at `final_seq`, which is exactly what the successor does not have — that is *why* the endpoint exists (SC-A4). So Alice, who spent coin `c` at seq 8100, replays her retained proof from seq 8000 and the successor recreates it; Alice, who holds the secret, spends it twice. And since anyone can obtain a proof for any hash, every payer holds the ledger hash of every by-hash output it ever funded. Restricting claims to the final root kills this outright: a coin spent before death is absent from the final tree.
   - **The price, stated:** coins created *and* spent inside the last checkpoint interval before death are unreconstructable by any party. That is a bounded, disclosed loss of ≤ one interval of traffic, and it is much better than an unbounded and unsafe alternative. §3.1's "non-inclusion proof lets the successor reject a stale proof" language is **deleted** — non-inclusion is the operation the successor cannot perform.
2. **Claims bind `(hash, amount, final_seq)` and are deduplicated and published.** `prune()` deletes spent rows, so a ledger hash can legitimately be recreated later; a bare-hash rule lets a stale proof redeem against an unrelated live coin at the same key (SC-D4). The successor MUST record every claimed hash, reject duplicates, and publish the honored set (hash + amount) so double-honoring and over-cap honoring are third-party detectable.

**And the honest verdict on the desk (AC-A14):** no successor's balance sheet improves by adopting orphaned liabilities denominated in nonconvertible credits, and `POST /succession/claim` requires a human to run an endpoint, adjudicate, and absorb abuse on a dead mint, unpaid. **F5 ships as two artifacts, not a program:** (i) the final cosigned root — a capped, verifiable, independently signed statement of what was owed, which is genuinely valuable as accounting, reinsurance, and litigation substrate; (ii) the hash-only claim rule, written into the profile as a permanent prohibition against secret-harvesting successors whether or not a desk ever exists. Build the desk when a funded successor actually exists. That is exactly the trigger discipline §15 demands.

Two collisions to resolve before F5 ships:
- **`BOOTSTRAP.md:314` already specifies succession** — "cross-signed rotation (§3.6) to a successor key held in escrow… 2-of-3 escrow across the operator and the first independent partners." Two succession paths with different thresholds and rosters and no precedence rule means an adversary takes the weaker one and two honest parties produce competing successors. One must be declared authoritative (§9).
- **A published haircut ratio `r < 1` is a quoted rate between two credit populations** and needs a ratified §4.3 Nonconvertibility-Covenant edges-document entry *before* F5 ships, or the first succession meets a covenant-defection accusation. It is very probably fine — closed-loop, credit-for-credit — but "probably fine" is not the standard for the project's declared legal shield.

### 1.10 `operator_held_mc` — an honest, unverifiable commitment device

Optional. A signed self-declaration of the unspent value at ledger keys the operator controls. **No party can verify it and under-declaration is undetectable.** It is included because the unclosable residual in §4.1 is bounded by exactly this quantity, and publishing it converts a silent bound into a stated one that a rug must actively lie about — and a lie here, combined with a later verifying-replica disagreement, is evidence. Its growth is a Loop-1 gossipable signal alongside issuance velocity. It is a commitment device, not a control, and the spec text must say so in those words.

### 1.11 Thresholds — and the parameter error that voided the draft's only security property

The draft's §3.7 table set `n = 5, k_ck = 2` and declared the H1-pulls-up / H3-pulls-down tension dissolved. Two red teams independently found the same flat error: **`2 + 2 = 4 < 5`, so checkpoint quorums do not intersect.** A mint presents fork A to {1,2} and fork B to {3,4}; both carry valid `k_ck` cosignatures; no cosigner ever signed two digests at one `seq`; the mint holds two independently attested histories of one `mint_id`. Non-equivocation is a **safety** property and safety thresholds are majorities. Worse, the draft's W2 shipped at `n=3, k_ck=2` (which intersects) and then W3 *grew the ring to n=5 while leaving `k_ck=2`* — the growth step silently destroyed the property.

**Normative, no exception for availability: `2 · k_ck > n`.**

**And a verifier-side rule, which the draft omitted entirely.** Thresholds stated only producer-side are decoration. A checkpoint is **binding** only when it carries signatures from a **majority of the roster named at `roster_seq`**; with fewer it is *published*, not *attested*, and MUST be labeled as such. Signature count MUST NOT be rendered as a continuous confidence score.

| Operation | Threshold | n=3 (minimum viable) | n=7 (target) | If quorum unavailable |
|---|---|---|---|---|
| Checkpoint attestation | `k_ck`, **majority, mandatory** | 2 | 4 | Chain goes "attesting dark." Visible in `effective_n`. **Payments unaffected.** |
| Exceptional issuance | `k_iss` | 3 | 5 | Exceptional issuance stalls. Drip continues. **Payments unaffected.** |
| Downward adjustment | `k_iss` | 3 | 5 | Corrections stall. Route-away downgrade covers the window (§1.7). |
| Policy loosening | `k_iss` + notice | 3 | 5 | Envelope cannot be loosened. Safe direction. |
| Roster change | `max(k_ck,k_iss,k_succ)` of **outgoing** roster | 3 | 5 | Roster frozen; terms lapse; `effective_n` falls visibly. |
| Succession | `k_succ`, ≥3 jurisdictions | n/a | 5, degrading (below) | Succession stalls — the safe direction for safety, the *losing* direction for H2. |
| **Settlement** | **none** | — | — | **Not gated. Ever.** |

**Why the draft's "three thresholds dissolve the tension" claim is only half true.** It dissolves for *settlement*, which is ungated. It does **not** dissolve for issuance or succession, where both forces still act on one `k`. At `n=5, k_succ=4`, only `n − k_succ + 1 = 2` silent or compelled volunteers block succession forever — the same cheap-halt error the draft charges BFT with, one level up (SC-B5). Two mitigations, both adopted:

1. **Raise `n`, do not tune `k` down.** At n=7, `k_succ=5` gives collusion resistance 5 and halt resistance 3.
2. **Time-degrading succession.** After `2 × succession_timeout_ms` with a continuously published stall predicate, `k_succ` steps down by one per further timeout period, floor at `⌊n/2⌋+1`, each step announced and logged in advance. This is a published schedule, not consensus, and it is the only lever that makes both thresholds acceptable at small `n`.

`n=7` named legal persons is an enormous ask and this document does not pretend otherwise (§3.3, §5).

---

## 2. What changes at Layer 0

**Unchanged, literally:** §3.1 token format. §3.2 ledger state. §3.3 exchange semantics and atomicity. §3.4 lock and its asymmetric witness rules. Wallet payment behavior. L1, L2, L4, L5, L6, L7, L8, L9, L10, L12, L13, L14, L15, L16 all survive untouched. §13's streak becomes **four consecutive revisions.**

Five items touch Layer 0's *text*. Each is justified against §13's discipline test.

**1. `checkpoint: null | { <header §1.2>, witness_signatures: [...] }` in the §3.6 descriptor.** Read-only metadata, no new operation, no new ledger state. Only the mint can sign its own supply numbers — §13 item 3's exact shape — and this passes on stronger grounds than the fields already there, because it makes an existing *self*-attested number *falsifiable*. A mint with no checkpoint publishes `null` and is honestly labeled uncommitted. The floor does not rise.

**2. `federation: null | { members[{witness_id, pubkey, endpoints[], jurisdiction, independence_disclosure_url, term_end}], n, effective_n, k_checkpoint, k_issuance, k_succession, k_roster, issuance_policy_digest, issuance_policy_url, checkpoint_interval_ms, min_activity_floor, succession_timeout_ms, succession_authority, roster_seq, roster_certificate }`.** The binding between a mint's identity and its ring must come from the mint's own signed descriptor, because anything else is a **directory** — the undesigned trusted infrastructure §1 forbids and `BOOTSTRAP.md:349` (DoNots #6) explicitly refuses. No higher layer can supply it.

**3. `with_proof` on `POST /v3/status`, plus `limits.proofs`, plus a conditional service obligation.** An optional read-only flag on an existing read-only endpoint (§13 item 3 precedent), and an obligation that binds **only** a mint that chose to publish a checkpoint. A mint that publishes a commitment and refuses to let anyone test it has published a reputational asset, not a commitment (§1.8).

**4. Amendment to §3.6: a checkpoint-publishing mint's descriptor `supply` block MUST be the *last checkpoint's* frozen supply block.** Two reasons, one of which is a live performance defect. (a) The draft made it a conformance rule that `supply.outstanding_mc == root.sum` while `supply` was live and the root was up to one interval stale — a rule every honest mint violates continuously (SC-B8). (b) `mintapi.py:407-427` computes `supply` under `BEGIN IMMEDIATE`, taking the ledger **write lock**, on every `/v3/mints` call. The draft simultaneously celebrated a 1–2 order-of-magnitude improvement in detection resolution from more frequent polling — i.e. it purchased its monitoring improvement on the payment path. Freezing `supply` to the last checkpoint satisfies §3.6's monotonicity rule, makes the equality exact, and removes a write-lock acquisition from a read path. Net improvement to the mint, not a cost.

**5. Amendment to §8 (retention compact): replicas and archives are governed by the compact.** F0's stream carries every insert and every spend, continuously, with no expiry in the draft — while `BOOTSTRAP.md` §2.1 makes graph mortality load-bearing for the compliance posture, because pruning is what bounds a subpoena to the recovery window. The operator's copy prunes; the custodians' did not. Pruning would stop being effective the day F0 shipped (SC-B9). Normative: replica segments expire on the same `recovery_window_ms` schedule; verifying replicas retain the **unspent set only** and never the spend history; custodian retention is contractual and published at `retention.policy_url`; checkpoint **headers** are class-(a) aggregate artifacts and are permanent; **leaf sets are never published, by anyone, ever.** This means the "F0 is zero protocol" framing is wrong on two counts (the other is §5's coordination cost), and it is corrected there.

**Deliberately NOT Layer 0:** the checkpoint wire protocol, the archive, all five certificate types, the succession endpoint, the restore rule, the claim rule, the haircut policy, the replication scheme, the verifying replica, the whole cosigner daemon. These live in **§6.3 Federation Profile** and in out-of-band artifacts (the `retention.policy_url` posture).

**Also not Layer 0, on purpose:** the ledger does not enforce the certificate requirement. **The check goes in `mintapi.admin_issue` (`mintapi.py:503`), not in `Ledger.issue()` (`ledgerstore.py:372`).** The draft put it in the ledger and then argued in the next section that the guarantee is economic, not enforced. The second position is right: putting Ed25519 verification, canonical JSON, roster lookup, and policy evaluation inside a `BEGIN IMMEDIATE` transaction in the file that *is* the audit artifact contradicts the whole thesis and grows the thing whose smallness is the project's most valued property (SC-D2). Gating in the API layer lets this document make a **stronger** claim: `ledgerstore.py` is unchanged apart from the §1.4(a) clock-ordering conformance fix.

**Reference-implementation conformance defects surfaced by this review, to be fixed regardless of whether any of this ships:**
- `ledgerstore.py:477` / `:395` read the clock before `BEGIN IMMEDIATE`, so lock conditions are not evaluated against the commit-time clock as §3.4 pins.
- No `journal_mode` or `synchronous` pragma is set on the ledger connection (`:233`), so a concurrent reader blocks the writer and the crash-consistency contract is implicit.
- `mintapi.py:407` takes the write lock on a read endpoint.

---

## 3. Cost

### 3.1 Payment path

`/v3/exchange` request and response are byte-identical. The honest latency accounting is **not** "zero everything" — the draft's "zero lines inside the atomic transaction" is retracted:

| | Cost |
|---|---|
| Lines inside the §3.3 transaction | **Zero** for a full-rebuild checkpointer (mandatory below 10⁵ live outputs). **One integer increment** (`commit_seq`) for an incremental checkpointer. That is the correct trade for the SC-A1 bug and it is cheap; say so rather than claiming zero. |
| `journal_mode=WAL` | Latency **improvement**: readers stop blocking the writer, which they do today. |
| `synchronous=FULL` | One fsync per commit — which a bearer ledger that must never resurrect a spent entry should already be paying. Parity, not regression. |
| Checkpoint build | Separate reader process, separate read snapshot. Under WAL it does not block writers. It **does** pin the WAL against checkpointing for its duration, so cadence must be derived from measured rebuild time. |
| `/v3/mints` | **Improvement** — the write-lock acquisition at `mintapi.py:407` goes away (§2 item 4). |
| `with_proof` | Off the payment path, separately rate-limited, sampled at 2% by wallets on calls they already make. |
| Cosignatures | Asynchronous. Silence delays *durability*, never *settlement*. A cosigner is not on the path and has no authority over it. |
| **§11 swaps** | **The one real cost.** B waits one checkpoint interval (default 5 min) after A funds before locking. It lands on quote validity and widens A's disclosed free option. Named as a slot; not hidden inside the margin. |

Note what this avoids: a geo-federated BFT mint's p99 rises 1–2 orders of magnitude, which through §11's mandated ≥10× safety factor pushes margin `M` from seconds to a minute-plus, stretches `T − T′`, forces §8's retention floor up to cover it, and widens the free option proportionally. **A federated mint would be a materially worse swap counterparty.** A committed mint is an unchanged one plus a wait.

A new, weaker, opt-in finality tier appears: **spend-final** (instant, as today) versus **commitment-durable** (next checkpoint). Only agents holding value across time consult the second, and only if they choose to — the same opt-in shape as §9.2's redeem-immediately rule.

### 3.2 New code, honestly counted

The draft claimed ~440 LOC mint-side against a 1,323-LOC trust core. That was an undercount and it excluded the parts that matter.

| Component | LOC | Trust-critical for double-spend? | Trust-critical for the supply claim? |
|---|---|---|---|
| SMT builder + proof serializer | ~200 | No | **Yes** |
| Header composer / signer / publisher | ~150 | No | **Yes** — it can kill the mint (§1.7) |
| Certificate verifiers (5 types) | ~200 | No | **Yes** |
| Proof endpoint + limits | ~80 | No | No |
| Descriptor fields | ~40 | No | No |
| Archiver extension (on the existing ~200-line archiver) | ~120 | No | **Yes** (it is the detector) |
| Verifying replica | ~200 + shares the tree code | No | **Yes** |
| Cosigner daemon (gossip, fsync, two keys, refusal log) | ~250 | No | **Yes** |
| Wallet sampler | ~30 | No | No |
| `ledgerstore.py` changes | ~5 | conformance fix | — |
| **Total** | **~1,275** | **~5** | **~1,120** |

The audit question "can a coin be double-spent?" is still answered by reading `_exchange_locked` and confirming one transaction boundary. The audit question "is the supply real?" now requires reading about a thousand more lines, and the draft's invitation to skim them is withdrawn.

### 3.3 Participant burden — the draft's least-defended sentence

The draft: *"a 200-line daemon holding ~150 bytes of state per mint, no custody, no liability, no uptime obligation on the money path"* and *"roughly an order of magnitude cheaper to recruit than a second mint operator."* Two red teams attacked this from opposite directions and both landed.

**What is actually being asked of a cosigner**, written out so a real person can say yes or no to it:

> A public, signed, append-only log on your own infrastructure (domain, TLS, storage). Two keys — a hot online checkpoint key on an unattended host, and an offline hardware policy key for the rare decisions. A published legal identity and jurisdiction, in a machine-readable descriptor, attached to someone else's money system. A published independence disclosure. A multi-day response SLA on exceptional issuance. A quarterly refusal drill you did not schedule. A term you must affirmatively renew. Years of it. Unpaid, and un-indemnified — in a project whose own bootstrap document names *named legal persons* as its cheapest kill (`BOOTSTRAP.md:174`).

Adopted consequences:

- **Two keys per cosigner** (AC-A8). Nobody touch-confirms 1,440 signatures a day, so a single hardware key at the draft's cadence is decorative and compromising the host *is* compromising the cosigner. Splitting online-checkpoint from offline-policy makes the rare decisions *physically* different from the routine ones, which does more against automation-without-attention than any drill does.
- **The "10× cheaper to recruit" claim is withdrawn.** Restated: *~10× cheaper to recruit and ~10× cheaper to fake.* `BOOTSTRAP.md:305` (P5)'s sybil detector does not transfer — its signals are decorrelated downtime, latency, cadence, hosting ASN, which exist because a real mint serves real traffic. A cosigner serves nothing. A cron job behind a rented residential IP is behaviorally identical to a real cosigner, forever. So cosigners must be recruited to the **same standard as mint operators** (`BOOTSTRAP.md:143`: distinct funding provenance, public organizational identity, published independence evidence) — which destroys the cheapness argument, and that is the correct conclusion.
- **The drill is not run by the mint** (MO-C3). The draft had the mint submit a deliberately out-of-policy request, choose when, and publish the results — which proves nothing and, worse, creates an alibi: a real out-of-policy attempt that gets caught is retconned as "that was the drill." Normative: drills are initiated by a non-mint party (rotating cosigner, or the `BOOTSTRAP.md` §4.1 governance quorum), **unannounced to the mint**, **pre-committed** (the initiator publishes a hash of the drill request in advance so no real attempt can be retconned), and failures are published by the *other* cosigners. Drills MUST include an in-policy-but-implausible adjustment request, which is the case that actually occurs.
- **A witness dossier**, mirroring `BOOTSTRAP.md`'s operator recruitment dossier: what you are signing, what you are not signing, your compulsion exposure, the absence of indemnity, get your own advice. Doing this honestly for operators and not for cosigners is the difference between recruiting people and recruiting people who will resent you.
- **`attestation_scope` inside the signed bytes** of every cosigner statement: *"arithmetic conformance over the mint's own published numbers and a pre-agreed policy envelope only; no opinion on backing, solvency, or the operator."* Scope must travel with the artifact so it cannot be stripped by whoever quotes it. "No liability for user funds" is asserted, not argued; a narrow, documented, self-carrying scope is the actual defense.

### 3.4 The reciprocal model — where the stake comes from

Every incentive problem above has one root: the design asks for a party with authority and no stake. And the trap closes on payment: credits are nonconvertible (L9), so paying a cosigner in credits means paying it in *this mint's liabilities* — which gives it an incentive to protect their value on the exact day it must refuse; and fiat payment is forbidden by `BOOTSTRAP.md:349` (DoNots #3) and converts a guardian into a contractor. **The only parties who can be compensated are the ones who cannot be independent.** That is structural, not a gap in the pitch.

There is an obvious population with a stake and no authority: **the mints, treasury pre-positioners, and swap counterparties who hold each other's credits** — a relationship `BOOTSTRAP.md` §1.3 Phase 3 already plans as first-class. Invert the model:

- A mint's ring is drawn from **parties with material exposure to it**.
- The incentive is reciprocity, not altruism: *I will not accept your credits unless I can check your supply, and you will not accept mine unless you can check mine.* That survives boredom and needs no compensation.
- Independence becomes **structural** rather than disclosed: L3 already makes a second organization's distrust of mint #1 rational.
- The "is this a ring I trust?" question — which in the draft was a trust decision about strangers, made by an automated wallet, which manufactures the reputable-witness list `BOOTSTRAP.md:349` refuses — becomes *"is this ring drawn from parties with exposure to this mint?"*, evaluable from facts a wallet already holds.
- Liability framing improves: a commercial counterparty performing due diligence is a different legal creature from a volunteer guardian cosigning someone else's money supply.
- It stops competing with the plurality gate and starts depending on it.

**Its honest weakness, named:** mutual witnessing is exactly the A-backs-B-backs-A circularity §6.3 rejects for reserve attestations. Mints share an interest in the network not looking fraudulent, and a cosigner holding the mint's credits has an incentive to conceal insolvency rather than expose it — the same trap as paying in credits. That is a real tension between two real forces, which is a system that can be tuned. The volunteer model requires a party subject to *no* forces, which is not a system but a hope.

**Practical consequence: do not ship F3 until mint #2 exists.** That is not a delay. It is `§15`'s trigger read literally — "multiple mutually distrusting parties need joint control of issuance" — and it means the ring arrives with an incentive structure instead of a recruiting problem.

### 3.5 The recruiting ledger

Before this document adds anything, the program must already recruit, all unfunded: mint #2's operator; the governance release quorum across ≥3 jurisdictions; a broadened persona-review pool; independent archiver operators; a skeptical design partner; a corridor-grade operator. None is secured. This design adds F0b custodians, F2v replica operators, and n cosigners.

**Adopted:** publish a single **recruiting ledger** — every distinct independent party the program requires, with status — as a first-class BOOTSTRAP artifact, and require any new design to show its draw against it. F2 draws on parties BOOTSTRAP already recruits (archivers). F3–F5 draw new ones and are gated accordingly.

---

## 4. What this actually solves

### 4.1 H1 — over-issuance: **bounded, not prevented; and the bound has a name**

| Attack | Today | With F1+F1s+F2 | With F2v | With F4 |
|---|---|---|---|---|
| **Disclosed inflation** — bump `issued`, mint a fortune, publish consistent numbers | Fully conformant. `BOOTSTRAP.md:222` already gossips issuance velocity and tightens exposure caps without any invariant break. | unchanged | unchanged | **Gated** below `k_iss` collusion against a policy envelope that cannot be unilaterally loosened |
| **Silent inflation** — insert rows, leave counters alone | Undetectable | **Bounded** by the operator's own parked inventory (below) | Same bound, at much higher operational cost to the attacker | **No marginal effect** (see below) |
| **Backing rug** — issue legitimately, swap out at §11, close | Unaddressed | Unaddressed | Unaddressed | **Unaddressed** |

**The finding that forced this rewrite.** The draft argued that excluding a coin from the committed tree "metastasizes": the excluded coin is live, its holder eventually spends it, the mint must rotate the exclusion across a growing population of innocent holders, each of whom gets a `not_found`, and detection probability approaches 1. All three premises fail. The exclusion is a **value budget**, not a coin, and the operator excludes **its own treasury** — a large, legitimately-issued, self-held, never-spent balance is not merely available to it, it is the expected shape of every mint at bootstrap (`BOOTSTRAP.md:301`). Nobody ever requests a proof for a coin only the operator holds. Zero `not_found`s. Zero rotation. Zero arithmetic drift. Detection probability is not "approaching 1" — it is **structurally zero** (MO-A1, SC-A5).

**Does the verifying replica close it? No.** It raises the cost substantially and it is worth building, but a determined operator can maintain a **divergent shadow ledger** — one that agrees with the real ledger on every coin any third party will ever touch, and differs only on counterfeits and parked treasury. With physical (not logical) replication plus wallet sampling that queries a randomly chosen replica (§1.8), the operator must keep both consistent forever, for every real holder's coin, and never let anyone who can compare them do so. That is a large increase in cost and in the chance of a fatal mistake. **It is not a proof.**

**The honest claim, which replaces "silent inflation is structurally caught":**

> **Undetected silent inflation is bounded above by the operator's own unspent, never-third-party-touched inventory at each moment.** That bound is set by past issuance and shrinks as the operator's own holdings are spent. The issuance policy envelope and the standing-drip design (which removes the incentive to hold large pre-authorized inventory) bound it over time. `operator_held_mc` (§1.10) makes it a published number a rug must lie about.

Which also means **F4's marginal security against a *malicious* operator is approximately zero** (MO-A4): the design's own reasoning says a rational rugger takes the silent path because it is strictly easier, and the silent path stays open. F4 defends against two real, narrow things — a **compromised ops credential** and an **honest operator under pressure** — and it should be scoped, costed, and sold as exactly that, not as "H1's mechanical half closed."

**What would close it, and why we are not building it:** publishing the leaf set (destroys §6.2, inverts §8's mortal bearer graph, and turns any later leak into cryptographically authenticated evidence — refused), or a zero-knowledge argument binding the committed set to the counters (L15 refuses ZK, and it would be trust-critical crypto several times the size of the ledger it protects). Both are named so nobody re-proposes a cheaper substitute.

**What is genuinely bought:** an *unbounded, silent, instantaneous* rug becomes a *bounded, rate-limited, pre-announced, publicly attributed* one, on top of BOOTSTRAP's already-shipping issuance-velocity gossip and exposure caps. That is a real improvement. It is not prevention, and the spec text must be written so that "supply is now trustworthy" is hard to misread out of it.

### 4.2 H2 — mint death: **solved for state; conditional on a successor existing**

- **F0a alone** gives near-zero-RPO durability against disk loss, site loss, datacenter loss, and ransomware (versioning + object lock). This is most of H2's technical half and it needs nobody.
- **F0b** adds survival of operator *disappearance*: custodians who cannot read the ciphertext plus a split restore key.
- **F1+F2/F3** make the restore **verifiable by parties who do not trust the operator** and **capped** by a number independent parties signed, with inflation during restore impossible by construction (§1.9).
- **F5's claim rule** closes spent-coin resurrection and secret harvesting.

**Limits, plainly:**
- (a) A **willing successor** is required. The certified root is a capped verifiable genesis oracle; it is not an underwriter.
- (b) Succession transfers **liabilities** without **assets**, and L9 guarantees there is no convertible backing to transfer. Absent a funded successor, a perfect proof is a signed, quantified receipt for a loss — worth something for reputation, accounting, and litigation, and not money.
- (c) **RPO is the replication interval, not zero.** The draft said both "zero-RPO" and "near-zero-RPO." The residual gap is exactly the money that vanishes in a restore, which is what makes the restore reserve routine rather than exotic.
- (d) Coins **created and spent inside the last checkpoint interval** before death are unreconstructable by anyone. Bounded and disclosed (§1.9).
- (e) A published haircut ratio creates a live market price for dead-mint claims — a pre-death signal that can itself trigger a run, and a moral hazard on the operator. Publish the policy; expect this; clear it against §4.3's covenant first.
- (f) **Shamir shares are a loss surface as well as a leak surface.** m-of-n where holders are hobbyists with three-year horizons means the realistic recovery-day discovery is two shares on a dead laptop, and shares emit no heartbeat. Mandatory: an annual signed **share-liveness attestation** (mirroring §4.3's re-attestation pattern), a **blocking reshare on every roster change**, and an **annual restore drill** that actually reconstructs the key and restores to a staging twin, added to BOOTSTRAP's existing quarterly kill-drill rotation. A backup nobody has restored is not a backup.

### 4.3 H3 — coercion: **partially mitigated, net-negative on one axis, and specifically not the part that matters**

**It does not reduce the probability of the cheapest kill by one percentage point.** `BOOTSTRAP.md:174` is right that a lawful cessation order against one legal person defeats any amount of infrastructure hardening, and the hot writer here is still one legal person in one jurisdiction. Compel them and payments stop; cosigners are structurally incapable of helping, by this design's own thesis.

**What genuinely changes:**
1. An adversary **cannot compel inflation** under F4 — that authority is not the operator's alone to surrender.
2. A compelled cessation becomes **survivable** *if a successor exists*: permanent death → an outage plus a jurisdictional relocation. Making the kill stick additionally requires compelling `n − k_succ + 1` cosigners across ≥3 jurisdictions.
3. **Detection resolution improves**, and now without a payment-path cost (§2 item 4). The checkpoint chain is a better liveness heartbeat than the §3.6 snapshot cadence BOOTSTRAP already routes on, and it is third-party observable.

**What is false in the draft and is corrected here:**

> *"An adversary can no longer compel seizure."* **Wrong.** L2/§3.2 means the operator cannot *spend* your coins. It does not stop the operator **deleting the row**. Real `outstanding` drops; the operator records an equal `Δburned`; burn is an unverified free variable that no party can distinguish from real traffic, and burn monotonicity is satisfied. **Compelled seizure = compelled deletion + one burn line, invisible to every mechanism here** — and the ring makes it *worse* by attaching a cosigned attestation that the books balanced. Unfixable within the budget: burn cannot be made verifiable without transaction-level publication (MO-D2). Stated as a residual, not engineered around.

**What is entirely unaddressed:** per-payment censorship; the operator's own solvency and freedom.

**What this design makes worse, counted against the ledger rather than buried:**
- **A new, cheaper partial kill.** Stopping exceptional issuance requires `n − k_iss + 1` unpaid volunteers to merely *stop* — two letters to two hobbyists with no lawyer, no indemnity, no revenue at risk, versus compelling an operator with a corporate shell and a compulsion runbook. Issuance is §7.1 — the only path by which value enters the system. "Payments unaffected" is true and is not the same as "harmless." The standing drip and a larger `n` mitigate; they do not remove it.
- **n new named legal persons publicly attached to a money-shaped system**, with jurisdiction and identity in a machine-readable descriptor. BOOTSTRAP's central CENSOR finding is that named legal persons are the cheapest kill; this multiplies them and publishes a target list. Mitigation: disclose jurisdiction at **ring granularity** ("this ring spans ≥3 jurisdictions") wherever the succession rule does not strictly require the finer grain.
- **New compellable data holders:** F0b custodians (ciphertext + a share) and F2v replica operators (a live unspent set in plaintext). The marginal harm is genuinely low — L2/§3.2 means a seized unspent set **cannot spend anyone's money**, and the operator already holds the plaintext and is already compellable — but the surface is real and §8-governed retention (§2 item 5) is mandatory, not advisory. **A Privacy Profile mint cannot host an external verifying replica without surrendering the correlation resistance the profile exists to provide; those mints get F1 + F2 archiving only, and their H1 story stays at the inventory bound.**

> **On the record, and structurally enforced, not merely warned:** this must not relax `BOOTSTRAP.md`'s Phase-1 operator-plurality gate. A textual warning is not a control, and "we have five independent parties across three jurisdictions" is a far easier sentence at a review than "we have one independent mint operator." Normative: **cosigner count MUST NOT appear in any dashboard, report, or exit-criteria table that also reports operator plurality**, and *"a ring stood up while operator plurality is absent"* joins `BOOTSTRAP.md:289`'s standing red-flag list — a flag, not a milestone. The claim that the ring is a recruiting *pipeline* for mint #2 is withdrawn: the two populations are disjoint (the ring role selects for people who want low commitment), and a party that has already discharged its sense of contribution on a zero-cost role is a *harder* ask afterward, not an easier one.

### 4.4 Marginal value over what BOOTSTRAP already ships

The honest comparison is not to today's spec but to BOOTSTRAP as ratified: the archiver network already diffs every signed snapshot and converts violations to portable proofs in machine time (`:222`); issuance-velocity gossip already tightens exposure caps on a spike with no invariant break (`:301`); exposure caps already bound any single rug's damage per holder. Against that baseline:

- **F1 + F1s** add falsifiability of `outstanding_mc` for zero coordination. Clear, large, unconditional win.
- **F2** adds an equivocation detector and a consumer for the alarm, on a role BOOTSTRAP already staffs. Cheap, and required — without it, "silence is the alarm" and "two headers at one seq is portable proof" have nobody assigned to them, which is the same shape as today's §14 residual: detectable, never detected.
- **F2v** raises the cost of the one attack nothing else touches. Real, expensive, and does not close it.
- **F3+F4** upgrade "detected in machine time and auto-de-weighted" to "gated below `k_iss` collusion *for a disclosed attack a rational attacker does not use*," purchased with n named legal persons, a new cheap issuance halt, and lumpier issuance if the drip is not built.

**The one-line value case: F1, F1s, and F2 are worth it unconditionally. F2v is worth it to a mint that has a counterparty with exposure. F3–F5 are worth it to a mint that must prove something to a specific counterparty, and to nobody else — which makes them a corridor admission requirement, not a volunteer program.**

---

## 5. Adoption path from a solo mint

| Phase | Ship | Coordination | Value alone |
|---|---|---|---|
| **F0a** | Encrypted, versioned, **object-locked** replication to ≥2 object stores in ≥2 clouds/regions under the operator's own accounts; key held offline by the operator; annual restore drill | **None** | Most of H2's technical half — disk, site, datacenter, ransomware. **This week, independent of every other decision here.** Its absence from `BOOTSTRAP.md`'s Phase-1 hardening list is a real gap. |
| **F1** | Checkpointer under the §1.4 rules (WAL, `synchronous=FULL`, one read snapshot, fsync-before-sign, no wall-clock watermark); descriptor `checkpoint`; `with_proof` + `limits.proofs` + the service obligation; frozen descriptor `supply`; cross-implementation tree vectors | **None** | `outstanding_mc` becomes falsifiable by any single holder. Lock terms become pinnable for §11. Highest value-per-line in this document. Survives a decision to abandon federation entirely. |
| **F1s** | Wallet `with_proof` sampling on calls it already makes; §9.5 gossip of proof failures; **`PendingAdjustment` Tier-1 downgrade in the wallet/archiver rules, shipping before any conformance rule binds `outstanding == root.sum`** | **None** | Turns detection from asymptotic into deployed. ~30 LOC. |
| **F2** | Archiver extension: pull directly, verify, **cross-fetch a peer and diff**, publish head + heartbeat | Existing archiver operators | Equivocation detection with no ring. The alarm gets a consumer. |
| **F0b + F2v** | Independent custodians; Shamir with **blocking reshare-on-change** and annual liveness attestations; ≥2 verifying replicas with read-only status surfaces | 3 custodians; 1–2 replica operators | Survives operator disappearance and doctored restores. Raises silent-inflation cost to a maintained shadow ledger. |
| **F3** | Cosigning ring under the **reciprocal** model; `2·k_ck > n`; verifier-side majority rule; gossip-before-signing; genesis anchor and published `first_seen_seq`; two keys per member; fixed renewable terms; explicit `RosterCertificate`; non-mint pre-committed drills | **Gated on mint #2 existing** — the §15 trigger read literally | Binding non-equivocation. Substrate for F4/F5. |
| **F4** | `IssuanceCertificate` (drip + batch) gating `mintapi.admin_issue`; `PolicyCertificate`; `AdjustmentCertificate` (≤0 only, budgeted, rate-limited) | Published, pinned policy envelope | Compromised-credential control; honest-operator commitment device. **Not** a control against a malicious operator (§4.1). |
| **F5** | Pre-signed `succession_authority` (sign this at ring formation, it is nearly free); `SuccessionCertificate`; restore rule; hash-only claims against the final root only, deduplicated, published, with a deadline. **No desk, no published haircut until §4.3's edges document covers it.** | ≥3 jurisdictions; reconciled against `BOOTSTRAP.md:314`'s 2-of-3 escrow | H2 completed; H3's survivability half. |

**Forced orderings, each with a reason:**
- **Never F1 without §1.4.** A wall-clock watermark or a split snapshot manufactures fraud proofs against an honest mint and, via `BOOTSTRAP.md:222`, auto-fires an evacuation.
- **Never a conformance rule binding `outstanding == root.sum` without the `PendingAdjustment` downgrade.** Alarm speed must not exceed exculpation speed by four orders of magnitude.
- **Never F3 without `2·k_ck > n` and the verifier-side majority rule.** Otherwise the ring's only security contribution does not exist.
- **Never F3 without cross-witness gossip.** Otherwise it is n oracles who each trust the mint for their whole view.
- **Never F4 without F2 and the `PolicyCertificate` path.** Certificates against an envelope the mint can rotate are self-imposed.
- **Never a fast succession path.** Fast succession is a weapon.
- **Never a positive adjustment.** Ever.

A solo mint publishing `checkpoint: null, federation: null` is fully conformant and honestly labeled. A mint at F1 is strictly better than today with zero coordination. There is no all-or-nothing step anywhere.

**Process note on §15.** The parked trigger reads: *"Mint federation. Trigger: multiple mutually distrusting parties need joint control of **issuance**."* Issuance, not settlement — the spec's authors anticipated approximately this shape. But a trigger is a fact about the world, not a permission slip. **F0, F1, F1s, and F2 are justified independently of it** — F0 is operations, F1 is a strict improvement to the existing §3.6 mitigation requiring no second party, F1s is twenty lines in a wallet, and F2 is an extension of a role BOOTSTRAP already ships. Hold F3–F5 until the trigger genuinely fires, which under §3.4's reciprocal conclusion means: until mint #2 exists and has exposure. That ordering has the pleasant property that the parts shipped early are precisely the parts that survive any later decision to abandon federation.

---

## 6. The escalation ladder

The trigger for going further is narrow and is written down now so nobody escalates on aesthetics: **H3 actually biting — a demonstrated compulsion event against a committed mint — or a corridor whose value at risk makes the last few seconds before a primary loss worth thousands of lines of trust-critical code.**

**Step 1 — replica witnesses as durability (F2v, already in the ladder above).** Storage only, no protocol change, no payment-path change. The draft filed this as an RPO nicety; it is the design's only mechanism that touches tree completeness at all, and promoting it is the draft's single largest correction.

**Step 2 — quorum-write settlement. The draft's construction does not work, and this document declines to ship it.**

The draft proposed: `mint_id` resolves to a roster of replicas each serving the standard endpoints; a wallet picks one and fails over; per exchange, the front end broadcasts to all n; each replica in one local `BEGIN IMMEDIATE` checks §3.3 steps 1–3 against its own copy, durably records `key → batch_digest`, and signs; `w > n/2` matching grants form a commit certificate; grants never expire. The safety argument (quorums intersect; the shared replica granted at most one digest per key; grants are all-or-nothing per replica so §3.3 multi-key atomicity is preserved) is correct **as far as it goes**. Four blocking problems mean it does not go far enough (SC-C1–C4):

1. **No anti-entropy, and it cannot have one under its own prohibitions.** A replica that missed a batch does not hold that batch's *outputs*; when those outputs are later spent it returns `unknown` and cannot grant. Liveness of every future spend therefore requires ≥ `w` replicas to hold every prior output, and every missed batch permanently degrades the set. There is no reconciliation mechanism, because prohibition 3 forbids a log — and state transfer without an order **is** a log. **As specified, step 2 has no convergence mechanism and is not implementable.**
2. **`claim_witness` is not quorum-replicated, so §11 atomicity silently breaks.** L6/§3.5 make claim-witness disclosure a Layer 0 MUST because cross-mint swaps do not exist without it. A claims with grants from {1,2,3}; {4,5} never see the witness; B, polling replica 4 as the design *mandates* it may, reads `unspent` forever, never learns `x`, and refunds while A has claimed both legs. Fixing it requires reading from `n − w + 1` replicas — a read quorum, which is the first half of the Paxos phase the same section prohibits. It also breaks L14 serve-then-batch-redeem and §9.1/§9.3 funding verification.
3. **"No grant expiry" converts wallet concurrency bugs into permanent fund loss.** Batch A grabs key₁ on {1,2}, batch B on {3,4}; neither reaches `w`; no expiry; no recovery round permitted. **Both coins are dead forever.** Self-inflicted — but "self-inflicted" includes a wallet retrying after a crash with regenerated output secrets, which promotes §5.1's persist-before-send convention from a recoverability best practice to a **fund-safety rule**. The prohibition on expiry is still *correct* (re-grantable grants let A commit on {1,2,3} while expired-1 plus {4,5} certify B — a double-spend), which is precisely the point: both branches are unacceptable.
4. **Idempotency is per-replica.** `idempotency_key → (body_digest, result)` lives in each replica's table (`ledgerstore.py`), so across a partial-grant batch replicas return different stored results for one key and §3.3's "MUST return the stored original result" becomes replica-dependent.

**The honest resolution.** Each failure has a tempting fix that ends in the same place: expiry wants recovery rounds; missed batches want state transfer; reconfiguration wants agreement; cross-replica reads want read quorums. The convergent answer is a **primary-ordered replicated log with view change plus quorum reads** — Raft or viewstamped replication with a status-read overlay. That is the heavier machinery, named: 6,000–20,000 lines of trust-critical code, 300 ms–1 s of the §0 latency budget, a permanent upgrade-coordination tax, a **net availability regression** (n=4/k=3 amateurs at 95% each = 98.6%, worse than one professional at 99.9% — durability up, availability down, and federation pitches routinely conflate them), materially worse §11 swaps, and §1's audit property outright, because the safety argument leaves the category of things you can read.

**So: step 2 is not on this ladder.** If H3 bites hard enough to need replicated settlement, the honest move is to pay the full price with eyes open, not to ship a clever half-measure whose failure modes are four separate silent money bugs. The three prohibitions the draft wanted written down (no grant expiry, no in-band reconfiguration, no total order) are recorded here as **what makes the half-measure unimplementable**, not as discipline that makes it safe.

**Out of scope at every level, permanently:** hash-space sharding (breaks §3.3 multi-key atomicity, requires a forbidden wallet change, and makes coercion resistance *strictly worse* by turning availability into an AND over operators); CRDT admission control (a G-Set converges to a state containing both conflicting spends — accept-both violates §14, deterministic tiebreak violates L1); Fedimint's mint module (a Chaumian blind-signature ledger — importing it changes the token format and drags blinding from the optional §6.2 profile into mandatory Layer 0); any cosigner attesting to an external fact (L10/§0.1 — refuse on sight).

**Also closed, so they stop being re-proposed:** client-side k-of-n value shares across mints — a bearer coin at an independent mint *is* value, independently spendable, so any k-of-n reconstruction costs `n/k · V`; plain replication, no coding gain; §3.4 locks gate *whether*, never *how much*; §3.2 mints cannot store a share. k-of-n over money requires a **shared liability**, which a portfolio can never be. And reserve/backing attestations — proving control of a foreign coin requires ZK (L15) or actually spending it; mutual A-backs-B circularity is undetectable; and reserves are not backing without a redemption right, which L9/§12 forbid. Only the asymmetric fragment survives: reserves cannot be proved present, but their *disappearance* can be proved — publish out-of-band at a policy URL, never in the descriptor.

---

## 7. Red-team ledger

Every finding from all three reports. **Adopted** = fixed in this document. **Adopted (restated)** = the mechanism stands but a claim was wrong and is corrected. **Declined** = not fixed, with a reason, and carried as a named residual in §8.

### 7.1 Malicious operator

| # | Finding | Verdict | Disposition |
|---|---|---|---|
| A1 | Phantom-leaf substitution: exclude own treasury, include counterfeit; conservation holds forever; zero innocent holders; §2.2's three premises all false | **Adopted (fatal to a headline claim)** | Detection claim **retracted** (§4.1). F2v promoted from a durability nicety to a core component. Honest bound published. "Skim the checkpointer" framing withdrawn (§1.4f). Not closed — see R1. |
| A2 | `k_ck = 2 of 5` has no quorum intersection; the growth step from n=3 to n=5 silently destroyed non-equivocation | **Adopted** | `2·k_ck > n` normative; verifier-side majority rule; signature count never a confidence score (§1.11). |
| A3 | (a) No genesis anchor — pre-inflate then ship, laundered forever; (b) unwitnessed history rewritable across a dark period; (c) batch catch-up is an equivocation engine | **Adopted** | `genesis` anchor in every header; published `first_seen_seq` so audit depth is machine-visible; **cross-cosigner gossip mandatory before signing, and especially before catch-up** (§1.6 Flow D). |
| A4 | `Ledger.issue()` precondition has zero marginal security against the named adversary; §7.1/§8 contradict §4 | **Adopted (restated)** | F4 rescoped to a compromised-credential control and an honest-operator commitment device (§4.1). Contradictory "H1's mechanical half closed" deleted. Gate moved out of the ledger (SC-D2). |
| B1 | Proof service optional → publish checkpoints, refuse proofs, keep the reputation | **Adopted** | Proof service is a conditional right; explicit non-inclusion answers; `not_found` vs `unavailable` distinguishable; `proof_service` machine-visible (§1.8). |
| B2 | Stale proofs replayable at the succession claim endpoint | **Adopted** | Claims against `final_checkpoint.seq` only; dedup; published honored set; deadline (§1.9). |
| B3 | Lock mutation after a proof is issued — and `lock_digest` is the fix nobody named | **Adopted** | Claimed explicitly as a §11 control (§1.3 req 5). Does not survive A1; free, and closes the careless version. |
| C1 | Cosigners are the cheapest sybil target and the doc sells that as a feature; BOOTSTRAP's P5 decorrelation signals do not transfer | **Adopted** | "10× cheaper to recruit" withdrawn and restated as "10× cheaper to fake"; cosigners recruited to `BOOTSTRAP.md:143`'s operator standard; reciprocal model (§3.4). |
| C2 | No stake, so bribery has no floor; no defection-bounding property at all, unlike §9.3 | **Adopted (partial) + residual** | Reciprocal model supplies stake. §9.3's `value/n` framing explicitly **not** borrowed. Carried as R4. |
| C3 | The refusal drill is administered by the mint → worthless, and an alibi | **Adopted** | Non-mint initiator, unannounced, **pre-committed hash**, failures published by other cosigners, adjustments included (§3.3). |
| C4 | Incentive decay is the recruiting pitch; the design recruits for the behavior it fears | **Adopted** | Two keys (rare decisions physically different); fixed renewable terms; `effective_n` published (§1.7, §3.3). |
| C5 | `roster_cross_signature` has no stated signer; one reading hands the operator the ring | **Adopted** | `RosterCertificate` signed by the **outgoing roster** at `max(k)`, never by the mint; notice window; first-class threshold row (§1.7, §1.11). |
| D1 | `AdjustmentCertificate` is a strictly weaker-gated issuance path at the same threshold; `data_loss` shipped as a cover story; no W2-phase threshold | **Adopted** | `delta_outstanding_mc < 0`, always. Positive value enters only via `IssuanceCertificate` or the bounded restore reserve. Budgeted and rate-limited (§1.7). |
| D2 | "Seizure-under-compulsion removed" is false — deletion-as-burn, concealed by the conservation equation | **Declined (unfixable in budget)** | Claim corrected in §4.3. Residual R5. Burn cannot be made verifiable without transaction-level publication. |
| D3 | Succession launders audit history under a preserved identity; the stated fork tiebreak names the hijacker as winner | **Adopted** | Stall predicate defined over cosigners' own published logs (§1.9); the "ring's cosignature is the tiebreak" convention **deleted** — see R6; pre-signed `succession_authority` gives the offline test a deterministic answer. |
| E1 | The header is a 60-second treasury tape; a strictly larger disclosure than the field §3.6 deliberately blurred | **Adopted** | `unspent_count`, `unspent_sum_mc`, `locked_count`, `locked_sum_mc` **dropped**; cadence to 5 min + activity floor + jitter (§1.2). |
| E2 | Inclusion proofs leak more than "≈3 bits" — the ladder is a MUST only in the Privacy Profile | **Adopted (partial)** | Leak restated correctly (R8). Sparse tree chosen over sorted specifically so non-inclusion discloses no neighbor keys. Ladder-MUST for checkpointing mints deferred to §9 Q6. |
| E3 | Recruiting capital competes with mint #2; `n: 5` will be read as a trust score | **Adopted** | Recruiting ledger (§3.5); reciprocal model; **structural** separation of cosigner count from plurality reporting + BOOTSTRAP red flag (§4.3). |

### 7.2 Systems critic

| # | Finding | Verdict | Disposition |
|---|---|---|---|
| A1 | `created_at`/`spent_at` are request-arrival, not commit-ordered; incremental checkpointer forks; spent coin honored again at the successor | **Adopted (blocking)** | §1.4(a): single read snapshot; commit counter for incremental; clock moved after `BEGIN IMMEDIATE` as a §3.4 conformance fix. "Zero lines inside the transaction" retracted (§3.1). |
| A2 | Same as MO-A2, plus: thresholds stated only producer-side | **Adopted** | §1.11. |
| A3 | Adjustment dominates issuance for an attacker; and it voids the absolute invariant permanently | **Adopted** | Negative-only adjustments; `cumulative_adjustment_mc` added to the header and the invariant, monotone non-increasing (§1.2, §1.7). |
| A4 | Successor cannot produce non-inclusion at the final root; resurrection; land grab; restore violates the cosigners' own monotonicity check | **Adopted (blocking)** | Claims against final root only; §3.1's non-inclusion language deleted; successor adopts final counters verbatim; gap carried as a bounded, deadline-terminated **claim reserve** (§1.9). |
| A5 | §2.2 is false — exclude coins you own; the achievable claim is an inventory bound | **Adopted** | §4.1 rewritten around the bound. "Detection probability approaches 1" and "blocked outright at monetization" deleted. |
| A6 | No WAL pragma exists; checkpointer needs a consistent two-read snapshot; sizing off by 1–2 OOM | **Adopted (blocking)** | WAL + `synchronous=FULL` normative; one read transaction; sizing corrected and full-rebuild made mandatory below 10⁵ (§1.3, §1.4). |
| B1 | Witness durability and re-bootstrap unspecified; and an honest checkpointer crash manufactures a fraud proof | **Adopted** | Cosigner fsync-before-reply; re-bootstrap must cross-check a peer, never initialize from the mint alone; checkpointer singleton, fsync-before-sign, byte-identical re-emit (§1.4d, §1.6). |
| B2 | Check 4 makes every legitimate issuance alarm from `n − k_iss` cosigners | **Adopted** | Check verifies ≥ `k_iss` roster signatures, not the cosigner's own; non-signers still advance `last_issuance_seq`; refusals recorded and published (§1.6). |
| B3 | Two cadences, one `seq` space — `seq == last+1` unsatisfiable | **Adopted** | One cadence. Internal checkpoints deleted (§1.2). |
| B4 | Roster and policy rotation thresholds undefined; the mint can rotate its own policy | **Adopted** | `RosterCertificate` and `PolicyCertificate` (§1.7). |
| B5 | Two silent cosigners veto recovery forever — the same cheap-halt error charged to BFT | **Adopted** | Raise `n`, not lower `k`; published time-degrading `k_succ` schedule (§1.11). Residual R7. |
| B6 | Succession legitimacy test requires an artifact death precludes | **Adopted** | Pre-signed `succession_authority` (§1.9). |
| B7 | Proof-before-swap cannot cover an age-zero locked output; margin claim wrong in kind | **Adopted** | Rule restated as "wait for the funded leg to appear"; `checkpoint_staleness` named; cost placed on quote validity; claim downgraded (§1.8). |
| B8 | §4 item 3 is violated continuously by honest mints; and the descriptor is on the write path | **Adopted** | Descriptor `supply` frozen to the last checkpoint; served from cache (§2 item 4). |
| B9 | F0 + a permanent archive repeal §8's mortal bearer graph | **Adopted** | §8 amendment (§2 item 5); verifying replicas hold the unspent set only; F0's "zero protocol" framing corrected. |
| B10 | The header is a 60 s amount oracle for individual locks | **Adopted** | Locked aggregates dropped; jitter and activity floor (§1.2). |
| B11 | `with_proof` amplification and tree residency are not free | **Adopted** | `limits.proofs` separate from §3.7's right; proofs against the latest checkpoint only (§1.8). |
| C1 | Step 2 has no anti-entropy and cannot have one under its own prohibitions — not implementable | **Adopted** | Step 2 removed from the ladder; the heavier machinery named (§6). |
| C2 | `claim_witness` not quorum-replicated → §11 atomicity voided by a Layer 0 escalation | **Adopted** | §6. |
| C3 | "No grant expiry" turns wallet concurrency bugs into permanent fund loss | **Adopted** | §6. |
| C4 | Idempotency is per-replica | **Adopted** | §6. |
| D1 | `sum_le8` modular hazard | **Adopted** | Unbounded ints; 16-byte BE; reject rather than wrap; cap on `cumulative_issued_mc` (§1.3 req 2). |
| D2 | Do not put the F4 precondition inside `Ledger.issue()` | **Adopted** | Gated in `mintapi.admin_issue`; `ledgerstore.py` claimed unchanged (§2). |
| D3 | Clocks — cosigners must use their own; `last_seen_at` must not be mint-supplied | **Adopted** | §1.6, §1.9. |
| D4 | Hash reuse after §8 pruning breaks bare-hash claim rules | **Adopted** | Claims bind `(hash, amount, final_seq)` (§1.9). |
| D5 | The alarm has no consumer — no party diffs the logs | **Adopted** | F2 folds the differ into BOOTSTRAP's existing archiver and routes to Loop 1 (§1.6 Flow B). Given A2, this is not optional. |

### 7.3 Adoption critic

| # | Finding | Verdict | Disposition |
|---|---|---|---|
| A1 | The recruiting ledger is already over-drawn | **Adopted** | Recruiting ledger as a BOOTSTRAP artifact; F3+ gated on mint #2 (§3.5, §5). |
| A2 | No incentive function; the only payable parties are structurally non-independent (L9 trap) | **Adopted** | Reciprocal witnessing (§3.4). CT precedent correction accepted: this design was importing the part of CT that failed to deploy. |
| A3 | `AdjustmentCertificate` is a re-imported attestation service and an uncapped inflation channel | **Adopted** | Negative-only; restore handled by a capped reserve, not an adjustment; annual budget in the envelope; drills cover it (§1.7). |
| A4 | The alarm outruns its exculpation by four orders of magnitude; a checkpointer bug auto-fires Loop 1 | **Adopted** | `PendingAdjustment` Tier-1 downgrade with a bounded window and a budget cap; single-snapshot + WAL normative; cross-implementation tree vectors before ship (§1.7, §1.4). |
| A5 | Participant exit is undesigned; both roster readings fatal; a config flag silently disables the gate | **Adopted** | Fixed renewable terms; explicit amendment rule; `effective_n`; "gating disabled while `federation != null`" joins BOOTSTRAP's red flags (§1.7). |
| A6 | Ceremony friction produces lumpy pre-authorized inventory — adverse to H1 | **Adopted** | Standing drip authorization + exceptional issuance (§1.7). Note this also shrinks the §4.1 exclusion pool, which is the residual's own bound. |
| A7 | Policy capture at genesis; the amendment path is unspecified | **Adopted** | `PolicyCertificate` with notice on loosening; default envelope with rationale published in the profile (§1.7). |
| A8 | 1,440 signatures/day vs "a hardware key"; and the public log is real infrastructure | **Adopted** | Two keys; cadence cut ~5×; the log obligation stated plainly in the dossier (§3.3). |
| A9 | F0's "zero protocol, ship this week" is false | **Adopted** | Split into F0a (genuinely zero coordination, this week) and F0b (gated with the ring); "zero-RPO" corrected to the replication interval (§5, §4.2c). |
| A10 | Shamir shares go stale; departed members keep power; shares are also a silent loss surface | **Adopted** | Blocking reshare on roster change; annual liveness attestation; annual restore drill to a staging twin (§4.2f). |
| A11 | Compelling two volunteers is cheaper than compelling the operator; n new named legal persons published as a target list; liability asserted not argued | **Adopted** | §14 row (R7); `attestation_scope` inside the signed bytes; witness dossier; ring-granularity jurisdiction where succession permits; drip absorbs the routine halt (§3.3, §4.3). |
| A12 | "A ring I trust" manufactures the registry `BOOTSTRAP.md:349` refuses | **Adopted** | Reciprocal model reframes the question to exposure; any emergent cosigner-reputation list is a standing red flag (§3.4, R9). |
| A13 | Proof-before-swap is an unenforceable MUST on Layer 3 and overclaims | **Adopted** | Restated with an explicit unwitnessed branch; claim downgraded to set membership; cost moved to quote validity (§1.8). |
| A14 | F5 has no rational successor, no staffable desk, a Covenant collision, and duplicates `BOOTSTRAP.md:314` | **Adopted** | Cut to the final root + the hash-only claim rule; desk deferred to a real successor; haircut gated on a §4.3 edges entry; escrow reconciliation is §9 Q8 (§1.9). |
| A15 | §2.2's detection needs a population that will not exist for two years | **Adopted** | F1s wallet sampling — the highest-leverage twenty lines here (§1.8). |
| A16 | The ring becomes a substitute for the plurality gate despite the warning | **Adopted** | Structural, not textual: reporting separation + BOOTSTRAP red flag; the "pipeline" claim withdrawn (§4.3). |
| A17 | The monitoring surface roughly doubles at the phase with the fewest people | **Adopted** | Fold into the existing archiver rather than create a role; publish the total standing-obligation count before and after (§9 Q9). |
| A18 | Marginal value over ratified BOOTSTRAP is smaller than the scorecard implies | **Adopted** | §4.4 states the honest value case against the right baseline. |
| — | **Reciprocal witnessing** (the structural fix) | **Adopted, with its weakness named** | §3.4, including the A-backs-B circularity it inherits. |

---

## 8. Residual risks

Written for §14 as new rows, not footnotes.

**R1 — Tree completeness is unprovable within the budget.** A mint can commit to a set of its own choosing. Verifying replicas raise the cost from three lines of SQL to a maintained divergent shadow ledger, consistent for every third-party-visible coin, forever. **Bound: undetected silent inflation ≤ the operator's own unspent, never-queried inventory.** Closing it requires publishing leaf sets (destroys §6.2 and §8) or ZK (L15). Neither is on any roadmap.

**R2 — Backing is not attested and never will be.** A policy-conformant issuance against zero real spend is fully certified. Five cosignatures attesting that operator O's credits exist does not make O's compute plural. L10/§0.1 forbid the thing that would check.

**R3 — Cosigner independence is unverifiable in-protocol, and this design makes it matter enormously.** `BOOTSTRAP.md:143` already concedes this for operator plurality (necessary-not-sufficient). Mandatory partial mitigations: per-member jurisdiction and independence disclosure; correlation clustering (decorrelated downtime, cadence, hosting ASN) applied at the *cluster* level by any party sizing exposure; `n` and `effective_n` MUST NOT be rendered as a trust score in any client UI or routing heuristic. Under the reciprocal model, exposure partially substitutes for verified independence — partially.

**R4 — Collusion is a cliff, not a slope, and the ring bounds no defection.** At `k − 1` defectors nothing happens; at `k` the outcome carries valid signatures. This is a **category difference** from §9.3's rung construction, where any single arbiter defection is bounded to `value/n` and provable. Do not borrow that framing. Mitigation is reputational and after the fact only: per-cosigner signature history is public and append-only, so a cosigner that signs an eventually-disproven header is permanently attributable.

**R5 — Seizure-by-deletion is unaddressed and is *concealed* by the conservation equation.** A compelled operator deletes rows and records an equal `Δburned`. Burn is an unverified free variable; the equation closes; the cosignature attests that the books balanced. Unfixable without transaction-level publication.

**R6 — Fork ambiguity after a resumed operator has no resolution.** Two mints claim one `mint_id`, both with valid-looking chains. There is no fork resolution without consensus. The draft's convention — "the ring's cosignature is the tiebreak" — is **deleted**, because it names the hijacker as the winner in exactly the case where a tiebreak is needed. The honest statement: *no tiebreak exists; both forks are visible and attributable; holders must choose.* The pre-signed `succession_authority` narrows it (a wallet's offline test has a deterministic answer, signed by the mint's own pinned key before any compulsion) but does not close it.

**R7 — This design creates a new, cheaper partial kill and n new compellable named persons.** Stopping exceptional issuance requires `n − k_iss + 1` unpaid volunteers merely to stop. Succession requires `n − k_succ + 1` to block. Both are far cheaper targets than the operator. Mitigated by the standing drip, larger `n`, and the time-degrading succession threshold; not removed. This belongs in the §14 table as its own row and must not be filed under H3's benefits.

**R8 — Proof disclosure is larger than the draft priced.** A proof discloses ~20 sibling `(digest, sum)` pairs, the upper ones aggregating over large fractions of the ledger. On a **non-ladder** mint a low-level sibling sum is a stranger's exact coin amount — the §4.2 ladder is a MUST only inside the Privacy Profile. A prober collecting proofs across many hashes reconstructs a substantial map of the value distribution, anonymously, over an endpoint the mint is obliged to serve. Sibling digests remain opaque and no raw neighbor ledger key is ever disclosed (§1.3 reqs 3–4). §6.2's non-retention rule extends to proof requests unchanged.

**R9 — An emergent cosigner-reputation list is the registry the project refuses.** If wallets need to decide which rings to trust, someone will publish a list, it will become load-bearing, and it will be a cheaper censorship target than any mint. The reciprocal model is the structural answer; the red flag is the backstop.

**R10 — Automation without attention is the most likely real-world failure, ahead of collusion.** Unpaid cosigners signing identical headers automate, and a rubber stamp is indistinguishable from a sybil, so decay converts an honest ring into a captured one with no event and no alarm. Two keys, terms, unannounced pre-committed drills, and independent heartbeats are the countermeasures, and they are weaker than the failure.

**R11 — A halt still silently redistributes value.** §3.4 expiries keep running while a mint is down; an outage converts §9.1 drawn-but-unsettled channel value and §9.3 undecided milestones from payee to payer. L16 discloses this; a longer succession window makes it larger and more frequent, and it deserves its own §14 row.

**R12 — Key management goes from one key to 2n+1.** §3.6's cross-signed rotation must extend to cosigner keys. A cosigner that loses its key without rotating silently reduces `effective_n`; if `effective_n` drops below `k_iss`, exceptional issuance stalls and the operator acquires a powerful incentive to build a bypass. The stall MUST be loudly visible in the descriptor so the bypass cannot be quiet.

**R13 — The checkpointer can kill the mint.** It cannot lose or misdirect money; it can emit a signed artifact that `BOOTSTRAP.md:222` treats as death. `PendingAdjustment` and the conformance vectors bound this; they do not eliminate it.

**R14 — Recruiting capital spent here is not spent on mint #2.** The scarce input is named independent legal persons willing to stay reachable for years, unpaid. `BOOTSTRAP.md` budgets four months to fill *one*. This design draws on the same well and, on the adoption critic's reading, may make the larger ask harder rather than easier.

**R15 — The Privacy Profile gets a strictly weaker version of all of this.** No external verifying replica without surrendering what the profile exists to provide; a coarser cadence; the R1 bound with no cost multiplier on top. Privacy Profile checkpointing is out of scope in v0.5 (§9 Q5) rather than reserved with a placeholder field.

---

## 9. Open questions for implementation

**Q1 — SMT performance, measured.** Build the tree, measure full rebuild at 10⁴/10⁵/10⁶ live outputs in the reference language, and set `checkpoint_interval_ms` defaults and the incremental threshold from data rather than from §1.3's estimate. Confirm the WAL-pinning behavior of a long read transaction under load.

**Q2 — `commit_seq`: one line in the transaction, or snapshot-only?** If measurement shows full rebuild is comfortable at the traffic the flagship will actually see for two years, the incremental path — and the one line inside §3.3 — may never be needed. Prefer not needing it.

**Q3 — Cross-implementation tree vectors.** A conformance vector set (empty tree, one leaf, adjacent keys, maximal-depth collisions, locked/unlocked leaves, sum-overflow rejection, non-inclusion at each depth) must exist before any conformance rule binds a root, because two conformant mints producing different roots is a false fraud accusation with an automated kill attached.

**Q4 — Cadence versus §11.** 5 minutes is chosen for privacy and signature load; §11 counterparties want freshness. Does a per-mint published cadence plus a named margin slot suffice, or do corridor mints need a separate faster commitment tier?

**Q5 — Privacy Profile.** Confirm out-of-scope for v0.5, rather than reserving a `blind_caps` field. A blind-signature ledger's key derivation is not §3.2's `sha256(secret)`, so the §1.3 tree is undefined there.

**Q6 — Should the §4.2 ladder become a MUST for any mint publishing a checkpoint?** It would materially shrink R8's amount leak. It is also a real constraint on a plain mint, and §4.2 is deliberately a SHOULD outside the Privacy Profile.

**Q7 — Verifying replica hosting.** Can a counterparty mint host one under §6.2/§8 obligations without creating a correlation asset it should not hold? What contractual retention language makes §2 item 5 enforceable rather than aspirational?

**Q8 — Reconcile F5 with `BOOTSTRAP.md:314`'s 2-of-3 successor-key escrow.** Two succession paths with different thresholds and rosters and no precedence rule is an attack surface and a fork generator. One must be declared authoritative. My inclination: BOOTSTRAP's escrow is the *key* path and F5 is the *state* path, and the `succession_authority` delegation should name the escrow's successor key — but this needs ratification, not an inclination.

**Q9 — Total standing-obligation count, before and after.** Publish it. `BOOTSTRAP.md` already carries archiver, probe, reachability, quarterly kill-drill, quarterly state-of-the-spec, annual covenant re-attestation, annual counsel review, and parked-item review. If this design roughly doubles that at the phase with the fewest people, the review should see the number, not the adjective.

**Q10 — Default policy envelope.** Publish one, with rationale, in the profile — rate ceiling, max single issuance, notice, drip rate, annual adjustment budget (count and mc) — so the first ring argues from an anchor rather than a page the operator filled in.

**Q11 — `n` and thresholds at F3 launch.** n=3 is the minimum that intersects; n=7 is where the halt thresholds stop being cheap. Under the reciprocal model, n is bounded by how many parties actually hold exposure, which at Phase 3 is small. State the honest starting point rather than the aspirational one.

**Q12 — Does the §15 trigger ever fire?** F3–F5 exist for "multiple mutually distrusting parties [needing] joint control of issuance." If, by the time mint #2 exists, exposure caps plus issuance-velocity gossip plus F1's falsifiable commitment have made the ring's marginal value smaller than its recruiting cost, the correct outcome is to ship F0a/F1/F1s/F2 and **never build the ring**. That is a legitimate result, and this document is deliberately structured so that outcome loses nothing already built.

---

## 10. One line for the spec's summary

> **v0.5 commits the mint's supply to a falsifiable Merkle sum root, gives the alarm a consumer inside the archiver network that already exists, and — only where mutually exposed parties actually exist — federates the mint's *rare* authorities: issuance, identity, and succession. It refuses to federate the hot one. Layer 0's ledger semantics are unchanged for the fourth consecutive revision; the payment path is byte-identical; a mint that commits to nothing remains fully conformant and honestly labeled; and the supply claim it buys is a *bound* on silent over-issuance, not detection of it.**