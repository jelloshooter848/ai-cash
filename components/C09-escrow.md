# C09 — escrow

**Module:** `aicash/escrow.py` · **Tests:** `tests/test_c09_escrow.py` · **Spec:** §9.3, §9.4, §9.6 · **Locked:** L15 · **Depends:** C07, C05, C12 (record formats)

## Purpose
The Conditional Work Exchange escrow conventions: single-arbiter milestones, the k-of-n rung construction with signed votes, split awards, decision-neutral fees, deadline arithmetic, commit-then-accept.

## Public API
```python
compute_deadlines(evidence_deadline, decision_deadline, grace_ms, settlement_margin) -> expiry_ms
    # enforces T_m >= decision_deadline + grace_ms + settlement_margin
rung_composition(total_mc, denoms_desc) -> list[int]   # §9.6 rung-set ladder composition
evidence_hash(evidence) -> str                          # b64u(sha256(canonical_json(evidence)))
class FundingInfo:        # frozen dataclass — the secret-free payer→payee funding handoff
    # fields: job_id, mint_id, outputs (tuple of {milestone, arbiter_id, rung, amount_mc,
    #         secret_hash, preimage_hash, expiry}), expiries ({m: T_m}), burn_mc, change_mc
    to_dict() -> dict     # canonical-JSON-safe wire form: string keys throughout (the expiries
        # milestone keys become decimal strings), hash fields b64u strings, no floats — pass it
        # through tokencodec.canonical_json to cross a process boundary
    FundingInfo.from_dict(d) -> FundingInfo   # strict parse of the wire form; raises EscrowError
        # on malformed input (§9.3 semantic verification stays verify_funding's job)
class Arbiter:            # one instance per panel member; holds its own rung preimages + signing key
    __init__(arbiter_id: str, keypair: tuple[bytes, bytes] | None = None)   # keypair defaults to a
        # fresh C05 Ed25519 pair; .public is the panel-distributable key
    set_panel(k: int, panel_pubs: dict) -> None   # quorum rule: k signed votes out of the named
        # panel members (arbiter_id -> Ed25519 public key); defaults to the k=1 solo panel
    attest_rungs(job_id, m, rung_values: list[int], fee_mc: int = 0) -> list[dict]
        # signed {job_id, milestone, arbiter_id, rung, amount_mc, preimage_hash}; fee_mc > 0 adds
        # this arbiter's decision-neutral "fee" attestation with its own fresh preimage
    vote(job_id, m, evidence, decision) -> dict   # signed vote bound to (job_id, m, evidence_hash)
    reveal(job_id, m, awarded_fraction, votes=(), force=False) -> dict   # rung preimages for its
        # awarded share (+ fee preimage) — refuses with QuorumNotMet without k valid signed votes;
        # force=True is a TEST-ONLY defection model, self-documenting via the honest "quorum" flag
    sign_dispute(record: dict) -> dict            # sign a §10.2 dispute-outcome record (C12)
class EscrowPayer:
    __init__(client, mint_id, funding_tokens: list[str], settlement_margin_ms=60_000,
             arbiter_pubs: dict | None = None)
    fund(job_id, milestones, attestations, payee_hashes, expiries) -> FundingInfo   # by-hash locked outputs
    refund_expired(m) -> int
    balance() -> int
class EscrowPayee:        # the output-secret holder: the payee proper, or the panel's fee account
    __init__(client, mint_id, arbiter_pubs: dict)
    generate_output_hashes(attestations, kinds=("rung",)) -> dict   # one fresh output secret per
        # attested output of the given kinds; returns {(m, arbiter_id, rung): secret_hash} for the
        # payer's by-hash funding; kinds=("fee",) for the panel's fee account
    verify_funding(info: FundingInfo | dict, attestations) -> None   # MANDATORY §9.3 pre-work check;
        # raises FundingInvalid naming the offending rung; accepts the to_dict() wire form too.
        # Validates each funded output's on-ledger §3.4 lock wire shape (preimage_hash / expiry /
        # refund_hash — see spec §3.4): lock present, preimage_hash equal to the arbiter-attested
        # value, expiry equal to the milestone's scheduled T_m
    redeem(m, reveals, allow_unverified=False) -> int   # allow_unverified models a negligent payee
        # in tests only — the default refuses redemption without a prior verify_funding
    balance() -> int
class CommitThenAccept:   # §9.4
    __init__(client, mint_id, redemption_margin_ms=60_000, grace_ms=None)
    worker_hash() -> str / worker_verify(amount_mc=None, expiry=None) / worker_redeem(preimage_b64u)
    payer_commit(hash_from_worker, amount_mc, expiry, funding_tokens) / payer_reveal()  # enforces the
        # reveal deadline expiry − grace_ms − redemption_margin
    payer_refund() -> int / reveal_deadline() -> int
make_dispute_record(job_id, milestone, claimed_mc, released_mc, arbiter_ids: list, evidence,
                    timestamp: int, votes: list, refusals=()) -> dict
    # the escrow-layer builder: DERIVES the decision from the amounts (released == claimed →
    # "released"; released == 0 → "refunded"; else "split") and takes the RAW evidence object
    # (hashing it internally via evidence_hash), then delegates to the C12 receipts primitive.
    # Distinct from receipts.make_dispute_record (the same name at the receipts layer), which
    # instead takes an explicit `decision` string and a pre-computed `evidence_hash`.
```

Split-award decisions (`Arbiter.vote` `decision` / `Arbiter.reveal` `awarded_fraction`) are `"release"` | `"refund"` | an exact `(num, den)` tuple or `fractions.Fraction` — floats raise `EscrowError` (no floats, ever).

## Requirements
1. **No joint secrets anywhere (L15):** every preimage is generated and held by exactly one party; grep-level review point.
2. **Funding verification is mandatory and complete:** every output exists, unspent, right amount/expiry, `preimage_hash` equals the matching signed attestation (signature verified against the arbiter's key). Failure names the offending rung.
3. Quorum convention: `Arbiter.reveal` refuses without k signed votes supplied (its local check); a test-only `force=True` exists to model defection — production path must not expose it silently.
4. Split awards release exact rung subsets; awarded fraction maps to rung denominations greedily; remainder refunds at expiry.
5. Fees: per-arbiter fee outputs locked to decision-independent fee preimages; revealed on ANY rendered decision; refund on silence. Never locked to a milestone release preimage (assert structurally).
6. Deadline ordering enforced at fund time; §9.4 reveal deadline (`expiry − grace − margin`) enforced in `payer_reveal`, late reveal raises and is recorded as refusal.
7. Distinct refund secrets per milestone.

## Benchmark (critic checklist)
- [ ] B1 §9.6 worked example end-to-end against a live mint, exact numbers: 90,000 budget; milestone 1 full release (27,000 + 3,000 fees), milestone 2 split 60/40 (16,200 payee / 10,800 refund via rungs `5×1000+4×100` per arbiter), milestone 3 full refund at T₃; all balances and burns reconcile.
- [ ] B2 Refund-after-delivery prevention: with correctly ordered deadlines, a payee who receives reveals by decision_deadline always settles before expiry (drive clock to the worst case allowed by the convention); conversely `compute_deadlines` rejects an ordering that would break it.
- [ ] B3 Self-invented-preimage attack: payer funds rung 2 with its own hash (not the attested one) → `verify_funding` raises naming rung 2; without the check the attack would succeed (demonstrate by skipping verification in a sandboxed assertion) — proving the check is load-bearing.
- [ ] B4 Defection bounds: one arbiter reveals without quorum (force path) → payee gains exactly value/n, and the signed-vote record proves the defection (test asserts the evidence tuple); one arbiter silent despite quorum → payee short exactly value/n after expiry, dispute record attributes it.
- [ ] B5 Fee neutrality: fees collected on release AND on refund decisions; unrendered decision → fees refund to payer. A fee output locked to a release preimage is structurally impossible via the API.
- [ ] B6 Commit-then-accept: happy path; payer reveal after deadline → raises + recorded refusal; worker never starts without on-ledger verification (funds absent → worker_verify raises).
- [ ] B7 k-of-n arithmetic: k=2,n=3 — reveal succeeds with 2 votes, refuses with 1; votes are C05-verifiable and bound to (job_id, m, evidence hash).
- [ ] B8 Milestone independence: distinct refund secrets — refunding milestone 1 does not enable refunding milestone 2 early (attempt fails).
