# C08 — channels

**Module:** `aicash/channels.py` · **Tests:** `tests/test_c08_channels.py` · **Spec:** §9.1, §9.5 (channel_draw), §7.3 · **Locked:** L7, L16 · **Depends:** C07 (wallet + MintClient)

## Purpose
The prefunded incremental channel: tagged hash chain, tranches, local draws, batch settlement, expiry refund.

## Public API
```python
CHAIN_TAG = b"aicash-chain"                      # exactly these 12 ASCII bytes (L7)
derive_chain(x_N: bytes, N: int) -> list[bytes]  # [x_1..x_N] with x_{i-1} = sha256(CHAIN_TAG + x_i)
split_tranches(N: int, capacity: int) -> list[int]   # §9.1 greedy tranche split
class ChannelInfo:                  # the §9.1 payer→payee handoff — public material only, no secrets
    # dataclass exposing the wire-form keys as directly-readable attributes (in addition to the
    # to_json/from_json pair): .channel_id, .mint_id, .unit_mc, .N, .expiry_ms, .tranches — read
    # these instead of re-parsing the JSON
    to_json() -> str                # wire form: one §3.3 canonical-JSON object (shape below)
    ChannelInfo.from_json(s: str) -> ChannelInfo   # strict parse of the wire form; raises
        # ChannelInvalid on malformed input (field/ledger verification stays accept()'s job)
class ChannelPayer:
    __init__(wallet: Wallet)
    estimate_open_cost(unit_mc: int, N: int) -> int  # total mc a subsequent open(unit_mc, N) will
        # cost ABOVE the locked N·unit_mc: funding-call burns + consolidation burns + the wallet's
        # coin-selection burns, computed against the wallet's CURRENT holdings (read-only — one
        # descriptor fetch, no exchanges); exact while holdings and burn policy are unchanged
    open(payee_hashes: list[str], unit_mc: int, N: int, expiry_ms: int) -> ChannelInfo
        # funds via wallet; per-tranche increment capacity is max_batch − 1 (§9.1/R18), so N opens
        # in ⌈N/(max_batch−1)⌉ tranches, each funded by ONE consolidated input; raises ChannelError
        # ("wallet ladder too fragmented for this mint's max_batch") when the wallet's ladder yields
        # more payment tokens than the consolidation call can carry (tokens + 1 output > max_batch);
        # returns the ChannelInfo to hand to the payee
    draw(k: int) -> dict            # -> {"channel_id", "k", "x_k"} (the §9.5 channel_draw object)
    refund() -> int                 # at/after expiry (mint clock): refund every unclaimed output, one
        # exchange per tranche; returns the net mc recovered (§7.3 burns deducted). The recovered
        # value lands as fresh plain tokens in the payer-held .refund_tokens list — hand those to a
        # Wallet.receive/receive_batch to credit them back into the payer's wallet (refund does NOT
        # auto-receive them). Refuses before expiry with ChannelError
class ChannelPayee:
    __init__(client, mint_id, *, settle_margin_ms=5_000, min_lifetime_ms=60_000, wallet=None)
    accept(info: ChannelInfo | str, secrets: list[bytes], *,
           expect_unit_mc: int | None = None, expect_n: int | None = None,
           expect_expiry_ms: int | None = None) -> None   # verify per §9.1 (batch status;
        # amounts, expiry, unspent, pinned lock-hash list; T − mint_time margin) — raises
        # ChannelInvalid; also accepts the to_json() wire string; a too-soon expiry rejection names
        # the min_lifetime_ms parameter and its value.
        # The payee SHOULD pass the negotiated terms via expect_unit_mc / expect_n / expect_expiry_ms:
        # when given, accept binds them (a handoff whose unit / N / expiry differs from the agreed
        # handshake is rejected with ChannelInvalid before the ledger round trip)
    on_draw(draw) -> int            # verify sha256(x_k)==pinned hash k (+ subsumption recovery); returns
        # cumulative verified increments; raises DrawInvalid on mismatch (stop-work signal).
        # Accepts BOTH the §9.5 wire dict from draw() (x_k a base64url string) AND the C12
        # ChannelDraw object from parse_envelope (x_k already-decoded raw 32 bytes) — the witness is
        # normalized on entry, so parse-the-envelope-then-hand-channel_draw-to-on_draw just works
        # (x_k accepted as bytes or b64u string either way; the ChannelDraw's channel_id is preserved
        # for O(1) resolution)
    settle() -> int                 # redeem verified draws per tranche; wallet=None: returns mc settled,
        # plain tokens accumulate in .settled_tokens (unchanged); with a wallet: feeds this call's
        # settled tokens into it (wallet.receive_batch if present, else wallet.receive per token) and
        # returns the net mc credited (settled net minus receive burns); .settled_tokens stays empty
```

## Wire form (`ChannelInfo.to_json`)
The cross-agent handoff after funding (§9.1 step 5) is one §3.3 canonical-JSON object with exactly
these keys — deterministic bytes, no secrets, no chain seeds:
```json
{
  "N": 120,
  "channel_id": "<first tranche's funding idempotency_key (§9.1)>",
  "expiry_ms": 1756003600000,
  "mint_id": "testmint",
  "tranches": [
    {"count": 50, "expiry": 1756003600000, "lock_hashes": ["<b64u sha256>", "..."],
     "secret_hashes": ["<b64u sha256>", "..."], "start": 1}
  ],
  "unit_mc": 10
}
```
`start` is the 1-based global draw index of the tranche's first increment; `secret_hashes` are the
payee's own output hashes in draw order; `lock_hashes` is the pinned per-increment lock-commitment
list; `expiry` repeats the channel-wide `expiry_ms` (the §9.1 `T`). `from_json` requires exactly
this key set; `ChannelPayee.accept` performs all §9.1 verification on either form.

## Requirements
1. Chain derivation uses the tag for chain steps and PLAIN sha256 for lock commitments; payee generates the output secrets (payer funds by hash) — both L7/§9.1 properties structural, not advisory.
2. Draws are fully local (no HTTP in `draw`/`on_draw` — assert via transport instrumentation).
3. Subsumption: `on_draw` for k after missing k−2..k−1 recovers and verifies the intermediates from x_k.
4. Tranches: per-tranche increment capacity is `max_batch − 1` (§9.1/R18 — `limits.max_batch` bounds `len(inputs)+len(outputs)` of one call, and funding needs one input, settlement one output); N above capacity splits into `⌈N/(max_batch−1)⌉` tranches, each with its own seed and refund secret; settlement is one exchange per tranche (one burn each). Funding raises `ChannelError` when the wallet's ladder cannot consolidate within one funding call (payment tokens + 1 output would exceed `max_batch`).
5. `settle` refuses to run inside the client-side safety margin (`expiry − grace_ms − margin`) unless forced; `refund` refuses before expiry.
6. Payee `accept` enforces every §9.1 verify item; a channel whose locks don't match the provided hash list, wrong unit, or short expiry is rejected before any work.

## Benchmark (critic checklist)
- [ ] B1 Full lifecycle vs live mint: open N=50 u=1mc, 30 draws, settle → payee +30 − burn, refund → payer recovers 20 − burn; mint supply reconciles.
- [ ] B2 **Witness-leak regression (L7):** an adversary armed with EVERYTHING public (all lock objects from status, ChannelInfo, and the payee's output secrets — i.e., a malicious payee pre-draw) attempts to claim output 1..N via forged witnesses derived from public hashes: every attempt rejected. Additionally a meta-test: recompute the chain WITHOUT the tag and assert lock_hash[i] would equal witness[i−1] — proving the tag is what closes the leak (guards against someone "simplifying" the tag away).
- [ ] B3 Clawback impossibility: the payer (holding all x_i and all public data, lacking payee secrets) attempts claim-path redemption of drawn outputs pre-expiry → rejected by the mint; refund attempt pre-expiry → `lock_not_expired`.
- [ ] B4 Undrawn increments unclaimable by payee: with k draws received, attempts on k+1..N fail (`lock_preimage_invalid`).
- [ ] B5 Subsumption: deliver draws {1, 5, 17} only; `on_draw(17)` verifies cumulative 17; settle redeems 17.
- [ ] B6 Garbage deep lock: payer funds lock j≠expected; payee accepts at open (opacity is by design), `on_draw(j)` raises DrawInvalid, settle still recovers 1..j−1 — loss bounded to the one increment, as specced.
- [ ] B7 Tranche math: N=120 at tranche capacity 50 (i.e. max_batch=51; capacity = max_batch − 1, §9.1/R18) → 3 tranches (50/50/20), per-tranche settlement burns assessed per call; draw numbering spans tranches correctly.
- [ ] B8 Expiry discipline (L16): unsettled draws after expiry are refundable by the payer (payee's loss — assert and document); settle inside margin refuses without force.
- [ ] B9 Locality: zero HTTP requests between open/accept and settle/refund apart from the draws' own absence — instrument transport call counts.
