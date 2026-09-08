# C11 — swap

**Module:** `aicash/swap.py` · **Tests:** `tests/test_c11_swap.py` · **Spec:** §11, §3.5 (claim_witness), §8 · **Locked:** L6 · **Depends:** C07 (two mints via C06)

## Purpose
Cross-mint atomic swap client: margin computation from descriptors, the two-lock ceremony, witness discovery by status polling, refund paths.

## Public API
```python
compute_margin(desc1: dict, desc2: dict, polling_interval_ms: int,
               assumed_latency_ms: int | None) -> int
# desc1 = Mint 1 (the leg that expires at T); desc2 = Mint 2 (the leg that expires at T′, where B
# polls and whose retention window is checked). §11 formula: grace(both) + precision(both) +
# polling + one status latency + 2×latency + skew.
# latency: descriptor p99 × 10 when performance present; else max(60_000, assumed) or raise QuoteRefused.
# A null-performance mint (either descriptor) makes compute_margin REFUSE to quote with QuoteRefused
# unless assumed_latency_ms is supplied — an uncomputable margin is a reason not to trade (§11).
# NOTE (test clocks): the mint nulls performance in its descriptor once it is stale —
# mint_time − performance.measured_at > window_days × 86_400_000. So when injecting a clock you must
# set performance.measured_at within window_days of the clock's mint_time, or the descriptor renders
# performance:null and this call refuses (unless you pass assumed_latency_ms).
# ALSO checks desc2's retention.recovery_window_ms covers the horizon — else QuoteRefused.
class SwapParty:      # symmetric roles built on Wallet/MintClient
    __init__(wallet: Wallet, other_client: MintClient, other_mint_id: str, *,
             polling_interval_ms=5_000, assumed_latency_ms=None)
        # `wallet` is at this party's HOME mint (where it funds its leg from); `other_client` /
        # `other_mint_id` name the OTHER mint (where it claims). Spec ↔ constructor name mapping:
        #   Party A (generates x, funds first, claims second): wallet at Mint 1, other = Mint 2
        #            → uses a_fund (funds Mint-1 leg, expiry T) then a_claim (claims Mint-2 leg).
        #   Party B (verifies, funds second, discovers x from the ledger): wallet at Mint 2,
        #            other = Mint 1 → uses b_fund (funds Mint-2 leg, expiry T′) then
        #            b_poll_and_claim (polls Mint 2, claims Mint-1 leg before T).
        # So Mint 1 = A's home / B's other (expiry T); Mint 2 = B's home / A's other (expiry T′).
    a_fund(amount_mc, counterparty_hash, expiry_ms)->x_hash / b_fund(amount_mc, counterparty_hash,
        x_hash, T, T_prime, claim_amount_mc) / a_claim(amount_mc, expiry_ms) /
        b_poll_and_claim(poller=None, max_polls=1_000) / refund_expired()
run_swap(a: SwapParty, b: SwapParty, amounts, T, T_prime, *, poller=None) -> SwapResult
    # orchestration helper. run_swap AND SwapResult are re-exported at the package root
    # (from aicash import run_swap, SwapResult, SwapParty, compute_margin, QuoteRefused, SwapError).
```

## Requirements
1. By-hash funding both legs (each party generates its own output secret for the leg it will claim).
2. `b_poll_and_claim` discovers `x` exclusively from Mint 2's `claim_witness` (§3.5) — never from A directly (assert structurally: no side channel argument exists).
3. Expiry safety: B refuses to fund unless `T − T′ >= compute_margin(...)`; A refuses to claim within grace of `T′`.
4. Refunds: both legs refundable at their expiries with their refund secrets.
5. All timing driven by injected clocks on both mints and a virtual poller in tests.

## Benchmark (critic checklist)
- [ ] B1 Happy path across two live in-process mints with different burn policies: A ends holding Mint-2 value, B holds Mint-1 value, both legs' burns accounted; neither mint's DB references the other.
- [ ] B2 **Silent-claim attack defeated (the §11 fix):** adversarial A claims at Mint 2 and sends nothing; B's poller reads `claim_witness` and claims at Mint 1 before T (drive clocks through the worst-case discovery: claim lands at T′ − ε, poll fires one full interval later). Assert B's recovery uses only public status data.
- [ ] B3 A stalls entirely: nothing claimed; both refund at their expiries; nobody can refund early (`lock_not_expired` before).
- [ ] B4 B stalls after A claims: A has Mint-2 value; B's leg at Mint 1 stays claimable by B until T even if B is late within margin; past T it refunds to A — and the test shows why the margin formula's terms are each load-bearing (shrink one term below formula → construct the failure).
- [ ] B5 compute_margin: numeric case from the verification report (grace 1s×2, precision 100ms×2, poll 5s, p99 200ms×10, skew 1s) produces the expected value (test computes independently); null-performance mint → 60s default path; insufficient retention window → QuoteRefused.
- [ ] B6 Same preimage valid at both mints (two independent Ledger instances) — the §3.4 pinning test at integration level.
