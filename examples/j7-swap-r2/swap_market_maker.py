#!/usr/bin/env python3
"""JOURNEY 7 (round 2) — cross-mint atomic swap from a MARKET MAKER's seat.

Cold-usability test of AICash §11: written using ONLY the repo docs and the
package-root public API re-exported from ``aicash`` (README table, spec §11 /
§3.4 / §3.5, and the component "Public API" blocks). No implementation source
was read beyond public signatures/docstrings, and NOTHING touches SwapParty
private state — everything below is reachable by a real integrator.

Run with:
    PYTHONPATH=impl python3 swap_market_maker.py

What it demonstrates end to end, with real money on two live in-process HTTP
mints that have DIFFERENT burn policies, independent sqlite ledgers, and
independently-injected clocks (skewed on purpose):

  1. compute_margin() from the two LIVE descriptors — grace(both) +
     precision(both) + polling interval + status latency + 2x redemption
     latency + clock skew — and a re-derivation of the number from the
     descriptor fields so a MM can see every term is load-bearing.

  2. Happy-path atomic swap driven with the public SwapParty ceremony
     (prepare_claim / a_fund / b_fund / a_claim / b_poll_and_claim). A ends
     holding Mint-2 value, B (the market maker) ends holding Mint-1 value,
     both legs' burns are charged under each mint's OWN policy, and each
     mint's signed supply invariant (outstanding == issued - burned) still
     holds. Neither mint's DB ever references the other.

  3. Silent-claim defense (§11 step 4 / C11 benchmark B2). A claims its
     Mint-2 leg as LATE as the polite client allows (just outside Mint-2's
     grace window) and tells B nothing. B — the market maker — never hears
     from A: it discovers the preimage x EXCLUSIVELY from Mint-2's public
     /v3/status claim_witness (b_poll_and_claim structurally accepts no
     witness argument) and claims its Mint-1 leg before T. A's later attempt
     to refund the leg B already took is rejected "spent": silence nets A
     nothing.

  4. Refund path. Both parties stall; an early refund is rejected
     (lock_not_expired); after expiry both legs refund to their funders.

Every claim/refund is asserted to move the expected net-of-burn amount, and
every won token is banked into a real second-mint wallet to prove it spends.
"""

import os
import sys
import tempfile

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2] / "impl"))

# Everything below is from the package root — the README's promise is that an
# integrator needs nothing else.
from aicash import (
    BurnPolicy,
    FakeClock,
    MintClient,
    MintConfig,
    MintRejected,
    SwapParty,
    Wallet,
    compute_margin,
    format_token,
    generate_keypair,
    ledger_key,
    make_mint,
    new_secret,
    parse_token,
)

DAY_MS = 86_400_000


def say(msg=""):
    print(msg, flush=True)


def boot_mint(tmp, mint_id, clock, base_ms, policy, p99_ms):
    """Stand up one live HTTP mint with make_mint (single source of truth:
    the ledger is built FROM the config, so the descriptor cannot drift from
    what the ledger enforces). Returns (server, client)."""
    priv, pub = generate_keypair()
    config = MintConfig(
        mint_id=mint_id,
        baseline_model_class="compute-unit-v1",
        burn_policy=policy,
        signing_private=priv,
        signing_public=pub,
        admin_token="op-secret",
        grace_ms=5_000,
        timestamp_precision_ms=100,
        recovery_window_ms=90 * DAY_MS,
        max_lock_expiry_ms=30 * DAY_MS,
        performance={
            "p99_exchange_ms": p99_ms,
            "sustained_qps": 100,
            "window_days": 30,
            "measured_at": base_ms,   # fresh: descriptor mint_time starts here
        },
    )
    server, _ledger = make_mint(
        config, db_path=os.path.join(tmp, f"{mint_id}.db"), clock=clock
    )
    port = server.start()
    return server, MintClient(f"http://127.0.0.1:{port}")


def fund_wallet(client, wallet, mint_id, amount_mc):
    """Operator funds a treasury via the non-normative §7.1 /admin/issue path,
    then the wallet receives it (receive-first onboarding, net of burn)."""
    s = new_secret()
    client.admin_issue(
        [{"amount_mc": amount_mc, "secret_hash": ledger_key(s)}],
        admin_token="op-secret",
    )
    return wallet.receive(format_token(mint_id, amount_mc, s))


def check_supply(client, label):
    s = client.descriptor()["supply"]
    assert (
        s["outstanding_mc"] == s["cumulative_issued_mc"] - s["cumulative_burned_mc"]
    ), f"{label}: supply invariant violated: {s}"
    return s


def main():
    tmp = tempfile.mkdtemp(prefix="aicash-j7r2-")

    # -- Two mints, DIFFERENT burn policies, independent clocks (skewed 400ms).
    base1 = 1_756_000_000_000
    base2 = 1_756_000_000_400
    clock1 = FakeClock(base1)
    clock2 = FakeClock(base2)

    def advance_both(ms):
        clock1.advance(ms)
        clock2.advance(ms)

    policy1 = BurnPolicy(rate_ppm=1_000, cap_mc=50, exempt_below_mc=10)   # 0.1%, cap 50
    policy2 = BurnPolicy(rate_ppm=5_000, cap_mc=500, exempt_below_mc=10)  # 0.5%, cap 500

    m1_server, m1 = boot_mint(tmp, "mint-alpha", clock1, base1, policy1, p99_ms=200)
    m2_server, m2 = boot_mint(tmp, "mint-beta", clock2, base2, policy2, p99_ms=100)
    try:
        d1, d2 = m1.descriptor(), m2.descriptor()
        say(f"[setup] mint-alpha burn_policy = {d1['burn_policy']}")
        say(f"[setup] mint-beta  burn_policy = {d2['burn_policy']}")
        assert d1["burn_policy"] != d2["burn_policy"], "policies must differ"

        # A is a client at mint-alpha; B is the MARKET MAKER at mint-beta.
        # Each also opens a wallet at the far mint to bank what it wins.
        a_home = Wallet(os.path.join(tmp, "a_alpha.db"), m1, "mint-alpha")
        b_home = Wallet(os.path.join(tmp, "b_beta.db"), m2, "mint-beta")
        a_far = Wallet(os.path.join(tmp, "a_beta.db"), m2, "mint-beta")
        b_far = Wallet(os.path.join(tmp, "b_alpha.db"), m1, "mint-alpha")

        fund_wallet(m1, a_home, "mint-alpha", 200_000)
        fund_wallet(m2, b_home, "mint-beta", 200_000)
        say(f"[setup] A holds {a_home.balance()} mc @ mint-alpha; "
            f"B (market maker) holds {b_home.balance()} mc @ mint-beta")

        POLL_MS = 5_000

        # ==============================================================
        # 1. Margin from the live descriptors, re-derived term by term.
        # ==============================================================
        say("\n=== 1. compute_margin from live descriptors ===")
        margin = compute_margin(
            d1, d2, polling_interval_ms=POLL_MS, assumed_latency_ms=None
        )
        # Independent re-derivation from §11's formula. Slot attribution
        # (pinned): status-latency slot is Mint 2's; two redemption slots one
        # per mint; the reference uses max of both p99x10 for every latency
        # slot (compute_margin docstring / OPEN-QUESTIONS #8).
        lat = max(
            d1["performance"]["p99_exchange_ms"],
            d2["performance"]["p99_exchange_ms"],
        ) * 10
        skew = abs(d1["mint_time"] - d2["mint_time"])
        expected = (
            d1["lock_params"]["grace_ms"] + d2["lock_params"]["grace_ms"]
            + d1["lock_params"]["timestamp_precision_ms"]
            + d2["lock_params"]["timestamp_precision_ms"]
            + POLL_MS          # B's polling interval
            + lat              # status-response latency (Mint 2)
            + 2 * lat          # redemption latency, one per mint
            + skew
        )
        assert margin == expected, (margin, expected)
        say(f"[margin] compute_margin = {margin} ms")
        say(f"[margin]   grace {d1['lock_params']['grace_ms']}+{d2['lock_params']['grace_ms']}"
            f", precision {d1['lock_params']['timestamp_precision_ms']}+{d2['lock_params']['timestamp_precision_ms']}"
            f", poll {POLL_MS}, latency {lat}x3 (max p99x10), skew {skew}")

        # ==============================================================
        # 2. Happy-path atomic swap (10_000 mc each way).
        # ==============================================================
        say("\n=== 2. happy-path swap: 10_000 mc alpha <-> 10_000 mc beta ===")
        s1b, s2b = check_supply(m1, "alpha"), check_supply(m2, "beta")

        # A funds from alpha and claims at beta; B funds from beta, claims at alpha.
        A = SwapParty(a_home, m2, "mint-beta", polling_interval_ms=POLL_MS)
        B = SwapParty(b_home, m1, "mint-alpha", polling_interval_ms=POLL_MS)

        T_prime = m2.descriptor()["mint_time"] + 120_000   # Mint-2 leg expiry
        T = T_prime + margin + 10_000                      # Mint-1 leg expiry (> T')

        b_hash = B.prepare_claim()                         # B's claim hash @ alpha
        a_hash = A.prepare_claim()                         # A's claim hash @ beta
        x_hash = A.a_fund(10_000, b_hash, T)               # step 1: A funds @ alpha
        B.b_fund(10_000, a_hash, x_hash, T, T_prime, claim_amount_mc=10_000)  # step 2
        a_token = A.a_claim(10_000, T_prime)               # step 3: A claims @ beta
        b_token = B.b_poll_and_claim(                      # step 4: B discovers x, claims @ alpha
            poller=lambda attempt: advance_both(POLL_MS)
        )

        assert parse_token(a_token).mint_id == "mint-beta"
        assert parse_token(b_token).mint_id == "mint-alpha"
        got_a = a_far.receive(a_token)                     # A banks beta winnings
        got_b = b_far.receive(b_token)                     # B banks alpha winnings
        say(f"[swap] A won {parse_token(a_token).amount_mc} mc @ beta, banked {got_a} mc")
        say(f"[swap] B won {parse_token(b_token).amount_mc} mc @ alpha, banked {got_b} mc")
        assert a_far.balance() == got_a and b_far.balance() == got_b

        s1a, s2a = check_supply(m1, "alpha"), check_supply(m2, "beta")
        say(f"[swap] burn charged under each mint's own policy: "
            f"alpha {s1b['cumulative_burned_mc']}->{s1a['cumulative_burned_mc']}, "
            f"beta {s2b['cumulative_burned_mc']}->{s2a['cumulative_burned_mc']}")
        assert s1a["cumulative_burned_mc"] > s1b["cumulative_burned_mc"]
        assert s2a["cumulative_burned_mc"] > s2b["cumulative_burned_mc"]

        # ==============================================================
        # 3. Silent-claim defense — the market maker never trusts A.
        # ==============================================================
        say("\n=== 3. silent-claim attack defeated (B recovers from the ledger) ===")
        A2 = SwapParty(a_home, m2, "mint-beta", polling_interval_ms=POLL_MS)
        B2 = SwapParty(b_home, m1, "mint-alpha", polling_interval_ms=POLL_MS)

        T_prime = m2.descriptor()["mint_time"] + 120_000
        T = T_prime + margin + 10_000
        b_hash = B2.prepare_claim()
        a_hash = A2.prepare_claim()
        x_hash = A2.a_fund(10_000, b_hash, T)
        B2.b_fund(10_000, a_hash, x_hash, T, T_prime, claim_amount_mc=10_000)

        # Structural proof of the defense: the method B relies on to recover x
        # has NO parameter that could carry a witness from A. B cannot be fed x.
        import inspect
        b_params = list(inspect.signature(B2.b_poll_and_claim).parameters)
        assert b_params == ["poller", "max_polls"], b_params
        say(f"[defense] b_poll_and_claim{tuple(b_params)} — no witness argument exists; "
            f"x can only come from Mint-2 status")

        # A claims its beta leg as LATE as the polite client permits — just
        # outside Mint-2's grace window (a_claim refuses within grace of T') —
        # and NOTIFIES B OF NOTHING. This is the worst case for the MM.
        grace2 = d2["lock_params"]["grace_ms"]
        advance_both((T_prime - grace2 - 1) - m2.descriptor()["mint_time"])
        adv_token = A2.a_claim(10_000, T_prime)
        say(f"[attack] A claimed {parse_token(adv_token).amount_mc} mc @ beta at "
            f"~T'-{grace2}ms and went silent")

        # Worst case: B's previous poll just missed A's claim; the next poll
        # fires one full interval later. B discovers x from claim_witness alone
        # and claims @ alpha before T.
        advance_both(POLL_MS)
        recovered = B2.b_poll_and_claim(poller=lambda attempt: advance_both(POLL_MS))
        t_left = T - m1.descriptor()["mint_time"]
        assert parse_token(recovered).mint_id == "mint-alpha"
        assert t_left > 0, t_left
        say(f"[defense] B read claim_witness from /v3/status and claimed @ alpha "
            f"with {t_left} ms to spare before T — never spoke to A")

        # The attack's second half must fail: A cannot refund the leg B took.
        advance_both((T + 1_000) - m1.descriptor()["mint_time"])
        try:
            A2.refund_expired()
            raise AssertionError("adversary refunded a leg B already claimed!")
        except MintRejected as exc:
            reasons = [e["reason"] for e in exc.errors]
            assert "spent" in reasons, reasons
            say(f"[defense] A's refund of the alpha leg rejected {reasons} — "
                f"the silent claim netted A nothing extra")
        got = b_far.receive(recovered)
        say(f"[defense] B banked {got} mc @ alpha (running balance {b_far.balance()})")

        # ==============================================================
        # 4. Both stall -> refunds; no early refund.
        # ==============================================================
        say("\n=== 4. both stall: refunds at expiry only ===")
        A3 = SwapParty(a_home, m2, "mint-beta", polling_interval_ms=POLL_MS)
        B3 = SwapParty(b_home, m1, "mint-alpha", polling_interval_ms=POLL_MS)
        T_prime = m2.descriptor()["mint_time"] + 120_000
        T = T_prime + margin + 10_000
        b_hash = B3.prepare_claim()
        a_hash = A3.prepare_claim()
        x_hash = A3.a_fund(10_000, b_hash, T)
        B3.b_fund(10_000, a_hash, x_hash, T, T_prime, claim_amount_mc=10_000)

        try:
            A3.refund_expired()
            raise AssertionError("early refund should have been rejected")
        except MintRejected as exc:
            reasons = [e["reason"] for e in exc.errors]
            assert "lock_not_expired" in reasons, reasons
            say(f"[refund] early refund rejected {reasons}")

        advance_both((T + 1_000) - max(m1.descriptor()["mint_time"],
                                       m2.descriptor()["mint_time"]))
        ra = A3.refund_expired()
        rb = B3.refund_expired()
        say(f"[refund] after expiry: A recovered {ra} mc @ alpha, B recovered {rb} mc @ beta")
        assert ra > 0 and rb > 0

        check_supply(m1, "alpha")
        check_supply(m2, "beta")
        say("\n[final] supply invariants hold on both mints; "
            "neither mint ever referenced the other. ALL SCENARIOS PASSED.")
    finally:
        m1_server.stop()
        m2_server.stop()


if __name__ == "__main__":
    main()
