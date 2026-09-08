#!/usr/bin/env python3
"""JOURNEY 7 — cross-mint atomic swap (spec §11), produced during a COLD
usability test of the AICash repo (an agent that had never seen the
codebase, working from repo contents alone).

Run with:  PYTHONPATH=/home/lando/projects/aicash/impl python3 swap_demo.py

What this demonstrates, end to end, with real money on two real
in-process HTTP mints (different burn policies, independent sqlite
ledgers, independent injected clocks):

  1. Margin computation from the two live mint descriptors
     (swap.compute_margin — grace + precision + polling + latency + skew).
  2. Happy-path atomic swap (run_swap): A ends holding Mint-2 value,
     B holds Mint-1 value, both legs' burns accounted, and each mint's
     supply invariant (outstanding == issued − burned) still holds.
  3. Silent-claim defense (§11 step 4 / component benchmark B2): an
     ADVERSARIAL A claims B's funded leg at Mint 2 at T′ − ε — inside the
     client grace window, bypassing the polite-client convention — and
     never notifies B.  B's poller discovers the preimage x purely from
     Mint 2's public /v3/status claim_witness one full polling interval
     later and claims at Mint 1 before T.  A's subsequent refund attempt
     at Mint 1 fails with "spent": the attack nets A nothing extra.
  4. Refund path: both parties stall; an early refund is rejected by the
     mint with lock_not_expired; after expiry both legs refund.

Notes for the reader: the two mints never learn of each other; witness
discovery is structurally side-channel-free (b_poll_and_claim has no
parameter that could carry x).  The adversarial claim in scenario 3
reaches into SwapParty's private state (a._x, a._claim_secret) because
the library — correctly — offers no public "claim late and stay silent"
API; a real adversary would simply run its own client.
"""

import hashlib
import os
import sys
import tempfile
import urllib.request
import json

sys.path.insert(0, "/home/lando/projects/aicash/impl")

from aicash.burncalc import BurnPolicy, compute_burn
from aicash.clock import FakeClock
from aicash.ledgerstore import Ledger
from aicash.mintapi import MintConfig, MintServer
from aicash.signing import generate_keypair
from aicash.swap import SwapParty, compute_margin, run_swap
from aicash.tokencodec import (
    b64u_decode,
    b64u_encode,
    format_token,
    ledger_key,
    parse_token,
)
from aicash.wallet import MintClient, MintRejected, Wallet

BASE_MS = 1_756_000_000_000  # arbitrary fixed epoch for the fake clocks
DAY_MS = 86_400_000


def say(msg: str) -> None:
    print(msg, flush=True)


def start_mint(tmp, name, clock, policy, p99_ms):
    """Stand up one real HTTP mint on 127.0.0.1 with an injected clock."""
    recovery_window_ms = 90 * DAY_MS
    max_lock_expiry_ms = 30 * DAY_MS
    ledger = Ledger(
        os.path.join(tmp, f"{name}.sqlite"),
        clock,
        policy,
        recovery_window_ms,
        max_lock_expiry_ms,
    )
    priv, pub = generate_keypair()
    config = MintConfig(
        mint_id=name,
        baseline_model_class="test-class",
        burn_policy=policy,          # NOTE: must repeat the Ledger's policy
        signing_private=priv,
        signing_public=pub,
        grace_ms=5_000,
        timestamp_precision_ms=100,
        recovery_window_ms=recovery_window_ms,   # NOTE: repeated again
        max_lock_expiry_ms=max_lock_expiry_ms,   # NOTE: repeated again
        performance={
            "p99_exchange_ms": p99_ms,
            "sustained_qps": 100,
            "window_days": 30,
            "measured_at": BASE_MS,
        },
    )
    server = MintServer(config, ledger)
    port = server.start()
    return server, MintClient(f"http://127.0.0.1:{port}"), f"http://127.0.0.1:{port}"


def issue_to_wallet(base_url, wallet, mint_id, amount_mc):
    """Operator funding via the non-normative /admin/issue path, then
    receive-first onboarding into the wallet (net of the receive burn)."""
    secret = os.urandom(32)
    body = json.dumps(
        {"outputs": [{"amount_mc": amount_mc, "secret": b64u_encode(secret), "lock": None}]}
    ).encode()
    req = urllib.request.Request(
        base_url + "/admin/issue", data=body,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        assert json.loads(resp.read())["status"] == "ok"
    return wallet.receive(format_token(mint_id, amount_mc, secret))


def supply_of(client):
    s = client.descriptor()["supply"]
    assert s["outstanding_mc"] == s["cumulative_issued_mc"] - s["cumulative_burned_mc"], (
        "supply invariant violated"
    )
    return s


def main():
    tmp = tempfile.mkdtemp(prefix="aicash-j7-")

    # -- two mints, DIFFERENT burn policies, independent clocks (400ms skew)
    clock1 = FakeClock(BASE_MS)
    clock2 = FakeClock(BASE_MS + 400)

    def advance_both(ms):
        clock1.advance(ms)
        clock2.advance(ms)

    policy1 = BurnPolicy(rate_ppm=1_000, cap_mc=50, exempt_below_mc=10)   # 0.1%, cap 50
    policy2 = BurnPolicy(rate_ppm=5_000, cap_mc=200, exempt_below_mc=10)  # 0.5%, cap 200
    m1_server, m1_client, m1_url = start_mint(tmp, "mint-alpha", clock1, policy1, 200)
    m2_server, m2_client, m2_url = start_mint(tmp, "mint-beta", clock2, policy2, 100)

    desc1, desc2 = m1_client.descriptor(), m2_client.descriptor()
    say(f"[setup] mint-alpha burn_policy={desc1['burn_policy']}")
    say(f"[setup] mint-beta  burn_policy={desc2['burn_policy']}")
    assert desc1["burn_policy"] != desc2["burn_policy"], "policies must differ"

    # -- wallets: A lives at mint 1, B at mint 2; each also gets a wallet at
    #    the other mint to bank the value it wins in the swap.
    wallet_a1 = Wallet(os.path.join(tmp, "a1.db"), m1_client, "mint-alpha")
    wallet_b2 = Wallet(os.path.join(tmp, "b2.db"), m2_client, "mint-beta")
    wallet_a2 = Wallet(os.path.join(tmp, "a2.db"), m2_client, "mint-beta")
    wallet_b1 = Wallet(os.path.join(tmp, "b1.db"), m1_client, "mint-alpha")

    a_net = issue_to_wallet(m1_url, wallet_a1, "mint-alpha", 200_000)
    b_net = issue_to_wallet(m2_url, wallet_b2, "mint-beta", 200_000)
    say(f"[setup] A funded at mint-alpha: balance {wallet_a1.balance()} mc (net of burn {200_000 - a_net})")
    say(f"[setup] B funded at mint-beta:  balance {wallet_b2.balance()} mc (net of burn {200_000 - b_net})")

    POLL_MS = 5_000

    # ================================================================
    # 1. Margin from live descriptors
    # ================================================================
    margin = compute_margin(desc1, desc2, polling_interval_ms=POLL_MS, assumed_latency_ms=None)
    lat = max(desc1["performance"]["p99_exchange_ms"], desc2["performance"]["p99_exchange_ms"]) * 10
    expected = (
        desc1["lock_params"]["grace_ms"] + desc2["lock_params"]["grace_ms"]
        + desc1["lock_params"]["timestamp_precision_ms"] + desc2["lock_params"]["timestamp_precision_ms"]
        + POLL_MS + lat + 2 * lat + abs(desc1["mint_time"] - desc2["mint_time"])
    )
    assert margin == expected, (margin, expected)
    say(f"\n[margin] compute_margin = {margin} ms "
        f"(grace {desc1['lock_params']['grace_ms']}+{desc2['lock_params']['grace_ms']}, "
        f"precision {desc1['lock_params']['timestamp_precision_ms']}+{desc2['lock_params']['timestamp_precision_ms']}, "
        f"poll {POLL_MS}, latency {lat}x3, skew {abs(desc1['mint_time'] - desc2['mint_time'])})")

    # ================================================================
    # 2. Happy-path atomic swap
    # ================================================================
    say("\n=== scenario 1: happy-path swap (10_000 mc each way) ===")
    s1_before, s2_before = supply_of(m1_client), supply_of(m2_client)

    a = SwapParty(wallet_a1, m2_client, "mint-beta", polling_interval_ms=POLL_MS)
    b = SwapParty(wallet_b2, m1_client, "mint-alpha", polling_interval_ms=POLL_MS)
    now2 = m2_client.descriptor()["mint_time"]
    T_prime = now2 + 120_000
    T = T_prime + margin + 10_000
    res = run_swap(a, b, (10_000, 10_000), T, T_prime,
                   poller=lambda attempt: advance_both(POLL_MS))

    assert parse_token(res.a_token).mint_id == "mint-beta"
    assert parse_token(res.b_token).mint_id == "mint-alpha"
    assert res.a_net_mc == 10_000 - compute_burn(10_000, policy2), res.a_net_mc
    assert res.b_net_mc == 10_000 - compute_burn(10_000, policy1), res.b_net_mc
    got_a = wallet_a2.receive(res.a_token)   # A banks its Mint-2 winnings
    got_b = wallet_b1.receive(res.b_token)   # B banks its Mint-1 winnings
    say(f"[swap] A claimed {res.a_net_mc} mc at mint-beta, banked {got_a} mc "
        f"-> wallet_a2 balance {wallet_a2.balance()}")
    say(f"[swap] B claimed {res.b_net_mc} mc at mint-alpha, banked {got_b} mc "
        f"-> wallet_b1 balance {wallet_b1.balance()}")
    assert wallet_a2.balance() == got_a and wallet_b1.balance() == got_b

    s1_after, s2_after = supply_of(m1_client), supply_of(m2_client)
    say(f"[swap] mint-alpha cumulative burn {s1_before['cumulative_burned_mc']} -> {s1_after['cumulative_burned_mc']}; "
        f"mint-beta {s2_before['cumulative_burned_mc']} -> {s2_after['cumulative_burned_mc']} "
        f"(supply invariant outstanding == issued - burned verified on both)")
    assert s1_after["cumulative_burned_mc"] > s1_before["cumulative_burned_mc"]
    assert s2_after["cumulative_burned_mc"] > s2_before["cumulative_burned_mc"]

    # ================================================================
    # 3. Silent-claim attack defeated
    # ================================================================
    say("\n=== scenario 2: adversarial silent claim (claim at T' - eps, no notification) ===")
    a2 = SwapParty(wallet_a1, m2_client, "mint-beta", polling_interval_ms=POLL_MS)
    b2 = SwapParty(wallet_b2, m1_client, "mint-alpha", polling_interval_ms=POLL_MS)
    b_hash = b2.prepare_claim()
    a_hash = a2.prepare_claim()
    now2 = m2_client.descriptor()["mint_time"]
    T_prime = now2 + 120_000
    T = T_prime + margin + 10_000
    x_hash = a2.a_fund(10_000, b_hash, T)
    b2.b_fund(10_000, a_hash, x_hash, T, T_prime, claim_amount_mc=10_000)

    # Drive the clocks to T' - 1s: INSIDE mint-beta's 5s grace window, where a
    # polite client refuses to claim but the mint (commit-time rule, §3.4)
    # still accepts. The adversary claims directly against the ledger and
    # tells B nothing.
    advance_both(T_prime - 1_000 - m2_client.descriptor()["mint_time"])
    adv_net = 10_000 - compute_burn(10_000, policy2)
    adv_fresh = os.urandom(32)
    m2_client.exchange(
        "adv-claim-1",
        [{
            "token": format_token("mint-beta", 10_000, a2._claim_secret),
            "witness": b64u_encode(a2._x),
        }],
        [{"amount_mc": adv_net, "secret_hash": ledger_key(adv_fresh), "lock": None}],
    )
    say(f"[attack] adversarial A claimed {adv_net} mc at mint-beta at T' - 1000ms and went silent")

    # Worst case: B's previous poll just missed the claim; the next one fires a
    # full polling interval later. B recovers x from claim_witness alone.
    advance_both(POLL_MS)
    b_token = b2.b_poll_and_claim(poller=lambda attempt: advance_both(POLL_MS))
    t_left = T - m1_client.descriptor()["mint_time"]
    say(f"[defense] B read claim_witness from mint-beta /v3/status and claimed at "
        f"mint-alpha with {t_left} ms to spare before T")
    assert parse_token(b_token).mint_id == "mint-alpha"
    assert t_left > 0
    # sanity: the witness B used is x (it produced a valid claim), and B got it
    # from status — structurally b_poll_and_claim accepts no witness argument.
    _mt, (entry,) = m2_client.status([b2._funded["hash"]])
    assert entry["state"] == "spent"
    assert b64u_decode(entry["claim_witness"]) == a2._x

    # The attack's second half — refund leg 1 after T — must now fail: B spent it.
    advance_both(T + 1_000 - m1_client.descriptor()["mint_time"])
    try:
        a2.refund_expired()
        raise AssertionError("adversary refunded a leg B already claimed!")
    except MintRejected as exc:
        say(f"[defense] adversary's refund of the mint-alpha leg rejected: "
            f"{[e['reason'] for e in exc.errors]} — the silent claim netted nothing extra")
        assert any(e["reason"] == "spent" for e in exc.errors)
    got = wallet_b1.receive(b_token)
    say(f"[defense] B banked {got} mc at mint-alpha; wallet_b1 balance {wallet_b1.balance()}")

    # ================================================================
    # 4. Both stall -> refunds; early refund impossible
    # ================================================================
    say("\n=== scenario 3: both parties stall; refunds at expiry only ===")
    a3 = SwapParty(wallet_a1, m2_client, "mint-beta", polling_interval_ms=POLL_MS)
    b3 = SwapParty(wallet_b2, m1_client, "mint-alpha", polling_interval_ms=POLL_MS)
    bh, ah = b3.prepare_claim(), a3.prepare_claim()
    now2 = m2_client.descriptor()["mint_time"]
    T_prime = now2 + 120_000
    T = T_prime + margin + 10_000
    xh = a3.a_fund(10_000, bh, T)
    b3.b_fund(10_000, ah, xh, T, T_prime, claim_amount_mc=10_000)

    try:
        b3.refund_expired()
        raise AssertionError("early refund should have been rejected")
    except MintRejected as exc:
        assert any(e["reason"] == "lock_not_expired" for e in exc.errors)
        say("[refund] early refund correctly rejected: lock_not_expired")

    advance_both(T + 1_000 - max(m1_client.descriptor()["mint_time"],
                                 m2_client.descriptor()["mint_time"]))
    ra = a3.refund_expired()
    rb = b3.refund_expired()
    say(f"[refund] after expiry: A recovered {ra} mc at mint-alpha, B recovered {rb} mc at mint-beta")
    assert ra == 10_000 - compute_burn(10_000, policy1)
    assert rb == 10_000 - compute_burn(10_000, policy2)

    # -- final accounting --------------------------------------------------
    supply_of(m1_client)
    supply_of(m2_client)
    say("\n[final] balances: A@alpha=%d A@beta=%d B@beta=%d B@alpha=%d" % (
        wallet_a1.balance(), wallet_a2.balance(),
        wallet_b2.balance(), wallet_b1.balance()))
    say("[final] supply invariants verified on both mints. ALL SCENARIOS PASSED.")

    m1_server.stop()
    m2_server.stop()


if __name__ == "__main__":
    main()
