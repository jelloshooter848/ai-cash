#!/usr/bin/env python3
"""JOURNEY 4 — streaming pair (AICash spec §9.1 channels).

Produced during a COLD USABILITY TEST of the AICash reference implementation:
this script was written by an AI agent that had never seen the repo before,
using only the repo's docs (components/C08-channels.md etc.) and the public
module APIs.

What it demonstrates, end to end against a REAL in-process mint over HTTP:

  1. Boot a mint (FakeClock injected -> we control expiry without waiting).
  2. Fund a payer wallet via the non-normative /admin/issue path + receive().
  3. Payee generates 100 output secrets; payer opens a channel N=100,
     unit = 1 mc, expiry T = now + 10 min.
  4. Payee verifies the funded channel (ChannelPayee.accept, §9.1 verify).
  5. Payer streams 60 per-token draws; payee verifies each locally (no HTTP).
  6. Payee settles mid-stream (after 30 draws), keeps working, settles again
     (draws 31..60); settled value lands in the payee's own wallet.
  7. Refund before expiry is refused; clock is advanced to T; payer refunds
     the 40 undrawn increments back into its wallet.
  8. Balances and the mint supply invariant are asserted, not eyeballed.

Run:  PYTHONPATH=/home/lando/projects/aicash/impl python3 streaming_pair.py
"""

import http.client
import json
import os
import sys
import tempfile

# Fallback so the script also runs without PYTHONPATH when kept in
# <repo>/examples/j4-streaming/.
_REPO_IMPL = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", "impl"
)
try:
    import aicash  # noqa: F401
except ImportError:
    sys.path.insert(0, os.path.abspath(_REPO_IMPL))

from aicash.burncalc import BurnPolicy
from aicash.channels import ChannelError, ChannelPayee, ChannelPayer
from aicash.clock import FakeClock
from aicash.ledgerstore import Ledger
from aicash.mintapi import MintConfig, MintServer
from aicash.signing import generate_keypair
from aicash.tokencodec import format_token, ledger_key
from aicash.wallet import MintClient, Wallet

MINT_ID = "mint-j4"
N = 100          # channel increments
UNIT_MC = 1      # 1 millicent per generated token
DRAWS = 60       # tokens actually generated/streamed
FUND_MC = 200    # operator funding for the payer


def admin_issue(port: int, outputs: list) -> dict:
    """POST /admin/issue (no MintClient method exists for it, so hand-rolled)."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        conn.request(
            "POST",
            "/admin/issue",
            json.dumps({"outputs": outputs}).encode(),
            {"Content-Type": "application/json"},
        )
        resp = conn.getresponse()
        body = json.loads(resp.read())
        assert resp.status == 200 and body.get("status") == "ok", body
        return body
    finally:
        conn.close()


def main() -> None:
    tmp = tempfile.mkdtemp(prefix="aicash-j4-")
    clock = FakeClock()  # mint time fully under our control (L17)
    t0 = clock()

    # --- 1. boot a real mint (HTTP on 127.0.0.1) -------------------------
    policy = BurnPolicy(rate_ppm=10_000, cap_mc=1_000, exempt_below_mc=10)
    priv, pub = generate_keypair()
    ledger = Ledger(
        db_path=os.path.join(tmp, "mint.sqlite"),
        clock=clock,
        burn_policy=policy,
        recovery_window_ms=90 * 24 * 3600 * 1000,
        max_lock_expiry_ms=30 * 24 * 3600 * 1000,
    )
    config = MintConfig(
        mint_id=MINT_ID,
        baseline_model_class="test-model-class",
        burn_policy=policy,  # NB: must repeat the ledger's policy by hand
        signing_private=priv,
        signing_public=pub,
    )
    server = MintServer(config, ledger)
    port = server.start()
    base = f"http://127.0.0.1:{port}"
    print(f"mint {MINT_ID} up at {base}, mint_time={t0}")

    # --- 2. fund the payer wallet ---------------------------------------
    payer_client = MintClient(base)
    payer_wallet = Wallet(os.path.join(tmp, "payer.sqlite"), payer_client, MINT_ID)
    fund_secret = os.urandom(32)
    admin_issue(
        port,
        [{"amount_mc": FUND_MC, "secret_hash": ledger_key(fund_secret), "lock": None}],
    )
    payer_wallet.receive(format_token(MINT_ID, FUND_MC, fund_secret))
    payer_start = payer_wallet.balance()
    print(f"payer wallet funded: {payer_start} mc (burn on receive: "
          f"{FUND_MC - payer_start} mc)")

    # --- 3. handshake + open --------------------------------------------
    # Payee generates the N output secrets; payer only ever sees hashes.
    payee_client = MintClient(base)
    payee_wallet = Wallet(os.path.join(tmp, "payee.sqlite"), payee_client, MINT_ID)
    payee_secrets = [os.urandom(32) for _ in range(N)]
    payee_hashes = [ledger_key(s) for s in payee_secrets]

    expiry = t0 + 600_000  # T = now + 10 minutes (mint clock)
    payer_ch = ChannelPayer(payer_wallet)
    info = payer_ch.open(payee_hashes, UNIT_MC, N, expiry)
    after_open = payer_wallet.balance()
    print(f"channel {info.channel_id[:8]}… opened: N={info.N}, unit={info.unit_mc} mc, "
          f"tranches={[t['count'] for t in info.tranches]}, expiry=T0+600s")
    print(f"payer wallet after open: {after_open} mc "
          f"(channel cost {payer_start - after_open} mc incl. burns)")

    # --- 4. payee verifies the funded channel (§9.1 verify) --------------
    payee_ch = ChannelPayee(payee_client, MINT_ID)
    payee_ch.accept(
        info,
        payee_secrets,
        expect_unit_mc=UNIT_MC,
        expect_n=N,
        expect_expiry_ms=expiry,
    )
    print("payee accepted the channel (batch status verified all 100 locks)")

    # --- 5./6. stream 60 draws with a mid-way settlement -----------------
    settled_total = 0
    for k in range(1, DRAWS + 1):
        clock.advance(50)                      # ~50 ms per generated token
        draw = payer_ch.draw(k)                # local, no I/O
        cumulative = payee_ch.on_draw(draw)    # local sha256 verify, no I/O
        assert cumulative == k, (cumulative, k)
        if k == 30:
            settled = payee_ch.settle()        # mid-stream settlement
            settled_total += settled
            print(f"mid-stream settle after draw 30: +{settled} mc")
    settled = payee_ch.settle()                # second settlement: draws 31..60
    settled_total += settled
    print(f"second settle after draw {DRAWS}: +{settled} mc "
          f"(total settled {settled_total} mc)")

    # Settled value into the payee's own wallet (fresh self-owned secrets).
    for tok in payee_ch.settled_tokens:
        payee_wallet.receive(tok)
    payee_balance = payee_wallet.balance()
    print(f"payee wallet balance: {payee_balance} mc")

    # --- 7. refund of the undrawn remainder ------------------------------
    try:
        payer_ch.refund()
        raise AssertionError("refund before expiry should have been refused")
    except ChannelError as exc:
        print(f"refund before expiry correctly refused: {exc}")

    clock.set(expiry)  # jump the mint clock to T (fake clock — no waiting)
    refunded = payer_ch.refund()
    print(f"refund at expiry recovered {refunded} mc "
          f"({N - DRAWS} undrawn increments, minus burn)")
    for tok in payer_ch.refund_tokens:
        payer_wallet.receive(tok)
    payer_final = payer_wallet.balance()
    print(f"payer wallet final balance: {payer_final} mc")

    # --- 8. hard assertions ----------------------------------------------
    assert settled_total == DRAWS * UNIT_MC - _burn_total(payee_ch), \
        (settled_total, DRAWS)
    assert payee_balance == settled_total  # receive() burned nothing extra here
    assert refunded == (N - DRAWS) * UNIT_MC  # 40 mc, under exempt/burn floor

    # A drawn+settled output must show spent on the ledger with its witness.
    _mt, results = payee_client.status([payee_hashes[0]])
    assert results[0]["state"] == "spent", results[0]
    assert results[0].get("claim_witness"), "settled via claim path"

    # An undrawn output must be spent too — by the REFUND path (no witness
    # from the payee side ever existed for it).
    _mt, results = payer_client.status([payee_hashes[N - 1]])
    assert results[0]["state"] == "spent", results[0]

    # Mint supply invariant.
    desc = payer_client.descriptor()
    supply = desc["supply"]
    assert supply["outstanding_mc"] == (
        supply["cumulative_issued_mc"] - supply["cumulative_burned_mc"]
    ), supply
    # Everything outstanding is now held by the two wallets.
    assert supply["outstanding_mc"] == payer_final + payee_balance, (
        supply["outstanding_mc"], payer_final, payee_balance)

    print("\nRECONCILIATION")
    print(f"  issued            {supply['cumulative_issued_mc']:>6} mc")
    print(f"  burned            {supply['cumulative_burned_mc']:>6} mc")
    print(f"  outstanding       {supply['outstanding_mc']:>6} mc")
    print(f"  payer wallet      {payer_final:>6} mc")
    print(f"  payee wallet      {payee_balance:>6} mc")
    print("\nOK: streamed 60 per-token payments, settled twice mid-flight, "
          "refunded the 40 undrawn increments at expiry.")

    server.stop()


def _burn_total(payee_ch: ChannelPayee) -> int:
    # Both settlements were 30 mc gross: 30*10_000//1_000_000 == 0 burn each
    # under the configured policy, so settled == drawn here. Kept as a
    # function to make the assertion above honest about what it claims.
    return 0


if __name__ == "__main__":
    main()
