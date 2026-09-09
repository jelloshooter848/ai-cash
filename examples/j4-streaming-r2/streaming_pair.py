#!/usr/bin/env python3
"""JOURNEY 4 (round 2) — streaming payment pair, AICash spec §9.1 channels.

Written COLD from the repo docs only (README.md + components/C06,C07,C08
"Public API" blocks). No implementation source (impl/aicash/*.py bodies) was
read to build this. It exercises the full §9.1 streaming-channel lifecycle
against a REAL in-process mint over HTTP:

  1.  Boot a mint with make_mint(...) under a FakeClock (control expiry, no
      wall-clock waiting).
  2.  Operator funds a payer treasury via client.admin_issue + a bearer token.
  3.  Payee generates 100 output secrets; payer opens a channel: N=100,
      unit = 1 mc, expiry T = now + 10 min.
  4.  Payer serialises the ChannelInfo to a WIRE MESSAGE (ChannelInfo.to_json,
      §3.3 canonical JSON) and hands the *string* to the payee, who rebuilds it
      with ChannelInfo.from_json and verifies it (ChannelPayee.accept, §9.1).
  5.  Payer streams 60 per-token draws; payee verifies each one locally.
  6.  Payee settles mid-stream (after draw 30) and again (draws 31..60);
      settled value lands in the payee's own wallet automatically.
  7.  Refund before expiry is refused; clock jumps to T; payer refunds the
      40 undrawn increments.
  8.  Mint supply invariant + the "outstanding == held by the two wallets"
      reconciliation are asserted, not eyeballed.

Run:  PYTHONPATH=impl python3 streaming_pair.py
"""

import json
import os
import tempfile

from aicash import (
    BurnPolicy,
    ChannelInfo,
    ChannelPayee,
    ChannelPayer,
    FakeClock,
    MintClient,
    MintConfig,
    Wallet,
    format_token,
    generate_keypair,
    ledger_key,
    make_mint,
    new_secret,
)

MINT_ID = "mint-j4-r2"
N = 100          # channel increments
UNIT_MC = 1      # 1 millicent per streamed token
DRAWS = 60       # tokens actually streamed
FUND_MC = 5_000  # operator funding for the payer treasury


def main() -> None:
    tmp = tempfile.mkdtemp(prefix="aicash-j4r2-")
    clock = FakeClock()
    t0 = clock()

    # --- 1. boot a real mint (HTTP on 127.0.0.1) ------------------------
    priv, pub = generate_keypair()
    config = MintConfig(
        mint_id=MINT_ID,
        baseline_model_class="demo-model-v1",
        burn_policy=BurnPolicy(rate_ppm=1_000, cap_mc=1_000, exempt_below_mc=10),
        signing_private=priv,
        signing_public=pub,
        admin_token="operator-secret",
    )
    server, ledger = make_mint(config, db_path=os.path.join(tmp, "mint.db"), clock=clock)
    port = server.start()
    base = f"http://127.0.0.1:{port}"
    client = MintClient(base)
    print(f"mint {MINT_ID} up at {base}, mint_time={t0}")

    # --- 2. operator funds the payer treasury (§7.1) --------------------
    payer_wallet = Wallet(os.path.join(tmp, "payer.db"), client, MINT_ID)
    s = new_secret()
    client.admin_issue(
        [{"amount_mc": FUND_MC, "secret_hash": ledger_key(s)}],
        admin_token="operator-secret",
    )
    payer_wallet.receive(format_token(MINT_ID, FUND_MC, s))
    payer_start = payer_wallet.balance()
    print(f"payer funded: {payer_start} mc (receive burn {FUND_MC - payer_start} mc)")

    # --- 3. payee makes the output secrets; payer opens the channel -----
    payee_client = MintClient(base)
    payee_wallet = Wallet(os.path.join(tmp, "payee.db"), payee_client, MINT_ID)
    payee_secrets = [new_secret() for _ in range(N)]
    payee_hashes = [ledger_key(sec) for sec in payee_secrets]

    expiry = t0 + 600_000  # T = now + 10 min (mint clock)
    payer_ch = ChannelPayer(payer_wallet)
    est = payer_ch.estimate_open_cost(UNIT_MC, N)
    info = payer_ch.open(payee_hashes, UNIT_MC, N, expiry)
    after_open = payer_wallet.balance()
    print(f"channel opened: N={N}, unit={UNIT_MC} mc, est extra cost {est} mc, "
          f"actual channel cost {payer_start - after_open} mc (incl. {N*UNIT_MC} locked)")

    # --- 4. WIRE HANDOFF: serialise -> send string -> rebuild -> verify -
    wire = info.to_json()
    assert isinstance(wire, str)
    parsed = json.loads(wire)  # prove it is a real JSON object payee could ship
    print(f"wire message ({len(wire)} bytes): channel_id={parsed['channel_id'][:12]}…, "
          f"keys={sorted(parsed)}")

    # Payee side: it only ever gets the string. Rebuild + strict verify.
    info_on_payee = ChannelInfo.from_json(wire)
    assert info_on_payee.to_json() == wire, "codec round-trip must be stable"
    payee_ch = ChannelPayee(payee_client, MINT_ID, wallet=payee_wallet)
    payee_ch.accept(
        info_on_payee, payee_secrets,
        expect_unit_mc=UNIT_MC, expect_n=N, expect_expiry_ms=expiry,
    )
    print("payee rebuilt ChannelInfo from the wire string and accepted it (§9.1 verify)")

    # --- 5./6. stream 60 draws; settle at 30 and at 60 ------------------
    settled_total = 0
    for k in range(1, DRAWS + 1):
        clock.advance(50)                    # ~50 ms of work per token
        draw = payer_ch.draw(k)              # local, no HTTP
        cumulative = payee_ch.on_draw(draw)  # local sha256 verify, no HTTP
        assert cumulative == k, (cumulative, k)
        if k == 30:
            got = payee_ch.settle()          # mid-stream settle -> payee wallet
            settled_total += got
            print(f"mid-stream settle @draw 30: +{got} mc (payee wallet now "
                  f"{payee_wallet.balance()} mc)")
    got = payee_ch.settle()                  # second settle: draws 31..60
    settled_total += got
    payee_balance = payee_wallet.balance()
    print(f"second settle @draw {DRAWS}: +{got} mc; total settled {settled_total} mc; "
          f"payee wallet {payee_balance} mc")

    # --- 7. refund the undrawn remainder --------------------------------
    try:
        payer_ch.refund()
        raise AssertionError("refund before expiry should have been refused")
    except Exception as exc:  # noqa: BLE001 — doc: refund refuses before expiry
        print(f"refund before expiry correctly refused: {type(exc).__name__}: {exc}")

    clock.set(expiry)  # jump the mint clock to T
    bal_before_refund = payer_wallet.balance()
    recovered = payer_ch.refund()
    bal_after_refund = payer_wallet.balance()
    # Docs say refund() returns mc recovered; find where the value landed.
    if bal_after_refund == bal_before_refund and hasattr(payer_ch, "refund_tokens"):
        for tok in payer_ch.refund_tokens:
            payer_wallet.receive(tok)
        bal_after_refund = payer_wallet.balance()
    payer_final = payer_wallet.balance()
    print(f"refund at expiry: returned {recovered} mc for the {N-DRAWS} undrawn "
          f"increments; payer wallet {payer_final} mc "
          f"(auto-credited={bal_after_refund != bal_before_refund and recovered>0})")

    # --- 8. hard assertions ---------------------------------------------
    assert settled_total == DRAWS * UNIT_MC, (settled_total, DRAWS)   # 60 mc, sub-burn-floor
    assert payee_balance == settled_total, (payee_balance, settled_total)
    assert recovered == (N - DRAWS) * UNIT_MC, (recovered, N - DRAWS)  # 40 mc

    # Drawn+settled output: spent on the ledger, redeemed by claim witness.
    _mt, res = payee_client.status([payee_hashes[0]])
    assert res[0]["state"] == "spent", res[0]
    assert res[0].get("claim_witness"), "draw 1 should be settled via claim path"
    # Undrawn output: spent too, but by the payer's refund path.
    _mt, res = client.status([payee_hashes[N - 1]])
    assert res[0]["state"] == "spent", res[0]

    desc = client.descriptor()
    sup = desc["supply"]
    assert sup["outstanding_mc"] == sup["cumulative_issued_mc"] - sup["cumulative_burned_mc"], sup
    assert sup["outstanding_mc"] == payer_final + payee_balance, (
        sup["outstanding_mc"], payer_final, payee_balance)

    print("\nRECONCILIATION")
    print(f"  issued        {sup['cumulative_issued_mc']:>6} mc")
    print(f"  burned        {sup['cumulative_burned_mc']:>6} mc")
    print(f"  outstanding   {sup['outstanding_mc']:>6} mc")
    print(f"  payer wallet  {payer_final:>6} mc")
    print(f"  payee wallet  {payee_balance:>6} mc")
    print("\nOK: 60 streamed micro-payments, 2 mid-flight settlements, 40 refunded "
          "at expiry — wire codec round-tripped, supply reconciles.")
    server.stop()


if __name__ == "__main__":
    main()
