"""Journey 3 (r3): metered API seller (ORACLE).

Cold-start test, docs-only:
  Part A - priced endpoint over the §9.5 envelope: 3 clients (incl. a
           double-spender) each POST a request wrapped by build_envelope;
           the seller parse_envelope -> verifies -> serves -> collects tokens,
           then batch-redeems N tokens in ONE receive_batch call.
  Part B - upgrade one client to a §9.1 channel and drive the channel draw
           THROUGH the envelope: parse_envelope -> Envelope.channel_draw ->
           ChannelPayee.on_draw (the path that was reported broken).

Run: PYTHONPATH=impl python3 examples/j3-metered-api-r3/metered_api.py
"""
import time

from aicash import (
    BurnPolicy, MintConfig, make_mint, generate_keypair, system_clock,
    Wallet, MintClient, new_secret, ledger_key, format_token,
    build_envelope, parse_envelope,
    ChannelPayer, ChannelPayee, ChannelInfo,
)

PRICE_MC = 100


def boot_mint(tmp):
    priv, pub = generate_keypair()
    config = MintConfig(
        mint_id="oracle-mint",
        baseline_model_class="oracle-model-v1",
        burn_policy=BurnPolicy(rate_ppm=1000, cap_mc=1000, exempt_below_mc=10),
        signing_private=priv, signing_public=pub,
        admin_token="operator-secret",
    )
    server, ledger = make_mint(config, db_path=f"{tmp}/oracle.db", clock=system_clock)
    port = server.start()
    base = f"http://127.0.0.1:{port}"
    return server, ledger, base, MintClient(base)


def fund_wallet(client, base, tmp, name, amount_mc):
    """Operator issues a treasury output, formats a bearer token, wallet receives it."""
    s = new_secret()
    client.admin_issue(
        [{"amount_mc": amount_mc, "secret_hash": ledger_key(s)}],
        admin_token="operator-secret",
    )
    token = format_token("oracle-mint", amount_mc, s)
    w = Wallet.connect(f"{tmp}/{name}.db", base)
    w.receive(token)
    return w


def main():
    tmp = "/tmp/claude-1000/-home-lando-projects-aicash/6984a879-ec56-42b8-89dd-68fa632aa7f3/scratchpad/j3r3"
    import os
    os.makedirs(tmp, exist_ok=True)

    server, ledger, base, client = boot_mint(tmp)
    try:
        MINT_ID = client.descriptor()["mint_id"]
        print(f"[boot] mint_id={MINT_ID}")

        # ---- The metered API seller's own receiving wallet ----
        seller = Wallet.connect(f"{tmp}/seller.db", base)

        # ---- Fund three client wallets ----
        wA = fund_wallet(client, base, tmp, "clientA", 500)
        wB = fund_wallet(client, base, tmp, "clientB", 500)
        wC = fund_wallet(client, base, tmp, "clientC", 500)  # the double-spender
        print(f"[fund] A={wA.balance()} B={wB.balance()} C={wC.balance()}")

        # =========================================================
        # PART A — priced endpoint over the §9.5 envelope
        # =========================================================
        # Each client builds a request envelope: the natural-language request
        # payload + tokens paying the PRICE_MC toll.
        def client_request(wallet, question):
            toll_tokens = wallet.pay(PRICE_MC)          # tokens summing to PRICE_MC
            req = {"endpoint": "/oracle/answer", "question": question}
            return build_envelope(req, MINT_ID, toll_tokens)

        envA = client_request(wA, "What is the capital of France?")
        envB = client_request(wB, "Define entropy.")
        envC = client_request(wC, "Is 91 prime?")

        # The double-spender: re-submit the *same* toll tokens in a second
        # request (replay of the exact bearer strings from envC).
        envC_replay = {**{k: v for k, v in envC.items() if k != "aicash"},
                       "aicash": dict(envC["aicash"])}
        # envC_replay carries the identical tokens as envC (double-spend).

        # ---- Seller side: verify -> serve -> collect ----
        collected = []           # token STRINGS to batch-redeem
        served = []

        def serve(env):
            e = parse_envelope(env)                      # strict §9.5 parse
            assert e.mint_id == MINT_ID, "foreign mint"
            paid = sum(t.amount_mc for t in e.tokens)
            assert paid >= PRICE_MC, f"underpaid: {paid} < {PRICE_MC}"
            # verify each token belongs to our mint (parse already checked),
            # reconstruct the bearer string for later batch redemption.
            for t in e.tokens:
                assert t.mint_id == MINT_ID
                collected.append(format_token(t.mint_id, t.amount_mc, t.secret))
            answer = f"answer to: {e.request['question']}"
            served.append(answer)
            return answer

        for env in (envA, envB, envC, envC_replay):
            serve(env)
        print(f"[serve] served {len(served)} requests; "
              f"collected {len(collected)} token strings (incl. replayed dup)")

        # ---- Batch-redeem: N tokens, ONE call, ONE burn (§9.2) ----
        seller_before = seller.balance()
        result = seller.receive_batch(collected)
        seller_after = seller.balance()
        credited = result["credited_mc"]
        dead = result["dead"]
        print(f"[batch] receive_batch({len(collected)} tokens) -> "
              f"credited_mc={credited} dead={dead}")
        print(f"[batch] seller balance {seller_before} -> {seller_after}")

        assert len(dead) >= 1, "double-spend should be enumerated dead"
        assert seller_after - seller_before == credited
        # 3 unique honest payments of 100 each = 300 gross, minus one batch burn;
        # the 4th (replay) is dead.
        assert credited > 0
        print("[PART A OK] double-spend caught, N tokens redeemed in ONE call\n")

        # =========================================================
        # PART B — upgrade client A to a §9.1 channel, draw THROUGH the envelope
        # =========================================================
        N = 8
        UNIT_MC = 10
        now_ms = int(time.time() * 1000)
        expiry_ms = now_ms + 3_600_000        # 1h out — clears min_lifetime_ms

        # Payee (the seller) generates its own output secrets; hands hashes to payer.
        payee_secrets = [new_secret() for _ in range(N)]
        payee_hashes = [ledger_key(s) for s in payee_secrets]

        payer = ChannelPayer(wA)              # funds from client A's wallet
        info = payer.open(payee_hashes, UNIT_MC, N, expiry_ms)   # -> ChannelInfo
        print(f"[chan] opened channel_id={info.channel_id} N={info.N} "
              f"unit_mc={info.unit_mc}")

        payee = ChannelPayee(client, MINT_ID, wallet=seller)
        payee.accept(info, payee_secrets,
                     expect_unit_mc=UNIT_MC, expect_n=N, expect_expiry_ms=expiry_ms)
        print("[chan] payee.accept OK (verified §9.1)")

        # Drive draws THROUGH the §9.5 envelope: draw -> build_envelope -> POST ->
        # parse_envelope -> Envelope.channel_draw -> on_draw. This is the exact
        # path that was reported broken.
        last_cumulative = 0
        for k in (1, 2, 3, 5):                # includes a subsumption gap (skips 4)
            draw = payer.draw(k)              # {channel_id, k, x_k}
            req = {"endpoint": "/oracle/stream", "chunk": k}
            env = build_envelope(req, MINT_ID, [], channel_draw=draw)

            # ---- seller side ----
            e = parse_envelope(env)
            assert e.channel_draw is not None, "envelope lost the channel_draw"
            cd = e.channel_draw
            assert cd.channel_id == info.channel_id
            cumulative = payee.on_draw(cd)    # <-- parse_envelope THEN on_draw
            print(f"[draw] k={k} -> on_draw cumulative={cumulative}")
            assert cumulative >= last_cumulative
            last_cumulative = cumulative

        assert last_cumulative == 5, f"expected cumulative 5, got {last_cumulative}"
        print("[chan] channel draw through envelope works")

        # Settle the verified draws => real money moves into the seller wallet.
        seller_pre = seller.balance()
        credited_chan = payee.settle()
        seller_post = seller.balance()
        print(f"[chan] settle() net credited={credited_chan}; "
              f"seller {seller_pre} -> {seller_post}")
        assert seller_post > seller_pre, "channel settlement moved no money"
        print("[PART B OK] parse_envelope -> on_draw -> settle, money moved\n")

        # ---- Final ledger reconciliation ----
        print(f"[final] seller balance = {seller.balance()} mc")
        print("ALL ASSERTIONS PASSED")
    finally:
        server.stop()


if __name__ == "__main__":
    main()
