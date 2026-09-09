"""J1 — cold-start worker (§7.2 receive-first).

Stand up a mint, have a funded treasury pay us ONE bearer token, receive it into
a fresh ZERO-capital wallet built with no registration, verify balance, spend
part of it, and demonstrate catching PaymentInvalid on an already-spent token.

Built only from README + components/C07-wallet.md Public API. No impl source read.
Run: PYTHONPATH=impl python3 first_token.py
"""
import os
import tempfile

from aicash import (
    BurnPolicy, MintConfig, make_mint, generate_keypair, system_clock,
    Wallet, MintClient, new_secret, ledger_key, format_token,
    PaymentInvalid,
)


def main():
    workdir = tempfile.mkdtemp(prefix="j1r3-")
    db = os.path.join(workdir, "mint.db")

    # --- Boot a mint (README quickstart pattern) ---
    priv, pub = generate_keypair()
    config = MintConfig(
        mint_id="j1-mint",
        baseline_model_class="demo-model-v1",
        burn_policy=BurnPolicy(rate_ppm=1000, cap_mc=1000, exempt_below_mc=10),
        signing_private=priv,
        signing_public=pub,
        admin_token="operator-secret",
    )
    server, ledger = make_mint(config, db_path=db, clock=system_clock)
    port = server.start()
    base_url = f"http://127.0.0.1:{port}"
    print(f"[mint] up at {base_url}")

    try:
        # --- Operator funds a treasury (§7.1) ---
        client = MintClient(base_url)
        s = new_secret()
        client.admin_issue(
            [{"amount_mc": 10_000, "secret_hash": ledger_key(s)}],
            admin_token="operator-secret",
        )
        treasury_token = format_token("j1-mint", 10_000, s)

        treasury = Wallet(os.path.join(workdir, "treasury.db"), client, "j1-mint")
        funded = treasury.receive(treasury_token)
        print(f"[treasury] funded, received {funded} mc; balance={treasury.balance()} mc")

        # --- Fresh, zero-capital worker: no registration, URL only (§7.2) ---
        worker = Wallet.connect(os.path.join(workdir, "worker.db"), base_url)
        assert worker.balance() == 0, "fresh wallet must start empty"
        print(f"[worker] connected zero-config, balance={worker.balance()} mc")

        # --- Treasury pays the worker ONE bearer token ---
        tokens = treasury.pay(1_000)
        print(f"[treasury] pay(1000) -> {len(tokens)} bearer token(s)")
        # Receive-first: worker takes the payment with no prior relationship.
        credited = 0
        for tok in tokens:
            credited += worker.receive(tok)
        # receive() re-exchanges into fresh secrets, so a re-exchange burn of
        # 0.1% (1 mc on 1000) applies: worker holds 999, not 1000.
        print(f"[worker] received {credited} mc; balance={worker.balance()} mc")
        assert worker.balance() == credited == 999, worker.balance()

        # --- Worker spends part of its holdings ---
        bal_before = worker.balance()
        q = worker.quote(250)
        print(f"[worker] quote(250) -> {q}")
        spend = worker.pay(250)
        print(f"[worker] spent 250 mc -> {len(spend)} token(s); balance={worker.balance()} mc")
        # pay debits 250 (face) + burn on the selected input sum.
        assert worker.balance() == bal_before - 250 - q["burn_mc"], worker.balance()
        # Verify the spend is real value by having the treasury receive it back.
        back = 0
        for tok in spend:
            back += treasury.receive(tok)
        print(f"[treasury] received worker's spend of {back} mc")
        assert back > 0

        # --- Error handling: an already-spent token ---
        # tokens[0] was consumed by worker.receive above (re-exchanged), so it is
        # now spent. Trying to receive it again must raise PaymentInvalid(spent).
        try:
            Wallet.connect(os.path.join(workdir, "thief.db"), base_url).receive(tokens[0])
            raise SystemExit("FAIL: re-receiving a spent token should have raised")
        except PaymentInvalid as e:
            print(f"[worker] caught PaymentInvalid on spent token; reasons={e.reasons}")
            assert "spent" in e.reasons, f"expected 'spent', got {e.reasons}"

        # --- Final reconciliation ---
        print(f"[final] worker balance={worker.balance()} mc, treasury balance={treasury.balance()} mc")
        assert worker.balance() == 999 - 250 - q["burn_mc"], worker.balance()
        print("J1 receive-first journey OK")

    finally:
        server.stop()


if __name__ == "__main__":
    main()
