"""AICash quickstart — boot a mint, fund a wallet, move money, verify.

Run:  PYTHONPATH=impl python3 examples/quickstart.py

Demonstrates the whole §0 loop end to end in ~30 lines: stand up an
in-process mint, fund a treasury via the operator path (§7.1), pay a
brand-new zero-config worker wallet (§7.2 receive-first), and have the
worker spend part of it — all with no accounts and no registration.
"""
from aicash import (
    BurnPolicy, MintConfig, make_mint, generate_keypair, system_clock,
    Wallet, MintClient, new_secret, ledger_key, format_token,
)

# 1. Boot a mint. make_mint builds the Ledger FROM the config, so the
#    descriptor and the ledger can never disagree about burn/retention policy.
priv, pub = generate_keypair()
config = MintConfig(
    mint_id="demo-mint",                              # must match MINT_ID_RE: [a-z0-9-]{1,64}
    baseline_model_class="demo-model-v1",             # this mint's unit-of-account peg (§4.1)
    burn_policy=BurnPolicy(rate_ppm=1000, cap_mc=1000, exempt_below_mc=10),  # 0.1%, drip-exempt
    signing_private=priv, signing_public=pub,
    admin_token="operator-secret",                    # gates the non-normative /admin/issue path
)
server, ledger = make_mint(config, db_path="/tmp/aicash-quickstart.db", clock=system_clock)
port = server.start()
base = f"http://127.0.0.1:{port}"
try:
    client = MintClient(base)

    # 2. Operator funds a treasury (§7.1). Issue a by-secret output we control,
    #    then format it as the bearer token string the treasury will hold.
    s = new_secret()
    client.admin_issue(
        [{"amount_mc": 10_000, "secret_hash": ledger_key(s)}],
        admin_token="operator-secret",
    )
    treasury_token = format_token("demo-mint", 10_000, s)

    import tempfile, os
    d = tempfile.mkdtemp()
    treasury = Wallet(os.path.join(d, "treasury.db"), client, "demo-mint")
    print("treasury receives:", treasury.receive(treasury_token), "mc")   # -> 10000

    # 3. Pay a brand-new worker that has never registered with anyone (§7.2).
    worker = Wallet.connect(os.path.join(d, "worker.db"), base)  # zero-config: fetches mint_id itself
    print("worker starts at:", worker.balance(), "mc")           # -> 0
    for tok in treasury.pay(1_000):
        worker.receive(tok)
    print("worker now holds:", worker.balance(), "mc")           # -> 1000 (bearer, unlinkable, final)

    # 4. Worker spends part of it to a third party — again, no relationship needed.
    third = Wallet.connect(os.path.join(d, "third.db"), base)
    for tok in worker.pay(300):
        third.receive(tok)
    print("third holds:", third.balance(), "| worker keeps:", worker.balance())

    # 5. The mint's signed supply snapshot reconciles: outstanding == issued - burned.
    desc = client.descriptor()
    sup = desc["supply"]
    assert sup["outstanding_mc"] == sup["cumulative_issued_mc"] - sup["cumulative_burned_mc"]
    print("supply ok: outstanding", sup["outstanding_mc"],
          "= issued", sup["cumulative_issued_mc"], "- burned", sup["cumulative_burned_mc"])
    print("\nOK — money moved with zero accounts, zero registration.")
finally:
    server.stop()
