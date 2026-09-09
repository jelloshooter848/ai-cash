"""J1 — cold-start worker, receive-first (§7.2).

Demonstrates the "solvent from job one" promise: a brand-new worker agent
with ZERO capital and NO registration anywhere gets paid a single bearer
token by a funded requester, sees its balance appear out of nothing,
verifies it, and immediately spends part of it onward to a third party --
again with no account and no relationship.

Written cold from README + components/C06,C07 Public API blocks only.

Run:  PYTHONPATH=impl python3 first_token.py
"""
import os
import tempfile

from aicash import (
    BurnPolicy, MintConfig, make_mint, generate_keypair, system_clock,
    Wallet, MintClient, new_secret, ledger_key, format_token,
)

MINT_ID = "acme-mint"
WORK_DIR = tempfile.mkdtemp(prefix="aicash-j1-")


def main():
    # --- Stand up a mint -----------------------------------------------------
    priv, pub = generate_keypair()
    config = MintConfig(
        mint_id=MINT_ID,
        baseline_model_class="acme-model-v1",
        burn_policy=BurnPolicy(rate_ppm=1000, cap_mc=1000, exempt_below_mc=10),
        signing_private=priv, signing_public=pub,
        admin_token="op-secret",
    )
    server, ledger = make_mint(
        config, db_path=os.path.join(WORK_DIR, "mint.db"), clock=system_clock,
    )
    port = server.start()
    base = f"http://127.0.0.1:{port}"

    try:
        client = MintClient(base)

        # --- A funded requester (the party that will pay us) -----------------
        # Operator funding path (§7.1): mint one output the requester controls,
        # hand it to the requester's wallet as a bearer token.
        s = new_secret()
        client.admin_issue(
            [{"amount_mc": 5_000, "secret_hash": ledger_key(s)}],
            admin_token="op-secret",
        )
        requester = Wallet(os.path.join(WORK_DIR, "requester.db"), client, MINT_ID)
        funded = requester.receive(format_token(MINT_ID, 5_000, s))
        print(f"requester funded with {funded} mc (balance={requester.balance()})")

        # --- The worker: fresh, zero-capital, never registered ---------------
        # Zero-config entry point: URL only, the wallet fetches the mint_id.
        worker = Wallet.connect(os.path.join(WORK_DIR, "worker.db"), base)
        assert worker.balance() == 0, "fresh wallet must start empty"
        print(f"worker cold-start balance: {worker.balance()} mc (no registration performed)")

        # --- Requester pays the worker ONE bearer token ----------------------
        # pay(1000) selects a single ladder-denomination coin -> one token str.
        tokens = requester.pay(1_000)
        print(f"requester handed over {len(tokens)} bearer token(s)")
        assert len(tokens) == 1, f"expected exactly one token, got {len(tokens)}"

        # --- Worker receives it into its fresh wallet ------------------------
        # receive() re-exchanges the incoming token for fresh self-owned coins
        # (§5.1), so a small re-exchange burn applies: 1000 mc -> 999 (0.1%).
        credited = worker.receive(tokens[0])
        print(f"worker received {credited} mc; balance now {worker.balance()} mc")
        assert worker.balance() == credited, worker.balance()
        assert credited == 999, credited  # 1000 - 1 mc re-exchange burn

        # --- Worker spends PART of it onward to a third party ----------------
        before = worker.balance()
        quote = worker.quote(300)
        print(f"worker quote to spend 300: {quote}")
        third = Wallet.connect(os.path.join(WORK_DIR, "third.db"), base)
        # third.receive re-exchanges too, so it nets 300 - its own re-exchange
        # burn; 300 > exempt_below so ~0 (floor of 0.3 = 0) -> lands at 300.
        recv = 0
        for tok in worker.pay(300):
            recv += third.receive(tok)
        print(f"third holds {third.balance()} mc | worker keeps {worker.balance()} mc")
        assert third.balance() == recv, third.balance()
        # worker keeps before - 300 - payer burn
        expected_worker = before - 300 - quote["burn_mc"]
        assert worker.balance() == expected_worker, (worker.balance(), expected_worker)

        # --- Mint supply reconciles ------------------------------------------
        sup = client.descriptor()["supply"]
        assert sup["outstanding_mc"] == (
            sup["cumulative_issued_mc"] - sup["cumulative_burned_mc"]
        )
        print(
            f"supply ok: outstanding {sup['outstanding_mc']} = "
            f"issued {sup['cumulative_issued_mc']} - burned {sup['cumulative_burned_mc']}"
        )
        print("\nOK - worker was solvent from job one, zero accounts, zero registration.")
    finally:
        server.stop()


if __name__ == "__main__":
    main()
