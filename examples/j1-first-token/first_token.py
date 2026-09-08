"""JOURNEY 1 — cold-start worker (receive-first onboarding, spec §7.2).

Produced during a cold usability test of the AICash v0.4 reference
implementation: an agent that had never seen this repo stood up an
in-process mint, had an operator-funded payer hand a freelance "worker"
agent one bearer token out-of-band, received it into a fresh zero-balance
wallet (no registration, no auth), verified the balance, then spent part
of it paying a third party.

Demonstrates, end to end over real HTTP against a real sqlite ledger:
  1. Standing up a mint: MintConfig + Ledger + MintServer (C06).
  2. §7.1 operator funding via the non-normative POST /admin/issue path.
  3. §7.2 receive-first onboarding: a wallet created with zero capital
     becomes solvent by Wallet.receive(token) — no registration exists.
  4. Spending: Wallet.pay() -> bearer token strings -> payee receive().
  5. Reconciliation: wallet balances + the signed §3.6 supply snapshot
     (outstanding == issued - burned) account for every millicredit.

Run with:  PYTHONPATH=/home/lando/projects/aicash/impl python3 first_token.py
"""

import http.client
import json
import sys
import tempfile
from pathlib import Path

# Allow running without PYTHONPATH set, too.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "impl"))

from aicash.burncalc import BurnPolicy
from aicash.clock import system_clock
from aicash.ledgerstore import Ledger
from aicash.mintapi import MintConfig, MintServer
from aicash.tokencodec import format_token, ledger_key, new_secret
from aicash.signing import generate_keypair
from aicash.wallet import MintClient, Wallet


def admin_issue(port: int, outputs: list[dict]) -> dict:
    """Call the non-normative /admin/issue endpoint (MintClient has no
    method for it — operator funding is outside Layer 0)."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        conn.request(
            "POST",
            "/admin/issue",
            json.dumps({"outputs": outputs}).encode(),
            {"Content-Type": "application/json"},
        )
        resp = conn.getresponse()
        body = json.loads(resp.read().decode())
        assert resp.status == 200 and body.get("status") == "ok", body
        return body
    finally:
        conn.close()


def main() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="aicash-j1-"))

    # ---- 1. Stand up a real in-process mint --------------------------------
    private, public = generate_keypair()
    policy = BurnPolicy(rate_ppm=1000, cap_mc=100, exempt_below_mc=10)  # 0.1%
    config = MintConfig(
        # NB: token codec requires mint_id to match [a-z0-9-]{1,64}; MintConfig
        # itself does NOT validate this ("mintA" was accepted, then every
        # format_token call failed).
        mint_id="mint-a",
        baseline_model_class="test-2026",
        burn_policy=policy,
        signing_private=private,
        signing_public=public,
    )
    # NOTE: policy / windows must be passed AGAIN to the Ledger and kept
    # consistent with MintConfig by hand — nothing derives one from the other.
    ledger = Ledger(
        db_path=str(tmp / "mint.sqlite"),
        clock=system_clock,
        burn_policy=policy,
        recovery_window_ms=config.recovery_window_ms,
        max_lock_expiry_ms=config.max_lock_expiry_ms,
    )
    server = MintServer(config, ledger)
    port = server.start()
    base_url = f"http://127.0.0.1:{port}"
    print(f"mint '{config.mint_id}' listening on {base_url}")

    try:
        client = MintClient(base_url)
        mint_id = client.descriptor()["mint_id"]

        # ---- 2. Operator funds the payer (§7.1) ----------------------------
        # The operator mints 10,000 mc to a secret it generated, then hands
        # the payer the resulting bearer token string.
        funding_secret = new_secret()
        funding_amount = 10_000
        admin_issue(
            port,
            [{"amount_mc": funding_amount, "secret_hash": ledger_key(funding_secret)}],
        )
        funding_token = format_token(mint_id, funding_amount, funding_secret)

        payer = Wallet(str(tmp / "payer.sqlite"), MintClient(base_url), mint_id)
        payer_net = payer.receive(funding_token)
        print(f"payer funded: received {payer_net} mc "
              f"(burn {funding_amount - payer_net} mc), balance {payer.balance()}")

        # ---- 3. §7.2 receive-first: the cold-start worker ------------------
        worker = Wallet(str(tmp / "worker.sqlite"), MintClient(base_url), mint_id)
        assert worker.balance() == 0, "worker must start with zero capital"

        # Payer pays the worker ONE bearer token, out-of-band (here: a
        # Python variable standing in for a tool-call response / message).
        payment_tokens = payer.pay(1_000)
        assert len(payment_tokens) == 1, payment_tokens
        wire_token = payment_tokens[0]
        print(f"payer handed worker 1 bearer token: {wire_token[:32]}...")

        # Worker receives it — no registration, no auth, immediately
        # re-exchanged for fresh secrets (§5.1).
        worker_net = worker.receive(wire_token)
        worker_balance = worker.balance()
        print(f"worker received {worker_net} mc; balance now {worker_balance} mc")
        assert worker_balance == worker_net > 0

        # The received string is now dead on the ledger (double-spend safe).
        _, results = client.status([ledger_key_from_token(wire_token)])
        assert results[0]["state"] == "spent", results
        print("received token verified spent on the ledger (re-exchange worked)")

        # ---- 4. Worker spends part of it, paying a third party -------------
        third = Wallet(str(tmp / "third.sqlite"), MintClient(base_url), mint_id)
        pay_amount = 300
        outgoing = worker.pay(pay_amount)
        third_net = sum(third.receive(t) for t in outgoing)
        print(f"worker paid {pay_amount} mc -> third party credited {third_net} mc "
              f"({len(outgoing)} token(s))")
        assert third.balance() == third_net

        # ---- 5. Reconcile everything to the millicredit --------------------
        d = client.descriptor()
        supply = d["supply"]
        held = payer.balance() + worker.balance() + third.balance()
        print(f"balances: payer={payer.balance()} worker={worker.balance()} "
              f"third={third.balance()}  held total={held}")
        print(f"mint supply: issued={supply['cumulative_issued_mc']} "
              f"burned={supply['cumulative_burned_mc']} "
              f"outstanding={supply['outstanding_mc']}")
        assert supply["outstanding_mc"] == (
            supply["cumulative_issued_mc"] - supply["cumulative_burned_mc"]
        )
        assert held == supply["outstanding_mc"], (
            "every outstanding millicredit must sit in exactly one wallet"
        )
        print("RECONCILED: wallets hold exactly the mint's outstanding supply.")
        print("JOURNEY 1 SUCCESS: cold-start worker was solvent from job one, "
              "no registration.")
    finally:
        server.stop()


def ledger_key_from_token(token_str: str) -> str:
    from aicash.tokencodec import parse_token
    return ledger_key(parse_token(token_str).secret)


if __name__ == "__main__":
    main()
