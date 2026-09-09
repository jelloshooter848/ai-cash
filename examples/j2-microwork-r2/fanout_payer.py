"""JOURNEY 2 (round 2) - micro-work fan-out (HYDRA pays a swarm of workers).

Cold usability test of the AICash v0.4 reference implementation, written by an
AI agent using ONLY the repo docs (README, spec, component "Public API" blocks)
and the package-root public API (`from aicash import ...`).

What this script demonstrates end to end against a real in-process C06 mint:

  1. Boot a mint with `make_mint` (single source of truth) and fund a treasury
     via the non-normative operator path `MintClient.admin_issue`.
  2. Budget before spending: `Wallet.quote(total)` returns {burn_mc, change_mc,
     inputs_mc} so HYDRA checks it can afford the whole payroll first.
  3. EFFICIENT fan-out: pay 20 distinct workers 1-500 mc each in ONE call
     (`Wallet.pay_many`) -> ONE /v3/exchange, ONE burn (asserted via the
     documented `MintClient._transport` seam).
  4. Spent-token handback: a worker returns a token it already redeemed; the
     treasury's `receive()` rejects it as `spent` (PaymentInvalid) - no funds
     move, the error is handled gracefully.
  5. Timeout + idempotent retry: a pay whose response is dropped after the mint
     already processed it is retried by the wallet under the SAME idempotency
     key, so exactly one exchange takes effect (no double-spend, no lost funds).
  6. Verify all 20 workers can spend what they received (each pays 1 mc to a
     sink) and reconcile balances.

Run:  PYTHONPATH=impl python3 fanout_payer.py
"""

import os
import random
import sys
import tempfile

from aicash import (
    BurnPolicy, MintConfig, make_mint, generate_keypair, system_clock,
    Wallet, MintClient, new_secret, ledger_key, format_token,
)
# PaymentInvalid is the documented raise of Wallet.receive() on a spent/unknown
# token (C07 requirement 4) but is NOT re-exported from the package root, so it
# must be imported from its component module.  See friction notes in the report.
from aicash.wallet import PaymentInvalid

MINT_ID = "hydra-mint"
N_WORKERS = 20


class FlakyMintClient(MintClient):
    """A MintClient with a fault-injection seam (C07 requirement 10:
    `_transport` is THE single chokepoint every request funnels through).

    - counts real /v3/exchange sends so we can prove pay_many is one call;
    - can drop exactly one exchange response AFTER the mint has processed it,
      which is what a network timeout looks like to the payer.
    """

    def __init__(self, base_url: str):
        super().__init__(base_url)
        self.exchange_sends = 0
        self.drop_next_exchange = False
        self.dropped = 0

    def _transport(self, method, path, body, extra_headers=None):
        status, raw = super()._transport(method, path, body, extra_headers)
        if path == "/v3/exchange":
            self.exchange_sends += 1
            if self.drop_next_exchange:
                self.drop_next_exchange = False
                self.dropped += 1
                # Mint HAS committed the exchange; payer never hears the answer.
                return 503, b'{"status": "unavailable"}'
        return status, raw


def main() -> int:
    rng = random.Random(2026)
    workdir = tempfile.mkdtemp(prefix="aicash-j2r2-")
    print(f"[setup] state dir: {workdir}")

    # ---- 1. Boot a mint (make_mint = config is the single source of truth) --
    priv, pub = generate_keypair()
    config = MintConfig(
        mint_id=MINT_ID,
        baseline_model_class="micro-work-v1",
        burn_policy=BurnPolicy(rate_ppm=1000, cap_mc=1000, exempt_below_mc=10),
        signing_private=priv,
        signing_public=pub,
        admin_token="operator-secret",
    )
    server, ledger = make_mint(
        config, db_path=os.path.join(workdir, "mint.db"), clock=system_clock
    )
    port = server.start()
    base_url = f"http://127.0.0.1:{port}"
    print(f"[setup] mint '{MINT_ID}' on {base_url}")

    try:
        # ---- 2. Fund the treasury (operator issue -> bearer token -> receive)
        client = FlakyMintClient(base_url)
        FUNDING = 100_000
        s = new_secret()
        client.admin_issue(
            [{"amount_mc": FUNDING, "secret_hash": ledger_key(s)}],
            admin_token="operator-secret",
        )
        funding_token = format_token(MINT_ID, FUNDING, s)

        treasury = Wallet(os.path.join(workdir, "treasury.db"), client, MINT_ID)
        credited = treasury.receive(funding_token)
        print(f"[fund] treasury credited {credited} mc "
              f"(balance={treasury.balance()})")
        assert treasury.balance() == credited

        # ---- 3. Decide the payroll: 20 workers, 1..500 mc each --------------
        amounts = [rng.randint(1, 500) for _ in range(N_WORKERS)]
        payroll = sum(amounts)
        print(f"[plan] {N_WORKERS} workers, amounts={amounts}")
        print(f"[plan] payroll total = {payroll} mc")

        # ---- 2b/ budget with a quote BEFORE sending ------------------------
        q = treasury.quote(payroll)
        print(f"[quote] to move {payroll} mc: burn={q['burn_mc']} "
              f"change={q['change_mc']} inputs={q['inputs_mc']}")
        assert q["inputs_mc"] == payroll + q["burn_mc"] + q["change_mc"]
        assert treasury.balance() >= q["inputs_mc"], "cannot afford payroll"

        # ---- 3. EFFICIENT fan-out: one call, one burn ----------------------
        sends_before = client.exchange_sends
        bal_before = treasury.balance()
        token_lists = treasury.pay_many(amounts)
        exchanges_used = client.exchange_sends - sends_before
        print(f"[fanout] pay_many({N_WORKERS} recipients) used "
              f"{exchanges_used} /v3/exchange call(s)")
        assert exchanges_used == 1, "fan-out must be a single exchange (one burn)"
        assert len(token_lists) == N_WORKERS
        spent_by_treasury = bal_before - treasury.balance()
        print(f"[fanout] treasury debited {spent_by_treasury} mc "
              f"(= payroll {payroll} + burn {spent_by_treasury - payroll})")

        # ---- deliver tokens; every worker receives & verifies its amount ---
        workers = []
        for i, toks in enumerate(token_lists):
            w = Wallet.connect(os.path.join(workdir, f"worker{i}.db"), base_url)
            got = sum(w.receive(t) for t in toks)
            assert got == amounts[i], (i, got, amounts[i])
            assert w.balance() == amounts[i]
            workers.append(w)
        print(f"[deliver] all {N_WORKERS} workers received & verified balances")

        # ---- 4. Spent-token handback ---------------------------------------
        # Worker 0 already redeemed token_lists[0][0] inside receive(); handing
        # that same string back to the treasury must fail as `spent`.
        stale = token_lists[0][0]
        try:
            treasury.receive(stale)
            raise AssertionError("expected spent-token handback to be rejected")
        except PaymentInvalid as e:
            print(f"[handback] rejected stale token, reasons={e.reasons}")
            assert "spent" in e.reasons, e.reasons

        # ---- 5. Timeout + idempotent retry ---------------------------------
        sink = Wallet.connect(os.path.join(workdir, "sink.db"), base_url)
        bal_pre = treasury.balance()
        client.drop_next_exchange = True
        sends_pre = client.exchange_sends
        retry_tokens = treasury.pay(50)          # first response dropped by seam
        sends_used = client.exchange_sends - sends_pre
        print(f"[timeout] pay(50) took {sends_used} transport send(s); "
              f"responses dropped={client.dropped}")
        assert client.dropped == 1
        assert sends_used >= 2, "expected a retry after the dropped response"
        debited = bal_pre - treasury.balance()
        assert debited >= 50, "treasury must have been debited exactly once"
        # exactly one payment took effect: the sink receives exactly 50 mc.
        got = sum(sink.receive(t) for t in retry_tokens)
        assert got == 50, got
        print(f"[timeout] sink received exactly {got} mc; treasury debited "
              f"{debited} mc -> no double-spend, no lost funds")

        # ---- 6. Verify ALL 20 workers can spend ----------------------------
        proof_sink = Wallet.connect(os.path.join(workdir, "proof.db"), base_url)
        spendable = 0
        for i, w in enumerate(workers):
            toks = w.pay(1)                       # every worker spends 1 mc
            proof_sink.receive(toks[0] if len(toks) == 1 else toks[0])
            for extra in toks[1:]:
                proof_sink.receive(extra)
            spendable += 1
        print(f"[verify] all {spendable}/{N_WORKERS} workers spent 1 mc "
              f"successfully; proof-sink balance={proof_sink.balance()}")
        assert spendable == N_WORKERS

        print("\nOK - journey 2 complete: funded, budgeted, fanned out in one "
              "call, handled a spent handback and a timeout retry, and all 20 "
              "workers can spend.")
        return 0
    finally:
        server.stop()


if __name__ == "__main__":
    sys.exit(main())
