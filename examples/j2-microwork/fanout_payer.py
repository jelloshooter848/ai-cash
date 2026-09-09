"""JOURNEY 2 — micro-work fan-out payer (HYDRA's job).

Produced during a COLD USABILITY TEST of the AICash v0.4 reference
implementation: written by an AI agent that had never seen this repo,
using only the repo's own docs and public APIs.

What this script demonstrates, end to end, against a real in-process mint
(C06 MintServer over real HTTP on 127.0.0.1):

  1. Start a mint (MintConfig + Ledger + MintServer) and fund a treasury
     wallet via the non-normative POST /admin/issue operator path.
  2. Pay 20 distinct "worker" wallets between 1 and 500 mc each for
     micro-tasks (one Wallet.pay per worker — the wallet API has no
     multi-recipient batch pay; see friction notes in the test report).
  3. Failure case A: a worker hands back an already-spent token — the
     treasury's receive() raises PaymentInvalid with reason "spent".
  4. Failure case B: simulated transport timeout on a pay — the request
     reaches the mint but the response is dropped; the wallet retries
     with the SAME idempotency key and the mint replays, so exactly one
     exchange takes effect (no double-spend, no lost funds).
  5. Verify all 20 workers can spend what they received (each pays 1 mc
     to a sink wallet), and reconcile: mint outstanding supply ==
     sum of all wallet balances.

Run:  PYTHONPATH=impl python3 fanout_payer.py
"""

import http.client
import json
import os
import random
import sys
import tempfile

from aicash.burncalc import BurnPolicy, compute_burn
from aicash.clock import system_clock
from aicash.ledgerstore import Ledger
from aicash.mintapi import MintConfig, MintServer
from aicash.signing import generate_keypair
from aicash.tokencodec import b64u_encode, canonical_json, format_token
from aicash.wallet import MintClient, PaymentInvalid, Wallet

MINT_ID = "hydra-test-mint"
FUNDING_MC = 100_000
N_WORKERS = 20


# --------------------------------------------------------------------------
# A MintClient with a fault-injection seam: deliver the request to the mint,
# then drop the response once — exactly what a network timeout looks like to
# the payer.  MintClient._transport is the documented seam for this
# ("tests may subclass to instrument / inject faults").
# --------------------------------------------------------------------------
class FlakyMintClient(MintClient):
    def __init__(self, base_url: str):
        super().__init__(base_url)
        self.drop_next_exchange_response = False
        self.exchange_sends = 0  # transport-level sends of /v3/exchange

    def _transport(self, method, path, body):
        if path == "/v3/exchange":
            self.exchange_sends += 1
        status, raw = super()._transport(method, path, body)
        if path == "/v3/exchange" and self.drop_next_exchange_response:
            self.drop_next_exchange_response = False
            # The mint HAS processed the request; the payer never hears back.
            raise TimeoutError("simulated timeout: response dropped")
        return status, raw


def admin_issue(port: int, outputs: list) -> dict:
    """POST /admin/issue — MintClient exposes no admin method, so raw HTTP."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        conn.request(
            "POST",
            "/admin/issue",
            canonical_json({"outputs": outputs}),
            {"Content-Type": "application/json"},
        )
        resp = conn.getresponse()
        body = json.loads(resp.read().decode("utf-8"))
        if resp.status != 200:
            raise RuntimeError(f"admin issue failed: {resp.status} {body}")
        return body
    finally:
        conn.close()


def main() -> int:
    rng = random.Random(42)  # reproducible worker amounts
    workdir = tempfile.mkdtemp(prefix="aicash-j2-")
    print(f"[setup] state dir: {workdir}")

    # ---- 1. Start a real in-process mint --------------------------------
    priv, pub = generate_keypair()
    policy = BurnPolicy(rate_ppm=10_000, cap_mc=50_000, exempt_below_mc=10)
    config = MintConfig(
        mint_id=MINT_ID,
        baseline_model_class="test-class-1",
        burn_policy=policy,
        signing_private=priv,
        signing_public=pub,
    )
    # NOTE: Ledger duplicates values MintConfig already holds — the
    # integrator must keep them consistent by hand.
    ledger = Ledger(
        db_path=os.path.join(workdir, "mint-ledger.sqlite"),
        clock=system_clock,
        burn_policy=policy,
        recovery_window_ms=config.recovery_window_ms,
        max_lock_expiry_ms=config.max_lock_expiry_ms,
    )
    server = MintServer(config, ledger)
    port = server.start()
    base_url = f"http://127.0.0.1:{port}"
    print(f"[setup] mint '{MINT_ID}' listening on {base_url}")

    try:
        # ---- 2. Fund the treasury wallet --------------------------------
        treasury_client = FlakyMintClient(base_url)
        treasury = Wallet(
            os.path.join(workdir, "treasury.sqlite"), treasury_client, MINT_ID
        )
        funding_secret = os.urandom(32)
        admin_issue(
            port,
            [{"amount_mc": FUNDING_MC, "secret": b64u_encode(funding_secret)}],
        )
        funding_token = format_token(MINT_ID, FUNDING_MC, funding_secret)
        credited = treasury.receive(funding_token)
        funding_burn = FUNDING_MC - credited
        print(
            f"[fund ] issued {FUNDING_MC} mc -> treasury credited {credited} mc"
            f" (receive burn {funding_burn} mc)"
        )
        assert treasury.balance() == credited, "treasury balance mismatch"

        # ---- 3. Fan out payments to 20 workers --------------------------
        amounts = [rng.randint(1, 500) for _ in range(N_WORKERS)]
        workers = []  # (name, wallet, face_amount, payment_tokens)
        retry_worker_idx = 7  # this one's payment suffers a "timeout"
        for i, amount in enumerate(amounts):
            name = f"worker-{i:02d}"
            if i == retry_worker_idx:
                # ---- Failure case B: timeout then retry (idempotency) ----
                sends_before = treasury_client.exchange_sends
                bal_before = treasury.balance()
                treasury_client.drop_next_exchange_response = True
                tokens = treasury.pay(amount)  # wallet retries internally,
                # same idempotency key; mint replays the first result.
                sends = treasury_client.exchange_sends - sends_before
                assert sends >= 2, "expected a retry after the dropped response"
                spent = bal_before - treasury.balance()
                print(
                    f"[retry] {name}: response dropped once, {sends} sends of"
                    f" ONE idempotent exchange; treasury debited exactly"
                    f" {spent} mc ({amount} mc + {spent - amount} mc burn)"
                    f" — no double-spend"
                )
            else:
                tokens = treasury.pay(amount)
            workers.append((name, None, amount, tokens))
        print(
            f"[pay  ] paid {N_WORKERS} workers, total face"
            f" {sum(amounts)} mc, treasury now {treasury.balance()} mc"
        )
        # (The wallet API pays one amount per call; the mint itself would
        #  accept up to max_batch outputs in a single exchange, but Wallet
        #  offers no multi-recipient fan-out — so this is 20 HTTP calls.)

        # ---- 4. Workers receive their pay -------------------------------
        finished = []
        for i, (name, _w, amount, tokens) in enumerate(workers):
            w = Wallet(os.path.join(workdir, f"{name}.sqlite"),
                       MintClient(base_url), MINT_ID)
            got = sum(w.receive(t) for t in tokens)
            expected_burn = compute_burn(amount, policy)
            assert got == amount - expected_burn, (
                f"{name}: credited {got}, expected {amount - expected_burn}"
            )
            finished.append((name, w, amount, tokens))
        workers = finished
        print(f"[recv ] all {N_WORKERS} workers received and re-exchanged pay")

        # ---- 5. Failure case A: worker hands back a spent token ---------
        # worker-03 already redeemed its tokens above; a dishonest (or
        # confused) worker hands the same strings back asking to be paid
        # again / refunded.  receive() must reject with reason "spent".
        name, _w, _amt, spent_tokens = workers[3]
        try:
            treasury.receive(spent_tokens[0])
            raise AssertionError("spent token was accepted — BUG")
        except PaymentInvalid as exc:
            assert "spent" in exc.reasons, f"unexpected reasons {exc.reasons}"
            print(
                f"[spent] {name} handed back an already-redeemed token:"
                f" treasury.receive raised PaymentInvalid(reasons="
                f"{exc.reasons}) as required"
            )

        # ---- 6. Every worker proves it can SPEND what it received -------
        sink = Wallet(os.path.join(workdir, "sink.sqlite"),
                      MintClient(base_url), MINT_ID)
        spend_burn_total = 0
        for name, w, _amt, _t in workers:
            before = w.balance()
            tokens_out = w.pay(1)  # 1 mc micro-spend proves the value is live
            got = sum(sink.receive(t) for t in tokens_out)
            assert got == 1, f"{name}: sink credited {got}, expected 1"
            # GOTCHA: burn is computed on the sum of the coins SELECTED as
            # inputs, not on the payment amount — a wallet holding only
            # 100-mc coins burns 1 mc even to pay 1 mc.  So the delta is
            # 1 + (input-dependent burn), not always 1.
            burn_borne = before - w.balance() - 1
            assert burn_borne >= 0, f"{name}: gained money paying?!"
            spend_burn_total += burn_borne
        print(
            f"[spend] all {N_WORKERS} workers spent 1 mc to the sink"
            f" (aggregate burn borne {spend_burn_total} mc);"
            f" sink balance {sink.balance()} mc"
        )

        # ---- 7. Reconcile against the mint's signed supply --------------
        desc = MintClient(base_url).descriptor()
        supply = desc["supply"]
        outstanding = supply["outstanding_mc"]
        total_held = (
            treasury.balance()
            + sum(w.balance() for _n, w, _a, _t in workers)
            + sink.balance()
        )
        print(
            f"[check] mint supply: issued={supply['cumulative_issued_mc']}"
            f" burned={supply['cumulative_burned_mc']}"
            f" outstanding={outstanding}; wallets hold {total_held} mc"
        )
        assert outstanding == total_held, (
            f"outstanding {outstanding} != sum of wallet balances {total_held}"
        )
        assert (
            supply["cumulative_issued_mc"] - supply["cumulative_burned_mc"]
            == outstanding
        )
        print("[done ] SUCCESS: fan-out, spent-token rejection, idempotent"
              " retry, and full supply reconciliation all verified")
        return 0
    finally:
        server.stop()


if __name__ == "__main__":
    sys.exit(main())
