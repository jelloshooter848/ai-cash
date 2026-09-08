"""AICash Journey 2 — micro-work fan-out (HYDRA).

Run:  PYTHONPATH=impl python3 examples/j2-microwork-r3/microwork.py

Fund a treasury, budget the fan-out with Wallet.quote, pay 20 workers
1-500 mc each in ONE pay_many call (one exchange, one burn), handle a
spent-token handback by catching PaymentInvalid and inspecting its
structured reason, demonstrate an idempotent timeout-retry, and verify
all 20 workers can spend. Uses only the package-root public API and the
component "Public API" blocks — no implementation source read.
"""
import os
import random
import tempfile

from aicash import (
    BurnPolicy, MintConfig, make_mint, generate_keypair, system_clock,
    Wallet, MintClient, new_secret, ledger_key, format_token,
    PaymentInvalid, InsufficientFunds, MintUnavailable,
)

MINT_ID = "hydra-mint"


class FlakyClient(MintClient):
    """MintClient whose _transport can drop ONE exchange response after it has
    already reached the mint — the classic timeout: request delivered, reply
    lost. The wallet's persist-before-send + idempotent-retry (C07 req 7) must
    replay under the SAME idempotency key and the mint must not double-execute.
    Instrumentation only — routes every request through the documented
    _transport seam (C07 req 10)."""

    def __init__(self, base_url):
        super().__init__(base_url)
        self.armed = False
        self.drops = 0
        self.exchange_hits = 0

    def _transport(self, method, path, body, extra_headers=None):
        status, raw = super()._transport(method, path, body, extra_headers)
        if path.endswith("/v3/exchange"):
            self.exchange_hits += 1
            if self.armed:
                self.armed = False
                self.drops += 1
                raise MintUnavailable("simulated timeout: response dropped after delivery")
        return status, raw


def main():
    rng = random.Random(20)  # deterministic 1..500 amounts
    d = tempfile.mkdtemp(prefix="hydra-")

    # --- Boot a mint (0.1% burn, cap 1000 mc, drips <=10 mc burn-free). ------
    priv, pub = generate_keypair()
    config = MintConfig(
        mint_id=MINT_ID,
        baseline_model_class="hydra-model-v1",
        burn_policy=BurnPolicy(rate_ppm=1000, cap_mc=1000, exempt_below_mc=10),
        signing_private=priv, signing_public=pub,
        admin_token="operator-secret",
        # Ladder-decomposing 20 arbitrary 1-500 mc payouts can exceed the
        # default max_batch (256); raise the mint's published batch limit so the
        # whole fan-out fits in ONE pay_many call (one exchange, one burn).
        max_batch=512,
    )
    server, ledger = make_mint(config, db_path=os.path.join(d, "mint.db"), clock=system_clock)
    port = server.start()
    base = f"http://127.0.0.1:{port}"

    try:
        client = MintClient(base)

        # --- 1. Fund a treasury (§7.1 operator funding). --------------------
        s = new_secret()
        client.admin_issue(
            [{"amount_mc": 100_000, "secret_hash": ledger_key(s)}],
            admin_token="operator-secret",
        )
        treasury = Wallet(os.path.join(d, "treasury.db"), client, MINT_ID)
        funded = treasury.receive(format_token(MINT_ID, 100_000, s))
        print(f"[fund] treasury funded, holds {funded} mc (after re-exchange burn)")

        # --- 2. Decide the 20 micro-payments, budget with Wallet.quote. -----
        amounts = [rng.randint(1, 500) for _ in range(20)]
        total = sum(amounts)
        q = treasury.quote(total)
        print(f"[quote] paying {total} mc total across 20 workers -> "
              f"burn {q['burn_mc']} mc, change {q['change_mc']} mc, "
              f"inputs selected {q['inputs_mc']} mc")
        assert q["inputs_mc"] == total + q["burn_mc"] + q["change_mc"], "quote identity"
        if treasury.balance() < q["inputs_mc"]:
            raise InsufficientFunds("treasury cannot cover the fan-out")
        print(f"[quote] treasury balance {treasury.balance()} mc covers it — proceeding")

        # --- 3. Pay all 20 workers in ONE pay_many call (one burn). ---------
        bal_before = treasury.balance()
        token_lists = treasury.pay_many(amounts)
        bal_after = treasury.balance()
        assert len(token_lists) == 20, "one token list per recipient"
        debited = bal_before - bal_after
        print(f"[fan-out] pay_many settled 20 recipients in one call; "
              f"treasury debited {debited} mc (= {total} paid + {debited - total} burn)")

        # --- 4. Spent-token handback -> catch PaymentInvalid, read reason. --
        # Grab a raw token from worker 0's list BEFORE worker 0 redeems it.
        stale_token = token_lists[0][0]

        workers = []
        for i, toks in enumerate(token_lists):
            w = Wallet(os.path.join(d, f"worker{i}.db"), MintClient(base), MINT_ID)
            res = w.receive_batch(toks)               # N tokens, ONE burn (§9.2)
            assert res["credited_mc"] == amounts[i], (
                f"worker {i}: credited {res['credited_mc']} != owed {amounts[i]}")
            assert res["dead"] == [], f"worker {i}: unexpected dead tokens {res['dead']}"
            workers.append(w)
        credited_total = sum(amounts)
        print(f"[receive] all 20 workers redeemed their lists; total credited "
              f"{credited_total} mc, each == its owed amount")

        # worker 0 already re-exchanged stale_token; handing it back is a spend
        # of an already-spent output. receive() must reject it structurally.
        try:
            treasury.receive(stale_token)
            raise AssertionError("expected PaymentInvalid on spent-token handback")
        except PaymentInvalid as e:
            # Attributes are documented in C07: .reasons and .errors (list of
            # {index, kind, reason}). No impl source consulted for these.
            print(f"[handback] caught PaymentInvalid — reasons={e.reasons} "
                  f"errors={e.errors}")
            assert "spent" in e.reasons, f"expected 'spent', got {e.reasons}"

        # --- 5. Demonstrate a timeout-retry (idempotent, no double-spend). --
        # Fund a small demo-treasury on a FlakyClient, arm a one-shot dropped
        # response on the next exchange, then pay: the wallet replays under the
        # same idempotency key and the mint executes exactly once.
        flaky = FlakyClient(base)
        s2 = new_secret()
        flaky.admin_issue(
            [{"amount_mc": 5_000, "secret_hash": ledger_key(s2)}],
            admin_token="operator-secret",
        )
        demo = Wallet(os.path.join(d, "demo.db"), flaky, MINT_ID)
        demo.receive(format_token(MINT_ID, 5_000, s2))
        demo_before = demo.balance()
        hits_before = flaky.exchange_hits
        flaky.armed = True                            # next exchange: deliver, drop reply
        pay_toks = demo.pay(400)                       # survives the dropped response
        demo_after = demo.balance()
        print(f"[timeout] dropped 1 response ({flaky.drops}); pay retried and "
              f"succeeded; exchange reached mint "
              f"{flaky.exchange_hits - hits_before}x, wallet debited "
              f"{demo_before - demo_after} mc (paid 400, once)")
        assert flaky.drops == 1 and demo_before - demo_after == 400, "single clean debit"
        sink0 = Wallet(os.path.join(d, "sink0.db"), MintClient(base), MINT_ID)
        got = sum(sink0.receive(t) for t in pay_toks)
        assert got == 400, f"sink got {got}, no duplicate/lost outputs from the retry"
        print(f"[timeout] payee received exactly {got} mc — no double-spend, no loss")

        # --- 6. Verify all 20 workers can actually spend. -------------------
        sink = Wallet(os.path.join(d, "sink.db"), MintClient(base), MINT_ID)
        spent_ok = 0
        for i, w in enumerate(workers):
            for t in w.pay(1):                         # 1 mc drip: always affordable
                sink.receive(t)
            spent_ok += 1
        print(f"[spend] {spent_ok}/20 workers each spent to the sink; "
              f"sink now holds {sink.balance()} mc")
        assert sink.balance() == 20, f"expected 20 mc in sink, got {sink.balance()}"

        # --- 7. Supply reconciles: outstanding == issued - burned. ----------
        sup = client.descriptor()["supply"]
        assert sup["outstanding_mc"] == sup["cumulative_issued_mc"] - sup["cumulative_burned_mc"]
        print(f"[verify] mint supply reconciles: outstanding {sup['outstanding_mc']} "
              f"= issued {sup['cumulative_issued_mc']} - burned {sup['cumulative_burned_mc']}")
        print("\nOK — 20 workers paid in one call, handback rejected, timeout "
              "survived, all 20 spent.")
    finally:
        server.stop()


if __name__ == "__main__":
    main()
