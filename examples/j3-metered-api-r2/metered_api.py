"""JOURNEY 3 (round 2) — metered API seller: §9.2 serve-then-batch-redeem + §9.1 channel upgrade.

Written cold against the AICash v0.4 repo DOCS ONLY (README + aicash-spec-v0.4.md
§9.2/§9.5/§9.1 + the component "Public API" blocks C07/C08 + the package-root
public signatures/docstrings for `aicash.envelope`). No implementation source
bodies were read.

What it demonstrates, end to end on a real in-process mint (real HTTP on 127.0.0.1):

  1. A priced "word-count oracle" endpoint charging 100 mc/request. Clients attach
     payment with the §9.5 envelope, BUILT with the new envelope tooling
     `aicash.build_envelope(...)` and PARSED on the seller side with
     `aicash.parse_envelope(...)` -> Envelope(request, mint_id, tokens, channel_draw).
     Refusals are the §3.8 body from `aicash.payment_error([...])`.

  2. §9.2 verify-serve-batch-redeem: the seller verifies each request's tokens via
     read-only batch `MintClient.status` (no burn), serves, and HOLDS the tokens;
     every 10 held tokens it redeems the whole batch with a SINGLE call —
     `Wallet.receive_batch(tokens)` -> {"credited_mc", "dead":[{index,reason}]} —
     which is one /v3/exchange and ONE §7.3 burn for the whole batch (never one
     burn per request).

  3. 50 requests from 3 clients, one of them a double-spender (mallory), exercising
     BOTH §9.2 double-spend flavors:
       (a) resubmitting an already-held token verbatim -> caught pre-serve by the
           seller's local held-token dedupe, refused 402 `spent`.
       (b) clawing a served-but-not-yet-redeemed token back via self-re-exchange ->
           surfaces at batch redemption as an enumerated `dead` entry (§9.2 exposure),
           absorbed as a quantified fraud loss.

  4. The best client (alice) is upgraded to a §9.1 prefunded channel
     (ChannelPayer/ChannelPayee): per-request drip via `channel_draw` with ZERO mint
     round trips per request, one settlement call at the end.

  5. Full-money verification: seller revenue confirmed unspent on the ledger via
     `status`, and the mint's signed supply arithmetic checked exactly
     (outstanding == issued − burned == sum(client balances) + seller balance).

Run:  PYTHONPATH=impl python3 metered_api.py
"""

import os
import tempfile
import uuid

from aicash import (
    BurnPolicy, MintConfig, make_mint, generate_keypair, system_clock,
    Wallet, MintClient, new_secret, ledger_key, format_token,
    build_envelope, parse_envelope, payment_error,
    ChannelPayer, ChannelPayee, parse_token,
)
from aicash.envelope import EnvelopeError

MINT_ID = "oracle-mint"
PRICE_MC = 100          # per request
REDEEM_EVERY = 10       # §9.2 "M": batch-redeem after this many held tokens
FUND_MC = 10_000        # operator funding per client wallet
ADMIN = "operator-secret"


# ---------------------------------------------------------------------------
# mint bring-up — one source of truth via make_mint (README quickstart)
# ---------------------------------------------------------------------------

def start_mint(workdir):
    priv, pub = generate_keypair()
    config = MintConfig(
        mint_id=MINT_ID,
        baseline_model_class="toy-model",
        burn_policy=BurnPolicy(rate_ppm=1000, cap_mc=100, exempt_below_mc=10),
        signing_private=priv, signing_public=pub,
        admin_token=ADMIN,
    )
    server, ledger = make_mint(config, db_path=os.path.join(workdir, "mint.db"),
                               clock=system_clock)
    port = server.start()          # start() returns the bound port
    return server, ledger, f"http://127.0.0.1:{port}"


def fund_wallet(client, wallet, amount_mc):
    """§7.2 receive-first: operator issues a bearer token, agent re-exchanges it."""
    s = new_secret()
    client.admin_issue([{"amount_mc": amount_mc, "secret_hash": ledger_key(s)}],
                        admin_token=ADMIN)
    return wallet.receive(format_token(MINT_ID, amount_mc, s))


# ---------------------------------------------------------------------------
# the seller — §9.2 serve-then-batch-redeem, with a §9.1 channel path
# ---------------------------------------------------------------------------

class MeteredSeller:
    def __init__(self, base_url, revenue_store):
        self.client = MintClient(base_url)
        # the seller's OWN wallet: batch-redeems held bearer tokens and receives
        # channel settlements — this is where realized revenue lands.
        self.wallet = Wallet(revenue_store, self.client, MINT_ID)
        self.held = []              # [{token, key, amount, client}]  verified, unredeemed
        self.held_keys = set()
        self.bearer_credited = 0    # net-of-burn revenue realized from bearer batches
        self.fraud_mc = 0
        self.fraud_events = []
        self.served = 0
        self.refused = 0
        self.status_calls = 0
        self.exchange_batches = 0
        self.channels = {}          # channel_id -> ChannelPayee

    @staticmethod
    def _work(query):
        return {"query": query, "word_count": len(query.split())}

    def handle_request(self, request, client_id):
        # -- §9.5 envelope parse (hostile input -> stable named reason) --------
        try:
            env = parse_envelope(request)
        except EnvelopeError as exc:
            return self._refuse([{"index": 0, "kind": "input",
                                  "reason": "bad_format"}], client_id,
                                note=f"envelope {exc.reason}")
        if env.mint_id != MINT_ID:
            return self._refuse([{"index": 0, "kind": "input",
                                  "reason": "bad_format"}], client_id)

        if env.channel_draw is not None:
            return self._handle_draw(env, request, client_id)

        # -- bearer path: local face-value + dedupe checks (free) -------------
        toks = env.tokens                       # already-parsed Token objects
        if not toks or sum(t.amount_mc for t in toks) < PRICE_MC:
            return self._refuse([{"index": 0, "kind": "input",
                                  "reason": "amount_mismatch"}], client_id)
        keys = [ledger_key(t.secret) for t in toks]
        for i, k in enumerate(keys):
            if k in self.held_keys:             # double-spend (a): resubmission
                return self._refuse([{"index": i, "kind": "input",
                                      "reason": "spent"}], client_id)

        # -- §9.2 step 2: verify via read-only batch status (no burn) ---------
        self.status_calls += 1
        _mt, results = self.client.status(keys)
        errs = [{"index": i, "kind": "input",
                 "reason": "spent" if r.get("state") == "spent" else "unknown"}
                for i, r in enumerate(results) if r.get("state") != "unspent"]
        if errs:
            return self._refuse(errs, client_id)

        # -- serve, then HOLD the tokens for batch redemption -----------------
        answer = self._work(request.get("query", ""))
        for t, k in zip(toks, keys):
            self.held.append({"token": format_token(MINT_ID, t.amount_mc, t.secret),
                              "key": k, "amount": t.amount_mc, "client": client_id})
            self.held_keys.add(k)
        self.served += 1
        if len(self.held) >= REDEEM_EVERY:
            self.redeem_held()
        return {"status": 200, "result": answer}

    def _refuse(self, errors, client_id, note=None):
        self.refused += 1
        body = payment_error(errors)            # §3.8-shaped {"status":"rejected","errors":[...]}
        # HTTP 402 (§9.5) carrying the §3.8 body; keep the two "status" fields
        # distinct — transport code vs the protocol error object.
        return {"status": 402, "errors": body["errors"], "body": body, "_note": note}

    # -- §9.2 step 3: batch redemption -- one call, one burn ------------------
    def redeem_held(self):
        if not self.held:
            return
        batch = list(self.held)
        self.exchange_batches += 1
        res = self.wallet.receive_batch([h["token"] for h in batch])  # ONE burn
        self.bearer_credited += res["credited_mc"]
        for d in res.get("dead", []):           # double-spend (b): clawed back
            h = batch[d["index"]]
            self.fraud_mc += h["amount"]
            self.fraud_events.append(
                f"client {h['client']} double-spent {h['amount']} mc "
                f"(reason={d['reason']}, caught at batch redemption — §9.2 exposure)")
        self.held = []
        self.held_keys = set()

    # -- §9.1 channel path ----------------------------------------------------
    def open_channel(self, n):
        """Payee side of §9.1: generate the N output secrets, hand back the hashes."""
        secrets = [new_secret() for _ in range(n)]
        return [ledger_key(s) for s in secrets], secrets

    def accept_channel(self, info, secrets, unit_mc, n):
        payee = ChannelPayee(self.client, MINT_ID, wallet=self.wallet)
        payee.accept(info, secrets, expect_unit_mc=unit_mc, expect_n=n)
        self.channels[info.channel_id] = payee
        return payee

    def _handle_draw(self, env, request, client_id):
        # NOTE (friction): parse_envelope DECODES x_k to bytes, but
        # ChannelPayee.on_draw wants the WIRE form (b64u string, as
        # ChannelPayer.draw emits). So we feed on_draw the raw request draw,
        # not env.channel_draw._asdict() (whose x_k would be bytes).
        draw = request["aicash"]["channel_draw"]
        payee = self.channels.get(env.channel_draw.channel_id)
        if payee is None:
            return self._refuse([{"index": 0, "kind": "input",
                                  "reason": "unknown"}], client_id)
        try:
            payee.on_draw(draw)                  # purely local: zero mint round trips
        except Exception:
            return self._refuse([{"index": 0, "kind": "input",
                                  "reason": "lock_preimage_invalid"}], client_id)
        self.served += 1
        return {"status": 200, "result": self._work(request.get("query", ""))}


# ---------------------------------------------------------------------------
# the journey
# ---------------------------------------------------------------------------

def main():
    workdir = tempfile.mkdtemp(prefix="aicash-j3r2-")
    server, ledger, base_url = start_mint(workdir)
    print(f"mint up at {base_url} (mint_id={MINT_ID})")
    try:
        run(workdir, ledger, base_url)
    finally:
        server.stop()


def run(workdir, ledger, base_url):
    # --- three funded client wallets (§7.2 receive-first) ----------------
    wallets = {}
    shared = MintClient(base_url)
    for name in ("alice", "bob", "mallory"):
        w = Wallet(os.path.join(workdir, f"{name}.db"), MintClient(base_url), MINT_ID)
        net = fund_wallet(shared, w, FUND_MC)
        wallets[name] = w
        print(f"funded {name}: {net} mc held (of {FUND_MC} issued)")

    seller = MeteredSeller(base_url, os.path.join(workdir, "seller.db"))

    # === PHASE 1: 50 bearer requests, batch-redeem every 10 (§9.2) =======
    print(f"\n== phase 1: 50 bearer requests, batch-redeem every {REDEEM_EVERY} ==")
    schedule = (["alice"] * 20) + (["bob"] * 15) + (["mallory"] * 15)
    mallory_first = None
    clawed = False

    for i, who in enumerate(schedule):
        w = wallets[who]

        # double-spend (a): mallory resubmits an already-held token verbatim
        if who == "mallory" and i == 44 and mallory_first is not None:
            req = build_envelope({"query": f"q{i}"}, MINT_ID, [mallory_first])
            resp = seller.handle_request(req, who)
            assert resp["status"] == 402 and resp["errors"][0]["reason"] == "spent", resp
            print(f"  req {i:2d} mallory : REFUSED 402 spent (token resubmission — dedupe)")
            continue

        tokens = w.pay(PRICE_MC)
        req = build_envelope({"query": f"q{i} some words here"}, MINT_ID, tokens)
        resp = seller.handle_request(req, who)
        assert resp["status"] == 200, resp

        if who == "mallory" and mallory_first is None:
            mallory_first = tokens[0]

        # double-spend (b): after being served, mallory claws a still-held token
        # back by re-exchanging it into her own wallet before the seller redeems.
        # request 40 (the 40th served) triggers an immediate batch redeem, so
        # strike at 41 while the token still sits in the held window.
        if who == "mallory" and not clawed and i == 41:
            recovered = w.receive(tokens[0])
            clawed = True
            print(f"  req {i:2d} mallory : served, then clawed back {recovered} mc "
                  f"via self-re-exchange (double-spend (b))")

    seller.redeem_held()   # flush the tail (< REDEEM_EVERY held)

    print(f"\nserved {seller.served}, refused {seller.refused} of {len(schedule)} requests")
    print(f"redemption calls: {seller.exchange_batches} exchanges for "
          f"{seller.served} served requests (batching: 1 burn per batch, not per req)")
    print(f"status calls: {seller.status_calls}")
    print(f"fraud losses: {seller.fraud_mc} mc")
    for ev in seller.fraud_events:
        print("  -", ev)

    assert seller.served == 49 and seller.refused == 1, (seller.served, seller.refused)
    assert seller.fraud_mc == PRICE_MC, seller.fraud_mc
    print(f"bearer revenue realized (net of burns): {seller.bearer_credited} mc")
    # 49 served − 1 clawed back = 48 paid; minus per-batch burns
    assert seller.bearer_credited > 47 * PRICE_MC

    # === PHASE 2: upgrade alice to a §9.1 prefunded channel ==============
    print("\n== phase 2: alice upgrades to a §9.1 prefunded channel ==")
    N = 15
    hashes, secrets = seller.open_channel(N)             # payee generates secrets
    payer = ChannelPayer(wallets["alice"])
    mint_time = seller.client.descriptor()["mint_time"]
    info = payer.open(hashes, unit_mc=PRICE_MC, N=N, expiry_ms=mint_time + 30 * 60_000)
    payee = seller.accept_channel(info, secrets, PRICE_MC, N)  # §9.1 verify
    print(f"channel {info.channel_id[:8]}… open+verified: N={N}, unit={PRICE_MC} mc")

    for k in range(1, N + 1):
        draw = payer.draw(k)                              # local, no I/O
        req = build_envelope({"query": f"drip {k}"}, MINT_ID, [], channel_draw=draw)
        resp = seller.handle_request(req, "alice")
        assert resp["status"] == 200, resp
    settled_net = payee.settle()                          # ONE exchange, one burn
    print(f"{N} drip requests served with 0 mint round trips/request; "
          f"settled {settled_net} mc net into seller wallet in one call")
    assert settled_net > 0

    # === VERIFICATION: the money actually moved =========================
    print("\n== verification ==")
    seller_bal = seller.wallet.balance()
    print(f"seller wallet balance (bearer + channel revenue): {seller_bal} mc")
    # Confirm the revenue is real, live, and spendable: the seller pays some out
    # and an independent sink wallet receives it (a full mint round-trip).
    proof = seller.wallet.pay(PRICE_MC)
    sink = Wallet(os.path.join(workdir, "sink.db"), MintClient(base_url), MINT_ID)
    got = sink.receive(proof[0])
    print(f"seller revenue is live & spendable: paid {PRICE_MC} mc out, "
          f"sink received {got} mc")

    balances = {n: w.balance() for n, w in wallets.items()}
    balances["seller"] = seller.wallet.balance()
    balances["sink"] = sink.balance()
    supply = ledger.supply()
    issued = supply["cumulative_issued_mc"]
    burned = supply["cumulative_burned_mc"]
    outstanding = supply["outstanding_mc"]
    print(f"balances: {balances}")
    print(f"supply: issued={issued}, burned={burned}, outstanding={outstanding}")
    assert outstanding == issued - burned, (outstanding, issued, burned)
    assert sum(balances.values()) == outstanding, (sum(balances.values()), outstanding)
    print(f"accounting identity holds: sum(all wallet balances) = "
          f"{sum(balances.values())} mc = outstanding = issued − burned")

    print("\nJOURNEY 3 (r2) COMPLETE — real money moved and verified.")


if __name__ == "__main__":
    main()
