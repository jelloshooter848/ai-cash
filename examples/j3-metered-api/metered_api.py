"""JOURNEY 3 — metered API seller (serve-then-batch-redeem, §9.2 + §9.5 + §9.1).

Produced during a COLD USABILITY TEST of the AICash v0.4 reference
implementation: written by an AI agent that had never seen this repo,
from the spec (aicash-spec-v0.4.md) and the impl/ public APIs alone.

What it demonstrates, end to end on a real in-process mint (C06 MintServer
over HTTP on 127.0.0.1):

  1. A toy priced endpoint (a word-count "oracle") charging 100 mc/request.
     Clients attach payment with the §9.5 envelope
     ``{"aicash": {"mint_id", "tokens", "channel_draw"}}``.
  2. The seller verifies tokens via batch ``/v3/status`` (read-only, no
     burn), serves, HOLDS the tokens, and batch-redeems every 10 requests
     in one ``/v3/exchange`` (§9.2 serve-then-batch-redeem — one §7.3 burn
     per batch, never per request).
  3. 50 bearer requests from 3 client wallets, including a hostile client
     that double-spends: (a) resubmits the same token in a second request
     (caught pre-serve by the seller's held-token dedupe) and (b) claws a
     token back via self-re-exchange AFTER being served but before the
     seller's batch redemption — the quantified §9.2 exposure, surfaced as
     an enumerated ``spent`` error (§3.8) at redemption time and absorbed
     as a fraud loss.
  4. The best client is then upgraded to a §9.1 prefunded channel
     (ChannelPayer/ChannelPayee): per-request drip via ``channel_draw``
     with ZERO mint round trips per request, one settlement call at the end.
  5. Full-money verification: every seller revenue token confirmed unspent
     via ``/v3/status``, and the mint's signed supply arithmetic
     (outstanding == issued − burned == wallets + seller revenue) checked
     exactly.

Run:  PYTHONPATH=impl python3 metered_api.py
"""

import http.client
import json
import os
import sys
import tempfile
import uuid

from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "impl"))

from aicash.burncalc import BurnPolicy, compute_burn
from aicash.channels import ChannelPayee, ChannelPayer
from aicash.clock import system_clock
from aicash.ledgerstore import Ledger
from aicash.mintapi import MintConfig, MintServer
from aicash.signing import generate_keypair
from aicash.receipts import payment_error
from aicash.tokencodec import b64u_encode, format_token, ledger_key, parse_token
from aicash.wallet import MintClient, MintRejected, Wallet

MINT_ID = "oracle-mint"
PRICE_MC = 100          # per request
REDEEM_EVERY = 10       # §9.2 "M": batch-redeem after this many held tokens
FUND_MC = 10_000        # operator funding per client wallet


# ---------------------------------------------------------------------------
# mint bring-up (in-process, real HTTP on 127.0.0.1)
# ---------------------------------------------------------------------------

def start_mint(workdir: str):
    burn = BurnPolicy(rate_ppm=1000, cap_mc=100, exempt_below_mc=10)
    private, public = generate_keypair()
    # NOTE (friction): Ledger and MintConfig each take overlapping policy
    # parameters (burn policy, lock/retention windows) and nothing ties
    # them together — the integrator must keep them consistent by hand.
    ledger = Ledger(
        db_path=os.path.join(workdir, "mint.sqlite"),
        clock=system_clock,
        burn_policy=burn,
        recovery_window_ms=90 * 86_400_000,
        max_lock_expiry_ms=30 * 86_400_000,
    )
    config = MintConfig(
        mint_id=MINT_ID,
        baseline_model_class="toy-model",
        burn_policy=burn,
        signing_private=private,
        signing_public=public,
    )
    server = MintServer(config, ledger)
    port = server.start()
    return server, ledger, f"http://127.0.0.1:{port}"


def admin_issue(base_url: str, outputs: list) -> None:
    """POST /admin/issue (non-normative §7.1 operator funding).

    NOTE (friction): MintClient exposes exchange/status/descriptor but NOT
    the admin funding path, so an integrator has to hand-roll HTTP here.
    """
    host, port = base_url.split("//")[1].split(":")
    conn = http.client.HTTPConnection(host, int(port), timeout=30)
    try:
        body = json.dumps({"outputs": outputs}).encode()
        conn.request("POST", "/admin/issue", body,
                     {"Content-Type": "application/json"})
        resp = conn.getresponse()
        data = json.loads(resp.read())
        if resp.status != 200 or data.get("status") != "ok":
            raise RuntimeError(f"admin issue failed: {data}")
    finally:
        conn.close()


def fund_wallet(base_url: str, wallet: Wallet, amount_mc: int) -> int:
    """§7.2 receive-first onboarding: operator issues a bearer token,
    hands the string to the agent, agent re-exchanges on receipt."""
    secret = os.urandom(32)
    admin_issue(base_url, [{"amount_mc": amount_mc, "secret": b64u_encode(secret)}])
    token = format_token(MINT_ID, amount_mc, secret)
    return wallet.receive(token)  # net of the §7.3 burn


# ---------------------------------------------------------------------------
# the seller — a toy priced endpoint using §9.2 serve-then-batch-redeem
# ---------------------------------------------------------------------------

class MeteredSeller:
    """A priced word-count oracle. 100 mc per request, §9.5 envelope in,
    batch verification via /v3/status, batch redemption every N requests."""

    def __init__(self, client: MintClient, mint_id: str):
        self.client = client
        self.mint_id = mint_id
        self.held: list[dict] = []      # verified-but-unredeemed tokens
        self.held_keys: set[str] = set()
        self.revenue: list[tuple[bytes, int]] = []  # (secret, amount) redeemed
        self.fraud_mc = 0
        self.fraud_events: list[str] = []
        self.served = 0
        self.rejections: list[dict] = []
        self.exchange_calls = 0
        self.status_calls = 0
        self.channels: dict[str, ChannelPayee] = {}  # channel_id -> payee

    # -- the "work" -------------------------------------------------------

    @staticmethod
    def _do_work(query: str) -> dict:
        return {"query": query, "word_count": len(query.split())}

    # -- §9.5 envelope handling ------------------------------------------

    def handle_request(self, request: dict, client_id: str) -> dict:
        env = request.get("aicash")
        if not isinstance(env, dict) or env.get("mint_id") != self.mint_id:
            return self._refuse([{"index": 0, "kind": "input",
                                  "reason": "bad_format"}], client_id)

        draw = env.get("channel_draw")
        if draw is not None:
            return self._handle_channel_draw(request, draw, client_id)

        tokens = env.get("tokens") or []
        # face-value + well-formedness check (local, free)
        parsed = []
        for i, t in enumerate(tokens):
            try:
                tok = parse_token(t)
            except Exception:
                return self._refuse([{"index": i, "kind": "input",
                                      "reason": "bad_format"}], client_id)
            if tok.mint_id != self.mint_id:
                return self._refuse([{"index": i, "kind": "input",
                                      "reason": "bad_format"}], client_id)
            parsed.append((t, tok))
        if sum(tok.amount_mc for _t, tok in parsed) < PRICE_MC:
            return self._refuse([{"index": 0, "kind": "input",
                                  "reason": "amount_mismatch"}], client_id)

        # local dedupe: a token we already hold is a double-spend attempt
        keys = [ledger_key(tok.secret) for _t, tok in parsed]
        for i, k in enumerate(keys):
            if k in self.held_keys:
                return self._refuse([{"index": i, "kind": "input",
                                      "reason": "spent"}], client_id)

        # §9.2 step 2: verify via batch /v3/status (read-only, no burn)
        self.status_calls += 1
        _mt, results = self.client.status(keys)
        errors = [{"index": i, "kind": "input", "reason":
                   ("spent" if r.get("state") == "spent" else "unknown")}
                  for i, r in enumerate(results) if r.get("state") != "unspent"]
        if errors:
            return self._refuse(errors, client_id)

        # serve, then hold the token(s) for batch redemption
        answer = self._do_work(request.get("query", ""))
        for (t, tok), k in zip(parsed, keys):
            self.held.append({"token": t, "key": k,
                              "amount_mc": tok.amount_mc, "client": client_id})
            self.held_keys.add(k)
        self.served += 1
        if len(self.held) >= REDEEM_EVERY:
            self.redeem_held()
        return {"status": 200, "result": answer}

    def _refuse(self, errors: list, client_id: str) -> dict:
        """HTTP-402-equivalent §9.5 refusal with the §3.8 error object.

        Entries are routed through C12 ``payment_error()`` so a refusal can
        never drift outside the §3.8 {input|output} kind / reason
        vocabulary — the enumerated indices/kinds/reasons are validated for
        us rather than hand-built.  Call-level refusals (a malformed
        envelope, an under-priced call, an unknown or bad channel draw) are
        reported against ``index 0, kind "input"`` — the §3.8 object has no
        call-level kind, and the offending witness/token is input 0.
        """
        errors = payment_error(errors)["errors"]  # validate + normalize
        self.rejections.append({"client": client_id, "errors": errors})
        return {"status": 402, "errors": errors}

    # -- §9.2 step 3: batch redemption -----------------------------------

    def redeem_held(self) -> None:
        """One /v3/exchange for everything held (one burn). Tokens that a
        client double-spent in the window come back as enumerated `spent`
        errors (§3.8); drop them as fraud losses and retry the rest."""
        while self.held:
            batch = list(self.held)
            gross = sum(h["amount_mc"] for h in batch)
            policy = self._policy()
            burn = compute_burn(gross, policy)
            secret = os.urandom(32)
            net = gross - burn
            try:
                self.exchange_calls += 1
                self.client.exchange(
                    str(uuid.uuid4()),
                    [h["token"] for h in batch],
                    [{"amount_mc": net, "secret_hash": ledger_key(secret),
                      "lock": None}],
                )
            except MintRejected as exc:
                bad = {e["index"] for e in exc.errors
                       if isinstance(e, dict) and e.get("kind") == "input"
                       and e.get("reason") in ("spent", "unknown")
                       and isinstance(e.get("index"), int)}
                if not bad:
                    raise
                for i in sorted(bad, reverse=True):
                    h = batch[i]
                    self.fraud_mc += h["amount_mc"]
                    self.fraud_events.append(
                        f"client {h['client']} double-spent {h['amount_mc']} mc "
                        f"(discovered at batch redemption — §9.2 exposure)")
                    self.held.remove(h)
                    self.held_keys.discard(h["key"])
                continue  # retry with the survivors
            self.revenue.append((secret, net))
            for h in batch:
                self.held_keys.discard(h["key"])
            self.held = [h for h in self.held if h not in batch]

    def _policy(self) -> BurnPolicy:
        bp = self.client.descriptor()["burn_policy"]
        return BurnPolicy(rate_ppm=bp["rate_ppm"], cap_mc=bp["cap_mc"],
                          exempt_below_mc=bp["exempt_below_mc"])

    # -- §9.1 channel path ------------------------------------------------

    def open_channel(self, n: int) -> tuple[list[str], list[bytes], ChannelPayee]:
        """Payee side of §9.1 open step 2: generate the N output secrets,
        hand the payer their hashes."""
        secrets = [os.urandom(32) for _ in range(n)]
        payee = ChannelPayee(self.client, self.mint_id)
        return [ledger_key(s) for s in secrets], secrets, payee

    def accept_channel(self, payee: ChannelPayee, info, secrets, unit, n):
        payee.accept(info, secrets, expect_unit_mc=unit, expect_n=n)
        self.channels[info.channel_id] = payee

    def _handle_channel_draw(self, request: dict, draw: dict, client_id: str):
        payee = self.channels.get(draw.get("channel_id"))
        if payee is None:
            return self._refuse([{"index": 0, "kind": "input",
                                  "reason": "unknown"}], client_id)
        try:
            payee.on_draw(draw)  # purely local: zero mint round trips
        except Exception:
            return self._refuse([{"index": 0, "kind": "input",
                                  "reason": "lock_preimage_invalid"}], client_id)
        self.served += 1
        return {"status": 200, "result": self._do_work(request.get("query", ""))}


# ---------------------------------------------------------------------------
# client helpers
# ---------------------------------------------------------------------------

def paid_request(seller: MeteredSeller, wallet: Wallet, client_id: str,
                 query: str, reuse_token: str | None = None):
    """One §9.5 bearer-paid request. Returns (response, tokens_sent)."""
    tokens = [reuse_token] if reuse_token else wallet.pay(PRICE_MC)
    request = {"query": query,
               "aicash": {"mint_id": MINT_ID, "tokens": tokens,
                          "channel_draw": None}}
    return seller.handle_request(request, client_id), tokens


# ---------------------------------------------------------------------------
# the journey
# ---------------------------------------------------------------------------

def main() -> None:
    workdir = tempfile.mkdtemp(prefix="aicash-j3-")
    server, ledger, base_url = start_mint(workdir)
    print(f"mint up at {base_url}  (mint_id={MINT_ID})")

    try:
        run(workdir, ledger, base_url)
    finally:
        server.stop()


def run(workdir: str, ledger: Ledger, base_url: str) -> None:
    # --- three client wallets, funded receive-first (§7.2) --------------
    wallets = {}
    for name in ("alice", "bob", "mallory"):
        w = Wallet(os.path.join(workdir, f"{name}.sqlite"),
                   MintClient(base_url), MINT_ID)
        net = fund_wallet(base_url, w, FUND_MC)
        wallets[name] = w
        print(f"funded {name}: {net} mc held (of {FUND_MC} mc issued)")

    seller = MeteredSeller(MintClient(base_url), MINT_ID)

    # --- PHASE 1: 50 bearer requests, serve-then-batch-redeem (§9.2) ----
    print("\n== phase 1: 50 bearer requests (batch-redeem every "
          f"{REDEEM_EVERY}) ==")
    ok = refused = 0
    mallory_first_token = None   # for double-spend flavor (a): resubmission
    clawback_done = False

    schedule = (["alice"] * 20) + (["bob"] * 15) + (["mallory"] * 15)
    for i, who in enumerate(schedule):
        w = wallets[who]
        if who == "mallory" and i == 37 and mallory_first_token:
            # double-spend (a): resubmit an already-held token verbatim
            resp, _ = paid_request(seller, w, who, f"query {i}",
                                   reuse_token=mallory_first_token)
            assert resp["status"] == 402, "dedup should refuse the reuse"
            assert resp["errors"][0]["reason"] == "spent"
            refused += 1
            print(f"  request {i} ({who}): REFUSED 402 "
                  f"{resp['errors'][0]['reason']} (token resubmission)")
            continue
        resp, tokens = paid_request(seller, w, who, f"query {i} some words here")
        assert resp["status"] == 200, resp
        ok += 1
        if who == "mallory" and mallory_first_token is None:
            mallory_first_token = tokens[0]
        # NOTE: the clawback only works while the token sits in the
        # seller's held window — request 40 is the 40th SERVED request and
        # triggers an immediate batch redemption, so strike at 41.
        if who == "mallory" and not clawback_done and i >= 41:
            # double-spend (b): after being SERVED, claw the token back by
            # re-exchanging it before the seller's batch redemption (§9.2
            # exposure). wallet.receive on our own handed-over token
            # retires the seller's copy.
            recovered = w.receive(tokens[0])
            clawback_done = True
            print(f"  request {i} ({who}): served, then clawed back "
                  f"{recovered} mc via self-re-exchange (double-spend (b))")

    seller.redeem_held()  # flush the tail (< REDEEM_EVERY tokens)

    print(f"\nserved {ok}, refused {refused} of {len(schedule)} requests")
    print(f"seller exchange calls: {seller.exchange_calls} "
          f"(vs {ok} served requests — batching works)")
    print(f"fraud losses: {seller.fraud_mc} mc")
    for ev in seller.fraud_events:
        print(f"  - {ev}")
    assert ok == 49 and refused == 1
    assert seller.fraud_mc == PRICE_MC, "exactly one clawed-back request"

    bearer_revenue = sum(a for _s, a in seller.revenue)
    print(f"bearer-phase revenue (net of burns): {bearer_revenue} mc")
    # 49 served − 1 clawed back = 48 paid requests; burns per batch call
    assert bearer_revenue > 47 * PRICE_MC

    # --- PHASE 2: upgrade alice (best client) to a §9.1 channel ---------
    print("\n== phase 2: alice upgrades to a prefunded channel (§9.1) ==")
    N = 20
    hashes, secrets, payee = seller.open_channel(N)          # payee step 2
    payer = ChannelPayer(wallets["alice"])                   # payer steps 3-5
    mint_time = seller.client.descriptor()["mint_time"]
    info = payer.open(hashes, unit_mc=PRICE_MC, N=N,
                      expiry_ms=mint_time + 30 * 60_000)
    seller.accept_channel(payee, info, secrets, PRICE_MC, N)  # §9.1 verify
    print(f"channel {info.channel_id[:8]}… open: N={N}, unit={PRICE_MC} mc, "
          "funded+verified")

    for k in range(1, N + 1):
        draw = payer.draw(k)                       # local, no I/O
        request = {"query": f"drip query {k}",
                   "aicash": {"mint_id": MINT_ID, "tokens": [],
                              "channel_draw": draw}}
        resp = seller.handle_request(request, "alice")
        assert resp["status"] == 200, resp
    settled = payee.settle()                       # ONE exchange, one burn
    channel_revenue = sum(parse_token(t).amount_mc
                          for t in payee.settled_tokens)
    print(f"{N} drip requests served with 0 mint round trips per request; "
          f"settled {settled} mc in one call")
    assert settled == channel_revenue == N * PRICE_MC - compute_burn(
        N * PRICE_MC, seller._policy())

    # --- verification: the money actually moved -------------------------
    print("\n== verification ==")
    revenue_keys = [ledger_key(s) for s, _a in seller.revenue]
    _mt, results = seller.client.status(revenue_keys)
    assert all(r["state"] == "unspent" for r in results), results
    checked = sum(r["amount_mc"] for r in results)
    assert checked == bearer_revenue
    print(f"seller bearer revenue on ledger, unspent: {checked} mc "
          f"({len(results)} outputs verified via /v3/status)")

    settle_keys = [ledger_key(parse_token(t).secret)
                   for t in payee.settled_tokens]
    _mt, results = seller.client.status(settle_keys)
    assert all(r["state"] == "unspent" for r in results)
    print(f"seller channel revenue on ledger, unspent: {channel_revenue} mc")

    balances = {n: w.balance() for n, w in wallets.items()}
    supply = ledger.supply()
    print(f"client balances: {balances}")
    print(f"mint supply: {supply}")
    issued, burned = supply["cumulative_issued_mc"], supply["cumulative_burned_mc"]
    assert supply["outstanding_mc"] == issued - burned          # §3.6 invariant
    total_accounted = (sum(balances.values()) + bearer_revenue
                       + channel_revenue)
    assert total_accounted == supply["outstanding_mc"], (
        total_accounted, supply["outstanding_mc"])
    print(f"accounting identity holds: wallets + seller revenue = "
          f"{total_accounted} mc = outstanding = issued({issued}) − "
          f"burned({burned})")

    # --- integration-effort comparison ----------------------------------
    print("\n== integration effort: §9.2 bearer vs §9.1 channel ==")
    print(f"  bearer  (48 paid req): {seller.status_calls} status calls "
          f"(1/request) + {seller.exchange_calls} redeem calls; exposure = "
          f"up to {REDEEM_EVERY * PRICE_MC} mc/client/window (we ate "
          f"{seller.fraud_mc} mc); seller code: envelope parse + dedupe + "
          "status verify + batch redeem + spent-error retry loop (~90 lines)")
    print(f"  channel ({N} paid req): 1 open handshake (2 messages) + 1 "
          "accept (1 status batch) + 0 mint calls per request + 1 settle; "
          "ZERO double-spend exposure after accept; seller code: "
          "ChannelPayee.accept/on_draw/settle (~15 lines)")
    print("\nJOURNEY 3 COMPLETE — real money moved and verified.")


if __name__ == "__main__":
    main()
