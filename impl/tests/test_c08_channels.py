"""C08 — channel tests: the prefunded incremental channel against a live
in-process C06 mint.

Benchmark items B1–B9 from components/C08-channels.md are named in each
test's docstring.  All mint time comes from a FakeClock injected through
the Ledger (L17); the channel code itself never reads wall time.

Tranche capacity note (B7, OPEN-QUESTIONS #7): §9.1's "⌈N/max_batch⌉
tranches" (tranches of max_batch increments) is unsatisfiable against a
C06 mint, whose max_batch bounds len(inputs)+len(outputs) of a single
call — a max_batch-sized tranche can neither be funded (needs an input)
nor settled (k inputs + 1 output) in one call.  The recorded interim
resolution is a per-tranche capacity of max_batch − 1 with a single
consolidated funding input.  B7's pinned 50/50/20 split is exercised both
as pure tranche math (split_tranches(120, 50)) and live against a mint
with max_batch=51 (capacity 50).
"""

import hashlib
import json
import os
import tempfile
import unittest
import uuid
from typing import NamedTuple

from aicash.burncalc import BurnPolicy, compute_burn
from aicash.channels import (
    CHAIN_TAG,
    ChannelError,
    ChannelInfo,
    ChannelInvalid,
    ChannelPayee,
    ChannelPayer,
    DrawInvalid,
    derive_chain,
    split_tranches,
)
from aicash.clock import FakeClock
from aicash.ledgerstore import Ledger, OutputSpec
from aicash.mintapi import MintConfig, MintServer
from aicash.tokencodec import (
    b64u_decode,
    b64u_encode,
    canonical_json,
    format_token,
    ledger_key,
    new_secret,
)
from aicash.wallet import InsufficientFunds, MintClient, MintRejected, Wallet

T0 = 1_756_000_000_000
HOUR_MS = 3_600_000
DAY_MS = 86_400_000
MINT_ID = "testmint"

#: 1% rate, cap 1000, exempt <= 10 — makes burns visible in arithmetic.
POLICY = BurnPolicy(rate_ppm=10_000, cap_mc=1_000, exempt_below_mc=10)


class Mint(NamedTuple):
    port: int
    clock: FakeClock
    config: MintConfig
    ledger: Ledger


class RecordingClient(MintClient):
    """Counts every request that actually goes on the wire (B9)."""

    def __init__(self, base_url):
        super().__init__(base_url)
        self.requests = []  # (method, path)

    def _transport(self, method, path, body):
        self.requests.append((method, path))
        return super()._transport(method, path, body)

    def exchange_count(self):
        return sum(1 for _m, p in self.requests if p == "/v3/exchange")


class CorruptingPayer(ChannelPayer):
    """B6: a payer that funds a garbage lock at one ladder position.

    ``corrupt_at`` is the 1-based tranche-local increment index whose lock
    commitment is replaced by a random unrelated hash.
    """

    def __init__(self, wallet, corrupt_at: int):
        super().__init__(wallet)
        self._corrupt_at = corrupt_at

    def _tranche_lock_hashes(self, chain):
        hashes = super()._tranche_lock_hashes(chain)
        hashes[self._corrupt_at - 1] = ledger_key(os.urandom(32))
        return hashes


class ChannelTest(unittest.TestCase):
    maxDiff = None

    # ------------------------------------------------------------------
    # fixture
    # ------------------------------------------------------------------

    def start_mint(self, *, burn_policy=POLICY, max_batch=256) -> Mint:
        from aicash.signing import generate_keypair

        clock = FakeClock(T0)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        priv, pub = generate_keypair()
        ledger = Ledger(
            os.path.join(tmp.name, "ledger.sqlite3"),
            clock,
            burn_policy,
            recovery_window_ms=90 * DAY_MS,
            max_lock_expiry_ms=30 * DAY_MS,
        )
        config = MintConfig(
            mint_id=MINT_ID,
            baseline_model_class="frontier-2026",
            burn_policy=burn_policy,
            signing_private=priv,
            signing_public=pub,
            max_batch=max_batch,
        )
        server = MintServer(config, ledger)
        port = server.start()
        self.addCleanup(server.stop)
        return Mint(port, clock, config, ledger)

    def base_url(self, mint: Mint) -> str:
        return f"http://127.0.0.1:{mint.port}"

    def make_wallet(self, mint: Mint, client=None) -> Wallet:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        client = client or MintClient(self.base_url(mint))
        return Wallet(os.path.join(tmp.name, "wallet.sqlite3"), client, MINT_ID)

    def fund_wallet(self, mint: Mint, wallet: Wallet, amount_mc: int) -> int:
        """Operator funding (§7.1) received into the wallet; returns net."""
        secret = new_secret()
        mint.ledger.issue(
            [OutputSpec(amount_mc=amount_mc, secret_hash=ledger_key(secret))]
        )
        return wallet.receive(format_token(MINT_ID, amount_mc, secret))

    def open_channel(
        self,
        mint: Mint,
        *,
        n: int,
        unit: int = 1,
        expiry: int | None = None,
        fund: int = 5_000,
        payer_cls=ChannelPayer,
        payer_kwargs=None,
        payee_kwargs=None,
        payer_client=None,
        payee_client=None,
    ):
        """Full §9.1 open + accept; returns (payer, payee, info, secrets)."""
        expiry = expiry if expiry is not None else T0 + HOUR_MS
        wallet = self.make_wallet(mint, client=payer_client)
        self.fund_wallet(mint, wallet, fund)
        payer = payer_cls(wallet, **(payer_kwargs or {}))
        secrets = [new_secret() for _ in range(n)]
        hashes = [ledger_key(s) for s in secrets]
        info = payer.open(hashes, unit, n, expiry)
        payee = ChannelPayee(
            payee_client or MintClient(self.base_url(mint)),
            MINT_ID,
            **(payee_kwargs or {}),
        )
        payee.accept(info, secrets)
        return payer, payee, info, secrets

    def deliver(self, payer, payee, k: int) -> int:
        return payee.on_draw(payer.draw(k))

    def statuses(self, mint: Mint, hashes: list[str]) -> list[str]:
        _mt, results = MintClient(self.base_url(mint)).status(hashes)
        return [r["state"] for r in results]

    def claim_attempt(self, client, amount, token_secret, witness_bytes):
        """One hostile claim-path exchange; returns sorted rejection
        reasons, or None if the mint accepted it (the attack worked)."""
        try:
            client.exchange(
                str(uuid.uuid4()),
                [
                    {
                        "token": format_token(MINT_ID, amount, token_secret),
                        "witness": b64u_encode(witness_bytes),
                    }
                ],
                [
                    {
                        "amount_mc": amount,
                        "secret_hash": ledger_key(new_secret()),
                        "lock": None,
                    }
                ],
            )
        except MintRejected as exc:
            return sorted({e["reason"] for e in exc.errors})
        return None

    # ------------------------------------------------------------------
    # chain derivation (L7 structural; supports B2)
    # ------------------------------------------------------------------

    def test_chain_derivation_is_tagged_and_locks_are_plain(self):
        """B2 (structural half): every chain step uses the 12-byte tag,
        the seed is x_N, and lock commitments are PLAIN sha256 (L7)."""
        self.assertEqual(CHAIN_TAG, b"aicash-chain")
        self.assertEqual(len(CHAIN_TAG), 12)
        seed = os.urandom(32)
        chain = derive_chain(seed, 10)
        self.assertEqual(len(chain), 10)
        self.assertEqual(chain[-1], seed)  # chain[i] is x_{i+1}
        for i in range(1, 10):
            self.assertEqual(
                chain[i - 1], hashlib.sha256(CHAIN_TAG + chain[i]).digest()
            )
        self.assertEqual(derive_chain(seed, 1), [seed])
        with self.assertRaises(ValueError):
            derive_chain(b"short", 5)
        with self.assertRaises(ValueError):
            derive_chain(seed, 0)

    def test_b2_meta_untagged_chain_would_leak(self):
        """B2 (meta-test): recompute the chain WITHOUT the tag and show
        that lock_hash[i+1] would equal witness x_i — each public lock hash
        IS the claim witness of the lock below it — while the tagged chain
        has no such identity.  Guards against 'simplifying' the tag away
        (L7, spec R6)."""
        seed = os.urandom(32)
        n = 8
        untagged = [seed]
        for _ in range(n - 1):
            untagged.append(hashlib.sha256(untagged[-1]).digest())
        untagged.reverse()  # u_1..u_n with u_{i-1} = sha256(u_i)
        locks = [hashlib.sha256(u).digest() for u in untagged]
        for i in range(1, n):
            # THE LEAK: untagged lock i+1 (index i) is exactly witness i.
            self.assertEqual(locks[i], untagged[i - 1])
        tagged = derive_chain(seed, n)
        tagged_locks = [hashlib.sha256(x).digest() for x in tagged]
        for i in range(1, n):
            self.assertNotEqual(tagged_locks[i], tagged[i - 1])

    def test_split_tranches_math(self):
        """B7 (pure tranche math): the §9.1 split at capacity 50 gives
        exactly 50/50/20 for N=120."""
        self.assertEqual(split_tranches(120, 50), [50, 50, 20])
        self.assertEqual(split_tranches(50, 255), [50])
        self.assertEqual(split_tranches(100, 50), [50, 50])
        self.assertEqual(split_tranches(1, 1), [1])
        self.assertEqual(split_tranches(3, 1), [1, 1, 1])

    # ------------------------------------------------------------------
    # B1 — full lifecycle
    # ------------------------------------------------------------------

    def test_b1_full_lifecycle_reconciles(self):
        """B1: open N=50 u=1mc against a live mint, 30 draws, settle →
        payee +30 − burn, refund at expiry → payer recovers 20 − burn;
        mint supply reconciles (outstanding == issued − burned == wallet +
        settled + refunded)."""
        mint = self.start_mint()
        payer, payee, info, secrets = self.open_channel(mint, n=50, unit=1)

        self.assertEqual(payer._wallet.balance(), 4_900)  # 4950 net - 50 gross
        cumulative = 0
        for k in range(1, 31):
            cumulative = self.deliver(payer, payee, k)
        self.assertEqual(cumulative, 30)

        settle_burn = compute_burn(30, POLICY)
        settled = payee.settle()
        self.assertEqual(settled, 30 - settle_burn)

        # Refund refuses before expiry, then recovers the undrawn 20.
        with self.assertRaises(ChannelError):
            payer.refund()
        mint.clock.set(T0 + HOUR_MS)
        refund_burn = compute_burn(20, POLICY)
        recovered = payer.refund()
        self.assertEqual(recovered, 20 - refund_burn)

        # Supply reconciliation.
        desc = MintClient(self.base_url(mint)).descriptor()
        supply = desc["supply"]
        self.assertEqual(supply["cumulative_issued_mc"], 5_000)
        self.assertEqual(
            supply["outstanding_mc"],
            supply["cumulative_issued_mc"] - supply["cumulative_burned_mc"],
        )
        self.assertEqual(
            supply["outstanding_mc"],
            payer._wallet.balance() + settled + recovered,
        )
        # The settled and refunded tokens are live ledger entries.
        for tok in payee.settled_tokens + payer.refund_tokens:
            key = ledger_key(b64u_decode(tok.split(":")[4], expect_len=32))
            self.assertEqual(self.statuses(mint, [key]), ["unspent"])

    # ------------------------------------------------------------------
    # B2 — witness-leak regression (live half)
    # ------------------------------------------------------------------

    def test_b2_forged_witnesses_from_public_data_all_rejected(self):
        """B2: an adversary holding EVERYTHING public (all lock objects
        from status, the ChannelInfo, and the payee's own output secrets —
        a malicious payee pre-draw) attempts claim-path redemption of every
        output 1..N with witnesses derived from the public hashes.  Every
        attempt is rejected with lock_preimage_invalid and the channel is
        untouched."""
        mint = self.start_mint()
        n = 8
        payer, payee, info, secrets = self.open_channel(mint, n=n, unit=1)
        client = MintClient(self.base_url(mint))
        hashes = info.tranches[0]["secret_hashes"]
        _mt, results = client.status(hashes)
        locks = [r["lock"] for r in results]

        for i in range(n):  # 0-based output i+1
            candidates = [
                b64u_decode(locks[i]["preimage_hash"], expect_len=32),
                b64u_decode(locks[i]["refund_hash"], expect_len=32),
            ]
            if i + 1 < n:  # the untagged-leak analog: lock hash above
                above = b64u_decode(locks[i + 1]["preimage_hash"], expect_len=32)
                candidates.append(above)
                candidates.append(hashlib.sha256(CHAIN_TAG + above).digest())
                candidates.append(hashlib.sha256(above).digest())
            if i > 0:
                candidates.append(
                    b64u_decode(locks[i - 1]["preimage_hash"], expect_len=32)
                )
            for cand in candidates:
                reasons = self.claim_attempt(client, 1, secrets[i], cand)
                self.assertEqual(
                    reasons,
                    ["lock_preimage_invalid"],
                    f"forged witness on output {i + 1} was not rejected",
                )

        self.assertEqual(self.statuses(mint, hashes), ["unspent"] * n)
        # The channel still works end to end afterwards.
        self.assertEqual(self.deliver(payer, payee, 3), 3)
        self.assertEqual(payee.settle(), 3 - compute_burn(3, POLICY))

    # ------------------------------------------------------------------
    # B3 — clawback impossibility
    # ------------------------------------------------------------------

    def test_b3_payer_cannot_claw_back_drawn_value_pre_expiry(self):
        """B3: the payer holds every x_i and all public data but no payee
        output secret.  Claim-path attempts are rejected (no valid token —
        unknown key); refund-path attempts pre-expiry get lock_not_expired.
        The payee settles untouched afterwards."""
        mint = self.start_mint()
        n = 5
        payer, payee, info, secrets = self.open_channel(mint, n=n, unit=1)
        for k in range(1, 4):
            self.deliver(payer, payee, k)
        client = MintClient(self.base_url(mint))
        tranche = payer._tranches[0]

        # Refund path pre-expiry with the REAL refund secret: temporal gate.
        witness = b64u_encode(tranche["refund_secret"])
        try:
            client.exchange(
                str(uuid.uuid4()),
                [{"hash": h, "witness": witness} for h in tranche["secret_hashes"]],
                [
                    {
                        "amount_mc": n - compute_burn(n, POLICY),
                        "secret_hash": ledger_key(new_secret()),
                        "lock": None,
                    }
                ],
            )
            self.fail("pre-expiry refund was accepted")
        except MintRejected as exc:
            self.assertEqual(
                sorted({e["reason"] for e in exc.errors}), ["lock_not_expired"]
            )

        # Claim path: the payer's best fabricated tokens resolve to unknown
        # ledger keys — it does not hold s_i (§3.4, R1).
        for fabricated in (tranche["chain"][0], tranche["refund_secret"]):
            reasons = self.claim_attempt(
                client, 1, fabricated, tranche["chain"][0]
            )
            self.assertEqual(reasons, ["unknown"])

        self.assertEqual(
            self.statuses(mint, tranche["secret_hashes"]), ["unspent"] * n
        )
        self.assertEqual(payee.settle(), 3 - compute_burn(3, POLICY))

    # ------------------------------------------------------------------
    # B4 — undrawn increments unclaimable by the payee
    # ------------------------------------------------------------------

    def test_b4_undrawn_increments_unclaimable(self):
        """B4: with k=3 draws received, claim attempts on outputs 4..6 with
        every witness the payee can plausibly derive fail with
        lock_preimage_invalid."""
        mint = self.start_mint()
        n = 6
        payer, payee, info, secrets = self.open_channel(mint, n=n, unit=1)
        for k in range(1, 4):
            self.deliver(payer, payee, k)
        client = MintClient(self.base_url(mint))
        x3 = payee._tranches[0]["verified"][3]
        lock_hashes = info.tranches[0]["lock_hashes"]

        for i in range(4, n + 1):
            for cand in (
                x3,  # highest witness held
                hashlib.sha256(CHAIN_TAG + x3).digest(),  # goes DOWN only
                hashlib.sha256(x3).digest(),
                b64u_decode(lock_hashes[i - 1], expect_len=32),
            ):
                reasons = self.claim_attempt(client, 1, secrets[i - 1], cand)
                self.assertEqual(
                    reasons,
                    ["lock_preimage_invalid"],
                    f"undrawn output {i} was claimable",
                )
        # Verified draws remain settleable.
        self.assertEqual(payee.settle(), 3 - compute_burn(3, POLICY))

    # ------------------------------------------------------------------
    # B5 — subsumption
    # ------------------------------------------------------------------

    def test_b5_subsumption_recovers_missed_draws(self):
        """B5: deliver draws {1, 5, 17} only; on_draw(17) verifies
        cumulative 17 via tagged-chain subsumption; settle redeems 17."""
        mint = self.start_mint()
        payer, payee, info, secrets = self.open_channel(mint, n=50, unit=1)
        self.assertEqual(self.deliver(payer, payee, 1), 1)
        self.assertEqual(self.deliver(payer, payee, 5), 5)
        self.assertEqual(self.deliver(payer, payee, 17), 17)

        settled = payee.settle()
        self.assertEqual(settled, 17 - compute_burn(17, POLICY))
        hashes = info.tranches[0]["secret_hashes"]
        self.assertEqual(self.statuses(mint, hashes[:17]), ["spent"] * 17)
        self.assertEqual(self.statuses(mint, hashes[17:]), ["unspent"] * 33)

    # ------------------------------------------------------------------
    # B6 — garbage deep lock
    # ------------------------------------------------------------------

    def test_b6_garbage_deep_lock_bounded_loss(self):
        """B6: the payer funds a garbage lock at position 4.  The payee
        accepts at open (chain opacity is the design), on_draw(4) raises
        DrawInvalid (stop-work), and settle still recovers 1..3 — loss
        bounded to the one increment.  Even draws past the bad rung verify
        (their own locks are honest), keeping the bound at exactly one."""
        mint = self.start_mint()
        n = 6
        payer, payee, info, secrets = self.open_channel(
            mint,
            n=n,
            unit=1,
            payer_cls=lambda w: CorruptingPayer(w, corrupt_at=4),
        )
        for k in range(1, 4):
            self.deliver(payer, payee, k)
        with self.assertRaises(DrawInvalid):
            self.deliver(payer, payee, 4)
        self.assertEqual(payee.settle(), 3 - compute_burn(3, POLICY))

        # Loss bound: a draw ABOVE the garbage rung still verifies itself
        # (5's lock is honest); only increment 4 is ever lost.
        with self.assertRaises(DrawInvalid):
            self.deliver(payer, payee, 5)  # walk hits the garbage at 4
        self.assertEqual(payee.settle(), 1)  # increment 5 recovered
        hashes = info.tranches[0]["secret_hashes"]
        self.assertEqual(self.statuses(mint, [hashes[3]]), ["unspent"])

    # ------------------------------------------------------------------
    # B7 — tranche math, live
    # ------------------------------------------------------------------

    def test_b7_tranches_live_50_50_20(self):
        """B7: N=120 at tranche capacity 50 (mint max_batch=51 — see the
        module docstring on OPEN-QUESTIONS #7) → 3 tranches of 50/50/20,
        each with its own seed and refund secret; draw numbering spans
        tranches; settlement is ONE exchange per tranche with the §7.3 burn
        assessed per call."""
        mint = self.start_mint(max_batch=51)
        payee_client = RecordingClient(self.base_url(mint))
        payer, payee, info, secrets = self.open_channel(
            mint, n=120, unit=10, fund=20_000, payee_client=payee_client
        )
        self.assertEqual([t["count"] for t in info.tranches], [50, 50, 20])
        self.assertEqual([t["start"] for t in info.tranches], [1, 51, 101])
        # Own seed and refund secret per tranche.
        seeds = {t["chain"][-1] for t in payer._tranches}
        refunds = {t["refund_secret"] for t in payer._tranches}
        self.assertEqual(len(seeds), 3)
        self.assertEqual(len(refunds), 3)

        # Three draw messages recover all 120 increments across tranches.
        self.assertEqual(self.deliver(payer, payee, 50), 50)
        self.assertEqual(self.deliver(payer, payee, 100), 100)
        self.assertEqual(self.deliver(payer, payee, 120), 120)

        before = payee_client.exchange_count()
        settled = payee.settle()
        self.assertEqual(payee_client.exchange_count() - before, 3)
        # Burns per call: 500→5, 500→5, 200→2 at 1%.
        expected = (
            (500 - compute_burn(500, POLICY)) * 2
            + (200 - compute_burn(200, POLICY))
        )
        self.assertEqual(settled, expected)
        self.assertEqual(settled, 1_188)

        supply = MintClient(self.base_url(mint)).descriptor()["supply"]
        self.assertEqual(
            supply["outstanding_mc"],
            supply["cumulative_issued_mc"] - supply["cumulative_burned_mc"],
        )

    # ------------------------------------------------------------------
    # B8 — expiry discipline (L16)
    # ------------------------------------------------------------------

    def test_b8_unsettled_draws_refund_to_payer_at_expiry(self):
        """B8 (L16): 30 draws delivered but NEVER settled; at expiry the
        payer refunds ALL 50 outputs — drawn-but-unsettled value is the
        payee's loss, by design (settlement discipline is the payee's job;
        disclosed, not a bug).  The payee's late settlement attempt finds
        the outputs spent."""
        mint = self.start_mint()
        payer, payee, info, secrets = self.open_channel(mint, n=50, unit=1)
        for k in range(1, 31):
            self.deliver(payer, payee, k)

        mint.clock.set(T0 + HOUR_MS)  # expiry
        recovered = payer.refund()
        self.assertEqual(recovered, 50 - compute_burn(50, POLICY))

        # The payee is inside (past) the margin: refused without force ...
        with self.assertRaises(ChannelError):
            payee.settle()
        # ... and forcing it just meets the mint's refusal: already spent.
        try:
            payee.settle(force=True)
            self.fail("settlement after refund was accepted")
        except MintRejected as exc:
            self.assertEqual(
                sorted({e["reason"] for e in exc.errors}), ["spent"]
            )
        self.assertEqual(payee.settled_tokens, [])

    def test_b8_settle_refuses_inside_margin_unless_forced(self):
        """B8: at mint_time == expiry − grace_ms − margin the client-side
        check refuses settlement; force=True still succeeds pre-expiry."""
        mint = self.start_mint()
        expiry = T0 + HOUR_MS
        payer, payee, info, secrets = self.open_channel(
            mint, n=50, unit=1, payee_kwargs={"settle_margin_ms": 5_000}
        )
        for k in range(1, 11):
            self.deliver(payer, payee, k)

        grace = mint.config.grace_ms
        mint.clock.set(expiry - grace - 5_000)  # exactly the deadline
        with self.assertRaises(ChannelError):
            payee.settle()
        self.assertEqual(payee.settle(force=True), 10 - compute_burn(10, POLICY))

    # ------------------------------------------------------------------
    # B9 — locality
    # ------------------------------------------------------------------

    def test_b9_draws_make_zero_http_requests(self):
        """B9 + requirement 2: between open/accept and settle, 30 full
        draw/verify cycles put NOTHING on the wire — neither the payer's
        nor the payee's transport sees a single request."""
        mint = self.start_mint()
        payer_client = RecordingClient(self.base_url(mint))
        payee_client = RecordingClient(self.base_url(mint))
        payer, payee, info, secrets = self.open_channel(
            mint, n=50, unit=1, payer_client=payer_client, payee_client=payee_client
        )
        payer_before = len(payer_client.requests)
        payee_before = len(payee_client.requests)
        for k in range(1, 31):
            self.deliver(payer, payee, k)
        self.assertEqual(len(payer_client.requests), payer_before)
        self.assertEqual(len(payee_client.requests), payee_before)
        # Settlement then talks to the mint again (sanity).
        payee.settle()
        self.assertGreater(len(payee_client.requests), payee_before)

    # ------------------------------------------------------------------
    # requirement 6 — accept rejections (§9.1 verify)
    # ------------------------------------------------------------------

    def make_payee(self, mint, **kwargs) -> ChannelPayee:
        return ChannelPayee(MintClient(self.base_url(mint)), MINT_ID, **kwargs)

    def test_accept_rejects_tampered_lock_hash_list(self):
        """Req 6: locks on the ledger must equal the pinned hash list —
        a tampered ChannelInfo is rejected before any work."""
        mint = self.start_mint()
        wallet = self.make_wallet(mint)
        self.fund_wallet(mint, wallet, 5_000)
        payer = ChannelPayer(wallet)
        secrets = [new_secret() for _ in range(6)]
        info = payer.open([ledger_key(s) for s in secrets], 1, 6, T0 + HOUR_MS)
        info.tranches[0]["lock_hashes"][2] = ledger_key(os.urandom(32))
        with self.assertRaises(ChannelInvalid):
            self.make_payee(mint).accept(info, secrets)

    def test_accept_rejects_wrong_unit(self):
        """Req 6: funded amounts must match the declared unit, and the
        handshake-agreed unit is enforceable via expect_unit_mc."""
        mint = self.start_mint()
        wallet = self.make_wallet(mint)
        self.fund_wallet(mint, wallet, 5_000)
        payer = ChannelPayer(wallet)
        secrets = [new_secret() for _ in range(6)]
        info = payer.open([ledger_key(s) for s in secrets], 2, 6, T0 + HOUR_MS)
        # Payer lies about the unit after funding 2 mc outputs.
        info.unit_mc = 1
        with self.assertRaises(ChannelInvalid):
            self.make_payee(mint).accept(info, secrets)
        # Handshake check: funded honestly at 2, but 1 was agreed.
        info.unit_mc = 2
        with self.assertRaises(ChannelInvalid):
            self.make_payee(mint).accept(info, secrets, expect_unit_mc=1)

    def test_accept_rejects_short_expiry(self):
        """Req 6: T − mint_time below the payee's required lifetime margin
        is rejected."""
        mint = self.start_mint()
        wallet = self.make_wallet(mint)
        self.fund_wallet(mint, wallet, 5_000)
        payer = ChannelPayer(wallet)
        secrets = [new_secret() for _ in range(6)]
        info = payer.open([ledger_key(s) for s in secrets], 1, 6, T0 + 30_000)
        with self.assertRaises(ChannelInvalid):
            self.make_payee(mint, min_lifetime_ms=60_000).accept(info, secrets)

    def test_accept_rejects_unfunded_and_foreign_hashes(self):
        """Req 6: a channel whose outputs are not on the ledger, or whose
        funded hashes are not this payee's own, is rejected."""
        mint = self.start_mint()
        secrets = [new_secret() for _ in range(4)]
        hashes = [ledger_key(s) for s in secrets]
        chain = derive_chain(os.urandom(32), 4)
        fake = ChannelInfo(
            channel_id="fake",
            mint_id=MINT_ID,
            unit_mc=1,
            N=4,
            expiry_ms=T0 + HOUR_MS,
            tranches=[
                {
                    "start": 1,
                    "count": 4,
                    "secret_hashes": hashes,
                    "lock_hashes": [
                        b64u_encode(hashlib.sha256(x).digest()) for x in chain
                    ],
                    "expiry": T0 + HOUR_MS,
                }
            ],
        )
        with self.assertRaises(ChannelInvalid):
            self.make_payee(mint).accept(fake, secrets)  # unfunded: unknown
        with self.assertRaises(ChannelInvalid):
            # Secrets that do not hash to the funded list.
            self.make_payee(mint).accept(fake, [new_secret() for _ in range(4)])

    # ------------------------------------------------------------------
    # protocol edges
    # ------------------------------------------------------------------

    def test_draw_and_on_draw_edges(self):
        """Req 2/3 edges: §9.5 draw shape; out-of-range k; wrong channel
        routing; malformed witness; contradictory re-delivery."""
        mint = self.start_mint()
        payer, payee, info, secrets = self.open_channel(mint, n=6, unit=1)

        d = payer.draw(2)
        self.assertEqual(set(d), {"channel_id", "k", "x_k"})
        self.assertEqual(d["channel_id"], info.channel_id)
        self.assertEqual(payee.on_draw(d), 2)

        with self.assertRaises(ChannelError):
            payer.draw(0)
        with self.assertRaises(ChannelError):
            payer.draw(7)
        with self.assertRaises(ChannelError):
            payee.on_draw({"channel_id": "other", "k": 1, "x_k": d["x_k"]})
        with self.assertRaises(DrawInvalid):
            payee.on_draw(
                {"channel_id": info.channel_id, "k": 3, "x_k": "not-b64u!!"}
            )
        # Contradictory re-delivery of a verified index.
        with self.assertRaises(DrawInvalid):
            payee.on_draw(
                {
                    "channel_id": info.channel_id,
                    "k": 2,
                    "x_k": b64u_encode(os.urandom(32)),
                }
            )
        # Honest re-delivery is idempotent.
        self.assertEqual(payee.on_draw(payer.draw(2)), 2)

    def test_on_draw_accepts_envelope_roundtripped_draw(self):
        """§9.5 seam regression: a draw from ChannelPayer.draw(), round-
        tripped through C12 build_envelope/parse_envelope — which DECODES
        x_k to raw 32 bytes — feeds straight into on_draw and verifies,
        exactly as the raw wire dict (x_k a b64u string) does.  This is the
        cross-component type mismatch a cold integrator hit: parse the
        envelope, hand its channel_draw to on_draw.  Both the ChannelDraw
        object and its dict form work; a raw-bytes witness in a plain dict
        works too."""
        from aicash.receipts import ChannelDraw, build_envelope, parse_envelope

        mint = self.start_mint()
        payer, payee, info, secrets = self.open_channel(mint, n=6, unit=1)

        # Raw wire dict (x_k a b64u string) — the pre-existing path.
        wire = payer.draw(1)
        self.assertIsInstance(wire["x_k"], str)
        self.assertEqual(payee.on_draw(wire), 1)

        # The parsed-envelope path: x_k comes back as raw 32 bytes, and the
        # ChannelDraw preserves the channel_id for O(1) resolution.
        env = parse_envelope(
            build_envelope({"tool": "t"}, MINT_ID, [], channel_draw=payer.draw(2))
        )
        self.assertIsInstance(env.channel_draw, ChannelDraw)
        self.assertIsInstance(env.channel_draw.x_k, bytes)
        self.assertEqual(len(env.channel_draw.x_k), 32)
        self.assertEqual(env.channel_draw.channel_id, info.channel_id)
        # The ChannelDraw object itself feeds straight into on_draw ...
        self.assertEqual(payee.on_draw(env.channel_draw), 2)
        # ... and so does its dict form (x_k still raw bytes).
        env3 = parse_envelope(
            build_envelope({"tool": "t"}, MINT_ID, [], channel_draw=payer.draw(3))
        )
        self.assertEqual(payee.on_draw(env3.channel_draw._asdict()), 3)

        # A raw-bytes witness of the wrong length is still rejected, and an
        # object that is neither dict nor ChannelDraw is refused.
        with self.assertRaises(DrawInvalid):
            payee.on_draw({"channel_id": info.channel_id, "k": 4, "x_k": b"short"})
        with self.assertRaises(DrawInvalid):
            payee.on_draw(("not", "a", "draw"))

    def test_checkpoint_settlement(self):
        """Req 4/5: settlement at checkpoints — a second settle redeems
        only the increments verified since the first; a settle with
        nothing new makes no exchange call and returns 0."""
        mint = self.start_mint()
        payee_client = RecordingClient(self.base_url(mint))
        payer, payee, info, secrets = self.open_channel(
            mint, n=50, unit=1, payee_client=payee_client
        )
        for k in range(1, 11):
            self.deliver(payer, payee, k)
        self.assertEqual(payee.settle(), 10 - compute_burn(10, POLICY))
        for k in range(11, 18):
            self.deliver(payer, payee, k)
        self.assertEqual(payee.settle(), 7 - compute_burn(7, POLICY))

        before = payee_client.exchange_count()
        self.assertEqual(payee.settle(), 0)
        self.assertEqual(payee_client.exchange_count(), before)
        hashes = info.tranches[0]["secret_hashes"]
        self.assertEqual(self.statuses(mint, hashes[:17]), ["spent"] * 17)

    def test_refund_refuses_before_expiry_and_recovers_partial(self):
        """Req 5: refund refuses before expiry (mint clock); after a
        partial settlement it recovers exactly the remaining outputs."""
        mint = self.start_mint()
        payer, payee, info, secrets = self.open_channel(mint, n=20, unit=1)
        for k in range(1, 6):
            self.deliver(payer, payee, k)
        payee.settle()
        with self.assertRaises(ChannelError):
            payer.refund()
        mint.clock.set(T0 + HOUR_MS)
        self.assertEqual(payer.refund(), 15 - compute_burn(15, POLICY))
        # Nothing left: a second refund recovers zero.
        self.assertEqual(payer.refund(), 0)

    def test_payer_funds_by_hash_only(self):
        """Req 1 (structural): open() takes only hashes — handing it raw
        secrets fails validation, and the funded outputs' claim path stays
        exclusive to the payee."""
        mint = self.start_mint()
        wallet = self.make_wallet(mint)
        self.fund_wallet(mint, wallet, 5_000)
        payer = ChannelPayer(wallet)
        with self.assertRaises((ValueError, TypeError)):
            payer.open([new_secret() for _ in range(4)], 1, 4, T0 + HOUR_MS)

    # ------------------------------------------------------------------
    # wire form — ChannelInfo.to_json / from_json (§9.1 handoff)
    # ------------------------------------------------------------------

    def test_wire_roundtrip_is_canonical_and_lossless(self):
        """to_json emits deterministic §3.3 canonical JSON; from_json
        restores a ChannelInfo equal to the original (multi-tranche layout
        included), and re-serializing reproduces the identical string."""
        mint = self.start_mint(max_batch=51)
        payer, payee, info, secrets = self.open_channel(
            mint, n=120, unit=10, fund=20_000
        )
        wire = info.to_json()
        self.assertIsInstance(wire, str)
        # Canonical bytes: parsing and re-canonicalizing is the identity.
        self.assertEqual(wire.encode("utf-8"), canonical_json(json.loads(wire)))
        info2 = ChannelInfo.from_json(wire)
        self.assertEqual(info2, info)
        self.assertEqual(info2.to_json(), wire)
        # The wire object carries only public material: no chain seeds, no
        # refund secrets — exactly the six §9.1 handoff keys.
        self.assertEqual(
            set(json.loads(wire)),
            {"channel_id", "mint_id", "unit_mc", "N", "expiry_ms", "tranches"},
        )

    def test_wire_from_json_rejects_malformed(self):
        """from_json is strict: non-JSON, non-objects, missing keys, extra
        keys, and non-string input all raise ChannelInvalid before any
        channel state is touched."""
        good = ChannelInfo(
            channel_id="c",
            mint_id=MINT_ID,
            unit_mc=1,
            N=1,
            expiry_ms=T0 + HOUR_MS,
            tranches=[],
        ).to_json()
        obj = json.loads(good)
        missing = {k: v for k, v in obj.items() if k != "tranches"}
        extra = dict(obj, extra=1)
        for bad in (
            "not json{",
            "[]",
            '"a string"',
            json.dumps(missing),
            json.dumps(extra),
            b"bytes",
            None,
        ):
            with self.assertRaises(ChannelInvalid):
                ChannelInfo.from_json(bad)
        # accept() routes malformed wire strings through the same rejection.
        mint = self.start_mint()
        with self.assertRaises(ChannelInvalid):
            self.make_payee(mint).accept("not json{", [])

    def test_wire_two_process_channel_flow(self):
        """Two-'process' simulation: payer and payee share ONLY JSON
        strings — the payee's output hashes go payer-ward as a JSON list,
        the funded channel comes back as ChannelInfo.to_json(), and every
        §9.5 draw crosses as JSON — and the full §9.1 flow (accept, draws,
        settle, expiry refund) completes against a live mint and
        reconciles."""
        mint = self.start_mint()
        n, unit, expiry = 40, 10, T0 + HOUR_MS

        # "Process B" (payee): generate output secrets, wire the hashes.
        payee = ChannelPayee(MintClient(self.base_url(mint)), MINT_ID)
        secrets = [new_secret() for _ in range(n)]
        hashes_wire = json.dumps([ledger_key(s) for s in secrets])

        # "Process A" (payer): fund from the wire form, answer with JSON.
        wallet = self.make_wallet(mint)
        self.fund_wallet(mint, wallet, 5_000)
        payer = ChannelPayer(wallet)
        info = payer.open(json.loads(hashes_wire), unit, n, expiry)
        wire = info.to_json()

        # "Process B": accept the wire STRING directly, verify JSON draws.
        payee.accept(wire, secrets)
        for k in (1, 12, 25):
            draw_wire = canonical_json(payer.draw(k)).decode("utf-8")
            self.assertEqual(payee.on_draw(json.loads(draw_wire)), k)
        self.assertEqual(payee.settle(), 250 - compute_burn(250, POLICY))

        # Expiry: the payer refunds the 15 undrawn increments.
        mint.clock.set(expiry)
        self.assertEqual(payer.refund(), 150 - compute_burn(150, POLICY))
        supply = MintClient(self.base_url(mint)).descriptor()["supply"]
        self.assertEqual(
            supply["outstanding_mc"],
            supply["cumulative_issued_mc"] - supply["cumulative_burned_mc"],
        )

    # ------------------------------------------------------------------
    # estimate_open_cost — budgeting before open
    # ------------------------------------------------------------------

    def estimate_then_open(self, mint, wallet, unit, n):
        """estimate first (asserted read-only), open second; returns
        (estimate, actual above-locked cost of the open)."""
        payer = ChannelPayer(wallet)
        exchanges_before = (
            wallet.client.exchange_count()
            if isinstance(wallet.client, RecordingClient)
            else None
        )
        est = payer.estimate_open_cost(unit, n)
        if exchanges_before is not None:
            self.assertEqual(
                wallet.client.exchange_count(), exchanges_before,
                "estimate_open_cost must not exchange",
            )
        before = wallet.balance()
        secrets = [new_secret() for _ in range(n)]
        payer.open([ledger_key(s) for s in secrets], unit, n, T0 + HOUR_MS)
        actual = before - wallet.balance() - n * unit
        return est, actual

    def test_estimate_open_cost_matches_actual_multi_tranche(self):
        """Ladder scenario 1: N=120 u=10 at capacity 50 (max_batch=51) —
        three tranches, three consolidations; the estimate equals the
        actual above-locked cost of the subsequent open exactly, and the
        estimate itself puts no exchange on the wire."""
        mint = self.start_mint(max_batch=51)
        client = RecordingClient(self.base_url(mint))
        wallet = self.make_wallet(mint, client=client)
        self.fund_wallet(mint, wallet, 20_000)
        est, actual = self.estimate_then_open(mint, wallet, 10, 120)
        self.assertEqual(est, actual)
        self.assertGreater(est, 0)

    def test_estimate_open_cost_matches_actual_fragmented_ladder(self):
        """Ladder scenario 2: a wallet funded through three separate
        receives (fragmented ladder, single tranche, N=50 u=100) — the
        estimate still equals the actual cost exactly."""
        mint = self.start_mint()
        client = RecordingClient(self.base_url(mint))
        wallet = self.make_wallet(mint, client=client)
        for amount in (3_000, 2_000, 500):
            self.fund_wallet(mint, wallet, amount)
        est, actual = self.estimate_then_open(mint, wallet, 100, 50)
        self.assertEqual(est, actual)
        self.assertGreater(est, 0)

    def test_estimate_open_cost_validation(self):
        """estimate_open_cost validates like open: bad unit/N raise
        ValueError, an already-opened payer refuses, and a wallet that
        cannot cover the funding raises InsufficientFunds — all without
        touching the mint's ledger."""
        mint = self.start_mint()
        wallet = self.make_wallet(mint)
        self.fund_wallet(mint, wallet, 1_000)
        payer = ChannelPayer(wallet)
        with self.assertRaises(ValueError):
            payer.estimate_open_cost(0, 5)
        with self.assertRaises(ValueError):
            payer.estimate_open_cost(1, 0)
        with self.assertRaises(InsufficientFunds):
            payer.estimate_open_cost(1_000, 50)  # 50,000 mc >> held 990
        secrets = [new_secret() for _ in range(4)]
        payer.open([ledger_key(s) for s in secrets], 1, 4, T0 + HOUR_MS)
        with self.assertRaises(ChannelError):
            payer.estimate_open_cost(1, 4)

    # ------------------------------------------------------------------
    # payee wallet integration — settle() credits the wallet
    # ------------------------------------------------------------------

    def test_settle_with_real_wallet_uses_receive_batch_one_burn(self):
        """A payee constructed with a real C07 Wallet: settle() hands the
        call's settled tokens (one per tranche) to wallet.receive_batch —
        ONE exchange, ONE burn on the batch sum (§3.3 burn-once) — and
        returns the net credited mc; settled_tokens stays empty."""
        mint = self.start_mint(max_batch=51)
        wallet_client = RecordingClient(self.base_url(mint))
        payee_wallet = self.make_wallet(mint, client=wallet_client)
        payer, payee, info, secrets = self.open_channel(
            mint, n=120, unit=10, fund=20_000,
            payee_kwargs={"wallet": payee_wallet},
        )
        self.deliver(payer, payee, 50)
        self.deliver(payer, payee, 100)
        self.deliver(payer, payee, 120)
        nets = [g - compute_burn(g, POLICY) for g in (500, 500, 200)]
        batch_sum = sum(nets)  # 1,188
        credited = batch_sum - compute_burn(batch_sum, POLICY)  # 1,177
        before = wallet_client.exchange_count()
        self.assertEqual(payee.settle(), credited)
        # One batch redeem on the wallet's own client, not one per token.
        self.assertEqual(wallet_client.exchange_count() - before, 1)
        self.assertEqual(payee_wallet.balance(), credited)
        self.assertEqual(payee.settled_tokens, [])
        # Nothing new verified: a second settle credits nothing.
        self.assertEqual(payee.settle(), 0)
        self.assertEqual(payee_wallet.balance(), credited)

    def test_settle_with_wallet_receive_fallback_per_token(self):
        """A wallet WITHOUT receive_batch: settle() falls back to
        wallet.receive per settled token and returns the summed nets."""
        mint = self.start_mint(max_batch=51)

        class ReceiveOnlyWallet:
            def __init__(self, inner):
                self.inner = inner
                self.received = []

            def receive(self, token):
                self.received.append(token)
                return self.inner.receive(token)

        wallet = ReceiveOnlyWallet(self.make_wallet(mint))
        payer, payee, info, secrets = self.open_channel(
            mint, n=120, unit=10, fund=20_000,
            payee_kwargs={"wallet": wallet},
        )
        self.deliver(payer, payee, 50)
        self.deliver(payer, payee, 100)
        self.deliver(payer, payee, 120)
        nets = [g - compute_burn(g, POLICY) for g in (500, 500, 200)]
        credited = sum(n - compute_burn(n, POLICY) for n in nets)  # per-token
        self.assertEqual(payee.settle(), credited)
        self.assertEqual(len(wallet.received), 3)  # one token per tranche
        self.assertEqual(wallet.inner.balance(), credited)
        self.assertEqual(payee.settled_tokens, [])

    def test_settle_with_duck_typed_receive_batch_int_return(self):
        """A duck-typed wallet whose receive_batch returns a plain int is
        supported: settle() passes the batch through once and returns it."""
        mint = self.start_mint()

        class BatchWallet:
            def __init__(self, inner):
                self.inner = inner
                self.batches = []

            def receive_batch(self, tokens):
                self.batches.append(list(tokens))
                return sum(self.inner.receive(t) for t in tokens)

        wallet = BatchWallet(self.make_wallet(mint))
        payer, payee, info, secrets = self.open_channel(
            mint, n=50, unit=10, fund=6_000,
            payee_kwargs={"wallet": wallet},
        )
        for k in range(1, 31):
            self.deliver(payer, payee, k)
        settle_net = 300 - compute_burn(300, POLICY)  # 297
        credited = settle_net - compute_burn(settle_net, POLICY)  # 295
        self.assertEqual(payee.settle(), credited)
        self.assertEqual(len(wallet.batches), 1)
        self.assertEqual(len(wallet.batches[0]), 1)
        self.assertEqual(wallet.inner.balance(), credited)
        self.assertEqual(payee.settled_tokens, [])

    # ------------------------------------------------------------------
    # accept rejection messages
    # ------------------------------------------------------------------

    def test_accept_short_expiry_names_min_lifetime_parameter(self):
        """A too-soon-expiry rejection names the min_lifetime_ms parameter
        and its configured value, so a stranger payer can see exactly which
        payee-side knob refused the channel."""
        mint = self.start_mint()
        wallet = self.make_wallet(mint)
        self.fund_wallet(mint, wallet, 5_000)
        payer = ChannelPayer(wallet)
        secrets = [new_secret() for _ in range(4)]
        info = payer.open([ledger_key(s) for s in secrets], 1, 4, T0 + 30_000)
        with self.assertRaises(ChannelInvalid) as ctx:
            self.make_payee(mint, min_lifetime_ms=45_000).accept(info, secrets)
        msg = str(ctx.exception)
        self.assertIn("min_lifetime_ms", msg)
        self.assertIn("45000", msg)
