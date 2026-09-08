"""C09 — escrow tests against a live in-process C06 mint (spec §9.3, §9.4, §9.6).

Every test runs a real MintServer over real HTTP with a FakeClock injected
through the Ledger (L17).  Benchmark items B1–B8 from
components/C09-escrow.md are named in each test's docstring.
"""

import dataclasses
import hashlib
import json
import os
import tempfile
import unittest
import uuid
from fractions import Fraction
from typing import NamedTuple

from aicash.burncalc import BurnPolicy
from aicash.clock import FakeClock
from aicash.escrow import (
    Arbiter,
    CommitThenAccept,
    DeadlineError,
    EscrowError,
    EscrowPayee,
    EscrowPayer,
    FundingInfo,
    FundingInvalid,
    LateReveal,
    QuorumNotMet,
    compute_deadlines,
    make_dispute_record,
    rung_composition,
)
from aicash.ledgerstore import Ledger, OutputSpec
from aicash.mintapi import MintConfig, MintServer
from aicash.signing import attach_sig, generate_keypair, verify_obj
from aicash.receipts import verify_dispute
from aicash.tokencodec import (
    b64u_decode,
    b64u_encode,
    canonical_json,
    format_token,
    ledger_key,
    new_secret,
)
from aicash.wallet import MintClient, MintRejected

T0 = 1_756_000_000_000
MIN = 60_000
HOUR = 3_600_000
DAY_MS = 86_400_000
MINT_ID = "testmint"
GRACE = 5_000  # MintConfig default grace_ms
MARGIN = 60_000  # settlement / redemption margin used throughout

#: 1% rate, cap 1000, exempt <= 10 — makes burns visible in arithmetic.
POLICY = BurnPolicy(rate_ppm=10_000, cap_mc=1_000, exempt_below_mc=10)


def sha256_b64u(data: bytes) -> str:
    return b64u_encode(hashlib.sha256(data).digest())


class Mint(NamedTuple):
    port: int
    clock: FakeClock
    ledger: Ledger


class Job(NamedTuple):
    payer: EscrowPayer
    payee: EscrowPayee
    fee_acct: EscrowPayee
    info: FundingInfo
    attestations: list
    expiries: dict
    milestones: list
    pubs: dict


class EscrowTest(unittest.TestCase):
    maxDiff = None

    # ------------------------------------------------------------------
    # fixture
    # ------------------------------------------------------------------

    def start_mint(self) -> Mint:
        clock = FakeClock(T0)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        priv, pub = generate_keypair()
        ledger = Ledger(
            os.path.join(tmp.name, "ledger.sqlite3"),
            clock,
            POLICY,
            recovery_window_ms=90 * DAY_MS,
            max_lock_expiry_ms=30 * DAY_MS,
        )
        config = MintConfig(
            mint_id=MINT_ID,
            baseline_model_class="frontier-2026",
            burn_policy=POLICY,
            signing_private=priv,
            signing_public=pub,
            max_batch=1024,
        )
        server = MintServer(config, ledger)
        port = server.start()
        self.addCleanup(server.stop)
        return Mint(port, clock, ledger)

    def client(self, mint: Mint) -> MintClient:
        return MintClient(f"http://127.0.0.1:{mint.port}")

    def issue_token(self, mint: Mint, amount_mc: int) -> str:
        secret = new_secret()
        mint.ledger.issue(
            [OutputSpec(amount_mc=amount_mc, secret_hash=ledger_key(secret))]
        )
        return format_token(MINT_ID, amount_mc, secret)

    @staticmethod
    def deadlines(m: int) -> tuple[int, int, int]:
        """(evidence_deadline, decision_deadline, minimum expiry) for
        milestone m, on the T0 clock."""
        ev = T0 + m * HOUR
        dec = ev + 10 * MIN
        return ev, dec, compute_deadlines(ev, dec, GRACE, MARGIN)

    def panel(self, n: int = 3, k: int = 2, ids=None) -> tuple[list, dict]:
        ids = ids or [f"a{j}" for j in range(1, n + 1)]
        arbs = [Arbiter(i) for i in ids]
        pubs = {a.arbiter_id: a.public for a in arbs}
        for a in arbs:
            a.set_panel(k, pubs)
        return arbs, pubs

    def make_job(
        self,
        mint: Mint,
        job_id: str,
        arbs: list,
        milestone_rungs: dict,
        fee_mc: int = 0,
        funding_mc: int = 0,
        verify: bool = True,
    ) -> Job:
        """Attest, generate output hashes, fund, and (optionally) run the
        mandatory §9.3 funding verification for both secret holders."""
        client = self.client(mint)
        pubs = {a.arbiter_id: a.public for a in arbs}
        attestations = []
        milestones = []
        expiries = {}
        for m, rungs in sorted(milestone_rungs.items()):
            evd, dec, expiry = self.deadlines(m)
            milestones.append(
                {"m": m, "evidence_deadline": evd, "decision_deadline": dec}
            )
            expiries[m] = expiry
            for a in arbs:
                attestations.extend(a.attest_rungs(job_id, m, rungs, fee_mc=fee_mc))
        payee = EscrowPayee(client, MINT_ID, pubs)
        fee_acct = EscrowPayee(client, MINT_ID, pubs)
        hashes = dict(payee.generate_output_hashes(attestations))
        hashes.update(fee_acct.generate_output_hashes(attestations, kinds=("fee",)))
        token = self.issue_token(mint, funding_mc)
        payer = EscrowPayer(
            client,
            MINT_ID,
            [token],
            settlement_margin_ms=MARGIN,
            arbiter_pubs=pubs,
        )
        info = payer.fund(job_id, milestones, attestations, hashes, expiries)
        if verify:
            payee.verify_funding(info, attestations)
            fee_acct.verify_funding(info, attestations)
        return Job(payer, payee, fee_acct, info, attestations, expiries, milestones, pubs)

    # ------------------------------------------------------------------
    # B1 — the §9.6 worked example, end to end, exact numbers
    # ------------------------------------------------------------------

    def test_b1_worked_example(self):
        """B1: 90,000 mc budget, n=3/k=2 panel, 9,000 mc rung sets
        (8×1000+9×100+10×10) + 1,000 mc fees; milestone 1 full release
        (27,000 + 3,000 fees), milestone 2 split 60/40 (16,200 payee /
        10,800 refund via 5×1000+4×100 per arbiter), milestone 3 full
        refund at T3; every balance and burn reconciles on a live mint."""
        mint = self.start_mint()
        arbs, pubs = self.panel(3, 2)
        rungs = rung_composition(9_000, (1_000, 100, 10))
        self.assertEqual(sorted(rungs, reverse=True), [1_000] * 8 + [100] * 9 + [10] * 10)
        job = self.make_job(
            mint, "b1", arbs, {1: rungs, 2: rungs, 3: rungs},
            fee_mc=1_000, funding_mc=92_000,
        )
        # Funding: 92,000 in → 90,000 escrowed + 920 burn + 1,080 change.
        self.assertEqual(job.info.burn_mc, 920)
        self.assertEqual(job.info.change_mc, 1_080)
        self.assertEqual(job.payer.balance(), 1_080)
        # 3 milestones × (81 rungs + 3 fees) by-hash locked outputs.
        self.assertEqual(len(job.info.outputs), 3 * (81 + 3))

        # -- Milestone 1: 2-of-3 release quorum; the dissenter reveals too.
        ev1 = {"job": "b1", "m": 1, "evidence": "delivered"}
        v1 = arbs[0].vote("b1", 1, ev1, "release")
        v2 = arbs[1].vote("b1", 1, ev1, "release")
        v3 = arbs[2].vote("b1", 1, ev1, "refund")
        self.assertTrue(all(verify_obj(v, pubs[v["arbiter_id"]]) for v in (v1, v2, v3)))
        reveals1 = [a.reveal("b1", 1, 1, votes=[v1, v2]) for a in arbs]
        self.assertTrue(all(r["quorum"] for r in reveals1))
        self.assertEqual(job.payee.redeem(1, reveals1), 26_730)  # 27,000 − 270
        self.assertEqual(job.fee_acct.redeem(1, reveals1), 2_970)  # 3,000 − 30

        # -- Milestone 2: split 60/40 — 5,400 mc of each 9,000 mc set.
        ev2 = {"job": "b1", "m": 2, "evidence": "partial"}
        split = Fraction(3, 5)
        va = arbs[0].vote("b1", 2, ev2, split)
        vb = arbs[1].vote("b1", 2, ev2, split)
        vc = arbs[2].vote("b1", 2, ev2, "refund")
        reveals2 = [a.reveal("b1", 2, split, votes=[va, vb]) for a in arbs]
        for r in reveals2:
            amounts = sorted(
                (e["amount_mc"] for e in r["preimages"] if e["rung"] != "fee"),
                reverse=True,
            )
            self.assertEqual(amounts, [1_000] * 5 + [100] * 4)  # the §9.6 rungs
        self.assertEqual(job.payee.redeem(2, reveals2), 16_038)  # 16,200 − 162
        self.assertEqual(job.fee_acct.redeem(2, reveals2), 2_970)  # fee on split too
        # §10.2 dispute-outcome record with decision "split" and the votes.
        rec = make_dispute_record(
            "b1", 2, 27_000, 16_200, ["a1", "a2", "a3"], ev2, T0,
            votes=[va, vb, vc],
        )
        self.assertEqual(rec["decision"], "split")
        signed = arbs[0].sign_dispute(rec)
        self.assertTrue(verify_dispute(signed, pubs))
        # Remainder refunds at T2.
        mint.clock.set(job.expiries[2])
        self.assertEqual(job.payer.refund_expired(2), 10_692)  # 10,800 − 108

        # -- Milestone 3: never started; full refund (incl. fees) at T3.
        mint.clock.set(job.expiries[3])
        self.assertEqual(job.payer.refund_expired(3), 29_700)  # 30,000 − 300
        self.assertEqual(job.payer.refund_expired(1), 0)  # m1 fully settled

        # -- Reconciliation against the live ledger.
        supply = mint.ledger.supply()
        burns = 920 + 270 + 30 + 162 + 30 + 108 + 300
        self.assertEqual(burns, 1_820)
        self.assertEqual(supply["cumulative_issued_mc"], 92_000)
        self.assertEqual(supply["cumulative_burned_mc"], burns)
        self.assertEqual(
            supply["outstanding_mc"],
            supply["cumulative_issued_mc"] - supply["cumulative_burned_mc"],
        )
        self.assertEqual(job.payee.balance(), 26_730 + 16_038)
        self.assertEqual(job.fee_acct.balance(), 2_970 + 2_970)
        self.assertEqual(job.payer.balance(), 1_080 + 10_692 + 29_700)
        self.assertEqual(
            job.payee.balance() + job.fee_acct.balance() + job.payer.balance() + burns,
            92_000,
        )

    # ------------------------------------------------------------------
    # B2 — refund-after-delivery prevention
    # ------------------------------------------------------------------

    def test_b2_deadline_ordering_prevents_refund_after_delivery(self):
        """B2: with conformant deadlines a payee revealed to at the WORST
        allowed moment (exactly decision_deadline) still settles before
        expiry and outside the grace convention; compute_deadlines and
        fund() reject any ordering that would break that."""
        mint = self.start_mint()
        arbs, _pubs = self.panel(1, 1, ids=["solo"])
        job = self.make_job(mint, "b2", arbs, {1: [400]}, funding_mc=500)
        evd, dec, expiry = self.deadlines(1)
        self.assertEqual(job.expiries[1], expiry)
        self.assertEqual(expiry - dec, GRACE + MARGIN)

        # Worst case allowed by the convention: preimages arrive exactly at
        # the decision deadline.
        mint.clock.set(dec)
        v = arbs[0].vote("b2", 1, {"e": 1}, "release")
        r = arbs[0].reveal("b2", 1, 1, votes=[v])
        # The claim commits now, strictly before expiry, and the submission
        # is not within grace_ms of expiry (client convention headroom).
        self.assertGreater(expiry - dec, GRACE)
        self.assertEqual(job.payee.redeem(1, [r]), 396)  # 400 − 4 burn

        # Conversely: orderings that would break the guarantee are refused.
        with self.assertRaises(DeadlineError):
            compute_deadlines(dec, dec, GRACE, MARGIN)  # decision <= evidence
        with self.assertRaises(DeadlineError):
            compute_deadlines(evd, dec, GRACE, 0)  # zero margin: reveal at
            # decision_deadline could land on the refund path boundary
        with self.assertRaises(DeadlineError):
            compute_deadlines(evd, dec, -1, MARGIN)
        with self.assertRaises(DeadlineError):
            compute_deadlines(1.5, dec, GRACE, MARGIN)  # no floats, ever

        # And fund() enforces the same arithmetic at fund time (req 6).
        arbs2, pubs2 = self.panel(1, 1, ids=["solo2"])
        atts = arbs2[0].attest_rungs("b2bad", 1, [400])
        client = self.client(mint)
        payee = EscrowPayee(client, MINT_ID, pubs2)
        hashes = payee.generate_output_hashes(atts)
        payer = EscrowPayer(
            client, MINT_ID, [self.issue_token(mint, 500)],
            settlement_margin_ms=MARGIN, arbiter_pubs=pubs2,
        )
        with self.assertRaises(DeadlineError):
            payer.fund(
                "b2bad",
                [{"m": 1, "evidence_deadline": evd, "decision_deadline": dec}],
                atts,
                hashes,
                {1: expiry - 1},  # one ms below the conformant minimum
            )

    # ------------------------------------------------------------------
    # B3 — the self-invented-preimage attack
    # ------------------------------------------------------------------

    def test_b3_self_invented_preimage_attack(self):
        """B3: a payer funds rung 2 with its own hash instead of the
        attested one → verify_funding raises FundingInvalid NAMING rung 2;
        skipping verification (sandboxed) lets the attack succeed — the
        payee cannot settle rung 2 after delivery and the payer refunds it
        — proving the check is load-bearing."""
        mint = self.start_mint()
        client = self.client(mint)
        arb = Arbiter("solo")
        pubs = {"solo": arb.public}
        atts = arb.attest_rungs("b3", 1, [100, 100, 100])
        payee = EscrowPayee(client, MINT_ID, pubs)
        hashes = payee.generate_output_hashes(atts)
        _evd, _dec, expiry = self.deadlines(1)

        # The ATTACKER funds manually: rung 2 locked to its own preimage.
        attacker_preimage = new_secret()
        refund_secret = new_secret()
        outputs, records = [], []
        for a in atts:
            key = (1, "solo", a["rung"])
            funded_hash = a["preimage_hash"]
            if a["rung"] == 2:
                funded_hash = sha256_b64u(attacker_preimage)  # self-invented
            outputs.append(
                {
                    "amount_mc": 100,
                    "secret_hash": hashes[key],
                    "lock": {
                        "preimage_hash": funded_hash,
                        "expiry": expiry,
                        "refund_hash": sha256_b64u(refund_secret),
                    },
                }
            )
            records.append(
                {  # the payer LIES in the handed-over info: claims attested
                    "milestone": 1,
                    "arbiter_id": "solo",
                    "rung": a["rung"],
                    "amount_mc": 100,
                    "secret_hash": hashes[key],
                    "preimage_hash": a["preimage_hash"],
                    "expiry": expiry,
                }
            )
        token = self.issue_token(mint, 310)  # 300 + 3 burn + 7 change
        change = new_secret()
        outputs.append(
            {"amount_mc": 7, "secret_hash": ledger_key(change), "lock": None}
        )
        client.exchange(str(uuid.uuid4()), [token], outputs)
        info = FundingInfo(
            job_id="b3", mint_id=MINT_ID, outputs=tuple(records), expiries={1: expiry}
        )

        # WITH the mandatory check: caught before any work, naming rung 2.
        with self.assertRaises(FundingInvalid) as ctx:
            payee.verify_funding(info, atts)
        self.assertEqual(ctx.exception.rung, 2)
        self.assertEqual(ctx.exception.milestone, 1)
        self.assertIn("rung 2", str(ctx.exception))

        # WITHOUT the check (sandboxed negligent payee): work is delivered,
        # the arbiter releases honestly, and the attack succeeds.
        v = arb.vote("b3", 1, {"e": 1}, "release")
        r = arb.reveal("b3", 1, 1, votes=[v])
        with self.assertRaises(EscrowError):
            payee.redeem(1, [r])  # unverified redemption is refused by default
        with self.assertRaises(MintRejected) as mctx:
            payee.redeem(1, [r], allow_unverified=True)
        errors = mctx.exception.errors
        self.assertIn(
            {"index": 2, "kind": "input", "reason": "lock_preimage_invalid"}, errors
        )
        # The payer waits out the expiry and takes everything back.
        mint.clock.set(expiry)
        refund_inputs = [
            {"hash": rec["secret_hash"], "witness": b64u_encode(refund_secret)}
            for rec in records
        ]
        out = new_secret()
        client.exchange(
            str(uuid.uuid4()),
            refund_inputs,
            [{"amount_mc": 297, "secret_hash": ledger_key(out), "lock": None}],
        )
        # Delivery happened; the payer holds the work AND the money back.
        self.assertEqual(mint.ledger.supply()["outstanding_mc"], 310 - 3 - 3)

    # ------------------------------------------------------------------
    # B4 — defection bounds (both directions), value/n, provable
    # ------------------------------------------------------------------

    def test_b4_early_reveal_defection_bounded_and_provable(self):
        """B4: one arbiter reveals WITHOUT quorum (force path) → the payee
        gains exactly value/n = 9,000 mc, and the evidence tuple (the
        defector's signed vote + its self-marked forced reveal) proves the
        defection; honest arbiters still refuse."""
        mint = self.start_mint()
        arbs, pubs = self.panel(3, 2)
        job = self.make_job(
            mint, "b4a", arbs, {1: [9_000]}, funding_mc=28_500
        )
        ev = {"job": "b4a", "m": 1}
        v1 = arbs[0].vote("b4a", 1, ev, "release")
        # Honest arbiters refuse below quorum (requirement 3).
        with self.assertRaises(QuorumNotMet):
            arbs[1].reveal("b4a", 1, 1, votes=[v1])
        # The defector force-reveals; the reveal is NOT silent about it.
        r1 = arbs[0].reveal("b4a", 1, 1, votes=[v1], force=True)
        self.assertFalse(r1["quorum"])
        net = job.payee.redeem(1, [r1])
        self.assertEqual(net + 90, 9_000)  # gains exactly value/n (gross)
        # Evidence tuple: signed vote verifies, revealed preimage is the
        # defector's own attested rung.
        self.assertTrue(verify_obj(v1, pubs["a1"]))
        att = next(
            a for a in job.attestations
            if a["arbiter_id"] == "a1" and a["milestone"] == 1 and a["rung"] == 0
        )
        self.assertEqual(
            sha256_b64u(b64u_decode(r1["preimages"][0]["preimage"], expect_len=32)),
            att["preimage_hash"],
        )
        # The other 2/3 of the milestone refunds to the payer at expiry.
        mint.clock.set(job.expiries[1])
        self.assertEqual(job.payer.refund_expired(1) + 180, 18_000)

    def test_b4_silent_arbiter_bounded_and_attributed(self):
        """B4: quorum reached but one arbiter stays silent → the payee is
        short exactly value/n = 9,000 mc after expiry, and the §10.2
        dispute record (vote set attached) attributes the defection."""
        mint = self.start_mint()
        arbs, pubs = self.panel(3, 2)
        job = self.make_job(mint, "b4b", arbs, {1: [9_000]}, funding_mc=28_500)
        ev = {"job": "b4b", "m": 1}
        votes = [a.vote("b4b", 1, ev, "release") for a in arbs]
        # a3 voted release with the quorum — then never reveals.
        reveals = [a.reveal("b4b", 1, 1, votes=votes[:2]) for a in arbs[:2]]
        net = job.payee.redeem(1, reveals)
        self.assertEqual(net + 180, 18_000)  # short exactly 9,000 gross
        mint.clock.set(job.expiries[1])
        self.assertEqual(job.payer.refund_expired(1) + 90, 9_000)
        # Dispute record: split outcome, full signed vote set attached —
        # a3's signed release vote plus its refunded rungs attribute the
        # silence to a3.
        rec = make_dispute_record(
            "b4b", 1, 27_000, 18_000, ["a1", "a2", "a3"], ev,
            job.expiries[1], votes=votes,
        )
        self.assertEqual(rec["decision"], "split")
        self.assertIn(votes[2], rec["votes"])
        self.assertTrue(verify_obj(votes[2], pubs["a3"]))
        signed = arbs[0].sign_dispute(rec)
        self.assertTrue(verify_dispute(signed, pubs))

    # ------------------------------------------------------------------
    # B5 — decision-neutral fees
    # ------------------------------------------------------------------

    def test_b5_fee_neutrality(self):
        """B5: fees are collected on release AND refund decisions; an
        unrendered decision refunds the fee to the payer; and a fee output
        locked to a release preimage is structurally impossible via the
        API."""
        mint = self.start_mint()
        arbs, _pubs = self.panel(1, 1, ids=["solo"])
        job = self.make_job(
            mint, "b5", arbs, {1: [500], 2: [500], 3: [500]},
            fee_mc=100, funding_mc=2_000,
        )
        a = arbs[0]
        # m1: RELEASE decision → fee collected.
        v1 = a.vote("b5", 1, {"m": 1}, "release")
        r1 = a.reveal("b5", 1, 1, votes=[v1])
        self.assertEqual(job.payee.redeem(1, [r1]), 495)
        self.assertEqual(job.fee_acct.redeem(1, [r1]), 99)  # 100 − 1 burn
        # m2: REFUND decision → payee gets nothing, fee STILL collected.
        v2 = a.vote("b5", 2, {"m": 2}, "refund")
        r2 = a.reveal("b5", 2, 0, votes=[v2])
        self.assertEqual(
            [e["rung"] for e in r2["preimages"]], ["fee"]
        )  # no rung preimages on a refund decision
        self.assertEqual(job.payee.redeem(2, [r2]), 0)
        self.assertEqual(job.fee_acct.redeem(2, [r2]), 99)
        mint.clock.set(job.expiries[2])
        self.assertEqual(job.payer.refund_expired(2), 495)  # value refunds
        # m3: SILENCE (no decision rendered) → fee refunds to the payer.
        mint.clock.set(job.expiries[3])
        self.assertEqual(job.payer.refund_expired(3), 594)  # 500 + 100 − 6
        # Structural impossibility: an attestation set that locks a "fee"
        # output to a rung release preimage is refused outright, at fund
        # time and at verification time.
        evil_arb = Arbiter("solo2")
        atts = evil_arb.attest_rungs("evil", 1, [500])
        evil_fee = attach_sig(
            {
                "kind": "attestation",
                "v": 4,
                "job_id": "evil",
                "milestone": 1,
                "arbiter_id": "solo2",
                "rung": "fee",
                "amount_mc": 100,
                "preimage_hash": atts[0]["preimage_hash"],  # the release hash!
            },
            evil_arb._private,
        )
        client = self.client(mint)
        pubs2 = {"solo2": evil_arb.public}
        payee2 = EscrowPayee(client, MINT_ID, pubs2)
        fee2 = EscrowPayee(client, MINT_ID, pubs2)
        hashes2 = dict(payee2.generate_output_hashes(atts + [evil_fee]))
        hashes2.update(
            fee2.generate_output_hashes(atts + [evil_fee], kinds=("fee",))
        )
        evd, dec, expiry = self.deadlines(1)
        payer2 = EscrowPayer(
            client, MINT_ID, [self.issue_token(mint, 700)],
            settlement_margin_ms=MARGIN, arbiter_pubs=pubs2,
        )
        with self.assertRaises(EscrowError) as ctx:
            payer2.fund(
                "evil",
                [{"m": 1, "evidence_deadline": evd, "decision_deadline": dec}],
                atts + [evil_fee],
                hashes2,
                {1: expiry},
            )
        self.assertIn("fee", str(ctx.exception))
        with self.assertRaises(FundingInvalid):
            payee2.verify_funding(
                FundingInfo("evil", MINT_ID, (), {1: expiry}), atts + [evil_fee]
            )

    # ------------------------------------------------------------------
    # B6 — commit-then-accept (§9.4)
    # ------------------------------------------------------------------

    def test_b6_commit_then_accept(self):
        """B6: happy path; a payer reveal after the §9.4 deadline raises
        LateReveal and is recorded as a refusal; a worker never starts
        without on-ledger verification (funds absent → worker_verify
        raises)."""
        mint = self.start_mint()
        client = self.client(mint)

        # Happy path.
        cta = CommitThenAccept(client, MINT_ID, redemption_margin_ms=MARGIN)
        wh = cta.worker_hash()
        cta.payer_commit(wh, 500, T0 + HOUR, [self.issue_token(mint, 600)])
        cta.worker_verify()  # committed funds confirmed before work starts
        preimage = cta.payer_reveal()
        self.assertEqual(cta.worker_redeem(preimage), 495)  # 500 − 5 burn

        # Late reveal: past expiry − grace_ms − redemption_margin.
        cta2 = CommitThenAccept(client, MINT_ID, redemption_margin_ms=MARGIN)
        wh2 = cta2.worker_hash()
        expiry2 = T0 + 2 * HOUR
        cta2.payer_commit(wh2, 500, expiry2, [self.issue_token(mint, 600)])
        deadline = cta2.reveal_deadline()
        self.assertEqual(deadline, expiry2 - GRACE - MARGIN)
        mint.clock.set(deadline + 1)
        with self.assertRaises(LateReveal):
            cta2.payer_reveal()
        self.assertEqual(len(cta2.refusals), 1)
        refusal = cta2.refusals[0]
        self.assertEqual(refusal["kind"], "late_reveal")
        self.assertEqual(refusal["party"], "payer")
        self.assertEqual(refusal["reveal_deadline"], deadline)
        # §10.2: the episode is recorded as a payer refusal.
        rec = make_dispute_record(
            "cta-job", 1, 500, 0, ["arb"], {"cta": True},
            deadline + 1, votes=[], refusals=["payer"],
        )
        self.assertEqual(rec["decision"], "refunded")
        self.assertEqual(rec["refusals"], ["payer"])
        # The worker was never trapped: funds return to the payer at expiry.
        mint.clock.set(expiry2)
        self.assertEqual(cta2.payer_refund(), 495)

        # Funds absent: verification refuses before any work.
        cta3 = CommitThenAccept(client, MINT_ID, redemption_margin_ms=MARGIN)
        cta3.worker_hash()
        with self.assertRaises(FundingInvalid):
            cta3.worker_verify(amount_mc=500, expiry=T0 + 3 * HOUR)

    # ------------------------------------------------------------------
    # B7 — k-of-n arithmetic and vote binding
    # ------------------------------------------------------------------

    def test_b7_kofn_arithmetic_and_vote_binding(self):
        """B7: k=2, n=3 — reveal succeeds with 2 valid votes and refuses
        with 1; votes are C05-verifiable and bound to (job_id, milestone,
        evidence hash), so tampered, foreign-evidence, impostor, and
        duplicate votes never count toward quorum."""
        mint = self.start_mint()
        arbs, pubs = self.panel(3, 2)
        job = self.make_job(mint, "b7", arbs, {1: [300]}, funding_mc=1_000)
        ev = {"job": "b7", "deliverable": "d1"}
        v1 = arbs[0].vote("b7", 1, ev, "release")
        v2 = arbs[1].vote("b7", 1, ev, "release")

        with self.assertRaises(QuorumNotMet):
            arbs[0].reveal("b7", 1, 1, votes=[v1])  # 1 < k
        with self.assertRaises(QuorumNotMet):
            arbs[0].reveal("b7", 1, 1, votes=[v1, v1])  # duplicates don't count
        # A vote bound to DIFFERENT evidence does not count.
        v_other = arbs[2].vote("b7", 1, {"job": "b7", "deliverable": "other"}, "release")
        with self.assertRaises(QuorumNotMet):
            arbs[0].reveal("b7", 1, 1, votes=[v1, v_other])
        # An impostor signing under a panel member's id does not count.
        impostor = Arbiter("a2")  # same id, different key
        v_fake = impostor.vote("b7", 1, ev, "release")
        with self.assertRaises(QuorumNotMet):
            arbs[0].reveal("b7", 1, 1, votes=[v1, v_fake])
        # A vote for a different award does not count toward this one.
        v_split = arbs[1].vote("b7", 1, ev, Fraction(1, 3))
        with self.assertRaises(QuorumNotMet):
            arbs[0].reveal("b7", 1, 1, votes=[v1, v_split])

        # C05 verifiability and binding.
        self.assertTrue(verify_obj(v1, pubs["a1"]))
        self.assertFalse(verify_obj(v1, pubs["a2"]))
        tampered = dict(v1)
        tampered["milestone"] = 2
        self.assertFalse(verify_obj(tampered, pubs["a1"]))
        self.assertEqual(v1["evidence_hash"], sha256_b64u(canonical_json(ev)))

        # 2 valid votes: quorum — every arbiter reveals, payee settles.
        reveals = [a.reveal("b7", 1, 1, votes=[v1, v2]) for a in arbs]
        self.assertTrue(all(r["quorum"] for r in reveals))
        self.assertEqual(job.payee.redeem(1, reveals), 891)  # 900 − 9

    # ------------------------------------------------------------------
    # B8 — milestone independence of refund secrets
    # ------------------------------------------------------------------

    def test_b8_milestone_refund_independence(self):
        """B8: refund secrets are distinct per milestone — refunding
        milestone 1 does not enable refunding milestone 2, neither early
        (lock_not_expired) nor at expiry with the wrong secret
        (refund_invalid)."""
        mint = self.start_mint()
        arbs, _pubs = self.panel(1, 1, ids=["solo"])
        job = self.make_job(mint, "b8", arbs, {1: [200], 2: [200]}, funding_mc=500)
        payer = job.payer
        self.assertNotEqual(payer._refund_secrets[1], payer._refund_secrets[2])

        mint.clock.set(job.expiries[1])
        self.assertEqual(payer.refund_expired(1), 198)  # 200 − 2 burn

        m2_hash = next(
            o["secret_hash"] for o in job.info.outputs if o["milestone"] == 2
        )
        client = self.client(mint)
        m1_witness = b64u_encode(payer._refund_secrets[1])
        out = {"amount_mc": 198, "secret_hash": ledger_key(new_secret()), "lock": None}

        # Early (before T2): the milestone-1 secret opens nothing.
        with self.assertRaises(MintRejected) as ctx:
            client.exchange(
                str(uuid.uuid4()),
                [{"hash": m2_hash, "witness": m1_witness}],
                [out],
            )
        self.assertIn(
            "lock_not_expired", [e["reason"] for e in ctx.exception.errors]
        )
        # At T2 with milestone 1's secret: still nothing.
        mint.clock.set(job.expiries[2])
        with self.assertRaises(MintRejected) as ctx:
            client.exchange(
                str(uuid.uuid4()),
                [{"hash": m2_hash, "witness": m1_witness}],
                [out],
            )
        self.assertIn(
            "refund_invalid", [e["reason"] for e in ctx.exception.errors]
        )
        # The correct milestone-2 secret works.
        self.assertEqual(payer.refund_expired(2), 198)

    # ------------------------------------------------------------------
    # supplementary — verify_funding is complete (requirement 2, B3)
    # ------------------------------------------------------------------

    def test_verify_funding_is_complete(self):
        """B3 (supplementary, requirement 2): verify_funding checks every
        output — existence, unspentness, amount, expiry, attested lock
        hash, attestation signatures — and every failure names the
        offending rung."""
        mint = self.start_mint()
        arbs, pubs = self.panel(1, 1, ids=["solo"])
        job = self.make_job(mint, "vf", arbs, {1: [100, 100], 2: [100, 100]},
                            funding_mc=500, verify=False)
        client = self.client(mint)

        def fresh_payee() -> EscrowPayee:
            p = EscrowPayee(client, MINT_ID, pubs)
            p._secrets = dict(job.payee._secrets)  # same holder, fresh state
            return p

        # The honest funding verifies.
        fresh_payee().verify_funding(job.info, job.attestations)

        # Tampered attestation → signature invalid, rung named.
        bad_att = [dict(a) for a in job.attestations]
        bad_att[0]["amount_mc"] += 1
        with self.assertRaises(FundingInvalid) as ctx:
            fresh_payee().verify_funding(job.info, bad_att)
        self.assertEqual(ctx.exception.rung, bad_att[0]["rung"])

        # Info claiming a different amount than attested.
        outs = [dict(o) for o in job.info.outputs]
        outs[0]["amount_mc"] = 999
        with self.assertRaises(FundingInvalid):
            fresh_payee().verify_funding(
                dataclasses.replace(job.info, outputs=tuple(outs)),
                job.attestations,
            )

        # A funded output missing from the set.
        with self.assertRaises(FundingInvalid) as ctx:
            fresh_payee().verify_funding(
                dataclasses.replace(job.info, outputs=job.info.outputs[1:]),
                job.attestations,
            )
        self.assertIn("missing", str(ctx.exception))

        # An expiry that differs from the agreed schedule.
        wrong = dict(job.info.expiries)
        wrong[2] += 1
        with self.assertRaises(FundingInvalid):
            fresh_payee().verify_funding(
                dataclasses.replace(job.info, expiries=wrong), job.attestations
            )

        # A spent output: refund milestone 1, then re-verify.
        mint.clock.set(job.expiries[1])
        job.payer.refund_expired(1)
        with self.assertRaises(FundingInvalid) as ctx:
            fresh_payee().verify_funding(job.info, job.attestations)
        self.assertEqual(ctx.exception.milestone, 1)
        self.assertIn("spent", str(ctx.exception))

    # ------------------------------------------------------------------
    # wire form — FundingInfo.to_dict / from_dict (§9.3 handoff)
    # ------------------------------------------------------------------

    def test_funding_wire_roundtrip_two_process_flow(self):
        """The payer→payee funding handoff crosses a process boundary as
        canonical JSON: FundingInfo.to_dict is canonical-JSON-safe (string
        keys, b64u hashes, no floats), from_dict restores an equal
        FundingInfo (int milestone keys, int-or-"fee" rungs included), and
        verify_funding accepts the raw wire dict — after which the full
        §9.3 flow (release, fee collection, expiry refund) completes end
        to end against a live mint with attestations, votes, and reveals
        that all crossed the same boundary as JSON."""
        mint = self.start_mint()
        arbs, _pubs = self.panel(1, 1, ids=["solo"])
        job = self.make_job(
            mint, "wire", arbs, {1: [400, 100], 2: [250]},
            fee_mc=100, funding_mc=1_000, verify=False,
        )

        # Serialize in the payer's object graph; parse into fresh objects.
        d = job.info.to_dict()
        wire = canonical_json(d)  # would raise on any non-wire-safe field
        d2 = json.loads(wire)
        info2 = FundingInfo.from_dict(d2)
        self.assertEqual(info2, job.info)  # lossless, int keys restored
        self.assertEqual(canonical_json(info2.to_dict()), wire)
        self.assertTrue(all(isinstance(k, str) for k in d["expiries"]))
        atts2 = json.loads(canonical_json(job.attestations))

        # "Process B": the mandatory §9.3 check runs on the wire forms.
        job.payee.verify_funding(d2, atts2)          # raw wire dict
        job.fee_acct.verify_funding(info2, atts2)    # parsed FundingInfo

        # Complete the flow; the vote and reveal cross as JSON too.
        v = json.loads(canonical_json(arbs[0].vote("wire", 1, {"m": 1}, "release")))
        r = json.loads(canonical_json(arbs[0].reveal("wire", 1, 1, votes=[v])))
        self.assertEqual(job.payee.redeem(1, [r]), 495)    # 500 − 5 burn
        self.assertEqual(job.fee_acct.redeem(1, [r]), 99)  # 100 − 1 burn
        # Milestone 2 never decided: refunds (fee included) at expiry.
        mint.clock.set(job.expiries[2])
        self.assertEqual(job.payer.refund_expired(2), 347)  # 350 − 3 burn
        supply = mint.ledger.supply()
        self.assertEqual(
            supply["outstanding_mc"],
            supply["cumulative_issued_mc"] - supply["cumulative_burned_mc"],
        )

    def test_funding_from_dict_rejects_malformed(self):
        """from_dict is strict about the wire shape: wrong container, key
        set deviations, float amounts, int expiries keys (the wire form
        uses decimal strings), non-canonical key strings, bad hash fields,
        and malformed outputs all raise EscrowError — and verify_funding
        routes wire dicts through the same parse."""
        mint = self.start_mint()
        arbs, _pubs = self.panel(1, 1, ids=["solo"])
        job = self.make_job(
            mint, "wf", arbs, {1: [200]}, funding_mc=300, verify=False
        )
        good = job.info.to_dict()

        def variant(**kw):
            d = {k: v for k, v in good.items()}
            d.update(kw)
            return d

        bad_missing_field = [dict(o) for o in good["outputs"]]
        bad_missing_field[0].pop("preimage_hash")
        bad_hash = [dict(o) for o in good["outputs"]]
        bad_hash[0]["secret_hash"] = "AAA"  # not a 32-byte b64u digest
        bad_rung = [dict(o) for o in good["outputs"]]
        bad_rung[0]["rung"] = None
        bad_amount = [dict(o) for o in good["outputs"]]
        bad_amount[0]["amount_mc"] = 200.0
        for bad in (
            "not a dict",
            None,
            {k: v for k, v in good.items() if k != "outputs"},  # missing key
            variant(extra=1),                   # extra key
            variant(outputs="nope"),
            variant(burn_mc=3.0),               # no floats, ever
            variant(change_mc=-1),
            variant(expiries={"01": T0}),       # non-canonical decimal key
            variant(expiries={1: T0}),          # int keys are not wire form
            variant(expiries={"1": 1.5}),
            variant(outputs=bad_missing_field),
            variant(outputs=bad_hash),
            variant(outputs=bad_rung),
            variant(outputs=bad_amount),
        ):
            with self.assertRaises(EscrowError):
                FundingInfo.from_dict(bad)
        # verify_funding: malformed wire dicts and non-FundingInfo values
        # are refused by the same strict parse ...
        with self.assertRaises(EscrowError):
            job.payee.verify_funding({"nope": 1}, job.attestations)
        with self.assertRaises(EscrowError):
            job.payee.verify_funding("garbage", job.attestations)
        # ... while the honest wire form still verifies completely.
        job.payee.verify_funding(good, job.attestations)


if __name__ == "__main__":
    unittest.main()
