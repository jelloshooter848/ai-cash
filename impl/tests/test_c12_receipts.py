"""Tests for C12 — receipts (aicash/receipts.py).

Each test docstring names the benchmark item(s) it covers (B1–B7 from
components/C12-receipts.md).
"""

import copy
import hashlib
import unittest

from aicash.receipts import (
    ChannelDraw,
    Envelope,
    EnvelopeError,
    ERROR_KINDS,
    ERROR_REASONS,
    build_envelope,
    make_attestation,
    make_dispute_record,
    make_receipt,
    parse_envelope,
    payment_error,
    receipt_status,
    sign_attestation,
    sign_dispute,
    sign_receipt,
    verify_attestation,
    verify_dispute,
    verify_receipt,
)
from aicash.signing import generate_keypair, verify_raw
from aicash.tokencodec import (
    b64u_encode,
    canonical_json,
    format_token,
    new_secret,
)


def _hash32(seed: bytes) -> str:
    return b64u_encode(hashlib.sha256(seed).digest())


def sample_receipt():
    return make_receipt(
        payer_id="agent-payer-1",
        payee_id="agent-payee-1",
        amount_mc=12345,
        mint_id="mint-a",
        token_hashes=[_hash32(b"t0"), _hash32(b"t1")],
        timestamp=1_756_000_000_000,
        memo="translation job 77",
        purpose="services",
    )


def sample_dispute(**overrides):
    kwargs = dict(
        job_id="job-42",
        milestone=1,
        claimed_mc=30_000,
        released_mc=30_000,
        decision="released",
        arbiter_ids=["arb-1", "arb-2", "arb-3"],
        evidence_hash=_hash32(b"evidence"),
        timestamp=1_756_000_100_000,
        votes=[
            {"arbiter_id": "arb-1", "vote": "release", "sig": "x"},
            {"arbiter_id": "arb-2", "vote": "release", "sig": "y"},
        ],
    )
    kwargs.update(overrides)
    return make_dispute_record(**kwargs)


class TestReceipt(unittest.TestCase):
    def setUp(self):
        self.payer_priv, self.payer_pub = generate_keypair()
        self.payee_priv, self.payee_pub = generate_keypair()

    def test_full_round_trip_payer_first(self):
        """B1: build -> payer signs -> payee counter-signs -> verify true."""
        r = sample_receipt()
        r = sign_receipt(r, self.payer_priv, "payer")
        r = sign_receipt(r, self.payee_priv, "payee")
        self.assertTrue(verify_receipt(r, self.payer_pub, self.payee_pub))

    def test_full_round_trip_payee_first(self):
        """B1: signing order irrelevant — payee-first also produces a
        verifying document."""
        r = sample_receipt()
        r = sign_receipt(r, self.payee_priv, "payee")
        r = sign_receipt(r, self.payer_priv, "payer")
        self.assertTrue(verify_receipt(r, self.payer_pub, self.payee_pub))

    def test_tamper_any_field_fails(self):
        """B1: either signature over different content -> false (every
        non-signature field is covered)."""
        r = sign_receipt(
            sign_receipt(sample_receipt(), self.payer_priv, "payer"),
            self.payee_priv,
            "payee",
        )
        for field, bad in [
            ("amount_mc", 99999),
            ("payer_id", "someone-else"),
            ("payee_id", "someone-else"),
            ("mint_id", "mint-b"),
            ("timestamp", 1),
            ("memo", "altered"),
            ("purpose", "altered"),
            ("token_hashes", [_hash32(b"other")]),
        ]:
            tampered = copy.deepcopy(r)
            tampered[field] = bad
            self.assertFalse(
                verify_receipt(tampered, self.payer_pub, self.payee_pub),
                "tampered %s should not verify" % field,
            )

    def test_signature_swap_fails(self):
        """B1: a signature made by the wrong key never verifies."""
        r = sign_receipt(
            sign_receipt(sample_receipt(), self.payer_priv, "payer"),
            self.payee_priv,
            "payee",
        )
        # Swap keys at verification: wrong pub for each role.
        self.assertFalse(verify_receipt(r, self.payee_pub, self.payer_pub))
        # Payee's signature actually produced by payer's key.
        forged = sign_receipt(
            sign_receipt(sample_receipt(), self.payer_priv, "payer"),
            self.payer_priv,
            "payee",
        )
        self.assertFalse(verify_receipt(forged, self.payer_pub, self.payee_pub))

    def test_half_signed_returns_false(self):
        """B1 + requirement 5: a half-signed receipt verifies False (status
        is receipt_status's business, not verify's)."""
        half = sign_receipt(sample_receipt(), self.payer_priv, "payer")
        self.assertFalse(verify_receipt(half, self.payer_pub, self.payee_pub))
        self.assertFalse(
            verify_receipt(sample_receipt(), self.payer_pub, self.payee_pub)
        )

    def test_countersigning_preserves_first_signature_bytes(self):
        """B6: adding the second signature changes nothing the first
        signature covers — the first signature still verifies over exactly
        the same signed bytes."""
        r1 = sign_receipt(sample_receipt(), self.payer_priv, "payer")
        bytes_before = canonical_json(
            {k: v for k, v in r1.items() if k != "signatures"}
        )
        sig_before = r1["signatures"]["payer"]
        r2 = sign_receipt(r1, self.payee_priv, "payee")
        bytes_after = canonical_json(
            {k: v for k, v in r2.items() if k != "signatures"}
        )
        self.assertEqual(bytes_before, bytes_after)
        self.assertEqual(r2["signatures"]["payer"], sig_before)
        # The stored payer signature is literally a valid Ed25519 signature
        # over those bytes.
        from aicash.tokencodec import b64u_decode

        self.assertTrue(
            verify_raw(bytes_after, b64u_decode(sig_before, expect_len=64), self.payer_pub)
        )
        self.assertTrue(verify_receipt(r2, self.payer_pub, self.payee_pub))

    def test_signing_does_not_mutate_input(self):
        """B6: sign_receipt returns a new dict and never mutates its input."""
        r = sample_receipt()
        snapshot = copy.deepcopy(r)
        signed = sign_receipt(r, self.payer_priv, "payer")
        self.assertEqual(r, snapshot)
        self.assertIsNot(signed, r)

    def test_receipt_status_all_four_states(self):
        """B7: receipt_status covers unsigned / payer_only / payee_only /
        complete."""
        r = sample_receipt()
        self.assertEqual(receipt_status(r), "unsigned")
        payer_only = sign_receipt(r, self.payer_priv, "payer")
        self.assertEqual(receipt_status(payer_only), "payer_only")
        payee_only = sign_receipt(r, self.payee_priv, "payee")
        self.assertEqual(receipt_status(payee_only), "payee_only")
        both = sign_receipt(payer_only, self.payee_priv, "payee")
        self.assertEqual(receipt_status(both), "complete")

    def test_make_receipt_validation(self):
        """B1: builder rejects malformed inputs (bad amounts, hashes,
        types) instead of producing unsignable garbage."""
        good = dict(
            payer_id="p",
            payee_id="q",
            amount_mc=1,
            mint_id="mint-a",
            token_hashes=[_hash32(b"t")],
            timestamp=0,
            memo="",
            purpose="",
        )
        make_receipt(**good)  # sanity: the base case is valid
        bad_cases = [
            dict(good, amount_mc=0),
            dict(good, amount_mc="1"),
            dict(good, amount_mc=True),
            dict(good, payer_id=""),
            dict(good, mint_id="Mint_A"),
            dict(good, token_hashes=[]),
            dict(good, token_hashes=["not-b64u!!"]),
            dict(good, token_hashes=[b64u_encode(b"short")]),
            dict(good, timestamp=-1),
            dict(good, memo=7),
        ]
        for case in bad_cases:
            with self.assertRaises(ValueError):
                make_receipt(**case)

    def test_verify_receipt_total_on_garbage(self):
        """B1: verify_receipt is total — garbage inputs return False, never
        raise."""
        for garbage in [None, 7, "x", [], {}, {"v": 3}, {"v": 4}]:
            self.assertFalse(
                verify_receipt(garbage, self.payer_pub, self.payee_pub)
            )
        r = sign_receipt(
            sign_receipt(sample_receipt(), self.payer_priv, "payer"),
            self.payee_priv,
            "payee",
        )
        broken = copy.deepcopy(r)
        broken["signatures"]["payer"] = "!!not-b64u!!"
        self.assertFalse(verify_receipt(broken, self.payer_pub, self.payee_pub))
        broken2 = copy.deepcopy(r)
        broken2["signatures"] = "nope"
        self.assertFalse(verify_receipt(broken2, self.payer_pub, self.payee_pub))

    def test_bad_role_rejected(self):
        """B1: only payer/payee roles exist on receipts."""
        with self.assertRaises(ValueError):
            sign_receipt(sample_receipt(), self.payer_priv, "arbiter")


class TestDispute(unittest.TestCase):
    def setUp(self):
        self.arb_keys = {}
        self.arb_pubs = {}
        for a in ("arb-1", "arb-2", "arb-3"):
            priv, pub = generate_keypair()
            self.arb_keys[a] = priv
            self.arb_pubs[a] = pub
        self.payer_priv, self.payer_pub = generate_keypair()
        self.payee_priv, self.payee_pub = generate_keypair()

    def test_arbiter_only_with_refusal_verifies(self):
        """B2: arbiter-only signature with refusals:["payer"] verifies true
        — the §10.2 contested case."""
        d = sample_dispute(refusals=["payer"])
        d = sign_dispute(d, self.arb_keys["arb-1"], "arb-1")
        self.assertTrue(verify_dispute(d, self.arb_pubs))
        # Also valid when party pubs are supplied but the party never signed.
        self.assertTrue(
            verify_dispute(d, self.arb_pubs, payer_pub=self.payer_pub,
                           payee_pub=self.payee_pub)
        )

    def test_zero_arbiter_signatures_false(self):
        """B2: zero arbiter signatures -> false, even with both party
        signatures present."""
        d = sample_dispute()
        self.assertFalse(verify_dispute(d, self.arb_pubs))
        both_parties = sign_dispute(
            sign_dispute(d, self.payer_priv, "payer"), self.payee_priv, "payee"
        )
        self.assertFalse(
            verify_dispute(both_parties, self.arb_pubs,
                           payer_pub=self.payer_pub, payee_pub=self.payee_pub)
        )

    def test_full_panel_and_parties_verify(self):
        """B2: fully counter-signed record (panel + both parties) verifies."""
        d = sample_dispute()
        for a in ("arb-1", "arb-2", "arb-3"):
            d = sign_dispute(d, self.arb_keys[a], a)
        d = sign_dispute(d, self.payer_priv, "payer")
        d = sign_dispute(d, self.payee_priv, "payee")
        self.assertTrue(
            verify_dispute(d, self.arb_pubs, payer_pub=self.payer_pub,
                           payee_pub=self.payee_pub)
        )

    def test_split_decision_bounds(self):
        """B2 + requirement 3: split requires 0 < released_mc < claimed_mc;
        released/refunded amounts must be consistent."""
        d = sample_dispute(decision="split", claimed_mc=30_000, released_mc=10_000)
        d = sign_dispute(d, self.arb_keys["arb-1"], "arb-1")
        self.assertTrue(verify_dispute(d, self.arb_pubs))
        with self.assertRaises(ValueError):
            sample_dispute(decision="split", claimed_mc=30_000, released_mc=0)
        with self.assertRaises(ValueError):
            sample_dispute(decision="split", claimed_mc=30_000, released_mc=30_000)
        with self.assertRaises(ValueError):
            sample_dispute(decision="split", claimed_mc=30_000, released_mc=40_000)
        with self.assertRaises(ValueError):
            sample_dispute(decision="banana", claimed_mc=30_000, released_mc=1)
        with self.assertRaises(ValueError):
            sample_dispute(decision="released", claimed_mc=30_000, released_mc=10_000)
        with self.assertRaises(ValueError):
            sample_dispute(decision="refunded", claimed_mc=30_000, released_mc=10_000)
        sample_dispute(decision="refunded", released_mc=0)  # consistent: ok
        # Bounds also enforced at verify time on a hand-tampered record.
        tampered = copy.deepcopy(d)
        tampered["released_mc"] = tampered["claimed_mc"]
        self.assertFalse(verify_dispute(tampered, self.arb_pubs))

    def test_tamper_detection(self):
        """B2: any signed-content change (including votes and refusals)
        invalidates the arbiter signature."""
        d = sample_dispute(refusals=["payer"])
        d = sign_dispute(d, self.arb_keys["arb-2"], "arb-2")
        for field, bad in [
            ("job_id", "job-43"),
            ("milestone", 2),
            ("evidence_hash", _hash32(b"forged")),
            ("votes", []),
            ("refusals", []),
            ("timestamp", 5),
        ]:
            t = copy.deepcopy(d)
            t[field] = bad
            self.assertFalse(
                verify_dispute(t, self.arb_pubs), "tampered %s verified" % field
            )

    def test_refused_party_cannot_sign_and_contradiction_fails(self):
        """B2: a role listed in refusals cannot sign; a record carrying both
        a refusal and that party's signature is invalid."""
        d = sample_dispute(refusals=["payer"])
        with self.assertRaises(ValueError):
            sign_dispute(d, self.payer_priv, "payer")
        # Forge the contradiction by hand: refusal added after payer signed.
        d2 = sample_dispute()
        d2 = sign_dispute(d2, self.payer_priv, "payer")
        d2 = copy.deepcopy(d2)
        d2["refusals"] = ["payer"]
        d2["signatures"]["arb-1"] = "AA"  # irrelevant; refusal check first
        self.assertFalse(
            verify_dispute(d2, self.arb_pubs, payer_pub=self.payer_pub)
        )

    def test_unknown_or_wrong_key_signatures_fail(self):
        """B2: signatures from unlisted roles, or arbiter signatures that do
        not verify against the panel's keys, invalidate the record."""
        d = sample_dispute()
        signed = sign_dispute(d, self.arb_keys["arb-1"], "arb-1")
        # Unlisted role.
        forged = copy.deepcopy(signed)
        forged["signatures"]["arb-9"] = forged["signatures"]["arb-1"]
        self.assertFalse(verify_dispute(forged, self.arb_pubs))
        # Wrong key for the role.
        wrong = sign_dispute(d, self.arb_keys["arb-2"], "arb-1")
        self.assertFalse(verify_dispute(wrong, self.arb_pubs))
        # Missing pub for a signing arbiter.
        self.assertFalse(verify_dispute(signed, {"arb-2": self.arb_pubs["arb-2"]}))
        # Party signed but no party pub supplied -> unverifiable -> False.
        with_payer = sign_dispute(signed, self.payer_priv, "payer")
        self.assertFalse(verify_dispute(with_payer, self.arb_pubs))
        self.assertTrue(
            verify_dispute(with_payer, self.arb_pubs, payer_pub=self.payer_pub)
        )

    def test_make_dispute_validation(self):
        """B2: builder rejects malformed records (bad arbiter lists, bad
        refusals, reserved role names, non-canonical votes)."""
        with self.assertRaises(ValueError):
            sample_dispute(arbiter_ids=[])
        with self.assertRaises(ValueError):
            sample_dispute(arbiter_ids=["arb-1", "arb-1"])
        with self.assertRaises(ValueError):
            sample_dispute(arbiter_ids=["payer"])
        with self.assertRaises(ValueError):
            sample_dispute(refusals=["arbiter"])
        with self.assertRaises(ValueError):
            sample_dispute(refusals=["payer", "payer"])
        with self.assertRaises(ValueError):
            sample_dispute(votes=[["not", "a", "dict"]])
        with self.assertRaises(ValueError):
            sample_dispute(votes=[{"weight": 0.5}])  # float: not canonical JSON
        with self.assertRaises(ValueError):
            sample_dispute(evidence_hash="tooshort")

    def test_verify_dispute_total_on_garbage(self):
        """B2: verify_dispute is total — never raises on hostile input."""
        for garbage in [None, 7, [], {}, {"v": 4}, {"v": 4, "signatures": None}]:
            self.assertFalse(verify_dispute(garbage, self.arb_pubs))
        d = sign_dispute(sample_dispute(), self.arb_keys["arb-1"], "arb-1")
        self.assertFalse(verify_dispute(d, "not-a-dict"))


class TestAttestation(unittest.TestCase):
    def setUp(self):
        self.worker_priv, self.worker_pub = generate_keypair()
        self.cp_priv, self.cp_pub = generate_keypair()

    def _both_signed(self, a):
        return sign_attestation(
            sign_attestation(a, self.worker_priv, "worker"), self.cp_priv, "counterparty"
        )

    def test_round_trip(self):
        """B3: attestation build -> both sign -> verify true, in either
        signing order."""
        a = make_attestation("worker-1", "client-1", 250, 812_500, "2026-08")
        self.assertTrue(verify_attestation(self._both_signed(a), self.worker_pub, self.cp_pub))
        other_order = sign_attestation(
            sign_attestation(a, self.cp_priv, "counterparty"), self.worker_priv, "worker"
        )
        self.assertTrue(verify_attestation(other_order, self.worker_pub, self.cp_pub))
        # Structured period form.
        b = make_attestation(
            "worker-1", "client-1", 3, 90,
            {"start_ms": 1_756_000_000_000, "end_ms": 1_756_600_000_000},
        )
        self.assertTrue(verify_attestation(self._both_signed(b), self.worker_pub, self.cp_pub))

    def test_tamper_detection(self):
        """B3: any field change breaks both signatures; half-signed is
        False (both-signed per §10.3)."""
        a = self._both_signed(
            make_attestation("worker-1", "client-1", 250, 812_500, "2026-08")
        )
        for field, bad in [
            ("tasks", 251),
            ("total_mc", 812_501),
            ("worker_id", "worker-2"),
            ("counterparty_id", "client-2"),
            ("period", "2026-09"),
        ]:
            t = copy.deepcopy(a)
            t[field] = bad
            self.assertFalse(
                verify_attestation(t, self.worker_pub, self.cp_pub),
                "tampered %s verified" % field,
            )
        half = sign_attestation(
            make_attestation("worker-1", "client-1", 250, 812_500, "2026-08"),
            self.worker_priv,
            "worker",
        )
        self.assertFalse(verify_attestation(half, self.worker_pub, self.cp_pub))
        # Wrong keys.
        self.assertFalse(verify_attestation(a, self.cp_pub, self.worker_pub))

    def test_validation_and_totality(self):
        """B3: builder input validation; verify_attestation never raises."""
        with self.assertRaises(ValueError):
            make_attestation("w", "c", 0, 100, "2026-08")
        with self.assertRaises(ValueError):
            make_attestation("w", "c", 1, -1, "2026-08")
        with self.assertRaises(ValueError):
            make_attestation("w", "c", 1, 100, "")
        with self.assertRaises(ValueError):
            make_attestation("w", "c", 1, 100, {"start_ms": 5})
        with self.assertRaises(ValueError):
            make_attestation("w", "c", 1, 100, {"start_ms": 9, "end_ms": 5})
        with self.assertRaises(ValueError):
            sign_attestation(
                make_attestation("w", "c", 1, 100, "p"), self.worker_priv, "payer"
            )
        for garbage in [None, [], {}, {"v": 4}, "x"]:
            self.assertFalse(verify_attestation(garbage, self.worker_pub, self.cp_pub))


class TestEnvelope(unittest.TestCase):
    def setUp(self):
        self.mint = "mint-a"
        self.tok1 = format_token(self.mint, 500, new_secret())
        self.tok2 = format_token(self.mint, 100, new_secret())
        self.x_k = new_secret()

    def test_round_trip_tokens_only(self):
        """B4: build -> parse round-trip, channel_draw null."""
        req = {"tool": "summarize", "args": {"doc": "d1"}}
        env_req = build_envelope(req, self.mint, [self.tok1, self.tok2])
        self.assertEqual(env_req["aicash"]["channel_draw"], None)
        env = parse_envelope(env_req)
        self.assertIsInstance(env, Envelope)
        self.assertEqual(env.mint_id, self.mint)
        self.assertEqual(env.request, req)
        self.assertEqual(len(env.tokens), 2)
        self.assertEqual(env.tokens[0].amount_mc, 500)
        self.assertEqual(env.tokens[1].amount_mc, 100)
        self.assertIsNone(env.channel_draw)

    def test_round_trip_channel_draw(self):
        """B4: build -> parse round-trip with a channel draw; x_k decodes to
        the original 32 raw bytes."""
        draw = {"channel_id": "idem-key-1", "k": 7, "x_k": self.x_k}
        env_req = build_envelope({"tool": "t"}, self.mint, [], channel_draw=draw)
        self.assertEqual(env_req["aicash"]["channel_draw"]["x_k"], b64u_encode(self.x_k))
        env = parse_envelope(env_req)
        self.assertEqual(env.channel_draw, ChannelDraw("idem-key-1", 7, self.x_k))
        self.assertEqual(env.tokens, ())

    def test_parsed_channel_draw_carries_channel_id_and_raw_x_k(self):
        """B4 seam: the parsed ChannelDraw preserves channel_id (for O(1)
        channel resolution by the payee) and decodes x_k to raw 32 bytes —
        the exact shape ChannelPayee.on_draw normalizes.  Documents the C12→
        C08 contract that a cold integrator relies on."""
        draw = {"channel_id": "chan-xyz", "k": 3, "x_k": self.x_k}
        env = parse_envelope(
            build_envelope({"tool": "t"}, self.mint, [], channel_draw=draw)
        )
        self.assertEqual(env.channel_draw.channel_id, "chan-xyz")
        self.assertEqual(env.channel_draw.k, 3)
        self.assertIsInstance(env.channel_draw.x_k, bytes)
        self.assertEqual(env.channel_draw.x_k, self.x_k)
        # _asdict() gives the on_draw-ready mapping (x_k still raw bytes).
        self.assertEqual(
            env.channel_draw._asdict(),
            {"channel_id": "chan-xyz", "k": 3, "x_k": self.x_k},
        )

    def test_malformed_corpus_named_reasons(self):
        """B4: corpus of malformed envelopes each rejected with a named
        reason — bad token, missing channel_draw fields, non-b64u x_k,
        extra fields, and more."""
        good_draw = {"channel_id": "c1", "k": 1, "x_k": b64u_encode(self.x_k)}

        def env(aicash):
            return {"tool": "t", "aicash": aicash}

        base = {"mint_id": self.mint, "tokens": [self.tok1], "channel_draw": None}
        corpus = [
            ("bad_request", "not a dict"),
            ("missing_aicash", {"tool": "t"}),
            ("bad_aicash", env("nope")),
            ("unknown_field", env({**base, "extra": 1})),
            ("missing_field", env({"tokens": [], "channel_draw": None})),
            ("missing_field", env({"mint_id": self.mint, "channel_draw": None})),
            ("bad_mint_id", env({**base, "mint_id": "Mint_A"})),
            ("bad_mint_id", env({**base, "mint_id": 7})),
            ("bad_tokens", env({**base, "tokens": "aicash:v3:..."})),
            ("bad_token", env({**base, "tokens": ["not-a-token"]})),
            ("bad_token", env({**base, "tokens": [self.tok1, "aicash:v2:m:1:AA"]})),
            ("bad_token", env({**base, "tokens": [42]})),
            ("mint_mismatch",
             env({**base, "tokens": [format_token("mint-b", 5, new_secret())]})),
            ("bad_channel_draw", env({**base, "channel_draw": "x"})),
            ("unknown_channel_field",
             env({**base, "channel_draw": {**good_draw, "bonus": 1}})),
            ("missing_channel_field",
             env({**base, "channel_draw": {"channel_id": "c1", "k": 1}})),
            ("missing_channel_field",
             env({**base, "channel_draw": {"k": 1, "x_k": good_draw["x_k"]}})),
            ("missing_channel_field",
             env({**base, "channel_draw": {"channel_id": "c1", "x_k": good_draw["x_k"]}})),
            ("bad_channel_id",
             env({**base, "channel_draw": {**good_draw, "channel_id": ""}})),
            ("bad_k", env({**base, "channel_draw": {**good_draw, "k": 0}})),
            ("bad_k", env({**base, "channel_draw": {**good_draw, "k": True}})),
            ("bad_k", env({**base, "channel_draw": {**good_draw, "k": "1"}})),
            ("bad_x_k", env({**base, "channel_draw": {**good_draw, "x_k": "!!"}})),
            ("bad_x_k",
             env({**base, "channel_draw": {**good_draw, "x_k": b64u_encode(b"short")}})),
            ("bad_x_k",
             env({**base,
                  "channel_draw": {**good_draw,
                                   "x_k": b64u_encode(self.x_k) + "=="}})),
            ("bad_x_k", env({**base, "channel_draw": {**good_draw, "x_k": 7}})),
        ]
        for expected_reason, request in corpus:
            with self.assertRaises(EnvelopeError) as ctx:
                parse_envelope(request)
            self.assertEqual(
                ctx.exception.reason,
                expected_reason,
                "case %r: got reason %r" % (request, ctx.exception.reason),
            )

    def test_bad_token_is_structured_not_leaked(self):
        """B4 + requirement 4: a C01 parse failure surfaces as EnvelopeError
        with the token index attached and a §3.8-compatible error entry —
        never a leaked TokenError."""
        request = {
            "aicash": {"mint_id": self.mint,
                       "tokens": [self.tok1, "garbage"],
                       "channel_draw": None}
        }
        try:
            parse_envelope(request)
        except EnvelopeError as exc:
            self.assertEqual(exc.reason, "bad_token")
            self.assertEqual(exc.index, 1)
            entries = exc.payment_errors()
            self.assertEqual(
                entries, [{"index": 1, "kind": "input", "reason": "bad_format"}]
            )
            # And those entries feed straight into the 402 body.
            body = payment_error(entries)
            self.assertEqual(body["status"], "rejected")
        else:
            self.fail("expected EnvelopeError")

    def test_elided_channel_draw_treated_as_null(self):
        """B4: an aicash object without the channel_draw key parses as
        channel_draw None (the field is nullable in §9.5)."""
        env = parse_envelope(
            {"aicash": {"mint_id": self.mint, "tokens": [self.tok1]}}
        )
        self.assertIsNone(env.channel_draw)

    def test_build_envelope_validation(self):
        """B4: builder-side validation — bad tokens, mint mismatch, aicash
        collision, malformed draw all raise ValueError."""
        with self.assertRaises(ValueError):
            build_envelope({"aicash": {}}, self.mint, [self.tok1])
        with self.assertRaises(ValueError):
            build_envelope({}, "BAD MINT", [self.tok1])
        with self.assertRaises(ValueError):
            build_envelope({}, self.mint, ["nope"])
        with self.assertRaises(ValueError):
            build_envelope({}, self.mint, [format_token("mint-b", 1, new_secret())])
        with self.assertRaises(ValueError):
            build_envelope({}, self.mint, [], channel_draw={"channel_id": "c"})
        with self.assertRaises(ValueError):
            build_envelope({}, self.mint, [],
                           channel_draw={"channel_id": "c", "k": 1, "x_k": b"short"})
        with self.assertRaises(ValueError):
            build_envelope("not-a-dict", self.mint, [])


class TestPaymentError(unittest.TestCase):
    def test_exact_shape(self):
        """B5: payment_error emits exactly the §3.8 shape."""
        body = payment_error(
            [
                {"index": 3, "kind": "input", "reason": "spent"},
                {"index": 7, "kind": "input", "reason": "lock_preimage_invalid"},
            ]
        )
        self.assertEqual(
            body,
            {
                "status": "rejected",
                "errors": [
                    {"index": 3, "kind": "input", "reason": "spent"},
                    {"index": 7, "kind": "input", "reason": "lock_preimage_invalid"},
                ],
            },
        )
        self.assertEqual(set(body.keys()), {"status", "errors"})
        for e in body["errors"]:
            self.assertEqual(set(e.keys()), {"index", "kind", "reason"})

    def test_vocabulary_restricted(self):
        """B5: kinds/reasons restricted to the spec vocabulary; everything
        outside raises."""
        self.assertEqual(
            ERROR_REASONS,
            {
                "unknown", "spent", "lock_preimage_invalid", "lock_expired",
                "lock_not_expired", "refund_invalid", "bad_witness_length",
                "amount_mismatch", "output_exists", "bad_format",
                "over_batch_limit",
            },
        )
        self.assertEqual(ERROR_KINDS, {"input", "output"})
        # Every vocabulary reason is accepted.
        for reason in sorted(ERROR_REASONS):
            payment_error([{"index": 0, "kind": "input", "reason": reason}])
        payment_error([{"index": 0, "kind": "output", "reason": "output_exists"}])
        bad_cases = [
            [{"index": 0, "kind": "input", "reason": "expired"}],
            [{"index": 0, "kind": "input", "reason": "SPENT"}],
            [{"index": 0, "kind": "token", "reason": "spent"}],
            [{"index": -1, "kind": "input", "reason": "spent"}],
            [{"index": True, "kind": "input", "reason": "spent"}],
            [{"index": "0", "kind": "input", "reason": "spent"}],
            [{"index": 0, "kind": "input"}],
            [{"index": 0, "kind": "input", "reason": "spent", "note": "x"}],
            [],
            "not-a-list",
            [42],
        ]
        for case in bad_cases:
            with self.assertRaises(ValueError):
                payment_error(case)

    def test_input_copied_not_aliased(self):
        """B5: the returned body does not alias caller dicts (mutating the
        input after the call cannot change the emitted body)."""
        entry = {"index": 1, "kind": "input", "reason": "spent"}
        body = payment_error([entry])
        entry["reason"] = "unknown"
        self.assertEqual(body["errors"][0]["reason"], "spent")


class TestStrictSchemas(unittest.TestCase):
    def test_field_added_after_signing_breaks_signature(self):
        """B1 + requirement 1: unknown fields are covered by the signed
        bytes — adding one after signing breaks verification; a document
        signed WITH an extra field verifies (preserved on verify)."""
        payer_priv, payer_pub = generate_keypair()
        payee_priv, payee_pub = generate_keypair()
        r = sample_receipt()
        signed = sign_receipt(sign_receipt(r, payer_priv, "payer"), payee_priv, "payee")
        with_extra = copy.deepcopy(signed)
        with_extra["rating"] = 5
        self.assertFalse(verify_receipt(with_extra, payer_pub, payee_pub))
        # Signed over the extra field from the start: both signatures cover
        # it, so it verifies — the field is preserved, not stripped.
        r2 = dict(sample_receipt())
        r2["rating"] = 5
        signed2 = sign_receipt(sign_receipt(r2, payer_priv, "payer"), payee_priv, "payee")
        self.assertTrue(verify_receipt(signed2, payer_pub, payee_pub))

    def test_v_field_pinned(self):
        """B1/B2/B3: every schema carries v: 4 and the wrong version never
        builds or verifies."""
        payer_priv, payer_pub = generate_keypair()
        payee_priv, payee_pub = generate_keypair()
        r = sign_receipt(
            sign_receipt(sample_receipt(), payer_priv, "payer"), payee_priv, "payee"
        )
        self.assertEqual(r["v"], 4)
        bumped = copy.deepcopy(r)
        bumped["v"] = 5
        self.assertFalse(verify_receipt(bumped, payer_pub, payee_pub))
        d = sample_dispute()
        self.assertEqual(d["v"], 4)
        a = make_attestation("w", "c", 1, 1, "p")
        self.assertEqual(a["v"], 4)


if __name__ == "__main__":
    unittest.main()
