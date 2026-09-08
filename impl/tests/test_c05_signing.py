"""Tests for C05 — signing (aicash/signing.py).

Each test docstring names the benchmark item(s) it covers (B1–B6 from
components/C05-signing.md).
"""

import base64
import copy
import unittest

from aicash.signing import (
    attach_sig,
    generate_keypair,
    pubkey_b64u,
    sign_obj,
    sign_raw,
    verify_obj,
    verify_raw,
)

# RFC 8032 §7.1 official test vectors (hex, straight from the RFC).
RFC8032_TEST1 = {
    "secret": bytes.fromhex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    ),
    "public": bytes.fromhex(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    ),
    "message": b"",
    "signature": bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    ),
}

RFC8032_TEST2 = {
    "secret": bytes.fromhex(
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
    ),
    "public": bytes.fromhex(
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
    ),
    "message": bytes.fromhex("72"),
    "signature": bytes.fromhex(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    ),
}


class TestRFC8032Vectors(unittest.TestCase):
    def test_rfc8032_test1_empty_message(self):
        """B1: RFC 8032 §7.1 TEST 1 (empty message) through sign_raw/verify_raw."""
        v = RFC8032_TEST1
        self.assertEqual(sign_raw(v["message"], v["secret"]), v["signature"])
        self.assertTrue(verify_raw(v["message"], v["signature"], v["public"]))

    def test_rfc8032_test2_one_byte_message(self):
        """B1: RFC 8032 §7.1 TEST 2 (one-byte message 0x72) through sign_raw/verify_raw."""
        v = RFC8032_TEST2
        self.assertEqual(sign_raw(v["message"], v["secret"]), v["signature"])
        self.assertTrue(verify_raw(v["message"], v["signature"], v["public"]))

    def test_rfc8032_public_key_derivation(self):
        """B1: the RFC vector public keys are what our private keys derive to
        (checked by verifying a fresh signature and via a cross-vector
        rejection: TEST 1's signature must not verify under TEST 2's key)."""
        v1, v2 = RFC8032_TEST1, RFC8032_TEST2
        self.assertTrue(
            verify_raw(v1["message"], sign_raw(v1["message"], v1["secret"]), v1["public"])
        )
        self.assertFalse(verify_raw(v1["message"], v1["signature"], v2["public"]))

    def test_verify_raw_is_total(self):
        """B4: verify_raw returns False (never raises) on wrong-length,
        empty, and garbage signatures and on bad keys."""
        v = RFC8032_TEST1
        self.assertFalse(verify_raw(v["message"], b"", v["public"]))
        self.assertFalse(verify_raw(v["message"], v["signature"][:-1], v["public"]))
        self.assertFalse(verify_raw(v["message"], v["signature"] + b"\x00", v["public"]))
        self.assertFalse(verify_raw(v["message"], b"\x00" * 64, v["public"]))
        self.assertFalse(verify_raw(v["message"], v["signature"], b"\x00" * 31))
        self.assertFalse(verify_raw(v["message"], v["signature"], b""))


class TestObjectSigning(unittest.TestCase):
    def setUp(self):
        self.private, self.public = generate_keypair()
        self.doc = {
            "v": 4,
            "outstanding_mc": 12345,
            "cumulative_issued_mc": 20000,
            "cumulative_burned_mc": 7655,
            "snapshot_seq": 9,
            "note": "Snapshot",
        }

    def test_attach_verify_round_trip(self):
        """B2: attach_sig then verify_obj is True."""
        signed = attach_sig(self.doc, self.private)
        self.assertIn("signature", signed)
        self.assertTrue(verify_obj(signed, self.public))

    def test_single_field_mutations_fail(self):
        """B2: any single field mutation (int +1, key rename, string case)
        flips verification to False."""
        signed = attach_sig(self.doc, self.private)

        bumped = dict(signed)
        bumped["snapshot_seq"] = signed["snapshot_seq"] + 1
        self.assertFalse(verify_obj(bumped, self.public))

        renamed = dict(signed)
        renamed["snapshot_sequence"] = renamed.pop("snapshot_seq")
        self.assertFalse(verify_obj(renamed, self.public))

        recased = dict(signed)
        recased["note"] = "snapshot"
        self.assertFalse(verify_obj(recased, self.public))

    def test_signature_stable_under_key_reordering(self):
        """B3: signing an object built in one insertion order verifies against
        the same content built in a different order, and sign_obj produces
        identical signature strings for both orders."""
        a = {"alpha": 1, "beta": "x", "gamma": [1, 2, {"z": 0, "a": 9}]}
        b = {"gamma": [1, 2, {"a": 9, "z": 0}], "beta": "x", "alpha": 1}
        self.assertEqual(sign_obj(a, self.private), sign_obj(b, self.private))

        signed_a = attach_sig(a, self.private)
        reordered = {"beta": "x", "signature": signed_a["signature"], "gamma": [1, 2, {"a": 9, "z": 0}], "alpha": 1}
        self.assertTrue(verify_obj(reordered, self.public))

    def test_bad_signature_strings_are_false_not_exceptions(self):
        """B4: tampered, truncated, empty, non-b64u, padded, and missing
        signature strings all yield False from verify_obj, never an
        exception."""
        signed = attach_sig(self.doc, self.private)
        good_sig = signed["signature"]

        def with_sig(s):
            d = dict(signed)
            d["signature"] = s
            return d

        # Tampered: flip the first character to a different b64u character.
        flipped = ("B" if good_sig[0] != "B" else "C") + good_sig[1:]
        self.assertFalse(verify_obj(with_sig(flipped), self.public))
        # Truncated.
        self.assertFalse(verify_obj(with_sig(good_sig[:-4]), self.public))
        self.assertFalse(verify_obj(with_sig(good_sig[:1]), self.public))
        # Empty.
        self.assertFalse(verify_obj(with_sig(""), self.public))
        # Non-b64u alphabet / whitespace / padding.
        self.assertFalse(verify_obj(with_sig("!!not-base64url!!"), self.public))
        self.assertFalse(verify_obj(with_sig(good_sig + "\n"), self.public))
        self.assertFalse(verify_obj(with_sig(good_sig + "=="), self.public))
        # Non-alphabet garbage appended/prepended/injected: Python's
        # urlsafe_b64decode silently DISCARDS such characters by default, so
        # these decode to the same 64 valid bytes — they must still be False
        # (one document, one valid signature string; no string malleability).
        self.assertFalse(verify_obj(with_sig(good_sig + "!!!!"), self.public))
        self.assertFalse(verify_obj(with_sig("!!!!" + good_sig), self.public))
        self.assertFalse(verify_obj(with_sig(good_sig + "****"), self.public))
        mid = len(good_sig) // 2
        self.assertFalse(
            verify_obj(with_sig(good_sig[:mid] + "@!" + good_sig[mid:]), self.public)
        )
        # Wrong type entirely.
        self.assertFalse(verify_obj(with_sig(12345), self.public))
        self.assertFalse(verify_obj(with_sig(None), self.public))
        # Missing signature field.
        self.assertFalse(verify_obj(dict(self.doc), self.public))
        # Not even a dict.
        self.assertFalse(verify_obj(["not", "a", "dict"], self.public))

    def test_non_canonical_trailing_bits_are_false(self):
        """B4: a signature string differing only in the final character's
        UNUSED trailing bits decodes to the same 64 bytes but is a different
        string — it must be rejected (False), not verify True. Exactly one
        canonical encoding per signature."""
        signed = attach_sig(self.doc, self.private)
        good_sig = signed["signature"]
        good_bytes = base64.urlsafe_b64decode(good_sig + "=" * (-len(good_sig) % 4))

        alphabet = (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        )
        variants = []
        for c in alphabet:
            if c == good_sig[-1]:
                continue
            v = good_sig[:-1] + c
            if base64.urlsafe_b64decode(v + "=" * (-len(v) % 4)) == good_bytes:
                variants.append(v)
        # 86 b64u chars carry 516 bits for a 512-bit signature: 4 unused
        # trailing bits, so 15 same-bytes variants of the last char exist.
        self.assertEqual(len(variants), 15)
        for v in variants:
            tampered = dict(signed)
            tampered["signature"] = v
            self.assertFalse(verify_obj(tampered, self.public))
        # And the canonical string itself still verifies.
        self.assertTrue(verify_obj(signed, self.public))

    def test_nested_signature_key_is_signed_content(self):
        """B5: a doc containing a sub-object with its own 'signature' key
        round-trips, and tampering with the NESTED signature breaks the outer
        signature (the nested one is signed content; only the top-level field
        is excluded)."""
        doc = {
            "v": 4,
            "receipt": {
                "payer_hash": "abc",
                "amount_mc": 500,
                "signature": "inner-sig-material-is-content",
            },
            "period": "2026-08",
        }
        signed = attach_sig(doc, self.private)
        self.assertTrue(verify_obj(signed, self.public))

        tampered = copy.deepcopy(signed)
        tampered["receipt"]["signature"] = "different-inner-sig"
        self.assertFalse(verify_obj(tampered, self.public))

    def test_wrong_public_key_fails(self):
        """B6: a signature valid under the signing key is False under a
        different (also valid) public key, and under malformed keys."""
        signed = attach_sig(self.doc, self.private)
        _, other_public = generate_keypair()
        self.assertFalse(verify_obj(signed, other_public))
        self.assertFalse(verify_obj(signed, b"\x00" * 32))
        self.assertFalse(verify_obj(signed, b"short"))
        self.assertTrue(verify_obj(signed, self.public))

    def test_attach_sig_does_not_mutate_and_replaces_old_sig(self):
        """B2 (hygiene): attach_sig returns a new dict, leaves the input
        untouched, and re-signing an already-signed doc replaces the old
        top-level signature rather than signing over it."""
        original = dict(self.doc)
        signed = attach_sig(self.doc, self.private)
        self.assertEqual(self.doc, original)
        self.assertNotIn("signature", self.doc)

        resigned = attach_sig(signed, self.private)
        self.assertTrue(verify_obj(resigned, self.public))
        # Ed25519 is deterministic: same content, same key, same signature.
        self.assertEqual(resigned["signature"], signed["signature"])

    def test_verify_obj_does_not_mutate(self):
        """B4 (hygiene): verify_obj pops the signature from a copy, not from
        the caller's dict."""
        signed = attach_sig(self.doc, self.private)
        snapshot = copy.deepcopy(signed)
        self.assertTrue(verify_obj(signed, self.public))
        self.assertEqual(signed, snapshot)

    def test_custom_sig_field(self):
        """B2/B5: a non-default sig_field is the excluded top-level field; a
        top-level 'signature' key is then ordinary signed content."""
        doc = {"v": 4, "signature": "someone-elses", "total_mc": 9}
        signed = attach_sig(doc, self.private, sig_field="mint_sig")
        self.assertTrue(verify_obj(signed, self.public, sig_field="mint_sig"))
        self.assertEqual(signed["signature"], "someone-elses")

        tampered = dict(signed)
        tampered["signature"] = "changed"
        self.assertFalse(verify_obj(tampered, self.public, sig_field="mint_sig"))

    def test_verify_obj_total_on_uncanonicalizable_content(self):
        """B4: verify_obj returns False (not an exception) when the object
        cannot be canonicalized at all (floats are forbidden by §3.3)."""
        signed = attach_sig(self.doc, self.private)
        bad = dict(signed)
        bad["rate"] = 1.5
        self.assertFalse(verify_obj(bad, self.public))


class TestKeysAndEncoding(unittest.TestCase):
    def test_generate_keypair_shape(self):
        """B1 (surface): raw 32-byte keys at the API boundary; distinct draws."""
        priv, pub = generate_keypair()
        self.assertEqual(len(priv), 32)
        self.assertEqual(len(pub), 32)
        priv2, pub2 = generate_keypair()
        self.assertNotEqual(priv, priv2)
        self.assertNotEqual(pub, pub2)

    def test_pubkey_b64u(self):
        """B1 (surface): pubkey_b64u is unpadded base64url of the raw key,
        checked against the RFC 8032 TEST 1 public key."""
        pub = RFC8032_TEST1["public"]
        expected = base64.urlsafe_b64encode(pub).rstrip(b"=").decode("ascii")
        self.assertEqual(pubkey_b64u(pub), expected)
        self.assertNotIn("=", pubkey_b64u(pub))
        self.assertEqual(len(pubkey_b64u(pub)), 43)  # ceil(32*8/6)
        with self.assertRaises(ValueError):
            pubkey_b64u(b"\x00" * 31)

    def test_sign_obj_signature_is_b64u_64_bytes(self):
        """B2 (surface): sign_obj returns unpadded base64url of a 64-byte
        Ed25519 signature."""
        priv, pub = generate_keypair()
        sig = sign_obj({"a": 1}, priv)
        self.assertNotIn("=", sig)
        decoded = base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4))
        self.assertEqual(len(decoded), 64)


if __name__ == "__main__":
    unittest.main()
