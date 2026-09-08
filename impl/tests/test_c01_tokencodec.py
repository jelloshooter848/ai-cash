"""Tests for C01 — tokencodec (spec §3.1–§3.4; components/C01-tokencodec.md).

Per benchmark item B7, this file imports only ``aicash.tokencodec`` and the
standard library.
"""

import base64
import hashlib
import json
import random
import unittest

from aicash.tokencodec import (
    MINT_ID_RE,
    Token,
    TokenError,
    b64u_decode,
    b64u_encode,
    body_digest,
    canonical_json,
    format_token,
    ledger_key,
    new_secret,
    parse_token,
)

# B3 known vector: secret = bytes 00 01 02 ... 1f
KNOWN_SECRET = bytes(range(32))
KNOWN_SECRET_B64U = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
KNOWN_LEDGER_KEY = "Yw3NKWbEM2aRElRIu7JbT_QSpJxzLbLIq8G4WBvXEN0"


class TestRoundTrip(unittest.TestCase):
    def test_roundtrip_100_random_triples(self):
        """B1: 100 random (mint_id, amount, secret) triples survive
        format→parse identically."""
        rng = random.Random(0xC01)
        alphabet = "abcdefghijklmnopqrstuvwxyz0123456789-"
        for _ in range(100):
            mint_id = "".join(
                rng.choice(alphabet) for _ in range(rng.randint(1, 64))
            )
            amount = rng.randint(1, 10**15)
            secret = new_secret()
            token_str = format_token(mint_id, amount, secret)
            parsed = parse_token(token_str)
            self.assertEqual(parsed.mint_id, mint_id)
            self.assertEqual(parsed.amount_mc, amount)
            self.assertEqual(parsed.secret, secret)
            # Re-formatting the parse reproduces the exact string.
            self.assertEqual(
                format_token(parsed.mint_id, parsed.amount_mc, parsed.secret),
                token_str,
            )

    def test_parse_returns_token_named_tuple(self):
        """B1: parse result carries the exact fields; parsing never mutates
        its input (str/bytes are immutable, and re-parsing the same string
        yields an equal result)."""
        s = format_token("mint-a", 5, KNOWN_SECRET)
        first = parse_token(s)
        second = parse_token(s)
        self.assertIsInstance(first, Token)
        self.assertEqual(first, second)
        self.assertEqual(
            s, "aicash:v3:mint-a:5:" + KNOWN_SECRET_B64U
        )


class TestMalformedCorpus(unittest.TestCase):
    """B2: every malformed token is rejected with TokenError."""

    def assert_bad(self, token_str):
        with self.assertRaises(TokenError) as ctx:
            parse_token(token_str)
        self.assertEqual(ctx.exception.reason, "bad_format")

    def test_wrong_prefix_and_version(self):
        """B2: wrong prefix, wrong version."""
        good_tail = "mint-a:100:" + KNOWN_SECRET_B64U
        self.assert_bad("xcash:v3:" + good_tail)
        self.assert_bad("AICASH:v3:" + good_tail)
        self.assert_bad(":v3:" + good_tail)
        self.assert_bad("aicash:v2:" + good_tail)
        self.assert_bad("aicash:v4:" + good_tail)
        self.assert_bad("aicash:V3:" + good_tail)

    def test_wrong_field_count(self):
        """B2: 4 or 6 colon-separated fields rejected."""
        self.assert_bad("aicash:v3:mint-a:100")  # 4 fields
        self.assert_bad(
            "aicash:v3:mint-a:100:%s:extra" % KNOWN_SECRET_B64U
        )  # 6 fields
        self.assert_bad("aicash:v3:mint-a:100:%s:" % KNOWN_SECRET_B64U)
        self.assert_bad("")

    def test_bad_base64url_secret(self):
        """B2: '='-padded, '+'/'/' alphabet, embedded newline rejected."""
        self.assert_bad("aicash:v3:mint-a:100:" + KNOWN_SECRET_B64U + "=")
        padded_44 = base64.urlsafe_b64encode(KNOWN_SECRET).decode()
        self.assertIn("=", padded_44)
        self.assert_bad("aicash:v3:mint-a:100:" + padded_44)
        self.assert_bad(
            "aicash:v3:mint-a:100:" + "+" + KNOWN_SECRET_B64U[1:]
        )
        self.assert_bad(
            "aicash:v3:mint-a:100:" + "/" + KNOWN_SECRET_B64U[1:]
        )
        self.assert_bad(
            "aicash:v3:mint-a:100:" + KNOWN_SECRET_B64U[:20] + "\n"
            + KNOWN_SECRET_B64U[20:]
        )
        self.assert_bad(
            "aicash:v3:mint-a:100: " + KNOWN_SECRET_B64U[1:]
        )

    def test_wrong_secret_length(self):
        """B2 / requirement 1: secrets decoding to 31 or 33 bytes rejected."""
        for n in (31, 33, 0, 16, 64):
            enc = b64u_encode(bytes(n))
            self.assert_bad("aicash:v3:mint-a:100:" + enc)

    def test_bad_amounts(self):
        """B2 / requirement 2: amount 0, 007, -5, 1.5, 1e3, +5 rejected."""
        for amt in ("0", "007", "-5", "1.5", "1e3", "+5", "", "10 ", " 10",
                    "0x10", "١٢٣"):
            self.assert_bad(
                "aicash:v3:mint-a:%s:%s" % (amt, KNOWN_SECRET_B64U)
            )

    def test_bad_mint_ids(self):
        """B2 / requirement 3: empty, oversize, uppercase mint_id rejected."""
        for mint in ("", "a" * 65, "MINT", "Mint-a", "mint_a", "mint.a",
                     "mint a", "minté"):
            # NB: an empty mint gives 5 fields with parts[2] == "" — still bad.
            self.assert_bad(
                "aicash:v3:%s:100:%s" % (mint, KNOWN_SECRET_B64U)
            )
        # 64 chars is the maximum and is accepted.
        ok = parse_token(
            "aicash:v3:%s:100:%s" % ("a" * 64, KNOWN_SECRET_B64U)
        )
        self.assertEqual(ok.mint_id, "a" * 64)

    def test_non_canonical_b64u_rejected(self):
        """B2 / requirement 4: strict b64u — nonzero trailing bits (a second
        encoding of the same bytes) are rejected."""
        # Last char '8' (0b111100) -> '9' (0b111101): same 32 bytes under a
        # lenient decoder, different string. Must be rejected.
        mutated = KNOWN_SECRET_B64U[:-1] + "9"
        self.assertEqual(
            base64.urlsafe_b64decode(mutated + "="), KNOWN_SECRET
        )
        self.assert_bad("aicash:v3:mint-a:100:" + mutated)
        with self.assertRaises(TokenError):
            b64u_decode(mutated)

    def test_format_token_rejections(self):
        """B2 / requirements 1-3 on the formatting side."""
        with self.assertRaises(TokenError):
            format_token("mint-a", 0, KNOWN_SECRET)
        with self.assertRaises(TokenError):
            format_token("mint-a", -5, KNOWN_SECRET)
        with self.assertRaises(TokenError):
            format_token("mint-a", 1.5, KNOWN_SECRET)
        with self.assertRaises(TokenError):
            format_token("mint-a", True, KNOWN_SECRET)
        with self.assertRaises(TokenError):
            format_token("mint-a", "100", KNOWN_SECRET)
        with self.assertRaises(TokenError):
            format_token("mint-a", 100, KNOWN_SECRET[:31])
        with self.assertRaises(TokenError):
            format_token("mint-a", 100, KNOWN_SECRET + b"\x00")
        with self.assertRaises(TokenError):
            format_token("mint-a", 100, KNOWN_SECRET_B64U)  # str, not bytes
        with self.assertRaises(TokenError):
            format_token("MINT", 100, KNOWN_SECRET)
        with self.assertRaises(TokenError):
            format_token("", 100, KNOWN_SECRET)
        with self.assertRaises(TokenError):
            format_token("a" * 65, 100, KNOWN_SECRET)

    def test_token_error_is_value_error_with_reason(self):
        """B2: TokenError subclasses ValueError and carries reason
        'bad_format'."""
        self.assertTrue(issubclass(TokenError, ValueError))
        try:
            parse_token("nope")
        except TokenError as e:
            self.assertEqual(e.reason, "bad_format")
        else:
            self.fail("expected TokenError")


class TestB64uAndLedgerKey(unittest.TestCase):
    def test_ledger_key_known_vector(self):
        """B3: ledger_key equals independently computed
        base64url(sha256(raw_secret)) and the hardcoded expected string."""
        self.assertEqual(ledger_key(KNOWN_SECRET), KNOWN_LEDGER_KEY)
        independent = (
            base64.urlsafe_b64encode(hashlib.sha256(KNOWN_SECRET).digest())
            .rstrip(b"=")
            .decode("ascii")
        )
        self.assertEqual(ledger_key(KNOWN_SECRET), independent)

    def test_ledger_key_random_agreement(self):
        """B3: ledger_key agrees with the independent construction on random
        secrets."""
        for _ in range(20):
            s = new_secret()
            independent = (
                base64.urlsafe_b64encode(hashlib.sha256(s).digest())
                .rstrip(b"=")
                .decode("ascii")
            )
            self.assertEqual(ledger_key(s), independent)

    def test_ledger_key_rejects_non_32(self):
        """B3 / requirement 1: ledger keys are hashes of exactly-32-byte
        secrets."""
        with self.assertRaises(TokenError):
            ledger_key(b"\x00" * 31)
        with self.assertRaises(TokenError):
            ledger_key(b"\x00" * 33)
        with self.assertRaises(TokenError):
            ledger_key(KNOWN_SECRET_B64U)  # str, not bytes

    def test_b64u_roundtrip_and_strictness(self):
        """B2/B4 support: b64u encode/decode round-trips; padded, wrong
        alphabet, whitespace, and wrong expect_len are rejected."""
        for n in (0, 1, 2, 3, 31, 32, 33, 100):
            b = n * b"\xfb"  # bytes whose standard b64 uses '+'/'/'
            enc = b64u_encode(b)
            self.assertNotIn("=", enc)
            self.assertNotIn("+", enc)
            self.assertNotIn("/", enc)
            self.assertEqual(b64u_decode(enc), b)
            self.assertEqual(b64u_decode(enc, expect_len=n), b)
        with self.assertRaises(TokenError):
            b64u_decode("AA==")
        with self.assertRaises(TokenError):
            b64u_decode("A+8A")
        with self.assertRaises(TokenError):
            b64u_decode("A/8A")
        with self.assertRaises(TokenError):
            b64u_decode("AA A")
        with self.assertRaises(TokenError):
            b64u_decode("AAAAA")  # len % 4 == 1 is impossible
        with self.assertRaises(TokenError):
            b64u_decode(b64u_encode(b"\x00" * 31), expect_len=32)


class TestCanonicalJson(unittest.TestCase):
    def test_key_order_and_whitespace_insensitivity(self):
        """B4: {"b":1,"a":[2,3]} and parsed '{ "a":[2,3], "b" : 1 }' produce
        identical canonical bytes."""
        a = canonical_json({"b": 1, "a": [2, 3]})
        b = canonical_json(json.loads('{ "a":[2,3], "b" : 1 }'))
        self.assertEqual(a, b)
        self.assertEqual(a, b'{"a":[2,3],"b":1}')

    def test_non_ascii_key_order(self):
        """B4 / requirement 6 (R21, normalize-then-sort): keys sorted by
        Unicode code point on the NFC-normalized key, including non-ASCII
        keys.  The e-acute key is supplied in DECOMPOSED form ('e' +
        U+0301), which under the old raw-key sort would land between 'a'
        and 'z'; after NFC it is U+00E9 (233) and must sort last among the
        Latin keys."""
        decomposed = "e\u0301"  # 'e' + combining acute accent
        composed = "\u00e9"     # e-acute, the NFC form of the above
        self.assertLess(decomposed, "z")   # raw sort would misplace it
        self.assertGreater(composed, "z")  # normalized sort puts it here
        obj = {decomposed: 1, "a": 2, "Z": 3, "z": 4, "中": 5, "0": 6}
        out = canonical_json(obj).decode("utf-8")
        # Normalized code point order: '0'(48) < 'Z'(90) < 'a'(97)
        #                   < 'z'(122) < 'é'(233) < '中'(20013)
        expected = (
            '{"0":6,"Z":3,"a":2,"z":4,"' + composed + '":1,"中":5}'
        )
        self.assertEqual(out, expected)

    def test_float_raises(self):
        """B4 / requirement 6: float input raises everywhere."""
        for bad in (1.5, {"a": 1.5}, [1.5], {"a": [0, {"b": 2.0}]}, 1e3):
            with self.assertRaises(TokenError):
                canonical_json(bad)
            with self.assertRaises(TokenError):
                body_digest(bad)

    def test_nfc_normalization(self):
        """B4: composed and decomposed 'é' produce identical bytes, as
        values and as keys."""
        composed = "\u00e9"  # e-acute, composed form
        decomposed = "e\u0301"  # e + combining acute, decomposed form
        self.assertNotEqual(composed, decomposed)
        self.assertEqual(
            canonical_json({"k": composed}), canonical_json({"k": decomposed})
        )
        self.assertEqual(
            canonical_json({composed: 1}), canonical_json({decomposed: 1})
        )
        self.assertEqual(
            canonical_json(decomposed), '"é"'.encode("utf-8")
        )

    def test_normalized_key_sort_position_and_digest(self):
        """B4 / requirement 6 (R21, normalize-then-sort): an object built
        with a decomposed-form key ('e' + U+0301) and one built with the
        composed form (U+00E9) produce IDENTICAL canonical bytes and
        body_digest, and the key sorts at the COMPOSED form's code-point
        position: U+00E9 (233) sorts after 'f' (102), whereas the raw
        decomposed key would sort between 'd' and 'f'."""
        decomposed = "e\u0301"  # 'e' + combining acute accent
        composed = "\u00e9"     # e-acute, the NFC form of the above
        self.assertNotEqual(decomposed, composed)
        # Raw code-point order would put the decomposed key before 'f';
        # normalized order must put it after 'f'.
        self.assertLess("d", decomposed)
        self.assertLess(decomposed, "f")
        self.assertGreater(composed, "f")

        obj_decomposed = {"f": 2, decomposed: 1, "d": 3}
        obj_composed = {"d": 3, composed: 1, "f": 2}
        out_decomposed = canonical_json(obj_decomposed)
        out_composed = canonical_json(obj_composed)
        # Identical canonical bytes and body_digest regardless of the raw
        # key form used to build the object.
        self.assertEqual(out_decomposed, out_composed)
        self.assertEqual(body_digest(obj_decomposed), body_digest(obj_composed))
        # Exact bytes, computed from the composed form: key order is
        # 'd' < 'f' < U+00E9 on the normalized key.
        expected = ('{"d":3,"f":2,"' + composed + '":1}').encode("utf-8")
        self.assertEqual(out_decomposed, expected)
        # The decomposed byte sequence must not appear in the output.
        self.assertNotIn(decomposed.encode("utf-8"), out_decomposed)

    def test_nfc_key_collision_rejected(self):
        """Requirement 6 (R21): two DISTINCT raw keys that become the same
        key after NFC normalization are rejected with TokenError
        ('bad_format'), at top level and nested."""
        decomposed = "e\u0301"  # 'e' + combining acute accent
        composed = "\u00e9"   # e-acute, the NFC form of the above
        colliding = {decomposed: 1, composed: 2}
        self.assertEqual(len(colliding), 2)  # distinct raw keys
        with self.assertRaises(TokenError) as ctx:
            canonical_json(colliding)
        self.assertEqual(ctx.exception.reason, "bad_format")
        with self.assertRaises(TokenError):
            body_digest(colliding)
        with self.assertRaises(TokenError):
            canonical_json({"outer": [{decomposed: 1, composed: 2}]})

    def test_stable_across_calls_and_types(self):
        """B4 / requirement 6: output stable across calls; ints in plain
        decimal; escapes and scalars pinned."""
        obj = {"n": 10**18, "s": "a\"b\\c\nd", "t": True, "f": False,
               "z": None, "l": [1, "x", None]}
        first = canonical_json(obj)
        self.assertEqual(first, canonical_json(obj))
        self.assertEqual(
            first,
            b'{"f":false,"l":[1,"x",null],"n":1000000000000000000,'
            b'"s":"a\\"b\\\\c\\nd","t":true,"z":null}',
        )
        with self.assertRaises(TokenError):
            canonical_json({"a": object()})
        with self.assertRaises(TokenError):
            canonical_json({1: "non-string key"})

    def test_body_digest_semantic_sensitivity(self):
        """B5: body_digest differs on any semantic change (amount 1→2) and
        is stable across dict insertion orders."""
        d1 = body_digest({"inputs": ["t"], "outputs": [{"amount_mc": 1}]})
        d2 = body_digest({"inputs": ["t"], "outputs": [{"amount_mc": 2}]})
        self.assertNotEqual(d1, d2)
        d1b = body_digest({"outputs": [{"amount_mc": 1}], "inputs": ["t"]})
        self.assertEqual(d1, d1b)
        # Digest is the b64u sha256 of the canonical bytes.
        obj = {"a": [2, 3], "b": 1}
        independent = (
            base64.urlsafe_b64encode(
                hashlib.sha256(b'{"a":[2,3],"b":1}').digest()
            ).rstrip(b"=").decode("ascii")
        )
        self.assertEqual(body_digest(obj), independent)


class TestNewSecret(unittest.TestCase):
    def test_new_secret_length_and_uniqueness(self):
        """B6: new_secret() returns 32 bytes; 1,000 draws contain no
        duplicates."""
        draws = [new_secret() for _ in range(1000)]
        for s in draws:
            self.assertIsInstance(s, bytes)
            self.assertEqual(len(s), 32)
        self.assertEqual(len(set(draws)), 1000)


class TestMintIdRe(unittest.TestCase):
    def test_public_constant_is_the_enforced_rule(self):
        """MINT_ID_RE is exported and is exactly the rule token parsing
        enforces: everything it matches formats/parses, everything it
        rejects raises."""
        import aicash.tokencodec as mod

        self.assertIn("MINT_ID_RE", mod.__all__)
        self.assertEqual(MINT_ID_RE.pattern, r"^[a-z0-9-]{1,64}$")
        secret = new_secret()
        for good in ("a", "mint-1", "a" * 64, "0-9", "testmint"):
            self.assertIsNotNone(MINT_ID_RE.fullmatch(good), good)
            self.assertEqual(
                parse_token(format_token(good, 5, secret)).mint_id, good
            )
        for bad in ("", "A", "mint_1", "a" * 65, "mïnt", "m t", "m:t"):
            self.assertIsNone(MINT_ID_RE.fullmatch(bad), bad)
            with self.assertRaises(TokenError):
                format_token(bad, 5, secret)


class TestModuleHygiene(unittest.TestCase):
    def test_no_io_network_or_logging(self):
        """B7 / requirement 7: the module imports no I/O/network libs and
        contains no print/logging of secret material (grep-level check on
        the module source)."""
        import inspect
        import aicash.tokencodec as mod

        src = inspect.getsource(mod)
        for forbidden in ("print(", "logging", "socket", "urllib",
                          "requests", "http", "subprocess", "sqlite3",
                          "open(", "sys.stdout", "sys.stderr"):
            self.assertNotIn(forbidden, src,
                             "forbidden text %r in tokencodec source"
                             % forbidden)
        allowed_modules = {"base64", "hashlib", "os", "re", "unicodedata",
                           "typing"}
        imported = {
            name for name, val in vars(mod).items()
            if inspect.ismodule(val)
        }
        self.assertTrue(
            imported <= allowed_modules,
            "unexpected imports: %s" % (imported - allowed_modules),
        )


if __name__ == "__main__":
    unittest.main()
