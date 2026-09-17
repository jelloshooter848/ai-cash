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
    MAX_AMOUNT_DIGITS,
    MAX_AMOUNT_MC,
    MAX_JSON_DEPTH,
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


class TestAmountIsBounded(unittest.TestCase):
    """D2, as a class rather than as the one field it was reported in.

    ``_AMOUNT_RE`` used to be an UNBOUNDED digit run and ``parse_token``
    called ``int()`` on whatever matched. Past CPython's int/str conversion
    limit (``sys.set_int_max_str_digits``, 4300 digits by default) ``int()``
    raises a BARE ``ValueError`` — not this module's ``TokenError`` — so it
    escaped every ``except TokenError`` in the tree and surfaced as an
    unenumerated HTTP 500. The first fix widened the exception handling at
    one JSON reader, which covered the output ``amount_mc`` the reporter
    happened to write down; the SAME digits one field over, in an input
    token's amount, went straight back to the 500. Fixed here instead,
    where the type discipline breaks, so every caller of this parser — both
    servers, the wallet, escrow, receipts, swap — is covered at once.
    """

    SECRET = KNOWN_SECRET_B64U

    def amount_token(self, amount_str):
        return "aicash:v3:mint-a:%s:%s" % (amount_str, self.SECRET)

    def test_the_reported_digits_and_every_length_around_them(self):
        """The literal (5,000 digits) and its neighbourhood. 4,299 already
        gave a clean refusal before the fix and must still; 4,301 and up did
        not. All of them are now the same answer, and the length at which
        the behaviour changes is this module's bound, not the
        interpreter's."""
        for digits in (1, 18, MAX_AMOUNT_DIGITS, MAX_AMOUNT_DIGITS + 1,
                       100, 4_299, 4_300, 4_301, 5_000, 10_000, 100_000):
            with self.subTest(digits=digits):
                token = self.amount_token("9" * digits)
                if digits <= MAX_AMOUNT_DIGITS:
                    # Short enough to be a number; may still be too LARGE.
                    try:
                        parsed = parse_token(token)
                    except TokenError:
                        self.assertGreater(int("9" * digits), MAX_AMOUNT_MC)
                        continue
                    self.assertLessEqual(parsed.amount_mc, MAX_AMOUNT_MC)
                    continue
                with self.assertRaises(TokenError) as caught:
                    parse_token(token)
                self.assertEqual(caught.exception.reason, "bad_format")

    def test_nothing_but_token_error_escapes_any_entry_point(self):
        """THE class assertion: no input, however shaped, gets a bare
        ValueError out of this module. A bare ValueError is what made D2 a
        500 instead of a §3.8 reason, and `TokenError` is itself a
        ValueError subclass, so `except ValueError` at a caller was never
        the thing that was missing — an error in THIS module's vocabulary
        was."""
        huge = "9" * 5_000
        hostile_tokens = [
            self.amount_token(huge),
            self.amount_token("1" + huge),
            self.amount_token("9" * 4_301),
            self.amount_token("0" * 5_000),          # leading zeros too
            "aicash:v3:" + "a" * 64 + ":%s:%s" % (huge, self.SECRET),
            "aicash:v3:mint-a:%s:%s" % (huge, "!" * 43),
        ]
        for token in hostile_tokens:
            with self.subTest(token=token[:40] + "..."):
                try:
                    parse_token(token)
                except TokenError:
                    pass
                except Exception as exc:  # noqa: BLE001 - that IS the test
                    self.fail("%s escaped parse_token: %s"
                              % (type(exc).__name__, exc))
        for name, amount in (("max+1", MAX_AMOUNT_MC + 1),
                             ("10**25", 10 ** 25),
                             ("10**5000", 10 ** 5_000),
                             ("2**64", 2 ** 64),
                             ("1<<20000", 1 << 20_000)):
            with self.subTest(name):
                try:
                    format_token("mint-a", amount, KNOWN_SECRET)
                except TokenError:
                    pass
                except Exception as exc:  # noqa: BLE001
                    self.fail("%s escaped format_token: %s"
                              % (type(exc).__name__, exc))

    def test_the_bound_is_the_ledgers_and_its_edges_are_exact(self):
        """MAX_AMOUNT_MC is the largest value a signed 64-bit ledger column
        holds. One below, and it itself, are ordinary amounts; one above is
        malformed, because no mint could have issued it and no ledger could
        hold it."""
        self.assertEqual(MAX_AMOUNT_MC, (1 << 63) - 1)
        self.assertEqual(MAX_AMOUNT_DIGITS, len(str(MAX_AMOUNT_MC)))
        for good in (1, 2, MAX_AMOUNT_MC - 1, MAX_AMOUNT_MC):
            with self.subTest(good=good):
                self.assertEqual(
                    parse_token(self.amount_token(str(good))).amount_mc, good
                )
        for bad in (MAX_AMOUNT_MC + 1, 1 << 63, 9_999_999_999_999_999_999):
            with self.subTest(bad=bad):
                with self.assertRaises(TokenError):
                    parse_token(self.amount_token(str(bad)))

    def test_the_encoder_and_the_decoder_agree_on_the_bound(self):
        """A bound enforced on only one side lets this module emit a token
        it refuses to read back — and lets `"%d" %` raise the same bare
        ValueError on the way out that `int()` raised on the way in."""
        for amount in (1, MAX_AMOUNT_MC - 1, MAX_AMOUNT_MC):
            self.assertEqual(
                parse_token(
                    format_token("mint-a", amount, KNOWN_SECRET)
                ).amount_mc,
                amount,
            )
        for name, amount in (("max+1", MAX_AMOUNT_MC + 1),
                             ("2**64", 1 << 64),
                             ("10**4301", 10 ** 4_301)):
            with self.subTest(name):
                with self.assertRaises(TokenError):
                    format_token("mint-a", amount, KNOWN_SECRET)

    def test_the_pattern_itself_cannot_hand_int_an_oversized_string(self):
        """The defence is the PATTERN, not a check after the conversion.
        A converter that is only reachable with inputs it can represent
        cannot raise, so there is no exception left to forget to catch —
        which is the difference between fixing this shape and catching it.
        """
        import aicash.tokencodec as mod

        self.assertIsNone(mod._AMOUNT_RE.fullmatch("9" * (MAX_AMOUNT_DIGITS
                                                          + 1)))
        self.assertIsNotNone(mod._AMOUNT_RE.fullmatch("9" * MAX_AMOUNT_DIGITS))
        # Every string the pattern accepts is one int() can convert without
        # meeting any interpreter limit.
        self.assertLess(MAX_AMOUNT_DIGITS, 4_300)


class TestCanonicalJsonIntegersAreBounded(unittest.TestCase):
    """The same conversion, arrow reversed — the sibling found by looking
    for the shape rather than for the report.

    ``_canon`` type-checked an int and then called ``str()`` on it, and
    ``str(int)`` raises the SAME bare ValueError past the conversion limit
    that ``int(str)`` does. Canonical JSON is the signing and digest form
    (§3.3), so a bare ValueError there escapes into whatever is computing a
    digest — in C06 that is `body_digest(body)` inside an `except
    TokenError`, one field away from another 500.
    """

    def test_an_integer_too_large_to_render_is_a_token_error(self):
        for name, value in (("10**5000", 10 ** 5_000),
                            ("-10**5000", -(10 ** 5_000)),
                            ("10**4301", 10 ** 4_301)):
            with self.subTest(name):
                with self.assertRaises(TokenError):
                    canonical_json({"n": value})
                with self.assertRaises(TokenError):
                    body_digest({"n": value})

    def test_a_value_the_renderer_can_still_print_is_left_alone(self):
        """The DOMAIN is not this round's to narrow. §3.3 is ratified and
        puts no bound on a JSON integer, and C06 pins a 4,299-digit
        ``amount_mc`` as something the money rules get to judge rather than
        the envelope parser — so an int64 bound here would be a normative
        change made by the back door. Only the ERROR TYPE moved."""
        for ok in (MAX_AMOUNT_MC + 1, -MAX_AMOUNT_MC - 2, 10 ** 25,
                   10 ** 4_299):
            with self.subTest(digits=len(str(ok))):
                self.assertEqual(canonical_json({"n": ok}),
                                 ('{"n":%d}' % ok).encode())

    def test_the_guard_is_total_not_a_list_of_known_bad_values(self):
        """Every way ``str()`` can refuse an int becomes TokenError, so
        there is no second spelling to come back for — including the one
        that appears when someone RAISES the interpreter's limit and the
        boundary moves underneath this module."""
        import sys

        original = sys.get_int_max_str_digits()
        self.addCleanup(sys.set_int_max_str_digits, original)
        sys.set_int_max_str_digits(640)  # the interpreter's floor
        try:
            with self.assertRaises(TokenError):
                canonical_json({"n": 10 ** 700})
            self.assertEqual(canonical_json({"n": 10 ** 600}),
                             ('{"n":%d}' % 10 ** 600).encode())
        finally:
            sys.set_int_max_str_digits(original)

    def test_every_integer_the_protocol_actually_carries_still_encodes(self):
        """Regression guard on the bound itself: amounts, millisecond
        timestamps, ppm rates, expiries and counters all fit."""
        self.assertEqual(
            canonical_json(
                {"a": MAX_AMOUNT_MC, "b": -MAX_AMOUNT_MC - 1, "c": 0,
                 "t": 1_756_000_000_000, "ppm": 10_000, "exp": 10 ** 15}
            ),
            b'{"a":9223372036854775807,"b":-9223372036854775808,"c":0,'
            b'"exp":1000000000000000,"ppm":10000,"t":1756000000000}',
        )

    def test_nested_and_listed_integers_are_bounded_too(self):
        """Not one call site: the check lives in the recursive renderer, so
        a huge int is refused wherever it sits in the document."""
        for name, doc in (("nested dict", {"a": {"b": [1, {"c": 10 ** 5_000}]}}),
                          ("bare list", [10 ** 5_000]),
                          ("list of lists", {"k": [[[10 ** 4_400]]]})):
            with self.subTest(name):
                with self.assertRaises(TokenError):
                    canonical_json(doc)


class TestCanonicalJsonRaisesOnlyTokenError(unittest.TestCase):
    """The D2 class, stated as the property instead of as its instances.

    D2's root cause was written down as "the pattern admitted values the
    conversion could not represent, and the conversion raised an error type
    the route does not catch". Every caller of this module guards
    canonicalization with ``except TokenError`` — C06's exchange route does
    it one line before computing a digest — so the property that actually
    protects them is not "the reported value is refused" but "NOTHING that
    leaves this function is anything other than a TokenError".

    Two converters were still outside that property after the round that
    closed the integer one, and both reproduced the identical original
    symptom (HTTP 500, no enumerated reason) from an anonymous request:
    ``str.encode`` raising ``UnicodeEncodeError`` on an unpaired surrogate,
    and ``_canon``'s own Python recursion raising ``RecursionError`` on a
    document a few hundred levels deep. Both are ``Exception`` and neither
    is a ``TokenError``. These tests assert the property directly, so a
    third converter cannot be found the same way twice.
    """

    def assert_only_token_error(self, doc, label):
        with self.subTest(label):
            try:
                canonical_json(doc)
            except TokenError:
                pass
            except BaseException as exc:  # noqa: B036 - that IS the assertion
                self.fail("%s raised %s, not TokenError: %r"
                          % (label, type(exc).__name__, exc))
            else:
                self.fail("%s was rendered; it should have been refused"
                          % label)

    # -- unpaired surrogates --------------------------------------------

    def test_an_unpaired_surrogate_is_a_token_error_wherever_it_sits(self):
        """Not one field: the renderer descends, so every position that can
        hold a string is the same defect. The reporter's own example used
        ``idempotency_key``; the fix must not be about that key."""
        for label, doc in (
            ("bare string", "\ud800"),
            ("idempotency_key",
             {"idempotency_key": "\ud800", "inputs": [], "outputs": []}),
            ("an extra top-level field",
             {"idempotency_key": "k", "inputs": [], "outputs": [],
              "j": "\udfff"}),
            ("an object KEY", {"\ud800": 1}),
            ("inside a list", {"inputs": ["\ud800"]}),
            ("nested three deep", {"a": {"b": [{"c": "\ud83d"}]}}),
            ("low surrogate alone", "\udc00"),
            ("the last surrogate code point", "\udfff"),
            ("a surrogate pair written backwards", "\udc00\ud800"),
            ("surrounded by ordinary text", "ok-\ud800-ok"),
        ):
            self.assert_only_token_error(doc, label)

    def test_every_surrogate_code_point_is_refused(self):
        """The whole block D800-DFFF, sampled across its range rather than
        at the two ends someone happened to report."""
        for cp in range(0xD800, 0xE000, 37):
            self.assert_only_token_error(chr(cp), "U+%04X" % cp)

    def test_a_legal_pair_is_not_refused(self):
        """This is a rule about MALFORMED input, and it has to stay one.

        A JSON document written with an escaped surrogate PAIR is decoded
        by ``json.loads`` into the single astral code point it denotes, so
        emoji, rare CJK and every other non-BMP character reach this module
        as ordinary characters and must render unchanged.
        """
        for text in ("\U0001F600", "\U0001F4B0 paid", "\U00020BB7",
                     "\U0010FFFF"):
            with self.subTest(text.encode("unicode_escape")):
                self.assertEqual(canonical_json(text),
                                 ('"%s"' % text).encode("utf-8"))
        parsed = json.loads('"\\ud83d\\ude00"')
        self.assertEqual(parsed, "\U0001F600")
        self.assertEqual(canonical_json(parsed), '"\U0001F600"'.encode("utf-8"))

    def test_body_digest_refuses_the_same_documents(self):
        """``body_digest`` is what C06 actually calls, and it is a different
        function; a guard that only held on ``canonical_json`` would leave
        the reported call path exactly as it was."""
        with self.assertRaises(TokenError):
            body_digest({"idempotency_key": "\ud800", "inputs": [],
                         "outputs": []})
        with self.assertRaises(TokenError):
            body_digest({"a": [[["\udfff"]]]})

    def test_the_refusal_says_what_is_wrong(self):
        """§3.8 owes an enumerated reason, and TokenError carries one."""
        with self.assertRaises(TokenError) as caught:
            canonical_json("\ud800")
        self.assertEqual(caught.exception.reason, "bad_format")
        self.assertIn("surrogate", str(caught.exception))

    # -- depth -----------------------------------------------------------

    def nest(self, depth, kind):
        doc = 1
        for _ in range(depth):
            doc = [doc] if kind == "list" else {"k": doc}
        return doc

    def test_a_document_deeper_than_the_bound_is_a_token_error(self):
        """The reported window was 500-2000 levels: deep enough that
        ``json.loads`` succeeds (so C06's body reader never sees it) and
        deep enough that ``_canon``'s own recursion does not. Swept well
        past both ends."""
        for depth in (MAX_JSON_DEPTH + 1, 200, 500, 600, 1_000, 2_000,
                      5_000):
            for kind in ("list", "dict"):
                self.assert_only_token_error(
                    self.nest(depth, kind), "%s x%d" % (kind, depth)
                )

    def test_the_bound_is_deeper_than_anything_the_protocol_builds(self):
        """The cost has to be nothing. The deepest document this system
        canonicalizes is an exchange call — envelope, outputs list, an
        output object, its lock — which is four."""
        self.assertGreaterEqual(MAX_JSON_DEPTH, 32)
        call = {"idempotency_key": "k", "inputs": ["aicash:v3:m:1:s"],
                "outputs": [{"amount_mc": 1, "secret_hash": "h",
                             "lock": {"preimage_hash": "p", "expiry": 1,
                                      "refund_hash": "r"}}]}
        self.assertIn(b'"amount_mc":1', canonical_json(call))
        for depth in (1, 8, MAX_JSON_DEPTH - 1, MAX_JSON_DEPTH):
            with self.subTest(depth=depth):
                self.assertTrue(canonical_json(self.nest(depth, "list")))
                self.assertTrue(canonical_json(self.nest(depth, "dict")))

    def test_the_bound_does_not_move_with_the_stack_it_is_called_from(self):
        """Why the depth is COUNTED rather than left to RecursionError.

        The interpreter's limit is a budget shared with every frame already
        on the stack, so a rule that fired only there would refuse a
        document on one call path and render it on another — and the deep
        call path is the ordinary one for a server. A counted bound gives
        the same answer everywhere.
        """
        doc = self.nest(MAX_JSON_DEPTH, "list")
        deep_doc = self.nest(MAX_JSON_DEPTH + 1, "list")
        expected = canonical_json(doc)

        def recurse(n):
            if n:
                return recurse(n - 1)
            self.assertEqual(canonical_json(doc), expected)
            with self.assertRaises(TokenError):
                canonical_json(deep_doc)
            return True

        self.assertTrue(recurse(300))

    def test_mixed_shapes_are_counted_the_same_way(self):
        """Depth is depth: alternating containers, and a deep branch hidden
        beside a shallow one, are both measured."""
        doc = 1
        for i in range(MAX_JSON_DEPTH + 40):
            doc = [doc] if i % 2 else {"k": doc}
        self.assert_only_token_error(doc, "alternating containers")
        self.assert_only_token_error(
            {"shallow": 1, "deep": self.nest(MAX_JSON_DEPTH + 5, "list")},
            "a deep branch beside a shallow one",
        )

    # -- the property, over a corpus -------------------------------------

    def test_no_document_in_the_corpus_escapes_as_another_exception(self):
        """The assertion the last round needed and did not make: sweep the
        hostile shapes together and require the TYPE, not the message."""
        corpus = [
            ("float", {"a": 1.5}),
            ("nan", float("nan")),
            ("bytes", b"raw"),
            ("set", {1, 2}),
            ("non-str key", {1: "a"}),
            ("huge int", {"n": 10 ** 5_000}),
            ("surrogate", "\ud800"),
            ("surrogate key", {"\udfff": 1}),
            ("deep list", self.nest(900, "list")),
            ("deep dict", self.nest(900, "dict")),
            ("deep and surrogate", self.nest(900, "list") + ["\ud800"]),
            ("surrogate under a huge int",
             {"a": {"b": ["\ud800", 10 ** 5_000]}}),
            ("complex", 1j),
            ("a class", TokenError),
        ]
        for label, doc in corpus:
            self.assert_only_token_error(doc, label)


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
