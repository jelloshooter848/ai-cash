"""Tests for C02 — lockeval (spec §3.4, §3.8; component spec C02-lockeval.md).

Each test's docstring names the benchmark item(s) it covers (B1–B7).

C02 treats the token as opaque (component requirement 4: secret-to-entry
binding is C04's job), so these tests use a sentinel object for the token.
"""

import base64
import hashlib
import inspect
import unittest

from aicash import lockeval
from aicash.lockeval import InputForm, Lock, LockError, evaluate, validate_lock


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


# Deterministic test material.
PREIMAGE = b"\x11" * 32
REFUND_SECRET = b"\x22" * 32
WRONG32 = b"\x33" * 32
SHORT31 = b"\x44" * 31
LONG33 = b"\x55" * 33
EXPIRY = 1_756_000_000_000  # ms since epoch (arbitrary fixed instant)

LOCK = Lock(
    preimage_hash=b64u(hashlib.sha256(PREIMAGE).digest()),
    expiry=EXPIRY,
    refund_hash=b64u(hashlib.sha256(REFUND_SECRET).digest()),
)

TOKEN = object()  # opaque to C02


def plain():
    return InputForm(kind="plain", token=TOKEN)


def claim(witness):
    return InputForm(kind="claim", token=TOKEN, witness=witness)


def refund(witness, hash_=b64u(b"\x66" * 32)):
    return InputForm(kind="refund", hash=hash_, witness=witness)


REASONS = {
    "ok",
    "bad_format",
    "lock_preimage_invalid",
    "lock_expired",
    "lock_not_expired",
    "refund_invalid",
    "bad_witness_length",
}


class TestTruthTable(unittest.TestCase):
    def test_exhaustive_truth_table(self):
        """B1: {unlocked, locked} x {plain, claim, refund} x {before, at, after
        expiry} x {good, bad, short(31), long(33) witness} — every listed §3.8
        reason is produced at least once and no case returns anything outside
        the table."""
        times = {"before": EXPIRY - 1, "at": EXPIRY, "after": EXPIRY + 1}
        witnesses = {
            "claim": {"good": PREIMAGE, "bad": WRONG32, "short": SHORT31, "long": LONG33},
            "refund": {"good": REFUND_SECRET, "bad": WRONG32, "short": SHORT31, "long": LONG33},
        }

        def expected(locked, kind, time_rel, wq):
            # Oracle transcribed from the component-spec truth table, with the
            # recorded interim resolution: the witness length gate fires before
            # the temporal path split on locked entries (§3.4 unconditional
            # "MUST reject any witness ... other than 32 bytes").
            if kind == "plain":
                return "ok" if not locked else "lock_preimage_invalid"
            if not locked:
                return "bad_format"  # witness-bearing form on unlocked input
            if wq in ("short", "long"):
                return "bad_witness_length"
            if kind == "claim":
                if time_rel in ("at", "after"):
                    return "lock_expired"
                return "ok" if wq == "good" else "lock_preimage_invalid"
            # refund
            if time_rel == "before":
                return "lock_not_expired"
            return "ok" if wq == "good" else "refund_invalid"

        produced = set()
        for locked in (False, True):
            lock = LOCK if locked else None
            for kind in ("plain", "claim", "refund"):
                for time_rel, now_ms in times.items():
                    wqs = ("n/a",) if kind == "plain" else ("good", "bad", "short", "long")
                    for wq in wqs:
                        if kind == "plain":
                            form = plain()
                        elif kind == "claim":
                            form = claim(witnesses["claim"][wq])
                        else:
                            form = refund(witnesses["refund"][wq])
                        got = evaluate(lock, form, now_ms)
                        want = expected(locked, kind, time_rel, wq)
                        self.assertEqual(
                            got,
                            want,
                            f"locked={locked} kind={kind} time={time_rel} wq={wq}",
                        )
                        self.assertIn(got, REASONS)
                        produced.add(got)
        self.assertEqual(produced, REASONS, "every reason in the table must be produced")

    def test_unlocked_plain_ok(self):
        """B1: unlocked entry + plain form -> ok."""
        self.assertEqual(evaluate(None, plain(), EXPIRY - 1), "ok")

    def test_unlocked_witness_forms_bad_format(self):
        """B1: unlocked entry + claim/refund form -> bad_format, regardless of
        witness quality or length."""
        for w in (PREIMAGE, WRONG32, SHORT31, LONG33):
            self.assertEqual(evaluate(None, claim(w), EXPIRY - 1), "bad_format")
            self.assertEqual(evaluate(None, refund(w), EXPIRY + 1), "bad_format")

    def test_locked_plain_lock_preimage_invalid(self):
        """B1: locked entry + plain form -> lock_preimage_invalid (claim path
        requires a witness), on both sides of expiry."""
        self.assertEqual(evaluate(LOCK, plain(), EXPIRY - 1), "lock_preimage_invalid")
        self.assertEqual(evaluate(LOCK, plain(), EXPIRY + 1), "lock_preimage_invalid")


class TestExpiryBoundary(unittest.TestCase):
    def test_at_expiry_belongs_to_refund_path(self):
        """B2: now == expiry -> claim with valid preimage returns lock_expired;
        refund with valid refund secret returns ok (R3: the boundary belongs
        to the refund path)."""
        self.assertEqual(evaluate(LOCK, claim(PREIMAGE), EXPIRY), "lock_expired")
        self.assertEqual(evaluate(LOCK, refund(REFUND_SECRET), EXPIRY), "ok")

    def test_one_ms_before_expiry_reversed(self):
        """B2: now == expiry - 1 -> claim with valid preimage returns ok;
        refund with valid refund secret returns lock_not_expired."""
        self.assertEqual(evaluate(LOCK, claim(PREIMAGE), EXPIRY - 1), "ok")
        self.assertEqual(evaluate(LOCK, refund(REFUND_SECRET), EXPIRY - 1), "lock_not_expired")

    def test_after_expiry(self):
        """B2 (adjacent): now == expiry + 1 behaves like the boundary."""
        self.assertEqual(evaluate(LOCK, claim(PREIMAGE), EXPIRY + 1), "lock_expired")
        self.assertEqual(evaluate(LOCK, refund(REFUND_SECRET), EXPIRY + 1), "ok")


class TestWitnessLength(unittest.TestCase):
    def test_31_byte_witness_rejected_even_if_hash_matches(self):
        """B3: a 31-byte witness -> bad_witness_length even when its sha256
        would match the lock's hash."""
        lock = Lock(
            preimage_hash=b64u(hashlib.sha256(SHORT31).digest()),
            expiry=EXPIRY,
            refund_hash=b64u(hashlib.sha256(SHORT31).digest()),
        )
        self.assertEqual(evaluate(lock, claim(SHORT31), EXPIRY - 1), "bad_witness_length")
        self.assertEqual(evaluate(lock, refund(SHORT31), EXPIRY), "bad_witness_length")

    def test_33_byte_witness_rejected_even_if_hash_matches(self):
        """B3: a 33-byte witness -> bad_witness_length even when its sha256
        would match the lock's hash."""
        lock = Lock(
            preimage_hash=b64u(hashlib.sha256(LONG33).digest()),
            expiry=EXPIRY,
            refund_hash=b64u(hashlib.sha256(LONG33).digest()),
        )
        self.assertEqual(evaluate(lock, claim(LONG33), EXPIRY - 1), "bad_witness_length")
        self.assertEqual(evaluate(lock, refund(LONG33), EXPIRY), "bad_witness_length")

    def test_length_gate_precedes_temporal_reasons(self):
        """B3 + component requirement 2: on a locked entry the length check
        fires before any other witness handling — including on the expired
        claim path and the not-yet-expired refund path."""
        self.assertEqual(evaluate(LOCK, claim(SHORT31), EXPIRY + 1), "bad_witness_length")
        self.assertEqual(evaluate(LOCK, refund(LONG33), EXPIRY - 1), "bad_witness_length")

    def test_empty_witness(self):
        """B3 (edge): a 0-byte witness on a locked entry -> bad_witness_length."""
        self.assertEqual(evaluate(LOCK, claim(b""), EXPIRY - 1), "bad_witness_length")
        self.assertEqual(evaluate(LOCK, refund(b""), EXPIRY), "bad_witness_length")


class TestKnownVector(unittest.TestCase):
    # Hardcoded pair: preimage bytes 00 01 02 ... 1f and its SHA-256 digest.
    KV_PREIMAGE = bytes(range(32))
    KV_DIGEST_B64U = "Yw3NKWbEM2aRElRIu7JbT_QSpJxzLbLIq8G4WBvXEN0"
    KV_DIGEST_HEX = "630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd"

    def test_known_vector(self):
        """B4: hardcoded preimage/hash pair verified against hashlib computed
        in the test itself, then accepted by evaluate on the claim path."""
        digest = hashlib.sha256(self.KV_PREIMAGE).digest()
        self.assertEqual(digest.hex(), self.KV_DIGEST_HEX)
        self.assertEqual(b64u(digest), self.KV_DIGEST_B64U)
        lock = Lock(
            preimage_hash=self.KV_DIGEST_B64U,
            expiry=EXPIRY,
            refund_hash=b64u(hashlib.sha256(REFUND_SECRET).digest()),
        )
        self.assertEqual(evaluate(lock, claim(self.KV_PREIMAGE), EXPIRY - 1), "ok")
        # One flipped bit in the witness must fail.
        flipped = bytes([self.KV_PREIMAGE[0] ^ 1]) + self.KV_PREIMAGE[1:]
        self.assertEqual(evaluate(lock, claim(flipped), EXPIRY - 1), "lock_preimage_invalid")


class TestCrossWitness(unittest.TestCase):
    def test_claim_never_accepts_refund_secret(self):
        """B5: the claim path rejects the (correct-length) refund secret."""
        self.assertEqual(evaluate(LOCK, claim(REFUND_SECRET), EXPIRY - 1), "lock_preimage_invalid")

    def test_refund_never_accepts_claim_preimage(self):
        """B5: the refund path rejects the (correct-length) claim preimage."""
        self.assertEqual(evaluate(LOCK, refund(PREIMAGE), EXPIRY), "refund_invalid")
        self.assertEqual(evaluate(LOCK, refund(PREIMAGE), EXPIRY + 1), "refund_invalid")

    def test_cross_witness_with_identical_hashes_still_path_bound(self):
        """B5: even when preimage_hash == refund_hash, each path compares only
        against its own hash field (the shared witness then opens both paths —
        but only via that path's own field and temporal window)."""
        same = b64u(hashlib.sha256(PREIMAGE).digest())
        lock = Lock(preimage_hash=same, expiry=EXPIRY, refund_hash=same)
        self.assertEqual(evaluate(lock, claim(PREIMAGE), EXPIRY - 1), "ok")
        self.assertEqual(evaluate(lock, refund(PREIMAGE), EXPIRY), "ok")
        self.assertEqual(evaluate(lock, refund(REFUND_SECRET), EXPIRY), "refund_invalid")


class TestValidateLock(unittest.TestCase):
    GOOD = {
        "preimage_hash": b64u(hashlib.sha256(PREIMAGE).digest()),
        "expiry": EXPIRY,
        "refund_hash": b64u(hashlib.sha256(REFUND_SECRET).digest()),
    }

    def assert_rejected(self, obj):
        with self.assertRaises(LockError) as ctx:
            validate_lock(obj)
        self.assertEqual(ctx.exception.reason, "bad_format")

    def test_valid_lock_parses(self):
        """B6 (positive control): a well-formed lock dict parses into a frozen
        Lock carrying the exact field values."""
        lock = validate_lock(dict(self.GOOD))
        self.assertEqual(lock.preimage_hash, self.GOOD["preimage_hash"])
        self.assertEqual(lock.expiry, EXPIRY)
        self.assertEqual(lock.refund_hash, self.GOOD["refund_hash"])
        with self.assertRaises(Exception):
            lock.expiry = 1  # frozen dataclass

    def test_missing_fields(self):
        """B6: each missing field -> LockError("bad_format"); empty dict and
        non-dict inputs rejected too."""
        for field in ("preimage_hash", "expiry", "refund_hash"):
            bad = dict(self.GOOD)
            del bad[field]
            self.assert_rejected(bad)
        self.assert_rejected({})
        self.assert_rejected(None)
        self.assert_rejected([self.GOOD])
        self.assert_rejected("not a dict")

    def test_extra_field_rejected(self):
        """B6 (strictness): an unknown extra key is rejected — the §3.4 lock
        object has exactly three pinned fields."""
        bad = dict(self.GOOD)
        bad["oracle"] = "no"
        self.assert_rejected(bad)

    def test_non_b64u_hashes(self):
        """B6: non-b64u hash strings rejected: padding, +, /, whitespace,
        non-canonical trailing bits, empty, non-string."""
        digest43 = self.GOOD["preimage_hash"]
        bad_hashes = [
            digest43 + "=",  # padded
            digest43[:-1] + "+",  # standard-alphabet char
            digest43[:-1] + "/",
            digest43[:-1] + " ",
            digest43 + "\n",
            "",
            42,
            None,
            hashlib.sha256(PREIMAGE).digest(),  # raw bytes, not str
            b64u(b"\x00" * 32)[:-1] + "B",  # nonzero trailing bits (non-canonical)
        ]
        for field in ("preimage_hash", "refund_hash"):
            for bh in bad_hashes:
                bad = dict(self.GOOD)
                bad[field] = bh
                self.assert_rejected(bad)

    def test_wrong_digest_lengths(self):
        """B6: 31-byte and 33-byte digests (valid b64u, wrong length) rejected."""
        for raw in (b"\x01" * 31, b"\x01" * 33, b"", b"\x01" * 16, b"\x01" * 64):
            for field in ("preimage_hash", "refund_hash"):
                bad = dict(self.GOOD)
                bad[field] = b64u(raw)
                self.assert_rejected(bad)

    def test_bad_expiry(self):
        """B6: float / negative / zero expiry rejected; also bool, string,
        None. Positive ints (including 1 and very large) accepted."""
        for bad_expiry in (1000.5, float(EXPIRY), -1, 0, True, False, "1000", None, [EXPIRY]):
            bad = dict(self.GOOD)
            bad["expiry"] = bad_expiry
            self.assert_rejected(bad)
        for good_expiry in (1, EXPIRY, 10**15):
            ok = dict(self.GOOD)
            ok["expiry"] = good_expiry
            self.assertEqual(validate_lock(ok).expiry, good_expiry)

    def test_lockerror_is_valueerror_with_reason(self):
        """B6: LockError subclasses ValueError and carries reason 'bad_format'."""
        self.assertTrue(issubclass(LockError, ValueError))
        self.assertEqual(LockError().reason, "bad_format")


class TestFormShape(unittest.TestCase):
    """Defensive form-legality checks (component API: exactly one of the three
    §3.3 shapes; anything else is bad_format)."""

    def test_malformed_forms_bad_format(self):
        """B1 (edge closure): InputForm combinations that match none of the
        three §3.3 shapes -> bad_format, never a crash, locked or not."""
        malformed = [
            InputForm(kind="claim", token=TOKEN, witness=None),  # claim w/o witness
            InputForm(kind="claim", token=None, witness=PREIMAGE),  # claim w/o token
            InputForm(kind="claim", token=TOKEN, hash=b64u(b"\x01" * 32), witness=PREIMAGE),
            InputForm(kind="refund", hash=None, witness=REFUND_SECRET),  # refund w/o hash
            InputForm(kind="refund", hash=b64u(b"\x01" * 32), witness=None),
            InputForm(kind="refund", token=TOKEN, hash=b64u(b"\x01" * 32), witness=REFUND_SECRET),
            InputForm(kind="plain", token=None),  # plain w/o token
            InputForm(kind="plain", token=TOKEN, witness=PREIMAGE),  # plain w/ witness
            InputForm(kind="plain", token=TOKEN, hash=b64u(b"\x01" * 32)),
            InputForm(kind="bogus", token=TOKEN),  # unknown kind
        ]
        for form in malformed:
            for lock in (None, LOCK):
                for now_ms in (EXPIRY - 1, EXPIRY, EXPIRY + 1):
                    self.assertEqual(evaluate(lock, form, now_ms), "bad_format", form)


class TestCodeProperties(unittest.TestCase):
    def test_constant_time_comparison(self):
        """B7: digest comparisons use hmac.compare_digest, never '==' — code
        inspection of the module source."""
        src = inspect.getsource(lockeval)
        self.assertIn("hmac.compare_digest", src)
        # No direct equality on computed digests anywhere in the module.
        self.assertNotIn(".digest() ==", src)
        self.assertNotIn("== hashlib", src)
        # The one comparison helper routes through compare_digest.
        helper_src = inspect.getsource(lockeval._witness_matches)
        self.assertIn("compare_digest", helper_src)

    def test_purity_no_clock_or_io(self):
        """Component requirement 5 (supports B1 trustworthiness): the module
        reads no clock and performs no I/O — no time/os/socket/sqlite imports,
        no open() calls."""
        src = inspect.getsource(lockeval)
        for banned in ("import time", "import os", "import socket", "import sqlite3",
                       "import urllib", "open(", "system_clock"):
            self.assertNotIn(banned, src)

    def test_dataclasses_frozen(self):
        """API shape: Lock and InputForm are frozen dataclasses."""
        with self.assertRaises(Exception):
            LOCK.expiry = 0
        form = plain()
        with self.assertRaises(Exception):
            form.kind = "claim"


if __name__ == "__main__":
    unittest.main()
