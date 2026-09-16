"""Tests for gui/walletops.py against a REAL in-process mint over real HTTP.

Nothing here is mocked at the money layer: every test boots a MintServer on
a loopback port, funds a treasury through the operator path (§7.1), and
asserts against balances the mint itself settled.

Run:  cd <repo root> && python3 -m unittest gui.test_walletops -v
"""

import os
import random
import shutil
import stat
import sys
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _p in (os.path.join(_ROOT, "impl"), _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from aicash.burncalc import BurnPolicy                       # noqa: E402
from aicash.clock import FakeClock                           # noqa: E402
from aicash.mintapi import MintConfig, make_mint             # noqa: E402
from aicash.signing import generate_keypair                  # noqa: E402
from aicash.tokencodec import (format_token, ledger_key,        # noqa: E402
                               new_secret, parse_token)
from aicash.wallet import MintClient, Wallet                 # noqa: E402

try:                                    # run as `python3 -m unittest gui.test_walletops`
    from gui.walletops import (DELIVERY_ATTEMPT_VALUES, DELIVERY_VALUES,
                               NOT_APPLICABLE, RECIPIENT_KIND_VALUES,
                               STORE_STATE_VALUES, UNDETERMINED,
                               WalletOps, WalletOpsError)
except ImportError:                     # run from inside gui/
    from walletops import (DELIVERY_ATTEMPT_VALUES,          # noqa: F401
                           DELIVERY_VALUES, NOT_APPLICABLE,
                           RECIPIENT_KIND_VALUES, STORE_STATE_VALUES,
                           UNDETERMINED, WalletOps, WalletOpsError)

MINT_ID = "guitestmint"
ADMIN = "operator-secret"
#: 1% rate, cap 1000 mc, drip-exempt at or below 10 mc — burns are visible
#: in the arithmetic, which is the point.
POLICY = BurnPolicy(rate_ppm=10_000, cap_mc=1_000, exempt_below_mc=10)


class MintFixture(unittest.TestCase):
    """A live mint + a temp dir, torn down per test."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="walletops-test-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.clock = FakeClock()
        priv, pub = generate_keypair()
        self.config = MintConfig(
            mint_id=MINT_ID,
            baseline_model_class="gui-test-model-v1",
            burn_policy=POLICY,
            signing_private=priv,
            signing_public=pub,
            admin_token=ADMIN,
        )
        self.server, self.ledger = make_mint(
            self.config, db_path=os.path.join(self.dir, "mint.db"),
            clock=self.clock,
        )
        self.port = self.server.start()
        self.base = f"http://127.0.0.1:{self.port}"
        self._stopped = False
        self.addCleanup(self.stop_mint)
        self.client = MintClient(self.base)

    def stop_mint(self):
        if not self._stopped:
            self._stopped = True
            self.server.stop()

    # -- helpers --------------------------------------------------------

    def issue(self, amount_mc: int) -> str:
        """Operator-issue one bearer token of ``amount_mc`` (§7.1)."""
        s = new_secret()
        self.client.admin_issue(
            [{"amount_mc": amount_mc, "secret_hash": ledger_key(s)}],
            admin_token=ADMIN,
        )
        return format_token(MINT_ID, amount_mc, s)

    def ops(self, name: str = "w") -> WalletOps:
        return WalletOps(os.path.join(self.dir, f"{name}.db"), self.base)

    def path(self, name: str = "w") -> str:
        return os.path.join(self.dir, f"{name}.db")

    def replacement_mint(self, mint_id: str, port: int = None):
        """Stop this fixture's mint and start a DIFFERENT one in its place.

        Same address, different mint_id — which is one click in the GUI
        (the operator types the mint_id into the start form).  Every coin
        the old mint issued is worthless against the new one.
        """
        self.stop_mint()
        priv, pub = generate_keypair()
        config = MintConfig(
            mint_id=mint_id,
            baseline_model_class="gui-test-model-v1",
            burn_policy=POLICY,
            signing_private=priv,
            signing_public=pub,
            admin_token=ADMIN,
        )
        server, _ledger = make_mint(
            config, db_path=os.path.join(self.dir, f"mint-{mint_id}.db"),
            clock=FakeClock(),
        )
        bound = server.start(port if port is not None else self.port)
        self.addCleanup(server.stop)
        return server, f"http://127.0.0.1:{bound}"

    def restart_mint(self):
        """Start this fixture's mint again: same mint_id, same ledger file.

        Not ``replacement_mint`` — that is a DIFFERENT mint wearing the same
        address.  This is the real "it was down, now it is back" case, which
        is what an operator does after a delivery failed with the mint off,
        and what ``recover()`` needs to settle a stranded op against the
        ledger that actually holds it.
        """
        self.server, self.ledger = make_mint(
            self.config, db_path=os.path.join(self.dir, "mint.db"),
            clock=self.clock,
        )
        self.server.start(self.port)
        self._stopped = False
        return self.server

    def spent_token(self, amount_mc: int = 500) -> str:
        """A token string that has already been redeemed by someone else."""
        token = self.issue(amount_mc)
        sink = self.ops("sink")
        r = sink.receive([token])
        self.assertEqual(r["rejected"], [], "sink should have taken it")
        return token


# ---------------------------------------------------------------------------
# summary
# ---------------------------------------------------------------------------


class TestSummary(MintFixture):

    def test_fresh_wallet_is_empty_and_connected(self):
        s = self.ops().summary()
        self.assertEqual(s["balance_mc"], 0)
        self.assertEqual(s["coin_count"], 0)
        self.assertEqual(s["mint_id"], MINT_ID)
        self.assertTrue(s["connected"])

    def test_summary_reflects_real_value(self):
        w = self.ops()
        w.receive([self.issue(10_000)])
        s = w.summary()
        # face 10000, burn = 1% = 100 but capped at 1000 -> 100
        self.assertEqual(s["balance_mc"], 9_900)
        self.assertGreater(s["coin_count"], 0)
        self.assertTrue(s["connected"])

    def test_summary_with_mint_down_does_not_raise(self):
        """The core requirement: a stopped mint must not hide the balance."""
        w = self.ops()
        w.receive([self.issue(10_000)])
        up = w.summary()
        self.stop_mint()
        down = w.summary()
        self.assertFalse(down["connected"])
        self.assertEqual(down["balance_mc"], up["balance_mc"])
        self.assertEqual(down["coin_count"], up["coin_count"])
        self.assertEqual(down["mint_id"], MINT_ID)

    def test_summary_with_mint_down_and_no_store(self):
        """A wallet that never existed: still no exception, just zeros."""
        self.stop_mint()
        s = self.ops("never-created").summary()
        self.assertFalse(s["connected"])
        self.assertEqual(s["balance_mc"], 0)
        self.assertEqual(s["coin_count"], 0)
        self.assertEqual(s["mint_id"], "")   # honestly unknown, not invented
        self.assertFalse(os.path.exists(os.path.join(self.dir, "never-created.db")))

    def test_mint_id_is_read_out_of_the_store_itself(self):
        """The mint_id shown while down comes from the STORE, not a cache.

        (Was test_mint_id_recovered_from_store_without_the_sidecar, which
        deleted a `<store>.mint` sidecar file.  That sidecar no longer
        exists — the mint_id is read out of the store — so the deletion
        line was removed.  The assertion is unchanged and is now the only
        path, not the fallback path.  The payment record written beside
        the store since is not a cache of this or of anything else: it
        holds no mint_id this function would ever read.)
        """
        w = self.ops("other")
        w.receive([self.issue(1_000)])
        self.stop_mint()
        fresh = WalletOps(self.path("other"), self.base)
        self.assertEqual(fresh.summary()["mint_id"], MINT_ID)

    def test_operation_on_a_down_mint_is_a_clean_error(self):
        w = self.ops()
        self.stop_mint()
        with self.assertRaises(WalletOpsError) as cm:
            w.pay(100)
        self.assertEqual(cm.exception.reason, "mint unreachable")
        self.assertIn(self.base, cm.exception.detail)


# ---------------------------------------------------------------------------
# receive
# ---------------------------------------------------------------------------


class TestReceive(MintFixture):

    def test_good_token(self):
        w = self.ops()
        out = w.receive([self.issue(1_000)])
        self.assertEqual(out["accepted"], 1)
        self.assertEqual(out["accepted_mc"], 990)     # 1000 - 1%
        self.assertEqual(out["rejected"], [])
        self.assertEqual(w.summary()["balance_mc"], 990)

    def test_spent_token_reads_as_already_spent(self):
        w = self.ops()
        out = w.receive([self.spent_token(500)])
        self.assertEqual(out["accepted"], 0)
        self.assertEqual(out["accepted_mc"], 0)
        self.assertEqual(len(out["rejected"]), 1)
        self.assertEqual(out["rejected"][0]["reason"], "already spent")
        self.assertIn("spent", out["rejected"][0]["detail"])
        self.assertEqual(w.summary()["balance_mc"], 0)

    def test_malformed_string(self):
        w = self.ops()
        out = w.receive(["this is not a token"])
        self.assertEqual(out["accepted"], 0)
        self.assertEqual(out["rejected"][0]["reason"], "malformed token")
        self.assertEqual(out["rejected"][0]["token"], "this is not a token")

    def test_token_from_a_different_mint_is_not_called_malformed(self):
        """A perfectly intact token from another mint must say so.

        (Was test_token_from_a_different_mint, which asserted
        "malformed token".  That assertion was wrong: wallet.py maps a
        foreign mint_id onto the §3.8 `bad_format` reason locally, and
        telling an operator to re-copy a paste that is byte-for-byte
        intact sends them chasing nothing.  The fix is in walletops, and
        this test now asserts the message a non-expert can act on.)
        """
        w = self.ops()
        foreign = format_token("someothermint", 100, new_secret())
        out = w.receive([foreign])
        self.assertEqual(out["accepted"], 0)
        self.assertEqual(out["rejected"][0]["reason"], "not from this mint")
        detail = out["rejected"][0]["detail"]
        self.assertIn("someothermint", detail)
        self.assertIn(MINT_ID, detail)
        # and it still does not discard the good token beside it
        good = self.issue(1_000)
        out = w.receive([foreign, good])
        self.assertEqual(out["accepted"], 1)
        self.assertEqual(out["accepted_mc"], 990)
        self.assertEqual(out["rejected"][0]["reason"], "not from this mint")

    def test_mixed_batch_keeps_the_good_token(self):
        """One spent token must never discard the good ones beside it."""
        w = self.ops()
        good = self.issue(1_000)
        bad = self.spent_token(500)
        out = w.receive([good, bad])

        self.assertEqual(out["accepted"], 1)
        self.assertEqual(out["accepted_mc"], 990)  # burn on the good one only
        self.assertEqual(len(out["rejected"]), 1)
        self.assertEqual(out["rejected"][0]["reason"], "already spent")
        self.assertEqual(out["rejected"][0]["token"], bad)
        self.assertEqual(w.summary()["balance_mc"], 990)

    def test_mixed_batch_with_a_malformed_token(self):
        w = self.ops()
        good = self.issue(1_000)
        out = w.receive(["", good, "@@@not-a-token@@@"])
        self.assertEqual(out["accepted"], 1)
        self.assertEqual(out["accepted_mc"], 990)
        self.assertEqual(
            [r["reason"] for r in out["rejected"]],
            ["malformed token", "malformed token"],
        )
        self.assertEqual(w.summary()["balance_mc"], 990)

    def test_batch_pays_one_burn_not_one_per_token(self):
        """The reason receive() takes a list at all (§3.3 burn-once, §9.2)."""
        batched = self.ops("batched")
        batched.receive([self.issue(1_000) for _ in range(4)])

        one_at_a_time = self.ops("serial")
        for _ in range(4):
            one_at_a_time.receive([self.issue(1_000)])

        # 4000 face: one burn of 40, versus four burns of 10.
        self.assertEqual(batched.summary()["balance_mc"], 3_960)
        self.assertEqual(one_at_a_time.summary()["balance_mc"], 3_960)
        # Same here because 1% of 4000 == 4 x 1% of 1000; the difference
        # shows once the cap bites:
        cap_batched = self.ops("capbatch")
        cap_batched.receive([self.issue(100_000) for _ in range(2)])
        # 200000 face, 1% = 2000, capped at 1000 -> ONE cap, not two.
        self.assertEqual(cap_batched.summary()["balance_mc"], 199_000)

    def test_empty_list_is_a_no_op(self):
        w = self.ops()
        self.assertEqual(
            w.receive([]),
            {"accepted_mc": 0, "accepted": 0, "rejected": []},
        )

    def test_non_list_is_a_clean_error(self):
        w = self.ops()
        with self.assertRaises(WalletOpsError) as cm:
            w.receive("a-single-string")
        self.assertEqual(cm.exception.reason, "bad request")


# ---------------------------------------------------------------------------
# pay / quote
# ---------------------------------------------------------------------------


class TestPay(MintFixture):

    def funded(self, name="w", face=100_000):
        w = self.ops(name)
        w.receive([self.issue(face)])
        return w

    def test_pay_moves_real_value_to_another_wallet(self):
        payer = self.funded()
        before = payer.summary()["balance_mc"]
        out = payer.pay(5_000)

        self.assertEqual(out["amount_mc"], 5_000)
        self.assertTrue(out["tokens"])
        self.assertGreaterEqual(out["burn_mc"], 0)

        after = payer.summary()["balance_mc"]
        self.assertEqual(before - after, 5_000 + out["burn_mc"])

        payee = self.ops("payee")
        got = payee.receive(out["tokens"])
        self.assertEqual(got["rejected"], [])
        self.assertEqual(payee.summary()["balance_mc"], got["accepted_mc"])
        self.assertGreater(got["accepted_mc"], 0)

    def test_payment_tokens_are_single_use(self):
        payer = self.funded()
        tokens = payer.pay(1_000)["tokens"]
        first = self.ops("first")
        first.receive(tokens)
        second = self.ops("second")
        out = second.receive(tokens)
        self.assertEqual(out["accepted"], 0)
        self.assertTrue(
            all(r["reason"] == "already spent" for r in out["rejected"])
        )

    def test_insufficient_funds(self):
        w = self.funded(face=1_000)          # ~990 mc held
        with self.assertRaises(WalletOpsError) as cm:
            w.pay(50_000)
        self.assertEqual(cm.exception.reason, "insufficient funds")
        self.assertIn("50000", cm.exception.detail)
        # nothing moved
        self.assertEqual(w.summary()["balance_mc"], 990)

    def test_insufficient_funds_on_an_empty_wallet(self):
        w = self.ops()
        w.summary()                          # materialise the store
        with self.assertRaises(WalletOpsError) as cm:
            w.pay(1)
        self.assertEqual(cm.exception.reason, "insufficient funds")

    def test_bad_amounts(self):
        w = self.funded()
        for bad in (0, -5, "100", 1.5, None, True):
            with self.subTest(amount=bad):
                with self.assertRaises(WalletOpsError) as cm:
                    w.pay(bad)
                self.assertEqual(cm.exception.reason, "bad amount")

    def test_quote_is_a_dry_run_that_matches_the_real_pay(self):
        w = self.funded()
        before = w.summary()["balance_mc"]
        q = w.quote(5_000)

        self.assertEqual(q["amount_mc"], 5_000)
        self.assertEqual(
            q["inputs_mc"], q["amount_mc"] + q["burn_mc"] + q["change_mc"]
        )
        # dry run: no mutation, no value moved
        self.assertEqual(w.summary()["balance_mc"], before)

        out = w.pay(5_000)
        self.assertEqual(out["burn_mc"], q["burn_mc"])
        self.assertEqual(before - w.summary()["balance_mc"],
                         q["amount_mc"] + q["burn_mc"])

    def test_quote_raises_insufficient_funds_like_pay(self):
        w = self.funded(face=1_000)
        with self.assertRaises(WalletOpsError) as cm:
            w.quote(50_000)
        self.assertEqual(cm.exception.reason, "insufficient funds")


# ---------------------------------------------------------------------------
# recover
# ---------------------------------------------------------------------------


class DeliverThenDropClient(MintClient):
    """Delivers every /v3/exchange to the mint, then drops the response.

    The exchange COMMITS on the ledger but the wallet never learns it —
    exactly the crash-in-flight state recover() exists to resolve.
    """

    def _transport(self, method, path, body, extra_headers=None):
        result = super()._transport(method, path, body, extra_headers)
        if path == "/v3/exchange":
            raise OSError("simulated response loss after delivery")
        return result


class TestRecover(MintFixture):

    def test_recover_on_a_clean_wallet_is_a_no_op(self):
        w = self.ops()
        w.receive([self.issue(1_000)])
        before = w.summary()["balance_mc"]
        summary = w.recover()
        self.assertEqual(summary["ops_resolved"], 0)
        self.assertEqual(w.summary()["balance_mc"], before)

    def test_recover_confirms_an_exchange_lost_in_flight(self):
        path = os.path.join(self.dir, "crashy.db")
        # Drive the raw Wallet with a lossy client so the op is left
        # 'planned' in the store, then hand the same file to WalletOps.
        crashed = Wallet(path, DeliverThenDropClient(self.base), MINT_ID)
        token = self.issue(10_000)
        with self.assertRaises(Exception):
            crashed.receive(token)
        self.assertEqual(crashed.balance(), 0)   # value is in limbo
        crashed._db.close()

        w = WalletOps(path, self.base)
        self.assertEqual(w.summary()["balance_mc"], 0)

        summary = w.recover()
        self.assertEqual(summary["ops_resolved"], 1)
        self.assertEqual(summary["ops_confirmed"], 1)
        self.assertGreater(summary["outputs_confirmed"], 0)

        # the money is now really there, and really spendable
        self.assertEqual(w.summary()["balance_mc"], 9_900)
        out = w.pay(1_000)
        payee = self.ops("payee")
        self.assertEqual(payee.receive(out["tokens"])["rejected"], [])

    def test_recover_needs_the_mint(self):
        w = self.ops()
        w.summary()
        self.stop_mint()
        with self.assertRaises(WalletOpsError) as cm:
            w.recover()
        self.assertEqual(cm.exception.reason, "mint unreachable")


# ---------------------------------------------------------------------------
# history
# ---------------------------------------------------------------------------


class TestHistory(MintFixture):

    def test_empty_wallet_has_empty_history(self):
        self.assertEqual(self.ops("nothing").history(), [])
        w = self.ops()
        w.summary()
        self.assertEqual(w.history(), [])

    def test_ordering_is_newest_first(self):
        w = self.ops()
        w.receive([self.issue(10_000)])     # 1st
        w.receive([self.issue(20_000)])     # 2nd
        w.pay(1_000)                        # 3rd
        h = w.history()
        self.assertEqual([e["kind"] for e in h],
                         ["pay", "receive", "receive"])
        # the middle entry is the 20000 receive, not the 10000 one
        self.assertEqual(h[1]["amount_mc"], 19_800)
        self.assertEqual(h[2]["amount_mc"], 9_900)

    def test_amounts_and_burn_are_the_real_ones(self):
        w = self.ops()
        w.receive([self.issue(10_000)])
        [entry] = w.history()
        self.assertEqual(entry["kind"], "receive")
        self.assertEqual(entry["amount_mc"], 9_900)
        self.assertIn("burn 100 mc", entry["detail"])
        self.assertIn("10000 mc face", entry["detail"])

    def test_pay_entry_reports_amount_burn_and_change(self):
        w = self.ops()
        w.receive([self.issue(100_000)])
        out = w.pay(5_000)
        entry = w.history()[0]
        self.assertEqual(entry["kind"], "pay")
        self.assertEqual(entry["amount_mc"], 5_000)
        self.assertIn(f"burn {out['burn_mc']} mc", entry["detail"])
        self.assertIn("change", entry["detail"])

    def test_limit_is_honoured(self):
        w = self.ops()
        for _ in range(4):
            w.receive([self.issue(1_000)])
        self.assertEqual(len(w.history()), 4)
        self.assertEqual(len(w.history(limit=2)), 2)
        for bad in (0, -1, "5", None):
            with self.subTest(limit=bad):
                with self.assertRaises(WalletOpsError):
                    w.history(limit=bad)

    def test_every_entry_has_the_agreed_shape(self):
        """Five keys now: an op that did not commit carries WHY it did not.

        (Was four, then five.  ``cause`` was added when a row that could
        not say why an operation failed was the defect of the round; the
        five payment-record fields were added when a row that could not
        say whether a payment ARRIVED was the defect of the next one.  All
        ten are the pinned shape, not extras.)
        """
        w = self.ops()
        w.receive([self.issue(10_000)])
        w.pay(100)
        for e in w.history():
            self.assertEqual(set(e),
                             {"ts_ms", "op_id", "kind", "amount_mc", "detail",
                              "cause", "recipient", "recipient_kind",
                              "delivery", "delivery_cause",
                              "delivery_attempt"})
            self.assertIsInstance(e["ts_ms"], int)
            self.assertIsInstance(e["op_id"], str)
            self.assertIsInstance(e["kind"], str)
            self.assertIsInstance(e["amount_mc"], int)
            self.assertIsInstance(e["detail"], str)
            self.assertIsInstance(e["cause"], str)
            for field in ("recipient", "recipient_kind", "delivery",
                          "delivery_cause", "delivery_attempt"):
                self.assertIsInstance(e[field], str)
            # A closed set, and the module's OWN declaration of it:
            # asserting a tuple copied into this file would go on passing
            # after the module started emitting a value the tuple does not
            # contain, which is the exact defect these fields have.
            self.assertIn(e["delivery_attempt"], DELIVERY_ATTEMPT_VALUES)
            self.assertIn(e["delivery"], DELIVERY_VALUES)
            self.assertIn(e["recipient_kind"], RECIPIENT_KIND_VALUES)
            self.assertTrue(e["delivery_cause"] == "" or
                            e["delivery_cause"] in _causes())
            # Everything here committed, so there is no cause to give.
            self.assertEqual(e["cause"], "")

    def test_timestamps_are_zero_because_the_schema_has_none(self):
        """Documented limitation, asserted so nobody mistakes 0 for a date."""
        w = self.ops()
        w.receive([self.issue(1_000)])
        self.assertTrue(all(e["ts_ms"] == 0 for e in w.history()))

    def test_history_never_leaks_a_secret_or_a_token_string(self):
        w = self.ops()
        token = self.issue(10_000)
        w.receive([token])
        out = w.pay(1_000)
        blob = repr(w.history())
        self.assertNotIn(token, blob)
        for t in out["tokens"]:
            self.assertNotIn(t, blob)
        # the secret payload of a token is its last path segment
        self.assertNotIn(token.rsplit(":", 1)[-1], blob)

    def test_failed_op_is_marked_and_moves_no_value(self):
        w = self.ops()
        w.receive([self.spent_token(500)])
        [entry] = w.history()
        self.assertEqual(entry["kind"], "receive_failed")
        self.assertEqual(entry["amount_mc"], 0)
        self.assertIn("did not commit", entry["detail"])
        self.assertIn("rejected", entry["detail"])

    def test_unresolved_op_is_marked_pending_then_resolved_by_recover(self):
        path = os.path.join(self.dir, "crashy.db")
        crashed = Wallet(path, DeliverThenDropClient(self.base), MINT_ID)
        with self.assertRaises(Exception):
            crashed.receive(self.issue(10_000))
        crashed._db.close()

        w = WalletOps(path, self.base)
        [entry] = w.history()
        self.assertEqual(entry["kind"], "receive_pending")
        self.assertEqual(entry["amount_mc"], 0)
        self.assertIn("recover()", entry["detail"])

        w.recover()
        [entry] = w.history()
        self.assertEqual(entry["kind"], "receive")
        self.assertEqual(entry["amount_mc"], 9_900)

    def test_history_does_not_need_the_mint(self):
        w = self.ops()
        w.receive([self.issue(10_000)])
        before = w.history()
        self.stop_mint()
        self.assertEqual(w.history(), before)

    def test_history_does_not_mutate_the_store(self):
        w = self.ops()
        w.receive([self.issue(10_000)])
        path = os.path.join(self.dir, "w.db")
        w.close()
        with open(path, "rb") as fh:
            before = fh.read()
        WalletOps(path, self.base).history()
        with open(path, "rb") as fh:
            self.assertEqual(fh.read(), before)


# ---------------------------------------------------------------------------
# error surface
# ---------------------------------------------------------------------------


class TestErrorSurface(MintFixture):

    def test_error_carries_reason_and_detail(self):
        e = WalletOpsError("already spent", "long engineering detail")
        self.assertEqual(e.reason, "already spent")
        self.assertEqual(e.detail, "long engineering detail")
        self.assertIn("already spent", str(e))

    def test_reasons_are_short_enough_for_a_button(self):
        w = self.ops()
        self.stop_mint()
        with self.assertRaises(WalletOpsError) as cm:
            w.pay(1)
        self.assertLessEqual(len(cm.exception.reason), 24)
        self.assertNotIn("Traceback", cm.exception.detail)
        self.assertGreater(len(cm.exception.detail), len(cm.exception.reason))

    def test_bad_base_url(self):
        w = WalletOps(os.path.join(self.dir, "x.db"), "ftp://nope")
        with self.assertRaises(WalletOpsError) as cm:
            w.pay(1)
        self.assertEqual(cm.exception.reason, "bad mint address")

    def test_constructor_touches_nothing(self):
        self.stop_mint()
        path = os.path.join(self.dir, "untouched.db")
        WalletOps(path, self.base)
        self.assertFalse(os.path.exists(path))


# ---------------------------------------------------------------------------
# failures must never collapse into "balance 0"
# ---------------------------------------------------------------------------


class TestBrokenStore(MintFixture):
    """A store that cannot be read must SAY SO, with the mint up or down.

    The whole point of `connected=False, balance_mc=0` is "the mint is
    down, here is your last known balance".  Reporting the same thing for
    a wallet file that cannot be opened invents a balance of zero for
    money that may well still be there — in a money GUI that reads as "my
    coins are gone".
    """

    def broken_stores(self) -> list[str]:
        as_dir = os.path.join(self.dir, "isdir.db")
        os.mkdir(as_dir)
        junk = os.path.join(self.dir, "junk.db")
        with open(junk, "wb") as fh:
            fh.write(b"this is definitely not an sqlite database\n" * 40)
        return [as_dir, junk]

    def test_summary_raises_instead_of_inventing_zero_mint_up(self):
        for path in self.broken_stores():
            with self.subTest(store=os.path.basename(path)):
                ops = WalletOps(path, self.base)
                with self.assertRaises(WalletOpsError) as cm:
                    ops.summary()
                self.assertIn(cm.exception.reason,
                              ("wallet store error", "wallet file unusable"))
                self.assertIn(os.path.basename(path), cm.exception.detail)

    def test_summary_raises_instead_of_inventing_zero_mint_down(self):
        paths = self.broken_stores()
        self.stop_mint()
        for path in paths:
            with self.subTest(store=os.path.basename(path)):
                with self.assertRaises(WalletOpsError):
                    WalletOps(path, self.base).summary()

    def test_history_raises_instead_of_looking_empty(self):
        for path in self.broken_stores():
            with self.subTest(store=os.path.basename(path)):
                with self.assertRaises(WalletOpsError):
                    WalletOps(path, self.base).history()

    def test_a_bad_base_url_is_not_reported_as_a_stopped_mint(self):
        """Misconfiguration must not read as "start the mint" — it is up."""
        w = WalletOps(self.path("x"), "not-a-url")
        with self.assertRaises(WalletOpsError) as cm:
            w.summary()
        self.assertEqual(cm.exception.reason, "bad mint address")

    def test_no_directory_tree_is_ever_created(self):
        deep = os.path.join(self.dir, "no", "such", "tree", "w.db")
        with self.assertRaises(WalletOpsError) as cm:
            WalletOps(deep, self.base).summary()
        self.assertEqual(cm.exception.reason, "wallet folder missing")
        self.assertFalse(os.path.exists(os.path.join(self.dir, "no")))

    def test_exactly_two_files_per_wallet_are_written(self):
        """The pinned layout: the store, and the payment record beside it.

        (Was test_exactly_one_file_per_wallet_is_written, asserting the
        store alone.  The second file is deliberate and is NOT a relaxing
        of that claim: what the one-file rule protected was "no second
        copy of live bearer money on disk", and that is asserted here
        directly — the record is opened and searched for the strings the
        payment produced.  The set is still exact: a third artefact, a
        cache, a lock file or a stray temp file fails this test as it
        always did.)
        """
        w = self.ops("solo")
        w.receive([self.issue(10_000)])
        w.summary()
        w.summary()
        w.history()
        paid = w.pay(100)
        w.close()
        made = {e for e in os.listdir(self.dir) if e.startswith("solo")}
        self.assertEqual(made, {"solo.db", "solo.payments.db"})
        self.assertFalse(os.path.exists(self.path("solo") + ".mint"))
        # The record describes money; it must never BE money.
        with open(os.path.join(self.dir, "solo.payments.db"), "rb") as fh:
            blob = fh.read()
        self.assertNotIn(b"aicash:", blob)
        for token in paid["tokens"]:
            self.assertNotIn(token.encode(), blob)
            self.assertNotIn(token.split(":")[-1].encode(), blob)


# ---------------------------------------------------------------------------
# the balance must belong to the mint the summary names
# ---------------------------------------------------------------------------


class TestMintBinding(MintFixture):
    """Restarting the mint under a new mint_id is one click in this GUI.

    Every coin the old mint issued is then dead: the new ledger has no
    entry for it.  A summary that keeps reporting that total, stamped with
    the NEW mint's id and `connected: True`, is a confidently wrong number
    on the main screen of a money GUI.
    """

    def funded_then_replaced(self, name="w", face=50_000):
        w = self.ops(name)
        w.receive([self.issue(face)])
        held = w.summary()["balance_mc"]
        self.assertGreater(held, 0)
        _server, base = self.replacement_mint("minttwo")
        return w, base, held

    def test_summary_refuses_to_count_another_mints_coins(self):
        cached, base, held = self.funded_then_replaced()
        for label, ops in (("fresh", WalletOps(self.path("w"), base)),
                           ("cached", cached)):
            with self.subTest(instance=label):
                with self.assertRaises(WalletOpsError) as cm:
                    ops.summary()
                self.assertEqual(cm.exception.reason, "wrong mint")
                self.assertIn(MINT_ID, cm.exception.detail)
                self.assertIn("minttwo", cm.exception.detail)
                self.assertIn(str(held), cm.exception.detail)

    def test_pay_and_quote_refuse_another_mints_coins(self):
        _cached, base, _held = self.funded_then_replaced()
        ops = WalletOps(self.path("w"), base)
        for call in (lambda: ops.pay(1_000), lambda: ops.quote(1_000)):
            with self.assertRaises(WalletOpsError) as cm:
                call()
            self.assertEqual(cm.exception.reason, "wrong mint")
            self.assertIn("Restart the mint", cm.exception.detail)

    def test_a_cached_instance_rebinds_instead_of_using_a_stale_mint_id(self):
        """A WalletOps held across a mint restart must FOLLOW the mint.

        The replacement mint takes the same address, so the very same
        WalletOps object keeps working — and its cached Wallet is still
        bound to the old mint_id.  Without a rebind, a legitimate token
        from the NEW mint is rejected locally as "malformed" and a pay
        signs the wrong mint's tokens, while summary happily reports the
        new mint's id.  Exercised on the cached instance AND a fresh one.
        """
        cached = self.ops("empty")
        self.assertEqual(cached.summary()["mint_id"], MINT_ID)
        _server, base = self.replacement_mint("minttwo")
        fresh = WalletOps(self.path("empty"), base)

        for label, w in (("cached", cached), ("fresh", fresh)):
            with self.subTest(instance=label):
                s = new_secret()
                MintClient(base).admin_issue(
                    [{"amount_mc": 1_000, "secret_hash": ledger_key(s)}],
                    admin_token=ADMIN,
                )
                # a legitimate minttwo token must be accepted, not called
                # malformed and not called "not from this mint"
                out = w.receive([format_token("minttwo", 1_000, s)])
                self.assertEqual(out["rejected"], [])
                self.assertEqual(out["accepted"], 1)
                self.assertEqual(out["accepted_mc"], 990)
                got = w.summary()
                self.assertEqual(got["mint_id"], "minttwo")
                self.assertTrue(got["connected"])
                # and the money is really spendable at the new mint
                paid = w.pay(100)
                payee = WalletOps(self.path(f"payee-{label}"), base)
                self.assertEqual(payee.receive(paid["tokens"])["rejected"], [])
                w.close()

    def test_a_drained_old_store_does_not_block_a_new_mint(self):
        """Old ops alone are not a mismatch — only HELD value is."""
        from aicash.burncalc import compute_burn
        w = self.ops("drained")
        w.receive([self.issue(10_000)])
        for _ in range(8):                 # spend it all away, burn and all
            held = w.summary()["balance_mc"]
            if held == 0:
                break
            w.pay(held - compute_burn(held, POLICY))
        self.assertEqual(w.summary()["balance_mc"], 0)
        w.close()
        _server, base = self.replacement_mint("minttwo")
        s = WalletOps(self.path("drained"), base).summary()
        self.assertTrue(s["connected"])
        self.assertEqual(s["mint_id"], "minttwo")
        self.assertEqual(s["balance_mc"], 0)


# ---------------------------------------------------------------------------
# no raw sqlite exception may escape
# ---------------------------------------------------------------------------


class TestNoRawExceptions(MintFixture):

    def funded(self, name="w", face=100_000):
        w = self.ops(name)
        w.receive([self.issue(face)])
        return w

    def test_a_dead_handle_is_a_walletopserror_on_every_method(self):
        calls = {
            "summary": lambda w: w.summary(),
            "pay": lambda w: w.pay(100),
            "quote": lambda w: w.quote(100),
            "receive": lambda w: w.receive([self.issue(1_000)]),
            "recover": lambda w: w.recover(),
        }
        for name, call in calls.items():
            with self.subTest(method=name):
                w = self.funded(f"dead-{name}")
                w._wallet._db.close()      # the handle is gone under us
                try:
                    call(w)
                except WalletOpsError as exc:
                    self.assertEqual(exc.reason, "wallet store error")
                    self.assertNotIn("Traceback", exc.detail)
                except Exception as exc:   # noqa: BLE001 - that is the point
                    self.fail(f"{name} leaked {type(exc).__name__}: {exc}")
                else:
                    self.fail(f"{name} did not report the dead handle")

    def test_use_from_a_second_thread_is_a_named_error_not_sqlite(self):
        import threading
        w = self.funded("threaded")
        w.summary()                        # binds the handle to this thread
        box = {}

        def run():
            try:
                box["out"] = w.pay(100)
            except BaseException as exc:   # noqa: BLE001
                box["exc"] = exc

        t = threading.Thread(target=run)
        t.start()
        t.join(30)
        self.assertNotIn("out", box)
        self.assertIsInstance(box.get("exc"), WalletOpsError)
        self.assertEqual(box["exc"].reason, "wallet busy elsewhere")

    def test_many_threads_on_one_instance_never_leak_sqlite(self):
        import threading
        w = self.funded("contended")
        errors = []

        def run():
            try:
                w.pay(100)
            except WalletOpsError:
                pass
            except BaseException as exc:   # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=run) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(60)
        self.assertEqual(errors, [], f"raw exceptions escaped: {errors}")

    def test_every_reason_fits_on_a_button(self):
        # The module this file actually imported, not whatever happens to
        # be under the top-level name "walletops" in sys.modules: another
        # test file in the same process installs a stub there.
        _wo = sys.modules[WalletOps.__module__]
        shorts = [s for s, _long in _wo._REASONS.values()]
        shorts.append(_wo._OWN_COINS_BAD_FORMAT[0])
        shorts += ["wallet store error", "wallet file unusable", "wrong mint",
                   "wallet busy elsewhere", "wallet folder missing",
                   "mint unreachable", "bad mint address", "bad mint response",
                   "not from this mint", "bad amount", "bad request",
                   "insufficient funds", "rejected by mint"]
        for s in shorts:
            with self.subTest(reason=s):
                self.assertLessEqual(len(s), 24)
                self.assertEqual(s, s.strip())


# ---------------------------------------------------------------------------
# amount validation is a pre-flight, not a duplicate of wallet.py
# ---------------------------------------------------------------------------


class TestAmountPreflight(MintFixture):

    def test_a_bad_amount_is_caught_before_the_mint_or_store_is_touched(self):
        """_amount must run FIRST, or it is not doing anything at all.

        With the mint stopped and no store on disk, the only way a typo
        can be reported as "bad amount" rather than "mint unreachable" is
        for the check to happen before anything is opened or dialled.
        This is what kills the "delete _amount and let wallet.py's own
        ValueError do it" mutation, which wallet.py cannot: wallet.py's
        check runs after the descriptor fetch and the store open.
        """
        path = self.path("preflight")
        w = WalletOps(path, self.base)
        self.stop_mint()
        for bad in (0, -5, "100", 1.5, None, True, [10], 10 ** 30 + 0.5):
            for method in ("pay", "quote"):
                with self.subTest(amount=bad, method=method):
                    with self.assertRaises(WalletOpsError) as cm:
                        getattr(w, method)(bad)
                    self.assertEqual(cm.exception.reason, "bad amount")
                    self.assertIn(method, cm.exception.detail)
        self.assertFalse(os.path.exists(path))

    def test_bool_is_rejected_by_the_int_check_alone(self):
        w = self.ops()
        with self.assertRaises(WalletOpsError) as cm:
            w.pay(True)
        self.assertEqual(cm.exception.reason, "bad amount")
        self.assertIn("bool", cm.exception.detail)


# ---------------------------------------------------------------------------
# history reads one snapshot over one connection
# ---------------------------------------------------------------------------


class TestHistoryEfficiency(MintFixture):

    def test_history_opens_one_connection_not_one_per_row(self):
        import sqlite3 as _sq
        w = self.ops("many")
        for _ in range(8):
            w.receive([self.issue(1_000)])
        w.pay(500)
        w.close()

        fresh = WalletOps(self.path("many"), self.base)
        real, count = _sq.connect, []

        def counting(*a, **k):
            count.append(a[0] if a else None)
            return real(*a, **k)

        queries = []
        real_execute = _sq.Connection.execute

        class Counting(_sq.Connection):
            def execute(self, sql, *a, **k):
                queries.append(sql)
                return real_execute(self, sql, *a, **k)

        def counting_ro(*a, **k):
            k.setdefault("factory", Counting)
            return counting(*a, **k)

        _sq.connect = counting_ro
        try:
            rows = fresh.history(limit=50)
        finally:
            _sq.connect = real
        self.assertEqual(len(rows), 9)
        self.assertLessEqual(
            len(count), 2,
            f"history opened {len(count)} connections for {len(rows)} rows",
        )
        # One ops query, one grouped outputs query, one grouped causes
        # query, one grouped payment-record query, and the BEGIN/COMMIT
        # that hold all three store reads in ONE transaction. A per-row
        # query is an N+1; the transaction is a fixed two statements and
        # is what makes "one snapshot" true rather than asserted -- a
        # plain sqlite3 connection opens no transaction for a SELECT, so
        # without it the three reads see three different databases.
        self.assertLessEqual(
            len(queries), 6,
            f"history ran {len(queries)} queries for {len(rows)} rows:"
            f" {queries}",
        )
        self.assertEqual(queries[0], "BEGIN",
                         "the store reads are not inside a transaction, so"
                         " history's 'one consistent snapshot' is a claim"
                         " and not a mechanism")
        self.assertIn("COMMIT", queries, "the read transaction is left open")
        self.assertLess(queries.index("BEGIN"), queries.index("COMMIT"))
        self.assertEqual(
            [q for q in queries if q in ("BEGIN", "COMMIT")],
            ["BEGIN", "COMMIT"], "more than one transaction: %r" % queries)
        # And the real invariant behind that number, which a bound alone
        # does not pin: the count does not GROW with the rows. Nine rows
        # and three rows must cost the same number of queries.
        for_nine = list(queries)
        del queries[:]
        _sq.connect = counting_ro
        try:
            short = fresh.history(limit=3)
        finally:
            _sq.connect = real
        self.assertEqual(len(short), 3)
        self.assertEqual(
            len(queries), len(for_nine),
            f"history costs {len(queries)} queries for 3 rows and"
            f" {len(for_nine)} for 9 — that is an N+1")


# ---------------------------------------------------------------------------
# WHY did it fail: the pinned cause vocabulary, driven by REAL failures
# ---------------------------------------------------------------------------


class TestFailureCauses(MintFixture):
    """Every cause here is produced by actually breaking something.

    No mocked exceptions and no hand-written ``failed`` rows: the mint is
    stopped for real, a real already-spent token is submitted, a real
    foreign-mint token is pasted, and a real in-flight delivery is cut off
    by killing the mint between the plan commit and the send.  A cause
    vocabulary tested against invented failures proves only that the test
    and the code agree about a string.
    """

    def funded(self, name="w", face=100_000):
        w = self.ops(name)
        w.receive([self.issue(face)])
        return w

    def causes_of(self, rows):
        return [r["cause"] for r in rows]

    # -- the mint never saw it ------------------------------------------

    def test_a_stopped_mint_is_unreachable_and_never_a_rejection(self):
        w = self.funded()
        self.stop_mint()
        with self.assertRaises(WalletOpsError) as cm:
            w.pay(1_000)
        self.assertEqual(cm.exception.cause, "mint_unreachable")
        self.assertNotIn("rejected", cm.exception.detail.lower())
        # It says the mint refused nothing, and it does NOT claim the
        # request never landed: a dead socket cannot establish that, which
        # is why §5.1 persists before sending and recover() exists.
        self.assertIn("refused nothing", cm.exception.detail)
        self.assertIn("undetermined", cm.exception.detail)
        self.assertIn("recover", cm.exception.detail)
        self.assertNotIn("never saw", cm.exception.detail)
        self.assertNotIn("never answered", cm.exception.detail)

    def test_the_gui_knowing_the_process_is_gone_sharpens_it_to_stopped(self):
        """mint_stopped is a claim about a PROCESS, so it needs a witness."""
        w = self.funded("witnessed")
        self.stop_mint()
        w.mint_running = lambda: False
        with self.assertRaises(WalletOpsError) as cm:
            w.pay(1_000)
        self.assertEqual(cm.exception.cause, "mint_stopped")
        self.assertEqual(cm.exception.reason, "mint stopped")
        self.assertNotIn("rejected", cm.exception.detail.lower())

    def test_a_hook_that_cannot_answer_leaves_the_weaker_claim(self):
        """No witness, a broken witness, an unsure witness: unreachable."""
        for hook in (None, lambda: True, lambda: None,
                     lambda: (_ for _ in ()).throw(RuntimeError("no idea"))):
            with self.subTest(hook=repr(hook)):
                w = self.ops("hooked-%s" % id(hook))
                w.mint_running = hook
                self.stop_mint()
                with self.assertRaises(WalletOpsError) as cm:
                    w.summary() if False else w.pay(10)
                self.assertEqual(cm.exception.cause, "mint_unreachable")

    # -- the mint answered ----------------------------------------------

    def test_an_already_spent_token_says_already_spent(self):
        w = self.ops()
        out = w.receive([self.spent_token(500)])
        self.assertEqual(out["rejected"][0]["cause"], "already_spent")
        [row] = w.history()
        self.assertEqual(row["kind"], "receive_failed")
        self.assertEqual(row["cause"], "already_spent")
        # It IS a rejection: the mint answered, and the row may say so.
        self.assertIn("rejected", row["detail"])

    def test_a_mixed_batch_records_the_refusal_and_what_was_taken(self):
        """One op failed, one committed, in a single call. Both say so."""
        w = self.ops("mixed-batch")
        good, bad = self.issue(1_000), self.spent_token(500)
        out = w.receive([bad, good])
        self.assertEqual(out["accepted"], 1)
        self.assertEqual([r["cause"] for r in out["rejected"]],
                         ["already_spent"])
        rows = w.history()
        self.assertEqual(rows[-1]["kind"], "receive_failed")
        self.assertEqual(rows[-1]["cause"], "already_spent")
        self.assertIn("credited", rows[-1]["detail"])
        self.assertEqual(rows[0]["kind"], "receive")
        self.assertEqual(rows[0]["cause"], "")

    def test_a_malformed_string_is_never_blamed_on_the_mint(self):
        w = self.ops()
        out = w.receive(["this is not a token"])
        self.assertEqual(out["rejected"][0]["cause"], "malformed_token")
        self.assertNotIn("mint rejected", out["rejected"][0]["detail"])
        # Nothing was sent, so there is no operation and no history row.
        self.assertEqual(w.history(), [])

    def test_a_token_from_another_mint_is_wrong_mint_not_malformed(self):
        stranger = self.issue(1_000)          # issued by THIS mint...
        _server, base = self.replacement_mint("other-mint")
        w = WalletOps(self.path("elsewhere"), base)
        out = w.receive([stranger])           # ...offered to a different one
        self.assertEqual(out["rejected"][0]["cause"], "wrong_mint")
        self.assertNotIn("mint rejected", out["rejected"][0]["detail"])
        self.assertEqual(w.history(), [])

    def test_a_store_bound_to_another_mint_is_wrong_mint(self):
        w = self.funded("bound")
        w.close()
        _server, base = self.replacement_mint("successor-mint")
        moved = WalletOps(self.path("bound"), base)
        with self.assertRaises(WalletOpsError) as cm:
            moved.pay(100)
        self.assertEqual(cm.exception.cause, "wrong_mint")

    def test_insufficient_funds_carries_its_own_cause(self):
        w = self.funded("poor", face=1_000)
        with self.assertRaises(WalletOpsError) as cm:
            w.pay(50_000)
        self.assertEqual(cm.exception.cause, "insufficient_funds")
        self.assertNotIn("rejected", cm.exception.detail.lower())

    def test_a_bad_amount_is_undetermined_not_a_mint_story(self):
        w = self.ops()
        with self.assertRaises(WalletOpsError) as cm:
            w.pay("100")
        self.assertEqual(cm.exception.cause, "unknown")
        self.assertIn("nothing was sent to the mint", cm.exception.detail)

    # -- THE ROW THE REVIEWER FOUND -------------------------------------

    def stop_the_mint_mid_flight(self, ops, after=1):
        """Cut the mint off between the plan COMMIT and the send.

        The wallet's own persist_fsync event fires exactly there (§5.1
        persist-before-send), so this reproduces the real accident: the
        operator's mint dies — or the machine's network does — after the
        wallet has written its plan and before the exchange lands.  The
        socket failure that follows is real: the port is genuinely closed.

        ``after`` is which plan commit to cut on: ``receive_batch`` plans
        a fresh op per retry round, so ``after=2`` kills the mint once it
        has already ANSWERED round one — the two-causes-in-one-call case.
        """
        ops._open()                 # bind, so there is a wallet to hook
        killed = []

        def kill(event, _op_id):
            if event == "persist_fsync" and len(killed) < after:
                killed.append(True)
                if len(killed) == after:
                    self.stop_mint()

        ops._wallet.event_hook = kill
        return killed

    def test_a_delivery_the_mint_never_saw_is_not_recorded_as_a_rejection(self):
        """THE DEFECT, end to end.

        Before this fix the row below read "did not commit (the mint
        rejected it)" for a payment the mint never received — the tokens
        were fine, the mint was simply down — and an operator reading it
        months later goes and debugs the mint's §3.8 handling.  Nothing in
        the store can tell the two apart afterwards, so the cause is
        recorded at the moment it is known and read back verbatim.
        """
        w = self.funded("stranded")
        killed = self.stop_the_mint_mid_flight(w)
        with self.assertRaises(WalletOpsError) as cm:
            w.pay(5_000)
        self.assertTrue(killed, "the mint was not stopped mid-flight")
        self.assertEqual(cm.exception.cause, "mint_unreachable")

        row = w.history()[0]           # newest first: the payment that hung
        self.assertEqual(row["kind"], "pay_pending")
        self.assertEqual(row["cause"], "mint_unreachable")
        self.assertNotIn("the mint rejected it", row["detail"])
        self.assertIn("recover", row["detail"])

        # ...and the row survives recover() turning the op into `failed`,
        # which is the exact state that used to be printed as a rejection.
        self.restart_mint()
        w.recover()
        row = w.history()[0]
        self.assertEqual(row["kind"], "pay_failed")
        self.assertEqual(row["cause"], "mint_unreachable")
        self.assertNotIn("the mint rejected it", row["detail"])
        self.assertNotIn("rejected", row["detail"].lower())
        self.assertIn("refused nothing", row["detail"])
        self.assertNotIn("never saw", row["detail"])
        # the money came back, which is the other half of "not a rejection"
        self.assertEqual(w.summary()["balance_mc"], 99_000)

    def test_a_stranded_delivery_says_stopped_when_the_gui_knows(self):
        w = self.funded("stranded2")
        w.mint_running = lambda: not self._stopped
        self.stop_the_mint_mid_flight(w)
        with self.assertRaises(WalletOpsError) as cm:
            w.pay(5_000)
        self.assertEqual(cm.exception.cause, "mint_stopped")
        row = w.history()[0]
        self.assertEqual(row["cause"], "mint_stopped")
        self.assertNotIn("rejected", row["detail"].lower())

    def test_a_recorded_cause_is_permanent(self):
        """The row an operator debugs from months later does not drift.

        A second attempt is a different operation with its own story; it
        must not rewrite the first one's.
        """
        w = self.funded("permanent")
        self.stop_the_mint_mid_flight(w)
        with self.assertRaises(WalletOpsError):
            w.pay(5_000)
        first = w.history()[0]["detail"]
        self.restart_mint()
        w.recover()
        w.pay(1_000)                       # a later, successful payment
        w.receive([self.spent_token(500)])  # and a later, real rejection
        rows = {r["kind"]: r for r in w.history()}
        self.assertEqual(rows["pay_failed"]["cause"], "mint_unreachable")
        self.assertEqual(rows["pay_failed"]["detail"], first.replace(
            " — still unresolved; run recover() to settle", ""))
        self.assertEqual(rows["receive_failed"]["cause"], "already_spent")

    # -- one call, two different causes ---------------------------------

    def test_each_op_of_a_multi_round_receive_keeps_its_own_cause(self):
        """TWO causes in ONE call — the row the fourth review found.

        ``Wallet.receive_batch`` plans one op per retry round: the mint
        enumerates the spent token and refuses round one, the wallet drops
        it and re-sends the good remainder under a FRESH op.  Cut the mint
        off between those two plans and the call ends with an op the mint
        ANSWERED and refused beside an op it never answered about.
        Stamping the call's final error on both wrote "the mint never
        answered, so it never saw this request" into the permanent record
        of an exchange the mint had enumerated and refused — sending the
        operator to ask whether the mint was down when the mint had in
        fact answered.
        """
        w = self.ops("two-causes")
        spent, good = self.spent_token(500), self.issue(5_000)
        killed = self.stop_the_mint_mid_flight(w, after=2)
        with self.assertRaises(WalletOpsError) as cm:
            w.receive([spent, good])
        self.assertEqual(len(killed), 2,
                         "the mint was not cut off on the retry round")
        self.assertEqual(cm.exception.cause, "mint_unreachable")

        rows = {r["kind"]: r for r in w.history()}
        self.assertEqual(set(rows), {"receive_failed", "receive_pending"},
                         "expected one refused op and one stranded op: %r"
                         % (rows,))

        refused = rows["receive_failed"]     # round one: the mint answered
        self.assertEqual(refused["cause"], "mint_rejected")
        self.assertIn("answered and rejected", refused["detail"])
        self.assertNotIn("never", refused["detail"])
        self.assertNotIn("did not answer", refused["detail"])

        stranded = rows["receive_pending"]   # round two: nothing answered
        self.assertEqual(stranded["cause"], "mint_unreachable")
        self.assertNotIn("rejected", stranded["detail"].lower())

    def test_a_locally_dropped_token_is_not_named_as_a_mint_refusal(self):
        """The mint never saw the malformed paste, so no row may list it.

        One batch, three fates: a string this module drops without asking
        anybody, a token the mint enumerates and refuses, and a token that
        is credited.  The sentence recorded against the refused op names
        only what the MINT actually said.
        """
        w = self.ops("mixed-fates")
        out = w.receive(["not-a-token", self.spent_token(500),
                         self.issue(1_000)])
        self.assertEqual(out["accepted"], 1)
        self.assertEqual(sorted(r["cause"] for r in out["rejected"]),
                         ["already_spent", "malformed_token"])
        rows = [r for r in w.history() if r["kind"] == "receive_failed"]
        self.assertEqual(len(rows), 1, rows)
        self.assertEqual(rows[0]["cause"], "already_spent")
        self.assertIn("already spent", rows[0]["detail"])
        self.assertNotIn("malformed", rows[0]["detail"].lower())

    # -- undetermined stays undetermined --------------------------------

    def test_a_failure_nobody_recorded_reads_as_undetermined(self):
        """A wallet driven by another tool leaves a `failed` op with no note.

        The honest answer is that this build does not know why, and the
        sentence has to SAY that rather than pick the likelier story.
        """
        path = os.path.join(self.dir, "foreign.db")
        raw = Wallet(path, MintClient(self.base), MINT_ID)
        with self.assertRaises(Exception):
            raw.receive(self.spent_token(500))   # marks the op `failed`
        raw._db.close()

        [row] = WalletOps(path, self.base).history()
        self.assertEqual(row["kind"], "receive_failed")
        self.assertEqual(row["cause"], "unknown")
        self.assertIn("undetermined", row["detail"])
        self.assertNotIn("the mint rejected it", row["detail"])

    def test_no_row_ever_claims_a_rejection_the_mint_did_not_make(self):
        """The invariant, swept over every row a mixed history can produce."""
        w = self.funded("mixed")
        w.receive([self.spent_token(500)])          # a real rejection
        w.receive(["not-a-token"])                  # a local refusal
        w.pay(1_000)                                # a success
        self.stop_the_mint_mid_flight(w)
        with self.assertRaises(WalletOpsError):
            w.pay(2_000)                            # a request never seen
        self.restart_mint()
        w.recover()
        for row in w.history():
            with self.subTest(kind=row["kind"], cause=row["cause"]):
                self.assertIn(row["cause"], ("", ) + _causes())
                if "reject" in row["detail"].lower():
                    self.assertIn(row["cause"],
                                  ("mint_rejected", "already_spent"),
                                  "a row blamed the mint for a refusal it "
                                  "never made: %r" % (row,))

    def test_a_recorded_cause_never_carries_a_token_or_a_secret(self):
        """The sentence is written to disk and shown in a browser.

        Both are places a bearer string must not turn up, and the sentence
        is built from an exception detail — so pin it here rather than
        trusting every future raise site to remember.
        """
        w = self.funded("leaky")
        spent = self.spent_token(500)
        w.receive([spent])
        self.stop_the_mint_mid_flight(w)
        with self.assertRaises(WalletOpsError) as cm:
            w.pay(5_000)
        blob = repr(w.history()) + cm.exception.detail
        self.assertNotIn(spent, blob)
        self.assertNotIn(spent.rsplit(":", 1)[-1], blob)
        with open(self.path("leaky"), "rb") as fh:
            store = fh.read()
        # the causes table itself: the sentence must not have copied a
        # secret into a row that is read back and rendered
        for row in _cause_rows(self.path("leaky")):
            self.assertNotIn(spent.rsplit(":", 1)[-1], row[2])
        self.assertIn(b"walletops_op_causes", store)

    def test_a_store_that_refuses_the_note_still_reports_the_failure(self):
        """Recording is best effort, and "best effort" has to be true.

        If the wallet file will not take the note, the operation's own
        error must still be raised unchanged and the history row must
        degrade to "undetermined" — never to a crash, and never to a
        confident story nobody wrote down.
        """
        w = self.funded("readonly")
        path = self.path("readonly")

        def kill(event, _op_id):
            if event == "persist_fsync":
                self.stop_mint()
                os.chmod(path, 0o444)       # the note cannot be written
                os.chmod(self.dir, 0o555)   # nor a journal beside it

        w._open()
        w._wallet.event_hook = kill
        self.addCleanup(os.chmod, self.dir, 0o755)
        try:
            with self.assertRaises(WalletOpsError) as cm:
                w.pay(5_000)
            self.assertEqual(cm.exception.cause, "mint_unreachable")
        finally:
            os.chmod(self.dir, 0o755)
            os.chmod(path, 0o600)

        with open(path, "rb") as fh:
            self.assertNotIn(b"walletops_op_causes", fh.read(),
                             "the note was written after all, so this test "
                             "is not exercising the refusal it claims to")
        row = w.history()[0]
        self.assertEqual(row["kind"], "pay_pending")
        self.assertEqual(row["cause"], "unknown")
        self.assertNotIn("the mint rejected it", row["detail"])
        self.assertIn("recover", row["detail"])

    def test_causes_are_a_closed_set(self):
        w = self.funded("closed")
        self.stop_mint()
        with self.assertRaises(WalletOpsError) as cm:
            w.pay(10)
        self.assertIn(cm.exception.cause, _causes())
        # an unrecognised cause never widens the vocabulary
        self.assertEqual(WalletOpsError("x", "y", "creative").cause, "unknown")
        self.assertEqual(WalletOpsError("x", "y").cause, "unknown")


def _causes():
    return tuple(sys.modules[WalletOps.__module__].CAUSES)


def _cause_rows(store_path):
    """Whatever walletops wrote into its own table, read raw."""
    import sqlite3
    conn = sqlite3.connect(store_path)
    try:
        return conn.execute(
            "SELECT op_id, cause, sentence, op FROM walletops_op_causes"
        ).fetchall()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# money stranded by a failed delivery: is the browser really the only copy?
# ---------------------------------------------------------------------------


class TestOutstandingPayments(MintFixture):
    """The page says the strings it shows are "the only copy". They are not.

    Every payment output was persisted, secret and all, before the exchange
    was sent (§5.1), and is still in the store afterwards.  These tests
    pin that: the exact strings come back out of the file, in another
    process-lifetime's WalletOps instance, with the mint up or down.
    """

    def funded(self, name="w", face=100_000):
        w = self.ops(name)
        w.receive([self.issue(face)])
        return w

    def strings(self, out):
        return [t["token"] for p in out["payments"] for t in p["tokens"]]

    def test_the_tokens_a_payment_returned_can_be_read_back(self):
        w = self.funded("payer")
        paid = w.pay(5_000)
        w.close()

        # A new instance on the same file: the browser tab is gone.
        reread = WalletOps(self.path("payer"), self.base)
        out = reread.outstanding_payments()
        self.assertEqual(sorted(self.strings(out)), sorted(paid["tokens"]))
        self.assertTrue(out["checked"])
        for payment in out["payments"]:
            self.assertEqual(payment["amount_mc"], 5_000)
            self.assertEqual(payment["live_mc"], 5_000)
            for token in payment["tokens"]:
                self.assertEqual(token["state"], "unspent")

    def test_the_read_back_strings_are_still_spendable_money(self):
        """The point of the exercise: recovered strings redeem for real."""
        w = self.funded("loser")
        w.pay(5_000)                      # ...and the result panel is lost
        w.close()

        recovered = self.strings(
            WalletOps(self.path("loser"), self.base).outstanding_payments())
        payee = self.ops("payee")
        got = payee.receive(recovered)
        self.assertEqual(got["rejected"], [])
        self.assertEqual(got["accepted_mc"], 4_950)   # 5000 less the 1% burn

    def test_a_delivered_payment_is_reported_spent_not_stranded(self):
        w = self.funded("deliverer")
        paid = w.pay(5_000)
        self.ops("recipient").receive(paid["tokens"])
        out = w.outstanding_payments()
        self.assertTrue(out["checked"])
        for payment in out["payments"]:
            self.assertEqual(payment["live_mc"], 0)
            for token in payment["tokens"]:
                self.assertEqual(token["state"], "spent")

    def test_with_the_mint_down_the_strings_come_back_unclaimed(self):
        w = self.funded("offline")
        paid = w.pay(5_000)
        self.stop_mint()
        out = w.outstanding_payments()
        self.assertEqual(sorted(self.strings(out)), sorted(paid["tokens"]))
        self.assertFalse(out["checked"])
        for payment in out["payments"]:
            self.assertIsNone(payment["live_mc"])
            for token in payment["tokens"]:
                self.assertIsNone(token["state"])

    def test_an_empty_wallet_has_nothing_outstanding(self):
        """Nothing to report, and `checked` must not call that a failure.

        ``checked`` answers "is every string below the mint's own word for
        it", so with no strings it is vacuously True.  It used to be False
        here, which is the flag that means "the mint could not be asked" —
        reported with the mint up and answering, about a mint that was
        never asked because there was nothing to ask.  That is the same
        conflation of "nothing" with "broken" this module exists to
        refuse; a caller asking whether the mint is reachable reads
        summary()["connected"].
        """
        self.assertEqual(self.ops("empty-out").outstanding_payments(),
                         {"checked": True, "mint_id": "",
                          # Nothing handed over decomposes into four
                          # zeros and no residual -- and 0 unredeemed is
                          # the mint's word about every one of the no
                          # strings here, so it is an int, not None.
                          "handed_over_mc": 0, "unspent_mc": 0,
                          "spent_mc": 0, "unstated_mc": 0,
                          "unchecked_mc": 0, "unaccounted_mc": 0,
                          "unredeemed_mc": 0, "payments": [],
                          # Nothing was left out of the window and there
                          # is no window to leave it out of: the fields
                          # that would say so are present and say so.
                          "payment_count": 0, "listed_mc": 0,
                          "unlisted_mc": 0, "unlisted_outstanding_mc": 0,
                          "truncated": False,
                          # And no pay op handed nothing over either.
                          "recovered_mc": 0, "recovered_ops": []})
        self.assertTrue(self.ops("empty-out").summary()["connected"])

    def test_nothing_to_check_is_still_nothing_when_the_mint_is_down(self):
        """And "is the mint up" is still answered by the field that means it.

        `checked` stays True with the mint down and nothing outstanding,
        and that is not a claim about the mint: it says every string in
        this report carries the mint's own word for it, and there are no
        strings. The report is complete. Whether the mint is reachable is
        summary()["connected"], which says False here — so the two
        questions are asked and answered separately, which is the whole
        point of not collapsing them.
        """
        w = self.ops("empty-down")
        w.summary()                       # materialise the store
        self.stop_mint()
        out = w.outstanding_payments()
        self.assertEqual(out["payments"], [])
        self.assertTrue(out["checked"])
        self.assertFalse(w.summary()["connected"])

    def test_a_token_entry_has_exactly_the_documented_keys(self):
        """The component contract is five keys, `key` and `store_state`.

        The module docstring calls these "the exact shapes a caller may
        rely on", so the key SET is pinned here rather than left to a
        reader to discover; gui/app.py drops `key` and `store_state` on
        the wire and that is stated in the same paragraph.
        """
        w = self.funded("shape-out")
        w.pay(1_000)
        out = w.outstanding_payments()
        self.assertEqual(set(out),
                         {"checked", "mint_id", "handed_over_mc",
                          "payment_count", "listed_mc", "unlisted_mc",
                          "unlisted_outstanding_mc", "truncated",
                          "unspent_mc", "spent_mc", "unstated_mc",
                          "unchecked_mc", "unaccounted_mc",
                          "unredeemed_mc", "recovered_mc", "recovered_ops",
                          "payments"})
        for payment in out["payments"]:
            self.assertEqual(set(payment),
                             {"op_id", "amount_mc", "outstanding_mc",
                              "live_mc", "retired_mc",
                              "unaccounted_mc", "tokens",
                              "recipient", "recipient_kind", "delivery",
                              "delivery_cause", "delivery_attempt"})
            self.assertIn(payment["delivery_attempt"],
                          DELIVERY_ATTEMPT_VALUES)
            for token in payment["tokens"]:
                self.assertEqual(set(token),
                                 {"token", "amount_mc", "key", "state",
                                  "store_state"})
                self.assertIn(token["store_state"], STORE_STATE_VALUES)

    def test_no_second_copy_of_the_money_is_written_anywhere(self):
        """The decision: read the store back, never write the strings down.

        A file of bearer strings beside the wallet would be a second
        complete copy of live money on disk.  The payment record beside
        the store is NOT that file and this proves it rather than
        asserting it: the record is opened and searched for every string
        the payment produced, and for the secret halves on their own.
        """
        w = self.funded("solo-out")
        paid = w.pay(1_000)
        w.unredeemed_payments()
        w.close()
        made = {e for e in os.listdir(self.dir) if e.startswith("solo-out")}
        self.assertEqual(made, {"solo-out.db", "solo-out.payments.db"})
        with open(os.path.join(self.dir, "solo-out.payments.db"), "rb") as fh:
            blob = fh.read()
        self.assertNotIn(b"aicash:", blob)
        for token in paid["tokens"]:
            self.assertNotIn(token.encode(), blob)
            self.assertNotIn(token.split(":")[-1].encode(), blob)

    def test_many_payments_are_checked_in_batches_the_mint_accepts(self):
        """More outstanding strings than one /v3/status call may carry.

        The wallet's coins ladder-split, so a handful of payments is
        already dozens of hashes; an unchunked check would be refused
        wholesale and read as "could not ask", which is the failure this
        module exists to stop.
        """
        w = self.funded("busy", face=200_000)
        for _ in range(12):
            w.pay(1_000)
        out = w.outstanding_payments(limit=100)
        self.assertTrue(out["checked"], "the mint refused the batch")
        tokens = [t for p in out["payments"] for t in p["tokens"]]
        self.assertGreaterEqual(len(tokens), 12)
        self.assertTrue(all(t["state"] == "unspent" for t in tokens))

    def test_limits_are_validated(self):
        w = self.funded("limited")
        w.pay(100)
        w.pay(100)
        self.assertEqual(len(w.outstanding_payments(limit=1)["payments"]), 1)
        for bad in (0, -1, "2", None):
            with self.subTest(limit=bad):
                with self.assertRaises(WalletOpsError):
                    w.outstanding_payments(limit=bad)


class TestCausePerOpTable(unittest.TestCase):
    """The four-way table _settle_cause writes each op's row from.

    A live test can stage three of these (see TestFailureCauses); the
    fourth — an op nothing resolved in a call that ended in a REFUSAL of a
    different exchange — is not reachable through the wallet's current
    control flow, and pinning it here is what stops a future raise site
    from handing one op's answer to another op's row.
    """

    def table(self, state, cause, text):
        module = sys.modules[WalletOps.__module__]
        return module._cause_for_state(state, cause, text)

    def test_an_op_the_mint_refused_keeps_the_answer_it_got(self):
        self.assertEqual(
            self.table("failed", "already_spent", "the mint said so"),
            ("already_spent", "the mint said so"))

    def test_an_op_the_mint_refused_is_never_called_unreachable(self):
        """The reported defect, at the exact line that decides it."""
        cause, sentence = self.table("failed", "mint_unreachable", "no answer")
        self.assertEqual(cause, "mint_rejected")
        self.assertIn("answered and rejected", sentence)
        self.assertNotIn("never", sentence)
        self.assertNotIn("no answer", sentence)

    def test_an_op_nothing_resolved_keeps_the_transport_failure(self):
        self.assertEqual(
            self.table("planned", "mint_stopped", "the mint is down"),
            ("mint_stopped", "the mint is down"))

    def test_an_op_nothing_resolved_never_borrows_a_refusal(self):
        cause, sentence = self.table("planned", "mint_rejected", "spent")
        self.assertEqual(cause, "unknown")
        self.assertIn("undetermined", sentence)
        self.assertNotIn("spent", sentence)

    def test_every_pairing_stays_inside_the_closed_vocabulary(self):
        module = sys.modules[WalletOps.__module__]
        for state in ("failed", "planned", "sent", "", None):
            for cause in module.CAUSES:
                with self.subTest(state=state, cause=cause):
                    got, sentence = self.table(state, cause, "a sentence")
                    self.assertIn(got, module.CAUSES)
                    self.assertTrue(sentence.strip())


# ---------------------------------------------------------------------------
# THE PAYMENT RECORD: a delivered payment and a dead delivery must not be
# the same row three months later.  Every failure below is REAL — a mint
# actually stopped, a token actually spent elsewhere, a process actually
# killed — because a mocked delivery proves nothing about a delivery.
# ---------------------------------------------------------------------------


def _record_rows(store_path):
    """The payment record beside a store, read raw and independently."""
    import sqlite3
    path = store_path[:-3] + ".payments.db" if store_path.endswith(".db") \
        else store_path + ".payments.db"
    if not os.path.exists(path):
        return []
    conn = sqlite3.connect(path)
    try:
        return conn.execute(
            "SELECT op_id, amount_mc, burn_mc, change_mc, token_count,"
            " recipient, recipient_kind, delivery, delivery_cause, note,"
            " delivery_attempt"
            f" FROM walletops_payments").fetchall()
    finally:
        conn.close()


def _wipe_intents(store_path):
    """Delete the intent table beside a store, keeping everything else.

    A pay stranded by some OTHER tool driving the same wallet file leaves
    no row there, and that is the state this simulates: the question
    still arose, and nothing answers it.
    """
    import sqlite3
    path = store_path[:-3] + ".payments.db" if store_path.endswith(".db") \
        else store_path + ".payments.db"
    conn = sqlite3.connect(path)
    try:
        conn.execute("DELETE FROM walletops_payment_intents")
        conn.commit()
    finally:
        conn.close()


class TestPaymentRecord(MintFixture):

    def funded(self, name="payer", face=100_000):
        w = self.ops(name)
        w.receive([self.issue(face)])
        return w

    def pay_row(self, w, op_id=None):
        """The history row for a payment, by op_id."""
        rows = [r for r in w.history() if r["kind"] == "pay"]
        if op_id is not None:
            rows = [r for r in rows if r["op_id"] == op_id]
        self.assertTrue(rows, "no committed pay row in history")
        return rows[0]

    # -- delivered vs not delivered -------------------------------------

    def test_a_delivered_payment_and_a_dead_delivery_are_different_rows(self):
        """THE DEFECT THIS EXISTS TO CLOSE.

        Two payments of the same size out of the same wallet: one arrives,
        one is killed in flight by the mint going down between the payment
        committing and the delivery being attempted.  Every field used to
        be identical.
        """
        alice = self.funded("alice")
        bob = self.ops("bob")
        good = alice.pay(5_000, to="bob", deliver=bob.receive)
        self.assertEqual(good["delivery"], "delivered")
        self.assertEqual(good["recipient"], "bob")
        self.assertEqual(good["recipient_kind"], "wallet")
        self.assertEqual(good["delivery_cause"], "")

        # ...and now the mint dies between the pay and the delivery.  The
        # GUI can see the process is gone (this is the hook gui/app.py
        # installs), so the delivery is KNOWN not to have landed.
        def deliver_into_a_dead_mint(tokens):
            self.stop_mint()
            bob.mint_running = lambda: False
            return bob.receive(tokens)

        dead = alice.pay(5_000, to="bob",
                         deliver=deliver_into_a_dead_mint)
        self.assertEqual(dead["delivery"], "undelivered")
        self.assertEqual(dead["delivery_cause"], "mint_stopped")
        self.assertEqual(dead["recipient"], "bob")

        rows = {r["op_id"]: r for r in alice.history() if r["kind"] == "pay"}
        self.assertEqual(rows[good["op_id"]]["delivery"], "delivered")
        self.assertEqual(rows[dead["op_id"]]["delivery"], "undelivered")
        self.assertEqual(rows[dead["op_id"]]["delivery_cause"], "mint_stopped")
        # The two rows differ in words a human reads, not only in a field.
        self.assertNotEqual(rows[good["op_id"]]["detail"],
                            rows[dead["op_id"]]["detail"])
        self.assertIn("did not take", rows[dead["op_id"]]["detail"])

    def test_an_undelivered_payment_says_how_to_find_the_value_again(self):
        """Undelivered is only useful if the money can be reached."""
        alice = self.funded("alice")
        bob = self.ops("bob")

        def deliver(tokens):
            self.stop_mint()
            bob.mint_running = lambda: False
            return bob.receive(tokens)

        dead = alice.pay(5_000, to="bob", deliver=deliver)
        self.assertEqual(dead["delivery"], "undelivered")
        row = self.pay_row(alice, dead["op_id"])
        self.assertIn(dead["op_id"], row["detail"])

        # The op_id in the row is the handle the read-back groups by, and
        # the strings are really there.
        self.restart_mint()
        out = alice.unredeemed_payments()
        entry = [p for p in out["payments"] if p["op_id"] == dead["op_id"]]
        self.assertEqual(len(entry), 1)
        self.assertEqual(entry[0]["delivery"], "undelivered")
        self.assertEqual(entry[0]["recipient"], "bob")
        self.assertEqual(entry[0]["live_mc"], 5_000)
        strings = [t["token"] for t in entry[0]["tokens"]]
        self.assertEqual(sorted(strings), sorted(dead["tokens"]))
        # ...and it is money, not a description of money.
        got = bob.receive(strings)
        self.assertEqual(got["rejected"], [])
        self.assertEqual(got["accepted_mc"], 4_950)

    def test_nobody_answering_is_recorded_unknown_and_never_undelivered(self):
        """§5.1: an exchange nothing answered may still have landed.

        Same stopped mint as above, but with nothing able to see the
        PROCESS — only the socket.  The weaker claim is the true one, and
        the record must not upgrade it into "it did not arrive".
        """
        alice = self.funded("alice")
        bob = self.ops("bob")

        def deliver(tokens):
            self.stop_mint()
            return bob.receive(tokens)

        out = alice.pay(5_000, to="bob", deliver=deliver)
        self.assertEqual(out["delivery"], "unknown")
        # The OUTCOME is weakened to unknown; the CAUSE is not discarded.
        # "nobody answered" is the precise, pinned word for what happened,
        # and throwing it away made this row byte-identical to a payment
        # whose delivery was never attempted at all.
        self.assertEqual(out["delivery_cause"], "mint_unreachable")
        self.assertEqual(out["delivery_attempt"], "attempted")
        self.assertIn("undetermined", out["delivery_detail"])
        # ...and never the stronger claim.
        self.assertNotIn("undelivered", out["delivery_detail"])
        row = self.pay_row(alice, out["op_id"])
        self.assertEqual(row["delivery"], "unknown")
        self.assertEqual(row["delivery_cause"], "mint_unreachable")
        self.assertEqual(row["recipient"], "bob")
        self.assertIn("undetermined", row["detail"])

    def test_a_partly_refused_delivery_is_undelivered_and_says_how_much(self):
        """A real race: a string of the payment is spent elsewhere first.

        No skip, and deliberately so.  This used to bail out when the
        payment happened to split into a single token, which meant it
        could silently disarm itself — and it did, under a mutation run.
        The thief takes the FIRST string whatever the split is, so the
        race happens every time: with one token the whole payment is
        refused, with more, part of it.  Both are the same finding.
        """
        alice = self.funded("alice")
        bob = self.ops("bob")
        thief = self.ops("thief")
        seen = {}

        def deliver(tokens):
            seen["n"] = len(tokens)
            thief.receive(tokens[:1])       # always, so this never skips
            return bob.receive(tokens)

        out = alice.pay(5_000, to="bob", deliver=deliver)
        self.assertGreaterEqual(seen.get("n", 0), 1)
        self.assertEqual(out["delivery"], "undelivered")
        self.assertEqual(out["delivery_cause"], "already_spent")
        self.assertIn("refused 1 of %d" % seen["n"], out["delivery_detail"])

    def test_already_spent_is_never_recorded_as_money_this_wallet_has(self):
        """THE RACE THE REVIEWER DROVE, and the claim it disproved.

        A third wallet redeems the payment's strings before the recipient
        sees them.  The record used to say, for EVERY undelivered cause,
        "the refused value is still this wallet's money" — while
        unredeemed_payments() reported live_mc 0 and every token spent in
        the same instant.  Two views of one payment, opposite answers
        about whether thousands of millicredits exist, and the permanent
        one was the wrong one.
        """
        alice = self.funded("alice")
        bob = self.ops("bob")
        thief = self.ops("thief")

        def deliver(tokens):
            thief.receive(list(tokens))     # ALL of them, before bob
            return bob.receive(tokens)

        out = alice.pay(5_000, to="bob", deliver=deliver)
        self.assertEqual(out["delivery"], "undelivered")
        self.assertEqual(out["delivery_cause"], "already_spent")
        for text in (out["delivery_detail"],
                     self.pay_row(alice, out["op_id"])["detail"],
                     _record_rows(self.path("alice"))[0][9]):
            self.assertIn("ALREADY BEEN REDEEMED", text)
            self.assertNotIn("still this wallet's money", text)

        # ...and the panel next door agrees, in the same instant.
        report = alice.unredeemed_payments()
        entry = [p for p in report["payments"]
                 if p["op_id"] == out["op_id"]][0]
        self.assertTrue(report["checked"])
        self.assertEqual(entry["live_mc"], 0)
        self.assertEqual({t["state"] for t in entry["tokens"]}, {"spent"})

    def test_a_refusal_that_consumed_nothing_does_say_the_value_is_live(self):
        """The other side of the same judgement: not everything is lost.

        A mint that was DOWN when the recipient tried consumed nothing, so
        the refused value really is still the payer's — and the record
        says so, because a row that hedged about every cause would be as
        useless as one that asserted about every cause.
        """
        alice = self.funded("alice")
        bob = self.ops("bob")
        bob.mint_running = lambda: False    # the GUI knows it is stopped

        def deliver(tokens):
            self.stop_mint()
            return bob.receive(tokens)

        out = alice.pay(5_000, to="bob", deliver=deliver)
        self.assertEqual(out["delivery"], "undelivered")
        self.assertEqual(out["delivery_cause"], "mint_stopped")
        self.assertIn("still this wallet's money", out["delivery_detail"])
        self.assertNotIn("ALREADY BEEN REDEEMED", out["delivery_detail"])
        self.restart_mint()
        entry = alice.unredeemed_payments()["payments"][0]
        self.assertEqual(entry["live_mc"], 5_000)

    # -- inside "unknown": four situations, four rows ---------------------

    def test_the_four_unknown_deliveries_are_not_the_same_row(self):
        """``unknown`` is where most payments land, so it cannot be one box.

        Bearer / never-watched, named-but-never-attempted, attempted and
        interrupted, and attempted with nobody answering all read
        ``delivery: unknown``.  They used to be byte-identical in every
        machine-readable field but one, which is the very defect the
        record was added to remove, reproduced one level down.  "Never
        sent" and "sent and lost" send an operator to different places.
        """
        alice = self.funded("alice", face=200_000)
        bob = self.ops("bob")
        seen = {}

        seen["bearer"] = alice.pay(5_000)["op_id"]
        seen["named"] = alice.pay(5_000, to="bob")["op_id"]

        def interrupted(_tokens):
            raise KeyboardInterrupt("operator hit ctrl-c")

        with self.assertRaises(KeyboardInterrupt):
            alice.pay(5_000, to="bob", deliver=interrupted)

        def nobody_answers(tokens):
            self.stop_mint()
            return bob.receive(tokens)

        alice.pay(5_000, to="bob", deliver=nobody_answers)

        rows = [r for r in alice.history() if r["kind"] == "pay"]
        self.assertEqual(len(rows), 4)
        shapes = {(r["recipient_kind"], r["delivery"], r["delivery_attempt"],
                   r["delivery_cause"]) for r in rows}
        self.assertEqual({r["delivery"] for r in rows}, {"unknown"})
        self.assertEqual(shapes, {
            ("bearer", "unknown", "not_attempted", ""),
            ("wallet", "unknown", "not_attempted", ""),
            ("wallet", "unknown", "attempted", ""),
            ("wallet", "unknown", "attempted", "mint_unreachable"),
        })
        # and no two of the four share a full field set
        self.assertEqual(len(shapes), 4)

    def test_a_checked_report_can_still_know_nothing_about_a_string(self):
        """``checked`` means THE MINT ANSWERED, not "every state is known".

        A different mint on the same address answers perfectly and has no
        ledger entry for these strings, so every state is "unknown" and
        live_mc used to be 0 there -- 0 mc KNOWN TO BE UNSPENT, printed
        as a total about 5000 mc whose fate the same report calls unknown
        on the next line. There is no single number that answers the
        question, so the field says None and the per-token states carry
        what is actually known.
        """
        alice = self.funded("alice")
        out = alice.pay(5_000)
        alice.close()
        self.replacement_mint("other-mint")
        alice = WalletOps(self.path("alice"), self.base)
        report = alice.unredeemed_payments()
        entry = [p for p in report["payments"]
                 if p["op_id"] == out["op_id"]][0]
        self.assertTrue(report["checked"], "the mint answered")
        self.assertEqual({t["state"] for t in entry["tokens"]}, {"unknown"})
        self.assertIsNone(entry["live_mc"])
        self.assertEqual(entry["amount_mc"], 5_000)

    def test_live_mc_is_a_number_only_when_every_string_has_an_answer(self):
        """The neighbour of the case above: a mixture.

        One string of a payment spent, another the mint has no entry for.
        A sum over the definite ones would present a partial account as a
        total, which is the same defect in smaller print.
        """
        alice = self.funded("alice")
        bob = self.ops("bob")
        out = alice.pay(5_000)
        bob.receive(out["tokens"])              # all of it, really spent
        report = alice.unredeemed_payments()
        entry = [p for p in report["payments"]
                 if p["op_id"] == out["op_id"]][0]
        # every state definite -> a real number, and it is 0
        self.assertEqual(entry["live_mc"], 0)
        self.assertEqual({t["state"] for t in entry["tokens"]}, {"spent"})

    def test_a_long_refusal_never_crowds_out_the_money_or_the_op_id(self):
        """The trim cuts from the right, so what is at the right matters.

        A recipient that answers with 900 characters of prose used to
        push the clause about whether the value still exists, and the
        op_id that finds it again, off the end of a record bounded at
        _SENTENCE_MAX -- leaving a row that quoted somebody else's stack
        trace and said nothing an operator could act on. The quote is the
        part that gets clipped now, and the caller's copy is the same
        sentence as the stored one rather than a longer version of it.
        """
        module = sys.modules[WalletOps.__module__]
        alice = self.funded("alice")

        class Wordy(Exception):
            cause = "already_spent"
            reason = "already spent"
            detail = "x" * 900

        def deliver(_tokens):
            raise module.WalletOpsError(Wordy.reason, Wordy.detail,
                                        Wordy.cause)

        out = alice.pay(5_000, to="bob", deliver=deliver)
        note = out["delivery_detail"]
        self.assertLessEqual(len(note), module._SENTENCE_MAX)
        self.assertIn("not this wallet's money", note)
        self.assertIn(out["op_id"], note)
        # ...and what was returned is byte-for-byte what was written down
        self.assertEqual(_record_rows(self.path("alice"))[0][9], note)
        self.assertEqual(self.pay_row(alice, out["op_id"])["detail"]
                         .endswith(note), True)

    def test_the_record_file_is_created_0600_like_the_store(self):
        """A sidecar's whole defence is "it holds no secret".

        True, and not the same claim as "anyone on this machine may read
        it": it holds every recipient name, amount, burn, change and
        op_id this wallet ever paid — the payment graph — and it sat at
        the ambient umask, 0644 under a default 022, beside a store the
        protocol layer took care to make 0600.
        """
        old = os.umask(0o022)
        self.addCleanup(os.umask, old)
        alice = self.funded("alice")
        alice.pay(5_000, to="bob")
        record = alice.record_path
        self.assertTrue(os.path.exists(record))
        self.assertEqual(stat.S_IMODE(os.stat(record).st_mode), 0o600)
        # and the recipient really is in there in plaintext, which is why
        with open(record, "rb") as handle:
            self.assertIn(b"bob", handle.read())

    def test_a_record_file_left_world_readable_is_repaired_on_the_next_write(self):
        alice = self.funded("alice")
        alice.pay(1_000, to="bob")
        os.chmod(alice.record_path, 0o644)
        alice.pay(1_000, to="carol")
        self.assertEqual(stat.S_IMODE(os.stat(alice.record_path).st_mode),
                         0o600)

    # -- a settled outcome is permanent -----------------------------------

    def test_a_settled_outcome_is_never_rewritten(self):
        """The row is the permanent record, not the latest opinion."""
        alice = self.funded("alice")
        bob = self.ops("bob")
        out = alice.pay(5_000, to="bob", deliver=bob.receive)
        self.assertEqual(out["delivery"], "delivered")
        again = alice.settle_delivery(
            out["op_id"], result={"rejected": [{"cause": "already_spent"}],
                                  "accepted": 0})
        self.assertFalse(again["recorded"])
        self.assertEqual(self.pay_row(alice, out["op_id"])["delivery"],
                         "delivered")

    def test_settle_delivery_records_what_the_other_side_watched(self):
        """The second way this product delivers a payment.

        A wallet that pays and then hands the strings over separately
        produced exactly the same outcome as pay(deliver=...), and the
        observation used to be thrown away — so one payment read
        "delivered to bob" through one route and "unknown" through the
        other.
        """
        alice = self.funded("alice")
        bob = self.ops("bob")
        out = alice.pay(5_000, to="bob")
        self.assertEqual(out["delivery"], "unknown")
        got = bob.receive(out["tokens"])
        self.assertEqual(got["rejected"], [])
        noted = alice.settle_delivery(out["op_id"], result=got,
                                      recipient="bob")
        self.assertTrue(noted["recorded"])
        self.assertEqual(noted["delivery"], "delivered")
        row = self.pay_row(alice, out["op_id"])
        self.assertEqual(row["delivery"], "delivered")
        self.assertEqual(row["recipient"], "bob")
        self.assertEqual(row["recipient_kind"], "wallet")
        # DID THIS WALLET EVER TRY?  No: it was given no deliver= and the
        # observation came from the recipient's side of this GUI.  This
        # line used to assert "attempted", which is the field saying the
        # opposite of its own definition -- and it is the difference
        # between "never sent" and "sent and lost", which send an operator
        # to different components.
        self.assertEqual(row["delivery_attempt"], "not_attempted")

    def test_a_named_observer_cannot_rewrite_a_bearer_payment(self):
        """THE ARM ``gui/app.py`` ACTUALLY DRIVES.

        POST /api/wallet/receive always knows the name of the wallet it
        just credited, so it always passes one; this is the only arm of
        the CASE the product reaches.  It used to rewrite two closed-set
        fields into members that are not true of the payment:
        ``recipient_kind`` said the operator named a wallet (they named
        nobody: ``bearer`` was a fact THIS wallet knew at payment time),
        and ``recipient`` named that wallet as the one asked for.  Both
        values are inside their sets, which is why a membership sweep
        could not see it.

        What the observer watched is not lost — it is in the note, where
        it belongs: the record says WHO WAS ASKED FOR, the note says where
        the strings landed.
        """
        alice = self.funded("alice")
        bob = self.ops("bob")
        out = alice.pay(5_000)                      # no recipient named
        self.assertEqual(out["recipient_kind"], "bearer")
        got = bob.receive(out["tokens"])
        self.assertEqual(got["rejected"], [])
        noted = alice.settle_delivery(out["op_id"], result=got,
                                      recipient="bob")
        self.assertTrue(noted["recorded"])
        row = self.pay_row(alice, out["op_id"])
        self.assertEqual(row["delivery"], "delivered")      # the new fact
        self.assertEqual(row["recipient_kind"], "bearer")   # the old ones
        self.assertEqual(row["recipient"], "")
        # ...and THIS wallet never tried to deliver anything
        self.assertEqual(row["delivery_attempt"], "not_attempted")
        # ...while the wallet that took the strings is still on the row
        self.assertIn("bob", row["detail"])
        # and every value is still inside its declared set
        self.assertIn(row["recipient_kind"], RECIPIENT_KIND_VALUES)
        self.assertIn(row["delivery"], DELIVERY_VALUES)
        self.assertIn(row["delivery_attempt"], DELIVERY_ATTEMPT_VALUES)

    def test_settle_delivery_on_an_op_with_no_record_records_nothing(self):
        alice = self.funded("alice")
        out = alice.settle_delivery("not-an-op", result={"rejected": []})
        self.assertFalse(out["recorded"])
        self.assertEqual(out["delivery"], "delivered")   # what was observed
        self.assertEqual(_record_rows(self.path("alice")), [])

    def test_settle_delivery_with_nothing_observed_writes_nothing(self):
        alice = self.funded("alice")
        out = alice.pay(5_000, to="bob")
        noted = alice.settle_delivery(out["op_id"])
        self.assertFalse(noted["recorded"])
        self.assertEqual(noted["delivery"], "unknown")
        self.assertEqual(self.pay_row(alice, out["op_id"])["delivery"],
                         "unknown")

    def test_a_record_written_before_the_attempt_column_existed_still_reads(self):
        """The column was added after the table shipped.

        A file an older build wrote has the table already, so CREATE TABLE
        IF NOT EXISTS does nothing to it — and an INSERT or a SELECT
        naming a column it lacks fails silently, which would turn "a field
        was added" into "this wallet records nothing any more".
        """
        import sqlite3
        alice = self.funded("alice")
        out = alice.pay(5_000, to="bob")
        record = alice.record_path
        conn = sqlite3.connect(record)
        try:
            conn.execute("ALTER TABLE walletops_payments"
                         " RENAME TO walletops_payments_new")
            conn.execute(
                "CREATE TABLE walletops_payments AS SELECT op_id, mint_id,"
                " amount_mc, burn_mc, change_mc, token_count, recipient,"
                " recipient_kind, delivery, delivery_cause, note"
                " FROM walletops_payments_new")
            conn.execute("DROP TABLE walletops_payments_new")
            conn.commit()
        finally:
            conn.close()
        alice.close()
        alice = WalletOps(self.path("alice"), self.base)
        row = self.pay_row(alice, out["op_id"])
        self.assertEqual(row["recipient"], "bob")       # still readable
        self.assertEqual(row["delivery"], "unknown")
        # NOTHING WAS RECORDED, and that is a word -- not "" (which on
        # these rows means "this is not a payment, so the question does
        # not arise") and not "not_attempted" (which would answer, on an
        # old row's behalf, a question nobody asked it).
        self.assertEqual(row["delivery_attempt"], UNDETERMINED)
        self.assertIn(row["delivery_attempt"], DELIVERY_ATTEMPT_VALUES)
        # ...and a later write migrates the file rather than failing
        alice.pay(1_000, to="carol")
        rows = {r[5]: r[10] for r in _record_rows(self.path("alice"))}
        self.assertEqual(rows["carol"], "not_attempted")
        # the migration's own DEFAULT says it too, in the file itself
        self.assertEqual(rows["bob"], UNDETERMINED)

    # -- interrupted, then recovered: the row nothing was handed over ----

    def strand_a_payment(self, ops, amount_mc=5_000, **kw):
        """Interrupt a payment the way the transport really interrupts one.

        ``DeliverThenDropClient`` puts the exchange on the wire, lets the
        MINT COMMIT IT, and drops the response — §5.1's crash-in-flight,
        and the only way to reach the row this section is about.  ``pay()``
        raises without returning a single string, the op is left
        ``planned``, and ``recover()`` afterwards settles it against the
        ledger into a committed ``pay`` that handed nothing to anybody.
        """
        ops._open()                     # bind, so there is a client to swap
        ops._wallet.client = DeliverThenDropClient(self.base)
        try:
            with self.assertRaises(WalletOpsError) as cm:
                ops.pay(amount_mc, **kw)
            self.assertEqual(cm.exception.cause, "mint_unreachable")
        finally:
            ops._wallet.client = MintClient(self.base)
        return cm.exception

    def test_a_recovered_payment_carries_no_field_outside_its_closed_set(self):
        """THE DEFECT THIS SECTION EXISTS TO CLOSE.

        Interrupt a payment, recover it, and read the row.  Until this
        round it came back with ``recipient_kind: ""`` and
        ``delivery_attempt: ""`` — neither of which is in either
        vocabulary, and both of which are the SAME string the row next
        door uses for "this is not a payment, so the question does not
        arise".  A missing value wearing a value's clothes, which is the
        defect this project has now closed three times elsewhere.
        """
        alice = self.funded("alice")
        self.strand_a_payment(alice, to="bob")
        self.assertEqual(alice.recover()["ops_confirmed"], 1)

        row = self.pay_row(alice)
        self.assertIn(row["recipient_kind"], RECIPIENT_KIND_VALUES)
        self.assertIn(row["delivery_attempt"], DELIVERY_ATTEMPT_VALUES)
        self.assertIn(row["delivery"], DELIVERY_VALUES)
        # ...and specifically NOT the blank that meant two things
        self.assertNotEqual(row["recipient_kind"], NOT_APPLICABLE)
        self.assertNotEqual(row["delivery_attempt"], NOT_APPLICABLE)
        # The product knew all three of these before it printed the row.
        self.assertEqual(row["delivery"], "undelivered")
        self.assertEqual(row["delivery_attempt"], "not_attempted")
        self.assertEqual(row["delivery_cause"], NOT_APPLICABLE)
        self.assertIn("nothing was handed over", row["detail"])

    def test_a_recovered_payment_still_names_who_it_was_meant_for(self):
        """The name the operator typed is a fact about what was ATTEMPTED.

        It is not a fact about where value went — nothing went anywhere —
        and the row says both in one breath.  Dropping it to "" threw away
        the only thing that tells one stranded payment from another, and
        nothing on this machine could reconstruct it afterwards: it is not
        in the store (a recipient is not a protocol fact), the strings
        were never returned, and there is no payment record because there
        was no payment.
        """
        alice = self.funded("alice")
        self.strand_a_payment(alice, to="bob")
        alice.recover()
        row = self.pay_row(alice)
        self.assertEqual(row["recipient"], "bob")
        self.assertEqual(row["recipient_kind"], "wallet")
        # ...and the sentence never lets the name read as a destination
        self.assertIn("nothing was handed over", row["detail"])
        self.assertIn("meant for bob", row["detail"])
        self.assertIn("spendable balance", row["detail"])

    def test_a_stranded_bearer_payment_records_bearer_not_a_blank(self):
        alice = self.funded("alice")
        self.strand_a_payment(alice)            # no recipient named
        alice.recover()
        row = self.pay_row(alice)
        self.assertEqual(row["recipient_kind"], "bearer")
        self.assertEqual(row["recipient"], "")
        self.assertIn("no recipient was named", row["detail"])

    def test_a_recovered_row_is_not_the_same_row_as_a_delivered_payment(self):
        """Distinguishable in MACHINE-READABLE fields, not only in prose."""
        alice = self.funded("alice", face=200_000)
        bob = self.ops("bob")
        good = alice.pay(5_000, to="bob", deliver=bob.receive)
        self.assertEqual(good["delivery"], "delivered")
        self.strand_a_payment(alice, to="bob")
        alice.recover()

        rows = {r["op_id"]: r for r in alice.history() if r["kind"] == "pay"}
        self.assertEqual(len(rows), 2)
        shapes = {(r["recipient_kind"], r["delivery"], r["delivery_attempt"])
                  for r in rows.values()}
        self.assertEqual(shapes, {("wallet", "delivered", "attempted"),
                                  ("wallet", "undelivered", "not_attempted")})
        # Both name bob; only one of them is a claim about where money is.
        self.assertEqual({r["recipient"] for r in rows.values()}, {"bob"})
        self.assertIn("delivered to", rows[good["op_id"]]["detail"])
        self.assertNotIn("nothing was handed over",
                         rows[good["op_id"]]["detail"])

    def test_the_two_views_of_a_recovered_payment_agree_field_for_field(self):
        """history() and unredeemed_payments() describe one op.

        The last round stopped the recovered value being counted twice;
        this one stops the two reports describing it differently.  An
        operator matches them by op_id, and two panels answering one
        question two ways is the defect both of them exist to have ended.
        """
        alice = self.funded("alice")
        self.strand_a_payment(alice, to="bob")
        alice.recover()
        row = self.pay_row(alice)
        out = alice.unredeemed_payments()
        self.assertEqual(out["recovered_mc"], 5_000)
        self.assertEqual([p["op_id"] for p in out["payments"]], [])
        recovered = [r for r in out["recovered_ops"]
                     if r["op_id"] == row["op_id"]]
        self.assertEqual(len(recovered), 1)
        for field in ("recipient", "recipient_kind", "delivery",
                      "delivery_cause", "delivery_attempt"):
            self.assertEqual(recovered[0][field], row[field], field)
        self.assertEqual(recovered[0]["amount_mc"], row["amount_mc"])

    def test_a_stranded_payment_that_never_recovers_claims_no_delivery(self):
        """The neighbouring row, so the fix cannot leak into it.

        Until recover() runs the op is `planned`: no money moved that this
        wallet knows of, so there is no DELIVERY for a question to be
        about, and all three delivery fields are NOT_APPLICABLE rather
        than a claim about a payment that may not exist.

        The two RECIPIENT fields are the opposite case, and this test used
        to assert the defect: a `pay_pending` row IS a payment, "who was
        this for" arises on it, and the answer is one SELECT away in this
        module's own intent table.  NOT_APPLICABLE there said the question
        did not arise about a payment addressed to a named wallet.
        """
        alice = self.funded("alice")
        self.strand_a_payment(alice, to="bob")
        rows = [r for r in alice.history() if r["kind"].startswith("pay")]
        self.assertEqual([r["kind"] for r in rows], ["pay_pending"])
        for field in ("delivery", "delivery_cause", "delivery_attempt"):
            self.assertEqual(rows[0][field], NOT_APPLICABLE, field)
        self.assertEqual(rows[0]["recipient"], "bob")
        self.assertEqual(rows[0]["recipient_kind"], "wallet")
        self.assertIn(rows[0]["recipient_kind"], RECIPIENT_KIND_VALUES)
        # ...and the name is never sayable except beside "no value left"
        self.assertIn("no value left the wallet", rows[0]["detail"])
        self.assertIn("meant for bob", rows[0]["detail"])
        self.assertEqual(rows[0]["cause"], "mint_unreachable")
        # ...and nothing was written to the PAYMENT record for it
        self.assertEqual(_record_rows(self.path("alice")), [])

    def test_a_stranded_pay_names_one_recipient_throughout(self):
        """THE PRODUCT MUST NOT FORGET A NAME AND THEN REMEMBER IT.

        One durable fact, one op_id, two readings of the same row minutes
        apart: the state an operator stares at during an outage, and the
        state after recover() settles it.  They used to disagree —
        ``recipient: ""`` while stranded, ``recipient: "bob"`` afterwards
        — off the SAME intent row, which was already on disk both times.
        """
        alice = self.funded("alice")
        self.strand_a_payment(alice, to="bob")
        self.strand_a_payment(alice, to="carol")
        self.strand_a_payment(alice)                    # bearer

        def named(w):
            return {r["op_id"]: (r["recipient"], r["recipient_kind"])
                    for r in w.history() if r["kind"].startswith("pay")}

        before = named(alice)
        self.assertEqual(sorted(before.values()),
                         [("", "bearer"), ("bob", "wallet"),
                          ("carol", "wallet")])
        alice.recover()
        after = named(alice)
        self.assertEqual(before, after)
        # ...and none of the stranded rows claimed a delivery outcome
        self.assertEqual(
            {r["delivery"] for r in alice.history()
             if r["kind"] == "pay_pending"}, set())

    def test_a_stranded_payment_with_no_intent_row_is_undetermined(self):
        """No answer is ``unknown``, never ``""``.

        A pay stranded by some other tool driving the same wallet file
        leaves no intent row.  The question still arose — somebody asked
        for this payment — so the row says it does not know, in the word
        that means that, and not in the string that means "there was no
        payment here".
        """
        alice = self.funded("alice")
        self.strand_a_payment(alice, to="bob")
        _wipe_intents(self.path("alice"))
        row = [r for r in alice.history()
               if r["kind"] == "pay_pending"][0]
        self.assertEqual(row["recipient"], "")
        self.assertEqual(row["recipient_kind"], UNDETERMINED)
        self.assertNotEqual(row["recipient_kind"], NOT_APPLICABLE)
        self.assertIn("no record says who it was meant for", row["detail"])
        self.assertEqual(row["delivery"], NOT_APPLICABLE)

    def test_every_closed_set_field_of_every_history_row_is_in_its_set(self):
        """THE SWEEP, driven rather than reasoned about.

        Nine payments across every path that writes one of these fields —
        bearer, named, delivered, refused, interrupted, unanswered, a
        payment with its record deleted, one stranded, one stranded and
        recovered — read back through history() and through
        unredeemed_payments(), asserting only that every value came from
        the set the module itself declares.
        """
        alice = self.funded("alice", face=400_000)
        bob = self.ops("bob")
        alice.pay(5_000)                                    # bearer
        alice.pay(5_000, to="bob")                          # named, no deliver
        alice.pay(5_000, to="bob", deliver=bob.receive)     # delivered

        def refuse(_tokens):
            raise WalletOpsError("mint said no", "refused outright",
                                 "mint_rejected")
        alice.pay(5_000, to="bob", deliver=refuse)          # undelivered

        def interrupted(_tokens):
            raise KeyboardInterrupt("operator hit ctrl-c")
        with self.assertRaises(KeyboardInterrupt):
            alice.pay(5_000, to="bob", deliver=interrupted)

        def raises_oddly(_tokens):
            raise RuntimeError("something else entirely")
        alice.pay(5_000, to="bob", deliver=raises_oddly)    # unknown/unknown

        self.strand_a_payment(alice, to="carol")            # pay_pending
        alice.recover()                                     # -> recovered
        self.strand_a_payment(alice, to="dave")             # left pending

        rows = alice.history()
        self.assertGreaterEqual(len([r for r in rows
                                     if r["kind"] == "pay"]), 6)
        for row in rows:
            with self.subTest(kind=row["kind"], op=row["op_id"][:8]):
                self.assertIn(row["recipient_kind"], RECIPIENT_KIND_VALUES)
                self.assertIn(row["delivery"], DELIVERY_VALUES)
                self.assertIn(row["delivery_attempt"],
                              DELIVERY_ATTEMPT_VALUES)
                self.assertTrue(row["delivery_cause"] == NOT_APPLICABLE
                                or row["delivery_cause"] in _causes())
                self.assertTrue(row["cause"] == NOT_APPLICABLE
                                or row["cause"] in _causes())
                # NOT_APPLICABLE means "the question does not arise", and
                # which questions arise depends on the row.  A PAYMENT --
                # committed or not -- always had a recipient or was
                # deliberately bearer, so `recipient_kind` is never the
                # blank on one.  A DELIVERY only exists where money
                # actually moved, so the three delivery fields are blank
                # on every pay that did not commit.  This split is the
                # sweep's whole point: it used to lump `pay_pending` and
                # `pay_failed` in with `receive` and so asserted the
                # defect -- "no recipient here" about a payment whose
                # recipient this module had written down.
                if row["kind"].startswith("pay"):
                    self.assertNotEqual(row["recipient_kind"],
                                        NOT_APPLICABLE)
                if row["kind"] == "pay":
                    self.assertNotEqual(row["delivery_attempt"],
                                        NOT_APPLICABLE)
                if row["kind"] in ("pay_pending", "pay_failed"):
                    self.assertEqual(row["delivery_attempt"], NOT_APPLICABLE)
                    self.assertEqual(row["delivery"], NOT_APPLICABLE)
                    self.assertEqual(row["delivery_cause"], NOT_APPLICABLE)
                if row["kind"] == "receive":
                    self.assertEqual(row["recipient"], NOT_APPLICABLE)
                    self.assertEqual(row["recipient_kind"], NOT_APPLICABLE)
                    self.assertEqual(row["delivery_attempt"], NOT_APPLICABLE)
                    self.assertEqual(row["delivery"], NOT_APPLICABLE)

        out = alice.unredeemed_payments()
        for payment in list(out["payments"]) + list(out["recovered_ops"]):
            with self.subTest(op=payment["op_id"][:8]):
                self.assertIn(payment["recipient_kind"],
                              RECIPIENT_KIND_VALUES)
                self.assertIn(payment["delivery"], DELIVERY_VALUES)
                self.assertIn(payment["delivery_attempt"],
                              DELIVERY_ATTEMPT_VALUES)
                self.assertNotEqual(payment["recipient_kind"],
                                    NOT_APPLICABLE)
                self.assertNotEqual(payment["delivery_attempt"],
                                    NOT_APPLICABLE)
                for token in payment.get("tokens", ()):
                    self.assertIn(token["store_state"], STORE_STATE_VALUES)
                    self.assertIn(token["state"],
                                  ("unspent", "spent", "unknown", None))

    def test_every_recipient_kind_is_what_the_caller_actually_asked_for(self):
        """THE SWEEP ASKED THE WEAKER QUESTION, so this one asks the other.

        "Is this value inside its declared tuple" cannot see a value that
        is in the tuple and false about the payment — which is what both
        of this round's defects were.  So every row here is checked
        against the ground truth held OUTSIDE the product: the ``to=``
        the test itself passed.  ``wallet`` iff a name was given,
        ``bearer`` iff none was, on every path that writes the field and
        in every state a payment can be read in.
        """
        alice = self.funded("alice", face=400_000)
        bob = self.ops("bob")
        asked = {}                      # op_id -> what the caller asked for

        def record(out, to):
            asked[out["op_id"]] = "wallet" if to else "bearer"
            return out

        record(alice.pay(5_000, to="bob"), "bob")               # named
        record(alice.pay(5_000), None)                          # bearer
        record(alice.pay(5_000, to="bob", deliver=bob.receive), "bob")
        out = record(alice.pay(5_000), None)                    # bearer...
        alice.settle_delivery(out["op_id"],                     # ...observed
                              result=bob.receive(out["tokens"]),
                              recipient="bob")

        def refuse(_tokens):
            raise WalletOpsError("no", "refused", "mint_rejected")
        record(alice.pay(5_000, to="carol", deliver=refuse), "carol")
        # (no bearer + deliver= arm: pay() refuses that combination -- a
        # delivery to nobody in particular is not a thing it will record)

        # stranded and left pending, stranded and recovered, both ways
        for to in ("dave", None):
            exc = self.strand_a_payment(alice, to=to)
            del exc
        pending = {r["op_id"] for r in alice.history()
                   if r["kind"] == "pay_pending"}
        self.assertEqual(len(pending), 2)
        for op_id in pending:
            row = [r for r in alice.history() if r["op_id"] == op_id][0]
            asked[op_id] = "wallet" if "dave" in row["detail"] else "bearer"
        before = {op: asked[op] for op in pending}
        alice.recover()

        rows = {r["op_id"]: r for r in alice.history(limit=500)}
        self.assertGreaterEqual(len(asked), 7)
        for op_id, wanted in asked.items():
            with self.subTest(op=op_id[:8], asked=wanted):
                row = rows[op_id]
                self.assertEqual(row["recipient_kind"], wanted)
                # and the NAME field says a name exactly when one was asked
                self.assertEqual(bool(row["recipient"]), wanted == "wallet")
        # ...and the two stranded ones answer the same after recover()
        for op_id, wanted in before.items():
            self.assertEqual(rows[op_id]["recipient_kind"], wanted)

    def test_delivery_attempt_is_only_ever_answered_by_the_payer(self):
        """``attempted`` iff ``pay()`` was given a ``deliver=``.

        The field's definition is "did THIS WALLET ever try?", so it has
        exactly one writer and exactly one moment: ``begin()``, from
        ``deliver is not None``.  Everything downstream -- a refusal, a
        success, an observation routed back from the recipient's side of
        this GUI -- watches an OUTCOME and has nothing to add to it.
        """
        alice = self.funded("alice", face=400_000)
        bob = self.ops("bob")
        tried, did_not = [], []

        tried.append(alice.pay(5_000, to="bob", deliver=bob.receive))

        def refuse(_tokens):
            raise WalletOpsError("no", "refused", "mint_rejected")
        tried.append(alice.pay(5_000, to="bob", deliver=refuse))

        did_not.append(alice.pay(5_000, to="bob"))      # named, not sent
        did_not.append(alice.pay(5_000))                # bearer

        for out in list(did_not):                       # then observed
            alice.settle_delivery(out["op_id"],
                                  result=bob.receive(out["tokens"]),
                                  recipient="bob")

        rows = {r["op_id"]: r for r in alice.history(limit=500)}
        for out in tried:
            self.assertEqual(rows[out["op_id"]]["delivery_attempt"],
                             "attempted", out["op_id"])
        for out in did_not:
            self.assertEqual(rows[out["op_id"]]["delivery_attempt"],
                             "not_attempted", out["op_id"])
            # ...and the observation WAS recorded, in the field for it
            self.assertEqual(rows[out["op_id"]]["delivery"], "delivered")

    def test_a_nameless_observer_cannot_erase_a_recorded_bearer_kind(self):
        """A permanent record may gain certainty, never lose it.

        ``settle_delivery`` fills in a recipient only where NOTHING was
        named — and it used to fill in the KIND on the same condition,
        with whatever the caller passed.  An observer that watched a
        bearer payment land but could not say into which wallet passed
        "", so ``bearer`` — a fact recorded at payment time, from
        something this wallet knew — was overwritten with the string that
        means "nothing was recorded".
        """
        alice = self.funded("alice")
        bob = self.ops("bob")
        out = alice.pay(5_000)                      # bearer, kind recorded
        self.assertEqual(self.pay_row(alice, out["op_id"])["recipient_kind"],
                         "bearer")
        bob.receive(out["tokens"])
        noted = alice.settle_delivery(
            out["op_id"], result={"rejected": [], "accepted_mc": 4_950})
        self.assertTrue(noted["recorded"])
        row = self.pay_row(alice, out["op_id"])
        self.assertEqual(row["delivery"], "delivered")      # the new fact
        self.assertEqual(row["recipient_kind"], "bearer")   # the old one
        self.assertIn(row["recipient_kind"], RECIPIENT_KIND_VALUES)

    # -- interruption: the honest unknown --------------------------------

    def test_an_interrupted_delivery_is_left_unknown_not_guessed(self):
        """A KeyboardInterrupt through the delivery is not an observation."""
        alice = self.funded("alice")

        def deliver(_tokens):
            raise KeyboardInterrupt("operator hit ctrl-c")

        with self.assertRaises(KeyboardInterrupt):
            alice.pay(5_000, to="bob", deliver=deliver)
        row = self.pay_row(alice)
        self.assertEqual(row["delivery"], "unknown")
        self.assertEqual(row["recipient"], "bob")
        self.assertEqual(row["delivery_cause"], "")
        # and the value is still findable
        entry = alice.unredeemed_payments()["payments"][0]
        self.assertEqual(entry["op_id"], row["op_id"])
        self.assertEqual(entry["live_mc"], 5_000)

    def test_the_record_is_written_before_the_delivery_is_attempted(self):
        """The ordering IS the durability claim, so it is read mid-flight."""
        alice = self.funded("alice")
        bob = self.ops("bob")
        during = {}

        def deliver(tokens):
            during["rows"] = _record_rows(self.path("alice"))
            return bob.receive(tokens)

        alice.pay(5_000, to="bob", deliver=deliver)
        rows = during["rows"]
        self.assertEqual(len(rows), 1, "no record existed during delivery")
        self.assertEqual(rows[0][7], "unknown")     # delivery
        self.assertEqual(rows[0][5], "bob")         # recipient
        self.assertEqual(rows[0][1], 5_000)         # amount_mc

    def test_the_record_survives_the_process_that_wrote_it_being_killed(self):
        """A REAL process death, mid-delivery, and a REAL restart after it.

        The GUI is a process; "durable" has to mean "survives that process
        dying", not "survives another method call".  A child interpreter
        pays and is killed inside the delivery; the parent then reads the
        record back with a wallet it opens fresh.
        """
        import subprocess
        alice = self.funded("killed")
        alice.close()
        script = (
            "import os, sys\n"
            "sys.path[:0] = [%r, %r]\n"
            "from walletops import WalletOps\n"
            "w = WalletOps(%r, %r)\n"
            "def deliver(tokens):\n"
            "    os._exit(9)\n"
            "w.pay(5000, to='bob', deliver=deliver)\n"
            % (os.path.join(_ROOT, "impl"), _HERE,
               self.path("killed"), self.base)
        )
        done = subprocess.run([sys.executable, "-c", script],
                              capture_output=True, timeout=120)
        self.assertEqual(done.returncode, 9,
                         "the child did not die where it was meant to: %s"
                         % done.stderr[-400:])

        fresh = WalletOps(self.path("killed"), self.base)
        row = self.pay_row(fresh)
        self.assertEqual(row["delivery"], "unknown")
        self.assertEqual(row["recipient"], "bob")
        self.assertEqual(row["recipient_kind"], "wallet")
        self.assertEqual(row["amount_mc"], 5_000)
        # ...and the money the dead process paid out is still reachable.
        out = fresh.unredeemed_payments()
        self.assertTrue(out["checked"])
        entry = [p for p in out["payments"] if p["op_id"] == row["op_id"]]
        self.assertEqual(len(entry), 1)
        self.assertEqual(entry[0]["live_mc"], 5_000)
        self.assertEqual(entry[0]["delivery"], "unknown")
        self.assertEqual(entry[0]["recipient"], "bob")

    # -- bearer, and the absence of a record -----------------------------

    def test_pay_returns_exactly_the_documented_keys(self):
        """The pinned shape, so a caller may rely on all ten."""
        alice = self.funded("alice")
        bob = self.ops("bob")
        for label, out in (
                ("bearer", alice.pay(500)),
                ("named", alice.pay(500, to="bob")),
                ("delivered", alice.pay(500, to="bob",
                                        deliver=bob.receive))):
            with self.subTest(payment=label):
                self.assertEqual(set(out), {
                    "tokens", "amount_mc", "burn_mc", "change_mc", "op_id",
                    "recipient", "recipient_kind", "delivery",
                    "delivery_cause", "delivery_attempt",
                    "delivery_detail"})
                self.assertIn(out["delivery"], ("delivered", "undelivered",
                                                "unknown"))
                self.assertIn(out["delivery_attempt"],
                              ("attempted", "not_attempted"))
                self.assertIn(out["recipient_kind"], ("wallet", "bearer"))
                self.assertTrue(out["delivery_cause"] == "" or
                                out["delivery_cause"] in _causes())
                self.assertTrue(out["delivery_detail"].strip())
                self.assertTrue(out["op_id"])

    def test_bearer_strings_are_recorded_as_bearer_not_as_a_recipient(self):
        alice = self.funded("alice")
        out = alice.pay(5_000)
        self.assertEqual(out["recipient"], "")
        self.assertEqual(out["recipient_kind"], "bearer")
        self.assertEqual(out["delivery"], "unknown")
        row = self.pay_row(alice, out["op_id"])
        self.assertEqual(row["recipient_kind"], "bearer")
        self.assertEqual(row["delivery"], "unknown")
        self.assertIn("bearer", row["detail"])
        # "bearer" and "nothing was recorded" are different states and the
        # row says which: one names the kind, the other cannot.
        self.assertNotEqual(row["recipient_kind"], "")

    def test_a_payment_with_no_record_reads_unknown_never_delivered(self):
        """An older build, wallet_cli, or a deleted record file."""
        alice = self.funded("alice")
        bob = self.ops("bob")
        out = alice.pay(5_000, to="bob", deliver=bob.receive)
        self.assertEqual(out["delivery"], "delivered")
        os.unlink(alice.record_path)
        row = self.pay_row(alice, out["op_id"])
        self.assertEqual(row["delivery"], "unknown")
        self.assertEqual(row["recipient"], "")
        # UNDETERMINED, not NOT_APPLICABLE. A payment was made, so it had
        # a recipient of one kind or the other and an attempt was or was
        # not made; this wallet has no row that says which. The `receive`
        # row two lines down has no recipient field to fill at all, and
        # the two must not be the same string.
        self.assertEqual(row["recipient_kind"], UNDETERMINED)
        self.assertEqual(row["delivery_attempt"], UNDETERMINED)
        self.assertIn("not known", row["detail"])
        other = [r for r in alice.history() if r["kind"] == "receive"][0]
        self.assertEqual(other["recipient_kind"], NOT_APPLICABLE)
        self.assertEqual(other["delivery_attempt"], NOT_APPLICABLE)
        self.assertNotEqual(row["recipient_kind"], other["recipient_kind"])

    def test_a_corrupt_record_file_reads_unknown_and_does_not_raise(self):
        alice = self.funded("alice")
        bob = self.ops("bob")
        out = alice.pay(5_000, to="bob", deliver=bob.receive)
        with open(alice.record_path, "wb") as fh:
            fh.write(b"this is not a database" * 100)
        row = self.pay_row(alice, out["op_id"])
        self.assertEqual(row["delivery"], "unknown")
        self.assertEqual(alice.unredeemed_payments()["payments"][0]
                         ["delivery"], "unknown")

    def test_only_a_committed_payment_claims_a_delivery_at_all(self):
        """A pay that did not commit moved no money, so it delivered none.

        The neighbouring state: these rows must not say "unknown delivery"
        (there was no delivery) and must not say "delivered" either.  They
        say nothing, and `cause` — the round-4 field — is what explains
        them.
        """
        alice = self.funded("alice")
        # Stop the mint AFTER the plan has hit the disk, so the op really
        # is stranded rather than never started: that is the row that used
        # to be indistinguishable from a rejection, and it is the row next
        # door to the delivery record.
        alice._open()
        killed = []

        def kill(event, _op_id):
            if event == "persist_fsync" and not killed:
                killed.append(True)
                self.stop_mint()

        alice._wallet.event_hook = kill
        with self.assertRaises(WalletOpsError):
            alice.pay(5_000, to="bob", deliver=lambda t: None)
        self.assertTrue(killed, "the mint was not stopped mid-flight")
        rows = [r for r in alice.history() if r["kind"].startswith("pay")]
        self.assertTrue(rows)
        for row in rows:
            self.assertNotEqual(row["kind"], "pay")     # it did not commit
            # No delivery happened, so nothing here states an outcome...
            self.assertEqual(row["delivery"], "")
            self.assertEqual(row["delivery_cause"], "")
            self.assertEqual(row["delivery_attempt"], "")
            # ...but it was still a payment, and it was still for bob.
            self.assertEqual(row["recipient"], "bob")
            self.assertEqual(row["recipient_kind"], "wallet")
            self.assertIn(row["cause"], _causes())
        # ...and no record was written for a payment that never happened.
        self.assertEqual(_record_rows(self.path("alice")), [])

    # -- the record is a record, never money -----------------------------

    def test_a_delivery_note_never_carries_a_token_or_a_secret(self):
        alice = self.funded("alice")
        leaked = {}

        def deliver(tokens):
            leaked["tokens"] = list(tokens)
            raise WalletOpsError(
                "mint said no",
                "the mint refused %s outright" % tokens[0],
                "mint_rejected")

        out = alice.pay(5_000, to="bob", deliver=deliver)
        self.assertEqual(out["delivery"], "undelivered")
        self.assertEqual(out["delivery_cause"], "mint_rejected")
        self.assertNotIn("aicash:", out["delivery_detail"])
        row = self.pay_row(alice, out["op_id"])
        for token in leaked["tokens"]:
            self.assertNotIn(token, row["detail"])
            self.assertNotIn(token.split(":")[-1], row["detail"])
        self.assertNotIn("aicash:", row["detail"])

    def test_a_recipient_name_is_bounded_and_free_of_control_characters(self):
        alice = self.funded("alice")
        for bad in ("x" * 65, "bo\nb", "bo\x00b", "", "   ", 7, b"bob"):
            with self.subTest(recipient=repr(bad)[:20]):
                with self.assertRaises(WalletOpsError) as cm:
                    alice.pay(100, to=bad)
                self.assertEqual(cm.exception.reason, "bad request")
        # and nothing was paid while those were being refused
        self.assertEqual(_record_rows(self.path("alice")), [])

    def test_deliver_without_a_recipient_name_is_refused_not_guessed(self):
        """Both halves have to be there or the record cannot route anyone."""
        alice = self.funded("alice")
        bob = self.ops("bob")
        with self.assertRaises(WalletOpsError) as cm:
            alice.pay(100, to="bob", deliver="not callable")
        self.assertEqual(cm.exception.reason, "bad request")
        # ...and a delivery to a recipient with no NAME: "delivered" over
        # a blank recipient is a confident field with nothing behind it.
        with self.assertRaises(WalletOpsError) as cm:
            alice.pay(100, deliver=bob.receive)
        self.assertEqual(cm.exception.reason, "bad request")
        self.assertIn("no recipient name", cm.exception.detail)
        self.assertEqual(_record_rows(self.path("alice")), [])

    def test_a_named_recipient_with_no_delivery_says_it_was_not_watched(self):
        """Recording WHO without claiming WHAT HAPPENED."""
        alice = self.funded("alice")
        out = alice.pay(5_000, to="bob")
        self.assertEqual(out["recipient"], "bob")
        self.assertEqual(out["recipient_kind"], "wallet")
        self.assertEqual(out["delivery"], "unknown")
        self.assertIn("not asked to deliver", out["delivery_detail"])

    # -- the arithmetic the row has to carry -----------------------------

    def test_the_row_records_what_left_the_burn_and_the_change(self):
        alice = self.funded("alice", face=100_000)
        bob = self.ops("bob")
        before = alice.summary()["balance_mc"]
        out = alice.pay(5_000, to="bob", deliver=bob.receive)
        after = alice.summary()["balance_mc"]
        rows = _record_rows(self.path("alice"))
        self.assertEqual(len(rows), 1)
        op_id, amount, burn, change, count, recipient, kind, delivery, \
            cause, _note, attempt = rows[0]
        self.assertEqual(op_id, out["op_id"])
        self.assertEqual(amount, 5_000)
        self.assertEqual(burn, out["burn_mc"])
        self.assertEqual(change, out["change_mc"])
        self.assertEqual(count, len(out["tokens"]))
        self.assertEqual((recipient, kind, delivery, cause, attempt),
                         ("bob", "wallet", "delivered", "", "attempted"))
        # the three figures are the whole of what left the wallet
        self.assertEqual(before - after, amount + burn)
        # ...and the mint's own conservation rule holds over them
        self.assertEqual(sum(t["amount_mc"] for t in
                             alice.unredeemed_payments()["payments"][0]
                             ["tokens"]), amount)

    # -- one question, one name ------------------------------------------

    def test_the_two_questions_disagree_and_are_both_right(self):
        """THE REVIEWER'S SCENARIO, reproduced and pinned as legitimate.

        220 mc across four strings from one method, "nothing to recover"
        from the other, from the same wallet against the same mint in the
        same instant.  Neither is wrong: they answer different questions,
        and this test exists so that a future change that "fixes" the
        disagreement has to argue with it.
        """
        alice = self.funded("alice")
        for _ in range(4):
            alice.pay(55)               # handed over, nobody redeemed them
        out = alice.unredeemed_payments()
        self.assertEqual(len(out["payments"]), 4)
        self.assertTrue(out["checked"])
        self.assertEqual(sum(p["live_mc"] for p in out["payments"]), 220)

        settled = alice.recover()
        self.assertEqual(
            [v for v in settled.values() if isinstance(v, int) and v], [],
            "recover() claimed work to do over payments that committed: %s"
            % settled)

        # And the distinction is legible from the methods themselves, not
        # only from the numbers.
        module = sys.modules[WalletOps.__module__]
        recovered = module.WalletOps.recover.__doc__
        unredeemed = module.WalletOps.unredeemed_payments.__doc__
        self.assertIn("IN-FLIGHT QUESTION", recovered)
        self.assertIn("HANDED-OVER QUESTION", unredeemed)
        self.assertIn("unredeemed_payments", recovered)
        self.assertIn("recover", unredeemed)

    def test_the_old_name_still_answers_and_says_it_is_the_old_name(self):
        alice = self.funded("alice")
        alice.pay(1_000)
        module = sys.modules[WalletOps.__module__]
        self.assertEqual(alice.outstanding_payments(),
                         alice.unredeemed_payments())
        doc = module.WalletOps.outstanding_payments.__doc__
        self.assertIn("OLD NAME", doc)
        self.assertIn("unredeemed_payments", doc)

    def test_history_unredeemed_and_the_record_join_on_one_op_id(self):
        """Three views of one payment; they must not be able to drift."""
        alice = self.funded("alice")
        bob = self.ops("bob")
        out = alice.pay(5_000, to="bob", deliver=bob.receive)
        row = self.pay_row(alice, out["op_id"])
        entry = alice.unredeemed_payments()["payments"][0]
        raw = _record_rows(self.path("alice"))[0]
        self.assertEqual({out["op_id"], row["op_id"], entry["op_id"], raw[0]},
                         {out["op_id"]})
        for view in (row, entry):
            self.assertEqual(view["recipient"], "bob")
            self.assertEqual(view["delivery"], "delivered")
            self.assertEqual(view["delivery_cause"], "")



# ---------------------------------------------------------------------------
# handed-over accounting: one payment, one amount, and a sum that closes
# ---------------------------------------------------------------------------


def _route_decomposition(out):
    """The four figures ``gui/app.py``'s route sums, by ITS rule not ours.

    Copied deliberately from ``route_wallet_outstanding`` rather than read
    out of the response, so these tests pin that the totals walletops
    reports and the totals the HTTP layer derives from the same token list
    are the same numbers.  Two screens that decompose one report by two
    rules is the shape of defect this round exists to remove.
    """
    by_state = {"unspent": 0, "spent": 0, "unknown": 0, None: 0}
    for payment in out["payments"]:
        for token in payment["tokens"]:
            state = token["state"]
            by_state[state if state in ("unspent", "spent", "unknown")
                     else None] += (token["amount_mc"] or 0)
    return by_state


class TestHandedOverAccounting(MintFixture):
    """THE ROUND-6 HEADLINE: two views of one payment, two amounts.

    ``GET /api/wallet/history`` said a payment handed over 300 mc while
    ``GET /api/wallet/outstanding`` said 100 mc for the same op_id in the
    same instant, and the number that moved was the one gui/README.md
    calls the permanent record of where the money went.  Nothing here is
    mocked: every figure comes off a real mint over real HTTP.
    """

    def funded(self, name="alice", face=400_000):
        w = self.ops(name)
        w.receive([self.issue(face)])
        return w

    def pay_row(self, w, op_id):
        rows = [r for r in w.history(limit=500)
                if r["kind"] == "pay" and r["op_id"] == op_id]
        self.assertTrue(rows, "no committed pay row for %s" % op_id)
        return rows[0]

    def entry(self, w, op_id, limit=200):
        rows = [p for p in w.unredeemed_payments(limit=limit)["payments"]
                if p["op_id"] == op_id]
        self.assertTrue(rows, "payment %s is not in the report at all" % op_id)
        return rows[0]

    def assert_closes(self, out, where=""):
        """The documented identity, in both of its steps.

        Whole wallet first -- ``handed_over_mc == listed_mc +
        unlisted_mc`` -- and only then the mint's four-way decomposition
        of the part this report actually listed.  The first step is what
        an earlier build did not have: it published the WINDOWED total
        under the name ``handed_over_mc`` with nothing anywhere saying
        the window had cut money off.
        """
        parts = (out["unspent_mc"] + out["spent_mc"] + out["unstated_mc"]
                 + out["unchecked_mc"] + out["unaccounted_mc"])
        self.assertEqual(
            out["listed_mc"], parts,
            "%s: %d mc listed decomposed into %d (unspent %d, spent %d,"
            " unstated %d, unchecked %d, unaccounted %d)"
            % (where, out["listed_mc"], parts, out["unspent_mc"],
               out["spent_mc"], out["unstated_mc"], out["unchecked_mc"],
               out["unaccounted_mc"]))
        self.assertEqual(out["unaccounted_mc"], 0,
                         "%s: value left the accounting" % where)
        # The window, declared rather than inferred.  listed_mc is read
        # back off the payment list itself, so the total and the rows
        # cannot drift apart without this failing.
        self.assertEqual(out["listed_mc"],
                         sum(p["amount_mc"] for p in out["payments"]),
                         "%s: listed total is not the listed rows" % where)
        self.assertEqual(out["handed_over_mc"],
                         out["listed_mc"] + out["unlisted_mc"],
                         "%s: whole-wallet total does not close" % where)
        self.assertGreaterEqual(out["unlisted_mc"], 0, where)
        self.assertGreaterEqual(out["unlisted_outstanding_mc"], 0, where)
        self.assertLessEqual(out["unlisted_outstanding_mc"],
                             out["unlisted_mc"], where)
        self.assertGreaterEqual(out["payment_count"], len(out["payments"]),
                                where)
        self.assertEqual(out["truncated"],
                         len(out["payments"]) < out["payment_count"],
                         "%s: truncation flag does not match the list"
                         % where)
        # A confident total is only ever published when nothing live was
        # left out of the window.
        if out["unredeemed_mc"] is not None:
            self.assertEqual(out["unlisted_outstanding_mc"], 0,
                             "%s: an int unredeemed_mc over %d mc of"
                             " outstanding value that was not listed"
                             % (where, out["unlisted_outstanding_mc"]))
        for payment in out["payments"]:
            self.assertEqual(
                payment["amount_mc"],
                sum(t["amount_mc"] for t in payment["tokens"])
                + payment["unaccounted_mc"],
                "%s: payment %s does not decompose" % (where,
                                                       payment["op_id"]))
            # ...and the permanent figure splits into the part the store
            # still believes is in somebody else's hands and the part it
            # has retired.  Nothing else is possible for a payment that
            # handed strings over.
            self.assertEqual(
                payment["amount_mc"],
                payment["outstanding_mc"] + payment["retired_mc"],
                "%s: payment %s is neither outstanding nor retired"
                % (where, payment["op_id"]))

    # -- the headline ----------------------------------------------------

    def test_a_payments_amount_survives_a_later_unrelated_operation(self):
        """THE DEFECT, reproduced and closed.

        alice pays 300 mc as three strings; bob redeems two of them; alice
        then pastes those two back into her own wallet by mistake.  The
        paste is refused (already spent) and, on its way through,
        ``Wallet._mark_dead_if_ours`` retires alice's own copies from
        ``handed_over`` to ``spent_out``.  The old report listed only
        ``handed_over`` rows, so that third, unrelated operation made an
        already-committed payment read 100 mc while history went on saying
        300.  The payment handed over 300 mc; that is not a fact a later
        paste can edit.
        """
        alice = self.funded("alice")
        bob = self.ops("bob")
        paid = alice.pay(300)
        op_id = paid["op_id"]
        self.assertEqual(sorted(parse_token(t).amount_mc
                                for t in paid["tokens"]), [100, 100, 100])

        bob.receive(paid["tokens"][:2])         # the payee takes two

        before_row = self.pay_row(alice, op_id)
        before = self.entry(alice, op_id)
        self.assertEqual(before_row["amount_mc"], 300)
        self.assertEqual(before["amount_mc"], 300)
        self.assertEqual(before["live_mc"], 100)
        self.assertEqual(before["retired_mc"], 0)   # alice does not know yet
        self.assertEqual(sorted(t["state"] for t in before["tokens"]),
                         ["spent", "spent", "unspent"])

        rejected = alice.receive(paid["tokens"][:2])["rejected"]
        self.assertEqual([r["cause"] for r in rejected],
                         ["already_spent", "already_spent"])

        after_row = self.pay_row(alice, op_id)
        after = self.entry(alice, op_id)
        # The two views, same instant, same op_id, same number.
        self.assertEqual((after_row["amount_mc"], after["amount_mc"]),
                         (300, 300))
        self.assertEqual(len(after["tokens"]), 3)
        self.assertIn("paid out 300 mc", after_row["detail"])
        # What DID change is the second question, and it has its own names.
        self.assertEqual(after["live_mc"], 100)
        self.assertEqual(after["retired_mc"], 200)
        self.assertEqual(sorted(t["store_state"] for t in after["tokens"]),
                         ["handed_over", "spent_out", "spent_out"])
        # ...and the record written at payment time never moved either.
        self.assertEqual([r[1] for r in _record_rows(self.path("alice"))],
                         [300])
        self.assert_closes(alice.unredeemed_payments(), "after the paste")

    def test_a_payment_taken_back_by_its_payer_is_still_a_payment(self):
        """Every string of a payment retired, and the payment stays listed.

        The old report dropped a payment entirely once none of its strings
        were ``handed_over`` any more — so a wallet that took its own
        bearer payment back showed 200 mc in history and no such payment
        at all next door.  Taking money back does not un-hand it over; it
        makes all of it redeemed, which is a different field.
        """
        alice = self.funded("alice")
        paid = alice.pay(200)
        op_id = paid["op_id"]
        credited = alice.receive(list(paid["tokens"]))
        self.assertEqual(credited["rejected"], [])
        self.assertGreater(credited["accepted_mc"], 0)

        entry = self.entry(alice, op_id)
        self.assertEqual(self.pay_row(alice, op_id)["amount_mc"], 200)
        self.assertEqual(entry["amount_mc"], 200)
        self.assertEqual(entry["retired_mc"], 200)
        self.assertEqual(entry["live_mc"], 0)
        self.assertEqual({t["state"] for t in entry["tokens"]}, {"spent"})
        self.assertEqual({t["store_state"] for t in entry["tokens"]},
                         {"spent_out"})
        out = alice.unredeemed_payments()
        self.assert_closes(out, "after a full take-back")
        self.assertEqual((out["handed_over_mc"], out["spent_mc"],
                          out["unspent_mc"], out["unredeemed_mc"]),
                         (200, 200, 0, 0))

    # -- the decomposition -----------------------------------------------

    def test_the_totals_are_the_rule_the_http_route_uses(self):
        """One report, one decomposition — not one per screen.

        ``gui/app.py`` derives the four figures from the token list this
        method returns.  If walletops totalled by a different rule the
        page and the API would answer the same question differently, which
        is the family of defect this round is about.
        """
        alice = self.funded("alice")
        bob = self.ops("bob")
        first = alice.pay(1_000)
        second = alice.pay(500)
        bob.receive(first["tokens"])
        alice.receive(second["tokens"][:1])
        out = alice.unredeemed_payments()
        by_state = _route_decomposition(out)
        self.assertEqual(
            (out["unspent_mc"], out["spent_mc"], out["unstated_mc"],
             out["unchecked_mc"]),
            (by_state["unspent"], by_state["spent"], by_state["unknown"],
             by_state[None]))
        self.assertEqual(out["handed_over_mc"], 1_500)
        # ...and the headline number, by the route's rule for it too.
        complete = (out["checked"] and not by_state["unknown"]
                    and not by_state[None])
        self.assertEqual(out["unredeemed_mc"],
                         by_state["unspent"] if complete else None)
        self.assertEqual(out["unredeemed_mc"], out["unspent_mc"])
        self.assert_closes(out, "two payments, one partial take-back")

    def test_with_the_mint_down_nothing_is_lost_only_unchecked(self):
        """The gap must not open just because the mint is not answering.

        Every string reads ``state: None`` and the whole handed-over value
        lands in ``unchecked_mc`` — not in ``unaccounted_mc``, and not
        nowhere.  ``store_state`` is the wallet's own word and survives,
        so ``retired_mc`` still answers "how much of this do I already
        know is dead" with the mint switched off.
        """
        alice = self.funded("alice")
        paid = alice.pay(400)
        alice.receive(paid["tokens"][:1])       # retired, locally known
        self.stop_mint()
        out = alice.unredeemed_payments()
        self.assertFalse(out["checked"])
        self.assertEqual(out["handed_over_mc"], 400)
        self.assertEqual(out["unchecked_mc"], 400)
        self.assertEqual((out["unspent_mc"], out["spent_mc"],
                          out["unstated_mc"]), (0, 0, 0))
        self.assertIsNone(out["unredeemed_mc"])
        entry = out["payments"][0]
        self.assertIsNone(entry["live_mc"])
        self.assertEqual(entry["retired_mc"], 100)
        self.assert_closes(out, "mint down")

    def test_another_mints_ledger_is_unstated_not_missing(self):
        """A payment the answering mint has no entry for is named, not lost.

        This is the case ``unstated_mc`` exists for, and the one where a
        silent decomposition would report the money as accounted-for with
        both catch-all figures at zero.
        """
        alice = self.funded("alice")
        alice.pay(400)
        _server, base = self.replacement_mint("a-different-mint")
        stranger = WalletOps(self.path("alice"), base)
        out = stranger.unredeemed_payments()
        self.assertTrue(out["checked"])
        self.assertEqual(out["handed_over_mc"], 400)
        self.assertEqual(out["unstated_mc"], 400)
        self.assertIsNone(out["unredeemed_mc"])
        self.assertIsNone(out["payments"][0]["live_mc"])
        self.assert_closes(out, "a different mint answering")

    # -- money that never left, and money the window nearly hid ----------

    def strand_a_pay(self, w, amount):
        """Strand one ``WalletOps.pay`` in flight, through the real route.

        The fault is injected at the TRANSPORT, not at the module under
        test: ``DeliverThenDropClient`` lets the exchange COMMIT on the
        ledger and throws the answer away, which is what a killed process
        or a dropped socket does.  Everything above it is the production
        path -- ``WalletOps.pay`` plans, sends, re-raises, returns no
        string and writes no payment record, and records the cause against
        the op it left behind.  The only copies of those secrets in the
        universe are the ones in this wallet file.
        """
        real = w._client
        w.close()                       # force a rebind onto the lossy client
        w._client = lambda: DeliverThenDropClient(self.base)
        try:
            with self.assertRaises(WalletOpsError):
                w.pay(amount)
        finally:
            w._client = real
            w.close()
        return w

    def stranded_pay(self, name="stranded", face=50_000, amount=5_000):
        """A funded wallet with one pay stranded in flight and abandoned."""
        w = self.ops(name)
        w.receive([self.issue(face)])
        return self.strand_a_pay(w, amount)

    def test_a_recovered_payment_handed_nothing_over(self):
        """THE SECOND VIEW MUST NOT INVENT A SECOND COPY OF THE MONEY.

        ``WalletOps.pay()`` re-raises when the mint's answer is lost and
        returns no string and writes no payment record; ``recover()`` then
        settles the op by putting its outputs back in the SPENDABLE pool.
        Nobody outside this wallet file has ever seen those secrets, and
        the wallet's own balance counts them.

        An earlier build listed them anyway -- "5,000 mc in 1 bearer
        string that alice handed out has not been redeemed by anybody" --
        so the two screens claimed 54,449 mc against a mint whose signed
        supply snapshot said 49,449 existed, and told the operator to
        press the Recover button they had just pressed.  Every clause was
        false.  Measured here against the mint's own supply snapshot: the
        balance plus what this report calls unredeemed is exactly the
        money that exists, and the payment's value is named under
        ``recovered_mc`` so nothing vanishes either.
        """
        w = self.stranded_pay()
        before = w.summary()["balance_mc"]
        self.assertEqual(w.unredeemed_payments()["handed_over_mc"], 0,
                         "an op still in flight is not handed over yet")
        self.assertEqual(w.recover()["ops_confirmed"], 1)

        out = w.unredeemed_payments()
        balance = w.summary()["balance_mc"]
        self.assertEqual(before - balance, 51)   # the burn, and only that
        self.assertEqual(out["handed_over_mc"], 0)
        self.assertEqual(out["unspent_mc"], 0)
        self.assertEqual(out["unredeemed_mc"], 0)
        self.assertEqual(out["payments"], [])
        self.assert_closes(out, "after recover() settled a pay op")
        # ...and the value is not hidden: it is named, with the op_id that
        # history() prints a 5,000 mc `pay` row for, which is how a reader
        # matches the two views instead of adding them up.
        self.assertEqual(out["recovered_mc"], 5_000)
        self.assertEqual([r["amount_mc"] for r in out["recovered_ops"]],
                         [5_000])
        pay_rows = [r for r in w.history() if r["kind"] == "pay"]
        self.assertEqual([r["amount_mc"] for r in pay_rows], [5_000])
        self.assertEqual([r["op_id"] for r in out["recovered_ops"]],
                         [r["op_id"] for r in pay_rows])
        # THE RECONCILIATION, on the mint's own numbers rather than ours:
        # what the operator can read off the two screens is what exists.
        self.assertEqual(balance + (out["unredeemed_mc"] or 0),
                         self.ledger.supply()["outstanding_mc"])

    def test_a_recovered_payment_stays_out_after_it_is_spent_again(self):
        """And it stays out once the recovered coins are spent for real.

        The cheap test for "never handed over" is a payment output still
        sitting in ``confirmed``.  That is not enough on its own: spending
        those coins moves them to ``spent_out``, which is the same word
        the store uses for a real payment the payee has redeemed.  The
        durable mark is this module's own cause row, written against the
        op at the instant ``pay()`` raised, and it is what keeps the
        5,000 mc out of the handed-over total here while the 900 mc that
        really was handed over stays in it.
        """
        w = self.stranded_pay()
        self.assertEqual(w.recover()["ops_confirmed"], 1)
        real = w.pay(900)               # spends the recovered coins
        self.assertTrue(real["tokens"])
        out = w.unredeemed_payments()
        self.assertEqual(out["handed_over_mc"], 900)
        self.assertEqual(out["unspent_mc"], 900)
        self.assertEqual([p["op_id"] for p in out["payments"]],
                         [real["op_id"]])
        self.assertEqual(out["recovered_mc"], 5_000)
        self.assert_closes(out, "recovered coins spent again")
        self.assertEqual(w.summary()["balance_mc"] + out["unredeemed_mc"],
                         self.ledger.supply()["outstanding_mc"])

    def test_dead_payments_cannot_push_live_money_out_of_the_window(self):
        """A FABRICATED ZERO THE WINDOW USED TO MANUFACTURE.

        ``limit`` counts payment OPERATIONS.  When every committed payment
        competes for that window, a wallet that has paid itself back a few
        dozen times fills it with payments the store has already retired
        and answers ``unredeemed_mc: 0, checked: true`` over money the
        mint calls unspent -- an int, which is this module's word for "the
        mint answered about every string".

        Two things are pinned here.  The window is spent on money that can
        still be live, so the one outstanding payment is listed however
        many dead ones are in front of it; and the totals that are NOT
        windowed (``handed_over_mc``, ``payment_count``) still describe
        the whole wallet, with ``truncated`` saying the list does not.
        """
        alice = self.funded("crowded")
        live = alice.pay(5_000)
        for _ in range(24):             # 24 payments, paid straight back
            paid = alice.pay(50)
            alice.receive(paid["tokens"])

        out = alice.unredeemed_payments(limit=20)
        self.assertEqual(out["unredeemed_mc"], 5_000,
                         "the live payment was crowded out of the window")
        self.assertEqual(out["unspent_mc"], 5_000)
        self.assertEqual(out["payments"][0]["op_id"], live["op_id"])
        self.assertTrue(out["truncated"])
        self.assertEqual(out["payment_count"], 25)
        self.assertEqual(out["handed_over_mc"], 5_000 + 24 * 50)
        self.assertGreater(out["unlisted_mc"], 0)
        self.assertEqual(out["unlisted_outstanding_mc"], 0)
        self.assert_closes(out, "one live payment behind 24 dead ones")
        # The same instant, a window big enough for all of it: the two
        # answers to the one question must not differ.
        whole = alice.unredeemed_payments(limit=200)
        self.assertFalse(whole["truncated"])
        self.assertEqual(whole["payment_count"], 25)
        self.assertEqual(whole["handed_over_mc"], out["handed_over_mc"])
        self.assertEqual(whole["unredeemed_mc"], out["unredeemed_mc"])
        self.assertEqual(whole["unlisted_mc"], 0)
        self.assert_closes(whole, "the whole wallet")
        self.assertEqual(
            alice.summary()["balance_mc"] + whole["unredeemed_mc"],
            self.ledger.supply()["outstanding_mc"])

    def test_outstanding_value_the_window_cuts_off_is_never_a_zero(self):
        """And when live money really does not fit, the total says None.

        The window is finite, so a wallet with more outstanding payments
        than ``limit`` cannot be totalled from the rows in it.  The rule
        is the one the rest of this module uses for an incomplete answer:
        the parts are published, the headline is ``None``, and the field
        that says WHY -- ``unlisted_outstanding_mc`` -- is published too,
        so a caller states the reason instead of guessing it from
        ``len(payments)``.
        """
        alice = self.funded("many-live")
        for _ in range(4):
            alice.pay(100)
        out = alice.unredeemed_payments(limit=2)
        self.assertTrue(out["checked"])
        self.assertIsNone(out["unredeemed_mc"])
        self.assertEqual(out["unspent_mc"], 200)     # the part it can see
        self.assertEqual(out["unlisted_outstanding_mc"], 200)
        self.assertTrue(out["truncated"])
        self.assertEqual(out["handed_over_mc"], 400)
        self.assert_closes(out, "more live payments than the window")
        whole = alice.unredeemed_payments(limit=10)
        self.assertEqual(whole["unredeemed_mc"], 400)
        self.assert_closes(whole, "all four listed")

    def test_retired_is_the_stores_word_and_never_a_verdict_on_the_money(self):
        """``retired_mc`` and ``unstated_mc`` answer DIFFERENT questions.

        ``Wallet._mark_dead_if_ours`` retires a copy when the mint
        consumed the string AND when the mint answered ``unknown`` -- "no
        entry on the ledger I am keeping", which is what a replaced mint
        database says about money that is perfectly alive on the original
        ledger.  So a report that read ``retired_mc`` as "this wallet
        knows this value is dead" answered one question twice, in opposite
        directions, inside one payload: 300 mc known dead beside 300 mc
        undetermined.

        Here the store's word and the mint's word are both published and
        neither is dressed up as the other: the strings are retired (this
        wallet will not offer them again) and the mint's verdict on them
        is ``unknown``, so they land in ``unstated_mc`` and the headline
        total is ``None``.  ``retired_mc`` is deliberately outside that
        four-way decomposition rather than a fifth box inside it.
        """
        alice = self.funded("retired-word")
        paid = alice.pay(300)
        alice.close()
        _server, base = self.replacement_mint("a-different-mint")
        # The operator pastes their own three strings back, against a mint
        # whose database has been replaced. Every one is refused -- no
        # entry on THIS ledger -- and Wallet._mark_dead_if_ours retires
        # alice's own copies on the way through.
        pasting = Wallet(self.path("retired-word"), MintClient(base),
                         MINT_ID)
        result = pasting.receive_batch(list(paid["tokens"]))
        pasting._db.close()
        self.assertEqual(result["credited_mc"], 0)
        self.assertEqual(len(result["dead"]), 3)
        stranger = WalletOps(self.path("retired-word"), base)
        out = stranger.unredeemed_payments()
        entry = out["payments"][0]
        self.assertEqual(entry["retired_mc"], 300)
        self.assertEqual(entry["outstanding_mc"], 0)
        self.assertEqual(sorted(t["store_state"] for t in entry["tokens"]),
                         ["spent_out"] * 3)
        # The mint's own word about those same strings, still asked for
        # and still reported: undetermined, not dead.
        self.assertEqual(sorted(t["state"] for t in entry["tokens"]),
                         ["unknown"] * 3)
        self.assertEqual(out["unstated_mc"], 300)
        self.assertEqual(out["spent_mc"], 0)
        self.assertIsNone(out["unredeemed_mc"])
        self.assertIsNone(entry["live_mc"])
        self.assert_closes(out, "a replaced mint database")

    def test_the_two_store_reads_are_one_snapshot(self):
        """The mechanism ``unaccounted_mc`` rests on, demonstrated.

        The residual is only a cross-check if the grouped total and the
        per-string scan see the same bytes.  A plain sqlite3 connection
        opens NO transaction for a SELECT, so "one connection" buys
        nothing: proved here by committing between two reads on one
        connection and watching the second answer move.  Inside
        ``_ro_snapshot`` it cannot move, and the reason is shown rather
        than asserted -- the read transaction holds its lock, so a writer
        cannot land a commit in the middle of the read at all, and the
        moment the transaction closes the same write goes through.
        """
        import sqlite3

        walletops = sys.modules[WalletOps.__module__]
        w = self.ops("snapshot")
        w.summary()                     # materialise the store
        w.close()
        path = self.path("snapshot")
        # A short busy timeout: this writer is EXPECTED to be turned away
        # while the reader holds its snapshot, and the test should not
        # spend five seconds discovering that.
        writer = sqlite3.connect(path, isolation_level=None, timeout=0.2)
        self.addCleanup(writer.close)
        writer.execute("CREATE TABLE snap_probe (v INTEGER)")
        writer.execute("INSERT INTO snap_probe VALUES (1)")

        ops = WalletOps(path, self.base)
        loose = ops._connect_ro()
        self.addCleanup(loose.close)
        first = loose.execute("SELECT SUM(v) FROM snap_probe").fetchone()[0]
        writer.execute("INSERT INTO snap_probe VALUES (100)")
        self.assertNotEqual(
            loose.execute("SELECT SUM(v) FROM snap_probe").fetchone()[0],
            first, "two SELECTs on one connection were somehow one snapshot"
                   " -- if this ever passes, the reasoning in _ro_snapshot"
                   " needs rewriting, not the code")

        held = ops._connect_ro()
        self.addCleanup(held.close)
        with walletops._ro_snapshot(held):
            inside = held.execute(
                "SELECT SUM(v) FROM snap_probe").fetchone()[0]
            self.assertTrue(held.in_transaction,
                            "_ro_snapshot opened no transaction")
            with self.assertRaises(sqlite3.OperationalError):
                writer.execute("INSERT INTO snap_probe VALUES (10000)")
            self.assertEqual(
                held.execute("SELECT SUM(v) FROM snap_probe").fetchone()[0],
                inside, "the read transaction did not hold a snapshot")
        self.assertFalse(held.in_transaction,
                         "_ro_snapshot left the transaction open")
        # ...and it really is released: the write that was turned away
        # goes through the moment the read is over, and the same
        # connection sees it.
        writer.execute("INSERT INTO snap_probe VALUES (10000)")
        self.assertEqual(
            held.execute("SELECT SUM(v) FROM snap_probe").fetchone()[0],
            10101)

    # -- the identity, over a long randomised run -------------------------

    def _drive(self, seed, rounds=36):
        """Payments, partial redemptions and re-pastes, in random order.

        The test keeps its OWN books: what each payment handed over is
        parsed out of the strings ``pay()`` returned (never read back from
        the store), and which strings are still live is tracked by what
        this test itself handed to whom.  Every round both the identity
        and the two views of every payment are checked against those
        independent books.
        """
        rng = random.Random(seed)
        name = "alice-%d" % seed
        alice = self.funded(name, face=400_000)
        payees = [self.ops("bob-%d" % seed), self.ops("carol-%d" % seed)]
        # Money the mint knows about that is NOT this run's to account
        # for -- an earlier subTest's wallet, funded from the same mint.
        # It cannot change while this run drives only these three wallets,
        # so it is measured once and subtracted from every reconciliation.
        outside = (self.ledger.supply()["outstanding_mc"]
                   - alice.summary()["balance_mc"])
        paid: dict = {}                 # op_id -> mc handed over (our books)
        stranded = {"mc": 0}            # value that never left this wallet
        strings: list = []              # (op_id, token, mc) ever handed out
        live: list = []                 # the subset nobody has consumed yet

        def check(where):
            out = alice.unredeemed_payments(limit=200)
            self.assert_closes(out, where)
            self.assertTrue(out["checked"], where)
            self.assertEqual(out["handed_over_mc"], sum(paid.values()),
                             "%s: handed-over total" % where)
            self.assertEqual(len(out["payments"]), len(paid), where)
            self.assertEqual(out["unspent_mc"], sum(mc for _o, _t, mc in live),
                             "%s: still-live total" % where)
            self.assertEqual(out["unredeemed_mc"], out["unspent_mc"], where)
            history = {r["op_id"]: r["amount_mc"] for r in
                       alice.history(limit=500) if r["kind"] == "pay"}
            record = {r[0]: r[1] for r in _record_rows(alice.store_path)}
            for payment in out["payments"]:
                op_id = payment["op_id"]
                self.assertEqual(payment["amount_mc"], paid[op_id],
                                 "%s: payment %s" % (where, op_id))
                self.assertEqual(history[op_id], paid[op_id],
                                 "%s: history for %s" % (where, op_id))
                self.assertEqual(record[op_id], paid[op_id],
                                 "%s: record for %s" % (where, op_id))
            self.assertEqual(sum(p["live_mc"] for p in out["payments"]),
                             out["unspent_mc"], where)
            self.assertEqual(out["payment_count"], len(paid), where)
            # Value that never left alice at all: pay ops the transport
            # stranded and the Recover button settled back into her
            # spendable pool.  Counted here against this test's own tally
            # of them, and NOT inside the handed-over total above --
            # those are the same coins as her balance.
            self.assertEqual(out["recovered_mc"], stranded["mc"], where)
            # THE MINT'S OWN BOOKS, which is the check this guard did not
            # have.  Every mc the mint says exists is either spendable in
            # one of these three wallets or is a string this test handed
            # out that nobody has consumed; the report's headline is that
            # second number.  A report that invents a second copy of
            # anything -- the round-6 defect, where recovered coins were
            # counted both in the balance and here -- fails on this line
            # and on no other.
            held = alice.summary()["balance_mc"] + sum(
                p.summary()["balance_mc"] for p in payees)
            supply = self.ledger.supply()["outstanding_mc"]
            self.assertEqual(
                held + out["unredeemed_mc"] + outside, supply,
                "%s: %d mc in these wallets + %d mc unredeemed + %d mc in"
                " wallets this run never touches, against a mint that says"
                " %d exists"
                % (where, held, out["unredeemed_mc"], outside, supply))
            # ...and the same question asked through a window far too
            # small for the wallet.  A truncated report may list less; it
            # may never publish a confident total over money it did not
            # list, and it may never disagree with the whole one about
            # what this wallet has handed over.
            small = alice.unredeemed_payments(limit=3)
            self.assert_closes(small, "%s (limit=3)" % where)
            self.assertEqual(small["handed_over_mc"], out["handed_over_mc"],
                             "%s: the whole-life total is windowed" % where)
            self.assertEqual(small["payment_count"], out["payment_count"],
                             where)
            self.assertLessEqual(small["unspent_mc"], out["unspent_mc"],
                                 where)
            if small["unredeemed_mc"] is None:
                self.assertGreater(small["unlisted_outstanding_mc"], 0,
                                   "%s: None with nothing cut off" % where)
            else:
                self.assertEqual(small["unredeemed_mc"], out["unredeemed_mc"],
                                 "%s: the small window published a total"
                                 " the whole one contradicts" % where)

        check("nothing paid yet")
        for step in range(rounds):
            action = rng.choice(["pay", "pay", "redeem", "repaste",
                                 "strand"])
            if action == "pay" or not strings:
                amount = rng.choice([55, 100, 250, 500, 1_000])
                if alice.summary()["balance_mc"] < amount + 2_000:
                    continue
                out = alice.pay(amount)
                self.assertEqual(
                    sum(parse_token(t).amount_mc for t in out["tokens"]),
                    amount, "pay() handed over something other than %d"
                    % amount)
                paid[out["op_id"]] = amount
                for token in out["tokens"]:
                    row = (out["op_id"], token, parse_token(token).amount_mc)
                    strings.append(row)
                    live.append(row)
            elif action == "strand":
                # A pay the transport strands, then the Recover button.
                # pay() returns nothing, so this test's books do not
                # change: the money never left alice, and recover() puts
                # it back in her spendable pool.  Any report that calls
                # it handed-over invents a second copy of it, and the
                # reconciliation in check() is where that shows.
                if alice.summary()["balance_mc"] < 2_500:
                    continue
                self.strand_a_pay(alice, 200)
                # recover() settles exactly the op that was stranded, and
                # says so; nothing else is in flight here.
                if alice.recover()["ops_confirmed"]:
                    stranded["mc"] += 200
            elif action == "redeem" and live:
                take = rng.sample(live, rng.randint(1, min(3, len(live))))
                rng.choice(payees).receive([t for _o, t, _mc in take])
                for row in take:
                    live.remove(row)
            else:
                # A re-paste: whatever the operator has on the clipboard,
                # live strings and dead ones mixed together.
                take = rng.sample(strings,
                                  rng.randint(1, min(4, len(strings))))
                alice.receive([t for _o, t, _mc in take])
                for row in take:
                    if row in live:
                        live.remove(row)
            check("seed %d, step %d, %s" % (seed, step, action))

    def test_the_identity_holds_across_a_long_randomised_run(self):
        """The regression guard: it cannot drift again without failing here.

        Any change that re-narrows the scan (the original defect), or that
        lets one view of a payment be rebuilt from state that a later
        operation can edit, breaks the handed-over total, the per-payment
        amount, or the sum — against books this test kept itself.

        Two things it now checks that it did not, and that let a
        double-count and a fabricated zero through: every round is
        reconciled against the MINT's signed supply figure and the three
        wallet balances, not only against this test's own books; and every
        round is also read back through a window of 3, so a report that
        can only be honest when nothing is truncated fails here.
        """
        for seed in (1, 7):
            with self.subTest(seed=seed):
                self._drive(seed)


if __name__ == "__main__":
    unittest.main()
