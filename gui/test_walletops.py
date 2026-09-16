"""Tests for gui/walletops.py against a REAL in-process mint over real HTTP.

Nothing here is mocked at the money layer: every test boots a MintServer on
a loopback port, funds a treasury through the operator path (§7.1), and
asserts against balances the mint itself settled.

Run:  cd <repo root> && python3 -m unittest gui.test_walletops -v
"""

import os
import shutil
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
from aicash.tokencodec import format_token, ledger_key, new_secret  # noqa: E402
from aicash.wallet import MintClient, Wallet                 # noqa: E402

try:                                    # run as `python3 -m unittest gui.test_walletops`
    from gui.walletops import WalletOps, WalletOpsError
except ImportError:                     # run from inside gui/
    from walletops import WalletOps, WalletOpsError          # noqa: F401

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
        exists — the module writes exactly one file, the store — so the
        deletion line was removed.  The assertion is unchanged and is now
        the only path, not the fallback path.)
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

        (Was four.  ``cause`` was added deliberately — a history row that
        cannot say why an operation failed is the defect this round closes,
        and the field is part of the pinned shape, not an extra.)
        """
        w = self.ops()
        w.receive([self.issue(10_000)])
        w.pay(100)
        for e in w.history():
            self.assertEqual(set(e),
                             {"ts_ms", "kind", "amount_mc", "detail", "cause"})
            self.assertIsInstance(e["ts_ms"], int)
            self.assertIsInstance(e["kind"], str)
            self.assertIsInstance(e["amount_mc"], int)
            self.assertIsInstance(e["detail"], str)
            self.assertIsInstance(e["cause"], str)
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

    def test_exactly_one_file_per_wallet_is_written(self):
        """The pinned layout is var/wallets/<name>.db — nothing beside it."""
        w = self.ops("solo")
        w.receive([self.issue(10_000)])
        w.summary()
        w.summary()
        w.history()
        w.pay(100)
        w.close()
        made = {e for e in os.listdir(self.dir) if e.startswith("solo")}
        self.assertEqual(made, {"solo.db"})
        self.assertFalse(os.path.exists(self.path("solo") + ".mint"))


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
        # One ops query plus one grouped outputs query. A per-row query is
        # an N+1 and also means each row is read under its own snapshot.
        self.assertLessEqual(
            len(queries), 3,
            f"history ran {len(queries)} queries for {len(rows)} rows:"
            f" {queries}",
        )


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
                         {"checked": True, "mint_id": "", "payments": []})
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
        """The component contract is four keys, `key` included.

        The module docstring calls these "the exact shapes a caller may
        rely on", so the key SET is pinned here rather than left to a
        reader to discover; gui/app.py drops `key` on the wire and that is
        stated in the same paragraph.
        """
        w = self.funded("shape-out")
        w.pay(1_000)
        out = w.outstanding_payments()
        self.assertEqual(set(out), {"checked", "mint_id", "payments"})
        for payment in out["payments"]:
            self.assertEqual(set(payment),
                             {"op_id", "amount_mc", "live_mc", "tokens"})
            for token in payment["tokens"]:
                self.assertEqual(set(token),
                                 {"token", "amount_mc", "key", "state"})

    def test_no_second_copy_of_the_money_is_written_anywhere(self):
        """The decision: read the store back, never write a sidecar.

        A file of bearer strings beside the wallet would be a second
        complete copy of live money on disk — and the pinned layout is one
        file per wallet.
        """
        w = self.funded("solo-out")
        w.pay(1_000)
        w.outstanding_payments()
        w.close()
        made = {e for e in os.listdir(self.dir) if e.startswith("solo-out")}
        self.assertEqual(made, {"solo-out.db"})

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


if __name__ == "__main__":
    unittest.main()
