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
        w = self.ops()
        w.receive([self.issue(10_000)])
        w.pay(100)
        for e in w.history():
            self.assertEqual(set(e), {"ts_ms", "kind", "amount_mc", "detail"})
            self.assertIsInstance(e["ts_ms"], int)
            self.assertIsInstance(e["kind"], str)
            self.assertIsInstance(e["amount_mc"], int)
            self.assertIsInstance(e["detail"], str)

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


if __name__ == "__main__":
    unittest.main()
