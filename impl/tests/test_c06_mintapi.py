"""C06 — mintapi tests: the HTTP surface of a mint.

Every test drives a real MintServer over real HTTP (127.0.0.1, stdlib
http.client). Benchmark items B1–B8 from components/C06-mintapi.md are
named in each test's docstring. All time comes from a FakeClock injected
through the Ledger (L17).
"""

import contextlib
import copy
import dataclasses
import email.parser
import hashlib
import http.client
import inspect
import io
import json
import os
import pickle
import re
import socket
import sqlite3
import tempfile
import threading
import time
import unittest
from typing import NamedTuple

from aicash import mintapi
from aicash.burncalc import BurnPolicy
from aicash.envelope import ERROR_KINDS, ERROR_REASONS
from aicash.clock import FakeClock
from aicash.ledgerstore import Ledger, OutputSpec
from aicash.mintapi import (
    ADMIN_ISSUANCE_DISABLED,
    ADMIN_ISSUANCE_OPEN,
    MAX_BODY_BYTES,
    MAX_IDEMPOTENCY_KEY_LEN,
    MAX_REQUEST_SECONDS,
    MintConfig,
    MintServer,
    _FAT_ENTRY_BYTES,
    _FRAMING_CONFUSABLE_RE,
    _FRAMING_FIELD_NAMES,
    _FRAMING_NAME_SEPARATOR,
    _Handler,
    _max_batch_ceiling,
)
from aicash.signing import generate_keypair, verify_obj
from aicash.tokencodec import (
    b64u_decode,
    b64u_encode,
    canonical_json,
    format_token,
    ledger_key,
    new_secret,
)

T0 = 1_756_000_000_000
DAY_MS = 86_400_000
MINT_ID = "testmint"
POLICY = BurnPolicy(rate_ppm=10_000, cap_mc=1_000, exempt_below_mc=10)

# The harness mints ARE gated. MintConfig.admin_token no longer has a
# default (an unset credential used to mean "allow everyone"), and the
# right answer for a harness that issues on nearly every test is a real
# credential rather than ADMIN_ISSUANCE_OPEN: these tests then exercise the
# same authorized code path an operator runs, and the one test that wants
# an open mint has to say ADMIN_ISSUANCE_OPEN where a reader can grep it.
HARNESS_ADMIN_TOKEN = "c06-harness-admin-credential"


def sha256_b64u(data: bytes) -> str:
    return b64u_encode(hashlib.sha256(data).digest())


def tok(amount_mc: int, secret: bytes, mint_id: str = MINT_ID) -> str:
    return format_token(mint_id, amount_mc, secret)


def out_hash(amount_mc: int, secret: bytes, lock=None) -> dict:
    return {"amount_mc": amount_mc, "secret_hash": ledger_key(secret), "lock": lock}


def out_secret(amount_mc: int, secret: bytes, lock=None) -> dict:
    return {"amount_mc": amount_mc, "secret": b64u_encode(secret), "lock": lock}


def make_lock(preimage: bytes, refund: bytes, expiry: int) -> dict:
    return {
        "preimage_hash": sha256_b64u(preimage),
        "expiry": expiry,
        "refund_hash": sha256_b64u(refund),
    }


def http_raw(port, method, path, body: bytes | None = None, headers=None,
             timeout=30):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        conn.request(method, path, body, headers or {})
        resp = conn.getresponse()
        raw = resp.read()
        return resp.status, raw, {k.lower(): v for k, v in resp.getheaders()}
    finally:
        conn.close()


def http_json(port, method, path, obj=None, headers=None, timeout=30):
    body = None if obj is None else json.dumps(obj).encode("utf-8")
    status, raw, hdrs = http_raw(port, method, path, body, headers, timeout)
    return status, json.loads(raw.decode("utf-8")), hdrs


def raw_request(port, request_bytes: bytes, *, shutdown_write=False,
                timeout=8.0) -> bytes:
    """Speak HTTP by hand and read until the server hangs up.

    http.client will not send a Content-Length that disagrees with the body
    it is given, which is precisely the shape these deployment tests need.
    """
    sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        sock.sendall(request_bytes)
        if shutdown_write:
            sock.shutdown(socket.SHUT_WR)
        chunks = []
        while True:
            part = sock.recv(65536)
            if not part:
                break
            chunks.append(part)
        return b"".join(chunks)
    finally:
        sock.close()


def parse_http(raw: bytes):
    """(status, headers-lowercased, parsed json body) from raw response bytes."""
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = int(lines[0].split()[1])
    headers = {}
    for line in lines[1:]:
        key, _, value = line.partition(b":")
        headers[key.decode("latin-1").strip().lower()] = (
            value.decode("latin-1").strip()
        )
    return status, headers, (json.loads(body.decode("utf-8")) if body else None)


class Mint(NamedTuple):
    port: int
    clock: FakeClock
    config: MintConfig
    ledger: Ledger
    pub: bytes


class MintHarness:
    """Mint-building and mint-driving helpers, and NOTHING else.

    Deliberately not a TestCase and deliberately carrying no test methods.
    A class that only wants ``start_mint``/``issue``/``exchange`` mixes this
    in beside ``unittest.TestCase``; subclassing ``MintApiTest`` instead
    would inherit that class's ~22 test methods and re-run every one of them
    under the new name, which inflates the module's test count with
    re-executions and roughly doubles its runtime without testing anything
    new.
    """

    maxDiff = None

    def start_mint(
        self,
        *,
        max_batch=256,
        performance=None,
        admin_token=HARNESS_ADMIN_TOKEN,
        profiles=("supervision",),
        burn_policy=POLICY,
        max_lock_expiry_ms=30 * DAY_MS,
        clock=None,
    ) -> Mint:
        clock = clock or FakeClock(T0)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        priv, pub = generate_keypair()
        ledger = Ledger(
            os.path.join(tmp.name, "ledger.sqlite3"),
            clock,
            burn_policy,
            recovery_window_ms=90 * DAY_MS,
            max_lock_expiry_ms=max_lock_expiry_ms,
        )
        config = MintConfig(
            mint_id=MINT_ID,
            baseline_model_class="frontier-2026",
            burn_policy=burn_policy,
            signing_private=priv,
            signing_public=pub,
            max_batch=max_batch,
            performance=performance,
            admin_token=admin_token,
            profiles=profiles,
            max_lock_expiry_ms=max_lock_expiry_ms,
            recovery_window_ms=90 * DAY_MS,
        )
        server = MintServer(config, ledger)
        port = server.start()
        self.addCleanup(server.stop)
        return Mint(port, clock, config, ledger, pub)

    def issue(self, mint: Mint, amount_mc: int, secret: bytes):
        headers = {}
        # A str is a credential to present; ADMIN_ISSUANCE_OPEN and
        # ADMIN_ISSUANCE_DISABLED are policies, not headers.
        if isinstance(mint.config.admin_token, str):
            headers["X-Admin-Token"] = mint.config.admin_token
        status, body, _ = http_json(
            mint.port,
            "POST",
            "/admin/issue",
            {"outputs": [out_hash(amount_mc, secret)]},
            headers,
        )
        self.assertEqual(status, 200, body)
        return body

    def exchange(self, mint: Mint, key: str, inputs: list, outputs: list):
        return http_json(
            mint.port,
            "POST",
            "/v3/exchange",
            {"idempotency_key": key, "inputs": inputs, "outputs": outputs},
        )

    def status_batch(self, mint: Mint, hashes: list):
        return http_json(mint.port, "POST", "/v3/status", {"hashes": hashes})


class MintApiTest(MintHarness, unittest.TestCase):
    """C06's own end-to-end conformance tests (B1-B9)."""

    # ------------------------------------------------------------------
    # B1
    # ------------------------------------------------------------------

    def test_b1_end_to_end_money_flow(self):
        """B1: admin-issue → exchange split (by-secret AND by-hash outputs in
        one call) → status confirms; amounts conserve minus burn."""
        mint = self.start_mint()
        s0, s1, s2 = new_secret(), new_secret(), new_secret()
        self.issue(mint, 100_000, s0)

        status, body, _ = self.exchange(
            mint,
            "b1-split",
            [tok(100_000, s0)],
            [out_hash(50_000, s1), out_secret(49_000, s2)],
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(
            body, {"status": "ok", "outputs_confirmed": 2, "burn_mc": 1_000}
        )
        # conservation: inputs == outputs + burn
        self.assertEqual(100_000, 50_000 + 49_000 + body["burn_mc"])

        status, sbody, _ = self.status_batch(
            mint, [ledger_key(s0), ledger_key(s1), ledger_key(s2)]
        )
        self.assertEqual(status, 200)
        r0, r1, r2 = sbody["results"]
        self.assertEqual(r0["state"], "spent")
        self.assertEqual(r0["amount_mc"], 100_000)
        self.assertEqual(r0["spent_at"], T0)
        self.assertEqual(r1, {
            "state": "unspent", "amount_mc": 50_000, "lock": None,
            "spent_at": None, "claim_witness": None,
        })
        self.assertEqual(r2["state"], "unspent")
        self.assertEqual(r2["amount_mc"], 49_000)

        _, desc, _ = http_json(mint.port, "GET", "/v3/mints")
        supply = desc["supply"]
        self.assertEqual(supply["cumulative_issued_mc"], 100_000)
        self.assertEqual(supply["cumulative_burned_mc"], 1_000)
        self.assertEqual(supply["outstanding_mc"], 99_000)

    # ------------------------------------------------------------------
    # B2
    # ------------------------------------------------------------------

    def test_b2_anonymous_layer0_and_admin_auth(self):
        """B2: all Layer 0 endpoints succeed with no auth header of any kind;
        /admin/issue refuses without/with-wrong token when one is configured."""
        mint = self.start_mint(admin_token="topsecretadmintoken")
        s0, s1 = new_secret(), new_secret()

        # Admin endpoint: refused bare, refused wrong, accepted right.
        req = {"outputs": [out_hash(100_000, s0)]}
        status, body, _ = http_json(mint.port, "POST", "/admin/issue", req)
        self.assertEqual(status, 401)
        self.assertEqual(body, {"status": "unauthorized"})
        status, body, _ = http_json(
            mint.port, "POST", "/admin/issue", req, {"X-Admin-Token": "wrong"}
        )
        self.assertEqual(status, 401)
        status, body, _ = http_json(
            mint.port,
            "POST",
            "/admin/issue",
            req,
            {"X-Admin-Token": "topsecretadmintoken"},
        )
        self.assertEqual(status, 200, body)

        # Layer 0 endpoints: bare requests (no Authorization, no cookie,
        # no registration) — all succeed.
        status, body, _ = self.exchange(
            mint, "b2-x", [tok(100_000, s0)], [out_hash(99_000, s1)]
        )
        self.assertEqual(status, 200, body)
        status, _, _ = http_raw(
            mint.port, "GET", "/v3/status/" + ledger_key(s1)
        )
        self.assertEqual(status, 200)
        status, _, _ = self.status_batch(mint, [ledger_key(s1)])
        self.assertEqual(status, 200)
        status, _, _ = http_raw(mint.port, "GET", "/v3/mints")
        self.assertEqual(status, 200)

        # A mint that opted in BY NAME serves /admin/issue bare. This used
        # to be what a mint built with no admin_token at all did; now it is
        # the only way to get one, and it is spelled out in source.
        mint2 = self.start_mint(admin_token=ADMIN_ISSUANCE_OPEN)
        status, body, _ = http_json(
            mint2.port,
            "POST",
            "/admin/issue",
            {"outputs": [out_hash(50_000, new_secret())]},
        )
        self.assertEqual(status, 200, body)

    # ------------------------------------------------------------------
    # B3
    # ------------------------------------------------------------------

    def test_signed_snapshot_carries_mint_id_and_baseline(self):
        mint = self.start_mint()
        status, raw, _ = http_raw(mint.port, "GET", "/v3/mints")
        self.assertEqual(status, 200)
        desc = json.loads(raw.decode("utf-8"))
        snap = desc["supply"]
        pub = b64u_decode(desc["signing_pubkey"], expect_len=32)
        self.assertIn("mint_id", snap)
        self.assertIn("baseline_model_class", snap)
        self.assertEqual(desc["baseline_model_class"], snap["baseline_model_class"],
                         "the signed copy must match the one served at top level")
        self.assertTrue(verify_obj(snap, pub),
                        "the served snapshot must verify as signed")

    def test_tampering_with_the_baseline_breaks_the_signature(self):
        # This is the whole point: an altered baseline must be detectable from
        # the artifact alone, without trusting the mint that served it.
        mint = self.start_mint()
        _, raw, _ = http_raw(mint.port, "GET", "/v3/mints")
        desc = json.loads(raw.decode("utf-8"))
        snap = desc["supply"]
        pub = b64u_decode(desc["signing_pubkey"], expect_len=32)
        self.assertTrue(verify_obj(snap, pub))
        snap["baseline_model_class"] = "cheaper-model-v2"
        self.assertFalse(verify_obj(snap, pub),
                         "a redefined baseline must invalidate the signature")

    def test_b3_descriptor_completeness_and_snapshot(self):
        """B3: every §3.6 field present with correct types; performance null
        renders as JSON null; snapshot verifies against signing_pubkey via
        C05; consecutive fetches → snapshot_seq strictly increases,
        cumulatives monotone; invariant outstanding == issued − burned."""
        mint = self.start_mint(performance=None)
        status, raw, hdrs = http_raw(mint.port, "GET", "/v3/mints")
        self.assertEqual(status, 200)
        self.assertEqual(hdrs["content-type"], "application/json")
        desc = json.loads(raw.decode("utf-8"))

        self.assertEqual(desc["mint_id"], MINT_ID)
        self.assertIsInstance(desc["baseline_model_class"], str)
        self.assertIsInstance(desc["mint_time"], int)
        self.assertEqual(desc["mint_time"], T0)
        self.assertIsInstance(desc["denominations_mc"], list)
        for d in desc["denominations_mc"]:
            self.assertIsInstance(d, int)
        self.assertEqual(
            desc["burn_policy"],
            {"rate_ppm": 10_000, "cap_mc": 1_000, "exempt_below_mc": 10},
        )
        self.assertIsNone(desc["burn_policy_next"])
        supply = desc["supply"]
        for k in (
            "outstanding_mc",
            "cumulative_issued_mc",
            "cumulative_burned_mc",
            "snapshot_seq",
            "snapshot_time",
        ):
            self.assertIsInstance(supply[k], int, k)
        self.assertIsInstance(supply["signature"], str)
        # performance: the null case renders JSON null on the wire — the
        # key is present, its value is None, and never zeros.
        self.assertIn("performance", desc)
        self.assertIsNone(desc["performance"])
        self.assertIn(b'"performance":null', raw)
        limits = desc["limits"]
        self.assertIsInstance(limits["max_batch"], int)
        # §3.6 pins the rate schema; asserting only "is a dict" is what let
        # the descriptor ship without `scope` against closed decision R15.
        for tier in ("anonymous_rate", "registered_rate"):
            self.assertIsInstance(limits[tier], dict)
            self.assertEqual({"per_caller_rps", "burst", "scope"},
                             set(limits[tier]), f"{tier} must match the §3.6 pinned schema")
            self.assertIsInstance(limits[tier]["burst"], int)
            self.assertIn(limits[tier]["scope"], ("ip", "connection", "global"))
        lp = desc["lock_params"]
        self.assertIsInstance(lp["grace_ms"], int)
        self.assertIsInstance(lp["timestamp_precision_ms"], int)
        self.assertIsInstance(lp["max_lock_expiry_ms"], int)
        ret = desc["retention"]
        self.assertIsInstance(ret["recovery_window_ms"], int)
        self.assertIsInstance(ret["prunes_spent_records"], bool)
        self.assertIsInstance(ret["policy_url"], str)
        self.assertEqual(desc["profiles"], ["supervision"])
        act = desc["activity"]
        for k in ("daily_exchange_count", "daily_volume_mc", "as_of"):
            self.assertIsInstance(act[k], int, k)
        self.assertIsInstance(desc["signing_pubkey"], str)

        # Snapshot verifies against the published key (C05).
        pub = b64u_decode(desc["signing_pubkey"], expect_len=32)
        self.assertTrue(verify_obj(supply, pub))
        # ... and NOT after tampering.
        tampered = dict(supply, outstanding_mc=supply["outstanding_mc"] + 1)
        self.assertFalse(verify_obj(tampered, pub))
        # Invariant at signing time.
        self.assertEqual(
            supply["outstanding_mc"],
            supply["cumulative_issued_mc"] - supply["cumulative_burned_mc"],
        )

        # Move money, then fetch again: seq strictly up, cumulatives monotone.
        s0, s1 = new_secret(), new_secret()
        self.issue(mint, 100_000, s0)
        self.exchange(mint, "b3-x", [tok(100_000, s0)], [out_hash(99_000, s1)])
        _, desc2, _ = http_json(mint.port, "GET", "/v3/mints")
        supply2 = desc2["supply"]
        self.assertGreater(supply2["snapshot_seq"], supply["snapshot_seq"])
        self.assertGreaterEqual(
            supply2["cumulative_issued_mc"], supply["cumulative_issued_mc"]
        )
        self.assertGreaterEqual(
            supply2["cumulative_burned_mc"], supply["cumulative_burned_mc"]
        )
        self.assertEqual(
            supply2["outstanding_mc"],
            supply2["cumulative_issued_mc"] - supply2["cumulative_burned_mc"],
        )
        self.assertTrue(verify_obj(supply2, pub))

    def test_b3_snapshot_seq_survives_server_restart(self):
        """B3/§3.6: snapshot_seq is monotonically increasing across server
        restarts on the same ledger — a restarted mint (same sqlite file,
        same static L17 signing key) must never sign a snapshot whose seq
        repeats or regresses, since two such signed snapshots would be
        §3.6's 'portable proof of nonconformance'."""
        clock = FakeClock(T0)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db_path = os.path.join(tmp.name, "ledger.sqlite3")
        priv, pub = generate_keypair()

        def build_server() -> MintServer:
            ledger = Ledger(
                db_path,
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
                # This test issues, so it wants a credential; it used to
                # issue bare off the old open-by-default config.
                admin_token=HARNESS_ADMIN_TOKEN,
            )
            return MintServer(config, ledger)

        server1 = build_server()
        port1 = server1.start()
        try:
            s0 = new_secret()
            status, body, _ = http_json(
                port1, "POST", "/admin/issue",
                {"outputs": [out_hash(100_000, s0)]},
                {"X-Admin-Token": HARNESS_ADMIN_TOKEN},
            )
            self.assertEqual(status, 200, body)
            status, body, _ = http_json(
                port1,
                "POST",
                "/v3/exchange",
                {
                    "idempotency_key": "restart-x",
                    "inputs": [tok(100_000, s0)],
                    "outputs": [out_hash(99_000, new_secret())],
                },
            )
            self.assertEqual(status, 200, body)
            _, d1, _ = http_json(port1, "GET", "/v3/mints")
            _, d2, _ = http_json(port1, "GET", "/v3/mints")
        finally:
            server1.stop()

        server2 = build_server()  # new process-equivalent: same db, same key
        port2 = server2.start()
        self.addCleanup(server2.stop)
        _, d3, _ = http_json(port2, "GET", "/v3/mints")
        _, d4, _ = http_json(port2, "GET", "/v3/mints")

        seqs = [d["supply"]["snapshot_seq"] for d in (d1, d2, d3, d4)]
        self.assertEqual(seqs, sorted(seqs))
        self.assertEqual(len(set(seqs)), 4, seqs)  # strictly increasing
        for d in (d1, d2, d3, d4):
            self.assertTrue(verify_obj(d["supply"], pub))
        # Cumulatives monotone and invariant intact across the restart.
        for before, after in ((d1, d2), (d2, d3), (d3, d4)):
            self.assertGreaterEqual(
                after["supply"]["cumulative_issued_mc"],
                before["supply"]["cumulative_issued_mc"],
            )
            self.assertGreaterEqual(
                after["supply"]["cumulative_burned_mc"],
                before["supply"]["cumulative_burned_mc"],
            )
        for d in (d3, d4):
            self.assertEqual(
                d["supply"]["outstanding_mc"],
                d["supply"]["cumulative_issued_mc"]
                - d["supply"]["cumulative_burned_mc"],
            )
        # Activity counters persist too: the restarted server still reports
        # the same mint-clock day's exchange, not a reset-to-zero figure.
        self.assertEqual(d3["activity"]["daily_exchange_count"], 1)
        self.assertEqual(d3["activity"]["daily_volume_mc"], 100_000)

    def test_activity_day_windowed_and_replay_not_double_counted(self):
        """§3.6 activity: 'daily' figures cover the current mint-clock day
        only (not process lifetime), and an idempotency replay does not
        re-count the same ledger effect."""
        clock = FakeClock(T0)
        mint = self.start_mint(clock=clock)
        s0, s1 = new_secret(), new_secret()
        self.issue(mint, 100_000, s0)

        body_obj = {
            "idempotency_key": "act-1",
            "inputs": [tok(100_000, s0)],
            "outputs": [out_hash(99_000, s1)],
        }
        body_bytes = json.dumps(body_obj).encode("utf-8")
        status, raw, _ = http_raw(mint.port, "POST", "/v3/exchange", body_bytes)
        self.assertEqual(status, 200, raw)
        _, desc, _ = http_json(mint.port, "GET", "/v3/mints")
        self.assertEqual(desc["activity"]["daily_exchange_count"], 1)
        # volume = outputs + burn = inputs total.
        self.assertEqual(desc["activity"]["daily_volume_mc"], 100_000)
        self.assertEqual(desc["activity"]["as_of"], T0)

        # Replay (byte-identical §3.3 no-op) must not re-count activity.
        status, raw2, _ = http_raw(
            mint.port, "POST", "/v3/exchange", body_bytes
        )
        self.assertEqual(status, 200)
        self.assertEqual(raw, raw2)
        _, desc, _ = http_json(mint.port, "GET", "/v3/mints")
        self.assertEqual(desc["activity"]["daily_exchange_count"], 1)
        self.assertEqual(desc["activity"]["daily_volume_mc"], 100_000)

        # Next mint-clock day: yesterday's figures no longer report as
        # 'daily' — a long-lived server never accumulates lifetime totals.
        clock.set(T0 + DAY_MS)
        _, desc, _ = http_json(mint.port, "GET", "/v3/mints")
        self.assertEqual(desc["activity"]["daily_exchange_count"], 0)
        self.assertEqual(desc["activity"]["daily_volume_mc"], 0)
        self.assertEqual(desc["activity"]["as_of"], T0 + DAY_MS)

        # A fresh exchange on the new day starts the new day's window.
        s2 = new_secret()
        status, body, _ = self.exchange(
            mint, "act-2", [tok(99_000, s1)], [out_hash(98_010, s2)]
        )
        self.assertEqual(status, 200, body)
        _, desc, _ = http_json(mint.port, "GET", "/v3/mints")
        self.assertEqual(desc["activity"]["daily_exchange_count"], 1)
        self.assertEqual(desc["activity"]["daily_volume_mc"], 99_000)

    def test_b3_performance_stale_renders_null_fresh_renders_dict(self):
        """B3 (+L11): a performance block older than its own window renders
        null (never zeros); a fresh one is served verbatim."""
        stale = {
            "p99_exchange_ms": 120,
            "sustained_qps": 50,
            "window_days": 30,
            "measured_at": T0 - 40 * DAY_MS,
        }
        mint = self.start_mint(performance=stale)
        _, desc, _ = http_json(mint.port, "GET", "/v3/mints")
        self.assertIsNone(desc["performance"])

        fresh = dict(stale, measured_at=T0 - 1 * DAY_MS)
        mint2 = self.start_mint(performance=fresh)
        _, desc2, _ = http_json(mint2.port, "GET", "/v3/mints")
        self.assertEqual(desc2["performance"], fresh)

    # ------------------------------------------------------------------
    # B4
    # ------------------------------------------------------------------

    def test_b4_enumerated_rejection_over_the_wire(self):
        """B4 (§3.8): a bad batch returns enumerated indices and reasons."""
        mint = self.start_mint()
        s0, s1 = new_secret(), new_secret()
        self.issue(mint, 100_000, s0)
        status, body, _ = self.exchange(
            mint, "b4-spend", [tok(100_000, s0)], [out_hash(99_000, s1)]
        )
        self.assertEqual(status, 200, body)

        unknown = new_secret()
        status, body, _ = self.exchange(
            mint,
            "b4-bad",
            [tok(100_000, s0), tok(50_000, unknown)],  # spent + unknown
            [out_hash(1_000, new_secret())],
        )
        self.assertEqual(status, 400)
        self.assertEqual(body["status"], "rejected")
        self.assertIn(
            {"index": 0, "kind": "input", "reason": "spent"}, body["errors"]
        )
        self.assertIn(
            {"index": 1, "kind": "input", "reason": "unknown"}, body["errors"]
        )

    def test_b4_over_batch_limit_exact_boundary(self):
        """B4: exactly max_batch items accepted; max_batch+1 rejected with
        over_batch_limit on both /v3/exchange and /v3/status."""
        mint = self.start_mint(max_batch=4)
        s0 = new_secret()
        self.issue(mint, 100_000, s0)
        # 1 input + 3 outputs = 4 == max_batch → accepted.
        status, body, _ = self.exchange(
            mint,
            "b4-at-limit",
            [tok(100_000, s0)],
            [out_hash(33_000, new_secret()) for _ in range(3)],
        )
        self.assertEqual(status, 200, body)

        s4 = new_secret()
        self.issue(mint, 100_000, s4)
        # 1 input + 4 outputs = 5 == max_batch + 1 → over_batch_limit.
        status, body, _ = self.exchange(
            mint,
            "b4-over-limit",
            [tok(100_000, s4)],
            [out_hash(24_750, new_secret()) for _ in range(4)],
        )
        self.assertEqual(status, 400)
        self.assertEqual(
            body["errors"],
            [{"index": None, "kind": "call", "reason": "over_batch_limit"}],
        )
        # The over-limit call evaluated nothing: s4 is still unspent.
        _, sbody, _ = self.status_batch(mint, [ledger_key(s4)])
        self.assertEqual(sbody["results"][0]["state"], "unspent")

        # Status batch boundary.
        hashes4 = [ledger_key(new_secret()) for _ in range(4)]
        status, _, _ = self.status_batch(mint, hashes4)
        self.assertEqual(status, 200)
        status, body, _ = self.status_batch(
            mint, hashes4 + [ledger_key(new_secret())]
        )
        self.assertEqual(status, 400)
        self.assertEqual(body["errors"][0]["reason"], "over_batch_limit")

    def test_b4_idempotency_replay_byte_identical_and_conflict(self):
        """B4 (§3.3/R7): replaying the identical request over HTTP returns a
        byte-identical body with no double effect; a reused key with a
        different body surfaces idempotency_conflict as a call-level error."""
        mint = self.start_mint()
        s0, s1 = new_secret(), new_secret()
        self.issue(mint, 100_000, s0)
        body_obj = {
            "idempotency_key": "b4-replay",
            "inputs": [tok(100_000, s0)],
            "outputs": [out_hash(99_000, s1)],
        }
        body_bytes = json.dumps(body_obj).encode("utf-8")
        st1, raw1, _ = http_raw(mint.port, "POST", "/v3/exchange", body_bytes)
        self.assertEqual(st1, 200, raw1)
        _, desc_before, _ = http_json(mint.port, "GET", "/v3/mints")

        st2, raw2, _ = http_raw(mint.port, "POST", "/v3/exchange", body_bytes)
        self.assertEqual(st2, 200)
        self.assertEqual(raw1, raw2)  # byte-identical replay
        _, desc_after, _ = http_json(mint.port, "GET", "/v3/mints")
        self.assertEqual(  # replay had no ledger effect
            desc_before["supply"]["cumulative_burned_mc"],
            desc_after["supply"]["cumulative_burned_mc"],
        )

        # Same key, different body → idempotency_conflict (call-level).
        conflict = dict(body_obj, outputs=[out_hash(99_000, new_secret())])
        status, body, _ = http_json(mint.port, "POST", "/v3/exchange", conflict)
        self.assertEqual(status, 400)
        self.assertEqual(
            body["errors"],
            [{"index": None, "kind": "call", "reason": "idempotency_conflict"}],
        )

        # Rejection replay is byte-identical too (§3.3: applies to rejected
        # calls; the rejection is stored, never the body).
        bad_obj = {
            "idempotency_key": "b4-replay-rejected",
            "inputs": [tok(5, new_secret())],
            "outputs": [out_hash(5, new_secret())],
        }
        bad_bytes = json.dumps(bad_obj).encode("utf-8")
        st3, raw3, _ = http_raw(mint.port, "POST", "/v3/exchange", bad_bytes)
        st4, raw4, _ = http_raw(mint.port, "POST", "/v3/exchange", bad_bytes)
        self.assertEqual(st3, 400)
        self.assertEqual(st4, 400)
        self.assertEqual(raw3, raw4)

    # ------------------------------------------------------------------
    # B5
    # ------------------------------------------------------------------

    def test_b5_lock_flows_over_the_wire(self):
        """B5: fund-locked, claim with witness, refund after expiry (fake
        clock injected through the Ledger), claim_witness visible in status;
        wrong-path attempts get their §3.8 reasons."""
        clock = FakeClock(T0)
        mint = self.start_mint(clock=clock)
        s0, s_lock, s_change = new_secret(), new_secret(), new_secret()
        x, r = new_secret(), new_secret()
        expiry = T0 + 60_000
        self.issue(mint, 100_000, s0)

        # Fund a locked output (by hash — the funder never knows s_lock's
        # spending power) plus change, in one call.
        status, body, _ = self.exchange(
            mint,
            "b5-fund",
            [tok(100_000, s0)],
            [
                out_hash(50_000, s_lock, lock=make_lock(x, r, expiry)),
                out_hash(49_000, s_change),
            ],
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(body["burn_mc"], 1_000)

        # Refund before expiry → lock_not_expired.
        status, body, _ = self.exchange(
            mint,
            "b5-early-refund",
            [{"hash": ledger_key(s_lock), "witness": b64u_encode(r)}],
            [out_hash(49_500, new_secret())],
        )
        self.assertEqual(status, 400)
        self.assertIn(
            {"index": 0, "kind": "input", "reason": "lock_not_expired"},
            body["errors"],
        )

        # Claim with the wrong preimage → lock_preimage_invalid.
        status, body, _ = self.exchange(
            mint,
            "b5-bad-claim",
            [{"token": tok(50_000, s_lock), "witness": b64u_encode(r)}],
            [out_hash(49_500, new_secret())],
        )
        self.assertEqual(status, 400)
        self.assertIn(
            {"index": 0, "kind": "input", "reason": "lock_preimage_invalid"},
            body["errors"],
        )

        # Claim: token secret + preimage witness, before expiry.
        s_claimed = new_secret()
        status, body, _ = self.exchange(
            mint,
            "b5-claim",
            [{"token": tok(50_000, s_lock), "witness": b64u_encode(x)}],
            [out_hash(49_500, s_claimed)],
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(body["burn_mc"], 500)

        # §3.5/L6: claim_witness is disclosed in status for claim spends.
        status, sbody, _ = http_json(
            mint.port, "GET", "/v3/status/" + ledger_key(s_lock)
        )
        self.assertEqual(status, 200)
        entry = sbody["result"]
        self.assertEqual(entry["state"], "spent")
        self.assertEqual(entry["claim_witness"], b64u_encode(x))
        self.assertEqual(entry["lock"]["preimage_hash"], sha256_b64u(x))

        # Second lock, driven to expiry via the fake clock, then refunded.
        s_lock2 = new_secret()
        x2, r2 = new_secret(), new_secret()
        status, body, _ = self.exchange(
            mint,
            "b5-fund2",
            [tok(49_000, s_change)],
            [
                out_hash(48_000, s_lock2, lock=make_lock(x2, r2, expiry)),
                out_hash(510, new_secret()),
            ],
        )
        self.assertEqual(status, 200, body)

        clock.set(expiry)  # mint_time == expiry belongs to the refund path
        # Claim at/after expiry → lock_expired.
        status, body, _ = self.exchange(
            mint,
            "b5-late-claim",
            [{"token": tok(48_000, s_lock2), "witness": b64u_encode(x2)}],
            [out_hash(47_520, new_secret())],
        )
        self.assertEqual(status, 400)
        self.assertIn(
            {"index": 0, "kind": "input", "reason": "lock_expired"},
            body["errors"],
        )
        # Refund path: ledger hash + refund witness, NO token secret.
        status, body, _ = self.exchange(
            mint,
            "b5-refund",
            [{"hash": ledger_key(s_lock2), "witness": b64u_encode(r2)}],
            [out_hash(47_520, new_secret())],
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(body["burn_mc"], 480)

        # Refund spends disclose nothing (§3.5).
        _, sbody, _ = self.status_batch(mint, [ledger_key(s_lock2)])
        self.assertEqual(sbody["results"][0]["state"], "spent")
        self.assertIsNone(sbody["results"][0]["claim_witness"])

    # ------------------------------------------------------------------
    # B6
    # ------------------------------------------------------------------

    def test_b6_concurrent_double_spend_race(self):
        """B6: 8 parallel HTTP clients racing the same input token — exactly
        one 200; every loser gets a 400 'spent' rejection."""
        mint = self.start_mint()
        s0 = new_secret()
        self.issue(mint, 100_000, s0)

        n = 8
        barrier = threading.Barrier(n)
        results = []
        results_lock = threading.Lock()

        def race(i: int):
            body = {
                "idempotency_key": f"b6-{i}",
                "inputs": [tok(100_000, s0)],
                "outputs": [out_hash(99_000, new_secret())],
            }
            barrier.wait()
            status, resp, _ = http_json(mint.port, "POST", "/v3/exchange", body)
            with results_lock:
                results.append((status, resp))

        threads = [threading.Thread(target=race, args=(i,)) for i in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
        self.assertEqual(len(results), n)
        winners = [r for r in results if r[0] == 200]
        losers = [r for r in results if r[0] == 400]
        self.assertEqual(len(winners), 1)
        self.assertEqual(len(losers), n - 1)
        for _, resp in losers:
            self.assertIn(
                {"index": 0, "kind": "input", "reason": "spent"},
                resp["errors"],
            )
        # Money conserved: exactly one spend happened.
        _, desc, _ = http_json(mint.port, "GET", "/v3/mints")
        self.assertEqual(desc["supply"]["cumulative_burned_mc"], 1_000)
        self.assertEqual(desc["supply"]["outstanding_mc"], 99_000)

    # ------------------------------------------------------------------
    # B7
    # ------------------------------------------------------------------

    def test_b7_no_secret_material_in_logs(self):
        """B7: a run whose requests carry tokens, secrets, witnesses, and an
        admin token leaves no secret material in the captured server log;
        access log lines are route pattern + status only."""
        admin_token = "b7-admin-credential"
        clock = FakeClock(T0)
        mint = self.start_mint(admin_token=admin_token, clock=clock)
        s0, s1, s_lock = new_secret(), new_secret(), new_secret()
        x, r = new_secret(), new_secret()

        with self.assertLogs("aicash.mintapi", level="INFO") as captured:
            self.issue(mint, 100_000, s0)
            st, body, _ = self.exchange(
                mint,
                "b7-fund",
                [tok(100_000, s0)],
                [
                    out_hash(50_000, s_lock, lock=make_lock(x, r, T0 + 60_000)),
                    out_secret(49_000, s1),
                ],
            )
            self.assertEqual(st, 200, body)
            st, body, _ = self.exchange(
                mint,
                "b7-claim",
                [{"token": tok(50_000, s_lock), "witness": b64u_encode(x)}],
                [out_hash(49_500, new_secret())],
            )
            self.assertEqual(st, 200, body)
            http_raw(mint.port, "GET", "/v3/status/" + ledger_key(s1))
            self.status_batch(mint, [ledger_key(s1)])
            http_raw(mint.port, "GET", "/v3/mints")

        log_text = "\n".join(rec.getMessage() for rec in captured.records)
        secret_material = [
            b64u_encode(s) for s in (s0, s1, s_lock, x, r)
        ] + [tok(100_000, s0), tok(50_000, s_lock), admin_token]
        for secret in secret_material:
            self.assertNotIn(secret, log_text)
        line_re = re.compile(
            r"^(GET|POST) (/v3/(mints|exchange|status|status/<hash>)"
            r"|/admin/issue) \d{3}$"
        )
        for rec in captured.records:
            self.assertRegex(rec.getMessage(), line_re)

    # ------------------------------------------------------------------
    # B8
    # ------------------------------------------------------------------

    def test_b8_single_status_matches_batch_entry_shape(self):
        """B8: GET /v3/status/<hash> single-entry form matches the batch
        form's entry shape, for known and unknown hashes."""
        mint = self.start_mint()
        s0 = new_secret()
        self.issue(mint, 100_000, s0)
        known = ledger_key(s0)
        unknown = ledger_key(new_secret())

        for h in (known, unknown):
            st_single, single, _ = http_json(
                mint.port, "GET", "/v3/status/" + h
            )
            st_batch, batch, _ = self.status_batch(mint, [h])
            self.assertEqual(st_single, 200)
            self.assertEqual(st_batch, 200)
            self.assertEqual(single["result"], batch["results"][0])
            self.assertIsInstance(single["mint_time"], int)
            self.assertIsInstance(batch["mint_time"], int)

        # §3.5 unknown shape: amount_mc absent; lock/spent_at/claim_witness null.
        _, body, _ = http_json(mint.port, "GET", "/v3/status/" + unknown)
        self.assertEqual(
            body["result"],
            {"state": "unknown", "lock": None, "spent_at": None,
             "claim_witness": None},
        )
        self.assertNotIn("amount_mc", body["result"])

    # ------------------------------------------------------------------
    # Requirements 2, 4, 6 — wire fidelity and error hygiene
    # ------------------------------------------------------------------

    def test_malformed_json_bad_format_and_no_traceback(self):
        """Req 4: malformed JSON → 400 bad_format; response bodies never
        contain a stack trace."""
        mint = self.start_mint()
        for path in ("/v3/exchange", "/v3/status"):
            status, raw, hdrs = http_raw(
                mint.port, "POST", path, b"{not json !!"
            )
            self.assertEqual(status, 400)
            self.assertEqual(hdrs["content-type"], "application/json")
            body = json.loads(raw.decode("utf-8"))
            self.assertEqual(
                body["errors"],
                [{"index": None, "kind": "call", "reason": "bad_format"}],
            )
            self.assertNotIn(b"Traceback", raw)

        # Missing idempotency_key → bad_format.
        status, body, _ = http_json(
            mint.port, "POST", "/v3/exchange", {"inputs": [], "outputs": []}
        )
        self.assertEqual(status, 400)
        self.assertEqual(body["errors"][0]["reason"], "bad_format")

        # Floats are never legal in the wire protocol (§3.1: no floats, ever).
        status, body, _ = http_json(
            mint.port,
            "POST",
            "/v3/exchange",
            {
                "idempotency_key": "float-call",
                "inputs": [],
                "outputs": [{"amount_mc": 1.5, "secret_hash": "x"}],
            },
        )
        self.assertEqual(status, 400)
        self.assertEqual(body["errors"][0]["reason"], "bad_format")

    def test_unknown_routes_404(self):
        """Req 4: unknown routes → 404 (JSON, no traceback)."""
        mint = self.start_mint()
        for method, path in (
            ("GET", "/nope"),
            ("GET", "/v3/exchange"),
            ("POST", "/v3/mints"),
            ("POST", "/v3/nowhere"),
            ("GET", "/v3/status/"),
        ):
            status, raw, hdrs = http_raw(mint.port, method, path, b"{}")
            self.assertEqual(status, 404, (method, path))
            self.assertEqual(hdrs["content-type"], "application/json")
            self.assertNotIn(b"Traceback", raw)

    def test_foreign_mint_token_rejected_bad_format(self):
        """Req 2 (+C04 claim binding note): a token naming a different
        mint_id is bad_format at its input index."""
        mint = self.start_mint()
        s0 = new_secret()
        self.issue(mint, 100_000, s0)
        status, body, _ = self.exchange(
            mint,
            "foreign",
            [tok(100_000, s0, mint_id="othermint")],
            [out_hash(99_000, new_secret())],
        )
        self.assertEqual(status, 400)
        self.assertIn(
            {"index": 0, "kind": "input", "reason": "bad_format"},
            body["errors"],
        )
        # The genuine token still spends.
        status, body, _ = self.exchange(
            mint, "genuine", [tok(100_000, s0)], [out_hash(99_000, new_secret())]
        )
        self.assertEqual(status, 200, body)

    def test_responses_are_canonical_json(self):
        """Req 6: response bytes are exactly C01 canonical_json of their
        content, so client-side digests are reproducible."""
        mint = self.start_mint()
        s0 = new_secret()
        self.issue(mint, 100_000, s0)
        for method, path, body in (
            ("GET", "/v3/mints", None),
            ("GET", "/v3/status/" + ledger_key(s0), None),
            (
                "POST",
                "/v3/status",
                json.dumps({"hashes": [ledger_key(s0)]}).encode(),
            ),
        ):
            status, raw, hdrs = http_raw(mint.port, method, path, body)
            self.assertEqual(status, 200)
            self.assertEqual(hdrs["content-type"], "application/json")
            self.assertEqual(raw, canonical_json(json.loads(raw.decode())))

    def test_mixed_input_forms_one_call(self):
        """Req 2: the three §3.3 input forms (string token, {token,witness},
        {hash,witness}) are accepted together in a single exchange call."""
        clock = FakeClock(T0)
        mint = self.start_mint(clock=clock)
        s_plain, s_claim, s_refund = new_secret(), new_secret(), new_secret()
        x, r = new_secret(), new_secret()
        x2, r2 = new_secret(), new_secret()
        base = new_secret()
        self.issue(mint, 100_000, base)
        expiry = T0 + 10_000
        status, body, _ = self.exchange(
            mint,
            "mix-fund",
            [tok(100_000, base)],
            [
                out_hash(30_000, s_plain),
                out_hash(30_000, s_claim, lock=make_lock(x, r, expiry)),
                out_hash(39_000, s_refund, lock=make_lock(x2, r2, expiry)),
            ],
        )
        self.assertEqual(status, 200, body)
        clock.set(expiry)  # refund path live for s_refund; s_claim expired too
        # Re-fund s_claim's value cannot be claimed now — so run the mixed
        # call with: plain + refund of s_refund + refund of s_claim.
        status, body, _ = self.exchange(
            mint,
            "mix-spend",
            [
                tok(30_000, s_plain),
                {"hash": ledger_key(s_claim), "witness": b64u_encode(r)},
                {"hash": ledger_key(s_refund), "witness": b64u_encode(r2)},
            ],
            [out_hash(98_010, new_secret())],
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(body["burn_mc"], 990)

    def test_mixed_forms_with_live_claim(self):
        """Req 2/B1: plain + claim-path inputs and by-secret + by-hash
        outputs in one call, before expiry."""
        mint = self.start_mint()
        s_plain, s_claim = new_secret(), new_secret()
        x, r = new_secret(), new_secret()
        base = new_secret()
        self.issue(mint, 100_000, base)
        status, body, _ = self.exchange(
            mint,
            "live-fund",
            [tok(100_000, base)],
            [
                out_hash(50_000, s_plain),
                out_hash(49_000, s_claim, lock=make_lock(x, r, T0 + 60_000)),
            ],
        )
        self.assertEqual(status, 200, body)
        status, body, _ = self.exchange(
            mint,
            "live-spend",
            [
                tok(50_000, s_plain),
                {"token": tok(49_000, s_claim), "witness": b64u_encode(x)},
            ],
            [
                out_hash(50_000, new_secret()),
                out_secret(48_010, new_secret()),
            ],
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(body["burn_mc"], 990)

    # ------------------------------------------------------------------
    # §3.8 amount_mismatch detail — expected_burn_mc over the wire
    # ------------------------------------------------------------------

    def test_amount_mismatch_reports_expected_burn(self):
        """§3.8 usability: the amount_mismatch rejection includes
        expected_burn_mc — the burn the mint computed from its published
        policy (public information) — so a mis-budgeted client can
        rebalance without re-deriving the arithmetic. The rest of the
        error shape is unchanged."""
        mint = self.start_mint()  # POLICY: 1% capped at 1000, exempt < 10
        s0 = new_secret()
        self.issue(mint, 100_000, s0)
        status, body, _ = self.exchange(
            mint,
            "mismatch-detail",
            [tok(100_000, s0)],
            [out_hash(100_000, new_secret())],  # forgot the burn entirely
        )
        self.assertEqual(status, 400)
        self.assertEqual(
            body["errors"],
            [{
                "index": None,
                "kind": "call",
                "reason": "amount_mismatch",
                "expected_burn_mc": 1_000,
            }],
        )
        # Nothing was mutated; the corrected batch then succeeds.
        status, body, _ = self.exchange(
            mint,
            "mismatch-fixed",
            [tok(100_000, s0)],
            [out_hash(100_000 - body["errors"][0]["expected_burn_mc"],
                      new_secret())],
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(body["burn_mc"], 1_000)


class MintConfigValidationTest(unittest.TestCase):
    """MintConfig.__post_init__ validates mint_id against the §3.1 rule
    (tokencodec.MINT_ID_RE) — a config violating it would mint tokens no
    parser accepts."""

    def make_config(self, mint_id):
        priv, pub = generate_keypair()
        return MintConfig(
            mint_id=mint_id,
            baseline_model_class="frontier-2026",
            burn_policy=POLICY,
            signing_private=priv,
            signing_public=pub,
            # These configs are never served; nothing here wants issuance.
            admin_token=ADMIN_ISSUANCE_DISABLED,
        )

    def test_valid_mint_ids_accepted(self):
        for good in ("testmint", "mint-1", "a", "a" * 64):
            self.assertEqual(self.make_config(good).mint_id, good)

    def test_invalid_mint_ids_rejected_with_rule_spelled_out(self):
        from aicash.tokencodec import MINT_ID_RE

        for bad in ("Testmint", "mint_1", "a" * 65, "mïnt", "m t", "m:t"):
            self.assertIsNone(MINT_ID_RE.fullmatch(bad), bad)
            with self.assertRaises(ValueError) as ctx:
                self.make_config(bad)
            message = str(ctx.exception)
            self.assertIn("mint_id", message)
            self.assertIn("^[a-z0-9-]{1,64}$", message)  # the rule, spelled out

    def test_empty_mint_id_still_rejected(self):
        with self.assertRaises(ValueError):
            self.make_config("")


class MakeMintTest(unittest.TestCase):
    """make_mint builds the Ledger FROM the config (single source of
    truth); MintServer refuses hand-wired config/ledger mismatches at
    boot, not at payment time."""

    def make_config(self, **kw):
        priv, pub = generate_keypair()
        defaults = dict(
            mint_id=MINT_ID,
            baseline_model_class="frontier-2026",
            burn_policy=POLICY,
            signing_private=priv,
            signing_public=pub,
            # Wiring tests; no test in this class calls /admin/issue.
            admin_token=ADMIN_ISSUANCE_DISABLED,
        )
        defaults.update(kw)
        return MintConfig(**defaults)

    def tmp_db(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        return os.path.join(tmp.name, "ledger.sqlite3")

    def test_make_mint_wires_ledger_from_config(self):
        from aicash.mintapi import make_mint

        config = self.make_config(
            recovery_window_ms=42 * DAY_MS, max_lock_expiry_ms=7 * DAY_MS
        )
        clock = FakeClock(T0)
        server, ledger = make_mint(config, self.tmp_db(), clock=clock)
        self.assertIsInstance(server, MintServer)
        self.assertIsInstance(ledger, Ledger)
        self.assertEqual(ledger.burn_policy, config.burn_policy)
        self.assertEqual(ledger.recovery_window_ms, 42 * DAY_MS)
        self.assertEqual(ledger.max_lock_expiry_ms, 7 * DAY_MS)
        # The pair serves real HTTP with the injected clock (L17) and the
        # returned ledger is the live one behind the server.
        port = server.start()
        self.addCleanup(server.stop)
        s0 = new_secret()
        ledger.issue([{"amount_mc": 1_000, "secret_hash": ledger_key(s0)}])
        status, body, _ = http_json(port, "GET", "/v3/mints")
        self.assertEqual(status, 200)
        self.assertEqual(body["mint_time"], T0)
        self.assertEqual(body["supply"]["cumulative_issued_mc"], 1_000)
        self.assertEqual(body["retention"]["recovery_window_ms"], 42 * DAY_MS)
        self.assertEqual(body["lock_params"]["max_lock_expiry_ms"], 7 * DAY_MS)

    def test_make_mint_default_clock_is_system_clock(self):
        """Omitting clock uses the wall clock (production default)."""
        from aicash.mintapi import make_mint

        server, ledger = make_mint(self.make_config(), self.tmp_db())
        _now, _ = ledger.status([])
        self.assertGreater(_now, 1_700_000_000_000)  # ms since epoch, sane

    def test_hand_wired_mismatch_fails_at_boot(self):
        """Config-vs-ledger disagreement on any shared parameter raises at
        construction, naming the parameter."""
        clock = FakeClock(T0)
        other_policy = BurnPolicy(
            rate_ppm=5_000, cap_mc=500, exempt_below_mc=10
        )
        mismatches = (
            ("burn_policy", dict(burn_policy=other_policy), {}),
            (
                "recovery_window_ms",
                dict(recovery_window_ms=1 * DAY_MS),
                {},
            ),
            (
                "max_lock_expiry_ms",
                dict(max_lock_expiry_ms=None),
                {},
            ),
        )
        for name, ledger_kw, config_kw in mismatches:
            ledger_args = dict(
                burn_policy=POLICY,
                recovery_window_ms=90 * DAY_MS,
                max_lock_expiry_ms=30 * DAY_MS,
            )
            ledger_args.update(ledger_kw)
            ledger = Ledger(
                self.tmp_db(),
                clock,
                ledger_args["burn_policy"],
                recovery_window_ms=ledger_args["recovery_window_ms"],
                max_lock_expiry_ms=ledger_args["max_lock_expiry_ms"],
            )
            config = self.make_config(
                recovery_window_ms=90 * DAY_MS,
                max_lock_expiry_ms=30 * DAY_MS,
                **config_kw,
            )
            with self.assertRaises(ValueError, msg=name) as ctx:
                MintServer(config, ledger)
            self.assertIn(name, str(ctx.exception))
            self.assertIn("make_mint", str(ctx.exception))

    def test_make_mint_hands_the_ledger_the_change_notice_too(self):
        """The descriptor publishes burn_policy_next and every client acts
        on it; a ledger that never received it charges the superseded
        policy from effective_at onwards and rejects everything."""
        from aicash.mintapi import make_mint

        nxt = BurnPolicy(rate_ppm=5_000, cap_mc=1_000, exempt_below_mc=10)
        effective_at = T0 + 30 * DAY_MS
        config = self.make_config(
            burn_policy=BurnPolicy(
                rate_ppm=1_000, cap_mc=1_000, exempt_below_mc=10
            ),
            burn_policy_next=(nxt, effective_at),
            burn_policy_announced_at=T0,
        )
        _server, ledger = make_mint(config, self.tmp_db(), clock=FakeClock(T0))
        self.assertEqual(ledger.burn_policy_next, (nxt, effective_at))

    def test_a_ledger_carrying_a_notice_the_config_does_not_publish_is_refused(
        self,
    ):
        """The direction that must never be reconciled away: the ledger
        would charge a §7.3 change the descriptor never announced."""
        nxt = BurnPolicy(rate_ppm=5_000, cap_mc=1_000, exempt_below_mc=10)
        ledger = Ledger(
            self.tmp_db(),
            FakeClock(T0),
            POLICY,
            recovery_window_ms=90 * DAY_MS,
            max_lock_expiry_ms=30 * DAY_MS,
            burn_policy_next=(nxt, T0 + 30 * DAY_MS),
        )
        config = self.make_config(
            recovery_window_ms=90 * DAY_MS, max_lock_expiry_ms=30 * DAY_MS
        )
        with self.assertRaises(ValueError) as ctx:
            MintServer(config, ledger)
        self.assertIn("burn_policy_next", str(ctx.exception))

    def test_two_different_notices_are_refused(self):
        """Two views of one fact disagreeing is the whole reason this check
        exists; a second notice is not a reconcilable absence."""
        a = BurnPolicy(rate_ppm=5_000, cap_mc=1_000, exempt_below_mc=10)
        b = BurnPolicy(rate_ppm=9_000, cap_mc=1_000, exempt_below_mc=10)
        low = BurnPolicy(rate_ppm=1_000, cap_mc=1_000, exempt_below_mc=10)
        ledger = Ledger(
            self.tmp_db(),
            FakeClock(T0),
            low,
            recovery_window_ms=90 * DAY_MS,
            max_lock_expiry_ms=30 * DAY_MS,
            burn_policy_next=(a, T0 + 30 * DAY_MS),
        )
        config = self.make_config(
            burn_policy=low,
            burn_policy_next=(b, T0 + 30 * DAY_MS),
            burn_policy_announced_at=T0,
            recovery_window_ms=90 * DAY_MS,
            max_lock_expiry_ms=30 * DAY_MS,
        )
        with self.assertRaises(ValueError) as ctx:
            MintServer(config, ledger)
        self.assertIn("burn_policy_next", str(ctx.exception))

    def test_a_ledger_built_before_the_notice_existed_adopts_it_loudly(self):
        """A hand-wired Ledger with no opinion is not drift — it was never
        told. Refusing to boot over a constructor argument that did not use
        to exist helps nobody; charging the superseded policy is the defect.
        So the config (which is what the descriptor publishes) wins, and the
        operator is told in the log."""
        low = BurnPolicy(rate_ppm=1_000, cap_mc=1_000, exempt_below_mc=10)
        nxt = BurnPolicy(rate_ppm=5_000, cap_mc=1_000, exempt_below_mc=10)
        effective_at = T0 + 30 * DAY_MS
        clock = FakeClock(T0)
        ledger = Ledger(
            self.tmp_db(),
            clock,
            low,
            recovery_window_ms=90 * DAY_MS,
            max_lock_expiry_ms=30 * DAY_MS,
        )
        config = self.make_config(
            burn_policy=low,
            burn_policy_next=(nxt, effective_at),
            burn_policy_announced_at=T0,
            recovery_window_ms=90 * DAY_MS,
            max_lock_expiry_ms=30 * DAY_MS,
        )
        with self.assertLogs("aicash.mintapi", level="WARNING") as logs:
            MintServer(config, ledger)
        self.assertIn("burn_policy_next", "\n".join(logs.output))
        self.assertEqual(ledger.burn_policy_next, (nxt, effective_at))

        # and the adopted notice is actually charged
        secret = new_secret()
        ledger.issue([{"amount_mc": 10_000, "secret_hash": ledger_key(secret)}])
        clock.set(effective_at)
        out = new_secret()
        from aicash.lockeval import InputForm
        from aicash.tokencodec import Token

        result = ledger.exchange(
            "adopted", "d",
            [InputForm(kind="plain", token=Token(MINT_ID, 10_000, secret))],
            outputs=[OutputSpec(amount_mc=9_950, secret_hash=ledger_key(out))],
        )
        self.assertEqual(result["burn_mc"], 50)  # 0.5%, the announced policy

    def test_matching_hand_wiring_still_accepted(self):
        clock = FakeClock(T0)
        config = self.make_config()
        ledger = Ledger(
            self.tmp_db(),
            clock,
            config.burn_policy,
            recovery_window_ms=config.recovery_window_ms,
            max_lock_expiry_ms=config.max_lock_expiry_ms,
        )
        MintServer(config, ledger)  # must not raise


class EnvelopeAliasTest(unittest.TestCase):
    """aicash.envelope is a discoverability alias for the §9.5 surface in
    aicash.receipts (journey feedback: testers did not find the envelope
    tooling under 'receipts'). Placed here because C12's own test file is
    outside this change set; the alias is pure re-export."""

    def test_reexports_are_the_same_objects(self):
        import aicash.envelope as envelope
        import aicash.receipts as receipts

        for name in (
            "build_envelope",
            "parse_envelope",
            "payment_error",
            "Envelope",
            "ChannelDraw",
            "EnvelopeError",
            "ERROR_KINDS",
            "ERROR_REASONS",
        ):
            self.assertIn(name, envelope.__all__)
            self.assertIs(
                getattr(envelope, name), getattr(receipts, name), name
            )
        self.assertIn("9.5", envelope.__doc__)

    def test_alias_round_trip_works(self):
        from aicash.envelope import build_envelope, parse_envelope

        token = tok(5_000, new_secret())
        wrapped = build_envelope({"job": "translate"}, MINT_ID, [token])
        env = parse_envelope(wrapped)
        self.assertEqual(env.mint_id, MINT_ID)
        self.assertEqual(env.request, {"job": "translate"})
        self.assertEqual(len(env.tokens), 1)
        self.assertEqual(env.tokens[0].amount_mc, 5_000)
        self.assertIsNone(env.channel_draw)


class RateSchemaConformance(unittest.TestCase):
    """§3.6 pins the rate schema. Nothing checked it, and the descriptor
    shipped without `scope` against OPEN-QUESTIONS R15, which had closed
    pinning it mandatory. Found 2026-09-08 by an outside implementation
    reading the published descriptor against the spec."""

    def _config(self, **over):
        priv, pub = generate_keypair()
        base = dict(mint_id="rate-test", baseline_model_class="b",
                    burn_policy=BurnPolicy(0, 0, 10),
                    signing_private=priv, signing_public=pub,
                    # Descriptor-shape tests; no issuance.
                    admin_token=ADMIN_ISSUANCE_DISABLED)
        base.update(over)
        return MintConfig(**base)

    def test_default_rates_carry_all_three_pinned_fields(self):
        c = self._config()
        for tier in (c.anonymous_rate, c.registered_rate):
            self.assertEqual({"per_caller_rps", "burst", "scope"}, set(tier))
            self.assertIn(tier["scope"], ("ip", "connection", "global"))

    def test_rate_missing_scope_is_rejected(self):
        with self.assertRaises(ValueError) as cm:
            self._config(anonymous_rate={"per_caller_rps": 50, "burst": 200})
        self.assertIn("scope", str(cm.exception))

    def test_rate_with_bad_scope_is_rejected(self):
        with self.assertRaises(ValueError):
            self._config(registered_rate={"per_caller_rps": 50, "burst": 200,
                                          "scope": "planetary"})

    def test_scope_is_not_required_to_be_an_int(self):
        # The old validator required every rate value to be a plain int, so
        # adding the mandatory string field would raise. Conformance was
        # structurally impossible, not merely absent.
        c = self._config(anonymous_rate={"per_caller_rps": 50, "burst": 200,
                                         "scope": "connection"})
        self.assertEqual("connection", c.anonymous_rate["scope"])



class DeploymentHardeningTest(unittest.TestCase):
    """Resource-exhaustion holes in the HTTP surface, found reviewing C06
    for a real deployment (2026-09-15).

    None of these is the §3.7 rate limiting L17 scopes out: each bounds a
    SINGLE request — how much one body may allocate, how long one silent
    peer may hold a thread, how much one caller may write into the §8
    recovery window, and whether an unauthenticated read takes the payment
    database's write lock. No request is ever counted per caller.

    The mint-building helpers are borrowed from MintApiTest rather than
    inherited, so the B1-B8 suite is not re-run under this class's name.
    """

    maxDiff = None
    start_mint = MintApiTest.start_mint
    issue = MintApiTest.issue
    exchange = MintApiTest.exchange
    status_batch = MintApiTest.status_batch

    # ------------------------------------------------------------------
    # 1. unbounded request body
    # ------------------------------------------------------------------

    def test_max_body_bytes_fits_a_full_max_batch_call(self):
        """The cap must not be able to reject a call the descriptor says is
        legal: a full limits.max_batch batch has to fit with room to spare.

        A boundary guard rather than a regression: it is what keeps the
        UNPUBLISHED byte cap from quietly overriding the one limit §3.6
        does publish. So it is driven over the wire, not just measured —
        the fattest legal call has to come back with per-index §3.8 errors
        (the tokens are made up), never with a call-level refusal, which
        is what the byte cap would produce."""
        mint = self.start_mint()
        _, desc, _ = http_json(mint.port, "GET", "/v3/mints")
        max_batch = desc["limits"]["max_batch"]
        call = {
            "idempotency_key": "k" * MAX_IDEMPOTENCY_KEY_LEN,
            "inputs": [
                {"token": tok(100_000, new_secret()),
                 "witness": b64u_encode(new_secret())}
                for _ in range(max_batch // 2)
            ],
            "outputs": [
                out_hash(1_000, new_secret(),
                         make_lock(new_secret(), new_secret(), T0 + DAY_MS))
                for _ in range(max_batch - max_batch // 2)
            ],
        }
        body = json.dumps(call).encode("utf-8")
        self.assertLess(
            len(body) * 4, MAX_BODY_BYTES,
            "MAX_BODY_BYTES must leave real headroom over the fattest legal "
            "max_batch call, or the byte cap silently overrides the "
            "published entry-count limit",
        )
        status, answer, _ = http_json(
            mint.port, "POST", "/v3/exchange", call, timeout=30
        )
        self.assertEqual(status, 400, answer)
        kinds = {e["kind"] for e in answer["errors"]}
        self.assertEqual(kinds, {"input"}, answer["errors"][:3])
        self.assertEqual(len(answer["errors"]), max_batch // 2)

    def test_oversized_content_length_rejected_before_reading_the_body(self):
        """A declared body over MAX_BODY_BYTES is refused on the header
        alone — no allocation, no read, no hang. Before the fix the server
        trusted Content-Length and called rfile.read(length), so this
        request (headers only, no body ever sent) parked the thread
        forever and a truthful huge length allocated that many bytes.

        The reason must be the PERMANENT one. §9.5 pins `over_batch_limit`
        as "retryable with backoff", but identical bytes over the byte cap
        fail identically forever, so that reason sends a spec-conforming
        payer into a retry loop over a call that can never succeed. Nor is
        MAX_BODY_BYTES a §3.6 published limit a client could aim at — the
        `limits` object holds max_batch and its scope guard is explicit —
        which is exactly why the honest answer is §3.8 `bad_format`: an
        envelope the mint will not parse, do not resend it as-is."""
        mint = self.start_mint()
        declared = MAX_BODY_BYTES + 1
        request = (
            b"POST /v3/status HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(declared).encode("ascii") + b"\r\n"
            b"\r\n"
        )  # deliberately: not one byte of body follows
        raw = raw_request(mint.port, request, timeout=8.0)
        status, headers, body = parse_http(raw)
        self.assertEqual(status, 400)
        self.assertEqual(body, {
            "status": "rejected",
            "errors": [{"index": None, "kind": "call",
                        "reason": "bad_format"}],
        })
        self.assertNotEqual(
            body["errors"][0]["reason"], "over_batch_limit",
            "§9.5 makes over_batch_limit retryable with backoff; a body "
            "past the byte cap fails permanently, so that reason would "
            "tell the payer to retry bytes that can never be accepted",
        )
        # The declared octets were never consumed, so the connection cannot
        # be reused: anything left would be read as the next request.
        self.assertEqual(headers.get("connection"), "close")
        # The mint is unharmed and still serving.
        st, desc, _ = http_json(mint.port, "GET", "/v3/mints", timeout=8)
        self.assertEqual(st, 200)
        self.assertEqual(desc["mint_id"], MINT_ID)

    def test_body_shorter_than_content_length_is_not_silently_accepted(self):
        """A short body is a truncated call, not a smaller one. Before the
        fix read() returned what had arrived and the server happily served
        it: this request declares 500 bytes, sends a complete but shorter
        document, and used to succeed with 200."""
        mint = self.start_mint()
        short = b'{"hashes": []}'
        request = (
            b"POST /v3/status HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: 500\r\n"
            b"\r\n" + short
        )
        raw = raw_request(mint.port, request, shutdown_write=True, timeout=8.0)
        status, headers, body = parse_http(raw)
        self.assertEqual(status, 400, body)
        self.assertEqual(body, {
            "status": "rejected",
            "errors": [{"index": None, "kind": "call",
                        "reason": "bad_format"}],
        })
        self.assertEqual(headers.get("connection"), "close")

    # ------------------------------------------------------------------
    # 2. no socket timeout
    # ------------------------------------------------------------------

    def test_handler_declares_a_finite_socket_timeout(self):
        """BaseHTTPRequestHandler's default is None. With HTTP/1.1 keep-alive
        that is an unbounded thread-and-fd hold for any anonymous caller."""
        self.assertIsNotNone(
            _Handler.timeout,
            "_Handler.timeout=None lets a silent peer park a daemon thread",
        )
        self.assertGreater(_Handler.timeout, 0)
        self.assertLessEqual(_Handler.timeout, 60)

    def test_silent_connection_is_closed_and_leaves_no_traceback(self):
        """Connect, send nothing, and the server must hang up on its own —
        cleanly, with no traceback on the process's stderr."""
        original = _Handler.timeout
        # Assert the SHIPPED default is finite before standing anything on
        # it — with timeout=None this connection is never closed at all and
        # the recv below would simply block. Then clamp it so the test
        # exercises the same mechanism in under a second instead of ten.
        self.assertIsNotNone(original, "_Handler.timeout must not be None")
        _Handler.timeout = min(original, 0.4)
        self.addCleanup(setattr, _Handler, "timeout", original)

        captured = io.StringIO()
        with contextlib.redirect_stderr(captured):
            mint = self.start_mint()
            sock = socket.create_connection(("127.0.0.1", mint.port),
                                            timeout=6.0)
            self.addCleanup(sock.close)
            started = time.monotonic()
            # recv raises socket.timeout at 6s if the server never closes,
            # which is exactly the pre-fix behaviour.
            data = sock.recv(65536)
            elapsed = time.monotonic() - started
            time.sleep(0.2)  # let the serving thread finish unwinding
        self.assertEqual(data, b"", "server should have closed the connection")
        self.assertLess(elapsed, 5.0)
        self.assertNotIn("Traceback", captured.getvalue())

    # ------------------------------------------------------------------
    # 3. unbounded idempotency key
    # ------------------------------------------------------------------

    def test_over_length_idempotency_key_rejected_before_the_ledger(self):
        """§3.3 keys are caller-chosen and C04 keeps them for the §8
        recovery window. An unbounded key is unbounded storage written by a
        stranger, so it is a malformed envelope: §3.8 call-level
        bad_format, and the exchange must not have executed."""
        mint = self.start_mint()
        s0, s1 = new_secret(), new_secret()
        self.issue(mint, 100_000, s0)
        long_key = "k" * (MAX_IDEMPOTENCY_KEY_LEN + 1)
        status, body, _ = self.exchange(
            mint, long_key, [tok(100_000, s0)], [out_hash(99_000, s1)]
        )
        self.assertEqual(status, 400, body)
        self.assertEqual(body, {
            "status": "rejected",
            "errors": [{"index": None, "kind": "call",
                        "reason": "bad_format"}],
        })
        # Rejected before C04 saw it: the input is untouched, the output
        # was never created, and nothing was written under that key.
        _, sbody, _ = self.status_batch(
            mint, [ledger_key(s0), ledger_key(s1)]
        )
        self.assertEqual(sbody["results"][0]["state"], "unspent")
        self.assertEqual(sbody["results"][1]["state"], "unknown")

    def test_idempotency_key_at_the_limit_is_accepted(self):
        """Off-by-one guard: the cap is a maximum, not an exclusive bound."""
        mint = self.start_mint()
        s0, s1 = new_secret(), new_secret()
        self.issue(mint, 100_000, s0)
        status, body, _ = self.exchange(
            mint, "k" * MAX_IDEMPOTENCY_KEY_LEN,
            [tok(100_000, s0)], [out_hash(99_000, s1)],
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(body["outputs_confirmed"], 1)

    # ------------------------------------------------------------------
    # 4. the descriptor endpoint was a write
    # ------------------------------------------------------------------

    def test_descriptor_fetch_does_not_take_the_payment_write_lock(self):
        """GET /v3/mints is unauthenticated (§3.7) and used to run BEGIN
        IMMEDIATE plus a snapshot_seq UPDATE on every fetch, so a poller
        serialized against real exchanges on the same sqlite file.

        Proof: hold the database's write lock from outside and serve
        descriptors anyway. Before the fix each fetch blocked on that lock
        (sqlite timeout 30s) and then failed; after it, a fetch is a read.
        §3.6 monotonicity is asserted throughout, including that the
        PERSISTED seq stays at or above every seq served — which is what
        makes a restart resume above, never inside, what was signed."""
        mint = self.start_mint()
        s0, s1, s2 = new_secret(), new_secret(), new_secret()
        self.issue(mint, 100_000, s0)
        self.exchange(mint, "dh-1", [tok(100_000, s0)], [out_hash(99_000, s1)])
        # Warm-up fetch: this one may reserve a seq block (one write).
        st, d0, _ = http_json(mint.port, "GET", "/v3/mints", timeout=8)
        self.assertEqual(st, 200)

        blocker = sqlite3.connect(
            mint.ledger._db_path, timeout=30.0, isolation_level=None
        )
        self.addCleanup(blocker.close)
        blocker.execute("BEGIN IMMEDIATE")  # sqlite's write lock, held
        try:
            descs = [d0]
            for _ in range(4):
                st, d, _ = http_json(mint.port, "GET", "/v3/mints", timeout=8)
                self.assertEqual(
                    st, 200,
                    "a descriptor fetch must not need the write lock",
                )
                descs.append(d)
            persisted = blocker.execute(
                "SELECT snapshot_seq FROM mintapi_state WHERE id = 1"
            ).fetchone()[0]
        finally:
            blocker.execute("ROLLBACK")

        supplies = [d["supply"] for d in descs]
        seqs = [s["snapshot_seq"] for s in supplies]
        self.assertEqual(seqs, sorted(seqs))
        self.assertEqual(len(set(seqs)), len(seqs), seqs)  # strictly up
        # The durable high-water mark covers everything signed, so a restart
        # can only continue above it (§3.6 "portable proof of nonconformance"
        # is a repeated or regressing seq; this is what forecloses it).
        self.assertGreaterEqual(persisted, max(seqs))
        for before, after in zip(supplies, supplies[1:]):
            self.assertGreaterEqual(after["cumulative_issued_mc"],
                                    before["cumulative_issued_mc"])
            self.assertGreaterEqual(after["cumulative_burned_mc"],
                                    before["cumulative_burned_mc"])
        for snap in supplies:
            self.assertTrue(verify_obj(snap, mint.pub))
            self.assertEqual(
                snap["outstanding_mc"],
                snap["cumulative_issued_mc"] - snap["cumulative_burned_mc"],
            )

    def test_descriptor_is_never_stale_behind_a_completed_exchange(self):
        """Cheap must not mean cached: the snapshot following an exchange
        has to show that exchange's burn and issuance, not the previous
        fetch's numbers."""
        mint = self.start_mint()
        _, before, _ = http_json(mint.port, "GET", "/v3/mints")
        _, before2, _ = http_json(mint.port, "GET", "/v3/mints")
        # Back-to-back fetches with no write between them still advance the
        # sequence (C06 requirement 3: strictly increasing per serve).
        self.assertGreater(before2["supply"]["snapshot_seq"],
                           before["supply"]["snapshot_seq"])

        s0, s1 = new_secret(), new_secret()
        self.issue(mint, 100_000, s0)
        status, body, _ = self.exchange(
            mint, "dh-stale", [tok(100_000, s0)], [out_hash(99_000, s1)]
        )
        self.assertEqual(status, 200, body)

        _, after, _ = http_json(mint.port, "GET", "/v3/mints")
        self.assertEqual(after["supply"]["cumulative_issued_mc"],
                         before2["supply"]["cumulative_issued_mc"] + 100_000)
        self.assertEqual(after["supply"]["cumulative_burned_mc"],
                         before2["supply"]["cumulative_burned_mc"] + 1_000)
        self.assertEqual(after["supply"]["outstanding_mc"], 99_000)
        self.assertGreater(after["supply"]["snapshot_seq"],
                           before2["supply"]["snapshot_seq"])
        self.assertTrue(verify_obj(after["supply"], mint.pub))
        self.assertEqual(after["activity"]["daily_exchange_count"], 1)

    # ------------------------------------------------------------------
    # 5. an idle timeout is not a request deadline
    # ------------------------------------------------------------------

    def test_request_deadline_is_finite_and_is_the_handler_default(self):
        """A per-recv idle timeout bounds nothing on its own, so there has
        to be a wall-clock ceiling on a whole request as well, and it has
        to be the shipped default rather than something only a test sets."""
        self.assertGreater(MAX_REQUEST_SECONDS, 0)
        self.assertLessEqual(MAX_REQUEST_SECONDS, 120)
        self.assertEqual(_Handler.request_timeout, MAX_REQUEST_SECONDS)
        # The deadline must be the LONGER of the two: otherwise it would be
        # doing the idle timeout's job and cutting slow-but-live clients.
        self.assertGreater(MAX_REQUEST_SECONDS, _Handler.timeout)

    def test_dripped_body_cannot_hold_a_thread_past_the_deadline(self):
        """The cheap version of the exhaustion the socket timeout was added
        for, and the one it does NOT close.

        `_Handler.timeout` is applied per recv, so a client that declares
        exactly MAX_BODY_BYTES (the byte cap never fires) and then sends
        one byte every few seconds resets it on every recv and holds a
        daemon thread and an fd for as long as it keeps dripping — at one
        byte per nine seconds, ~109 days for a single connection, and
        ThreadingHTTPServer caps neither connections nor threads.

        So the drip here is deliberately far FASTER than the idle timeout:
        nothing but a wall-clock deadline on the whole request can end it.
        The shipped ceiling is asserted above; it is clamped here only so
        the test takes a second instead of thirty.
        """
        original = _Handler.request_timeout
        self.assertIsNotNone(original)
        _Handler.request_timeout = 1.0
        self.addCleanup(setattr, _Handler, "request_timeout", original)
        # The idle timeout stays at its shipped value on purpose: if it
        # were what ended this connection the test would prove nothing.
        self.assertGreaterEqual(_Handler.timeout, 5)

        captured = io.StringIO()
        with contextlib.redirect_stderr(captured):
            mint = self.start_mint()
            sock = socket.create_connection(("127.0.0.1", mint.port),
                                            timeout=20.0)
            self.addCleanup(sock.close)
            sock.sendall(
                b"POST /v3/status HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: " + str(MAX_BODY_BYTES).encode("ascii")
                + b"\r\n\r\n"
            )
            started = time.monotonic()
            sock.settimeout(0.1)
            closed = False
            while time.monotonic() - started < 15.0:
                try:
                    sock.sendall(b"{")  # one byte of the declared megabyte
                except OSError:
                    closed = True  # server hung up on us mid-drip
                    break
                try:
                    if sock.recv(65536) == b"":
                        closed = True
                        break
                    # A 400 arrived; drain to EOF and stop.
                    while sock.recv(65536):
                        pass
                    closed = True
                    break
                except TimeoutError:
                    pass
            elapsed = time.monotonic() - started
            time.sleep(0.2)  # let the serving thread unwind
        self.assertTrue(
            closed,
            "a dripped body held the connection (and its thread) open",
        )
        self.assertLess(
            elapsed, 5.0,
            "the request outlived its deadline: %.1fs" % elapsed,
        )
        self.assertNotIn("Traceback", captured.getvalue())
        # And the mint is still serving everyone else.
        st, desc, _ = http_json(mint.port, "GET", "/v3/mints", timeout=8)
        self.assertEqual(st, 200)
        self.assertEqual(desc["mint_id"], MINT_ID)

    def test_body_refusal_reason_is_not_carried_on_handler_state(self):
        """The §3.8 reason for a refused body must be derivable from the
        route, not left on the handler by whoever read the body.

        `_read_json` is overridable — C10's Supervision Profile handler is
        the live subclass — and a subclass cannot be asked to maintain a
        private attribute it has never heard of. While the reason rode on
        one, an inherited Layer 0 route served whatever the class default
        happened to be, so the same wire bytes drew two different §3.8
        reasons depending on profile (L13/B9 forbid exactly that)."""
        self.assertFalse(
            hasattr(_Handler, "_body_error"),
            "the body-refusal reason is out-of-band handler state again; "
            "an overriding subclass will serve a stale default",
        )

    # ------------------------------------------------------------------
    # 6. one ledger file, one mint process (§3.6 monotonicity)
    # ------------------------------------------------------------------

    def _server_on(self, db_path: str) -> MintServer:
        """An unstarted MintServer over `db_path`. Called twice on one path
        it models the deployment slip §3.6 monotonicity has to survive: two
        run_mint.py processes on the same ledger, different ports (the only
        collision run_mint.py can detect today is the port bind)."""
        priv, pub = generate_keypair()
        ledger = Ledger(
            db_path,
            FakeClock(T0),
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
            recovery_window_ms=90 * DAY_MS,
            max_lock_expiry_ms=30 * DAY_MS,
            # Single-writer/flock tests; these mints never issue.
            admin_token=ADMIN_ISSUANCE_DISABLED,
        )
        return MintServer(config, ledger)

    def _shared_ledger_pair(self) -> tuple[MintServer, MintServer]:
        """Two MintServers over ONE sqlite file; the first is serving."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db_path = os.path.join(tmp.name, "ledger.sqlite3")
        first = self._server_on(db_path)
        first.start()
        self.addCleanup(first.stop)
        second = self._server_on(db_path)
        self.addCleanup(second.stop)
        return first, second

    def test_second_mint_on_the_same_ledger_refuses_to_start(self):
        """§3.6 monotonicity is a property of the mint_id and its signing
        key, not of a process.

        Ordering a snapshot's supply read against its seq used to be
        sqlite's job (one BEGIN IMMEDIATE covered both), which held across
        any number of processes sharing the file. Making the descriptor a
        read moved that ordering onto a threading.Lock, which exists once
        per process: two mints on one ledger draw disjoint seq blocks but
        order their supply reads independently, so the one holding the
        higher block can sign a higher seq over an OLDER supply — two
        signed snapshots violating monotonicity, which §3.6 calls portable
        proof of nonconformance against an honest mint. The precondition
        is therefore enforced, not left to DEPLOYMENT.md."""
        first, second = self._shared_ledger_pair()
        with self.assertRaises(RuntimeError) as caught:
            second.start()
        self.assertIn("ledger", str(caught.exception).lower())
        # Refused at the door, so no port was bound and nothing is serving.
        self.assertIsNone(second._httpd)
        # The mint that does hold the ledger is untouched.
        port = first._httpd.server_address[1]
        st, desc, _ = http_json(port, "GET", "/v3/mints", timeout=8)
        self.assertEqual(st, 200)
        self.assertEqual(desc["mint_id"], MINT_ID)

    def test_a_mint_without_the_claim_refuses_to_sign_a_snapshot(self):
        """Enforced where the guarantee lives, not only at start().

        A server class that binds its own socket without going through
        MintServer.start (C10's SupervisionServer does exactly that) would
        otherwise sign snapshots with no claim at all, so the descriptor
        re-checks it: a mint that cannot hold the ledger declines to sign
        rather than signing something that may be §3.6 proof of
        nonconformance against its own key."""
        _, second = self._shared_ledger_pair()
        with self.assertRaises(RuntimeError):
            second._core.descriptor()  # start() bypassed entirely

    def test_the_claim_is_released_so_a_restart_can_take_it(self):
        """A stopped mint must hand the ledger back: a single-writer guard
        that outlived its process would turn every restart into an
        outage."""
        first, second = self._shared_ledger_pair()
        with self.assertRaises(RuntimeError):
            second.start()
        first.stop()
        port = second.start()  # must not raise now
        st, desc, _ = http_json(port, "GET", "/v3/mints", timeout=8)
        self.assertEqual(st, 200)
        self.assertEqual(desc["mint_id"], MINT_ID)

    # ------------------------------------------------------------------
    # 7. a GET body is never consumed, so it must not be reusable
    # ------------------------------------------------------------------

    def test_get_with_a_declared_body_cannot_frame_a_second_request(self):
        """`do_GET` reads no body, so a GET that declares one leaves octets
        on the wire. Held open, a keep-alive peer or a pipelining proxy
        parses them as the next request line — request N's body becomes
        request N+1. Same desync the POST path closes; the GET itself is a
        legal §3.7 anonymous read, so it is answered and then hung up on,
        not rejected."""
        mint = self.start_mint()
        smuggled = b'{"x":1}GET /v3/status/smuggled HTTP/1.1\r\nHost: h\r\n\r\n'
        request = (
            b"GET /v3/mints HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Length: 7\r\n"
            b"\r\n" + smuggled
        )
        raw = raw_request(mint.port, request, timeout=8.0)
        status, headers, body = parse_http(raw)
        self.assertEqual(status, 200)
        self.assertEqual(body["mint_id"], MINT_ID)
        self.assertEqual(headers.get("connection"), "close")
        # Exactly one answer came back: the smuggled line was never served.
        self.assertEqual(raw.count(b"HTTP/1.1 "), 1, raw[:400])
        self.assertNotIn(b"smuggled", raw)


class ScheduledBurnChangeDoesNotBreakTheFleetTest(unittest.TestCase):
    """§7.3's change notice, end to end, through a real wallet.

    The descriptor publishes `burn_policy_next` and every reference client
    switches policy the instant `mint_time` reaches `effective_at`
    (burncalc.effective_policy — wallet, channels, swap and escrow all do
    it). The Ledger was built from `config.burn_policy` alone and held it
    forever, so from `effective_at` onwards the mint and its whole fleet
    disagreed about §3.3 step 1: every client-built exchange failed
    `amount_mismatch`, a plain receive of a freshly issued token included.
    An honest operator using the documented mechanism, exactly as
    documented, broke its own mint. Reproduced by outside review
    2026-09-16; this is that reproduction.
    """

    CURRENT = BurnPolicy(rate_ppm=1_000, cap_mc=1_000, exempt_below_mc=10)
    ANNOUNCED = BurnPolicy(rate_ppm=5_000, cap_mc=1_000, exempt_below_mc=10)
    # Default max_lock_expiry_ms is 30 days, and §7.3 wants max(7 days,
    # lock horizon) of notice for an increase — so a conforming notice here
    # is 30 days, not 7.
    EFFECTIVE_AT = T0 + 31 * DAY_MS

    def scheduled_mint(self, clock):
        priv, pub = generate_keypair()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        config = MintConfig(
            mint_id=MINT_ID,
            baseline_model_class="frontier-2026",
            burn_policy=self.CURRENT,
            burn_policy_next=(self.ANNOUNCED, self.EFFECTIVE_AT),
            burn_policy_announced_at=T0,
            signing_private=priv,
            signing_public=pub,
            admin_token=HARNESS_ADMIN_TOKEN,
        )
        from aicash.mintapi import make_mint

        server, ledger = make_mint(
            config, os.path.join(tmp.name, "ledger.sqlite3"), clock=clock
        )
        port = server.start()
        self.addCleanup(server.stop)
        return port, ledger, tmp.name

    def funded_token(self, ledger, amount_mc):
        secret = new_secret()
        ledger.issue([{"amount_mc": amount_mc, "secret_hash": ledger_key(secret)}])
        return format_token(MINT_ID, amount_mc, secret)

    def test_a_wallet_can_still_receive_and_pay_after_the_change_lands(self):
        """Thalamus's scenario: schedule the change, advance the mint clock
        past effective_at, and a plain receive and a plain pay must both
        still work — at the NEW policy, which is the one the descriptor
        advertises at that instant."""
        from aicash.wallet import MintClient, Wallet

        clock = FakeClock(T0)
        port, ledger, tmpdir = self.scheduled_mint(clock)
        token = self.funded_token(ledger, 100_000)

        clock.set(self.EFFECTIVE_AT + DAY_MS)  # the change is in force

        wallet = Wallet(
            os.path.join(tmpdir, "wallet.sqlite3"),
            MintClient("http://127.0.0.1:%d" % port),
            MINT_ID,
        )
        # 0.5% of 100_000 = 500 under the ANNOUNCED policy (0.1% -> 100
        # under the superseded one, which is what the ledger used to charge)
        credited = wallet.receive(token)
        self.assertEqual(credited, 100_000 - 500)
        self.assertEqual(wallet.balance(), 99_500)

        paid = wallet.pay(1_000)
        self.assertEqual(sum(int(t.split(":")[3]) for t in paid), 1_000)

    def test_before_the_change_the_old_policy_is_the_one_charged(self):
        """The other side of the same clock: nothing flips early."""
        from aicash.wallet import MintClient, Wallet

        clock = FakeClock(T0)
        port, ledger, tmpdir = self.scheduled_mint(clock)
        token = self.funded_token(ledger, 100_000)
        wallet = Wallet(
            os.path.join(tmpdir, "wallet.sqlite3"),
            MintClient("http://127.0.0.1:%d" % port),
            MINT_ID,
        )
        self.assertEqual(wallet.receive(token), 100_000 - 100)  # 0.1%

    def test_the_ledger_and_the_descriptor_agree_at_every_instant(self):
        """State it as the invariant, not as two numbers that happen to
        match: whatever burn the descriptor's effective policy implies for
        a sum is the burn the ledger charges for it, at the instant before
        the flip and at the instant of the flip."""
        from aicash.burncalc import compute_burn, effective_policy

        clock = FakeClock(T0)
        port, ledger, _ = self.scheduled_mint(clock)
        for when in (T0, self.EFFECTIVE_AT - 1, self.EFFECTIVE_AT,
                     self.EFFECTIVE_AT + 10**6):
            with self.subTest(when=when):
                clock.set(when)
                _status, desc, _ = http_json(port, "GET", "/v3/mints")
                bp = desc["burn_policy"]
                nxt = desc["burn_policy_next"]
                published = effective_policy(
                    BurnPolicy(**bp),
                    (BurnPolicy(**nxt["policy"]), nxt["effective_at"]),
                    desc["mint_time"],
                )
                expected = compute_burn(10_000, published)
                secret = new_secret()
                ledger.issue([
                    {"amount_mc": 10_000, "secret_hash": ledger_key(secret)}
                ])
                out = new_secret()
                status, body, _ = http_json(
                    port, "POST", "/v3/exchange",
                    {
                        "idempotency_key": "agree-%d" % when,
                        "inputs": [tok(10_000, secret)],
                        "outputs": [out_hash(10_000 - expected, out)],
                    },
                )
                self.assertEqual(status, 200, body)
                self.assertEqual(body["burn_mc"], expected)

    def test_a_mint_started_after_the_flip_still_boots_and_prices_the_new_policy(self):
        """The boot-time config/ledger consistency check compares
        CONFIGURATION to CONFIGURATION, so it must keep passing for a mint
        whose clock is already past `effective_at` — `Ledger.burn_policy`
        stays the configured value for the object's whole life, and the
        instant-dependent answer lives in `effective_burn_policy(now)`.
        Pinned because collapsing the two (making `burn_policy` itself
        follow the clock) looks like a tidy fix and would make a mint
        started after its own announced change refuse to boot."""
        clock = FakeClock(self.EFFECTIVE_AT + DAY_MS)
        port, ledger, _ = self.scheduled_mint(clock)  # boots, or this raises
        self.assertEqual(ledger.burn_policy, self.CURRENT)
        self.assertEqual(ledger.burn_policy_next,
                         (self.ANNOUNCED, self.EFFECTIVE_AT))
        self.assertEqual(ledger.effective_burn_policy(clock()), self.ANNOUNCED)

        secret = new_secret()
        ledger.issue([{"amount_mc": 10_000, "secret_hash": ledger_key(secret)}])
        out = new_secret()
        status, body, _ = http_json(
            port, "POST", "/v3/exchange",
            {
                "idempotency_key": "post-flip-boot",
                "inputs": [tok(10_000, secret)],
                "outputs": [out_hash(10_000 - 50, out)],  # 0.5% announced
            },
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(body["burn_mc"], 50)

    def test_the_mint_side_answer_to_what_does_a_call_cost_is_public(self):
        """A mint-side caller that pre-computes a burn before calling
        `ledger.exchange` (C10's supervision profile does, for deposit and
        withdraw) must be able to ask the ledger what it will charge,
        rather than reading the frozen private `_burn_policy` or
        re-assembling the selection rule from the two published halves.
        `Ledger.effective_burn_policy(now)` is that accessor, and a caller
        using it agrees with the conservation check on both sides of the
        flip."""
        from aicash.burncalc import compute_burn

        clock = FakeClock(T0)
        port, ledger, _ = self.scheduled_mint(clock)
        for when, expected in ((T0, 10), (self.EFFECTIVE_AT, 50)):
            with self.subTest(when=when):
                clock.set(when)
                # exactly the shape of a mint-side pre-computing caller
                burn = compute_burn(10_000, ledger.effective_burn_policy(clock()))
                self.assertEqual(burn, expected)
                secret = new_secret()
                ledger.issue([
                    {"amount_mc": 10_000, "secret_hash": ledger_key(secret)}
                ])
                out = new_secret()
                status, body, _ = http_json(
                    port, "POST", "/v3/exchange",
                    {
                        "idempotency_key": "mintside-%d" % when,
                        "inputs": [tok(10_000, secret)],
                        "outputs": [out_hash(10_000 - burn, out)],
                    },
                )
                self.assertEqual(status, 200, body)
                self.assertEqual(body["burn_mc"], burn)


class BurnChangeNoticeIsValidatedTest(unittest.TestCase):
    """§7.3: "a burn increase MUST be pre-announced ... at least 7 days (or
    the mint's max_lock_expiry_ms, whichever is longer) before
    effective_at".

    burncalc has carried `validate_notice` since C03 and no configuration
    path ever called it, so a mint could be constructed — and would publish
    in its descriptor as a conforming §7.3 notice — an increase taking
    effect a hundred seconds from its announcement. Found by outside review
    2026-09-16.
    """

    LOW = BurnPolicy(rate_ppm=1_000, cap_mc=1_000, exempt_below_mc=10)
    HIGH = BurnPolicy(rate_ppm=5_000, cap_mc=1_000, exempt_below_mc=10)

    def make_config(self, **kw):
        priv, pub = generate_keypair()
        defaults = dict(
            mint_id=MINT_ID,
            baseline_model_class="frontier-2026",
            burn_policy=self.LOW,
            signing_private=priv,
            signing_public=pub,
            admin_token=ADMIN_ISSUANCE_DISABLED,
        )
        defaults.update(kw)
        return MintConfig(**defaults)

    def test_a_hundred_second_notice_on_an_increase_is_refused(self):
        with self.assertRaises(ValueError) as ctx:
            self.make_config(
                burn_policy_next=(self.HIGH, T0 + 100_000),
                burn_policy_announced_at=T0,
            )
        self.assertIn("notice", str(ctx.exception))

    def test_seven_days_is_not_enough_when_locks_run_longer(self):
        """The rule is max(7 days, max_lock_expiry_ms) — funds locked
        mid-flight must not be repriced by surprise."""
        with self.assertRaises(ValueError):
            self.make_config(
                max_lock_expiry_ms=30 * DAY_MS,
                burn_policy_next=(self.HIGH, T0 + 7 * DAY_MS),
                burn_policy_announced_at=T0,
            )
        self.make_config(  # the lock horizon's worth of notice is enough
            max_lock_expiry_ms=30 * DAY_MS,
            burn_policy_next=(self.HIGH, T0 + 30 * DAY_MS),
            burn_policy_announced_at=T0,
        )

    def test_seven_days_is_enough_when_there_are_no_locks_to_protect(self):
        with self.assertRaises(ValueError):
            self.make_config(
                max_lock_expiry_ms=None,
                burn_policy_next=(self.HIGH, T0 + 7 * DAY_MS - 1),
                burn_policy_announced_at=T0,
            )
        self.make_config(
            max_lock_expiry_ms=None,
            burn_policy_next=(self.HIGH, T0 + 7 * DAY_MS),
            burn_policy_announced_at=T0,
        )

    def test_an_increase_without_an_announcement_time_is_refused(self):
        """The interval is unmeasurable without it, and silently skipping
        the check is how it came to be unmeasured for seven rounds. The
        message says what to set and that a decrease needs none."""
        with self.assertRaises(ValueError) as ctx:
            self.make_config(burn_policy_next=(self.HIGH, T0 + 365 * DAY_MS))
        message = str(ctx.exception)
        self.assertIn("burn_policy_announced_at", message)
        self.assertIn("7 days", message)
        self.assertIn("DECREASE", message)

    def test_a_decrease_may_be_immediate_and_needs_no_announcement(self):
        """§7.3: "Decreases may be immediate." A mint lowering its burn
        must not be made to wait a month to do it."""
        config = self.make_config(
            burn_policy=self.HIGH, burn_policy_next=(self.LOW, T0)
        )
        self.assertEqual(config.burn_policy_next, (self.LOW, T0))

    def test_an_announcement_time_announcing_nothing_is_refused(self):
        with self.assertRaises(ValueError) as ctx:
            self.make_config(burn_policy_announced_at=T0)
        self.assertIn("burn_policy_next", str(ctx.exception))

    def test_the_announcement_time_must_be_a_plain_int_of_ms(self):
        for bad in ("yesterday", -1, 1.0, True):
            with self.subTest(bad=bad):
                with self.assertRaises((ValueError, TypeError)):
                    self.make_config(
                        burn_policy_next=(self.HIGH, T0 + 365 * DAY_MS),
                        burn_policy_announced_at=bad,
                    )

    def test_a_conforming_notice_reaches_the_descriptor(self):
        """The point of the refusal is that what IS published conforms."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        from aicash.mintapi import make_mint

        config = self.make_config(
            max_lock_expiry_ms=30 * DAY_MS,
            burn_policy_next=(self.HIGH, T0 + 30 * DAY_MS),
            burn_policy_announced_at=T0,
        )
        server, _ledger = make_mint(
            config, os.path.join(tmp.name, "l.sqlite3"), clock=FakeClock(T0)
        )
        port = server.start()
        self.addCleanup(server.stop)
        _status, desc, _ = http_json(port, "GET", "/v3/mints")
        self.assertEqual(
            desc["burn_policy_next"],
            {
                "policy": {"rate_ppm": 5_000, "cap_mc": 1_000,
                           "exempt_below_mc": 10},
                "effective_at": T0 + 30 * DAY_MS,
            },
        )
        # announced_at is config, not a §3.6 field: a restarted mint must
        # be able to re-state a notice it gave a month ago without the
        # notice period starting over.
        self.assertNotIn("burn_policy_announced_at", desc)


class BodyThisLayerCannotReadIsRefusedAndFramedTest(
    MintHarness, unittest.TestCase
):
    """Two ways a POST body defeats the reader, both of which used to leave
    the mint in a worse state than a rejection. Found by outside review
    2026-09-16, one of them visible in the mint's own access log.
    """

    def test_a_chunked_post_cannot_frame_a_second_request(self):
        """D1: `Transfer-Encoding: chunked` with no Content-Length.

        The reader sized the body from Content-Length alone, so it read the
        chunked POST as EMPTY, answered 400 — and did not hang up. The chunk
        octets stayed on the keep-alive socket and were parsed as the start
        of the next request: the access log showed three entries where there
        should have been two, the middle one a phantom with method None. The
        GET path has always carried this guard (`_close_if_body_goes_unread`
        checks Transfer-Encoding explicitly); the POST path now applies the
        same one.
        """
        mint = self.start_mint()
        body = json.dumps(
            {"idempotency_key": "chunked-1", "inputs": [], "outputs": []}
        ).encode()
        chunked = b"%x\r\n%s\r\n0\r\n\r\n" % (len(body), body)
        request = (
            b"POST /v3/exchange HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Type: application/json\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n" + chunked
        )
        raw = raw_request(mint.port, request, timeout=8.0)
        status, headers, parsed = parse_http(raw)
        self.assertEqual(status, 400)
        self.assertEqual(
            parsed,
            {"status": "rejected",
             "errors": [{"index": None, "kind": "call",
                         "reason": "bad_format"}]},
        )
        self.assertEqual(headers.get("connection"), "close")
        # Exactly one answer: no phantom request was framed out of the
        # chunk octets the server never read.
        self.assertEqual(raw.count(b"HTTP/1.1 "), 1, raw[:400])
        self.assertNotIn(b"Bad request syntax", raw)

    def test_a_chunked_post_to_every_post_route_is_refused_the_same_way(self):
        """One rule, not one route's rule: §3.8 reasons are a property of
        the request, and /v3/status and /admin/issue frame bodies off the
        same socket."""
        mint = self.start_mint()
        for path in ("/v3/exchange", "/v3/status"):
            with self.subTest(path=path):
                request = (
                    b"POST " + path.encode() + b" HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\n"
                    b"Transfer-Encoding: chunked\r\n"
                    b"\r\n5\r\nhello\r\n0\r\n\r\n"
                )
                raw = raw_request(mint.port, request, timeout=8.0)
                status, headers, parsed = parse_http(raw)
                self.assertEqual(status, 400)
                self.assertEqual(parsed["errors"][0]["reason"], "bad_format")
                self.assertEqual(headers.get("connection"), "close")
                self.assertEqual(raw.count(b"HTTP/1.1 "), 1, raw[:400])

    def test_duplicate_content_length_cannot_frame_a_request(self):
        """The CL.CL smuggling pair, on Layer 0.

        ``self.headers.get("Content-Length")`` silently returns the FIRST
        of a duplicated header, so `2` then `46` made the reader take two
        octets off /v3/exchange and leave forty-four on a keep-alive socket
        to be framed as the next request line: one request in, TWO
        responses out. C10 closed this door in its own reader; Layer 0 kept
        it open for another round, which is exactly why the verdict is now
        one shared method.

        Both orderings are sent, so a "take the LAST value" fix fails here
        too, and the single-header comma spelling is checked as well.
        """
        mint = self.start_mint()
        smuggled = (
            b'{"idempotency_key":"smuggle","inputs":[],"outputs":[]}'
        )
        shapes = {
            "low-then-high": b"Content-Length: 2\r\nContent-Length: %d\r\n"
                             % len(smuggled),
            "high-then-low": b"Content-Length: %d\r\nContent-Length: 2\r\n"
                             % len(smuggled),
            "one-header-comma": b"Content-Length: 2, %d\r\n" % len(smuggled),
        }
        for name, cl in shapes.items():
            with self.subTest(name):
                request = (
                    b"POST /v3/exchange HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\n"
                    b"Content-Type: application/json\r\n"
                    + cl +
                    b"\r\n" + smuggled +
                    b"GET /v3/mints HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
                )
                raw = raw_request(mint.port, request, timeout=8.0)
                status, headers, parsed = parse_http(raw)
                self.assertEqual(status, 400)
                self.assertEqual(
                    parsed["errors"][0]["reason"], "bad_format", parsed
                )
                self.assertEqual(headers.get("connection"), "close")
                # THE assertion: one request accepted, one answer given.
                self.assertEqual(raw.count(b"HTTP/1.1 "), 1, raw[:400])
                self.assertNotIn(b"mint_id", raw)

    def test_duplicate_content_length_cannot_frame_a_request_on_a_GET(self):
        """The GET guard has its own version of the same hole, and it is
        the nastier spelling: `Content-Length: 0` followed by
        `Content-Length: 46`. ``headers.get`` returns the FIRST, so the
        guard concluded there was no body to go unread at all, kept the
        connection, and the 46 octets behind it were framed as the next
        request. The verdict moved into ``_body_framing_is_unreadable``
        precisely so the GET side inherits it rather than needing its own
        copy."""
        mint = self.start_mint()
        request = (
            b"GET /v3/mints HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Length: 0\r\nContent-Length: 46\r\n\r\n"
            + b"a" * 46 +
            b"GET /v3/mints HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        )
        raw = raw_request(mint.port, request, timeout=8.0)
        # The GET itself is well formed and §3.7 says anyone may make it,
        # so it is ANSWERED -- and then the socket is dropped rather than
        # reused for octets we never read.
        self.assertEqual(raw.count(b"HTTP/1.1 "), 1, raw[:400])
        status, headers, _ = parse_http(raw)
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("connection"), "close")

    def test_a_single_content_length_still_frames_a_keep_alive_request(self):
        """The guard costs ordinary pipelining nothing: two well-formed
        POSTs on one connection still get two answers."""
        mint = self.start_mint()
        def post(key):
            body = json.dumps(
                {"idempotency_key": key, "inputs": [], "outputs": []}
            ).encode()
            return (
                b"POST /v3/exchange HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: %d\r\n\r\n" % len(body)
            ) + body
        raw = raw_request(
            mint.port, post("keep-1") + post("keep-2"),
            shutdown_write=True, timeout=8.0,
        )
        self.assertEqual(raw.count(b"HTTP/1.1 "), 2, raw[:600])
        self.assertNotIn(b"HTTP/1.1 400", raw)

    def test_the_framing_rule_is_one_rule_shared_with_the_get_guard(self):
        """The GET guard already knew that Transfer-Encoding means an
        unreadable body. A second, separately-worded copy on the POST side
        is how the two drift apart again, so both ask the same rule.

        RETARGETED this round, and strengthened. The assertion was that
        both methods name ``_body_framing_is_unreadable``; the GET guard
        named it in a docstring while its CODE hand-wrote
        ``FramingVerdict.must_close``'s definition out in two clauses. Both
        halves now reach ``_framing_verdict`` -- the one method that turns
        a header block into a decision -- and each takes the field it needs
        off the object it returns, so "the same rule" is a fact about the
        code and not about the prose.
        """
        guard = inspect.getsource(
            _Handler._close_if_body_goes_unread).split('"""')[-1]
        reader = inspect.getsource(_Handler._read_json).split('"""')[-1]
        self.assertIn("_framing_verdict", guard)
        self.assertIn("must_close", guard)
        self.assertIn("_body_framing_is_unreadable", reader)
        self.assertIn(
            "_framing_verdict",
            inspect.getsource(_Handler._framed_body_length).split('"""')[-1],
        )

    def test_an_oversized_numeric_literal_is_bad_format_not_500(self):
        """D2: a body that is valid UTF-8 and valid JSON whose `amount_mc`
        is a 5,000-digit integer. CPython's int-string digit limit makes
        int() raise a PLAIN ValueError out of json.loads — not a
        JSONDecodeError — and the reader caught only UnicodeDecodeError and
        JSONDecodeError, so it escaped to the 500 handler. §3.8 owes an
        enumerated reason; a bare 500 is not one."""
        mint = self.start_mint()
        body = (
            b'{"idempotency_key":"big","inputs":[],"outputs":'
            b'[{"amount_mc":' + b"1" * 5_000 + b',"secret_hash":"x"}]}'
        )
        status, raw, _ = http_raw(
            mint.port, "POST", "/v3/exchange", body,
            {"Content-Type": "application/json"},
        )
        self.assertEqual(status, 400)
        self.assertEqual(
            json.loads(raw.decode("utf-8")),
            {"status": "rejected",
             "errors": [{"index": None, "kind": "call",
                         "reason": "bad_format"}]},
        )

    def test_a_literal_the_parser_can_still_read_is_handled_normally(self):
        """The boundary is CPython's limit, not "a big number", and the
        widened handling must not swallow bodies the parser CAN read: a
        4,299-digit amount still parses, and is then refused by a MONEY
        rule at its own index rather than as a malformed envelope.

        WHICH money rule moved this round, and the move is the point. It
        used to be §3.3 conservation, at call level: an amount no entry
        could hold reached the ledger, could not balance against zero
        inputs, and came back `amount_mismatch`. That was the accident
        that hid a real defect — the SAME value through `/admin/issue`
        has no inputs and therefore no conservation to catch it, so it
        bound 9999999999999999999 straight into sqlite and answered a
        bare 500 with no `errors` list at all (§3.8 owes an enumerated
        reason, always). C04 now bounds an output amount to what the
        column holds, at the one place both routes resolve an output, so
        the answer here is `bad_format` at output index 0: the amount is
        malformed, not merely unbalanced, and it is said the same way on
        both routes.

        Both halves are asserted below, because "handled normally" means
        an enumerated per-index answer AND that conservation itself still
        works for an amount the ledger CAN hold.
        """
        mint = self.start_mint()
        body = (
            b'{"idempotency_key":"big-ok","inputs":[],"outputs":'
            b'[{"amount_mc":' + b"1" * 4_299 + b',"secret_hash":"'
            + ledger_key(new_secret()).encode() + b'"}]}'
        )
        status, raw, _ = http_raw(
            mint.port, "POST", "/v3/exchange", body,
            {"Content-Type": "application/json"},
        )
        self.assertEqual(status, 400)
        errors = json.loads(raw.decode("utf-8"))["errors"]
        self.assertEqual([e["reason"] for e in errors], ["bad_format"])
        # PER-INDEX, not call level: the body was read and this one entry
        # was judged, which is what "the parser can still read it" means.
        self.assertEqual(errors[0]["kind"], "output")
        self.assertEqual(errors[0]["index"], 0)
        # ...and the conservation rule this test used to land on is still
        # there, reached by an amount the ledger can actually store.
        storable = json.dumps({
            "idempotency_key": "big-ok-2",
            "inputs": [],
            "outputs": [{"amount_mc": (1 << 62),
                         "secret_hash": ledger_key(new_secret())}],
        }).encode()
        status, raw, _ = http_raw(
            mint.port, "POST", "/v3/exchange", storable,
            {"Content-Type": "application/json"},
        )
        self.assertEqual(status, 400)
        errors = json.loads(raw.decode("utf-8"))["errors"]
        self.assertEqual([e["reason"] for e in errors], ["amount_mismatch"])
        self.assertEqual(errors[0]["kind"], "call")

    def test_a_deeply_nested_body_is_bad_format_not_500(self):
        """The same uncaught shape one level up, found looking for it: a
        200 KB body of nothing but `[` blows the JSON parser's stack with a
        RecursionError, which is not a ValueError at all. Well inside
        MAX_BODY_BYTES, so nothing else stopped it either."""
        mint = self.start_mint()
        body = b"[" * 100_000 + b"]" * 100_000
        self.assertLess(len(body), MAX_BODY_BYTES)
        status, raw, _ = http_raw(
            mint.port, "POST", "/v3/exchange", body,
            {"Content-Type": "application/json"},
        )
        self.assertEqual(status, 400)
        self.assertEqual(
            json.loads(raw.decode("utf-8"))["errors"][0]["reason"],
            "bad_format",
        )

    def test_the_mint_still_serves_after_each_of_them(self):
        """A refusal is not a wound: the server takes the next request."""
        mint = self.start_mint()
        for body in (
            b'{"amount_mc":' + b"1" * 5_000 + b"}",
            b"[" * 100_000 + b"]" * 100_000,
            b"{not json",
        ):
            http_raw(mint.port, "POST", "/v3/exchange", body,
                     {"Content-Type": "application/json"})
        status, desc, _ = http_json(mint.port, "GET", "/v3/mints")
        self.assertEqual(status, 200)
        self.assertEqual(desc["mint_id"], MINT_ID)

    def test_no_traceback_reaches_any_of_those_callers(self):
        """Requirement 4, restated over the bodies that used to 500."""
        mint = self.start_mint()
        for body in (
            b'{"amount_mc":' + b"1" * 5_000 + b"}",
            b"[" * 100_000 + b"]" * 100_000,
        ):
            _status, raw, _ = http_raw(
                mint.port, "POST", "/v3/exchange", body,
                {"Content-Type": "application/json"},
            )
            self.assertNotIn(b"Traceback", raw)
            self.assertNotIn(b"aicash/", raw)


class FramingDoesNotDependOnSpellingAHeaderTest(
    MintHarness, unittest.TestCase
):
    """D1's variation: the fix that named a header, and the class it missed.

    The first fix asked ``self.headers`` for ``Transfer-Encoding``. Python's
    email parser does not register ``Transfer-Encoding : chunked`` — one
    space before the colon — as a field AT ALL, so the lookup returned
    None, the framing check saw neither a transfer coding nor a
    Content-Length, defaulted the body to zero octets, never read the chunk
    data, answered 400 WITHOUT ``Connection: close``, and the chunk octets
    were then framed as the next request line: a second response on the
    socket for one request, with no status line on it at all, and two
    access-log entries for one request, the second with a null method. RFC
    7230 §3.2.4 requires a server to REJECT whitespace before the colon for
    exactly this reason. ``Transfer_Encoding:`` did the same by a different
    road, and front ends that normalise ``_`` to ``-`` make it likelier
    than the spaced spelling, not more exotic.

    Adding those two spellings to the lookup would have been the same
    mistake one level down. The rule is now derived from the length the
    server can COMPUTE (``_framed_body_length``): a request whose body this
    layer was about to read, carrying no Content-Length it can parse, is
    unframable whatever the reason — including a reason nobody has thought
    of. That property is checked below over every spelling anyone has
    produced so far, and the point of stating it this way is that the list
    below is evidence, not the specification.
    """

    def assert_refused_and_hung_up(self, port, request, *, path="/v3/exchange"):
        """One answer, an announced close, and no second payload.

        The trailing GET is the smuggle: if the server keeps the connection
        after failing to read the body, the unread octets are framed as a
        request line and something ELSE appears on the wire — either a
        second HTTP response or the stdlib's status-line-less "Bad request
        syntax" page (HTTP/0.9 fallback, which is why counting status lines
        alone was not enough to see this).
        """
        raw = raw_request(port, request, timeout=8.0)
        status, headers, parsed = parse_http(raw)
        self.assertEqual(status, 400, raw[:400])
        self.assertEqual(
            parsed["errors"][0]["reason"], "bad_format", parsed
        )
        self.assertEqual(headers.get("connection"), "close", raw[:400])
        self.assertEqual(raw.count(b"HTTP/1."), 1, raw[:400])
        self.assertNotIn(b"Bad request syntax", raw)
        self.assertNotIn(b"<!DOCTYPE HTML>", raw)
        self.assertNotIn(b"mint_id", raw)  # the smuggled GET never answered

    # -- the reported spelling, its variations, and its neighbours -------

    SMUGGLE = (
        b"GET /v3/mints HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
    )

    def chunked_post(self, header_line, path=b"/v3/exchange"):
        body = json.dumps(
            {"idempotency_key": "te", "inputs": [], "outputs": []}
        ).encode()
        return (
            b"POST " + path + b" HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Type: application/json\r\n"
            + header_line +
            b"\r\n"
            b"%x\r\n%s\r\n0\r\n\r\n" % (len(body), body)
        ) + self.SMUGGLE

    def test_every_spelling_of_a_transfer_coded_post_is_refused_and_closed(self):
        """The reported one, the two the verifier found, and the ones found
        by asking what else the parser does with a field name."""
        spellings = {
            # Already held before this round; must not regress.
            "canonical": b"Transfer-Encoding: chunked\r\n",
            "lowercase": b"transfer-encoding: chunked\r\n",
            "tab-separated value": b"Transfer-Encoding:\tchunked\r\n",
            "obsolete line folding": b"Transfer-Encoding: \r\n chunked\r\n",
            "identity then chunked":
                b"Transfer-Encoding: identity, chunked\r\n",
            "chunked beside a zero length":
                b"Transfer-Encoding: chunked\r\nContent-Length: 0\r\n",
            # THE REPORTED VARIATION and its family: the parser registers
            # no field at all, so no lookup by name can ever see them.
            "one space before the colon":
                b"Transfer-Encoding : chunked\r\n",
            "two spaces before the colon":
                b"Transfer-Encoding  : chunked\r\n",
            "a tab before the colon": b"Transfer-Encoding\t: chunked\r\n",
            "no colon at all": b"Transfer-Encoding chunked\r\n",
            # Registered, but under a name the lookup does not ask for.
            # A front end that normalises `_` to `-` has already dechunked.
            "underscore": b"Transfer_Encoding: chunked\r\n",
            "dot": b"Transfer.Encoding: chunked\r\n",
            # Not a header the mint knows at all: the class says the
            # verdict must not depend on recognising the name.
            "a name nobody has reserved yet":
                b"X-Body-Framing-2031: chunked\r\n",
        }
        mint = self.start_mint()
        for name, header_line in spellings.items():
            with self.subTest(name):
                self.assert_refused_and_hung_up(
                    mint.port, self.chunked_post(header_line)
                )

    def test_the_same_spellings_are_refused_on_every_post_route(self):
        """§3.8 reasons are a property of the request, and /v3/status frames
        its body off the same socket /v3/exchange does."""
        mint = self.start_mint()
        for path in (b"/v3/exchange", b"/v3/status"):
            for header_line in (b"Transfer-Encoding : chunked\r\n",
                                b"Transfer_Encoding: chunked\r\n"):
                with self.subTest(path=path, header=header_line):
                    self.assert_refused_and_hung_up(
                        mint.port, self.chunked_post(header_line, path)
                    )

    def test_a_stated_length_beside_a_dropped_framing_header_is_refused(self):
        """The hole the length rule ALONE left, found by sweeping this fix
        rather than by re-reading the report.

        ``Content-Length: 57`` beside ``Transfer-Encoding : chunked`` passes
        every length clause: the length is single, parseable, honest, and
        the transfer coding is invisible to the parser. So the body framed
        cleanly, the connection stayed pooled, and the pipelined request
        behind it was answered — the CL.TE half of the same smuggling pair,
        still open after the header-name lookup had been replaced by a
        length rule. A header block the parser could not read WHOLE is now
        the precondition on every length it computes: no defect, no obsolete
        folding, or there is no length at all.
        """
        mint = self.start_mint()
        body = json.dumps(
            {"idempotency_key": "cl-te", "inputs": [], "outputs": []}
        ).encode()
        hidden = {
            "spaced transfer-encoding":
                b"Transfer-Encoding : chunked\r\n",
            "tabbed transfer-encoding":
                b"Transfer-Encoding\t: chunked\r\n",
            "a colonless line": b"Transfer-Encoding chunked\r\n",
            "folded onto the line above": b" Transfer-Encoding: chunked\r\n",
        }
        for name, header_line in hidden.items():
            with self.subTest(name):
                request = (
                    b"POST /v3/exchange HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Content-Length: %d\r\n" % len(body)
                    + header_line + b"\r\n" + body + self.SMUGGLE
                )
                self.assert_refused_and_hung_up(mint.port, request)

    def test_a_get_whose_header_block_did_not_parse_whole_hangs_up(self):
        """The GET side of the same precondition. A GET reads no body, so
        the request is ANSWERED (§3.7 says anyone may make it) and THEN the
        socket is dropped — without this, `GET` + a spaced Transfer-Encoding
        answered 200, kept the connection, and framed the chunk octets as
        the next request line: the reporter's two-log-lines-for-one-request
        symptom, on the route that reads nothing at all."""
        mint = self.start_mint()
        body = b'{"x":1}'
        chunked = b"%x\r\n%s\r\n0\r\n\r\n" % (len(body), body)
        for name, header_line in {
            "spaced transfer-encoding": b"Transfer-Encoding : chunked\r\n",
            "spaced content-length": b"Content-Length : 7\r\n",
            "folded onto the line above": b" Transfer-Encoding: chunked\r\n",
        }.items():
            with self.subTest(name):
                request = (
                    b"GET /v3/mints HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\n"
                    + header_line + b"\r\n" + chunked + self.SMUGGLE
                )
                raw = raw_request(mint.port, request, timeout=8.0)
                status, headers, _ = parse_http(raw)
                self.assertEqual(status, 200, raw[:300])
                self.assertEqual(headers.get("connection"), "close", raw[:300])
                self.assertEqual(raw.count(b"HTTP/1."), 1, raw[:400])
                self.assertNotIn(b"Bad request syntax", raw)

    def test_a_post_that_states_no_length_at_all_is_unframable(self):
        """The class rule itself, with no misspelled header in sight.

        A POST carrying a body and no Content-Length is not "a POST with an
        empty body": it is a POST whose framing was never stated, which is
        what every dropped, misspelled or front-end-rewritten framing header
        degrades into by the time this parser is done with it. The server
        cannot tell the two apart, so it refuses to reuse the connection
        either way — and that, not any list of header names, is what closes
        the spellings above.
        """
        mint = self.start_mint()
        body = json.dumps(
            {"idempotency_key": "nolen", "inputs": [], "outputs": []}
        ).encode()
        request = (
            b"POST /v3/exchange HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Type: application/json\r\n"
            b"\r\n" + body + self.SMUGGLE
        )
        self.assert_refused_and_hung_up(mint.port, request)

    def test_a_post_with_no_length_and_no_body_is_closed_too(self):
        """Even with nothing behind it. The server does not get to decide
        after the fact that there was no body: it never knew."""
        mint = self.start_mint()
        request = (
            b"POST /v3/exchange HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Type: application/json\r\n"
            b"\r\n" + self.SMUGGLE
        )
        self.assert_refused_and_hung_up(mint.port, request)

    # -- the neighbouring field: Content-Length itself -------------------

    def test_content_length_is_read_the_way_http_defines_it(self):
        """``int()`` is a LOOSER parser than RFC 7230 §3.3.2's ``1*DIGIT``.

        It accepts a leading sign, PEP 515 underscore separators, and
        surrounding whitespace, so ``Content-Length: +53`` and
        ``Content-Length: 5_3`` both read as 53 HERE while an intermediary
        reads them as malformed or as nothing — a length two parties
        compute differently, which is the same smuggling primitive as the
        duplicated header, reached through the neighbouring field rather
        than through Transfer-Encoding.
        """
        mint = self.start_mint()
        body = json.dumps(
            {"idempotency_key": "cl", "inputs": [], "outputs": []}
        ).encode()
        spellings = {
            "leading plus": b"+%d" % len(body),
            "underscore separator":
                b"%d_%d" % (len(body) // 10, len(body) % 10),
            "leading minus": b"-%d" % len(body),
            "not a number": b"abc",
            "empty": b"",
            "the comma form": b"2, %d" % len(body),
            "a digit run past the conversion limit": b"1" * 5_000,
            "twenty digits": b"9" * 20,
            "a float": b"%d.0" % len(body),
            "hex": b"0x%x" % len(body),
        }
        for name, value in spellings.items():
            with self.subTest(name):
                request = (
                    b"POST /v3/exchange HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Content-Length: " + value + b"\r\n"
                    b"\r\n" + body + self.SMUGGLE
                )
                self.assert_refused_and_hung_up(mint.port, request)

    def test_a_spaced_content_length_is_unframable_too(self):
        """The reported variation, moved to the neighbouring field. The
        parser drops `Content-Length : 53` exactly as it drops the spaced
        Transfer-Encoding, and before this round that request read as a
        zero-length body and kept its connection."""
        mint = self.start_mint()
        body = json.dumps(
            {"idempotency_key": "cl-sp", "inputs": [], "outputs": []}
        ).encode()
        for header_line in (b"Content-Length : %d\r\n" % len(body),
                            b"Content_Length: %d\r\n" % len(body),
                            b"Content-Length\t: %d\r\n" % len(body)):
            with self.subTest(header_line):
                request = (
                    b"POST /v3/exchange HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\n"
                    b"Content-Type: application/json\r\n"
                    + header_line + b"\r\n" + body + self.SMUGGLE
                )
                self.assert_refused_and_hung_up(mint.port, request)

    # -- and the cost of all that, which must be nothing ----------------

    def test_the_spellings_http_actually_allows_still_keep_alive(self):
        """The guard must not become a keep-alive tax. Optional whitespace
        after the colon and leading zeros are both ``1*DIGIT`` with OWS, so
        both still frame, and the pipelined GET behind them is answered."""
        mint = self.start_mint()
        def post(key, length_value):
            body = json.dumps(
                {"idempotency_key": key, "inputs": [], "outputs": []}
            ).encode()
            return (
                b"POST /v3/exchange HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length:" + length_value + b"\r\n\r\n"
            ) + body
        cases = {
            "one space": b" %d",
            "several spaces": b"   %d",
            "a tab": b"\t%d",
            "leading zeros": b" 00000%d",
            "no space at all": b"%d",
        }
        body_len = len(json.dumps(
            {"idempotency_key": "x" * 5, "inputs": [], "outputs": []}
        ).encode())
        for name, template in cases.items():
            with self.subTest(name):
                key = "ka%03d" % len(name)
                body = json.dumps(
                    {"idempotency_key": key, "inputs": [], "outputs": []}
                ).encode()
                request = (
                    b"POST /v3/exchange HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Content-Length:" + (template % len(body)) +
                    b"\r\n\r\n" + body + self.SMUGGLE
                )
                raw = raw_request(mint.port, request, shutdown_write=True,
                                  timeout=8.0)
                self.assertEqual(raw.count(b"HTTP/1."), 2, raw[:600])
                self.assertIn(b"mint_id", raw)  # the pipelined GET answered

    def test_an_ordinary_get_still_keeps_its_connection(self):
        """`body_expected` is False on the GET guard for a reason: no
        conforming client sends `Content-Length: 0` on a GET, so treating an
        absent length as unframable there would close every well-formed
        connection this mint serves."""
        mint = self.start_mint()
        request = (
            b"GET /v3/mints HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
            b"GET /v3/mints HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        )
        raw = raw_request(mint.port, request, shutdown_write=True,
                          timeout=8.0)
        self.assertEqual(raw.count(b"HTTP/1."), 2, raw[:600])
        self.assertNotIn(b"Connection: close", raw)

    # -- the shape of the rule, not just its answers ---------------------

    def test_the_framing_rule_yields_a_length_or_nothing(self):
        """The verdict and the number come from ONE method, so the length
        a reader acts on and the verdict that the socket is re-framable
        cannot disagree — which is how the two used to drift apart."""
        self.assertIn(
            "_framed_body_length",
            inspect.getsource(_Handler._body_framing_is_unreadable),
        )
        self.assertIn(
            "_framed_body_length", inspect.getsource(_Handler._read_json)
        )
        # The GET guard READS ``FramingVerdict.must_close``; it does not
        # re-derive it. RETARGETED, and strengthened, this round: the
        # assertion used to be that this method mentions
        # `_body_framing_is_unreadable`, and it did -- in a docstring,
        # while its code spelled out `must_close`'s own definition
        # ("unframable, OR framed with a declared length that is not
        # zero") by hand, in the file that DEFINES the field, and
        # `must_close` itself had no executing consumer anywhere in the
        # package. The other three servers act on that field. A contract
        # field its owner re-implements is a contract field free to drift
        # from its definition, so the guard reads it now and this says so.
        guard_code = inspect.getsource(
            _Handler._close_if_body_goes_unread).split('"""')[-1]
        self.assertIn("must_close", guard_code)
        self.assertIn("_framing_verdict", guard_code)
        for rederived in ("_framed_body_length",
                          "_body_framing_is_unreadable", "!= 0"):
            self.assertNotIn(rederived, guard_code, rederived)
        # The reader must not re-parse Content-Length behind the rule's
        # back: that duplicate parse is exactly what the rule replaced.
        self.assertNotIn(
            'int(self.headers.get("Content-Length"',
            inspect.getsource(_Handler._read_json),
        )
        # And the precondition lives in the same ONE rule, so the GET
        # guard, the POST reader and C10's reader all inherit it together.
        # That rule is now the exported `framing_verdict`, because three
        # other servers in this repository need it too and the private
        # method they could not import is why they each had a copy of a
        # WRONG one; `_framed_body_length` is the delegation, asserted
        # here so the arithmetic cannot quietly move back in beside it.
        source = inspect.getsource(mintapi.framing_verdict)
        self.assertIn("headers.defects", source)
        # The handler-side chokepoint is `_framing_verdict`: ONE method
        # turns `self.headers` into a decision, and both readers take a
        # field off what it returns. RETARGETED from
        # `_framed_body_length`, which is where the delegation used to sit
        # -- it still delegates, but through the verdict method now, so a
        # subclass narrowing framing narrows `must_close` and `length`
        # together instead of only the number. Both are asserted, so
        # neither can grow the arithmetic back.
        chokepoint = inspect.getsource(_Handler._framing_verdict)
        self.assertIn("framing_verdict(", chokepoint.split('"""')[-1])
        self.assertIn("self.headers", chokepoint.split('"""')[-1])
        delegator = inspect.getsource(_Handler._framed_body_length)
        self.assertIn("_framing_verdict", delegator.split('"""')[-1])
        self.assertIn(".length", delegator.split('"""')[-1])
        for method in (chokepoint, delegator):
            self.assertNotIn("headers.defects", method.split('"""')[-1])
            self.assertNotIn("_FRAMING_CONFUSABLE_RE", method)
            self.assertNotIn("_FOLDED_FRAMING_NAMES", method)
            self.assertNotIn("_TCHAR", method)

    def test_a_body_expecting_reader_gets_the_strict_verdict_by_default(self):
        """C10's ``_read_sup_json`` calls ``_body_framing_is_unreadable()``
        with no arguments and lives in a file this change does not touch, so
        the DEFAULT has to be the body-expecting one. If that default ever
        flips, the Supervision routes — including the authenticated deposit
        route the same token reaches — go back to framing a chunked POST as
        empty while Layer 0 does not: one server, one socket, two answers.
        """
        signature = inspect.signature(_Handler._body_framing_is_unreadable)
        self.assertIs(
            signature.parameters["body_expected"].default, True
        )
        self.assertIs(
            signature.parameters["body_expected"].kind,
            inspect.Parameter.KEYWORD_ONLY,
        )

    def test_the_mint_still_serves_after_every_refusal(self):
        """A hang-up is not a wound: a fresh connection still works."""
        mint = self.start_mint()
        for header_line in (b"Transfer-Encoding : chunked\r\n",
                            b"Transfer_Encoding: chunked\r\n",
                            b""):
            raw_request(mint.port, self.chunked_post(header_line),
                        timeout=8.0)
        status, desc, _ = http_json(mint.port, "GET", "/v3/mints")
        self.assertEqual(status, 200)
        self.assertEqual(desc["mint_id"], MINT_ID)


class AFramingHeaderCannotHideBehindItsOwnNameTest(
    MintHarness, unittest.TestCase
):
    """D1, one step past the fix that was supposed to close it.

    The previous round replaced a list of bad header spellings with a rule
    about the length the server can COMPUTE — and then kept one literal
    name lookup, ``self.headers.get("Transfer-Encoding")``, described in
    its own comment as a belt over the braces whose every miss "is caught
    by the no-computable-length rule instead". That sentence is true
    everywhere except the one place the clause was load-bearing:
    ``Content-Length: 0`` beside an invisible transfer coding. A truthful,
    single, well-formed ``Content-Length`` is a computable length, so no
    other clause can fire, and the verdict fell through to a comparison
    against one spelling of one name. Every other spelling — and RFC 7230
    §3.2.4 makes a field name any run of tchars, so there are as many as
    anyone cares to type — framed as a zero-octet body, answered WITHOUT
    ``Connection: close``, and left the chunk data to be read as the next
    request line: two access-log entries for one request, the second with
    a null method, which is the reporter's original evidence reproduced by
    changing one character of a header name.

    The rule is no longer a name. ``_FRAMING_CONFUSABLE_RE`` is DERIVED
    from ``_FRAMING_FIELD_NAMES`` by letting every hyphen be any character
    or none, so the question asked of each field is "could any hop read
    this as framing?" rather than "is this spelled the way we expect?".
    The sweeps below are evidence for that property; the property is what
    is being tested, and ``test_the_rule_is_generated_from_the_names`` is
    the test that fails if someone turns it back into a list.
    """

    SMUGGLE = b"GET /v3/mints HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"

    # RFC 7230 §3.2.6 tchar, minus the characters that cannot appear here:
    # the field name is delimited by a colon, and CR/LF end the line.
    TCHARS = (
        "!#$%&'*+-.^_`|~"
        "0123456789"
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    )

    def assert_refused_and_hung_up(self, port, request):
        raw = raw_request(port, request, timeout=8.0)
        status, headers, parsed = parse_http(raw)
        self.assertEqual(status, 400, raw[:400])
        self.assertEqual(parsed["errors"][0]["reason"], "bad_format", parsed)
        self.assertEqual(headers.get("connection"), "close", raw[:400])
        self.assertEqual(raw.count(b"HTTP/1."), 1, raw[:400])
        self.assertNotIn(b"Bad request syntax", raw)
        self.assertNotIn(b"mint_id", raw)  # the smuggled GET never answered

    def chunked_post_with_a_truthful_length(self, field_name,
                                            path=b"/v3/exchange"):
        """The exact shape the length rule cannot help with.

        ``Content-Length: 0`` is single, parseable and defect-free, so it
        IS a computable length; the only thing wrong with the request is a
        field name this server does not recognise as framing and some
        other hop might.
        """
        return (
            b"POST " + path + b" HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: 0\r\n"
            + field_name + b": chunked\r\n"
            b"\r\n"
            b"3d\r\n" + b"A" * 61 + b"\r\n0\r\n\r\n"
        ) + self.SMUGGLE

    def test_every_tchar_in_place_of_the_hyphen_is_refused_and_closed(self):
        """The whole substitution class, not the three spellings reported.

        Each of these is a DIFFERENT field name to Python's email parser,
        so no lookup can see them; each is a name an intermediary may
        normalise back into ``Transfer-Encoding`` (nginx has
        ``underscores_in_headers``; Apache and IIS historically folded
        ``_`` to ``-``) and then dechunk on this server's behalf.
        """
        mint = self.start_mint()
        names = ["Transfer%sEncoding" % c for c in self.TCHARS]
        names.append("TransferEncoding")  # the separator removed entirely
        names.append("transfer_encoding")  # and lowercased
        names.append("TRANSFER.ENCODING")
        # Separator RUNS, for a gateway that rewrites punctuation with a
        # substitution rather than character by character.
        names.append("Transfer__Encoding")
        names.append("Transfer--Encoding")
        names.append("Transfer-_.Encoding")
        names.append("Transfer~~~Encoding")
        for name in names:
            with self.subTest(name):
                self.assert_refused_and_hung_up(
                    mint.port,
                    self.chunked_post_with_a_truthful_length(name.encode()),
                )

    def test_the_same_names_are_refused_on_every_post_route(self):
        """One server, one socket: the verdict is a property of the
        request, not of the route it was aimed at."""
        mint = self.start_mint()
        for path in (b"/v3/exchange", b"/v3/status", b"/admin/issue"):
            for name in (b"Transfer_Encoding", b"TransferaEncoding",
                         b"Transfer~Encoding"):
                with self.subTest(path=path, name=name):
                    raw = raw_request(
                        mint.port,
                        self.chunked_post_with_a_truthful_length(name, path),
                        timeout=8.0,
                    )
                    status, headers, _ = parse_http(raw)
                    self.assertEqual(headers.get("connection"), "close",
                                     raw[:400])
                    self.assertEqual(raw.count(b"HTTP/1."), 1, raw[:400])
                    self.assertNotIn(b"mint_id", raw)

    def test_the_get_side_needs_no_content_length_at_all(self):
        """The same class where there is no length to be truthful about.

        A GET reads no body, so an absent Content-Length is the ordinary
        case and cannot be the trigger; the misspelled transfer coding is
        the ONLY thing to go on. Answered (§3.7 lets anyone ask) and then
        hung up, so the chunk octets are never framed as a request.
        """
        mint = self.start_mint()
        for c in self.TCHARS:
            name = ("Transfer%sEncoding" % c).encode()
            with self.subTest(name):
                request = (
                    b"GET /v3/mints HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\n"
                    + name + b": chunked\r\n\r\n"
                    b"3d\r\n" + b"A" * 61 + b"\r\n0\r\n\r\n"
                ) + self.SMUGGLE
                raw = raw_request(mint.port, request, timeout=8.0)
                status, headers, _ = parse_http(raw)
                self.assertEqual(status, 200, raw[:300])
                self.assertEqual(headers.get("connection"), "close",
                                 raw[:300])
                self.assertEqual(raw.count(b"HTTP/1."), 1, raw[:400])

    def test_the_neighbouring_framing_field_gets_the_same_treatment(self):
        """``Content-Length`` is the other name in ``_FRAMING_FIELD_NAMES``,
        and the rule is derived from the tuple rather than written for one
        entry of it. A hop that normalises ``Content_Length: 53`` has a
        length this server does not, which is the same disagreement read
        from the other side — and it is a disagreement even when a real
        ``Content-Length`` sits beside it."""
        mint = self.start_mint()
        body = json.dumps(
            {"idempotency_key": "cl-conf", "inputs": [], "outputs": []}
        ).encode()
        for c in self.TCHARS:
            name = ("Content%sLength" % c).encode()
            if name.lower() == b"content-length":
                continue  # that one IS the framing header, read below
            for extra in (b"", b"Content-Length: %d\r\n" % len(body)):
                with self.subTest(name=name, real_length=bool(extra)):
                    request = (
                        b"POST /v3/exchange HTTP/1.1\r\n"
                        b"Host: 127.0.0.1\r\n"
                        b"Content-Type: application/json\r\n"
                        + extra + name + b": %d\r\n" % len(body)
                        + b"\r\n" + body + self.SMUGGLE
                    )
                    self.assert_refused_and_hung_up(mint.port, request)

    # -- the rule's shape, so it cannot quietly become a list again ------

    def test_the_rule_is_generated_from_the_names(self):
        """THE test for this round's failure mode.

        A pattern built by hand is a list with better punctuation: it can
        be complete on the day it is written and stale the day a framing
        header is added. This asserts the pattern is a FUNCTION of
        ``_FRAMING_FIELD_NAMES`` by rebuilding it here from the tuple and
        requiring the same answers, and asserts the framing decision
        contains no name lookup of its own.
        """
        source = inspect.getsource(mintapi.framing_verdict)
        self.assertNotIn('get("Transfer-Encoding")', source)
        self.assertNotIn('get_all("Content-Length")', source)
        self.assertIn("_FRAMING_CONFUSABLE_RE", source)
        punctuation = "".join(c for c in self.TCHARS if not c.isalnum())
        for name in _FRAMING_FIELD_NAMES:
            self.assertTrue(_FRAMING_CONFUSABLE_RE.fullmatch(name), name)
            for i, ch in enumerate(name):
                if ch != "-":
                    continue
                separators = list(self.TCHARS)          # one character
                separators.append("")                   # removed entirely
                separators.append(punctuation)          # a run of it
                separators.extend(c * 3 for c in punctuation)
                for sep in separators:
                    spelling = name[:i] + sep + name[i + 1:]
                    self.assertTrue(
                        _FRAMING_CONFUSABLE_RE.fullmatch(spelling),
                        "a hop could read %r as %r" % (spelling, name),
                    )
        # And it must still be a rule about CONFUSION, not about everything
        # with a familiar-looking word in it: a name that is genuinely a
        # different header keeps its keep-alive.
        for innocent in ("content-type", "content-encoding", "accept-encoding",
                         "x-transfer-encoding", "transfer-encodings",
                         "content-length-hint", "user-agent"):
            self.assertIsNone(_FRAMING_CONFUSABLE_RE.fullmatch(innocent),
                              innocent)

    def test_adding_a_framing_header_extends_the_rule_with_no_second_edit(
        self
    ):
        """The tuple is the specification and the pattern is its shadow. If
        a future round has to treat another header as framing, adding it
        here must cover every confusion of it too — otherwise the next
        maintainer is back to writing spellings down."""
        import re as _re

        extended = _re.compile(
            "|".join(
                n.replace("-", _FRAMING_NAME_SEPARATOR)
                for n in _FRAMING_FIELD_NAMES + ("content-encoding",)
            )
        )
        for spelling in ("content-encoding", "content_encoding",
                         "content.encoding", "contentXencoding",
                         "content__encoding", "contentencoding"):
            self.assertTrue(extended.fullmatch(spelling), spelling)
        # The existing entries keep working; extending is not replacing.
        for spelling in ("transfer_encoding", "content--length"):
            self.assertTrue(extended.fullmatch(spelling), spelling)

    # -- and the cost of all of it, which must still be nothing ----------

    def test_ordinary_headers_do_not_lose_keep_alive(self):
        """A rule that refused everything it did not recognise would be a
        keep-alive tax on every proxy, client and credential header this
        mint actually sees. The axis is confusability with a framing name,
        not unfamiliarity."""
        mint = self.start_mint()
        body = json.dumps(
            {"idempotency_key": "ka-ord", "inputs": [], "outputs": []}
        ).encode()
        extra = (
            b"User-Agent: curl/8.4.0\r\n"
            b"Accept: */*\r\n"
            b"Accept-Encoding: gzip, deflate\r\n"
            b"X-Forwarded-For: 203.0.113.7\r\n"
            b"X-Real-IP: 203.0.113.7\r\n"
            b"Via: 1.1 gateway\r\n"
            b"X-Admin-Token: not-the-one\r\n"
            b"X-Transfer-Encoding-Notes: none\r\n"
            b"Content-Encoding: identity\r\n"
            b"Transfer-Encodings-Supported: none\r\n"
        )
        request = (
            b"POST /v3/exchange HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Type: application/json\r\n"
            + extra +
            b"Content-Length: %d\r\n\r\n" % len(body)
            + body + self.SMUGGLE
        )
        raw = raw_request(mint.port, request, shutdown_write=True,
                          timeout=8.0)
        self.assertEqual(raw.count(b"HTTP/1."), 2, raw[:800])
        self.assertIn(b"mint_id", raw)  # the pipelined GET was answered
        self.assertNotIn(b"Connection: close", raw)


class ContentLengthIsStrippedTheWayHttpDefinesItTest(
    MintHarness, unittest.TestCase
):
    """D1's other step: a spec-strict pattern fed a Python-defined strip.

    ``_CONTENT_LENGTH_RE`` was introduced last round precisely because
    ``int()`` is looser than RFC 7230 §3.3.2 — and then it was handed
    ``value.strip()``. Bare ``str.strip()`` removes Python's whitespace
    set, which is not HTTP's OWS (SP and HTAB, §3.2.3): it also eats
    \x0b \x0c \x1c \x1d \x1e \x1f \x85 and \xa0. So
    ``Content-Length: 5\x0b`` framed five octets and kept the connection,
    while the sibling rule that then lived in the same process
    (C10's ``_sup_framing_is_unreadable``, which stripped " \t")
    refused the identical bytes. That sibling is gone now -- its token
    check and its hard fold were folded into ``framing_verdict`` and the
    method deleted -- which is what makes "the same bytes get one verdict"
    structural rather than a coincidence two rules had to keep achieving. \xa0 is legal obs-text, so the header
    LINE is well formed and nothing upstream rejects the message for us —
    only its value is invalid, and RFC 7230 §3.3.3 rule 4 says an invalid
    Content-Length is unrecoverable.

    The sweep below is over all 256 octets rather than the eight that were
    reported, because the question is which octets HTTP calls whitespace,
    and the answer is two.
    """

    # NOTE ON THE SIBLING RULE, AND WHY THERE ISN'T ONE ANY MORE. C10 used
    # to carry `_sup_framing_is_unreadable`, a second framing rule in the
    # same process, and the note that used to stand here said C10 "may
    # refuse MORE; it cannot accept an octet Layer 0 refuses". That was
    # true and it was the problem: the two rules were incomparable, not
    # nested. C10's hard fold reached 435 names C06's regex did not, so
    # when framing was lifted into one shared function the LAXER of the two
    # was the one exported -- to the operator GUI and the operator console,
    # which had had no rule at all. Both halves are inside
    # `framing_verdict` now and their union is the rule; C10 refuses
    # exactly what Layer 0 refuses because it asks the same function.

    SMUGGLE = b"GET /v3/mints HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"

    def request_with(self, raw_length_value):
        body = b'{"idempotency_key":"ows","inputs":[],"outputs":[]}'
        return (
            b"POST /v3/exchange HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + raw_length_value + b"\r\n"
            b"\r\n" + body + self.SMUGGLE
        ), body

    def test_only_sp_and_htab_are_whitespace_around_a_length(self):
        """Every octet a value could end with, swept. CR and LF are left
        out because they end the header line rather than sit inside it."""
        mint = self.start_mint()
        body_len = len(b'{"idempotency_key":"ows","inputs":[],"outputs":[]}')
        for octet in range(256):
            if octet in (0x0A, 0x0D):
                continue
            trailer = bytes([octet])
            request, body = self.request_with(
                b"%d" % body_len + trailer
            )
            with self.subTest(octet="0x%02x" % octet):
                raw = raw_request(mint.port, request, shutdown_write=True,
                                  timeout=8.0)
                if octet in (0x20, 0x09):
                    # Real OWS: the length is legal, so the body frames and
                    # the pipelined GET behind it is answered. The guard is
                    # not allowed to become a keep-alive tax.
                    self.assertEqual(raw.count(b"HTTP/1."), 2, raw[:600])
                    self.assertIn(b"mint_id", raw)
                else:
                    status, headers, _ = parse_http(raw)
                    self.assertEqual(status, 400, raw[:400])
                    self.assertEqual(headers.get("connection"), "close",
                                     raw[:400])
                    self.assertEqual(raw.count(b"HTTP/1."), 1, raw[:400])
                    self.assertNotIn(b"mint_id", raw)

    def test_leading_and_repeated_whitespace_is_read_the_same_way(self):
        """OWS is allowed on both sides and in runs; the non-OWS octets are
        refused on both sides too. Which side the octet sits on is not a
        property anything in HTTP distinguishes."""
        mint = self.start_mint()
        body_len = len(b'{"idempotency_key":"ows","inputs":[],"outputs":[]}')
        legal = [b" \t %d" % body_len, b"%d \t " % body_len,
                 b"\t%d\t" % body_len]
        illegal = [b"\x0b%d" % body_len, b"%d\x0b" % body_len,
                   b"\xa0%d" % body_len, b"%d\xa0" % body_len,
                   b"\x1e %d" % body_len, b"%d \x85" % body_len]
        for value in legal:
            with self.subTest(value=value):
                request, _ = self.request_with(value)
                raw = raw_request(mint.port, request, shutdown_write=True,
                                  timeout=8.0)
                self.assertEqual(raw.count(b"HTTP/1."), 2, raw[:600])
        for value in illegal:
            with self.subTest(value=value):
                request, _ = self.request_with(value)
                raw = raw_request(mint.port, request, shutdown_write=True,
                                  timeout=8.0)
                status, headers, _ = parse_http(raw)
                self.assertEqual(status, 400, raw[:400])
                self.assertEqual(headers.get("connection"), "close",
                                 raw[:400])

    def test_the_two_framing_rules_in_this_process_agree(self):
        """The disagreement is the defect, so the assertion is agreement.

        C10 read the same socket in the same process with a rule of its
        own that stripped " \t" with an explicit digit walk. If Layer 0
        accepts an octet C10 refuses, the same wire bytes get two verdicts
        depending on which route they were aimed at, and the half that is
        laxer is the smuggleable one -- which is what happened, in the
        other direction, on 435 header NAMES. There is one rule now and
        this pins the octet half of it: the OWS strip stays HTTP's.
        """
        source = inspect.getsource(mintapi.framing_verdict)
        self.assertIn('lengths[0].strip(" \\t")', source)
        # The Python-defined strip is what reintroduced the looseness the
        # digit pattern had just removed; it must not come back on the
        # value the length is parsed from.
        self.assertNotIn("lengths[0].strip()", source)
        # And the arithmetic stays in ONE place, which is what makes the
        # agreement structural rather than a coincidence two files have to
        # keep re-achieving: C10 reaches this same method through
        # `_body_framing_is_unreadable` instead of counting digits again.
        # Asserted against C06's own source rather than C10's, so this test
        # pins the property it owns and not another file's wording.
        self.assertIn(
            "_framed_body_length",
            inspect.getsource(_Handler._body_framing_is_unreadable),
        )
        # ...and `_framed_body_length` is itself a delegation to the ONE
        # exported rule, so "one arithmetic" is now a property of the whole
        # repository and not only of this class: the GUI and the console
        # call `framing_verdict` directly.
        self.assertIn(
            "framing_verdict(",
            inspect.getsource(_Handler._framed_body_length),
        )


class TheHeaderBlockPreconditionIsThePropertyItClaimsTest(
    MintHarness, unittest.TestCase
):
    """The precondition everything else in the framing rule rests on.

    ``_framed_body_length`` documents its first clause as "a header block
    this parser could not read WHOLE", and tested only ``defects``.
    email's feedparser has a silent stop that records no defect at all: a
    final header line beginning with ``From `` is unread-lined into the
    message PAYLOAD and header parsing simply returns. The bytes are real,
    they were never interpreted, and ``defects`` is empty — so the clause
    passed and the socket was kept.

    Not exploitable on its own today (a ``From `` line anywhere but last
    raises MisplacedEnvelopeHeaderDefect), which is exactly why it is
    worth closing now: the whole argument for the rest of the rule is that
    this precondition is total, and a precondition that is only accidentally
    total is one parser change away from not being. C10's sibling rule
    already checked the payload; Layer 0 asking the weaker question is the
    drift that puts two answers on one socket.
    """

    SMUGGLE = b"GET /v3/mints HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"

    def test_bytes_the_header_parser_silently_stopped_on_close_the_socket(
        self
    ):
        mint = self.start_mint()
        for trailing in (b"From nobody\r\n",
                         b"From nobody Sat Sep 13 00:00:00 2026\r\n",
                         b"From \r\n"):
            with self.subTest(trailing):
                request = (
                    b"POST /v3/exchange HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Content-Length: 0\r\n"
                    + trailing + b"\r\n"
                    b"3d\r\n" + b"A" * 61 + b"\r\n0\r\n\r\n"
                ) + self.SMUGGLE
                raw = raw_request(mint.port, request, timeout=8.0)
                status, headers, _ = parse_http(raw)
                self.assertEqual(status, 400, raw[:400])
                self.assertEqual(headers.get("connection"), "close",
                                 raw[:400])
                self.assertEqual(raw.count(b"HTTP/1."), 1, raw[:400])
                self.assertNotIn(b"mint_id", raw)

    def test_the_precondition_asks_about_the_payload_as_well(self):
        """Stated in the code, not only in behaviour: the next parser
        change must fail this, not pass it by luck."""
        source = inspect.getsource(mintapi.framing_verdict)
        self.assertIn("headers.defects", source)
        self.assertIn("get_payload()", source)

    def test_an_ordinary_request_leaves_no_payload_and_keeps_alive(self):
        """The precondition must not fire on well-formed traffic: a normal
        request block has an empty payload, so this costs nothing."""
        mint = self.start_mint()
        body = json.dumps(
            {"idempotency_key": "payload-ok", "inputs": [], "outputs": []}
        ).encode()
        request = (
            b"POST /v3/exchange HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: %d\r\n\r\n" % len(body)
            + body + self.SMUGGLE
        )
        raw = raw_request(mint.port, request, shutdown_write=True,
                          timeout=8.0)
        self.assertEqual(raw.count(b"HTTP/1."), 2, raw[:600])
        self.assertIn(b"mint_id", raw)


class ABodyTheDigestCannotRenderIsAnEnumeratedRejectionTest(
    MintHarness, unittest.TestCase
):
    """D2, one converter over, over real HTTP.

    D2's root cause was "the pattern admitted values the conversion could
    not represent, and the conversion raised an error type the route does
    not catch". ``/v3/exchange`` computes ``body_digest(body)`` inside an
    ``except TokenError``, and two converters reachable from that one line
    still raised something else:

    * an unpaired surrogate anywhere in the body — ``json.loads`` decodes
      the escape ``\\ud800`` happily, and ``str.encode("utf-8")`` then
      raises ``UnicodeEncodeError``;
    * a body nested a few hundred levels deep — ``json.loads`` survives it
      (only ~50,000 levels reaches the RecursionError guard in the body
      reader), and ``_canon``'s own recursion raises ``RecursionError``.

    Both produced the byte-identical original symptom from an anonymous
    caller: HTTP 500, ``{"status":"error"}``, no errors list, no §3.8
    reason. C01 now refuses both as ``TokenError``; these tests assert the
    wire answer, because the wire answer is what the reporter saw.
    """

    def post_raw(self, port, body, path="/v3/exchange"):
        status, raw, headers = http_raw(
            port, "POST", path, body,
            {"Content-Type": "application/json"},
        )
        return status, json.loads(raw.decode("utf-8"))

    def assert_enumerated_rejection(self, port, body, path="/v3/exchange"):
        status, parsed = self.post_raw(port, body, path)
        self.assertEqual(status, 400, parsed)
        self.assertEqual(parsed["status"], "rejected", parsed)
        self.assertEqual(parsed["errors"][0]["reason"], "bad_format", parsed)
        self.assertNotEqual(parsed.get("status"), "error")

    def test_an_unpaired_surrogate_anywhere_in_the_body_is_bad_format(self):
        mint = self.start_mint()
        bodies = {
            "idempotency_key":
                b'{"idempotency_key":"\\ud800","inputs":[],"outputs":[]}',
            "an extra top-level field":
                b'{"idempotency_key":"s2","inputs":[],"outputs":[],'
                b'"j":"\\udfff"}',
            "an object key":
                b'{"idempotency_key":"s3","inputs":[],"outputs":[],'
                b'"\\ud800":1}',
            "an input string":
                b'{"idempotency_key":"s5","inputs":["\\ud800"],'
                b'"outputs":[]}',
            "nested inside an extra field":
                b'{"idempotency_key":"s7","inputs":[],"outputs":[],'
                b'"p":{"q":[{"r":"\\udc00"}]}}',
            "the low end of the block":
                b'{"idempotency_key":"s8","inputs":[],"outputs":[],'
                b'"j":"\\udc00"}',
        }
        for name, body in bodies.items():
            with self.subTest(name):
                self.assert_enumerated_rejection(mint.port, body)

    def test_a_legal_surrogate_pair_is_still_an_ordinary_call(self):
        """The rejection is about MALFORMED input. An escaped PAIR is a
        legal spelling of an astral character and must pay normally."""
        mint = self.start_mint()
        secret = new_secret()
        self.issue(mint, 1_000, secret)
        status, parsed = self.post_raw(
            mint.port,
            json.dumps({
                "idempotency_key": "emoji-\U0001F600",
                "inputs": [tok(1_000, secret)],
                "outputs": [out_hash(990, new_secret())],
            }).encode("utf-8"),
        )
        self.assertEqual(status, 200, parsed)

    def test_a_deeply_nested_body_is_bad_format_not_an_internal_error(self):
        """The reported window was 500-2000 levels — deep enough that
        ``json.loads`` succeeds and shallow enough that the body reader's
        RecursionError guard never fires. Swept across and past it."""
        mint = self.start_mint()
        for depth in (150, 400, 500, 600, 1_000, 2_000, 5_000):
            with self.subTest(depth=depth):
                body = (
                    b'{"idempotency_key":"d%d","inputs":[],"outputs":[],'
                    b'"p":' % depth
                    + b"[" * depth + b"1" + b"]" * depth + b"}"
                )
                self.assert_enumerated_rejection(mint.port, body)

    def test_the_depth_sweep_has_no_gap_that_answers_500(self):
        """The defect was a WINDOW between two guards, so the assertion is
        over a range rather than at a point: every depth from shallow to
        past the old json.loads limit answers with a §3.8 reason."""
        mint = self.start_mint()
        for depth in list(range(1, 12)) + [50, 99, 100, 101, 250, 3_000,
                                           20_000, 60_000]:
            with self.subTest(depth=depth):
                body = (
                    b'{"idempotency_key":"g%d","inputs":[],"outputs":[],'
                    b'"p":' % depth
                    + b"[" * depth + b"1" + b"]" * depth + b"}"
                )
                status, parsed = self.post_raw(mint.port, body)
                self.assertNotEqual(status, 500, (depth, parsed))
                self.assertIn(status, (200, 400), (depth, parsed))

    def test_nothing_in_the_sweep_reaches_the_500_handler(self):
        """The handler that produces ``{"status":"error"}`` exists for
        genuine internal faults; a malformed anonymous body is not one, and
        the reporter's evidence was that exact object."""
        mint = self.start_mint()
        hostile = [
            b'{"idempotency_key":"\\ud800","inputs":[],"outputs":[]}',
            b'{"idempotency_key":"z","inputs":[],"outputs":[],'
            b'"p":' + b"[" * 900 + b"1" + b"]" * 900 + b"}",
            b'{"idempotency_key":"z2","inputs":[],"outputs":[],'
            b'"n":' + b"9" * 5_000 + b"}",
            b'{"idempotency_key":"z3","inputs":[],"outputs":[],"f":1.5}',
        ]
        for body in hostile:
            with self.subTest(body[:48]):
                status, parsed = self.post_raw(mint.port, body)
                self.assertNotEqual(status, 500, parsed)
                self.assertNotEqual(parsed.get("status"), "error", parsed)

    def test_the_same_bodies_are_answered_on_the_other_layer_0_routes(self):
        """A converter defect is not a property of one route. /v3/status
        and /admin/issue read bodies off the same socket and must not turn
        a malformed one into an unenumerated 500 either."""
        mint = self.start_mint()
        deep = b"[" * 900 + b"1" + b"]" * 900
        for path, body in (
            ("/v3/status", b'{"hashes":["\\ud800"]}'),
            ("/v3/status", b'{"hashes":' + deep + b"}"),
            ("/admin/issue",
             b'{"outputs":[{"amount_mc":1,"secret_hash":"\\ud800"}]}'),
            ("/admin/issue", b'{"outputs":' + deep + b"}"),
        ):
            with self.subTest(path=path, body=body[:40]):
                status, raw, _ = http_raw(
                    mint.port, "POST", path, body,
                    {"Content-Type": "application/json",
                     "X-Admin-Token": mint.config.admin_token},
                )
                parsed = json.loads(raw.decode("utf-8"))
                self.assertNotEqual(status, 500, parsed)
                self.assertNotEqual(parsed.get("status"), "error", parsed)

    def test_the_mint_still_serves_after_every_refusal(self):
        """A refusal is not a wound."""
        mint = self.start_mint()
        self.post_raw(
            mint.port,
            b'{"idempotency_key":"\\ud800","inputs":[],"outputs":[]}',
        )
        status, desc, _ = http_json(mint.port, "GET", "/v3/mints")
        self.assertEqual(status, 200)
        self.assertEqual(desc["mint_id"], MINT_ID)


class AnOversizedAmountIsBadFormatInEveryFieldTest(
    MintHarness, unittest.TestCase
):
    """D2's variation: the same 5,000 digits, one field over.

    The first fix widened the exception handling at the JSON reader, which
    covers every shape where the digits sit in a JSON NUMBER — the reported
    output ``amount_mc`` among them. Move them into the INPUT TOKEN's amount
    and they are a JSON STRING: ``json.loads`` is perfectly happy, and the
    bare ValueError comes out of ``int()`` inside ``parse_token`` instead,
    past every ``except TokenError`` on the route, to the generic 500 with
    an empty error list — byte-identical to the behaviour the fix was
    supposed to have removed.

    Fixed in C01 where the type discipline breaks (``_AMOUNT_RE`` is now
    length-bounded and the module states its own ``MAX_AMOUNT_MC``), so
    every caller of that parser is covered rather than this one route.
    These tests check the route, because the route is where the 500 was.
    """

    SECRET_B64U = "A" * 43

    def token_with_amount(self, digits, mint_id=MINT_ID):
        return "aicash:v3:%s:%s:%s" % (mint_id, digits, self.SECRET_B64U)

    def assert_enumerated_rejection(self, mint, body, *, kind=None):
        status, raw, _ = http_raw(
            mint.port, "POST", "/v3/exchange", body,
            {"Content-Type": "application/json"},
        )
        self.assertEqual(status, 400, raw[:200])
        parsed = json.loads(raw.decode("utf-8"))
        self.assertEqual(parsed["status"], "rejected", parsed)
        self.assertTrue(parsed["errors"], "a 500 answers no reason at all")
        for err in parsed["errors"]:
            self.assertEqual(err["reason"], "bad_format", parsed)
            if kind is not None:
                self.assertEqual(err["kind"], kind, parsed)
        self.assertNotIn(b"Traceback", raw)
        return parsed

    def test_the_reported_variation_an_input_tokens_amount(self):
        """5,000 digits in the INPUT token's amount. Before this round:
        HTTP 500, ``{"status": "error"}``, no errors list at all."""
        mint = self.start_mint()
        body = json.dumps({
            "idempotency_key": "in-big",
            "inputs": [self.token_with_amount("1" * 5_000)],
            "outputs": [],
        }).encode()
        self.assert_enumerated_rejection(mint, body, kind="input")

    def test_every_input_form_that_carries_a_token(self):
        """§3.3 has two token-bearing input forms and the claim form parses
        its token by the same call. A fix at one form is the same mistake
        one level down."""
        mint = self.start_mint()
        digits = "1" * 5_000
        forms = {
            "plain string": self.token_with_amount(digits),
            "claim form": {"token": self.token_with_amount(digits),
                           "witness": b64u_encode(b"\x00" * 32)},
        }
        for name, form in forms.items():
            with self.subTest(name):
                body = json.dumps({
                    "idempotency_key": "form-%s" % name.replace(" ", "-"),
                    "inputs": [form],
                    "outputs": [],
                }).encode()
                self.assert_enumerated_rejection(mint, body, kind="input")

    def test_every_length_of_digit_run_in_an_input_token(self):
        """The boundary must be the protocol's bound, not the interpreter's.
        4,299 digits gave a clean refusal before the fix and 5,000 gave a
        500; every length now gives the same enumerated reason, and so does
        a 20-digit amount that fits in a JSON number but not in a ledger
        column."""
        mint = self.start_mint()
        lengths = (20, 25, 100, 4_299, 4_300, 4_301, 5_000, 20_000)
        for digits in lengths:
            with self.subTest(digits=digits):
                body = json.dumps({
                    "idempotency_key": "len-%d" % digits,
                    "inputs": [self.token_with_amount("9" * digits)],
                    "outputs": [],
                }).encode()
                self.assert_enumerated_rejection(mint, body, kind="input")

    def test_an_amount_that_fits_the_ledger_is_still_an_ordinary_amount(self):
        """The bound is 2**63-1 because that is what the entries column
        holds. An unspent token for that amount is not malformed; it is
        simply unknown to this mint, and must answer so."""
        mint = self.start_mint()
        biggest = (1 << 63) - 1
        body = json.dumps({
            "idempotency_key": "in-max",
            "inputs": [self.token_with_amount(str(biggest))],
            "outputs": [],
        }).encode()
        status, raw, _ = http_raw(
            mint.port, "POST", "/v3/exchange", body,
            {"Content-Type": "application/json"},
        )
        self.assertEqual(status, 400)
        errors = json.loads(raw.decode("utf-8"))["errors"]
        self.assertEqual([e["reason"] for e in errors], ["unknown"])

    def test_the_digits_in_a_status_lookup_hash_and_in_the_output_field(self):
        """The neighbouring fields on the neighbouring routes, checked
        because the last fix passed its tests and failed this question."""
        mint = self.start_mint()
        digits = b"1" * 5_000
        # The output amount_mc: the LITERAL the first fix closed. Still
        # closed, and now closed in C01 as well as at the JSON reader.
        self.assert_enumerated_rejection(
            mint,
            b'{"idempotency_key":"out","inputs":[],"outputs":'
            b'[{"amount_mc":' + digits + b',"secret_hash":"x"}]}',
            kind="call",
        )
        # A batch status lookup takes hashes, not amounts, but it is the
        # other route that reads a body off this socket.
        status, raw, _ = http_raw(
            mint.port, "POST", "/v3/status",
            b'{"hashes":[' + b'"' + digits + b'"]}',
            {"Content-Type": "application/json"},
        )
        self.assertIn(status, (200, 400), raw[:200])
        self.assertNotIn(b"Traceback", raw)
        self.assertNotIn(b'"status":"error"', raw)

    def test_no_body_carrying_those_digits_ever_answers_a_bare_500(self):
        """The class assertion at the HTTP surface: sweep the digits through
        every field of the envelope that a §3.8 reason could attach to, and
        assert no request answers 500 with an empty error list."""
        mint = self.start_mint()
        digits = "1" * 5_000
        tok_big = self.token_with_amount(digits)
        bodies = [
            {"idempotency_key": "s1", "inputs": [tok_big], "outputs": []},
            {"idempotency_key": "s2",
             "inputs": [{"token": tok_big, "witness": "AA"}], "outputs": []},
            {"idempotency_key": "s3", "inputs": [tok_big, tok_big],
             "outputs": []},
            {"idempotency_key": "s4", "inputs": [],
             "outputs": [{"amount_mc": 1, "secret_hash": digits}]},
            {"idempotency_key": digits[:64], "inputs": [], "outputs": []},
            {"idempotency_key": "s6",
             "inputs": [self.token_with_amount(digits, mint_id="other")],
             "outputs": []},
        ]
        for i, body in enumerate(bodies):
            with self.subTest(i=i):
                status, raw, _ = http_raw(
                    mint.port, "POST", "/v3/exchange",
                    json.dumps(body).encode(),
                    {"Content-Type": "application/json"},
                )
                self.assertNotEqual(status, 500, raw[:200])
                self.assertNotIn(b'"status":"error"', raw)
                self.assertNotIn(b"Traceback", raw)


class MaxBatchFitsTheBodyCapTest(unittest.TestCase):
    """max_batch is PUBLISHED; MAX_BODY_BYTES is not — so they must agree.

    §3.6's `limits.max_batch` is a promise: a caller may send that many
    entries. MAX_BODY_BYTES is a deployment bound that is deliberately NOT
    published (that object's scope guard is explicit), and a body over it is
    refused with `bad_format`, which §9.5 pins as PERMANENT. A config whose
    published limit its own byte cap cannot carry therefore advertises a
    batch size whose maximal call always fails, with a reason that tells the
    payer never to retry it — nothing a conforming client can do about it.
    (Entries smaller than the allowance still get through at such a
    max_batch, which is what made the mismatch silent: the published limit
    is not unusable, only unreachable at the entry size it promises.) The
    two numbers were never cross-checked; max_batch=8000 was accepted
    silently.
    """

    def make_config(self, **kw):
        priv, pub = generate_keypair()
        return MintConfig(
            mint_id=MINT_ID,
            baseline_model_class="frontier-2026",
            burn_policy=POLICY,
            signing_private=priv,
            signing_public=pub,
            # max_batch/body-cap arithmetic; no issuance anywhere in here.
            admin_token=ADMIN_ISSUANCE_DISABLED,
            **kw,
        )

    # -- the fattest LEGAL entry, built and measured, not assumed ---------

    @staticmethod
    def big() -> str:
        """43 characters of b64u: the length every §3.3 hash field has."""
        return b64u_encode(b"\xff" * 32)

    @classmethod
    def fat_output(cls) -> dict:
        """The fattest §3.3 output a conforming caller sends.

        Every field at the longest the spec's own shapes make it: a
        19-digit amount (the largest that fits a signed 64-bit int, which
        is as far as any real balance goes), a 43-character b64u
        secret_hash and a §3.4 lock whose two hashes are also 43
        characters with a 13-digit expiry. NOT the largest string §3.1
        will parse — see test_an_entry_the_mint_parses_can_exceed_the
        _allowance for that.
        """
        big = cls.big()
        return {
            "amount_mc": 9_223_372_036_854_775_807,
            "secret_hash": big,
            "lock": {
                "preimage_hash": big,
                "expiry": 9_999_999_999_999,
                "refund_hash": big,
            },
        }

    @staticmethod
    def fat_input() -> dict:
        """The fattest §3.3 input a conforming caller sends: a claim form
        whose token carries a 64-character mint_id (the §3.1 maximum)."""
        return {
            "token": format_token(
                "m" * 64, 9_223_372_036_854_775_807, b"\xff" * 32
            ),
            "witness": b64u_encode(b"\xff" * 32),
        }

    def start_mint(self, max_batch: int) -> int:
        """A real mint at `max_batch`, bound to a port. Returns the port."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        priv, pub = generate_keypair()
        ledger = Ledger(
            os.path.join(tmp.name, "ledger.sqlite3"),
            FakeClock(T0),
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
            max_batch=max_batch,
            max_lock_expiry_ms=30 * DAY_MS,
            recovery_window_ms=90 * DAY_MS,
            # Oversized-body tests drive /v3/exchange only.
            admin_token=ADMIN_ISSUANCE_DISABLED,
        )
        server = MintServer(config, ledger)
        port = server.start()
        self.addCleanup(server.stop)
        return port

    def fat_body(self, entries: int) -> dict:
        """A whole request at `entries` entries, all of them the fattest
        conforming kind, with the longest idempotency key this mint
        accepts."""
        return {
            "idempotency_key": "k" * MAX_IDEMPOTENCY_KEY_LEN,
            "inputs": [],
            "outputs": [self.fat_output()] * entries,
        }

    def test_the_per_entry_allowance_is_not_smaller_than_a_real_entry(self):
        """_FAT_ENTRY_BYTES must cover the fattest entry a CONFORMING caller
        sends — every §3.3 field at the longest the spec's own shapes make
        it, including the whitespace json.dumps adds by default, since
        nothing obliges a caller to post canonical JSON.

        Deliberately NOT a claim that the allowance bounds every entry the
        mint will parse: it does not, and the next test sends one that
        breaks it. What this pins is the direction that would make the
        ceiling arithmetic dishonest in the ordinary case — an allowance
        retuned BELOW a real, spec-shaped entry.
        """
        for name, entry in (
            ("locked output", self.fat_output()),
            ("claim input", self.fat_input()),
        ):
            with self.subTest(entry=name):
                self.assertLessEqual(
                    len(canonical_json(entry)), _FAT_ENTRY_BYTES
                )
                self.assertLessEqual(
                    len(json.dumps(entry).encode("utf-8")), _FAT_ENTRY_BYTES
                )

    def test_an_entry_the_mint_parses_can_exceed_the_allowance(self):
        """The known hole in the allowance, pinned so it cannot be quietly
        forgotten or quietly claimed shut.

        §3.1 pins an amount's FORM but not its LENGTH, so an output with a
        1000-digit amount is an entry the mint READS — it answers at THIS
        ENTRY'S INDEX, which is only possible for a body it parsed, rather
        than refusing the whole call — at nearly 3x _FAT_ENTRY_BYTES. So
        max_batch entries of this shape still exceed the body cap at a
        max_batch the ceiling admits: the cross-check narrows that, it
        does not close it. Closing it needs an amount length bound in C01,
        which is protocol, not deployment config. If that bound ever
        lands, this test fails and _FAT_ENTRY_BYTES can be promoted from
        an allowance to a real upper bound.

        The per-index REASON changed this round and the hole did not. C04
        now bounds an output amount to what its sqlite column holds (a
        1000-digit amount does not fit), so this entry is `bad_format` at
        index 0 where it used to be `amount_mismatch` at call level. That
        is a VALUE bound in C04, not the LENGTH bound in C01 the paragraph
        above is waiting for: the entry is still one a caller can put in a
        body, still parsed, still enumerated per index, and still fatter
        than the allowance — so the arithmetic this class checks is
        untouched. The assertions below therefore pin the property that
        actually matters here (read, and answered per index) and no longer
        lean on which money rule does the refusing.
        """
        entry = {"amount_mc": int("9" * 1000), "secret_hash": self.big()}
        self.assertGreater(len(canonical_json(entry)), _FAT_ENTRY_BYTES)
        port = self.start_mint(max_batch=256)
        status, body, _ = http_json(
            port,
            "POST",
            "/v3/exchange",
            {
                "idempotency_key": "fat-amount",
                "inputs": [],
                "outputs": [entry],
            },
        )
        self.assertEqual(status, 400, body)
        # Parsed, and judged AT ITS INDEX. A call-level error with a null
        # index would mean the mint refused the body whole and the entry
        # is not one a caller can actually put in a body — which is the
        # thing this class's arithmetic would then be excused from.
        self.assertEqual(len(body["errors"]), 1, body)
        self.assertEqual(body["errors"][0]["kind"], "output", body)
        self.assertEqual(body["errors"][0]["index"], 0, body)
        self.assertEqual(body["errors"][0]["reason"], "bad_format", body)

    def test_the_largest_accepted_max_batch_actually_fits(self):
        """The ceiling is not merely arithmetic: a real request at exactly
        the largest accepted max_batch, every entry the fattest conforming
        one, is SENT to a real mint at that max_batch and must be read and
        enumerated — not refused whole for its size.

        An over-size body comes back as one call-level `bad_format` with a
        null index (``_read_json`` refuses before parsing). Per-index
        output errors can only be produced by a body the mint actually
        read, which is the property the arithmetic is claiming.
        """
        ceiling = _max_batch_ceiling()
        config = self.make_config(max_batch=ceiling)  # must not raise
        self.assertEqual(config.max_batch, ceiling)
        body = self.fat_body(ceiling)
        self.assertLessEqual(len(canonical_json(body)), MAX_BODY_BYTES)
        wire = json.dumps(body).encode("utf-8")  # the fatter, realistic form
        self.assertLessEqual(len(wire), MAX_BODY_BYTES)

        port = self.start_mint(max_batch=ceiling)
        status, answer, _ = http_raw(
            port,
            "POST",
            "/v3/exchange",
            wire,
            {"Content-Type": "application/json"},
        )
        self.assertEqual(status, 400, answer[:200])
        parsed = json.loads(answer.decode("utf-8"))
        errors = parsed["errors"]
        # Every entry was reached and answered about individually: the body
        # was read in full, which is what "it fits" means here.
        enumerated = [e for e in errors if e["index"] is not None]
        self.assertEqual(
            [e["index"] for e in enumerated], list(range(ceiling))
        )
        self.assertEqual({e["kind"] for e in enumerated}, {"output"})
        # ...and NOT the call-level, null-index bad_format _read_json gives
        # a body it refuses on size, which is the failure under test.
        self.assertNotIn(
            ("call", "bad_format"),
            {(e["kind"], e["reason"]) for e in errors},
            errors[-1],
        )

    def test_max_batch_past_the_body_cap_is_refused_at_construction(self):
        """The gate's measured case: max_batch=8000 used to construct
        silently, and a maximal spec-shaped call at that published limit
        measures ~1.9 MB against a 1 MiB cap. The mint must refuse to boot
        rather than publish a limit whose maximal call it always rejects.

        The message must quote the BUDGET it actually refused on — the
        allowance arithmetic — and that budget must not be under the real
        body it is standing in for.
        """
        with self.assertRaises(ValueError) as caught:
            self.make_config(max_batch=8000)
        message = str(caught.exception)
        worst = len(canonical_json(self.fat_body(8000)))
        self.assertGreater(worst, MAX_BODY_BYTES)  # the premise, measured
        self.assertIn("max_batch", message)
        self.assertIn("8000", message)
        # Both numbers, so the operator can see the gap without reading code.
        self.assertIn(str(MAX_BODY_BYTES), message)
        self.assertRegex(message, r"about [0-9]+ bytes")
        # ...and the budget it quotes is not below a real maximal body (it
        # is an allowance, so it is above; what would be dishonest is a
        # figure smaller than the thing it stands for).
        stated = int(re.search(r"about ([0-9]+) bytes", message).group(1))
        self.assertGreaterEqual(stated, worst)
        # ...and it says what to do about it, both ways out.
        self.assertIn("Lower max_batch", message)
        self.assertIn("MAX_BODY_BYTES", message)
        self.assertIn(str(_max_batch_ceiling()), message)

    def test_the_boundary_is_exact(self):
        """One past the ceiling is refused; the ceiling itself is not."""
        ceiling = _max_batch_ceiling()
        self.make_config(max_batch=ceiling)
        with self.assertRaises(ValueError):
            self.make_config(max_batch=ceiling + 1)

    def test_the_shipped_default_still_constructs(self):
        """A config that boots today must keep booting: the refusal is aimed
        at limits the cap cannot carry, not at the shipped mint."""
        config = self.make_config()
        self.assertEqual(config.max_batch, 256)  # the shipped default
        self.assertEqual(MintConfig.max_batch, 256)  # ...on the dataclass too
        # And the default is not marginal. Measured against real bytes,
        # not restated from the two constants the ceiling is made of: four
        # maximal calls at the shipped max_batch still fit in one body.
        biggest = len(json.dumps(self.fat_body(256)).encode("utf-8"))
        self.assertLess(biggest * 4, MAX_BODY_BYTES)

    def test_the_ceiling_follows_a_retuned_body_cap(self):
        """The refusal has to be validated against the cap the SERVER will
        enforce, which is the live module global — ``_read_json`` reads it
        per request.

        Binding it in a default argument (``body_cap: int = MAX_BODY_BYTES``)
        froze it at import, so an operator who followed the message's own
        second remedy — raise MAX_BODY_BYTES — got the same refusal, now
        printing the raised cap and the requirement as the SAME number and
        still refusing, while the reader enforced one cap and the config
        check enforced another. This drives the remedy the message prints.
        """
        original = mintapi.MAX_BODY_BYTES
        self.addCleanup(setattr, mintapi, "MAX_BODY_BYTES", original)
        with self.assertRaises(ValueError) as caught:
            self.make_config(max_batch=8000)
        wanted = int(
            re.search(
                r"raise MAX_BODY_BYTES to at least ([0-9]+)",
                str(caught.exception),
            ).group(1)
        )
        # Do exactly what the operator was told to do, and no more.
        mintapi.MAX_BODY_BYTES = wanted
        self.assertEqual(_max_batch_ceiling(), 8000)
        config = self.make_config(max_batch=8000)  # must not raise
        self.assertEqual(config.max_batch, 8000)
        # ...and the ceiling is still a ceiling at the new cap.
        with self.assertRaises(ValueError):
            self.make_config(max_batch=8001)
        # The other remedy the message prints works at the untouched cap.
        mintapi.MAX_BODY_BYTES = original
        self.assertEqual(self.make_config(max_batch=2728).max_batch, 2728)


# ======================================================================
# The publish blocker: an absent admin credential is REFUSAL, not
# permission.
#
# The defect these pin: MintConfig.admin_token defaulted to None and
# admin_authorized() returned True for None, so any program that built a
# mint from a default config served POST /admin/issue -- unlimited
# issuance -- to anyone who could reach the port. Nothing failed a check;
# there was no check.
#
# Every test below fails if the refusal is removed, and the ones that
# matter most are the ones asserting that openness cannot be reached by
# SAYING NOTHING: it has to be spelled ADMIN_ISSUANCE_OPEN in source.
# ======================================================================


class AdminCredentialIsMandatoryTest(unittest.TestCase):
    """MintConfig will not build without one of the three named states."""

    def config(self, **kw):
        priv, pub = generate_keypair()
        base = dict(
            mint_id=MINT_ID,
            baseline_model_class="frontier-2026",
            burn_policy=POLICY,
            signing_private=priv,
            signing_public=pub,
        )
        base.update(kw)
        return MintConfig(**base)

    def test_a_config_that_says_nothing_will_not_build(self):
        """THE regression. Omitting admin_token used to yield an open mint;
        it now yields no mint at all."""
        with self.assertRaises(ValueError) as caught:
            self.config()
        msg = str(caught.exception)
        self.assertIn("admin_token was not set", msg)
        # The refusal has to be actionable: it names all three ways out.
        self.assertIn("ADMIN_ISSUANCE_DISABLED", msg)
        self.assertIn("ADMIN_ISSUANCE_OPEN", msg)
        self.assertIn("X-Admin-Token", msg)

    def test_none_is_rejected_and_says_what_it_used_to_mean(self):
        """None was the old spelling of "allow everyone". It must not be
        quietly re-read as "allow no one" either -- code carrying it
        forward asked for something, and has to say which."""
        with self.assertRaises(ValueError) as caught:
            self.config(admin_token=None)
        msg = str(caught.exception)
        self.assertIn("no longer means anything", msg)
        self.assertIn("allow everyone", msg)
        self.assertIn("ADMIN_ISSUANCE_OPEN", msg)
        self.assertIn("ADMIN_ISSUANCE_DISABLED", msg)

    def test_the_empty_string_is_not_a_credential(self):
        """An empty token would gate /admin/issue on a header every caller
        can send -- open issuance wearing a credential's clothes."""
        with self.assertRaises(ValueError) as caught:
            self.config(admin_token="")
        self.assertIn("NON-EMPTY", str(caught.exception))

    def test_whitespace_is_not_a_credential_either(self):
        """The empty-string hole reached the way it actually happens.

        `if not tok` lets " ", "\n" and "\t" through because they are
        truthy, so a credential read from an empty token file or an unset
        environment variable produced a mint gated on a header every caller
        can send -- the same defect as the empty string, arrived at by the
        more likely route. It must be REFUSED, not trimmed: trimming would
        bring the mint up on a credential nobody supplied.
        """
        for bad in (" ", "   ", "\t", "\n", "\r\n", " \t \n "):
            with self.assertRaises(ValueError, msg=repr(bad)) as caught:
                self.config(admin_token=bad)
            msg = str(caught.exception)
            self.assertIn("whitespace", msg, repr(bad))
            # The guidance has to be here too: this is somebody's mint
            # failing to start, and they need the three names.
            self.assertIn("ADMIN_ISSUANCE_DISABLED", msg)

    def test_whitespace_inside_a_real_credential_is_left_alone(self):
        """Only an ALL-whitespace token is refused. A token that merely
        contains a space is a token, and it must not be altered."""
        for good in ("has space inside", " leading", "trailing ", "a b"):
            self.assertEqual(
                self.config(admin_token=good).admin_token, good,
                "a real credential was rejected or silently rewritten")

    def test_a_non_credential_non_mode_value_is_rejected(self):
        for bad in (0, 1, True, b"bytes-are-not-a-token", ["list"], object()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.config(admin_token=bad)

    def test_the_rejected_value_is_not_echoed_into_the_message(self):
        """§3.1 requirement 5: whatever was passed was meant to be a
        credential, and a ValueError from a mint that fails to start goes
        straight into a log. Name the type, never the value."""
        with self.assertRaises(ValueError) as caught:
            self.config(admin_token=b"a-real-secret-in-the-wrong-type")
        msg = str(caught.exception)
        self.assertNotIn("a-real-secret-in-the-wrong-type", msg)
        self.assertIn("bytes", msg)

    def test_the_three_named_states_all_build(self):
        self.assertEqual(self.config(admin_token="s3cret").admin_token, "s3cret")
        self.assertIs(
            self.config(admin_token=ADMIN_ISSUANCE_DISABLED).admin_token,
            ADMIN_ISSUANCE_DISABLED,
        )
        self.assertIs(
            self.config(admin_token=ADMIN_ISSUANCE_OPEN).admin_token,
            ADMIN_ISSUANCE_OPEN,
        )

    def test_the_modes_are_distinguishable_and_not_falsy_tokens(self):
        """ADMIN_ISSUANCE_* are identity-compared sentinels, not strings: a
        caller cannot reach one by sending a header, and they cannot be
        confused with each other."""
        self.assertIsNot(ADMIN_ISSUANCE_OPEN, ADMIN_ISSUANCE_DISABLED)
        self.assertNotIsInstance(ADMIN_ISSUANCE_OPEN, str)
        self.assertNotIsInstance(ADMIN_ISSUANCE_DISABLED, str)
        self.assertEqual(repr(ADMIN_ISSUANCE_OPEN), "ADMIN_ISSUANCE_OPEN")
        self.assertEqual(
            repr(ADMIN_ISSUANCE_DISABLED), "ADMIN_ISSUANCE_DISABLED"
        )


class AdminIssuanceOverHttpTest(MintHarness, unittest.TestCase):
    """End to end over real HTTP, one class per issuance state."""

    def test_a_gated_mint_still_issues_for_the_right_credential(self):
        mint = self.start_mint(admin_token="the-right-credential")
        req = {"outputs": [out_hash(100_000, new_secret())]}
        for headers in (None, {"X-Admin-Token": "the-wrong-credential"},
                        {"X-Admin-Token": ""}):
            status, body, _ = http_json(
                mint.port, "POST", "/admin/issue", req, headers
            )
            self.assertEqual(status, 401, (headers, body))
            self.assertEqual(body, {"status": "unauthorized"})
        status, body, _ = http_json(
            mint.port, "POST", "/admin/issue", req,
            {"X-Admin-Token": "the-right-credential"},
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(body["outputs_confirmed"], 1)

    def test_a_disabled_mint_refuses_every_caller_including_the_operator(self):
        mint = self.start_mint(admin_token=ADMIN_ISSUANCE_DISABLED)
        req = {"outputs": [out_hash(100_000, new_secret())]}
        for headers in (None, {"X-Admin-Token": ""},
                        {"X-Admin-Token": "ADMIN_ISSUANCE_DISABLED"},
                        {"X-Admin-Token": "None"},
                        {"X-Admin-Token": "anything-at-all"}):
            status, body, _ = http_json(
                mint.port, "POST", "/admin/issue", req, headers
            )
            self.assertEqual(status, 401, (headers, body))
            self.assertEqual(body, {"status": "unauthorized"})

    def test_a_disabled_mint_is_still_a_conforming_layer_0_mint(self):
        """L2/§3.7: shutting /admin/issue must not touch the anonymous
        bearer-access right. Issuance happens in-process instead."""
        mint = self.start_mint(admin_token=ADMIN_ISSUANCE_DISABLED)
        s0, s1 = new_secret(), new_secret()
        mint.ledger.issue([OutputSpec(amount_mc=100_000,
                                      secret_hash=ledger_key(s0))])
        status, body, _ = self.exchange(
            mint, "disabled-x", [tok(100_000, s0)], [out_hash(99_000, s1)]
        )
        self.assertEqual(status, 200, body)
        status, _, _ = http_raw(mint.port, "GET", "/v3/mints")
        self.assertEqual(status, 200)
        status, _, _ = self.status_batch(mint, [ledger_key(s1)])
        self.assertEqual(status, 200)

    def test_openness_requires_saying_the_word(self):
        """The grep property. A mint that serves /admin/issue bare exists
        only where ADMIN_ISSUANCE_OPEN is written down: saying nothing
        raises, and the other named state refuses."""
        req = {"outputs": [out_hash(50_000, new_secret())]}

        with self.assertRaises(ValueError):
            self.start_mint(admin_token=None)

        shut = self.start_mint(admin_token=ADMIN_ISSUANCE_DISABLED)
        status, _, _ = http_json(shut.port, "POST", "/admin/issue", req)
        self.assertEqual(status, 401)

        opened = self.start_mint(admin_token=ADMIN_ISSUANCE_OPEN)
        status, body, _ = http_json(opened.port, "POST", "/admin/issue", req)
        self.assertEqual(status, 200, body)

    def test_an_open_mint_announces_itself_at_construction(self):
        """Explicitly chosen is allowed; silent is not. The whole defect
        class was "nothing gets reported"."""
        with self.assertLogs("aicash.mintapi", level="WARNING") as captured:
            self.start_mint(admin_token=ADMIN_ISSUANCE_OPEN)
        text = "\n".join(r.getMessage() for r in captured.records)
        self.assertIn("UNAUTHENTICATED", text)
        self.assertIn("ADMIN_ISSUANCE_OPEN", text)


class IssuanceModeIdentitySurvivesCopyingTest(MintHarness, unittest.TestCase):
    """The modes are compared with `is`, so a copy must BE the original.

    MintConfig.__post_init__ validates admin_token by identity and
    admin_authorized() authorizes by identity. That makes ordinary copying
    a correctness question, not a curiosity: ``dataclasses.replace`` on a
    MintConfig is on the live path (SupervisionServer rebuilds every
    supervision mint's config with it), and a config that has been through
    ``copy.deepcopy`` or a pickle round trip has to come out the other side
    holding the same objects it went in with.

    Before __copy__/__deepcopy__/__reduce__ existed, it did not:
      * a deep-copied ADMIN_ISSUANCE_OPEN mint fell through to the non-str
        branch of admin_authorized() and refused EVERY caller, silently --
        the safe direction, but a deliberate choice reversed with nothing
        said anywhere; and
      * a deep-copied ADMIN_ISSUANCE_DISABLED config could not be rebuilt
        at all: dataclasses.replace() raised "is not one of the named
        issuance modes" about a value whose own repr printed
        ADMIN_ISSUANCE_DISABLED.
    """

    MODES = (ADMIN_ISSUANCE_OPEN, ADMIN_ISSUANCE_DISABLED)

    def config(self, admin_token, **kw):
        priv, pub = generate_keypair()
        base = dict(
            mint_id=MINT_ID,
            baseline_model_class="frontier-2026",
            burn_policy=POLICY,
            signing_private=priv,
            signing_public=pub,
            admin_token=admin_token,
        )
        base.update(kw)
        return MintConfig(**base)

    def test_copy_deepcopy_and_pickle_all_return_the_same_object(self):
        for mode in self.MODES:
            with self.subTest(mode=repr(mode)):
                self.assertIs(copy.copy(mode), mode)
                self.assertIs(copy.deepcopy(mode), mode)
                self.assertIs(pickle.loads(pickle.dumps(mode)), mode)
                for proto in range(pickle.HIGHEST_PROTOCOL + 1):
                    self.assertIs(
                        pickle.loads(pickle.dumps(mode, proto)), mode, proto
                    )
        # The private "nobody said" sentinel too: it is the value the
        # construction-time refusal keys off, so a copy of it that is merely
        # equal would be a non-credential that no branch recognises.
        self.assertIs(
            copy.deepcopy(mintapi._ADMIN_TOKEN_UNSET),
            mintapi._ADMIN_TOKEN_UNSET,
        )
        self.assertIs(
            pickle.loads(pickle.dumps(mintapi._ADMIN_TOKEN_UNSET)),
            mintapi._ADMIN_TOKEN_UNSET,
        )

    def test_a_deep_copied_config_keeps_the_policy_it_was_built_with(self):
        for mode in self.MODES:
            with self.subTest(mode=repr(mode)):
                copied = copy.deepcopy(self.config(mode))
                self.assertIs(copied.admin_token, mode)
                # ...and is still rebuildable, which is what
                # SupervisionServer.__init__ does to every mint it wraps.
                replaced = dataclasses.replace(
                    copied, profiles=("supervision",)
                )
                self.assertIs(replaced.admin_token, mode)

    def test_a_deep_copied_open_mint_is_still_open_over_http(self):
        """The silent reversal, pinned end to end: an ADMIN_ISSUANCE_OPEN
        config that has been through deepcopy must still serve bare
        /admin/issue. If identity is lost the mint runs and refuses
        everyone, reporting nothing."""
        mint = self.start_mint(admin_token=ADMIN_ISSUANCE_OPEN)
        copied_config = copy.deepcopy(mint.config)
        self.assertIs(copied_config.admin_token, ADMIN_ISSUANCE_OPEN)
        # Its own ledger file: one ledger is served by exactly one process
        # (the single-writer claim), and this test is about the config, not
        # about sharing state with the mint it was copied from.
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        ledger = Ledger(
            os.path.join(tmp.name, "ledger.sqlite3"),
            FakeClock(T0),
            POLICY,
            recovery_window_ms=90 * DAY_MS,
            max_lock_expiry_ms=30 * DAY_MS,
        )
        server = MintServer(copied_config, ledger)
        port = server.start()
        self.addCleanup(server.stop)
        status, body, _ = http_json(
            port, "POST", "/admin/issue",
            {"outputs": [out_hash(100_000, new_secret())]},
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(body["outputs_confirmed"], 1)

    def test_a_mode_that_is_only_a_look_alike_is_refused_and_said_so(self):
        """A mode built elsewhere is not the object, and the refusal must
        not claim it "is not one of the named issuance modes" while
        printing one of those very names."""
        impostor = mintapi._AdminIssuanceMode("ADMIN_ISSUANCE_OPEN")
        self.assertEqual(repr(impostor), "ADMIN_ISSUANCE_OPEN")
        with self.assertRaises(ValueError) as caught:
            self.config(impostor)
        msg = str(caught.exception)
        self.assertNotIn("is not one of the named issuance modes", msg)
        self.assertIn("compared by identity", msg)
        self.assertIn("aicash.mintapi", msg)


class GuidanceNamesAWorkingImportTest(unittest.TestCase):
    """The refusal tells the reader what to do; that instruction must run.

    The whole value of a loud ValueError is that the next thing the reader
    types works. The message names two sentinels, so it has to say where
    they come from, and the import it prints has to be one Python accepts.
    """

    def guidance(self):
        priv, pub = generate_keypair()
        with self.assertRaises(ValueError) as caught:
            MintConfig(
                mint_id=MINT_ID,
                baseline_model_class="frontier-2026",
                burn_policy=POLICY,
                signing_private=priv,
                signing_public=pub,
            )
        return str(caught.exception)

    def test_the_message_names_the_module_the_sentinels_live_in(self):
        msg = self.guidance()
        self.assertIn("ADMIN_ISSUANCE_DISABLED", msg)
        self.assertIn("ADMIN_ISSUANCE_OPEN", msg)
        self.assertIn("from aicash.mintapi import", msg)

    def test_the_import_line_it_prints_actually_executes(self):
        """Run the exact line out of the message, and check it binds the
        real objects rather than anything merely equal to them."""
        lines = [ln.strip() for ln in self.guidance().splitlines()]
        imports = [ln for ln in lines if ln.startswith("from aicash")]
        self.assertTrue(imports, self.guidance())
        for line in imports:
            with self.subTest(line=line):
                ns = {}
                exec(compile(line, "<guidance>", "exec"), ns)
                bound = {k: v for k, v in ns.items() if not k.startswith("__")}
                self.assertTrue(bound, line)
                for name, value in bound.items():
                    self.assertIs(value, getattr(mintapi, name), name)


class PackageRootSurfaceTest(unittest.TestCase):
    """`from aicash import X` must work for every X the docs promise.

    Round 4 gave MintConfig two sentinels, ADMIN_ISSUANCE_DISABLED and
    ADMIN_ISSUANCE_OPEN, and made a mint refuse to build until one of them
    or a real credential is named. They went into aicash.mintapi.__all__
    and not into the package root, while aicash/__init__.py's own docstring
    tells an embedder the integrator-facing surface lives at the root. So
    `from aicash import ADMIN_ISSUANCE_DISABLED` -- the single line whose
    entire job is to stop someone shipping an open mint -- raised
    ImportError, and the audience that hardening existed to protect was the
    audience it stranded.

    Adding those two names fixes one instance. These tests are written to
    fail on the NEXT name that lands in the same shape: they derive what the
    root must carry from the modules themselves, so a name added to mintapi
    (or a new exception, or a new return type) and forgotten here fails
    here, with a message naming it.
    """

    # Empty, and it has to be earned back. The one entry that used to sit
    # here said aicash.lockeval.LockError never reaches an integrator
    # because "ledgerstore catches it internally". That was written from
    # reading ledgerstore.py:351 (validate_lock, which IS wrapped) and not
    # ledgerstore.py:303 (evaluate, which is not): a mint.db row whose
    # lock_preimage_hash is not b64u makes Ledger.exchange -- a root-
    # exported class's method -- raise LockError straight out at the
    # caller. test_lockerror_really_does_escape_to_a_root_only_caller
    # causes exactly that, every run.
    #
    # So the rule for adding an entry back: do not reason about whether an
    # exception can escape, CAUSE it escaping or failing to. An allowlist
    # entry is a claim about runtime behaviour, and the wrong kind of claim
    # to take on trust -- it is the one thing in this class that turns the
    # detector off.
    EXCEPTIONS_DELIBERATELY_OFF_ROOT: set = set()

    # Every module whose whole __all__ the root mirrors. The rule is not
    # "mintapi is special", it is "a module an embedder integrates against
    # has no member they are meant to be kept away from": mintapi builds a
    # mint, wallet pays and gets paid (the README's headline surface),
    # envelope is the §9.5 wire object between two agents, supervision runs
    # a fleet. Pinning only mintapi left wallet -- the surface most people
    # touch first -- guarded by nothing for non-exception names.
    #
    # NOT on this list, with the reason, because an unexplained split is
    # how the last gap hid: burncalc, channels, escrow, ledgerstore,
    # lockeval, receipts, signing, swap and tokencodec all export internals
    # (validate_policy, split_tranches, parse_output_wire, sign_raw,
    # SCHEMA_V, ...) that belong to the implementation's own layering, not
    # to a first integration. Those modules are covered by the narrower
    # return-type / parameter-type / exception sweeps below instead.
    WHOLLY_MIRRORED_MODULES = ("mintapi", "wallet", "envelope", "supervision")

    @staticmethod
    def aicash_modules():
        """Every submodule of the package, imported."""
        import importlib
        import pkgutil

        import aicash

        mods = []
        for info in pkgutil.iter_modules(aicash.__path__):
            mods.append(importlib.import_module("aicash." + info.name))
        return mods

    def test_every_name_in_all_is_actually_importable_from_the_root(self):
        """`__all__` is a promise `from aicash import *` has to keep."""
        import aicash

        for name in aicash.__all__:
            with self.subTest(name=name):
                ns = {}
                try:
                    exec("from aicash import %s" % name, ns)
                except ImportError as exc:
                    self.fail("aicash.__all__ promises %r: %s" % (name, exc))
                self.assertIs(ns[name], getattr(aicash, name), name)
        self.assertEqual(
            len(set(aicash.__all__)), len(aicash.__all__),
            "aicash.__all__ lists a name twice: %s"
            % sorted({n for n in aicash.__all__ if aicash.__all__.count(n) > 1}),
        )

    def test_the_import_line_in_the_package_docstring_runs(self):
        """The docstring shows an import. Readers type what they are shown."""
        import aicash

        shown = re.findall(r"from aicash import ([^`\n]+)", aicash.__doc__ or "")
        self.assertTrue(shown, "the package docstring no longer shows an import")
        for clause in shown:
            names = [n.strip() for n in clause.split(",")]
            names = [n for n in names if n and n != "..."]
            self.assertTrue(names, clause)
            for name in names:
                with self.subTest(name=name):
                    self.assertIn(name, aicash.__all__)
                    self.assertTrue(hasattr(aicash, name), name)

    def test_the_integrator_facing_modules_reach_the_root_whole(self):
        """The defect this class exists for, stated as a set difference.

        Round 4's gap was mintapi's; the rule is wider than mintapi. Each
        module in WHOLLY_MIRRORED_MODULES is one an embedder integrates
        against, with no member meant to be kept away from them, so the
        whole of its __all__ belongs at the root. The next name added to
        ANY of them is caught here without editing this test.

        Identity, not name: a same-named object from another module bound
        at the root is exactly the silent substitution this is meant to
        catch, and it is not hypothetical -- aicash.escrow.__all__ and
        aicash.receipts.__all__ both name make_dispute_record, and they are
        two different functions with different signatures.
        """
        import importlib

        import aicash

        for mod_name in self.WHOLLY_MIRRORED_MODULES:
            mod = importlib.import_module("aicash." + mod_name)
            with self.subTest(module=mod_name):
                missing = [n for n in mod.__all__ if n not in aicash.__all__]
                self.assertEqual(
                    missing, [],
                    "aicash.%s.__all__ names %s, which aicash/__init__.py"
                    " does not re-export. Add them to the import and to"
                    " __all__ there: the package docstring points"
                    " integrators at the root and names this module as one"
                    " it mirrors whole." % (mod_name, missing),
                )
                for name in mod.__all__:
                    with self.subTest(name=name):
                        self.assertIs(
                            getattr(aicash, name), getattr(mod, name),
                            "aicash.%s is not aicash.%s.%s -- the root binds"
                            " a different object under the same name"
                            % (name, mod_name, name),
                        )

    def test_the_mirror_list_names_only_real_modules_with_an_all(self):
        """A typo in WHOLLY_MIRRORED_MODULES would silently guard nothing."""
        import importlib

        for mod_name in self.WHOLLY_MIRRORED_MODULES:
            with self.subTest(module=mod_name):
                mod = importlib.import_module("aicash." + mod_name)
                self.assertTrue(
                    getattr(mod, "__all__", None),
                    "aicash.%s is listed as wholly mirrored but declares no"
                    " __all__, so the check above compares nothing" % mod_name,
                )

    @staticmethod
    def annotated_targets():
        """(label, callable) for everything reachable from the root.

        Exported functions, exported classes' public methods, and each
        exported class's __init__ -- a constructor argument is a type the
        caller has to be able to NAME just as much as a return value is.
        """
        import inspect

        import aicash

        targets = []
        for name in aicash.__all__:
            obj = getattr(aicash, name)
            if inspect.isclass(obj):
                targets.append(("%s.__init__" % name, obj.__init__))
                for attr in dir(obj):
                    if attr.startswith("_"):
                        continue
                    member = getattr(obj, attr, None)
                    if callable(member):
                        targets.append(("%s.%s" % (name, attr), member))
            elif callable(obj):
                targets.append((name, obj))
        return targets

    @staticmethod
    def leaked_annotations(which):
        """Classes named in annotations that the root cannot bind.

        `which` is "return" or "param". A class is fine if the root binds
        THAT object -- identity, not name. A same-named different class at
        the root is the substitution the sentinel test guards against with
        assertIs, and these sweeps used to accept it.
        """
        import inspect
        import typing

        import aicash

        leaked = {}
        for label, fn in PackageRootSurfaceTest.annotated_targets():
            try:
                hints = typing.get_type_hints(fn)
            except Exception:
                continue  # forward ref we cannot resolve; not this test's job
            if which == "return":
                items = [("return", hints.get("return"))]
            else:
                items = [(k, v) for k, v in hints.items() if k != "return"]
            for pname, ann in items:
                for cand in (ann,) + tuple(typing.get_args(ann) or ()):
                    if not inspect.isclass(cand):
                        continue
                    if not getattr(cand, "__module__", "").startswith("aicash."):
                        continue
                    if cand.__name__.startswith("_"):
                        # A private class is one the caller is never meant
                        # to name: MintConfig.admin_token is annotated
                        # `str | _AdminIssuanceMode`, and every legal value
                        # of it (a credential string, ADMIN_ISSUANCE_OPEN,
                        # ADMIN_ISSUANCE_DISABLED) is nameable at the root
                        # without the class. Exempt by construction, not by
                        # allowlist, so it cannot go stale.
                        continue
                    if getattr(aicash, cand.__name__, None) is cand:
                        continue
                    where = "%s:%s" % (label, pname) if which == "param" else label
                    leaked.setdefault(
                        "%s.%s" % (cand.__module__, cand.__name__), []
                    ).append(where)
        return {k: sorted(set(v)) for k, v in leaked.items()}

    def test_types_the_surface_returns_can_be_named_from_the_surface(self):
        """A call at the root that hands back a class only a submodule
        names forces the caller back into implementation source to write an
        annotation or an isinstance check. parse_token -> Token and
        parse_envelope -> Envelope were both in that state."""
        leaked = self.leaked_annotations("return")
        self.assertEqual(
            leaked, {},
            "these types are returned by package-root calls but cannot be"
            " imported from the package root: %s" % (leaked,),
        )

    def test_types_the_surface_demands_can_be_named_from_the_surface(self):
        """The neighbour of the test above, and the reason it is here.

        The return sweep covered types a root call hands BACK and said
        nothing about types it ASKS FOR -- and a caller who cannot name an
        argument type is in exactly the same scavenger hunt: they cannot
        annotate the variable they are about to pass, or build one. Clean
        today; the point is that it stays clean when a public helper class
        is added to a submodule and threaded into a root-exported call.
        """
        leaked = self.leaked_annotations("param")
        self.assertEqual(
            leaked, {},
            "these types are accepted as arguments by package-root calls"
            " but cannot be imported from the package root: %s" % (leaked,),
        )

    def test_exceptions_the_surface_raises_are_catchable_from_the_surface(self):
        """Round 4's shape, generalised. aicash/__init__.py already says
        'error handling is part of the integration surface' and the README
        promises the exception classes each call can raise are re-exported;
        PolicyError (raised by the root-exported compute_burn) and
        EnvelopeError (raised by the root-exported parse_envelope) were not.
        A new exception class either lands on the root or gets written into
        EXCEPTIONS_DELIBERATELY_OFF_ROOT with the reason."""
        import inspect

        import aicash

        off_root = []
        for mod in self.aicash_modules():
            for name, obj in vars(mod).items():
                if not inspect.isclass(obj) or not issubclass(obj, BaseException):
                    continue
                if obj.__module__ != mod.__name__:
                    continue  # imported into this module, owned by another
                qual = "%s.%s" % (obj.__module__, name)
                if qual in self.EXCEPTIONS_DELIBERATELY_OFF_ROOT:
                    continue
                # Identity, not name: `except SomeError` that binds a
                # different class of the same name is a bare `except` that
                # looks careful. Matching on the name alone accepted that.
                if getattr(aicash, name, None) is obj:
                    continue
                off_root.append(qual)
        self.assertEqual(
            sorted(off_root), [],
            "these exception classes cannot be caught by a caller who"
            " imported only from the package root: %s. Re-export them in"
            " aicash/__init__.py, or list them in"
            " EXCEPTIONS_DELIBERATELY_OFF_ROOT with why a caller never"
            " sees them." % (sorted(off_root),),
        )

    def test_the_allowlist_does_not_outlive_the_names_on_it(self):
        """A stale exemption is how the next gap hides. Every entry must
        still name a real exception class."""
        import importlib

        for qual in self.EXCEPTIONS_DELIBERATELY_OFF_ROOT:
            with self.subTest(qual=qual):
                mod_name, _, cls_name = qual.rpartition(".")
                mod = importlib.import_module(mod_name)
                cls = getattr(mod, cls_name, None)
                self.assertTrue(
                    isinstance(cls, type) and issubclass(cls, BaseException),
                    "%s is exempted from the package surface but is no longer"
                    " an exception class defined there; drop the entry" % qual,
                )

    def test_lockerror_really_does_escape_to_a_root_only_caller(self):
        """Causes the escape the old allowlist entry said was impossible.

        The entry read "ledgerstore catches it internally rather than
        letting it reach a caller". ledgerstore wraps validate_lock on the
        way IN (:351) and does not wrap evaluate on the way OUT (:303),
        and _lock_from_row re-validates nothing -- so a mint.db row with an
        unreadable lock_preimage_hash (damaged file, hand-edited row,
        restored-from-a-bad-backup operator) raises aicash.lockeval.LockError
        out of Ledger.exchange, which is a root-exported class's method.

        This test exists so the claim is re-caused on every run rather than
        re-reasoned. If ledgerstore ever does catch it, this fails and says
        so -- at which point LockError may go back on the allowlist WITH a
        pointer to that catch, and not before.
        """
        import base64

        import aicash
        from aicash.lockeval import InputForm
        from aicash.tokencodec import Token, new_secret

        def b64u(raw):
            return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "mint.db")
            ledger = aicash.Ledger(
                db,
                FakeClock(1_000),
                BurnPolicy(rate_ppm=0, cap_mc=0, exempt_below_mc=10),
                0,
                None,
            )
            secret = new_secret()
            preimage = os.urandom(32)
            ledger.issue([
                aicash.OutputSpec(
                    amount_mc=100,
                    secret=secret,
                    lock={
                        "preimage_hash": b64u(hashlib.sha256(preimage).digest()),
                        "expiry": 10 ** 12,
                        "refund_hash": b64u(hashlib.sha256(os.urandom(32)).digest()),
                    },
                )
            ])
            conn = sqlite3.connect(db)
            conn.execute("UPDATE entries SET lock_preimage_hash = '!!!not-b64u!!!'")
            conn.commit()
            conn.close()

            form = InputForm(
                kind="claim",
                token=Token(mint_id="mint-abc", amount_mc=100, secret=secret),
                witness=preimage,
            )
            # The point of the test: an integrator holding only root
            # imports must be able to WRITE this except clause.
            with self.assertRaises(aicash.LockError):
                ledger.exchange(
                    "idem-corrupt-lock",
                    "digest-corrupt-lock",
                    [form],
                    None,
                    [aicash.OutputSpec(amount_mc=100, secret=new_secret())],
                )

        self.assertNotIn(
            "aicash.lockeval.LockError", self.EXCEPTIONS_DELIBERATELY_OFF_ROOT,
            "LockError escapes Ledger.exchange (just demonstrated above), so"
            " it cannot be exempted from the package root",
        )

    # (repo-relative file, the stale sentence in it). Each pair must be
    # mentioned in the package docstring's "Known-stale neighbours" block
    # exactly while the sentence is still there -- see the test below.
    STALE_NEIGHBOURS = (
        ("components/C06-mintapi.md", "admin_token: str | None = None"),
        ("components/C06-mintapi.md",
         "With no token configured the route is open"),
        ("README.md", "61 names"),
        ("USABILITY-REPORT.md", "61 names"),
    )

    @staticmethod
    def repo_root():
        here = os.path.dirname(os.path.abspath(__file__))       # impl/tests
        return os.path.dirname(os.path.dirname(here))           # repo root

    @staticmethod
    def stale_notes_block():
        """The package docstring's "Known-stale neighbours" section."""
        import aicash

        doc = aicash.__doc__ or ""
        _, sep, rest = doc.partition("Known-stale neighbours")
        return rest if sep else ""

    def test_the_root_docstring_corrects_the_docs_that_contradict_it(self):
        """The adjacency this class could not fix by editing its own files.

        README.md:73 sends a reader to the components/ "Public API" blocks
        as THE per-module reference, and aicash/__init__.py's docstring
        repeats that pointer. components/C06-mintapi.md still documents
        `admin_token: str | None = None` and still says /admin/issue is
        open when unconfigured -- the exact footgun round 4 removed, and
        the opposite of what LOCKED-DESIGN-DECISIONS.md, DEPLOYMENT.md and
        the code say. Two neighbouring documents, opposite answers to "what
        happens if I say nothing about admin_token?", and the wrong one is
        the safety-critical one.

        components/ is not this slice's to edit, so the root docstring --
        which IS -- carries the correction, and this test keeps the
        correction honest in both directions: it fails if a stale sentence
        is still out there unmentioned, and it fails if someone fixes the
        document and leaves a note here claiming it is still broken. Either
        way the note cannot quietly become the next false statement.
        """
        block = self.stale_notes_block()
        for rel, sentence in self.STALE_NEIGHBOURS:
            with self.subTest(file=rel, sentence=sentence):
                path = os.path.join(self.repo_root(), rel)
                try:
                    with io.open(path, encoding="utf-8") as fh:
                        text = fh.read()
                except OSError:
                    text = ""
                still_stale = sentence in text
                basename = os.path.basename(rel)
                noted = basename in block and sentence in block
                if still_stale:
                    self.assertTrue(
                        noted,
                        "%s still says %r, and the package docstring's"
                        " Known-stale neighbours block does not say so. An"
                        " integrator pointed at that document by README.md"
                        " gets the pre-round-4 answer with nothing at the"
                        " root to contradict it." % (rel, sentence),
                    )
                else:
                    self.assertFalse(
                        noted,
                        "%s no longer says %r -- drop it from the package"
                        " docstring's Known-stale neighbours block before"
                        " the correction becomes the stale statement."
                        % (rel, sentence),
                    )

    @staticmethod
    def name_collisions():
        """Names two modules both export, bound to different objects.

        The root can bind only one of them, so `from aicash import <name>`
        silently gives one module's caller the other module's function.
        """
        import collections
        import importlib
        import pkgutil

        import aicash

        owners = collections.defaultdict(list)
        for info in pkgutil.iter_modules(aicash.__path__):
            mod = importlib.import_module("aicash." + info.name)
            for name in getattr(mod, "__all__", ()):
                owners[name].append((info.name, getattr(mod, name)))
        return {
            name: sorted(m for m, _ in owned)
            for name, owned in owners.items()
            if len(owned) > 1 and len({id(o) for _, o in owned}) > 1
        }

    def test_every_root_name_two_modules_fight_over_is_disclosed(self):
        """Found while sweeping the neighbours of the mirror rule.

        aicash.escrow.__all__ and aicash.receipts.__all__ both name
        make_dispute_record, and they are different functions taking
        different arguments (evidence vs evidence_hash). `from aicash
        import make_dispute_record` binds the receipts one, so an escrow
        user who followed the root -- the import line this package's
        docstring tells everyone to use -- gets a function that does not
        take their arguments, with no error until call time.

        Renaming either belongs to those modules. What belongs here is
        that the collision is stated where the root sends people, and this
        pins that both ways: a new collision must be disclosed, and a
        disclosure must be deleted once the collision is gone.
        """
        collisions = self.name_collisions()
        block = self.stale_notes_block()
        for name in sorted(collisions):
            with self.subTest(name=name):
                self.assertIn(
                    name, block,
                    "aicash.%s is exported by %s with different objects"
                    " behind it; the package docstring does not tell a"
                    " reader which one the root binds"
                    % (name, collisions[name]),
                )
        for line in block.splitlines():
            if "aicash.escrow.__all__" not in line:
                continue
            self.assertTrue(
                collisions,
                "the package docstring still discloses a two-module name"
                " collision, but no module pair exports the same name with"
                " different objects any more; delete the note",
            )

    def test_the_note_about_components_not_naming_the_sentinels_is_current(self):
        """Same two-way pin for the other half of the C06 gap: the two
        sentinels a mint cannot be built without appear nowhere under
        components/, though the root docstring and DEPLOYMENT.md lead with
        them."""
        claim = "does not yet mention either sentinel"
        block = self.stale_notes_block()
        root = os.path.join(self.repo_root(), "components")
        found = []
        for dirpath, _dirs, files in os.walk(root):
            for fname in files:
                if not fname.endswith(".md"):
                    continue
                with io.open(os.path.join(dirpath, fname), encoding="utf-8") as fh:
                    if "ADMIN_ISSUANCE" in fh.read():
                        found.append(fname)
        if found:
            self.assertNotIn(
                claim, block,
                "components/%s now names ADMIN_ISSUANCE_*; the package"
                " docstring still says components/ does not mention the"
                " sentinels" % (sorted(found),),
            )
        else:
            self.assertIn(
                claim, block,
                "no file under components/ mentions ADMIN_ISSUANCE_OPEN or"
                " ADMIN_ISSUANCE_DISABLED -- the names round 4 made"
                " mandatory -- and the package docstring no longer says so",
            )

    def test_the_root_docstring_states_the_live_admin_token_rule(self):
        """The correcting half has to be right, not just present: build a
        MintConfig the stale component doc endorses and check the root
        docstring already told the reader what happens."""
        import aicash

        doc = aicash.__doc__ or ""
        priv, pub = generate_keypair()
        base = dict(
            mint_id="mint-doc-check",
            baseline_model_class="frontier-2026",
            burn_policy=POLICY,
            signing_private=priv,
            signing_public=pub,
        )
        # Exactly the config components/C06-mintapi.md still says is legal.
        with self.assertRaises(ValueError) as unset:
            MintConfig(**base)
        with self.assertRaises(ValueError) as explicit_none:
            MintConfig(admin_token=None, **base)
        self.assertIn("admin_token", str(unset.exception))
        self.assertIn("admin_token", str(explicit_none.exception))
        flat = " ".join(doc.split())
        self.assertIn("``MintConfig`` has NO default for ``admin_token``", flat)
        self.assertIn("``admin_token=None`` is rejected by name", flat)
        for name in ("ADMIN_ISSUANCE_DISABLED", "ADMIN_ISSUANCE_OPEN"):
            self.assertIn(name, doc, name)

    def test_the_two_sentinels_survive_the_trip_through_the_root(self):
        """Identity, not equality: admin_authorized() compares with `is`,
        so a root re-export that produced a copy would silently disable the
        refusal it exists to serve."""
        import aicash

        self.assertIs(aicash.ADMIN_ISSUANCE_OPEN, ADMIN_ISSUANCE_OPEN)
        self.assertIs(aicash.ADMIN_ISSUANCE_DISABLED, ADMIN_ISSUANCE_DISABLED)
        priv, pub = generate_keypair()
        cfg = MintConfig(
            mint_id=MINT_ID,
            baseline_model_class="frontier-2026",
            burn_policy=POLICY,
            signing_private=priv,
            signing_public=pub,
            admin_token=aicash.ADMIN_ISSUANCE_DISABLED,
        )
        self.assertIs(cfg.admin_token, ADMIN_ISSUANCE_DISABLED)


class AdminAuthorizedUnitTest(unittest.TestCase):
    """admin_authorized() directly, including the comparison it must use."""

    def core(self, admin_token):
        priv, pub = generate_keypair()
        config = MintConfig(
            mint_id=MINT_ID,
            baseline_model_class="frontier-2026",
            burn_policy=POLICY,
            signing_private=priv,
            signing_public=pub,
            admin_token=admin_token,
        )
        return mintapi._Core.__new__(mintapi._Core), config

    def authorized(self, admin_token, presented):
        core, config = self.core(admin_token)
        core.config = config
        return mintapi._Core.admin_authorized(core, presented)

    def test_disabled_refuses_every_presented_value(self):
        for presented in (None, "", "x", "ADMIN_ISSUANCE_OPEN", " "):
            self.assertFalse(
                self.authorized(ADMIN_ISSUANCE_DISABLED, presented),
                repr(presented),
            )

    def test_open_accepts_every_presented_value(self):
        for presented in (None, "", "x"):
            self.assertTrue(self.authorized(ADMIN_ISSUANCE_OPEN, presented))

    def test_a_secret_matches_only_itself(self):
        self.assertTrue(self.authorized("abcdef", "abcdef"))
        for presented in (None, "", "abcde", "abcdeg", "abcdef ", " abcdef",
                          "ABCDEF"):
            self.assertFalse(self.authorized("abcdef", presented),
                             repr(presented))

    def test_the_comparison_is_still_constant_time(self):
        """Not weakened by the refusal work: the match arm goes through
        hmac.compare_digest, never ==."""
        calls = []
        real = mintapi.hmac.compare_digest

        def spy(a, b):
            calls.append((a, b))
            return real(a, b)

        original = mintapi.hmac.compare_digest
        mintapi.hmac.compare_digest = spy
        self.addCleanup(
            setattr, mintapi.hmac, "compare_digest", original
        )
        self.assertTrue(self.authorized("abcdef", "abcdef"))
        self.assertFalse(self.authorized("abcdef", "abcdeg"))
        self.assertEqual(len(calls), 2)
        for a, b in calls:
            self.assertIsInstance(a, bytes)
            self.assertIsInstance(b, bytes)
        # ...and the refusing states never reach it at all: there is no
        # comparison to win when the answer is a flat no.
        calls.clear()
        self.assertFalse(self.authorized(ADMIN_ISSUANCE_DISABLED, "abcdef"))
        self.assertEqual(calls, [])


class DescriptorCompletenessTest(MintHarness, unittest.TestCase):
    """§3.6: "All fields mandatory unless marked profile-scoped"."""

    def test_signing_pubkey_next_is_published_as_an_explicit_null(self):
        """signing_pubkey_next is typed `null | {...}` and carries no
        profile marking, so it is mandatory and nullable. An ABSENT key
        reads to a §3.6 client as a mint predating the field; an explicit
        null says "no rotation announced". Rotation itself stays out of
        scope (L17), so the value is null and nothing may set it without
        the cross-signature §3.6 requires."""
        mint = self.start_mint()
        status, raw, _ = http_raw(mint.port, "GET", "/v3/mints")
        self.assertEqual(status, 200)
        desc = json.loads(raw.decode("utf-8"))
        self.assertIn("signing_pubkey_next", desc)
        self.assertIsNone(desc["signing_pubkey_next"])
        # Its sibling nullable-change-notice field is published the same
        # way, which is the precedent this follows.
        self.assertIn("burn_policy_next", desc)
        self.assertIsNone(desc["burn_policy_next"])

    def test_every_mandatory_3_6_field_is_present(self):
        mint = self.start_mint()
        _, raw, _ = http_raw(mint.port, "GET", "/v3/mints")
        desc = json.loads(raw.decode("utf-8"))
        for key in (
            "mint_id", "baseline_model_class", "mint_time",
            "denominations_mc", "burn_policy", "burn_policy_next", "supply",
            "performance", "limits", "signing_pubkey", "signing_pubkey_next",
            "lock_params", "retention", "profiles", "activity",
        ):
            self.assertIn(key, desc, key)


# ======================================================================== #
# JOB 1 — the framing rule is ONE exported function, and the mint's own    #
# handlers are among its callers.                                          #
# ======================================================================== #


class TheFramingRuleIsOneSharedFunctionTest(MintHarness, unittest.TestCase):
    """The defect this class exists for is not a framing defect.

    It is the third time in this repository that a defect was fixed where
    it was found while its siblings sat untouched. The framing rule was
    fixed in the mint for ONE spelling, fixed again properly against the
    class, and the two other HTTP servers in the same tree kept the broken
    version: nineteen of twenty-five spellings still framed a body on the
    operator GUI, on every POST route AND on its GET routes.

    So the rule is now ``aicash.mintapi.framing_verdict`` — public,
    importable, and called by all four servers. These tests assert the
    property that makes that structural rather than aspirational: THE
    MINT'S OWN HANDLERS GO THROUGH IT. Written against the exported
    function's observed CALLS, not against anybody's source text, so an
    internal refactor (a new private helper, a different override point, a
    renamed method) keeps passing and a handler that grows its own private
    copy of the rule fails — which is the only failure mode worth a test
    here.
    """

    def install_recorder(self):
        """Replace the module global with a recording pass-through.

        Returns the list it records into. Restored on cleanup. The
        replacement must be looked up as a module global at CALL time for
        this to see anything, which is itself part of what is asserted: a
        handler holding its own bound copy records nothing.
        """
        calls = []
        real = mintapi.framing_verdict

        def recorder(headers, **kwargs):
            verdict = real(headers, **kwargs)
            calls.append(
                {
                    "probe": headers.get("X-Framing-Probe"),
                    "kwargs": kwargs,
                    "verdict": verdict,
                }
            )
            return verdict

        mintapi.framing_verdict = recorder
        self.addCleanup(setattr, mintapi, "framing_verdict", real)
        return calls

    def probe(self, port, method, path, probe, extra=b"", body=b""):
        """One hand-built request carrying a unique probe header."""
        request = (
            ("%s %s HTTP/1.1\r\n" % (method, path)).encode("ascii")
            + b"Host: 127.0.0.1\r\n"
            + b"X-Framing-Probe: " + probe.encode("ascii") + b"\r\n"
            + extra
            + b"Content-Length: %d\r\n" % len(body)
            + b"Connection: close\r\n\r\n"
            + body
        )
        return raw_request(port, request, timeout=8.0)

    # -- the handlers are callers ---------------------------------------

    def test_the_post_handler_routes_through_the_exported_function(self):
        """A real POST /v3/exchange, and the exported rule saw THIS
        request's headers. The probe header is what makes it this request
        and not a coincidental call from somewhere else in the process."""
        mint = self.start_mint()
        calls = self.install_recorder()
        body = json.dumps(
            {"idempotency_key": "job1-post", "inputs": [], "outputs": []}
        ).encode()
        raw = self.probe(mint.port, "POST", "/v3/exchange", "post-1", body=body)
        self.assertIn(b"200", raw.split(b"\r\n")[0], raw[:200])
        seen = [c for c in calls if c["probe"] == "post-1"]
        self.assertTrue(
            seen,
            "the POST body reader did not ask mintapi.framing_verdict:"
            " a handler is deciding framing on its own again",
        )
        # The body-bearing question, which is the one whose default the
        # whole class turns on.
        self.assertTrue(
            any(c["kwargs"].get("body_expected", True) for c in seen), seen
        )

    def test_the_get_handler_routes_through_the_exported_function(self):
        """The GET guard too. It is the half an earlier round left behind:
        a rule that only covers POST leaves every GET route smuggleable on
        the same socket."""
        mint = self.start_mint()
        calls = self.install_recorder()
        raw = self.probe(mint.port, "GET", "/v3/mints", "get-1")
        self.assertIn(b"200", raw.split(b"\r\n")[0], raw[:200])
        seen = [c for c in calls if c["probe"] == "get-1"]
        self.assertTrue(
            seen,
            "the GET guard did not ask mintapi.framing_verdict:"
            " a handler is deciding framing on its own again",
        )
        self.assertTrue(
            any(c["kwargs"].get("body_expected") is False for c in seen),
            seen,
        )

    def test_every_route_on_this_server_asks_it(self):
        """Not two handlers: every route. A route that answers without
        asking is a route with its own framing rule, whatever its source
        looks like."""
        mint = self.start_mint()
        calls = self.install_recorder()
        routes = [
            ("POST", "/v3/exchange",
             b'{"idempotency_key":"j1","inputs":[],"outputs":[]}'),
            ("POST", "/v3/status", b'{"hashes":[]}'),
            ("POST", "/admin/issue", b'{"outputs":[]}'),
            ("GET", "/v3/mints", b""),
            ("GET", "/v3/status/" + "A" * 43, b""),
            ("GET", "/nope", b""),
            ("POST", "/nope", b'{}'),
        ]
        for i, (method, path, body) in enumerate(routes):
            with self.subTest(route=path, method=method):
                tag = "r%d" % i
                self.probe(mint.port, method, path, tag, body=body)
                self.assertTrue(
                    [c for c in calls if c["probe"] == tag],
                    "%s %s answered without asking framing_verdict" % (
                        method, path),
                )

    # -- what the function may and may not carry -------------------------

    def test_the_verdict_carries_the_pinned_fields_and_no_http(self):
        """The contract its four callers share. It decides FRAMING: no
        status codes, no error envelopes, because the mint answers §3.8
        `bad_format`, the supervision profile answers its own shape, and
        the two operator consoles answer theirs. A verdict carrying a
        status would be usable by exactly one of them."""
        message = email.parser.Parser().parsestr(
            "Host: h\r\nContent-Length: 7\r\n\r\n"
        )
        verdict = mintapi.framing_verdict(message)
        for field in ("length", "framed", "must_close", "reason"):
            self.assertTrue(hasattr(verdict, field), field)
        self.assertEqual(verdict.length, 7)
        self.assertIs(verdict.framed, True)
        self.assertIs(verdict.must_close, False)
        self.assertIsInstance(verdict.reason, str)
        self.assertIn(verdict.reason, mintapi.FRAMING_REASONS)
        # No HTTP anywhere in it: no int that could be read as a status,
        # no "errors" list, no "status" key.
        values = [getattr(verdict, f) for f in dir(verdict)
                  if not f.startswith("_")]
        for value in values:
            self.assertNotIsInstance(value, (list, dict))
        self.assertFalse(hasattr(verdict, "status"))
        self.assertFalse(hasattr(verdict, "errors"))
        self.assertFalse(hasattr(verdict, "code"))

    def test_the_pinned_call_shape_works_with_one_argument(self):
        """`framing_verdict(headers)` is the pinned spelling, so the
        body-expecting verdict has to be the DEFAULT — a caller that
        forgets the keyword must get the strict answer, never the lax
        one."""
        signature = inspect.signature(mintapi.framing_verdict)
        self.assertEqual(
            [p for p in signature.parameters], ["headers", "body_expected"]
        )
        self.assertIs(
            signature.parameters["body_expected"].default, True
        )
        self.assertIs(
            signature.parameters["body_expected"].kind,
            inspect.Parameter.KEYWORD_ONLY,
        )
        no_length = email.parser.Parser().parsestr("Host: h\r\n\r\n")
        self.assertIs(mintapi.framing_verdict(no_length).framed, False)

    def test_length_and_framed_are_the_same_fact(self):
        """`length is None` iff `not framed`, on every verdict this rule
        can produce. A caller that reads one and a caller that reads the
        other must never disagree — that disagreement is what the two
        halves of the mint had."""
        for raw_headers in (
            "Host: h\r\n\r\n",
            "Host: h\r\nContent-Length: 0\r\n\r\n",
            "Host: h\r\nContent-Length: 12\r\n\r\n",
            "Host: h\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
            "Host: h\r\nContent-Length: +5\r\n\r\n",
            "Host: h\r\nTransfer_Encoding: chunked\r\nContent-Length: 0\r\n\r\n",
            "Host: h\r\nTransfer-Encoding: chunked\r\n\r\n",
            "Host: h\r\nContent-Length : 5\r\n\r\n",
        ):
            for expected in (True, False):
                with self.subTest(headers=raw_headers, body=expected):
                    message = email.parser.Parser().parsestr(raw_headers)
                    v = mintapi.framing_verdict(
                        message, body_expected=expected
                    )
                    self.assertIs(v.framed, v.length is not None, v)
                    self.assertIn(v.reason, mintapi.FRAMING_REASONS, v)
                    if not v.framed:
                        self.assertIs(v.must_close, True, v)

    def test_must_close_is_what_the_mint_actually_does(self):
        """`must_close` is the field the other three servers act on, so it
        has to agree with the mint's own wire behaviour rather than merely
        exist. Driven over a socket: the connection header the mint sends
        IS the assertion."""
        mint = self.start_mint()
        cases = [
            # (method, path, extra headers, body, probe)
            ("GET", "/v3/mints", b"", b""),
            ("GET", "/v3/mints", b"Content-Length: 4\r\n", b"junk"),
            ("GET", "/v3/mints", b"Transfer-Encoding: chunked\r\n", b""),
            ("GET", "/v3/mints", b"Content_Length: 4\r\n", b""),
            ("GET", "/v3/mints",
             b"Content-Length: 0\r\nContent-Length: 0\r\n", b""),
        ]
        for i, (method, path, extra, body) in enumerate(cases):
            with self.subTest(extra=extra):
                request = (
                    ("%s %s HTTP/1.1\r\n" % (method, path)).encode("ascii")
                    + b"Host: 127.0.0.1\r\n" + extra + b"\r\n" + body
                )
                message = email.parser.Parser().parsestr(
                    (b"Host: 127.0.0.1\r\n" + extra + b"\r\n"
                     ).decode("latin-1")
                )
                verdict = mintapi.framing_verdict(
                    message, body_expected=False
                )
                raw = raw_request(mint.port, request, shutdown_write=True,
                                  timeout=8.0)
                _, headers, _ = parse_http(raw)
                closed = headers.get("connection") == "close"
                self.assertIs(
                    closed, verdict.must_close,
                    "verdict %r vs wire %r" % (verdict, headers),
                )

    # -- and it is exported the way the other integrator names are -------

    def test_the_rule_is_on_the_package_root(self):
        """Three other servers import it. A rule that can only be reached
        by reaching into a private method of a private handler class is a
        rule that gets copied instead, which is the whole history here."""
        import aicash

        self.assertIn("framing_verdict", mintapi.__all__)
        self.assertIn("FramingVerdict", mintapi.__all__)
        self.assertIn("FRAMING_REASONS", mintapi.__all__)
        self.assertIs(aicash.framing_verdict, mintapi.framing_verdict)
        self.assertIs(aicash.FramingVerdict, mintapi.FramingVerdict)
        ns = {}
        exec("from aicash.mintapi import framing_verdict", ns)
        self.assertIs(ns["framing_verdict"], mintapi.framing_verdict)

    #: Every RFC 7230 ``tchar``. The corpus below is BUILT from these
    #: rather than listed, for the reason the rule itself is: a list of bad
    #: spellings is what was wrong the first two times, and the third time
    #: it was a list of bad spellings wearing a regex.
    TCHAR = ("!#$%&'*+-.^_`|~0123456789"
             "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

    #: The tchars that are SEPARATORS — punctuation, i.e. every tchar that
    #: is not alphanumeric. This is the axis along which other software
    #: rewrites a field name (``_``/``-`` through CGI and WSGI, doubling,
    #: stripping), so a framing name wearing one of these anywhere folds
    #: back onto the framing name for somebody and must be refused here.
    #: Alphanumerics are deliberately NOT on this axis at insertion
    #: positions: ``Content-Length2`` and ``0Content-Length`` are different
    #: field names, not renamings, and refusing them would mean refusing
    #: ``X-Content-Length`` too — see
    #: ``test_the_rule_does_not_refuse_ordinary_traffic``.
    SEPARATORS = "!#$%&'*+-.^_`|~"

    #: Characters a header NAME may not contain at all (RFC 7230 §3.2.6).
    #: A name carrying one is either refused as a non-token or never
    #: reaches the loop because the parser recorded a defect; both are
    #: unframable, and which one fires is not the assertion.
    NON_TOKEN = ';"(),/<=>?@[\\]{} \t'

    def mechanical_confusions(self):
        """Every mechanical renaming of a framing header name, generated.

        THIS IS THE SWEEP THAT WAS MISSING. The corpus this class shipped
        with was nineteen names and every one of them was a separator
        SUBSTITUTION at the hyphen — the one axis
        ``_FRAMING_CONFUSABLE_RE`` can express. So it could not see that
        435 other names (``Content-Length;``, ``Transfer-Encoding.``,
        ``Con-tent-Length``, ``Content-Length-``, ``_Transfer-Encoding``)
        fell out of that pattern entirely and were neither read as a
        length nor refused: they were IGNORED, on every mint route
        including anonymous GETs, and the mint's own access log showed the
        unread octets framed as the next request line — the original
        report's symptom, reproduced through the rule that was supposed to
        have closed it. The Supervision Profile refused all 435 with a
        rule that lived twenty feet away in the same repository.

        Four generators, one per way a name gets rewritten:

        * a separator PREPENDED or APPENDED (``_Transfer-Encoding``,
          ``Content-Length-``);
        * a separator INSERTED at any interior position
          (``Con-tent-Length``, ``Trans-fer-Encoding``);
        * the hyphen SUBSTITUTED by any single tchar, removed, doubled, or
          replaced by a pair (``Transfer_Encoding``, ``Transfer0Encoding``,
          ``TransferEncoding``, ``Content--Length``, ``Content_.Length``);
        * a NON-TOKEN character in any of those positions
          (``Content-Length;``, ``Transfer"Encoding``).

        A corpus generated from the grammar cannot have the shape of hole
        the hand-written one had: it does not know which axis the
        implementation happens to cover.
        """
        names = set()
        for base in ("Content-Length", "Transfer-Encoding"):
            hyphen = base.index("-")
            for c in self.SEPARATORS:
                names.add(c + base)
                names.add(base + c)
                for i in range(1, len(base)):
                    names.add(base[:i] + c + base[i:])
            for c in self.TCHAR:
                names.add(base[:hyphen] + c + base[hyphen + 1:])
            names.add(base.replace("-", ""))
            names.add(base.replace("-", "--"))
            names.add(base.replace("-", "_."))
            for c in self.NON_TOKEN:
                names.add(c + base)
                names.add(base + c)
                names.add(base[:hyphen] + c + base[hyphen + 1:])
        return sorted(names)

    def test_every_mechanical_confusion_of_a_framing_name_is_refused(self):
        """Seven hundred and fifty-nine generated names, and not one of
        them may frame a body.

        Each is parsed in a real header block beside an honest
        ``Content-Length: 0`` — the case where no other clause can help,
        because there is nothing wrong with the length. A name the parser
        itself cannot read (it lands in defects or in the payload) is
        unframable for that reason and still counts; what must never
        happen is ``framed=True`` with the connection kept.
        """
        corpus = self.mechanical_confusions()
        self.assertGreater(len(corpus), 700, "the generator stopped working")
        kept = []
        for name in corpus:
            message = email.parser.Parser().parsestr(
                "Host: h\r\n%s: chunked\r\nContent-Length: 0\r\n\r\n" % name
            )
            for expected in (True, False):
                verdict = mintapi.framing_verdict(
                    message, body_expected=expected
                )
                if verdict.framed or not verdict.must_close:
                    kept.append((name, expected, verdict.reason))
        self.assertEqual(
            kept[:12], [],
            "%d of %d generated spellings still frame a body"
            % (len(kept), 2 * len(corpus)),
        )

    def test_the_rule_does_not_refuse_ordinary_traffic(self):
        """The bound on the generator above. "Refuse everything" passes
        every confusion test ever written, so the over-refusal cost is
        asserted here and the two tests are read together.

        A header that merely CONTAINS a framing word, an ordinary vendor
        extension, and a name whose only oddity is an alphanumeric all
        keep their keep-alive. ``X-Content-Length`` is the one that
        matters: it is why the fold keeps alphanumerics, and therefore why
        ``0Content-Length`` and ``Content-Length2`` are framed rather than
        refused. Those are different field names; no front end renames a
        header by inserting a digit, and refusing them would cost real
        traffic for no reduction in the confusion class.
        """
        for innocent in ("Content-Type", "Content-Encoding",
                         "Accept-Encoding", "X-Transfer-Encoding",
                         "X-Content-Length", "Content-Length-Hint",
                         "Content-Language", "Content-Disposition",
                         "X-Trace-Id", "X-Underscored_Name",
                         "0Content-Length", "Content-Length2",
                         "User-Agent", "Authorization"):
            with self.subTest(innocent=innocent):
                message = email.parser.Parser().parsestr(
                    "Host: h\r\n%s: x\r\n\r\n" % innocent
                )
                verdict = mintapi.framing_verdict(
                    message, body_expected=False
                )
                self.assertIs(verdict.framed, True, verdict)
                self.assertIs(verdict.must_close, False, verdict)

    def test_the_twenty_five_spellings_reach_one_verdict(self):
        """The sweep that found the siblings, run against the exported
        rule so a fifth server inherits the answer instead of re-deriving
        it. Every spelling of a framing header that another hop could read
        must be unframable, and an innocent neighbour must not be.

        The named half of the corpus. The generated half is
        ``test_every_mechanical_confusion_of_a_framing_name_is_refused``
        above; these are kept by name because each one was reported,
        argued about, or fixed at some point and a named regression is
        worth reading.
        """
        confusable = [
            # The punctuation axis the regex could not express: a
            # separator ADDED rather than substituted, at a position that
            # is not the hyphen. All of these framed a body on the mint,
            # the GUI and the console while the supervision profile
            # refused them.
            "Content-Length;", "Content-Length.", "Content-Length-",
            "Content-Length_", "Content_Length_", "-Content-Length",
            "_Content-Length", "Con-tent-Length", "ContentLength-",
            "Transfer-Encoding;", "Transfer-Encoding.", "Transfer-Encoding_",
            "Transfer-Encoding'", 'Transfer-Encoding"', "_Transfer-Encoding",
            "Trans-fer-Encoding", "Transfer-Encod-ing", ".Transfer-Encoding",
            "Transfer-Encoding", "transfer-encoding", "TRANSFER-ENCODING",
            "Transfer_Encoding", "Transfer.Encoding", "TransferEncoding",
            "Transfer__Encoding", "Transfer0Encoding", "transfer|encoding",
            "Transfer--Encoding", "TRANSFER_ENCODING", "transfer.encoding",
            "Content_Length", "Content.Length", "ContentLength",
            "Content--Length", "content_length", "CONTENT_LENGTH",
            "Content0Length",
        ]
        for name in confusable:
            with self.subTest(name=name):
                message = email.parser.Parser().parsestr(
                    "Host: h\r\n%s: chunked\r\nContent-Length: 0\r\n\r\n"
                    % name
                )
                for expected in (True, False):
                    verdict = mintapi.framing_verdict(
                        message, body_expected=expected
                    )
                    self.assertIs(verdict.framed, False, verdict)
                    self.assertIs(verdict.must_close, True, verdict)
        # Whitespace before the colon, which the parser drops entirely.
        for name in ("Transfer-Encoding ", "Content-Length\t"):
            with self.subTest(name=name):
                message = email.parser.Parser().parsestr(
                    "Host: h\r\n%s: 5\r\n\r\n" % name
                )
                self.assertIs(
                    mintapi.framing_verdict(message).framed, False
                )
        # ...and the rule stays a rule about confusion. A genuinely
        # different header keeps its keep-alive on a GET.
        for innocent in ("Content-Type", "Content-Encoding",
                         "Accept-Encoding", "X-Transfer-Encoding",
                         "Content-Length-Hint", "User-Agent"):
            with self.subTest(innocent=innocent):
                message = email.parser.Parser().parsestr(
                    "Host: h\r\n%s: x\r\n\r\n" % innocent
                )
                verdict = mintapi.framing_verdict(
                    message, body_expected=False
                )
                self.assertIs(verdict.framed, True, verdict)
                self.assertIs(verdict.must_close, False, verdict)


# ======================================================================== #
# JOB 1 (acceptance) — ALL FOUR SERVERS, IDENTICAL BYTES, ONE VERDICT      #
# ======================================================================== #


class FourServersOneFramingRuleTest(unittest.TestCase):
    """The test the round was convened to produce, and the one that was
    missing when it shipped.

    There are four HTTP servers in this repository: the mint, the
    supervision profile, the operator GUI and the older operator console.
    Three times now a framing defect has been fixed where it was found
    while its siblings sat untouched, and the third time the fix itself
    was the vector: the rule that got promoted to
    ``aicash.mintapi.framing_verdict`` was the NARROWER of the two rules
    the repository already contained, so promoting it made the GUI and the
    console — which previously had no rule at all — adopt one with a
    435-name hole, while the supervision profile kept the wider rule
    privately. "One rule everywhere" was true of the source and false of
    the behaviour, and nothing in the suite could see the difference,
    because the only cross-server test drove four inputs both sides
    already refused.

    So this drives all four servers over real sockets with byte-identical
    requests and asserts they reach the same framing decision. It does not
    assert they send the same RESPONSE: the mint answers §3.8
    ``bad_format``, the supervision profile answers its own ``rejected``
    shape, the GUI answers ``unframable_request`` and the console answers
    ``bad_framing``. Three vocabularies, one decision — which is exactly
    the split ``framing_verdict``'s contract draws.

    A fifth server inherits this or fails it.
    """

    #: Names the shared rule must refuse, spanning BOTH axes it is built
    #: from: separator substitution at the hyphen (which the regex half
    #: covers) and an added, moved or misplaced separator anywhere else
    #: (which only the fold half covers, and which nothing covered when
    #: this round shipped).
    REFUSED = (
        "Transfer-Encoding", "Transfer_Encoding", "Transfer.Encoding",
        "Transfer0Encoding", "TransferEncoding",
        "Transfer-Encoding.", "Transfer-Encoding;", "Transfer-Encoding_",
        "_Transfer-Encoding", "Trans-fer-Encoding",
        "Content_Length", "Content--Length", "Content0Length",
        "Content-Length;", "Content-Length-", "Con-tent-Length",
        "-Content-Length",
    )

    #: ...and names it must NOT refuse, so "refuse everything" cannot pass.
    #: Asserted by the ABSENCE of each server's own framing word, because
    #: the four disagree about keep-alive on a 404 for reasons that have
    #: nothing to do with framing.
    INNOCENT = (
        "Content-Type", "Content-Encoding", "X-Content-Length",
        "Content-Length-Hint", "X-Trace-Id", "X-Underscored_Name",
    )

    #: Every word one of the four servers puts in a body when IT decides a
    #: request is unframable. Three vocabularies; the union is what "this
    #: server refused the framing" looks like from the wire.
    FRAMING_WORDS = (b"bad_format", b"unframable_request", b"bad_framing")

    # -- the four servers, started for real ------------------------------

    def load_operator_servers(self):
        """Import the GUI and the console, which live above ``impl/``.

        Deliberately a hard failure rather than a skip. A cross-server
        acceptance test that quietly does not run is worse than no test:
        it is the same false assurance that let 435 spellings through.
        """
        import sys
        repo = os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        )
        if repo not in sys.path:
            sys.path.insert(0, repo)
        try:
            import gui.app as gui_app
            import mint_console
        except Exception as exc:          # pragma: no cover - diagnostic
            self.fail(
                "the operator GUI and console could not be imported from %r,"
                " so this acceptance test cannot drive all four servers: %r"
                % (repo, exc)
            )
        return gui_app, mint_console

    def build_mint(self, cls):
        from aicash.supervision import SupervisionServer  # noqa: F401
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        priv, pub = generate_keypair()
        ledger = Ledger(
            os.path.join(tmp.name, "ledger.sqlite3"),
            FakeClock(T0),
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
            profiles=(),
            admin_token=HARNESS_ADMIN_TOKEN,
        )
        server = cls(config, ledger)
        port = server.start()
        self.addCleanup(server.stop)
        return port

    def start_four(self):
        """(name -> port) for the mint, the profile, the GUI, the console."""
        from aicash.supervision import SupervisionServer

        gui_app, mint_console = self.load_operator_servers()
        ports = {
            "mint": self.build_mint(MintServer),
            "supervision": self.build_mint(SupervisionServer),
        }
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        gui = gui_app.serve(0, os.path.join(tmp.name, "gui"))
        self.addCleanup(gui.server_close)
        self.addCleanup(gui.shutdown)
        threading.Thread(target=gui.serve_forever, daemon=True).start()
        ports["gui"] = gui.server_address[1]

        console = mint_console.serve(
            0, ports["mint"], MINT_ID, HARNESS_ADMIN_TOKEN,
            announce=False, stream=io.StringIO(),
        )
        self.addCleanup(console.server_close)
        self.addCleanup(console.shutdown)
        threading.Thread(target=console.serve_forever, daemon=True).start()
        ports["console"] = console.server_address[1]
        return ports

    # -- identical bytes --------------------------------------------------

    def request_bytes(self, method, path, name, value, *, pipeline=True):
        """One request carrying ONE suspicious header, with a complete
        second request pipelined behind it. A server that mis-frames the
        first swallows or replays the second, and both show up on the
        wire."""
        tail = (b"GET /v3/mints HTTP/1.1\r\nHost: smuggled\r\n\r\n"
                if pipeline else b"")
        close = b"" if pipeline else b"Connection: close\r\n"
        return (
            ("%s %s HTTP/1.1\r\n" % (method, path)).encode("ascii")
            + b"Host: 127.0.0.1\r\n"
            + b"Content-Length: 0\r\n"
            + close
            + name.encode("ascii") + b": " + value + b"\r\n\r\n"
            + tail
        )

    def test_all_four_servers_refuse_the_same_spellings(self):
        """Identical bytes on four servers: one answer each, connection
        closed each, and nothing smuggled out of the octets that follow.
        The bytes never change between servers -- that is the whole
        assertion.

        On the POST half each server must also SAY it refused the framing,
        in its own word, which is where the three vocabularies show and
        where the single decision has to show through them.
        """
        ports = self.start_four()
        for method, path in (("POST", "/v3/exchange"), ("GET", "/v3/mints")):
            for name in self.REFUSED:
                request = self.request_bytes(method, path, name, b"chunked")
                verdict = mintapi.framing_verdict(
                    email.parser.Parser().parsestr(
                        "Host: h\r\nContent-Length: 0\r\n%s: chunked\r\n\r\n"
                        % name
                    ),
                    body_expected=(method == "POST"),
                )
                self.assertIs(
                    verdict.framed, False,
                    "the shared rule itself frames %r" % name)
                for server, port in sorted(ports.items()):
                    with self.subTest(server=server, name=name,
                                      method=method):
                        raw = raw_request(port, request, timeout=8.0)
                        head = raw.partition(b"\r\n\r\n")[0]
                        self.assertEqual(
                            raw.count(b"HTTP/1."), 1,
                            "%s answered twice: the pipelined request was"
                            " framed out of unread octets: %r"
                            % (server, raw[:400]))
                        self.assertIn(
                            b"Connection: close", head,
                            "%s kept the socket on an unframable request:"
                            " %r" % (server, head[:300]))
                        if method == "POST":
                            self.assertTrue(
                                any(w in raw for w in self.FRAMING_WORDS),
                                "%s answered %r without naming a framing"
                                " refusal" % (server, raw[:300]))

    def test_all_four_servers_accept_the_same_innocents(self):
        """The other half, without which "refuse everything" passes. A
        header that merely contains a framing word, or that is an ordinary
        vendor extension, must reach the route on every one of the four --
        so the shared rule cannot be widened into a denial of service the
        way it was once too narrow to be a rule.

        Asserted by the ABSENCE of each server's own framing word rather
        than by keep-alive: the four disagree about reusing a connection
        after a 404 for reasons that have nothing to do with framing, and
        a cross-server test must assert the thing that is actually shared.
        """
        ports = self.start_four()
        for name in self.INNOCENT:
            request = self.request_bytes(
                "GET", "/v3/mints", name, b"7", pipeline=False)
            verdict = mintapi.framing_verdict(
                email.parser.Parser().parsestr(
                    "Host: h\r\nContent-Length: 0\r\n%s: 7\r\n\r\n" % name),
                body_expected=False,
            )
            self.assertIs(verdict.framed, True, name)
            self.assertIs(verdict.must_close, False, name)
            for server, port in sorted(ports.items()):
                with self.subTest(server=server, name=name):
                    raw = raw_request(port, request, timeout=8.0)
                    self.assertTrue(raw, "%s answered nothing" % server)
                    for word in self.FRAMING_WORDS:
                        self.assertNotIn(
                            word, raw,
                            "%s refused the framing of an innocent header"
                            " %r: %r" % (server, name, raw[:300]))

    #: Request lines the standard library cannot version, plus the two
    #: target forms none of the four routes on. Every one of them used to
    #: be answered by the mint and the supervision profile with NO STATUS
    #: LINE AT ALL, because their ``default_request_version`` was the
    #: library's ``"HTTP/0.9"`` and in 0.9 ``send_response_only``,
    #: ``send_header`` and ``end_headers`` are no-ops. The console and the
    #: GUI had each already closed it, one with the default and one with a
    #: ``send_error`` override; the two servers underneath them never had.
    #: Driven at all four here for the same reason the header spellings
    #: are: a defect fixed where it was found, three times running, is a
    #: defect still live on its siblings.
    REQUEST_LINES = {
        "unparseable": b"@@@@\r\n\r\n",
        "one word": b"GET\r\n\r\n",
        "two words": b"GET /v3/mints\r\n\r\n",
        "two words POST": b"POST /v3/exchange\r\n\r\n",
        "four words": b"GET / HTTP/1.1 spare\r\nHost: 127.0.0.1\r\n\r\n",
        "bad version": b"GET / HTTP/9.9\r\nHost: 127.0.0.1\r\n\r\n",
        "absolute form": (b"GET http://127.0.0.1/v3/mints HTTP/1.1\r\n"
                          b"Host: 127.0.0.1\r\n\r\n"),
        "authority form": b"GET 127.0.0.1:80 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        "over-long target": (b"GET /" + b"a" * 70000
                             + b" HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"),
    }

    def assert_one_framed_answer(self, server, where, raw):
        """One well-formed response, nothing after its declared length.

        Both halves matter and the second is the one a status-line count
        cannot see: the defect these shapes exist against wrote bodies with
        NO status line, so when they landed behind a previous response they
        were invisible to any check that counts answers.
        """
        self.assertTrue(raw, "%s answered %s with nothing at all" % (server, where))
        self.assertTrue(
            raw.startswith(b"HTTP/1."),
            "%s answered %s with NO STATUS LINE: %r"
            % (server, where, raw[:160]))
        head, sep, body = raw.partition(b"\r\n\r\n")
        self.assertTrue(sep, "%s / %s: no header block: %r"
                        % (server, where, raw[:160]))
        declared = None
        for line in head.split(b"\r\n")[1:]:
            name, _, value = line.partition(b":")
            if name.strip().lower() == b"content-length":
                declared = int(value.strip())
        self.assertIsNotNone(
            declared, "%s / %s: no Content-Length: %r"
            % (server, where, head[:200]))
        self.assertEqual(
            body[declared:], b"",
            "%s / %s: %d octets FOLLOW the declared Content-Length of %d,"
            " carrying no framing of their own: %r"
            % (server, where, len(body) - declared, declared,
               body[declared:][:160]))
        self.assertIn(
            b"Connection: close", head,
            "%s / %s kept the socket: %r" % (server, where, head[:200]))

    def test_all_four_servers_frame_every_request_line(self):
        """Identical bytes, four servers, one decision — on the REQUEST
        LINE this time, not on a header.

        The header half of this rule reached ``framing_verdict`` and all
        four already agree on it. This is the layer underneath, where the
        standard library decides what protocol it was spoken to in before
        any of these four gets a say, and where two of the four were still
        answering with naked bodies.
        """
        ports = self.start_four()
        for name, request in self.REQUEST_LINES.items():
            for server, port in sorted(ports.items()):
                with self.subTest(server=server, shape=name):
                    raw = raw_request(port, request, timeout=8.0)
                    self.assert_one_framed_answer(server, name, raw)

    #: THE SPELLED-OUT 0.9 VERSION, and the reason it is not in
    #: ``REQUEST_LINES`` above: THREE of the four frame it, not four.
    #:
    #: Every shape in ``REQUEST_LINES`` is either well-versioned HTTP/1.1 or
    #: a version the standard library REFUSES, so none of them reaches the
    #: state this one does: a version the library ACCEPTS
    #: (``request_version == "HTTP/0.9"``, read off the wire) in which
    #: ``send_response_only``, ``send_header`` and ``end_headers`` are all
    #: no-ops. On the mint and the supervision profile that state served the
    #: signed descriptor naked until the version check in
    #: ``_Handler.parse_request`` closed it.
    #:
    #: MEASURED ON ALL FOUR, AFTER THAT FIX. The mint, the supervision
    #: profile and the operator GUI answer a framed 400 ``bad_version`` and
    #: hang up. THE OPERATOR CONSOLE DOES NOT: its refusal is a word count
    #: (``mint_console.py``, ``_handle``), the same heuristic this handler
    #: carried, so ``GET / HTTP/0.9`` still returns 845 octets of its
    #: not-authorised HTML page with no status line, ``FROB /v3/mints
    #: HTTP/0.9`` 357 octets of the library's HTML page naked, and
    #: ``GET /v3/mints HTTP/0.9`` a naked 169-octet JSON body. That is the
    #: SAME defect in the same shape, one file over — reported, not fixed,
    #: because ``mint_console.py`` is not this round's file to edit. When it
    #: takes the version check, these shapes move into ``REQUEST_LINES``
    #: and this test goes away.
    REQUEST_LINES_SPELLED_OUT_0_9 = {
        "0.9 on a route": b"GET /v3/mints HTTP/0.9\r\nHost: 127.0.0.1\r\n\r\n",
        "0.9 on no route": b"GET /nope HTTP/0.9\r\nHost: 127.0.0.1\r\n\r\n",
        "0.9 POST with a body": (b"POST /v3/exchange HTTP/0.9\r\n"
                                 b"Host: 127.0.0.1\r\nContent-Length: 2\r\n"
                                 b"\r\n{}"),
        "0.9 absolute form": (b"GET http://127.0.0.1/v3/mints HTTP/0.9\r\n"
                              b"Host: 127.0.0.1\r\n\r\n"),
    }

    def test_the_spelled_out_0_9_version_is_framed_wherever_it_is_refused(self):
        """The other 0.9 spelling, on the three servers that frame it.

        The mint and the profile are this round's; the GUI is here because
        it is where the fix came from — it refuses on
        ``request_version == "HTTP/0.9"`` and has done since the round that
        found "the other way to emit a response with no status line". Three
        servers, one decision, identical bytes; the console's absence is
        documented on the fixture above and is a finding, not an exemption.
        """
        ports = self.start_four()
        for name, request in self.REQUEST_LINES_SPELLED_OUT_0_9.items():
            for server in ("gui", "mint", "supervision"):
                with self.subTest(server=server, shape=name):
                    raw = raw_request(ports[server], request, timeout=8.0)
                    self.assert_one_framed_answer(server, name, raw)

    def test_the_two_servers_this_round_owns_say_the_same_word_for_both_0_9s(self):
        """Two spellings of one protocol, one refusal word.

        A word count and a version check are different tests and it would
        be easy to answer them differently; the mint and the profile must
        reach ``_refuse_transport(400, "bad_version")`` from both, because a
        caller that matches on ``reason`` is matching on the DECISION, not
        on which branch took it.
        """
        ports = self.start_four()
        for server in ("mint", "supervision"):
            for name, request in (
                    ("two words", b"GET /v3/mints\r\n\r\n"),
                    ("explicit 0.9",
                     b"GET /v3/mints HTTP/0.9\r\nHost: 127.0.0.1\r\n\r\n"),
            ):
                with self.subTest(server=server, shape=name):
                    raw = raw_request(ports[server], request, timeout=8.0)
                    self.assert_one_framed_answer(server, name, raw)
                    status, _headers, body = parse_http(raw)
                    self.assertEqual(status, 400, raw[:200])
                    self.assertEqual(
                        body, {"status": "bad_request",
                               "reason": "bad_version"}, body)
                    self.assertNotIn(b"signature", raw)

    def test_all_four_servers_refuse_to_splice_past_a_declared_length(self):
        """The keep-alive regression, driven at all four.

        A well-formed request and then a two-word one down the same socket.
        On the mint and the supervision profile this produced a correct
        response declaring a Content-Length and then, past it, the mint's
        own signed descriptor — about a kilobyte that was not part of that
        response and carried no framing at all. That is response splitting, and behind
        the reverse proxy DEPLOYMENT.md mandates it is the entire
        mechanism.

        What is asserted is the property, not the answer: whatever each
        server says to the second request, it says it with a status line,
        so nothing on the socket is ever unattributable to a response.
        """
        ports = self.start_four()
        # BOTH 0.9 SPELLINGS as the second request. The two-word one is what
        # this fixture drove at first, and it is the one the handler already
        # refused; the spelled-out one is the one it SERVED — 200 with a
        # declared length, then that many octets of signed descriptor with
        # no framing of their own. A splice fixture that never sends it
        # cannot see the splice.
        seconds = {
            "two words": b"GET /v3/mints\r\n\r\n",
            "explicit 0.9": (b"GET /v3/mints HTTP/0.9\r\n"
                             b"Host: 127.0.0.1\r\n\r\n"),
        }
        for label, second in seconds.items():
            request = (b"GET /v3/mints HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
                       + second)
            for server, port in sorted(ports.items()):
                if server == "console" and label == "explicit 0.9":
                    # The console answers this shape with no status line at
                    # all (fixture REQUEST_LINES_SPELLED_OUT_0_9 above has
                    # the measurements); its word-count refusal is the
                    # defect this round closed one file over and could not
                    # edit here. Its two-word cell is still driven.
                    continue
                with self.subTest(server=server, second=label):
                    raw = raw_request(port, request, timeout=8.0)
                    head, sep, rest = raw.partition(b"\r\n\r\n")
                    self.assertTrue(sep, "%s: %r" % (server, raw[:200]))
                    declared = int(re.search(
                        rb"[Cc]ontent-[Ll]ength:\s*(\d+)", head).group(1))
                    trailing = rest[declared:]
                    self.assertTrue(
                        trailing == b"" or trailing.startswith(b"HTTP/1."),
                        "%s: %d octets follow a declared Content-Length of %d"
                        " with no framing of their own: %r"
                        % (server, len(trailing), declared, trailing[:200]))
                    self.assertNotIn(
                        b"signature", trailing,
                        "%s spliced signed mint state in past a declared"
                        " Content-Length" % server)

    def test_all_four_servers_call_the_same_function_object(self):
        """Behaviour can agree by coincidence; identity cannot. Each of
        the four reaches ``aicash.mintapi.framing_verdict`` itself -- not a
        copy, not a wrapper with its own clauses -- so a fifth server that
        imports it inherits every future widening, and one that does not
        fails here."""
        import aicash
        from aicash import supervision

        gui_app, mint_console = self.load_operator_servers()
        for where, func in (
            ("aicash package root", aicash.framing_verdict),
            ("supervision profile", supervision.framing_verdict),
            ("operator GUI", gui_app.framing_verdict),
            ("operator console", mint_console.framing_verdict),
        ):
            with self.subTest(server=where):
                self.assertIs(func, mintapi.framing_verdict, where)
        # ...and the wider half of the rule is shared the same way: the
        # fold was C10's alone, and being C10's alone is what made the
        # promotion export the laxer answer to the other three.
        self.assertIs(
            supervision._fold_header_name, mintapi._fold_header_name
        )
        # No server may hold its own bound copy: the recorder in
        # TheFramingRuleIsOneSharedFunctionTest only sees callers that
        # look the name up on the module at call time, and these two do.
        for module in (gui_app, mint_console):
            self.assertIn(
                "framing_verdict",
                inspect.getsource(module).split("def ", 1)[0]
                + inspect.getsource(module),
            )


# ======================================================================== #
# JOB 2 — the issuance route owes an enumerated reason, at the route       #
# ======================================================================== #


class IssuanceNeverAnswersABare500Test(MintHarness, unittest.TestCase):
    """The route half of C04's range bound.

    ``POST /admin/issue`` with ``{"amount_mc": 9999999999999999999}`` — one
    digit more than a signed 64-bit column holds — bound the value straight
    into sqlite, raised ``OverflowError`` past every ``except
    ExchangeRejected`` on the way out, and answered HTTP 500
    ``{"status":"error"}``. §3.8 promises an enumerated reason for every
    value a mint refuses, and a bare 500 with no ``errors`` list is not
    one: a caller cannot tell "this amount is too large" from "the mint is
    broken", and the second reading gets retried forever.

    The identical body on ``/v3/exchange`` answered correctly, because
    conservation cannot balance an amount no entry can hold. That is the
    accident this class exists to stop relying on — so it asserts the two
    routes, on identical amounts, both answer enumerated.
    """

    UNSTORABLE = (
        int("9" * 19),          # the reported value: nineteen nines
        1 << 63,                # the boundary itself
        (1 << 63) + 1,
        10 ** 25,
        10 ** 600,              # far past anything a column could hold
    )

    def issue_amount(self, mint, amount, key="i"):
        return http_raw(
            mint.port, "POST", "/admin/issue",
            json.dumps({
                "outputs": [{"amount_mc": amount,
                             "secret_hash": ledger_key(new_secret())}],
            }).encode(),
            {"Content-Type": "application/json",
             "X-Admin-Token": HARNESS_ADMIN_TOKEN},
        )

    def assert_enumerated(self, status, raw):
        self.assertEqual(status, 400, raw[:300])
        body = json.loads(raw.decode("utf-8"))
        self.assertEqual(body["status"], "rejected", body)
        self.assertTrue(body.get("errors"), body)
        for err in body["errors"]:
            self.assertIn(err["reason"], ERROR_REASONS, err)
            self.assertIn(err["kind"], ERROR_KINDS, err)
        return body

    def test_an_amount_no_column_can_hold_is_enumerated_not_500(self):
        mint = self.start_mint()
        for amount in self.UNSTORABLE:
            with self.subTest(amount=str(amount)[:14]):
                status, raw, _ = self.issue_amount(mint, amount)
                body = self.assert_enumerated(status, raw)
                self.assertEqual(
                    body["errors"],
                    [{"index": 0, "kind": "output", "reason": "bad_format"}],
                )

    def test_the_two_routes_agree_on_the_same_amount(self):
        """One value, two routes, one answer. They disagreed before: a
        bare 500 on issuance and a call-level `amount_mismatch` on
        exchange, which is exactly why nobody saw the 500."""
        mint = self.start_mint()
        amount = int("9" * 19)
        status, raw, _ = self.issue_amount(mint, amount)
        issue_body = self.assert_enumerated(status, raw)
        status, raw, _ = http_raw(
            mint.port, "POST", "/v3/exchange",
            json.dumps({
                "idempotency_key": "two-routes",
                "inputs": [],
                "outputs": [{"amount_mc": amount,
                             "secret_hash": ledger_key(new_secret())}],
            }).encode(),
            {"Content-Type": "application/json"},
        )
        exchange_body = self.assert_enumerated(status, raw)
        self.assertEqual(
            [(e["kind"], e["reason"]) for e in issue_body["errors"]],
            [(e["kind"], e["reason"]) for e in exchange_body["errors"]],
        )

    def test_a_lock_expiry_no_column_can_hold_is_enumerated_too(self):
        """The neighbouring number on the same row, over the wire. Driven
        against a mint with NO finite lock horizon, because a mint that
        has one refuses that expiry for an unrelated reason — the same
        accidental cover that hid the amount."""
        mint = self.start_mint(max_lock_expiry_ms=None)
        status, raw, _ = http_raw(
            mint.port, "POST", "/admin/issue",
            json.dumps({
                "outputs": [{
                    "amount_mc": 5,
                    "secret_hash": ledger_key(new_secret()),
                    "lock": {"preimage_hash": ledger_key(new_secret()),
                             "expiry": 10 ** 19,
                             "refund_hash": ledger_key(new_secret())},
                }],
            }).encode(),
            {"Content-Type": "application/json",
             "X-Admin-Token": HARNESS_ADMIN_TOKEN},
        )
        self.assert_enumerated(status, raw)

    def test_a_batch_whose_sum_overflows_is_enumerated_too(self):
        """Every amount storable, the total not. No per-value bound
        reaches this one; the route must still answer §3.8."""
        mint = self.start_mint()
        biggest = (1 << 63) - 1
        status, raw, _ = http_raw(
            mint.port, "POST", "/admin/issue",
            json.dumps({
                "outputs": [
                    {"amount_mc": biggest,
                     "secret_hash": ledger_key(new_secret())},
                    {"amount_mc": biggest,
                     "secret_hash": ledger_key(new_secret())},
                ],
            }).encode(),
            {"Content-Type": "application/json",
             "X-Admin-Token": HARNESS_ADMIN_TOKEN},
        )
        body = self.assert_enumerated(status, raw)
        self.assertEqual(
            body["errors"],
            [{"index": 1, "kind": "output", "reason": "bad_format"}],
        )

    def test_the_mint_still_issues_an_amount_it_can_hold(self):
        """The bound is the column's: a fix that refused the largest
        storable amount would be worse than the defect."""
        mint = self.start_mint()
        status, raw, _ = self.issue_amount(mint, (1 << 63) - 1)
        self.assertEqual(status, 200, raw[:200])
        self.assertEqual(
            json.loads(raw.decode("utf-8"))["status"], "ok"
        )

    def test_the_route_survives_every_one_of_them(self):
        """A refusal is not a wound, and no traceback ever reaches a
        caller."""
        mint = self.start_mint()
        for amount in self.UNSTORABLE:
            status, raw, _ = self.issue_amount(mint, amount)
            self.assertNotIn(b"Traceback", raw)
            self.assertNotIn(b'"status":"error"', raw)
        status, raw, _ = http_raw(mint.port, "GET", "/v3/mints")
        self.assertEqual(status, 200, raw[:200])


# ======================================================================== #
# THE REQUEST LINE — no shape of one may answer without a status line      #
# ======================================================================== #


class EveryRequestLineGetsAStatusLineTest(MintHarness, unittest.TestCase):
    """The framing rule reached every HEADER. These are the REQUEST LINES.

    The verification pass that closed the header family drove 58 framing
    spellings at 55 routes across this repository's four HTTP servers and
    found 51 of them perfect everywhere. The seven that were not are all
    the same defect, one layer below the shared rule: this handler set
    ``protocol_version`` (what it answers IN) and never set
    ``default_request_version`` (what it assumes it was asked IN), whose
    class default is ``"HTTP/0.9"`` — and in HTTP/0.9 the standard
    library makes ``send_response_only()``, ``send_header()`` and
    ``end_headers()`` NO-OPS, because 0.9 has no status line and no
    headers.

    So for any request line the library could not version, everything this
    mint composed went onto the socket as a NAKED BODY. Measured, on every
    one of the mint's seven routes and every one of the supervision
    profile's twenty-one:

      * ``@@@@`` — the library's own HTML error page, 359 octets in this
        harness, with no status line in front of it.
      * ``GET /v3/mints`` with no version — this mint's OWN SIGNED
        DESCRIPTOR, roughly a kilobyte, naked. (The exact count moves with
        the mint_id and the signature; the verification pass measured 1,087
        on its mint and this harness measures 1,067 on its own.)
      * ``GET /v3/mints HTTP/9.9`` — the naked error page again.

    ``test_keep_alive_never_splices_a_second_body_past_a_declared_length``
    below is why that is critical and not untidy.

    AND IT HAS A SECOND SPELLING, which the first fix here missed: a
    request line whose version token is literally ``HTTP/0.9`` is one the
    library CAN read, so it sets ``request_version`` from the wire and the
    no-ops come back — on every route, for the descriptor, for the §3.8
    bodies, and for the transport refusals themselves. The first fix
    refused 0.9 by WORD COUNT, which that shape walks straight past, and
    the sweep could not see it because every shape the sweep built said
    HTTP/1.1 or a version the library REFUSES. ``explicit 0.9`` below is
    that shape and it is why the shape list, not only the handler, had to
    change.

    The fix is not invented here: the operator console set
    ``default_request_version``, and the operator GUI both overrode
    ``send_error`` AND refused on ``request_version == "HTTP/0.9"`` in its
    own ``_handle``. All three are what this handler now carries — the
    console's default alone leaves the GUI's two doors open, and the GUI's
    ``send_error`` alone leaves the route path open. Measured across all
    four servers in ``FourServersOneFramingRuleTest``: the GUI frames the
    spelled-out 0.9 shapes too, and the operator CONSOLE does not — it
    still answers them with no status line, because its refusal is the
    same word count this handler has just stopped relying on
    (``REQUEST_LINES_SPELLED_OUT_0_9`` carries the measurements and says
    why that server is reported rather than changed here).
    """

    #: Every route this handler answers, so a fix that reached one of them
    #: cannot pass. ``<unknown>`` paths are here on purpose: the 404 branch
    #: composes a response too, and a naked 404 is as unframed as a naked
    #: 200.
    ROUTES = (
        ("GET", "/v3/mints"),
        ("GET", "/v3/status/abc"),
        ("GET", "/no-such-route"),
        ("POST", "/v3/exchange"),
        ("POST", "/v3/status"),
        ("POST", "/admin/issue"),
        ("POST", "/no-such-route"),
    )

    def request_line_shapes(self, method, path):
        """Request lines the standard library cannot version, one way each.

        Each is a DIFFERENT door into the same room, which is why they are
        swept rather than sampled: the two-word line reaches ``do_GET`` and
        is answered by the ROUTE, the unparseable line and the bad version
        are answered by the LIBRARY before ``parse_request`` returns, and
        the over-long line is answered by ``handle_one_request`` before
        ``parse_request`` is even called — three different pieces of code
        composing a response, all of them silenced by the same field.

        AND ONE OF THEM IS A VERSION THE LIBRARY CAN READ. Every shape in
        the first version of this list was either HTTP/1.1 or a version the
        library refuses outright (``HTTP/9.9``, ``HTTPX``), so the list had
        the same blind spot the code had: nothing here spelled a version
        the library ACCEPTS and that nonetheless disables header writing.
        ``explicit 0.9`` is that shape, and the sweep is only a sweep with
        it in.
        """
        return {
            "unparseable": b"@@@@\r\n\r\n",
            "one word": b"GET\r\n\r\n",
            "two words": ("%s %s\r\n\r\n" % (method, path)).encode(),
            # THE SPELLING THE FIRST FIX MISSED, and the one the sweep
            # could not see because every other shape here is either
            # HTTP/1.1 or a version the library REFUSES. This one the
            # library ACCEPTS: three words, a well-formed version token,
            # ``request_version`` set to ``"HTTP/0.9"`` FROM THE WIRE — and
            # from that moment ``send_response_only``, ``send_header`` and
            # ``end_headers`` are no-ops again, so the route runs and writes
            # its body naked. Measured on this handler before the version
            # check: ``GET /v3/mints HTTP/0.9`` returned 1,067 octets of the
            # mint's own signed descriptor with no status line.
            "explicit 0.9": (
                "%s %s HTTP/0.9\r\nHost: h\r\n\r\n"
                % (method, path)).encode(),
            "four words": (
                "%s %s HTTP/1.1 spare\r\nHost: h\r\n\r\n"
                % (method, path)).encode(),
            "bad version": (
                "%s %s HTTP/9.9\r\nHost: h\r\n\r\n"
                % (method, path)).encode(),
            "versionless junk": (
                "%s %s HTTPX\r\nHost: h\r\n\r\n"
                % (method, path)).encode(),
            "over-long target": (
                ("%s /" % method).encode() + b"a" * 70000
                + b" HTTP/1.1\r\nHost: h\r\n\r\n"),
            "absolute form": (
                "%s http://127.0.0.1%s HTTP/1.1\r\nHost: h\r\n\r\n"
                % (method, path)).encode(),
            "authority form": (
                "%s 127.0.0.1:80 HTTP/1.1\r\nHost: h\r\n\r\n"
                % (method,)).encode(),
            "unknown method": (
                "FROB %s HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n"
                % (path,)).encode(),
        }

    def assert_one_framed_response(self, raw, where):
        """Exactly one well-formed response, and nothing after its length.

        THE ABSOLUTE BAR, and both halves of it are load-bearing. A status
        line alone is not enough: the defect this class exists against
        produced bytes with no status line, and the same field produced
        them APPENDED past a previous response's declared Content-Length,
        which is the half a status-line count cannot see.
        """
        self.assertTrue(raw, "%s: no answer at all" % where)
        self.assertTrue(
            raw.startswith(b"HTTP/1."),
            "%s: a response with NO STATUS LINE: %r" % (where, raw[:160]))
        head, sep, body = raw.partition(b"\r\n\r\n")
        self.assertTrue(sep, "%s: no header block: %r" % (where, raw[:160]))
        declared = None
        for line in head.split(b"\r\n")[1:]:
            name, _, value = line.partition(b":")
            if name.strip().lower() == b"content-length":
                declared = int(value.strip())
        self.assertIsNotNone(
            declared, "%s: no Content-Length: %r" % (where, head[:200]))
        self.assertEqual(
            body[declared:], b"",
            "%s: %d octets FOLLOW the declared Content-Length of %d, with"
            " no framing of their own: %r"
            % (where, len(body) - declared, declared, body[declared:][:160]))
        self.assertIn(
            b"Connection: close", head,
            "%s: the socket was kept after a refused request line: %r"
            % (where, head[:200]))

    def test_no_request_line_shape_answers_without_a_status_line(self):
        """The sweep. Seventy-seven cells on this server: seven routes,
        eleven shapes, one framed answer each."""
        mint = self.start_mint()
        for method, path in self.ROUTES:
            for name, request in self.request_line_shapes(method, path).items():
                with self.subTest(route="%s %s" % (method, path), shape=name):
                    raw = raw_request(mint.port, request, timeout=8.0)
                    self.assert_one_framed_response(
                        raw, "%s %s / %s" % (method, path, name))

    def test_the_two_word_request_line_no_longer_serves_the_descriptor(self):
        """The loudest cell, named on its own because of WHAT it leaked.

        ``GET /v3/mints`` with no version reached ``do_GET``, built the
        descriptor, and then wrote it to the socket raw: the whole of this
        mint's signed state, about a kilobyte, with no status line, no
        Content-Length and no ``Connection: close``. Feeding those bytes to ``http.client``
        raises ``BadStatusLine``; feeding them to a proxy that is reading
        by length appends them to whatever came before.
        """
        mint = self.start_mint()
        raw = raw_request(mint.port, b"GET /v3/mints\r\n\r\n", timeout=8.0)
        self.assert_one_framed_response(raw, "two-word GET /v3/mints")
        status, headers, body = parse_http(raw)
        self.assertEqual(status, 400, raw[:200])
        self.assertEqual(body["reason"], "bad_version", body)
        # The descriptor is not in the answer at all -- not merely framed.
        self.assertNotIn(b"signature", raw)
        self.assertNotIn(MINT_ID.encode("ascii"), raw)

    def test_keep_alive_never_splices_a_second_body_past_a_declared_length(self):
        """THE REGRESSION. Response splitting, in five lines of bytes.

        One socket, two requests: a well-formed GET, then a two-word one.
        What came back was a correct response declaring a Content-Length
        and then that many MORE octets after it — this mint's own signed
        descriptor — which are not part of that response and carry no
        framing of their own.

        Behind the reverse proxy DEPLOYMENT.md makes mandatory, that is the
        whole mechanism: the proxy reads the declared length and stops, the
        client reads what follows, and the two disagree about where the
        response ended. The injected octets are attacker-chosen in the
        sense that matters — the attacker picks which route produces them.

        The assertion is on the FIRST response's frame, not on a count of
        status lines: the injected bytes had no status line, so a count saw
        one response and nothing wrong.
        """
        mint = self.start_mint()
        # BOTH SPELLINGS OF THE SECOND REQUEST. The first fixture here said
        # only ``GET /v3/mints`` (two words), so this test drove the one 0.9
        # spelling the handler refused and never the one it served: with the
        # version token spelled out the splice was still live — 200,
        # ``Content-Length: 1067``, then 1,067 further octets containing
        # ``signature`` and no framing of their own.
        for label, second in (
                ("two words", b"GET /v3/mints\r\n\r\n"),
                ("explicit 0.9",
                 b"GET /v3/mints HTTP/0.9\r\nHost: 127.0.0.1\r\n\r\n"),
        ):
            with self.subTest(second=label):
                self.assert_no_splice(mint.port, second)

    def assert_no_splice(self, port, second_request):
        """A good request, then ``second_request``, down one socket: the
        first answer is framed and NOTHING that follows its declared length
        is unattributable to a response of its own."""
        raw = raw_request(
            port,
            b"GET /v3/mints HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
            + second_request,
            timeout=8.0,
        )
        head, sep, rest = raw.partition(b"\r\n\r\n")
        self.assertTrue(sep, raw[:200])
        self.assertTrue(head.startswith(b"HTTP/1.1 200"), head[:120])
        declared = int(re.search(
            rb"[Cc]ontent-[Ll]ength:\s*(\d+)", head).group(1))
        first, trailing = rest[:declared], rest[declared:]
        self.assertIn(b"signature", first)          # the honest answer
        # Whatever answers the second request, it is a RESPONSE: it has a
        # status line of its own. Naked octets here are the defect.
        self.assertTrue(
            trailing.startswith(b"HTTP/1.1 "),
            "%d octets follow the declared length with no framing of their"
            " own: %r" % (len(trailing), trailing[:200]))
        self.assertNotIn(
            b"signature", trailing,
            "the descriptor was spliced in past a declared Content-Length")
        self.assertIn(
            b"Connection: close", trailing.partition(b"\r\n\r\n")[0])

    def test_one_empty_line_before_the_request_line_is_ignored(self):
        """A perfectly well-formed request, preceded by one CRLF, used to
        get NO ANSWER AT ALL.

        RFC 7230 §3.5: a server SHOULD ignore at least one empty line
        received before the request line — the shape a client emits when it
        terminates a body with an extra CRLF. The standard library does not
        ignore it: an empty request line makes ``words`` empty and
        ``parse_request`` return False with nothing written, so the request
        was silently DISCARDED and the socket closed. Behind the reverse
        proxy DEPLOYMENT.md mandates that is uniform request loss on a shape
        the RFC blesses — the "no response at all" class, which is the other
        half of this class's subject.
        """
        mint = self.start_mint()
        raw = raw_request(
            mint.port,
            b"\r\nGET /v3/mints HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            b"Connection: close\r\n\r\n",
            timeout=8.0)
        self.assert_one_framed_response(raw, "one CRLF then a good request")
        status, _headers, _body = parse_http(raw)
        self.assertEqual(status, 200, raw[:200])
        self.assertIn(b"signature", raw)

        # The skip does not skip the REFUSALS: the request line behind the
        # empty line is judged exactly as if it had arrived first.
        raw = raw_request(
            mint.port,
            b"\r\nGET /v3/mints HTTP/0.9\r\nHost: 127.0.0.1\r\n\r\n",
            timeout=8.0)
        self.assert_one_framed_response(raw, "one CRLF then a 0.9 line")
        status, _headers, body = parse_http(raw)
        self.assertEqual(status, 400, raw[:200])
        self.assertEqual(body, {"status": "bad_request",
                                "reason": "bad_version"}, body)
        self.assertNotIn(b"signature", raw)

        # ONE line, which is what the RFC asks for, and deliberately not a
        # loop: a loop lets an anonymous peer hold a thread by trickling
        # CRLFs inside the request deadline. Two empty lines are still not
        # answered — what is asserted is the bar, not the answer: whatever
        # comes back is either nothing or a response with a status line on
        # it, never a naked body.
        raw = raw_request(
            mint.port,
            b"\r\n\r\nGET /v3/mints HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            b"Connection: close\r\n\r\n",
            timeout=8.0)
        self.assertTrue(
            raw == b"" or raw.startswith(b"HTTP/1."),
            "two empty lines produced octets with no status line: %r"
            % (raw[:160],))

    def test_the_transport_vocabulary_is_this_mints_and_not_the_interpreters(self):
        """The machine words in ``status`` and ``reason`` are spelled in
        this module, not derived from ``BaseHTTPRequestHandler.responses``.

        They were derived from the library's reason phrase, so a 414
        answered ``request_uri_too_long`` on python3.12 — and CPython has
        already renamed several of those members for RFC 9110 (413, 414,
        416, 422), which means the same mint on a different interpreter
        answered a different machine word for the same request. A field a
        client matches on may not move with the interpreter, so the words
        are asserted here against the table and NOT against
        ``HTTPStatus(code).phrase``.
        """
        from http import HTTPStatus

        # ON THE WIRE FIRST: the words a client actually receives.
        mint = self.start_mint()
        raw = raw_request(
            mint.port,
            b"GET /" + b"a" * 70000 + b" HTTP/1.1\r\nHost: h\r\n\r\n",
            timeout=8.0)
        self.assert_one_framed_response(raw, "over-long request line")
        status, _headers, body = parse_http(raw)
        self.assertEqual(status, 414, raw[:200])
        self.assertEqual(body, {"status": "uri_too_long",
                                "reason": "request_line_too_long"}, body)
        raw = raw_request(
            mint.port,
            b"GET /v3/mints HTTP/1.1\r\nHost: h\r\n"
            + b"".join(b"X-Pad-%d: 1\r\n" % i for i in range(300))
            + b"\r\n",
            timeout=8.0)
        self.assert_one_framed_response(raw, "300 header lines")
        status, _headers, body = parse_http(raw)
        self.assertEqual(status, 431, raw[:200])
        self.assertEqual(body, {"status": "header_fields_too_large",
                                "reason": "header_block_too_large"}, body)

        self.assertEqual(mintapi._transport_status(414), "uri_too_long")
        self.assertEqual(mintapi._transport_status(431),
                         "header_fields_too_large")
        self.assertEqual(mintapi._transport_status(404), "not_found")
        self.assertEqual(mintapi._transport_status(401), "unauthorized")
        # An unknown code is still interpreter-independent.
        self.assertEqual(mintapi._transport_status(599), "http_599")
        # And the reason is never a restatement of the status word.
        for code, why in mintapi._TRANSPORT_WHY.items():
            self.assertNotEqual(
                why, mintapi._transport_status(code),
                "%d answers its own status word in the reason field" % code)
        # The interpreter's phrase for 414 is what used to be shipped; if
        # this ever equals the word above again, the table has been removed.
        self.assertNotEqual(
            mintapi._transport_status(414),
            HTTPStatus(414).phrase.lower().replace(" ", "_").replace("-", "_"),
            "the status word is the interpreter's phrase again")

    def test_the_librarys_html_error_page_never_reaches_the_wire(self):
        """An unparseable request line used to send 359 octets of the
        standard library's HTML, naked. Now it is this mint's own JSON,
        framed — and it does not quote the caller's request line back at
        it, which the library's message (``Bad request syntax (%r)``, on a
        line that may be 64 KiB) does."""
        mint = self.start_mint()
        for line in (b"@@@@", b"GET", b"GET / HTTP/1.1 spare"):
            with self.subTest(line=line):
                raw = raw_request(mint.port, line + b"\r\n\r\n", timeout=8.0)
                self.assert_one_framed_response(raw, repr(line))
                self.assertNotIn(b"<!DOCTYPE", raw)
                self.assertNotIn(b"<html", raw)
                self.assertNotIn(b"Error response", raw)
                status, _, body = parse_http(raw)
                self.assertEqual(status, 400, raw[:200])
                # NOT ``{"reason": "bad_request"}``: that restated the
                # status word in the field a caller reads for WHY, which
                # looks parseable and says nothing. This is the library's
                # own refusal class, named.
                self.assertEqual(body, {"status": "bad_request",
                                        "reason": "bad_request_line"}, body)
                self.assertNotIn(line, raw)

    def test_a_version_this_mint_will_not_speak_is_a_framed_505(self):
        """The bodiless-protocol family's third door. The library refuses
        the version itself, from inside ``parse_request``, and its refusal
        was as naked as the others."""
        mint = self.start_mint()
        raw = raw_request(
            mint.port,
            b"GET /v3/mints HTTP/9.9\r\nHost: 127.0.0.1\r\n\r\n", timeout=8.0)
        self.assert_one_framed_response(raw, "HTTP/9.9")
        status, _, body = parse_http(raw)
        self.assertEqual(status, 505, raw[:200])
        self.assertEqual(body["status"], "http_version_not_supported", body)
        # The version string is the caller's text; it is not echoed.
        self.assertNotIn(b"9.9", raw.partition(b"\r\n\r\n")[2])

    def test_an_absolute_form_target_is_refused_and_the_socket_goes(self):
        """The third of the three cross-server disagreements, and the one
        that was a defect.

        This handler routes on ``self.path`` verbatim, so only origin-form
        ever matches: ``GET http://host/v3/mints`` has always been a 404
        and always will be. Answering 404 and then INVITING another request
        on the same socket is the part that was wrong — RFC 7230 §5.3.2
        says an origin server that takes absolute-form must ignore ``Host``
        and route on the target's own authority, and this mint does
        neither, so the request carries two unreconciled statements of
        which server it is for. DEPLOYMENT.md puts a proxy in front of
        every deployed mint, so there is always a second hop that may
        reconcile them the other way.

        The operator GUI and the operator console both close on these
        bytes. This is the change that makes all four agree on them.
        """
        mint = self.start_mint()
        for target in (b"http://127.0.0.1/v3/mints", b"http://[",
                       b"https://evil.example/v3/exchange",
                       b"127.0.0.1:80", b"*"):
            with self.subTest(target=target):
                raw = raw_request(
                    mint.port,
                    b"GET " + target + b" HTTP/1.1\r\nHost: h\r\n\r\n",
                    timeout=8.0)
                self.assert_one_framed_response(raw, repr(target))
                status, _, body = parse_http(raw)
                self.assertEqual(status, 400, raw[:200])
                self.assertEqual(body["reason"], "bad_request_target", body)
                self.assertNotIn(target, raw)

    def test_a_refused_head_carries_no_body_after_its_declared_length(self):
        """The one shape the fix could have broken, so it is pinned.

        ``send_error`` now writes this mint's JSON through ``_send``, and
        ``_send`` used to write its body unconditionally. No route here
        answers HEAD — the library refuses it 501 before dispatch — so the
        only HEAD response that exists is that refusal, and a refusal that
        declared a length and then sent the body after a HEAD would be a
        framing violation in the server whose subject is framing.
        """
        mint = self.start_mint()
        raw = raw_request(
            mint.port,
            b"HEAD /v3/mints HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n",
            timeout=8.0)
        head, sep, body = raw.partition(b"\r\n\r\n")
        self.assertTrue(sep, raw[:200])
        self.assertTrue(head.startswith(b"HTTP/1.1 501"), head[:120])
        self.assertIn(b"Content-Length:", head)
        self.assertEqual(body, b"", "a HEAD response carried a body: %r" % body)

    def test_octets_past_a_request_are_answered_never_appended(self):
        """The two remaining cross-server disagreements, decided, with the
        reason written down.

        The verification pass reports three spellings on which this mint
        and the supervision profile keep the socket while the operator GUI
        and the operator console close it: an absolute-form target (a real
        defect, fixed above), a declared length SHORTER than the octets
        actually sent, and no declared length with octets sent. The last
        two are decided the other way, and deliberately.

        On the wire those two shapes are the pipelining this mint supports
        and this suite already pins (``test_an_ordinary_get_still_keeps_
        its_connection``, and the CL-tolerance tests that require the
        pipelined GET behind a refused body to be ANSWERED). They are the
        same bytes: a request whose body this server read in full or had
        none of, followed by octets this server has not read yet. Nothing
        at this layer can tell a pipelined request from a smuggled tail,
        and closing on them would delete those tests. The other two servers
        are not making a framing decision on these bytes either — the
        console answers HTTP/1.0 and closes on everything, and the GUI
        closes because its auth gate denied the request and a denied
        request may carry an unread body. Copying either would be copying
        an accident.

        What this mint owes instead is the absolute bar, and that is what
        is asserted: whatever those trailing octets turn into, it is a
        RESPONSE with a status line of its own. Before this round they were
        answered with the library's naked HTML page, appended past a
        declared Content-Length with no framing at all — which is the
        actual harm the disagreement was standing in for.
        """
        mint = self.start_mint()
        cases = {
            "declared length shorter than the octets sent": (
                b"POST /v3/exchange HTTP/1.1\r\nHost: h\r\n"
                b"Content-Length: 2\r\n\r\n{}@@@@\r\n\r\n"),
            "no declared length, octets sent": (
                b"GET /v3/mints HTTP/1.1\r\nHost: h\r\n\r\n@@@@\r\n\r\n"),
        }
        for name, request in cases.items():
            with self.subTest(shape=name):
                raw = raw_request(mint.port, request, timeout=8.0)
                head, sep, rest = raw.partition(b"\r\n\r\n")
                self.assertTrue(sep, raw[:200])
                declared = int(re.search(
                    rb"[Cc]ontent-[Ll]ength:\s*(\d+)", head).group(1))
                trailing = rest[declared:]
                self.assertTrue(
                    trailing.startswith(b"HTTP/1.1 "),
                    "%s: %d octets follow the declared Content-Length of %d"
                    " with no framing of their own: %r"
                    % (name, len(trailing), declared, trailing[:200]))
                self.assertNotIn(b"<!DOCTYPE", raw)

    def test_ordinary_pipelining_still_costs_nothing(self):
        """The half that keeps the decision above from being a denial of
        service: two well-formed requests down one socket are still two
        answers on that socket."""
        mint = self.start_mint()
        raw = raw_request(
            mint.port,
            b"GET /v3/mints HTTP/1.1\r\nHost: h\r\n\r\n"
            b"GET /v3/mints HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n",
            timeout=8.0)
        self.assertEqual(raw.count(b"HTTP/1.1 200"), 2, raw[:200])


if __name__ == "__main__":
    unittest.main()
