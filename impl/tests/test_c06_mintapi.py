"""C06 — mintapi tests: the HTTP surface of a mint.

Every test drives a real MintServer over real HTTP (127.0.0.1, stdlib
http.client). Benchmark items B1–B8 from components/C06-mintapi.md are
named in each test's docstring. All time comes from a FakeClock injected
through the Ledger (L17).
"""

import contextlib
import hashlib
import http.client
import io
import json
import os
import re
import socket
import sqlite3
import tempfile
import threading
import time
import unittest
from typing import NamedTuple

from aicash.burncalc import BurnPolicy
from aicash.clock import FakeClock
from aicash.ledgerstore import Ledger
from aicash.mintapi import (
    MAX_BODY_BYTES,
    MAX_IDEMPOTENCY_KEY_LEN,
    MAX_REQUEST_SECONDS,
    MintConfig,
    MintServer,
    _Handler,
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


class MintApiTest(unittest.TestCase):
    maxDiff = None

    def start_mint(
        self,
        *,
        max_batch=256,
        performance=None,
        admin_token=None,
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
        if mint.config.admin_token is not None:
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

        # A mint with no admin token configured serves /admin/issue bare.
        mint2 = self.start_mint(admin_token=None)
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
            )
            return MintServer(config, ledger)

        server1 = build_server()
        port1 = server1.start()
        try:
            s0 = new_secret()
            status, body, _ = http_json(
                port1, "POST", "/admin/issue",
                {"outputs": [out_hash(100_000, s0)]},
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


if __name__ == "__main__":
    unittest.main()


class RateSchemaConformance(unittest.TestCase):
    """§3.6 pins the rate schema. Nothing checked it, and the descriptor
    shipped without `scope` against OPEN-QUESTIONS R15, which had closed
    pinning it mandatory. Found 2026-09-08 by an outside implementation
    reading the published descriptor against the spec."""

    def _config(self, **over):
        priv, pub = generate_keypair()
        base = dict(mint_id="rate-test", baseline_model_class="b",
                    burn_policy=BurnPolicy(0, 0, 10),
                    signing_private=priv, signing_public=pub)
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
