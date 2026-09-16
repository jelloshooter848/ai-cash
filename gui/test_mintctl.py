#!/usr/bin/env python3
"""Tests for gui/mintctl.py.

Real subprocesses, real ports, real temp directories. Nothing here is
mocked: the whole point of this module is what happens to an actual
``run_mint.py`` process, and a mock of that process would agree with
whatever this file believed on the day it was written.

Run:  cd <repo> && python3 -m unittest gui.test_mintctl -v
"""
import hashlib
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gui.mintctl import (  # noqa: E402
    REDACTED, MintControl, MintControlError, _strip_tracebacks)


def free_port() -> int:
    """A port nothing was listening on a moment ago.

    Inherently advisory — the kernel can hand the same port to somebody
    else before it is used. Every test that depends on it also asserts on
    the mint that answers there, so a collision fails loudly rather than
    passing by accident.
    """
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def http_get(port: int, path: str, timeout: float = 5.0):
    import http.client
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


class MintControlTestCase(unittest.TestCase):
    """Base: a temp workdir per test, and a guarantee that nothing survives it."""

    def setUp(self):
        self.workdir = tempfile.mkdtemp(prefix="mintctl-test-")
        self.controllers = []
        self.addCleanup(self._cleanup)

    def control(self, workdir=None) -> MintControl:
        mc = MintControl(workdir or self.workdir)
        # Failures in these tests should be fast, not a 30s stare.
        mc.start_timeout_s = 20.0
        self.controllers.append(mc)
        return mc

    def _cleanup(self):
        # 1. ask nicely through the public API
        for mc in self.controllers:
            try:
                mc.stop(drain_seconds=3)
            except Exception:
                pass
        # 2. then, independently of the state file, kill anything we spawned
        #    ourselves. A test that loses the state file (or writes a bogus
        #    one) must still not leak a mint holding a port.
        for mc in self.controllers:
            proc = getattr(mc, "_proc", None)
            if proc is not None and proc.poll() is None:
                proc.kill()
                try:
                    proc.wait(timeout=5)
                except Exception:
                    pass
        # 3. and anything a state file still points at
        for mc in self.controllers:
            try:
                with open(mc.state_path) as fh:
                    pid = json.load(fh).get("pid")
            except Exception:
                pid = None
            if isinstance(pid, int) and pid > 0:
                for sig in (signal.SIGTERM, signal.SIGKILL):
                    try:
                        os.kill(pid, sig)
                    except OSError:
                        break
                    time.sleep(0.3)
        import shutil
        shutil.rmtree(self.workdir, ignore_errors=True)

    def start_a_mint(self, mc=None, *, mint_id="test-mint",
                     baseline="baseline-v1", port=None, **kw):
        mc = mc or self.control()
        port = port or free_port()
        status = mc.start(mint_id=mint_id, baseline_model_class=baseline,
                          port=port, rate_ppm=kw.pop("rate_ppm", 0),
                          cap_mc=kw.pop("cap_mc", 0),
                          exempt_below_mc=kw.pop("exempt_below_mc", 10))
        return mc, status


class TestStartStop(MintControlTestCase):

    def test_start_serves_before_it_returns(self):
        """start() must not return until the mint really answers."""
        mc, status = self.start_a_mint()
        self.assertTrue(status["running"])
        self.assertEqual(status["mint_id"], "test-mint")
        self.assertEqual(status["base_url"], "http://127.0.0.1:%d" % status["port"])
        self.assertIsInstance(status["pid"], int)
        self.assertIsNone(status["last_error"])
        # No sleep, no retry: the contract is that the port is live NOW.
        code, body = http_get(status["port"], "/v3/mints")
        self.assertEqual(code, 200)
        descriptor = json.loads(body)
        self.assertEqual(descriptor["mint_id"], "test-mint")
        self.assertEqual(descriptor["baseline_model_class"], "baseline-v1")

    def test_workdir_layout_and_admin_token(self):
        mc, status = self.start_a_mint()
        for path in (mc.db_path, mc.keys_path, mc.admin_token_path, mc.log_path):
            self.assertTrue(os.path.exists(path), path)
        token = mc.admin_token()
        self.assertTrue(token)
        # The credential file is a secret, and the credential never reaches
        # anything the GUI will show.
        self.assertEqual(os.stat(mc.admin_token_path).st_mode & 0o777, 0o600)
        # Nothing should ever write it to the log; that it is absent here is
        # worth asserting but proves nothing about the redaction, which is
        # what TestCredentialRedaction is for.
        self.assertNotIn(token, "\n".join(mc.logs(lines=1000)))
        # It really is the live credential: it opens /admin/issue, and a
        # different token does not. (Empty outputs issue nothing; this is an
        # authentication check, not a minting one.)
        self.assertEqual(200, _admin_issue(status["port"], token))
        self.assertEqual(401, _admin_issue(status["port"], token + "x"))

    def test_logs_tail_is_oldest_first(self):
        mc, status = self.start_a_mint()
        for _ in range(3):
            http_get(status["port"], "/v3/mints")
        lines = mc.logs(lines=2)
        self.assertEqual(len(lines), 2)
        self.assertTrue(all("/v3/mints" in ln for ln in lines), lines)
        self.assertEqual(len(mc.logs(lines=200)) >= 2, True)

    def test_stop_frees_the_port_and_clears_status(self):
        mc, status = self.start_a_mint()
        port, pid = status["port"], status["pid"]
        after = mc.stop(drain_seconds=5)
        self.assertFalse(after["running"])
        self.assertIsNone(after["pid"])
        # last known identity survives, so the UI can still name the mint
        self.assertEqual(after["port"], port)
        self.assertEqual(after["mint_id"], "test-mint")
        self.assertFalse(_pid_alive(pid))
        s = socket.socket()
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", port))  # nothing left listening
        finally:
            s.close()

    def test_stop_when_stopped_is_not_an_error(self):
        mc = self.control()
        first = mc.stop()
        self.assertFalse(first["running"])
        self.assertIsNone(first["pid"])
        mc2, _ = self.start_a_mint(mc=mc)
        mc.stop(drain_seconds=5)
        again = mc.stop(drain_seconds=5)  # idempotent
        self.assertFalse(again["running"])

    def test_restart_after_stop_keeps_the_same_identity(self):
        mc, first = self.start_a_mint()
        mc.stop(drain_seconds=5)
        second = mc.start(mint_id="test-mint", baseline_model_class="baseline-v1",
                          port=free_port(), rate_ppm=0, cap_mc=0,
                          exempt_below_mc=10)
        self.assertTrue(second["running"])
        code, body = http_get(second["port"], "/v3/mints")
        self.assertEqual(json.loads(body)["mint_id"], "test-mint")

    def test_double_start_is_refused_and_the_first_survives(self):
        mc, status = self.start_a_mint()
        with self.assertRaises(MintControlError) as ctx:
            mc.start(mint_id="test-mint", baseline_model_class="baseline-v1",
                     port=free_port(), rate_ppm=0, cap_mc=0, exempt_below_mc=10)
        self.assertIn("already running", str(ctx.exception))
        self.assertIn(str(status["pid"]), str(ctx.exception))
        still = mc.status()
        self.assertTrue(still["running"])
        self.assertEqual(still["pid"], status["pid"])
        self.assertEqual(http_get(status["port"], "/v3/mints")[0], 200)

    def test_a_second_controller_reattaches(self):
        """The GUI can restart; the mint it started must still be found."""
        mc, status = self.start_a_mint()
        fresh = self.control()  # no memory of the Popen object at all
        seen = fresh.status()
        self.assertTrue(seen["running"])
        self.assertEqual(seen["pid"], status["pid"])
        self.assertEqual(seen["port"], status["port"])
        self.assertTrue(fresh.admin_token())
        self.assertFalse(fresh.stop(drain_seconds=5)["running"])
        self.assertFalse(mc.status()["running"])


class TestWedgedMint(MintControlTestCase):
    """The paths that exist because a child can refuse to cooperate."""

    def test_a_mint_that_cannot_answer_sigterm_is_killed(self):
        mc, status = self.start_a_mint()
        pid = status["pid"]
        # SIGSTOP: the process still exists, still holds the port, and will
        # not run its SIGTERM handler. This is what "wedged" looks like.
        os.kill(pid, signal.SIGSTOP)
        after = mc.stop(drain_seconds=1)
        self.assertFalse(after["running"])
        self.assertIn("killed", (after["last_error"] or "").lower())
        self.assertFalse(_pid_alive(pid))
        # and it was WAITED for, not just killed: an unreaped child stays a
        # zombie — with a readable /proc/<pid>/stat — for the life of the
        # GUI process, which is exactly what the pid identity check reads.
        self.assertFalse(os.path.exists("/proc/%d" % pid),
                         "the killed mint was left behind as a zombie")

    def test_start_times_out_and_leaves_nothing_behind(self):
        """A launcher that never serves must not be reported as running."""
        stub = os.path.join(self.workdir, "stub_mint.py")
        pidfile = os.path.join(self.workdir, "stub.pid")
        with open(stub, "w") as fh:
            fh.write("import os, sys, time\n"
                     "open(%r, 'w').write(str(os.getpid()))\n"
                     "time.sleep(300)\n" % pidfile)
        import gui.mintctl as mintctl
        real = mintctl.RUN_MINT
        mintctl.RUN_MINT = stub
        self.addCleanup(setattr, mintctl, "RUN_MINT", real)
        mc = self.control()
        mc.start_timeout_s = 2.0
        with self.assertRaises(MintControlError) as ctx:
            mc.start(mint_id="test-mint", baseline_model_class="baseline-v1",
                     port=free_port(), rate_ppm=0, cap_mc=0, exempt_below_mc=10)
        self.assertIn("did not answer", str(ctx.exception))
        self.assertFalse(mc.status()["running"])
        with open(pidfile) as fh:
            stub_pid = int(fh.read())
        self.assertFalse(_pid_alive(stub_pid), "the stalled child was left alive")


class TestStaleState(MintControlTestCase):
    """status() honesty: a pid file is not evidence."""

    def _write_state(self, mc, **fields):
        blob = {"pid": None, "port": 65000, "mint_id": "test-mint",
                "proc_start_ticks": None, "started_at_ms": 1,
                "last_error": None}
        blob.update(fields)
        with open(mc.state_path, "w") as fh:
            json.dump(blob, fh)

    def test_dead_pid_is_not_running(self):
        dead = subprocess.Popen([sys.executable, "-c", "pass"])
        dead.wait()  # reaped here, so the pid is genuinely free
        mc = self.control()
        self._write_state(mc, pid=dead.pid, proc_start_ticks="12345")
        status = mc.status()
        self.assertFalse(status["running"])
        self.assertIsNone(status["pid"])
        self.assertIn("no longer running", (status["last_error"] or "").lower())
        # and the stale pid is cleared, not left to be re-tested forever
        with open(mc.state_path) as fh:
            self.assertIsNone(json.load(fh)["pid"])

    def test_recycled_pid_is_not_running(self):
        """A live pid whose start time does not match is somebody else."""
        mc = self.control()
        self._write_state(mc, pid=os.getpid(), proc_start_ticks="1")
        status = mc.status()
        self.assertFalse(status["running"])
        self.assertIn("reused", (status["last_error"] or ""))

    def test_live_pid_that_is_not_our_mint_is_not_running(self):
        """Even with the true start time, an unrelated process is not a mint."""
        mc = self.control()
        import gui.mintctl as mintctl
        ticks = mintctl._proc_start_ticks(os.getpid())
        self.assertIsNotNone(ticks)  # /proc is expected on this platform
        self._write_state(mc, pid=os.getpid(), proc_start_ticks=ticks)
        status = mc.status()
        self.assertFalse(status["running"])
        self.assertIn("not this workdir's mint", (status["last_error"] or ""))

    def test_another_workdirs_mint_is_not_this_workdirs_mint(self):
        """Same launcher, same start time, different --db: still not ours."""
        # inside self.workdir so the base cleanup removes it, and removes it
        # AFTER the mint in it has been stopped (cleanups run last-in-first-out)
        other = os.path.join(self.workdir, "other-mint-workdir")
        running, status = self.start_a_mint(mc=self.control(other),
                                            mint_id="other-mint")
        mine = self.control()
        with open(running.state_path) as fh:
            ticks = json.load(fh)["proc_start_ticks"]
        self._write_state(mine, pid=status["pid"], mint_id="other-mint",
                          port=status["port"], proc_start_ticks=ticks)
        self.assertFalse(mine.status()["running"])

    def test_stop_on_a_stale_pid_file_is_quiet(self):
        dead = subprocess.Popen([sys.executable, "-c", "pass"])
        dead.wait()  # reaped here, so the pid is genuinely free
        mc = self.control()
        self._write_state(mc, pid=dead.pid, proc_start_ticks="12345")
        self.assertFalse(mc.stop(drain_seconds=2)["running"])

    def test_missing_state_file_reads_as_stopped(self):
        mc = self.control()
        status = mc.status()
        self.assertEqual(
            status,
            {"running": False, "pid": None, "port": None, "mint_id": None,
             "base_url": None, "started_at_ms": None, "last_error": None,
             "responding": False})
        self.assertEqual(mc.logs(), [])
        self.assertIsNone(mc.admin_token())


class TestRefusals(MintControlTestCase):

    def test_port_already_in_use(self):
        held = socket.socket()
        self.addCleanup(held.close)
        held.bind(("127.0.0.1", 0))
        held.listen(1)
        port = held.getsockname()[1]
        mc = self.control()
        with self.assertRaises(MintControlError) as ctx:
            mc.start(mint_id="test-mint", baseline_model_class="baseline-v1",
                     port=port, rate_ppm=0, cap_mc=0, exempt_below_mc=10)
        message = str(ctx.exception)
        self.assertIn(str(port), message)
        self.assertIn("port", message.lower())
        self.assertFalse(mc.status()["running"])
        # the refusal is remembered, so a GUI restart can still explain it
        self.assertIn(str(port), mc.status()["last_error"] or "")

    def test_baseline_change_is_refused(self):
        mc, _ = self.start_a_mint(baseline="baseline-v1")
        mc.stop(drain_seconds=5)
        with self.assertRaises(MintControlError) as ctx:
            mc.start(mint_id="test-mint", baseline_model_class="baseline-v2",
                     port=free_port(), rate_ppm=0, cap_mc=0, exempt_below_mc=10)
        message = str(ctx.exception)
        self.assertIn("baseline", message.lower())
        self.assertIn("baseline-v1", message)
        self.assertIn("baseline-v2", message)
        self.assertFalse(mc.status()["running"])
        # the refusal changed nothing on disk
        with open(mc.keys_path) as fh:
            self.assertEqual(json.load(fh)["baseline_model_class"], "baseline-v1")
        # and the original mint still starts
        self.assertTrue(self.start_a_mint(mc=mc)[1]["running"])

    def test_baseline_refusal_from_the_launcher_itself(self):
        """The same refusal, taken from run_mint.py's exit instead of ours.

        mintctl pre-checks the key file so the operator gets an answer
        without a process being spawned. That pre-check could drift from
        the launcher's §4.1 rule, so this test disables it and asserts that
        the child's own refusal is surfaced as a MintControlError with the
        launcher's words in it — not as a swallowed exit code.
        """
        mc, _ = self.start_a_mint(baseline="baseline-v1")
        mc.stop(drain_seconds=5)
        mc._preflight_keys = lambda *a, **k: None  # type: ignore[method-assign]
        with self.assertRaises(MintControlError) as ctx:
            mc.start(mint_id="test-mint", baseline_model_class="baseline-v2",
                     port=free_port(), rate_ppm=0, cap_mc=0, exempt_below_mc=10)
        message = str(ctx.exception)
        self.assertIn("baseline", message.lower())
        self.assertIn("4.1", message)  # quoted from the launcher
        self.assertFalse(mc.status()["running"])

    def test_wrong_mint_id_for_this_workdir(self):
        mc, _ = self.start_a_mint(mint_id="test-mint")
        mc.stop(drain_seconds=5)
        with self.assertRaises(MintControlError) as ctx:
            mc.start(mint_id="other-mint", baseline_model_class="baseline-v1",
                     port=free_port(), rate_ppm=0, cap_mc=0, exempt_below_mc=10)
        self.assertIn("test-mint", str(ctx.exception))

    def test_unpinned_baseline_asks_a_human(self):
        """A key file from before identity pinning must not be pinned blind."""
        mc = self.control()
        with open(mc.keys_path, "w") as fh:
            json.dump({"private": "x", "public": "y"}, fh)
        with self.assertRaises(MintControlError) as ctx:
            mc.start(mint_id="test-mint", baseline_model_class="baseline-v1",
                     port=free_port(), rate_ppm=0, cap_mc=0, exempt_below_mc=10)
        self.assertIn("--pin-baseline", str(ctx.exception))

    def test_bad_settings_never_spawn_anything(self):
        mc = self.control()
        bad = [
            (dict(mint_id="Test Mint"), "lowercase"),
            (dict(mint_id=""), "usable mint id"),
            (dict(baseline_model_class=""), "baseline_model_class"),
            (dict(port=0), "fixed port"),
            (dict(port=99999), "65535"),
            (dict(rate_ppm=10001), "10000"),
            (dict(rate_ppm=-1), "rate_ppm"),
            (dict(cap_mc=-5), "cap_mc"),
            (dict(exempt_below_mc=9), "exempt_below_mc"),
        ]
        for overrides, needle in bad:
            kwargs = dict(mint_id="test-mint", baseline_model_class="baseline-v1",
                          port=free_port(), rate_ppm=0, cap_mc=0,
                          exempt_below_mc=10)
            kwargs.update(overrides)
            with self.subTest(**overrides):
                with self.assertRaises(MintControlError) as ctx:
                    mc.start(**kwargs)
                self.assertIn(needle, str(ctx.exception))
        # nothing was created, nothing was started
        self.assertFalse(os.path.exists(mc.db_path))
        self.assertFalse(os.path.exists(mc.keys_path))
        self.assertFalse(mc.status()["running"])

    def test_missing_launcher_is_a_clear_error(self):
        mc = self.control()
        import gui.mintctl as mintctl
        real = mintctl.RUN_MINT
        mintctl.RUN_MINT = os.path.join(self.workdir, "not-here.py")
        self.addCleanup(setattr, mintctl, "RUN_MINT", real)
        with self.assertRaises(MintControlError) as ctx:
            mc.start(mint_id="test-mint", baseline_model_class="baseline-v1",
                     port=free_port(), rate_ppm=0, cap_mc=0, exempt_below_mc=10)
        self.assertIn("not-here.py", str(ctx.exception))


class TestNoTracebackEverEscapes(MintControlTestCase):
    """app.py copies these messages into an HTTP body and onto a page.

    run_mint.py converts exactly one startup failure — the bind — into a
    readable sys.exit. Everything else (a corrupt ledger, a hand-edited key
    file, mintapi's single-writer refusal) dies with a full Python
    traceback on stderr, and the pinned contract says an error is never a
    traceback.
    """

    def _assert_no_traceback(self, message):
        self.assertNotIn("Traceback (most recent call last)", message)
        self.assertNotIn('File "', message)
        self.assertNotIn("run_mint.py\", line", message)
        self.assertNotIn("^^^", message)
        # and no absolute path into the interpreter or the repo internals
        self.assertNotIn("/impl/aicash/", message)

    def test_a_corrupt_ledger_is_one_line_not_a_traceback(self):
        """The real launcher, a real sqlite failure, a real traceback."""
        mc = self.control()
        with open(mc.db_path, "w") as fh:
            fh.write("this is not a database")
        with self.assertRaises(MintControlError) as ctx:
            mc.start(mint_id="test-mint", baseline_model_class="baseline-v1",
                     port=free_port(), rate_ppm=0, cap_mc=0, exempt_below_mc=10)
        message = str(ctx.exception)
        self._assert_no_traceback(message)
        # the one line that tells the operator what broke is kept
        self.assertIn("DatabaseError", message)
        self.assertIn("not a database", message)
        self.assertLess(len(message), 400, message)
        self.assertFalse(mc.status()["running"])

    def test_a_broken_key_file_is_one_line_not_a_traceback(self):
        """A key file with the pinned identity but no signing key."""
        mc = self.control()
        with open(mc.keys_path, "w") as fh:
            json.dump({"public": "x", "mint_id": "test-mint",
                       "baseline_model_class": "baseline-v1"}, fh)
        with self.assertRaises(MintControlError) as ctx:
            mc.start(mint_id="test-mint", baseline_model_class="baseline-v1",
                     port=free_port(), rate_ppm=0, cap_mc=0, exempt_below_mc=10)
        message = str(ctx.exception)
        self._assert_no_traceback(message)
        self.assertIn("KeyError", message)
        self.assertIn("private", message)

    def test_the_single_writer_refusal_is_explained_not_dumped(self):
        """Two mints on one ledger: mintapi raises, run_mint.py does not catch.

        The flock is taken here rather than by starting a second mint,
        because a second mint on this workdir is now caught earlier (see
        TestOrphanedMint) and would never reach the launcher.
        """
        import fcntl
        mc = self.control()
        fd = os.open(mc.db_path, os.O_RDWR | os.O_CREAT, 0o600)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with self.assertRaises(MintControlError) as ctx:
            mc.start(mint_id="test-mint", baseline_model_class="baseline-v1",
                     port=free_port(), rate_ppm=0, cap_mc=0, exempt_below_mc=10)
        message = str(ctx.exception)
        self._assert_no_traceback(message)
        self.assertIn("one database, one mint", message)
        self.assertIn("already serves this ledger", message)

    def test_a_launcher_that_dies_mid_start_is_summarised(self):
        """A traceback written after some ordinary output, as a real one is."""
        stub = os.path.join(self.workdir, "crash_mint.py")
        with open(stub, "w") as fh:
            fh.write("import sys\n"
                     "print('starting up', file=sys.stderr)\n"
                     "raise RuntimeError('the widget was not frobnicated')\n")
        import gui.mintctl as mintctl
        real = mintctl.RUN_MINT
        mintctl.RUN_MINT = stub
        self.addCleanup(setattr, mintctl, "RUN_MINT", real)
        mc = self.control()
        with self.assertRaises(MintControlError) as ctx:
            mc.start(mint_id="test-mint", baseline_model_class="baseline-v1",
                     port=free_port(), rate_ppm=0, cap_mc=0, exempt_below_mc=10)
        message = str(ctx.exception)
        self._assert_no_traceback(message)
        self.assertIn("RuntimeError: the widget was not frobnicated", message)
        self.assertIn("starting up", message)  # ordinary stderr survives

    def test_strip_tracebacks_keeps_what_an_operator_needs(self):
        """Frames go; the exception line, and INDENTED ADVICE, stay.

        run_mint.py's own refusals indent the command they want run, so a
        blanket 'drop indented lines' would eat the fix along with the noise.
        """
        text = (
            "cannot bind port 8787: [Errno 98] Address already in use\n"
            "another mint is probably already running. Check with:\n"
            "  ss -ltnp | grep 8787\n")
        clean, saw = _strip_tracebacks(text)
        self.assertFalse(saw)
        self.assertIn("  ss -ltnp | grep 8787", clean)

        chained = (
            "Traceback (most recent call last):\n"
            '  File "/repo/a.py", line 1, in <module>\n'
            "    boom()\n"
            "    ^^^^^^\n"
            "KeyError: 'private'\n"
            "\n"
            "During handling of the above exception, another exception "
            "occurred:\n"
            "\n"
            "Traceback (most recent call last):\n"
            '  File "/repo/b.py", line 9, in main\n'
            "    raise RuntimeError('no signing key')\n"
            "RuntimeError: no signing key\n")
        clean, saw = _strip_tracebacks(chained)
        self.assertTrue(saw)
        self.assertEqual(clean,
                         "KeyError: 'private'\nRuntimeError: no signing key")

        # The log tail is read with a byte limit, so the "Traceback" header
        # is the first thing lost. A frame on its own is still a frame.
        beheaded = (
            '  File "/repo/aicash/ledgerstore.py", line 233, in _conn\n'
            "    conn = sqlite3.connect(\n"
            "           ^^^^^^^^^^^^^^^^\n"
            "sqlite3.DatabaseError: file is not a database\n")
        clean, saw = _strip_tracebacks(beheaded)
        self.assertTrue(saw)
        self.assertEqual(clean,
                         "sqlite3.DatabaseError: file is not a database")


class TestStopValidatesFirst(MintControlTestCase):

    def test_a_bad_drain_is_refused_before_anything_is_signalled(self):
        """A public method raises MintControlError, and never half-acts.

        Sending SIGTERM and only then discovering the wait budget is
        unusable would leave a dead mint, a bare ValueError, and a state
        file still claiming the pid is live.
        """
        mc, status = self.start_a_mint()
        for bad in ("abc", None, float("nan"), float("inf"), -1, [5]):
            with self.subTest(drain_seconds=bad):
                with self.assertRaises(MintControlError) as ctx:
                    mc.stop(drain_seconds=bad)
                self.assertIn("drain_seconds", str(ctx.exception))
                # the mint is untouched: still running, still serving
                still = mc.status()
                self.assertTrue(still["running"])
                self.assertEqual(still["pid"], status["pid"])
                self.assertEqual(http_get(status["port"], "/v3/mints")[0], 200)
        self.assertFalse(mc.stop(drain_seconds=5)["running"])


class TestSymlinkedWorkdir(MintControlTestCase):

    def test_two_spellings_of_one_workdir_are_one_mint(self):
        """A workdir reached through a symlink is the SAME workdir.

        Comparing path strings instead of resolving them made a live mint
        read as stopped, made stop() a no-op on it, and blamed pid reuse
        for what was a spelling difference.
        """
        real = os.path.join(self.workdir, "real-workdir")
        os.makedirs(real)
        link = os.path.join(self.workdir, "link-workdir")
        os.symlink(real, link)
        through_link, status = self.start_a_mint(mc=self.control(link),
                                                 mint_id="sym-mint")
        through_real = self.control(real)
        seen = through_real.status()
        self.assertTrue(seen["running"], seen)
        self.assertEqual(seen["pid"], status["pid"])
        self.assertEqual(seen["port"], status["port"])
        self.assertFalse(through_real.stop(drain_seconds=5)["running"])
        self.assertFalse(_pid_alive(status["pid"]))

    def test_a_mint_started_by_hand_through_a_symlink_is_still_ours(self):
        """The OTHER spelling: argv's --db, not our workdir, is the odd one.

        A mint started by hand — or by an older GUI, or from a shell script
        — with --db reaching the ledger through a symlink is serving this
        workdir's ledger and holds its single-writer lock. Comparing that
        argument as a string would make it invisible to status() and a
        no-op for stop(), while it kept the port.
        """
        import gui.mintctl as mintctl
        real = os.path.join(self.workdir, "real-workdir")
        os.makedirs(real)
        link = os.path.join(self.workdir, "link-workdir")
        os.symlink(real, link)
        port = free_port()
        proc = subprocess.Popen(
            [sys.executable, mintctl.RUN_MINT,
             "--port", str(port),
             "--db", os.path.join(link, "mint.db"),
             "--keys", os.path.join(link, "mint-keys.json"),
             "--mint-id", "byhand-mint",
             "--model-class", "baseline-v1",
             "--rate-ppm", "0", "--cap-mc", "0", "--exempt-below-mc", "10",
             "--admin-token-file", os.path.join(link, "mint-admin-keys.json"),
             "--access-log", os.path.join(link, "mint.log"),
             "--console-port", "0"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(_hard_kill, proc)
        deadline = time.monotonic() + 20
        while True:
            try:
                if http_get(port, "/v3/mints", timeout=1.0)[0] == 200:
                    break
            except OSError:
                pass
            self.assertIsNone(proc.poll(), "the hand-started mint died")
            self.assertLess(time.monotonic(), deadline, "it never came up")
            time.sleep(0.1)
        mc = self.control(real)   # spells the ledger without the symlink
        seen = mc.status()
        self.assertTrue(seen["running"], seen)
        self.assertEqual(seen["pid"], proc.pid)
        self.assertEqual(seen["port"], port)
        self.assertEqual(seen["mint_id"], "byhand-mint")
        self.assertFalse(mc.stop(drain_seconds=5)["running"])
        self.assertIsNotNone(proc.wait(timeout=5))


class TestOrphanedMint(MintControlTestCase):
    """The supervision file can go missing; the mint it described cannot."""

    def test_a_lost_state_file_does_not_strand_a_running_mint(self):
        mc, status = self.start_a_mint(mint_id="orphan-mint")
        os.unlink(mc.state_path)
        fresh = self.control()  # a GUI that has never heard of this mint
        seen = fresh.status()
        self.assertTrue(seen["running"], seen)
        self.assertEqual(seen["pid"], status["pid"])
        self.assertEqual(seen["port"], status["port"])
        self.assertEqual(seen["mint_id"], "orphan-mint")
        self.assertTrue(seen["responding"])
        self.assertIsInstance(seen["started_at_ms"], int)

    def test_starting_over_an_orphan_says_what_is_actually_wrong(self):
        """Not 'that port is busy, pick another' — which makes it worse."""
        mc, status = self.start_a_mint(mint_id="orphan-mint")
        os.unlink(mc.state_path)
        fresh = self.control()
        with self.assertRaises(MintControlError) as ctx:
            fresh.start(mint_id="orphan-mint", baseline_model_class="baseline-v1",
                        port=free_port(), rate_ppm=0, cap_mc=0, exempt_below_mc=10)
        message = str(ctx.exception)
        self.assertIn("already running", message)
        self.assertIn(str(status["pid"]), message)
        self.assertEqual(http_get(status["port"], "/v3/mints")[0], 200)

    def test_an_orphan_can_still_be_stopped(self):
        mc, status = self.start_a_mint(mint_id="orphan-mint")
        os.unlink(mc.state_path)
        fresh = self.control()
        self.assertFalse(fresh.stop(drain_seconds=5)["running"])
        self.assertFalse(_pid_alive(status["pid"]))

    def test_a_busy_port_serving_this_mint_id_says_stop_it_not_move_it(self):
        """'Pick a different port' is the wrong advice for a mint.

        Moving ports leaves two mints claiming one mint id, and if the
        listener is this workdir's own lost mint, the second one is refused
        by the ledger's single-writer lock — a worse error, about a problem
        the operator was never told they had.
        """
        other = os.path.join(self.workdir, "other-workdir")
        _, status = self.start_a_mint(mc=self.control(other),
                                      mint_id="test-mint")
        mine = self.control()
        with self.assertRaises(MintControlError) as ctx:
            mine.start(mint_id="test-mint", baseline_model_class="baseline-v1",
                       port=status["port"], rate_ppm=0, cap_mc=0,
                       exempt_below_mc=10)
        message = str(ctx.exception)
        self.assertIn("already serving 'test-mint'", message)
        self.assertNotIn("Pick a different port", message)
        self.assertFalse(mine.status()["running"])
        self.assertEqual(http_get(status["port"], "/v3/mints")[0], 200)

    def test_a_busy_port_serving_a_different_mint_names_it(self):
        other = os.path.join(self.workdir, "other-workdir")
        _, status = self.start_a_mint(mc=self.control(other),
                                      mint_id="other-mint")
        mine = self.control()
        with self.assertRaises(MintControlError) as ctx:
            mine.start(mint_id="test-mint", baseline_model_class="baseline-v1",
                       port=status["port"], rate_ppm=0, cap_mc=0,
                       exempt_below_mc=10)
        message = str(ctx.exception)
        self.assertIn("A different mint ('other-mint')", message)
        self.assertIn("Pick a different port", message)

    def test_a_busy_port_that_is_not_ours_still_says_pick_another(self):
        """The orphan message must not be handed out for an unrelated listener."""
        held = socket.socket()
        self.addCleanup(held.close)
        held.bind(("127.0.0.1", 0))
        held.listen(1)
        mc = self.control()
        with self.assertRaises(MintControlError) as ctx:
            mc.start(mint_id="test-mint", baseline_model_class="baseline-v1",
                     port=held.getsockname()[1], rate_ppm=0, cap_mc=0,
                     exempt_below_mc=10)
        self.assertIn("Pick a different port", str(ctx.exception))


class TestCredentialRedaction(MintControlTestCase):
    """The redaction is the safety net under 'the token never reaches the page'.

    Nothing writes the credential to mint.log today, so a test that only
    checks it is absent from a normal log passes with the redaction deleted.
    These put one there on purpose.
    """

    def _leak(self, mc, token, note="X-Admin-Token"):
        with open(mc.log_path, "a") as fh:
            fh.write("127.0.0.1 POST /admin/issue 200 %s: %s\n" % (note, token))

    def test_a_credential_in_the_log_is_redacted(self):
        mc, _ = self.start_a_mint()
        token = mc.admin_token()
        self._leak(mc, token)
        shown = "\n".join(mc.logs(lines=50))
        self.assertNotIn(token, shown)
        self.assertIn(REDACTED, shown)

    def test_a_rotated_out_credential_is_still_redacted(self):
        """run_mint.py writes a FRESH credential on every start.

        mint.log is appended to across restarts, so redacting only the
        token currently in mint-admin-keys.json leaves every previous one
        in clear.
        """
        mc, _ = self.start_a_mint()
        old = mc.admin_token()
        self._leak(mc, old)
        mc.stop(drain_seconds=5)
        # exactly what a second start does to that file
        with open(mc.admin_token_path, "w") as fh:
            json.dump({"mint_id": "test-mint",
                       "admin_token": "aaaabbbbccccddddeeeeffff11112222"}, fh)
        shown = "\n".join(mc.logs(lines=50))
        self.assertNotIn(old, shown)
        self.assertIn(REDACTED, shown)

    def test_the_digest_file_holds_no_credential(self):
        """Remembering the old secrets in clear to redact them is its own leak."""
        mc, _ = self.start_a_mint()
        token = mc.admin_token()
        self._leak(mc, token)
        mc.logs(lines=50)
        with open(mc.digests_path) as fh:
            blob = fh.read()
        self.assertNotIn(token, blob)
        self.assertIn(hashlib.sha256(token.encode()).hexdigest(), blob)

    def test_redaction_does_not_eat_ordinary_log_lines(self):
        mc, status = self.start_a_mint()
        for _ in range(3):
            http_get(status["port"], "/v3/mints")
        shown = "\n".join(mc.logs(lines=20))
        self.assertIn("/v3/mints", shown)
        self.assertNotIn(REDACTED, shown)

    def test_a_credential_in_a_failed_start_is_redacted_too(self):
        """_log_since quotes the log into a MintControlError message."""
        mc, _ = self.start_a_mint()
        token = mc.admin_token()
        mc.stop(drain_seconds=5)
        stub = os.path.join(self.workdir, "leaky_mint.py")
        with open(stub, "w") as fh:
            fh.write("import sys\n"
                     "print('admin token is %s', file=sys.stderr)\n"
                     "sys.exit('gave up')\n" % token)
        import gui.mintctl as mintctl
        realpath = mintctl.RUN_MINT
        mintctl.RUN_MINT = stub
        self.addCleanup(setattr, mintctl, "RUN_MINT", realpath)
        with self.assertRaises(MintControlError) as ctx:
            mc.start(mint_id="test-mint", baseline_model_class="baseline-v1",
                     port=free_port(), rate_ppm=0, cap_mc=0, exempt_below_mc=10)
        self.assertNotIn(token, str(ctx.exception))
        self.assertIn(REDACTED, str(ctx.exception))


class TestDamagedStateFile(MintControlTestCase):
    """status() is the method that has to stay honest over a broken workdir."""

    def test_an_impossible_port_is_not_reported_as_a_port(self):
        mc = self.control()
        with open(mc.state_path, "w") as fh:
            json.dump({"pid": 1, "port": 70000, "mint_id": 5}, fh)
        status = mc.status()
        self.assertIsNone(status["port"])
        self.assertIsNone(status["base_url"])
        self.assertIsNone(status["mint_id"])
        self.assertFalse(status["running"])

    def test_other_junk_ports_are_ignored(self):
        mc = self.control()
        for junk in (0, -1, True, "8787", 1.5, None, [8787]):
            with self.subTest(port=junk):
                with open(mc.state_path, "w") as fh:
                    json.dump({"pid": None, "port": junk,
                               "mint_id": "test-mint"}, fh)
                status = mc.status()
                self.assertIsNone(status["port"])
                self.assertIsNone(status["base_url"])


def _admin_issue(port: int, token: str) -> int:
    """POST /admin/issue with no outputs; returns the HTTP status."""
    import http.client
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        conn.request("POST", "/admin/issue", body=json.dumps({"outputs": []}),
                     headers={"Content-Type": "application/json",
                              "X-Admin-Token": token})
        return conn.getresponse().status
    finally:
        conn.close()


def _hard_kill(proc) -> None:
    """Leave nothing running, whatever the test did or did not get to."""
    if proc.poll() is None:
        try:
            proc.kill()
        except OSError:
            pass
    try:
        proc.wait(timeout=5)
    except Exception:
        pass


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    # a reaped-but-unwaited child shows as a zombie; that is not alive
    try:
        with open("/proc/%d/stat" % pid, "rb") as fh:
            return fh.read().rpartition(b")")[2].split()[0] not in (b"Z", b"X")
    except OSError:
        return False


if __name__ == "__main__":
    unittest.main()
