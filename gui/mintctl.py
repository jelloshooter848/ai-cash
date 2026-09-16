#!/usr/bin/env python3
"""Run and supervise ``run_mint.py`` as a subprocess, for the operator GUI.

Nothing here is protocol and nothing here changes mint behaviour: this
module only starts, stops, watches and reads the launcher that already
exists. Every flag it passes is a flag ``run_mint.py`` documents.

Layout, fixed by the GUI contract — one workdir holds one mint:

    <workdir>/mint.db              ledger
    <workdir>/mint-keys.json       Ed25519 signing key + pinned identity
    <workdir>/mint-admin-keys.json generated /admin/issue credential (0600)
    <workdir>/mint.log             access log + the mint's stderr
    <workdir>/mint-control.json    this module's own supervision state
    <workdir>/mint-token-digests.json  SHA-256 of every admin credential
                                   this workdir has held — digests only,
                                   never a secret; see the redaction note

Three decisions worth knowing about:

* **The child's stdout is discarded; its stderr goes to mint.log.**
  ``run_mint.py --access-log PATH`` already writes every request line to
  PATH *and* mirrors it to stdout, so capturing stdout as well would
  double every line. Discarding it also means that even if someone one
  day adds ``--show-admin-token``, the live credential cannot land in a
  log file this module will happily print back. The startup banner is
  lost with it, which costs nothing: everything in it is either in the
  descriptor or is a path this module already knows.

* **The console is disabled** (``--console-port 0``). The GUI *is* the
  console, and the default 8080 would bind a second port nobody asked
  for.

* **Retention pruning is left at the launcher's own default** (6h, which
  pins ``prunes_spent_records: true`` into the key file for good on the
  first start). Overriding it here would make a GUI-started mint publish
  a different §8(b) claim than a hand-started one, and this module is not
  allowed to change mint behaviour. Operators who want a mint that keeps
  every spent record should start it by hand once with
  ``--prune-interval-hours 0`` before the claim is pinned.

One behaviour worth knowing about before reading status(): a mint is
identified by the LEDGER IT SERVES, not by mint-control.json. If that
supervision file is lost — deleted, restored over, or never written
because the GUI was killed between the spawn and the write — status() and
stop() find the running mint by looking for the process whose ``--db``
resolves to this workdir's mint.db and re-adopt it. Without that, a live
mint holding the port and the ledger's single-writer lock would be
invisible to the panel and unstoppable through it.

Deviations from the pinned GUI contract, all of them deliberate and none
of them visible to the other two modules as a different call signature:

* ``__init__`` **creates the workdir** (``os.makedirs(..., exist_ok=True)``)
  and nothing else — no process, no key file, no ledger. The contract only
  says it takes a path; creating the directory here means every later
  method can assume it exists instead of each one racing to make it.
* ``start(port=0)`` **is refused**, although ``run_mint.py`` documents
  ``--port 0`` as "picks an ephemeral port". The mint would come up on a
  port it prints to a stdout this module discards, and nothing could then
  tell the GUI, a wallet, or a payer where it went. A GUI restriction, not
  a mint one: an operator who wants an ephemeral port can still start the
  mint by hand.
* ``status()`` returns one **additive** key, ``responding`` (did the
  descriptor answer on this call), and keeps the last-known
  ``port``/``mint_id``/``base_url`` when ``running`` is False, so the panel
  can still name the mint a stopped workdir holds.
* ``stop(drain_seconds=...)`` is **this call's** wait budget before SIGKILL.
  The child's own in-flight drain deadline is fixed at start time
  (``child_drain_s``).
* The start/kill timeouts are class attributes, not parameters.
* There is no ``--pin-baseline`` path: a key file that predates baseline
  pinning is reported, never pinned, because guessing wrong redefines the
  credit permanently.

Two error rules this module holds itself to, because app.py copies its
messages straight into an HTTP body and a page:

* **No traceback ever leaves here.** ``run_mint.py`` turns only a bind
  failure into a clean ``sys.exit``; a corrupt ledger, a hand-edited key
  file or the single-writer refusal all die with a full Python traceback
  on stderr. Everything quoted out of mint.log goes through
  ``_strip_tracebacks`` first, which keeps the final ``Type: message``
  line and drops the frames and absolute paths above it. ``logs()`` is the
  deliberate exception: it is the log VIEWER, not an error, and a traceback
  in mint.log is exactly what an operator opened it to read.
* **The admin credential never appears in anything this module returns.**
  ``run_mint.py`` writes a fresh one on every start, so redacting only the
  token currently in mint-admin-keys.json would let a rotated-out one
  resurface from an append-only log. Digests (SHA-256, never the secrets)
  of every credential this workdir has held are kept in
  ``mint-token-digests.json`` and every log line is matched against them.

Import-safe: importing this module starts no processes and creates no
files.
"""
from __future__ import annotations

import errno
import hashlib
import http.client
import json
import math
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time

__all__ = ["MintControl", "MintControlError"]

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
RUN_MINT = os.path.join(_REPO, "run_mint.py")

try:  # the authoritative rule, so it cannot drift from the mint's own
    sys.path.insert(0, os.path.join(_REPO, "impl"))
    from aicash.tokencodec import MINT_ID_RE  # type: ignore
except Exception:  # pragma: no cover - only if impl/ is unavailable
    # Same pattern as aicash.tokencodec.MINT_ID_RE (§3.1). Duplicated only
    # so that a broken impl/ import degrades into a slightly worse error
    # message instead of an unimportable GUI.
    MINT_ID_RE = re.compile(r"^[a-z0-9-]{1,64}$")

#: §7.3 via aicash.burncalc; checked here only to produce a readable error
#: instead of a ValueError traceback out of the child.
MAX_RATE_PPM = 10_000
MIN_EXEMPT_BELOW_MC = 10

_HAVE_PROC = os.path.isdir("/proc/self")


class MintControlError(Exception):
    """A start/stop this operator can do something about.

    The message is meant to be shown to a non-expert verbatim: what went
    wrong, and what to change.
    """


# --------------------------------------------------------------------------
# process identity
#
# The hard requirement on status() is that a pid file must never be enough
# to claim "running". A pid is a small recycled integer; between one GUI run
# and the next it can belong to an unrelated program, and an unrelated
# program answering `kill -0` would otherwise read as a live mint.
#
# So a recorded pid is trusted only when THREE things still agree:
#   1. /proc/<pid>/stat exists and the process is not a zombie;
#   2. its start time (field 22, in clock ticks since boot) is byte-for-byte
#      the value recorded when we spawned it. The kernel assigns this; it
#      cannot be forged by a later process and it is what makes (pid,
#      starttime) a genuinely unique process identifier on Linux. A recycled
#      pid always has a later start time, so recycling is caught here;
#   3. its command line still names OUR run_mint.py and OUR database path.
#      This is what makes the check specific to *this* mint rather than to
#      any mint: two workdirs, two mints, two different --db arguments.
#
# Reachability of the port is then a separate question, answered by the
# descriptor probe and reported in "responding"/"last_error" — a mint that
# is mid-drain, or wedged, is still *running*, and telling the operator it
# is not would invite them to start a second one on the same ledger.
# Where /proc is unavailable (not Linux), the descriptor probe becomes the
# identity check instead: mint_id must match what we recorded.
# --------------------------------------------------------------------------


def _proc_stat_fields(pid: int):
    """The fields of /proc/<pid>/stat after the comm field, or None."""
    try:
        with open("/proc/%d/stat" % pid, "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    # comm is parenthesised and may itself contain spaces and parens, so
    # split after the LAST ')'.
    rest = data.rpartition(b")")[2].split()
    if len(rest) < 20:
        return None
    return rest


def _proc_start_ticks(pid: int) -> str | None:
    fields = _proc_stat_fields(pid)
    if fields is None:
        return None
    return fields[19].decode("ascii", "replace")  # field 22 overall


def _proc_is_zombie(pid: int) -> bool:
    fields = _proc_stat_fields(pid)
    return bool(fields) and fields[0] in (b"Z", b"X", b"x")


def _proc_argv(pid: int) -> list[str]:
    """/proc/<pid>/cmdline split back into real argv.

    Split on the NULs the kernel actually stores rather than flattening to
    a string: a path containing a space is then still one argument, which
    is what makes the ``--db`` comparison below trustworthy.
    """
    try:
        with open("/proc/%d/cmdline" % pid, "rb") as fh:
            raw = fh.read()
    except OSError:
        return []
    parts = raw.split(b"\0")
    while parts and parts[-1] == b"":
        parts.pop()
    return [p.decode("utf-8", "replace") for p in parts]


def _argv_value(argv: list[str], flag: str) -> str | None:
    """The value of ``--flag VALUE`` or ``--flag=VALUE`` in argv, or None."""
    prefix = flag + "="
    for i, arg in enumerate(argv):
        if arg == flag:
            return argv[i + 1] if i + 1 < len(argv) else None
        if arg.startswith(prefix):
            return arg[len(prefix):]
    return None


def _same_path(a: str, b: str) -> bool:
    """Do two spellings name the same file?

    realpath, not abspath: a workdir reached through a symlink
    (/srv/mint -> /var/lib/mint-2026) is the SAME workdir, and comparing
    the strings would make this workdir's own live mint invisible — and,
    worse, blame pid reuse for what is a spelling difference.
    """
    try:
        return os.path.realpath(a) == os.path.realpath(b)
    except OSError:  # pragma: no cover - realpath barely fails
        return a == b


def _argv_serves_ledger(argv: list[str], db_path: str) -> bool:
    """Is this argv a run_mint.py serving exactly this ledger file?"""
    if not argv:
        return False
    wanted = {os.path.basename(RUN_MINT), "run_mint.py"}
    if not any(os.path.basename(a) in wanted for a in argv):
        return False
    db = _argv_value(argv, "--db")
    return db is not None and _same_path(db, db_path)


def _find_ledger_server(db_path: str) -> tuple[int, list[str]] | None:
    """The live run_mint.py serving this ledger, found the hard way.

    This is the recovery path for a lost mint-control.json: without it a
    deleted (or never-written, or replaced) supervision file strands a
    running mint — invisible to status(), unstoppable through stop(), and
    holding both the port and the single-writer lock on the ledger. The
    ledger path is the identity: one database, one mint.
    """
    if not _HAVE_PROC:  # pragma: no cover - non-Linux fallback
        return None
    try:
        names = os.listdir("/proc")
    except OSError:  # pragma: no cover
        return None
    me = os.getpid()
    for name in names:
        if not name.isdigit():
            continue
        pid = int(name)
        if pid == me:
            continue
        argv = _proc_argv(pid)
        if not _argv_serves_ledger(argv, db_path):
            continue
        if _proc_is_zombie(pid):
            continue
        return pid, argv
    return None


def _proc_start_ms(pid: int) -> int | None:
    """Wall-clock start time of a process, from /proc, in ms since the epoch.

    Only used for a mint this process did not spawn, where there is no
    remembered started_at_ms to report.
    """
    ticks = _proc_start_ticks(pid)
    if ticks is None:
        return None
    try:
        hz = os.sysconf("SC_CLK_TCK") or 100
        btime = None
        with open("/proc/stat") as fh:
            for line in fh:
                if line.startswith("btime "):
                    btime = int(line.split()[1])
                    break
        if btime is None:
            return None
        return int((btime + int(ticks) / float(hz)) * 1000)
    except (OSError, ValueError, AttributeError):  # pragma: no cover
        return None


_TB_HEADER = "Traceback (most recent call last):"
_TB_CHAIN = (
    "During handling of the above exception, another exception occurred:",
    "The above exception was the direct cause of the following exception:",
)
_TB_FRAME_RE = re.compile(r'^\s*File "[^"]*", line \d+')


def _strip_tracebacks(text: str) -> tuple[str, bool]:
    """(text with every traceback reduced to its last line, was there one).

    app.py puts whatever this module raises into ``{"error": {"detail":
    ...}}`` and the page shows it, and the contract says never a traceback.
    run_mint.py only converts a bind OSError into a clean sys.exit — a
    corrupt ledger, a hand-edited key file, or mintapi's single-writer
    RuntimeError all reach stderr as eight hundred characters of frames
    and absolute repo paths. The final ``Type: message`` line is the part
    an operator can act on, and it is the only part kept.

    Indented lines are dropped only INSIDE a traceback: run_mint.py's own
    refusals indent the command it wants you to run, and that must survive.
    """
    out: list[str] = []
    in_tb = False
    saw = False
    # A blank line is only worth keeping if ordinary text follows it. The
    # blanks around "During handling of the above exception" would otherwise
    # outlive the line they were separating.
    pending_blank = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == _TB_HEADER:
            in_tb, saw, pending_blank = True, True, False
            continue
        if stripped in _TB_CHAIN:
            pending_blank = False
            continue
        if in_tb:
            # frames, source echoes and ^^^^ markers are all indented; the
            # first unindented line is the exception itself and ends the block
            if not line[:1].strip():
                continue
            in_tb = False
            out.append(line)
            continue
        if _TB_FRAME_RE.match(line):
            # A frame with no header above it: the header was cut off by
            # the tail limit. One frame is proof enough — enter the block
            # here, so the source echo and ^^^^ markers under it go too.
            in_tb, saw, pending_blank = True, True, False
            continue
        if not stripped:
            pending_blank = True
            continue
        if pending_blank and out:
            out.append("")
        pending_blank = False
        out.append(line)
    return "\n".join(out).strip(), saw


#: What a redacted credential looks like in a log line.
REDACTED = "<admin token redacted>"
#: run_mint.py generates its credential as urlsafe-base64 of 24 random
#: bytes, so a candidate is a run of [A-Za-z0-9_-]. Length floor keeps the
#: hashing off every short word in the log.
_TOKENISH = re.compile(r"[A-Za-z0-9_\-]{16,}")
#: How many rotated-out credentials this workdir remembers the digest of.
_MAX_TOKEN_DIGESTS = 200


def _pid_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists, owned by someone else
    except OSError:
        return False
    return True


def _clean_port(value) -> int | None:
    """A port number, or None for anything that is not one.

    status() is the one method the contract asks to stay honest over a
    damaged workdir, so a hand-edited mint-control.json saying
    ``"port": 70000`` must not become a base_url nothing can ever connect
    to. bool is excluded on purpose: True is an int and is not a port.
    """
    if not isinstance(value, int) or isinstance(value, bool):
        return None
    return value if 0 < value < 65536 else None


def _now_ms() -> int:
    return int(time.time() * 1000)


class MintControl:
    """Supervise one mint in one workdir."""

    #: How long start() waits for the mint to actually serve its descriptor
    #: before giving up and killing the child. Instance-overridable.
    start_timeout_s: float = 30.0
    #: How long the child is given to die after SIGKILL before stop() gives up.
    kill_grace_s: float = 5.0
    #: --drain-seconds handed to the child at start: how long IT waits for
    #: in-flight handlers on SIGTERM. Fixed at start time, so stop()'s own
    #: drain_seconds cannot change it afterwards (see stop()).
    child_drain_s: float = 10.0

    def __init__(self, workdir: str) -> None:
        """Bind to one workdir, CREATING IT if it does not exist.

        That side effect is the one thing this constructor does beyond
        computing paths — no process, no key file, no ledger (see the
        module docstring's deviations list).

        The path is resolved with ``realpath``, not ``abspath``: process
        identity below is decided by comparing the ``--db`` argument of a
        live mint against this workdir's ledger, and two spellings of the
        same directory (one of them through a symlink) must not read as
        two different mints.
        """
        os.makedirs(os.path.abspath(workdir), exist_ok=True)
        self.workdir = os.path.realpath(os.path.abspath(workdir))
        self.db_path = os.path.join(self.workdir, "mint.db")
        self.keys_path = os.path.join(self.workdir, "mint-keys.json")
        self.admin_token_path = os.path.join(self.workdir, "mint-admin-keys.json")
        self.log_path = os.path.join(self.workdir, "mint.log")
        self.state_path = os.path.join(self.workdir, "mint-control.json")
        self.digests_path = os.path.join(self.workdir, "mint-token-digests.json")
        # app.py serves requests on threads; start/stop must not interleave.
        # Reentrant because start() and stop() both call status().
        self._lock = threading.RLock()
        # Set only when THIS process spawned the mint. A GUI restart loses
        # it and falls back to /proc, which is why status() never depends
        # on it being present.
        self._proc: subprocess.Popen | None = None
        # (monotonic time, port, mint_id, answered) of the last probe
        self._probe_at: tuple[float, object, object, bool] | None = None

    # -- persisted supervision state ------------------------------------

    def _read_state(self) -> dict:
        try:
            with open(self.state_path) as fh:
                blob = json.load(fh)
        except (OSError, ValueError):
            return {}
        return blob if isinstance(blob, dict) else {}

    def _write_state(self, blob: dict) -> None:
        """Atomic replace: a half-written state file reads as no state, and
        no state means 'not running', which would strand a live mint."""
        tmp = "%s.%d.tmp" % (self.state_path, os.getpid())
        try:
            with open(tmp, "w") as fh:
                fh.write(json.dumps(blob, indent=2))
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.state_path)
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def _mark_not_running(self, state: dict, last_error: str | None) -> dict:
        """Clear the live-process fields, keep the last-known identity."""
        new = dict(state)
        new["pid"] = None
        new["proc_start_ticks"] = None
        new["started_at_ms"] = None
        new["last_error"] = last_error
        new["stopped_at_ms"] = _now_ms()
        try:
            self._write_state(new)
        except OSError:
            pass  # reporting the truth matters more than recording it
        return new

    # -- identity checks -------------------------------------------------

    def _reap(self, *, block_s: float = 0.0) -> None:
        """Reap our own child if it has exited.

        Two reasons this is not optional. A child nobody waits on stays a
        zombie, and a zombie still has a /proc/<pid>/stat — so an unreaped
        mint would keep looking alive to the check below. And a Popen whose
        process is still unwaited at garbage-collection time warns.

        Polls by default, so status() never blocks on a live mint. stop()
        passes a budget instead, because a non-blocking poll loses the race
        it is in: the wait below ends the moment /proc says the pid is a
        zombie, which is a hair earlier than waitpid() will hand the status
        over, and the last poll then reaps nothing. The child is already
        dead by then, so the wait returns at once.
        """
        proc = self._proc
        if proc is None:
            return
        if block_s > 0:
            try:
                proc.wait(timeout=block_s)
            except subprocess.TimeoutExpired:  # pragma: no cover - not ours
                pass
        else:
            proc.poll()

    def _process_matches(self, state: dict) -> tuple[bool, str | None]:
        """(is our mint alive, reason it is not)."""
        self._reap()
        pid = state.get("pid")
        if not isinstance(pid, int) or pid <= 0:
            return False, None
        proc = self._proc
        if proc is not None and proc.pid == pid and proc.returncode is not None:
            return False, ("the mint exited (status %s); see mint.log"
                           % proc.returncode)
        if not _HAVE_PROC:  # pragma: no cover - non-Linux fallback
            if not _pid_exists(pid):
                return False, "the mint is no longer running (pid %d is gone)." % pid
            # Without /proc the pid alone proves nothing, so the descriptor
            # has to carry the identity instead.
            if self._descriptor_confirms(state):
                return True, None
            return False, (
                "pid %d is alive but is not serving mint_id %r; treating the "
                "mint as stopped." % (pid, state.get("mint_id")))
        ticks = _proc_start_ticks(pid)
        if ticks is None:
            return False, "the mint is no longer running (pid %d is gone)." % pid
        if _proc_is_zombie(pid):
            return False, "the mint has exited (pid %d is a zombie)." % pid
        recorded = state.get("proc_start_ticks")
        if recorded is not None and str(recorded) != ticks:
            return False, (
                "pid %d is alive but it is a different program — the mint "
                "that had that pid is gone and the number was reused." % pid)
        if not _argv_serves_ledger(_proc_argv(pid), self.db_path):
            return False, (
                "pid %d is alive but it is not this workdir's mint — the "
                "number was reused by another program." % pid)
        return True, None

    def _adopt_orphan(self, state: dict) -> dict | None:
        """Re-attach to a mint serving this ledger that state has lost.

        mint-control.json can go missing — deleted with a stray rm, lost
        with the directory it was restored into, or never written because
        the GUI was killed between the spawn and the write. Without this,
        the mint that is still up and still holding the port and the
        ledger's single-writer lock reads as stopped, cannot be stopped
        through the GUI, and makes start() fail with a port-in-use message
        that blames some other program.

        Returns the repaired state, or None when no such process exists.

        Costs a /proc scan (~2ms here) and runs on every status() that has
        no live pid on record, which is the idle case. Cheap enough not to
        cache: a cache here would mean a mint that has just been adopted
        somewhere else, or has just appeared, is reported wrongly for the
        life of the cache, and honesty is this method's whole job.
        """
        found = _find_ledger_server(self.db_path)
        if found is None:
            return None
        pid, argv = found
        try:
            port = int(_argv_value(argv, "--port"))
        except (TypeError, ValueError):
            return None
        if not (0 < port < 65536):
            return None
        mint_id = _argv_value(argv, "--mint-id")
        new = dict(state)
        new.update({
            "pid": pid,
            "proc_start_ticks": _proc_start_ticks(pid),
            "port": port,
            "mint_id": mint_id if isinstance(mint_id, str) and mint_id
                       else state.get("mint_id"),
            "baseline_model_class": _argv_value(argv, "--model-class")
                                    or state.get("baseline_model_class"),
            "started_at_ms": _proc_start_ms(pid),
            "argv": argv,
            "adopted": True,
            "last_error": None,
        })
        try:
            self._write_state(new)
        except OSError:
            pass  # reporting the truth matters more than recording it
        self._probe_at = None
        return new

    def _descriptor(self, port: int, timeout: float = 2.0) -> dict | None:
        """GET /v3/mints on loopback, or None. http.client, not urllib:
        urllib honours http_proxy, and a proxy has no business standing
        between the GUI and 127.0.0.1."""
        if not isinstance(port, int) or not (0 < port < 65536):
            return None
        conn = None
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
            conn.request("GET", "/v3/mints")
            resp = conn.getresponse()
            body = resp.read()
            if resp.status != 200:
                return None
            blob = json.loads(body.decode("utf-8"))
            return blob if isinstance(blob, dict) else None
        except (OSError, ValueError, http.client.HTTPException):
            return None
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

    def _descriptor_confirms(self, state: dict) -> bool:
        return self._probe(state.get("port") or 0, state.get("mint_id"))

    #: How long a descriptor probe is reused for. A GET /v3/mints is not
    #: free — the mint signs a fresh supply snapshot for each one (§3.6) —
    #: and app.py may call status() several times while serving one page.
    #: One second is short enough that the panel still feels live.
    _probe_ttl_s = 1.0

    def _probe(self, port, mint_id) -> bool:
        """Is the mint we recorded answering on the port we recorded?"""
        now = time.monotonic()
        cached = self._probe_at
        if cached is not None:
            when, was_port, was_id, result = cached
            if was_port == port and was_id == mint_id and now - when < self._probe_ttl_s:
                return result
        d = self._descriptor(port or 0, timeout=2.0)
        result = bool(d) and d.get("mint_id") == mint_id
        self._probe_at = (now, port, mint_id, result)
        return result

    # -- public API ------------------------------------------------------

    def status(self) -> dict:
        """Current state of the mint in this workdir.

        Keys: running, pid, port, mint_id, base_url, started_at_ms,
        last_error — plus ``responding``, which is additive: True when the
        descriptor answered on this call.

        When ``running`` is False, ``pid`` and ``started_at_ms`` are None
        but ``port``/``mint_id``/``base_url`` keep the LAST KNOWN values
        (None if this workdir has never run a mint), so the UI can still
        show which mint this workdir holds and a wallet can still show a
        last-known balance while the mint is down. ``running`` is the only
        field that answers "is it up".
        """
        with self._lock:
            state = self._read_state()
            alive, reason = self._process_matches(state)
            if not alive and state.get("pid") is not None:
                # A stale pid is cleared as soon as it is detected, so the
                # next caller does not re-derive the same conclusion (and
                # so a recycled pid cannot later be "confirmed" by luck).
                state = self._mark_not_running(state, reason or state.get("last_error"))
            if not alive:
                # ... but "no live pid on record" is not the same as "no
                # mint": the record itself can be gone. Ask the ledger.
                adopted = self._adopt_orphan(state)
                if adopted is not None:
                    state, alive, reason = adopted, True, None
            port = _clean_port(state.get("port"))
            mint_id = state.get("mint_id")
            responding = False
            last_error = state.get("last_error")
            if alive:
                responding = self._probe(port, mint_id)
                if responding:
                    last_error = None
                elif not last_error:
                    last_error = (
                        "the mint process (pid %s) is running but is not "
                        "answering on port %s yet — it may be starting up or "
                        "shutting down." % (state.get("pid"), port))
            base_url = "http://127.0.0.1:%d" % port if port else None
            return {
                "running": bool(alive),
                "pid": state.get("pid") if alive else None,
                "port": port,
                "mint_id": mint_id if isinstance(mint_id, str) else None,
                "base_url": base_url,
                "started_at_ms": (state.get("started_at_ms")
                                  if alive and isinstance(
                                      state.get("started_at_ms"), int)
                                  and not isinstance(
                                      state.get("started_at_ms"), bool)
                                  else None),
                "last_error": last_error,
                "responding": responding,
            }

    def start(self, *, mint_id: str, baseline_model_class: str, port: int,
              rate_ppm: int, cap_mc: int, exempt_below_mc: int) -> dict:
        """Start the mint and wait until it actually answers. Returns status().

        Raises MintControlError — never a raw exit code, never a traceback —
        for every refusal an operator can act on.
        """
        with self._lock:
            current = self.status()
            if current["running"]:
                raise MintControlError(
                    "a mint is already running here (pid %s, port %s). Stop it "
                    "before starting another." % (current["pid"], current["port"]))
            try:
                return self._start(mint_id, baseline_model_class, port,
                                   rate_ppm, cap_mc, exempt_below_mc)
            except MintControlError as exc:
                # Remembered, not just raised: the GUI may be restarted (or
                # the operator may look at another tab) before they read it,
                # and "nothing is running and nobody says why" is the worst
                # thing this panel can show. Safe here because the check
                # above proved nothing is running in this workdir.
                self._mark_not_running(self._read_state(), str(exc))
                raise

    def _start(self, mint_id, baseline_model_class, port, rate_ppm, cap_mc,
               exempt_below_mc) -> dict:
        """The body of start(), split out only so that every way it can fail
        is recorded in one place. Called with the lock held, and only after
        start() has established that nothing is running here."""
        self._validate(mint_id, baseline_model_class, port, rate_ppm,
                       cap_mc, exempt_below_mc)
        self._preflight_keys(mint_id, baseline_model_class)
        self._preflight_port(port, mint_id)

        argv = [
            sys.executable, RUN_MINT,
            "--port", str(port),
            "--db", self.db_path,
            "--keys", self.keys_path,
            "--mint-id", mint_id,
            "--model-class", baseline_model_class,
            "--rate-ppm", str(rate_ppm),
            "--cap-mc", str(cap_mc),
            "--exempt-below-mc", str(exempt_below_mc),
            "--admin-token-file", self.admin_token_path,
            "--access-log", self.log_path,
            "--console-port", "0",   # the GUI is the console
            "--drain-seconds", str(self.child_drain_s),
        ]
        # Everything the child writes after this offset belongs to THIS
        # attempt, which is what makes a failure message quotable.
        offset = self._log_size()
        errlog = None
        try:
            # Append-only, unbuffered: the child inherits this fd, and the
            # launcher's own FileHandler appends to the same file. O_APPEND
            # writes interleave line-wise instead of overwriting.
            errlog = open(self.log_path, "ab", buffering=0)
            # start_new_session: the mint must survive a ctrl-c aimed at
            # the GUI, and must not be killed by the GUI's terminal.
            proc = subprocess.Popen(
                argv, cwd=self.workdir,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,   # see module docstring
                stderr=errlog,
                start_new_session=True,
                close_fds=True,
            )
        except OSError as exc:
            raise MintControlError(
                "could not run the mint launcher (%s): %s\nExpected it at "
                "%s." % (type(exc).__name__, exc, RUN_MINT)) from None
        finally:
            # The child has its own copy; holding one here would keep the
            # descriptor open for the life of the GUI.
            if errlog is not None:
                errlog.close()
        self._proc = proc
        ticks = _proc_start_ticks(proc.pid) if _HAVE_PROC else None
        started_at = _now_ms()
        self._write_state({
            "pid": proc.pid,
            "proc_start_ticks": ticks,
            "port": port,
            "mint_id": mint_id,
            "baseline_model_class": baseline_model_class,
            "started_at_ms": started_at,
            "argv": argv,
            "last_error": None,
        })
        self._await_descriptor(proc, mint_id, port, offset)
        # Record the digest of the credential run_mint.py just generated,
        # NOW rather than the first time someone views the log: the next
        # start rotates the file, and a credential whose digest was never
        # captured can never be redacted out of an append-only log again.
        self._remember_token(self.admin_token())
        self._probe_at = None  # it just answered; do not report a stale probe
        return self.status()

    def stop(self, *, drain_seconds: int = 10) -> dict:
        """SIGTERM the mint, wait, return status(). Doing nothing is fine.

        ``drain_seconds`` is how long THIS call waits for the process to
        disappear before escalating to SIGKILL. The child's own in-flight
        drain deadline was fixed at start time (``child_drain_s``, 10s by
        default): passing a smaller value here can therefore cut a drain
        short rather than shorten it.

        Raises MintControlError — never a bare ValueError — and validates
        before it signals anything: half-performing a kill and THEN
        refusing the argument that governs the wait would leave a dead
        mint and a state file still claiming it is up.
        """
        budget = self._drain_budget(drain_seconds)
        with self._lock:
            state = self._read_state()
            alive, reason = self._process_matches(state)
            if not alive:
                adopted = self._adopt_orphan(state)
                if adopted is not None:
                    state, alive, reason = adopted, True, None
            if not alive:
                if state.get("pid") is not None:
                    self._mark_not_running(state, reason)
                return self.status()
            pid = int(state["pid"])
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            except PermissionError:
                raise MintControlError(
                    "not allowed to stop pid %d — it belongs to another user. "
                    "Stop it from the account that started it." % pid) from None
            killed = self._wait_gone(pid, budget)
            note = None
            if not killed:
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
                if self._wait_gone(pid, self.kill_grace_s):
                    note = ("the mint did not shut down within %gs and was "
                            "killed; an in-flight request may have been cut "
                            "off (clients can safely retry)." % budget)
                else:
                    self._mark_not_running(
                        state,
                        "pid %d did not die even after SIGKILL; stop it by "
                        "hand before starting another mint here." % pid)
                    raise MintControlError(
                        "could not stop the mint: pid %d is still alive after "
                        "SIGTERM and SIGKILL." % pid)
            self._reap(block_s=self.kill_grace_s)
            self._proc = None
            self._probe_at = None
            self._mark_not_running(state, note)
            return self.status()

    @staticmethod
    def _drain_budget(drain_seconds) -> float:
        """Validate stop()'s wait budget BEFORE anything irreversible."""
        try:
            budget = float(drain_seconds)
        except (TypeError, ValueError):
            raise MintControlError(
                "drain_seconds must be a number of seconds to wait for the "
                "mint to shut down, got %r. Use 0 to kill it immediately."
                % (drain_seconds,)) from None
        if not math.isfinite(budget):
            raise MintControlError(
                "drain_seconds must be a finite number of seconds, got %r."
                % (drain_seconds,))
        if budget < 0:
            raise MintControlError(
                "drain_seconds cannot be negative, got %r. Use 0 to kill the "
                "mint immediately." % (drain_seconds,))
        return budget

    def logs(self, *, lines: int = 200) -> list[str]:
        """Last ``lines`` lines of mint.log, newest last. [] if there are none."""
        try:
            want = max(0, int(lines))
        except (TypeError, ValueError):
            want = 200
        if want == 0:
            return []
        try:
            size = os.path.getsize(self.log_path)
            with open(self.log_path, "rb") as fh:
                # Read a bounded tail rather than the whole file: this log
                # is appended to by every request the mint serves.
                back = min(size, max(8192, want * 400))
                fh.seek(size - back)
                blob = fh.read()
        except OSError:
            return []
        if back < size:
            blob = blob.partition(b"\n")[2]  # drop the partial first line
        text = self._redact(blob.decode("utf-8", "replace"))
        out = [ln for ln in text.splitlines() if ln.strip()]
        return out[-want:]

    def admin_token(self) -> str | None:
        """The generated /admin/issue credential, read from the 0600 key file.

        Server-side only: this value must never be put in an HTTP response,
        in a page, or in a log line. app.py uses it to call /admin/issue on
        the operator's behalf and returns only the resulting tokens.
        """
        try:
            with open(self.admin_token_path) as fh:
                blob = json.load(fh)
        except (OSError, ValueError):
            return None
        if not isinstance(blob, dict):
            return None
        token = blob.get("admin_token")
        return token if isinstance(token, str) and token else None

    # -- credential redaction --------------------------------------------
    #
    # Belt and braces: the credential is never printed to the child's
    # stderr and its stdout is discarded, so nothing should ever put one in
    # mint.log. "Should never" is not a reason to hand a secret to a
    # browser, and mint.log is append-only across restarts while
    # run_mint.py writes a FRESH credential on every start — so redacting
    # only the token currently in mint-admin-keys.json would cover the one
    # credential least likely to be in an old log line and miss every
    # rotated-out one.
    #
    # Remembering the old secrets in cleartext to redact them would be its
    # own leak, so only SHA-256 digests are kept. Every [A-Za-z0-9_-] run
    # in the log (the exact alphabet run_mint.py's urlsafe-base64
    # credential uses) is hashed and compared against them.

    def _known_digests(self) -> list[str]:
        try:
            with open(self.digests_path) as fh:
                blob = json.load(fh)
        except (OSError, ValueError):
            return []
        if not isinstance(blob, list):
            return []
        return [d for d in blob if isinstance(d, str)]

    def _remember_token(self, token: str | None) -> set[str]:
        """Record the digest of a credential; return every digest known."""
        known = self._known_digests()
        if token:
            digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
            if digest not in known:
                known = (known + [digest])[-_MAX_TOKEN_DIGESTS:]
                tmp = "%s.%d.tmp" % (self.digests_path, os.getpid())
                try:
                    with open(tmp, "w") as fh:
                        json.dump(known, fh)
                    os.replace(tmp, self.digests_path)
                except OSError:
                    try:
                        os.unlink(tmp)
                    except OSError:
                        pass
        return set(known)

    def _redact(self, text: str) -> str:
        """Strip every credential this workdir has ever held out of text."""
        known = self._remember_token(self.admin_token())
        if not known:
            return text
        return _TOKENISH.sub(
            lambda m: REDACTED
            if hashlib.sha256(m.group(0).encode("utf-8")).hexdigest() in known
            else m.group(0),
            text)

    # -- start() helpers -------------------------------------------------

    def _validate(self, mint_id, baseline_model_class, port, rate_ppm,
                  cap_mc, exempt_below_mc) -> None:
        if not isinstance(mint_id, str) or not MINT_ID_RE.fullmatch(mint_id):
            suggestion = ""
            if isinstance(mint_id, str) and mint_id:
                slug = re.sub(r"-+", "-", re.sub(r"[^a-z0-9-]", "-",
                                                 mint_id.lower())).strip("-")[:64]
                if slug and MINT_ID_RE.fullmatch(slug):
                    suggestion = " Try %r." % slug
            raise MintControlError(
                "%r is not a usable mint id. It must be 1-64 characters and may "
                "contain only lowercase letters a-z, digits 0-9 and hyphens — no "
                "spaces, no capitals, no dots.%s" % (mint_id, suggestion))
        if not isinstance(baseline_model_class, str) or not baseline_model_class.strip():
            raise MintControlError(
                "baseline_model_class cannot be empty: it is the definition of "
                "one millicredit for this mint, and §4.1 fixes it for the life "
                "of the mint id. Something like 'baseline-v1'.")
        if not isinstance(port, int) or isinstance(port, bool):
            raise MintControlError("port must be a whole number, got %r." % (port,))
        if port == 0:
            raise MintControlError(
                "port 0 would let the operating system pick any free port, and "
                "then nothing could tell the GUI where the mint went. Choose a "
                "fixed port, for example 8787.")
        if not (1 <= port <= 65535):
            raise MintControlError(
                "port %d is not a port number; it must be between 1 and 65535." % port)
        for name, value in (("rate_ppm", rate_ppm), ("cap_mc", cap_mc),
                            ("exempt_below_mc", exempt_below_mc)):
            if not isinstance(value, int) or isinstance(value, bool):
                raise MintControlError("%s must be a whole number, got %r."
                                       % (name, value))
        if not (0 <= rate_ppm <= MAX_RATE_PPM):
            raise MintControlError(
                "rate_ppm must be between 0 and %d (that is 1%%, the ceiling the "
                "spec puts on the burn rate in §7.3); got %d."
                % (MAX_RATE_PPM, rate_ppm))
        if cap_mc < 0:
            raise MintControlError(
                "cap_mc cannot be negative; got %d. Use 0 for no cap." % cap_mc)
        if exempt_below_mc < MIN_EXEMPT_BELOW_MC:
            raise MintControlError(
                "exempt_below_mc must be at least %d — §7.3 requires that small "
                "payments are never burned; got %d."
                % (MIN_EXEMPT_BELOW_MC, exempt_below_mc))

    def _preflight_keys(self, mint_id: str, baseline: str) -> None:
        """Refuse what run_mint.py would refuse, but in the GUI's own words.

        run_mint.py checks these itself (and would sys.exit with a good
        message that _await_descriptor would quote). Checking here too means
        the operator gets the answer without a process being spawned, a log
        line being written, or a token file being touched.
        """
        if not os.path.exists(self.keys_path):
            return
        try:
            with open(self.keys_path) as fh:
                blob = json.load(fh)
            if not isinstance(blob, dict):
                raise ValueError("not an object")
        except (OSError, ValueError) as exc:
            raise MintControlError(
                "cannot read this mint's key file %s (%s). That file holds the "
                "mint's signing key — do not delete it: every token ever issued "
                "by this mint is signed with it. Restore it from a backup, or "
                "point the GUI at a different workdir."
                % (self.keys_path, exc)) from None
        was_id = blob.get("mint_id")
        was_base = blob.get("baseline_model_class")
        if was_id is not None and was_id != mint_id:
            raise MintControlError(
                "this workdir already belongs to the mint %r, so it cannot be "
                "started as %r. Use the mint id %r, or start the other mint in "
                "a different workdir." % (was_id, mint_id, was_id))
        if was_base is not None and was_base != baseline:
            raise MintControlError(
                "refusing to start: %r has always used the baseline model class "
                "%r, and this would change it to %r.\nThe baseline is the "
                "definition of a millicredit (§4.1), so changing it silently "
                "reprices every credit this mint has already issued while every "
                "supply number stays the same. A different baseline is a "
                "different mint: pick a new mint id and a new workdir."
                % (mint_id, was_base, baseline))
        if was_base is None:
            raise MintControlError(
                "the key file %s predates baseline pinning, so nothing here can "
                "confirm that %r is the baseline this mint has been publishing. "
                "Pinning the wrong one would redefine the credit permanently and "
                "invisibly.\nCheck what earlier descriptors said, then record it "
                "once by hand:\n  python3 %s --keys %s --mint-id %s "
                "--model-class <the real one> --pin-baseline"
                % (self.keys_path, baseline, RUN_MINT, self.keys_path, mint_id))

    def _preflight_port(self, port: int, mint_id: str) -> None:
        """Say 'that port is taken' before a child says it in a log file.

        SO_REUSEADDR mirrors what http.server does, so a socket merely in
        TIME_WAIT does not read as a busy port; a live listener still does.
        This is advisory — something could grab the port in the moment
        between here and the child's own bind, which is why the child's
        bind failure is also handled, in _await_descriptor.

        A busy port is asked WHAT it is before the operator is told what to
        do about it. "Pick a different port" is the right advice only when
        the listener is unrelated; when it is a mint already serving this
        mint_id, moving to another port walks the operator into the ledger
        single-writer refusal instead, which is a worse error about a
        problem they were never told they had.
        """
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            probe.bind(("127.0.0.1", port))
        except OSError as exc:
            if exc.errno in (errno.EADDRINUSE, errno.EACCES, errno.EADDRNOTAVAIL):
                raise MintControlError(
                    "cannot use port %d: %s. %s"
                    % (port, exc.strerror,
                       self._busy_port_hint(port, mint_id, exc))) from None
            raise MintControlError(
                "cannot use port %d: %s." % (port, exc)) from None
        finally:
            probe.close()

    def _busy_port_hint(self, port: int, mint_id: str, exc: OSError) -> str:
        if exc.errno == errno.EACCES and port < 1024:
            return "You need administrator rights for ports below 1024."
        descriptor = self._descriptor(port, timeout=1.0)
        if descriptor is not None:
            serving = descriptor.get("mint_id")
            if serving == mint_id:
                return (
                    "That is not some other program — it is a mint already "
                    "serving %r on that port. Do NOT just pick a different "
                    "port: if it is this workdir's own mint (one the GUI lost "
                    "track of when mint-control.json was deleted or replaced) "
                    "a second one on the same ledger is refused anyway, one "
                    "database one mint; and if it is a mint elsewhere on this "
                    "machine, moving ports would leave two mints claiming the "
                    "same mint id. Find it with `ss -ltnp | grep %d` and stop "
                    "it, then start again." % (mint_id, port))
            return ("A different mint (%r) is already serving that port. Pick "
                    "a different port, or stop that mint." % (serving,))
        return ("Something else is already listening there. Pick a different "
                "port, or stop the other program (ss -ltnp | grep %d)." % port)

    def _log_size(self) -> int:
        try:
            return os.path.getsize(self.log_path)
        except OSError:
            return 0

    def _log_since(self, offset: int, limit: int = 4000) -> str:
        try:
            with open(self.log_path, "rb") as fh:
                fh.seek(offset)
                blob = fh.read(limit * 4)
        except OSError:
            return ""
        return self._redact(blob.decode("utf-8", "replace").strip())[-limit:]

    def _await_descriptor(self, proc, mint_id: str, port: int, offset: int) -> None:
        """Block until the mint serves its own descriptor, or fail loudly.

        Returning on spawn would make the GUI say 'running' while the port
        is still closed, and the operator's first action would fail for a
        reason the GUI just told them was impossible.
        """
        deadline = time.monotonic() + max(1.0, float(self.start_timeout_s))
        while True:
            rc = proc.poll()
            if rc is None:
                d = self._descriptor(port, timeout=1.0)
                if d is not None and d.get("mint_id") == mint_id:
                    return
                if d is not None:
                    # Someone else's mint is on this port. Ours must not be
                    # left running behind it, and must not be reported as up.
                    self._terminate(proc)
                    self._fail("port %d is already serving a different mint "
                               "(%r, not %r). Pick another port."
                               % (port, d.get("mint_id"), mint_id))
            else:
                self._proc = None
                self._fail(self._explain_exit(rc, self._log_since(offset)))
            if time.monotonic() >= deadline:
                self._terminate(proc)
                self._proc = None
                tail, _ = _strip_tracebacks(self._log_since(offset))
                self._fail(
                    "the mint did not answer on port %d within %gs, so it was "
                    "stopped again. Nothing was left running.%s"
                    % (port, self.start_timeout_s,
                       ("\nLast output:\n%s" % tail) if tail else ""))
            time.sleep(0.1)

    def _fail(self, message: str):
        state = self._read_state()
        self._mark_not_running(state, message)
        raise MintControlError(message)

    def _terminate(self, proc) -> None:
        try:
            proc.terminate()
        except OSError:
            pass
        try:
            proc.wait(timeout=max(1.0, self.child_drain_s))
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except OSError:
                pass
            try:
                proc.wait(timeout=self.kill_grace_s)
            except subprocess.TimeoutExpired:
                pass

    @staticmethod
    def _explain_exit(rc: int, tail: str) -> str:
        """Turn 'exit 1 plus some stderr' into one sentence and the evidence.

        run_mint.py's own refusals are already written for a human, so they
        are quoted rather than paraphrased; the lead sentence exists so the
        operator knows what to do before reading them.

        What run_mint.py does NOT write for a human is everything that is
        not a bind failure: the ledger single-writer refusal, a corrupt
        mint.db, a hand-edited key file. Those die with a full traceback on
        stderr, and app.py copies whatever is raised here verbatim into an
        HTTP error body and onto the page — which the contract forbids. So
        the tail is reduced to its exception lines first, and the frames,
        the source echoes and the absolute repo paths never leave.
        """
        tail, had_traceback = _strip_tracebacks(tail)
        lead = ("the mint crashed while it was starting up."
                if had_traceback else "the mint would not start.")
        if "baseline_model_class" in tail and "refusing to start" in tail:
            lead = ("the mint refused to start because its baseline model "
                    "class would change. That is fixed for the life of a mint "
                    "id, so this needs a new mint id and a new workdir.")
        elif "no pinned baseline_model_class" in tail:
            lead = ("this mint's key file predates baseline pinning, so the "
                    "baseline has to be recorded by hand once.")
        elif "belongs to mint_id" in tail:
            lead = "the key file in this workdir belongs to a different mint."
        elif "cannot bind port" in tail:
            lead = ("the port is already taken — something else grabbed it "
                    "just now. Pick another port and try again.")
        elif "already serves this ledger" in tail:
            lead = ("another mint process is already using this workdir's "
                    "database. Stop it first: one database, one mint.")
        elif "error:" in tail and "usage:" in tail:
            lead = "the mint rejected one of these settings."
        elif rc < 0:
            lead = ("the mint was killed by signal %d before it finished "
                    "starting." % -rc)
        if tail:
            detail = "\n%s" % tail
        elif had_traceback:
            detail = ("\nIts error message did not survive the end of the log "
                      "(exit status %s); the full text is in mint.log." % rc)
        else:
            detail = "\nNothing was written to mint.log (exit status %s)." % rc
        return lead + detail

    def _wait_gone(self, pid: int, budget: float) -> bool:
        end = time.monotonic() + max(0.0, budget)
        while True:
            self._reap()
            proc = self._proc
            if proc is not None and proc.pid == pid and proc.returncode is not None:
                return True
            if _HAVE_PROC:
                if _proc_start_ticks(pid) is None or _proc_is_zombie(pid):
                    return True
            elif not _pid_exists(pid):  # pragma: no cover - non-Linux
                return True
            if time.monotonic() >= end:
                return False
            time.sleep(0.05)
