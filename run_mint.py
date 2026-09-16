#!/usr/bin/env python3
"""Start an aicash mint. Nothing here is protocol - it is only a launcher.

  python3 run_mint.py [--port N] [--db PATH] [--keys PATH] [--mint-id ID]

Keys are generated on first run and reused after, so the mint keeps its
identity across restarts; a fresh keypair would invalidate every token
already issued against the old one. The descriptor is printed at startup so
a client has everything it needs to talk to this mint.

Defaults are for a local functional test: loopback only, plain HTTP. TLS is
deployment, not code (LOCKED-DESIGN-DECISIONS L17), so do not expose this
port beyond localhost without a reverse proxy terminating TLS in front.

Three things here exist for supervised runs rather than laptops:

  * SIGTERM is handled like ctrl-c, and the shutdown path then JOINS the
    in-flight request handlers itself (mintapi runs them as daemon threads
    that nothing else joins - see drain_handlers), so a process manager's
    stop does not truncate a response mid-write.
  * The generated operator credential goes to a 0600 file instead of stdout,
    because under a supervisor stdout is a shipped log stream. It is written
    only AFTER the port is bound: a launcher that dies during startup must
    not have already overwritten the credential of the mint that is actually
    running.
  * Retention pruning (§8(b)) runs on a timer, and the published
    ``prunes_spent_records`` claim is PINNED into the key file the way
    mint_id and baseline_model_class are, so it cannot flip back to false on
    a database whose history has already been deleted.
"""
import argparse, base64, binascii, json, logging, math, os, signal, sys
import threading, time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "impl"))

from aicash.burncalc import BurnPolicy
from aicash.mintapi import MintConfig, make_mint
from aicash.signing import generate_keypair, pubkey_b64u

# Anything nonzero below this is rejected rather than accepted silently:
# prune() takes BEGIN IMMEDIATE, so each pass blocks every writer for the
# length of its DELETE. A sub-second "interval" is not a retention policy,
# it is a self-inflicted lock storm.
MIN_PRUNE_HOURS = 0.01  # 36 seconds


def write_secret(path, text):
    """Replace ``path`` with ``text``, atomically and 0600-only.

    ``json.dump(blob, open(path, "w"))`` truncates the target before a single
    byte of the new content is written. A crash, a full disk or a SIGKILL in
    that window leaves a zero-length key file — and the Ed25519 private key it
    held is the mint's identity, so losing it invalidates every token ever
    issued against that mint_id (§4.1: the mint_id is the key). Write a fresh
    temp file in the SAME directory (os.replace is only atomic within a
    filesystem), fsync it so the bytes are on disk before the rename, then
    rename over the target: any crash leaves either the whole old file or the
    whole new one.

    The temp file is created with os.open(O_CREAT|O_EXCL, 0o600) rather than
    open()-then-chmod, because chmod-afterwards leaves a window in which the
    private key is readable at whatever the umask allows.
    """
    path = os.path.abspath(path)
    directory = os.path.dirname(path)
    # O_EXCL means a name collision is an error, not a silent overwrite, so the
    # suffix is random rather than just the pid (two runs, same pid, chroots).
    tmp = os.path.join(
        directory,
        ".%s.%d.%s.tmp" % (os.path.basename(path), os.getpid(),
                           binascii.hexlify(os.urandom(6)).decode()))
    # os.open is INSIDE the try: if os.fdopen() itself raises (ENOMEM, a
    # descriptor limit), the fd is already allocated and nothing outside this
    # function will ever close it. `fd = None` inside the with-body marks the
    # point where fdopen has taken ownership, so cleanup never double-closes.
    fd = None
    created = False
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
        with os.fdopen(fd, "w") as f:  # fdopen takes ownership of fd
            fd = None
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if created:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        raise
    # The rename itself is metadata: fsync the directory so the replacement
    # survives a power cut, not just a process crash. Not every platform or
    # filesystem allows this, and a failure here does not lose data.
    try:
        dir_fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(dir_fd)
    except OSError:
        pass
    finally:
        os.close(dir_fd)


def write_secret_json(path, blob):
    """Atomic, 0600 JSON write. json.dumps first: a serialisation error must
    fail before the temp file exists, not halfway through writing it."""
    write_secret(path, json.dumps(blob))


def prune_forever(ledger, interval_s, stop):
    """§8(b) retention, applied on a timer instead of never.

    Ledger.prune() deletes spent entries and idempotency records older than
    the published recovery_window_ms; unspent and locked state is never
    touched. Nothing else in the build calls it, so without this thread the
    idempotency table grows for the whole retention window and any caller who
    can reach /v3/exchange — no credential required — can grow it.

    Low frequency on purpose: prune() takes BEGIN IMMEDIATE, so it blocks
    writers for the length of the DELETE. Hours, not seconds. A failure here
    must never take the mint down, so exceptions are logged and retried on the
    next tick.

    The wait comes FIRST, deliberately. prune() is irreversible — a spent
    entry and its claim_witness are gone (§8) — so the first run of this
    launcher against a mint.db that has never been pruned must not delete a
    decade of history in the second before the operator reads the startup
    banner. One full interval is the window in which `--prune-interval-hours
    0` and a restart still saves everything.
    """
    log = logging.getLogger("aicash.prune")
    while not stop.wait(interval_s):
        try:
            deleted = ledger.prune()
            # prune() returns the ledger-entry count only; the idempotency
            # rows it drops on the same schedule are not counted by C04.
            log.info("prune: deleted %d spent ledger entries (plus expired "
                     "idempotency records) older than the retention window",
                     deleted)
        except Exception:
            log.exception("prune failed; retrying at the next interval")


def handler_port(thread):
    """Port the connection a handler thread is serving was accepted on, or None.

    socketserver passes the accepted socket to ``process_request_thread`` as
    its first positional argument, and Thread keeps the args it was built
    with. That is the only handle from out here on whether a given handler
    belongs to the MINT or to the operator console — and the difference
    matters: mint_console's handler class sets no ``timeout``, so a browser
    sitting on the console page parks an idle keep-alive handler forever, and
    draining that one would add the full deadline to every ctrl-c.

    None means "could not tell" (a different CPython, a thread that is not a
    socketserver handler at all). Callers treat that as drainable: waiting on
    a thread that did not need it costs a shutdown pause, while skipping one
    that did truncates a response.
    """
    try:
        return thread._args[0].getsockname()[1]
    except Exception:
        return None


def drain_handlers(mint_port, deadline_s):
    """Join the request handlers that nothing else in the stack will join.

    impl/aicash/mintapi.py sets ``daemon_threads = True`` on its
    ThreadingHTTPServer. CPython's ``socketserver._Threads.append()`` returns
    early for daemon threads, so the server tracks none of them:
    ``server_close()`` joins nothing and ``MintServer.stop()`` joins only the
    accept thread. Without this, the process exits roughly a second after
    SIGTERM with handlers still inside a response, and `docker stop` truncates
    an exchange mid-write. Clients recover (§3.3 idempotency replays the
    request), but "SIGTERM must not kill in-flight handlers" is the whole
    reason this launcher traps the signal, and it cannot fix daemon_threads
    from here — mintapi is not this file's to change — so it joins them here.

    Candidates are found by name: everything this launcher starts is named
    ``aicash-*``, and socketserver's handler threads keep the default
    ``Thread-N (process_request_thread)``. Anything else alive after the
    listening socket is closed is a request in flight — on the mint's port
    (see handler_port).

    Returns the number of handlers still running when the deadline expired
    (0 means the drain completed).
    """
    end = time.monotonic() + deadline_s
    while True:
        alive = []
        for t in threading.enumerate():
            if (t is threading.main_thread() or not t.is_alive()
                    or t.name.startswith("aicash-")):
                continue
            port = handler_port(t)
            if port is None or port == mint_port:
                alive.append(t)
        if not alive:
            return 0
        remaining = end - time.monotonic()
        if remaining <= 0:
            return len(alive)
        # Short joins in a loop rather than one long join: handlers finish in
        # any order, and the deadline covers the whole drain, not each thread.
        alive[0].join(timeout=min(remaining, 0.2))


def load_or_create_keys(path, mint_id, baseline, pin=False):
    """Return (private, public, pins), generating and persisting keys once.

    ``pins`` is the key file's record of the values this mint has already
    committed to. mint_id and baseline_model_class are pinned because §4.1
    makes the baseline immutable for the life of a mint_id: it is the
    definition of the unit, so changing it reprices every outstanding credit
    while the §3.6 supply counters, being denominated in mc, stay unchanged
    and the invariant still holds. Nothing in the ledger can detect that, so
    the launcher refuses it. ``prunes_spent_records`` is pinned for the same
    class of reason (see pin_retention).
    """
    if os.path.exists(path):
        with open(path) as f:
            blob = json.load(f)
        was_id = blob.get("mint_id")
        was_base = blob.get("baseline_model_class")
        if was_id is not None and was_id != mint_id:
            sys.exit(f"this key file belongs to mint_id {was_id!r}, not {mint_id!r}.\n"
                     f"Use --keys for a different file, or --mint-id {was_id}.")
        if was_base is not None and was_base != baseline:
            sys.exit(
                f"refusing to start: baseline_model_class for mint_id {mint_id!r} "
                f"was {was_base!r} and is now {baseline!r}.\n"
                f"§4.1 makes the baseline immutable for the life of a mint_id — it "
                f"is the definition of the millicredit, so changing it silently "
                f"reprices every credit already issued while every supply counter "
                f"stays put.\nA different baseline is a different mint: pass a new "
                f"--mint-id with a new --keys and --db.")
        if was_base is None:
            # The file predates identity pinning, so nothing here can confirm
            # what the baseline WAS. Writing whatever was passed would pin the
            # attacker's value on the first run and call it the original —
            # which is exactly what this check exists to prevent. Make a human
            # assert it instead.
            if not pin:
                sys.exit(
                    f"{path} has no pinned baseline_model_class, so this cannot "
                    f"verify that {baseline!r} is the one this mint has been using.\n"
                    f"If it is, re-run with --pin-baseline to record it. If you are "
                    f"not certain, check what earlier descriptors published first: "
                    f"pinning the wrong value makes a redefinition permanent and "
                    f"invisible.")
            blob.update(mint_id=mint_id, baseline_model_class=baseline)
            write_secret_json(path, blob)
            print(f"pinned baseline_model_class={baseline!r} for mint_id={mint_id!r}")
        elif was_id is None:
            blob["mint_id"] = mint_id
            write_secret_json(path, blob)
        return (base64.b64decode(blob["private"]),
                base64.b64decode(blob["public"]),
                blob)
    private, public = generate_keypair()
    # 0600 from creation, never open()-then-chmod: the signing key IS the
    # mint's identity, so a readable window is a permanent compromise.
    blob = {"private": base64.b64encode(private).decode(),
            "public": base64.b64encode(public).decode(),
            "mint_id": mint_id,
            "baseline_model_class": baseline}
    write_secret_json(path, blob)
    print(f"generated a new mint keypair -> {path}")
    return private, public, blob


def pin_retention(path):
    """Record that this mint_id has started deleting spent records.

    §8(b) makes ``retention.prunes_spent_records`` a published claim, and §11
    step 4 has a counterparty read it off the descriptor before quoting a
    swap. Deriving it from a per-process flag alone makes it retractable: run
    once with pruning on, restart with --prune-interval-hours 0, and the mint
    publishes "I keep spent records" about a database from which they have
    already been deleted. That is a false published claim, and the deletion
    cannot be undone.

    So the claim is pinned next to mint_id and baseline_model_class — the two
    other values this file already refuses to let change silently — and from
    then on it is published as true whatever the flag says. True on a mint
    that has stopped pruning only over-warns a counterparty; false on a mint
    that has pruned misleads one.
    """
    with open(path) as f:
        blob = json.load(f)
    if blob.get("prunes_spent_records"):
        return
    blob["prunes_spent_records"] = True
    write_secret_json(path, blob)


def prune_interval_hours(text):
    """argparse type for --prune-interval-hours: 0, or at least MIN_PRUNE_HOURS.

    Two inputs used to disable a §8(b) obligation silently: a negative value
    (clamped to 0 by max()) and NaN (which survives max() and fails `> 0`).
    Both now fail loudly, as does a sub-second interval — see MIN_PRUNE_HOURS.
    """
    try:
        value = float(text)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError(f"{text!r} is not a number")
    if math.isnan(value) or math.isinf(value):
        raise argparse.ArgumentTypeError(
            f"{text!r} is not a usable interval; pass 0 to disable pruning")
    if value < 0:
        raise argparse.ArgumentTypeError(
            f"{value!r} is negative; pass 0 to disable pruning, and note that "
            f"disabling it does not retract a prunes_spent_records claim this "
            f"mint has already published")
    if 0 < value < MIN_PRUNE_HOURS:
        raise argparse.ArgumentTypeError(
            f"{value!r}h is below the {MIN_PRUNE_HOURS}h minimum: prune() takes "
            f"BEGIN IMMEDIATE and blocks every writer for the length of its "
            f"DELETE, so this would be a lock storm, not a retention policy")
    return value


def main():
    ap = argparse.ArgumentParser(description="Run an aicash mint.")
    ap.add_argument("--port", type=int, default=8787,
                    help="0 picks an ephemeral port")
    ap.add_argument("--db", default="mint.db")
    ap.add_argument("--keys", default="mint-keys.json")
    ap.add_argument("--mint-id", default="local-test-mint")
    ap.add_argument("--console-port", type=int, default=8080,
                    help="operator console in a browser; 0 disables it")
    ap.add_argument("--access-log", default="mint-access.log",
                    help="request log: method, route pattern and status. The "
                         "mint already emits these at INFO and nothing was "
                         "listening. Never contains token secrets.")
    ap.add_argument("--model-class", default="baseline-v1")
    ap.add_argument("--rate-ppm", type=int, default=0,
                    help="burn rate in parts per million (default 0: no burn)")
    ap.add_argument("--cap-mc", type=int, default=0)
    ap.add_argument("--exempt-below-mc", type=int, default=10)
    ap.add_argument("--pin-baseline", action="store_true",
                    help="record baseline_model_class into a key file that "
                         "predates identity pinning. Assert it, do not guess.")
    ap.add_argument("--admin-token",
                    help="operator credential for POST /admin/issue. Generated "
                         "if omitted. A token you supply is used as given and "
                         "is NEVER written to disk — it is already wherever you "
                         "keep it.")
    # The default basename ends in -keys.json on purpose: the repo .gitignore
    # ignores *-keys.json (for the signing key), and a live minting credential
    # sitting untracked in the working directory is one `git add -A` away from
    # being committed. Keep the name matching that pattern if you change it.
    ap.add_argument("--admin-token-file", default="mint-admin-keys.json",
                    help="0600 JSON file the GENERATED credential is written "
                         "to (field \"admin_token\"), so it stays out of "
                         "stdout. Empty string disables the file, which then "
                         "requires --admin-token or --show-admin-token.")
    ap.add_argument("--show-admin-token", action="store_true",
                    help="also print the live credential to stdout. Off by "
                         "default: under a process manager stdout is a log.")
    ap.add_argument("--prune-interval-hours", type=prune_interval_hours,
                    default=6.0,
                    help="how often to apply the §8(b) retention window "
                         "(delete spent entries and idempotency records older "
                         "than recovery_window_ms). The first pass runs one "
                         "full interval after startup, not immediately. 0 "
                         "disables pruning, but does NOT retract a "
                         "prunes_spent_records claim already pinned for this "
                         "mint_id.")
    ap.add_argument("--drain-seconds", type=float, default=10.0,
                    help="on ctrl-c/SIGTERM, how long to wait for in-flight "
                         "request handlers to finish before exiting anyway.")
    ap.add_argument("--open-issuance", action="store_true",
                    help="DANGEROUS: leave /admin/issue unauthenticated, which "
                         "lets anyone who can reach the port mint without limit. "
                         "MintConfig.admin_token=None means 'allow everyone', "
                         "not 'allow no one'.")
    args = ap.parse_args()

    if args.open_issuance and args.admin_token:
        ap.error("--admin-token with --open-issuance is contradictory: "
                 "--open-issuance makes /admin/issue accept everyone, so the "
                 "token would be silently ignored. Pick one.")
    if (not args.open_issuance and not args.admin_token
            and not args.admin_token_file and not args.show_admin_token):
        # Otherwise the mint would run its whole life with a random credential
        # that was never written anywhere and never printed — unusable, and
        # unrecoverable: re-running generates a DIFFERENT one.
        ap.error("--admin-token-file '' leaves nowhere to put the generated "
                 "credential. Pass --admin-token to supply your own, or "
                 "--show-admin-token to print it, or keep the token file.")

    if args.access_log:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(message)s",
            handlers=[logging.FileHandler(args.access_log),
                      logging.StreamHandler(sys.stdout)],
        )

    private, public, pins = load_or_create_keys(
        args.keys, args.mint_id, args.model_class, args.pin_baseline)
    generated_token = None
    if args.open_issuance:
        admin_token = None
        print("WARNING: /admin/issue is unauthenticated. Anyone who can reach "
              f"port {args.port} can mint without limit.", file=sys.stderr)
    elif args.admin_token:
        admin_token = args.admin_token
    else:
        # The credential used to be printed in the startup JSON. On a laptop
        # that is convenient; under a process manager stdout is a log stream
        # that gets shipped, indexed and retained, which puts a live minting
        # credential in a system nobody is treating as a secret store. Keep it
        # discoverable — same atomic 0600 write as the signing key, so it is
        # one read away — but out of the log unless explicitly asked for.
        admin_token = base64.urlsafe_b64encode(os.urandom(24)).decode().rstrip("=")
        generated_token = admin_token

    prune_interval_s = args.prune_interval_hours * 3600.0
    pinned_prunes = bool(pins.get("prunes_spent_records"))
    # Publish true if this mint has EVER pruned, whatever this run's flag says.
    publishes_prunes = pinned_prunes or prune_interval_s > 0
    if pinned_prunes and prune_interval_s <= 0:
        print("NOTE: pruning is disabled this run, but the descriptor still "
              "says prunes_spent_records: true — this mint_id has pruned "
              "before and those records (and their claim_witness) are gone. "
              "§8(b) claims are about the database, not about this process.",
              file=sys.stderr)
    config = MintConfig(
        mint_id=args.mint_id,
        baseline_model_class=args.model_class,
        burn_policy=BurnPolicy(rate_ppm=args.rate_ppm, cap_mc=args.cap_mc,
                               exempt_below_mc=args.exempt_below_mc),
        signing_private=private,
        signing_public=public,
        admin_token=admin_token,
        # §8(b) requires the mint to publish its retention policy truthfully.
        # If the prune thread is running — or ever has run for this mint_id —
        # this mint really does drop spent records, so the descriptor has to
        # say so; a client sizing a §11 swap margin reads this field. (True is
        # only legal with a finite max_lock_expiry_ms, which MintConfig
        # defaults to and this launcher never overrides — C06 raises if that
        # ever stops being true.)
        prunes_spent_records=publishes_prunes,
    )
    server, ledger = make_mint(config, args.db)
    try:
        port = server.start(args.port)
    except OSError as exc:
        # A stale mint on this port is worse than no mint: clients connect,
        # everything "works", and the results come from a database you are
        # not looking at. Fail loudly rather than let that happen.
        sys.exit(f"cannot bind port {args.port}: {exc}\n"
                 f"another mint is probably already running. Check with:\n"
                 f"  ss -ltnp | grep {args.port}\n"
                 f"then stop it, or pass a different --port.")

    # Everything that touches durable state on disk happens AFTER the bind.
    # A start that fails — and "another mint is already running" is the most
    # likely way for it to fail — must not have overwritten the token file
    # that holds the RUNNING mint's only copy of its /admin/issue credential,
    # nor pinned a retention claim for a mint that never came up.
    token_path = None
    try:
        if args.open_issuance and args.admin_token_file:
            # A stale token file next to an unauthenticated mint tells whoever
            # reads it that /admin/issue is protected. It is not.
            try:
                os.unlink(args.admin_token_file)
                print(f"removed stale {os.path.abspath(args.admin_token_file)}: "
                      f"issuance is open, that credential means nothing now.",
                      file=sys.stderr)
            except FileNotFoundError:
                pass
        elif generated_token is not None and args.admin_token_file:
            write_secret_json(args.admin_token_file,
                              {"mint_id": args.mint_id,
                               "admin_token": generated_token})
            token_path = os.path.abspath(args.admin_token_file)
        if publishes_prunes and not pinned_prunes:
            pin_retention(args.keys)
    except OSError as exc:
        # Nothing else knows the generated credential, so a mint that is up but
        # unusable is worse than no mint: stop cleanly and say why.
        server.stop()
        sys.exit(f"started, then failed to persist startup state: {exc}")

    base = f"http://127.0.0.1:{port}"
    print(json.dumps({
        "mint_id": args.mint_id,
        "url": base,
        "descriptor": f"{base}/v3/mints",
        "pubkey": pubkey_b64u(public),
        "db": os.path.abspath(args.db),
        "burn_policy": {"rate_ppm": args.rate_ppm, "cap_mc": args.cap_mc,
                        "exempt_below_mc": args.exempt_below_mc},
        "admin_token": (
            "(NONE - issuance is open to anyone)" if admin_token is None
            else admin_token if args.show_admin_token
            else "(as supplied on the command line; not written to disk)"
            if generated_token is None
            else f'(written to {token_path}, JSON field "admin_token")'),
        "access_log": os.path.abspath(args.access_log) if args.access_log else None,
    }, indent=2))
    console = None
    if args.console_port:
        import mint_console
        console = mint_console.serve(args.console_port, port, args.mint_id, admin_token)
        threading.Thread(target=console.serve_forever, daemon=True,
                         name="aicash-console").start()
        # No URL is printed here on purpose. mint_console.serve() has just
        # printed the ONE address that works: it carries the capability key
        # the console generated a moment ago, and this process has no other
        # way to know that key. A bare http://127.0.0.1:<port> printed here
        # used to be the LAST line the operator saw, so it was the one they
        # clicked, and it answers 401. The keyed URL is also on the server
        # object as console.console_url if anything downstream needs it.

    stop = threading.Event()
    if prune_interval_s > 0:
        # Daemon: a prune in flight must never hold up shutdown, and the
        # DELETE is in a transaction that simply rolls back if the process
        # dies mid-way. The thread waits one interval before its first pass
        # and exits as soon as `stop` is set.
        threading.Thread(target=prune_forever,
                         args=(ledger, prune_interval_s, stop),
                         daemon=True, name="aicash-prune").start()
        first = time.strftime("%H:%M:%S", time.localtime(
            time.time() + prune_interval_s))
        print(f"\n  retention   pruning every {args.prune_interval_hours}h, "
              f"first pass at {first}"
              f"\n              deletes spent entries and their claim_witness "
              f"older than the recovery window — irreversible."
              f"\n              stop now and re-run with "
              f"--prune-interval-hours 0 to keep them"
              f"\n              (descriptor says prunes_spent_records: true)")

    def request_stop(signum, _frame):
        # Signal handlers run in the main thread between bytecodes, so do the
        # minimum here — flip the event and let the code below, which is not
        # running inside a handler, do the real shutdown.
        print(f"\nstopping on {signal.Signals(signum).name}...", flush=True)
        stop.set()
        # Then get out of the way. console.shutdown(), server.stop()'s 10s
        # join and the handler drain can all block, and while they do, a
        # handler that only re-sets an already-set Event makes ctrl-c a no-op
        # — before SIGTERM was trapped at all, a second ctrl-c raised
        # KeyboardInterrupt and aborted a wedged shutdown. Restoring the
        # default action keeps that escape: the next signal kills the process.
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, signal.SIG_DFL)
            except (OSError, ValueError, RuntimeError):
                pass

    # SIGTERM is how systemd, `docker stop` and kubelet ask a service to go
    # away; its default action terminates the process outright, so the
    # listening socket and the sqlite connections owned by handler threads
    # close only because the process died, and any response half-written goes
    # out truncated. Route SIGTERM through exactly the same shutdown path as
    # ctrl-c, which closes the socket and then drains the handlers.
    for _sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(_sig, request_stop)

    print(f"\nmint is up. ctrl-c or SIGTERM to stop."
          f"\n  descriptor  GET  {base}/v3/mints"
          f"\n  exchange    POST {base}/v3/exchange"
          f"\n  status      POST {base}/v3/status  (or GET /v3/status/<id>)"
          f"\n  issue       POST {base}/admin/issue  (operator credential)",
          flush=True)
    try:
        # Short timeout rather than a bare wait(): the loop then does not
        # depend on lock acquisition being signal-interruptible, on any
        # platform or Python build.
        while not stop.wait(1.0):
            pass
    except KeyboardInterrupt:
        # Only reachable if a handler failed to install (Windows, a
        # non-main-thread caller). Same path, so shutdown still happens.
        print("\nstopping...", flush=True)
        stop.set()
    if console:
        console.shutdown()
    server.stop()  # joins the HTTP serve thread, closes the listening socket
    stranded = drain_handlers(port, max(0.0, args.drain_seconds))
    if stranded:
        print(f"{stranded} request handler(s) still running after "
              f"{args.drain_seconds}s; exiting anyway. Their clients will see a "
              f"truncated response and can safely retry (§3.3 idempotency).",
              flush=True)
    print("stopped.", flush=True)


if __name__ == "__main__":
    main()
