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
"""
import argparse, base64, json, logging, os, sys, threading

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "impl"))

from aicash.burncalc import BurnPolicy
from aicash.mintapi import MintConfig, make_mint
from aicash.signing import generate_keypair, pubkey_b64u


def load_or_create_keys(path, mint_id, baseline, pin=False):
    """Return (private, public), generating and persisting them once.

    Also pins mint_id and baseline_model_class. §4.1 makes the baseline
    immutable for the life of a mint_id: it is the definition of the unit, so
    changing it reprices every outstanding credit while the §3.6 supply
    counters, being denominated in mc, stay unchanged and the invariant still
    holds. Nothing in the ledger can detect that, so the launcher refuses it.
    """
    if os.path.exists(path):
        blob = json.load(open(path))
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
            json.dump(blob, open(path, "w"))
            print(f"pinned baseline_model_class={baseline!r} for mint_id={mint_id!r}")
        elif was_id is None:
            blob["mint_id"] = mint_id
            json.dump(blob, open(path, "w"))
        return (base64.b64decode(blob["private"]), base64.b64decode(blob["public"]))
    private, public = generate_keypair()
    with open(path, "w") as f:
        json.dump({"private": base64.b64encode(private).decode(),
                   "public": base64.b64encode(public).decode(),
                   "mint_id": mint_id, "baseline_model_class": baseline}, f)
    os.chmod(path, 0o600)  # the signing key is the mint's identity
    print(f"generated a new mint keypair -> {path}")
    return private, public


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
                    help="operator credential for POST /admin/issue. "
                         "Generated and printed if omitted.")
    ap.add_argument("--open-issuance", action="store_true",
                    help="DANGEROUS: leave /admin/issue unauthenticated, which "
                         "lets anyone who can reach the port mint without limit. "
                         "MintConfig.admin_token=None means 'allow everyone', "
                         "not 'allow no one'.")
    args = ap.parse_args()

    if args.access_log:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(message)s",
            handlers=[logging.FileHandler(args.access_log),
                      logging.StreamHandler(sys.stdout)],
        )

    private, public = load_or_create_keys(args.keys, args.mint_id, args.model_class,
                                              args.pin_baseline)
    if args.open_issuance:
        admin_token = None
        print("WARNING: /admin/issue is unauthenticated. Anyone who can reach "
              f"port {args.port} can mint without limit.", file=sys.stderr)
    else:
        admin_token = args.admin_token or base64.urlsafe_b64encode(
            os.urandom(24)).decode().rstrip("=")
    config = MintConfig(
        mint_id=args.mint_id,
        baseline_model_class=args.model_class,
        burn_policy=BurnPolicy(rate_ppm=args.rate_ppm, cap_mc=args.cap_mc,
                               exempt_below_mc=args.exempt_below_mc),
        signing_private=private,
        signing_public=public,
        admin_token=admin_token,
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

    base = f"http://127.0.0.1:{port}"
    print(json.dumps({
        "mint_id": args.mint_id,
        "url": base,
        "descriptor": f"{base}/v3/mints",
        "pubkey": pubkey_b64u(public),
        "db": os.path.abspath(args.db),
        "burn_policy": {"rate_ppm": args.rate_ppm, "cap_mc": args.cap_mc,
                        "exempt_below_mc": args.exempt_below_mc},
        "admin_token": admin_token or "(NONE - issuance is open to anyone)",
        "access_log": os.path.abspath(args.access_log) if args.access_log else None,
    }, indent=2))
    console = None
    if args.console_port:
        import mint_console
        console = mint_console.serve(args.console_port, port, args.mint_id, admin_token)
        threading.Thread(target=console.serve_forever, daemon=True,
                         name="aicash-console").start()
        print(f"\n  CONSOLE     http://127.0.0.1:{args.console_port}   <- open this in a browser")

    print(f"\nmint is up. ctrl-c to stop."
          f"\n  descriptor  GET  {base}/v3/mints"
          f"\n  exchange    POST {base}/v3/exchange"
          f"\n  status      POST {base}/v3/status  (or GET /v3/status/<id>)"
          f"\n  issue       POST {base}/admin/issue  (operator credential)",
          flush=True)
    try:
        while True:
            __import__("time").sleep(3600)
    except KeyboardInterrupt:
        print("\nstopping...")
        if console:
            console.shutdown()
        server.stop()


if __name__ == "__main__":
    main()
