#!/usr/bin/env python3
"""A wallet against a running aicash mint.

  wallet_cli.py --store PATH balance
  wallet_cli.py --store PATH receive TOKEN [TOKEN ...]
  wallet_cli.py --store PATH pay AMOUNT_MC
  wallet_cli.py --store PATH quote AMOUNT_MC
  wallet_cli.py --store PATH recover

The store is this wallet's sqlite file and holds its secrets: whoever has
the file has the money. Two wallets are two --store paths.
"""
import argparse, json, os, sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "impl"))
from aicash.wallet import Wallet, MintRejected, PaymentInvalid, InsufficientFunds


def main():
    ap = argparse.ArgumentParser(description="aicash wallet")
    ap.add_argument("--store", required=True, help="wallet sqlite path")
    ap.add_argument("--mint", default="http://127.0.0.1:8787")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("balance")
    r = sub.add_parser("receive"); r.add_argument("tokens", nargs="+")
    p = sub.add_parser("pay"); p.add_argument("amount_mc", type=int)
    q = sub.add_parser("quote"); q.add_argument("amount_mc", type=int)
    sub.add_parser("recover")
    args = ap.parse_args()

    w = Wallet.connect(args.store, args.mint)
    try:
        if args.cmd == "balance":
            print(json.dumps({"balance_mc": w.balance()}, indent=2))
        elif args.cmd == "receive":
            got = w.receive_batch(args.tokens) if len(args.tokens) > 1 else \
                  {"accepted_mc": w.receive(args.tokens[0])}
            print(json.dumps({**got, "balance_mc": w.balance()}, indent=2))
        elif args.cmd == "quote":
            print(json.dumps(w.quote(args.amount_mc), indent=2))
        elif args.cmd == "pay":
            tokens = w.pay(args.amount_mc)
            print(json.dumps({"tokens": tokens, "balance_mc": w.balance()}, indent=2))
        elif args.cmd == "recover":
            print(json.dumps({**w.recover(), "balance_mc": w.balance()}, indent=2))
    except InsufficientFunds as e:
        print(json.dumps({"error": "insufficient_funds", "detail": str(e)}), file=sys.stderr); return 2
    except (MintRejected, PaymentInvalid) as e:
        print(json.dumps({"error": type(e).__name__, "detail": str(e)}), file=sys.stderr); return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
