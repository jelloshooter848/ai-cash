# AICash

**Sub-cent, sub-second, account-free value exchange between AI agents for small units of cognitive work.**

That is the one thing AICash is for, and it is deliberately bad at everything else. No card network can price a 20-token completion between two agents that have never met; no bank rail settles in milliseconds without a pre-negotiated account; no chain settles without wallets, gas, and finality delay. AICash fills exactly that gap: a bearer token is a plain string an agent pastes into a tool-call response, and receiving it needs no registration, no identity, and no relationship with the payer.

- **Spec:** [`aicash-spec-v0.4.md`](aicash-spec-v0.4.md) — the ratified protocol. Start with §0 (thesis/scope) and §2 (the layer stack).
- **Design decisions that are settled:** [`LOCKED-DESIGN-DECISIONS.md`](LOCKED-DESIGN-DECISIONS.md).
- **Bootstrap/adoption/censorship strategy:** [`BOOTSTRAP.md`](BOOTSTRAP.md).
- **Reference implementation:** [`impl/`](impl/) — Python 3.12, stdlib + `cryptography` (Ed25519) only.
- **Per-module API reference:** the "Public API" block of each [`components/CNN-*.md`](components/).
- **Runnable examples:** [`examples/`](examples/) — one directory per usage journey, each runnable with `PYTHONPATH=impl python3 examples/<dir>/<script>.py`.

## Quickstart

Boot a mint, fund a treasury, pay a brand-new worker that never registered, and have it spend — the whole §0 loop:

```python
from aicash import (
    BurnPolicy, MintConfig, make_mint, generate_keypair, system_clock,
    Wallet, MintClient, new_secret, ledger_key, format_token,
)

# Boot a mint. make_mint builds the ledger FROM the config, so the descriptor
# and the ledger can never disagree about burn/retention policy.
priv, pub = generate_keypair()
config = MintConfig(
    mint_id="demo-mint",                          # must match [a-z0-9-]{1,64} (aicash.MINT_ID_RE)
    baseline_model_class="demo-model-v1",         # this mint's unit-of-account peg (§4.1)
    burn_policy=BurnPolicy(rate_ppm=1000, cap_mc=1000, exempt_below_mc=10),  # 0.1%, drip-exempt
    signing_private=priv, signing_public=pub,
    admin_token="operator-secret",                # gates the non-normative /admin/issue funding path
)
server, ledger = make_mint(config, db_path="/tmp/demo.db", clock=system_clock)
port = server.start()
client = MintClient(f"http://127.0.0.1:{port}")

# Operator funds a treasury (§7.1): issue an output we control, format it as a bearer token.
s = new_secret()
client.admin_issue([{"amount_mc": 10_000, "secret_hash": ledger_key(s)}], admin_token="operator-secret")
treasury_token = format_token("demo-mint", 10_000, s)

treasury = Wallet("treasury.db", client, "demo-mint")
treasury.receive(treasury_token)                  # 9990 mc (10 mc re-exchange burn)

# Pay a brand-new worker — no registration anywhere (§7.2 receive-first).
worker = Wallet.connect("worker.db", f"http://127.0.0.1:{port}")   # zero-config: fetches mint_id itself
for tok in treasury.pay(1_000):
    worker.receive(tok)                            # worker holds 999 mc (1 mc re-exchange burn), bearer and final

server.stop()
```

Run the complete, asserted version:

```bash
PYTHONPATH=impl python3 examples/quickstart.py
```

## What's in the box

| You want to… | Use | Journey / doc |
|---|---|---|
| Get paid with zero setup | `Wallet.connect`, `Wallet.receive` | §7.2, `examples/j1-first-token/` |
| Pay many workers in one call | `Wallet.pay_many` (one burn) | `examples/j2-microwork/` |
| Sell metered API calls | `Wallet.receive_batch`, the §9.5 envelope (`aicash.envelope`) | §9.2, `examples/j3-metered-api/` |
| Stream per-token payment | `ChannelPayer` / `ChannelPayee` | §9.1, `examples/j4-streaming/` |
| Run milestone escrow with an arbiter panel | `EscrowPayer` / `EscrowPayee` / `Arbiter` | §9.3/§9.6, `examples/j5-escrow/` |
| Supervise a fleet (caps, freeze, statements) | `SupervisionServer` | §6.1, `examples/j6-fleet/` |
| Move value across mints atomically | `SwapParty`, `compute_margin` | §11, `examples/j7-swap/` |
| Budget a payment before making it | `Wallet.quote` | — |

`from aicash import *`-able: everything an integrator needs — types, functions, **and the exception classes each call can raise** (`PaymentInvalid`, `InsufficientFunds`, `ExchangeRejected`, `ChannelInvalid`, `FundingInvalid`, `QuoteRefused`, …) — is re-exported from the package root (`aicash.__all__`, 61 names). You should not need to read implementation source to integrate — if you do, that's a bug in these docs; the component "Public API" blocks are the reference, and each documents the exceptions its methods raise.

## Two things that will bite you if unsaid

- **Burn is charged on the sum of selected coins, not the face amount** (§7.3). Paying 1 mc from a wallet holding only 100-mc coins still burns on the 100. Call `Wallet.quote(amount)` first to see `{burn_mc, change_mc, inputs_mc}`. Drip amounts ≤ `exempt_below_mc` are burn-free.
- **A bearer token is a password with no recovery** (L8). Lose the secret and the value is gone — no seed phrase, no operator override. Supervised fleets use custodial mode (`SupervisionServer`) for recoverability; unsupervised agents shard their secrets. Never log a token.

## Running the tests

```bash
cd impl && python3 -m unittest discover -s tests -t .
```

293 tests, covering every component and the adversarial cases (double-spend races, channel witness-leak attempts, cross-mint silent-claim attacks, freeze/pull interactions). The reference implementation is the seed of the conformance suite (see `BOOTSTRAP.md` §4).

## Status

Draft v0.4 (revision 2). The protocol is ratified through an eight-persona design review; the implementation clears a builder/critic gauntlet and a cold-start usability gauntlet. It is a reference, not a production deployment — see `BOOTSTRAP.md` for what standing up a real, censorship-resistant network actually requires (short version: independent operator plurality is the load-bearing prerequisite, not an afterthought).
