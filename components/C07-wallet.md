# C07 — wallet

**Module:** `aicash/wallet.py` · **Tests:** `tests/test_c07_wallet.py` · **Spec:** §5.1, §5.3, §7.2 (receive-first), §9.5 (client side), §4.2 · **Locked:** L1, L8 · **Depends:** C01, C06 (as live mint)

## Purpose
The bearer client: durable local token store with the mandatory persist-before-send ordering, receive-and-re-exchange, ladder-aware coin selection, crash recovery.

## Public API
```python
class MintClient:      # thin HTTP client for C06 endpoints (also reused by C08–C11)
    exchange(idempotency_key, inputs, outputs) -> dict   # raises MintRejected (§3.8) / MintUnavailable
    status(hashes) -> (mint_time, results)               # raises MintRejected / MintUnavailable
    descriptor() -> dict                                 # raises MintUnavailable
    admin_issue(outputs, admin_token=None) -> dict       # POST /admin/issue (non-normative §7.1 funding);
                                                         # raises MintRejected / MintUnavailable (incl. 401);
                                                         # outputs are §3.3 wire dicts {amount_mc, secret|secret_hash, lock?};
                                                         # X-Admin-Token header sent when a token is given
    # fault-injection seam: EVERY request goes through
    # _transport(method, path, body, extra_headers=None) -> (status, raw_bytes)
    # — tests subclass it to record the wire, drop responses, or raise
    # before/after delivery (see B2/B3/B8/B9/B10). Existing 3-arg
    # subclasses keep working: extra_headers is only passed for admin_issue.
class Wallet:
    def __init__(self, store_path: str, client: MintClient, mint_id: str): ...
    connect(store_path, base_url) -> Wallet # classmethod; zero-config §7.2 entry point:
                                            # builds a MintClient, fetches the descriptor, binds its mint_id
    balance() -> int
    receive(token_str: str) -> int          # §5.1 on-receipt: re-exchange for fresh secret(s); returns amount
                                            # raises PaymentInvalid (bad_format / spent / unknown) | MintUnavailable
    receive_batch(tokens: list[str]) -> dict  # §9.2 batch-redeem: N tokens, ONE exchange, ONE burn;
                                            # -> {"credited_mc": int, "dead": [{index, reason}]}; enumerated-bad
                                            # tokens dropped and retried without them under a FRESH idempotency key
                                            # raises PaymentInvalid | MintUnavailable | ValueError (tokens not a list)
    pay(amount_mc: int) -> list[str]        # returns token strings to hand over; change returns to store
                                            # raises InsufficientFunds | MintRejected | MintUnavailable | ValueError
    pay_many(amounts: list[int]) -> list[list[str]]  # multi-recipient fan-out: ONE exchange, ONE burn;
                                            # one token list per recipient; ValueError (chunk!) if inputs+outputs
                                            # would exceed the descriptor's limits.max_batch
                                            # raises InsufficientFunds | MintRejected | MintUnavailable | ValueError
    quote(amount_mc) -> dict                # read-only dry-run of pay's selection:
                                            # {"burn_mc", "change_mc", "inputs_mc"}; effective policy incl. burn_policy_next
                                            # raises InsufficientFunds | MintUnavailable | ValueError
    recover() -> dict                       # batch-status every non-final secret; reconcile store
                                            # raises MintUnavailable
    handle_refused(tokens: list[str])       # §9.5: re-exchange refused tokens to retire payee copies
                                            # raises PaymentInvalid | MintRejected | MintUnavailable
```

## Exceptions
All raised types are re-exported at the package root (`from aicash import PaymentInvalid, ...`).

- **`PaymentInvalid`** — a received/refused token failed validation or the mint rejected it (§3.8: `spent`, `unknown`, `bad_format`, …). Raised by `receive`, `receive_batch`, and `handle_refused`. Carries `.errors` (the list of `{index, kind, reason}` objects, as the mint enumerated them or as synthesized for a locally-detected `bad_format` / foreign-mint token) and `.reasons` (the `reason` value pulled from each error dict, in order). Messages never embed a token string or secret.
- **`InsufficientFunds`** — held balance cannot cover `amount + burn`. Raised by `pay`, `pay_many`, and the read-only `quote`. No structured attributes; the message states the mc needed vs. selectable.
- **`MintRejected`** — `/v3/exchange` (or `/v3/status`, `/admin/issue`) returned a §3.8 rejection. Carries `.errors`, the list of `{index, kind, reason}` objects. Propagates out of `pay` / `pay_many` unchanged; inside `receive` / `receive_batch` / `handle_refused` it is caught and re-surfaced as `PaymentInvalid` (or drives the enumerated-bad drop-and-retry). §3.8 rejections are definitive — never retried.
- **`MintUnavailable`** — transport-level failure (connection refused, timeout, non-JSON / unexpected response). The operation may or may not have reached the mint; resolve with `recover()`. Any wallet method that touches the wire (including `connect`, `receive`, `pay`, `quote`, `recover`, …) can raise it after `MAX_ATTEMPTS` (3) idempotent retries of a transient send.

`ValueError` guards plainly-invalid arguments (non-positive `amount_mc`, a non-list `tokens`/`amounts`, or a `pay_many` fan-out that would exceed `limits.max_batch`) — raised BEFORE anything is persisted or sent.

## Requirements
1. **Persist-before-send (§5.1, mandatory):** every locally generated output secret is written and fsync'd to the sqlite store with state `pending` BEFORE any `exchange` call that references it. Enforce structurally: the only code path to `exchange` goes through a method that asserts persistence happened.
2. **States:** `pending → confirmed | orphan`; `held → spent_out`. `recover()` resolves pending via batch status: ledger-known → confirmed; unknown after its exchange definitively failed → orphan (input tokens restored per the stored plan).
3. **Coin selection:** ladder-preferring greedy over held tokens; the burn is charged to the payer: `pay(X)` selects inputs totaling `X + burn + change`, produces payment outputs summing X (in ladder denominations where possible) plus change outputs; computes burn from the descriptor's policy.
4. **receive():** immediately re-exchanges into fresh self-generated secrets (splitting to ladder denominations); a spent/unknown received token raises `PaymentInvalid` with the §3.8 reasons; the received token string is never stored as held value (only its replacement).
5. Receive-first onboarding (§7.2): a fresh wallet with zero balance can `receive()` — no registration call exists anywhere in this component.
6. Store is sqlite at `store_path`; no secret ever logged; store survives process kill at any point (see B3).
7. Idempotency keys are generated per logical operation and REUSED on retry of that operation (so a timeout retry replays). Exception: when `receive_batch` retries after an ENUMERATED rejection, the request body has changed (the bad inputs were dropped), so the retry MUST use a fresh idempotency key — replaying the old key would be a §3.3 `idempotency_conflict`.
8. **Burn is a function of sum(inputs), never of the face amount (§7.3):** `pay(X)` / `pay_many(amounts)` charge `compute_burn(sum(selected inputs))` — overshoot and the consolidation sweep can raise the input sum and therefore the burn. `quote(X)` runs the IDENTICAL selection read-only and returns `{burn_mc, change_mc, inputs_mc}` with `inputs_mc == X + burn_mc + change_mc`, using the descriptor's effective policy (`burn_policy_next` applied per the mint's own `mint_time` — L17), so a payer can budget before spending.
9. **Batch = one call = one burn (§3.3 burn-once):** `pay_many` fans out to N recipients in ONE `/v3/exchange`; `receive_batch` settles N received tokens in ONE `/v3/exchange` (a §9.2 seller must never pay per-token burns). Both respect the descriptor's `limits.max_batch` (`pay_many` refuses with a clear chunking error before persisting anything).
10. **Transport fault-injection seam:** every HTTP request `MintClient` makes funnels through the single method `_transport(method, path, body, extra_headers=None)`. Tests subclass it to instrument the wire and inject faults (record request order, raise before send, deliver-then-drop the response, drop only the first response). The seam is load-bearing for B2/B3/B8/B9/B10 — new client methods MUST route through it, never open their own connections.

## Benchmark (critic checklist)
- [ ] B1 Happy path against a live in-process C06 mint: issue→receive→pay→counterparty receives; balances and mint supply reconcile to the mc, burn accounted.
- [ ] B2 Ordering proof: instrument the client transport to record (persist_fsync, http_send) event order; run 20 pays; every send strictly follows its outputs' persistence. A transport that RAISES before sending leaves the wallet recoverable with zero loss.
- [ ] B3 Crash recovery: simulate crash-after-send-before-response (transport delivers to mint, response dropped, process state discarded, wallet reloaded from disk): `recover()` finds the confirmed outputs via status and final balance is correct (no loss, no double-count). Also the inverse: crash-before-send → recover marks orphan and restores inputs.
- [ ] B4 Received-token double-spend: same token string given to two wallets; exactly one `receive()` succeeds, the other raises `PaymentInvalid` with reason `spent`.
- [ ] B5 Coin selection: with held ladder {1×1000, 5×100, 10×10, 10×1}, pay(237) at rate_ppm=1000 selects correctly, change is ladder-decomposed, and repeated pays don't fragment unboundedly (assert a consolidation bound or strategy).
- [ ] B6 handle_refused: after a payee "refuses" (tokens returned via error path), re-exchange makes the old strings dead — a later redeem attempt of the refused string fails with `spent`/`unknown`.
- [ ] B7 Fresh-wallet receive-first: zero-config wallet receives its first token successfully (no auth, no registration — assert no such HTTP calls occur).
- [ ] B8 Idempotent retry: forced timeout-then-retry of one pay produces no double-spend and no duplicate outputs (same idempotency key observed by the mint exactly once in effect).
- [ ] B9 pay_many fan-out: 20 recipients through exactly ONE `/v3/exchange` (asserted via the `_transport` seam), one burn on the call's input sum, every recipient's token list sums to its amount and is receivable; a fan-out that would exceed `limits.max_batch` raises a chunking error BEFORE anything is persisted or sent.
- [ ] B10 receive_batch (§9.2): 10 tokens with one already spent — exactly two exchange calls (the enumerated rejection, then the retry under a FRESH idempotency key), `dead` enumerates `{index, reason}`, the rest credited under ONE burn equal to the final successful call's input-sum burn; locally malformed/foreign strings die as `bad_format` with no wire call; an empty good set credits 0.
- [ ] B11 quote: `quote(X)` equals what `pay(X)` then actually does (balance debits `X + burn_mc`; the mint assesses exactly `burn_mc`, computed on the input sum, not on X), is read-only (no store rows, no exchange), and tracks `burn_policy_next` once the mint's own `mint_time` passes `effective_at`.
- [ ] B12 Wallet.connect: URL-only zero-config construction (§7.2) binds the descriptor's `mint_id` and can receive immediately; reconnecting the same store finds the balance.
- [ ] B13 admin_issue (§7.1): operator funding over `POST /admin/issue` with `X-Admin-Token`; a wrong or missing token is refused with nothing issued; both §3.3 output forms issue and the funded tokens are received end-to-end.
