# AICash usability report

Cold-start usability gauntlet: fresh agents, each role-playing an AI agent with a real job, given nothing but the repository and told to make real money move. Success = value actually transferred on a live in-process mint, verified by balances and the mint's signed supply arithmetic. The bar for **usable**: complete the journey from repo *docs* alone (README + spec + component "Public API" blocks + public signatures) **without** reading implementation source.

## Final verdicts — 7/7 usable

| Journey | Persona / need | Verdict | Confirmed |
|---|---|---|---|
| J1 receive-first worker | zero-capital agent gets paid, no registration (§7.2) | **usable** | round 3, no source read |
| J2 micro-work fan-out | pay 20 strangers in one call, handle spent/timeout (HYDRA) | **usable** | round 3, no source read |
| J3 metered API + channel | serve-then-batch-redeem + §9.5 envelope→§9.1 channel (ORACLE) | **usable** | direct path verification + regression test |
| J4 streaming pair | per-token channel, wire handoff, settle/refund (§9.1) | **usable** | round 2, no source read |
| J5 milestone escrow | 3-arbiter k=2 panel, split award, attack caught (FOREMAN) | **usable** | round 2, no source read |
| J6 fleet operator | caps, freeze, no-withdraw flag, pull, signed statement (ATLAS-OPS) | **usable** | round 2, no source read |
| J7 cross-mint swap | margin from descriptors, silent-claim defense (BRIDGE) | **usable** | round 2, no source read |

Every journey **completed** (real value moved, supply reconciled) in every round from round 1 on; the work across rounds was closing the gap between "the code delivers the promise" and "an integrator reaches it from docs without spelunking."

## What the three rounds changed

**Round 1 (all 7 completed, all `usable_with_fixes`).** The code worked; discoverability did not. Universal finding: no README/quickstart, so a cold agent reconstructed the mint-boot sequence from spec sections and constructor source; no client path for operator funding; duplicated Ledger/MintConfig policy params with no consistency check; a `mint_id` validated in the codec but not in config (boots, then fails at payment time); missing batch/fan-out and wire codecs for cross-agent handoff objects.

**Fixes applied (spec-faithful, no checks weakened):**
- `README.md` + runnable `examples/quickstart.py` (the whole §0 loop in ~30 lines, executed and asserted).
- Package-root exports: 61 names including every integrator-facing type, function, **and the exception classes each call raises**.
- Ergonomic client surface: `MintClient.admin_issue`, `Wallet.connect` (zero-config §7.2 entry), `Wallet.pay_many` and `Wallet.receive_batch` (one call = one burn), `Wallet.quote` (budget before paying), `make_mint` factory (single source of truth for policy), `ChannelPayer.estimate_open_cost`.
- Wire codecs for the cross-agent handoffs the spec defines as messages: `ChannelInfo.to_json/from_json`, `FundingInfo.to_dict/from_dict`, and a discoverable `aicash.envelope` module.
- Traps closed: `mint_id` now validated in config (fails at boot, not payment); `:memory:` rejected with an explanation; the misspelled `freezed` response field renamed `frozen`; `amount_mismatch` errors now carry `expected_burn_mc`.

**Round 2 (4 `usable`, 2 `usable_with_fixes`, 1 output-format error).** Convergent, small remaining gaps: exception classes not yet exported/documented (forced a source read for their attributes), and one real interop bug — `parse_envelope` decoded `channel_draw.x_k` to bytes while `ChannelPayee.on_draw` expected the b64u string, so the natural "parse the envelope, dispatch the draw" pattern raised a spurious error that looked like a hostile client.

**Fixes applied:**
- Exported all exception types; documented per-method `raises` and exception attributes in the component "Public API" blocks.
- Fixed the envelope↔channel type mismatch: `on_draw` now normalizes `x_k` from bytes **or** b64u string and accepts the parsed `ChannelDraw` object or the raw dict; regression test added; the shipped J3 example routed through `payment_error()` so its 402 vocabulary can't drift.
- Documented the clock protocol as a public contract (`FakeClock.now_ms` accessor added), the `SwapParty`↔spec name mapping, split-award decision types, and the real `make_dispute_record` signature.

**Round 3 (confirmation).** J1 and J2 reached `usable` with no source reading. J3's previously-broken path (`build_envelope → parse_envelope → on_draw`) was verified end to end against a live mint using only the public API — see `examples/j3-metered-api-r3/envelope_channel.py`.

## Honest residual friction (minor, non-blocking)

- `quote(sum(amounts))` is an exact pre-check for `pay_many` only while coin selection is deterministic; a `quote_many` would remove the caveat. Documented, not yet added.
- `ChannelPayer.refund()` leaves recovered value as tokens in `.refund_tokens` rather than auto-crediting a wallet — documented as actual behavior after a doc/code discrepancy was caught during the fix pass.
- A few doc pointers (lock wire shape in escrow `verify_funding`, ChannelInfo readable attributes) were added rather than left implicit.

## Bottom line

An AI agent — or the framework wrapping one — can integrate AICash for any of the seven core value-exchange patterns from the repository's own documentation, without reading implementation internals, and the first payment is a `Wallet.connect(...).receive(token)` away. The remaining friction is cosmetic. Suite: **307 tests, 0 failures**, covering the adversarial cases behind each journey.
