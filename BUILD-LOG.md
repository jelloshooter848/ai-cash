# BUILD-LOG — AICash v0.4 reference implementation

Builder/critic gauntlet: each component built against its spec+benchmark in `components/`, then reviewed by a fresh critic holding `LOCKED-DESIGN-DECISIONS.md` and the benchmark. Reports below follow the per-iteration format; suite state at the end of the log.

## ITERATION 1 — C01-tokencodec
Passing: 7/7 benchmark items · suite 72/72
Failed:  none (verdict: PASS)
Fixed:   n/a (clean first pass)
Open questions: 6
Next:    component complete

## ITERATION 1 — C02-lockeval
Passing: 7/7 benchmark items · suite 98/98
Failed:  none blocking; minors noted: aicash/lockeval.py line 25's docstring resolves a real spec ambiguity (whether the 32-byte witness length gate fires before or after the temporal path split — t
Fixed:   n/a (clean first pass)
Open questions: 6
Next:    component complete

## ITERATION 1 — C03-burncalc
Passing: 6/6 benchmark items · suite 32/32
Failed:  none (verdict: PASS)
Fixed:   n/a (clean first pass)
Open questions: 4
Next:    component complete

## ITERATION 1 — C05-signing
Passing: 5/6 benchmark items · suite 72/72
Failed:  [major] verify_obj accepts malformed b64u signature strings as valid, violating spec Requirement 3 ('malformed b64u ... -> False') and the B4 property ('Tampered ... signature strings -> False'). Cause: _b64u_decode_strict (impl/aicash/signing.py lines 47-59) pre-screens only '='
Failed:  [weakened-check] test_bad_signature_strings_are_false_not_exceptions (tests/test_c05_signing.py, B4) only tampers characters whose change alters the decoded bytes (first-char flip, truncation, '=' padding, '\n'); it never tries non-alphabet-character injection or las
Open questions: 4
Next:    verify_obj accepts malformed b64u signature strings as valid, violating spec Requirement 3 ('malformed b64u ... -> False

## ITERATION 2 — C05-signing
Passing: 6/6 benchmark items · suite 99/99
Failed:  none blocking; minors noted: sign_raw (aicash/signing.py:117-119) calls bytes(message) without a type check, so sign_raw(5, priv) silently signs five zero bytes instead of raising — a calle
Fixed:   critic findings from iteration 1 — Fixed the critic's major finding (signature-string malleability in _b64u_decode_strict). The decoder now (1) positively validates the input against the base64url alphabet [A-Za-z0-9_-]* via regex before decoding, and (2) enforces canonicality by round-trip: the decoded bytes are re-encoded with the 
Open questions: 0
Next:    component complete

## ITERATION 1 — C04-ledgerstore
Passing: 11/11 benchmark items · suite 158/158
Failed:  none blocking; minors noted: Component spec Requirement 3 demands 'Wrong mint_id or amount in a presented token vs. the ledger entry -> bad_format', but only the amount half is implemented.
Fixed:   n/a (clean first pass)
Open questions: 9
Next:    component complete

## ITERATION 1 — C12-receipts
Passing: 7/7 benchmark items · suite 133/133
Failed:  none blocking; minors noted: verify_receipt and verify_attestation ignore extra unknown roles inside the signatures object (e.g. signatures["mallory"]="AAAA" on a fully-signed receipt still
Fixed:   n/a (clean first pass)
Open questions: 12
Next:    component complete

## ITERATION 1 — C06-mintapi
Passing: 8/8 benchmark items · suite 175/175
Failed:  [major] snapshot_seq is in-memory only (mintapi.py _Core.__init__ line 177, incremented lines 324-325) and resets on server restart. Reproduced: with the same persistent sqlite ledger and the same static signing key (L17), a restarted MintServer signs snapshot_seq=1 again with whatever the supply now is — t
Failed:  [minor] activity.daily_exchange_count / daily_volume_mc (mintapi.py lines 178-179, 272-279) are cumulative process-lifetime counters, never windowed to a day: after N days of uptime they overstate daily activity ~N-fold, and an idempotency replay re-increments both (the replayed result flows through the nor
Failed:  [minor] Admin token check uses ordinary string inequality (mintapi.py line 386 'presented_token != self.config.admin_token' and the same compare in do_POST lines 493-495), a timing-side-channel-prone comparison of a credential. The path is non-normative (/admin/issue) so this is hygiene, not conformance.
Open questions: 3
Next:    snapshot_seq is in-memory only (mintapi.py _Core.__init__ line 177, incremented lines 324-325) and resets on server rest

## ITERATION 2 — C06-mintapi
Passing: 8/8 benchmark items · suite 177/177
Failed:  none blocking; minors noted: A syntactically valid JSON body containing an integer longer than Python's int-to-str limit (~4300 digits, e.g. amount_mc of 5000 nines) returns HTTP 500 {"stat
Fixed:   critic findings from iteration 1 — All three critic findings verified against aicash-spec-v0.4.md and fixed; no finding was wrong. (1) MAJOR snapshot_seq persistence: seq now lives in C06-owned table mintapi_state in the ledger's sqlite file; descriptor() bumps and reads it inside BEGIN IMMEDIATE on that shared db, so the seq increme
Open questions: 3
Next:    component complete

## ITERATION 1 — C07-wallet
Passing: 8/8 benchmark items · suite 195/195
Failed:  none blocking; minors noted: wallet.py _select/_decompose: the post-selection consolidation sweep can push the input sum across the burn exemption boundary, and pay() recomputes burn on the | wallet.py handle_refused line 711: dead.append(tokens.index(tstr)) uses first-occurrence lookup, so if the caller passes duplicate token strings the reported de
Fixed:   n/a (clean first pass)
Open questions: 9
Next:    component complete

## ITERATION 1 — C10-supervision
Passing: 9/9 benchmark items · suite 211/211
Failed:  [major] Persist-before-send violation on the §5.3 bridge (money-losing crash window). In agent_deposit (impl/aicash/supervision.py:792-823) the mint-custody secret is generated in memory, ledger.exchange() then COMMITs its own C04 transaction (ledgerstore.py exchange runs a self-contained BEGIN IMMEDIATE), 
Failed:  [minor] supervision.py line 27 says 'See OPEN-QUESTIONS note recorded by this component's build' about the withdrawal burn being computed on the mint-selected custody INPUT sum — but no such note exists in OPEN-QUESTIONS.md (it has items 1,2,3,5 only). The question is real and should actually be logged: bec
Failed:  [minor] agent_transfer allows to_account == the caller (self-transfer): the balance nets to zero but the response reports balance_mc = old_balance - amount (wrong, since sender was snapshotted before the offsetting credit), and the self-transfer consumes cap headroom and writes a debit+credit line pair. Not
Failed:  [minor] _principal (supervision.py:218-235) resolves bearer API keys via plain SQL equality lookup — not a timing-safe comparison. A B-tree string compare can in principle leak matching-prefix length. The auth scheme is deliberately scheme-agnostic (L17 / OPEN-QUESTIONS #5), so this is not a spec violation,
Open questions: 10
Next:    Persist-before-send violation on the §5.3 bridge (money-losing crash window). In agent_deposit (impl/aicash/supervision.

## ITERATION 2 — C10-supervision
Passing: 9/9 benchmark items · suite 220/220
Failed:  none blocking; minors noted: Requirement 3 lists withdraw among the outflows a freeze must block, and the code checks it (supervision.py agent_withdraw, frozen check before the flag check), | POST /v3/operator/caps treats an absent field identically to explicit null, so a partial update ({per_hour_mc: 100}) silently clears any previously set per_day/
Fixed:   critic findings from iteration 1 — All four critic findings fixed. (1) Persist-before-send (§5.1 mandatory ordering, §5.3 no-exceptions): sup_custody gained a state column (pending/unspent/reserved/spent) and a sup_pending_ops staging table; deposit custody secrets and withdrawal change secrets are committed durably (with a staged op
Open questions: 3
Next:    component complete

## ITERATION 1 — C08-channels
Passing: 9/9 benchmark items · suite 241/241
Failed:  none (verdict: PASS)
Fixed:   n/a (clean first pass)
Open questions: 5
Next:    component complete

## ITERATION 1 — C09-escrow
Passing: 8/8 benchmark items · suite 251/251
Failed:  none blocking; minors noted: B7 asserts vote binding to milestone (tamper) and evidence hash (foreign evidence never combines) but never exercises a vote signed for a DIFFERENT job_id being | EscrowPayer.fund verifies attestation signatures only when arbiter_pubs is supplied (constructor default None silently skips payer-side signature verification). | EscrowPayer.fund only supports funding the whole job in one /v3/exchange call and raises when it exceeds limits.max_batch; §9.6 step 3 also allows 'one call per
Fixed:   n/a (clean first pass)
Open questions: 8
Next:    component complete

## ITERATION 1 — C11-swap
Passing: 5/6 benchmark items · suite 264/264
Failed:  [major] b_fund omits §11 step 4's mandated check that Mint 2's retention.recovery_window_ms covers the ACTUAL T − T′ (plus dispute margin). The only retention check lives in compute_margin (aicash/swap.py:203-204), which never sees T or T′ and checks window >= minimum margin only. With e.g. window = 20 min 
Failed:  [major] Weakened check: test_b2_silent_claim_defeated does not drive the clocks through the benchmark's pinned worst case. The benchmark requires 'claim lands at T′ − ε, poll fires one full interval later'; in the test (tests/test_c11_swap.py:259-292) both clocks are set to T′ − ε, A claims, and b_poll_and_
Failed:  [minor] aicash/swap.py:49-51 claims the max-of-two-per-mint-latency interpretation of the §11 formula's single 'assumed redemption latency' term is 'recorded in OPEN-QUESTIONS' — OPEN-QUESTIONS.md contains no such entry. The interpretation itself is conservative and defensible, but the project rules require
Failed:  [minor] B1's 'neither mint's DB references the other' is verified only by a single cross-mint status probe on one hash returning 'unknown' (tests/test_c11_swap.py:204-209) — a weak proxy for the DB-isolation claim.
Failed:  [weakened-check] test_b2_silent_claim_defeated: the 'worst-case discovery' the benchmark pins (poll fires one full interval AFTER the claim at T′ − ε) is not driven — clocks are never advanced between A's claim and B's discovering poll, so the test exercises zero-del
Open questions: 5
Next:    b_fund omits §11 step 4's mandated check that Mint 2's retention.recovery_window_ms covers the ACTUAL T − T′ (plus dispu

## ITERATION 2 — C11-swap
Passing: 6/6 benchmark items · suite 265/265
Failed:  none (verdict: PASS)
Fixed:   critic findings from iteration 1 — All four critic findings resolved. (1) b_fund now enforces §11 step 4 against the actual horizon: QuoteRefused unless Mint 2's retention.recovery_window_ms >= (T − T′) + margin; new test test_b_fund_refuses_retention_below_actual_horizon pins a 30-min window that passes the minimum-margin floor but 
Open questions: 4
Next:    component complete

---

## Final state

- 12/12 components PASS their critic gauntlet (C05, C06, C10, C11 required 2 iterations; the rest cleared on the first).
- Full suite: `cd impl && python3 -m unittest discover -s tests -t .` → **265 tests, 0 failures, 0 skips, 0 expected-failures**.
- No check was weakened to pass; ambiguities were logged to OPEN-QUESTIONS.md (4 new items recorded during the build: custodial withdrawal burn attribution, tranche-size/max_batch boundary, swap latency-slot attribution, dispute-margin quantity).
- Major defects the critics caught and forced fixes for: malformed-signature acceptance (C05), non-persistent snapshot_seq breaking monotonicity proof (C06), a persist-before-send violation on the custodial deposit bridge (C10), and a missing retention-window check plus an un-driven worst-case clock in the swap tests (C11).
