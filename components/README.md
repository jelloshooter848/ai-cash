# AICash v0.4 reference implementation — component plan

Authority chain: `aicash-spec-v0.4.md` > component spec > code. `LOCKED-DESIGN-DECISIONS.md` binds all critics. Ambiguities go to `OPEN-QUESTIONS.md`, never into silent guesses.

**Language/toolchain:** Python 3.12, stdlib + `cryptography` (Ed25519 only), sqlite3, `unittest`.
**Layout:** package `impl/aicash/`, tests `impl/tests/test_cNN_*.py`.
**Run tests:** `cd impl && python3 -m unittest discover -s tests -t . -v`
**Clock rule (L17):** all time-dependent code takes an injectable clock (`clock()` → int ms). Tests use fake clocks; no `time.time()` in ledger/lock/caps logic.

## Components and dependency waves

| Wave | ID | Name | Spec sections | Depends on |
|---|---|---|---|---|
| 1 | C01 | tokencodec | §3.1, §3.2, §3.3 (canonical JSON) | — |
| 1 | C02 | lockeval | §3.4 | — |
| 1 | C03 | burncalc | §7.3 | — |
| 1 | C05 | signing | §3.6, §6.1(7), §10 | — |
| 2 | C04 | ledgerstore | §3.2, §3.3, §3.5, §7.1, §8 | C01–C03 |
| 3 | C06 | mintapi | §3.3, §3.5–§3.8 | C04, C05 |
| 4 | C07 | wallet | §5.1, §5.3, §9.5 | C01, C06 |
| 4 | C10 | supervision | §5.2, §6.1 | C04–C06 |
| 5 | C08 | channels | §9.1, §9.5 | C07 |
| 5 | C09 | escrow | §9.3, §9.4, §9.6 | C07, C05, C12 formats |
| 5 | C12 | receipts | §10.1–10.3, §9.5 | C01, C05 |
| 6 | C11 | swap | §11 | C08-level clients, two mints |

Each component ships: module(s) + its own unittest file + docstring mapping tests → benchmark items. A component is done when its critic confirms every benchmark item is covered by a passing, honest test (no skips, no expected-failures, no weakened assertions).
