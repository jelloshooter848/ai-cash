# C04 — ledgerstore (the trust core)

**Module:** `aicash/ledgerstore.py` · **Tests:** `tests/test_c04_ledgerstore.py` · **Spec:** §3.2, §3.3, §3.5 (data), §7.1, §7.3 (assessment point), §8 · **Locked:** L1–L6, L12 · **Depends:** C01, C02, C03

## Purpose
The sqlite-backed ledger with the one atomic operation. This is the only place double-spending is prevented; it cannot be best-effort (§3.3). Everything here is behind a Python API; HTTP is C06's job.

## Public API
```python
class Ledger:
    def __init__(self, db_path: str, clock: Callable[[], int], burn_policy: BurnPolicy,
                 recovery_window_ms: int, max_lock_expiry_ms: int | None): ...
        # db_path must be a real file path. ':memory:' is REJECTED (ValueError) with an
        # explanation: server threads open independent sqlite connections, and each
        # in-memory connection is its own separate empty database — the threads would
        # never see each other's entries. Tests should use a temp-directory file.
    # Read-only properties: burn_policy, recovery_window_ms, max_lock_expiry_ms —
    # exposed so C06's MintServer can assert config/ledger consistency at boot.
    def issue(self, outputs: list) -> None
        # §7.1 operator funding: insert unspent entries, cumulative_issued += sum. No inputs, no burn.
        # Each output is an OutputSpec OR a §3.3 wire-form dict — {"amount_mc","secret_hash"} /
        # {"amount_mc","secret"} with optional "lock" — parsed by the module-level
        # parse_output_wire helper, the SAME parser C06's HTTP layer uses (shared, never
        # duplicated, so the two surfaces cannot drift). A dict of unrecognized shape gets the
        # usual §3.8 bad_format error at its index AND an exception message naming the
        # expected forms.
    def exchange(self, idempotency_key: str, body_digest: str,
                 inputs: list[InputForm], input_amount_hint: None = None,
                 outputs: list[OutputSpec]) -> dict
        # returns {"status":"ok","outputs_confirmed":n,"burn_mc":b}
        # raises ExchangeRejected(errors=[{index,kind,reason},...]) — enumerated per §3.8
    def status(self, hashes: list[str]) -> tuple[int, list[dict]]   # (mint_time, results order-aligned)
    def supply(self) -> dict      # {outstanding_mc, cumulative_issued_mc, cumulative_burned_mc} (unsigned)
    def prune(self) -> int        # delete spent records older than recovery_window; returns count
# OutputSpec: (amount_mc: int, secret_hash: str | None, secret: bytes | None, lock: Lock | None)
#   exactly one of secret_hash/secret set (§3.3 by-hash preferred / by-secret accepted)
```

## Requirements
1. **Atomicity:** `exchange` runs in a single sqlite transaction (`BEGIN IMMEDIATE`); steps: resolve inputs → evaluate locks (C02) with `now = clock()` captured once per call → conservation check `sum(in) == sum(out) + compute_burn(sum(in), policy)` → duplicate-output check (against table AND within the batch) → mark spent (recording `claim_witness` for claim-path spends, `spent_at`) → insert outputs. Any failure rolls back everything.
2. **Enumerated rejection (§3.8):** collect ALL failing input/output indices with reasons (`unknown|spent|lock_preimage_invalid|lock_expired|lock_not_expired|refund_invalid|bad_witness_length|bad_format|output_exists|amount_mismatch`), not just the first. `amount_mismatch` is a call-level error (index null); its entry additionally carries `expected_burn_mc`, the burn the mint computed from the published policy and the input sum (public information — lets the caller rebalance the batch without re-deriving §7.3 arithmetic). Shape otherwise unchanged.
3. **Claim binding:** a claim-form input must present the token whose secret hashes to an existing entry; a refund-form input references the entry by hash directly. Plain inputs are tokens for unlocked entries. Wrong mint_id or amount in a presented token vs. the ledger entry → `bad_format` for that index.
4. **Idempotency (§3.3):** store `key → (body_digest, result_json)` including rejections; replay identical digest (return stored result / re-raise stored rejection); different digest → `idempotency_conflict` error. Never store request bodies or secrets. Idempotency records prune with §8(b).
5. **By-secret outputs:** hash immediately, never persist the raw secret (code-inspection requirement).
6. **Locks:** validate via C02 `validate_lock`; if `max_lock_expiry_ms` is set, reject locks with `expiry > now + max_lock_expiry_ms` (`bad_format`). Locked and unspent entries are NEVER pruned (§8(b)).
7. **Supply invariant:** after any sequence of operations, `outstanding == cumulative_issued − cumulative_burned` where outstanding = sum of unspent amounts; maintained transactionally with the operations (§3.6).
8. **Clock:** injected only; captured once per exchange so every lock in a batch sees the same `now`.
9. **status():** per §3.5 pinned schema: `state`, `amount_mc`, full `lock` object or null, `spent_at`, `claim_witness` (b64u, only for claim-path spends still in retention). Unknown → `{state:"unknown"}` only.
10. **prune():** deletes only spent entries with `spent_at < now − recovery_window_ms` and expired idempotency records. `claim_witness` disappears with its record — that is the §8 design.

## Benchmark (critic checklist)
- [ ] B1 Conservation: exchange with `sum(out) = sum(in) − burn` succeeds; off-by-one in either direction → `amount_mismatch`; burn recorded in `cumulative_burned_mc` and response.
- [ ] B2 **Double-spend race:** 8 threads racing `exchange` calls sharing one input over ≥50 rounds: exactly one winner per round (count via distinct successful outputs), no partial state (loser's outputs absent), DB invariant (req 7) holds after every round.
- [ ] B3 Enumerated rejection: a 5-input call with input[1] spent and input[3] unknown returns BOTH indices with correct reasons; batch with duplicate output hash inside the batch → `output_exists` at the right index; nothing was mutated (all inputs still unspent).
- [ ] B4 Idempotent replay: same key+digest after a successful call returns the identical result object without re-executing (outputs not double-inserted — assert by supply and row counts); same key, different digest → `idempotency_conflict`; replay of a stored REJECTION reproduces the rejection.
- [ ] B5 Lock lifecycle through the API: fund locked output (by-hash) → claim-form spend with valid witness pre-expiry succeeds and `status` then shows `claim_witness` == the witness; refund-form succeeds only at/after expiry (drive with fake clock, including the `now == expiry` boundary → refund yes, claim no).
- [ ] B6 Asymmetric credentials (L5): claim-form with correct witness but a token whose secret does not hash to the entry → rejected; refund-form needs no secret (only hash + refund witness) → succeeds.
- [ ] B7 issue(): increases outstanding and cumulative_issued equally; supply invariant holds; issued by-hash outputs spendable later by their secret holders.
- [ ] B8 prune(): spent-and-old records vanish (status → `unknown`), unspent and locked-unspent records survive regardless of age; supply invariant unaffected by pruning; claim_witness no longer served after prune.
- [ ] B9 max_lock_expiry enforcement, and locked-entry `status` returns the full lock object (needed by §9.1/§9.3/§11 flows).
- [ ] B10 No raw secret at rest: after by-secret output creation, scan the sqlite file bytes for the secret's b64u and raw form — absent. Idempotency table stores digests only.
- [ ] B11 `status` batch results order-aligned with request, unknown handled, `mint_time` returned from the injected clock.
