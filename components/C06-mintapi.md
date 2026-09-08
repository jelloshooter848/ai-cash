# C06 — mintapi

**Module:** `aicash/mintapi.py` · **Tests:** `tests/test_c06_mintapi.py` · **Spec:** §3.3, §3.5, §3.6, §3.7, §3.8 · **Locked:** L2, L11, L17 · **Depends:** C04, C05

## Purpose
The HTTP surface of a mint: JSON in/out over stdlib `http.server` (ThreadingHTTPServer), wiring C04 + C05 and assembling the §3.6 descriptor. Also the in-process test harness other components use as "a real mint."

## Public API
```python
@dataclass(frozen=True)
class MintConfig:
    mint_id: str                       # MUST match tokencodec.MINT_ID_RE (^[a-z0-9-]{1,64}$);
                                       # __post_init__ raises ValueError otherwise
    baseline_model_class: str
    burn_policy: BurnPolicy            # C03; validated
    signing_private: bytes             # 32 raw bytes (L17 static Ed25519 key)
    signing_public: bytes              # 32 raw bytes
    denominations_mc: tuple[int, ...] = (1, 10, 100, 1_000, 10_000, 100_000)
    burn_policy_next: tuple[BurnPolicy, int] | None = None   # (policy, effective_at_ms) — §7.3 notice
    max_batch: int = 256
    anonymous_rate: dict = {"per_caller_rps": 50, "burst": 200}   # published, not enforced (L17)
    registered_rate: dict = {"per_caller_rps": 50, "burst": 200}
    grace_ms: int = 5_000
    timestamp_precision_ms: int = 1
    max_lock_expiry_ms: int | None = 30 days                 # ms; None = unbounded
    recovery_window_ms: int = 90 days                        # ms
    prunes_spent_records: bool = False   # True REQUIRES finite max_lock_expiry_ms (§8(b))
    policy_url: str = "about:blank"
    performance: dict | None = None      # see "performance shape" below
    profiles: tuple[str, ...] = ()
    admin_token: str | None = None       # gates /admin/issue when set (non-normative)

class MintServer:
    def __init__(self, config: MintConfig, ledger: Ledger): ...
        # Asserts at boot that config and ledger AGREE on the shared parameters
        # burn_policy / recovery_window_ms / max_lock_expiry_ms (read from the
        # Ledger's read-only properties). A hand-wired mismatch — descriptor
        # advertising one policy, ledger enforcing another — raises ValueError
        # here, never surfacing later as a mystery amount_mismatch at payment time.
    def start(self) -> int      # binds 127.0.0.1:0, returns port; serves on background threads
    def stop(self) -> None

def make_mint(config: MintConfig, db_path: str, clock=system_clock) -> tuple[MintServer, Ledger]:
    # The recommended constructor: builds the Ledger FROM the config's
    # burn_policy / recovery_window_ms / max_lock_expiry_ms (single source of
    # truth — nothing to hand-wire, nothing to drift), returns both. `clock`
    # defaults to the wall-clock aicash.clock.system_clock; tests inject a
    # FakeClock (L17). Call server.start() to bind a port; use the returned
    # ledger for issuance/pruning/direct inspection.

# Endpoints: POST /v3/exchange · GET /v3/status/<hash> · POST /v3/status · GET /v3/mints
#            POST /admin/issue   (non-normative test/ops path for §7.1 operator funding)
```

### `POST /admin/issue` (non-normative)
Not part of the spec's Layer 0 surface — a reference-implementation operator path for §7.1 funding. When `MintConfig.admin_token` is set, the request MUST carry it in the `X-Admin-Token` header (constant-time compared); a missing/wrong header → `401 {"status": "unauthorized"}`. With no token configured the route is open (test/ops bootstrap).
```
Request:  { "outputs": [ <§3.3 output form>, ... ] }        # by-hash {amount_mc, secret_hash}
                                                            # or by-secret {amount_mc, secret},
                                                            # optional "lock" per §3.4
Response: 200 { "status": "ok", "outputs_confirmed": <n> }
          400 { "status": "rejected", "errors": [ {index, kind:"output", reason}, ... ] }  # §3.8
```

### `GET /v3/status/<hash>` — exact wrapper shape
The single-entry form wraps ONE §3.5 entry (identical to a batch entry) as:
```
200 { "mint_time": <int ms>, "result": { ...one §3.5 entry... } }
```
(the batch form `POST /v3/status` returns `{ "mint_time": <int ms>, "results": [ ... ] }`). Unknown hashes are still 200 with `result: {"state":"unknown", "lock":null, "spent_at":null, "claim_witness":null}` — never a 404.

### `MintConfig.performance` shape and the staleness-null rule (L11)
`performance` is `None` or a dict with EXACTLY these four keys, every value a plain non-negative int (`window_days >= 1`):
```
{ "p99_exchange_ms": int, "sustained_qps": int, "window_days": int, "measured_at": int }
```
Descriptor rendering: served verbatim while fresh; once `mint_time - measured_at > window_days` in ms, the descriptor renders `performance: null` — a stale measurement MUST render null, never zeros and never the old numbers.

## Requirements
1. **Anonymous access (§3.7, L2):** `/v3/exchange` and `/v3/status*` require no auth header, no registration, no cookie — assert by serving bare requests. `/admin/issue` MAY require a configured admin token (it is not Layer 0).
2. **Wire fidelity:** request/response shapes exactly as §3.3/§3.5/§3.8 — mixed input forms (string token / {token,witness} / {hash,witness}), outputs by `secret_hash` or `secret`, `{status:"ok",outputs_confirmed,burn_mc}` on success; rejections as HTTP 400 with `{status:"rejected", errors:[{index,kind,reason}]}`; `idempotency_conflict` as a call-level error; batch status order-aligned with response-level `mint_time`. The `amount_mismatch` call-level entry additionally carries `expected_burn_mc` — the burn the mint computed from its published §7.3 policy (public information), so a mis-budgeted caller can rebalance without re-deriving the arithmetic; the entry is otherwise shape-identical.
3. **Descriptor (§3.6):** every pinned field present: `mint_id, baseline_model_class, mint_time, denominations_mc, burn_policy, burn_policy_next, supply{...signed...}, performance (null when config stale/absent — never zeros), limits{max_batch, anonymous_rate, registered_rate}, lock_params{grace_ms, timestamp_precision_ms, max_lock_expiry_ms}, retention{recovery_window_ms, prunes_spent_records, policy_url}, profiles, activity, signing_pubkey`. Supply snapshot: `snapshot_seq` strictly increasing per serve, signed via C05, invariant `outstanding == issued − burned` true at signing time (read transactionally from C04).
4. **Errors:** malformed JSON → 400 `bad_format`; over `limits.max_batch` on exchange inputs+outputs or status hashes → 400 `over_batch_limit`; unknown routes → 404. Never a stack trace in a response body.
5. **No secret logging** (§3.1): the server MUST NOT log request bodies; access log lines carry route + status only.
6. Content-Type `application/json`; responses serialized with C01 canonical_json (stable bytes make client-side digests reproducible).

## Benchmark (critic checklist)
- [ ] B1 End-to-end money flow over real HTTP: admin-issue → exchange split (by-secret and by-hash outputs in one call) → status confirms; amounts conserve minus burn.
- [ ] B2 Anonymous conformance: all Layer 0 endpoints succeed with no auth; admin endpoint refuses without token when configured.
- [ ] B3 Descriptor completeness: every field of req 3 present with correct types; `performance: null` case renders null (not 0); snapshot verifies against `signing_pubkey` with C05; two consecutive fetches → `snapshot_seq` increases and cumulatives monotone; invariant holds.
- [ ] B4 §3.8 over the wire: a bad batch returns enumerated indices/reasons; over_batch_limit at exactly max_batch+1 (max_batch accepted); idempotency replay over HTTP returns byte-identical body; conflict case surfaces.
- [ ] B5 Lock flows over the wire: fund-locked, claim with witness, refund after expiry (fake clock injected through Ledger), `claim_witness` visible in status response.
- [ ] B6 Concurrency: ≥8 parallel HTTP clients racing the same input token — exactly one 200.
- [ ] B7 No-log check: server's captured log output for a run containing tokens/secrets does not contain any secret material (test asserts against collected log strings).
- [ ] B8 GET /v3/status/<hash> single-entry form matches the batch form's entry shape.
