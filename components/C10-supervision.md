# C10 — supervision

**Module:** `aicash/supervision.py` (+ routes in mintapi) · **Tests:** `tests/test_c10_supervision.py` · **Spec:** §5.2, §5.3, §6.1, §7.3 (custodial rules), §8(c) · **Locked:** L13, L17 · **Depends:** C04, C05, C06

## Purpose
The optional Supervision Profile: custodial accounts under operator identities, the seven operations, and signed statements. Mounted onto a C06 server (profile advertised in descriptor).

## Public API (Python)
```python
class SupervisionServer(MintServer):          # a C06 mint with the profile mounted
    def __init__(self, config: MintConfig, ledger: Ledger): ...
        # Same constructor contract as MintServer (including the boot-time
        # config/ledger consistency check on burn_policy / recovery_window_ms /
        # max_lock_expiry_ms). The descriptor's `profiles` gains "supervision"
        # automatically when mounted — the config passed in need not list it
        # (requirement 8); an explicitly listed "supervision" is not duplicated.
    def start(self) -> int      # binds 127.0.0.1:0, returns port; Layer 0 routes
                                # (C06) and supervision routes on the same port
    def stop(self) -> None
```
**Time:** supervision has no clock parameter anywhere — all supervision time (cap windows, pull expiry, statement periods, journal timestamps) flows from the Ledger's injected clock, observed through `Ledger.status` (L17). Inject a `FakeClock` into the Ledger and the whole supervised mint moves with it.

## Public API (HTTP, under the C06 server)
```
POST /v3/operator/register            {operator_name} -> {operator_id, operator_key}      (test bootstrap)
POST /v3/operator/agents              op-auth; {agent_name} -> {agent_id, agent_key}
POST /v3/operator/caps                op-auth; {agent_id, per_hour_mc|null, per_day_mc|null, absolute_mc|null}
POST /v3/operator/freeze | unfreeze   op-auth; {agent_id | "ALL"} -> {status:"ok", frozen:[...]} / {status:"ok", unfrozen:[...]}
POST /v3/operator/flags               op-auth; {agent_id, no_bearer_withdrawal: bool}
GET  /v3/agent/balance                agent- or op-auth; ?agent_id -> {balance_mc, spend_rate...}
POST /v3/agent/authorize_pull         agent-auth; {payee_account, cap_mc_per_day, expires_at} -> {auth_id}
POST /v3/agent/revoke_pull            agent-auth; {auth_id}
POST /v3/pull                         payee-agent-auth; {auth_id, amount_mc, ref}
POST /v3/agent/transfer               agent-auth; {to_account, amount_mc, ref}     (custodial→custodial)
POST /v3/agent/deposit                agent-auth; {tokens:[...]}                    (bearer→balance, via C04)
POST /v3/agent/withdraw               agent-auth; {outputs:[{amount_mc, secret_hash}]}  (balance→bearer, via C04)
GET  /v3/operator/statement           op-auth; ?agent_id|fleet&from&to -> §6.1(7) signed statement
```
**Wire fix (pre-1.0):** the freeze/unfreeze response field listing the affected agent ids was originally misspelled `freezed`/`unfreezed`; it is now `frozen`/`unfrozen`. Renamed before 1.0 while no external caller could depend on it — no compatibility alias is served. The §6.1(7) journal *kinds* were always `freeze`/`unfreeze` and are unchanged.

## Error envelope
Supervision-level rejections are FLAT — `{"status": "rejected", "reason": "<code>"}` — not the §3.8 `errors` array (there are no batch indices to enumerate). Three shapes exist:
* `401 {"status": "unauthorized"}` — no key / unknown key on an authed route; `403 {"status": "forbidden"}` — a valid key of the wrong role (also: an agent querying another agent's balance).
* `400/404 {"status": "rejected", "reason": ...}` — the supervision-level rejections below. `unknown_agent` is served as 404 (and deliberately identical for "no such agent" and "another operator's agent" — no cross-operator existence oracle); everything else is 400.
* Pass-through: when a deposit/withdraw's underlying C04 exchange rejects, the response is the §3.8 form `400 {"status":"rejected", "errors":[{index,kind,reason},...]}` verbatim.

Route × reason table (every POST route can also return `bad_format` for a malformed/mis-typed body):

| Route | Possible `reason` codes |
|---|---|
| POST /v3/operator/register | `bad_format` |
| POST /v3/operator/agents | `bad_format` |
| POST /v3/operator/caps | `bad_format`, `unknown_agent` (404) |
| POST /v3/operator/freeze, /unfreeze | `bad_format`, `unknown_agent` (404) |
| POST /v3/operator/flags | `bad_format`, `unknown_agent` (404) |
| GET /v3/operator/statement | `bad_format`, `unknown_agent` (404) |
| GET /v3/agent/balance | `bad_format` (operator without ?agent_id), `unknown_agent` (404); 403 for an agent naming another agent |
| POST /v3/agent/authorize_pull | `bad_format`, `unknown_account` |
| POST /v3/agent/revoke_pull | `bad_format`, `authorization_missing` |
| POST /v3/pull | `bad_format`, `authorization_missing`, `authorization_revoked`, `authorization_expired`, `account_frozen`, `pull_cap_exceeded`, `agent_cap_exceeded`, `insufficient_balance` |
| POST /v3/agent/transfer | `bad_format`, `unknown_account`, `account_frozen`, `agent_cap_exceeded`, `insufficient_balance` |
| POST /v3/agent/deposit | `bad_format`; C04 §3.8 `errors` pass-through |
| POST /v3/agent/withdraw | `bad_format`, `account_frozen`, `withdrawal_disabled`, `agent_cap_exceeded`, `insufficient_balance`; C04 §3.8 `errors` pass-through |

## Recipe: fund a custodial fleet
From an empty mint to spendable agent balances (what an operator's bootstrap script does):
1. `POST /v3/operator/register {"operator_name": ...}` → keep `operator_key`; `POST /v3/operator/agents` per agent → keep each `agent_key`.
2. Mint bearer value via C06's non-normative `/admin/issue` (with `X-Admin-Token` if configured). Simplest: generate `secret = new_secret()` yourself and issue **by-hash** `{"amount_mc": N, "secret_hash": ledger_key(secret)}` (the by-secret wire form also works — the mint hashes and discards).
3. Build the token string with C01: `token = format_token(mint_id, N, secret)`.
4. `POST /v3/agent/deposit {"tokens": [token]}` with the agent's key → the mint runs a real §5.3 exchange into custody and credits the balance net of the deposit burn (`deposited_mc`, `burn_mc` in the response).
Thereafter transfers/pulls are burn-free custodial moves; withdrawals return bearer tokens by-hash.

## Requirements
1. **Auth separation (§6.1(1)):** operator and agent keys are distinct random bearer keys; agent keys cannot call operator routes (403), and vice versa for agent-private routes. Supervision controls bind only registered agents (L13) — Layer 0 routes stay authless.
2. **Caps (§6.1(2)):** rolling trailing windows 3600s/86400s, evaluated at commit with the injected clock; ALL debit kinds count: transfer, pull_out, withdrawal gross (amount + burn). Absolute = lifetime total. Exceeding → `agent_cap_exceeded`, atomic (no partial debit).
3. **Freeze (§6.1(3)):** per-agent and operator-wide; frozen accounts fail every outflow (transfer, withdraw, pull against them) with `account_frozen`; nothing queues; credits IN to a frozen account still land.
4. **No-bearer-withdrawal flag (§6.1(4)):** while set, `/v3/agent/withdraw` fails with `withdrawal_disabled`. Deposits still allowed.
5. **Pulls (§6.1(6)):** payee must be a custodial account at this mint; atomic debit+credit; enforce `pull_cap_exceeded` (per-auth trailing day), `authorization_missing|revoked|expired`, granting-agent caps, freeze; revocation is immediate.
6. **Custodial/ledger bridge (§5.3):** deposit spends bearer tokens into mint custody via a real C04 exchange (tokens → mint-internal by-hash outputs) crediting the balance; withdraw debits balance then creates caller-specified by-hash outputs via C04 issue-like exchange from mint custody. Custodial internal transfers/pulls never touch C04 and never burn (§7.3); deposits/withdrawals burn as the exchanges they are — the withdrawing agent is charged `compute_burn(amount_withdrawn)` on the requested amount, never on the mint-selected custody inputs; any ledger-level burn difference is absorbed by the mint (§7.3, R17).
7. **Statements (§6.1(7), §8(c)):** exact pinned schema; kind partition as specced (withdrawal net-of-burn + separate burn line, freeze/unfreeze amount 0 excluded from sums); signed with the mint key (C05); balance invariant enforced at generation; producible on demand for any in-retention period.
8. Descriptor gains `"supervision"` in `profiles` when mounted.
9. All state in the mint's sqlite; atomicity via transactions on the shared connection discipline used by C04.

## Benchmark (critic checklist)
- [ ] B1 The three coherence clauses as dedicated tests: (a) freeze suspends pulls with `account_frozen` and nothing queues (unfreeze → a NEW pull succeeds, the failed one did not execute); (b) pulls count against the granting agent's caps — a pull that would exceed per-hour fails atomically; (c) statement produced on demand for a just-closed period and verifies (schema, signature, invariant).
- [ ] B2 Withdrawal-flag: with flag set, withdraw → `withdrawal_disabled` and no ledger change; unset → succeeds; flag set by operator key only (agent attempt → 403).
- [ ] B3 Rolling windows with fake clock: cap 100/hour; spend 60 at t=0, 40 at t=30min, next 1 mc fails; at t=61min the t=0 spend ages out and 60 more succeeds; per-day and absolute analogous; window is trailing, not calendar (spend at 23:59 still counts at 00:01).
- [ ] B4 Operator-wide freeze halts every agent of that operator in one call, and only that operator's agents.
- [ ] B5 Deposit/withdraw round-trip: bearer→custodial→bearer conserves value minus the two exchange burns; withdraw is by-hash (mint never knows the new secrets — verify secrets absent from mint DB); custodial transfer between two agents burns nothing.
- [ ] B6 Pull lifecycle: authorize → pull ok → revoke → `authorization_revoked`; expiry via fake clock → `authorization_expired`; per-auth day cap enforced.
- [ ] B7 Statement cross-check: run a scripted week (issue, deposits, transfers, pulls, withdrawal, freeze period) and assert the statement's lines reproduce it exactly, sums match the invariant, and an independently recomputed balance equals `closing_balance_mc`.
- [ ] B8 Auth separation matrix: every route × {agent key, operator key, no key} → expected 200/403/401 table.
- [ ] B9 L13 scope: bearer-mode Layer 0 calls by unregistered callers remain fully functional and un-capped on a Supervision mint.
