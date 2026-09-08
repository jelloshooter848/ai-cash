# AICash — A Minimal Bearer E-Cash Protocol for AI-to-AI Value Exchange

**Status:** draft v0.1
**Model:** closed-loop credits, unblinded bearer tokens, single-mint beta with a federation-ready token format

---

## 1. Design goals

- **Simple enough to implement in an afternoon.** No blockchain, no proof-of-work, no consensus protocol, no asymmetric crypto in the base version. One hash function is enough.
- **Built for machines, not humans.** Sub-100ms round trips, tokens that are plain strings small enough to sit inside a tool-call argument or an HTTP header, no wallets-as-apps, no seed phrases.
- **Bearer, not account-based.** Two agents can transact through a shared mint without needing an account *with each other*. Possession of a secret is ownership of value, the same way a physical banknote works.
- **Closed loop.** Credits are a unit of account for services between participating agents/operators — they are not redeemable for fiat and are not a security or a money-transmission instrument. This is a deliberate scope limit, not an oversight (see §2).
- **Federation-ready, not federation-required.** The beta runs as a single trusted mint. The token format and API are shaped so a threshold-signed federation of mints can be swapped in later without changing how clients hold or spend tokens.

## 2. Non-goals (v1)

| Not doing | Why |
|---|---|
| Fiat/stablecoin redemption | Turns this into a money-transmitter/custody problem overnight. Out of scope; could be bridged externally later by a party willing to take that on. |
| Chaumian blind signatures | Real public-key crypto, fixed denominations, meaningfully more code and more ways to get it wrong. Re-randomization by hopping (§7) gets most of the practical benefit for v1. |
| Proof-of-work issuance | Webcash's PoW mining exists to make external minting fair and Sybil-resistant. Since this is closed-loop with a governed issuance policy, we don't need it. |
| On-chain settlement | No blockchain. The mint's ledger is a plain key-value store. |

## 3. Core concept

A token is nothing but a **secret** — a random string — plus an **amount**. Whoever holds the secret owns the value it represents. The mint never stores secrets, only hashes of them, so the mint cannot spend anyone's money; it can only answer "has this hash been spent already?"

```
token := aicash:v1:<mint_id>:<amount>:<secret>
```

- `secret`: 32 random bytes, hex or base64url encoded.
- `amount`: unsigned integer, smallest unit = 1 credit (no floats, ever).
- `mint_id`: short identifier for the issuing mint (or, later, federation). Present even in single-mint beta so the client-side format never has to change.

The token string is a **claim**, not proof by itself — validity is whatever the mint's ledger says about `hash(secret)` at the moment it's checked. This matters: a token string can be copied infinitely, but only the first party to redeem the underlying secret with the mint actually gets the value. Copying the string without the recipient successfully exchanging it first gets you nothing.

## 4. The ledger

The mint holds one table:

```
hash(secret) -> { amount: int, spent: bool, created_at, spent_at }
```

That's the entire durable state of the system. No transaction graph, no accounts, no blockchain — just a set of not-yet-redeemed commitments.

## 5. Mint API (single-mint beta)

All endpoints are plain HTTPS + JSON. TLS is doing the transport security; nothing here invents its own crypto beyond hashing.

### `POST /v1/mint`
Issues new credits to a registered agent, subject to the mint's **issuance policy** (see §6). Not a core protocol concern — pluggable per deployment.

```
Request:  { agent_id, requested_amount, auth_token }
Response: { tokens: [ "aicash:v1:...", ... ] }
```

### `POST /v1/exchange`
The one endpoint that does everything: pay, split, merge, make change. Atomic.

```
Request:
{
  idempotency_key: "uuid",
  inputs:  [ "aicash:v1:...", "aicash:v1:..." ],   // secrets being spent, in full
  outputs: [ { amount: 30, secret: "..." },         // new secrets, chosen by the caller
             { amount: 70, secret: "..." } ]
}

Response: { status: "ok", outputs_confirmed: 2 }
```

Server behavior, atomically:
1. Reject if `sum(input amounts) != sum(output amounts)`.
2. Hash every input secret; reject the whole batch if any hash is unknown or already `spent`.
3. Hash every output secret; reject the whole batch if any hash already exists (no overwrites).
4. Mark all inputs `spent`, insert all outputs as new unspent entries.
5. Discard the raw output secrets immediately after hashing — the mint never retains a spendable secret, only ever the hash.

Steps 1–4 happen inside a single atomic transaction (or an equivalent compare-and-set per hash) — this is the only place double-spending can be prevented, so it cannot be best-effort.

`idempotency_key` matters because a client that loses the response after a timeout must be able to retry safely and get the *original* result back rather than erroring on "already spent" or silently double-processing.

### `GET /v1/status/{hash}`
Check whether a given secret's hash is unspent/spent/unknown, without spending it. Useful for crash recovery and for a payee who wants to confirm a token is good before treating a transaction as final.

### `GET /v1/mints`
Federation discovery stub. In beta, returns a single entry describing this mint as a "federation of one." In v2, returns the guardian set and their public keys for a real federation.

## 6. Issuance policy (pluggable, not core protocol)

Since there's no external asset backing credits, something has to govern how they enter circulation. This is deliberately kept outside the core spec so operators can choose their own model:

- **Allocation:** operator grants each registered agent a periodic credit budget (like an API quota).
- **Earned issuance:** an attestation service verifies "agent X completed task Y worth Z credits" and the mint mints Z credits to X. This is how a marketplace of AI-provided services would likely want to bootstrap supply.
- **Purchased allocation (still closed-loop):** a human operator buys a credit pool for their fleet of agents through whatever billing relationship they already have with the mint operator — the *credits themselves* still never redeem back to fiat, only the initial acquisition does, which keeps the protocol itself out of money-transmission territory.

None of this affects §5's `/exchange` endpoint, which is the only part that needs to be identical across every deployment.

## 7. Privacy: re-randomization instead of blinding

Without blind signatures, the mint can see amounts and timing at every `/exchange` call. What it *cannot* see is a labeled "from/to" — there's no sender or recipient field, only "these secrets in, these secrets out." An agent that wants to obscure its transaction history can:

- Route a received token through `/exchange` for a fresh secret of the same value before using it again — severing any timing link between "when I received X" and "when I spent X."
- Split and recombine amounts to avoid amount-based fingerprinting.
- Batch multiple unrelated payments into one `/exchange` call.

This is cash-in-your-pocket-level privacy, not cryptographic unlinkability — the mint operator, if malicious or compelled, can still correlate patterns. Full Chaumian blinding is the natural v2 upgrade if that threat matters more than it does today; it slots in without changing the bearer-token model, only how outputs get authorized.

## 8. Federation upgrade path (v2, not built yet)

The beta explicitly runs as a **single trusted mint**. To upgrade to a federation later:

- `mint_id` in the token format already refers to an abstract minting authority, not literally "one server" — so no token format change is needed.
- Replace the single ledger with an N-of-M threshold scheme across guardian servers (comparable to Fedimint): an `/exchange` call requires threshold agreement rather than one party's database write.
- `GET /v1/mints` starts returning the real guardian set instead of a single stub entry.
- Clients don't need to know or care whether `mint_id` resolves to one server or seven — that's entirely a server-side implementation detail behind the same API shape in §5.

This is why §5's endpoints are specified as opaque operations rather than "the server does X" — so the beta and the eventual federation are the same protocol at different trust configurations.

## 9. Wallet client behavior

A wallet is just a local list of `{ secret, amount, mint_id, status }`.

**To pay:** select unspent tokens covering the amount owed (like coin selection in any UTXO-ish system), generate two new secrets locally — one for the payment amount, one for change — call `/exchange` with the old tokens as inputs and the two new ones as outputs, then hand the payment secret to the recipient out of band (this string transfer *is* the payment).

**Critical ordering rule:** the client MUST persist newly generated output secrets to local storage *before* calling `/exchange`, not after. If the call succeeds but the response never arrives (timeout, crash, dropped connection), the client still has the secrets it generated and can call `/v1/status/{hash}` to find out whether they made it into the ledger. Generating secrets and only saving them after a successful response risks losing money to a network blip.

**On receipt:** the recipient should immediately call `/exchange` to swap the received secret for a freshly generated one before treating the payment as final — this both confirms the token was real and unspent, and performs the re-randomization from §7 in the same step.

## 10. Threat model (beta / single-mint)

| Threat | Mitigation |
|---|---|
| Mint operator double-issues or forges balances | Not cryptographically prevented in beta — explicit trust assumption on the single mint, same as trusting webcash.org or any centralized ledger. This is the primary reason federation (§8) exists as the intended endpoint, not the starting point. |
| Network eavesdropper captures a token in transit | TLS covers the wire; tokens must otherwise be treated like passwords — never logged, never cached in plaintext, never put in URL query strings. |
| Double-spend by racing two `/exchange` calls with the same input | Prevented by an atomic check-and-mark on the hash in step 2–4 of §5; this is the one place the implementation cannot cut corners. |
| Lost token due to client crash mid-payment | Mitigated by the persist-before-send ordering rule in §9 and the `/v1/status` recovery check. |
| Replay of a legitimate retry after a timeout | `idempotency_key` returns the original result instead of erroring or double-processing. |

## 11. Example flow

```
Agent A wants to pay Agent B 30 credits for a completed sub-task.

1. A selects a held token worth 100 credits.
2. A generates two new secrets locally: s_pay (30), s_change (70).
   A persists both to local wallet storage as "pending."
3. A calls POST /v1/exchange:
     inputs:  [ old 100-credit token ]
     outputs: [ {30, s_pay}, {70, s_change} ]
4. Mint atomically spends the 100-credit input, creates two new unspent entries.
5. A marks s_change as "confirmed, held" in its wallet.
6. A sends the token string for s_pay to B (as part of its tool-call response, a
   message, whatever channel A and B already share).
7. B calls POST /v1/exchange to swap s_pay for a fresh secret it controls —
   confirming the payment cleared and re-randomizing in one step.
```

No accounts were created. Neither A nor B had to register with the other. The only shared trust is in the mint.

## 12. Open questions for v2

- Federation guardian selection and threshold-signature scheme (Fedimint-style vs. something lighter).
- Whether to add optional Chaumian blinding as an opt-in mode per mint, and how that interacts with the plaintext-amount mode for mints that don't need it.
- Standard issuance-policy attestation format, if this is meant to support a real marketplace of AI-provided services rather than a single operator's internal fleet.
- Whether a "settle to running balance" endpoint is worth adding for high-volume payees who'd rather not manage bearer-token UTXOs at all (trades bearer-token properties for account-ledger convenience, opt-in per recipient).
