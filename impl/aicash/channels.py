"""C08 — channels: the prefunded incremental channel (spec §9.1, §9.5, §7.3).

Tagged hash chain, tranches, local draws, batch settlement, expiry refund.
Locked decisions L7 (mandatory chain domain separation) and L16 (drawn-but-
unsettled value refunds to the payer at expiry) apply.

Structural properties (component requirements 1–2):

* Chain derivation uses ``sha256(CHAIN_TAG || x)`` for every chain step and
  PLAIN ``sha256(x)`` for every lock commitment — two disjoint functions, so
  no public ledger value reveals a witness (L7, spec R6).  ``derive_chain``
  is the only chain-step function in the codebase and it always prepends the
  tag; ``_lock_hash`` is the only lock-commitment function and never does.
* The payee generates the output secrets; ``ChannelPayer.open`` accepts only
  their HASHES (``payee_hashes``) — the payer funds by hash (§3.3) and can
  never construct the claim path (§3.4, R1).
* ``ChannelPayer.draw`` and ``ChannelPayee.on_draw`` perform no I/O of any
  kind: neither method touches the mint client (assert via transport
  instrumentation in the tests).  A draw is one dict; verification is one
  (or, with subsumption recovery, a few) local SHA-256 evaluations.

Tranche capacity — resolved rule (§9.1, pinned as R18; was OPEN-QUESTIONS #7):
``limits.max_batch`` bounds ``len(inputs)+len(outputs)`` of one
`/v3/exchange` call, and the funding call needs at least one input while the
settlement call needs one output — so the per-tranche increment capacity is
``max_batch − 1`` and a channel of ``N`` increments opens in
``⌈N/(max_batch−1)⌉`` tranches.  Each tranche is funded by exactly ONE
consolidated input (so funding = 1 + m ≤ max_batch) and settled into exactly
ONE output (so settlement = k + 1 ≤ max_batch).  Everything else follows
§9.1 exactly: one funding call, one chain seed and one refund secret per
tranche, one settlement call (one burn) per tranche.  When the wallet's
ladder is too fragmented for the consolidation call itself to fit in
``max_batch`` (payment tokens + 1 output), funding raises ``ChannelError``.

Timestamps are integer ms since epoch UTC (§3.2).  This module NEVER reads
wall time: every temporal decision uses the mint's clock as reported by the
descriptor / status responses (L17).

Secret hygiene: no logging anywhere; exception messages never embed secret
or witness material.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from dataclasses import dataclass, field

from aicash.burncalc import BurnPolicy, compute_burn, effective_policy
from aicash.receipts import ChannelDraw
from aicash.tokencodec import (
    TokenError,
    b64u_decode,
    b64u_encode,
    canonical_json,
    format_token,
    ledger_key,
)
from aicash.wallet import MintClient, Wallet

__all__ = [
    "CHAIN_TAG",
    "derive_chain",
    "split_tranches",
    "ChannelError",
    "ChannelInvalid",
    "DrawInvalid",
    "ChannelInfo",
    "ChannelPayer",
    "ChannelPayee",
]

#: L7 / §9.1: exactly these 12 ASCII bytes, prepended on every chain step.
CHAIN_TAG = b"aicash-chain"
assert CHAIN_TAG == b"aicash-chain" and len(CHAIN_TAG) == 12


# ---------------------------------------------------------------------------
# exceptions
# ---------------------------------------------------------------------------


class ChannelError(Exception):
    """State/timing misuse of the channel protocol (refund before expiry,
    settle inside the safety margin without force, bad draw routing, ...)."""


class ChannelInvalid(ChannelError):
    """The payee's §9.1 open-verification failed: the channel is rejected
    before any work is performed."""


class DrawInvalid(ChannelError):
    """A draw failed verification against the pinned lock-hash list.  Per
    §9.1 this is the stop-work signal; loss is bounded to one increment."""


# ---------------------------------------------------------------------------
# chain derivation (L7 — structural)
# ---------------------------------------------------------------------------


def _chain_step(x: bytes) -> bytes:
    """One chain step: ``x_{i-1} = sha256(CHAIN_TAG || x_i)`` (L7)."""
    return hashlib.sha256(CHAIN_TAG + x).digest()


def _lock_hash(x: bytes) -> str:
    """Lock commitment: PLAIN ``sha256(x)``, b64u — the §3.4 hash (L7)."""
    return b64u_encode(hashlib.sha256(x).digest())


def derive_chain(x_N: bytes, N: int) -> list[bytes]:
    """Derive ``[x_1 .. x_N]`` from the seed ``x_N``.

    ``x_{i-1} = sha256(CHAIN_TAG + x_i)`` — the tagged chain function is
    disjoint from the plain-sha256 lock commitment, so no public lock hash
    is ever a witness (L7, spec R6).
    """
    if not isinstance(x_N, bytes) or len(x_N) != 32:
        raise ValueError("chain seed must be exactly 32 bytes")
    if type(N) is not int or N < 1:
        raise ValueError("N must be a positive int")
    chain = [x_N]
    for _ in range(N - 1):
        chain.append(_chain_step(chain[-1]))
    chain.reverse()  # chain[i] is x_{i+1}
    return chain


def split_tranches(N: int, capacity: int) -> list[int]:
    """§9.1 tranche split: greedy full tranches then the remainder.

    ``capacity`` is the per-tranche increment capacity (``max_batch − 1``
    for a live mint — see the module docstring / OPEN-QUESTIONS #7).
    ``split_tranches(120, 50) == [50, 50, 20]``.
    """
    if type(N) is not int or N < 1:
        raise ValueError("N must be a positive int")
    if type(capacity) is not int or capacity < 1:
        raise ValueError("capacity must be a positive int")
    sizes = []
    remaining = N
    while remaining > 0:
        m = min(capacity, remaining)
        sizes.append(m)
        remaining -= m
    return sizes


# ---------------------------------------------------------------------------
# shared descriptor helpers
# ---------------------------------------------------------------------------


def _policy_from_descriptor(desc: dict) -> BurnPolicy:
    """The burn policy in force per the MINT's clock (L17 — never wall time)."""
    bp = desc["burn_policy"]
    current = BurnPolicy(
        rate_ppm=bp["rate_ppm"],
        cap_mc=bp["cap_mc"],
        exempt_below_mc=bp["exempt_below_mc"],
    )
    nxt = desc.get("burn_policy_next")
    next_t = None
    if nxt is not None:
        np = nxt["policy"]
        next_t = (
            BurnPolicy(
                rate_ppm=np["rate_ppm"],
                cap_mc=np["cap_mc"],
                exempt_below_mc=np["exempt_below_mc"],
            ),
            nxt["effective_at"],
        )
    return effective_policy(current, next_t, desc["mint_time"])


def _gross_for_net(net: int, policy: BurnPolicy) -> int:
    """Least ``G`` with ``G − burn(G) == net`` (§7.3 fixed point).

    ``G ↦ net + burn(G)`` is monotone nondecreasing and bounded by
    ``net + cap_mc``, so iterating from ``net`` stabilizes at an exact
    solution (the burn step is at most 1 per mc since rate_ppm ≤ 10_000).
    """
    g = net
    while True:
        g2 = net + compute_burn(g, policy)
        if g2 == g:
            return g
        g = g2


def _chunks(items: list, size: int):
    for i in range(0, len(items), max(1, size)):
        yield items[i : i + size]


# ---------------------------------------------------------------------------
# ChannelInfo — what the payer hands the payee (no secrets, no chain seeds)
# ---------------------------------------------------------------------------


@dataclass
class ChannelInfo:
    """The tranche layout the payer sends the payee after funding (§9.1
    step 5).  Contains ONLY public material: the payee's own output hashes
    (in draw order) and the funded lock-hash lists the payee will pin.

    Each tranche dict: ``{"start": int (1-based global draw index of the
    tranche's first increment), "count": int, "secret_hashes": [b64u...],
    "lock_hashes": [b64u...], "expiry": int}``.
    """

    channel_id: str
    mint_id: str
    unit_mc: int
    N: int
    expiry_ms: int  # absolute ms since epoch (the §9.1 T)
    tranches: list = field(default_factory=list)

    #: Exactly the fields of the §9.1 handoff wire object, in one place.
    _WIRE_FIELDS = ("channel_id", "mint_id", "unit_mc", "N", "expiry_ms", "tranches")

    def to_json(self) -> str:
        """The wire form of the payer→payee handoff: §3.3 canonical JSON.

        One object with exactly the keys ``channel_id``, ``mint_id``,
        ``unit_mc``, ``N``, ``expiry_ms``, ``tranches`` (see the class
        docstring for the tranche shape).  Deterministic bytes — the same
        ChannelInfo always serializes identically — and secret-free by
        construction (ChannelInfo carries only public material).
        """
        return canonical_json(
            {name: getattr(self, name) for name in self._WIRE_FIELDS}
        ).decode("utf-8")

    @classmethod
    def from_json(cls, s: str) -> "ChannelInfo":
        """Parse the wire form back into a ChannelInfo.

        Accepts exactly the ``to_json`` shape: a JSON object with exactly
        the six wire keys — no more, no fewer.  Raises ``ChannelInvalid``
        on anything else.  Field-level verification (types, tranche
        layout, on-ledger state) remains ``ChannelPayee.accept``'s job.
        """
        if not isinstance(s, str):
            raise ChannelInvalid("channel wire form must be a JSON string")
        try:
            obj = json.loads(s)
        except json.JSONDecodeError:
            raise ChannelInvalid("channel wire form is not valid JSON") from None
        if not isinstance(obj, dict):
            raise ChannelInvalid("channel wire form must be a JSON object")
        if set(obj) != set(cls._WIRE_FIELDS):
            raise ChannelInvalid(
                "channel wire form must have exactly the keys %s"
                % (cls._WIRE_FIELDS,)
            )
        return cls(**{name: obj[name] for name in cls._WIRE_FIELDS})


# ---------------------------------------------------------------------------
# ChannelPayer
# ---------------------------------------------------------------------------


class ChannelPayer:
    """The payer side: funds via its Wallet, issues local draws, refunds at
    expiry.  One instance manages one channel."""

    def __init__(self, wallet: Wallet):
        if not isinstance(wallet, Wallet):
            raise TypeError("wallet must be a C07 Wallet")
        self._wallet = wallet
        self._client: MintClient = wallet.client
        self._mint_id: str = wallet.mint_id
        self._tranches: list[dict] = []  # private: chain, refund_secret, ...
        self._info: ChannelInfo | None = None
        #: plain tokens recovered by refund() (payer-held; §9.1 refund)
        self.refund_tokens: list[str] = []

    # -- funding helpers --------------------------------------------------

    def _fund_one_input(self, gross: int, policy: BurnPolicy, max_batch: int) -> bytes:
        """Produce ONE ledger entry of exactly ``gross`` mc that this payer
        can spend, sourced from the wallet.

        ``wallet.pay`` returns ladder tokens; one consolidation exchange
        turns them into the single exact-value entry the funding call needs
        (see the module docstring on tranche capacity).  Returns the entry's
        secret.  Burns along the way are ordinary §7.3 per-call burns.
        """
        # A − burn(A) == gross: what the wallet must hand over.
        pay_amount = _gross_for_net(gross, policy)
        tokens = self._wallet.pay(pay_amount)
        if len(tokens) + 1 > max_batch:
            raise ChannelError(
                "wallet ladder too fragmented for this mint's max_batch"
            )
        secret = os.urandom(32)
        self._client.exchange(
            str(uuid.uuid4()),
            tokens,
            [{"amount_mc": gross, "secret_hash": ledger_key(secret), "lock": None}],
        )
        return secret

    def estimate_open_cost(self, unit_mc: int, N: int) -> int:
        """Total mc the wallet will spend ABOVE the locked value ``N·unit_mc``
        for a subsequent ``open(_, unit_mc, N, _)`` — so a payer can budget
        before opening.  Read-only: one descriptor fetch, no exchanges.

        The estimate replays open()'s exact arithmetic per tranche against
        the wallet's CURRENT holdings: the §4.2 coin-selection burn of
        ``wallet.pay`` (including any consolidation-sweep inputs), the
        consolidation call's §7.3 burn, and the funding call's burn.  The
        simulated ladder evolves tranche to tranche (change returns to the
        pool), so multi-tranche opens are estimated exactly.  Exact as long
        as the wallet's holdings and the mint's burn policy do not change
        between the estimate and the open.  Raises ``InsufficientFunds`` /
        ``ChannelError`` exactly where the open itself would.
        """
        if self._info is not None:
            raise ChannelError("channel already opened")
        if type(unit_mc) is not int or unit_mc < 1:
            raise ValueError("unit_mc must be a positive int")
        if type(N) is not int or N < 1:
            raise ValueError("N must be a positive int")
        # Same parameter source as wallet.pay (one descriptor round trip).
        policy, denoms, max_batch = self._wallet._mint_params()
        capacity = max_batch - 1  # §9.1/R18
        if capacity < 1:
            raise ChannelError("mint max_batch too small for channels")

        coins = list(self._wallet._held_coins())
        cost = 0
        sim = 0
        for m in split_tranches(N, capacity):
            gross = _gross_for_net(m * unit_mc, policy)
            pay_amount = _gross_for_net(gross, policy)
            # The consolidation call must fit: payment tokens + 1 output.
            if len(self._wallet._decompose(pay_amount, denoms)) + 1 > max_batch:
                raise ChannelError(
                    "wallet ladder too fragmented for this mint's max_batch"
                )
            # Replay wallet.pay's selection (burn depends on sum(inputs)).
            picked, total = self._wallet._select(
                coins, pay_amount, policy, denoms
            )
            pay_burn = compute_burn(total, policy)
            change = total - pay_amount - pay_burn
            # pay burn + consolidation burn (pay_amount − gross) + funding
            # burn (gross − m·u), all collapsed:
            cost += pay_burn + pay_amount - m * unit_mc
            # Evolve the simulated ladder: spent coins out, change back in.
            picked_keys = {c[0] for c in picked}
            coins = [c for c in coins if c[0] not in picked_keys]
            for amount in self._wallet._decompose(change, denoms):
                sim += 1
                coins.append(("~estimate-%d" % sim, "", amount))
            coins.sort(key=lambda c: (-c[2], c[0]))
        return cost

    # -- open (§9.1 open steps 3–5) ---------------------------------------

    def open(
        self,
        payee_hashes: list[str],
        unit_mc: int,
        N: int,
        expiry_ms: int,
    ) -> ChannelInfo:
        """Fund the channel: tagged chain + one funding call per tranche.

        ``payee_hashes`` are the payee-generated output-secret hashes
        ``h_i = sha256(s_i)`` in draw order (§9.1 step 2) — the payer never
        sees a payee secret.  ``expiry_ms`` is the absolute §9.1 ``T``.
        Returns the ChannelInfo to hand to the payee.
        """
        if self._info is not None:
            raise ChannelError("channel already opened")
        if type(unit_mc) is not int or unit_mc < 1:
            raise ValueError("unit_mc must be a positive int")
        if type(N) is not int or N < 1:
            raise ValueError("N must be a positive int")
        if type(expiry_ms) is not int or expiry_ms < 1:
            raise ValueError("expiry_ms must be a positive int (absolute ms)")
        if not isinstance(payee_hashes, list) or len(payee_hashes) != N:
            raise ValueError("payee_hashes must list exactly N hashes")
        for h in payee_hashes:
            try:
                b64u_decode(h, expect_len=32)
            except TokenError:
                raise ValueError("payee_hashes entries must be b64u sha256 digests") from None
        if len(set(payee_hashes)) != N:
            raise ValueError("payee_hashes must be distinct")

        desc = self._client.descriptor()
        if desc["mint_id"] != self._mint_id:
            raise ChannelError("descriptor mint_id mismatch")
        if expiry_ms <= desc["mint_time"]:
            raise ValueError("expiry_ms is not in the mint's future")
        policy = _policy_from_descriptor(desc)
        max_batch = desc["limits"]["max_batch"]
        capacity = max_batch - 1  # OPEN-QUESTIONS #7 (module docstring)
        if capacity < 1:
            raise ChannelError("mint max_batch too small for channels")

        channel_id: str | None = None
        info_tranches: list[dict] = []
        start = 1
        for m in split_tranches(N, capacity):
            seed = os.urandom(32)
            chain = derive_chain(seed, m)  # [x_1 .. x_m], tranche-local
            lock_hashes = self._tranche_lock_hashes(chain)
            refund_secret = os.urandom(32)
            tranche_hashes = payee_hashes[start - 1 : start - 1 + m]

            # One consolidated input of exactly gross = m·u + burn(gross).
            gross = _gross_for_net(m * unit_mc, policy)
            fund_secret = self._fund_one_input(gross, policy, max_batch)

            funding_key = str(uuid.uuid4())
            outputs = [
                {
                    "amount_mc": unit_mc,
                    "secret_hash": tranche_hashes[i],
                    "lock": {
                        "preimage_hash": lock_hashes[i],
                        "expiry": expiry_ms,
                        "refund_hash": ledger_key(refund_secret),
                    },
                }
                for i in range(m)
            ]
            self._client.exchange(
                funding_key,
                [format_token(self._mint_id, gross, fund_secret)],
                outputs,
            )
            if channel_id is None:
                channel_id = funding_key  # §9.1: first tranche's funding key

            self._tranches.append(
                {
                    "start": start,
                    "count": m,
                    "chain": chain,
                    "refund_secret": refund_secret,
                    "secret_hashes": tranche_hashes,
                    "lock_hashes": lock_hashes,
                    "funding_key": funding_key,
                }
            )
            info_tranches.append(
                {
                    "start": start,
                    "count": m,
                    "secret_hashes": list(tranche_hashes),
                    "lock_hashes": list(lock_hashes),
                    "expiry": expiry_ms,
                }
            )
            start += m

        assert channel_id is not None
        self._info = ChannelInfo(
            channel_id=channel_id,
            mint_id=self._mint_id,
            unit_mc=unit_mc,
            N=N,
            expiry_ms=expiry_ms,
            tranches=info_tranches,
        )
        return self._info

    def _tranche_lock_hashes(self, chain: list[bytes]) -> list[str]:
        """Lock commitments for one tranche: PLAIN sha256 per link (L7).

        Seam for hostile tests (B6): a subclass may corrupt one entry to
        model a payer who funded a garbage lock deep in the ladder.
        """
        return [_lock_hash(x) for x in chain]

    # -- draw (§9.5 channel_draw; fully local — requirement 2) -------------

    def draw(self, k: int) -> dict:
        """The §9.5 ``channel_draw`` object for increment ``k`` (1-based,
        global across tranches).  No I/O whatsoever."""
        if self._info is None:
            raise ChannelError("channel not opened")
        if type(k) is not int or not 1 <= k <= self._info.N:
            raise ChannelError("draw index out of range")
        t, j = self._locate(k)
        return {
            "channel_id": self._info.channel_id,
            "k": k,
            "x_k": b64u_encode(t["chain"][j - 1]),
        }

    def _locate(self, k: int) -> tuple[dict, int]:
        for t in self._tranches:
            if t["start"] <= k < t["start"] + t["count"]:
                return t, k - t["start"] + 1
        raise ChannelError("draw index out of range")  # pragma: no cover

    # -- refund (§9.1 refund; L16) -----------------------------------------

    def refund(self) -> int:
        """At/after expiry (mint clock): refund every unclaimed output, one
        exchange per tranche.  Returns the net mc recovered (§7.3 burns
        deducted).  Refuses before expiry (requirement 5)."""
        if self._info is None:
            raise ChannelError("channel not opened")
        desc = self._client.descriptor()
        mint_time = desc["mint_time"]
        if mint_time < self._info.expiry_ms:
            raise ChannelError("channel not yet expired (mint clock)")
        policy = _policy_from_descriptor(desc)
        max_batch = desc["limits"]["max_batch"]
        unit = self._info.unit_mc
        total = 0
        for t in self._tranches:
            unspent: list[str] = []
            for chunk in _chunks(t["secret_hashes"], max_batch):
                _mt, results = self._client.status(chunk)
                for h, r in zip(chunk, results):
                    if r.get("state") == "unspent":
                        unspent.append(h)
            if not unspent:
                continue
            witness = b64u_encode(t["refund_secret"])
            inputs = [{"hash": h, "witness": witness} for h in unspent]
            gross = len(unspent) * unit
            net = gross - compute_burn(gross, policy)
            secret = os.urandom(32)
            self._client.exchange(
                str(uuid.uuid4()),
                inputs,
                [{"amount_mc": net, "secret_hash": ledger_key(secret), "lock": None}],
            )
            self.refund_tokens.append(format_token(self._mint_id, net, secret))
            total += net
        return total


# ---------------------------------------------------------------------------
# ChannelPayee
# ---------------------------------------------------------------------------


class ChannelPayee:
    """The payee side: verifies the funded channel (§9.1 verify), verifies
    draws locally, settles per tranche before expiry."""

    def __init__(
        self,
        client: MintClient,
        mint_id: str,
        *,
        settle_margin_ms: int = 5_000,
        min_lifetime_ms: int = 60_000,
        wallet=None,
    ):
        """``wallet`` (optional): when provided, ``settle()`` immediately
        credits each settled token into it — via ``wallet.receive_batch``
        when the wallet has one, else ``wallet.receive`` per token — and
        returns the net credited mc.  When None (the default), settled
        tokens accumulate in ``settled_tokens`` exactly as before."""
        if not isinstance(client, MintClient):
            raise TypeError("client must be a MintClient")
        self._client = client
        self._mint_id = mint_id
        self._settle_margin_ms = settle_margin_ms
        self._min_lifetime_ms = min_lifetime_ms
        self._wallet = wallet
        self._info: ChannelInfo | None = None
        self._secrets: list[bytes] = []
        self._tranches: list[dict] = []  # verified witnesses, settled sets
        self._grace_ms: int | None = None
        #: plain tokens produced by settle() (payee-held settled value)
        self.settled_tokens: list[str] = []

    # -- accept (§9.1 verify — requirement 6) ------------------------------

    def accept(
        self,
        info: ChannelInfo | str,
        secrets: list[bytes],
        *,
        expect_unit_mc: int | None = None,
        expect_n: int | None = None,
        expect_expiry_ms: int | None = None,
    ) -> None:
        """Verify the funded channel per §9.1 before any work.

        ``info`` is the payer's handoff: a ChannelInfo, or its wire form —
        the ``ChannelInfo.to_json`` canonical-JSON string as received from
        a stranger payer across a process boundary.

        Checks, in order: agreed terms (optional ``expect_*`` from the
        handshake), structural layout, the payee's OWN secret-hash list in
        draw order, then one batch `/v3/status` round trip per tranche:
        every output unspent, amount ``unit_mc``, locked with expiry ``T``
        and EXACTLY the pinned lock-hash list, and finally the
        ``T − mint_time`` lifetime margin.  Raises ChannelInvalid on any
        failure.  The chain's internal structure is deliberately NOT
        verifiable here (§9.1 opacity) — a garbage lock deep in the ladder
        is discovered at its draw, bounding loss to one increment.
        """
        if self._info is not None:
            raise ChannelError("channel already accepted")
        if isinstance(info, str):
            info = ChannelInfo.from_json(info)
        if not isinstance(info, ChannelInfo):
            raise ChannelInvalid("info must be a ChannelInfo")
        if not isinstance(info.channel_id, str) or not info.channel_id:
            raise ChannelInvalid("missing channel_id")
        if info.mint_id != self._mint_id:
            raise ChannelInvalid("wrong mint")
        if type(info.unit_mc) is not int or info.unit_mc < 1:
            raise ChannelInvalid("bad unit")
        if type(info.N) is not int or info.N < 1:
            raise ChannelInvalid("bad N")
        if type(info.expiry_ms) is not int or info.expiry_ms < 1:
            raise ChannelInvalid("bad expiry")
        if expect_unit_mc is not None and info.unit_mc != expect_unit_mc:
            raise ChannelInvalid("unit differs from the agreed handshake")
        if expect_n is not None and info.N != expect_n:
            raise ChannelInvalid("N differs from the agreed handshake")
        if expect_expiry_ms is not None and info.expiry_ms != expect_expiry_ms:
            raise ChannelInvalid("expiry differs from the agreed handshake")

        # Structural layout: contiguous 1-based tranches covering 1..N.
        if not isinstance(info.tranches, list) or not info.tranches:
            raise ChannelInvalid("missing tranche layout")
        expected_start = 1
        for t in info.tranches:
            if (
                not isinstance(t, dict)
                or t.get("start") != expected_start
                or type(t.get("count")) is not int
                or t["count"] < 1
                or not isinstance(t.get("secret_hashes"), list)
                or not isinstance(t.get("lock_hashes"), list)
                or len(t["secret_hashes"]) != t["count"]
                or len(t["lock_hashes"]) != t["count"]
                or t.get("expiry") != info.expiry_ms
            ):
                raise ChannelInvalid("malformed tranche layout")
            for lh in t["lock_hashes"]:
                try:
                    b64u_decode(lh, expect_len=32)
                except TokenError:
                    raise ChannelInvalid("malformed lock hash") from None
            expected_start += t["count"]
        if expected_start - 1 != info.N:
            raise ChannelInvalid("tranche counts do not sum to N")

        # The payer must have funded EXACTLY this payee's hashes, in order.
        if len(secrets) != info.N:
            raise ChannelInvalid("need exactly N output secrets")
        expected_hashes = []
        for s in secrets:
            if not isinstance(s, bytes) or len(s) != 32:
                raise ChannelInvalid("output secrets must be 32 bytes each")
            expected_hashes.append(ledger_key(s))
        declared = [h for t in info.tranches for h in t["secret_hashes"]]
        if declared != expected_hashes:
            raise ChannelInvalid("funded outputs are not this payee's hashes")
        if len(set(declared)) != info.N:
            raise ChannelInvalid("duplicate outputs")

        desc = self._client.descriptor()
        max_batch = desc["limits"]["max_batch"]
        self._grace_ms = desc["lock_params"]["grace_ms"]

        # One batch-status round trip per tranche (§9.1 verify).
        mint_time = None
        for t in info.tranches:
            offset = 0
            for chunk in _chunks(t["secret_hashes"], max_batch):
                mint_time, results = self._client.status(chunk)
                for i, r in enumerate(results):
                    idx = offset + i
                    if r.get("state") != "unspent":
                        raise ChannelInvalid(
                            "output %d not unspent on the ledger" % (t["start"] + idx)
                        )
                    if r.get("amount_mc") != info.unit_mc:
                        raise ChannelInvalid(
                            "output %d has the wrong amount" % (t["start"] + idx)
                        )
                    lock = r.get("lock")
                    if not isinstance(lock, dict):
                        raise ChannelInvalid(
                            "output %d is not locked" % (t["start"] + idx)
                        )
                    if lock.get("expiry") != info.expiry_ms:
                        raise ChannelInvalid(
                            "output %d has the wrong expiry" % (t["start"] + idx)
                        )
                    if lock.get("preimage_hash") != t["lock_hashes"][idx]:
                        raise ChannelInvalid(
                            "output %d lock does not match the pinned hash list"
                            % (t["start"] + idx)
                        )
                offset += len(chunk)
        assert mint_time is not None

        # T − mint_time must comfortably exceed work + settlement margin.
        if info.expiry_ms - mint_time < self._min_lifetime_ms:
            raise ChannelInvalid(
                "expiry too soon: T − mint_time = %d ms is below this"
                " payee's min_lifetime_ms=%d"
                % (info.expiry_ms - mint_time, self._min_lifetime_ms)
            )

        self._info = info
        self._secrets = list(secrets)
        self._tranches = [
            {
                "start": t["start"],
                "count": t["count"],
                "lock_hashes": list(t["lock_hashes"]),
                "verified": {},  # local index (1-based) -> witness bytes
                "settled": set(),
            }
            for t in info.tranches
        ]

    # -- on_draw (fully local — requirement 2; subsumption — requirement 3) -

    @staticmethod
    def _normalize_witness(value) -> bytes:
        """A §9.5 witness as EITHER raw 32 bytes (the ``parse_envelope``
        ChannelDraw form) OR a base64url string (the wire-dict form),
        normalized to raw 32 bytes.  DrawInvalid on anything else."""
        if isinstance(value, bytes):
            if len(value) != 32:
                raise DrawInvalid("malformed witness")
            return value
        try:
            return b64u_decode(value, expect_len=32)
        except TokenError:
            raise DrawInvalid("malformed witness") from None

    def _cumulative(self) -> int:
        return sum(len(t["verified"]) for t in self._tranches)

    def on_draw(self, draw) -> int:
        """Verify one §9.5 ``channel_draw`` locally; returns the cumulative
        count of verified increments.

        ``draw`` may be either the wire dict emitted by
        ``ChannelPayer.draw()`` (``x_k`` a base64url string) OR the
        ``ChannelDraw`` object produced by C12 ``parse_envelope`` (``x_k``
        already decoded to raw 32 bytes).  The witness is normalized on
        entry — decoded when a string, length-checked either way — so the
        parse-the-envelope-then-hand-``channel_draw``-to-``on_draw``
        integrator path and the raw-wire-dict path both verify (§9.5 seam).

        Subsumption recovery: from ``x_k`` every missed earlier witness of
        the same tranche is derived via the tagged chain step and verified
        against its pinned lock hash.  Any mismatch raises DrawInvalid (the
        stop-work signal); witnesses already verified during the walk are
        kept, so loss stays bounded to the single bad increment.  No I/O.
        """
        if self._info is None:
            raise ChannelError("no accepted channel")
        if isinstance(draw, dict):
            channel_id, k, x_k_field = draw.get("channel_id"), draw.get("k"), draw.get("x_k")
        elif isinstance(draw, ChannelDraw):
            channel_id, k, x_k_field = draw.channel_id, draw.k, draw.x_k
        else:
            raise DrawInvalid("draw must be a channel_draw dict or ChannelDraw")
        if channel_id != self._info.channel_id:
            raise ChannelError("draw is for a different channel")
        if type(k) is not int or not 1 <= k <= self._info.N:
            raise DrawInvalid("draw index out of range")
        x_k = self._normalize_witness(x_k_field)

        t, j = self._locate(k)
        verified: dict = t["verified"]
        if j in verified:
            # Re-delivery must match what was already verified.
            if x_k != verified[j]:
                raise DrawInvalid("witness differs from the verified one")
            return self._cumulative()

        walked: list[tuple[int, bytes]] = []
        i, x = j, x_k
        bad = False
        while i >= 1 and i not in verified:
            if _lock_hash(x) != t["lock_hashes"][i - 1]:
                bad = True
                break
            walked.append((i, x))
            x = _chain_step(x)  # x_{i-1} = sha256(CHAIN_TAG || x_i)
            i -= 1
        for idx, w in walked:
            verified[idx] = w
        if bad:
            raise DrawInvalid("witness does not match pinned lock hash %d" % i)
        return self._cumulative()

    def _locate(self, k: int) -> tuple[dict, int]:
        for t in self._tranches:
            if t["start"] <= k < t["start"] + t["count"]:
                return t, k - t["start"] + 1
        raise ChannelError("draw index out of range")  # pragma: no cover

    # -- settle (§9.1 settle — requirements 4 and 5) ------------------------

    def settle(self, force: bool = False) -> int:
        """Redeem all verified-but-unsettled draws: ONE exchange (one §7.3
        burn) per tranche.

        Without a wallet (``wallet=None`` at construction): returns the net
        mc settled and appends the fresh plain tokens to
        ``settled_tokens`` — unchanged behavior.  With a wallet: feeds this
        call's settled token strings straight into it —
        ``wallet.receive_batch(tokens)`` when available (the C07 batch
        redeem: one call, one burn; its ``credited_mc`` — or a plain int
        return from a duck-typed wallet — is passed through), else
        ``wallet.receive(token)`` per token — and returns the net mc
        actually credited (the settled net minus the receive burn(s)); the
        consumed strings are NOT kept in ``settled_tokens``.

        Refuses to run at/inside the client-side safety margin
        ``expiry − grace_ms − settle_margin_ms`` (mint clock) unless
        ``force=True`` (requirement 5; §9.1 "settle no later than ...").
        """
        if self._info is None:
            raise ChannelError("no accepted channel")
        desc = self._client.descriptor()
        mint_time = desc["mint_time"]
        grace = self._grace_ms
        assert grace is not None
        deadline = self._info.expiry_ms - grace - self._settle_margin_ms
        if not force and mint_time >= deadline:
            raise ChannelError(
                "inside the settlement safety margin; pass force=True to attempt anyway"
            )
        policy = _policy_from_descriptor(desc)
        unit = self._info.unit_mc
        total = 0
        fresh_tokens: list[str] = []
        for t in self._tranches:
            todo = sorted(set(t["verified"]) - t["settled"])
            if not todo:
                continue
            inputs = [
                {
                    "token": format_token(
                        self._mint_id, unit, self._secrets[t["start"] - 1 + j - 1]
                    ),
                    "witness": b64u_encode(t["verified"][j]),
                }
                for j in todo
            ]
            gross = len(todo) * unit
            net = gross - compute_burn(gross, policy)
            secret = os.urandom(32)
            self._client.exchange(
                str(uuid.uuid4()),
                inputs,
                [{"amount_mc": net, "secret_hash": ledger_key(secret), "lock": None}],
            )
            t["settled"] |= set(todo)
            token = format_token(self._mint_id, net, secret)
            fresh_tokens.append(token)
            if self._wallet is None:
                self.settled_tokens.append(token)
            total += net
        if self._wallet is None or not fresh_tokens:
            return total
        receive_batch = getattr(self._wallet, "receive_batch", None)
        if callable(receive_batch):
            result = receive_batch(fresh_tokens)
            if isinstance(result, dict):
                # The C07 Wallet shape: {"credited_mc": int, "dead": [...]}.
                return result["credited_mc"]
            return result
        return sum(self._wallet.receive(token) for token in fresh_tokens)
