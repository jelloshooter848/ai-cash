"""C11 — swap: cross-mint atomic swap client (spec §11, §3.5, §8; L6).

Margin computation from two mint descriptors, the two-lock ceremony,
witness discovery by status polling, and the refund paths.  Built on the
C07 ``Wallet``/``MintClient`` against two independent C06 mints — neither
mint ever learns the other exists (§11).

Protocol roles (§11), as implemented by the symmetric ``SwapParty``:

  A holds value at Mint 1 and wants Mint-2 value; B the reverse.
  1. B generates the output secret for the leg it will CLAIM (at Mint 1)
     and sends A only its hash (``prepare_claim``).  A funds a by-hash
     locked output at Mint 1 to that hash, locked to ``sha256(x)`` with
     ``x`` known only to A, expiry ``T`` (``a_fund`` — returns the lock
     hash for B).
  2. A likewise sends B only the hash of A's own claim secret; B verifies
     A's funded leg on Mint 1's ledger, checks the §11 margin
     ``T − T′ ≥ compute_margin(...)``, and funds the Mint-2 leg to A's
     hash, locked to the SAME ``sha256(x)``, expiry ``T′ < T``
     (``b_fund``).
  3. A claims at Mint 2 with its secret + witness ``x`` (``a_claim``).
  4. B discovers ``x`` EXCLUSIVELY from Mint 2's ledger: it polls
     `/v3/status` on its own funded output's hash and reads the
     ``claim_witness`` the moment the entry goes spent (§3.5, L6), then
     claims at Mint 1 before ``T`` (``b_poll_and_claim``).  Structurally
     there is NO side channel: ``b_poll_and_claim`` has no parameter that
     could carry a witness, and nothing else on the B path accepts one.

Either side stalls → both legs refund at their expiries with their refund
secrets (``refund_expired``).  ``refund_expired`` performs no client-side
expiry pre-check: the mint's commit-time evaluation is the authority, so
an early attempt surfaces the mint's ``lock_not_expired`` rejection
(§3.4 — nobody can refund early, and the test proves it at the ledger).

Margin formula (§11, pinned by the component spec)::

    T − T′  >=  grace_ms(M1) + grace_ms(M2)
              + timestamp_precision_ms(M1) + timestamp_precision_ms(M2)
              + polling_interval
              + one status-response latency
              + 2 × redemption latency
              + clock skew (|mint_time(M1) − mint_time(M2)|)

Latency per descriptor: self-attested p99 × 10 when ``performance`` is
present; against a null-``performance`` mint, ``max(60_000,
assumed_latency_ms)`` — or ``QuoteRefused`` when no assumed latency was
supplied ("an uncomputable margin is a reason not to trade, not a reason
to guess", §11).  The two descriptors may attest different latencies; the
three latency slots all use the CONSERVATIVE ``max`` of the two per-mint
estimates (the spec writes the terms with a single "assumed redemption
latency" — logged as OPEN-QUESTIONS #8).  Retention (§11 step 4, §8) is
checked twice: ``compute_margin`` refuses to quote when Mint 2's
published ``retention.recovery_window_ms`` does not cover even the
minimum margin (it never sees ``T``/``T′``), and ``b_fund`` — which has
both expiries in hand — additionally refuses unless the window covers
the ACTUAL horizon ``(T − T′) + dispute margin``: the ``claim_witness``
disclosure only lasts as long as the spent record does.  The spec leaves
the dispute-margin quantity unpinned (OPEN-QUESTIONS #9); the interim
resolution uses the computed §11 minimum margin.

Client-side grace convention (§3.4, R3): a preimage spend is never
submitted within the target mint's ``grace_ms`` of the lock expiry —
``a_claim`` refuses within grace of ``T′``, ``b_poll_and_claim`` within
grace of ``T``.

Time discipline (L17): this module never reads wall time.  Every temporal
decision uses a mint's own clock as reported in its descriptor or status
responses; test timing is driven entirely by the mints' injected clocks
and a virtual poller callback.

Secret hygiene: no logging; no exception message embeds a secret, witness,
or token string.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from dataclasses import dataclass

from aicash.burncalc import BurnPolicy, compute_burn, effective_policy
from aicash.tokencodec import (
    TokenError,
    b64u_decode,
    b64u_encode,
    format_token,
    ledger_key,
    parse_token,
)
from aicash.wallet import MintClient, Wallet

__all__ = [
    "DEFAULT_LATENCY_FLOOR_MS",
    "LATENCY_SAFETY_FACTOR",
    "QuoteRefused",
    "SwapError",
    "SwapParty",
    "SwapResult",
    "compute_margin",
    "run_swap",
]

#: §11: "p99 multiplied by a safety factor of at least 10".
LATENCY_SAFETY_FACTOR = 10

#: §11: "a conservative default of no less than 60 seconds" for a
#: null-``performance`` mint (used as a floor under the caller's assumed
#: latency; with no assumed latency the quote is refused instead).
DEFAULT_LATENCY_FLOOR_MS = 60_000


class SwapError(Exception):
    """State/timing misuse of the swap protocol, or a failed swap step."""


class QuoteRefused(SwapError):
    """§11 refusal to quote/fund: uncomputable margin (null performance,
    no assumed latency), a retention window that does not cover the swap
    horizon, or ``T − T′`` below the computed minimum margin."""


# ---------------------------------------------------------------------------
# margin computation (§11)
# ---------------------------------------------------------------------------


def _descriptor_int(desc: dict, path: tuple, minimum: int = 0) -> int:
    obj = desc
    for part in path:
        if not isinstance(obj, dict) or part not in obj:
            raise ValueError("descriptor missing field %s" % ".".join(path))
        obj = obj[part]
    if type(obj) is not int or obj < minimum:
        raise ValueError("descriptor field %s malformed" % ".".join(path))
    return obj


def _latency_ms(desc: dict, assumed_latency_ms: int | None) -> int:
    """Per-descriptor redemption/status latency estimate (§11).

    Self-attested p99 × ``LATENCY_SAFETY_FACTOR`` when ``performance`` is
    present; otherwise ``max(DEFAULT_LATENCY_FLOOR_MS, assumed)``, or
    QuoteRefused when the caller supplied no assumed latency.
    """
    perf = desc.get("performance")
    if perf is not None:
        if not isinstance(perf, dict):
            raise ValueError("descriptor performance malformed")
        p99 = perf.get("p99_exchange_ms")
        if type(p99) is not int or p99 < 0:
            raise ValueError("descriptor p99_exchange_ms malformed")
        return p99 * LATENCY_SAFETY_FACTOR
    if assumed_latency_ms is None:
        raise QuoteRefused(
            "mint performance is null and no assumed latency was supplied"
            " — an uncomputable margin is a reason not to trade (§11)"
        )
    return max(DEFAULT_LATENCY_FLOOR_MS, assumed_latency_ms)


def compute_margin(
    desc1: dict,
    desc2: dict,
    polling_interval_ms: int,
    assumed_latency_ms: int | None,
) -> int:
    """Minimum §11 expiry margin ``T − T′`` for a swap where the Mint-1
    leg expires at ``T`` and the Mint-2 leg at ``T′`` (B polls Mint 2 and
    claims at Mint 1).

    Formula: grace(both) + timestamp precision(both) + B's polling
    interval + one status-response latency + 2 × redemption latency +
    clock skew (from the two descriptors' ``mint_time``).  The latency
    slots use the conservative max of the two per-descriptor estimates
    (module docstring; OPEN-QUESTIONS #8).  Also enforces the floor of
    §11 step 4: Mint 2's ``retention.recovery_window_ms`` must cover at
    least the computed margin — else QuoteRefused.  This function never
    sees ``T``/``T′``; the full step-4 check against the ACTUAL horizon
    ``(T − T′) + dispute margin`` is performed by ``b_fund``.
    """
    if type(polling_interval_ms) is not int or polling_interval_ms < 1:
        raise ValueError("polling_interval_ms must be a positive int")
    if assumed_latency_ms is not None and (
        type(assumed_latency_ms) is not int or assumed_latency_ms < 1
    ):
        raise ValueError("assumed_latency_ms must be None or a positive int")
    grace1 = _descriptor_int(desc1, ("lock_params", "grace_ms"))
    grace2 = _descriptor_int(desc2, ("lock_params", "grace_ms"))
    prec1 = _descriptor_int(desc1, ("lock_params", "timestamp_precision_ms"))
    prec2 = _descriptor_int(desc2, ("lock_params", "timestamp_precision_ms"))
    mint_time1 = _descriptor_int(desc1, ("mint_time",))
    mint_time2 = _descriptor_int(desc2, ("mint_time",))
    latency = max(
        _latency_ms(desc1, assumed_latency_ms),
        _latency_ms(desc2, assumed_latency_ms),
    )
    skew = abs(mint_time1 - mint_time2)
    margin = (
        grace1
        + grace2
        + prec1
        + prec2
        + polling_interval_ms
        + latency  # one status-response latency
        + 2 * latency  # 2 × redemption latency
        + skew
    )
    recovery_window = _descriptor_int(desc2, ("retention", "recovery_window_ms"))
    if recovery_window < margin:
        raise QuoteRefused(
            "mint-2 retention.recovery_window_ms does not cover the swap"
            " horizon (§11 step 4) — the claim witness would not outlive"
            " the margin"
        )
    return margin


# ---------------------------------------------------------------------------
# descriptor / burn helpers (local copies of the C08 conventions)
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
    """Least ``G`` with ``G − burn(G) == net`` (§7.3 fixed point)."""
    g = net
    while True:
        g2 = net + compute_burn(g, policy)
        if g2 == g:
            return g
        g = g2


def _require_hash(name: str, value: object) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a b64u sha256 digest string")
    try:
        b64u_decode(value, expect_len=32)
    except TokenError:
        raise ValueError(f"{name} must be a b64u sha256 digest string") from None
    return value


# ---------------------------------------------------------------------------
# SwapParty
# ---------------------------------------------------------------------------


class SwapParty:
    """One side of a §11 swap: a wallet at its home mint (where it funds
    its leg from) plus a client to the other mint (where it claims).

    The same class serves both roles: ``a_fund``/``a_claim`` for the party
    that generates ``x`` (A), ``b_fund``/``b_poll_and_claim`` for the
    party that discovers ``x`` from the ledger (B).  ``refund_expired``
    serves either role.  One instance runs one swap.
    """

    def __init__(
        self,
        wallet: Wallet,
        other_client: MintClient,
        other_mint_id: str,
        *,
        polling_interval_ms: int = 5_000,
        assumed_latency_ms: int | None = None,
    ):
        if not isinstance(wallet, Wallet):
            raise TypeError("wallet must be a C07 Wallet")
        if not isinstance(other_client, MintClient):
            raise TypeError("other_client must be a MintClient")
        if not isinstance(other_mint_id, str) or not other_mint_id:
            raise ValueError("other_mint_id must be a non-empty string")
        if type(polling_interval_ms) is not int or polling_interval_ms < 1:
            raise ValueError("polling_interval_ms must be a positive int")
        if assumed_latency_ms is not None and (
            type(assumed_latency_ms) is not int or assumed_latency_ms < 1
        ):
            raise ValueError("assumed_latency_ms must be None or a positive int")
        self._wallet = wallet
        self._home_client: MintClient = wallet.client
        self._home_mint_id: str = wallet.mint_id
        self._other_client = other_client
        self._other_mint_id = other_mint_id
        self._polling_interval_ms = polling_interval_ms
        self._assumed_latency_ms = assumed_latency_ms
        # -- per-swap state --------------------------------------------
        self._claim_secret: bytes | None = None  # secret for the leg claimed
        self._x: bytes | None = None  # A only: the swap preimage
        self._funded: dict | None = None  # leg funded at the home mint
        self._claim_leg: dict | None = None  # B only: pinned Mint-1 leg terms
        #: plain tokens produced by successful claims (other-mint value)
        self.claimed_tokens: list[str] = []
        #: plain tokens produced by refund_expired (home-mint value)
        self.refund_tokens: list[str] = []

    # ------------------------------------------------------------------
    # step 0 — each party generates its own output secret (requirement 1)
    # ------------------------------------------------------------------

    def prepare_claim(self) -> str:
        """Generate this party's output secret for the leg it will claim
        at the OTHER mint; return only its hash (the by-hash funding form,
        §3.3).  The counterparty funds to this hash and can never spend
        the output it pays for (§3.4, R1)."""
        if self._claim_secret is not None:
            raise SwapError("claim secret already generated for this swap")
        self._claim_secret = os.urandom(32)
        return ledger_key(self._claim_secret)

    # ------------------------------------------------------------------
    # funding plumbing
    # ------------------------------------------------------------------

    def _fund_locked(
        self, amount_mc: int, out_hash: str, preimage_hash: str, expiry_ms: int
    ) -> None:
        """Fund one by-hash locked output of ``amount_mc`` at the home
        mint: wallet ladder tokens in, exactly one §3.4-locked output out
        (burn per §7.3 on the call).  The refund secret is generated here
        and never leaves this party."""
        if type(amount_mc) is not int or amount_mc < 1:
            raise ValueError("amount_mc must be a positive int")
        if type(expiry_ms) is not int or expiry_ms < 1:
            raise ValueError("expiry_ms must be a positive int (absolute ms)")
        desc = self._home_client.descriptor()
        if desc["mint_id"] != self._home_mint_id:
            raise SwapError("home descriptor mint_id mismatch")
        if expiry_ms <= desc["mint_time"]:
            raise ValueError("expiry_ms is not in the home mint's future")
        policy = _policy_from_descriptor(desc)
        gross = _gross_for_net(amount_mc, policy)
        tokens = self._wallet.pay(gross)
        if len(tokens) + 1 > desc["limits"]["max_batch"]:
            raise SwapError("wallet ladder too fragmented for this mint's max_batch")
        refund_secret = os.urandom(32)
        self._home_client.exchange(
            str(uuid.uuid4()),
            tokens,
            [
                {
                    "amount_mc": amount_mc,
                    "secret_hash": out_hash,
                    "lock": {
                        "preimage_hash": preimage_hash,
                        "expiry": expiry_ms,
                        "refund_hash": ledger_key(refund_secret),
                    },
                }
            ],
        )
        self._funded = {
            "amount_mc": amount_mc,
            "hash": out_hash,
            "expiry": expiry_ms,
            "refund_secret": refund_secret,
        }

    # ------------------------------------------------------------------
    # role A — funds first, generates x, claims at Mint 2
    # ------------------------------------------------------------------

    def a_fund(self, amount_mc: int, counterparty_hash: str, expiry_ms: int) -> str:
        """§11 step 1: fund the Mint-1 leg by hash for the counterparty,
        locked to a fresh ``sha256(x)`` with ``x`` known only to this
        party, expiry ``T``.  Returns the lock hash (b64u) to send to B —
        never ``x`` itself."""
        if self._funded is not None:
            raise SwapError("this party already funded its leg")
        _require_hash("counterparty_hash", counterparty_hash)
        self._x = os.urandom(32)
        x_hash = b64u_encode(hashlib.sha256(self._x).digest())
        self._fund_locked(amount_mc, counterparty_hash, x_hash, expiry_ms)
        return x_hash

    def a_claim(self, amount_mc: int, expiry_ms: int) -> str:
        """§11 step 3: claim the Mint-2 leg with this party's own claim
        secret and its preimage ``x``.  Refuses within the other mint's
        ``grace_ms`` of ``T′`` (the §3.4 client convention — requirement
        3).  Returns the fresh plain token (net of burn) at the other
        mint."""
        if self._claim_secret is None:
            raise SwapError("prepare_claim was never called")
        if self._x is None:
            raise SwapError("this party holds no preimage (it did not fund as A)")
        desc = self._other_client.descriptor()
        if desc["mint_id"] != self._other_mint_id:
            raise SwapError("other descriptor mint_id mismatch")
        grace = desc["lock_params"]["grace_ms"]
        if desc["mint_time"] >= expiry_ms - grace:
            raise SwapError(
                "within grace_ms of the leg's expiry — refusing to submit a"
                " preimage spend (§3.4 client convention)"
            )
        return self._claim_at_other(amount_mc, self._x, desc)

    # ------------------------------------------------------------------
    # role B — verifies, funds second, discovers x from the ledger
    # ------------------------------------------------------------------

    def b_fund(
        self,
        amount_mc: int,
        counterparty_hash: str,
        x_hash: str,
        T: int,
        T_prime: int,
        claim_amount_mc: int,
    ) -> None:
        """§11 step 2: verify A's funded Mint-1 leg, check the expiry
        margin, then fund the Mint-2 leg to the same lock hash.

        Refuses (QuoteRefused) unless ``T − T′ >= compute_margin(...)``
        over the two live descriptors (requirement 3; margin seam
        ``_required_margin``), and unless Mint 2's published
        ``retention.recovery_window_ms`` covers the ACTUAL horizon
        ``(T − T′) + dispute margin`` (§11 step 4 — the claim witness
        must still be readable when B polls, however late within the
        margin B is).  Also verifies on Mint 1's ledger that A
        actually funded ``claim_amount_mc`` to this party's own claim
        hash, locked to ``x_hash`` with expiry ``T`` — B never funds
        against an unfunded or mislocked counterleg."""
        if self._funded is not None:
            raise SwapError("this party already funded its leg")
        if self._claim_secret is None:
            raise SwapError("prepare_claim was never called")
        _require_hash("counterparty_hash", counterparty_hash)
        _require_hash("x_hash", x_hash)
        if type(T) is not int or type(T_prime) is not int:
            raise ValueError("T and T_prime must be ints (absolute ms)")
        if type(claim_amount_mc) is not int or claim_amount_mc < 1:
            raise ValueError("claim_amount_mc must be a positive int")

        desc_other = self._other_client.descriptor()  # Mint 1: B claims there
        desc_home = self._home_client.descriptor()  # Mint 2: B funds & polls
        if desc_other["mint_id"] != self._other_mint_id:
            raise SwapError("other descriptor mint_id mismatch")
        margin = self._required_margin(desc_other, desc_home)
        if T - T_prime < margin:
            raise QuoteRefused(
                "insufficient expiry margin: T − T′ = %d < required %d (§11)"
                % (T - T_prime, margin)
            )

        # §11 step 4: "Before quoting, B MUST check Mint 2's published
        # retention.recovery_window_ms covers T − T′ plus dispute margin" —
        # the ACTUAL swap horizon, not merely the minimum margin (which
        # compute_margin's floor check covers).  A's claim can land any
        # time up to T′ and B may act as late as T: the spent record and
        # its claim_witness must outlive that whole span, plus a dispute
        # margin.  The spec does not pin the dispute-margin quantity
        # (OPEN-QUESTIONS #9); interim resolution: use the §11 computed
        # minimum margin, which budgets every discovery/claim term.
        recovery_window = _descriptor_int(
            desc_home, ("retention", "recovery_window_ms")
        )
        if recovery_window < (T - T_prime) + margin:
            raise QuoteRefused(
                "mint-2 retention.recovery_window_ms %d does not cover the"
                " actual swap horizon T − T′ = %d plus dispute margin %d"
                " (§11 step 4) — the claim witness could prune before B"
                " reads it" % (recovery_window, T - T_prime, margin)
            )

        # Verify A's leg before committing any value (§11 step 2).
        my_hash = ledger_key(self._claim_secret)
        _mt, results = self._other_client.status([my_hash])
        leg = results[0]
        if leg.get("state") != "unspent":
            raise SwapError("counterparty leg is not unspent on mint 1")
        if leg.get("amount_mc") != claim_amount_mc:
            raise SwapError("counterparty leg has the wrong amount")
        lock = leg.get("lock")
        if not isinstance(lock, dict):
            raise SwapError("counterparty leg is not locked")
        if lock.get("preimage_hash") != x_hash:
            raise SwapError("counterparty leg is locked to a different hash")
        if lock.get("expiry") != T:
            raise SwapError("counterparty leg has the wrong expiry")

        self._fund_locked(amount_mc, counterparty_hash, x_hash, T_prime)
        self._claim_leg = {
            "amount_mc": claim_amount_mc,
            "expiry": T,
            "x_hash": x_hash,
        }

    def _required_margin(self, desc_other: dict, desc_home: dict) -> int:
        """The minimum ``T − T′`` this party will accept: the §11 formula.

        Seam for hostile tests: a subclass may return less to model a
        misconfigured B, so the ledger-level consequence of a shrunken
        margin term can be constructed (component benchmark B4)."""
        return compute_margin(
            desc_other,
            desc_home,
            self._polling_interval_ms,
            self._assumed_latency_ms,
        )

    def b_poll_and_claim(self, poller=None, max_polls: int = 1_000) -> str:
        """§11 step 4: poll `/v3/status` on this party's own funded output
        at the home mint (Mint 2); the moment it reads ``spent``, the
        response's ``claim_witness`` IS ``x`` (§3.5, L6).  Then claim the
        Mint-1 leg before ``T``.

        ``x`` is discovered EXCLUSIVELY from the mint's public status
        data: this method deliberately has no parameter that could carry a
        witness (requirement 2).  ``poller`` is an optional callable
        invoked as ``poller(attempt)`` after each unsuccessful poll — in
        tests it advances the injected clocks (virtual polling interval);
        ``max_polls`` bounds the loop.  Returns the fresh plain token (net
        of burn) at the other mint."""
        if self._funded is None or self._claim_leg is None:
            raise SwapError("b_fund was never called")
        assert self._claim_secret is not None  # b_fund requires it
        if type(max_polls) is not int or max_polls < 1:
            raise ValueError("max_polls must be a positive int")
        poll_hash = self._funded["hash"]
        x: bytes | None = None
        for attempt in range(max_polls):
            _mint_time, results = self._home_client.status([poll_hash])
            entry = results[0]
            state = entry.get("state")
            if state == "unknown":
                raise SwapError("funded output unknown at the home mint")
            if state == "spent":
                witness = entry.get("claim_witness")
                if witness is None:
                    raise SwapError(
                        "funded leg was spent via the refund path — no claim"
                        " occurred and there is nothing to discover"
                    )
                x = b64u_decode(witness, expect_len=32)
                break
            if poller is not None:
                poller(attempt)
        if x is None:
            raise SwapError("poll budget exhausted before a claim was observed")
        # Defense in depth: the disclosed witness must open the pinned lock.
        if b64u_encode(hashlib.sha256(x).digest()) != self._claim_leg["x_hash"]:
            raise SwapError(
                "disclosed claim_witness does not match the pinned lock hash"
            )
        desc = self._other_client.descriptor()
        if desc["mint_id"] != self._other_mint_id:
            raise SwapError("other descriptor mint_id mismatch")
        grace = desc["lock_params"]["grace_ms"]
        if desc["mint_time"] >= self._claim_leg["expiry"] - grace:
            raise SwapError(
                "witness discovered inside grace_ms of T — refusing to submit"
                " a preimage spend (§3.4 client convention)"
            )
        return self._claim_at_other(self._claim_leg["amount_mc"], x, desc)

    # ------------------------------------------------------------------
    # shared claim / refund
    # ------------------------------------------------------------------

    def _claim_at_other(self, amount_mc: int, x: bytes, desc: dict) -> str:
        """Claim the locked leg at the other mint: input = this party's
        own output token + witness ``x`` (§3.4 claim path); output = one
        fresh unlocked entry net of the §7.3 burn."""
        policy = _policy_from_descriptor(desc)
        net = amount_mc - compute_burn(amount_mc, policy)
        if net < 1:
            raise SwapError("leg amount would be entirely consumed by the burn")
        fresh = os.urandom(32)
        self._other_client.exchange(
            str(uuid.uuid4()),
            [
                {
                    "token": format_token(
                        self._other_mint_id, amount_mc, self._claim_secret
                    ),
                    "witness": b64u_encode(x),
                }
            ],
            [{"amount_mc": net, "secret_hash": ledger_key(fresh), "lock": None}],
        )
        token = format_token(self._other_mint_id, net, fresh)
        self.claimed_tokens.append(token)
        return token

    def refund_expired(self) -> int:
        """Refund the leg this party funded at its home mint via the §3.4
        refund path (ledger hash + refund witness, no token secret — L5).

        No client-side expiry pre-check: the mint's commit-time clock is
        the authority, so calling before expiry surfaces the mint's
        ``lock_not_expired`` rejection (``MintRejected``).  Returns the
        net mc recovered; the fresh token lands in ``refund_tokens``."""
        if self._funded is None:
            raise SwapError("this party funded no leg")
        if self._funded.get("refunded"):
            raise SwapError("leg already refunded")
        desc = self._home_client.descriptor()
        policy = _policy_from_descriptor(desc)
        amount = self._funded["amount_mc"]
        net = amount - compute_burn(amount, policy)
        if net < 1:
            raise SwapError("refund would be entirely consumed by the burn")
        fresh = os.urandom(32)
        self._home_client.exchange(
            str(uuid.uuid4()),
            [
                {
                    "hash": self._funded["hash"],
                    "witness": b64u_encode(self._funded["refund_secret"]),
                }
            ],
            [{"amount_mc": net, "secret_hash": ledger_key(fresh), "lock": None}],
        )
        self._funded["refunded"] = True
        token = format_token(self._home_mint_id, net, fresh)
        self.refund_tokens.append(token)
        return net


# ---------------------------------------------------------------------------
# orchestration helper
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SwapResult:
    """Outcome of a completed happy-path swap."""

    a_token: str  # A's claimed Mint-2 value (plain token, net of burn)
    b_token: str  # B's claimed Mint-1 value (plain token, net of burn)
    a_net_mc: int
    b_net_mc: int
    x_hash: str  # the shared §3.4 lock hash (public)
    T: int
    T_prime: int


def run_swap(
    a: SwapParty,
    b: SwapParty,
    amounts: tuple[int, int],
    T: int,
    T_prime: int,
    *,
    poller=None,
) -> SwapResult:
    """Run the full §11 ceremony: hashes exchanged, A funds Mint 1 with
    ``amounts[0]`` (expiry ``T``), B verifies and funds Mint 2 with
    ``amounts[1]`` (expiry ``T′``), A claims, B discovers ``x`` by status
    polling and claims.  ``poller`` is passed through to
    ``b_poll_and_claim``."""
    if not isinstance(a, SwapParty) or not isinstance(b, SwapParty):
        raise TypeError("a and b must be SwapParty instances")
    amount1, amount2 = amounts
    b_hash = b.prepare_claim()
    a_hash = a.prepare_claim()
    x_hash = a.a_fund(amount1, b_hash, T)
    b.b_fund(amount2, a_hash, x_hash, T, T_prime, claim_amount_mc=amount1)
    a_token = a.a_claim(amount2, T_prime)
    b_token = b.b_poll_and_claim(poller=poller)
    return SwapResult(
        a_token=a_token,
        b_token=b_token,
        a_net_mc=parse_token(a_token).amount_mc,
        b_net_mc=parse_token(b_token).amount_mc,
        x_hash=x_hash,
        T=T,
        T_prime=T_prime,
    )
