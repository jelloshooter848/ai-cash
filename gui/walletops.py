"""GUI wallet operations — a thin, honest wrapper over ``aicash.wallet.Wallet``.

This module is NOT protocol.  It adds no rules, changes no mint behaviour and
writes nothing into ``impl/aicash``.  It exists so a local operator GUI can
drive a wallet without catching six different library exceptions and without
ever showing a traceback to a human who pasted a bad token string.

What it adds over ``Wallet``
----------------------------
* every failure raised out of this module is a ``WalletOpsError`` carrying a
  short ``.reason`` (fits on a button: "already spent") and a long
  ``.detail`` (an engineer can debug from it).  Concretely: every sqlite
  call this module makes, directly or through ``Wallet``, is inside a
  ``_store_errors`` guard, so a closed handle, a corrupt file, a locked db
  or cross-thread misuse surfaces as ``WalletOpsError`` and never as a raw
  ``sqlite3.Error``;
* ``summary()`` never raises merely because the MINT is down — it reports
  the wallet's last known held balance with ``connected=False``.  It does
  raise when the STORE itself cannot be read, and when the store's coins
  belong to a different mint than the one now answering: see "failures are
  never collapsed" below;
* ``receive()`` takes a LIST and uses ``Wallet.receive_batch``, so a batch
  pays ONE burn on the input sum (§3.3 burn-once / §7.3) instead of one burn
  per token, and a single spent or malformed token is dropped without
  discarding the good tokens sent with it;
* ``history()`` reconstructs a transaction log from the wallet's own sqlite,
  READ-ONLY, over ONE connection and ONE snapshot.  See the limitations
  below — they are real.

FAILURES ARE NEVER COLLAPSED
----------------------------
"Balance 0" must mean "this wallet holds nothing", never "something went
wrong".  Three unrelated conditions are therefore reported three ways:

=========================  =====================================
the MINT is not answering  ``connected=False`` plus the real, locally
                           readable balance and the mint_id the held
                           coins were issued by.  No exception.
the STORE cannot be read   ``WalletOpsError("wallet store error" /
                           "wallet file unusable")``.  Never a
                           fabricated zero.
the store's coins belong   ``WalletOpsError("wrong mint")`` from
to another mint            ``summary`` / ``pay`` / ``quote``, naming
                           both mint ids.  Never a balance presented
                           as spendable against a mint that will not
                           honour it.
=========================  =====================================

FILES, SIDE EFFECTS AND CONTAINMENT
-----------------------------------
This module writes exactly ONE file: the wallet store itself, at the
``store_path`` it was constructed with.  There is no sidecar, no cache
file and no second artefact of any kind, so the pinned workdir layout
(``var/wallets/<name>.db``, one sqlite file per named wallet) holds
exactly.  It never creates a directory either: if the parent directory of
``store_path`` does not exist the call fails with a clear error rather
than materialising a tree somewhere on the filesystem.

``summary()`` DOES create the store file when the mint is reachable and
the file does not exist yet.  That is deliberate and is the mechanism
``POST /api/wallet/create`` uses to materialise a new wallet.  It is the
only write ``summary()`` performs; reads of an existing wallet touch
nothing.

THREADING
---------
A ``WalletOps`` instance is thread-affine, because the sqlite connection
inside ``Wallet`` is: the thread that first opens the store owns it.
Every public method takes an instance lock, and use from a second thread
raises ``WalletOpsError("wallet busy elsewhere")`` rather than sqlite's
"SQLite objects created in a thread can only be used in that same
thread".  A threaded server should build one ``WalletOps`` per request
(which is what ``gui/app.py`` does) rather than share one.

HISTORY: WHAT THE EXISTING SCHEMA CAN AND CANNOT TELL US
--------------------------------------------------------
The wallet store has exactly two tables and neither has a clock column::

    wallet_tokens(key, secret, amount_mc, state, role, op_id, reserved_by)
    wallet_ops(op_id, kind, state, request_json)

``op_id`` is a random uuid4, so it sorts by nothing.  Therefore:

* **There are no timestamps.  None.**  ``ts_ms`` is returned as ``0`` on
  every row.  It is a placeholder to satisfy the agreed shape, not data.
  A UI must not render it as a date.  Ordering comes from the sqlite
  ``rowid`` of ``wallet_ops``, which is insertion order — the order the
  operations were *planned*, which for this single-threaded wallet is also
  the order they were attempted.  It is not wall-clock time and it cannot
  be compared against anything outside this one store.  Producing a real
  ``ts_ms`` would need a clock column in the wallet schema or a second
  file beside the store; both are ruled out here, so the field is
  honestly inert rather than quietly invented.
* ``pay`` and ``pay_many`` are both recorded as kind ``pay``.  A fan-out to
  three recipients is indistinguishable from one payment of the total, and
  the per-recipient split is not recoverable.
* There is **no counterparty information anywhere** — not who paid us, not
  who we paid.  ``detail`` can only describe amounts.
* A payment that was handed over is terminal in the store.  Whether the
  payee actually redeemed it is not knowable locally; a refusal appears
  only as a separate later ``refused`` op.
* Operator issuance (``/admin/issue``) is not a wallet operation, so money
  arriving from the mint operator shows up only as the ``receive`` that
  redeemed it.
* Tokens retired by ``_mark_dead_if_ours`` (a copy we held that was
  consumed elsewhere) generate no op row and so no history row.
* For an op that did NOT commit (``failed`` / still ``planned``) the amount
  is reported as ``0``, because no value moved; the attempted amount is put
  in ``detail`` instead.  The kind is suffixed ``_failed`` / ``_pending``.

What IS honest and is therefore what ``history()`` returns: per committed
op, the direction (receive / pay / refused), the value that actually moved,
and the burn the mint actually charged — burn is derived as
``sum(input face amounts) - sum(output amounts)`` from the stored plan,
which is the arithmetic the mint itself enforced (§3.3 conservation).

DECLARED RETURN SHAPES (the contract fixes some of these loosely; these
are the exact shapes a caller may rely on)
-----------------------------------------------------------------------
``summary()``  -> ``{"balance_mc": int, "mint_id": str, "coin_count": int,
                  "connected": bool}`` — exactly these four keys.
                  ``mint_id`` is ``""`` only when it is genuinely unknown
                  (a store with no recorded operation, mint down).  When
                  ``connected`` is True the ``mint_id`` is the live mint's
                  AND every held coin has been checked to belong to it.
``receive()``  -> ``{"accepted_mc": int, "accepted": int,
                  "rejected": [{"token": str, "reason": str,
                  "detail": str}]}``
``quote()``    -> ``{"amount_mc": int, "burn_mc": int, "change_mc": int,
                  "inputs_mc": int}`` — a superset of the contract's
                  unspecified ``dict``; ``inputs_mc == amount_mc +
                  burn_mc + change_mc`` always.
``pay()``      -> ``{"tokens": [str], "amount_mc": int, "burn_mc": int}``
``recover()``  -> ``Wallet.recover``'s counters, passed through unchanged.
``history()``  -> ``[{"ts_ms": int, "kind": str, "amount_mc": int,
                  "detail": str}]``, newest first.  ``kind`` is drawn from
                  a CLOSED set — a caller may switch on it exhaustively::

                      receive   receive_failed   receive_pending
                      pay       pay_failed       pay_pending
                      refused   refused_failed   refused_pending

                  plus, only if a NEWER wallet build writes an op kind
                  this one does not know, that kind verbatim with the same
                  three suffixes.  Treat an unrecognised ``kind`` as
                  "some operation", read ``detail``, and do not crash.
                  ``amount_mc`` is ALWAYS a non-negative magnitude: there
                  is no sign convention, the direction lives in ``kind``
                  (``receive``/``refused`` in, ``pay`` out), and it is
                  ``0`` for any op that did not commit.
"""

from __future__ import annotations

import contextlib
import json
import os
import sqlite3
import sys
import threading
import urllib.request

_IMPL = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "impl"
)
if _IMPL not in sys.path:
    sys.path.insert(0, _IMPL)

from aicash.tokencodec import TokenError, parse_token  # noqa: E402
from aicash.wallet import (  # noqa: E402
    InsufficientFunds,
    MintClient,
    MintRejected,
    MintUnavailable,
    PaymentInvalid,
    Wallet,
)

__all__ = ["WalletOps", "WalletOpsError"]


# ---------------------------------------------------------------------------
# errors
# ---------------------------------------------------------------------------


class WalletOpsError(Exception):
    """One error type for the whole GUI surface.

    ``.reason`` is a short human phrase safe to put on a button or a toast.
    ``.detail`` is the long form: the underlying exception type, the §3.8
    reasons the mint enumerated, the store path — whatever an engineer
    needs.  Neither field ever contains a secret or a token string.
    """

    def __init__(self, reason: str, detail: str = ""):
        self.reason = str(reason)
        self.detail = str(detail)
        super().__init__(self.reason if not self.detail
                         else f"{self.reason}: {self.detail}")


#: §3.8 / lock-evaluation reasons -> short phrase, long explanation.
_REASONS: dict[str, tuple[str, str]] = {
    "spent": (
        "already spent",
        "the mint has already retired this token's ledger entry — bearer"
        " value is one-shot (§3.8 spent); somebody redeemed it first",
    ),
    "unknown": (
        "not from this mint",
        "the mint has no ledger entry for this token (§3.8 unknown): it was"
        " issued by a different mint, or the mint's database was replaced",
    ),
    "bad_format": (
        "malformed token",
        "the string is not a well-formed aicash token for this mint (§3.8"
        " bad_format): a truncated paste, or not a token at all",
    ),
    "lock_preimage_invalid": (
        "wrong lock secret",
        "the token is locked and the preimage presented does not open it",
    ),
    "bad_witness_length": (
        "bad lock witness",
        "the token is locked and the witness supplied is the wrong length",
    ),
    "lock_expired": (
        "lock expired",
        "the token's lock deadline has passed; only the refund path applies",
    ),
    "lock_not_expired": (
        "refund too early",
        "the token's lock has not expired yet, so a refund claim is invalid",
    ),
    "refund_invalid": (
        "not refundable",
        "this token has no refund path the mint will honour",
    ),
    "amount_mismatch": (
        "amount mismatch",
        "inputs did not equal outputs plus the mint's burn (§3.3"
        " conservation); the wallet built an unbalanced exchange",
    ),
    "idempotency_conflict": (
        "duplicate request",
        "an exchange was replayed under the same idempotency key with"
        " different contents (§3.3)",
    ),
}

#: ``bad_format`` means two very different things depending on where it
#: came from.  On ``receive`` the operator pasted the string, so "check
#: your paste" is actionable.  On ``pay`` / ``recover`` the operator typed
#: a number and pasted nothing: the offending strings are the wallet's OWN
#: stored coins, so the real fault is a store bound to the wrong mint, and
#: telling the operator their paste is malformed would be nonsense.
_OWN_COINS_BAD_FORMAT = (
    "coins not from this mint",
    "the mint rejected this wallet's own stored coins as not its own (§3.8"
    " bad_format).  Nothing you typed is wrong: the store is bound to a"
    " different mint than the one answering on this address — check the"
    " mint_id the mint was started with",
)


def _explain(reason, where: str = "receive") -> tuple[str, str]:
    key = str(reason)
    if key == "bad_format" and where not in ("receive", "paste"):
        return _OWN_COINS_BAD_FORMAT
    if key in _REASONS:
        return _REASONS[key]
    return (key or "rejected", f"mint rejection reason {key!r} (§3.8)")


def _reasons_of(errors) -> list[str]:
    out = []
    for e in errors or ():
        if isinstance(e, dict) and e.get("reason") is not None:
            out.append(str(e["reason"]))
    return out


def _from_rejection(errors, where: str) -> WalletOpsError:
    reasons = _reasons_of(errors)
    if not reasons:
        return WalletOpsError(
            "rejected by mint", f"{where}: the mint rejected the exchange"
            " without naming a reason"
        )
    short, long = _explain(reasons[0], where)
    if len(set(reasons)) > 1:
        short = "rejected by mint"
    return WalletOpsError(
        short,
        f"{where}: mint rejected the exchange, §3.8 reasons "
        + ", ".join(sorted(set(reasons)))
        + f" — {long}",
    )


def _unavailable(exc: Exception, base_url: str) -> WalletOpsError:
    return WalletOpsError(
        "mint unreachable",
        f"could not talk to the mint at {base_url}: {type(exc).__name__}:"
        f" {exc} — is the mint running on that port?",
    )


# ---------------------------------------------------------------------------
# WalletOps
# ---------------------------------------------------------------------------

_HELD = "confirmed"  # the only spendable state in wallet.py

#: sqlite has a bound on host parameters per statement; chunk IN () lists.
_SQL_CHUNK = 200


class WalletOps:
    """Operations on ONE named wallet store against ONE mint base_url.

    Construction touches nothing: no file is created and no HTTP call is
    made, so building a ``WalletOps`` for a stopped mint is safe.  The
    underlying ``Wallet`` is opened lazily on the first operation that
    genuinely needs the mint (the ``Wallet`` constructor needs the
    descriptor's ``mint_id``).

    Thread-affine — see the module docstring.  One instance per request.
    """

    def __init__(self, store_path: str, base_url: str) -> None:
        self._store_path = os.path.abspath(str(store_path))
        self._base_url = str(base_url).rstrip("/")
        self._wallet: Wallet | None = None
        self._owner: int | None = None
        self._lock = threading.RLock()

    # -- paths ----------------------------------------------------------

    @property
    def store_path(self) -> str:
        return self._store_path

    @property
    def base_url(self) -> str:
        return self._base_url

    # -- threading ------------------------------------------------------

    @contextlib.contextmanager
    def _entered(self):
        """Serialise one public call and refuse cross-thread reuse.

        sqlite connections belong to the thread that opened them.  Rather
        than let that surface as a raw ``sqlite3.ProgrammingError``, an
        instance that already owns an open store refuses a second thread
        by name.
        """
        if not self._lock.acquire(timeout=30.0):
            raise WalletOpsError(
                "wallet busy elsewhere",
                f"another operation on {self._store_path} is still running"
                " after 30s; a WalletOps instance serves one caller at a"
                " time — build one per request",
            )
        try:
            me = threading.get_ident()
            if self._wallet is not None and self._owner not in (None, me):
                raise WalletOpsError(
                    "wallet busy elsewhere",
                    f"{self._store_path} was opened on thread"
                    f" {self._owner} and sqlite handles cannot cross"
                    " threads; build one WalletOps per thread/request"
                    " instead of sharing this one",
                )
            yield
        finally:
            self._lock.release()

    # -- error guards ---------------------------------------------------

    @contextlib.contextmanager
    def _store_errors(self, where: str):
        """Every sqlite failure inside becomes exactly one WalletOpsError.

        This is the guard that makes the module docstring's promise true:
        corruption, permission denied, a locked database, a closed handle
        and cross-thread misuse all come out as ``wallet store error``
        with the underlying sqlite type and message in ``.detail``.
        """
        try:
            yield
        except sqlite3.Error as exc:
            raise WalletOpsError(
                "wallet store error",
                f"{where}: sqlite failure on {self._store_path}:"
                f" {type(exc).__name__}: {exc}",
            ) from exc

    # -- mint plumbing --------------------------------------------------

    def _client(self) -> MintClient:
        try:
            return MintClient(self._base_url)
        except ValueError as exc:
            raise WalletOpsError(
                "bad mint address",
                f"{self._base_url!r} is not a usable mint base url"
                f" (expected http://host:port): {exc}",
            ) from exc

    def descriptor(self) -> dict:
        """The mint's §3.6 descriptor.  Raises WalletOpsError if it is down."""
        client = self._client()
        try:
            return client.descriptor()
        except MintUnavailable as exc:
            raise _unavailable(exc, self._base_url) from exc
        except (KeyError, TypeError, ValueError) as exc:
            raise WalletOpsError(
                "bad mint response",
                f"the mint at {self._base_url} returned a descriptor this"
                f" build cannot read: {type(exc).__name__}: {exc}",
            ) from exc

    def _live_mint_id(self) -> str | None:
        """The answering mint's id, or None when it is simply not there.

        Only DOWNTIME returns None.  A base_url that is not a usable mint
        address, or a mint answering with an unreadable descriptor, is a
        misconfiguration and still raises — collapsing those into "mint is
        down" would tell the operator to start a mint that is already
        running.
        """
        desc = None
        try:
            desc = self.descriptor()
        except WalletOpsError as exc:
            if exc.reason == "mint unreachable":
                return None
            raise
        mint_id = desc.get("mint_id")
        if not isinstance(mint_id, str) or not mint_id:
            raise WalletOpsError(
                "bad mint response",
                f"the descriptor from {self._base_url} carries no mint_id",
            )
        return mint_id

    def _open(self, mint_id: str | None = None) -> Wallet:
        """Open (creating if needed) the wallet store.  Needs the mint up.

        Re-checks the binding on every call: if the mint answering on this
        address now calls itself something else (the operator restarted it
        under a new mint_id — one click in this GUI), the cached ``Wallet``
        is dropped and rebound, so we never send a stale mint's tokens or
        report a stale mint's id.
        """
        if mint_id is None:
            mint_id = self._live_mint_id()
            if mint_id is None:
                raise _unavailable(
                    MintUnavailable("no descriptor"), self._base_url
                )
        if self._wallet is not None:
            if self._wallet.mint_id == mint_id:
                return self._wallet
            self._close_locked()  # identity changed under us: rebind
        parent = os.path.dirname(self._store_path) or "."
        if not os.path.isdir(parent):
            raise WalletOpsError(
                "wallet folder missing",
                f"{parent} does not exist, and this module never creates"
                f" directories; create the wallets folder first",
            )
        try:
            self._wallet = Wallet(self._store_path, self._client(), mint_id)
        except sqlite3.Error as exc:
            raise WalletOpsError(
                "wallet file unusable",
                f"sqlite could not open {self._store_path}:"
                f" {type(exc).__name__}: {exc}",
            ) from exc
        except OSError as exc:
            raise WalletOpsError(
                "wallet file unusable",
                f"could not create {self._store_path}:"
                f" {type(exc).__name__}: {exc}",
            ) from exc
        self._owner = threading.get_ident()
        return self._wallet

    def _close_locked(self) -> None:
        w, self._wallet, self._owner = self._wallet, None, None
        if w is not None:
            # Wallet exposes no close(); the handle is private and this is
            # the one place this module reaches for it.  app.py relies on
            # close() to avoid leaking a handle per polled request.
            try:
                w._db.close()
            except sqlite3.Error:
                pass

    def close(self) -> None:
        """Release the sqlite handle.  Idempotent; never raises.

        Beyond the pinned contract, and deliberately so: ``gui/app.py``
        builds one WalletOps per HTTP request and calls this in a finally
        block, without which a polled wallet list leaks a handle per poll.
        """
        with self._lock:
            self._close_locked()

    # -- read-only store access ----------------------------------------

    def _connect_ro(self) -> sqlite3.Connection | None:
        """A READ-ONLY connection to the store, or None if it does not exist.

        ``mode=ro`` means this can never create the file and never mutates
        a byte of it.  sqlite failures are NOT swallowed: they propagate
        to the caller's ``_store_errors`` guard, because "this file cannot
        be read" and "this wallet is empty" must not look alike.
        """
        if not os.path.exists(self._store_path):
            return None
        uri = "file:" + urllib.request.pathname2url(self._store_path) + "?mode=ro"
        return sqlite3.connect(uri, uri=True)

    def _read(self, sql: str, params: tuple, where: str) -> list[tuple] | None:
        """One read-only query.  None ONLY when the store does not exist."""
        with self._store_errors(where):
            conn = self._connect_ro()
            if conn is None:
                return None
            try:
                return conn.execute(sql, params).fetchall()
            finally:
                conn.close()

    def _held(self) -> tuple[int, int]:
        """(balance_mc, coin_count) of spendable coins, without the mint."""
        if self._wallet is not None:
            with self._store_errors("balance"):
                rows = self._wallet._db.execute(
                    "SELECT COALESCE(SUM(amount_mc), 0), COUNT(*)"
                    " FROM wallet_tokens WHERE state = ?",
                    (_HELD,),
                ).fetchall()
        else:
            rows = self._read(
                "SELECT COALESCE(SUM(amount_mc), 0), COUNT(*)"
                " FROM wallet_tokens WHERE state = ?",
                (_HELD,),
                "balance",
            )
        if not rows:
            return 0, 0
        return int(rows[0][0] or 0), int(rows[0][1] or 0)

    def _balance(self, wallet: Wallet, where: str) -> int:
        with self._store_errors(where):
            return int(wallet.balance())

    # -- which mint does this store's money belong to? ------------------

    def _held_by_mint(self) -> list[tuple[str, int, int]]:
        """[(mint_id, held_mc, coin_count)] over CURRENTLY HELD value.

        A held coin was created as an output of some op; that op's stored
        plan lists the input token strings it was exchanged from, and a
        token string carries its mint_id.  So the mint a coin is worth
        money at is recoverable exactly, without a schema change and
        without trusting any cache.  ``mint_id`` is ``""`` for an op whose
        inputs could not be parsed.  Newest op first.
        """
        rows = self._read(
            "SELECT o.request_json, COALESCE(SUM(t.amount_mc), 0), COUNT(*)"
            " FROM wallet_tokens t JOIN wallet_ops o ON o.op_id = t.op_id"
            " WHERE t.state = ? GROUP BY o.op_id ORDER BY o.rowid DESC",
            (_HELD,),
            "mint binding",
        )
        merged: dict[str, list[int]] = {}
        order: list[str] = []
        for request_json, total, count in rows or ():
            mint_id = _plan_mint_id(request_json)
            if mint_id not in merged:
                merged[mint_id] = [0, 0]
                order.append(mint_id)
            merged[mint_id][0] += int(total or 0)
            merged[mint_id][1] += int(count or 0)
        return [(m, merged[m][0], merged[m][1]) for m in order]

    def _known_mint_id(self) -> str:
        """Best effort mint_id while the mint is DOWN.

        Preferred source: the mint the currently held coins were issued
        by.  Fallback for a wallet that holds nothing right now: the most
        recent operation's inputs.  Returns "" when the store has never
        recorded an operation at all — honestly unknown, not invented.
        """
        for mint_id, _mc, _n in self._held_by_mint():
            if mint_id:
                return mint_id
        rows = self._read(
            "SELECT request_json FROM wallet_ops ORDER BY rowid DESC LIMIT 20",
            (),
            "mint binding",
        )
        for (request_json,) in rows or ():
            mint_id = _plan_mint_id(request_json)
            if mint_id:
                return mint_id
        return ""

    def _assert_binding(self, live_mint_id: str, where: str) -> None:
        """Refuse to treat another mint's coins as money at this mint.

        Restarting the mint under a different mint_id on the same port is
        one click in this GUI.  The held coins are then worthless here —
        the ledger has no entry for them — and presenting their total as a
        balance, or trying to spend it, is the one confidently-wrong
        number a money UI must never show.
        """
        for mint_id, mc, count in self._held_by_mint():
            if mint_id and mint_id != live_mint_id:
                raise WalletOpsError(
                    "wrong mint",
                    f"this wallet holds {mc} mc ({count} coin"
                    f"{'' if count == 1 else 's'}) issued by mint"
                    f" {mint_id!r}, but the mint answering at"
                    f" {self._base_url} calls itself {live_mint_id!r}."
                    f" {live_mint_id!r} has no ledger entry for those"
                    f" coins, so they cannot be spent or counted here"
                    f" ({where}).  Restart the mint with mint_id"
                    f" {mint_id!r} to reach this money again.",
                )

    # -- the contract ---------------------------------------------------

    def summary(self) -> dict:
        """{"balance_mc", "mint_id", "coin_count", "connected"}.

        Never raises for a mint that is merely down: ``connected`` is
        False and the balance is the last known held value read straight
        off the local store, which is the truth about what this wallet
        holds regardless of whether the mint is answering.  ``mint_id`` is
        then the mint that money belongs to, read out of the store — never
        a live id that would contradict ``connected=False``.

        It DOES raise, rather than report a fabricated zero, when the
        store cannot be read at all, and when the held coins belong to a
        different mint than the one now answering.

        Side effect: when the mint is reachable and the store file does
        not exist yet, it is created (this is how a new wallet is
        materialised).  Nothing else is ever written.
        """
        with self._entered():
            live = self._live_mint_id()
            if live is None:
                balance, count = self._held()
                return {
                    "balance_mc": balance,
                    "mint_id": self._known_mint_id(),
                    "coin_count": count,
                    "connected": False,
                }
            self._assert_binding(live, "summary")
            self._open(live)
            balance, count = self._held()
            return {
                "balance_mc": balance,
                "mint_id": live,
                "coin_count": count,
                "connected": True,
            }

    def receive(self, tokens: list[str]) -> dict:
        """Redeem a batch of pasted token strings.

        ONE ``/v3/exchange`` for the whole batch, so ONE burn on the input
        sum rather than a burn per token (§3.3, §7.3, §9.2).  A token that
        is spent, unknown or malformed is reported in ``rejected`` and the
        remaining good tokens are re-sent under a fresh idempotency key —
        one bad paste never costs the caller the good tokens beside it.

        Returns {"accepted_mc", "accepted", "rejected": [{token, reason,
        detail}]}.  ``accepted_mc`` is NET of the burn.
        """
        if not isinstance(tokens, list) or not all(
            isinstance(t, str) for t in tokens
        ):
            raise WalletOpsError(
                "bad request",
                "receive() takes a list of token strings; got"
                f" {type(tokens).__name__}",
            )
        if not tokens:
            return {"accepted_mc": 0, "accepted": 0, "rejected": []}
        with self._entered():
            wallet = self._open()
            try:
                with self._store_errors("receive"):
                    result = wallet.receive_batch(tokens)
            except PaymentInvalid as exc:
                raise _from_rejection(exc.errors, "receive") from exc
            except MintRejected as exc:
                raise _from_rejection(exc.errors, "receive") from exc
            except MintUnavailable as exc:
                raise _unavailable(exc, self._base_url) from exc
            except ValueError as exc:
                raise WalletOpsError("bad request", f"receive: {exc}") from exc
            rejected = []
            for dead in result.get("dead", []):
                i = dead.get("index")
                token = tokens[i] if isinstance(i, int) and 0 <= i < len(
                    tokens) else ""
                short, long = self._explain_paste(
                    dead.get("reason"), token, wallet.mint_id)
                rejected.append(
                    {"token": token, "reason": short, "detail": long}
                )
            accepted_mc = int(result.get("credited_mc", 0))
            return {
                "accepted_mc": accepted_mc,
                "accepted": len(tokens) - len(rejected),
                "rejected": rejected,
            }

    @staticmethod
    def _explain_paste(reason, token: str, mint_id: str) -> tuple[str, str]:
        """Reason for ONE rejected pasted token, refined locally.

        ``Wallet.receive_batch`` maps a perfectly well-formed token from
        ANOTHER mint to ``bad_format`` before any HTTP call, so the §3.8
        table alone would tell the operator to re-copy a paste that is in
        fact intact.  Re-parsing the string here recovers the distinction:
        parses fine but names a different mint -> "not from this mint",
        with both ids in the detail.
        """
        if str(reason) == "bad_format" and token:
            try:
                tok = parse_token(token)
            except TokenError:
                pass
            else:
                if tok.mint_id != mint_id:
                    return (
                        "not from this mint",
                        f"this is a well-formed token — nothing is wrong"
                        f" with the paste — but it was issued by mint"
                        f" {tok.mint_id!r} and this wallet is connected to"
                        f" {mint_id!r}.  Only {mint_id!r} can redeem it.",
                    )
        return _explain(reason, "paste")

    def quote(self, amount_mc: int) -> dict:
        """Dry run of ``pay(amount_mc)``: what it would cost, no mutation.

        {"amount_mc", "burn_mc", "change_mc", "inputs_mc"} where
        ``inputs_mc == amount_mc + burn_mc + change_mc``.  The burn is a
        function of the INPUT sum, not of the amount (§7.3), so overshoot
        and the anti-fragmentation sweep can raise it — that is exactly
        what this exposes.
        """
        amount_mc = _amount(amount_mc, "quote")
        with self._entered():
            live = self._live_mint_id()
            if live is None:
                raise _unavailable(
                    MintUnavailable("no descriptor"), self._base_url
                )
            self._assert_binding(live, "quote")
            wallet = self._open(live)
            try:
                with self._store_errors("quote"):
                    q = wallet.quote(amount_mc)
            except InsufficientFunds as exc:
                raise _insufficient(exc, self._held()[0], amount_mc) from exc
            except MintUnavailable as exc:
                raise _unavailable(exc, self._base_url) from exc
            except ValueError as exc:
                raise WalletOpsError("bad amount", f"quote: {exc}") from exc
            return {
                "amount_mc": amount_mc,
                "burn_mc": int(q["burn_mc"]),
                "change_mc": int(q["change_mc"]),
                "inputs_mc": int(q["inputs_mc"]),
            }

    def pay(self, amount_mc: int) -> dict:
        """Produce bearer token strings totalling ``amount_mc``.

        {"tokens", "amount_mc", "burn_mc"}.  ``burn_mc`` is measured, not
        predicted: it is the drop in held balance minus the amount paid,
        which is precisely what the mint burned on this exchange.
        """
        amount_mc = _amount(amount_mc, "pay")
        with self._entered():
            live = self._live_mint_id()
            if live is None:
                raise _unavailable(
                    MintUnavailable("no descriptor"), self._base_url
                )
            self._assert_binding(live, "pay")
            wallet = self._open(live)
            before = self._balance(wallet, "pay")
            try:
                with self._store_errors("pay"):
                    tokens = wallet.pay(amount_mc)
            except InsufficientFunds as exc:
                raise _insufficient(exc, before, amount_mc) from exc
            except MintRejected as exc:
                raise _from_rejection(exc.errors, "pay") from exc
            except PaymentInvalid as exc:
                raise _from_rejection(exc.errors, "pay") from exc
            except MintUnavailable as exc:
                raise _unavailable(exc, self._base_url) from exc
            except ValueError as exc:
                raise WalletOpsError("bad amount", f"pay: {exc}") from exc
            after = self._balance(wallet, "pay")
            return {
                "tokens": list(tokens),
                "amount_mc": amount_mc,
                "burn_mc": max(0, (before - after) - amount_mc),
            }

    def recover(self) -> dict:
        """Resolve operations left in flight by a crash, against the mint.

        Passes through ``Wallet.recover``'s summary counters unchanged.
        Deliberately NOT gated on the mint-binding check: resolving an
        in-flight op against whatever mint is there is exactly what a
        stranded operator needs, and recover() moves no new value.
        """
        with self._entered():
            wallet = self._open()
            try:
                with self._store_errors("recover"):
                    return dict(wallet.recover())
            except MintUnavailable as exc:
                raise _unavailable(exc, self._base_url) from exc
            except MintRejected as exc:
                raise _from_rejection(exc.errors, "recover") from exc

    def history(self, *, limit: int = 50) -> list[dict]:
        """Reconstructed transaction log, newest first.

        Rows are ``{"ts_ms", "kind", "amount_mc", "detail"}``.  READ THE
        MODULE DOCSTRING before trusting a field: the store has no clock,
        so ``ts_ms`` is always ``0`` and "newest first" means newest by
        sqlite insertion order, not by time.  ``kind`` is drawn from the
        closed set listed in the module docstring; ``amount_mc`` is always
        a non-negative magnitude, direction lives in ``kind``.

        Reads the store READ-ONLY over ONE connection, so the page a
        caller gets is one consistent snapshot even if the wallet is being
        written to at the same time.  Raises rather than returning ``[]``
        when the store cannot be read: "no activity" and "unreadable" are
        not the same answer.
        """
        if type(limit) is not int or limit <= 0:
            raise WalletOpsError(
                "bad request", f"limit must be a positive int, got {limit!r}"
            )
        with self._entered():
            with self._store_errors("history"):
                conn = self._connect_ro()
                if conn is None:
                    return []
                try:
                    ops = conn.execute(
                        "SELECT op_id, kind, state, request_json FROM"
                        " wallet_ops ORDER BY rowid DESC LIMIT ?",
                        (limit,),
                    ).fetchall()
                    if not ops:
                        return []
                    out_by_op = _outputs_by_op(conn, [o[0] for o in ops])
                finally:
                    conn.close()
        return [
            _history_row(op_id, kind, state, request_json,
                         out_by_op.get(op_id, {}))
            for op_id, kind, state, request_json in ops
        ]


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _outputs_by_op(conn, op_ids: list) -> dict:
    """{op_id: {role: total_mc}} for many ops in ONE grouped query.

    Deliberately not one query per row: ``history()`` is polled, and a
    per-row query is both an N+1 and a different snapshot per row.
    """
    out: dict = {}
    for start in range(0, len(op_ids), _SQL_CHUNK):
        chunk = op_ids[start:start + _SQL_CHUNK]
        marks = ",".join("?" * len(chunk))
        rows = conn.execute(
            "SELECT op_id, role, COALESCE(SUM(amount_mc), 0) FROM"
            f" wallet_tokens WHERE op_id IN ({marks}) GROUP BY op_id, role",
            tuple(chunk),
        ).fetchall()
        for op_id, role, total in rows:
            out.setdefault(op_id, {})[str(role)] = int(total or 0)
    return out


def _history_row(op_id, kind, state, request_json, out_by_role: dict) -> dict:
    inputs = _plan_inputs(request_json)
    face_in, unparsed = 0, 0
    for tok in inputs:
        try:
            face_in += parse_token(tok).amount_mc
        except TokenError:
            unparsed += 1
    out_total = sum(out_by_role.values())
    # The mint's conservation rule is sum(in) == sum(out) + burn (§3.3),
    # so the burn charged is recoverable exactly — provided every input
    # token string parsed.
    burn = face_in - out_total if not unparsed else None
    burn_txt = f"burn {burn} mc" if burn is not None and burn >= 0 else \
        "burn not reconstructible"

    committed = state == "done"
    suffix = "" if committed else (
        "_failed" if state == "failed" else "_pending"
    )
    if kind == "pay":
        paid = out_by_role.get("payment", 0)
        change = out_by_role.get("change", 0)
        if committed:
            amount, detail = paid, (
                f"paid out {paid} mc, {burn_txt}, {change} mc change"
                " returned to the wallet"
            )
        else:
            amount, detail = 0, (
                f"payment of {paid} mc did not commit"
                f" ({_state_note(state)}); no value left the wallet"
            )
    elif kind == "receive":
        n = len(inputs)
        if committed:
            amount, detail = out_total, (
                f"redeemed {n} token{'' if n == 1 else 's'}"
                f" worth {face_in} mc face, {burn_txt},"
                f" {out_total} mc credited"
            )
        else:
            amount, detail = 0, (
                f"redeeming {n} token{'' if n == 1 else 's'}"
                f" ({face_in} mc face) did not commit"
                f" ({_state_note(state)})"
            )
    elif kind == "refused":
        if committed:
            amount, detail = out_total, (
                f"reclaimed {len(inputs)} refused payment token(s),"
                f" {face_in} mc face, {burn_txt},"
                f" {out_total} mc back in the wallet"
            )
        else:
            amount, detail = 0, (
                f"reclaiming {len(inputs)} refused token(s) did not"
                f" commit ({_state_note(state)})"
            )
    else:  # a kind this build does not know — report, do not invent
        amount = out_total if committed else 0
        detail = (
            f"operation kind {str(kind)!r} recorded by a newer wallet"
            f" build; {out_total} mc of outputs, state {state}"
        )
    if unparsed:
        detail += (
            f" — {unparsed} input token string(s) in the stored plan"
            " could not be parsed, so the face total is incomplete"
        )
    return {
        "ts_ms": 0,  # the wallet store keeps no timestamps; see docstring
        "kind": f"{kind}{suffix}",
        "amount_mc": int(amount),
        "detail": detail,
    }


def _state_note(state) -> str:
    if state == "failed":
        return "the mint rejected it"
    if state == "planned":
        return "still unresolved — run recover()"
    return f"state {state}"


def _plan_inputs(request_json) -> list[str]:
    """The plain token strings of a stored plan's inputs.

    Used only to read their FACE AMOUNTS and their mint_id.  These strings
    carry live secrets: they are never returned, logged, or put in a
    detail string.
    """
    try:
        body = json.loads(request_json)
    except (TypeError, ValueError):
        return []
    if not isinstance(body, dict):
        return []
    return [i for i in body.get("inputs", []) if isinstance(i, str)]


def _plan_mint_id(request_json) -> str:
    """The mint_id the inputs of a stored plan were issued by, or ""."""
    for tok in _plan_inputs(request_json):
        try:
            return parse_token(tok).mint_id
        except TokenError:
            continue
    return ""


def _amount(amount_mc, where: str) -> int:
    """Validate an amount BEFORE anything is opened or dialled.

    ``type(x) is not int`` already rejects ``bool`` (``type(True) is
    bool``), so no separate bool clause is needed.  The point of checking
    here rather than leaving it to ``Wallet``'s identical check is that a
    typo must not need a running mint and an open store to be reported:
    ``pay("100")`` says "bad amount" even with the mint stopped.
    """
    if type(amount_mc) is not int:
        raise WalletOpsError(
            "bad amount",
            f"{where}: amount_mc must be a whole number of millicents,"
            f" got {type(amount_mc).__name__}",
        )
    if amount_mc <= 0:
        raise WalletOpsError(
            "bad amount",
            f"{where}: amount_mc must be greater than zero, got {amount_mc}",
        )
    return amount_mc


def _insufficient(exc: Exception, held_mc: int, amount_mc: int) -> WalletOpsError:
    return WalletOpsError(
        "insufficient funds",
        f"cannot pay {amount_mc} mc: the wallet holds {held_mc} mc and the"
        f" burn is charged on top of the amount (§7.3) — {exc}",
    )
