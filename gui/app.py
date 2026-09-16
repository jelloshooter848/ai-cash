#!/usr/bin/env python3
"""Local operator GUI for an aicash mint: one command, one browser tab.

Run it, open the printed URL, and you can start a mint, create wallets,
fund one and pay another without a terminal and without reading the spec.

Nothing here is protocol. This process starts ``run_mint.py`` as a child
(via gui/mintctl.py) and drives ``aicash.wallet.Wallet`` (via
gui/walletops.py); it never reimplements either, and it changes no mint
behaviour. The pieces it does own are the ones a browser forces on you:

  * ONE ORIGIN. The page and every API route are served by this server, so
    the page never makes a cross-origin request and no CORS header is ever
    needed. Anything that must reach the mint is proxied here.
  * THE CREDENTIAL STAYS HERE. The mint's /admin/issue token is read from
    the workdir, used as an ``X-Admin-Token`` header on the server side,
    and scrubbed out of every response body and log line on the way out.
    It is never in page.html and never in a JSON response.
  * LOOPBACK ONLY, AND SAME-ORIGIN ONLY. The listener refuses any
    non-loopback bind address, and refuses a request whose Host header is
    not a loopback name, so a page on the internet cannot rebind DNS and
    drive your mint. It also refuses any request a browser marks as coming
    from another site (Sec-Fetch-Site / Origin), because a cross-site POST
    to 127.0.0.1 needs no rebinding and no CORS permission to fire.
  * NO TRACEBACK EVER REACHES THE PAGE. Every route returns JSON; failures
    return ``{"error": {"reason", "detail"}}`` with a detail a non-expert
    can act on.

gui/mintctl.py and gui/walletops.py are written against a pinned contract
and may be missing or newer than this file. Every use of them goes through
_Components, which turns "not importable", "wrong attributes" and "returned
a shape I did not expect" into a plain 503/502 naming the file at fault,
rather than a 500 with a stack trace.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import errno
import ipaddress
import json
import os
import re
import socket
import sys
import threading
import traceback
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
for _p in (HERE, os.path.join(REPO, "impl")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

DEFAULT_PORT = 8799
DEFAULT_WORKDIR = os.path.join(HERE, "var")
MINT_HTTP_TIMEOUT_S = 15.0
MAX_BODY_BYTES = 1 << 20
# A whole-second deadline on one connection. Without it a client that sends
# "Content-Length: 500" and then four bytes pins a handler thread forever.
REQUEST_TIMEOUT_S = 30
# JSON numbers above 2**53 stop being exact in a browser, and the mint has
# its own bounds anyway; refuse them here with a sentence instead of
# relaying the mint's 500.
MAX_AMOUNT_MC = (1 << 53) - 1
WALLET_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$")
# Mirrors aicash.tokencodec.MINT_ID_RE. Checked here only to give a better
# message than a component exception would; MintControl re-checks it, and the
# mint itself is the authority.
MINT_ID_RE = re.compile(r"^[a-z0-9-]{1,64}$")


class GuiError(Exception):
    """An error with an HTTP status, a machine reason and a human detail."""

    def __init__(self, status: int, reason: str, detail: str):
        super().__init__(f"{reason}: {detail}")
        self.status = status
        self.reason = reason
        self.detail = detail


# ----------------------------------------------------------------------
# the two modules this file does not own
# ----------------------------------------------------------------------
class _Components:
    """Import and call gui/mintctl.py and gui/walletops.py defensively.

    They are built in parallel with this file against the same written
    contract. Coding against the contract is right; *assuming* the contract
    held is not, because the failure mode of a wrong assumption here is a
    500 with a traceback on the operator's screen. So: import lazily (the
    GUI still starts and still explains itself when one file is absent),
    check the attributes the contract names, and validate the shape of
    every return value before the page ever sees it.
    """

    def __init__(self, workdir: str):
        self.workdir = workdir
        self._lock = threading.RLock()
        self._mintctl_mod = None
        self._mint = None
        self._walletops_mod = None

    # -- module loading -------------------------------------------------
    @staticmethod
    def _load(module_name: str, needed: tuple) -> object:
        try:
            module = __import__(module_name)
        except ImportError as exc:
            raise GuiError(
                503, "gui_incomplete",
                f"gui/{module_name}.py could not be imported ({exc}). It is "
                f"part of this GUI and must sit next to app.py. Everything "
                f"that needs it is unavailable until it does; the rest of "
                f"the page still works.")
        except Exception as exc:  # the module itself raised at import time
            raise GuiError(
                500, "component_error",
                f"gui/{module_name}.py failed while being imported "
                f"({type(exc).__name__}: {exc}). Fix that file; this GUI "
                f"cannot work around it.")
        missing = [n for n in needed if not hasattr(module, n)]
        if missing:
            raise GuiError(
                503, "gui_incomplete",
                f"gui/{module_name}.py does not define {', '.join(missing)}. "
                f"It does not match the contract this page was built "
                f"against.")
        return module

    def mint(self):
        """The shared MintControl instance."""
        with self._lock:
            if self._mint is None:
                module = self._load("mintctl", ("MintControl", "MintControlError"))
                try:
                    self._mint = module.MintControl(self.workdir)
                except Exception as exc:
                    raise GuiError(
                        500, "component_error",
                        f"MintControl({self.workdir!r}) raised "
                        f"{type(exc).__name__}: {exc}")
                self._mintctl_mod = module
            return self._mint

    def wallet(self, store_path: str, base_url: str):
        """A fresh WalletOps for one wallet file.

        Fresh per call on purpose: aicash.wallet.Wallet holds an sqlite
        connection, and sqlite connections belong to the thread that made
        them. This is a ThreadingHTTPServer.
        """
        with self._lock:
            if self._walletops_mod is None:
                self._walletops_mod = self._load(
                    "walletops", ("WalletOps", "WalletOpsError"))
            module = self._walletops_mod
        try:
            return module.WalletOps(store_path, base_url)
        except Exception as exc:
            raise self._translate(exc, f"WalletOps({os.path.basename(store_path)})")

    # -- calling --------------------------------------------------------
    @staticmethod
    def _reason(text) -> str:
        """One machine vocabulary for `error.reason`, whatever the source.

        The components phrase their reasons for a human ("insufficient
        funds"); this file phrases its own for a machine ("bad_request").
        A client cannot switch on a mixture, so every reason that leaves
        here is snake_case. The human sentence is `detail`, which is
        passed through untouched.
        """
        slug = re.sub(r"[^a-z0-9]+", "_", str(text).strip().lower()).strip("_")
        return slug[:60] or "error"

    def _translate(self, exc: BaseException, what: str) -> GuiError:
        """Turn a component exception into a GuiError, keeping its message."""
        if isinstance(exc, GuiError):
            return exc
        ops_err = getattr(self._walletops_mod, "WalletOpsError", None)
        if ops_err is not None and isinstance(exc, ops_err):
            reason = getattr(exc, "reason", None) or "wallet_error"
            detail = getattr(exc, "detail", None) or str(exc)
            return GuiError(400, self._reason(reason), str(detail) or str(exc))
        mint_err = getattr(self._mintctl_mod, "MintControlError", None)
        if mint_err is not None and isinstance(exc, mint_err):
            return GuiError(400, "mint_control", str(exc) or type(exc).__name__)
        return GuiError(
            500, "component_error",
            f"{what} raised {type(exc).__name__}: {exc}")

    def call(self, what: str, fn, *args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except BaseException as exc:
            raise self._translate(exc, what) from None

    # -- shape checking -------------------------------------------------
    @staticmethod
    def expect_dict(value, what: str, required=()) -> dict:
        if not isinstance(value, dict):
            raise GuiError(
                502, "bad_component_response",
                f"{what} returned {type(value).__name__}, not a dict. That "
                f"file does not match the contract this page expects.")
        missing = [k for k in required if k not in value]
        if missing:
            raise GuiError(
                502, "bad_component_response",
                f"{what} returned a dict without {', '.join(missing)}. That "
                f"file does not match the contract this page expects.")
        return value

    @staticmethod
    def expect_list(value, what: str) -> list:
        if not isinstance(value, list):
            raise GuiError(
                502, "bad_component_response",
                f"{what} returned {type(value).__name__}, not a list. That "
                f"file does not match the contract this page expects.")
        return value


def _as_int(value, default=None):
    """Lenient int for COMPONENT OUTPUT. Never raises: an unexpected shape
    renders as '-' in the UI rather than failing a whole request."""
    if isinstance(value, bool) or value is None:
        return default
    if isinstance(value, int):
        return value
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


_DIGITS_RE = re.compile(r"[+-]?[0-9]+")


def _strict_int(value, default=None):
    """Strict int for CALLER INPUT. Anything that is not exactly a whole
    number is ``default`` (which the callers turn into a 400), never a
    truncation: an amount of 12.7 is a mistake, not twelve."""
    if isinstance(value, bool) or value is None:
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if value.is_integer() else default
    if isinstance(value, str) and _DIGITS_RE.fullmatch(value.strip()):
        return int(value.strip())
    return default


# ----------------------------------------------------------------------
# the API
# ----------------------------------------------------------------------
class Api:
    """Every route's body, independent of HTTP. Raises GuiError; returns JSON-able."""

    def __init__(self, workdir: str):
        self.workdir = os.path.abspath(workdir)
        self.wallets_dir = os.path.join(self.workdir, "wallets")
        os.makedirs(self.wallets_dir, exist_ok=True)
        self.components = _Components(self.workdir)
        self._mint_lock = threading.Lock()
        self._wallet_locks: dict = {}
        self._wallet_locks_guard = threading.Lock()
        self._state_path = os.path.join(self.workdir, "gui-state.json")

    # -- helpers --------------------------------------------------------
    @contextlib.contextmanager
    def _wallet(self, name: str, path: str, base: str):
        """A WalletOps for the length of one request, then released.

        WalletOps owns an sqlite connection. One per request is deliberate
        (sqlite connections belong to the thread that opened them, and this
        is a ThreadingHTTPServer), which makes closing it deliberate too:
        without this, every poll of the wallet list would leak a handle.
        """
        ops = self.components.wallet(path, base)
        try:
            yield ops
        finally:
            closer = getattr(ops, "close", None)
            if callable(closer):
                try:
                    closer()
                except Exception:
                    pass

    def _wallet_lock(self, name: str) -> threading.Lock:
        with self._wallet_locks_guard:
            return self._wallet_locks.setdefault(name, threading.Lock())

    def _remember(self, key: str, value) -> None:
        """Best-effort note-to-self in the workdir. Never fails a request."""
        try:
            try:
                with open(self._state_path) as handle:
                    state = json.load(handle)
            except (OSError, ValueError):
                state = {}
            if not isinstance(state, dict):
                state = {}
            state[key] = value
            tmp = self._state_path + ".tmp"
            with open(tmp, "w") as handle:
                json.dump(state, handle)
            os.replace(tmp, self._state_path)
        except OSError:
            pass

    def _recall(self, key: str, default=None):
        try:
            with open(self._state_path) as handle:
                state = json.load(handle)
            if isinstance(state, dict):
                return state.get(key, default)
        except (OSError, ValueError):
            pass
        return default

    def admin_token(self):
        """The /admin/issue credential. Server-side only; never serialised."""
        control = self.components.mint()
        if not hasattr(control, "admin_token"):
            return None
        token = self.components.call("MintControl.admin_token", control.admin_token)
        return token if isinstance(token, str) and token else None

    def mint_status(self) -> dict:
        control = self.components.mint()
        raw = self.components.call("MintControl.status", control.status)
        raw = self.components.expect_dict(raw, "MintControl.status", ("running",))
        status = {
            "running": bool(raw.get("running")),
            "pid": _as_int(raw.get("pid")),
            "port": _as_int(raw.get("port")),
            "mint_id": raw.get("mint_id") if isinstance(raw.get("mint_id"), str) else None,
            "base_url": raw.get("base_url") if isinstance(raw.get("base_url"), str) else None,
            "started_at_ms": _as_int(raw.get("started_at_ms")),
            "last_error": raw.get("last_error") if isinstance(raw.get("last_error"), str) else None,
        }
        # No _remember() here on purpose: /api/mint/status is a GET, and a
        # GET does not write to the workdir. MintControl.status() keeps the
        # last known port/base_url across a stop by itself, and start()
        # records what a GUI restart would otherwise forget.
        status["last_start"] = self._recall("last_start") or None
        return status

    def base_url(self, *, required: bool) -> str:
        """Where the mint is. Falls back to the last one we saw.

        A stopped mint is not an error for reads: a wallet must still be
        able to show its last known balance, which is what the fallback is
        for. It is an error for anything that needs the mint to answer.
        """
        try:
            status = self.mint_status()
        except GuiError:
            # mintctl itself is broken or absent. A read that only wants the
            # last known state should still work — the wallet files are right
            # there and do not need the supervisor to be healthy.
            if required:
                raise
            return self._recall("last_base_url") or "http://127.0.0.1:8787"
        if status["running"] and status["base_url"]:
            return status["base_url"]
        if required:
            detail = "The mint is not running. Start it in the MINT panel first."
            if status["last_error"]:
                detail += f" Last error: {status['last_error']}"
            raise GuiError(409, "mint_stopped", detail)
        # Stopped: MintControl keeps the last known base_url, and the note
        # written by the last successful start covers a GUI restart with a
        # component that does not.
        return (status["base_url"]
                or self._recall("last_base_url")
                or "http://127.0.0.1:8787")

    def _mint_http(self, method: str, path: str, body=None, *, admin=False):
        """One request to the running mint, from this process."""
        base = self.base_url(required=True)
        data = None if body is None else json.dumps(body).encode()
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if admin:
            token = self.admin_token()
            if token:
                headers["X-Admin-Token"] = token
        request = urllib.request.Request(
            base.rstrip("/") + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=MINT_HTTP_TIMEOUT_S) as response:
                payload = response.read()
                status = response.status
        except urllib.error.HTTPError as exc:  # a real answer, just not 2xx
            payload = exc.read()
            status = exc.code
        except urllib.error.URLError as exc:
            raise GuiError(
                502, "mint_unreachable",
                f"The mint says it is running but did not answer at {base} "
                f"({exc.reason}). Try stopping and starting it.") from None
        except OSError as exc:
            raise GuiError(
                502, "mint_unreachable",
                f"Could not reach the mint at {base}: {exc}") from None
        try:
            obj = json.loads(payload or b"{}")
        except ValueError:
            raise GuiError(
                502, "mint_unreachable",
                f"The mint answered {status} with something that is not "
                f"JSON.") from None
        return status, obj

    # -- mint routes ----------------------------------------------------
    def route_mint_status(self, _query, _body) -> dict:
        return self.mint_status()

    def route_mint_start(self, _query, body) -> dict:
        mint_id = str(body.get("mint_id") or "").strip()
        baseline = str(body.get("baseline_model_class") or "").strip()
        if not MINT_ID_RE.fullmatch(mint_id):
            raise GuiError(
                400, "bad_request",
                "Mint id must be 1-64 characters of lowercase letters, "
                "digits and hyphens, e.g. local-test-mint.")
        if not baseline:
            raise GuiError(
                400, "bad_request",
                "Baseline model class cannot be empty. baseline-v1 is the "
                "usual value.")
        port = _strict_int(body.get("port"))
        if port is None or not 1 <= port <= 65535:
            raise GuiError(400, "bad_request",
                           "Port must be a whole number from 1 to 65535.")
        numbers = {}
        for field, low in (("rate_ppm", 0), ("cap_mc", 0), ("exempt_below_mc", 0)):
            value = _strict_int(body.get(field))
            if value is None or value < low:
                raise GuiError(
                    400, "bad_request",
                    f"{field} must be a whole number of at least {low}.")
            numbers[field] = value
        if not self._mint_lock.acquire(blocking=False):
            raise GuiError(409, "busy",
                           "Another start or stop is already in progress.")
        try:
            control = self.components.mint()
            result = self.components.call(
                "MintControl.start", control.start, mint_id=mint_id,
                baseline_model_class=baseline, port=port, **numbers)
            self.components.expect_dict(result, "MintControl.start", ("running",))
        finally:
            self._mint_lock.release()
        status = self.mint_status()
        # What this mint was actually started with. The page reads it back
        # into the form, so a later Stop/Start cannot quietly re-send the
        # form's defaults and rewrite the mint's economics; and it survives
        # a GUI or browser restart, when the form would otherwise reset.
        started = {"mint_id": mint_id, "baseline_model_class": baseline,
                   "port": port, **numbers}
        self._remember("last_start", started)
        if status.get("base_url"):
            self._remember("last_base_url", status["base_url"])
        status["last_start"] = started
        return status

    def route_mint_stop(self, _query, body) -> dict:
        drain = _strict_int(body.get("drain_seconds"), 10)
        if drain is None or not 0 <= drain <= 120:
            raise GuiError(400, "bad_request",
                           "drain_seconds must be a whole number from 0 to 120.")
        if not self._mint_lock.acquire(blocking=False):
            raise GuiError(409, "busy",
                           "Another start or stop is already in progress.")
        try:
            control = self.components.mint()
            self.components.call("MintControl.stop", control.stop,
                                 drain_seconds=drain)
        finally:
            self._mint_lock.release()
        return self.mint_status()

    def route_mint_logs(self, query, _body) -> dict:
        lines = _strict_int(query.get("lines"), 200) or 200
        lines = max(1, min(lines, 2000))
        control = self.components.mint()
        raw = self.components.call("MintControl.logs", control.logs, lines=lines)
        raw = self.components.expect_list(raw, "MintControl.logs")
        return {"lines": [str(line).rstrip("\n") for line in raw]}

    def route_mint_descriptor(self, _query, _body) -> dict:
        status, obj = self._mint_http("GET", "/v3/mints")
        if status != 200 or not isinstance(obj, dict) or "mint_id" not in obj:
            raise GuiError(
                502, "mint_unreachable",
                f"The mint did not return a descriptor (http {status}).")
        return obj

    def route_mint_issue(self, _query, body) -> dict:
        """§7.1 operator funding. The only place new money is created.

        The token strings exist ONLY in this response: the mint stores
        hashes, never secrets, so a token that is issued and not shown is
        money nobody can ever spend. Hence issue-then-return, and the page
        credits a wallet as a separate step it can retry.
        """
        amount = _strict_int(body.get("amount_mc"))
        count = _strict_int(body.get("count"), 1)
        if amount is None or amount <= 0:
            raise GuiError(400, "bad_request",
                           "Amount must be a whole number of millicredits "
                           "greater than zero.")
        if amount > MAX_AMOUNT_MC:
            raise GuiError(400, "bad_request",
                           f"Amount must be at most {MAX_AMOUNT_MC} "
                           f"millicredits.")
        if count is None or not 1 <= count <= 100:
            raise GuiError(400, "bad_request",
                           "Count must be a whole number from 1 to 100.")
        try:
            from aicash.tokencodec import format_token, ledger_key, new_secret
        except Exception as exc:
            raise GuiError(
                500, "component_error",
                f"Could not load the aicash token codec from impl/ "
                f"({exc}).") from None
        mint_id = self.mint_status()["mint_id"]
        if not mint_id:
            descriptor = self.route_mint_descriptor(None, None)
            mint_id = descriptor.get("mint_id")
        if not isinstance(mint_id, str) or not mint_id:
            raise GuiError(502, "mint_unreachable",
                           "Could not determine which mint is running.")
        secrets = [new_secret() for _ in range(count)]
        outputs = [{"amount_mc": amount, "secret_hash": ledger_key(s)}
                   for s in secrets]
        status, obj = self._mint_http("POST", "/admin/issue",
                                      {"outputs": outputs}, admin=True)
        if status == 401:
            raise GuiError(
                403, "not_authorized",
                "The mint refused the operator credential. It is read from "
                f"{os.path.join(self.workdir, 'mint-admin-keys.json')}; that "
                "file belongs to the mint that is running now.")
        if status != 200:
            raise GuiError(
                502, "issue_rejected",
                f"The mint rejected the issue request (http {status}): "
                f"{json.dumps(obj)[:400]}")
        return {"amount_mc": amount,
                "count": count,
                "total_mc": amount * count,
                "tokens": [format_token(mint_id, amount, s) for s in secrets]}

    def route_token_status(self, query, _body) -> dict:
        text = (query.get("token") or "").strip()
        if not text:
            raise GuiError(400, "bad_request",
                           "Paste a token string or a ledger key to look up.")
        key = text
        if text.startswith("aicash:"):
            parts = text.split(":")
            if len(parts) != 5:
                raise GuiError(400, "bad_token",
                               "That is not a whole token string. A token "
                               "looks like aicash:v3:<mint>:<amount>:<secret>.")
            try:
                from aicash.tokencodec import ledger_key
                pad = "=" * (-len(parts[4]) % 4)
                key = ledger_key(base64.urlsafe_b64decode(parts[4] + pad))
            except Exception:
                raise GuiError(400, "bad_token",
                               "The secret part of that token is not valid "
                               "base64url.") from None
        status, obj = self._mint_http("POST", "/v3/status", {"hashes": [key]})
        if status != 200:
            raise GuiError(502, "mint_unreachable",
                           f"The mint answered http {status} to the status "
                           f"lookup.")
        results = obj.get("results") if isinstance(obj, dict) else None
        first = results[0] if isinstance(results, list) and results else None
        return {"query": text, "ledger_key": key, "result": first, "raw": obj}

    # -- wallet routes --------------------------------------------------
    def _store_path(self, name: str) -> str:
        if not isinstance(name, str) or not WALLET_NAME_RE.fullmatch(name):
            raise GuiError(
                400, "bad_name",
                "A wallet name is 1-32 characters: letters, digits, "
                "hyphen and underscore, starting with a letter or digit.")
        path = os.path.join(self.wallets_dir, name + ".db")
        # Belt and braces over the regex: the name becomes a filename.
        if os.path.dirname(os.path.abspath(path)) != self.wallets_dir:
            raise GuiError(400, "bad_name", "That wallet name is not allowed.")
        return path

    def wallet_names(self) -> list:
        try:
            entries = sorted(os.listdir(self.wallets_dir))
        except OSError as exc:
            raise GuiError(500, "workdir_unreadable",
                           f"Could not read {self.wallets_dir}: {exc}") from None
        return [e[:-3] for e in entries
                if e.endswith(".db") and WALLET_NAME_RE.fullmatch(e[:-3])]

    def _summary(self, name: str, base: str) -> dict:
        """One wallet's summary, degraded rather than fatal."""
        try:
            with self._wallet(name, self._store_path(name), base) as ops:
                raw = self.components.call(
                    f"WalletOps({name}).summary", ops.summary)
                raw = self.components.expect_dict(
                    raw, f"WalletOps({name}).summary")
            return {"name": name,
                    "balance_mc": _as_int(raw.get("balance_mc")),
                    "coin_count": _as_int(raw.get("coin_count")),
                    "mint_id": raw.get("mint_id"),
                    "connected": bool(raw.get("connected")),
                    "error": None}
        except GuiError as exc:
            return {"name": name, "balance_mc": None, "coin_count": None,
                    "mint_id": None, "connected": False, "error": exc.detail}

    def route_wallet_list(self, _query, _body) -> dict:
        base = self.base_url(required=False)
        names = self.wallet_names()
        return {"wallets": [self._summary(n, base) for n in names],
                "dir": self.wallets_dir}

    def route_wallet_create(self, _query, body) -> dict:
        name = str(body.get("name") or "").strip()
        path = self._store_path(name)
        if os.path.exists(path):
            raise GuiError(409, "wallet_exists",
                           f"A wallet called {name} already exists.")
        # A new wallet binds to the running mint's id, so it needs the mint.
        base = self.base_url(required=True)
        with self._wallet_lock(name):
            if os.path.exists(path):
                raise GuiError(409, "wallet_exists",
                               f"A wallet called {name} already exists.")
            summary = self._summary(name, base)
        if summary["error"]:
            # Do not leave a half-made store lying around under a name the
            # operator will try again with.
            if os.path.exists(path) and summary["balance_mc"] in (None, 0):
                try:
                    os.unlink(path)
                except OSError:
                    pass
            raise GuiError(500, "wallet_create_failed", summary["error"])
        return summary

    def _wallet_ops(self, query_or_body) -> tuple:
        name = str(query_or_body.get("name") or "").strip()
        path = self._store_path(name)
        if not os.path.exists(path):
            raise GuiError(404, "wallet_not_found",
                           f"There is no wallet called {name} in "
                           f"{self.wallets_dir}.")
        return name, path

    def route_wallet_summary(self, query, _body) -> dict:
        name, _path = self._wallet_ops(query)
        summary = self._summary(name, self.base_url(required=False))
        if summary["error"] and summary["balance_mc"] is None:
            raise GuiError(502, "wallet_error", summary["error"])
        return summary

    def route_wallet_history(self, query, _body) -> dict:
        name, path = self._wallet_ops(query)
        limit = _strict_int(query.get("limit"), 50) or 50
        limit = max(1, min(limit, 500))
        with self._wallet(name, path, self.base_url(required=False)) as ops:
            rows = self.components.call(f"WalletOps({name}).history",
                                        ops.history, limit=limit)
        rows = self.components.expect_list(rows, f"WalletOps({name}).history")
        out = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            out.append({"ts_ms": _as_int(row.get("ts_ms")),
                        "kind": str(row.get("kind", "")),
                        "amount_mc": _as_int(row.get("amount_mc")),
                        "detail": str(row.get("detail", ""))})
        return {"name": name, "history": out}

    def route_wallet_receive(self, _query, body) -> dict:
        name, path = self._wallet_ops(body)
        tokens = body.get("tokens")
        if isinstance(tokens, str):
            tokens = [tokens]
        if not isinstance(tokens, list) or not tokens:
            raise GuiError(400, "bad_request",
                           "Paste at least one token string, one per line.")
        tokens = [str(t).strip() for t in tokens if str(t).strip()]
        if not tokens:
            raise GuiError(400, "bad_request",
                           "Paste at least one token string, one per line.")
        if len(tokens) > 100:
            raise GuiError(400, "bad_request",
                           "Receive at most 100 tokens at a time.")
        base = self.base_url(required=True)
        with self._wallet_lock(name):
            with self._wallet(name, path, base) as ops:
                raw = self.components.call(f"WalletOps({name}).receive",
                                           ops.receive, tokens)
                raw = self.components.expect_dict(
                    raw, f"WalletOps({name}).receive")
            summary = self._summary(name, base)
        rejected = []
        for item in (raw.get("rejected") or []):
            if isinstance(item, dict):
                rejected.append({"token": str(item.get("token", ""))[:120],
                                 "reason": str(item.get("reason", "rejected")),
                                 "detail": str(item.get("detail", ""))})
        return {"name": name,
                "accepted": _as_int(raw.get("accepted"), 0),
                "accepted_mc": _as_int(raw.get("accepted_mc"), 0),
                "rejected": rejected,
                "balance_mc": summary["balance_mc"]}

    def _amount(self, body) -> int:
        amount = _strict_int(body.get("amount_mc"))
        if amount is None or amount <= 0:
            raise GuiError(400, "bad_request",
                           "Amount must be a whole number of millicredits "
                           "greater than zero.")
        if amount > MAX_AMOUNT_MC:
            raise GuiError(400, "bad_request",
                           f"Amount must be at most {MAX_AMOUNT_MC} "
                           f"millicredits.")
        return amount

    def route_wallet_quote(self, _query, body) -> dict:
        name, path = self._wallet_ops(body)
        amount = self._amount(body)
        base = self.base_url(required=True)
        with self._wallet(name, path, base) as ops:
            raw = self.components.call(f"WalletOps({name}).quote",
                                       ops.quote, amount)
        raw = self.components.expect_dict(raw, f"WalletOps({name}).quote")
        return {"name": name, "amount_mc": amount,
                "burn_mc": _as_int(raw.get("burn_mc")),
                "change_mc": _as_int(raw.get("change_mc")),
                "inputs_mc": _as_int(raw.get("inputs_mc"))}

    def route_wallet_pay(self, _query, body) -> dict:
        name, path = self._wallet_ops(body)
        amount = self._amount(body)
        base = self.base_url(required=True)
        with self._wallet_lock(name):
            with self._wallet(name, path, base) as ops:
                raw = self.components.call(f"WalletOps({name}).pay",
                                           ops.pay, amount)
                raw = self.components.expect_dict(
                    raw, f"WalletOps({name}).pay", ("tokens",))
                tokens = self.components.expect_list(
                    raw.get("tokens"), f"WalletOps({name}).pay tokens")
            summary = self._summary(name, base)
        return {"name": name,
                "tokens": [str(t) for t in tokens],
                "amount_mc": _as_int(raw.get("amount_mc"), amount),
                "burn_mc": _as_int(raw.get("burn_mc")),
                "balance_mc": summary["balance_mc"]}

    def route_wallet_recover(self, _query, body) -> dict:
        name, path = self._wallet_ops(body)
        base = self.base_url(required=True)
        with self._wallet_lock(name):
            with self._wallet(name, path, base) as ops:
                raw = self.components.call(f"WalletOps({name}).recover",
                                           ops.recover)
                raw = self.components.expect_dict(
                    raw, f"WalletOps({name}).recover")
            summary = self._summary(name, base)
        return {"name": name, "result": raw, "balance_mc": summary["balance_mc"]}


# ----------------------------------------------------------------------
# HTTP
# ----------------------------------------------------------------------
ROUTES = {
    ("GET", "/api/mint/status"): "route_mint_status",
    ("POST", "/api/mint/start"): "route_mint_start",
    ("POST", "/api/mint/stop"): "route_mint_stop",
    ("GET", "/api/mint/logs"): "route_mint_logs",
    ("GET", "/api/mint/descriptor"): "route_mint_descriptor",
    ("POST", "/api/mint/issue"): "route_mint_issue",
    ("GET", "/api/wallet/list"): "route_wallet_list",
    ("POST", "/api/wallet/create"): "route_wallet_create",
    ("GET", "/api/wallet/summary"): "route_wallet_summary",
    ("GET", "/api/wallet/history"): "route_wallet_history",
    ("POST", "/api/wallet/receive"): "route_wallet_receive",
    ("POST", "/api/wallet/pay"): "route_wallet_pay",
    ("POST", "/api/wallet/quote"): "route_wallet_quote",
    ("POST", "/api/wallet/recover"): "route_wallet_recover",
    ("GET", "/api/token/status"): "route_token_status",
}

_ALLOWED_HOSTNAMES = {"127.0.0.1", "localhost", "::1", "[::1]"}


class Handler(BaseHTTPRequestHandler):
    api: Api = None            # set by serve()
    page_path: str = ""
    server_version = "aicash-gui"
    sys_version = ""
    # A deadline on one connection. Without it, a client that announces
    # "Content-Length: 500" and then sends four bytes holds a handler
    # thread for as long as it likes, and enough of those exhaust the
    # server with no request ever completing.
    timeout = REQUEST_TIMEOUT_S
    # HTTP/1.1 so the page's 4-second poll reuses one connection instead of
    # opening three. Every response here carries an exact Content-Length,
    # and any path that answers without draining a request body closes the
    # connection rather than leave the next read misaligned.
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        """Silent by design: a request line can carry a token in a query
        string, and this server's log would be the one place it landed."""

    # -- plumbing -------------------------------------------------------
    def _redact(self, text: str) -> str:
        """Last line of defence for the operator credential.

        Nothing here deliberately serialises the admin token, but component
        error messages are pasted through verbatim and one of them could
        quote a command line. Strip it on the way out rather than trust
        that none of them ever will.
        """
        try:
            token = self.api.admin_token()
        except Exception:
            token = None
        if token and len(token) >= 8 and token in text:
            text = text.replace(token, "[admin token redacted]")
        return text

    def _send(self, code: int, payload: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        if code != 204:  # a 204 has no body by definition
            self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        # Self-contained page, no CDN: say so in a header the browser enforces.
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; connect-src 'self'; "
            "img-src 'self' data:; base-uri 'none'; form-action 'none'")
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def _json(self, code: int, obj):
        try:
            text = json.dumps(obj, default=str)
        except (TypeError, ValueError):
            code, text = 500, json.dumps(
                {"error": {"reason": "bad_component_response",
                           "detail": "A component returned something that "
                                     "cannot be sent as JSON."}})
        self._send(code, self._redact(text).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _error(self, code: int, reason: str, detail: str):
        self._json(code, {"error": {"reason": reason, "detail": detail}})

    def _host_ok(self) -> bool:
        """Refuse a Host header that is not loopback.

        Without this, a page on the public internet can point a hostname at
        127.0.0.1 (DNS rebinding) and drive this API from the victim's own
        browser, which would let it mint and spend every wallet here.
        """
        host = (self.headers.get("Host") or "").strip()
        name = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
        if host.startswith("["):
            name = host.split("]")[0] + "]"
        # A missing Host used to pass. No browser omits it, so allowing it
        # bought nothing and left a hole in the control the README presents
        # as the outer defence.
        return name in _ALLOWED_HOSTNAMES

    def _origin_ok(self) -> bool:
        """Refuse a request that another site told the browser to make.

        The Host check above stops DNS rebinding. It does NOT stop the
        simpler attack: any page the operator has open in another tab can
        POST straight to http://127.0.0.1:<port> with a simple content
        type, which the browser sends with our own Host header and with no
        preflight to veto. The attacker cannot read the reply, but it does
        not need to — the request alone mints money, pays every wallet out
        to token strings only it will ever see, or stops the mint.

        Two headers close it, and a browser sends at least one of them on
        any request that came from a page:

          * ``Sec-Fetch-Site``: ``same-origin`` and ``none`` (typed in the
            address bar) are ours; ``cross-site`` and ``same-site`` are
            another page driving us.
          * ``Origin``: when present it must be exactly this server.

        A request carrying neither is not a browser request — curl, a
        script, the examples in the README — and is allowed, because those
        cannot be conscripted by a web page in the first place.
        """
        site = (self.headers.get("Sec-Fetch-Site") or "").strip().lower()
        if site and site not in ("same-origin", "none"):
            return False
        origin = (self.headers.get("Origin") or "").strip()
        if not origin:
            return True
        if origin.lower() == "null":  # sandboxed iframe, file://, data:
            return False
        try:
            parsed = urllib.parse.urlsplit(origin)
            port = parsed.port
        except ValueError:
            return False
        if parsed.scheme != "http":
            return False
        if (parsed.hostname or "").lower() not in {"127.0.0.1", "localhost", "::1"}:
            return False
        try:
            mine = self.server.server_address[1]
        except Exception:
            mine = None
        return port is not None and mine is not None and port == mine

    def _guard(self) -> bool:
        """Both origin controls, before anything else looks at the request."""
        if not self._host_ok():
            self.close_connection = True
            self._error(
                421, "not_loopback",
                "This GUI only answers requests addressed to 127.0.0.1 or "
                "localhost. It is a local operator tool, not a hosted "
                "service.")
            return False
        if not self._origin_ok():
            self.close_connection = True
            self._error(
                403, "cross_site",
                "That request came from another web page. This GUI can mint "
                "money and spend every wallet in its workdir, so it answers "
                "only its own page, opened directly at this address.")
            return False
        return True

    def _read_body(self) -> dict:
        length = _as_int(self.headers.get("Content-Length"), 0) or 0
        if length > MAX_BODY_BYTES:
            raise GuiError(413, "too_large",
                           "That request body is too large for this GUI.")
        if length <= 0:
            return {}
        try:
            raw = self.rfile.read(length)
        except OSError as exc:
            raise GuiError(400, "bad_request",
                           f"The request body did not arrive ({exc}).") from None
        try:
            obj = json.loads(raw or b"{}")
        except ValueError:
            raise GuiError(400, "bad_json",
                           "The request body was not valid JSON.") from None
        if not isinstance(obj, dict):
            raise GuiError(400, "bad_json",
                           "The request body must be a JSON object.")
        return obj

    # -- dispatch -------------------------------------------------------
    def _handle(self, method: str):
        if not self._guard():
            return
        # A body we never read would leave the next request on a reused
        # connection misaligned, so any path that skips it closes instead.
        drained = False
        raw_path, _, raw_query = self.path.partition("?")
        path = urllib.parse.unquote(raw_path).rstrip("/") or "/"
        query = {k: v[-1] for k, v in urllib.parse.parse_qs(raw_query).items()}
        try:
            if path in ("/", "/index.html") and method in ("GET", "HEAD"):
                return self._serve_page()
            if path == "/favicon.ico":
                return self._send(204, b"", "image/x-icon")
            if not path.startswith("/api/"):
                return self._error(404, "not_found",
                                   f"No page at {path}. The GUI is at /.")
            name = ROUTES.get((method, path))
            if name is None:
                other = [m for (m, p) in ROUTES if p == path]
                if other:
                    return self._error(
                        405, "method_not_allowed",
                        f"{path} answers {', '.join(sorted(other))}, not "
                        f"{method}.")
                return self._error(404, "not_found", f"No API route {path}.")
            if method == "POST":
                body = self._read_body()
                drained = True
            else:
                body = {}
            result = getattr(self.api, name)(query, body)
            return self._json(200, result)
        except GuiError as exc:
            return self._error(exc.status, exc.reason, exc.detail)
        except Exception as exc:
            # The whole point of this clause: the operator gets one sentence,
            # never a stack trace, and the trace goes to this process's stderr
            # where it belongs.
            traceback.print_exc()
            return self._error(
                500, "internal_error",
                f"{type(exc).__name__}: {exc}. The full detail is in the "
                f"terminal running app.py.")
        finally:
            if method == "POST" and not drained:
                self.close_connection = True

    def _serve_page(self):
        try:
            with open(self.page_path, "rb") as handle:
                payload = handle.read()
        except OSError as exc:
            message = (f"<!doctype html><meta charset=utf-8>"
                       f"<title>aicash operator</title>"
                       f"<body style='font:15px system-ui;padding:40px'>"
                       f"<h1>page.html is missing</h1><p>app.py could not read"
                       f" <code>{self.page_path}</code>: {exc}</p>"
                       f"<p>The API is still running; the interface is not.</p>")
            return self._send(500, message.encode("utf-8"),
                              "text/html; charset=utf-8")
        return self._send(200, payload, "text/html; charset=utf-8")

    def do_GET(self):
        self._handle("GET")

    def do_HEAD(self):
        self._handle("HEAD")

    def do_POST(self):
        self._handle("POST")

    def _unsupported(self, method: str):
        """A method no route uses — still JSON, still behind the guards.

        BaseHTTPRequestHandler would answer these with a 501 HTML page,
        which breaks the one promise every client of this API is allowed to
        rely on, and it would answer before the loopback checks ran.
        """
        self.close_connection = True
        if not self._guard():
            return
        self._error(
            405, "method_not_allowed",
            f"This GUI answers GET and POST only; no route uses {method}.")

    def do_PUT(self):
        self._unsupported("PUT")

    def do_PATCH(self):
        self._unsupported("PATCH")

    def do_DELETE(self):
        self._unsupported("DELETE")

    def do_OPTIONS(self):
        # Deliberately no CORS headers: the page is served by this same
        # server, so nothing it does is cross-origin, and an Access-Control
        # answer here would invite precisely the cross-site request
        # _origin_ok() exists to refuse.
        self._unsupported("OPTIONS")

    def send_error(self, code, message=None, explain=None):
        """The base class's own failures, in this GUI's error envelope.

        handle_one_request() calls this directly for a request line it
        cannot parse, a method with no handler, an over-long header block.
        Its default body is HTML; the contract here says every failure is
        {"error": {"reason", "detail"}}.
        """
        self.close_connection = True
        short, long = self.responses.get(
            code, ("error", "The request could not be handled."))
        detail = explain or long
        if message and message != short:
            detail = f"{message}. {detail}"
        try:
            self._error(int(code), _Components._reason(message or short),
                        str(detail))
        except Exception:  # the socket is already gone; nothing to report to
            pass



class GuiServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class GuiServer6(GuiServer):
    """The same server on an IPv6 loopback (``--host ::1``).

    socketserver takes the address family from the class, so binding ::1
    needs its own class rather than the same one: with AF_INET it fails
    with "Address family for hostname not supported", which main() would
    then report as a busy port.
    """
    address_family = socket.AF_INET6


def require_loopback(host: str, port: int = DEFAULT_PORT) -> int:
    """Resolve ``host`` and refuse anything the world could reach.

    This process can create money and can spend every wallet in the
    workdir, with no authentication of any kind. Binding it to a routable
    address does not expose a dashboard, it exposes the mint's operator
    credential to everyone who can route a packet to the machine.
    """
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise SystemExit(f"cannot resolve --host {host!r}: {exc}")
    families = set()
    for info in infos:
        address = info[4][0].split("%")[0]
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            raise SystemExit(f"--host {host!r} resolved to something that is "
                             f"not an IP address ({address!r}).")
        if not parsed.is_loopback:
            raise SystemExit(
                f"refusing to bind {host!r} ({address}): it is not a loopback "
                f"address.\n"
                f"This GUI has no login. Anyone who can reach its port can "
                f"mint money and spend every wallet in the workdir, so it "
                f"binds 127.0.0.1 only.\n"
                f"To reach it from another machine, forward the port over "
                f"ssh:  ssh -L {port}:127.0.0.1:{port} user@this-host")
        families.add(info[0])
    # IPv4 when the name offers it (localhost usually offers both), IPv6
    # only when that is all there is — ::1 asked for explicitly, say.
    return (socket.AF_INET if socket.AF_INET in families
            else socket.AF_INET6 if socket.AF_INET6 in families
            else socket.AF_INET)


def serve(port: int, workdir: str, host: str = "127.0.0.1") -> GuiServer:
    family = require_loopback(host, port)
    # One handler class per server, so the workdir belongs to the server
    # rather than to the module: two GuiServers in one process (the tests
    # do exactly that) must not share an Api and a workdir.
    bound = type("BoundHandler", (Handler,),
                 {"api": Api(workdir),
                  "page_path": os.path.join(HERE, "page.html")})
    server_class = GuiServer6 if family == socket.AF_INET6 else GuiServer
    return server_class((host, port), bound)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Local operator GUI for an aicash mint.")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help=f"port for this GUI (default {DEFAULT_PORT})")
    parser.add_argument("--host", default="127.0.0.1",
                        help="loopback address to bind; anything else is "
                             "refused with an explanation")
    parser.add_argument("--workdir", default=DEFAULT_WORKDIR,
                        help="where the mint database, keys, log and wallets "
                             f"live (default {DEFAULT_WORKDIR})")
    args = parser.parse_args(argv)

    workdir = os.path.abspath(args.workdir)
    os.makedirs(os.path.join(workdir, "wallets"), exist_ok=True)
    try:
        httpd = serve(args.port, workdir, args.host)
    except OSError as exc:
        if exc.errno in (errno.EADDRINUSE, errno.EACCES):
            why = ("something else is already listening there. Stop it, or "
                   "pass --port with a different number."
                   if exc.errno == errno.EADDRINUSE else
                   "this user is not allowed to bind that port. Pass --port "
                   "with a number above 1024.")
        else:
            why = ("that address could not be bound at all. 127.0.0.1 is the "
                   "default and always works; --host takes a loopback "
                   "address, not a hostname of this machine.")
        print(f"cannot bind {args.host}:{args.port}: {exc}\n{why}",
              file=sys.stderr)
        return 2

    shown = args.host if ":" not in args.host else f"[{args.host}]"
    url = f"http://{shown}:{httpd.server_address[1]}/"
    print(f"\n  aicash operator GUI")
    print(f"  workdir   {workdir}")
    print(f"  wallets   {os.path.join(workdir, 'wallets')}")
    print(f"\n  OPEN      {url}   <- open this in a browser\n")
    print(f"  Loopback only, and no password. Anyone who reaches this port "
          f"can mint\n  money and spend every wallet in the workdir. Ctrl-C "
          f"to stop.\n", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping the GUI. A mint started from here keeps running; "
              "stop it from the page, or start the GUI again and press Stop.")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
