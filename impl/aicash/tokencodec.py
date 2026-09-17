"""C01 — tokencodec: pure encoding layer (spec §3.1–§3.4).

Token strings, base64url secrets/hashes, ledger keys, canonical JSON.
No I/O, no state, no clock.  Tokens are passwords (§3.1): nothing in this
module writes, prints, or records secret material anywhere.
"""

import base64
import hashlib
import os
import re
import unicodedata
from typing import NamedTuple

__all__ = [
    "MINT_ID_RE",
    "MAX_AMOUNT_MC",
    "MAX_AMOUNT_DIGITS",
    "TokenError",
    "Token",
    "b64u_encode",
    "b64u_decode",
    "new_secret",
    "ledger_key",
    "format_token",
    "parse_token",
    "canonical_json",
    "body_digest",
]

SECRET_LEN = 32
TOKEN_PREFIX = "aicash"
TOKEN_VERSION = "v3"

MINT_ID_RE = re.compile(r"^[a-z0-9-]{1,64}$")
"""The §3.1 mint-id rule, as the compiled regex this module enforces.

A valid mint_id is 1–64 characters drawn from lowercase ASCII letters,
digits, and hyphen (``^[a-z0-9-]{1,64}$``). Exported so other components
(C06 config validation, C12 envelopes, operator tooling) can validate a
mint_id with the exact same rule token parsing applies — never a
re-typed copy of the pattern."""
MAX_AMOUNT_MC = (1 << 63) - 1
"""Largest amount this module will encode or decode, in millicredits.

THE BOUND, named once, because "how big can an amount be" was previously
answered nowhere and therefore answered by CPython. The ledger stores
``amount_mc`` in a SQLite ``INTEGER`` column, which is a signed 64-bit
value: 9223372036854775807 is the largest amount that can be written to an
entry at all, and one millicredit more raises ``OverflowError`` out of the
SQLite binding. So a token whose amount field exceeds this is not a token
for a very large amount; it is a token for an amount no mint could ever
have issued and no ledger could ever hold. Malformed, in this module's
own vocabulary (``TokenError``), and said so HERE so that every caller of
``parse_token``/``format_token`` — C06's exchange route, C10's deposit
route, the wallet, escrow, receipts, swap — gets the same answer without
each one re-deriving it.

Found by outside review 2026-09-16: ``_AMOUNT_RE`` used to be an
UNBOUNDED digit run, and ``int()`` on a 5,000-digit run raises a BARE
``ValueError`` (CPython's int/str conversion limit, added in 3.11 and
tunable with ``sys.set_int_max_str_digits``; 4300 digits by default). A bare ValueError is
not a ``TokenError``, so it escaped every ``except TokenError`` in the
tree and surfaced as an unenumerated HTTP 500 — §3.8 owes an enumerated
reason. The digit limit is a symptom; the defect is that the pattern
admitted values the conversion could not represent. A bounded pattern
cannot: 19 digits is the most ``MAX_AMOUNT_MC`` needs, far below any
plausible digit limit, so ``int()`` on a string this pattern accepts can
no longer raise anything at all."""

MAX_AMOUNT_DIGITS = len(str(MAX_AMOUNT_MC))

MAX_JSON_DEPTH = 100
"""How deep a document this renderer will descend before refusing.

A RESOURCE bound on the renderer, deliberately not a change to the §3.3
wire format: every document any component of this system builds is a
handful of levels deep (the deepest is an exchange call's
inputs/outputs/lock, four), so nothing legal is refused and no
recommendation to the spec owner is needed to keep this true. What it
refuses is the shape that has no legitimate sender.

Here for the same reason MAX_AMOUNT_DIGITS is: ``_canon`` descends by
Python recursion, and Python answers "too deep" with ``RecursionError``,
which is not a ``ValueError`` and therefore not a ``TokenError``. Every
caller in the tree guards canonicalization with ``except TokenError``, so
a document ~500 levels deep escaped all of them and surfaced as an
unenumerated 500 — the same defect as the over-long amount, one converter
over. Counting the levels ourselves makes the refusal a ``TokenError``
with a stated reason, and makes it DETERMINISTIC: the interpreter's own
limit moves with the caller's stack depth and with
``sys.setrecursionlimit``, so a rule that fired only there would refuse
different documents on different call paths. This one refuses the same
document everywhere.

100 is far below what CPython's default recursion limit can carry from
any call site in this tree (``_canon`` spends about two frames per level,
so ~200 of the default 1000) and far above anything this protocol
describes."""

# Positive decimal, no leading zeros, and LENGTH-BOUNDED: a digit run
# longer than MAX_AMOUNT_MC needs cannot describe a storable amount, so it
# is refused by the pattern rather than by int(). The bound is on the
# pattern and not only on the parsed value because a pattern that admits
# what the converter cannot take is exactly the defect being closed --
# int() must never see a string this module has not already sized.
_AMOUNT_RE = re.compile(r"^[1-9][0-9]{0,%d}$" % (MAX_AMOUNT_DIGITS - 1))
_B64U_ALPHABET_RE = re.compile(r"^[A-Za-z0-9_-]*$")


class TokenError(ValueError):
    """Raised on any malformed token / encoding input."""

    def __init__(self, message: str, reason: str = "bad_format"):
        super().__init__(message)
        self.reason = reason


class Token(NamedTuple):
    mint_id: str
    amount_mc: int
    secret: bytes


def b64u_encode(b: bytes) -> str:
    """base64url without padding (§3.1)."""
    if not isinstance(b, bytes):
        raise TokenError("b64u_encode requires bytes")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64u_decode(s: str, expect_len: int | None = None) -> bytes:
    """Strict base64url-no-padding decode.

    Rejects: non-str input, `=` padding, `+`/`/` (standard-alphabet) chars,
    whitespace or any other character outside [A-Za-z0-9_-], impossible
    lengths (len % 4 == 1), non-canonical encodings (nonzero trailing bits),
    and — when ``expect_len`` is given — any decoded length other than it.
    """
    if not isinstance(s, str):
        raise TokenError("b64u_decode requires str")
    if not _B64U_ALPHABET_RE.fullmatch(s):
        raise TokenError("invalid base64url character")
    if len(s) % 4 == 1:
        raise TokenError("invalid base64url length")
    pad = (-len(s)) % 4
    try:
        raw = base64.urlsafe_b64decode(s + "=" * pad)
    except Exception as exc:  # pragma: no cover - alphabet/length already checked
        raise TokenError("invalid base64url") from exc
    # Canonicality: re-encoding must reproduce the input exactly (rejects
    # nonzero trailing bits, so each byte string has exactly one encoding).
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != s:
        raise TokenError("non-canonical base64url")
    if expect_len is not None and len(raw) != expect_len:
        raise TokenError(
            "decoded length %d, expected %d" % (len(raw), expect_len)
        )
    return raw


def new_secret() -> bytes:
    """32 random bytes from os.urandom (§3.1: generated by the holder)."""
    return os.urandom(SECRET_LEN)


def ledger_key(secret: bytes) -> str:
    """b64u(sha256(raw 32 secret bytes)) — the ledger key encoding (§3.2)."""
    if not isinstance(secret, bytes):
        raise TokenError("ledger_key requires bytes")
    if len(secret) != SECRET_LEN:
        raise TokenError("secret must be exactly 32 bytes")
    return b64u_encode(hashlib.sha256(secret).digest())


def _check_mint_id(mint_id: object) -> str:
    if not isinstance(mint_id, str) or not MINT_ID_RE.fullmatch(mint_id):
        raise TokenError("invalid mint_id")
    return mint_id


def format_token(mint_id: str, amount_mc: int, secret: bytes) -> str:
    """"aicash:v3:<mint>:<amt>:<b64u secret>" (§3.1)."""
    _check_mint_id(mint_id)
    if isinstance(amount_mc, bool) or not isinstance(amount_mc, int):
        raise TokenError("amount_mc must be an int")
    if amount_mc <= 0:
        raise TokenError("amount_mc must be positive")
    if amount_mc > MAX_AMOUNT_MC:
        # The encoding half of the same rule parse_token applies. "%d"
        # below is an int->str conversion and raises the SAME bare
        # ValueError past the interpreter's digit limit, so a checker that
        # only bounded the DECODER would leave this module able to emit a
        # token it refuses to read back -- and able to raise a non-TokenError
        # at any caller that builds a token from a number it got elsewhere.
        raise TokenError("amount_mc exceeds the largest storable amount")
    if not isinstance(secret, bytes):
        raise TokenError("secret must be bytes")
    if len(secret) != SECRET_LEN:
        raise TokenError("secret must be exactly 32 bytes")
    return "%s:%s:%s:%d:%s" % (
        TOKEN_PREFIX,
        TOKEN_VERSION,
        mint_id,
        amount_mc,
        b64u_encode(secret),
    )


def parse_token(s: str) -> Token:
    """Parse a token string; raises TokenError('bad_format') on anything off."""
    if not isinstance(s, str):
        raise TokenError("token must be a string")
    parts = s.split(":")
    if len(parts) != 5:
        raise TokenError("token must have exactly 5 colon-separated fields")
    prefix, version, mint_id, amount_str, secret_str = parts
    if prefix != TOKEN_PREFIX:
        raise TokenError("bad token prefix")
    if version != TOKEN_VERSION:
        raise TokenError("bad token version")
    _check_mint_id(mint_id)
    if not _AMOUNT_RE.fullmatch(amount_str):
        # Includes an over-long digit run: see MAX_AMOUNT_MC. The pattern
        # is what keeps int() below total -- it can only ever be handed at
        # most MAX_AMOUNT_DIGITS digits, so it cannot raise.
        raise TokenError("invalid amount")
    amount_mc = int(amount_str)
    if amount_mc > MAX_AMOUNT_MC:
        # MAX_AMOUNT_DIGITS digits is a slightly larger range than
        # MAX_AMOUNT_MC, so the pattern alone lets a handful of
        # unstorable values through; the value check closes that gap.
        raise TokenError("amount exceeds the largest storable amount")
    secret = b64u_decode(secret_str, expect_len=SECRET_LEN)
    return Token(mint_id=mint_id, amount_mc=amount_mc, secret=secret)


# ---------------------------------------------------------------------------
# Canonical JSON (§3.3, pinned; OPEN-QUESTIONS R21, normalize-then-sort):
# UTF-8; all strings (keys and values) NFC-normalized FIRST, then object
# keys sorted by Unicode code point on the NORMALIZED key; two distinct raw
# keys that collide after NFC are rejected; no insignificant whitespace,
# plain decimal integers (no floats anywhere).
# ---------------------------------------------------------------------------

_STRING_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def _canon_string(s: str) -> str:
    s = unicodedata.normalize("NFC", s)
    out = ['"']
    for ch in s:
        esc = _STRING_ESCAPES.get(ch)
        if esc is not None:
            out.append(esc)
        elif ord(ch) < 0x20:
            out.append("\\u%04x" % ord(ch))
        elif 0xD800 <= ord(ch) <= 0xDFFF:
            # A LONE surrogate: a code point reserved for pairing in UTF-16
            # and not encodable in UTF-8 at all (Unicode 3.9, D92). §3.3
            # pins canonical JSON as UTF-8, so a str carrying one is not a
            # string this format can represent, and saying so here is the
            # same rule as the float clause below — a value the renderer
            # cannot render is malformed in this module's own vocabulary.
            #
            # Caught at the CHARACTER, not at the final encode, because the
            # character is where the reason is legible: an unpaired
            # surrogate reaches a mint as the JSON escape "\ud800", which
            # json.loads decodes without complaint into a str that cannot
            # be re-encoded. A legal PAIR is decoded by json.loads into the
            # single non-surrogate code point it denotes and never arrives
            # here, so no valid input is refused by this clause.
            raise TokenError(
                "unpaired surrogate is not representable in UTF-8"
            )
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _canon(obj, depth: int = 0) -> str:
    if depth > MAX_JSON_DEPTH:
        # See MAX_JSON_DEPTH. Checked on the way DOWN, before the recursive
        # call that would deepen the stack, so the interpreter's own
        # RecursionError can never be the thing that stops this descent.
        raise TokenError(
            "document nests deeper than canonical JSON will render"
        )
    if obj is None:
        return "null"
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, int):
        # str(int) is a conversion, and past the interpreter's digit limit
        # it raises the same BARE ValueError that int(str) does -- the D2
        # defect with the arrow reversed, found by looking for the shape
        # rather than for the report. §3.3 is a RATIFIED wire format and it
        # puts no bound on a JSON integer, so which values are LEGAL here
        # is not this round's to change (an int64 bound is recommended to
        # the spec owner instead, and would make these three lines dead).
        # Which ERROR they raise is: a value this renderer cannot turn into
        # a decimal string is not representable in canonical JSON, and this
        # module says so in its own vocabulary rather than letting a bare
        # ValueError escape a caller's `except TokenError` into an
        # unenumerated 500 -- which is exactly how D2 reached one.
        # Total for this converter: every way str() can fail on an int
        # becomes TokenError. The converters either side of it are held
        # to the same standard rather than assumed safe -- the depth
        # guard above and the surrogate clause in _canon_string are the
        # other two ways this renderer can meet a value it cannot
        # render, and canonical_json guards the final encode as well, so
        # nothing leaves this module as an exception a caller's
        # `except TokenError` does not see.
        try:
            return str(obj)
        except ValueError as exc:
            raise TokenError(
                "integer too large to render in canonical JSON"
            ) from exc
    if isinstance(obj, float):
        raise TokenError("floats are forbidden in canonical JSON")
    if isinstance(obj, str):
        return _canon_string(obj)
    if isinstance(obj, (list, tuple)):
        return "[" + ",".join(_canon(item, depth + 1) for item in obj) + "]"
    if isinstance(obj, dict):
        for key in obj:
            if not isinstance(key, str) or isinstance(key, bool):
                raise TokenError("canonical JSON object keys must be strings")
        # Normalize-then-sort (requirement 6; §3.3 R21): NFC-normalize every
        # key FIRST, reject distinct raw keys that collide after NFC, then
        # sort by Unicode code point on the *normalized* key; Python's
        # default str ordering is exactly code-point order.
        norm_items = []
        seen = set()
        for key in obj:
            norm_key = unicodedata.normalize("NFC", key)
            if norm_key in seen:
                raise TokenError(
                    "duplicate object key after NFC normalization"
                )
            seen.add(norm_key)
            norm_items.append((norm_key, obj[key]))
        norm_items.sort(key=lambda item: item[0])
        pieces = [
            _canon_string(norm_key) + ":" + _canon(value, depth + 1)
            for norm_key, value in norm_items
        ]
        return "{" + ",".join(pieces) + "}"
    raise TokenError(
        "type %s is not representable in canonical JSON" % type(obj).__name__
    )


def canonical_json(obj) -> bytes:
    """§3.3 pinned canonical JSON as UTF-8 bytes.

    Raises ``TokenError`` and nothing else. The encode is guarded for the
    same reason ``_canon`` guards ``str(int)``: ``str.encode`` raises
    ``UnicodeEncodeError``, a ``ValueError`` subclass that is NOT a
    ``TokenError``, so a caller writing the documented ``except TokenError``
    around a canonicalization would not have caught it. ``_canon_string``
    already refuses the only input that can get here — an unpaired
    surrogate — so this clause has no known reachable case; it is kept
    because "no known case" is what the last two rounds of this defect were
    each built on, and a converter whose failure type nobody re-checked is
    exactly the shape being closed. The guarantee wanted here is about the
    TYPE that leaves this function, and a guarantee about a type is cheap
    to make total and expensive to make selective.
    """
    try:
        return _canon(obj).encode("utf-8")
    except UnicodeEncodeError as exc:  # pragma: no cover - see docstring
        raise TokenError(
            "canonical JSON is UTF-8 and this document is not encodable"
        ) from exc


def body_digest(obj) -> str:
    """b64u(sha256(canonical_json(obj))) (§3.3 idempotency digests)."""
    return b64u_encode(hashlib.sha256(canonical_json(obj)).digest())
