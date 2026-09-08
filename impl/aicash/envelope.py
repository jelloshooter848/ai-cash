"""The §9.5 payment request envelope — discoverability alias.

Journey feedback: testers looking for "the envelope tooling" did not think
to look under ``aicash.receipts``. The §9.5 surface is implemented in C12
(``aicash/receipts.py``) because the envelope shares the record-format
machinery (canonical JSON, the §3.8 error vocabulary); this module simply
re-exports it under the name people search for. Import from either module —
the objects are identical.

Surface (spec aicash-spec-v0.4.md §9.5, §3.8):

* ``build_envelope(request, mint_id, tokens, channel_draw=None)`` — attach
  the ``aicash`` field to a payer's request.
* ``parse_envelope(request)`` — strict payee-side validation; raises
  ``EnvelopeError`` with a stable named ``reason`` (C01 errors are never
  leaked).
* ``payment_error(errors)`` — the §3.8-shaped HTTP 402 body.
* ``Envelope`` / ``ChannelDraw`` — the parsed forms.
* ``ERROR_KINDS`` / ``ERROR_REASONS`` — the §3.8 vocabulary
  ``payment_error`` enforces.
"""

from aicash.receipts import (
    ERROR_KINDS,
    ERROR_REASONS,
    ChannelDraw,
    Envelope,
    EnvelopeError,
    build_envelope,
    parse_envelope,
    payment_error,
)

__all__ = [
    "ERROR_KINDS",
    "ERROR_REASONS",
    "ChannelDraw",
    "Envelope",
    "EnvelopeError",
    "build_envelope",
    "parse_envelope",
    "payment_error",
]
