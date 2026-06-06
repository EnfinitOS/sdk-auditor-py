"""enfinitos_auditor — canonical JSON encoder.

Byte-exact parity with the platform's two canonical encoders:

1. **Field-ordered (proof receipts)** — emits ``ProofReceiptPayload``
   fields in a hand-coded declared order. This is the encoding the
   Ed25519 signature is over.

2. **Sort-key recursive (rights/basis/offer/meter/settlement)** — a
   recursive sort-key encoder. Used wherever the platform emits
   content-addressable hashes over composite objects.

We DELIBERATELY do not implement a single "smart" encoder. Callers
pick the encoder matching the shape they are hashing.

Number policy
-------------
JSON.stringify on numbers gives a deterministic minimal-round-trip
representation. Python's ``json.dumps(separators=(',', ':'))`` is
byte-equal **for integers and for finite floats that fit IEEE 754
exactly** — and the platform never emits NaN/Infinity. We assert that
and emit via ``json.dumps`` for parity.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
from typing import Any, Dict, Iterable, List, Tuple

from .types import ProofReceiptPayload


# Field order matches apps/api/src/services/spatialChain/canonicalise.ts
PROOF_PAYLOAD_FIELDS: Tuple[str, ...] = (
    "version",
    "receiptId",
    "correlationId",
    "spatialAnchorId",
    "spatialPlacementId",
    "issuedAt",
    "renderedAt",
    "dwellMs",
    "nonce",
    "witness",
)


# Map from Python snake_case attribute names → wire JSON keys.
# The two are intentionally distinct so the Python type can stay
# Pythonic without leaking camelCase to attribute access.
_PYTHON_TO_WIRE: Dict[str, str] = {
    "version": "version",
    "receipt_id": "receiptId",
    "correlation_id": "correlationId",
    "spatial_anchor_id": "spatialAnchorId",
    "spatial_placement_id": "spatialPlacementId",
    "issued_at": "issuedAt",
    "rendered_at": "renderedAt",
    "dwell_ms": "dwellMs",
    "nonce": "nonce",
    "witness": "witness",
}

# Reverse map for parsing.
_WIRE_TO_PYTHON: Dict[str, str] = {v: k for k, v in _PYTHON_TO_WIRE.items()}


def _assert_finite(n: float | int, label: str) -> None:
    """Reject NaN / +Inf / -Inf — they would JSON-encode as ``null``."""

    if isinstance(n, float) and not math.isfinite(n):
        raise ValueError(
            f"canonical_json: non-finite number for {label} ({n!r}). "
            "Proof receipts must not contain NaN / Infinity."
        )


def canonicalise_proof_payload(payload: ProofReceiptPayload) -> str:
    """Produce the exact bytes the platform signed.

    Format (must match canonicalise.ts byte-for-byte):

      {"version":"1","receiptId":"…","correlationId":null,…}

    - Wire keys in PROOF_PAYLOAD_FIELDS order
    - No whitespace between key/value/comma
    - Each value json.dumped individually
    """

    _assert_finite(payload.dwell_ms, "dwell_ms")

    parts: List[str] = []
    # Project explicit fields (not vars(payload)) — defends against a
    # future dataclass-extension accidentally smuggling an unknown key.
    for wire_field in PROOF_PAYLOAD_FIELDS:
        py_field = _WIRE_TO_PYTHON[wire_field]
        value = getattr(payload, py_field)
        # The TS encoder uses ``JSON.stringify(field)+":"+JSON.stringify(value)``.
        # Python's json.dumps with default separators emits the same
        # for the value types we accept (str, int, None).
        encoded_value = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
        encoded_key = json.dumps(wire_field, separators=(",", ":"), ensure_ascii=False)
        parts.append(f"{encoded_key}:{encoded_value}")
    return "{" + ",".join(parts) + "}"


def canonicalise_proof_signing_input(
    payload: ProofReceiptPayload, key_id: str
) -> str:
    """``<canonical_payload>|<key_id>`` — the full signing input.

    The Ed25519 signature is over the UTF-8 bytes of this string.
    """

    return f"{canonicalise_proof_payload(payload)}|{key_id}"


def canonical_sort_keys(value: Any) -> str:
    """Generic canonical encoder for rights/basis/offer/meter/settlement.

    Algorithm (replicated from rights/service.ts ``canonicalJson``):
      - ``null`` / array / primitive → JSON.stringify as-is
      - object → keys sorted lexicographically (code-unit), recurse

    **Arrays are NOT sorted** — their order is significant.
    """

    return json.dumps(
        _normalise_for_sort_keys(value), separators=(",", ":"), ensure_ascii=False
    )


def _normalise_for_sort_keys(value: Any) -> Any:
    """Recursively sort keys of dicts; preserve list order."""

    if isinstance(value, dict):
        return {k: _normalise_for_sort_keys(value[k]) for k in sorted(value.keys())}
    if isinstance(value, (list, tuple)):
        return [_normalise_for_sort_keys(v) for v in value]
    return value


# ---------------------------------------------------------------------
# Base64url helpers
# ---------------------------------------------------------------------


def base64url_encode(b: bytes | Iterable[int]) -> str:
    """Base64url-encode a byte slice. Strips trailing ``=`` padding.

    Matches the platform's ``base64UrlEncode``.
    """

    if not isinstance(b, (bytes, bytearray)):
        b = bytes(b)
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def base64url_decode(s: str) -> bytes:
    """Base64url-decode. Accepts both padded and unpadded input."""

    padding_needed = (4 - (len(s) % 4)) % 4
    padded = s + ("=" * padding_needed)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


_BASE64URL_ALPHABET = re.compile(r"^[A-Za-z0-9_-]*$")


def base64url_decode_strict(s: str) -> bytes:
    """Strict base64url-decode (RFC 4648 §5) — exact parity with the
    TS reference's ``base64UrlDecode``.

    Rejects, with a stable message:
      - whitespace anywhere in the input (malleability surface)
      - explicit padding (``=``) — every EnfinitOS signer emits
        unpadded base64url; accepting padded input would let the same
        logical signature have two different wire spellings
      - characters outside the base64url alphabet ``[A-Za-z0-9_-]``
      - lengths with ``len % 4 == 1`` (cannot represent a byte
        sequence)

    Used by the provenance verifier; the permissive
    :func:`base64url_decode` above is kept for the pre-0.0.2 receipt
    path's behaviour. (Note: stdlib ``base64.urlsafe_b64decode``
    silently DISCARDS invalid characters unless ``validate=True``, so
    a strict gate is mandatory for parity with the TS decoder.)
    """

    if not isinstance(s, str):
        raise ValueError("base64url_decode_strict: input must be a string")
    if any(c.isspace() for c in s):
        raise ValueError(
            "base64url_decode_strict: whitespace not allowed in base64url"
        )
    if "=" in s:
        raise ValueError(
            "base64url_decode_strict: padding ('=') not allowed; "
            "use unpadded base64url"
        )
    if not _BASE64URL_ALPHABET.match(s):
        raise ValueError("base64url_decode_strict: invalid base64url character")
    if len(s) % 4 == 1:
        raise ValueError("base64url_decode_strict: invalid length (mod 4 == 1)")
    padding_needed = (4 - (len(s) % 4)) % 4
    padded = s + ("=" * padding_needed)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


# ---------------------------------------------------------------------
# sha256 / prefixed
# ---------------------------------------------------------------------


def sha256_prefixed(canonical: str) -> str:
    """sha256 of canonical input, returned as ``sha256:<hex>``.

    Lives here next to the encoder because it pairs naturally with
    ``canonical_sort_keys`` callers.
    """

    return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


# Public name → wire-field helpers, exported for the parser.
def python_to_wire(field: str) -> str:
    return _PYTHON_TO_WIRE[field]


def wire_to_python(field: str) -> str:
    return _WIRE_TO_PYTHON[field]


__all__ = [
    "PROOF_PAYLOAD_FIELDS",
    "base64url_decode",
    "base64url_decode_strict",
    "base64url_encode",
    "canonical_sort_keys",
    "canonicalise_proof_payload",
    "canonicalise_proof_signing_input",
    "python_to_wire",
    "sha256_prefixed",
    "wire_to_python",
]
