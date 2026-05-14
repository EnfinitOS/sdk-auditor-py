"""enfinitos_auditor — sha256 helpers.

Same three sha256 flavours as the TypeScript port:

  1. **Plain hex** — ``ProofRecord.after_hash = sha256(payload_canonical)``,
     bare hex. Matches the proof receipt's ``afterHash`` field.
  2. **Prefixed hex** — ``"sha256:<hex>"`` for rights/basis/offer chains.
  3. **Meter idem key** — ``sha256(f"{proof_receipt_id}|{unit_type}")``.
  4. **Settlement idem key** — ``sha256(f"{meter_idem_key}|{party_role}")``.

Why these stay as separate named helpers
----------------------------------------
Each call site picks the right helper for the artefact it's hashing.
A single overloaded helper would be one source of subtle bugs.
"""

from __future__ import annotations

import hashlib
import hmac


def sha256_hex(payload: str) -> str:
    """sha256 hex of a string — bare hex, no prefix."""

    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def sha256_hex_prefixed(payload: str) -> str:
    """sha256 hex with the ``"sha256:"`` prefix the rights chain uses."""

    return f"sha256:{sha256_hex(payload)}"


def meter_idem_key(proof_receipt_id: str, unit_type: str) -> str:
    """Reconstruct a meter record's idem key from its inputs.

    Mirrors the platform's ``meterService.ts`` formula.
    """

    return sha256_hex(f"{proof_receipt_id}|{unit_type}")


def settlement_idem_key(meter_record_idem_key: str, party_role: str) -> str:
    """Reconstruct a settlement line's idem key from its inputs.

    Mirrors the platform's ``settlementService.ts`` formula.
    """

    return sha256_hex(f"{meter_record_idem_key}|{party_role}")


def constant_time_equal(a: bytes, b: bytes) -> bool:
    """Constant-time byte comparison.

    The audit context is offline (no adversarial timing channel in
    practice), but constant-time compare costs nothing and is the
    right default. ``hmac.compare_digest`` is the stdlib helper for
    this.
    """

    return hmac.compare_digest(a, b)


def constant_time_hex_equal(a: str, b: str) -> bool:
    """Constant-time hex-string comparison."""

    if len(a) != len(b):
        return False
    return hmac.compare_digest(a.encode("ascii"), b.encode("ascii"))


__all__ = [
    "constant_time_equal",
    "constant_time_hex_equal",
    "meter_idem_key",
    "settlement_idem_key",
    "sha256_hex",
    "sha256_hex_prefixed",
]
