"""enfinitos_auditor — proof pack parsing + signature verification.

Mirrors the TS ``proofPack.ts`` semantics. Takes raw JSON
(``dict`` / ``list``), validates structurally, and verifies every
record's Ed25519 signature against the supplied ``KeyDirectory``.

Signature verification path (identical to TS):
  1. base64url-decode signature → 64 raw bytes
  2. Re-canonicalise the payload locally + assert byte-equality
  3. Build signing input: ``<payload_canonical>|<key_id>``
  4. Recompute ``after_hash = sha256(payload_canonical)`` + assert
  5. Look up the public key in the directory
  6. Call the Ed25519 verify primitive (``cryptography``)
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Protocol, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical_json import (
    base64url_decode_strict,
    canonicalise_proof_payload,
    canonicalise_proof_signing_input,
)
from .errors import AuditorError
from .hashing import constant_time_hex_equal, sha256_hex
from .keys import KeyDirectory, KeyLookupHit, KeyLookupMiss
from .types import (
    SUPPORTED_ENVELOPE_VERSIONS,
    SUPPORTED_SIGNATURE_ALGORITHMS,
    AuditStep,
    EnvelopeVersion,
    MeterRecord,
    MeteringSummary,
    ProofReceiptPayload,
    ProofRecord,
    SettlementLine,
    SettlementSummary,
    SettlementTotals,
    SignedProofPack,
)


# ---------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------


def parse_signed_proof_pack(raw: Any) -> SignedProofPack:
    """Parse + structurally validate raw JSON into a ``SignedProofPack``.

    Does NOT verify signatures — that's ``verify_proof_record``.
    Raises ``AuditorError`` with code ``INVALID_INPUT`` on malformed
    shape; the caller may convert that into an INVALID audit step.
    """

    if not isinstance(raw, dict):
        raise AuditorError("INVALID_INPUT", "proof pack must be a JSON object")

    envelope_version = _req_str(raw, "envelopeVersion")
    if envelope_version not in SUPPORTED_ENVELOPE_VERSIONS:
        raise AuditorError(
            "INVALID_INPUT",
            f"unsupported envelopeVersion {envelope_version!r}",
            reason="UNSUPPORTED_ENVELOPE_VERSION",
            detail={"supported": list(SUPPORTED_ENVELOPE_VERSIONS)},
        )

    records_raw = raw.get("records")
    if not isinstance(records_raw, list):
        raise AuditorError("INVALID_INPUT", "proof pack: 'records' must be an array")

    records = [_parse_proof_record(r, i) for i, r in enumerate(records_raw)]

    pack = SignedProofPack(
        envelope_version=envelope_version,
        issued_at=_req_str(raw, "issuedAt"),
        org_id=_req_str(raw, "orgId"),
        pack_id=_req_str(raw, "packId"),
        records=records,
    )
    if "label" in raw and isinstance(raw["label"], str):
        pack.label = raw["label"]
    if "metering" in raw and raw["metering"] is not None:
        pack.metering = _parse_metering_summary(raw["metering"])
    if "settlement" in raw and raw["settlement"] is not None:
        pack.settlement = _parse_settlement_summary(raw["settlement"])
    return pack


def _req_str(raw: Dict[str, Any], key: str) -> str:
    v = raw.get(key)
    if not isinstance(v, str):
        raise AuditorError(
            "INVALID_INPUT", f"proof pack: '{key}' must be a string"
        )
    return v


def _parse_proof_record(raw: Any, idx: int) -> ProofRecord:
    if not isinstance(raw, dict):
        raise AuditorError(
            "INVALID_INPUT", f"records[{idx}] must be an object"
        )
    payload_raw = raw.get("payload")
    if not isinstance(payload_raw, dict):
        raise AuditorError(
            "INVALID_INPUT", f"records[{idx}].payload must be an object"
        )

    for key in (
        "version",
        "receiptId",
        "spatialAnchorId",
        "issuedAt",
        "renderedAt",
        "nonce",
    ):
        if not isinstance(payload_raw.get(key), str):
            raise AuditorError(
                "INVALID_INPUT",
                f"records[{idx}].payload.{key} must be a string",
            )
    if payload_raw["version"] != "1":
        raise AuditorError(
            "INVALID_INPUT",
            f"records[{idx}].payload.version must be \"1\"",
            detail={"got": payload_raw["version"]},
        )
    dwell = payload_raw.get("dwellMs")
    if not isinstance(dwell, (int, float)) or isinstance(dwell, bool):
        raise AuditorError(
            "INVALID_INPUT",
            f"records[{idx}].payload.dwellMs must be a finite number",
        )

    algorithm = raw.get("algorithm")
    if not isinstance(algorithm, str) or algorithm not in SUPPORTED_SIGNATURE_ALGORITHMS:
        raise AuditorError(
            "INVALID_INPUT",
            f"records[{idx}].algorithm {algorithm!r} unsupported",
            reason="UNSUPPORTED_ALGORITHM",
            detail={"supported": list(SUPPORTED_SIGNATURE_ALGORITHMS)},
        )

    for key in ("keyId", "signature", "payloadCanonical", "afterHash"):
        if not isinstance(raw.get(key), str):
            raise AuditorError(
                "INVALID_INPUT", f"records[{idx}].{key} must be a string"
            )

    before_hash = raw.get("beforeHash")
    if before_hash is not None and not isinstance(before_hash, str):
        raise AuditorError(
            "INVALID_INPUT",
            f"records[{idx}].beforeHash must be a string or null",
        )

    payload = ProofReceiptPayload(
        version="1",
        receipt_id=payload_raw["receiptId"],
        correlation_id=payload_raw.get("correlationId"),
        spatial_anchor_id=payload_raw["spatialAnchorId"],
        spatial_placement_id=payload_raw.get("spatialPlacementId"),
        issued_at=payload_raw["issuedAt"],
        rendered_at=payload_raw["renderedAt"],
        dwell_ms=int(dwell),
        nonce=payload_raw["nonce"],
        witness=payload_raw.get("witness"),
    )
    return ProofRecord(
        payload=payload,
        key_id=raw["keyId"],
        algorithm="ed25519",
        signature=raw["signature"],
        payload_canonical=raw["payloadCanonical"],
        before_hash=before_hash,
        after_hash=raw["afterHash"],
    )


def _parse_metering_summary(raw: Any) -> MeteringSummary:
    if not isinstance(raw, dict):
        raise AuditorError("INVALID_INPUT", "metering must be an object")
    if raw.get("schemaVersion") != "metering.v1":
        raise AuditorError(
            "INVALID_INPUT",
            f"unsupported metering schemaVersion {raw.get('schemaVersion')!r}",
        )
    records: List[MeterRecord] = []
    for i, r in enumerate(raw.get("records", [])):
        records.append(
            MeterRecord(
                idem_key=r["idemKey"],
                proof_receipt_id=r["proofReceiptId"],
                unit_type=r["unitType"],
                unit_count=str(r["unitCount"]),
                weight=str(r["weight"]),
                spatial_anchor_id=r["spatialAnchorId"],
                spatial_placement_id=r.get("spatialPlacementId"),
                observed_at=r["observedAt"],
                status=r["status"],
            )
        )
    summary = MeteringSummary(
        schema_version="metering.v1",
        org_id=raw["orgId"],
        period_start=raw["periodStart"],
        period_end=raw["periodEnd"],
        records=records,
        totals=raw.get("totals"),
    )
    return summary


def _parse_settlement_summary(raw: Any) -> SettlementSummary:
    if not isinstance(raw, dict):
        raise AuditorError("INVALID_INPUT", "settlement must be an object")
    schema_version = raw.get("schemaVersion")
    if schema_version not in ("settlement.v1", "settlement.v2"):
        raise AuditorError(
            "INVALID_INPUT",
            f"unsupported settlement schemaVersion {schema_version!r}",
        )
    lines: List[SettlementLine] = []
    for r in raw.get("lines", []):
        lines.append(
            SettlementLine(
                idem_key=r["idemKey"],
                meter_record_idem_key=r["meterRecordIdemKey"],
                party_role=r["partyRole"],
                share=str(r["share"]),
                ledger_account_code=r["ledgerAccountCode"],
                amount_cents=int(r["amountCents"]),
                currency=r["currency"],
                status=r["status"],
            )
        )
    totals_raw = raw.get("totals")
    totals = None
    if totals_raw is not None:
        totals = SettlementTotals(
            gross_cents=int(totals_raw["grossCents"]),
            net_to_tenant_cents=int(totals_raw["netToTenantCents"]),
            platform_fee_cents=int(totals_raw["platformFeeCents"]),
        )
    return SettlementSummary(
        schema_version=schema_version,
        org_id=raw["orgId"],
        period_start=raw["periodStart"],
        period_end=raw["periodEnd"],
        currency=raw["currency"],
        meter_gross={k: int(v) for k, v in raw["meterGross"].items()},
        lines=lines,
        totals=totals,
    )


# ---------------------------------------------------------------------
# Signature verification
# ---------------------------------------------------------------------


class SignatureVerifier(Protocol):
    """Pluggable Ed25519 verify backend.

    Mirrors the TS ``SignatureVerifier`` interface. Implementations:
      - ``Ed25519SignatureVerifier`` (default, ``cryptography``)
    """

    def verify_ed25519(
        self, public_key: bytes, message: bytes, signature: bytes
    ) -> bool:  # pragma: no cover - protocol
        ...


class Ed25519SignatureVerifier:
    """Default verifier using ``cryptography``'s Ed25519 primitives."""

    def verify_ed25519(
        self, public_key: bytes, message: bytes, signature: bytes
    ) -> bool:
        if len(public_key) != 32 or len(signature) != 64:
            return False
        try:
            pk = Ed25519PublicKey.from_public_bytes(public_key)
            pk.verify(signature, message)
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False


_DEFAULT_VERIFIER = Ed25519SignatureVerifier()


def default_signature_verifier() -> SignatureVerifier:
    return _DEFAULT_VERIFIER


# ---------------------------------------------------------------------
# Per-record verification
# ---------------------------------------------------------------------


def verify_proof_record(
    record: ProofRecord,
    record_index: int,
    keys: KeyDirectory,
    verifier: Optional[SignatureVerifier] = None,
) -> List[AuditStep]:
    """Re-canonicalise + re-hash + verify the signature on one record.

    Returns audit steps in order:
      canonicalisation, after-hash, key-lookup, signature.
    """

    verifier = verifier or _DEFAULT_VERIFIER
    steps: List[AuditStep] = []

    # 1. Canonicalisation parity.
    try:
        local_canonical = canonicalise_proof_payload(record.payload)
    except Exception as exc:
        steps.append(
            AuditStep(
                target=f"record[{record_index}].payloadCanonical",
                kind="canonicalisation",
                status="INVALID",
                reason="PAYLOAD_CANONICAL_MISMATCH",
                message=f"canonicalisation threw: {exc}",
            )
        )
        return steps

    if local_canonical != record.payload_canonical:
        steps.append(
            AuditStep(
                target=f"record[{record_index}].payloadCanonical",
                kind="canonicalisation",
                status="INVALID",
                reason="PAYLOAD_CANONICAL_MISMATCH",
                message=(
                    "the canonical payload the SDK computed does not match the "
                    "bytes the pack ships — encoder version skew or tampering"
                ),
                detail={
                    "expected": record.payload_canonical[:256],
                    "actual": local_canonical[:256],
                },
            )
        )
    else:
        steps.append(
            AuditStep(
                target=f"record[{record_index}].payloadCanonical",
                kind="canonicalisation",
                status="VALID",
                message="canonical payload bytes match",
            )
        )

    # 2. afterHash parity.
    expected_after_hash = sha256_hex(local_canonical)
    if not constant_time_hex_equal(expected_after_hash, record.after_hash):
        steps.append(
            AuditStep(
                target=f"record[{record_index}].afterHash",
                kind="canonicalisation",
                status="INVALID",
                reason="AFTER_HASH_MISMATCH",
                message="record afterHash does not equal sha256(payloadCanonical)",
                detail={"expected": expected_after_hash, "actual": record.after_hash},
            )
        )
    else:
        steps.append(
            AuditStep(
                target=f"record[{record_index}].afterHash",
                kind="canonicalisation",
                status="VALID",
                message="afterHash equals sha256(payloadCanonical)",
            )
        )

    # 3. Key lookup.
    lookup = keys.lookup(record.key_id, record.payload.issued_at)
    if isinstance(lookup, KeyLookupMiss):
        steps.append(
            AuditStep(
                target=f"record[{record_index}].keyId",
                kind="key_lookup",
                status="INVALID",
                reason=lookup.reason,
                message=_key_miss_message(lookup.reason, record.key_id),
                detail={"keyId": record.key_id, "issuedAt": record.payload.issued_at},
            )
        )
        return steps
    assert isinstance(lookup, KeyLookupHit)
    steps.append(
        AuditStep(
            target=f"record[{record_index}].keyId",
            kind="key_lookup",
            status="VALID",
            message=f"key {record.key_id!r} resolved and valid for issuedAt",
        )
    )

    # 4. Signature verification.
    try:
        # CRYPTO-05: strict base64url — reject malformed signature/public-key
        # strings rather than letting stdlib silently drop invalid characters.
        # Parity with the provenance path and the TS/Rust reference decoders.
        sig_bytes = base64url_decode_strict(record.signature)
        pub_bytes = base64url_decode_strict(lookup.key.public_key)
    except Exception as exc:
        steps.append(
            AuditStep(
                target=f"record[{record_index}].signature",
                kind="signature",
                status="INVALID",
                reason="SIGNATURE_MALFORMED",
                message=f"signature/public-key decoding failed: {exc}",
            )
        )
        return steps

    if len(sig_bytes) != 64 or len(pub_bytes) != 32:
        steps.append(
            AuditStep(
                target=f"record[{record_index}].signature",
                kind="signature",
                status="INVALID",
                reason="SIGNATURE_MALFORMED",
                message=(
                    f"expected 64-byte signature / 32-byte public key, got "
                    f"{len(sig_bytes)} / {len(pub_bytes)}"
                ),
            )
        )
        return steps

    signing_input = canonicalise_proof_signing_input(record.payload, record.key_id)
    try:
        ok = verifier.verify_ed25519(pub_bytes, signing_input.encode("utf-8"), sig_bytes)
    except Exception as exc:
        steps.append(
            AuditStep(
                target=f"record[{record_index}].signature",
                kind="signature",
                status="INVALID",
                reason="SIGNATURE_INVALID",
                message=f"signature verify threw: {exc}",
            )
        )
        return steps

    steps.append(
        AuditStep(
            target=f"record[{record_index}].signature",
            kind="signature",
            status="VALID" if ok else "INVALID",
            reason=None if ok else "SIGNATURE_INVALID",
            message=(
                "Ed25519 signature verifies against the declared key"
                if ok
                else (
                    "Ed25519 signature did NOT verify — the record has been "
                    "tampered with, or the keyId points to a different key "
                    "than the one that actually signed it"
                )
            ),
        )
    )
    return steps


def _key_miss_message(reason: str, key_id: str) -> str:
    if reason == "UNKNOWN_KEY_ID":
        return f"keyId {key_id!r} is not in the verification key directory"
    if reason == "KEY_OUTSIDE_VALIDITY_WINDOW":
        return (
            f"keyId {key_id!r} is outside its declared validity window for "
            "the record's issuedAt"
        )
    if reason == "KEY_REVOKED_BEFORE_ISSUANCE":
        return (
            f"keyId {key_id!r} was revoked before the record's issuedAt — "
            "the record cannot be trusted"
        )
    return f"keyId {key_id!r} miss reason {reason!r}"


__all__ = [
    "Ed25519SignatureVerifier",
    "SignatureVerifier",
    "default_signature_verifier",
    "parse_signed_proof_pack",
    "verify_proof_record",
]
