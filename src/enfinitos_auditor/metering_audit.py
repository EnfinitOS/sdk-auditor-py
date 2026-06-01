"""enfinitos_auditor — metering re-projection audit.

Mirrors the TS ``meteringAudit.ts`` semantics. Re-projects every
meter record from the source proof receipt and asserts equality.

What this module proves
-----------------------
Given a verified ProofPack and a platform-issued MeteringSummary:

  1. Every MeterRecord references a proof receipt in the pack
     (METER_RECORD_FOR_UNKNOWN_PROOF if not).
  2. orgId on the metering summary matches the pack's
     (METER_ORG_MISMATCH if not).
  3. Recomputed idemKey = sha256(proofReceiptId|unitType) per record
     matches (METER_IDEM_KEY_MISMATCH if not).
  4. Re-projection of unitCount from dwellMs / weight matches
     (METER_UNIT_COUNT_MISMATCH if not).
  5. Per-unit-type totals re-aggregate to ``summary.totals`` if
     provided (METER_TOTAL_MISMATCH if not).

Decimal precision
-----------------
The platform persists ``Prisma.Decimal`` at 6 decimal places. We
re-produce the same 6dp string here using scaled-integer arithmetic
to avoid IEEE 754 round-trip errors.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Optional

from .hashing import sha256_hex
from .types import (
    SDK_VERSION,
    AuditStep,
    MeterRecord,
    MeteringSummary,
    ProjectionAuditReport,
    ProofRecord,
)


DECIMAL_PLACES = 6
_FACTOR = 10 ** DECIMAL_PLACES


def verify_metering_projection(
    proof_records: List[ProofRecord],
    metering: MeteringSummary,
    pack_org_id: Optional[str] = None,
) -> ProjectionAuditReport:
    """Re-project every meter record from the source proof receipt.

    The pack is the source-of-truth; the summary is candidate-under-audit.
    """

    verified_at = datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z")
    steps: List[AuditStep] = []

    proof_by_receipt_id: Dict[str, ProofRecord] = {
        r.payload.receipt_id: r for r in proof_records
    }

    # 1. Org parity.
    if pack_org_id is not None:
        if metering.org_id != pack_org_id:
            steps.append(
                AuditStep(
                    target="metering.orgId",
                    kind="meter_projection",
                    status="INVALID",
                    reason="METER_ORG_MISMATCH",
                    message=(
                        f"metering.orgId {metering.org_id!r} does not match "
                        f"pack.orgId {pack_org_id!r}"
                    ),
                )
            )
        else:
            steps.append(
                AuditStep(
                    target="metering.orgId",
                    kind="meter_projection",
                    status="VALID",
                    message="metering summary orgId matches pack",
                )
            )

    # 2..4 — walk every record.
    computed_totals: Dict[str, int] = {}
    for i, m in enumerate(metering.records):
        proof = proof_by_receipt_id.get(m.proof_receipt_id)
        if proof is None:
            steps.append(
                AuditStep(
                    target=f"metering.records[{i}].proofReceiptId",
                    kind="meter_projection",
                    status="INVALID",
                    reason="METER_RECORD_FOR_UNKNOWN_PROOF",
                    message=(
                        f"meter record references proofReceiptId "
                        f"{m.proof_receipt_id!r} that is not in the proof pack — "
                        "the meter cannot be verified"
                    ),
                )
            )
            continue

        # 3. idemKey reconstruction.
        expected_idem = sha256_hex(f"{m.proof_receipt_id}|{m.unit_type}")
        if expected_idem != m.idem_key:
            steps.append(
                AuditStep(
                    target=f"metering.records[{i}].idemKey",
                    kind="meter_projection",
                    status="INVALID",
                    reason="METER_IDEM_KEY_MISMATCH",
                    message=(
                        "idemKey on meter record does not equal "
                        "sha256(proofReceiptId|unitType)"
                    ),
                    detail={"expected": expected_idem, "actual": m.idem_key},
                )
            )
        else:
            steps.append(
                AuditStep(
                    target=f"metering.records[{i}].idemKey",
                    kind="meter_projection",
                    status="VALID",
                    message="idemKey matches sha256(proofReceiptId|unitType)",
                )
            )

        # 4. unitCount reconstruction.
        expected_unit_count = _project_unit_count(
            proof.payload.dwell_ms,
            _parse_decimal_to_scaled(m.weight),
            m.unit_type,
        )
        if expected_unit_count is None:
            steps.append(
                AuditStep(
                    target=f"metering.records[{i}].unitCount",
                    kind="meter_projection",
                    status="INVALID",
                    reason="METER_UNIT_COUNT_MISMATCH",
                    message=(
                        f"unit type {m.unit_type!r} has no known projection — "
                        "the SDK build is older than the platform's policy table"
                    ),
                )
            )
            continue
        actual_scaled = _parse_decimal_to_scaled(m.unit_count)
        if actual_scaled != expected_unit_count:
            steps.append(
                AuditStep(
                    target=f"metering.records[{i}].unitCount",
                    kind="meter_projection",
                    status="INVALID",
                    reason="METER_UNIT_COUNT_MISMATCH",
                    message=(
                        f"unitCount does not match deterministic re-projection "
                        f"from proof.dwellMs={proof.payload.dwell_ms} "
                        f"weight={m.weight} unitType={m.unit_type}"
                    ),
                    detail={
                        "expected": _format_scaled_decimal(expected_unit_count),
                        "actual": m.unit_count,
                    },
                )
            )
        else:
            steps.append(
                AuditStep(
                    target=f"metering.records[{i}].unitCount",
                    kind="meter_projection",
                    status="VALID",
                    message=f"unitCount={m.unit_count} re-projects exactly from proof",
                )
            )

        # Roll into totals regardless of pass/fail — we still want a totals
        # check if later records pass.
        computed_totals[m.unit_type] = (
            computed_totals.get(m.unit_type, 0) + expected_unit_count
        )

    # 5. Totals.
    if metering.totals is not None:
        for unit_type, claimed in metering.totals.items():
            computed = computed_totals.get(unit_type, 0)
            claimed_scaled = _parse_decimal_to_scaled(claimed)
            if claimed_scaled != computed:
                steps.append(
                    AuditStep(
                        target=f"metering.totals.{unit_type}",
                        kind="meter_total",
                        status="INVALID",
                        reason="METER_TOTAL_MISMATCH",
                        message=(
                            f"claimed total for {unit_type} does not match sum of "
                            "per-record projections"
                        ),
                        detail={
                            "expected": _format_scaled_decimal(computed),
                            "actual": claimed,
                        },
                    )
                )
            else:
                steps.append(
                    AuditStep(
                        target=f"metering.totals.{unit_type}",
                        kind="meter_total",
                        status="VALID",
                        message=f"claimed total for {unit_type} matches sum of records",
                    )
                )

    any_invalid = any(s.status == "INVALID" for s in steps)
    return ProjectionAuditReport(
        status="INVALID" if any_invalid else "VALID",
        verified_at=verified_at,
        sdk_version=SDK_VERSION,
        proof_record_count=len(proof_records),
        meter_record_count=len(metering.records),
        steps=steps,
    )


def _project_unit_count(
    dwell_ms: int, weight_scaled: int, unit_type: str
) -> Optional[int]:
    """Mirror the platform's meter projection policy at 6dp.

    Policy table:
      - DWELL_SECONDS / ATTENTION_SECONDS / OCCUPANCY_WEIGHTED_EXPOSURE:
            (dwell_ms / 1000) * weight
      - IMPRESSION_IN_PLACE: 1 * weight
      - COMPLIANT_DELIVERY_MINUTE: (dwell_ms / 60000) * weight
      - CUSTOM: unaudited — returns None (forces an INVALID step).
    """

    if unit_type in (
        "DWELL_SECONDS",
        "ATTENTION_SECONDS",
        "OCCUPANCY_WEIGHTED_EXPOSURE",
    ):
        dwell_scaled = (dwell_ms * _FACTOR) // 1000
        return (dwell_scaled * weight_scaled) // _FACTOR
    if unit_type == "IMPRESSION_IN_PLACE":
        return weight_scaled
    if unit_type == "COMPLIANT_DELIVERY_MINUTE":
        dwell_scaled = (dwell_ms * _FACTOR) // 60000
        return (dwell_scaled * weight_scaled) // _FACTOR
    return None


def _parse_decimal_to_scaled(s: str) -> int:
    """``"12.345"`` → 12345000 (when DECIMAL_PLACES=6)."""

    s = s.strip()
    sign = -1 if s.startswith("-") else 1
    if s.startswith("-") or s.startswith("+"):
        s = s[1:]
    if "." in s:
        int_part, frac_part = s.split(".", 1)
    else:
        int_part, frac_part = s, ""
    if not int_part or not int_part.isdigit():
        raise ValueError(f"metering decimal {s!r} has invalid integer part")
    if frac_part and not frac_part.isdigit():
        raise ValueError(f"metering decimal {s!r} has invalid fractional part")
    padded = (frac_part + "0" * DECIMAL_PLACES)[:DECIMAL_PLACES]
    return sign * int(f"{int_part}{padded}")


def _format_scaled_decimal(n: int) -> str:
    """Inverse of ``_parse_decimal_to_scaled``."""

    sign = "-" if n < 0 else ""
    abs_n = abs(n)
    s = str(abs_n).zfill(DECIMAL_PLACES + 1)
    int_part = s[: len(s) - DECIMAL_PLACES]
    frac_part = s[len(s) - DECIMAL_PLACES :]
    return f"{sign}{int_part}.{frac_part}"


__all__ = ["verify_metering_projection"]
