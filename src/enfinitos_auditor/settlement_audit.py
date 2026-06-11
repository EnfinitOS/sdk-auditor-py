"""enfinitos_auditor — settlement reconciliation audit.

Mirrors the TS ``settlementAudit.ts``. Given a MeteringSummary
(already audited as projecting from proofs) and a SettlementSummary:

  1. orgId parity with metering.
  2. Each settlement line references a meter in the metering summary
     (SETTLEMENT_LINE_FOR_UNKNOWN_METER).
  3. Per-meter shares sum to exactly 1.000000
     (SETTLEMENT_SHARE_SUM_NOT_ONE).
  4. amountCents = round(grossAmountCents * share) within rounding
     tolerance (SETTLEMENT_AMOUNT_MISMATCH).
  5. line.idem_key = sha256(meter.idem_key|party_role|ledger_account_code)
     (SETTLEMENT_IDEM_KEY_MISMATCH) — settlement.v2 3-field content hash.
  6. Totals reconcile if provided (SETTLEMENT_TOTAL_MISMATCH).

Rounding policy
---------------
Floor of (gross * share / 1_000_000) at the line level. The
largest-share line absorbs the rounding residual so the per-meter
total reconciles exactly.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List

from .hashing import settlement_idem_key
from .types import (
    SDK_VERSION,
    AuditStep,
    MeteringSummary,
    SettlementAuditReport,
    SettlementLine,
    SettlementSummary,
)


_SHARE_PLACES = 6
_SHARE_FACTOR = 10 ** _SHARE_PLACES


def verify_settlement_reconciliation(
    metering: MeteringSummary,
    settlement: SettlementSummary,
) -> SettlementAuditReport:
    """Re-derive every settlement line and assert equality."""

    verified_at = datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z")
    steps: List[AuditStep] = []

    # 1. Org parity.
    if settlement.org_id != metering.org_id:
        steps.append(
            AuditStep(
                target="settlement.orgId",
                kind="settlement_line",
                status="INVALID",
                reason="SETTLEMENT_ORG_MISMATCH",
                message=(
                    f"settlement.orgId {settlement.org_id!r} does not match "
                    f"metering.orgId {metering.org_id!r}"
                ),
            )
        )
    else:
        steps.append(
            AuditStep(
                target="settlement.orgId",
                kind="settlement_line",
                status="VALID",
                message="settlement orgId matches metering",
            )
        )

    meter_by_idem = {r.idem_key: r for r in metering.records}

    # Group settlement lines by meter idem key for the share-sum check.
    lines_by_meter: Dict[str, List[SettlementLine]] = {}
    for line in settlement.lines:
        lines_by_meter.setdefault(line.meter_record_idem_key, []).append(line)

    # 2..5: walk every line.
    computed_gross_cents = 0
    computed_net_to_tenant = 0
    computed_platform_fee = 0

    for i, line in enumerate(settlement.lines):
        meter = meter_by_idem.get(line.meter_record_idem_key)
        if meter is None:
            steps.append(
                AuditStep(
                    target=f"settlement.lines[{i}].meterRecordIdemKey",
                    kind="settlement_line",
                    status="INVALID",
                    reason="SETTLEMENT_LINE_FOR_UNKNOWN_METER",
                    message=(
                        f"settlement line references meterRecordIdemKey "
                        f"{line.meter_record_idem_key!r} not in metering summary"
                    ),
                )
            )
            continue

        # 5. idemKey reconstruction (settlement.v2 — 3-field content hash).
        expected_idem = settlement_idem_key(
            line.meter_record_idem_key, line.party_role, line.ledger_account_code
        )
        if line.idem_key != expected_idem:
            steps.append(
                AuditStep(
                    target=f"settlement.lines[{i}].idemKey",
                    kind="settlement_line",
                    status="INVALID",
                    reason="SETTLEMENT_IDEM_KEY_MISMATCH",
                    message=(
                        "settlement-line idemKey does not equal "
                        "sha256(meterIdemKey|partyRole|ledgerAccountCode)"
                    ),
                    detail={"expected": expected_idem, "actual": line.idem_key},
                )
            )
        else:
            steps.append(
                AuditStep(
                    target=f"settlement.lines[{i}].idemKey",
                    kind="settlement_line",
                    status="VALID",
                    message="settlement idemKey matches reconstruction",
                )
            )

        # 4. amountCents reconstruction.
        gross = settlement.meter_gross.get(line.meter_record_idem_key)
        if gross is None:
            steps.append(
                AuditStep(
                    target=f"settlement.meterGross.{line.meter_record_idem_key}",
                    kind="settlement_line",
                    status="INVALID",
                    reason="SETTLEMENT_LINE_FOR_UNKNOWN_METER",
                    message=(
                        f"no gross amount for meterIdemKey "
                        f"{line.meter_record_idem_key!r}"
                    ),
                )
            )
            continue

        share_scaled = _parse_decimal_to_scaled(line.share, _SHARE_PLACES)
        expected = (gross * share_scaled) // _SHARE_FACTOR
        if expected != line.amount_cents:
            group = lines_by_meter.get(line.meter_record_idem_key, [])
            is_largest = all(
                _parse_decimal_to_scaled(g.share, _SHARE_PLACES) <= share_scaled
                for g in group
            )
            if not is_largest or abs(expected - line.amount_cents) > len(group):
                steps.append(
                    AuditStep(
                        target=f"settlement.lines[{i}].amountCents",
                        kind="settlement_line",
                        status="INVALID",
                        reason="SETTLEMENT_AMOUNT_MISMATCH",
                        message=(
                            "amountCents does not match floor(grossCents * share) "
                            "within rounding tolerance"
                        ),
                        detail={
                            "expected": expected,
                            "actual": line.amount_cents,
                            "gross": gross,
                            "share": line.share,
                        },
                    )
                )
                continue

        steps.append(
            AuditStep(
                target=f"settlement.lines[{i}].amountCents",
                kind="settlement_line",
                status="VALID",
                message=(
                    f"amountCents={line.amount_cents} matches gross={gross} * "
                    f"share={line.share}"
                ),
            )
        )
        computed_gross_cents += line.amount_cents
        if line.party_role == "TENANT":
            computed_net_to_tenant += line.amount_cents
        elif line.party_role == "PLATFORM":
            computed_platform_fee += line.amount_cents

    # 3. Per-meter share-sum check.
    for meter_idem, group in lines_by_meter.items():
        sum_scaled = sum(
            _parse_decimal_to_scaled(line.share, _SHARE_PLACES) for line in group
        )
        if sum_scaled != _SHARE_FACTOR:
            steps.append(
                AuditStep(
                    target=f"settlement.lines[meter={meter_idem}].share",
                    kind="settlement_line",
                    status="INVALID",
                    reason="SETTLEMENT_SHARE_SUM_NOT_ONE",
                    message=(
                        f"shares for meter {meter_idem!r} sum to "
                        f"{_format_scaled_decimal(sum_scaled, _SHARE_PLACES)}, "
                        "not 1.000000"
                    ),
                )
            )
        else:
            steps.append(
                AuditStep(
                    target=f"settlement.lines[meter={meter_idem}].share",
                    kind="settlement_line",
                    status="VALID",
                    message=f"shares for meter {meter_idem!r} sum to 1.000000",
                )
            )

    # 6. Totals.
    if settlement.totals is not None:
        _push_total_check(
            steps, "grossCents", settlement.totals.gross_cents, computed_gross_cents
        )
        _push_total_check(
            steps,
            "netToTenantCents",
            settlement.totals.net_to_tenant_cents,
            computed_net_to_tenant,
        )
        _push_total_check(
            steps,
            "platformFeeCents",
            settlement.totals.platform_fee_cents,
            computed_platform_fee,
        )

    any_invalid = any(s.status == "INVALID" for s in steps)
    return SettlementAuditReport(
        status="INVALID" if any_invalid else "VALID",
        verified_at=verified_at,
        sdk_version=SDK_VERSION,
        meter_record_count=len(metering.records),
        settlement_line_count=len(settlement.lines),
        steps=steps,
    )


def _push_total_check(
    steps: List[AuditStep], label: str, claimed: int, computed: int
) -> None:
    if claimed != computed:
        steps.append(
            AuditStep(
                target=f"settlement.totals.{label}",
                kind="settlement_total",
                status="INVALID",
                reason="SETTLEMENT_TOTAL_MISMATCH",
                message=(
                    f"claimed {label}={claimed} does not match recomputed "
                    f"{computed}"
                ),
            )
        )
    else:
        steps.append(
            AuditStep(
                target=f"settlement.totals.{label}",
                kind="settlement_total",
                status="VALID",
                message=f"{label}={claimed} reconciles",
            )
        )


def _parse_decimal_to_scaled(s: str, places: int) -> int:
    s = s.strip()
    sign = -1 if s.startswith("-") else 1
    if s.startswith("-") or s.startswith("+"):
        s = s[1:]
    if "." in s:
        int_part, frac_part = s.split(".", 1)
    else:
        int_part, frac_part = s, ""
    if not int_part or not int_part.isdigit():
        raise ValueError(f"settlement decimal {s!r} has invalid integer part")
    if frac_part and not frac_part.isdigit():
        raise ValueError(f"settlement decimal {s!r} has invalid fractional part")
    padded = (frac_part + "0" * places)[:places]
    return sign * int(f"{int_part}{padded}")


def _format_scaled_decimal(n: int, places: int) -> str:
    sign = "-" if n < 0 else ""
    abs_n = abs(n)
    s = str(abs_n).zfill(places + 1)
    return f"{sign}{s[: len(s) - places]}.{s[len(s) - places :]}"


__all__ = ["verify_settlement_reconciliation"]
