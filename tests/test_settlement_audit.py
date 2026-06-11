"""Settlement reconciliation audit."""

from __future__ import annotations

from dataclasses import replace

from enfinitos_auditor.hashing import settlement_idem_key
from enfinitos_auditor.settlement_audit import verify_settlement_reconciliation
from enfinitos_auditor.types import (
    MeterRecord,
    MeteringSummary,
    SettlementLine,
    SettlementSummary,
    SettlementTotals,
)

from tests.fixtures.builder import (
    build_metering_summary,
    build_multi_record_chain,
    build_settlement_summary,
    generate_key,
)


def test_passes_for_100_percent_tenant_single_line_projection() -> None:
    key = generate_key()
    pack = build_multi_record_chain(3, key)
    metering = build_metering_summary(pack)
    settlement = build_settlement_summary(metering)
    report = verify_settlement_reconciliation(metering, settlement)
    assert report.status == "VALID"


def test_flags_settlement_line_for_unknown_meter() -> None:
    key = generate_key()
    pack = build_multi_record_chain(2, key)
    metering = build_metering_summary(pack)
    settlement = build_settlement_summary(metering)
    settlement.lines[0] = replace(
        settlement.lines[0], meter_record_idem_key="ghost_meter_idem"
    )
    report = verify_settlement_reconciliation(metering, settlement)
    assert any(
        s.reason == "SETTLEMENT_LINE_FOR_UNKNOWN_METER" for s in report.steps
    )


def test_flags_settlement_amount_mismatch() -> None:
    key = generate_key()
    pack = build_multi_record_chain(2, key)
    metering = build_metering_summary(pack)
    settlement = build_settlement_summary(metering)
    settlement.lines[0] = replace(
        settlement.lines[0], amount_cents=settlement.lines[0].amount_cents + 1000
    )
    report = verify_settlement_reconciliation(metering, settlement)
    assert any(s.reason == "SETTLEMENT_AMOUNT_MISMATCH" for s in report.steps)


def test_flags_settlement_idem_key_mismatch() -> None:
    key = generate_key()
    pack = build_multi_record_chain(2, key)
    metering = build_metering_summary(pack)
    settlement = build_settlement_summary(metering)
    settlement.lines[0] = replace(settlement.lines[0], idem_key="0" * 64)
    report = verify_settlement_reconciliation(metering, settlement)
    assert any(s.reason == "SETTLEMENT_IDEM_KEY_MISMATCH" for s in report.steps)


def test_flags_settlement_share_sum_not_one() -> None:
    key = generate_key()
    pack = build_multi_record_chain(1, key)
    metering = build_metering_summary(pack)
    settlement = build_settlement_summary(metering)
    settlement.lines[0] = replace(settlement.lines[0], share="0.500000")
    report = verify_settlement_reconciliation(metering, settlement)
    assert any(s.reason == "SETTLEMENT_SHARE_SUM_NOT_ONE" for s in report.steps)


def test_flags_settlement_org_mismatch() -> None:
    key = generate_key()
    pack = build_multi_record_chain(1, key)
    metering = build_metering_summary(pack)
    settlement = build_settlement_summary(metering)
    settlement.org_id = "org_other"
    report = verify_settlement_reconciliation(metering, settlement)
    assert any(s.reason == "SETTLEMENT_ORG_MISMATCH" for s in report.steps)


def test_flags_settlement_total_mismatch() -> None:
    key = generate_key()
    pack = build_multi_record_chain(2, key)
    metering = build_metering_summary(pack)
    settlement = build_settlement_summary(metering)
    assert settlement.totals is not None
    settlement.totals.gross_cents = 0
    report = verify_settlement_reconciliation(metering, settlement)
    assert any(s.reason == "SETTLEMENT_TOTAL_MISMATCH" for s in report.steps)


# ---------------------------------------------------------------------
# CRYPTO-04 — exact-cent multi-party split
#
# Production splits a meter's gross across party shares as a deterministic
# integer split (floor per share + residual reabsorbed into the largest-share
# line). The auditor mirrors that split and requires EXACT-cent equality — no
# ±band — so a single-cent error on any line, including the residual-bearing
# largest line, is caught.
# ---------------------------------------------------------------------

_METER_IDEM = "meter_multiparty_x"


def _build_multi_party_split() -> "tuple[MeteringSummary, SettlementSummary]":
    gross = 10001  # 0.7 / 0.25 / 0.05 -> 7000.7 / 2500.25 / 500.05
    metering = MeteringSummary(
        schema_version="metering.v1",
        org_id="org_test",
        period_start="2027-01-01T00:00:00.000Z",
        period_end="2027-02-01T00:00:00.000Z",
        records=[
            MeterRecord(
                idem_key=_METER_IDEM,
                proof_receipt_id="rcpt_multiparty_x",
                unit_type="DWELL_SECONDS",
                unit_count="100",
                weight="1",
                spatial_anchor_id="anchor_x",
                spatial_placement_id=None,
                observed_at="2027-01-15T00:00:00.000Z",
                status="ACCEPTED",
            )
        ],
    )

    def mk(party_role: str, share: str, code: str, amount: int) -> SettlementLine:
        return SettlementLine(
            idem_key=settlement_idem_key(_METER_IDEM, party_role, code),
            meter_record_idem_key=_METER_IDEM,
            party_role=party_role,  # type: ignore[arg-type]
            share=share,
            ledger_account_code=code,
            amount_cents=amount,
            currency="GBP",
            status="PROJECTED",
        )

    settlement = SettlementSummary(
        schema_version="settlement.v2",
        org_id="org_test",
        period_start="2027-01-01T00:00:00.000Z",
        period_end="2027-02-01T00:00:00.000Z",
        currency="GBP",
        meter_gross={_METER_IDEM: gross},
        lines=[
            mk("TENANT", "0.700000", "SPATIAL_REVENUE_GROSS", 7001),  # residual +1
            mk("VENUE", "0.250000", "SPATIAL_VENUE_PAYOUT", 2500),
            mk("PLATFORM", "0.050000", "SPATIAL_PLATFORM_FEE", 500),
        ],
        totals=SettlementTotals(
            gross_cents=10001, net_to_tenant_cents=7001, platform_fee_cents=500
        ),
    )
    return metering, settlement


def test_exact_cent_multi_party_split_passes() -> None:
    metering, settlement = _build_multi_party_split()
    report = verify_settlement_reconciliation(metering, settlement)
    assert report.status == "VALID"


def test_exact_cent_flags_one_cent_error_on_residual_line() -> None:
    metering, settlement = _build_multi_party_split()
    settlement.lines[0] = replace(settlement.lines[0], amount_cents=7000)  # was 7001
    report = verify_settlement_reconciliation(metering, settlement)
    assert report.status == "INVALID"
    assert any(s.reason == "SETTLEMENT_AMOUNT_MISMATCH" for s in report.steps)


def test_exact_cent_flags_one_cent_error_on_non_largest_line() -> None:
    metering, settlement = _build_multi_party_split()
    settlement.lines[1] = replace(settlement.lines[1], amount_cents=2499)  # was 2500
    report = verify_settlement_reconciliation(metering, settlement)
    assert report.status == "INVALID"
    assert any(s.reason == "SETTLEMENT_AMOUNT_MISMATCH" for s in report.steps)
