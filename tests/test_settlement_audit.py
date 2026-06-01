"""Settlement reconciliation audit."""

from __future__ import annotations

from dataclasses import replace

from enfinitos_auditor.settlement_audit import verify_settlement_reconciliation

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
