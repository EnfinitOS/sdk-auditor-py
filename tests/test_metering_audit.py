"""Metering re-projection audit."""

from __future__ import annotations

from dataclasses import replace

from enfinitos_auditor.metering_audit import verify_metering_projection

from tests.fixtures.builder import (
    build_metering_summary,
    build_multi_record_chain,
    generate_key,
)


def test_passes_when_metering_reprojects_exactly_from_proof() -> None:
    key = generate_key()
    pack = build_multi_record_chain(4, key)
    metering = build_metering_summary(pack)
    report = verify_metering_projection(pack.records, metering, pack.org_id)
    assert report.status == "VALID"
    assert report.meter_record_count == 4


def test_flags_meter_record_for_unknown_proof() -> None:
    key = generate_key()
    pack = build_multi_record_chain(2, key)
    metering = build_metering_summary(pack)
    metering.records[0] = replace(metering.records[0], proof_receipt_id="ghost_id")
    report = verify_metering_projection(pack.records, metering, pack.org_id)
    assert report.status == "INVALID"
    assert any(
        s.reason == "METER_RECORD_FOR_UNKNOWN_PROOF" for s in report.steps
    )


def test_flags_meter_idem_key_mismatch() -> None:
    key = generate_key()
    pack = build_multi_record_chain(2, key)
    metering = build_metering_summary(pack)
    metering.records[0] = replace(metering.records[0], idem_key="0" * 64)
    report = verify_metering_projection(pack.records, metering, pack.org_id)
    assert any(s.reason == "METER_IDEM_KEY_MISMATCH" for s in report.steps)


def test_flags_meter_unit_count_mismatch() -> None:
    key = generate_key()
    pack = build_multi_record_chain(2, key)
    metering = build_metering_summary(pack)
    metering.records[0] = replace(metering.records[0], unit_count="9999.999999")
    report = verify_metering_projection(pack.records, metering, pack.org_id)
    assert any(s.reason == "METER_UNIT_COUNT_MISMATCH" for s in report.steps)


def test_flags_meter_org_mismatch() -> None:
    key = generate_key()
    pack = build_multi_record_chain(2, key)
    metering = build_metering_summary(pack)
    metering.org_id = "org_different"
    report = verify_metering_projection(pack.records, metering, pack.org_id)
    assert any(s.reason == "METER_ORG_MISMATCH" for s in report.steps)


def test_flags_meter_total_mismatch() -> None:
    key = generate_key()
    pack = build_multi_record_chain(2, key)
    metering = build_metering_summary(pack)
    assert metering.totals is not None
    metering.totals["DWELL_SECONDS"] = "0.000001"
    report = verify_metering_projection(pack.records, metering, pack.org_id)
    assert any(s.reason == "METER_TOTAL_MISMATCH" for s in report.steps)
