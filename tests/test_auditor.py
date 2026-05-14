"""Top-level end-to-end behaviour for ``EnfinitOSAuditor.verify_*``."""

from __future__ import annotations

from dataclasses import replace

import pytest

from enfinitos_auditor import (
    AuditBundle,
    EnfinitOSAuditor,
)
from enfinitos_auditor.errors import AuditorError

from tests.fixtures.builder import (
    build_metering_summary,
    build_multi_record_chain,
    build_settlement_summary,
    build_valid_pack,
    generate_key,
)


def test_verify_proof_pack_valid_honest_pack() -> None:
    pack, key = build_valid_pack()
    auditor = EnfinitOSAuditor(
        verification_key_source="local",
        local_keys=[key.verification_key],
    )
    report = auditor.verify_proof_pack(pack)
    assert report.status == "VALID"
    assert report.pack_id == pack.pack_id
    assert report.keys_snapshot.source == "local"
    assert report.keys_snapshot.key_ids == [key.key_id]


def test_verify_proof_pack_invalid_for_tampered_payload() -> None:
    pack, key = build_valid_pack()
    tampered_payload = replace(pack.records[0].payload, dwell_ms=99999)
    tampered_record = replace(pack.records[0], payload=tampered_payload)
    tampered = replace(pack, records=[tampered_record])
    auditor = EnfinitOSAuditor(
        verification_key_source="local", local_keys=[key.verification_key]
    )
    report = auditor.verify_proof_pack(tampered)
    assert report.status == "INVALID"


def test_verify_proof_pack_returns_single_step_invalid_on_unparseable_input() -> None:
    auditor = EnfinitOSAuditor(verification_key_source="local", local_keys=[])
    report = auditor.verify_proof_pack("not a pack")
    assert report.status == "INVALID"
    assert report.envelope_version == "unknown"


def test_verify_all_full_pipeline_reconciles() -> None:
    key = generate_key()
    pack = build_multi_record_chain(3, key)
    metering = build_metering_summary(pack)
    settlement = build_settlement_summary(metering)
    auditor = EnfinitOSAuditor(
        verification_key_source="local", local_keys=[key.verification_key]
    )
    full = auditor.verify_all(
        AuditBundle(pack=pack, metering=metering, settlement=settlement)
    )
    assert full.status == "VALID"
    assert full.pack.status == "VALID"
    assert full.chain.status == "VALID"
    assert full.metering.status == "VALID"
    assert full.settlement.status == "VALID"


def test_verify_all_skips_metering_and_settlement_when_not_in_bundle() -> None:
    pack, key = build_valid_pack()
    auditor = EnfinitOSAuditor(
        verification_key_source="local", local_keys=[key.verification_key]
    )
    full = auditor.verify_all(AuditBundle(pack=pack))
    assert full.metering.status == "SKIPPED"
    assert full.settlement.status == "SKIPPED"
    assert full.status == "VALID"


def test_verify_all_demotes_to_invalid_when_any_substep_fails() -> None:
    key = generate_key()
    pack = build_multi_record_chain(2, key)
    metering = build_metering_summary(pack)
    settlement = build_settlement_summary(metering)
    # Tamper a settlement amount.
    bad_line = replace(settlement.lines[0], amount_cents=settlement.lines[0].amount_cents + 999)
    settlement.lines[0] = bad_line
    auditor = EnfinitOSAuditor(
        verification_key_source="local", local_keys=[key.verification_key]
    )
    full = auditor.verify_all(
        AuditBundle(pack=pack, metering=metering, settlement=settlement)
    )
    assert full.status == "INVALID"
    assert full.settlement.status == "INVALID"


def test_constructor_rejects_local_source_without_local_keys() -> None:
    with pytest.raises(AuditorError):
        EnfinitOSAuditor(verification_key_source="local")


def test_fetch_keys_returns_loaded_directory() -> None:
    pack, key = build_valid_pack()
    auditor = EnfinitOSAuditor(
        verification_key_source="local", local_keys=[key.verification_key]
    )
    keys = auditor.fetch_keys()
    assert len(keys) == 1
    assert keys[0].key_id == key.key_id
