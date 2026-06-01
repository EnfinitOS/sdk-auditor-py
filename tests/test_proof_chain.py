"""Chain walking — genesis, continuity, ordering."""

from __future__ import annotations

from dataclasses import replace

from enfinitos_auditor.proof_chain import verify_proof_chain

from tests.fixtures.builder import build_multi_record_chain, generate_key


def test_walks_a_valid_5_record_chain() -> None:
    key = generate_key()
    pack = build_multi_record_chain(5, key)
    report = verify_proof_chain(pack.records)
    assert report.status == "VALID"
    assert report.record_count == 5


def test_flags_an_empty_chain() -> None:
    report = verify_proof_chain([])
    assert report.status == "INVALID"


def test_flags_genesis_before_hash_not_null() -> None:
    key = generate_key()
    pack = build_multi_record_chain(3, key)
    broken = list(pack.records)
    broken[0] = replace(broken[0], before_hash="deadbeef")
    report = verify_proof_chain(broken)
    assert report.status == "INVALID"
    assert any(s.reason == "GENESIS_BEFORE_HASH_NOT_NULL" for s in report.steps)


def test_flags_chain_link_mismatch() -> None:
    key = generate_key()
    pack = build_multi_record_chain(3, key)
    broken = list(pack.records)
    broken[1] = replace(broken[1], before_hash="deadbeef")
    report = verify_proof_chain(broken)
    assert report.status == "INVALID"
    assert any(s.reason == "CHAIN_LINK_MISMATCH" for s in report.steps)


def test_flags_chain_out_of_order() -> None:
    key = generate_key()
    pack = build_multi_record_chain(3, key)
    broken = list(pack.records)
    swapped_payload = replace(
        broken[1].payload, issued_at="2020-01-01T00:00:00.000Z"
    )
    broken[1] = replace(broken[1], payload=swapped_payload)
    report = verify_proof_chain(broken)
    assert any(s.reason == "CHAIN_OUT_OF_ORDER" for s in report.steps)
