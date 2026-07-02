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


# ---------------------------------------------------------------------
# Cross-pack chain anchor (prior_after_hash).
#
# The platform seals packs in series: pack 2's records[0].beforeHash
# equals pack 1's LAST afterHash, not null (sealProofPack threads
# previousAfterHash — packages/sandbox-core/src/tenantState.ts). Passing
# the prior pack's tail hash verifies cross-pack continuity instead of
# falsely tripping GENESIS_BEFORE_HASH_NOT_NULL. Mirrors the TS
# verifyProofChain priorAfterHash semantics.
# ---------------------------------------------------------------------


def test_second_pack_fails_genesis_without_prior_after_hash() -> None:
    key = generate_key()
    pack1 = build_multi_record_chain(3, key)
    tail = pack1.records[-1].after_hash
    pack2 = build_multi_record_chain(2, key, prior_after_hash=tail, start_index=3)
    # Legacy behaviour retained: no anchor supplied → genesis violation.
    report = verify_proof_chain(pack2.records)
    assert report.status == "INVALID"
    assert any(s.reason == "GENESIS_BEFORE_HASH_NOT_NULL" for s in report.steps)


def test_second_pack_verifies_with_prior_after_hash() -> None:
    key = generate_key()
    pack1 = build_multi_record_chain(3, key)
    tail = pack1.records[-1].after_hash
    pack2 = build_multi_record_chain(2, key, prior_after_hash=tail, start_index=3)
    report = verify_proof_chain(pack2.records, prior_after_hash=tail)
    assert report.status == "VALID"
    assert any(
        s.target == "records[0].beforeHash" and s.status == "VALID"
        for s in report.steps
    )


def test_second_pack_flags_chain_link_mismatch_on_wrong_prior() -> None:
    key = generate_key()
    pack1 = build_multi_record_chain(3, key)
    tail = pack1.records[-1].after_hash
    pack2 = build_multi_record_chain(2, key, prior_after_hash=tail, start_index=3)
    report = verify_proof_chain(pack2.records, prior_after_hash="0" * 64)
    assert report.status == "INVALID"
    assert any(
        s.target == "records[0].beforeHash" and s.reason == "CHAIN_LINK_MISMATCH"
        for s in report.steps
    )


def test_first_pack_with_null_genesis_fails_when_prior_supplied() -> None:
    # Symmetric guard: claiming a prior anchor for a genesis pack must
    # also fail — records[0].beforeHash (None) != the supplied anchor.
    key = generate_key()
    pack1 = build_multi_record_chain(2, key)
    report = verify_proof_chain(pack1.records, prior_after_hash="a" * 64)
    assert report.status == "INVALID"
    assert any(s.reason == "CHAIN_LINK_MISMATCH" for s in report.steps)
