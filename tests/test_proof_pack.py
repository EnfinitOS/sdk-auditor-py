"""Parse + per-record signature verification."""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import replace

import pytest

from enfinitos_auditor.canonical_json import canonicalise_proof_payload
from enfinitos_auditor.errors import AuditorError
from enfinitos_auditor.keys import KeyDirectory, KeyDirectorySnapshot
from enfinitos_auditor.proof_pack import (
    Ed25519SignatureVerifier,
    parse_signed_proof_pack,
    verify_proof_record,
)

from tests.fixtures.builder import build_valid_pack, generate_key


def _pack_as_dict(pack):
    return {
        "envelopeVersion": pack.envelope_version,
        "issuedAt": pack.issued_at,
        "orgId": pack.org_id,
        "packId": pack.pack_id,
        "records": [
            {
                "payload": {
                    "version": r.payload.version,
                    "receiptId": r.payload.receipt_id,
                    "correlationId": r.payload.correlation_id,
                    "spatialAnchorId": r.payload.spatial_anchor_id,
                    "spatialPlacementId": r.payload.spatial_placement_id,
                    "issuedAt": r.payload.issued_at,
                    "renderedAt": r.payload.rendered_at,
                    "dwellMs": r.payload.dwell_ms,
                    "nonce": r.payload.nonce,
                    "witness": r.payload.witness,
                },
                "keyId": r.key_id,
                "algorithm": r.algorithm,
                "signature": r.signature,
                "payloadCanonical": r.payload_canonical,
                "beforeHash": r.before_hash,
                "afterHash": r.after_hash,
            }
            for r in pack.records
        ],
    }


def test_parse_accepts_well_formed_pack() -> None:
    pack, _ = build_valid_pack()
    parsed = parse_signed_proof_pack(_pack_as_dict(pack))
    assert parsed.envelope_version == "envelope.v1"
    assert len(parsed.records) == 1
    assert parsed.records[0].payload.receipt_id == "rec_001"


def test_parse_rejects_non_object_input() -> None:
    with pytest.raises(AuditorError, match="JSON object"):
        parse_signed_proof_pack("nope")


def test_parse_rejects_unsupported_envelope_version() -> None:
    pack, _ = build_valid_pack()
    raw = _pack_as_dict(pack)
    raw["envelopeVersion"] = "envelope.v99"
    with pytest.raises(AuditorError, match="unsupported envelopeVersion"):
        parse_signed_proof_pack(raw)


def test_parse_rejects_missing_payload_version() -> None:
    pack, _ = build_valid_pack()
    raw = _pack_as_dict(pack)
    del raw["records"][0]["payload"]["version"]
    with pytest.raises(AuditorError, match=r"payload\.version"):
        parse_signed_proof_pack(raw)


def test_parse_rejects_unknown_algorithm() -> None:
    pack, _ = build_valid_pack()
    raw = _pack_as_dict(pack)
    raw["records"][0]["algorithm"] = "rsa"
    with pytest.raises(AuditorError, match="algorithm"):
        parse_signed_proof_pack(raw)


# Per-record verify_proof_record


def _local_dir(keys):
    return KeyDirectory(
        KeyDirectorySnapshot(
            source="local", snapshot_id=None, issued_at=None, keys=keys
        )
    )


def test_verify_proof_record_all_valid_for_honest_record() -> None:
    pack, key = build_valid_pack()
    dir_ = _local_dir([key.verification_key])
    steps = verify_proof_record(pack.records[0], 0, dir_, Ed25519SignatureVerifier())
    for s in steps:
        assert s.status == "VALID", s


def test_verify_proof_record_flags_payload_canonical_mismatch() -> None:
    pack, key = build_valid_pack()
    tampered = replace(pack.records[0], payload_canonical="{}")
    dir_ = _local_dir([key.verification_key])
    steps = verify_proof_record(tampered, 0, dir_, Ed25519SignatureVerifier())
    assert any(s.reason == "PAYLOAD_CANONICAL_MISMATCH" for s in steps)


def test_verify_proof_record_flags_after_hash_mismatch() -> None:
    pack, key = build_valid_pack()
    tampered = replace(pack.records[0], after_hash="deadbeef")
    dir_ = _local_dir([key.verification_key])
    steps = verify_proof_record(tampered, 0, dir_, Ed25519SignatureVerifier())
    assert any(s.reason == "AFTER_HASH_MISMATCH" for s in steps)


def test_verify_proof_record_flags_unknown_key_id() -> None:
    pack, _ = build_valid_pack()
    other_key = generate_key("other_key")
    dir_ = _local_dir([other_key.verification_key])
    steps = verify_proof_record(pack.records[0], 0, dir_, Ed25519SignatureVerifier())
    assert any(s.reason == "UNKNOWN_KEY_ID" for s in steps)


def test_verify_proof_record_flags_signature_invalid_when_payload_tampered() -> None:
    pack, key = build_valid_pack()
    tampered_payload = replace(pack.records[0].payload, dwell_ms=999999)
    new_canonical = canonicalise_proof_payload(tampered_payload)
    fixed_tamper = replace(
        pack.records[0],
        payload=tampered_payload,
        payload_canonical=new_canonical,
        after_hash=hashlib.sha256(new_canonical.encode("utf-8")).hexdigest(),
    )
    dir_ = _local_dir([key.verification_key])
    steps = verify_proof_record(fixed_tamper, 0, dir_, Ed25519SignatureVerifier())
    sig = next((s for s in steps if s.kind == "signature"), None)
    assert sig is not None
    assert sig.status == "INVALID"
    assert sig.reason == "SIGNATURE_INVALID"
