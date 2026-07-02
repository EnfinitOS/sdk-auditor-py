"""Signed-export verification (export.v1) — round-trip + tamper tests.

The fixture signs exactly the way the platform does
(packages/sandbox-core/src/exports.ts): canonical_sort_keys(payload),
sha256 hex of the canonical bytes, Ed25519 over
``f"{canonical}|{key_id}"``. Mirrors
packages/sdks/auditor-ts/__tests__/exports.test.ts.
"""

from __future__ import annotations

import hashlib
from dataclasses import replace
from typing import Any

from enfinitos_auditor.canonical_json import base64url_encode, canonical_sort_keys
from enfinitos_auditor.exports import SignedExport, verify_signed_export
from enfinitos_auditor.keys import KeyDirectory, KeyDirectorySnapshot

from tests.fixtures.builder import GeneratedKey, generate_key


def _directory_for(key: GeneratedKey) -> KeyDirectory:
    return KeyDirectory(
        KeyDirectorySnapshot(
            source="local",
            snapshot_id=None,
            issued_at=None,
            keys=[key.verification_key],
        )
    )


def _sign_export(
    kind: str,
    org_id: str,
    payload: Any,
    key: GeneratedKey,
    exported_at: str = "2026-07-01T00:00:00.000Z",
) -> SignedExport:
    """Mirror of the platform signer (sandbox-core exports.ts signExport)."""

    payload_canonical = canonical_sort_keys(payload)
    payload_canonical_hash = hashlib.sha256(
        payload_canonical.encode("utf-8")
    ).hexdigest()
    signature_bytes = key.private_key.sign(
        f"{payload_canonical}|{key.key_id}".encode("utf-8")
    )
    return SignedExport(
        kind=kind,
        envelope_version="export.v1",
        org_id=org_id,
        exported_at=exported_at,
        key_id=key.key_id,
        algorithm="ed25519",
        payload=payload,
        payload_canonical=payload_canonical,
        payload_canonical_hash=payload_canonical_hash,
        signature=base64url_encode(signature_bytes),
    )


_METERING_PAYLOAD = {
    "schemaVersion": "metering.v1",
    "orgId": "org_demo",
    "periodStart": "2026-06-01T00:00:00.000Z",
    "periodEnd": "2026-07-01T00:00:00.000Z",
    "records": [
        {
            "idemKey": "a" * 64,
            "proofReceiptId": "rcpt_demo_0001",
            "unitType": "ATTENTION_SECONDS",
            "unitCount": "6.500000",
            "weight": "1",
            "spatialAnchorId": "wsp_northgate",
            "spatialPlacementId": None,
            "observedAt": "2026-06-14T12:00:00.000Z",
            "status": "PROJECTED",
        }
    ],
    "totals": {"ATTENTION_SECONDS": "6.500000"},
}


def test_round_trips_a_freshly_signed_metering_export_as_valid() -> None:
    key = generate_key()
    exp = _sign_export("metering.export.v1", "org_demo", _METERING_PAYLOAD, key)
    report = verify_signed_export(exp, _directory_for(key))
    assert report.status == "VALID"
    assert report.kind == "metering.export.v1"
    assert all(s.status == "VALID" for s in report.steps)


def test_accepts_the_raw_wire_dict_shape() -> None:
    # A regulator feeds json.load(file) directly — camelCase wire keys.
    key = generate_key()
    exp = _sign_export("metering.export.v1", "org_demo", _METERING_PAYLOAD, key)
    wire = {
        "kind": exp.kind,
        "envelopeVersion": exp.envelope_version,
        "orgId": exp.org_id,
        "exportedAt": exp.exported_at,
        "keyId": exp.key_id,
        "algorithm": exp.algorithm,
        "payload": exp.payload,
        "payloadCanonical": exp.payload_canonical,
        "payloadCanonicalHash": exp.payload_canonical_hash,
        "signature": exp.signature,
    }
    report = verify_signed_export(wire, _directory_for(key))
    assert report.status == "VALID"


def test_detects_a_tampered_payload_payload_canonical_mismatch() -> None:
    key = generate_key()
    exp = _sign_export("metering.export.v1", "org_demo", _METERING_PAYLOAD, key)
    tampered = replace(
        exp, payload={**_METERING_PAYLOAD, "orgId": "org_attacker"}
    )
    report = verify_signed_export(tampered, _directory_for(key))
    assert report.status == "INVALID"
    assert any(s.reason == "PAYLOAD_CANONICAL_MISMATCH" for s in report.steps)


def test_detects_a_tampered_transparency_hash() -> None:
    key = generate_key()
    exp = _sign_export("metering.export.v1", "org_demo", _METERING_PAYLOAD, key)
    tampered = replace(exp, payload_canonical_hash="0" * 64)
    report = verify_signed_export(tampered, _directory_for(key))
    assert report.status == "INVALID"
    assert any(s.reason == "EXPORT_PAYLOAD_HASH_MISMATCH" for s in report.steps)


def test_rejects_a_signature_from_a_different_key() -> None:
    key = generate_key()
    other_key = generate_key("fixture_other")
    exp = _sign_export(
        "settlement.export.v1", "org_demo", _METERING_PAYLOAD, other_key
    )
    # Present it as if signed by `key` — directory resolves key, signature
    # is other's. keyId is bound into the signed bytes AND the key differs,
    # so the signature cannot verify.
    forged = replace(exp, key_id=key.key_id)
    report = verify_signed_export(forged, _directory_for(key))
    assert report.status == "INVALID"
    assert any(s.reason == "SIGNATURE_INVALID" for s in report.steps)


def test_reports_an_unknown_key_id_as_a_key_lookup_failure() -> None:
    key = generate_key()
    stranger = generate_key("fixture_stranger")
    exp = _sign_export("metering.export.v1", "org_demo", _METERING_PAYLOAD, stranger)
    report = verify_signed_export(exp, _directory_for(key))
    assert report.status == "INVALID"
    assert any(
        s.kind == "key_lookup" and s.reason == "UNKNOWN_KEY_ID"
        for s in report.steps
    )


def test_rejects_an_unsupported_envelope_version() -> None:
    key = generate_key()
    exp = replace(
        _sign_export("metering.export.v1", "org_demo", _METERING_PAYLOAD, key),
        envelope_version="export.v9",
    )
    report = verify_signed_export(exp, _directory_for(key))
    assert report.status == "INVALID"
    assert any(
        s.reason == "UNSUPPORTED_ENVELOPE_VERSION" for s in report.steps
    )
