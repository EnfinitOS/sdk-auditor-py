"""Byte-exact parity with the platform's canonical JSON encoders."""

from __future__ import annotations

import pytest

from enfinitos_auditor.canonical_json import (
    base64url_decode,
    base64url_encode,
    canonical_sort_keys,
    canonicalise_proof_payload,
    canonicalise_proof_signing_input,
    sha256_prefixed,
)
from enfinitos_auditor.types import ProofReceiptPayload


FIXTURE = ProofReceiptPayload(
    version="1",
    receipt_id="rec_001",
    correlation_id=None,
    spatial_anchor_id="anchor_A",
    spatial_placement_id="place_A",
    issued_at="2026-04-01T12:00:00.000Z",
    rendered_at="2026-04-01T11:59:59.000Z",
    dwell_ms=3500,
    nonce="n0001",
    witness=None,
)


def test_canonicalise_proof_payload_emits_fields_in_declared_order() -> None:
    out = canonicalise_proof_payload(FIXTURE)
    assert out == (
        '{"version":"1",'
        '"receiptId":"rec_001",'
        '"correlationId":null,'
        '"spatialAnchorId":"anchor_A",'
        '"spatialPlacementId":"place_A",'
        '"issuedAt":"2026-04-01T12:00:00.000Z",'
        '"renderedAt":"2026-04-01T11:59:59.000Z",'
        '"dwellMs":3500,'
        '"nonce":"n0001",'
        '"witness":null}'
    )


def test_canonicalise_proof_signing_input_appends_key_id() -> None:
    out = canonicalise_proof_signing_input(FIXTURE, "key_001")
    assert out.endswith("|key_001")
    assert " " not in out


def test_canonical_sort_keys_sorts_object_keys() -> None:
    out = canonical_sort_keys({"b": 2, "a": 1, "c": 3})
    assert out == '{"a":1,"b":2,"c":3}'


def test_canonical_sort_keys_preserves_array_order() -> None:
    out = canonical_sort_keys([3, 1, 2])
    assert out == "[3,1,2]"


def test_canonical_sort_keys_recurses_into_objects_not_arrays() -> None:
    out = canonical_sort_keys(
        {"arr": [{"z": 1, "a": 2}, {"y": 1}], "nested": {"b": 1, "a": 2}}
    )
    assert out == '{"arr":[{"a":2,"z":1},{"y":1}],"nested":{"a":2,"b":1}}'


def test_canonical_sort_keys_handles_null_and_primitives() -> None:
    assert canonical_sort_keys(None) == "null"
    assert canonical_sort_keys(42) == "42"
    assert canonical_sort_keys("hello") == '"hello"'
    assert canonical_sort_keys(True) == "true"


def test_base64url_round_trips_arbitrary_bytes() -> None:
    bytes_in = bytes([0, 1, 2, 250, 251, 252, 253, 254, 255])
    enc = base64url_encode(bytes_in)
    assert "+" not in enc
    assert "/" not in enc
    assert "=" not in enc
    back = base64url_decode(enc)
    assert back == bytes_in


def test_base64url_decodes_padded_and_unpadded() -> None:
    padded = "AQIDBA=="
    unpadded = "AQIDBA"
    assert base64url_decode(padded) == base64url_decode(unpadded)


def test_sha256_prefixed_emits_platform_form() -> None:
    out = sha256_prefixed("abc")
    assert out == "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
