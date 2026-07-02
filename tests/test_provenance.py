"""Rights-provenance write-time signature verification tests.

Mirrors ``packages/sdks/auditor-ts/__tests__/provenance.test.ts``
case-for-case so the three SDKs stay behaviourally in sync: honest
chain VALID, field tamper → PROVENANCE_CANONICAL_MISMATCH, signature
splice → PROVENANCE_SIGNATURE_INVALID, malformed b64 →
PROVENANCE_SIGNATURE_MALFORMED, unknown key, key revocation, mixed
legacy back-compat, all-legacy SKIPPED, org splice, empty set,
pre-built directory acceptance.
"""

from __future__ import annotations

from dataclasses import replace

from enfinitos_auditor.keys import KeyDirectory, KeyDirectorySnapshot
from enfinitos_auditor.provenance import (
    PROVENANCE_SIGNING_VERSION,
    ProvenanceSigningFields,
    canonicalise_provenance_signing_input,
    verify_provenance_chain,
    verify_provenance_record,
)

from tests.fixtures.builder import (
    build_legacy_provenance_record,
    generate_key,
    sign_provenance_record,
)


def _directory_for(key) -> KeyDirectory:
    return KeyDirectory(
        KeyDirectorySnapshot(
            source="local",
            snapshot_id=None,
            issued_at=None,
            keys=[key.verification_key],
        )
    )


def _issued_fields(org_id: str = "org_test") -> ProvenanceSigningFields:
    """A representative RIGHT_ISSUED signing-fields shape — same
    values as the TS suite's ``issuedFields``."""

    return ProvenanceSigningFields(
        org_id=org_id,
        event_type="RIGHT_ISSUED",
        right_id="rgh_001",
        basis_id="bas_001",
        offer_id=None,
        before_hash=None,
        after_hash="sha256:" + "1" * 64,
    )


# ---------------------------------------------------------------------
# canonicalise_provenance_signing_input
# ---------------------------------------------------------------------


def test_canonical_input_produces_pipe_delimited_right_provenance_v1_form() -> None:
    out = canonicalise_provenance_signing_input(_issued_fields(), "key-1")
    assert out == (
        f"{PROVENANCE_SIGNING_VERSION}|org_test|RIGHT_ISSUED|rgh_001|"
        f"bas_001|-|-|sha256:{'1' * 64}|key-1"
    )


def test_canonical_input_encodes_none_and_empty_string_identically_as_dash() -> None:
    with_none = _issued_fields()
    with_none.offer_id = None
    with_empty = _issued_fields()
    with_empty.offer_id = ""
    assert canonicalise_provenance_signing_input(
        with_none, "key-1"
    ) == canonicalise_provenance_signing_input(with_empty, "key-1")


def test_canonical_input_includes_the_key_id() -> None:
    a = canonicalise_provenance_signing_input(_issued_fields(), "key-a")
    b = canonicalise_provenance_signing_input(_issued_fields(), "key-b")
    assert a != b


# ---------------------------------------------------------------------
# verify_provenance_record — write-time signed records
# ---------------------------------------------------------------------


def test_record_all_valid_steps_for_an_honest_record() -> None:
    key = generate_key("prov_key_1")
    record = sign_provenance_record(_issued_fields(), key)
    steps = verify_provenance_record(record, 0, _directory_for(key))
    assert len(steps) > 0
    for s in steps:
        assert s.status == "VALID", s


def test_record_flags_canonical_mismatch_when_a_raw_field_is_edited() -> None:
    key = generate_key()
    record = sign_provenance_record(_issued_fields(), key)
    # Move the right to a different id without re-signing — the
    # classic post-write tamper the write-time signature exists for.
    tampered = replace(record, right_id="rgh_evil")
    steps = verify_provenance_record(tampered, 0, _directory_for(key))
    fail = next(
        (s for s in steps if s.reason == "PROVENANCE_CANONICAL_MISMATCH"), None
    )
    assert fail is not None
    assert fail.status == "INVALID"


def test_record_flags_canonical_mismatch_when_payload_canonical_missing() -> None:
    key = generate_key()
    record = sign_provenance_record(_issued_fields(), key)
    partial = replace(record, payload_canonical=None)
    steps = verify_provenance_record(partial, 0, _directory_for(key))
    assert any(s.reason == "PROVENANCE_CANONICAL_MISMATCH" for s in steps)


def test_record_flags_signature_invalid_when_signature_bytes_spliced() -> None:
    key = generate_key()
    record_a = sign_provenance_record(_issued_fields(), key)
    record_b = sign_provenance_record(
        ProvenanceSigningFields(
            org_id="org_test",
            event_type="RIGHT_SUSPENDED",
            right_id="rgh_001",
            basis_id="bas_001",
            offer_id=None,
            before_hash="sha256:" + "1" * 64,
            after_hash="sha256:" + "2" * 64,
        ),
        key,
    )
    # A's claims with B's signature — both internally well-formed.
    spliced = replace(record_a, signature=record_b.signature)
    steps = verify_provenance_record(spliced, 0, _directory_for(key))
    fail = next(
        (s for s in steps if s.reason == "PROVENANCE_SIGNATURE_INVALID"), None
    )
    assert fail is not None
    assert fail.status == "INVALID"


def test_record_flags_signature_malformed_for_bad_b64_or_truncation() -> None:
    key = generate_key()
    record = sign_provenance_record(_issued_fields(), key)

    # Bad alphabet + padding — strict base64url rejects.
    bad_alphabet = replace(record, signature="not+base64url/safe==")
    steps = verify_provenance_record(bad_alphabet, 0, _directory_for(key))
    assert any(s.reason == "PROVENANCE_SIGNATURE_MALFORMED" for s in steps)

    # Truncated signature still canonical-matches (claims intact), so
    # the failure has to come from the byte-length gate.
    truncated = replace(record, signature=record.signature[:16])
    steps = verify_provenance_record(truncated, 0, _directory_for(key))
    assert any(s.reason == "PROVENANCE_SIGNATURE_MALFORMED" for s in steps)


def test_record_flags_unknown_key_id_when_directory_lacks_signing_key() -> None:
    key = generate_key("prov_key_signing")
    other = generate_key("prov_key_other")
    record = sign_provenance_record(_issued_fields(), key)
    steps = verify_provenance_record(record, 0, _directory_for(other))
    fail = next((s for s in steps if s.reason == "UNKNOWN_KEY_ID"), None)
    assert fail is not None
    assert fail.kind == "key_lookup"


def test_record_flags_key_revoked_before_issuance() -> None:
    key = generate_key("prov_key_revoked")
    revoked_key = replace(
        key.verification_key, revoked_at="2026-01-01T00:00:00.000Z"
    )
    directory = KeyDirectory(
        KeyDirectorySnapshot(
            source="local",
            snapshot_id=None,
            issued_at=None,
            keys=[revoked_key],
        )
    )
    record = sign_provenance_record(
        _issued_fields(), key, occurred_at="2026-06-01T00:00:00.000Z"
    )
    steps = verify_provenance_record(record, 0, directory)
    assert any(s.reason == "KEY_REVOKED_BEFORE_ISSUANCE" for s in steps)


# ---------------------------------------------------------------------
# verify_provenance_record — legacy (pre-Wave-14) records
# ---------------------------------------------------------------------


def test_legacy_record_reports_informational_skipped_never_invalid() -> None:
    key = generate_key()
    legacy = build_legacy_provenance_record()
    steps = verify_provenance_record(legacy, 0, _directory_for(key))
    assert len(steps) == 1
    assert steps[0].status == "SKIPPED"
    assert steps[0].reason == "PROVENANCE_UNSIGNED_RECORD"
    assert steps[0].kind == "provenance_signature"


# ---------------------------------------------------------------------
# verify_provenance_chain
# ---------------------------------------------------------------------


def test_chain_valid_for_a_clean_signed_lifecycle() -> None:
    key = generate_key()
    records = [
        sign_provenance_record(_issued_fields(), key),
        sign_provenance_record(
            ProvenanceSigningFields(
                org_id="org_test",
                event_type="RIGHT_SUSPENDED",
                right_id="rgh_001",
                basis_id=None,
                offer_id=None,
                before_hash="sha256:" + "1" * 64,
                after_hash="sha256:" + "2" * 64,
            ),
            key,
        ),
        sign_provenance_record(
            ProvenanceSigningFields(
                org_id="org_test",
                event_type="RIGHT_REACTIVATED",
                right_id="rgh_001",
                basis_id=None,
                offer_id=None,
                before_hash="sha256:" + "2" * 64,
                after_hash="sha256:" + "3" * 64,
            ),
            key,
        ),
    ]

    report = verify_provenance_chain(records, [key.verification_key])
    assert report.status == "VALID"
    assert report.record_count == 3
    assert report.signed_record_count == 3
    assert report.unsigned_record_count == 0
    assert all(s.status == "VALID" for s in report.steps)


def test_chain_invalid_and_points_at_the_tampered_records_index() -> None:
    key = generate_key()
    records = [
        sign_provenance_record(_issued_fields(), key),
        sign_provenance_record(
            ProvenanceSigningFields(
                org_id="org_test",
                event_type="RIGHT_REVOKED",
                right_id="rgh_001",
                basis_id=None,
                offer_id=None,
                before_hash="sha256:" + "1" * 64,
                after_hash="sha256:" + "9" * 64,
            ),
            key,
        ),
    ]
    # Flip the revocation into a reactivation without re-signing.
    records[1] = replace(records[1], provenance_event_type="RIGHT_REACTIVATED")

    report = verify_provenance_chain(records, [key.verification_key])
    assert report.status == "INVALID"
    fail = next(
        (
            s
            for s in report.steps
            if s.status == "INVALID"
            and s.reason == "PROVENANCE_CANONICAL_MISMATCH"
        ),
        None,
    )
    assert fail is not None
    assert "provenance[1]" in fail.target


def test_chain_mixed_signed_plus_legacy_sets_valid_with_informational() -> None:
    key = generate_key()
    records = [
        build_legacy_provenance_record(org_id="org_test"),
        sign_provenance_record(_issued_fields(), key),
    ]

    report = verify_provenance_chain(records, [key.verification_key])
    assert report.status == "VALID"
    assert report.signed_record_count == 1
    assert report.unsigned_record_count == 1
    informational = [
        s for s in report.steps if s.reason == "PROVENANCE_UNSIGNED_RECORD"
    ]
    assert len(informational) == 1
    assert informational[0].status == "SKIPPED"


def test_chain_all_legacy_set_reports_skipped() -> None:
    key = generate_key()
    records = [
        build_legacy_provenance_record(),
        build_legacy_provenance_record(
            provenance_event_type="RIGHT_SUSPENDED"
        ),
    ]
    report = verify_provenance_chain(records, [key.verification_key])
    assert report.status == "SKIPPED"
    assert report.signed_record_count == 0
    assert report.unsigned_record_count == 2
    assert all(s.status == "SKIPPED" for s in report.steps)


def test_chain_flags_org_mismatch_on_a_tenant_spliced_record_set() -> None:
    key = generate_key()
    records = [
        sign_provenance_record(_issued_fields("org_test"), key),
        sign_provenance_record(_issued_fields("org_other"), key),
    ]
    report = verify_provenance_chain(
        records, [key.verification_key], expected_org_id="org_test"
    )
    assert report.status == "INVALID"
    fail = next(
        (s for s in report.steps if s.reason == "PROVENANCE_ORG_MISMATCH"),
        None,
    )
    assert fail is not None
    assert fail.target == "provenance[1].orgId"


def test_chain_rejects_an_empty_record_set_as_invalid() -> None:
    key = generate_key()
    report = verify_provenance_chain([], [key.verification_key])
    assert report.status == "INVALID"
    assert report.steps[0].reason == "MALFORMED_PACK"


def test_chain_accepts_a_pre_built_key_directory() -> None:
    key = generate_key()
    record = sign_provenance_record(_issued_fields(), key)
    report = verify_provenance_chain([record], _directory_for(key))
    assert report.status == "VALID"


def test_report_stamps_sdk_version_and_counts() -> None:
    # The report carries the SDK version + the signed/unsigned
    # partition so a regulator can quote "N of M records carry
    # write-time signatures" directly — same wire-level claims as the
    # TS/Rust reports.
    key = generate_key()
    record = sign_provenance_record(_issued_fields(), key)
    report = verify_provenance_chain([record], [key.verification_key])
    # Compare against the exported constant, not a hardcoded literal, so a
    # version bump can never break this test again (it asserts the report
    # STAMPS the SDK version — not which version that is).
    from enfinitos_auditor import SDK_VERSION

    assert report.sdk_version == SDK_VERSION
    assert report.record_count == 1
    assert report.signed_record_count == 1
    assert report.unsigned_record_count == 0
