"""enfinitos_auditor — rights-provenance write-time signature
verification.

Wave 14 Phase 2. Python port of the TS reference ``provenance.ts``;
identical canonical-string construction, reason codes, report shape,
and legacy posture, so a regulator auditing the same record set with
either SDK gets the same verdict on every step.

Independently verifies the per-record Ed25519 signatures the platform
computes at write time on every rights-provenance row
(apps/api/src/modules/rights/provenanceSigner.ts): basis
assert/verify/reject, right issue/suspend/resume/revoke/expire, offer
propose/accept/counter/reject/withdraw/expire, and challenge
open/resolve/withdraw.

The signing input is a flat pipe-delimited string — NOT canonical
JSON — so TS / Rust / Python verifiers reconstruct the exact bytes
without sharing a canonical-JSON library::

    "rightProvenance.v1|<orgId>|<eventType>|<rightId|->|<basisId|->|
     <offerId|->|<beforeHash|->|<afterHash|->|<keyId>"

where ``-`` encodes absence (None or empty string — the platform
deliberately collapses the two so an absent rightId cannot collide
with a literal empty-string rightId).

Verification path per record
----------------------------
  ed25519 records (write-time signed):
    1. Re-derive the canonical signing input from the record's raw
       fields + signer_key_id, and assert byte-equality against the
       record's ``payload_canonical`` transparency field
       (PROVENANCE_CANONICAL_MISMATCH on divergence).
    2. Look the signer_key_id up in the KeyDirectory; reject if
       missing / outside validity window / revoked
       (UNKNOWN_KEY_ID / KEY_OUTSIDE_VALIDITY_WINDOW /
       KEY_REVOKED_BEFORE_ISSUANCE — same codes as receipts).
    3. Decode the base64url signature + public key
       (PROVENANCE_SIGNATURE_MALFORMED if not strict base64url or not
       64/32 bytes).
    4. Ed25519-verify the signature over the canonical bytes
       (PROVENANCE_SIGNATURE_INVALID on failure).

  hmac-sha256 records (legacy, pre-Wave-14):
    The platform synthesised a read-time transport HMAC; there is
    nothing write-signed for an independent party to verify. The
    verifier reports a single SKIPPED step per record carrying the
    informational reason PROVENANCE_UNSIGNED_RECORD — NEVER an
    INVALID. Published 0.0.1-era exports keep verifying, with the
    unsigned records clearly labelled.

Relationship to the other chain verifiers
-----------------------------------------
This module verifies WHO wrote each row (non-repudiation). It is
deliberately orthogonal to:
  - ``tenant_chain`` — verifies the rows' POSITION in the tenant's
    append-only history (insertion/rewrite detection). Run both for
    the full provenance posture.
  - ``proof_chain`` — the spatial-chain receipt walker; receipts are
    a different artefact with a different canonical encoding.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional, Sequence, Union

from .canonical_json import base64url_decode_strict
from .keys import KeyDirectory, KeyDirectorySnapshot, KeyLookupMiss
from .proof_pack import SignatureVerifier, default_signature_verifier
from .types import (
    SDK_VERSION,
    AuditStep,
    ProvenanceAuditReport,
    ProvenanceRecord,
    VerificationKey,
)


#: Stable canonical signing-input version tag.
PROVENANCE_SIGNING_VERSION: str = "rightProvenance.v1"


class ProvenanceSigningFields:
    """The subset of :class:`ProvenanceRecord` fields that participate
    in the canonical signing input. Kept as its own type so callers
    building conformance fixtures don't have to fabricate the envelope
    fields.
    """

    __slots__ = (
        "org_id",
        "event_type",
        "right_id",
        "basis_id",
        "offer_id",
        "before_hash",
        "after_hash",
    )

    def __init__(
        self,
        org_id: str,
        event_type: str,
        right_id: Optional[str] = None,
        basis_id: Optional[str] = None,
        offer_id: Optional[str] = None,
        before_hash: Optional[str] = None,
        after_hash: Optional[str] = None,
    ) -> None:
        self.org_id = org_id
        #: The platform's raw lifecycle event tag (e.g. RIGHT_ISSUED).
        self.event_type = event_type
        self.right_id = right_id
        self.basis_id = basis_id
        self.offer_id = offer_id
        self.before_hash = before_hash
        self.after_hash = after_hash


def canonicalise_provenance_signing_input(
    fields: ProvenanceSigningFields, key_id: str
) -> str:
    """Reconstruct the exact canonical string the platform signed at
    write time. Pure; byte-for-byte parity with
    apps/api/src/modules/rights/provenanceSigner.ts
    ``canonicaliseProvenanceSigningInput`` and the TS / Rust SDK
    ports. Absence (None or empty string) encodes as ``-``.
    """

    def f(v: Optional[str]) -> str:
        return "-" if v is None or v == "" else v

    return "|".join(
        [
            PROVENANCE_SIGNING_VERSION,
            f(fields.org_id),
            f(fields.event_type),
            f(fields.right_id),
            f(fields.basis_id),
            f(fields.offer_id),
            f(fields.before_hash),
            f(fields.after_hash),
            f(key_id),
        ]
    )


# ---------------------------------------------------------------------
# Per-record verification
# ---------------------------------------------------------------------


def verify_provenance_record(
    record: ProvenanceRecord,
    record_index: int,
    keys: KeyDirectory,
    verifier: Optional[SignatureVerifier] = None,
) -> List[AuditStep]:
    """Verify one rights-provenance record's write-time signature.

    Returns audit steps mirroring the receipt-side
    ``verify_proof_record`` shape:

      - legacy (hmac-sha256) record → one SKIPPED step with the
        informational reason PROVENANCE_UNSIGNED_RECORD.
      - ed25519 record → canonicalisation step, key-lookup step,
        signature step; each VALID or INVALID with a structured
        reason.
    """

    verifier = verifier or default_signature_verifier()
    steps: List[AuditStep] = []

    def target(suffix: str) -> str:
        return f"provenance[{record_index}].{suffix}"

    # Legacy partition — informational, never a failure. There is no
    # write-time signature to verify; the platform's honest-history
    # decision at Wave 14 was to tag rather than back-sign.
    if record.signature_algorithm != "ed25519":
        steps.append(
            AuditStep(
                target=target("signature"),
                kind="provenance_signature",
                status="SKIPPED",
                reason="PROVENANCE_UNSIGNED_RECORD",
                message=(
                    "record pre-dates write-time provenance signing "
                    "(read-time HMAC only) — not independently verifiable; "
                    "informational, not a failure"
                ),
                detail={
                    "signatureAlgorithm": record.signature_algorithm,
                    "provenanceEventType": record.provenance_event_type,
                },
            )
        )
        return steps

    # 1. Canonical-input parity. The record ships ``payload_canonical``
    # as a transparency aid; we re-derive from the raw fields and
    # compare byte-for-byte. A divergence means the raw fields were
    # edited after signing, or the canonicaliser version skewed.
    reconstructed = canonicalise_provenance_signing_input(
        ProvenanceSigningFields(
            org_id=record.org_id,
            event_type=record.provenance_event_type,
            right_id=record.right_id,
            basis_id=record.basis_id,
            offer_id=record.offer_id,
            before_hash=record.provenance_before_hash,
            after_hash=record.provenance_after_hash,
        ),
        record.signer_key_id,
    )
    if record.payload_canonical is None:
        steps.append(
            AuditStep(
                target=target("payloadCanonical"),
                kind="provenance_signature",
                status="INVALID",
                reason="PROVENANCE_CANONICAL_MISMATCH",
                message=(
                    "ed25519 record carries no payloadCanonical — the "
                    "signed bytes cannot be attested; partial-fill violates "
                    "the write-time signing contract"
                ),
            )
        )
        return steps
    if reconstructed != record.payload_canonical:
        steps.append(
            AuditStep(
                target=target("payloadCanonical"),
                kind="provenance_signature",
                status="INVALID",
                reason="PROVENANCE_CANONICAL_MISMATCH",
                message=(
                    "the canonical signing input the SDK reconstructed "
                    "from the record's raw fields does not match the bytes "
                    "the record ships — field tampering or canonicaliser "
                    "version skew"
                ),
                detail={
                    "expected": record.payload_canonical[:256],
                    "actual": reconstructed[:256],
                },
            )
        )
        # Continue: the signature step over the SHIPPED canonical
        # bytes still tells the auditor whether the signature is at
        # least internally consistent — useful forensics either way.
    else:
        steps.append(
            AuditStep(
                target=target("payloadCanonical"),
                kind="provenance_signature",
                status="VALID",
                message="canonical signing input reconstructs from the raw fields",
            )
        )

    # 2. Key lookup — same directory + validity-window semantics as the
    # receipt verifier; ``occurred_at`` plays the role of issued_at.
    lookup = keys.lookup(record.signer_key_id, record.occurred_at)
    if isinstance(lookup, KeyLookupMiss):
        steps.append(
            AuditStep(
                target=target("signerKeyId"),
                kind="key_lookup",
                status="INVALID",
                reason=lookup.reason,
                message=(
                    f"provenance signing key {record.signer_key_id!r} "
                    f"rejected: {lookup.reason}"
                ),
                detail={
                    "signerKeyId": record.signer_key_id,
                    "occurredAt": record.occurred_at,
                },
            )
        )
        return steps
    steps.append(
        AuditStep(
            target=target("signerKeyId"),
            kind="key_lookup",
            status="VALID",
            message=(
                f"key {record.signer_key_id!r} resolved and valid for occurredAt"
            ),
        )
    )

    # 3. Decode signature + public key — strict base64url (unpadded).
    # The strict decoder is mandatory here: stdlib b64decode silently
    # discards invalid characters, which would mask malformed wire
    # spellings the TS reference rejects.
    try:
        sig_bytes = base64url_decode_strict(record.signature)
        pub_bytes = base64url_decode_strict(lookup.key.public_key)
    except Exception as exc:
        steps.append(
            AuditStep(
                target=target("signature"),
                kind="provenance_signature",
                status="INVALID",
                reason="PROVENANCE_SIGNATURE_MALFORMED",
                message=f"signature/public-key decoding failed: {exc}",
            )
        )
        return steps
    if len(sig_bytes) != 64 or len(pub_bytes) != 32:
        steps.append(
            AuditStep(
                target=target("signature"),
                kind="provenance_signature",
                status="INVALID",
                reason="PROVENANCE_SIGNATURE_MALFORMED",
                message=(
                    f"expected 64-byte signature / 32-byte public key, got "
                    f"{len(sig_bytes)} / {len(pub_bytes)}"
                ),
            )
        )
        return steps

    # 4. Ed25519 verify — over the SHIPPED canonical bytes (the exact
    # bytes the platform claims it signed). If step 1 already flagged a
    # canonical mismatch, a VALID result here means "internally
    # consistent signature over tampered claims" — the report is
    # already INVALID from step 1, so no failure is masked.
    message = record.payload_canonical.encode("utf-8")
    try:
        ok = verifier.verify_ed25519(pub_bytes, message, sig_bytes)
    except Exception as exc:
        steps.append(
            AuditStep(
                target=target("signature"),
                kind="provenance_signature",
                status="INVALID",
                reason="PROVENANCE_SIGNATURE_INVALID",
                message=f"signature verify threw: {exc}",
            )
        )
        return steps
    steps.append(
        AuditStep(
            target=target("signature"),
            kind="provenance_signature",
            status="VALID" if ok else "INVALID",
            reason=None if ok else "PROVENANCE_SIGNATURE_INVALID",
            message=(
                "Ed25519 write-time signature verifies against the declared key"
                if ok
                else (
                    "Ed25519 write-time signature did NOT verify — the "
                    "record was tampered with after signing, or the "
                    "signerKeyId points to a different key than the one "
                    "that signed it"
                )
            ),
        )
    )

    return steps


# ---------------------------------------------------------------------
# Chain-level verification
# ---------------------------------------------------------------------


def verify_provenance_chain(
    records: Sequence[ProvenanceRecord],
    keys: Union[Sequence[VerificationKey], KeyDirectory],
    expected_org_id: Optional[str] = None,
    verifier: Optional[SignatureVerifier] = None,
) -> ProvenanceAuditReport:
    """Verify the write-time signatures across a rights-provenance
    record set (e.g. the records array of a ``/proof/export`` archive,
    or a ``/proof/:id/chain`` walk).

    Per record this runs :func:`verify_provenance_record`; legacy
    (hmac-sha256) records surface as informational SKIPPED steps with
    the PROVENANCE_UNSIGNED_RECORD reason and never fail the report.

    Report status:
      - INVALID if any step is INVALID;
      - VALID if at least one record verified and none failed;
      - SKIPPED if every record was legacy (nothing was verifiable) —
        conservative: a fully-unsigned set must not be promoted to
        VALID just because nothing contradicted it.

    Backwards compatibility: exports produced before the platform
    shipped write-time provenance signing verify as SKIPPED with
    informational findings only — never INVALID.

    ``expected_org_id``: when supplied, every record's org_id must
    match — a mixed-tenant record set is reported as
    PROVENANCE_ORG_MISMATCH (a spliced export). Omit for multi-tenant
    forensic walks.

    NOTE: this primitive proves WHO signed each record. To prove the
    records' POSITION in the tenant's append-only history (insertion /
    rewrite detection), additionally run :func:`verify_tenant_chain`
    over the same records' tenant-chain fields.
    """

    verified_at = _now_iso()
    verifier = verifier or default_signature_verifier()
    if isinstance(keys, KeyDirectory):
        directory = keys
    else:
        directory = KeyDirectory(
            KeyDirectorySnapshot(
                source="local",
                snapshot_id=None,
                issued_at=None,
                keys=list(keys),
            )
        )

    steps: List[AuditStep] = []
    signed_record_count = 0
    unsigned_record_count = 0

    if len(records) == 0:
        return ProvenanceAuditReport(
            status="INVALID",
            verified_at=verified_at,
            sdk_version=SDK_VERSION,
            record_count=0,
            signed_record_count=0,
            unsigned_record_count=0,
            steps=[
                AuditStep(
                    target="records",
                    kind="provenance_signature",
                    status="INVALID",
                    reason="MALFORMED_PACK",
                    message=(
                        "provenance signature audit received an empty "
                        "record set — nothing to verify"
                    ),
                )
            ],
        )

    for i, record in enumerate(records):
        # Org consistency — a spliced multi-tenant export is rejected
        # before the signature even runs (the signature would verify;
        # the splice is at the SET level, not the record level).
        if expected_org_id is not None and record.org_id != expected_org_id:
            steps.append(
                AuditStep(
                    target=f"provenance[{i}].orgId",
                    kind="provenance_signature",
                    status="INVALID",
                    reason="PROVENANCE_ORG_MISMATCH",
                    message=(
                        f"record orgId {record.org_id!r} does not match the "
                        f"expected orgId {expected_org_id!r} — record set "
                        "spliced across tenants"
                    ),
                    detail={
                        "expected": expected_org_id,
                        "actual": record.org_id,
                    },
                )
            )

        if record.signature_algorithm == "ed25519":
            signed_record_count += 1
        else:
            unsigned_record_count += 1

        steps.extend(verify_provenance_record(record, i, directory, verifier))

    any_invalid = any(s.status == "INVALID" for s in steps)
    any_valid = any(s.status == "VALID" for s in steps)
    status = "INVALID" if any_invalid else ("VALID" if any_valid else "SKIPPED")

    return ProvenanceAuditReport(
        status=status,
        verified_at=verified_at,
        sdk_version=SDK_VERSION,
        record_count=len(records),
        signed_record_count=signed_record_count,
        unsigned_record_count=unsigned_record_count,
        steps=steps,
    )


def _now_iso() -> str:
    """ISO-8601 UTC timestamp — same convention as the other audit-
    report producers."""

    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


__all__ = [
    "PROVENANCE_SIGNING_VERSION",
    "ProvenanceSigningFields",
    "canonicalise_provenance_signing_input",
    "verify_provenance_chain",
    "verify_provenance_record",
]
