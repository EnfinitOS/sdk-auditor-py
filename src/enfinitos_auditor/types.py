"""enfinitos_auditor — wire + domain types.

Pydantic-free dataclass shapes that mirror — verbatim — the platform's
wire formats:

  - ProofReceiptPayload   ← apps/api/src/services/spatialChain/proofService.ts
  - ProofRecord           ← same (with beforeHash/afterHash provenance)
  - SignedProofPack       ← the top-level envelope a regulator audits
  - MeterRecord / Metering Summary ← meterService.ts projection
  - SettlementLine / Summary       ← settlementService.ts projection
  - VerificationKey       ← /v1/runtime-keys directory entries
  - AuditReport family            ← the structured verdicts we emit

Why the types live here, not in pydantic
────────────────────────────────────────
The audit SDK has a regulator-grade trust requirement: zero runtime
surprises, byte-exact reproducibility. Pydantic would do shape-checking
plus validators we can't predict. Plain dataclasses give us exactly what
we need: structural typing + a deliberate, hand-coded parser that
matches the TS implementation byte-for-byte.

Type alignment with TypeScript
──────────────────────────────
Every field name on this side maps to the same JSON key on the TS side.
We use ``snake_case`` for Python identifiers but Python dataclasses
serialise field names as-is, so we never expose the snake_case version
to the wire — see ``proof_pack.parse_signed_proof_pack`` for the JSON
boundary, which renames camelCase JSON keys into snake_case Python
attributes and back.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Literal, Optional, Tuple, Union

# ---------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------

# Bumped on any semantic break in the SignedProofPack shape.
SUPPORTED_ENVELOPE_VERSIONS: Tuple[str, ...] = ("envelope.v1",)

# Algorithm identifiers the SDK understands. We only ship Ed25519 today.
SUPPORTED_SIGNATURE_ALGORITHMS: Tuple[str, ...] = ("ed25519",)

# Stamped onto every AuditReport.
SDK_VERSION: str = "0.0.3"

EnvelopeVersion = str
SignatureAlgorithm = Literal["ed25519"]


# ---------------------------------------------------------------------
# Verification keys
# ---------------------------------------------------------------------


@dataclass(frozen=True)
class VerificationKey:
    """One of N public keys the platform may have used to sign records.

    Field semantics mirror the TS ``VerificationKey`` type:

    - ``public_key`` is base64url-encoded 32 raw bytes (Ed25519).
    - ``not_before`` / ``not_after`` bound the key's validity window;
      any record whose payload.issued_at is outside the window will be
      rejected as ``KEY_OUTSIDE_VALIDITY_WINDOW``.
    - ``revoked_at`` removes a key from any record issued after that
      timestamp, even within ``[not_before, not_after]``.
    """

    key_id: str
    algorithm: SignatureAlgorithm
    public_key: str
    not_before: str
    not_after: Optional[str]
    revoked_at: Optional[str]
    purpose: Optional[str] = None


# ---------------------------------------------------------------------
# Proof pack
# ---------------------------------------------------------------------


@dataclass(frozen=True)
class ProofReceiptPayload:
    """Exactly the shape platform proof receipts emit, version "1".

    The auditor SDK MUST not reorder fields when re-canonicalising —
    even a key-reorder produces a different signature input.
    """

    version: Literal["1"]
    receipt_id: str
    correlation_id: Optional[str]
    spatial_anchor_id: str
    spatial_placement_id: Optional[str]
    issued_at: str
    rendered_at: str
    dwell_ms: int
    nonce: str
    witness: Optional[str]


@dataclass(frozen=True)
class ProofRecord:
    """A single signed receipt + provenance chain fields.

    The chain shape mirrors the basis/right/offer provenance trail —
    every record carries a ``before_hash`` (predecessor's after_hash,
    or None for genesis) and an ``after_hash`` (sha256 of this
    record's canonical payload).
    """

    payload: ProofReceiptPayload
    key_id: str
    algorithm: SignatureAlgorithm
    signature: str
    payload_canonical: str
    before_hash: Optional[str]
    after_hash: str


# ---------------------------------------------------------------------
# Rights-provenance records — Wave 14 write-time signing contract
# ---------------------------------------------------------------------


@dataclass(frozen=True)
class ProvenanceRecord:
    """One rights-provenance ledger entry as the platform's proof read
    surface emits it (apps/api/src/modules/proof/decoder.ts →
    ProofRecord, proof.v1).

    This is a DIFFERENT artefact from the spatial-chain
    :class:`ProofRecord` above: that one wraps a ProofReceiptPayload
    signed over a canonical-JSON encoding; this one is a rights
    lifecycle event (basis assert/verify/reject, right issue/suspend/
    resume/revoke/expire, offer propose/accept/counter/reject/
    withdraw/expire, challenge open/resolve/withdraw) signed over a
    flat pipe-delimited canonical string::

        "rightProvenance.v1|<orgId>|<eventType>|<rightId|->|<basisId|->|
         <offerId|->|<beforeHash|->|<afterHash|->|<keyId>"

    where ``-`` encodes an absent field. The hand-rolled form is what
    lets TS / Rust / Python verifiers reconstruct the signed bytes
    without sharing a canonical-JSON library.

    Signature presence is per-record:
      - ``signature_algorithm == "ed25519"`` → write-time signed.
        ``signature`` is the base64url (unpadded) 64-byte Ed25519
        signature; ``signer_key_id`` matches a
        :class:`VerificationKey`. ``payload_canonical`` carries the
        exact signed string as a transparency aid — the SDK re-derives
        it from the raw fields and asserts byte-equality before
        verifying.
      - ``signature_algorithm == "hmac-sha256"`` → legacy
        (pre-Wave-14) record. Read-time transport HMAC only; the
        verifier reports PROVENANCE_UNSIGNED_RECORD as an
        informational SKIPPED step, never INVALID — published
        0.0.1-era exports keep verifying.
    """

    #: Stable record id (the RightProvenance row id).
    proof_id: str
    #: Tenant the record belongs to. Part of the signing input.
    org_id: str
    #: The platform's raw lifecycle event tag (e.g. RIGHT_ISSUED).
    #: Part of the signing input. NOTE: this is NOT the proof
    #: surface's collapsed 10-value ``type`` taxonomy — the wire field
    #: is ``provenanceEventType``.
    provenance_event_type: str
    #: ISO-8601 — when the event was recorded. Drives key-validity
    #: checks (plays the role of issued_at).
    occurred_at: str
    #: Entity pointers — each part of the signing input; None when absent.
    right_id: Optional[str]
    basis_id: Optional[str]
    offer_id: Optional[str]
    #: Raw entity-chain hashes exactly as persisted (typically
    #: ``sha256:<hex>``-prefixed; None on auxiliary birth rows). Wire
    #: fields are ``provenanceBeforeHash`` / ``provenanceAfterHash``.
    provenance_before_hash: Optional[str]
    provenance_after_hash: Optional[str]
    #: "ed25519" (write-time signed) or "hmac-sha256" (legacy).
    signature_algorithm: Literal["ed25519", "hmac-sha256"]
    #: For ed25519 records: base64url (unpadded) 64-byte Ed25519
    #: signature over the canonical signing input. For hmac-sha256
    #: records: the platform's transport HMAC (hex) — opaque to the SDK.
    signature: str
    #: For ed25519 records: the signing key id, resolvable in the
    #: published verification-key directory. For hmac-sha256 records:
    #: the synthetic ``ledger.v1.<orgId>`` tag.
    signer_key_id: str
    #: For ed25519 records: the exact canonical string that was
    #: signed. None on legacy records.
    payload_canonical: Optional[str]


@dataclass
class ProvenanceAuditReport:
    """``verify_provenance_chain`` output.

    Same shape family as :class:`ChainAuditReport`, with the
    signed/unsigned partition surfaced so a regulator can quote
    "N of M records carry write-time signatures" directly.
    """

    status: AuditStepStatus
    verified_at: str
    sdk_version: str
    record_count: int
    #: Records carrying a write-time Ed25519 signature.
    signed_record_count: int
    #: Legacy records (read-time HMAC only) — informational.
    unsigned_record_count: int
    steps: List[AuditStep]


MeterUnitType = Literal[
    "DWELL_SECONDS",
    "IMPRESSION_IN_PLACE",
    "ATTENTION_SECONDS",
    "OCCUPANCY_WEIGHTED_EXPOSURE",
    "COMPLIANT_DELIVERY_MINUTE",
    "CUSTOM",
]

MeterStatus = Literal["PROJECTED", "ACCEPTED", "SETTLED", "VOID"]


@dataclass(frozen=True)
class MeterRecord:
    """One billable unit projection of one ProofReceipt.

    ``unit_count`` / ``weight`` are decimal strings preserved verbatim
    so the auditor sees byte-exact precision (round-tripping through a
    float loses precision beyond 2^53).
    """

    idem_key: str
    proof_receipt_id: str
    unit_type: MeterUnitType
    unit_count: str
    weight: str
    spatial_anchor_id: str
    spatial_placement_id: Optional[str]
    observed_at: str
    status: MeterStatus


@dataclass
class MeteringSummary:
    schema_version: Literal["metering.v1"]
    org_id: str
    period_start: str
    period_end: str
    records: List[MeterRecord]
    # Optional convenience aggregate — the auditor recomputes from
    # records and asserts equality.
    totals: Optional[Dict[str, str]] = None


# Full role union per the May-2026 enterprise settlement rebuild —
# counterparty-addressed splits can pay agencies, affiliates,
# resellers, and tax authorities. The audit logic is role-agnostic;
# this stays in field-for-field parity with sandbox-core + auditor-ts.
SettlementPartyRole = Literal[
    "TENANT",
    "VENUE",
    "CUSTOMER",
    "PLATFORM",
    "AGENCY",
    "AFFILIATE",
    "RESELLER",
    "TAX_AUTHORITY",
]
SettlementStatus = Literal["PROJECTED", "ACCEPTED", "POSTED", "VOID"]


@dataclass(frozen=True)
class SettlementLine:
    idem_key: str
    meter_record_idem_key: str
    party_role: SettlementPartyRole
    share: str
    ledger_account_code: str
    amount_cents: int
    currency: str
    status: SettlementStatus


@dataclass
class SettlementTotals:
    gross_cents: int
    net_to_tenant_cents: int
    platform_fee_cents: int


@dataclass
class SettlementSummary:
    # ``settlement.v2`` is the current shape: the line idemKey is the
    # 3-field content hash sha256(meterRecordIdemKey|partyRole|
    # ledgerAccountCode). ``settlement.v1`` (2-field idemKey) is still
    # accepted for back-compat at the parse boundary.
    schema_version: Literal["settlement.v1", "settlement.v2"]
    org_id: str
    period_start: str
    period_end: str
    currency: str
    meter_gross: Dict[str, int]
    lines: List[SettlementLine]
    totals: Optional[SettlementTotals] = None


@dataclass
class SignedProofPack:
    """Top-level envelope. Carries N ProofRecords in issuance order."""

    envelope_version: EnvelopeVersion
    issued_at: str
    org_id: str
    pack_id: str
    records: List[ProofRecord]
    label: Optional[str] = None
    metering: Optional[MeteringSummary] = None
    settlement: Optional[SettlementSummary] = None


@dataclass
class ProofPack:
    """Same shape as ``SignedProofPack`` without signatures.

    Used when re-projecting metering after signatures are already
    verified out-of-band — for instance in regression tests.
    """

    envelope_version: EnvelopeVersion
    issued_at: str
    org_id: str
    pack_id: str
    records: List[ProofRecord]


@dataclass
class AuditBundle:
    """Input to ``verify_all`` — pack + optional metering/settlement.

    In practice, a regulator receives the bundle as a ZIP from the
    platform's regulator-export endpoint, unpacks it, and feeds it
    into ``verify_all`` in a single call.
    """

    pack: SignedProofPack
    metering: Optional[MeteringSummary] = None
    settlement: Optional[SettlementSummary] = None
    verification_keys: Optional[List[VerificationKey]] = None


# ---------------------------------------------------------------------
# Audit reports
# ---------------------------------------------------------------------

AuditStepStatus = Literal["VALID", "INVALID", "SKIPPED"]

AuditReasonCode = Literal[
    # Envelope / pack-level
    "UNSUPPORTED_ENVELOPE_VERSION",
    "MALFORMED_PACK",
    "EMPTY_PACK",
    "PACK_ORG_MISMATCH",
    "UNSUPPORTED_ALGORITHM",
    # Signature
    "SIGNATURE_INVALID",
    "SIGNATURE_MALFORMED",
    "UNKNOWN_KEY_ID",
    "KEY_OUTSIDE_VALIDITY_WINDOW",
    "KEY_REVOKED_BEFORE_ISSUANCE",
    # Canonicalisation
    "PAYLOAD_CANONICAL_MISMATCH",
    "AFTER_HASH_MISMATCH",
    # Chain
    "GENESIS_BEFORE_HASH_NOT_NULL",
    "CHAIN_LINK_MISMATCH",
    "CHAIN_OUT_OF_ORDER",
    "CHAIN_NONCE_REUSED",
    # Metering re-projection
    "METER_RECORD_FOR_UNKNOWN_PROOF",
    "METER_UNIT_COUNT_MISMATCH",
    "METER_IDEM_KEY_MISMATCH",
    "METER_TOTAL_MISMATCH",
    "METER_ORG_MISMATCH",
    # Settlement reconciliation
    "SETTLEMENT_LINE_FOR_UNKNOWN_METER",
    "SETTLEMENT_SHARE_SUM_NOT_ONE",
    "SETTLEMENT_AMOUNT_MISMATCH",
    "SETTLEMENT_IDEM_KEY_MISMATCH",
    "SETTLEMENT_TOTAL_MISMATCH",
    "SETTLEMENT_ORG_MISMATCH",
    # Rights-provenance write-time signing (Wave 14 Phase 2). Additive —
    # packs/exports produced before the platform shipped write-time
    # provenance signing never trip these.
    "PROVENANCE_SIGNATURE_INVALID",
    "PROVENANCE_SIGNATURE_MALFORMED",
    "PROVENANCE_CANONICAL_MISMATCH",
    "PROVENANCE_UNSIGNED_RECORD",
    "PROVENANCE_ORG_MISMATCH",
    # Keys
    "KEYS_FETCH_FAILED",
    "KEYS_RESPONSE_MALFORMED",
]

AuditStepKind = Literal[
    "envelope",
    "signature",
    "canonicalisation",
    "chain_link",
    "meter_projection",
    "meter_total",
    "settlement_line",
    "settlement_total",
    "key_lookup",
    # Wave 14 Phase 2 — rights-provenance write-time signature checks.
    "provenance_signature",
]


@dataclass
class AuditStep:
    target: str
    kind: AuditStepKind
    status: AuditStepStatus
    message: str
    reason: Optional[AuditReasonCode] = None
    detail: Optional[Dict[str, object]] = None


@dataclass
class KeysSnapshot:
    source: Literal["platform", "local"]
    snapshot_id: Optional[str]
    key_count: int
    key_ids: List[str]


@dataclass
class AuditReport:
    status: AuditStepStatus
    pack_id: str
    org_id: str
    verified_at: str
    sdk_version: str
    envelope_version: str
    keys_snapshot: KeysSnapshot
    steps: List[AuditStep]


@dataclass
class ChainAuditReport:
    status: AuditStepStatus
    verified_at: str
    sdk_version: str
    record_count: int
    steps: List[AuditStep]


@dataclass
class ProjectionAuditReport:
    status: AuditStepStatus
    verified_at: str
    sdk_version: str
    proof_record_count: int
    meter_record_count: int
    steps: List[AuditStep]


@dataclass
class SettlementAuditReport:
    status: AuditStepStatus
    verified_at: str
    sdk_version: str
    meter_record_count: int
    settlement_line_count: int
    steps: List[AuditStep]


@dataclass
class FullAuditReport:
    status: AuditStepStatus
    pack_id: str
    org_id: str
    verified_at: str
    sdk_version: str
    keys_snapshot: KeysSnapshot
    pack: AuditReport
    chain: ChainAuditReport
    metering: ProjectionAuditReport
    settlement: SettlementAuditReport


__all__ = [
    "AuditBundle",
    "AuditReasonCode",
    "AuditReport",
    "AuditStep",
    "AuditStepKind",
    "AuditStepStatus",
    "ChainAuditReport",
    "EnvelopeVersion",
    "FullAuditReport",
    "KeysSnapshot",
    "MeterRecord",
    "MeterStatus",
    "MeterUnitType",
    "MeteringSummary",
    "ProjectionAuditReport",
    "ProofPack",
    "ProofReceiptPayload",
    "ProofRecord",
    "ProvenanceAuditReport",
    "ProvenanceRecord",
    "SDK_VERSION",
    "SUPPORTED_ENVELOPE_VERSIONS",
    "SUPPORTED_SIGNATURE_ALGORITHMS",
    "SettlementAuditReport",
    "SettlementLine",
    "SettlementPartyRole",
    "SettlementStatus",
    "SettlementSummary",
    "SettlementTotals",
    "SignatureAlgorithm",
    "SignedProofPack",
    "VerificationKey",
]
