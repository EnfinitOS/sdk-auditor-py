"""enfinitos_auditor — public surface.

Python port of @enfinitos/sdk-auditor. The wire shapes, canonicalisation
rules, and verification semantics are deliberately identical to the
TypeScript reference: a regulator auditing the same proof pack with
either SDK MUST get the same VALID/INVALID verdict on every step.
"""

from .auditor import EnfinitOSAuditor
from .canonical_json import (
    base64url_decode,
    base64url_encode,
    canonical_sort_keys,
    canonicalise_proof_payload,
    canonicalise_proof_signing_input,
    sha256_prefixed,
)
from .errors import AuditorError

# Signed exports (export.v1) — verify the platform's signed metering /
# settlement exports (``?export=true``) offline. This is the signature
# gate; pass ``export.payload`` on to verify_metering_projection /
# verify_settlement_reconciliation for the content checks.
from .exports import (
    SignedExport,
    SignedExportAuditReport,
    parse_signed_export,
    verify_signed_export,
)
from .hashing import (
    constant_time_equal,
    meter_idem_key,
    settlement_idem_key,
    settlement_idem_key_v1,
    sha256_hex,
    sha256_hex_prefixed,
)
from .keys import KeyDirectory, load_key_directory
from .metering_audit import verify_metering_projection
from .proof_chain import verify_proof_chain
from .proof_pack import (
    Ed25519SignatureVerifier,
    parse_signed_proof_pack,
    verify_proof_record,
)

# Wave 14 Phase 2 — rights-provenance write-time signature
# verification. Verifies WHO signed each rights lifecycle record;
# pair with verify_tenant_chain (position) for the full posture.
from .provenance import (
    PROVENANCE_SIGNING_VERSION,
    ProvenanceSigningFields,
    canonicalise_provenance_signing_input,
    verify_provenance_chain,
    verify_provenance_record,
)
from .settlement_audit import verify_settlement_reconciliation
from .tenant_chain import (
    TENANT_CHAIN_VERSION,
    TenantChainedRecord,
    canonicalise_tenant_chain_link,
    genesis_chain_tip,
    verify_tenant_chain,
)
from .types import (
    SDK_VERSION,
    SUPPORTED_ENVELOPE_VERSIONS,
    SUPPORTED_SIGNATURE_ALGORITHMS,
    AuditBundle,
    AuditReport,
    AuditStep,
    AuditStepStatus,
    ChainAuditReport,
    FullAuditReport,
    MeteringSummary,
    MeterRecord,
    ProjectionAuditReport,
    ProofPack,
    ProofReceiptPayload,
    ProofRecord,
    ProvenanceAuditReport,
    ProvenanceRecord,
    SettlementAuditReport,
    SettlementLine,
    SettlementSummary,
    SignedProofPack,
    VerificationKey,
)

__all__ = [
    "AuditBundle",
    "AuditReport",
    "AuditStep",
    "AuditStepStatus",
    "AuditorError",
    "ChainAuditReport",
    "Ed25519SignatureVerifier",
    "EnfinitOSAuditor",
    "FullAuditReport",
    "KeyDirectory",
    "MeterRecord",
    "MeteringSummary",
    "PROVENANCE_SIGNING_VERSION",
    "ProjectionAuditReport",
    "ProofPack",
    "ProofReceiptPayload",
    "ProofRecord",
    "ProvenanceAuditReport",
    "ProvenanceRecord",
    "ProvenanceSigningFields",
    "SDK_VERSION",
    "SUPPORTED_ENVELOPE_VERSIONS",
    "SUPPORTED_SIGNATURE_ALGORITHMS",
    "SettlementAuditReport",
    "SettlementLine",
    "SettlementSummary",
    "SignedExport",
    "SignedExportAuditReport",
    "SignedProofPack",
    "TENANT_CHAIN_VERSION",
    "TenantChainedRecord",
    "VerificationKey",
    "base64url_decode",
    "base64url_encode",
    "canonical_sort_keys",
    "canonicalise_proof_payload",
    "canonicalise_proof_signing_input",
    "canonicalise_provenance_signing_input",
    "constant_time_equal",
    "load_key_directory",
    "meter_idem_key",
    "parse_signed_export",
    "parse_signed_proof_pack",
    "settlement_idem_key",
    "settlement_idem_key_v1",
    "sha256_hex",
    "sha256_hex_prefixed",
    "sha256_prefixed",
    "verify_metering_projection",
    "verify_proof_chain",
    "verify_proof_record",
    "verify_provenance_chain",
    "verify_provenance_record",
    "verify_settlement_reconciliation",
    "verify_signed_export",
]
