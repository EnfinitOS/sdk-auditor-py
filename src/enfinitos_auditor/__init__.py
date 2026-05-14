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
from .hashing import (
    constant_time_equal,
    meter_idem_key,
    settlement_idem_key,
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
from .settlement_audit import verify_settlement_reconciliation
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
    "ProjectionAuditReport",
    "ProofPack",
    "ProofReceiptPayload",
    "ProofRecord",
    "SDK_VERSION",
    "SUPPORTED_ENVELOPE_VERSIONS",
    "SUPPORTED_SIGNATURE_ALGORITHMS",
    "SettlementAuditReport",
    "SettlementLine",
    "SettlementSummary",
    "SignedProofPack",
    "VerificationKey",
    "base64url_decode",
    "base64url_encode",
    "canonical_sort_keys",
    "canonicalise_proof_payload",
    "canonicalise_proof_signing_input",
    "constant_time_equal",
    "load_key_directory",
    "meter_idem_key",
    "parse_signed_proof_pack",
    "settlement_idem_key",
    "sha256_hex",
    "sha256_hex_prefixed",
    "sha256_prefixed",
    "verify_metering_projection",
    "verify_proof_chain",
    "verify_proof_record",
    "verify_settlement_reconciliation",
]
