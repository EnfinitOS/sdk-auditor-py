"""enfinitos_auditor — signed-export verification (export.v1).

The platform signs its metering + settlement summaries on demand
(``GET /v1/metering?export=true``, ``GET /v1/settlement?export=true``)
into a ``SignedExport`` envelope so a third party can hold a portable,
offline-verifiable copy of the money-plane numbers — the same "verify
us without trusting us" guarantee the proof packs carry. This module
is the verifier side; the signer is
``packages/sandbox-core/src/exports.ts`` and the two are byte-parity
mirrors (as is the TS reference verifier, ``auditor-ts/src/exports.ts``):

    payload_canonical      = canonical_sort_keys(payload)   (recursive
                             lexicographic key sort, array order preserved)
    payload_canonical_hash = sha256 hex (bare, no prefix) of payload_canonical
    signature              = base64url( Ed25519( utf8(f"{payload_canonical}|{key_id}") ) )

The key_id is bound into the signed bytes, so a signature cannot be
lifted onto a different key. NOTE (documented signer behaviour): the
envelope metadata OUTSIDE ``payload`` — ``kind``, ``envelope_version``,
``org_id``, ``exported_at`` — is NOT covered by the signature. Treat
the signed payload as the evidence; treat the envelope metadata as
convenience labelling. The payload itself carries ``orgId`` and period
bounds, so the load-bearing facts are all inside the signed bytes.

Verification never raises on bad input — every failure is an
``AuditStep`` with a stable reason code, mirroring the rest of the SDK.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

from .canonical_json import base64url_decode_strict, canonical_sort_keys
from .hashing import sha256_hex
from .keys import KeyDirectory, KeyLookupMiss
from .proof_pack import SignatureVerifier, default_signature_verifier
from .types import SDK_VERSION, AuditStep, AuditStepStatus


@dataclass
class SignedExport:
    """Wire-compatible mirror of the platform envelope
    (packages/sandbox-core/src/exports.ts ``SignedExport<T>``).
    """

    #: "metering.export.v1" | "settlement.export.v1" (open for future kinds).
    kind: str
    #: Envelope version — this verifier supports "export.v1".
    envelope_version: str
    org_id: str
    #: ISO-8601. Also the instant the signing key is validity-checked against.
    exported_at: str
    key_id: str
    algorithm: str
    #: The summary as issued (metering / settlement summary / …).
    payload: Any
    #: Transparency copy of the exact bytes that were hashed + signed.
    payload_canonical: str
    #: sha256 hex of payload_canonical.
    payload_canonical_hash: str
    #: base64url Ed25519 signature over ``f"{payload_canonical}|{key_id}"``.
    signature: str


@dataclass
class SignedExportAuditReport:
    status: AuditStepStatus
    #: Envelope ``kind`` as declared (unsigned metadata — see module note).
    kind: str
    org_id: str
    key_id: str
    exported_at: str
    #: ISO-8601 — when the audit ran.
    verified_at: str
    sdk_version: str
    steps: List[AuditStep]


def parse_signed_export(raw: Dict[str, Any]) -> SignedExport:
    """Coerce a wire-format JSON dict (camelCase keys) into a
    :class:`SignedExport`.

    Deliberately lenient: missing / non-string fields coerce to ``""``
    so :func:`verify_signed_export` reports a structured INVALID step
    (e.g. UNSUPPORTED_ENVELOPE_VERSION) rather than raising — the TS
    reference gets the same behaviour from structural typing.
    """

    def _s(key: str) -> str:
        v = raw.get(key)
        return v if isinstance(v, str) else ""

    return SignedExport(
        kind=_s("kind"),
        envelope_version=_s("envelopeVersion"),
        org_id=_s("orgId"),
        exported_at=_s("exportedAt"),
        key_id=_s("keyId"),
        algorithm=_s("algorithm"),
        payload=raw.get("payload"),
        payload_canonical=_s("payloadCanonical"),
        payload_canonical_hash=_s("payloadCanonicalHash"),
        signature=_s("signature"),
    )


def verify_signed_export(
    export: Union[SignedExport, Dict[str, Any]],
    keys: KeyDirectory,
    verifier: Optional[SignatureVerifier] = None,
) -> SignedExportAuditReport:
    """Verify a signed export offline against a key directory.

    Steps (each an AuditStep; overall status is INVALID if any step is):
      1. envelope         — envelope_version is "export.v1", algorithm
                            "ed25519".
      2. key_lookup       — key_id resolves in the directory and is inside
                            its validity window (checked at ``exported_at``),
                            not revoked.
      3. canonicalisation — re-canonicalising ``payload`` reproduces
                            ``payload_canonical`` byte-for-byte, and its
                            sha256 matches ``payload_canonical_hash``.
      4. signature        — Ed25519 over ``f"{payload_canonical}|{key_id}"``
                            verifies under the directory key.

    The deeper content checks (does the metering re-project? does the
    settlement reconcile?) remain the job of
    ``verify_metering_projection`` / ``verify_settlement_reconciliation``
    — pass them ``export.payload`` after this signature gate passes.

    Accepts either a :class:`SignedExport` or the raw wire dict
    (``json.load(file)``) — dicts are coerced via
    :func:`parse_signed_export`.
    """

    exp = export if isinstance(export, SignedExport) else parse_signed_export(export)
    verifier = verifier or default_signature_verifier()
    steps: List[AuditStep] = []

    # -- 1. Envelope ----------------------------------------------------
    if exp.envelope_version != "export.v1":
        steps.append(
            AuditStep(
                target="export.envelopeVersion",
                kind="envelope",
                status="INVALID",
                reason="UNSUPPORTED_ENVELOPE_VERSION",
                message=(
                    f'unsupported export envelope version "{exp.envelope_version}" '
                    '(verifier supports "export.v1")'
                ),
            )
        )
    else:
        steps.append(
            AuditStep(
                target="export.envelopeVersion",
                kind="envelope",
                status="VALID",
                message="envelope version export.v1",
            )
        )
    if exp.algorithm != "ed25519":
        steps.append(
            AuditStep(
                target="export.algorithm",
                kind="envelope",
                status="INVALID",
                reason="UNSUPPORTED_ALGORITHM",
                message=f'unsupported signature algorithm "{exp.algorithm}"',
            )
        )
    else:
        steps.append(
            AuditStep(
                target="export.algorithm",
                kind="envelope",
                status="VALID",
                message="algorithm ed25519",
            )
        )

    # -- 2. Key lookup (validity window anchored at exported_at) ---------
    lookup = keys.lookup(exp.key_id, exp.exported_at)
    if isinstance(lookup, KeyLookupMiss):
        steps.append(
            AuditStep(
                target="export.keyId",
                kind="key_lookup",
                status="INVALID",
                reason=lookup.reason,
                message=(
                    f'signing key "{exp.key_id}" not usable at '
                    f"{exp.exported_at}: {lookup.reason}"
                ),
            )
        )
        return _finish(exp, steps)
    steps.append(
        AuditStep(
            target="export.keyId",
            kind="key_lookup",
            status="VALID",
            message=f'key "{exp.key_id}" resolved and inside its validity window',
        )
    )

    # -- 3. Canonicalisation + hash transparency --------------------------
    recomputed_canonical = canonical_sort_keys(exp.payload)
    if recomputed_canonical != exp.payload_canonical:
        steps.append(
            AuditStep(
                target="export.payloadCanonical",
                kind="canonicalisation",
                status="INVALID",
                reason="PAYLOAD_CANONICAL_MISMATCH",
                message=(
                    "re-canonicalising the payload does not reproduce "
                    "payloadCanonical — the payload was modified after signing"
                ),
            )
        )
        return _finish(exp, steps)
    steps.append(
        AuditStep(
            target="export.payloadCanonical",
            kind="canonicalisation",
            status="VALID",
            message="payload re-canonicalises byte-for-byte",
        )
    )

    recomputed_hash = sha256_hex(recomputed_canonical)
    if recomputed_hash != exp.payload_canonical_hash:
        steps.append(
            AuditStep(
                target="export.payloadCanonicalHash",
                kind="canonicalisation",
                status="INVALID",
                reason="EXPORT_PAYLOAD_HASH_MISMATCH",
                message="sha256(payloadCanonical) does not equal payloadCanonicalHash",
                detail={
                    "expected": recomputed_hash,
                    "actual": exp.payload_canonical_hash,
                },
            )
        )
        return _finish(exp, steps)
    steps.append(
        AuditStep(
            target="export.payloadCanonicalHash",
            kind="canonicalisation",
            status="VALID",
            message="payload hash matches",
        )
    )

    # -- 4. Signature over f"{payload_canonical}|{key_id}" ----------------
    try:
        public_key_bytes = base64url_decode_strict(lookup.key.public_key)
        signature_bytes = base64url_decode_strict(exp.signature)
    except Exception:
        steps.append(
            AuditStep(
                target="export.signature",
                kind="signature",
                status="INVALID",
                reason="SIGNATURE_MALFORMED",
                message="signature or public key is not valid base64url",
            )
        )
        return _finish(exp, steps)
    message = f"{exp.payload_canonical}|{exp.key_id}".encode("utf-8")
    ok = verifier.verify_ed25519(public_key_bytes, message, signature_bytes)
    steps.append(
        AuditStep(
            target="export.signature",
            kind="signature",
            status="VALID" if ok else "INVALID",
            reason=None if ok else "SIGNATURE_INVALID",
            message=(
                "Ed25519 signature verifies under the directory key"
                if ok
                else "Ed25519 signature does not verify — the export is not authentic"
            ),
        )
    )
    return _finish(exp, steps)


def _finish(exp: SignedExport, steps: List[AuditStep]) -> SignedExportAuditReport:
    status: AuditStepStatus = (
        "INVALID" if any(s.status == "INVALID" for s in steps) else "VALID"
    )
    return SignedExportAuditReport(
        status=status,
        kind=exp.kind,
        org_id=exp.org_id,
        key_id=exp.key_id,
        exported_at=exp.exported_at,
        verified_at=datetime.now(tz=timezone.utc)
        .isoformat()
        .replace("+00:00", "Z"),
        sdk_version=SDK_VERSION,
        steps=steps,
    )


__all__ = [
    "SignedExport",
    "SignedExportAuditReport",
    "parse_signed_export",
    "verify_signed_export",
]
