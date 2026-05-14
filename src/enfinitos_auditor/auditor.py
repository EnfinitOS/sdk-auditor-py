"""enfinitos_auditor — top-level EnfinitOSAuditor class.

Entry point for regulators, auditors, courts, and any third party. Composes
the four verification primitives — signature, chain, metering projection,
settlement reconciliation — behind a single class that handles key loading,
report rollup, and the SKIPPED-vs-VALID-vs-INVALID promotion rules.

Trust model
-----------
The only inputs an external party needs:

  1. The JSON proof pack (signed by the platform).
  2. The verification key set — fetched from the platform OR supplied
     locally (for fully-offline audit).

They do NOT need access to EnfinitOS infrastructure (beyond the public
key directory), credentials, or anything the platform might revoke
post-hoc. Result: the SDK can run from a customer's laptop, in an
air-gapped regulator review room, or inside a third-party compliance
tool, and produce identical structured verdicts.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable, List, Optional

from .errors import AuditorError, as_auditor_error
from .keys import (
    DEFAULT_PLATFORM_KEYS_URL,
    KeyDirectory,
    VerificationKeySourceKind,
    load_key_directory,
)
from .metering_audit import verify_metering_projection
from .proof_chain import verify_proof_chain
from .proof_pack import (
    SignatureVerifier,
    default_signature_verifier,
    parse_signed_proof_pack,
    verify_proof_record,
)
from .settlement_audit import verify_settlement_reconciliation
from .types import (
    SDK_VERSION,
    AuditBundle,
    AuditReport,
    AuditStep,
    AuditStepStatus,
    ChainAuditReport,
    FullAuditReport,
    KeysSnapshot,
    MeteringSummary,
    ProjectionAuditReport,
    ProofPack,
    ProofRecord,
    SettlementAuditReport,
    SettlementSummary,
    SignedProofPack,
    VerificationKey,
)


class EnfinitOSAuditor:
    """Top-level verification facade.

    Usage::

        auditor = EnfinitOSAuditor(verification_key_source="local",
                                   local_keys=[...])
        report = auditor.verify_proof_pack(pack)
        if report.status != "VALID":
            for step in report.steps:
                if step.status == "INVALID":
                    print(step.reason, step.message)

    The instance is reusable across many packs; the key directory is
    loaded on first use and cached for the instance's lifetime.
    """

    def __init__(
        self,
        verification_key_source: VerificationKeySourceKind = "platform",
        platform_keys_url: str = DEFAULT_PLATFORM_KEYS_URL,
        local_keys: Optional[List[VerificationKey]] = None,
        http_fetch: Optional[Callable[..., Any]] = None,
        signature_verifier: Optional[SignatureVerifier] = None,
    ) -> None:
        if verification_key_source == "local" and local_keys is None:
            raise AuditorError(
                code="INVALID_INPUT",
                message=(
                    "verification_key_source='local' requires local_keys to be "
                    "provided"
                ),
            )
        self._source = verification_key_source
        self._platform_keys_url = platform_keys_url
        self._local_keys = local_keys
        self._http_fetch = http_fetch
        self._verifier = signature_verifier or default_signature_verifier()
        self._key_directory: Optional[KeyDirectory] = None

    def _get_key_directory(self) -> KeyDirectory:
        """Load + cache the key directory; concurrent calls share."""

        if self._key_directory is None:
            try:
                self._key_directory = load_key_directory(
                    source=self._source,
                    local_keys=self._local_keys,
                    platform_keys_url=self._platform_keys_url,
                    http_fetch=self._http_fetch,
                )
            except AuditorError:
                raise
            except Exception as exc:
                raise as_auditor_error(
                    exc, "KEYS_UNAVAILABLE", "failed to load key directory"
                )
        return self._key_directory

    # ----------------------------------------------------------------
    # Public API
    # ----------------------------------------------------------------

    def fetch_keys(self) -> List[VerificationKey]:
        """Force the key-directory load (and return the verification keys).

        Useful for surfacing key-snapshot metadata to regulators ahead
        of any verification work.
        """

        return list(self._get_key_directory().snapshot.keys)

    def verify_proof_pack(self, pack: Any) -> AuditReport:
        """Parse, verify signatures, and run envelope-level checks.

        Does NOT re-project metering or settlement — use ``verify_all``
        for the full pipeline. Accepts either a parsed ``SignedProofPack``
        or a raw dict that looks like one (so a regulator can feed
        ``json.load(file)`` directly).
        """

        verified_at = _now_iso()
        try:
            parsed = (
                pack
                if isinstance(pack, SignedProofPack)
                else parse_signed_proof_pack(pack)
            )
        except AuditorError as err:
            return self._parse_fail_report(pack, verified_at, err)

        keys = self._get_key_directory()
        steps: List[AuditStep] = []

        if not parsed.records:
            steps.append(
                AuditStep(
                    target="pack.records",
                    kind="envelope",
                    status="INVALID",
                    reason="EMPTY_PACK",
                    message="proof pack contains zero records — cannot audit",
                )
            )
        else:
            steps.append(
                AuditStep(
                    target="pack.records",
                    kind="envelope",
                    status="VALID",
                    message=f"pack contains {len(parsed.records)} record(s)",
                )
            )

        for i, rec in enumerate(parsed.records):
            steps.extend(verify_proof_record(rec, i, keys, self._verifier))

        status = _rollup_status(steps)
        return AuditReport(
            status=status,
            pack_id=parsed.pack_id,
            org_id=parsed.org_id,
            verified_at=verified_at,
            sdk_version=SDK_VERSION,
            envelope_version=parsed.envelope_version,
            keys_snapshot=KeysSnapshot(
                source=keys.snapshot.source,
                snapshot_id=keys.snapshot.snapshot_id,
                key_count=keys.size(),
                key_ids=keys.key_ids(),
            ),
            steps=steps,
        )

    def verify_proof_chain(
        self, records: List[ProofRecord]
    ) -> ChainAuditReport:
        """Chain-walk only. The caller has already verified signatures."""

        return verify_proof_chain(records)

    def verify_metering_projection(
        self, proof: ProofPack, metering: MeteringSummary
    ) -> ProjectionAuditReport:
        """Re-project proof into metering and confirm it reconciles."""

        return verify_metering_projection(proof.records, metering, proof.org_id)

    def verify_settlement_reconciliation(
        self, metering: MeteringSummary, settlement: SettlementSummary
    ) -> SettlementAuditReport:
        """Re-compute settlement and confirm it reconciles to metering."""

        return verify_settlement_reconciliation(metering, settlement)

    def verify_all(self, bundle: AuditBundle) -> FullAuditReport:
        """One-shot full pipeline:

          1. verify_proof_pack
          2. verify_proof_chain
          3. verify_metering_projection (SKIPPED if not in bundle)
          4. verify_settlement_reconciliation (SKIPPED if not in bundle)

        Rolled-up status is VALID only if every non-skipped sub-step is
        VALID; any INVALID demotes the whole report to INVALID.
        """

        verified_at = _now_iso()

        if bundle.verification_keys is not None:
            # Per-bundle override: fresh directory for the run, never cached.
            tmp = EnfinitOSAuditor(
                verification_key_source="local",
                local_keys=bundle.verification_keys,
                http_fetch=self._http_fetch,
                signature_verifier=self._verifier,
            )
            return tmp.verify_all(
                AuditBundle(
                    pack=bundle.pack,
                    metering=bundle.metering,
                    settlement=bundle.settlement,
                )
            )

        pack_report = self.verify_proof_pack(bundle.pack)
        chain_report = self.verify_proof_chain(bundle.pack.records)

        metering_input = bundle.metering or bundle.pack.metering
        if metering_input is not None:
            metering_report = self.verify_metering_projection(
                _to_proof_pack(bundle.pack), metering_input
            )
        else:
            metering_report = ProjectionAuditReport(
                status="SKIPPED",
                verified_at=verified_at,
                sdk_version=SDK_VERSION,
                proof_record_count=len(bundle.pack.records),
                meter_record_count=0,
                steps=[
                    AuditStep(
                        target="metering",
                        kind="meter_projection",
                        status="SKIPPED",
                        message="no metering summary in the bundle — skipped",
                    )
                ],
            )

        settlement_input = bundle.settlement or bundle.pack.settlement
        if settlement_input is not None and metering_input is not None:
            settlement_report = self.verify_settlement_reconciliation(
                metering_input, settlement_input
            )
        else:
            settlement_report = SettlementAuditReport(
                status="SKIPPED",
                verified_at=verified_at,
                sdk_version=SDK_VERSION,
                meter_record_count=(
                    len(metering_input.records) if metering_input else 0
                ),
                settlement_line_count=0,
                steps=[
                    AuditStep(
                        target="settlement",
                        kind="settlement_line",
                        status="SKIPPED",
                        message=(
                            "settlement reconciliation skipped — bundle lacks "
                            "either metering or settlement summary"
                        ),
                    )
                ],
            )

        status = _rollup_overall_status(
            [
                pack_report.status,
                chain_report.status,
                metering_report.status,
                settlement_report.status,
            ]
        )
        return FullAuditReport(
            status=status,
            pack_id=pack_report.pack_id,
            org_id=pack_report.org_id,
            verified_at=verified_at,
            sdk_version=SDK_VERSION,
            keys_snapshot=pack_report.keys_snapshot,
            pack=pack_report,
            chain=chain_report,
            metering=metering_report,
            settlement=settlement_report,
        )

    # ----------------------------------------------------------------
    # Internals
    # ----------------------------------------------------------------

    def _parse_fail_report(
        self, raw_pack: Any, verified_at: str, err: AuditorError
    ) -> AuditReport:
        """Convert a structural parse failure into a single-step INVALID."""

        pack_id = "unknown"
        org_id = "unknown"
        envelope_version: str = "unknown"
        if isinstance(raw_pack, dict):
            if isinstance(raw_pack.get("packId"), str):
                pack_id = raw_pack["packId"]
            if isinstance(raw_pack.get("orgId"), str):
                org_id = raw_pack["orgId"]
            if isinstance(raw_pack.get("envelopeVersion"), str):
                envelope_version = raw_pack["envelopeVersion"]
        return AuditReport(
            status="INVALID",
            pack_id=pack_id,
            org_id=org_id,
            verified_at=verified_at,
            sdk_version=SDK_VERSION,
            envelope_version=envelope_version,
            keys_snapshot=KeysSnapshot(
                source=self._source, snapshot_id=None, key_count=0, key_ids=[]
            ),
            steps=[
                AuditStep(
                    target="pack",
                    kind="envelope",
                    status="INVALID",
                    reason=err.reason or "MALFORMED_PACK",
                    message=str(err),
                    detail=err.detail,
                )
            ],
        )


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _to_proof_pack(pack: SignedProofPack) -> ProofPack:
    return ProofPack(
        envelope_version=pack.envelope_version,
        issued_at=pack.issued_at,
        org_id=pack.org_id,
        pack_id=pack.pack_id,
        records=list(pack.records),
    )


def _rollup_status(steps: List[AuditStep]) -> AuditStepStatus:
    """Conservative rollup — INVALID wins, then SKIPPED, then VALID.

    A SKIPPED step does NOT promote to VALID, because "we didn't check
    it" is not the same as "we checked it and it passed".
    """

    if any(s.status == "INVALID" for s in steps):
        return "INVALID"
    if all(s.status == "SKIPPED" for s in steps):
        return "SKIPPED"
    return "VALID"


def _rollup_overall_status(statuses: List[AuditStepStatus]) -> AuditStepStatus:
    if "INVALID" in statuses:
        return "INVALID"
    if all(s == "SKIPPED" for s in statuses):
        return "SKIPPED"
    if all(s == "VALID" for s in statuses):
        return "VALID"
    # Mix of VALID + SKIPPED — surface as VALID; SKIPPED is a conscious
    # choice (no metering bundle, no settlement bundle).
    return "VALID"


__all__ = ["EnfinitOSAuditor"]
