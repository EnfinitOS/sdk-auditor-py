"""Fixture builder — generate proof packs under freshly-minted Ed25519 keys.

Mirrors the TS ``builder.ts`` in ``packages/sdks/auditor-ts/__tests__/fixtures/``.
The test suite builds a pack, signs it, audits it, and asserts VALID; then
tampers a byte and asserts INVALID.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, replace
from typing import Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from enfinitos_auditor.canonical_json import (
    base64url_encode,
    canonicalise_proof_payload,
    canonicalise_proof_signing_input,
)
from enfinitos_auditor.hashing import (
    meter_idem_key as build_meter_idem_key,
    settlement_idem_key as build_settlement_idem_key,
    sha256_hex,
)
from enfinitos_auditor.provenance import (
    ProvenanceSigningFields,
    canonicalise_provenance_signing_input,
)
from enfinitos_auditor.types import (
    MeterRecord,
    MeteringSummary,
    ProofReceiptPayload,
    ProofRecord,
    ProvenanceRecord,
    SettlementLine,
    SettlementSummary,
    SettlementTotals,
    SignedProofPack,
    VerificationKey,
)


@dataclass
class GeneratedKey:
    key_id: str
    public_key_b64: str
    private_key: Ed25519PrivateKey
    verification_key: VerificationKey


def generate_key(key_id: Optional[str] = None) -> GeneratedKey:
    """Fresh Ed25519 keypair, plus a VerificationKey consumable by the auditor."""

    private_key = Ed25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes_raw()
    public_key_b64 = base64url_encode(public_bytes)
    kid = key_id or "fixture_key_" + secrets.token_hex(4)
    verification_key = VerificationKey(
        key_id=kid,
        algorithm="ed25519",
        public_key=public_key_b64,
        not_before="2020-01-01T00:00:00.000Z",
        not_after=None,
        revoked_at=None,
        purpose="test_fixture",
    )
    return GeneratedKey(
        key_id=kid,
        public_key_b64=public_key_b64,
        private_key=private_key,
        verification_key=verification_key,
    )


def sign_record(
    payload: ProofReceiptPayload,
    key: GeneratedKey,
    before_hash: Optional[str] = None,
) -> ProofRecord:
    """Produce a fully-formed ProofRecord from a payload + key.

    Mirrors the platform's signing path byte-for-byte.
    """

    payload_canonical = canonicalise_proof_payload(payload)
    signing_input = canonicalise_proof_signing_input(payload, key.key_id)
    signature_bytes = key.private_key.sign(signing_input.encode("utf-8"))
    signature = base64url_encode(signature_bytes)
    after_hash = hashlib.sha256(payload_canonical.encode("utf-8")).hexdigest()
    return ProofRecord(
        payload=payload,
        key_id=key.key_id,
        algorithm="ed25519",
        signature=signature,
        payload_canonical=payload_canonical,
        before_hash=before_hash,
        after_hash=after_hash,
    )


def build_valid_pack(
    key: Optional[GeneratedKey] = None,
    org_id: str = "org_test",
    pack_id: str = "pack_001",
    payload_overrides: Optional[dict] = None,
) -> Tuple[SignedProofPack, GeneratedKey]:
    """Single-record VALID pack."""

    key = key or generate_key()
    base = ProofReceiptPayload(
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
    if payload_overrides:
        base = replace(base, **payload_overrides)
    record = sign_record(base, key)
    pack = SignedProofPack(
        envelope_version="envelope.v1",
        issued_at="2026-04-01T12:00:00.500Z",
        org_id=org_id,
        pack_id=pack_id,
        records=[record],
    )
    return pack, key


def build_multi_record_chain(count: int, key: GeneratedKey) -> SignedProofPack:
    """Produce N records, properly chained."""

    from datetime import datetime, timedelta, timezone

    records = []
    base_time = datetime(2026, 4, 1, 12, 0, 0, tzinfo=timezone.utc)
    base_rendered = datetime(2026, 4, 1, 11, 59, 0, tzinfo=timezone.utc)
    for i in range(count):
        payload = ProofReceiptPayload(
            version="1",
            receipt_id=f"rec_{str(i).zfill(3)}",
            correlation_id=None,
            spatial_anchor_id=f"anchor_{i % 3}",
            spatial_placement_id=None,
            issued_at=(base_time + timedelta(minutes=i))
            .isoformat()
            .replace("+00:00", "Z"),
            rendered_at=(base_rendered + timedelta(seconds=i))
            .isoformat()
            .replace("+00:00", "Z"),
            dwell_ms=1000 + i * 250,
            nonce=f"nonce_{i}",
            witness=None,
        )
        before = None if i == 0 else records[i - 1].after_hash
        records.append(sign_record(payload, key, before))
    return SignedProofPack(
        envelope_version="envelope.v1",
        issued_at="2026-04-01T13:00:00.000Z",
        org_id="org_test",
        pack_id="pack_multi",
        records=records,
    )


def build_metering_summary(pack: SignedProofPack) -> MeteringSummary:
    """Project the pack into metering using the auditor's own formula."""

    factor = 10 ** 6
    records = []
    total_scaled = 0
    for r in pack.records:
        unit_count_scaled = (r.payload.dwell_ms * factor) // 1000
        unit_count = _format_decimal(unit_count_scaled, 6)
        records.append(
            MeterRecord(
                idem_key=build_meter_idem_key(r.payload.receipt_id, "DWELL_SECONDS"),
                proof_receipt_id=r.payload.receipt_id,
                unit_type="DWELL_SECONDS",
                unit_count=unit_count,
                weight="1.000000",
                spatial_anchor_id=r.payload.spatial_anchor_id,
                spatial_placement_id=r.payload.spatial_placement_id,
                observed_at=r.payload.rendered_at,
                status="PROJECTED",
            )
        )
        total_scaled += unit_count_scaled
    return MeteringSummary(
        schema_version="metering.v1",
        org_id=pack.org_id,
        period_start=pack.records[0].payload.issued_at,
        period_end=pack.records[-1].payload.issued_at,
        records=records,
        totals={
            "DWELL_SECONDS": _format_decimal(total_scaled, 6),
            "IMPRESSION_IN_PLACE": "0.000000",
            "ATTENTION_SECONDS": "0.000000",
            "OCCUPANCY_WEIGHTED_EXPOSURE": "0.000000",
            "COMPLIANT_DELIVERY_MINUTE": "0.000000",
            "CUSTOM": "0.000000",
        },
    )


def build_settlement_summary(metering: MeteringSummary) -> SettlementSummary:
    """Single-line TENANT-100% projection at 100 cents / DWELL_SECOND."""

    price_per_second_cents = 100
    meter_gross: dict = {}
    lines = []
    for m in metering.records:
        seconds = _parse_decimal(m.unit_count, 6) // (10 ** 6)
        gross = int(seconds) * price_per_second_cents
        meter_gross[m.idem_key] = gross
        lines.append(
            SettlementLine(
                idem_key=build_settlement_idem_key(m.idem_key, "TENANT"),
                meter_record_idem_key=m.idem_key,
                party_role="TENANT",
                share="1.000000",
                ledger_account_code="SPATIAL_REVENUE_GROSS",
                amount_cents=gross,
                currency="USD",
                status="PROJECTED",
            )
        )
    total_gross = sum(l.amount_cents for l in lines)
    return SettlementSummary(
        schema_version="settlement.v1",
        org_id=metering.org_id,
        period_start=metering.period_start,
        period_end=metering.period_end,
        currency="USD",
        meter_gross=meter_gross,
        lines=lines,
        totals=SettlementTotals(
            gross_cents=total_gross,
            net_to_tenant_cents=total_gross,
            platform_fee_cents=0,
        ),
    )


def sign_provenance_record(
    fields: ProvenanceSigningFields,
    key: GeneratedKey,
    occurred_at: str = "2026-05-29T12:00:00.000Z",
    proof_id: Optional[str] = None,
) -> ProvenanceRecord:
    """Produce a write-time-signed rights-provenance record.

    Mirrors the platform's apps/api/src/modules/rights/
    provenanceSigner.ts ``signProvenance`` path byte-for-byte:
    canonical pipe-delimited signing input, raw 64-byte Ed25519
    signature, base64url unpadded. Same helper name family as the TS
    ``signProvenanceRecord`` fixture.
    """

    payload_canonical = canonicalise_provenance_signing_input(fields, key.key_id)
    signature_bytes = key.private_key.sign(payload_canonical.encode("utf-8"))
    return ProvenanceRecord(
        proof_id=proof_id or "rp_" + secrets.token_hex(4),
        org_id=fields.org_id,
        provenance_event_type=fields.event_type,
        occurred_at=occurred_at,
        right_id=fields.right_id,
        basis_id=fields.basis_id,
        offer_id=fields.offer_id,
        provenance_before_hash=fields.before_hash,
        provenance_after_hash=fields.after_hash,
        signature_algorithm="ed25519",
        signature=base64url_encode(signature_bytes),
        signer_key_id=key.key_id,
        payload_canonical=payload_canonical,
    )


def build_legacy_provenance_record(
    org_id: str = "org_test",
    provenance_event_type: str = "RIGHT_ISSUED",
) -> ProvenanceRecord:
    """A pre-Wave-14 record carrying only the platform's read-time
    transport HMAC. Not independently verifiable; the verifier reports
    it as an informational PROVENANCE_UNSIGNED_RECORD finding.
    """

    return ProvenanceRecord(
        proof_id="rp_legacy_" + secrets.token_hex(4),
        org_id=org_id,
        provenance_event_type=provenance_event_type,
        occurred_at="2026-03-01T12:00:00.000Z",
        right_id="rgh_legacy",
        basis_id=None,
        offer_id=None,
        provenance_before_hash=None,
        provenance_after_hash="sha256:" + "a" * 64,
        signature_algorithm="hmac-sha256",
        signature="c0ffee" * 10 + "abcd",
        signer_key_id=f"ledger.v1.{org_id}",
        payload_canonical=None,
    )


def _parse_decimal(s: str, places: int) -> int:
    if "." in s:
        int_part, frac_part = s.split(".", 1)
    else:
        int_part, frac_part = s, ""
    padded = (frac_part + "0" * places)[:places]
    return int(f"{int_part}{padded}")


def _format_decimal(n: int, places: int) -> str:
    s = str(n).zfill(places + 1)
    return f"{s[: len(s) - places]}.{s[len(s) - places :]}"
