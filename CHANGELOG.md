# Changelog — enfinitos-sdk-auditor (Python)

All notable changes to the Python auditor SDK. Tracks the reference
TypeScript implementation (`@enfinitos/sdk-auditor` on npm)
release-for-release with identical wire shapes, reason codes, and
verdicts.

## 0.0.2 — 2026-06-05

### Added

- **Rights-provenance write-time signature verification** (Wave 14
  Phase 2). New `enfinitos_auditor.provenance` module, exported from
  the package root:
  - `verify_provenance_chain(records, keys, expected_org_id=None,
    verifier=None)` — verifies the per-record Ed25519 signatures the
    platform computes at write time on every rights-provenance row
    (basis assert/verify/reject, right issue/suspend/resume/revoke/
    expire, offer propose/accept/counter/reject/withdraw/expire,
    challenge open/resolve/withdraw). Returns a
    `ProvenanceAuditReport` with the signed/unsigned record partition
    surfaced.
  - `verify_provenance_record(record, index, keys, verifier=None)` —
    the per-record primitive.
  - `canonicalise_provenance_signing_input(fields, key_id)` +
    `PROVENANCE_SIGNING_VERSION` — byte-for-byte reconstruction of
    the platform's flat pipe-delimited signing input
    (`rightProvenance.v1|org|eventType|rightId|basisId|offerId|`
    `beforeHash|afterHash|keyId`, `-` for absent fields).
  - New types: `ProvenanceRecord`, `ProvenanceAuditReport`,
    `ProvenanceSigningFields`.
  - Five new stable reason codes (additive):
    `PROVENANCE_SIGNATURE_INVALID`, `PROVENANCE_SIGNATURE_MALFORMED`,
    `PROVENANCE_CANONICAL_MISMATCH`, `PROVENANCE_UNSIGNED_RECORD`,
    `PROVENANCE_ORG_MISMATCH`; new step kind `provenance_signature`.
- `canonical_json.base64url_decode_strict` — strict RFC 4648 §5
  base64url decoding (rejects whitespace, padding, off-alphabet
  characters, mod-4==1 lengths), parity with the TS reference's
  `base64UrlDecode`. Mandatory for the provenance verifier because
  stdlib `base64.urlsafe_b64decode` silently discards invalid
  characters; the permissive `base64url_decode` keeps the pre-0.0.2
  receipt path's behaviour.
- **Legacy posture**: records written before write-time provenance
  signing (`signature_algorithm == "hmac-sha256"`) report as
  informational SKIPPED steps with reason
  `PROVENANCE_UNSIGNED_RECORD` — never INVALID. Exports produced
  under 0.0.1 keep verifying unchanged; an all-legacy set reports
  SKIPPED (nothing verifiable, nothing failed).

### Changed

- `SettlementPartyRole` widened from 4 to 8 roles — added `AGENCY`,
  `AFFILIATE`, `RESELLER`, `TAX_AUTHORITY` to match the platform's
  May-2026 enterprise settlement rebuild (counterparty-addressed
  splits). All settlement checks were already role-agnostic and the
  Python `Literal` union is non-enforcing at runtime, so 0.0.1
  callers were not affected at parse time (unlike Rust — see the
  Rust CHANGELOG); verification semantics are unchanged.
- `SDK_VERSION` constant (stamped onto every audit report) bumped to
  `"0.0.2"`.

### Packaging

- Build metadata follows the modern setuptools contract:
  `license = "MIT"` as an SPDX expression in `[project]`,
  `setuptools>=77` in the build requirements, and no deprecated
  `License ::` trove classifier — `twine check` passes clean on
  setuptools ≥77 output.

### Notes

- No breaking changes. The provenance verifier is a new, parallel
  primitive; the receipt/chain/metering/settlement pipeline is
  untouched.
- Pair `verify_provenance_chain` (WHO signed each record) with
  `verify_tenant_chain` (each record's POSITION in the tenant's
  append-only history) for the full provenance posture.

## 0.0.1 — 2026-06-03

Initial public release on PyPI.

- `EnfinitOSAuditor` + `verify_all` — full-bundle verification:
  envelope checks, per-record Ed25519 signature + canonicalisation +
  after-hash parity, proof-chain walk, metering re-projection,
  settlement reconciliation.
- `verify_tenant_chain` — tenant append-only history verification.
- Offline / pinned-key audit via `verification_key_source="local"`.
- Stable, enumerable reason-code set for regulator citation.
