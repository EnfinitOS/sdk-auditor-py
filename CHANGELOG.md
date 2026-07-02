# Changelog — enfinitos-sdk-auditor (Python)

All notable changes to the Python auditor SDK. Tracks the reference
TypeScript implementation (`@enfinitos/sdk-auditor` on npm)
release-for-release with identical wire shapes, reason codes, and
verdicts.

## 0.0.4 — 2026-07-02

### Added

- **Cross-pack chain anchor (`prior_after_hash`).** The platform seals
  proof packs in series: pack 2's `records[0].beforeHash` equals pack
  1's last `afterHash`, not null (`sealProofPack` threads
  `previousAfterHash`). `verify_proof_chain(records,
  prior_after_hash=None)` gains an optional keyword argument — pass the
  previous pack's tail `after_hash` to verify cross-pack continuity;
  a mismatch reports `CHAIN_LINK_MISMATCH`. Omitted (the default), the
  legacy genesis invariant (`records[0].before_hash is None`) applies
  unchanged, so single-pack callers are unaffected. Threaded through
  `EnfinitOSAuditor.verify_proof_chain` and `verify_all` via the new
  `AuditBundle.prior_after_hash` field. Mirrors the TS
  `priorAfterHash` semantics exactly.
- **Legacy `settlement.v1` verification (VER-02).** New
  `settlement_idem_key_v1(meter_record_idem_key, party_role)` — the
  2-field `sha256(meterIdemKey|partyRole)` used by packs sealed before
  the CRYPTO-01 / `settlement.v2` flip.
  `verify_settlement_reconciliation` now selects the reconstruction
  formula by the summary's `schema_version`, so genuine historical
  `settlement.v1` evidence verifies VALID instead of every line
  flagging `SETTLEMENT_IDEM_KEY_MISMATCH`. This supersedes the 0.0.3
  migration note below — re-issuing v1 summaries is no longer
  required.
- **Signed-export verification (`verify_signed_export`)** — verifies
  the `export.v1` envelopes the platform issues from
  `GET /v1/metering?export=true` and `GET /v1/settlement?export=true`:
  key-directory lookup (validity window anchored at `exportedAt`),
  payload re-canonicalisation (`canonical_sort_keys`),
  transparency-hash check, and Ed25519 verification over
  `f"{payloadCanonical}|{keyId}"`. New module
  `enfinitos_auditor.exports` with `SignedExport`,
  `SignedExportAuditReport`, and `parse_signed_export` (accepts the
  raw wire dict from `json.load`). New reason code
  `EXPORT_PAYLOAD_HASH_MISMATCH`; all other failures reuse the
  existing envelope / key / canonicalisation / signature codes. After
  the signature gate passes, feed `export.payload` to
  `verify_metering_projection` / `verify_settlement_reconciliation`
  for the content checks.

### Changed

- `SDK_VERSION` constant (stamped onto every audit report) bumped to
  `"0.0.4"`.

### Publishing note

- **The published 0.0.2 packages fail every settlement.v2 pack the
  platform now issues** (every line flags
  `SETTLEMENT_IDEM_KEY_MISMATCH` under the old 2-field key). 0.0.4 is
  the minimum version that verifies current packs — republish
  npm/PyPI/crates together and treat 0.0.2/0.0.3 as superseded.

## 0.0.3 — 2026-06-11

### Changed (BREAKING — settlement reconciliation)

- **Settlement idemKey is now a 3-field content hash** (`settlement.v2`,
  CRYPTO-01). `settlement_idem_key(...)` takes a third argument,
  `ledger_account_code`, and hashes
  `sha256(meterRecordIdemKey|partyRole|ledgerAccountCode)` instead of
  the previous 2-field `sha256(meterRecordIdemKey|partyRole)`. This
  binds each settlement line to the ledger account it posts to, so two
  lines that differ only by ledger account no longer collide on the
  same idemKey. Byte-identical to the TypeScript and Rust references.
- `verify_settlement_reconciliation` re-derives each line's idemKey
  with all three fields (the settlement line already carries
  `ledger_account_code`). The `SETTLEMENT_IDEM_KEY_MISMATCH` message
  now reads `sha256(meterIdemKey|partyRole|ledgerAccountCode)`.
- `SettlementSummary.schema_version` now accepts `"settlement.v2"`
  alongside `"settlement.v1"`; the proof-pack parser accepts and
  preserves either value. Amount/rounding logic is unchanged
  (floor + largest-share residual absorption, same rounding
  tolerance).

### Migration

- A `settlement.v1` summary whose lines were idem-keyed with the old
  2-field formula will now report `SETTLEMENT_IDEM_KEY_MISMATCH`
  against the 3-field re-derivation. Re-export settlement summaries
  from a platform on `settlement.v2`. Receipt, chain, metering, and
  provenance verification are untouched.

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
