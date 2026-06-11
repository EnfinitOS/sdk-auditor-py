# enfinitos-sdk-auditor (Python)

EnfinitOS **Auditor / Verifier SDK** for Python — the cryptographic
verification library that regulators, auditors, courts, and third-party
compliance tools use to verify signed proof packs issued by EnfinitOS,
**without having to trust EnfinitOS as a vendor**.

Python port of the reference
[`@enfinitos/sdk-auditor`](https://github.com/EnfinitOS/sdk-auditor-ts)
TypeScript implementation (a
[Rust port](https://github.com/EnfinitOS/sdk-auditor-rs) also
exists). The wire shapes, canonicalisation rules, and verification
semantics are deliberately identical: a regulator auditing the same
proof pack with any of the SDKs MUST get the same VALID/INVALID
verdict on every step.

## What's new in 0.0.3

**Settlement idemKey is now a 3-field content hash** (`settlement.v2`,
BREAKING). Each settlement line's idemKey is
`sha256(meterRecordIdemKey|partyRole|ledgerAccountCode)` — up from the
previous 2-field `sha256(meterRecordIdemKey|partyRole)` — binding the
line to the ledger account it posts to so lines differing only by
ledger account no longer collide. `SettlementSummary.schema_version`
accepts `"settlement.v2"` (and still `"settlement.v1"` at the parse
boundary). Amounts/rounding are unchanged. Byte-identical to the
TypeScript and Rust references. See
[CHANGELOG.md](https://github.com/EnfinitOS/sdk-auditor-py/blob/main/CHANGELOG.md)
for migration notes.

## What's new in 0.0.2

**Rights-provenance write-time signature verification.** The platform
now Ed25519-signs every rights-provenance ledger row at write time
(basis, right, offer, and challenge lifecycle events); 0.0.2 ships
the independent verifier:

```python
from enfinitos_auditor import verify_provenance_chain

report = verify_provenance_chain(
    export_archive_records,      # list[ProvenanceRecord] from /proof/export
    pinned_keys,                 # list[VerificationKey] or a KeyDirectory
    expected_org_id="org_abc",
)
report.status                    # "VALID" | "INVALID" | "SKIPPED"
report.signed_record_count      # write-time-signed records
report.unsigned_record_count    # legacy (pre-write-time) records
```

Legacy records (pre-write-time signing,
`signature_algorithm == "hmac-sha256"`) surface as informational
SKIPPED findings — never INVALID — so 0.0.1-era exports keep
verifying. Also in 0.0.2: `SettlementPartyRole` widened to the
platform's full 8-role union (`AGENCY`, `AFFILIATE`, `RESELLER`,
`TAX_AUTHORITY` added), and packaging metadata moved to the modern
setuptools contract (SPDX `license = "MIT"`, `setuptools>=77`, no
deprecated `License ::` classifier). See
[CHANGELOG.md](https://github.com/EnfinitOS/sdk-auditor-py/blob/main/CHANGELOG.md)
for the full release notes.

## The trust model

EnfinitOS issues signed evidence as part of every spatial-chain run:
a proof receipt for every render, a metering summary projecting
those proofs into billable units, and a settlement summary
reconciling those units into invoiced amounts.

The trust model is **"don't trust us — verify"**:

1. **We sign every record with our private key.** The corresponding
   public key is published at `/v1/runtime-keys`, a deliberately
   public, unauthenticated endpoint. The same endpoint is also
   archived in a regulator-pinnable JSON snapshot, so an auditor can
   verify a months-old proof pack using exactly the key set we
   published at the time it was issued.

2. **Every proof receipt is chained.** Each record carries a
   `before_hash` (the previous record's `after_hash`) and an
   `after_hash` (sha256 of its own canonical payload). The chain
   makes single-record tampering detectable by any party walking the
   chain in order.

3. **Metering is a pure projection of proof.** No platform-side
   alchemy: every meter record is `dwell_ms / 1000` (or one of a few
   other deterministic policies). The auditor SDK ships the same
   projection formulae and re-derives them, asserting equality.

4. **Settlement is a pure projection of metering.** Same logic — a
   share table, a gross price per unit, banker's rounding. The
   auditor SDK ships the same formulae and reconciles.

5. **The auditor has the full canonical-JSON encoder.** Whatever we
   signed, the auditor recomputes from the wire payload, byte-exact.
   A 1-bit divergence between our encoder and theirs would make every
   verification fail — that's a feature: it surfaces immediately.

What this means in practice: an auditor running this SDK on a proof
pack we issued does **not** need access to our infrastructure (beyond
the public key directory), does **not** need credentials, and does
**not** need to take our word for anything. They get back a structured
`AuditReport` that says VALID, INVALID, or SKIPPED per step, with
stable reason codes.

## Installation

```bash
pip install enfinitos-sdk-auditor
```

In an air-gapped environment, install from a wheel:

```bash
pip install ./enfinitos_sdk_auditor-0.0.2-py3-none-any.whl --no-deps
pip install cryptography httpx  # transitive deps
```

Runtime dependencies (kept minimal):
- [`cryptography`](https://cryptography.io/) — Ed25519 verify primitive
- [`httpx`](https://www.python-httpx.org/) — only used when
  `verification_key_source="platform"`; offline audits don't need it

## Five-minute getting started

```python
import json
from enfinitos_auditor import EnfinitOSAuditor

with open("./pack.json") as f:
    pack = json.load(f)

auditor = EnfinitOSAuditor(
    # "platform" fetches from https://api.enfinitos.com/v1/runtime-keys.
    # "local" reads from local_keys (offline audit).
    verification_key_source="platform",
)

report = auditor.verify_proof_pack(pack)
print(report.status)  # "VALID" | "INVALID" | "SKIPPED"

if report.status != "VALID":
    for step in report.steps:
        if step.status == "INVALID":
            print(f"[{step.reason}] {step.target}: {step.message}")
```

## Architecture

```
                  ┌─────────────────────────────────────────┐
                  │           SignedProofPack JSON          │
                  │     (envelope.v1, signed by EnfinitOS)  │
                  └────────────────────┬────────────────────┘
                                       │
                                       ▼
                  ┌─────────────────────────────────────────┐
                  │   parse_signed_proof_pack (proof_pack)  │
                  └────────────────────┬────────────────────┘
                                       │
                  ┌────────────────────┴────────────────────┐
                  │                                         │
                  ▼                                         ▼
   ┌────────────────────────────┐         ┌─────────────────────────┐
   │   verify_proof_record × N  │         │   verify_proof_chain    │
   │   (proof_pack)             │         │   (proof_chain)         │
   │                            │         │                         │
   │   • canonicalise payload   │         │   • before_hash links   │
   │   • check after_hash       │         │   • genesis null check  │
   │   • lookup key_id in dir   │         │   • issued_at ordering  │
   │   • Ed25519 verify         │         └─────────────────────────┘
   └────────────────────────────┘
                  │
                  ▼
   ┌────────────────────────────┐
   │  verify_metering_projection│
   │     (metering_audit)       │
   │                            │
   │   • idem_key reconstruct   │
   │   • unit_count re-project  │
   │   • totals reconcile       │
   └─────────────┬──────────────┘
                 │
                 ▼
   ┌────────────────────────────┐
   │ verify_settlement_reconcil.│
   │   (settlement_audit)       │
   │                            │
   │   • idem_key reconstruct   │
   │   • share-sum == 1         │
   │   • amount_cents recompute │
   │   • totals reconcile       │
   └─────────────┬──────────────┘
                 │
                 ▼
   ┌────────────────────────────┐
   │     FullAuditReport        │
   │                            │
   │   status: VALID / INVALID  │
   │   + steps[] per primitive  │
   │   + reason codes (stable)  │
   └────────────────────────────┘
```

## Sample workflows

### "I'm a regulator inspecting a campaign's evidence"

```python
import json
from enfinitos_auditor import EnfinitOSAuditor, AuditBundle, VerificationKey

with open("./pinned-keys-2026-q1.json") as f:
    keys_raw = json.load(f)
    local_keys = [VerificationKey(**k) for k in keys_raw]

with open("./regulator-export.json") as f:
    bundle_raw = json.load(f)

auditor = EnfinitOSAuditor(
    verification_key_source="local",
    local_keys=local_keys,
)

# AuditBundle from a parsed pack is built using the SDK's parser.
from enfinitos_auditor.proof_pack import parse_signed_proof_pack

pack = parse_signed_proof_pack(bundle_raw)
report = auditor.verify_all(AuditBundle(
    pack=pack,
    metering=pack.metering,
    settlement=pack.settlement,
))

print(f"Pack {report.pack_id} verdict: {report.status}")
for sub_name, sub in [
    ("pack", report.pack),
    ("chain", report.chain),
    ("metering", report.metering),
    ("settlement", report.settlement),
]:
    print(f"  {sub_name}: {sub.status}")
    for step in sub.steps:
        if step.status == "INVALID":
            print(f"    [{step.reason}] {step.target}: {step.message}")
```

### "I'm a customer dispute team verifying delivery"

```python
# We only have the proof pack (no metering/settlement); we just need
# to know the records weren't fabricated.
report = auditor.verify_proof_pack(pack)
# Walks each record's signature + canonicalisation + chain link.
# Reports VALID iff the platform's claims internally cohere.
```

### "I'm an external auditor confirming the operator's claims"

```python
# Full pipeline including settlement reconciliation.
full = auditor.verify_all(AuditBundle(pack=pack,
                                      metering=metering,
                                      settlement=settlement))
# full.status == "VALID" means every line of every settlement row
# re-derives from a re-projected meter row that re-derives from a
# re-canonicalised proof receipt whose Ed25519 signature verifies
# against a public key we pulled from the platform's published
# directory.
```

## API reference

### `EnfinitOSAuditor`

```python
EnfinitOSAuditor(
    verification_key_source: Literal["platform", "local"] = "platform",
    platform_keys_url: str = "https://api.enfinitos.com/v1/runtime-keys",
    local_keys: list[VerificationKey] | None = None,
    http_fetch: Callable | None = None,
    signature_verifier: SignatureVerifier | None = None,
)
```

Methods:

- `verify_proof_pack(pack) → AuditReport`
- `verify_proof_chain(records) → ChainAuditReport`
- `verify_metering_projection(proof, metering) → ProjectionAuditReport`
- `verify_settlement_reconciliation(metering, settlement) → SettlementAuditReport`
- `verify_all(bundle) → FullAuditReport`
- `fetch_keys() → list[VerificationKey]`

### `parse_signed_proof_pack(raw) → SignedProofPack`

Pure parsing + structural validation. Raises
`AuditorError(code="INVALID_INPUT")` on malformed input.

### `verify_proof_chain(records) → ChainAuditReport`

Walks records in order, asserts genesis-null, link continuity, and
issued_at ordering.

### `verify_metering_projection(proof_records, metering, pack_org_id=None) → ProjectionAuditReport`

Re-projects proof receipts into meter records using the same
deterministic formula the platform uses.

### `verify_settlement_reconciliation(metering, settlement) → SettlementAuditReport`

Re-derives settlement lines from metering using the share table.

### `load_key_directory(...) → KeyDirectory`

Fetches verification keys from `/v1/runtime-keys` or accepts a local
set. Validates key shape; caches in-process.

### Canonical JSON helpers

- `canonicalise_proof_payload(payload) → str`
- `canonicalise_proof_signing_input(payload, key_id) → str`
- `canonical_sort_keys(value) → str`
- `sha256_prefixed(canonical) → str`
- `base64url_encode(bytes) → str`
- `base64url_decode(s) → bytes`

## Error model

Two failure classes (identical to TS):

1. **Audit failures** — pack contents fail verification. Returned
   inside `AuditReport.steps[]` with a stable `reason` code. Never
   raised.

2. **Operational errors** — the SDK can't run. Raised as `AuditorError`
   with a stable `code` (`INVALID_INPUT`, `KEYS_UNAVAILABLE`,
   `KEYS_MALFORMED`, `PLATFORM_RESPONSE`, `INTERNAL`).

See the
[TypeScript README](https://github.com/EnfinitOS/sdk-auditor-ts#error-model)
for the full stable reason-code table — every code is identical
across the SDKs.

## Offline / pinned-key audit

A regulator auditing a proof pack issued months ago wants to use
**the same key set that was published at the time of issuance** — not
the current set (which may have been rotated). The audit run is
**reproducible**: months later, anyone with the same pack + the same
pinned key set will get exactly the same `FullAuditReport`.

```python
from enfinitos_auditor import EnfinitOSAuditor, VerificationKey

local_keys = [
    VerificationKey(
        key_id="key_2026q1",
        algorithm="ed25519",
        public_key="6KQR9xKHdM1JCJ2GpWnHvWNd0vZkjjvbR9eEKwBPgJ4",  # base64url
        not_before="2026-01-01T00:00:00.000Z",
        not_after="2026-04-01T00:00:00.000Z",
        revoked_at=None,
    ),
]
auditor = EnfinitOSAuditor(
    verification_key_source="local",
    local_keys=local_keys,
)
report = auditor.verify_all(bundle)
```

## Verification

```bash
cd packages/sdks/auditor-py
python -m pytest          # runs the test suite (requires pytest)
```

Cross-references to the platform-side counterpart:
- canonical.ts: `apps/api/src/services/spatialChain/canonicalise.ts`
- proof signing: `apps/api/src/services/spatialChain/proofService.ts`
- metering projection: `apps/api/src/services/spatialChain/meterService.ts`
- settlement projection: `apps/api/src/services/spatialChain/settlementService.ts`
- right/basis/offer hashes: `apps/api/src/modules/rights/service.ts`
