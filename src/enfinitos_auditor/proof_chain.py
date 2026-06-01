"""enfinitos_auditor — proof-chain walking + continuity verification.

Mirrors the TS ``proofChain.ts`` semantics. Walks records in issuance
order and verifies three invariants:

  1. **Genesis.**    records[0].before_hash MUST be None.
  2. **Continuity.** For i ≥ 1, records[i].before_hash MUST equal
                     records[i-1].after_hash.
  3. **Ordering.**   issued_at MUST be non-decreasing along the chain.

This module does NOT re-hash payloads — that's
``proof_pack.verify_proof_record``. The chain walk trusts the
``after_hash`` values; if it can't, the pack is already invalid at
the canonicalisation layer (a separate audit step).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from .types import (
    SDK_VERSION,
    AuditStep,
    ChainAuditReport,
    ProofRecord,
)


def verify_proof_chain(records: List[ProofRecord]) -> ChainAuditReport:
    """Walk records in array order; report each link's status.

    The report's overall status is INVALID if any step is INVALID,
    otherwise VALID. An empty input set is reported as INVALID
    (auditing zero records is meaningless).
    """

    verified_at = datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z")
    steps: List[AuditStep] = []

    if not records:
        return ChainAuditReport(
            status="INVALID",
            verified_at=verified_at,
            sdk_version=SDK_VERSION,
            record_count=0,
            steps=[
                AuditStep(
                    target="records",
                    kind="chain_link",
                    status="INVALID",
                    reason="MALFORMED_PACK",
                    message="proof chain is empty — cannot audit a zero-record pack",
                )
            ],
        )

    # 1. Genesis check.
    first = records[0]
    if first.before_hash is not None:
        steps.append(
            AuditStep(
                target="records[0].beforeHash",
                kind="chain_link",
                status="INVALID",
                reason="GENESIS_BEFORE_HASH_NOT_NULL",
                message=(
                    "first record carries a non-null beforeHash — the chain "
                    "is rooted at a record the auditor has not been given. "
                    "The pack is incomplete."
                ),
                detail={"beforeHash": first.before_hash},
            )
        )
    else:
        steps.append(
            AuditStep(
                target="records[0].beforeHash",
                kind="chain_link",
                status="VALID",
                message="genesis record has null beforeHash, as expected",
            )
        )

    # 2. Continuity + 3. ordering, walking forward.
    prev_issued_at_ms: Optional[float] = _parse_iso_or_none(first.payload.issued_at)
    for i in range(1, len(records)):
        curr = records[i]
        prev = records[i - 1]

        if curr.before_hash is None:
            steps.append(
                AuditStep(
                    target=f"records[{i}].beforeHash",
                    kind="chain_link",
                    status="INVALID",
                    reason="GENESIS_BEFORE_HASH_NOT_NULL",
                    message=(
                        f"non-genesis record at index {i} carries a null "
                        "beforeHash — chain broken"
                    ),
                )
            )
        elif curr.before_hash != prev.after_hash:
            steps.append(
                AuditStep(
                    target=f"records[{i}].beforeHash",
                    kind="chain_link",
                    status="INVALID",
                    reason="CHAIN_LINK_MISMATCH",
                    message=(
                        f"record[{i}].beforeHash does not equal "
                        f"record[{i - 1}].afterHash — chain link broken"
                    ),
                    detail={"expected": prev.after_hash, "actual": curr.before_hash},
                )
            )
        else:
            steps.append(
                AuditStep(
                    target=f"records[{i}].beforeHash",
                    kind="chain_link",
                    status="VALID",
                    message=f"record[{i}] correctly chains off record[{i - 1}]",
                )
            )

        curr_issued_at_ms = _parse_iso_or_none(curr.payload.issued_at)
        if (
            curr_issued_at_ms is not None
            and prev_issued_at_ms is not None
            and curr_issued_at_ms < prev_issued_at_ms
        ):
            steps.append(
                AuditStep(
                    target=f"records[{i}].payload.issuedAt",
                    kind="chain_link",
                    status="INVALID",
                    reason="CHAIN_OUT_OF_ORDER",
                    message=(
                        f"record[{i}].issuedAt ({curr.payload.issued_at}) is "
                        f"earlier than record[{i - 1}].issuedAt "
                        f"({prev.payload.issued_at}) — chain reordered"
                    ),
                )
            )
        prev_issued_at_ms = curr_issued_at_ms

    any_invalid = any(s.status == "INVALID" for s in steps)
    return ChainAuditReport(
        status="INVALID" if any_invalid else "VALID",
        verified_at=verified_at,
        sdk_version=SDK_VERSION,
        record_count=len(records),
        steps=steps,
    )


def _parse_iso_or_none(iso: str) -> Optional[float]:
    if not iso:
        return None
    try:
        s = iso.replace("Z", "+00:00")
        return datetime.fromisoformat(s).timestamp() * 1000.0
    except ValueError:
        return None


__all__ = ["verify_proof_chain"]
