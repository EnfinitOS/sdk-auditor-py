"""Tenant-level chain verification — Wave 27 / pre-pilot punch #1 Phase 4.

Independently verifies the tenant-level chain that links every
rights-provenance row a tenant has ever written (Wave 25 / Phase 2).
Link shape::

    tenantChainNext_n = sha256(
        "tenantChain.v1|<prev>|<rowAfterHash>|<sequence>"
    )

Pipe-delimited so this Python verifier reconstructs the same bytes the
TypeScript writer produced — no canonical-JSON library needed.

Cross-language conformance: a tenant chain written by the platform
(TypeScript) MUST verify here in Python, and the reverse — a chain
built by the Python test fixture MUST verify in the TS auditor and
the Rust auditor. The smoke at
``packages/sandbox-core/scripts/smoke-proof-signing.mjs`` exercises
every direction.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional, Sequence

from .types import (
    SDK_VERSION,
    AuditStep,
    ChainAuditReport,
)

#: Stable canonical chain-link version. Bumping requires a new
#: verifier path; never silently change without coordinating with the
#: TS and Rust SDKs.
TENANT_CHAIN_VERSION = "tenantChain.v1"


@dataclass
class TenantChainedRecord:
    """One tenant-chained record.

    Decoupled from :class:`ProofRecord` so this verifier does not pull
    the entire receipt-side type system in.
    """

    row_after_hash: str
    tenant_chain_prev: Optional[str]
    tenant_chain_next: str
    tenant_chain_sequence: str


def canonicalise_tenant_chain_link(
    prev: Optional[str],
    row_after_hash: str,
    sequence: str,
) -> str:
    """Compute the canonical chain-link bytes the platform hashed at
    write time. Pure; hand-rolled pipe-delimited form so cross-
    language verifiers reconstruct without a canonical-JSON library.
    """
    prev_str = prev if prev else "-"
    return f"{TENANT_CHAIN_VERSION}|{prev_str}|{row_after_hash}|{sequence}"


def genesis_chain_tip(org_id: str) -> str:
    """Genesis seed value for a tenant. Length differs from any
    sha256 hex output (always 64 chars), so the seed cannot collide
    with a real link hash.
    """
    return f"provenance.{TENANT_CHAIN_VERSION}.{org_id}"


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def verify_tenant_chain(
    records: Sequence[TenantChainedRecord],
    expected_genesis: str,
) -> ChainAuditReport:
    """Verify the tenant-level chain across a sequence of rows.

    Invariants checked, in order:
        1. Sequence monotonicity. ``records[i].tenant_chain_sequence``
           MUST equal ``records[i-1].tenant_chain_sequence + 1``.
           Gaps or duplicates indicate inserted/dropped rows.
        2. Prev linkage. For i ≥ 1, ``records[i].tenant_chain_prev``
           MUST equal ``records[i-1].tenant_chain_next``. For i = 0
           (genesis), ``tenant_chain_prev`` MUST equal the supplied
           ``expected_genesis``.
        3. Next recomputation. ``records[i].tenant_chain_next`` MUST
           equal ``sha256(canonicalise_tenant_chain_link(prev, after,
           sequence))``. Catches a tampered link that still chains
           correctly to the neighbours but was forged.

    Returns a :class:`ChainAuditReport` — same shape as the TS SDK so
    a regulator can render the two reports side-by-side.
    """
    verified_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )
    steps: List[AuditStep] = []

    if not records:
        steps.append(
            AuditStep(
                target="records",
                kind="chain_link",
                status="INVALID",
                reason="MALFORMED_PACK",
                message="tenant chain audit received an empty record set — nothing to verify",
                detail=None,
            )
        )
        return ChainAuditReport(
            status="INVALID",
            verified_at=verified_at,
            sdk_version=SDK_VERSION,
            record_count=0,
            steps=steps,
        )

    # 1. Genesis link.
    first = records[0]
    first_prev = first.tenant_chain_prev or ""
    if first_prev != expected_genesis:
        steps.append(
            AuditStep(
                target="records[0].tenantChainPrev",
                kind="chain_link",
                status="INVALID",
                reason="CHAIN_LINK_MISMATCH",
                message=(
                    "first record's tenantChainPrev does not equal the expected"
                    " genesis seed — chain is rooted at an unknown prior tip"
                ),
                detail={
                    "expected": expected_genesis,
                    "actual": first_prev,
                },
            )
        )
    else:
        steps.append(
            AuditStep(
                target="records[0].tenantChainPrev",
                kind="chain_link",
                status="VALID",
                reason=None,
                message="genesis prev seed matches the expected tenant seed",
                detail=None,
            )
        )

    # 2. Walk: monotonicity, prev linkage, next recomputation.
    prev_sequence: Optional[int] = None
    for i, curr in enumerate(records):
        # Sequence monotonicity.
        try:
            curr_sequence = int(curr.tenant_chain_sequence)
        except (TypeError, ValueError):
            steps.append(
                AuditStep(
                    target=f"records[{i}].tenantChainSequence",
                    kind="chain_link",
                    status="INVALID",
                    reason="MALFORMED_PACK",
                    message=(
                        f"tenantChainSequence at index {i} is not a valid integer"
                        " string"
                    ),
                    detail={"value": curr.tenant_chain_sequence},
                )
            )
            continue
        if prev_sequence is not None and curr_sequence != prev_sequence + 1:
            steps.append(
                AuditStep(
                    target=f"records[{i}].tenantChainSequence",
                    kind="chain_link",
                    status="INVALID",
                    reason="CHAIN_OUT_OF_ORDER",
                    message=(
                        f"tenantChainSequence at index {i} is {curr_sequence},"
                        f" expected {prev_sequence + 1} (gaps or duplicates"
                        " indicate inserted/dropped rows)"
                    ),
                    detail={
                        "expected": str(prev_sequence + 1),
                        "actual": str(curr_sequence),
                    },
                )
            )
        prev_sequence = curr_sequence

        # Prev linkage (skip for genesis — covered above).
        if i > 0:
            prev_record = records[i - 1]
            curr_prev = curr.tenant_chain_prev or ""
            if curr_prev != prev_record.tenant_chain_next:
                steps.append(
                    AuditStep(
                        target=f"records[{i}].tenantChainPrev",
                        kind="chain_link",
                        status="INVALID",
                        reason="CHAIN_LINK_MISMATCH",
                        message=(
                            f"record[{i}].tenantChainPrev does not equal"
                            f" record[{i - 1}].tenantChainNext — chain link"
                            " broken"
                        ),
                        detail={
                            "expected": prev_record.tenant_chain_next,
                            "actual": curr_prev,
                        },
                    )
                )
            else:
                steps.append(
                    AuditStep(
                        target=f"records[{i}].tenantChainPrev",
                        kind="chain_link",
                        status="VALID",
                        reason=None,
                        message=(
                            f"record[{i}] correctly chains off record[{i - 1}]"
                        ),
                        detail=None,
                    )
                )

        # Next recomputation.
        expected_next = _sha256_hex(
            canonicalise_tenant_chain_link(
                curr.tenant_chain_prev,
                curr.row_after_hash,
                str(curr_sequence),
            )
        )
        if expected_next != curr.tenant_chain_next:
            steps.append(
                AuditStep(
                    target=f"records[{i}].tenantChainNext",
                    kind="chain_link",
                    status="INVALID",
                    reason="CHAIN_LINK_MISMATCH",
                    message=(
                        f"record[{i}].tenantChainNext does not equal the"
                        " recomputed link — value was tampered with after write"
                    ),
                    detail={
                        "expected": expected_next,
                        "actual": curr.tenant_chain_next,
                    },
                )
            )
        else:
            steps.append(
                AuditStep(
                    target=f"records[{i}].tenantChainNext",
                    kind="chain_link",
                    status="VALID",
                    reason=None,
                    message=(
                        f"record[{i}].tenantChainNext matches the recomputed link"
                    ),
                    detail=None,
                )
            )

    any_invalid = any(s.status == "INVALID" for s in steps)
    final_status = "INVALID" if any_invalid else "VALID"
    return ChainAuditReport(
        status=final_status,
        verified_at=verified_at,
        sdk_version=SDK_VERSION,
        record_count=len(records),
        steps=steps,
    )


__all__ = [
    "TENANT_CHAIN_VERSION",
    "TenantChainedRecord",
    "canonicalise_tenant_chain_link",
    "genesis_chain_tip",
    "verify_tenant_chain",
]
