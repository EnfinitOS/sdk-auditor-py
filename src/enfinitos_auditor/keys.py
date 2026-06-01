"""enfinitos_auditor — verification key source.

Mirrors the TS ``keys.ts`` semantics:

  1. **Platform endpoint** — fetch ``/v1/runtime-keys`` once, cache in
     process, record snapshot ID into every report.

  2. **Local file** — caller supplies a list of ``VerificationKey``
     dataclasses pinned at a specific moment. This is the regulator
     path — no live HTTP dependency.

The cache is **deliberately not time-bounded.** A long-running audit
process working on a months-old proof pack must NOT have its key
directory silently rotate mid-audit; that would change verification
outcomes mid-walk, which violates "an audit run is reproducible".
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, List, Literal, Optional, Protocol

from .errors import AuditorError, as_auditor_error
from .types import SUPPORTED_SIGNATURE_ALGORITHMS, VerificationKey


VerificationKeySourceKind = Literal["platform", "local"]


@dataclass
class KeyDirectorySnapshot:
    source: VerificationKeySourceKind
    snapshot_id: Optional[str]
    issued_at: Optional[str]
    keys: List[VerificationKey]


# Pluggable HTTP fetcher; tests inject. Signature mirrors a minimal
# ``httpx``-style call.
class FetchLike(Protocol):
    def __call__(
        self, url: str, headers: Optional[Dict[str, str]] = None
    ) -> "FetchResponse":  # pragma: no cover - protocol
        ...


class FetchResponse(Protocol):
    status_code: int

    def json(self) -> Any: ...  # pragma: no cover - protocol
    def text(self) -> str: ...  # pragma: no cover - protocol


DEFAULT_PLATFORM_KEYS_URL = "https://api.enfinitos.com/v1/runtime-keys"


# ---------------------------------------------------------------------
# KeyDirectory
# ---------------------------------------------------------------------


KeyLookupReason = Literal[
    "UNKNOWN_KEY_ID",
    "KEY_OUTSIDE_VALIDITY_WINDOW",
    "KEY_REVOKED_BEFORE_ISSUANCE",
]


@dataclass
class KeyLookupHit:
    key: VerificationKey


@dataclass
class KeyLookupMiss:
    reason: KeyLookupReason


KeyLookupResult = KeyLookupHit | KeyLookupMiss


class KeyDirectory:
    """Immutable index over a snapshot of verification keys.

    Lookups apply validity-window + revocation checks at the call site
    (per record), not at construction — the same key may be valid for
    one record's ``issued_at`` and invalid for another's.
    """

    def __init__(self, snapshot: KeyDirectorySnapshot) -> None:
        index: Dict[str, VerificationKey] = {}
        for k in snapshot.keys:
            if k.key_id in index:
                raise AuditorError(
                    code="KEYS_MALFORMED",
                    message=f"duplicate keyId in key directory: {k.key_id}",
                )
            index[k.key_id] = k
        self._index = index
        self.snapshot = snapshot

    def lookup(self, key_id: str, issued_at_iso: str) -> KeyLookupResult:
        key = self._index.get(key_id)
        if key is None:
            return KeyLookupMiss(reason="UNKNOWN_KEY_ID")
        issued_at = _parse_iso_ms(issued_at_iso)
        if issued_at is None:
            return KeyLookupMiss(reason="KEY_OUTSIDE_VALIDITY_WINDOW")
        not_before = _parse_iso_ms(key.not_before)
        if not_before is not None and issued_at < not_before:
            return KeyLookupMiss(reason="KEY_OUTSIDE_VALIDITY_WINDOW")
        if key.not_after is not None:
            not_after = _parse_iso_ms(key.not_after)
            if not_after is not None and issued_at > not_after:
                return KeyLookupMiss(reason="KEY_OUTSIDE_VALIDITY_WINDOW")
        if key.revoked_at is not None:
            revoked_at = _parse_iso_ms(key.revoked_at)
            if revoked_at is not None and issued_at > revoked_at:
                return KeyLookupMiss(reason="KEY_REVOKED_BEFORE_ISSUANCE")
        return KeyLookupHit(key=key)

    def size(self) -> int:
        return len(self._index)

    def key_ids(self) -> List[str]:
        return sorted(self._index.keys())


def _parse_iso_ms(iso: str) -> Optional[float]:
    """Parse an ISO-8601 timestamp into millisecond-since-epoch float.

    Returns None on unparseable input.
    """

    if not iso:
        return None
    try:
        # Accept the platform's standard "...Z" suffix.
        s = iso.replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        return dt.timestamp() * 1000.0
    except ValueError:
        return None


# ---------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------


def load_key_directory(
    source: VerificationKeySourceKind = "local",
    local_keys: Optional[List[VerificationKey]] = None,
    platform_keys_url: str = DEFAULT_PLATFORM_KEYS_URL,
    http_fetch: Optional[Callable[..., Any]] = None,
) -> KeyDirectory:
    """Load a KeyDirectory from local keys or by fetching the platform endpoint.

    On platform fetch the function uses ``httpx`` if available;
    callers in air-gapped environments inject ``http_fetch``.
    """

    if source == "local":
        if local_keys is None:
            raise AuditorError(
                code="INVALID_INPUT",
                message="source=local requires local_keys to be provided",
            )
        validated = [_assert_valid_key(k, i) for i, k in enumerate(local_keys)]
        return KeyDirectory(
            KeyDirectorySnapshot(
                source="local",
                snapshot_id=None,
                issued_at=None,
                keys=validated,
            )
        )

    fetch_fn = http_fetch or _default_http_fetch
    try:
        response = fetch_fn(platform_keys_url, headers={"Accept": "application/json"})
    except AuditorError:
        raise
    except Exception as exc:  # pragma: no cover - network branch
        raise as_auditor_error(
            exc,
            "KEYS_UNAVAILABLE",
            f"failed to fetch verification keys from {platform_keys_url}",
        )

    status = getattr(response, "status_code", None)
    if status is None or status >= 300 or status < 200:
        body = ""
        try:
            body = response.text() if callable(response.text) else response.text  # type: ignore[truthy-function]
        except Exception:  # pragma: no cover - defensive
            pass
        raise AuditorError(
            code="PLATFORM_RESPONSE",
            message=f"key directory returned HTTP {status}",
            detail={"status": status, "body": (body or "")[:256]},
        )

    try:
        parsed = response.json() if callable(response.json) else response.json  # type: ignore[truthy-function]
    except Exception as exc:
        raise as_auditor_error(
            exc, "KEYS_MALFORMED", "key directory response was not valid JSON"
        )

    if not _is_runtime_keys_response(parsed):
        raise AuditorError(
            code="KEYS_MALFORMED",
            message="key directory response did not match the runtime_keys.v1 envelope",
        )

    raw_keys = parsed["data"]["keys"]
    validated = [_assert_valid_key(_coerce_key(k), i) for i, k in enumerate(raw_keys)]
    return KeyDirectory(
        KeyDirectorySnapshot(
            source="platform",
            snapshot_id=parsed["data"].get("snapshotId"),
            issued_at=parsed["data"]["issuedAt"],
            keys=validated,
        )
    )


def _coerce_key(raw: Any) -> VerificationKey:
    """Coerce a wire-format JSON dict into a ``VerificationKey``."""

    if not isinstance(raw, dict):
        raise AuditorError(code="KEYS_MALFORMED", message="key entry is not an object")
    return VerificationKey(
        key_id=raw.get("keyId"),  # type: ignore[arg-type]
        algorithm=raw.get("algorithm"),  # type: ignore[arg-type]
        public_key=raw.get("publicKey"),  # type: ignore[arg-type]
        not_before=raw.get("notBefore"),  # type: ignore[arg-type]
        not_after=raw.get("notAfter"),
        revoked_at=raw.get("revokedAt"),
        purpose=raw.get("purpose"),
    )


def _assert_valid_key(k: VerificationKey, idx: int) -> VerificationKey:
    label = f"keys[{idx}]"
    for field_name in ("key_id", "algorithm", "public_key", "not_before"):
        v = getattr(k, field_name, None)
        if not isinstance(v, str):
            raise AuditorError(
                code="KEYS_MALFORMED", message=f"{label}.{field_name} must be a string"
            )
    if k.not_after is not None and not isinstance(k.not_after, str):
        raise AuditorError(
            code="KEYS_MALFORMED", message=f"{label}.not_after must be a string or None"
        )
    if k.revoked_at is not None and not isinstance(k.revoked_at, str):
        raise AuditorError(
            code="KEYS_MALFORMED", message=f"{label}.revoked_at must be a string or None"
        )
    if k.algorithm not in SUPPORTED_SIGNATURE_ALGORITHMS:
        raise AuditorError(
            code="KEYS_MALFORMED",
            message=(
                f"{label}.algorithm {k.algorithm!r} is not supported "
                f"(only 'ed25519')"
            ),
        )
    return k


def _is_runtime_keys_response(v: Any) -> bool:
    if not isinstance(v, dict):
        return False
    if v.get("ok") is not True:
        return False
    if not isinstance(v.get("contractVersion"), str):
        return False
    data = v.get("data")
    if not isinstance(data, dict):
        return False
    if not isinstance(data.get("keys"), list):
        return False
    if not isinstance(data.get("issuedAt"), str):
        return False
    return True


def _default_http_fetch(url: str, headers: Optional[Dict[str, str]] = None) -> Any:
    """Best-effort fetch using ``httpx``; raises if not installed."""

    try:
        import httpx  # type: ignore
    except ImportError as exc:  # pragma: no cover - env-dependent
        raise AuditorError(
            code="KEYS_UNAVAILABLE",
            message=(
                "no http_fetch supplied and 'httpx' is not installed; "
                "either install httpx or pass source='local' with local_keys"
            ),
            cause=exc,
        )
    response = httpx.get(url, headers=headers or {}, timeout=30.0)
    return _HttpxAdapter(response)


class _HttpxAdapter:
    """Adapt a synchronous ``httpx.Response`` to our FetchResponse protocol.

    ``httpx`` already has ``.json()`` / ``.text`` / ``.status_code`` but
    our protocol calls them; we provide callable versions for both
    shapes.
    """

    def __init__(self, response: Any) -> None:
        self._response = response

    @property
    def status_code(self) -> int:
        return int(self._response.status_code)

    def json(self) -> Any:
        return self._response.json()

    def text(self) -> str:
        return self._response.text


__all__ = [
    "DEFAULT_PLATFORM_KEYS_URL",
    "FetchLike",
    "FetchResponse",
    "KeyDirectory",
    "KeyDirectorySnapshot",
    "KeyLookupHit",
    "KeyLookupMiss",
    "KeyLookupReason",
    "KeyLookupResult",
    "VerificationKeySourceKind",
    "load_key_directory",
]
