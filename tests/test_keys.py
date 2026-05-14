"""KeyDirectory lookup / loading semantics."""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Dict, Optional

import pytest

from enfinitos_auditor.errors import AuditorError
from enfinitos_auditor.keys import (
    KeyDirectory,
    KeyDirectorySnapshot,
    KeyLookupHit,
    KeyLookupMiss,
    load_key_directory,
)
from enfinitos_auditor.types import VerificationKey


K = VerificationKey(
    key_id="k1",
    algorithm="ed25519",
    public_key="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    not_before="2025-01-01T00:00:00.000Z",
    not_after="2027-01-01T00:00:00.000Z",
    revoked_at=None,
)


def _local_dir(keys):
    return KeyDirectory(
        KeyDirectorySnapshot(
            source="local", snapshot_id=None, issued_at=None, keys=keys
        )
    )


def test_lookup_returns_hit_for_key_in_window() -> None:
    dir_ = _local_dir([K])
    r = dir_.lookup("k1", "2026-04-01T12:00:00.000Z")
    assert isinstance(r, KeyLookupHit)


def test_lookup_returns_miss_unknown_key_id() -> None:
    dir_ = _local_dir([K])
    r = dir_.lookup("nope", "2026-04-01T12:00:00.000Z")
    assert isinstance(r, KeyLookupMiss)
    assert r.reason == "UNKNOWN_KEY_ID"


def test_lookup_returns_miss_before_not_before() -> None:
    dir_ = _local_dir([K])
    r = dir_.lookup("k1", "2024-04-01T12:00:00.000Z")
    assert isinstance(r, KeyLookupMiss)
    assert r.reason == "KEY_OUTSIDE_VALIDITY_WINDOW"


def test_lookup_returns_miss_after_not_after() -> None:
    dir_ = _local_dir([K])
    r = dir_.lookup("k1", "2028-04-01T12:00:00.000Z")
    assert isinstance(r, KeyLookupMiss)
    assert r.reason == "KEY_OUTSIDE_VALIDITY_WINDOW"


def test_lookup_returns_miss_for_revoked_before_issuance() -> None:
    revoked = replace(K, revoked_at="2026-01-01T00:00:00.000Z")
    dir_ = _local_dir([revoked])
    r = dir_.lookup("k1", "2026-04-01T12:00:00.000Z")
    assert isinstance(r, KeyLookupMiss)
    assert r.reason == "KEY_REVOKED_BEFORE_ISSUANCE"


def test_lookup_accepts_issuance_before_revocation() -> None:
    revoked = replace(K, revoked_at="2026-06-01T00:00:00.000Z")
    dir_ = _local_dir([revoked])
    r = dir_.lookup("k1", "2026-04-01T12:00:00.000Z")
    assert isinstance(r, KeyLookupHit)


def test_directory_rejects_duplicate_key_ids() -> None:
    with pytest.raises(AuditorError):
        _local_dir([K, K])


def test_load_key_directory_local_validates_each_key_shape() -> None:
    bad = replace(K, algorithm="rsa")  # type: ignore[arg-type]
    with pytest.raises(AuditorError, match="not supported"):
        load_key_directory(source="local", local_keys=[bad])


def test_load_key_directory_local_requires_local_keys() -> None:
    with pytest.raises(AuditorError, match="local_keys"):
        load_key_directory(source="local")


def test_load_key_directory_local_returns_directory() -> None:
    dir_ = load_key_directory(source="local", local_keys=[K])
    assert dir_.size() == 1
    assert dir_.key_ids() == ["k1"]
    assert dir_.snapshot.source == "local"


# ---------------------------------------------------------------------
# Platform-source path — uses an injected fake fetcher
# ---------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, status: int, body: Any, text: str = "") -> None:
        self.status_code = status
        self._body = body
        self._text = text

    def json(self) -> Any:
        return self._body

    def text(self) -> str:  # type: ignore[override]
        return self._text


def test_load_key_directory_platform_propagates_unavailable() -> None:
    def fake(url: str, headers: Optional[Dict[str, str]] = None) -> _FakeResponse:
        raise RuntimeError("ECONNREFUSED")

    with pytest.raises(AuditorError, match="ECONNREFUSED"):
        load_key_directory(source="platform", http_fetch=fake)


def test_load_key_directory_platform_propagates_non_2xx() -> None:
    def fake(url: str, headers: Optional[Dict[str, str]] = None) -> _FakeResponse:
        return _FakeResponse(503, {}, "service unavailable")

    with pytest.raises(AuditorError, match="HTTP 503"):
        load_key_directory(source="platform", http_fetch=fake)


def test_load_key_directory_platform_parses_well_formed_envelope() -> None:
    def fake(url: str, headers: Optional[Dict[str, str]] = None) -> _FakeResponse:
        return _FakeResponse(
            200,
            {
                "ok": True,
                "contractVersion": "runtime_keys.v1",
                "data": {
                    "keys": [
                        {
                            "keyId": "k1",
                            "algorithm": "ed25519",
                            "publicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                            "notBefore": "2025-01-01T00:00:00.000Z",
                            "notAfter": "2027-01-01T00:00:00.000Z",
                            "revokedAt": None,
                        }
                    ],
                    "issuedAt": "2026-04-01T00:00:00.000Z",
                    "snapshotId": "snap_1",
                },
            },
        )

    dir_ = load_key_directory(source="platform", http_fetch=fake)
    assert dir_.size() == 1
    assert dir_.snapshot.snapshot_id == "snap_1"


def test_load_key_directory_platform_rejects_malformed_envelope() -> None:
    def fake(url: str, headers: Optional[Dict[str, str]] = None) -> _FakeResponse:
        return _FakeResponse(200, {"not": "an envelope"})

    with pytest.raises(AuditorError, match="runtime_keys.v1 envelope"):
        load_key_directory(source="platform", http_fetch=fake)
