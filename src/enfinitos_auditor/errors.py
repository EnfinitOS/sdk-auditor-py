"""enfinitos_auditor — typed error envelope.

The auditor SDK distinguishes two kinds of failures, mirroring TS:

1. **Audit failures** — the artefact under audit fails a verification
   step. NOT raised; recorded inside an ``AuditReport`` step as
   ``INVALID`` with a stable reason code.

2. **Operational errors** — the SDK itself cannot run (network
   failure, malformed JSON, unsupported envelope version). Raised as
   ``AuditorError`` so the caller can distinguish "can't verify"
   from "verified-and-failed".

The line between (1) and (2) is "did we get far enough to produce a
useful structured verdict?" — if yes, audit failure; if no,
operational error.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from .types import AuditReasonCode


# Distinct operational-failure modes — see TS ``AuditorErrorCode``.
AuditorErrorCode = str  # one of:
#   "INVALID_INPUT"
#   "KEYS_UNAVAILABLE"
#   "KEYS_MALFORMED"
#   "PLATFORM_RESPONSE"
#   "INTERNAL"


class AuditorError(Exception):
    """Raised only for operational failures.

    Carries:
      - ``code``   : machine-readable enum (one of the strings above)
      - ``reason`` : optional ``AuditReasonCode`` for callers that
                     want to surface it like a normal audit step
      - ``detail`` : optional structured payload for advanced shells
    """

    def __init__(
        self,
        code: AuditorErrorCode,
        message: str,
        reason: Optional[AuditReasonCode] = None,
        detail: Optional[Dict[str, Any]] = None,
        cause: Optional[BaseException] = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.reason = reason
        self.detail = detail
        self.cause = cause

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"AuditorError(code={self.code!r}, reason={self.reason!r}, "
            f"message={str(self)!r})"
        )


def as_auditor_error(
    exc: BaseException,
    fallback_code: AuditorErrorCode,
    fallback_message: str,
) -> AuditorError:
    """Wrap an arbitrary exception as an ``AuditorError``.

    Used at every IO / crypto boundary where a generic call might
    raise something we did not anticipate.
    """

    if isinstance(exc, AuditorError):
        return exc
    msg = str(exc) if str(exc) else fallback_message
    return AuditorError(code=fallback_code, message=msg, cause=exc)


__all__ = ["AuditorError", "AuditorErrorCode", "as_auditor_error"]
