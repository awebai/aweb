"""Signed certificate validity, shared by registry and relying services.

This validates authenticated fields, not signatures or revocation. Callers must
first verify the controller signature and current revocation state. No expiry is
the default; no process-wide lifetime policy is imposed here.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})\Z")


class CertificateValidationError(ValueError):
    def __init__(self, code: str, message: str, replacement_certificate_id: str | None = None):
        super().__init__(message)
        self.code = code
        self.replacement_certificate_id = replacement_certificate_id


def certificate_timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        raise CertificateValidationError("certificate_malformed", f"Invalid certificate {field}")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError as exc:
        raise CertificateValidationError("certificate_malformed", f"Invalid certificate {field}") from exc


def validate_certificate_lifetime(
    certificate: dict[str, Any], *, now: datetime | None = None,
    max_lifetime_seconds: int | None = None,
) -> datetime | None:
    """Return the optional expiry; reject invalid, over-policy or expired values.

    v1 without expiry keeps its historical semantics. v2's validity class is
    independent of local/global identity scope. Optional means absent, not null.
    """
    version = certificate.get("version")
    if type(version) is not int or version not in (1, 2):
        raise CertificateValidationError("certificate_malformed", "Unsupported certificate version")
    if version == 2 and certificate.get("validity_class") not in ("member", "ephemeral"):
        raise CertificateValidationError("certificate_malformed", "Invalid certificate validity_class")
    if version == 1 and ("expires_at" in certificate or "validity_class" in certificate):
        raise CertificateValidationError("certificate_malformed", "Lifetime fields require certificate version 2")
    if "expires_at" not in certificate:
        if version == 2:
            certificate_timestamp(certificate.get("issued_at"), "issued_at")
        return None
    issued = certificate_timestamp(certificate.get("issued_at"), "issued_at")
    expires = certificate_timestamp(certificate["expires_at"], "expires_at")
    if expires <= issued:
        raise CertificateValidationError("certificate_malformed", "Certificate expiry must follow issuance")
    if max_lifetime_seconds is not None and (expires - issued).total_seconds() > max_lifetime_seconds:
        raise CertificateValidationError("certificate_lifetime_exceeded", "Certificate exceeds team lifetime policy")
    if expires <= (now if now is not None else datetime.now(timezone.utc)):
        raise CertificateValidationError("certificate_expired", "Team certificate expired")
    return expires
