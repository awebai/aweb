"""The credential-shape detector (secrets §7.6 step 5).

A response looks like it carries a credential when it has a credential-named
field (``access_token``, ``SecretAccessKey``, ``api_key`` and the like, in
JSON, including JSON cut short, in XML or form encoding) with a non-empty
string value, or a high-confidence token pattern: an AWS key id with a secret
key beside it, a PEM private key, a JWT, or a well-known vendor token prefix. The same patterns refuse
credential-shaped request header values (§7.4).

Detection is a default-deny tripwire, not a proof: a credential in a shape it
does not know passes.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from time import monotonic
from typing import Any

# One budget covers response headers and body, or both runner streams.
_SCAN_SECONDS = 15.0


class CredentialScanUnavailable(RuntimeError):
    """Inspection could not finish. The caller must withhold the output."""


@dataclass(frozen=True)
class CredentialScan:
    deadline: float = field(default_factory=lambda: monotonic() + _SCAN_SECONDS)

    @classmethod
    def within(cls, seconds: float) -> CredentialScan:
        return cls(monotonic() + min(_SCAN_SECONDS, seconds))

    def check(self) -> None:
        if monotonic() >= self.deadline:
            raise CredentialScanUnavailable()


# Credential field names, compared lowercased with "_" and "-" removed.
_CREDENTIAL_FIELDS = frozenset(
    {
        "token",
        "clienttoken",
        "authtoken",
        "bearertoken",
        "secretkey",
        "accesstoken",
        "refreshtoken",
        "idtoken",
        "clientsecret",
        "password",
        "rootpassword",
        "adminpassword",
        "initialpassword",
        "privatekey",
        "secret",
        "secretaccesskey",
        "sessiontoken",
        "apikey",
    }
)
_FIELD_NAME = r"[A-Za-z][A-Za-z0-9_-]{2,40}"
# Names have bounded width. Whitespace is consumed once; none of the
# following separators or value characters can be part of that whitespace.
_JSON_FIELD = re.compile(rf'"({_FIELD_NAME})"\s*+:\s*+"[^"]')
_XML_FIELD = re.compile(rf"<({_FIELD_NAME})>\s*+[^<\s]")
_FORM_FIELD = re.compile(rf"(?:^|[&?#\s])({_FIELD_NAME})=[^&\s]")

_BASE64URL = r"[A-Za-z0-9_-]"
_BASE64URL_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")
_JWT_MIDDLE = re.compile(rf"\.eyJ(?={_BASE64URL}{{8,}}+\.{_BASE64URL}{{16}})")
_JWT_START = re.compile(r"\beyJ")

# Vendor rules have no right boundary. Matching the minimum already proves
# existence and bounds the work at each candidate, regardless of its suffix.
_TOKEN_PATTERNS = (
    # A PEM marker cannot begin inside the words after another marker.
    re.compile(r"-----BEGIN (?:[A-Z0-9]++ )*PRIVATE KEY-----"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22}"),
    re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10}"),
    re.compile(r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{16}"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}"),
    re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{32}"),
    re.compile(r"\bglpat-[A-Za-z0-9_-]{20}"),
    re.compile(r"\bnpm_[A-Za-z0-9]{36}"),
)
_AWS_KEY_ID = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_AWS_SECRET_KEY = re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])")


def is_credential_field(name: str) -> bool:
    return name.lower().replace("_", "").replace("-", "") in _CREDENTIAL_FIELDS


def has_credential_value(value: Any) -> bool:
    """A credential field contains a nonempty string, directly or nested."""
    return _json_has_credential_field(value, in_credential_field=True)


def _json_children(value: Any, in_credential_field: bool) -> Iterator[tuple[Any, bool]]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield item, in_credential_field or is_credential_field(key)
    elif isinstance(value, list):
        for item in value:
            yield item, in_credential_field


def _json_has_credential_field(value: Any, *, in_credential_field: bool = False) -> bool:
    # Carry the ancestor decision down the tree so nested credential fields
    # do not rescan their descendants. Keep iterators so auxiliary space
    # grows with depth even for a wide array.
    pending = [iter(((value, in_credential_field),))]
    while pending:
        item = next(pending[-1], None)
        if item is None:
            pending.pop()
            continue
        value, in_credential_field = item
        if isinstance(value, str) and value and in_credential_field:
            return True
        if isinstance(value, (dict, list)):
            pending.append(_json_children(value, in_credential_field))
    return False


def _has_jwt(text: str) -> bool:
    # Only a dot can start a middle segment. Each candidate consumes a
    # disjoint base64url run in the lookahead. The left runs are also
    # disjoint; look for eyJ with eight characters still available.
    for middle in _JWT_MIDDLE.finditer(text):
        dot = middle.start()
        start = dot
        while start > 0 and text[start - 1] in _BASE64URL_CHARS:
            start -= 1
        if dot - start >= 11 and _JWT_START.search(text, start, dot - 8):
            return True
    return False


def _has_token_pattern(text: str, scan: CredentialScan | None = None) -> bool:
    if _has_jwt(text):
        return True
    for pattern in _TOKEN_PATTERNS:
        if scan is not None:
            scan.check()
        if pattern.search(text):
            return True
    if scan is not None:
        scan.check()
    return _AWS_KEY_ID.search(text) is not None and _AWS_SECRET_KEY.search(text) is not None


def is_credential_shaped_value(value: str) -> bool:
    """Whether one value, such as a request header value, looks like a token."""
    return _has_token_pattern(value)


def _has_credential_shape(body: bytes, scan: CredentialScan) -> bool:
    text = body.decode("utf-8", errors="replace")
    scan.check()
    try:
        if _json_has_credential_field(json.loads(text)):
            return True
    except ValueError:
        pass
    for pattern in (_JSON_FIELD, _XML_FIELD, _FORM_FIELD):
        scan.check()
        if any(is_credential_field(match.group(1)) for match in pattern.finditer(text)):
            return True
    scan.check()
    return _has_token_pattern(text, scan)


def has_credential_shape(body: bytes, *, scan: CredentialScan | None = None) -> bool:
    """Whether a response body looks like it carries a credential."""
    scan = scan or CredentialScan()
    scan.check()
    try:
        detected = _has_credential_shape(body, scan)
    except RecursionError:
        raise CredentialScanUnavailable() from None
    scan.check()
    return detected
