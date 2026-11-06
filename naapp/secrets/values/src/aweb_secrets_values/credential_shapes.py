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
from typing import Any

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
        "privatekey",
        "secret",
        "secretaccesskey",
        "sessiontoken",
        "apikey",
    }
)
_FIELD_NAME = r"[A-Za-z][A-Za-z0-9_-]{2,40}"
_JSON_FIELD = re.compile(rf'"({_FIELD_NAME})"\s*:\s*"[^"]')
_XML_FIELD = re.compile(rf"<({_FIELD_NAME})>\s*[^<\s]")
_FORM_FIELD = re.compile(rf"(?:^|[&?#\s])({_FIELD_NAME})=[^&\s]")

_TOKEN_PATTERNS = [
    re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}"),
    re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}"),
    re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{32,}"),
    re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}"),
    re.compile(r"\bnpm_[A-Za-z0-9]{36,}"),
]
_AWS_KEY_ID = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_AWS_SECRET_KEY = re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])")


def is_credential_field(name: str) -> bool:
    return name.lower().replace("_", "").replace("-", "") in _CREDENTIAL_FIELDS


def has_credential_value(value: Any) -> bool:
    """A credential field contains a nonempty string, directly or nested."""
    if isinstance(value, str):
        return value != ""
    if isinstance(value, dict):
        return any(has_credential_value(item) for item in value.values())
    if isinstance(value, list):
        return any(has_credential_value(item) for item in value)
    return False


def _json_has_credential_field(value: Any) -> bool:
    if isinstance(value, dict):
        return any(
            (is_credential_field(key) and has_credential_value(item))
            or _json_has_credential_field(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_json_has_credential_field(item) for item in value)
    return False


def _has_token_pattern(text: str) -> bool:
    if any(pattern.search(text) for pattern in _TOKEN_PATTERNS):
        return True
    return bool(_AWS_KEY_ID.search(text) and _AWS_SECRET_KEY.search(text))


def is_credential_shaped_value(value: str) -> bool:
    """Whether one value, such as a request header value, looks like a token."""
    return _has_token_pattern(value)


def has_credential_shape(body: bytes) -> bool:
    """Whether a response body looks like it carries a credential."""
    text = body.decode("utf-8", errors="replace")
    try:
        if _json_has_credential_field(json.loads(text)):
            return True
    except ValueError:
        pass
    for pattern in (_JSON_FIELD, _XML_FIELD, _FORM_FIELD):
        if any(is_credential_field(match.group(1)) for match in pattern.finditer(text)):
            return True
    return _has_token_pattern(text)
