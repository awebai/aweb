"""Shared non-secret kind parameters for console entry (secrets.md §6.2)."""

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum

from aweb_secrets.secret import ClientAuthentication, SecretKind

KIND_NAMES: Mapping[str, str] = {
    SecretKind.BEARER: "Bearer token",
    SecretKind.BASIC: "Basic credentials",
    SecretKind.HEADER: "Custom header",
    SecretKind.QUERY: "Query parameter",
    SecretKind.OAUTH2_CLIENT_CREDENTIALS: "OAuth2 client credentials",
    SecretKind.AWS_SIGV4: "AWS Signature Version 4",
}


class FieldRequirement(StrEnum):
    REQUIRED = "required"
    OPTIONAL = "optional"


@dataclass(frozen=True, kw_only=True)
class KindParameter:
    name: str
    label: str
    requirement: FieldRequirement


KIND_PARAMETERS = {
    SecretKind.HEADER: (
        KindParameter(name="name", label="Header name", requirement=FieldRequirement.REQUIRED),
        KindParameter(name="prefix", label="Header prefix", requirement=FieldRequirement.OPTIONAL),
    ),
    SecretKind.QUERY: (
        KindParameter(
            name="param", label="Query parameter name", requirement=FieldRequirement.REQUIRED
        ),
    ),
    SecretKind.OAUTH2_CLIENT_CREDENTIALS: (
        KindParameter(
            name="token_endpoint", label="Token endpoint URL", requirement=FieldRequirement.REQUIRED
        ),
        KindParameter(name="scope", label="OAuth scopes", requirement=FieldRequirement.OPTIONAL),
    ),
    SecretKind.AWS_SIGV4: (
        KindParameter(name="region", label="AWS region", requirement=FieldRequirement.REQUIRED),
        KindParameter(name="service", label="AWS service", requirement=FieldRequirement.REQUIRED),
    ),
}


def kind_parameter_controls(kind: SecretKind, *, prefix: str) -> str:
    fields = []
    for parameter in KIND_PARAMETERS.get(kind, ()):
        identity = f"{prefix}-{kind}-{parameter.name}"
        fields.append(
            f'<label for="{identity}">{parameter.label}</label><input id="{identity}" '
            f'data-param="{parameter.name}" autocomplete="off" spellcheck="false"'
            + (" required" if parameter.requirement is FieldRequirement.REQUIRED else "")
            + ">"
        )
    if kind is SecretKind.OAUTH2_CLIENT_CREDENTIALS:
        fields.append(
            f'<label for="{prefix}-client-auth">Client authentication</label>'
            f'<select id="{prefix}-client-auth" data-param="client_auth">'
            f'<option value="{ClientAuthentication.BASIC}">HTTP Basic authentication</option>'
            f'<option value="{ClientAuthentication.POST}">Form body</option></select>'
        )
    return "".join(fields)
