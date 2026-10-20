"""The secret record v1: what an owner sets about a secret, never its value (§6.2).

``kind`` is the auth scheme the broker executes (§7.5, decision 36), and
``kind_params`` holds that scheme's non-secret parameters. The record is the
change/1 ``after`` v1 of a secret, so its fields are exactly those of ``after``.
"""

from __future__ import annotations

import re
import secrets as random
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

KINDS = (
    "bearer",
    "basic",
    "header",
    "query",
    "oauth2-client-credentials",
    "aws-sigv4",
)
SENSITIVITIES = ("standard", "sensitive")
BACKENDS = ("native", "1password")
FIELDS = frozenset(
    {
        "v",
        "secret_id",
        "ref",
        "description",
        "kind",
        "kind_params",
        "sensitivity",
        "approve_only",
        "backend",
    }
)
MAX_DESCRIPTION = 512

SECRET_ID = re.compile(r"sec_[A-Za-z0-9_-]{6,64}")
REF = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
_HEADER_NAME = re.compile(r"[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}")
_PREFIX = re.compile(r"[\x20-\x7e]{0,64}")
_QUERY_PARAM = re.compile(r"[A-Za-z0-9_.-]{1,64}")
_AWS_NAME = re.compile(r"[a-z0-9-]{1,64}")
_CONTROLS = re.compile(r"[\x00-\x1f\x7f‪-‮⁦-⁩]")

# Headers that frame or route the request, which a credential may never set.
_FRAMING_HEADERS = frozenset(
    {
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "keep-alive",
        "te",
        "trailer",
        "upgrade",
        "proxy-authorization",
        "proxy-connection",
    }
)


class SecretInvalid(ValueError):
    """The record does not have the secret record v1 shape."""


def mint_secret_id() -> str:
    return "sec_" + random.token_urlsafe(16)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise SecretInvalid(message)


def _matches(pattern: re.Pattern[str], value: Any) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _check_kind_params(kind: str, params: Any) -> None:
    _require(isinstance(params, Mapping), "kind_params is an object")
    if kind in ("bearer", "basic"):
        _require(not params, f"{kind} takes no parameters")
    elif kind == "header":
        _require(set(params) == {"name", "prefix"}, "header takes name and prefix")
        _require(_matches(_HEADER_NAME, params["name"]), "the header name is a token")
        _require(params["name"].lower() not in _FRAMING_HEADERS, "the header frames the request")
        _require(_matches(_PREFIX, params["prefix"]), "the prefix is printable ASCII")
    elif kind == "query":
        _require(set(params) == {"param"}, "query takes param")
        _require(_matches(_QUERY_PARAM, params["param"]), "the query parameter is a plain name")
    elif kind == "aws-sigv4":
        _require(set(params) == {"region", "service"}, "aws-sigv4 takes region and service")
        _require(_matches(_AWS_NAME, params["region"]), "the region is a lowercase AWS name")
        _require(_matches(_AWS_NAME, params["service"]), "the service is a lowercase AWS name")
    else:
        # The token endpoint is a destination: it is checked by the egress
        # guard's canonical form, which this record does not yet carry.
        raise SecretInvalid(f"{kind} parameters cannot be checked")


def _check(after: Any) -> None:
    _require(
        isinstance(after, Mapping) and set(after) == FIELDS,
        f"a secret needs exactly {sorted(FIELDS)}",
    )
    _require(type(after["v"]) is int and after["v"] == 1, "this is secret record v1")
    _require(_matches(SECRET_ID, after["secret_id"]), "secret_id is a minted secret id")
    _require(_matches(REF, after["ref"]), "the ref is a lowercase slug")
    description = after["description"]
    _require(
        isinstance(description, str)
        and len(description) <= MAX_DESCRIPTION
        and _CONTROLS.search(description) is None,
        "the description is bounded text without control characters",
    )
    _require(after["kind"] in KINDS, "kind is one of the auth schemes")
    _check_kind_params(after["kind"], after["kind_params"])
    _require(after["sensitivity"] in SENSITIVITIES, "sensitivity is standard or sensitive")
    _require(isinstance(after["approve_only"], bool), "approve_only is a boolean")
    _require(
        not after["approve_only"] or after["sensitivity"] == "sensitive",
        "approve_only implies sensitive",
    )
    _require(after["backend"] in BACKENDS, "backend is native or 1password")


@dataclass(frozen=True)
class SecretRecord:
    secret_id: str
    ref: str
    description: str
    kind: str
    kind_params: Mapping[str, Any]
    sensitivity: str
    approve_only: bool
    backend: str

    @classmethod
    def from_after(cls, after: Mapping[str, Any]) -> SecretRecord:
        """The record for a change/1 ``after``, refused unless it is secret record v1."""
        _check(after)
        return cls(**{name: after[name] for name in FIELDS - {"v"}})

    @property
    def after(self) -> dict[str, Any]:
        return {
            "v": 1,
            "secret_id": self.secret_id,
            "ref": self.ref,
            "description": self.description,
            "kind": self.kind,
            "kind_params": dict(self.kind_params),
            "sensitivity": self.sensitivity,
            "approve_only": self.approve_only,
            "backend": self.backend,
        }
