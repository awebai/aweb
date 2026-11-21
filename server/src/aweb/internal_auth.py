from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Optional, TypedDict

from fastapi import HTTPException
from starlette.requests import Request

from aweb.member_team_key import (
    CURRENT_MEMBERSHIP_REQUIRED_DETAIL,
    current_member,
    member_row_active,
    read_member_projection,
)

from starlette.applications import Starlette
from starlette.datastructures import State

logger = logging.getLogger(__name__)

_TEAM_NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")
_DOMAIN_INVALID_RE = re.compile(r"[:/\s]")


def _is_valid_proxy_team_id(team_id: str) -> bool:
    """Validate that team_id is a canonical colon-form like ops:acme.com."""
    if team_id.count(":") != 1:
        return False
    name, domain = team_id.split(":", 1)
    if not name or not domain:
        return False
    if not _TEAM_NAME_RE.fullmatch(name):
        return False
    if _DOMAIN_INVALID_RE.search(domain):
        return False
    if domain != domain.lower().rstrip("."):
        return False
    if ".." in domain:
        return False
    return True


class ProxyHeaderTrust(StrEnum):
    DISABLED = "disabled"
    SHARED_SECRET = "shared_secret"


class ProxyVerificationConfigurationError(ValueError):
    """Invalid application configuration, without secret values in diagnostics."""


@dataclass(frozen=True, kw_only=True)
class ProxyVerificationConfig:
    """Immutable proxy configuration captured before an application serves."""

    trust: ProxyHeaderTrust
    shared_secret: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.trust, ProxyHeaderTrust):
            raise ProxyVerificationConfigurationError(
                "Choose ProxyHeaderTrust.DISABLED or SHARED_SECRET before constructing the application."
            )
        if self.shared_secret is not None and not isinstance(self.shared_secret, str):
            raise ProxyVerificationConfigurationError(
                "Configure the shared secret as text before constructing the application."
            )
        if self.trust is ProxyHeaderTrust.SHARED_SECRET and not self.shared_secret:
            raise ProxyVerificationConfigurationError(
                "Configure a nonempty shared secret or disable proxy header trust before constructing the application."
            )

    @classmethod
    def capture(cls, configured: ProxyVerificationConfig | None = None) -> ProxyVerificationConfig:
        """Resolve explicit configuration or capture environment at construction only."""
        if configured is not None:
            if not isinstance(configured, cls):
                raise ProxyVerificationConfigurationError(
                    "Pass a ProxyVerificationConfig before constructing the application."
                )
            return configured
        enabled = os.getenv("AWEB_TRUST_PROXY_HEADERS", "").strip().lower() in ("1", "true", "yes", "on")
        return cls(
            trust=ProxyHeaderTrust.SHARED_SECRET if enabled else ProxyHeaderTrust.DISABLED,
            shared_secret=os.getenv("AWEB_INTERNAL_AUTH_SECRET"),
        )

    def install(self, app: Starlette) -> None:
        """Bind this snapshot while constructing a host that mounts native routers.

        Full native and embedded apps use their constructor keyword. Custom
        router hosts call this before exposing their app. No process settings
        are read or written here.
        """
        app.state.proxy_verification = self


_DISABLED_PROXY_VERIFICATION = ProxyVerificationConfig(trust=ProxyHeaderTrust.DISABLED)


def application_proxy_verification(state: State | None) -> ProxyVerificationConfig:
    """Select this app's config; a resource reference wins over a host shadow."""
    resources = getattr(state, "native_resources", None)
    configured = (
        getattr(resources, "proxy_verification", None) if resources is not None
        else getattr(state, "proxy_verification", _DISABLED_PROXY_VERIFICATION)
    )
    if not isinstance(configured, ProxyVerificationConfig):
        raise ProxyVerificationConfigurationError(
            "Configure proxy verification through the application constructor before serving requests."
        )
    return configured


INTERNAL_AUTH_HEADER = "X-AWEB-Auth"
INTERNAL_TEAM_HEADER = "X-Team-ID"
INTERNAL_USER_HEADER = "X-User-ID"
INTERNAL_API_KEY_ID_HEADER = "X-API-Key"
INTERNAL_ACTOR_ID_HEADER = "X-AWEB-Actor-ID"


class InternalAuthContext(TypedDict):
    team_id: str
    principal_type: str
    principal_id: str
    actor_id: str


def build_internal_auth_header_value(
    *, secret: str, team_id: str, principal_type: str, principal_id: str, actor_id: str
) -> str:
    msg = f"v2:{team_id}:{principal_type}:{principal_id}:{actor_id}"
    sig = hmac.new(
        secret.encode("utf-8"),
        msg.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"{msg}:{sig}"


def parse_internal_auth_context(
    request: Request, *, proxy_verification: ProxyVerificationConfig | None = None,
) -> Optional[InternalAuthContext]:
    """Parse and validate trusted proxy auth headers.

    Returns None when this app disables proxy trust or no internal header is
    present. Malformed or invalid material raises 401. Constructors capture the
    configuration; request parsing never consults the environment.
    """
    config = proxy_verification if proxy_verification is not None else application_proxy_verification(
        getattr(request.scope.get("app"), "state", None)
    )
    if config.trust is ProxyHeaderTrust.DISABLED:
        return None
    secret = config.shared_secret
    assert secret is not None  # Enabled configuration was validated at construction.

    internal_auth = request.headers.get(INTERNAL_AUTH_HEADER)
    if not internal_auth:
        return None

    team_id = (request.headers.get(INTERNAL_TEAM_HEADER) or "").strip()
    if not team_id:
        raise HTTPException(status_code=401, detail="Authentication required")
    if not _is_valid_proxy_team_id(team_id):
        raise HTTPException(status_code=401, detail="Authentication required")

    user_id = request.headers.get(INTERNAL_USER_HEADER)
    api_key_id = request.headers.get(INTERNAL_API_KEY_ID_HEADER)
    if user_id:
        try:
            user_id = str(uuid.UUID(user_id))
        except ValueError as exc:
            raise HTTPException(status_code=401, detail="Authentication required") from exc
        principal_type = "u"
        principal_id = user_id
    elif api_key_id:
        try:
            api_key_id = str(uuid.UUID(api_key_id))
        except ValueError as exc:
            raise HTTPException(status_code=401, detail="Authentication required") from exc
        principal_type = "k"
        principal_id = api_key_id
    else:
        raise HTTPException(status_code=401, detail="Authentication required")

    actor_id = request.headers.get(INTERNAL_ACTOR_ID_HEADER)
    if not actor_id:
        raise HTTPException(status_code=401, detail="Authentication required")
    try:
        actor_id = str(uuid.UUID(actor_id))
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="Authentication required") from exc

    expected = build_internal_auth_header_value(
        secret=secret,
        team_id=team_id,
        principal_type=principal_type,
        principal_id=principal_id,
        actor_id=actor_id,
    )
    if not hmac.compare_digest(internal_auth, expected):
        raise HTTPException(status_code=401, detail="Authentication required")

    return {
        "team_id": team_id,
        "principal_type": principal_type,
        "principal_id": principal_id,
        "actor_id": actor_id,
    }


async def read_internal_actor_projection(aweb_db, internal: InternalAuthContext):
    """The agent a trusted proxy forwards a request for.

    The proxy's signature says which actor the request is for; it does not say
    that the actor is still a member. Every resolver that admits a forwarded
    request reads the actor here.

    Returns the agent's row when the actor id names an active member of the
    forwarded team: status 'active', not deleted. Returns None when it names no
    agent row at all, which is how a proxy forwards a caller that has no agent
    (a team-scoped key before it is bound, a dashboard person, a public
    reader): a resolver that needs an agent refuses None, one that admits a
    team-level principal goes on without an agent. Raises 403 when it names an
    agent row that is not an active member of that team: one that is retired,
    archived, deleted, or another team's.
    """
    row = await read_member_projection(aweb_db, agent_id=internal["actor_id"])
    if row is None:
        return None
    if (
        row["team_id"] != internal["team_id"]
        or not member_row_active(row)
    ):
        raise HTTPException(status_code=403, detail="Agent not connected")
    if not current_member(row):
        logger.warning(
            "Forwarded actor refused: membership not admitted under the current team key"
        )
        raise HTTPException(
            status_code=403,
            detail=CURRENT_MEMBERSHIP_REQUIRED_DETAIL,
        )
    return row


async def resolve_internal_actor(aweb_db, internal: InternalAuthContext):
    """Return marker-verified actor metadata after current-member eligibility."""
    row = await read_internal_actor_projection(aweb_db, internal)
    return row.verified_identity() if row is not None else None
