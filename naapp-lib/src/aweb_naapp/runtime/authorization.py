"""Authorization of an authenticated team-auth request.

A valid team-auth signature proves who signed one request, not that the signer
may perform it. After :func:`aweb_naapp.runtime.team_auth.authenticate_request`,
:func:`authorize_request` admits the request only when all of these hold:

1. the raw external path is canonical, so the segments matched here are the
   segments the app's router dispatches on (otherwise ``400 target_not_canonical``):
   no percent-encoded ``/``, ``\\`` or NUL, no dot segment raw or encoded, and the
   decoded scope path splits exactly as the raw path does;
2. the method and raw external path match exactly one tool the app's manifest
   declares (otherwise ``403 operation_undeclared``);
3. the app's grant source returns a fresh installed grant for the team
   (no installation: ``403 scope_denied``; stale or unreachable authority:
   ``503 authority_unavailable``, with no fallback);
4. the grant contains every scope the tool declares (``403 scope_denied``);
5. the app's resource/action policy allows this principal to act
   (``403 action_denied``).
"""

from __future__ import annotations

import logging
import re
import time
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import unquote

from fastapi import HTTPException, Request

from aweb_naapp.runtime.team_auth import Principal, raw_request_target

logger = logging.getLogger(__name__)

MANIFEST_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})
_PLACEHOLDER = re.compile(r"^\{[^{}/]+\}$")
_ENCODED_SEPARATOR = re.compile(r"%(2f|5c|00)", re.IGNORECASE)


@dataclass(frozen=True)
class DeclaredTool:
    name: str
    method: str
    path: str
    scopes: frozenset[str]

    @property
    def segments(self) -> tuple[str, ...]:
        return tuple(self.path.split("/"))


def is_placeholder(segment: str) -> bool:
    return _PLACEHOLDER.fullmatch(segment) is not None


def _segment_matches(template: str, raw: str) -> bool:
    return bool(raw) if is_placeholder(template) else template == raw


def _templates_overlap(a: DeclaredTool, b: DeclaredTool) -> bool:
    if a.method != b.method or len(a.segments) != len(b.segments):
        return False
    return all(
        x == y or is_placeholder(x) or is_placeholder(y) for x, y in zip(a.segments, b.segments, strict=True)
    )


def _declared_tool(tool: Mapping[str, Any]) -> DeclaredTool:
    name = tool.get("name")
    method = tool.get("method")
    path = tool.get("path")
    scopes = tool.get("scopes")
    if not isinstance(name, str) or not name:
        raise ValueError("manifest tool needs a name")
    if method not in MANIFEST_METHODS:
        raise ValueError(f"manifest tool {name!r} has an unsupported method")
    if not isinstance(path, str) or not path.startswith("/") or "?" in path or "#" in path:
        raise ValueError(f"manifest tool {name!r} needs a relative path without query or fragment")
    for segment in path.split("/"):
        if ("{" in segment or "}" in segment) and not is_placeholder(segment):
            raise ValueError(f"manifest tool {name!r} has a malformed path placeholder")
    if not isinstance(scopes, list) or not scopes or not all(isinstance(s, str) and s for s in scopes):
        raise ValueError(f"manifest tool {name!r} must declare the scopes it requires")
    return DeclaredTool(name=name, method=method, path=path, scopes=frozenset(scopes))


class DeclaredTools:
    """The operations an app's manifest declares, matched by method and raw path."""

    def __init__(self, tools: list[DeclaredTool]) -> None:
        for i, a in enumerate(tools):
            for b in tools[i + 1 :]:
                if _templates_overlap(a, b):
                    raise ValueError(f"manifest tools {a.name!r} and {b.name!r} match the same requests")
        self._tools = tuple(tools)

    def __iter__(self) -> Iterator[DeclaredTool]:
        return iter(self._tools)

    @classmethod
    def from_manifest(cls, manifest: Mapping[str, Any]) -> DeclaredTools:
        return cls([_declared_tool(tool) for tool in manifest["tools"]])

    def match(self, method: str, raw_path: str) -> DeclaredTool | None:
        segments = raw_path.split("/")
        for tool in self._tools:
            if tool.method == method and len(tool.segments) == len(segments) and all(
                _segment_matches(t, r) for t, r in zip(tool.segments, segments, strict=True)
            ):
                return tool
        return None


@dataclass(frozen=True, kw_only=True)
class Grant:
    """The team's installed grant for this app, as its authority reports it.

    A source returns a grant only for an active installation of its own app.
    ``fresh_until`` is a :func:`time.monotonic` deadline after which the grant
    must not be used. ``installation_id`` and ``generation`` are ``None`` when
    the authority does not supply them; they are never derived from other fields.
    """

    team_id: str
    scopes: frozenset[str]
    fresh_until: float
    installation_id: str | None
    generation: int | None


class GrantUnavailable(Exception):
    """The grant authority could not answer; the request must not be admitted."""


class GrantSource(Protocol):
    async def grant_for(self, team_id: str) -> Grant | None:
        """The team's current grant, ``None`` when the app is not installed.

        Raises :class:`GrantUnavailable` when the authority cannot be read.
        """
        ...


class ActionPolicy(Protocol):
    async def __call__(self, request: Request, principal: Principal, tool: DeclaredTool) -> bool:
        """Whether this principal may perform this tool on the requested resource."""
        ...


@dataclass(frozen=True)
class Authorization:
    """Evidence that one request was authenticated, declared, granted and allowed."""

    principal: Principal
    tool: DeclaredTool
    grant: Grant


def _refuse(status_code: int, code: str, message: str) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"code": code, "message": message})


def _is_canonical_target(request: Request, raw_path: str) -> bool:
    raw_segments = raw_path.split("/")
    for segment in raw_segments:
        if _ENCODED_SEPARATOR.search(segment) or unquote(segment) in (".", ".."):
            return False
    decoded = "/".join(unquote(segment) for segment in raw_segments)
    scope_path = str(request.scope.get("path") or "")
    root_path = str(request.scope.get("root_path") or "")
    return decoded in (scope_path, root_path + scope_path)


async def authorize_request(
    request: Request,
    *,
    principal: Principal,
    tools: DeclaredTools,
    grants: GrantSource,
    policy: ActionPolicy,
    monotonic: Callable[[], float] = time.monotonic,
) -> Authorization:
    method = request.method.upper()
    raw_path = raw_request_target(request).split("?", 1)[0]
    if not _is_canonical_target(request, raw_path):
        logger.warning("Refused non-canonical target %r for team %s", raw_path, principal.team_id)
        raise _refuse(400, "target_not_canonical", "The request path is not in canonical form")
    tool = tools.match(method, raw_path)
    if tool is None:
        logger.warning("Refused undeclared operation %s %s for team %s", method, raw_path, principal.team_id)
        raise _refuse(403, "operation_undeclared", "This operation is not declared by the app manifest")

    try:
        grant = await grants.grant_for(principal.team_id)
    except GrantUnavailable:
        logger.exception("Grant authority unavailable for team %s", principal.team_id)
        raise _refuse(503, "authority_unavailable", "The app's installation grant cannot be verified") from None
    if grant is None:
        logger.warning("Refused %s for team %s: app not installed", tool.name, principal.team_id)
        raise _refuse(403, "scope_denied", "The team has not granted this app any scopes")
    if grant.team_id != principal.team_id:
        logger.error("Grant source returned team %s's grant for team %s", grant.team_id, principal.team_id)
        raise _refuse(503, "authority_unavailable", "The app's installation grant cannot be verified")
    if grant.fresh_until <= monotonic():
        logger.warning("Refused %s for team %s: installation grant is stale", tool.name, principal.team_id)
        raise _refuse(503, "authority_unavailable", "The app's installation grant is not fresh")
    if not tool.scopes <= grant.scopes:
        logger.warning(
            "Refused %s for team %s: missing scopes %s",
            tool.name, principal.team_id, sorted(tool.scopes - grant.scopes),
        )
        raise _refuse(403, "scope_denied", "The team's grant does not include this operation's scopes")

    if not await policy(request, principal, tool):
        logger.warning("Refused %s for %s in team %s by app policy", tool.name, principal.alias, principal.team_id)
        raise _refuse(403, "action_denied", "The app's policy does not allow this action")
    return Authorization(principal=principal, tool=tool, grant=grant)
