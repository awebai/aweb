"""Authorization of an authenticated team-auth request.

A valid team-auth signature proves who signed one request, not that the signer
may perform it. After :func:`aweb_naapp.runtime.team_auth.authenticate_request`,
:func:`authorize_request` admits the request only when all of these hold:

1. the raw external path is canonical, so the segments matched here are the
   segments the app's router dispatches on (otherwise ``400 target_not_canonical``):
   no percent-encoded ``/``, ``\\`` or NUL, no dot segment raw or encoded, and the
   decoded scope path splits exactly as the raw path does;
2. the method and raw external path match exactly one tool the app's manifest
   declares (otherwise ``403 operation_undeclared``), and the caller's context
   (agent or surface) is one the tool declares (otherwise
   ``403 tool_context_denied``);
3. the app's grant source returns a fresh installed grant for the team
   (no installation: ``403 scope_denied``; stale or unreachable authority:
   ``503 authority_unavailable``, with no fallback);
4. the grant contains every scope the tool declares (``403 scope_denied``);
5. the request delivers no answer except through a surface's answer tool:
   a JSON body for a version 2 tool carries no ``answer`` member
   (``403 answer_payload_refused``), the app's ``action_kind`` resolves no
   ``answer``-kind page action (``403 answer_action_refused``), and a surface's
   invoke tool performs an action whose kind resolves (otherwise
   ``403 action_unresolved``, including when the app supplies no
   ``action_kind``);
6. the app's resource/action policy allows this principal to act
   (``403 action_denied``).
"""

from __future__ import annotations

import json
import logging
import re
import time
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import unquote

from fastapi import HTTPException, Request

from aweb_naapp.manifest import Manifest, ManifestError
from aweb_naapp.runtime.attestation import VerifiedAttestation
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
    # The caller contexts the tool serves: agent, surface and/or hook.
    contexts: frozenset[str]
    # A surface's invoke tool, which performs page actions.
    invokes: bool = False
    # A surface's answer tool, the one tool that takes answers.
    answers: bool = False
    # The request body is a JSON document (body mode json), not raw bytes.
    json_body: bool = True

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


def _declared_tool(
    name: str, tool: Mapping[str, Any], contexts: frozenset[str], *, invokes: bool, answers: bool
) -> DeclaredTool:
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
    # The manifest reader trims the mode and reads an empty one as json.
    json_body = str((tool.get("body") or {}).get("mode") or "").strip() != "raw"
    return DeclaredTool(
        name=name, method=method, path=path, scopes=frozenset(scopes), contexts=contexts,
        invokes=invokes, answers=answers, json_body=json_body,
    )


class DeclaredTools:
    """The operations an app's manifest declares, matched by method and raw path.

    Two tools whose templates can match the same request are refused, even in a
    manifest the shared reader accepts: each request must authorize as exactly
    one tool, with that tool's scopes and contexts.
    """

    def __init__(self, tools: list[DeclaredTool], manifest: Manifest) -> None:
        for i, a in enumerate(tools):
            for b in tools[i + 1 :]:
                if _templates_overlap(a, b):
                    raise ValueError(f"manifest tools {a.name!r} and {b.name!r} match the same requests")
        self._tools = tuple(tools)
        self.manifest = manifest

    def __iter__(self) -> Iterator[DeclaredTool]:
        return iter(self._tools)

    @classmethod
    def from_manifest(cls, manifest: Manifest) -> DeclaredTools:
        """The tools of a manifest that :func:`~aweb_naapp.manifest.load_manifest` resolved."""
        invoke_tools = {surface["invoke_tool"] for surface in manifest.surfaces}
        answer_tools = {surface["answer_tool"] for surface in manifest.surfaces}
        tools = []
        for name, tool in manifest.tools_by_name().items():
            contexts = manifest.tool_contexts(name)
            assert contexts is not None
            tools.append(_declared_tool(
                name, tool, contexts, invokes=name in invoke_tools, answers=name in answer_tools
            ))
        return cls(tools, manifest)

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
    async def grant_for(self, team_id: str, certificate_id: str | None = None) -> Grant | None:
        """The team's current grant, ``None`` when the app is not installed.

        Raises :class:`GrantUnavailable` when the authority cannot be read.
        """
        ...


class ActionPolicy(Protocol):
    async def __call__(self, request: Request, principal: Principal, tool: DeclaredTool) -> bool:
        """Whether this principal may perform this tool on the requested resource."""
        ...


ANSWER_KIND = "answer"


class ActionKind(Protocol):
    async def __call__(self, request: Request, principal: Principal, tool: DeclaredTool) -> str | None:
        """The kind of the page action this request performs, resolved from the
        app's page action definitions, or ``None`` when it performs none or the
        action cannot be resolved."""
        ...


@dataclass(frozen=True)
class Authorization:
    """Evidence that one request was authenticated, declared, granted and allowed."""

    principal: Principal
    tool: DeclaredTool
    grant: Grant
    # The request's verified principal attestation; None when it carries none.
    attestation: VerifiedAttestation | None = None


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
    caller: str,
    tools: DeclaredTools,
    grants: GrantSource,
    policy: ActionPolicy,
    action_kind: ActionKind | None = None,
    monotonic: Callable[[], float] = time.monotonic,
    on_resolved: Callable[[DeclaredTool, Grant], None] | None = None,
) -> Authorization:
    """Admit one authenticated request, or raise the refusal.

    ``caller`` is the request's invocation context, from
    :func:`aweb_naapp.runtime.attestation.caller_context`. ``action_kind``
    resolves the page action a request performs; without it, a surface's
    invoke tool admits nothing. ``on_resolved`` observes the matched tool and
    fresh installation grant before scope/policy admission; it grants no
    authority and must perform no effect or awaited work.
    """
    method = request.method.upper()
    raw_path = raw_request_target(request).split("?", 1)[0]
    if not _is_canonical_target(request, raw_path):
        logger.warning("Refused non-canonical target for team %s", principal.team_id)
        raise _refuse(400, "target_not_canonical", "The request path is not in canonical form")
    tool = tools.match(method, raw_path)
    if tool is None:
        logger.warning("Refused undeclared %s operation for team %s", method, principal.team_id)
        raise _refuse(403, "operation_undeclared", "This operation is not declared by the app manifest")
    if caller not in tool.contexts:
        logger.warning("Refused %s for team %s: not available to %s callers", tool.name, principal.team_id, caller)
        raise _refuse(403, "tool_context_denied", "This operation is not available to this caller")

    try:
        grant = await grants.grant_for(principal.team_id, certificate_id=principal.certificate_id)
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
    # Data-only admission observation: a complete, authenticated request can
    # now be attributed to an installation even if scope/policy refuses it.
    # This callback grants no authority and performs no effect or DB write.
    if on_resolved is not None:
        on_resolved(tool, grant)
    if not tool.scopes <= grant.scopes:
        logger.warning(
            "Refused %s for team %s: missing scopes %s",
            tool.name, principal.team_id, sorted(tool.scopes - grant.scopes),
        )
        raise _refuse(403, "scope_denied", "The team's grant does not include this operation's scopes")

    await _refuse_answers(request, principal, tool, tools.manifest, action_kind)

    if not await policy(request, principal, tool):
        logger.warning("Refused %s for %s in team %s by app policy", tool.name, principal.alias, principal.team_id)
        raise _refuse(403, "action_denied", "The app's policy does not allow this action")
    return Authorization(principal=principal, tool=tool, grant=grant)


async def _refuse_answers(
    request: Request, principal: Principal, tool: DeclaredTool, manifest: Manifest,
    action_kind: ActionKind | None,
) -> None:
    """Refuse a request that would deliver an answer other than through a
    surface's answer tool."""
    if tool.answers:
        return
    if tool.json_body:
        body = await request.body()
        try:
            payload = json.loads(body) if body else None
        except ValueError:
            payload = None
        try:
            manifest.check_answer_payload(tool.name, payload)
        except ManifestError as refused:
            logger.warning("Refused %s for team %s: body carries an answer", tool.name, principal.team_id)
            raise _refuse(403, refused.code, "Answers reach this app only through its answer tool") from None
    kind = None if action_kind is None else await action_kind(request, principal, tool)
    if kind == ANSWER_KIND:
        logger.warning("Refused %s for team %s: answer-kind action", tool.name, principal.team_id)
        raise _refuse(403, "answer_action_refused", "Answers reach this app only through its answer tool")
    if kind is None and tool.invokes:
        logger.warning("Refused %s for team %s: unresolved page action", tool.name, principal.team_id)
        raise _refuse(403, "action_unresolved", "The page action this request performs cannot be resolved")
