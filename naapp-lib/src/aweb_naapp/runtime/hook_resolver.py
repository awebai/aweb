"""Hook resolution: where an app delivers a team's hook events, and whom it accepts them from.

The reads of app-team-server-api §4, signed under the ``hook-resolve``
purpose. The team's server is always the one its ``aweb.team-server/1``
record names, found through :class:`TeamServerDirectory`, never an origin an
event or a request names; when that record changes, the next resolution
follows it. Answers are reused through :class:`FreshnessCache` for at most
``min(max_age_seconds, 60)`` seconds and an expired one is never served.

A binding is listed while its state is active, including before its
``active_from``. The caller compares ``active_from`` with an event's
``occurred_at``; nothing here does.

Errors fail closed:

- :class:`HookBindingRequired` is the server's ``403 hook_binding_required``:
  the caller holds no active binding of the complementary kind.
- :class:`HookResolutionUnavailable` is every other failure: discovery,
  an outage, a timeout, an answer that does not hold, and a refused
  credential. That includes ``403 app_key_not_registered``: the app's own
  installation moved away from the key's digest, which is a fault to fail
  closed on, not an empty answer. The grant source deliberately reads the
  same refusal as "not granted", because there the grant itself is the
  answer; the two are not to be unified.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import httpx

from aweb_naapp.runtime.app_credentials import HOOK_RESOLVE, AppCredentialSigner
from aweb_naapp.runtime.freshness import (
    DEFAULT_REFRESH_TIMEOUT_SECONDS,
    FreshnessCache,
    RefreshTimedOut,
)
from aweb_naapp.runtime.team_server import TeamServer, TeamServerDirectory, TeamServerUnavailable

HOOK_BINDING_REQUIRED = "hook_binding_required"
HOOK_KEY_PURPOSES = frozenset({"hook-event", "hook-delivery"})
STATES = ("pending", "active", "revoked", "superseded")
ENDED_BY = ("owner_act", "uninstall", "generation")
REQUEST_TIMEOUT_SECONDS = 5.0
# Far more than any resolution answer holds; a server sending more is not read.
MAX_ANSWER_BYTES = 4 << 20

_BINDING_TIME = "%Y-%m-%dT%H:%M:%S.%fZ"
_KEY_TIME = "%Y-%m-%dT%H:%M:%SZ"
_BINDING_TIME_SHAPE = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z"
)
_KEY_TIME_SHAPE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")


class HookResolutionUnavailable(Exception):
    """No answer that can be trusted: fail closed."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class HookBindingRequired(Exception):
    """The caller holds no active binding of the complementary kind for the hook."""


class _Malformed(Exception):
    pass


@dataclass(frozen=True)
class HookBinding:
    binding_id: UUID
    kind: str
    app_id: str
    installation_id: str | None
    generation: int | None
    origin: str
    method: str | None
    path: str | None
    digest: str
    active_from: datetime | None


@dataclass(frozen=True)
class ProducerKey:
    kid: str
    did_key: str
    purposes: tuple[str, ...]


@dataclass(frozen=True)
class HookProduction(HookBinding):
    keys: tuple[ProducerKey, ...]


@dataclass(frozen=True)
class OwnHookBinding(HookBinding):
    catalog_id: str
    catalog_version: int
    hook: str
    state: str
    ended_by: str | None
    activated_at: datetime | None
    revoked_at: datetime | None


@dataclass(frozen=True)
class CoreProducerKey:
    kid: str
    did_key: str
    valid_from: datetime
    valid_until: datetime | None


@dataclass(frozen=True)
class Resolution[T]:
    team_id: str
    server_url: str
    items: tuple[T, ...]
    # The time.monotonic() deadline after which this answer must not be used.
    fresh_until: float


class HookResolver:
    """Hook resolution for one app, signed with its ``hook-resolve`` key.

    ``app_origin`` is the app's own origin: its own bindings must name it."""

    def __init__(
        self,
        *,
        directory: TeamServerDirectory,
        signer: AppCredentialSigner,
        app_origin: str,
        transport: httpx.AsyncBaseTransport | None = None,
        refresh_timeout: float = DEFAULT_REFRESH_TIMEOUT_SECONDS,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if signer.purpose != HOOK_RESOLVE:
            raise ValueError(
                f"hook resolution signs with a {HOOK_RESOLVE} key, not {signer.purpose}"
            )
        self._directory = directory
        self._signer = signer
        self._app_origin = app_origin
        self._transport = transport
        self._cache: FreshnessCache[tuple[Any, ...], tuple[Any, ...]] = FreshnessCache(
            refresh_timeout=refresh_timeout, monotonic=monotonic
        )

    async def registrations(
        self, team_id: str, catalog_id: str, catalog_version: int, hook: str
    ) -> Resolution[HookBinding]:
        """Where to deliver: the team's active registrations of the hook."""
        path = f"/v1/apps/self/hooks/{catalog_id}/{catalog_version}/{hook}/registrations"
        return await self._read(
            team_id,
            ("registrations", catalog_id, catalog_version, hook),
            path,
            signed=True,
            parse=lambda body: _list_answer(
                body, team_id, catalog_id, catalog_version, hook, "registration"
            ),
        )

    async def productions(
        self, team_id: str, catalog_id: str, catalog_version: int, hook: str
    ) -> Resolution[HookProduction]:
        """Who may produce: the team's active productions of the hook, with their hook keys."""
        path = f"/v1/apps/self/hooks/{catalog_id}/{catalog_version}/{hook}/productions"
        return await self._read(
            team_id,
            ("productions", catalog_id, catalog_version, hook),
            path,
            signed=True,
            parse=lambda body: _list_answer(
                body, team_id, catalog_id, catalog_version, hook, "production"
            ),
        )

    async def own_bindings(
        self,
        team_id: str,
        *,
        binding_id: UUID | None = None,
        hook: tuple[str, int, str] | None = None,
    ) -> Resolution[OwnHookBinding]:
        """This app's own bindings in the team, in every state, by id or by hook."""
        if (binding_id is None) == (hook is None):
            raise ValueError("select own bindings by exactly one of binding_id or hook")
        key: tuple[Any, ...]
        if binding_id is not None:
            query, key = f"binding_id={binding_id}", ("own", str(binding_id))
        else:
            assert hook is not None
            query, key = f"hook={hook[0]}/{hook[1]}/{hook[2]}", ("own", hook)
        return await self._read(
            team_id,
            key,
            f"/v1/apps/self/hooks/bindings?{query}",
            signed=True,
            parse=lambda body: _own_answer(body, team_id, self._signer.app_id, self._app_origin),
        )

    async def core_producer_keys(self, team_id: str) -> Resolution[CoreProducerKey]:
        """The public keys the team's server signs core hook events with, retired ones included."""
        return await self._read(
            team_id,
            ("producer-keys",),
            "/v1/hooks/producer-keys",
            signed=False,
            parse=_producer_keys_answer,
        )

    async def _read(
        self,
        team_id: str,
        selection: tuple[Any, ...],
        path: str,
        *,
        signed: bool,
        parse: Callable[[dict[str, Any]], tuple[Any, ...]],
    ) -> Resolution[Any]:
        try:
            server = await self._directory.resolve(team_id)
        except TeamServerUnavailable as exc:
            raise HookResolutionUnavailable(exc.code) from exc
        # The anchored server is part of the key, so a changed record never
        # reuses an answer from the server it replaced.
        key = (team_id, server.server_url, server.audience, server.team_did_key, *selection)

        async def fetch() -> tuple[tuple[Any, ...], int]:
            body = await self._get(server, team_id, path, signed=signed)
            try:
                return parse(body), _max_age(body)
            except (_Malformed, KeyError, TypeError, ValueError) as exc:
                raise HookResolutionUnavailable("answer_malformed") from exc

        try:
            fresh = await self._cache.get(key, fetch)
        except (HookBindingRequired, HookResolutionUnavailable):
            raise
        except RefreshTimedOut as exc:
            raise HookResolutionUnavailable("timeout") from exc
        except ValueError as exc:
            raise HookResolutionUnavailable("answer_malformed") from exc
        return Resolution(
            team_id=team_id,
            server_url=server.server_url,
            items=fresh.value,
            fresh_until=fresh.fresh_until,
        )

    async def _get(
        self, server: TeamServer, team_id: str, path: str, *, signed: bool
    ) -> dict[str, Any]:
        url = f"{server.server_url}{path}"
        headers = (
            self._signer.sign(method="GET", target=url, team_id=team_id).headers if signed else {}
        )
        options: dict[str, Any] = {"timeout": REQUEST_TIMEOUT_SECONDS, "follow_redirects": False}
        if self._transport is not None:
            options["transport"] = self._transport
        try:
            async with httpx.AsyncClient(**options) as client:
                async with client.stream("GET", url, headers=headers) as response:
                    content = await _bounded_body(response)
        except httpx.HTTPError as exc:
            raise HookResolutionUnavailable("server_unreachable") from exc
        if response.status_code == 403 and _detail(content) == HOOK_BINDING_REQUIRED:
            raise HookBindingRequired()
        if response.status_code != 200:
            raise HookResolutionUnavailable(f"server_status_{response.status_code}")
        try:
            body = json.loads(content)
        except ValueError as exc:
            raise HookResolutionUnavailable("answer_malformed") from exc
        if not isinstance(body, dict):
            raise HookResolutionUnavailable("answer_malformed")
        return body


async def _bounded_body(response: httpx.Response) -> bytes:
    """The response body, refused unread past MAX_ANSWER_BYTES."""
    content = bytearray()
    async for chunk in response.aiter_bytes():
        content += chunk
        if len(content) > MAX_ANSWER_BYTES:
            raise HookResolutionUnavailable("answer_too_large")
    return bytes(content)


def _detail(content: bytes) -> object:
    try:
        return json.loads(content).get("detail")
    except (ValueError, AttributeError):
        return None


def _max_age(body: dict[str, Any]) -> int:
    value = body["max_age_seconds"]
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise _Malformed("max_age_seconds")
    return value


def _require(condition: bool, what: str) -> None:
    if not condition:
        raise _Malformed(what)


def _text(value: object, what: str, *, optional: bool = False) -> Any:
    if value is None and optional:
        return None
    _require(isinstance(value, str) and value != "", what)
    return value


def _time(
    value: object, what: str, shape: re.Pattern[str], layout: str, *, optional: bool = False
) -> Any:
    if value is None and optional:
        return None
    _require(isinstance(value, str) and bool(shape.fullmatch(value)), what)
    return datetime.strptime(value, layout).replace(tzinfo=UTC)  # type: ignore[arg-type]


def _binding_fields(item: object, kind: str) -> dict[str, Any]:
    _require(isinstance(item, dict), "binding")
    assert isinstance(item, dict)
    _require(item["kind"] == kind, "kind")
    generation = item["generation"]
    _require(
        generation is None or (isinstance(generation, int) and not isinstance(generation, bool)),
        "generation",
    )
    fields = {
        "binding_id": UUID(_text(item["binding_id"], "binding_id")),
        "kind": kind,
        "app_id": _text(item["app_id"], "app_id"),
        "installation_id": _text(item["installation_id"], "installation_id", optional=True),
        "generation": generation,
        "origin": _text(item["origin"], "origin"),
        "method": _text(item["method"], "method", optional=kind == "production"),
        "path": _text(item["path"], "path", optional=kind == "production"),
        "digest": _text(item["digest"], "digest"),
        "active_from": _time(
            item["active_from"], "active_from", _BINDING_TIME_SHAPE, _BINDING_TIME, optional=True
        ),
    }
    if kind == "registration":
        _require(fields["method"] is not None and fields["path"] is not None, "registration target")
    return fields


def _list_answer(
    body: dict[str, Any], team_id: str, catalog_id: str, catalog_version: int, hook: str, kind: str
) -> tuple[Any, ...]:
    _require(body["team_id"] == team_id, "team_id")
    _require(body["catalog"] == {"id": catalog_id, "version": catalog_version}, "catalog")
    _require(body["hook"] == hook, "hook")
    _require(isinstance(body["bindings"], list), "bindings")
    items: list[Any] = []
    for item in body["bindings"]:
        fields = _binding_fields(item, kind)
        _require(fields["active_from"] is not None, "active_from")
        if kind == "production":
            keys = item["keys"]
            _require(isinstance(keys, list), "keys")
            parsed = []
            for key in keys:
                purposes = key["purposes"]
                _require(
                    isinstance(purposes, list) and all(isinstance(p, str) for p in purposes),
                    "purposes",
                )
                _require(bool(HOOK_KEY_PURPOSES & set(purposes)), "key purpose")
                parsed.append(
                    ProducerKey(
                        kid=_text(key["kid"], "kid"),
                        did_key=_text(key["did_key"], "did_key"),
                        purposes=tuple(purposes),
                    )
                )
            items.append(HookProduction(**fields, keys=tuple(parsed)))
        else:
            _require("keys" not in item, "keys")
            items.append(HookBinding(**fields))
    return tuple(items)


def _own_answer(
    body: dict[str, Any], team_id: str, app_id: str, app_origin: str
) -> tuple[Any, ...]:
    _require(body["team_id"] == team_id, "team_id")
    _require(isinstance(body["bindings"], list), "bindings")
    items: list[OwnHookBinding] = []
    for item in body["bindings"]:
        _require(
            isinstance(item, dict) and item.get("kind") in ("registration", "production"), "kind"
        )
        fields = _binding_fields(item, item["kind"])
        _require(fields["app_id"] == app_id, "app_id")
        _require(fields["origin"] == app_origin, "origin")
        catalog = item["catalog"]
        _require(isinstance(catalog, dict) and set(catalog) == {"id", "version"}, "catalog")
        _require(item["state"] in STATES, "state")
        _require(item["ended_by"] is None or item["ended_by"] in ENDED_BY, "ended_by")
        items.append(
            OwnHookBinding(
                **fields,
                catalog_id=_text(catalog["id"], "catalog.id"),
                catalog_version=catalog["version"],
                hook=_text(item["hook"], "hook"),
                state=item["state"],
                ended_by=item["ended_by"],
                activated_at=_time(
                    item["activated_at"],
                    "activated_at",
                    _BINDING_TIME_SHAPE,
                    _BINDING_TIME,
                    optional=True,
                ),
                revoked_at=_time(
                    item["revoked_at"],
                    "revoked_at",
                    _BINDING_TIME_SHAPE,
                    _BINDING_TIME,
                    optional=True,
                ),
            )
        )
    return tuple(items)


def _producer_keys_answer(body: dict[str, Any]) -> tuple[Any, ...]:
    _require(isinstance(body["keys"], list), "keys")
    keys = []
    for item in body["keys"]:
        _require(
            isinstance(item, dict) and set(item) == {"kid", "did_key", "valid_from", "valid_until"},
            "key",
        )
        keys.append(
            CoreProducerKey(
                kid=_text(item["kid"], "kid"),
                did_key=_text(item["did_key"], "did_key"),
                valid_from=_time(item["valid_from"], "valid_from", _KEY_TIME_SHAPE, _KEY_TIME),
                valid_until=_time(
                    item["valid_until"], "valid_until", _KEY_TIME_SHAPE, _KEY_TIME, optional=True
                ),
            )
        )
    return tuple(keys)
