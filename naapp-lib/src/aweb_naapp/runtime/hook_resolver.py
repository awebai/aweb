"""Hook resolution: where an app delivers a team's hook events, and whom it accepts them from.

The reads of app-team-server-api §4, signed under the ``hook-resolve``
purpose. The team's server is always the one its ``aweb.team-server/1``
record names, found through :class:`TeamServerDirectory`, never an origin an
event or a request names; when that record changes, the next resolution
follows it. Answers are reused through :class:`FreshnessCache` for at most
``min(max_age_seconds, 60)`` seconds and an expired one is never served. Each
:class:`Resolution` says how old its data may be: ``as_of`` is the wall-clock
time its request was sent, which the server read after, and ``max_age_seconds``
the window it was reused for, so a caller bounding the data's age measures the
data, not the time it asked. That bound holds because the server's resolution
endpoints read their bindings from its database per request, after the request
arrives; if they ever answer from a server-side cache, ``as_of`` must come from
the server's own read time instead.

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
from urllib.parse import quote, urlencode
from uuid import UUID

import httpx

from aweb_naapp.runtime.app_credentials import HOOK_RESOLVE, AppCredentialSigner
from aweb_naapp.runtime.freshness import (
    DEFAULT_REFRESH_TIMEOUT_SECONDS,
    FRESHNESS_CEILING_SECONDS,
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


# The names a binding can carry, as the server reads them.
_CATALOG_ID = re.compile(r"[a-z][a-z0-9.-]{0,63}")
_HOOK = re.compile(r"[a-z][a-z0-9-]{0,63}")
MAX_CATALOG_VERSION = 999_999_999


def _is_count(value: object, *, maximum: int | None = None) -> bool:
    """A whole number from 1, never a bool."""
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value >= 1
        and (maximum is None or value <= maximum)
    )


def _names_a_hook(catalog_id: object, catalog_version: object, hook: object) -> bool:
    return (
        isinstance(catalog_id, str)
        and bool(_CATALOG_ID.fullmatch(catalog_id))
        and _is_count(catalog_version, maximum=MAX_CATALOG_VERSION)
        and isinstance(hook, str)
        and bool(_HOOK.fullmatch(hook))
    )


def _segments(catalog_id: str, catalog_version: int, hook: str) -> str:
    return "/".join(quote(str(part), safe="") for part in (catalog_id, catalog_version, hook))


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
    # The wall-clock time the data is no older than, and the window it is reused for.
    as_of: datetime
    max_age_seconds: int


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
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if signer.purpose != HOOK_RESOLVE:
            raise ValueError(
                f"hook resolution signs with a {HOOK_RESOLVE} key, not {signer.purpose}"
            )
        self._directory = directory
        self._signer = signer
        self._app_origin = app_origin
        self._transport = transport
        self._clock = clock
        self._cache: FreshnessCache[tuple[Any, ...], tuple[Any, ...]] = FreshnessCache(
            refresh_timeout=refresh_timeout, monotonic=monotonic
        )

    async def registrations(
        self, team_id: str, catalog_id: str, catalog_version: int, hook: str
    ) -> Resolution[HookBinding]:
        """Where to deliver: the team's active registrations of the hook."""
        return await self._list("registration", team_id, catalog_id, catalog_version, hook)

    async def productions(
        self, team_id: str, catalog_id: str, catalog_version: int, hook: str
    ) -> Resolution[HookProduction]:
        """Who may produce: the team's active productions of the hook, with their hook keys."""
        return await self._list("production", team_id, catalog_id, catalog_version, hook)

    async def _list(
        self, kind: str, team_id: str, catalog_id: str, catalog_version: int, hook: str
    ) -> Resolution[Any]:
        # A hook no binding could name has no binding to hold: the server's
        # answer would be hook_binding_required, so nothing is sent.
        if not _names_a_hook(catalog_id, catalog_version, hook):
            raise HookBindingRequired()
        path = f"/v1/apps/self/hooks/{_segments(catalog_id, catalog_version, hook)}/{kind}s"
        return await self._read(
            team_id,
            (f"{kind}s", catalog_id, catalog_version, hook),
            path,
            signed=True,
            parse=lambda body: _list_answer(body, team_id, catalog_id, catalog_version, hook, kind),
        )

    async def own_bindings(
        self,
        team_id: str,
        *,
        binding_id: UUID | None = None,
        hook: tuple[str, int, str] | None = None,
    ) -> Resolution[OwnHookBinding]:
        """This app's own bindings in the team, in every state, by id or by hook.

        A hook no binding could name is refused with ValueError before anything
        is sent."""
        if (binding_id is None) == (hook is None):
            raise ValueError("select own bindings by exactly one of binding_id or hook")
        key: tuple[Any, ...]
        if binding_id is not None:
            if not isinstance(binding_id, UUID):
                raise ValueError("binding_id is a UUID")
            query, key = urlencode({"binding_id": str(binding_id)}), ("own", str(binding_id))
        else:
            assert hook is not None
            if not _names_a_hook(*hook):
                raise ValueError(
                    "hook is (catalog_id, catalog_version, hook) as a binding names it"
                )
            query, key = urlencode({"hook": f"{hook[0]}/{hook[1]}/{hook[2]}"}), ("own", hook)
        return await self._read(
            team_id,
            key,
            f"/v1/apps/self/hooks/bindings?{query}",
            signed=True,
            parse=lambda body: _own_answer(
                body,
                team_id,
                self._signer.app_id,
                self._app_origin,
                binding_id=binding_id,
                hook=hook,
            ),
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
            requested_at = self._clock()
            body = await self._get(server, team_id, path, signed=signed)
            try:
                max_age = _max_age(body)
                window = min(max_age, FRESHNESS_CEILING_SECONDS)
                return (parse(body), requested_at, window), max_age
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
        items, as_of, window = fresh.value
        return Resolution(
            team_id=team_id,
            server_url=server.server_url,
            items=items,
            fresh_until=fresh.fresh_until,
            as_of=as_of,
            max_age_seconds=window,
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
        except (httpx.HTTPError, httpx.InvalidURL) as exc:
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
    _require(_is_count(value), "max_age_seconds")
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


def _uuid(value: object) -> UUID:
    """A UUID in its one canonical spelling."""
    parsed = UUID(_text(value, "binding_id"))
    _require(str(parsed) == value, "binding_id")
    return parsed


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
        "binding_id": _uuid(item["binding_id"]),
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
    catalog = body["catalog"]
    _require(isinstance(catalog, dict) and set(catalog) == {"id", "version"}, "catalog")
    _require(catalog["id"] == catalog_id and _is_count(catalog["version"]), "catalog")
    _require(catalog["version"] == catalog_version, "catalog")
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
    body: dict[str, Any],
    team_id: str,
    app_id: str,
    app_origin: str,
    *,
    binding_id: UUID | None,
    hook: tuple[str, int, str] | None,
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
        _require(_names_a_hook(catalog["id"], catalog["version"], item["hook"]), "catalog")
        # Every binding answers the selector it was asked for.
        if binding_id is not None:
            _require(fields["binding_id"] == binding_id, "binding_id")
        else:
            _require((catalog["id"], catalog["version"], item["hook"]) == hook, "hook")
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
