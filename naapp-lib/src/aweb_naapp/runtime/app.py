"""The wiring and public surface every naapp shares.

An app creates a :class:`NaappRuntime`, builds its FastAPI app with the
runtime's lifespan, and calls :func:`mount_naapp_routes` for the standard public
surface. An app without the docs surface calls :func:`mount_manifest_routes`
and :func:`aweb_naapp.runtime.health.mount_health` instead.

The runtime reads the app's manifest once, at construction, for its configured
public origin: :attr:`NaappRuntime.manifest_bytes` are the bytes served at the
manifest routes, and the tools authorization checks against are parsed from
those same bytes, never from the app's authoring dict or a later file. The
bytes are read with :func:`aweb_naapp.manifest.load_manifest`, the reader the
aw CLI's conformance vectors pin, so a manifest it refuses stops the app.

Member operations are guarded with ``Depends(runtime.authorized(grants=...,
policy=...))``. It admits a request only when it is signed by a team member,
declared by the served manifest for the caller's invocation context (an agent,
or a surface when a verified principal attestation names the dashboard),
covered by the team's installed grant, and allowed by the app's policy. ``Depends(runtime.principal)`` only
authenticates: it says who signed the request, never that they may act, so it
is for routes that need nothing more than the signer's identity.

The font files under ``/fonts/`` are the app's: this package names the fonts
its stylesheet loads and serves them from the app's directory, but does not
ship them.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import UTC, datetime
from ipaddress import IPv4Network, IPv6Network
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit
from uuid import UUID

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.dependencies.models import Dependant
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from fastapi.routing import APIRoute
from pgdbm import AsyncDatabaseManager
from starlette.routing import BaseRoute, Host, Mount

from aweb_naapp.css import FONT_NAMES, aweb_css
from aweb_naapp.hooks.producer import HookProducer
from aweb_naapp.hooks.resolver import TeamServerRegistrations
from aweb_naapp.manifest import (
    CATALOG_PATH,
    LEGACY_MANIFEST_PATH,
    Manifest,
    ManifestError,
    canonical_bytes,
    fill_manifest,
    load_manifest,
)
from aweb_naapp.outbox import outbox_status, run_drain
from aweb_naapp.robots import robots_txt
from aweb_naapp.runtime.app_credentials import APP_GRANT_READ, HOOK_RESOLVE, AppCredentialSigner
from aweb_naapp.runtime.app_keys import AppKeyError, declared_did_keys, load_app_key
from aweb_naapp.runtime.attestation import (
    AttestationRefused,
    AWIDAttestationRecords,
    VerifiedAttestation,
    caller_context,
    request_attestation,
)
from aweb_naapp.runtime.authorization import (
    ActionKind,
    ActionPolicy,
    Authorization,
    DeclaredTool,
    DeclaredTools,
    Grant,
    GrantSource,
    authorize_request,
    is_placeholder,
)
from aweb_naapp.runtime.db import NaappDatabase, Store
from aweb_naapp.runtime.event_emit import AppEvents, is_loopback_host
from aweb_naapp.runtime.health import CheckResult, HealthCheck, mount_health
from aweb_naapp.runtime.hook_resolver import HookResolver
from aweb_naapp.runtime.hooks import RuntimeHooks
from aweb_naapp.runtime.installation import InstallationFence
from aweb_naapp.runtime.manifest_hooks import ManifestEvidence, bounded_body, prepare
from aweb_naapp.runtime.settings import NaappSettings
from aweb_naapp.runtime.team_auth import (
    AWIDTeamCache,
    MembershipProof,
    Principal,
    authenticate_request,
    record_observed_principal,
)
from aweb_naapp.runtime.team_grants import AppIdentity, TeamGrantSource
from aweb_naapp.runtime.team_server import TeamServerDirectory
from aweb_naapp.skills import Skills

if TYPE_CHECKING:
    from pgdbm.core import TransactionManager

    from aweb_naapp.egress import Egress

logger = logging.getLogger(__name__)

# Where a version 2 manifest's bytes are served, as its catalog lists them.
MANIFEST_V2_PATH = "/manifests/v2.json"

NOINDEX_ROBOTS_HEADER = "noindex, nofollow, noarchive"
_NOSNIFF = {"X-Content-Type-Options": "nosniff"}


class NaappRuntime:
    """A naapp's database, identity cache and shared team-server clients.

    ``root_path`` is the external prefix the server serves the app under, if
    any. Declared tool paths are external paths, so it is part of them.

    ``manifest_path`` is the app's committed manifest file. It is read here,
    once per process, for ``settings.public_origin`` (configuration, never a
    request): ``manifest_bytes`` are served verbatim, and ``manifest`` and
    ``declared_tools`` are parsed from them; a manifest the shared reader
    refuses raises :class:`~aweb_naapp.manifest.ManifestError`. The app-event key the manifest
    declares is loaded here too, so a missing or wrong key stops the app
    before it serves anything, and ``app_events`` emits through it. A declared
    hook-resolve key is also loaded at construction for the shared
    :meth:`hook_resolver`. Identity discovery objects are available without
    I/O before the lifespan, so grant sources can register route guards first.
    """

    def __init__(
        self,
        settings: NaappSettings,
        *,
        module_name: str,
        migrations_path: Path,
        manifest_path: Path,
        root_path: str = "",
        awid_transport: httpx.AsyncBaseTransport | None = None,
        team_server_transport: httpx.AsyncBaseTransport | None = None,
        stores: Sequence[Store] = (),
        hook_egress: Egress | None = None,
        hook_internal_cidr: IPv4Network | IPv6Network | None = None,
    ) -> None:
        self.settings = settings
        # The external prefix the server serves the app under (its ASGI root path).
        self.root_path = root_path.rstrip("/")
        self.module_name = module_name
        self.migrations_path = migrations_path
        self.stores = tuple(stores)
        self._awid_transport = awid_transport
        self._database: NaappDatabase | None = None
        self._attestation_records: AWIDAttestationRecords | None = None
        template = json.loads(manifest_path.read_bytes())
        _refuse_the_hosted_app_id_elsewhere(settings, template)
        self._manifest_bytes = fill_manifest(
            template,
            app_id=settings.app_id,
            origin=settings.public_origin,
            did_keys=declared_did_keys(settings, template),
        )
        self._manifest = load_manifest(self._manifest_bytes)
        self._catalog_bytes = (
            _catalog_bytes(self._manifest, self._manifest_bytes)
            if self._manifest.manifest_version == 2
            else None
        )
        self._declared_tools = DeclaredTools.from_manifest(self._manifest)
        self._app_events = AppEvents.from_settings(settings, self._manifest)
        # Configuration only: these objects perform no I/O until a request.
        # Grant sources and guards must be wired before lifespan validation.
        self._team_cache = AWIDTeamCache(
            registry_url=settings.awid_registry_url,
            ttl_seconds=settings.auth_cache_ttl_seconds,
            service_token=settings.awid_service_token,
            transport=awid_transport,
        )
        self._team_server_directory = TeamServerDirectory(
            team_cache=self._team_cache, transport=awid_transport,
        )
        self._installation_fence: InstallationFence | None = None
        self._installation_grants = None
        if self.manifest.app_keys_for(APP_GRANT_READ):
            key = load_app_key(settings, self.manifest, APP_GRANT_READ)
            self._installation_grants = TeamGrantSource(
                identity=AppIdentity(app_id=self.manifest.app_id,
                    origin=self.manifest.document["app"]["origin"],
                    digest="sha256:" + hashlib.sha256(self.manifest_bytes).hexdigest()),
                signer=AppCredentialSigner(app_id=self.manifest.app_id, key=key, purpose=APP_GRANT_READ),
                discovery=self.team_server_directory(), transport=team_server_transport,
            )
        hook_key = (
            load_app_key(settings, self._manifest, HOOK_RESOLVE)
            if self._manifest.app_keys_for(HOOK_RESOLVE) else None
        )
        self._hook_resolver = (
            HookResolver(
                directory=self._team_server_directory,
                signer=AppCredentialSigner(
                    app_id=self._manifest.app_id, key=hook_key, purpose=HOOK_RESOLVE,
                ),
                app_origin=self._manifest.document["app"]["origin"],
                transport=team_server_transport,
            ) if hook_key is not None else None
        )
        self._hooks = RuntimeHooks.from_settings(
            settings, self._manifest, resolver=self._hook_resolver,
            egress=hook_egress, internal_cidr=hook_internal_cidr,
        )
        # Each authorized() guard, with the action_kind it was given.
        self._guards: dict[Callable[..., object], ActionKind | None] = {}

    @property
    def manifest_bytes(self) -> bytes:
        """The manifest bytes served at the manifest routes, fixed at construction."""
        return self._manifest_bytes

    @property
    def catalog_bytes(self) -> bytes | None:
        """The manifest catalog served for a version 2 manifest, fixed at
        construction; ``None`` for a version 1 manifest, which consumers
        discover at the legacy path."""
        return self._catalog_bytes

    @property
    def manifest(self) -> Manifest:
        """The served manifest, validated and resolved."""
        return self._manifest

    @property
    def declared_tools(self) -> DeclaredTools:
        """The tools authorization checks against, parsed from the served bytes."""
        return self._declared_tools

    @property
    def app_events(self) -> AppEvents:
        """The app's app-event emits, drained by the lifespan."""
        return self._app_events

    @asynccontextmanager
    async def lifespan(self, app: FastAPI) -> AsyncIterator[None]:
        self.check_authorized_routes(app)
        database = NaappDatabase(
            self.settings,
            module_name=self.module_name,
            migrations_path=self.migrations_path,
            stores=self.stores,
        )
        await database.connect()
        self._database = database
        self._attestation_records = AWIDAttestationRecords(
            registry_url=self.settings.awid_registry_url, transport=self._awid_transport
        )
        stop = asyncio.Event()
        client = httpx.AsyncClient(timeout=self.settings.app_emit_timeout_seconds)
        app_events_drain = (
            asyncio.create_task(
                run_drain(database.db, stop=stop, **self._app_events.drain_options(client))
            )
            if self._app_events.key is not None
            else None
        )
        hooks_drain = (
            asyncio.create_task(run_drain(database.db, stop=stop, **self._hooks.drain_options()))
            if self._hooks.key is not None else None
        )
        try:
            yield
        finally:
            stop.set()
            drains = [task for task in (app_events_drain, hooks_drain) if task is not None]
            if drains:
                await asyncio.gather(*drains)
            await client.aclose()
            self._installation_fence = None
            self._database = None
            self._attestation_records = None
            await database.disconnect()

    def connected_db(self) -> AsyncDatabaseManager | None:
        """The database while the app is running, or None, for surfaces that
        must render without it."""
        return self._database.db if self._database is not None else None

    def db(self) -> AsyncDatabaseManager:
        """FastAPI dependency: the app's database."""
        if self._database is None:
            raise RuntimeError("naapp database is not initialized")
        return self._database.db

    def health_checks(self) -> dict[str, HealthCheck]:
        """The runtime's dependencies for the health routes: the database, and
        the age of the oldest outbox event not yet delivered (``None`` when
        every event is delivered). Neither is healthy outside the lifespan."""

        async def database() -> CheckResult:
            db = self.connected_db()
            if db is None:
                return CheckResult(ok=False)
            await db.fetch_value("SELECT 1")
            return CheckResult(ok=True)

        async def outbox() -> CheckResult:
            db = self.connected_db()
            if db is None:
                return CheckResult(ok=False)
            status = await outbox_status(db)
            ages = [
                target.oldest_undelivered_age_seconds
                for target in status.targets.values()
                if target.oldest_undelivered_age_seconds is not None
            ] + [team.oldest_age_seconds for team in status.unmaterialized.values()]
            return CheckResult(
                ok=True, detail={"oldest_undelivered_age_seconds": max(ages, default=None)}
            )

        return {"database": database, "outbox": outbox}

    def team_cache(self) -> AWIDTeamCache:
        """The process's identity cache, available before startup without I/O."""
        return self._team_cache

    def team_server_directory(self) -> TeamServerDirectory:
        """The single directory on :meth:`team_cache`, also shared by hooks.

        Pass this instance to grant sources when registering route guards,
        before entering the lifespan. Discovery verifies controller-signed
        records through the configured AWID transport.
        """
        return self._team_server_directory

    def installation_grants(self) -> TeamGrantSource:
        """The process's one G1 source/cache for its exact served manifest.

        Member tools, presentation/session fences and records consume this same
        object. A key for another purpose never substitutes for grant-read.
        """
        if self._installation_grants is None:
            raise AppKeyError("manifest declares no app-grant-read key")
        return self._installation_grants

    def installation_fence(self) -> InstallationFence:
        """One shared SQL fence over this runtime's G1 source and database.

        Apps opting in apply the shared installation store before their own
        migrations. No app creates another copy of this authority protocol.
        """
        if self._installation_fence is None:
            self._installation_fence = InstallationFence(
                self.db(), app_id=self.manifest.app_id, grants=self.installation_grants(),
            )
        return self._installation_fence

    def hook_resolver(self) -> HookResolver:
        """The shared resolver, signing with the hook-resolve key loaded at startup.

        A manifest without that purpose remains valid, but cannot obtain a
        resolver by substituting a key declared for another purpose.
        """
        if self._hook_resolver is None:
            raise AppKeyError("manifest declares no hook-resolve key")
        return self._hook_resolver

    def hook_registrations(self) -> TeamServerRegistrations:
        """The producer/drain's one source on :meth:`hook_resolver`.

        Fetch its view before authority locks, then pass that view to the
        producer's caller-transaction enqueue or admission check.
        """
        if self._hooks.registrations is None:
            raise AppKeyError("manifest declares no hook production")
        return self._hooks.registrations

    def hook_producer(self, *, installation_id: str, generation: int) -> HookProducer:
        """A producer using the installation resolved by the app's grant/fence.

        Pass the actual effect/operational-record transaction to its enqueue;
        no transaction is supplied by an Authorization or a completed response.
        """
        return self._hooks.producer(installation_id=installation_id, generation=generation)

    async def require_current_member(
        self, team_id: str, *, certificate_id: str, team_did_key: str
    ) -> None:
        """Check membership before a transaction without retaining a proof.

        May perform network I/O. For creator-scoped link access, retain the
        result of :meth:`check_current_member` for local checking under the lock.
        """
        await self.check_current_member(
            team_id, certificate_id=certificate_id, team_did_key=team_did_key
        )

    async def check_current_member(
        self, team_id: str, *, certificate_id: str, team_did_key: str
    ) -> MembershipProof:
        """Fetch/check mint evidence before opening any transaction or lock.

        Retain the in-process proof for a local evidence/expiry check after the
        link lock is acquired. Its deadline is the original AWID facts' expiry.
        """
        return await self.team_cache().check_current_member(
            team_id, certificate_id=certificate_id, team_did_key=team_did_key
        )

    async def principal(self, request: Request) -> Principal:
        """FastAPI dependency: the team member who signed this request.

        Authentication only: any certified member of any team passes. Guard
        member operations with :meth:`authorized` instead.
        """
        return await authenticate_request(
            request,
            public_origin=self.settings.public_origin,
            team_cache=self.team_cache(),
            timestamp_skew_seconds=self.settings.timestamp_skew_seconds,
            did_aw_profile=self.settings.did_aw_profile,
        )

    def authorized(
        self, *, grants: GrantSource, policy: ActionPolicy, action_kind: ActionKind | None = None
    ) -> Callable[[Request], Awaitable[Authorization]]:
        """A FastAPI dependency admitting only authorized member requests.

        It authenticates the request, resolves the caller's invocation
        context from its principal attestation (none means an agent), then
        authorizes it against the tools of the served manifest, the team's
        grant from ``grants`` and the app's ``policy``. ``action_kind``
        resolves the page action a request performs, so that answers reach the
        app only through a surface's answer tool; without it, a surface's
        invoke tool admits nothing. An attestation that does
        not verify refuses the request with its code (``503`` when the registry
        cannot be read); the admitted :class:`Authorization` carries the
        verified attestation for the app's policy. Only an admitted member is
        recorded as observed. A configured manifest production separately
        records complete attributable authorization refusals in its outbox.
        """

        async def authorized_request(request: Request) -> Authorization:
            if self._hooks.manifest_request_key is not None:
                await bounded_body(request, self.settings.manifest_hook_max_request_bytes)
            principal = await self.principal(request)
            attestation, caller = await self._attestation(request, principal)
            evidence: ManifestEvidence | None = None

            def resolved(tool: DeclaredTool, grant: Grant) -> None:
                nonlocal evidence
                if self._hooks.manifest_request_key is not None and tool.name not in self._hooks.tool_effects:
                    evidence = prepare(
                        request, key=self._hooks.manifest_request_key, app_id=self.manifest.app_id,
                        principal=principal, tool=tool, grant=grant,
                    )

            try:
                authorization = await authorize_request(
                    request, principal=principal, caller=caller, tools=self.declared_tools,
                    grants=grants, policy=policy, action_kind=action_kind,
                    on_resolved=resolved,
                )
            except HTTPException as refusal:
                if evidence is not None:
                    async with self.db().transaction() as tx:
                        await self._hooks.record_manifest(
                            tx, evidence, http_status=refusal.status_code, refused=True,
                        )
                raise
            request.state.aweb_manifest_evidence = evidence
            await record_observed_principal(self.db(), principal)
            return replace(authorization, attestation=attestation)

        self._guards[authorized_request] = action_kind
        return authorized_request

    async def record_manifest_command(
        self,
        tx: TransactionManager,
        *,
        request: Request,
        authorization: Authorization,
        http_status: int,
        refused: bool = False,
        resource_refs: Sequence[str] = (),
        result_ref: str | None = None,
    ) -> UUID | None:
        """Record the matched command in its actual effect/outcome transaction.

        Admission prepared the bounded original request commitment once, before
        policy or injection. Reads opt in through the production, and tools
        mapped to a specific hook never fire this generic hook. Final live
        authority/fence checks remain the effect owner's responsibility.
        """
        if self._hooks.manifest_request_key is None or authorization.tool.name in self._hooks.tool_effects:
            return None
        evidence = getattr(request.state, "aweb_manifest_evidence", None)
        if evidence is None or (
            evidence.principal is not authorization.principal
            or evidence.tool is not authorization.tool
            or evidence.grant is not authorization.grant
        ):
            raise RuntimeError("manifest recording needs this request's matched admission evidence")
        return await self._hooks.record_manifest(
            tx, evidence, http_status=http_status, refused=refused,
            resource_refs=resource_refs, result_ref=result_ref,
        )

    async def _attestation(self, request: Request, principal: Principal) -> tuple[VerifiedAttestation | None, str]:
        """The request's verified attestation and its caller context, or the refusal."""
        if self._attestation_records is None:
            raise RuntimeError("naapp attestation records are not initialized")
        try:
            verified = await request_attestation(
                request, principal, records=self._attestation_records, now=datetime.now(UTC)
            )
            return verified, caller_context(verified)
        except AttestationRefused as refused:
            logger.warning("Refused attestation for team %s: %s", principal.team_id, refused.code)
            status = 503 if refused.code == "authority_unavailable" else 403
            raise HTTPException(
                status_code=status,
                detail={"code": refused.code, "message": "The request's principal attestation is refused"},
            ) from None

    def check_authorized_routes(self, app: FastAPI) -> None:
        """Refuse to start unless every route guarded by :meth:`authorized` is
        exactly one of its declared tools.

        The route's method and external path template (``root_path`` plus the
        route's path, placeholders compared by position, not by name) must
        equal a declared tool's. A route that merely matches a declared template,
        such as ``/v1/things/purge`` under a declared ``/v1/things/{id}``, would
        otherwise run its own handler while being authorized as the declared
        tool. Path converters are refused, because they change which requests a
        placeholder matches. Guarded routes must be declared on the runtime's
        own app: one inside a mounted or host-routed application is refused. A
        route that is a surface's invoke tool must be guarded with an
        ``action_kind``, since without one every invoke would be refused.
        The lifespan runs this check before anything else.
        """
        for route in app.routes:
            if isinstance(route, Mount | Host):
                if self._contains_guards(route.routes):
                    raise RuntimeError(
                        "authorized routes must be declared on the runtime's own app, "
                        f"not inside a mounted application ({route!r})"
                    )
                continue
            if not isinstance(route, APIRoute):
                continue
            if self._is_guarded(route.dependant):
                path = self.root_path + route.path_format
                if route.path != route.path_format:
                    raise RuntimeError(
                        f"authorized route {route.path} uses a path converter; declare it plainly"
                    )
                template = _template(path.split("/"))
                for method in sorted(route.methods or ()):
                    tool = next(
                        (
                            tool for tool in self.declared_tools
                            if tool.method == method and _template(tool.segments) == template
                        ),
                        None,
                    )
                    if tool is None:
                        raise RuntimeError(
                            f"authorized route {method} {path} is not exactly a declared manifest tool"
                        )
                    if tool.invokes and any(
                        self._guards[guard] is None for guard in self._route_guards(route.dependant)
                    ):
                        raise RuntimeError(
                            f"authorized route {method} {path} is the invoke tool {tool.name!r}; "
                            "guard it with an action_kind"
                        )

    def _contains_guards(self, routes: Sequence[BaseRoute]) -> bool:
        for route in routes:
            if isinstance(route, Mount | Host) and self._contains_guards(route.routes):
                return True
            if isinstance(route, APIRoute) and self._is_guarded(route.dependant):
                return True
        return False

    def _route_guards(self, dependant: Dependant) -> list[Callable[..., object]]:
        guards = []
        for dependency in dependant.dependencies:
            if dependency.call in self._guards:
                guards.append(dependency.call)
            guards.extend(self._route_guards(dependency))
        return guards

    def _is_guarded(self, dependant: Dependant) -> bool:
        return any(
            dependency.call in self._guards or self._is_guarded(dependency)
            for dependency in dependant.dependencies
        )


def _refuse_the_hosted_app_id_elsewhere(settings: NaappSettings, template: Mapping[str, Any]) -> None:
    """A deployment others can reach must configure its own app id: serving the
    hosted one there would claim the hosted app's identity. Only the hosted
    origin and a loopback origin, which no other team can reach, may serve it."""
    hosted = template.get("app")
    if not isinstance(hosted, dict):
        return
    if not isinstance(hosted.get("origin"), str):
        raise ManifestError("manifest_template_invalid", "a manifest template names the hosted app.origin")
    origin = settings.public_origin.rstrip("/")
    if origin == hosted["origin"].rstrip("/") or is_loopback_host(urlsplit(origin).hostname or ""):
        return
    if settings.app_id == hosted.get("id"):
        prefix = settings.model_config.get("env_prefix", "")
        raise ValueError(
            f"{prefix}APP_ID is the hosted app id {hosted['id']!r} but {prefix}PUBLIC_ORIGIN is not the "
            "hosted origin; set the deployment's own app_id"
        )


def _catalog_bytes(manifest: Manifest, variant_bytes: bytes) -> bytes:
    """The manifest catalog listing ``variant_bytes`` as the app's version 2 variant."""
    return canonical_bytes({
        "catalog_version": 1,
        "app_id": manifest.app_id,
        "variants": [{
            "manifest_version": 2,
            "url": MANIFEST_V2_PATH,
            "digest": "sha256:" + hashlib.sha256(variant_bytes).hexdigest(),
        }],
    })


def _template(segments: Sequence[str]) -> tuple[str, ...]:
    return tuple("{}" if is_placeholder(segment) else segment for segment in segments)


def mount_manifest_routes(app: FastAPI, *, runtime: NaappRuntime) -> None:
    """Serve the runtime's ``manifest_bytes`` verbatim, for an app with or
    without the docs surface.

    A version 1 manifest is served at the RFC 8615 well-known path the
    dispatcher and gateway fetch. A version 2 manifest is discovered through
    its catalog (``catalog_bytes``), which lists the bytes served at the
    variant path; no version 1 copy is served, so the legacy well-known path
    is not found. Either way the bare path the docs surface links serves the
    manifest itself.
    """
    manifest_bytes = runtime.manifest_bytes
    catalog_bytes = runtime.catalog_bytes

    async def _manifest_response() -> Response:
        return Response(
            content=manifest_bytes,
            media_type="application/json",
            headers=_NOSNIFF,
        )

    if catalog_bytes is None:
        @app.get(LEGACY_MANIFEST_PATH)
        async def well_known_manifest_route() -> Response:
            return await _manifest_response()
    else:
        @app.get(CATALOG_PATH)
        async def manifest_catalog_route() -> Response:
            return Response(content=catalog_bytes, media_type="application/json", headers=_NOSNIFF)

        @app.get(MANIFEST_V2_PATH)
        async def manifest_v2_route() -> Response:
            return await _manifest_response()

    @app.get("/aweb-app.json")
    async def aweb_app_manifest_route() -> Response:
        return await _manifest_response()


def mount_naapp_routes(
    app: FastAPI,
    *,
    runtime: NaappRuntime,
    skills: Skills,
    landing: Callable[[], Awaitable[str]],
    reference_html: str,
    llms_txt: str,
    og_card_png: bytes,
    fonts_dir: Path,
    robots_disallow: Sequence[str] = (),
    noindex_paths: Sequence[str] = (),
    health_checks: Mapping[str, HealthCheck] | None = None,
) -> None:
    """Serve the standard naapp public surface.

    ``fonts_dir`` holds the app's copies of the fonts the stylesheet loads
    (``FONT_NAMES``); only those names are served, and a directory missing one
    is refused here.

    The landing page, robots rules and noindex paths are the app's: ``landing``
    renders the front door on each request, ``robots_disallow`` lists the paths
    crawlers must skip, and every response under ``noindex_paths`` (found or
    not) carries ``X-Robots-Tag``. The manifest routes serve the runtime's
    ``manifest_bytes`` verbatim, as :func:`mount_manifest_routes` does. The
    health routes check the runtime's dependencies plus the app's own
    ``health_checks``.
    """
    settings = runtime.settings
    noindex_prefixes = tuple(noindex_paths)

    if noindex_prefixes:

        @app.middleware("http")
        async def noindex(
            request: Request, call_next: Callable[[Request], Awaitable[Response]]
        ) -> Response:
            response = await call_next(request)
            if request.url.path.startswith(noindex_prefixes):
                response.headers["X-Robots-Tag"] = NOINDEX_ROBOTS_HEADER
            return response

    @app.get("/", response_class=HTMLResponse)
    async def landing_route() -> HTMLResponse:
        return HTMLResponse(await landing())

    def _aweb_css_response(immutable: bool) -> Response:
        # The fingerprinted URL is content-addressed, so it can be cached forever;
        # the legacy /css/aweb.css keeps a short TTL.
        cache = "public, max-age=31536000, immutable" if immutable else "public, max-age=3600"
        return Response(
            content=aweb_css(),
            media_type="text/css",
            headers={**_NOSNIFF, "Cache-Control": cache},
        )

    @app.get("/css/aweb.css")
    async def aweb_css_route() -> Response:
        return _aweb_css_response(immutable=False)

    @app.get("/css/aweb.{fingerprint}.css")
    async def aweb_css_fingerprinted_route(fingerprint: str) -> Response:
        return _aweb_css_response(immutable=True)

    fonts = {name: (fonts_dir / name).read_bytes() for name in sorted(FONT_NAMES)}

    @app.get("/fonts/{font_name}")
    async def font_route(font_name: str) -> Response:
        font = fonts.get(font_name)
        if font is None:
            raise HTTPException(status_code=404, detail="Font not found")
        return Response(
            content=font,
            media_type="font/woff2",
            headers={**_NOSNIFF, "Cache-Control": "public, max-age=31536000, immutable"},
        )

    @app.get("/og-card.png")
    async def og_card_route() -> Response:
        return Response(
            content=og_card_png,
            media_type="image/png",
            headers={"Cache-Control": "public, max-age=86400"},
        )

    @app.get("/reference", response_class=HTMLResponse)
    async def reference_route() -> HTMLResponse:
        return HTMLResponse(reference_html)

    @app.get("/llms.txt", response_class=PlainTextResponse)
    async def llms_route() -> PlainTextResponse:
        return PlainTextResponse(llms_txt, headers=_NOSNIFF)

    @app.get("/robots.txt", response_class=PlainTextResponse)
    async def robots_route() -> PlainTextResponse:
        return PlainTextResponse(robots_txt(robots_disallow), headers=_NOSNIFF)

    @app.get("/skills/", response_class=PlainTextResponse)
    async def skills_index_route() -> PlainTextResponse:
        return PlainTextResponse(skills.index(), headers=_NOSNIFF)

    @app.get("/skills/{skill_name}/SKILL.md", response_class=PlainTextResponse)
    async def skill_route(skill_name: str) -> PlainTextResponse:
        skill = skills.read(skill_name)
        if skill is None:
            raise HTTPException(status_code=404, detail="Skill not found")
        return PlainTextResponse(skill, headers=_NOSNIFF)

    mount_manifest_routes(app, runtime=runtime)
    mount_health(app, settings, checks={**runtime.health_checks(), **(health_checks or {})})
