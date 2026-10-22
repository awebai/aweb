"""Folio's thin member and read-only capability adapters over shared stores."""

import hashlib
import json
from datetime import UTC, datetime, timedelta
from importlib.resources import files
from typing import Annotated
from urllib.parse import urlsplit

import httpx
from aweb_naapp.page_store import Scope, StoreError, principal_id
from aweb_naapp.pages import validate_page
from aweb_naapp.pages.render import page_shell
from aweb_naapp.runtime.app import NaappRuntime
from aweb_naapp.runtime.app_credentials import APP_GRANT_READ, AppCredentialSigner
from aweb_naapp.runtime.app_keys import load_app_key
from aweb_naapp.runtime.authorization import Authorization, GrantUnavailable
from aweb_naapp.runtime.capability_links import (
    LinkCreator,
    LinkRefused,
    LinkScope,
    Readable,
    authenticate,
    exchange,
    load_link_creator,
    mint,
    read,
    revoke,
)
from aweb_naapp.runtime.capability_links.routes import LINK_RESPONSE_HEADERS, refusal_response
from aweb_naapp.runtime.installation import InstallationFence, InstallationRefused
from aweb_naapp.runtime.team_auth import MembershipProof, raw_request_target
from aweb_naapp.runtime.team_grants import AppIdentity, TeamGrantSource
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

from folio.collection_documents import collection_scope, find_collection_document
from folio.record_collections import TABLE_WIDGET_ID
from folio.record_link_responses import link_http_refusal
from folio.record_models import (
    CollectionDefineRequest,
    RecordAddRequest,
    RecordDeleteRequest,
    RecordQueryRequest,
    RecordUpdateRequest,
)
from folio.record_service import RecordService
from folio.record_storage import RecordStorage


def now() -> datetime:
    return datetime.now(UTC)


def store_http(error: StoreError | InstallationRefused) -> HTTPException:
    return HTTPException(error.status, detail={"code": error.code})


class CollectionAuthority:
    """N5 receives canonical store identity only after its shared proof gate."""

    def __init__(self, host, scope=None):
        self.host = host
        self.scope = scope

    async def require_current_creator(self, tx, *, creator, proof):
        checked = Scope(creator.scope.installation_id, creator.scope.team_id,
                        self.host.runtime.manifest.app_id, creator.scope.page_id)
        if self.scope is not None and self.scope != checked:
            raise LinkRefused("action_denied", 403)
        # N5 has already checked the in-process proof under its link lock.
        # No network or second identity lookup is allowed in this callback.
        self.scope = checked

    async def readable(self, tx, *, creator, page_id, collection, link_mode, record_ids):
        if self.scope is None or self.scope.page_id != page_id:
            raise LinkRefused("action_denied", 403)
        metadata = await self.host.storage.require_store().collection_access_on(
            tx, self.scope, creator_id=creator, collection=collection,
            link_mode=link_mode, record_ids=record_ids,
        )
        if metadata is None:
            return None
        ids = metadata["record_ids"]
        return Readable(None if ids is None else tuple(ids), frozenset(metadata["fields"]))

    async def can_read_asset(self, tx, **context):
        return False  # Collection tables mint no assets or actions.

    async def action_kind(self, tx, **context):
        return None

    async def can_act(self, tx, **context):
        return False

    async def is_team_agent(self, tx, **context):
        return False


class RecordHost:
    def __init__(
        self, runtime: NaappRuntime, storage: RecordStorage, *,
        team_server_transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.runtime, self.storage = runtime, storage
        self.settings = runtime.settings
        self.grants = TeamGrantSource(
            identity=AppIdentity(app_id=runtime.manifest.app_id,
                                 origin=runtime.manifest.document["app"]["origin"],
                                 digest="sha256:" + hashlib.sha256(runtime.manifest_bytes).hexdigest()),
            signer=AppCredentialSigner(app_id=runtime.manifest.app_id,
                                      key=load_app_key(self.settings, runtime.manifest, APP_GRANT_READ),
                                      purpose=APP_GRANT_READ),
            discovery=runtime.team_server_directory(), transport=team_server_transport,
        )

        async def policy(request, principal, tool):
            # Record-level and field-level authority is decided inside PageStore.
            return tool.name in {"collection-define", "record-add", "record-update", "record-delete",
                                 "record-query", "list", "present", "revoke"}

        self.guard = runtime.authorized(grants=self.grants, policy=policy)

    def fence(self) -> InstallationFence:
        return InstallationFence(self.runtime.db(), app_id=self.runtime.manifest.app_id, grants=self.grants)

    def service(self) -> RecordService:
        return RecordService(self.storage.require_store())

    async def member_operation(self, authorization, method, payload):
        try:
            async with self.runtime.db().transaction() as tx:
                admitted = await self.fence().admit(tx, authorization.grant)
                service = self.service()
                if method == "define_on":
                    scope = collection_scope(admitted, payload.collection_id)
                    return await service.define_on(tx, admitted, authorization.principal, payload,
                                                   owner_id=principal_id(authorization.principal, scope))
                return await getattr(service, method)(tx, admitted, authorization.principal, payload)
        except (StoreError, InstallationRefused) as error:
            raise store_http(error) from None

    async def documents(self, authorization):
        if self.settings.page_deletion_database_url is None:
            return []  # Legacy documents remain usable; no structured data is disclosed.
        try:
            async with self.runtime.db().transaction() as tx:
                admitted = await self.fence().admit(tx, authorization.grant)
                return await self.service().list_documents_on(tx, admitted, authorization.principal)
        except (StoreError, InstallationRefused) as error:
            raise store_http(error) from None

    async def present(self, authorization, payload):
        try:
            async with self.runtime.db().transaction() as tx:
                admitted = await self.fence().admit(tx, authorization.grant)
                entry = await find_collection_document(tx, admitted, slug=payload.slug)
                if entry is None:
                    return None
                if payload.editable or payload.version is not None:
                    raise HTTPException(422, detail={"code": "read_only_table"})
                scope = collection_scope(admitted, entry["collection_id"])
                owner = principal_id(authorization.principal, scope)
                store = self.storage.require_store()
                metadata = await store.collection_access_on(
                    tx, scope, creator_id=owner, collection=entry["collection_id"], link_mode="live",
                )
                if metadata is None:
                    raise HTTPException(404, detail={"code": "resource_not_found"})
                # Dashboard clicks mint a short-lived read-only self-view.
                ttl = min(payload.ttl_seconds or 900, 900, self.settings.max_present_ttl_seconds)
                link = await mint(
                    tx, CollectionAuthority(self, scope),
                    scope=LinkScope(scope.team_id, scope.installation_id, scope.page_id),
                    creator=owner, creator_certificate_id=authorization.principal.certificate_id,
                    creator_team_did_key=authorization.principal.team_did_key,
                    request={"mode": "live", "page_rev": None,
                             "projection": {"collections": [{"collection": entry["collection_id"],
                                                              "record_ids": "*", "fields": metadata["fields"]}],
                                            "assets": []},
                             "actions": [], "intent_sponsor_did": None, "one_use": False,
                             "expires_at": (now() + timedelta(seconds=ttl)).strftime("%Y-%m-%dT%H:%M:%SZ")},
                    now=now(),
                )
                return {"token": link.link_id, "expires_at": link.expires_at,
                        "url": self.settings.public_origin.rstrip("/") + "/present/links/" + link.link_id + "#k=" + link.secret}
        except (StoreError, InstallationRefused) as error:
            raise store_http(error) from None

    async def revoke(self, authorization, link_id):
        try:
            creator = await load_link_creator(self.runtime.db(), link_id=link_id)
            if creator.scope.team_id != authorization.principal.team_id:
                raise HTTPException(404, detail={"code": "link_unavailable"})
            scope = Scope(creator.scope.installation_id, creator.scope.team_id,
                          self.runtime.manifest.app_id, creator.scope.page_id)
            # Management is independent of the mint creator's later membership loss.
            async with self.runtime.db().transaction() as tx:
                await revoke(tx, scope=creator.scope, link_id=link_id,
                             actor=principal_id(authorization.principal, scope), is_owner=False, now=now())
        except LinkRefused as error:
            raise HTTPException(error.status, detail={"code": error.code}) from None

    async def membership(self, creator: LinkCreator) -> MembershipProof:
        return await self.runtime.check_current_member(
            creator.scope.team_id, certificate_id=creator.certificate_id, team_did_key=creator.team_did_key,
        )

    async def holder(self, request, link_id):
        caller = await authenticate(
            self.runtime.db(), authorization=request.headers.get("Authorization"),
            signed_payload=request.headers.get("X-AWEB-Signed-Payload"), method=request.method,
            target=raw_request_target(request), body=await request.body(), origin=request.headers.get("Origin"),
            csrf=request.headers.get("X-AWEB-CSRF"), app_origin=self.settings.public_origin, now=now(),
        )
        if caller.link_id != link_id:
            raise LinkRefused("action_denied", 403)
        creator = await load_link_creator(self.runtime.db(), link_id=link_id)
        proof = await self.membership(creator)  # Remote checks precede any joined tx.
        try:
            grant = await self.grants.grant_for(creator.scope.team_id)
        except GrantUnavailable:
            raise HTTPException(503, detail={"code": "authority_unavailable"}) from None
        if grant is None or "folio:read" not in grant.scopes:
            raise HTTPException(403, detail={"code": "scope_denied"})
        admitted = self.fence().for_admission(grant).admitted
        if admitted.installation_id != creator.scope.installation_id:
            raise LinkRefused("action_denied", 403)
        return caller, creator, proof, grant

    async def holder_read(self, request, link_id, *, query=False):
        caller, creator, proof, grant = await self.holder(request, link_id)
        scope = Scope(creator.scope.installation_id, creator.scope.team_id,
                      self.runtime.manifest.app_id, creator.scope.page_id)
        async with self.runtime.db().transaction() as tx:
            # Lock order is installation fence -> link -> page; everything local.
            await self.fence().admit(tx, grant)
            checked = await read(tx, CollectionAuthority(self, scope), caller=caller,
                                 page_id=scope.page_id, now=now(), proof=proof)
            store = self.storage.require_store()
            if request.method == "POST":
                raise LinkRefused("action_denied", 403)  # No table action is minted.
            if checked.mode == "pinned":
                if query:
                    raise LinkRefused("action_denied", 403)
                return await store.project_link_snapshot_on(
                    tx, scope, creator_id=checked.creator, projection=checked.projection,
                    allowed_action_ids=[], source_snapshot=checked.source_snapshot,
                    expected_page_rev=checked.page_rev,
                )
            entries = checked.projection["collections"]
            if query:
                try:
                    raw = request.query_params.get("bind", "{}")
                    if len(raw) > 16384:
                        raise ValueError
                    bind = json.loads(raw)
                    revision = int(request.query_params["snapshot_rev"])
                except (ValueError, KeyError):
                    raise HTTPException(422, detail={"code": "schema_invalid"}) from None
            else:
                bind = {"collection": entries[0]["collection"], "limit": 50} if entries else None
                revision = None
            result = None
            if bind is not None:
                result = await store.query_widget_on(
                    tx, scope, creator_id=checked.creator, widget_id=TABLE_WIDGET_ID, bind=bind,
                    link_id=caller.link_id, expected_page_rev=revision, projection=checked.projection,
                )
            if query:
                return result
            projection = {"collections": [{**entry, "record_ids": [r["id"] for r in result["records"]]}
                                           for entry in entries], "assets": []}
            # Capture only the already authorized first page's named IDs. This
            # returns the stored/redacted layout and schema; the live wildcard
            # never enters a bounded snapshot API or becomes a frozen link.
            page = await store.capture_link_snapshot_on(
                tx, scope, creator_id=checked.creator, projection=projection, allowed_action_ids=[],
                expected_page_rev=result["page_rev"] if result else None,
            )
            if not validate_page(page).valid:
                raise StoreError("schema_invalid")
            return page

    def mount(self, app: FastAPI) -> None:
        guard = self.guard

        @app.post("/v1/collections")
        async def define(payload: CollectionDefineRequest, authorization: Annotated[Authorization, Depends(guard)]):
            return await self.member_operation(authorization, "define_on", payload)

        @app.post("/v1/records/add")
        async def add(payload: RecordAddRequest, authorization: Annotated[Authorization, Depends(guard)]):
            return await self.member_operation(authorization, "add_on", payload)

        @app.post("/v1/records/update")
        async def update(payload: RecordUpdateRequest, authorization: Annotated[Authorization, Depends(guard)]):
            return await self.member_operation(authorization, "update_on", payload)

        @app.post("/v1/records/delete")
        async def delete(payload: RecordDeleteRequest, authorization: Annotated[Authorization, Depends(guard)]):
            return await self.member_operation(authorization, "delete_on", payload)

        @app.post("/v1/records/query")
        async def query(payload: RecordQueryRequest, authorization: Annotated[Authorization, Depends(guard)]):
            return await self.member_operation(authorization, "query_on", payload)

        # Fixed packaged routes precede Folio's legacy /assets/{asset_id} route.
        @app.get("/assets/page-renderer.js", include_in_schema=False)
        async def renderer_js():
            return Response(files("aweb_naapp.pages").joinpath("assets/page-renderer.js").read_bytes(), media_type="text/javascript")

        @app.get("/assets/page-link-client.js", include_in_schema=False)
        async def client_js():
            return Response(files("aweb_naapp.pages").joinpath("assets/page-link-client.js").read_bytes(), media_type="text/javascript")

        @app.get("/assets/page-renderer.css", include_in_schema=False)
        async def renderer_css():
            return Response(files("aweb_naapp.pages").joinpath("assets/page-renderer.css").read_bytes(), media_type="text/css")

        @app.get("/assets/folio-record-table.mjs", include_in_schema=False)
        async def host_js():
            return Response(files("folio").joinpath("assets/record-table-host.mjs").read_bytes(), media_type="text/javascript")

        @app.get("/present/links/{link_id}", include_in_schema=False)
        async def table_shell(link_id: str):
            # Table links grant no media; use the configured HTTPS asset ceiling
            # even for loopback HTTP development. No request chooses this origin.
            origin = urlsplit(self.settings.public_origin)
            shell = page_shell(script_path="/assets/folio-record-table.mjs", asset_origin="https://" + origin.netloc)
            return HTMLResponse(shell.html, headers={**shell.headers, "X-Robots-Tag": "noindex, nofollow, noarchive"})

        @app.post("/v1/links/{link_id}/session", include_in_schema=False)
        async def session(link_id: str, request: Request):
            try:
                result = await exchange(
                    self.runtime.db(), CollectionAuthority(self), link_id=link_id, body=await request.body(),
                    client=request.client.host if request.client else "unknown", now=now(),
                    check_current_member=self.membership,
                )
                return JSONResponse({"session_id": result.session_id, "csrf_token": result.csrf_token,
                                     "expires_at": result.expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                     "link": dict(result.link)}, headers=LINK_RESPONSE_HEADERS)
            except LinkRefused as error:
                return refusal_response(error)
            except HTTPException as error:
                return link_http_refusal(error)
            except (StoreError, InstallationRefused) as error:
                return link_http_refusal(store_http(error))

        async def view(link_id: str, request: Request):
            try:
                result = await self.holder_read(request, link_id, query=request.url.path.endswith("/query"))
                return JSONResponse(result, headers=LINK_RESPONSE_HEADERS)
            except LinkRefused as error:
                return refusal_response(error)
            except HTTPException as error:
                return link_http_refusal(error)
            except (StoreError, InstallationRefused) as error:
                return link_http_refusal(store_http(error))

        app.add_api_route("/v1/links/{link_id}/page", view, methods=["GET"], include_in_schema=False)
        app.add_api_route("/v1/links/{link_id}/query", view, methods=["GET"], include_in_schema=False)
        app.add_api_route("/v1/links/{link_id}/admit", view, methods=["POST"], include_in_schema=False)
