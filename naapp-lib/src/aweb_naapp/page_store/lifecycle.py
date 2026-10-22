"""Portable exports and durable, resumable erasure with application-owned hooks.

Hooks are trusted app adapters, never caller-supplied objects. Calls are
idempotent by job_id, report non-content evidence only, and must reconcile any
already-dispatched external work. This module cannot declare another owner's
assets, backups, tasks, capabilities or effects erased without its receipt.
"""

from __future__ import annotations

import copy
import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from aweb_naapp.idempotency import expire_keys
from aweb_naapp.page_store.models import Access, RetentionPolicy, StoreError
from aweb_naapp.page_store.support import canonical, decoded, identity, validated, widgets


@dataclass(frozen=True)
class Coverage:
    complete: bool
    details: dict[str, Any]


@dataclass(frozen=True)
class ExternalArchive:
    # App adapter supplies only artifacts accessible to the exporter. No keys,
    # bearer links or live capabilities. Binary assets use base64 plus checksum.
    artifacts: dict[str, Any]
    unresolved_references: list[dict[str, str]]


class LifecycleHooks:
    async def export(self, scope, principal) -> ExternalArchive:
        raise NotImplementedError

    async def revoke(self, scope, job_id: str) -> Coverage:
        """Revoke links, invalidate approvals and cancel undispatched requests."""
        raise NotImplementedError

    async def purge(self, scope, job_id: str) -> Coverage:
        """Assets/caches/search, retained tasks and dispatched-effect reconciliation."""
        raise NotImplementedError

    async def backup_status(self, scope, job_id: str) -> Coverage:
        """Encrypted backup expiry and asset-provider deletion evidence."""
        raise NotImplementedError


class LifecycleMixin:
    async def _lifecycle_grant(self, scope, principal, operation):
        identity(principal, scope)
        return self.lifecycle_authorizer is not None and await self.lifecycle_authorizer(
            scope, principal, operation
        )

    async def export_page(self, scope, principal):
        actor = identity(principal, scope)
        await self._fence(scope)
        async with self.db.transaction() as tx:
            # Hold a single revision cut through current data and all histories.
            row = await tx.fetch_one(
                "SELECT document,access,deleted,retention_policy FROM {{tables.pages}} WHERE scope=$1 FOR UPDATE",
                scope.key,
            )
            if row is None or row["deleted"]:
                raise StoreError("resource_not_found", 404)
            access = Access.from_dict(decoded(row["access"]))
            if actor != access.owner and not await self._lifecycle_grant(
                scope, principal, "export"
            ):
                raise StoreError("action_denied", 403)
            document = decoded(row["document"])
            resource_policy = decoded(row["retention_policy"])
            full_records = {}
            for collection in document["collections"]:
                full_records[collection["id"]] = [
                    {
                        **r,
                        "value": {
                            f: v
                            for f, v in r["value"].items()
                            if f in access.value_fields(actor, collection, r["value"])
                        },
                    }
                    for r in await self._records(tx, scope, collection["id"])
                    if access.visible_row(actor, collection["id"], r["id"])
                ]
            snapshot = await self._project(tx, scope, copy.deepcopy(document), access, actor)
            layouts = []
            for row in await tx.fetch_all(
                "SELECT version,snapshot FROM {{tables.page_layout_context}} WHERE scope=$1 ORDER BY version",
                scope.key,
            ):
                historical = self._redact_snapshot(decoded(row["snapshot"]), access, actor)
                layouts.append(
                    {
                        "version": row["version"],
                        "layout": historical["layout"],
                        "snapshot": historical,
                    }
                )
            schemas = []
            for row in await tx.fetch_all(
                "SELECT collection,version,definition FROM {{tables.page_schemas}} WHERE scope=$1 ORDER BY collection,version",
                scope.key,
            ):
                definition = decoded(row["definition"])
                definition["schema"] = access.redact_schema(actor, definition)
                schemas.append(definition)
            visible = {cid: {r["id"] for r in records} for cid, records in full_records.items()}
            audit = []
            for row in await tx.fetch_all(
                "SELECT transaction_id,old_rev,new_rev,evidence,changed,created_at FROM {{tables.page_audit}} WHERE scope=$1 ORDER BY new_rev",
                scope.key,
            ):
                changes = []
                for change in decoded(row["changed"]):
                    if isinstance(change, dict) and "collection" in change:
                        cid = change["collection"]
                        if change["record_id"] not in visible.get(cid, set()):
                            continue
                        definition = next(c for c in document["collections"] if c["id"] == cid)
                        change["fields"] = sorted(
                            set(change["fields"]) & access.visible_fields(actor, definition)
                        )
                    changes.append(change)
                audit.append(
                    {
                        "transaction_id": str(row["transaction_id"]),
                        "old_rev": row["old_rev"],
                        "new_rev": row["new_rev"],
                        "evidence": decoded(row["evidence"]),
                        "changed": changes,
                        "server_time": row["created_at"].isoformat(),
                    }
                )
            external = (
                await self.lifecycle.export(scope, principal)
                if self.lifecycle
                else ExternalArchive({}, [])
            )
            # No adapter means nothing can be claimed about external holdings.
            unresolved = (
                external.unresolved_references
                if self.lifecycle
                else [{"kind": "application_inventory", "reason": "adapter_unconfigured"}]
            )
            content = {
                "snapshot": snapshot,
                "records": full_records,
                "layouts": layouts,
                "schemas": schemas,
                "audit": audit,
                "artifacts": external.artifacts,
            }
            imported = await tx.fetch_value(
                "SELECT history FROM {{tables.page_import_history}} WHERE scope=$1", scope.key
            )
            if imported is not None and actor == access.owner:
                content["imported_history"] = decoded(imported)
            manifest = {
                "format": "aweb.page-export/1",
                "page_format": "aweb.page/1",
                "scope": scope.key,
                "revision_cut": document["rev"],
                "layout_version": document["layout_version"],
                "policy": resource_policy,
                "principal_refs": [access.owner],
                "unresolved_references": unresolved,
                "artifact_checksums": {
                    name: hashlib.sha256(canonical(value).encode()).hexdigest()
                    for name, value in external.artifacts.items()
                },
                "sha256": hashlib.sha256(canonical(content).encode()).hexdigest(),
            }
            await self._fence(scope)
            return {"manifest": manifest, "content": content}

    async def export_installation(self, scope, principal):
        if not await self._lifecycle_grant(scope, principal, "export_installation"):
            raise StoreError("action_denied", 403)
        # Scope prefix binds installation/team/app; the host must grant every
        # page's export independently, and its row/field restrictions still apply.
        rows = await self.db.fetch_all(
            "SELECT scope FROM {{tables.pages}} WHERE scope[1:3]=$1 AND NOT deleted ORDER BY scope",
            scope.key[:3],
        )
        from aweb_naapp.page_store.models import Scope

        return {
            "format": "aweb.installation-export/1",
            "pages": [await self.export_page(Scope(*r["scope"]), principal) for r in rows],
        }

    async def import_page(self, scope, principal, *, archive, access, acl_mapping, key):
        self._policy()
        manifest, content = archive.get("manifest", {}), archive.get("content", {})
        if (
            manifest.get("format") != "aweb.page-export/1"
            or manifest.get("sha256") != hashlib.sha256(canonical(content).encode()).hexdigest()
        ):
            raise StoreError("archive_checksum_invalid")
        if (
            any(ref not in acl_mapping for ref in manifest.get("principal_refs", []))
            or acl_mapping.get(content["snapshot"]["owner"]) != access.owner
        ):
            raise StoreError("acl_mapping_required")
        document = copy.deepcopy(content["snapshot"])
        # Import is a new resource. Historical evidence remains data, never live
        # task/approval/capability/execution authority. Backups use start(), not import.
        document.update(
            page_id=scope.page_id, owner=access.owner, rev=1, layout_version=1, widget_state={}
        )
        for widget in widgets(document["layout"]):
            if widget["type"] == "decision_card":
                wid = widget["id"]
                widget.clear()
                widget.update(
                    id=wid,
                    type="imported_decision",
                    props={},
                    fallback="Historical decision; create a new request to act.",
                )
        all_records = content["records"]
        for collection in document["collections"]:
            collection["records"] = all_records.get(collection["id"], [])[:200]
            for record in all_records.get(collection["id"], []):
                self._validate_record(scope, document, collection, record)
        validated(document)
        # Validate all archived definitions too, before activation. They cannot
        # reinterpret imported values or create active effects.
        for definition in content["schemas"]:
            probe = {
                **document,
                "layout": [],
                "actions": [],
                "widget_state": {},
                "collections": [{**definition, "records": []}],
            }
            validated(probe)
        for layout in content["layouts"]:
            validated(layout["snapshot"])
        # All rows and immutable imported history share the creation transaction.
        async with self.db.transaction() as tx:
            receipt = await self._create(
                tx,
                scope,
                principal,
                document,
                access=access,
                key=key,
                request_context=hashlib.sha256(canonical(archive).encode()).hexdigest(),
            )
            if not await tx.fetch_value(
                "SELECT 1 FROM {{tables.page_import_history}} WHERE scope=$1", scope.key
            ):
                for collection in document["collections"]:
                    for record in all_records.get(collection["id"], [])[200:]:
                        await self._put_record(tx, scope, collection["id"], record)
                await tx.execute(
                    "INSERT INTO {{tables.page_import_history}} VALUES($1,$2::jsonb)",
                    scope.key,
                    canonical({"unverified_import": content, "source_manifest": manifest}),
                )
            return receipt

    async def request_delete(self, scope, principal, *, expected_rev, key):
        actor = identity(principal, scope)
        if not isinstance(key, str) or not key:
            raise StoreError("precondition_required", 428)
        request_hash = hashlib.sha256(
            canonical({"scope": scope.key, "op": "delete", "expected_rev": expected_rev}).encode()
        ).hexdigest()
        existing = await self.ledger.fetch_one(
            "SELECT requester,receipt FROM {{tables.page_deletions}} WHERE scope=$1", scope.key
        )
        if existing is not None:
            if existing["requester"] != actor and not await self._lifecycle_grant(
                scope, principal, "delete"
            ):
                raise StoreError("resource_not_found", 404)
            receipt = decoded(existing["receipt"])
            if receipt["request_hash"] != request_hash or receipt["request_key"][-1] != key:
                raise StoreError("idempotency_conflict", 409)
            policy = receipt["policy"]
            if policy and datetime.now(UTC) >= datetime.fromisoformat(
                receipt["requested_at"]
            ) + timedelta(days=policy["retry_horizon_days"]):
                raise StoreError("idempotency_expired", 410)
            return receipt["request_receipt"]
        if not self._ready:
            raise StoreError("restore_not_ready", 503)
        async with self.db.transaction() as tx:
            row = await tx.fetch_one(
                "SELECT document,access,deleted,retention_policy FROM {{tables.pages}} WHERE scope=$1 FOR UPDATE",
                scope.key,
            )
            if row is not None and row["deleted"]:
                return await self.request_delete(
                    scope, principal, expected_rev=expected_rev, key=key
                )
            if row is None:
                raise StoreError("resource_not_found", 404)
            access = Access.from_dict(decoded(row["access"]))
            if actor != access.owner and not await self._lifecycle_grant(
                scope, principal, "delete"
            ):
                raise StoreError("resource_not_found", 404)
            document = decoded(row["document"])
            self._precondition(document, expected_rev)
            if document["rev"] == 2**53 - 1:
                raise StoreError("revision_exhausted", 409)
            resource_policy = decoded(row["retention_policy"])
            if resource_policy is None:
                raise StoreError("retention_policy_required", 503)
            transaction, _ = await self._claim(
                tx,
                scope,
                principal,
                key,
                {"op": "delete", "expected_rev": expected_rev},
                retention=RetentionPolicy(**resource_policy),
            )
            job_id = str(transaction)
            now = datetime.now(UTC)
            # Deletion stays available without a configured collection policy;
            # missing deadlines are disclosed and prevent a completion claim.
            policy = resource_policy
            receipt = {
                "job_id": job_id,
                "state": "requested",
                "tombstone_rev": document["rev"] + 1,
                "requested_at": now.isoformat(),
                "policy": policy,
                "retention_deadline": (
                    now + timedelta(days=policy["backup_expiry_days"])
                ).isoformat(),
                "coverage": {},
                "remaining": [
                    "application_revocation",
                    "primary_content",
                    "application_purge",
                    "backups",
                ],
                "legal_exceptions": policy["legal_exceptions"],
            }
            stored = {
                **receipt,
                "request_hash": request_hash,
                "request_key": [scope.installation_id, scope.team_id, actor, key],
                "request_receipt": copy.deepcopy(receipt),
            }
            inserted = await self.ledger.fetch_value(
                "INSERT INTO {{tables.page_deletions}} (scope,job_id,tombstone_rev,requester,state,receipt) VALUES($1,$2,$3,$4,'requested',$5::jsonb) ON CONFLICT(scope) DO NOTHING RETURNING job_id",
                scope.key,
                UUID(job_id),
                receipt["tombstone_rev"],
                actor,
                canonical(stored),
            )
            if inserted is None:
                # Another request can only win after it passed current authority.
                raise StoreError("idempotency_conflict", 409)
            await self._purge_content_in(tx, scope, receipt["tombstone_rev"])
            return receipt

    async def deletion_status(self, scope, principal):
        actor = identity(principal, scope)
        row = await self.ledger.fetch_one(
            "SELECT requester,receipt FROM {{tables.page_deletions}} WHERE scope=$1", scope.key
        )
        if row is None or (
            row["requester"] != actor
            and not await self._lifecycle_grant(scope, principal, "status")
        ):
            raise StoreError("resource_not_found", 404)
        return self._public_deletion(decoded(row["receipt"]))

    @staticmethod
    def _public_deletion(receipt):
        return {
            k: v
            for k, v in receipt.items()
            if k not in {"request_hash", "request_key", "request_receipt"}
        }

    async def advance_delete(self, scope):
        """Trusted worker entry point. Repeating a job never rearms external work."""
        async with self.ledger.transaction() as ledger_tx:
            row = await ledger_tx.fetch_one(
                "SELECT job_id,tombstone_rev,receipt FROM {{tables.page_deletions}} WHERE scope=$1 FOR UPDATE",
                scope.key,
            )
            if row is None:
                raise StoreError("resource_not_found", 404)
            receipt = decoded(row["receipt"])
            if receipt["state"] == "complete":
                return self._public_deletion(receipt)
            job_id = str(row["job_id"])
            await self._purge_content(scope, row["tombstone_rev"])
            receipt["coverage"]["primary_content"] = {
                "erased": True,
                "tombstone_rev": row["tombstone_rev"],
            }
            if "application_revocation" not in receipt["coverage"]:
                if self.lifecycle is None:
                    receipt["remaining"] = ["application_revocation"]
                else:
                    revoked = await self.lifecycle.revoke(scope, job_id)
                    if revoked.complete:
                        receipt["coverage"]["application_revocation"] = revoked.details
                        receipt["state"] = "access_revoked"
            if "application_revocation" in receipt["coverage"]:
                await self._purge_content(scope, row["tombstone_rev"])
                receipt["coverage"]["primary_content"] = {
                    "erased": True,
                    "tombstone_rev": row["tombstone_rev"],
                }
                receipt["state"] = "purging"
                for name, hook in (
                    ("application_purge", self.lifecycle.purge),
                    ("backups", self.lifecycle.backup_status),
                ):
                    outcome = await hook(scope, job_id)
                    receipt["coverage"][name] = {**outcome.details, "complete": outcome.complete}
                receipt["remaining"] = [
                    name
                    for name in ("application_purge", "backups")
                    if not receipt["coverage"][name]["complete"]
                ]
                if receipt["policy"] is None:
                    receipt["remaining"].append("retention_policy_required")
                if receipt["legal_exceptions"]:
                    receipt["remaining"].append("legal_retention")
                if not receipt["remaining"]:
                    receipt["state"] = "complete"
            await ledger_tx.execute(
                "UPDATE {{tables.page_deletions}} SET state=$2,receipt=$3::jsonb WHERE scope=$1",
                scope.key,
                receipt["state"],
                canonical(receipt),
            )
            return self._public_deletion(receipt)

    async def enforce_retention(self):
        """Erase expired audit content and key payloads; jobs keep visible coverage."""
        policy = self._policy()
        await self.db.execute(
            "UPDATE {{tables.page_audit}} SET evidence='{}'::jsonb,changed='[]'::jsonb WHERE created_at < NOW()-$1::interval",
            timedelta(days=policy.audit_content_days),
        )
        await self.db.execute("DELETE FROM {{tables.page_cursors}} WHERE expires_at<=NOW()")
        await expire_keys(self.db)
        await expire_keys(self.ledger)
