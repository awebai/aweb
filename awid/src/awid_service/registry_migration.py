"""Internal, DB-credential operator protocol for registry cutovers."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from awid.did import validate_did
from awid.external_authority import canonical_protocol_domain
from awid.log import canonical_server_origin
from awid.registry_migration import (
    CanonicalOverlapPayload,
    DNSAuthorizationPayload,
    DestinationCompletePayload,
    OverlapObservationPayload,
    make_receipt,
    parse_receipt,
    receipt_payload_bytes,
)
from awid.delegation import parse_delegation_assertion
from awid.signing import canonical_json_bytes
from awid_service.delegation_state import stored_delegation_chain


class RegistryMigrationError(RuntimeError):
    pass


@dataclass(frozen=True)
class MigrationArtifact:
    payload: dict[str, Any]
    snapshot_digest: str

    def as_dict(self) -> dict[str, Any]:
        return {"payload": self.payload, "snapshot_digest": self.snapshot_digest}


_KIND_TABLE = {
    "did": "did_aw_mappings",
    "did_log": "did_aw_log",
    "namespace": "dns_namespaces",
    "address": "public_addresses",
    "replacement": "replacement_announcements",
    "team": "teams",
    "certificate": "team_certificates",
    "encryption_key": "identity_encryption_keys",
    "a2a_delegation": "a2a_bridge_delegations",
    "a2a_publication": "a2a_route_publications",
    "delegation_head": "namespace_delegation_heads",
    "delegation_entry": "namespace_delegation_entries",
    "delegation_signature": "namespace_delegation_signatures",
}
_IMPORT_ORDER = tuple(_KIND_TABLE)
_DELETE_ORDER = tuple(reversed(_IMPORT_ORDER))
_SEMANTIC_PROJECTION_VERSION = "awid.registry-migration-semantic-projection.v1"


class RegistryMigrationService:
    def __init__(self, db, *, verify_domain=None, public_origin: str | None = None) -> None:
        self.db = db
        self.verify_domain = verify_domain
        self.public_origin = (
            None if public_origin is None else canonical_server_origin(public_origin)
        )

    async def registry_id(self) -> str:
        value = await self.db.fetch_value(
            "SELECT registry_instance_id FROM {{tables.registry_state}} WHERE singleton = TRUE"
        )
        return str(value)

    @staticmethod
    def _digest(value: object) -> str:
        return "sha256:" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()

    @classmethod
    def _validate_artifact_payload(
        cls, payload: dict[str, Any], snapshot_digest: str
    ) -> None:
        digest_re = re.compile(r"^sha256:[0-9a-f]{64}$")
        for field in ("source_registry_id", "destination_registry_id", "cutover_id"):
            try:
                parsed = uuid.UUID(payload[field])
            except (KeyError, TypeError, ValueError) as exc:
                raise RegistryMigrationError(f"invalid canonical artifact {field}") from exc
            if str(parsed) != payload[field]:
                raise RegistryMigrationError(f"invalid canonical artifact {field}")
        try:
            canonical_root = canonical_protocol_domain(payload["root_domain"])
        except Exception as exc:
            raise RegistryMigrationError("invalid canonical artifact root_domain") from exc
        if canonical_root != payload["root_domain"]:
            raise RegistryMigrationError("invalid canonical artifact root_domain")
        generation = payload.get("source_generation")
        if isinstance(generation, bool) or not isinstance(generation, int) or generation < 0:
            raise RegistryMigrationError("invalid artifact source_generation")
        for field, value in (
            ("snapshot_digest", snapshot_digest),
            ("manifest_digest", payload.get("manifest_digest")),
        ):
            if not isinstance(value, str) or not digest_re.fullmatch(value):
                raise RegistryMigrationError(f"invalid artifact {field}")
        for field in ("expected_source_origin", "expected_destination_origin"):
            value = payload.get(field)
            try:
                canonical = canonical_server_origin(value)
            except Exception as exc:
                raise RegistryMigrationError(f"invalid artifact {field}") from exc
            if canonical != value:
                raise RegistryMigrationError(f"invalid artifact {field}")
        evidence = payload.get("old_selection_evidence")
        evidence_keys = {
            "dns_name", "old_registry_origin", "controller_did", "ttl_seconds",
            "authority_answer_digest", "observed_at", "evidence_hash",
        }
        if not isinstance(evidence, dict) or set(evidence) != evidence_keys:
            raise RegistryMigrationError("invalid old_selection_evidence fields")
        try:
            dns_domain = canonical_protocol_domain(
                evidence["dns_name"].removeprefix("_awid.")
            )
        except Exception as exc:
            raise RegistryMigrationError("invalid old selection DNS name") from exc
        if evidence["dns_name"] != "_awid." + dns_domain:
            raise RegistryMigrationError("invalid old selection DNS name")
        try:
            canonical_old_origin = canonical_server_origin(
                evidence["old_registry_origin"]
            )
        except Exception as exc:
            raise RegistryMigrationError("invalid old selection origin") from exc
        if canonical_old_origin != evidence["old_registry_origin"]:
            raise RegistryMigrationError("invalid old selection origin")
        if payload["expected_source_origin"] != evidence["old_registry_origin"]:
            raise RegistryMigrationError(
                "old selection origin differs from expected source origin"
            )
        if not validate_did(evidence["controller_did"]):
            raise RegistryMigrationError("invalid old selection controller")
        ttl = evidence["ttl_seconds"]
        if isinstance(ttl, bool) or not isinstance(ttl, int) or ttl <= 0:
            raise RegistryMigrationError("invalid old selection TTL")
        if (
            not isinstance(evidence["authority_answer_digest"], str)
            or not digest_re.fullmatch(evidence["authority_answer_digest"])
        ):
            raise RegistryMigrationError("invalid old selection answer digest")
        expected_answer_digest = cls._digest({
            "controller_did": evidence["controller_did"],
            "dns_name": evidence["dns_name"],
            "registry_origin": evidence["old_registry_origin"],
        })
        if evidence["authority_answer_digest"] != expected_answer_digest:
            raise RegistryMigrationError("old selection answer digest mismatch")
        timestamp = evidence["observed_at"]
        if (
            not isinstance(timestamp, str)
            or not re.fullmatch(
                r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z",
                timestamp,
            )
        ):
            raise RegistryMigrationError("invalid old selection observed_at")
        try:
            datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError as exc:
            raise RegistryMigrationError("invalid old selection observed_at") from exc
        evidence_payload = {
            key: value for key, value in evidence.items() if key != "evidence_hash"
        }
        if (
            not isinstance(evidence["evidence_hash"], str)
            or not digest_re.fullmatch(evidence["evidence_hash"])
            or evidence["evidence_hash"] != cls._digest(evidence_payload)
        ):
            raise RegistryMigrationError("old selection evidence hash mismatch")
        for item in payload["items"]:
            try:
                derived_key = cls._row_key(item["kind"], item["row"])
            except (KeyError, TypeError, ValueError) as exc:
                raise RegistryMigrationError(
                    f"invalid deterministic item key for {item.get('kind')}"
                ) from exc
            if item["key"] != derived_key:
                raise RegistryMigrationError(
                    f"artifact item key mismatch for {item['kind']}:{item['key']}"
                )

    @staticmethod
    def _semantic_row(row: dict[str, Any]) -> dict[str, Any]:
        return {
            key: value
            for key, value in row.items()
            if key not in {
                "state_source_registry_id",
                "state_cutover_id",
                "state_generation",
            }
        }

    @classmethod
    def _semantic_projection(
        cls, kind: str, key: str, row: dict[str, Any]
    ) -> dict[str, Any]:
        return {
            "version": _SEMANTIC_PROJECTION_VERSION,
            "kind": kind,
            "key": key,
            "row": cls._semantic_row(row),
        }

    @staticmethod
    def _row_key(kind: str, row: dict[str, Any]) -> str:
        if kind == "did":
            return row["did_aw"]
        if kind == "did_log":
            return f"{row['did_aw']}:{row['seq']}"
        if kind == "namespace":
            return row["namespace_id"]
        if kind == "address":
            return row["address_id"]
        if kind == "replacement":
            return row["announcement_id"]
        if kind == "team":
            return row["team_uuid"]
        if kind == "certificate":
            return row["id"]
        if kind == "encryption_key":
            return f"{row['did_aw']}:{row['encryption_key_id']}"
        if kind == "a2a_delegation":
            return row["delegation_id"]
        if kind == "a2a_publication":
            return row["assertion_id"]
        if kind == "delegation_head":
            return row["child_domain"]
        if kind == "delegation_entry":
            return f"{row['child_domain']}:{row['sequence']}"
        if kind == "delegation_signature":
            return f"{row['child_domain']}:{row['sequence']}:{row['controller_did']}"
        raise RegistryMigrationError(f"unknown migration item kind: {kind}")

    @staticmethod
    def _key_predicate(kind: str, key: str, *, start: int = 1):
        def marker(offset: int) -> str:
            return f"${start + offset}"

        if kind == "did":
            return f"did_aw={marker(0)}", (key,)
        if kind == "did_log":
            did_aw, seq = key.rsplit(":", 1)
            return f"did_aw={marker(0)} AND seq={marker(1)}", (did_aw, int(seq))
        if kind == "namespace":
            return f"namespace_id={marker(0)}::uuid", (key,)
        if kind == "address":
            return f"address_id={marker(0)}::uuid", (key,)
        if kind == "replacement":
            return f"announcement_id={marker(0)}::uuid", (key,)
        if kind == "team":
            return f"team_uuid={marker(0)}::uuid", (key,)
        if kind == "certificate":
            return f"id={marker(0)}::uuid", (key,)
        if kind == "encryption_key":
            did_aw, digest = key.rsplit(":sha256:", 1)
            return (
                f"did_aw={marker(0)} AND encryption_key_id={marker(1)}",
                (did_aw, "sha256:" + digest),
            )
        if kind == "a2a_delegation":
            return f"delegation_id={marker(0)}", (key,)
        if kind == "a2a_publication":
            return f"assertion_id={marker(0)}", (key,)
        if kind == "delegation_head":
            return f"child_domain={marker(0)}", (key,)
        if kind == "delegation_entry":
            child_domain, sequence = key.rsplit(":", 1)
            return (
                f"child_domain={marker(0)} AND sequence={marker(1)}",
                (child_domain, int(sequence)),
            )
        if kind == "delegation_signature":
            child_domain, sequence, controller_did = key.split(":", 2)
            return (
                f"child_domain={marker(0)} AND sequence={marker(1)} "
                f"AND controller_did={marker(2)}",
                (child_domain, int(sequence), controller_did),
            )
        raise RegistryMigrationError(f"unknown migration item kind: {kind}")

    async def _actual_rows_by_kind(
        self, tx, item_keys, *, for_update: bool = False
    ) -> dict[tuple[str, str], dict[str, Any]]:
        values: dict[tuple[str, str], dict[str, Any]] = {}
        for kind, key in sorted(item_keys, key=lambda value: (_IMPORT_ORDER.index(value[0]), value[1])):
            table = _KIND_TABLE[kind]
            predicate, args = self._key_predicate(kind, key)
            suffix = " FOR UPDATE" if for_update else ""
            value = await tx.fetch_one(
                f"SELECT to_jsonb(t)::text AS data FROM {{{{tables.{table}}}}} t WHERE {predicate}{suffix}",
                *args,
            )
            if value is not None:
                values[(kind, key)] = json.loads(value["data"])
        return values

    async def _verify_source_authority(self, db, domain: str, authority) -> None:
        row = await db.fetch_one(
            """
            SELECT controller_did FROM {{tables.dns_namespaces}}
            WHERE domain=$1 ORDER BY (deleted_at IS NULL) DESC,created_at DESC LIMIT 1
            """,
            domain,
        )
        if row is None:
            raise RegistryMigrationError("migration root namespace is absent")
        authority_domain = authority.dns_name.removeprefix("_awid.").rstrip(".").lower()
        if authority.inherited:
            chain = await stored_delegation_chain(db, domain)
            if not chain:
                raise RegistryMigrationError("inherited migration root has no stored delegation chain")
            first = parse_delegation_assertion(chain[0])
            authority_row = await db.fetch_one(
                """
                SELECT controller_did FROM {{tables.dns_namespaces}}
                WHERE domain=$1 AND deleted_at IS NULL AND verification_status='verified'
                """,
                authority_domain,
            )
            authority_signature = any(
                signature.controller_did == authority.controller_did
                for signature in first.signatures
            )
            if first.payload.operation == "revoke":
                authority_signature = bool(
                    await db.fetch_value(
                        """
                        SELECT EXISTS(
                            SELECT 1 FROM {{tables.namespace_delegation_entries}} e
                            JOIN {{tables.namespace_delegation_signatures}} s
                              ON s.child_domain=e.child_domain AND s.sequence=e.sequence
                            WHERE e.child_domain=$1 AND e.parent_domain=$2
                              AND e.operation IN ('delegate','rotate')
                              AND s.controller_did=$3
                        )
                        """,
                        domain,
                        authority_domain,
                        authority.controller_did,
                    )
                )
            if (
                first.payload.parent_domain != authority_domain
                or authority_row is None
                or authority_row["controller_did"] != authority.controller_did
                or not authority_signature
            ):
                raise RegistryMigrationError(
                    "stored delegation suffix does not terminate at live DNS authority"
                )
        elif row["controller_did"] != authority.controller_did:
            raise RegistryMigrationError(
                "exact-DNS migration root controller differs from registry row"
            )

    async def _lock_cutover_admission(
        self, tx, *, role: str, root_domain: str, cutover_id: str
    ) -> None:
        await tx.fetch_value(
            "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
            "namespace-authority-admission",
        )
        rollover = await tx.fetch_one(
            """
            SELECT rollover_id,parent_domain
            FROM {{tables.namespace_controller_rollovers}}
            WHERE state NOT IN ('completed','canceled')
              AND (parent_domain=$1 OR parent_domain LIKE ('%.' || $1)
                   OR $1 LIKE ('%.' || parent_domain))
            LIMIT 1
            """,
            root_domain,
        )
        if rollover is not None:
            raise RegistryMigrationError(
                f"active controller rollover intersects cutover root: {rollover['rollover_id']} ({rollover['parent_domain']})"
            )
        # One role-wide admission lock makes the overlap query itself race-free;
        # the query then applies the narrower stable subtree invariant.
        await tx.fetch_value(
            "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
            "registry-cutover-admission",
        )
        conflict = await tx.fetch_one(
            """
            SELECT cutover_id,root_domain
            FROM {{tables.registry_migration_cutovers}}
            WHERE state NOT IN ('completed','canceled')
              AND (cutover_id <> $2::uuid OR role <> $1)
              AND (
                root_domain=$3 OR root_domain LIKE ('%.' || $3)
                OR $3 LIKE ('%.' || root_domain)
              )
            LIMIT 1
            """,
            role,
            cutover_id,
            root_domain,
        )
        if conflict is not None:
            raise RegistryMigrationError(
                f"active overlapping {role} cutover conflict: {conflict['cutover_id']} ({conflict['root_domain']})"
            )

    async def _cohort_rows(self, tx, root_domain: str) -> list[dict[str, Any]]:
        suffix = "%." + root_domain
        queries = [
            (
                "namespace",
                "SELECT namespace_id::text AS key, to_jsonb(t)::text AS data FROM {{tables.dns_namespaces}} t WHERE domain = $1 OR domain LIKE $2",
                (root_domain, suffix),
            ),
            (
                "address",
                """SELECT t.address_id::text AS key, to_jsonb(t)::text AS data
                   FROM {{tables.public_addresses}} t JOIN {{tables.dns_namespaces}} n ON n.namespace_id=t.namespace_id
                   WHERE n.domain=$1 OR n.domain LIKE $2""",
                (root_domain, suffix),
            ),
            (
                "did",
                """SELECT t.did_aw AS key, to_jsonb(t)::text AS data FROM {{tables.did_aw_mappings}} t
                   WHERE t.did_aw IN (SELECT DISTINCT a.did_aw FROM {{tables.public_addresses}} a JOIN {{tables.dns_namespaces}} n ON n.namespace_id=a.namespace_id WHERE n.domain=$1 OR n.domain LIKE $2)""",
                (root_domain, suffix),
            ),
            (
                "did_log",
                """SELECT t.did_aw || ':' || t.seq::text AS key, to_jsonb(t)::text AS data FROM {{tables.did_aw_log}} t
                   WHERE t.did_aw IN (SELECT DISTINCT a.did_aw FROM {{tables.public_addresses}} a JOIN {{tables.dns_namespaces}} n ON n.namespace_id=a.namespace_id WHERE n.domain=$1 OR n.domain LIKE $2)""",
                (root_domain, suffix),
            ),
            (
                "encryption_key",
                """SELECT t.did_aw || ':' || t.encryption_key_id AS key, to_jsonb(t)::text AS data FROM {{tables.identity_encryption_keys}} t
                   WHERE t.did_aw IN (SELECT DISTINCT a.did_aw FROM {{tables.public_addresses}} a JOIN {{tables.dns_namespaces}} n ON n.namespace_id=a.namespace_id WHERE n.domain=$1 OR n.domain LIKE $2)""",
                (root_domain, suffix),
            ),
            (
                "replacement",
                """SELECT t.announcement_id::text AS key, to_jsonb(t)::text AS data FROM {{tables.replacement_announcements}} t
                   JOIN {{tables.dns_namespaces}} n ON n.namespace_id=t.namespace_id WHERE n.domain=$1 OR n.domain LIKE $2""",
                (root_domain, suffix),
            ),
            (
                "team",
                "SELECT t.team_uuid::text AS key, to_jsonb(t)::text AS data FROM {{tables.teams}} t WHERE domain=$1 OR domain LIKE $2",
                (root_domain, suffix),
            ),
            (
                "certificate",
                """SELECT t.id::text AS key, to_jsonb(t)::text AS data FROM {{tables.team_certificates}} t
                   JOIN {{tables.teams}} team ON team.team_uuid=t.team_uuid WHERE team.domain=$1 OR team.domain LIKE $2""",
                (root_domain, suffix),
            ),
            (
                "a2a_delegation",
                "SELECT t.delegation_id AS key, to_jsonb(t)::text AS data FROM {{tables.a2a_bridge_delegations}} t WHERE split_part(address,'/',1)=$1 OR split_part(address,'/',1) LIKE $2",
                (root_domain, suffix),
            ),
            (
                "a2a_publication",
                "SELECT t.assertion_id AS key, to_jsonb(t)::text AS data FROM {{tables.a2a_route_publications}} t WHERE split_part(address,'/',1)=$1 OR split_part(address,'/',1) LIKE $2",
                (root_domain, suffix),
            ),
            (
                "delegation_head",
                "SELECT t.child_domain AS key, to_jsonb(t)::text AS data FROM {{tables.namespace_delegation_heads}} t WHERE child_domain=$1 OR child_domain LIKE $2",
                (root_domain, suffix),
            ),
            (
                "delegation_entry",
                "SELECT t.child_domain || ':' || t.sequence::text AS key, to_jsonb(t)::text AS data FROM {{tables.namespace_delegation_entries}} t WHERE child_domain=$1 OR child_domain LIKE $2",
                (root_domain, suffix),
            ),
            (
                "delegation_signature",
                "SELECT t.child_domain || ':' || t.sequence::text || ':' || t.controller_did AS key, to_jsonb(t)::text AS data FROM {{tables.namespace_delegation_signatures}} t WHERE child_domain=$1 OR child_domain LIKE $2",
                (root_domain, suffix),
            ),
        ]
        items: list[dict[str, Any]] = []
        for kind, query, args in queries:
            for row in await tx.fetch_all(query, *args):
                items.append({"kind": kind, "key": row["key"], "row": json.loads(row["data"])})

        # Add only the delegation records needed to prove a delegated root to
        # its persisted direct/dormant root. Ancestor namespace rows and their
        # unrelated state are deliberately not migrated.
        current = root_domain
        visited: set[str] = set()
        while current not in visited:
            visited.add(current)
            namespace = await tx.fetch_one(
                """
                SELECT controller_did,active_delegation_hash,deleted_at
                FROM {{tables.dns_namespaces}}
                WHERE domain=$1
                ORDER BY created_at DESC LIMIT 1
                """,
                current,
            )
            if namespace is None:
                break
            head = await tx.fetch_one(
                """
                SELECT * FROM {{tables.namespace_delegation_heads}}
                WHERE child_domain=$1
                """,
                current,
            )
            if namespace["deleted_at"] is not None and current == root_domain:
                if head is None or head["head_operation"] != "revoke":
                    raise RegistryMigrationError("deleted migration root lacks its revocation tombstone")
            elif namespace["active_delegation_hash"] is None:
                break
            elif (
                head is None
                or head["head_operation"] == "revoke"
                or head["head_hash"] != namespace["active_delegation_hash"]
                or head["head_controller_did"] != namespace["controller_did"]
            ):
                raise RegistryMigrationError("delegated migration root suffix is inconsistent")
            extra_queries = [
                (
                    "delegation_head",
                    "SELECT child_domain AS key,to_jsonb(t)::text AS data FROM {{tables.namespace_delegation_heads}} t WHERE child_domain=$1",
                ),
                (
                    "delegation_entry",
                    "SELECT child_domain || ':' || sequence::text AS key,to_jsonb(t)::text AS data FROM {{tables.namespace_delegation_entries}} t WHERE child_domain=$1",
                ),
                (
                    "delegation_signature",
                    "SELECT child_domain || ':' || sequence::text || ':' || controller_did AS key,to_jsonb(t)::text AS data FROM {{tables.namespace_delegation_signatures}} t WHERE child_domain=$1",
                ),
            ]
            existing_keys = {(item["kind"], item["key"]) for item in items}
            for kind, query in extra_queries:
                for row in await tx.fetch_all(query, current):
                    if (kind, row["key"]) not in existing_keys:
                        items.append({"kind": kind, "key": row["key"], "row": json.loads(row["data"])})
            current = head["parent_domain"]
        return sorted(items, key=lambda item: (_IMPORT_ORDER.index(item["kind"]), item["key"]))

    async def prepare(
        self,
        *,
        root_domain: str,
        destination_registry_id: str,
        cutover_id: str | None = None,
        expected_source_origin: str | None = None,
        expected_destination_origin: str | None = None,
    ) -> MigrationArtifact:
        root_domain = canonical_protocol_domain(root_domain)
        if expected_source_origin is not None:
            expected_source_origin = canonical_server_origin(expected_source_origin)
        if expected_destination_origin is not None:
            expected_destination_origin = canonical_server_origin(
                expected_destination_origin
            )
        cutover_id = cutover_id or str(uuid.uuid4())
        if self.verify_domain is None:
            raise RegistryMigrationError("live DNS verifier is required for source prepare")
        if expected_source_origin is None:
            raise RegistryMigrationError("expected source registry origin is required")
        if expected_destination_origin is None:
            raise RegistryMigrationError("expected destination registry origin is required")
        async with self.db.transaction() as tx:
            await tx.execute("SET LOCAL TIME ZONE 'UTC'")
            await self._lock_cutover_admission(
                tx, role="source", root_domain=root_domain, cutover_id=cutover_id
            )
            # Lock cohort tables before registry_state. Existing writers finish
            # before the snapshot; later writers resume only after the fence is
            # committed and therefore observe it in their trigger snapshot.
            await tx.execute(
                """
                LOCK TABLE {{tables.did_aw_mappings}},{{tables.did_aw_log}},
                    {{tables.dns_namespaces}},{{tables.public_addresses}},
                    {{tables.replacement_announcements}},{{tables.teams}},
                    {{tables.team_certificates}},{{tables.identity_encryption_keys}},
                    {{tables.a2a_bridge_delegations}},{{tables.a2a_route_publications}},
                    {{tables.namespace_delegation_heads}},
                    {{tables.namespace_delegation_entries}},
                    {{tables.namespace_delegation_signatures}}
                IN SHARE MODE
                """
            )
            state = await tx.fetch_one(
                "SELECT registry_instance_id,current_generation FROM {{tables.registry_state}} WHERE singleton=TRUE FOR UPDATE"
            )
            source_registry_id = str(state["registry_instance_id"])
            existing = await tx.fetch_one(
                "SELECT * FROM {{tables.registry_migration_cutovers}} WHERE cutover_id=$1::uuid AND role='source' FOR UPDATE",
                cutover_id,
            )
            if existing is not None:
                if (
                    str(existing["source_registry_id"]) != source_registry_id
                    or str(existing["destination_registry_id"]) != destination_registry_id
                    or existing["root_domain"] != root_domain
                    or existing["expected_destination_origin"]
                    != expected_destination_origin
                    or existing["state"] not in {"frozen", "dns_authorized", "overlap", "completed"}
                ):
                    raise RegistryMigrationError("conflicting source cutover retry")
                items = await self._cohort_rows(tx, root_domain)
                for item in items:
                    item["row"]["state_source_registry_id"] = source_registry_id
                    item["row"]["state_cutover_id"] = cutover_id
                    item["row"]["state_generation"] = existing["source_generation"]
                stored_evidence = self._json_value(existing["old_selection_evidence"])
                if (
                    stored_evidence is None
                    or stored_evidence.get("old_registry_origin")
                    != expected_source_origin
                ):
                    raise RegistryMigrationError(
                        "conflicting source cutover retry expected origin"
                    )
                payload = {
                    "version": "awid.registry-migration.v1",
                    "source_registry_id": source_registry_id,
                    "destination_registry_id": destination_registry_id,
                    "cutover_id": cutover_id,
                    "root_domain": root_domain,
                    "source_generation": existing["source_generation"],
                    "manifest_digest": self._digest(items),
                    "old_selection_evidence": stored_evidence,
                    "expected_source_origin": (
                        None if stored_evidence is None else stored_evidence.get("old_registry_origin")
                    ),
                    "expected_destination_origin": existing[
                        "expected_destination_origin"
                    ],
                    "items": items,
                }
                snapshot_digest = self._digest(payload)
                if (
                    payload["manifest_digest"] != existing["manifest_digest"]
                    or snapshot_digest != existing["snapshot_digest"]
                ):
                    raise RegistryMigrationError("frozen source cohort readback changed")
                return MigrationArtifact(payload, snapshot_digest)
            authority = await self.verify_domain(root_domain)
            if authority.registry_url != expected_source_origin:
                raise RegistryMigrationError(
                    "live DNS no longer selects the expected source registry"
                )
            if (
                authority.authoritative_ttl_seconds is None
                or authority.authoritative_ttl_seconds <= 0
            ):
                raise RegistryMigrationError(
                    "authoritative old registry-selection DNS TTL is unavailable"
                )
            authority_projection = {
                "controller_did": authority.controller_did,
                "dns_name": authority.dns_name,
                "registry_origin": authority.registry_url,
            }
            evidence_payload = {
                "dns_name": authority.dns_name,
                "old_registry_origin": authority.registry_url,
                "controller_did": authority.controller_did,
                "ttl_seconds": authority.authoritative_ttl_seconds,
                "authority_answer_digest": self._digest(authority_projection),
                "observed_at": datetime.now(timezone.utc)
                .isoformat()
                .replace("+00:00", "Z"),
            }
            old_selection_evidence = {
                **evidence_payload,
                "evidence_hash": self._digest(evidence_payload),
            }
            await self._verify_source_authority(tx, root_domain, authority)
            await tx.execute(
                """INSERT INTO {{tables.registry_migration_cutovers}}
                   (cutover_id,role,source_registry_id,destination_registry_id,
                    expected_destination_origin,root_domain,source_generation,
                    snapshot_digest,manifest_digest,state,old_selection_evidence)
                   VALUES ($1::uuid,'source',$2::uuid,$3::uuid,$4,$5,$6,$7,$7,'preparing',$8::jsonb)""",
                cutover_id,
                source_registry_id,
                destination_registry_id,
                expected_destination_origin,
                root_domain,
                state["current_generation"],
                "sha256:" + "0" * 64,
                None if old_selection_evidence is None else json.dumps(old_selection_evidence),
            )
            items = await self._cohort_rows(tx, root_domain)
            for item in items:
                item["row"]["state_source_registry_id"] = source_registry_id
                item["row"]["state_cutover_id"] = cutover_id
                item["row"]["state_generation"] = state["current_generation"]
            manifest_digest = self._digest(items)
            payload = {
                "version": "awid.registry-migration.v1",
                "source_registry_id": source_registry_id,
                "destination_registry_id": destination_registry_id,
                "cutover_id": cutover_id,
                "root_domain": root_domain,
                "source_generation": state["current_generation"],
                "manifest_digest": manifest_digest,
                "old_selection_evidence": old_selection_evidence,
                "expected_source_origin": expected_source_origin,
                "expected_destination_origin": expected_destination_origin,
                "items": items,
            }
            snapshot_digest = self._digest(payload)
            for item in items:
                await tx.execute(
                    """INSERT INTO {{tables.registry_migration_items}}
                       (cutover_id,role,kind,item_key,content_digest,source_registry_id,source_generation)
                       VALUES ($1::uuid,'source',$2,$3,$4,$5::uuid,$6)""",
                    cutover_id,
                    item["kind"],
                    item["key"],
                    self._digest(item),
                    source_registry_id,
                    state["current_generation"],
                )
            await tx.execute(
                """UPDATE {{tables.registry_migration_cutovers}}
                   SET snapshot_digest=$2,manifest_digest=$3,state='frozen',updated_at=NOW()
                   WHERE cutover_id=$1::uuid AND role='source'""",
                cutover_id,
                snapshot_digest,
                manifest_digest,
            )
            return MigrationArtifact(payload, snapshot_digest)

    async def import_artifact(self, artifact_value: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(artifact_value, dict):
            raise RegistryMigrationError("migration artifact must be an object")
        if set(artifact_value) != {"payload", "snapshot_digest"}:
            raise RegistryMigrationError("invalid migration artifact fields")
        payload = artifact_value["payload"]
        if not isinstance(payload, dict):
            raise RegistryMigrationError("migration artifact payload must be an object")
        if set(payload) != {
            "version", "source_registry_id", "destination_registry_id", "cutover_id",
            "root_domain", "source_generation", "manifest_digest",
            "old_selection_evidence", "expected_source_origin",
            "expected_destination_origin", "items",
        }:
            raise RegistryMigrationError("invalid migration artifact payload fields")
        if not isinstance(payload.get("items"), list):
            raise RegistryMigrationError("migration artifact items must be a list")
        item_keys = []
        for item in payload["items"]:
            if not isinstance(item, dict) or set(item) != {"kind", "key", "row"}:
                raise RegistryMigrationError("invalid migration artifact item fields")
            if item["kind"] not in _KIND_TABLE or not isinstance(item["key"], str) or not isinstance(item["row"], dict):
                raise RegistryMigrationError("invalid migration artifact item")
            item_keys.append((item["kind"], item["key"]))
        if len(item_keys) != len(set(item_keys)):
            raise RegistryMigrationError("duplicate migration artifact item")
        self._validate_artifact_payload(payload, artifact_value["snapshot_digest"])
        if self._digest(payload) != artifact_value["snapshot_digest"]:
            raise RegistryMigrationError("migration artifact snapshot digest mismatch")
        if payload.get("version") != "awid.registry-migration.v1":
            raise RegistryMigrationError("unsupported migration artifact version")
        if self.public_origin is None:
            raise RegistryMigrationError("configured destination public origin is required")
        if payload["expected_destination_origin"] != self.public_origin:
            raise RegistryMigrationError("artifact expected destination origin mismatch")
        if self._digest(payload.get("items")) != payload.get("manifest_digest"):
            raise RegistryMigrationError("migration artifact manifest mismatch")
        async with self.db.transaction() as tx:
            await tx.execute("SET LOCAL TIME ZONE 'UTC'")
            await self._lock_cutover_admission(
                tx,
                role="destination",
                root_domain=payload["root_domain"],
                cutover_id=payload["cutover_id"],
            )
            await tx.fetch_value(
                "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                "registry-import:" + payload["cutover_id"],
            )
            await tx.execute(
                """
                LOCK TABLE {{tables.did_aw_mappings}},{{tables.did_aw_log}},
                    {{tables.dns_namespaces}},{{tables.public_addresses}},
                    {{tables.replacement_announcements}},{{tables.teams}},
                    {{tables.team_certificates}},{{tables.identity_encryption_keys}},
                    {{tables.a2a_bridge_delegations}},{{tables.a2a_route_publications}},
                    {{tables.namespace_delegation_heads}},
                    {{tables.namespace_delegation_entries}},
                    {{tables.namespace_delegation_signatures}}
                IN SHARE MODE
                """
            )
            state = await tx.fetch_one(
                "SELECT registry_instance_id FROM {{tables.registry_state}} WHERE singleton=TRUE FOR UPDATE"
            )
            if str(state["registry_instance_id"]) != payload["destination_registry_id"]:
                raise RegistryMigrationError("artifact destination registry id mismatch")
            existing = await tx.fetch_one(
                "SELECT state,snapshot_digest FROM {{tables.registry_migration_cutovers}} WHERE cutover_id=$1::uuid AND role='destination' FOR UPDATE",
                payload["cutover_id"],
            )
            if existing is not None:
                if (
                    existing["state"] in {"verified", "dns_authorized", "overlap", "completed"}
                    and existing["snapshot_digest"] == artifact_value["snapshot_digest"]
                ):
                    return await self.readback(payload["cutover_id"], tx=tx)
                raise RegistryMigrationError("conflicting destination cutover")
            actual_before = await self._actual_rows_by_kind(
                tx,
                [(item["kind"], item["key"]) for item in payload["items"]],
                for_update=True,
            )
            namespace_items = [
                item for item in payload["items"] if item["kind"] == "namespace"
            ]
            for item in namespace_items:
                active_same_domain = await tx.fetch_one(
                    """
                    SELECT namespace_id FROM {{tables.dns_namespaces}}
                    WHERE domain=$1 AND deleted_at IS NULL FOR UPDATE
                    """,
                    item["row"]["domain"],
                )
                if (
                    active_same_domain is not None
                    and str(active_same_domain["namespace_id"]) != item["key"]
                ):
                    raise RegistryMigrationError(
                        f"destination semantic conflict for namespace domain:{item['row']['domain']}"
                    )
            preflight = []
            for item in payload["items"]:
                key = (item["kind"], item["key"])
                existing_row = actual_before.get(key)
                semantic = self._semantic_row(item["row"])
                semantic_digest = self._digest(
                    self._semantic_projection(item["kind"], item["key"], item["row"])
                )
                owner_source = owner_cutover = owner_generation = None
                if existing_row is None:
                    disposition = "inserted"
                else:
                    if self._semantic_row(existing_row) != semantic:
                        raise RegistryMigrationError(
                            f"destination semantic conflict for {item['kind']}:{item['key']}"
                        )
                    disposition = "reused"
                    owner_source = existing_row.get("state_source_registry_id")
                    owner_cutover = existing_row.get("state_cutover_id")
                    owner_generation = existing_row.get("state_generation")
                    if owner_cutover is not None:
                        owner = await tx.fetch_one(
                            """
                            SELECT state FROM {{tables.registry_migration_cutovers}}
                            WHERE cutover_id=$1::uuid AND role='destination'
                              AND source_registry_id=$2::uuid AND source_generation=$3
                            """,
                            owner_cutover,
                            owner_source,
                            owner_generation,
                        )
                        if owner is None or owner["state"] not in {
                            "dns_authorized", "overlap", "completed"
                        }:
                            raise RegistryMigrationError(
                                f"shared imported dependency owner is still cancelable for {item['kind']}:{item['key']}"
                            )
                preflight.append(
                    {
                        "item": item,
                        "disposition": disposition,
                        "source_item_digest": self._digest(item),
                        "semantic_digest": semantic_digest,
                        "owner_source": owner_source,
                        "owner_cutover": owner_cutover,
                        "owner_generation": owner_generation,
                    }
                )
            await tx.execute(
                """INSERT INTO {{tables.registry_migration_cutovers}}
                   (cutover_id,role,source_registry_id,destination_registry_id,
                    expected_destination_origin,root_domain,source_generation,
                    snapshot_digest,manifest_digest,state,old_selection_evidence)
                   VALUES ($1::uuid,'destination',$2::uuid,$3::uuid,$4,$5,$6,$7,$8,'importing',$9::jsonb)""",
                payload["cutover_id"],
                payload["source_registry_id"],
                payload["destination_registry_id"],
                payload["expected_destination_origin"],
                payload["root_domain"],
                payload["source_generation"],
                artifact_value["snapshot_digest"],
                payload["manifest_digest"],
                None if payload.get("old_selection_evidence") is None else json.dumps(payload["old_selection_evidence"]),
            )
            for name, value in (
                ("awid.registry_import_mode", "true"),
                ("awid.registry_import_cutover_id", payload["cutover_id"]),
                ("awid.registry_import_source_registry_id", payload["source_registry_id"]),
                ("awid.registry_import_source_generation", str(payload["source_generation"])),
            ):
                await tx.fetch_value("SELECT set_config($1,$2,TRUE)", name, value)
            for decision in preflight:
                item = decision["item"]
                table = _KIND_TABLE[item["kind"]]
                if decision["disposition"] == "inserted":
                    await tx.execute(
                        f"INSERT INTO {{{{tables.{table}}}}} SELECT (jsonb_populate_record(NULL::{{{{tables.{table}}}}}, $1::jsonb)).*",
                        json.dumps(item["row"], separators=(",", ":")),
                    )
                await tx.execute(
                    """INSERT INTO {{tables.registry_migration_items}}
                       (cutover_id,role,kind,item_key,content_digest,source_item_digest,
                        semantic_digest,disposition,owner_source_registry_id,
                        owner_cutover_id,owner_generation,source_registry_id,
                        source_generation,imported)
                       VALUES ($1::uuid,'destination',$2,$3,$4,$4,$5,$6,$7,$8,$9,$10::uuid,$11,TRUE)""",
                    payload["cutover_id"], item["kind"], item["key"],
                    decision["source_item_digest"], decision["semantic_digest"],
                    decision["disposition"], decision["owner_source"],
                    decision["owner_cutover"], decision["owner_generation"],
                    payload["source_registry_id"], payload["source_generation"],
                )
            count = await tx.fetch_value(
                "SELECT COUNT(*) FROM {{tables.registry_migration_items}} WHERE cutover_id=$1::uuid AND role='destination' AND imported=TRUE",
                payload["cutover_id"],
            )
            if count != len(payload["items"]):
                raise RegistryMigrationError("destination readback item count mismatch")
            actual_after = await self._actual_rows_by_kind(
                tx, [(item["kind"], item["key"]) for item in payload["items"]]
            )
            for decision in preflight:
                item = decision["item"]
                actual = actual_after.get((item["kind"], item["key"]))
                if actual is None:
                    raise RegistryMigrationError("destination actual-table readback omitted an item")
                actual_digest = self._digest(
                    self._semantic_projection(item["kind"], item["key"], actual)
                )
                if actual_digest != decision["semantic_digest"]:
                    raise RegistryMigrationError("destination actual-table semantic readback mismatch")
            await tx.execute(
                "UPDATE {{tables.registry_migration_cutovers}} SET state='verified',updated_at=NOW() WHERE cutover_id=$1::uuid AND role='destination'",
                payload["cutover_id"],
            )
            return await self.readback(payload["cutover_id"], tx=tx)

    async def readback(self, cutover_id: str, *, tx=None) -> dict[str, Any]:
        if tx is None:
            async with self.db.transaction() as read_tx:
                await read_tx.execute("SET LOCAL TIME ZONE 'UTC'")
                return await self.readback(cutover_id, tx=read_tx)
        db = tx
        await db.execute("SET LOCAL TIME ZONE 'UTC'")
        row = await db.fetch_one(
            "SELECT * FROM {{tables.registry_migration_cutovers}} WHERE cutover_id=$1::uuid AND role='destination'",
            cutover_id,
        )
        if row is None:
            raise RegistryMigrationError("destination cutover not found")
        if row["state"] not in {"verified", "dns_authorized", "overlap", "completed"}:
            raise RegistryMigrationError("destination readback is unavailable in current state")
        item_rows = await db.fetch_all(
            """
            SELECT kind,item_key,source_item_digest,semantic_digest,disposition,
                   owner_source_registry_id,owner_cutover_id,owner_generation
            FROM {{tables.registry_migration_items}}
            WHERE cutover_id=$1::uuid AND role='destination'
            ORDER BY kind,item_key
            """,
            cutover_id,
        )
        actual = await self._actual_rows_by_kind(
            db, [(item["kind"], item["item_key"]) for item in item_rows]
        )
        counts: dict[str, dict[str, int]] = {}
        decisions = []
        for item in item_rows:
            row_value = actual.get((item["kind"], item["item_key"]))
            if row_value is None:
                raise RegistryMigrationError("destination actual-table readback omitted an item")
            semantic_digest = self._digest(
                self._semantic_projection(item["kind"], item["item_key"], row_value)
            )
            if semantic_digest != item["semantic_digest"]:
                raise RegistryMigrationError("destination actual-table semantic readback mismatch")
            counts.setdefault(item["kind"], {"inserted": 0, "reused": 0})[
                item["disposition"]
            ] += 1
            decisions.append({
                "kind": item["kind"], "key": item["item_key"],
                "source_item_digest": item["source_item_digest"],
                "semantic_digest": item["semantic_digest"],
                "disposition": item["disposition"],
                "owner_source_registry_id": (
                    None if item["owner_source_registry_id"] is None
                    else str(item["owner_source_registry_id"])
                ),
                "owner_cutover_id": (
                    None if item["owner_cutover_id"] is None
                    else str(item["owner_cutover_id"])
                ),
                "owner_generation": item["owner_generation"],
            })
        payload = {
            "version": "awid.registry-migration-readback.v1",
            "source_registry_id": str(row["source_registry_id"]),
            "destination_registry_id": str(row["destination_registry_id"]),
            "expected_destination_origin": row["expected_destination_origin"],
            "cutover_id": str(row["cutover_id"]),
            "source_generation": row["source_generation"],
            "snapshot_digest": row["snapshot_digest"],
            "manifest_digest": row["manifest_digest"],
            "destination_state": row["state"],
            "counts": counts,
            "semantic_manifest_digest": self._digest(decisions),
        }
        return {"payload": payload, "readback_hash": self._digest(payload)}

    async def status(self, cutover_id: str) -> dict[str, Any]:
        async with self.db.transaction() as tx:
            await tx.execute("SET LOCAL TIME ZONE 'UTC'")
            return await self._status(tx, cutover_id)

    async def _status(self, db, cutover_id: str) -> dict[str, Any]:
        rows = await db.fetch_all(
            """
            SELECT role,state,root_domain,source_registry_id,destination_registry_id,
                   expected_destination_origin,source_generation,snapshot_digest,
                   manifest_digest,complete_after,
                   cancel_digest,updated_at
            FROM {{tables.registry_migration_cutovers}}
            WHERE cutover_id=$1::uuid ORDER BY role
            """,
            cutover_id,
        )
        if not rows:
            raise RegistryMigrationError("cutover not found")
        result = []
        for row in rows:
            counts = await db.fetch_all(
                """
                SELECT kind,COALESCE(disposition,'source') AS disposition,
                       COUNT(*)::int AS count
                FROM {{tables.registry_migration_items}}
                WHERE cutover_id=$1::uuid AND role=$2
                GROUP BY kind,COALESCE(disposition,'source')
                ORDER BY kind,disposition
                """,
                cutover_id,
                row["role"],
            )
            result.append({
                "role": row["role"], "state": row["state"],
                "root_domain": row["root_domain"],
                "source_registry_id": str(row["source_registry_id"]),
                "destination_registry_id": str(row["destination_registry_id"]),
                "source_generation": row["source_generation"],
                "snapshot_digest": row["snapshot_digest"],
                "manifest_digest": row["manifest_digest"],
                "complete_after": (
                    None if row["complete_after"] is None
                    else row["complete_after"].astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
                ),
                "cancel_digest": row["cancel_digest"],
                "updated_at": row["updated_at"].astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
                "counts": [dict(value) for value in counts],
            })
        origins = {row["expected_destination_origin"] for row in rows}
        if len(origins) != 1:
            raise RegistryMigrationError("cutover roles disagree on destination origin")
        return {
            "cutover_id": cutover_id,
            "expected_destination_origin": origins.pop(),
            "roles": result,
        }

    async def cancel_destination(self, cutover_id: str) -> dict[str, Any]:
        async with self.db.transaction() as tx:
            await tx.execute(
                """
                LOCK TABLE {{tables.did_aw_mappings}},{{tables.did_aw_log}},
                    {{tables.dns_namespaces}},{{tables.public_addresses}},
                    {{tables.replacement_announcements}},{{tables.teams}},
                    {{tables.team_certificates}},{{tables.identity_encryption_keys}},
                    {{tables.a2a_bridge_delegations}},{{tables.a2a_route_publications}},
                    {{tables.namespace_delegation_heads}},
                    {{tables.namespace_delegation_entries}},
                    {{tables.namespace_delegation_signatures}},
                    {{tables.namespace_delegation_read_snapshots}},
                    {{tables.namespace_delegation_read_pages}}
                IN EXCLUSIVE MODE
                """
            )
            row = await tx.fetch_one(
                "SELECT * FROM {{tables.registry_migration_cutovers}} WHERE cutover_id=$1::uuid AND role='destination' FOR UPDATE",
                cutover_id,
            )
            if row is None:
                raise RegistryMigrationError("destination cutover not found")
            if row["state"] == "canceled":
                return {
                    "state": "canceled",
                    "counts": self._json_value(row["cancel_counts"]),
                    "cancel_digest": row["cancel_digest"],
                }
            if row["state"] not in {"importing", "verified"}:
                raise RegistryMigrationError("destination cutover can no longer be canceled")
            expected_inserted = {
                (item["kind"], item["item_key"])
                for item in await tx.fetch_all(
                    """
                    SELECT kind,item_key FROM {{tables.registry_migration_items}}
                    WHERE cutover_id=$1::uuid AND role='destination'
                      AND disposition='inserted'
                    """,
                    cutover_id,
                )
            }
            actual_provenance = set()
            for kind in _IMPORT_ORDER:
                table = _KIND_TABLE[kind]
                rows = await tx.fetch_all(
                    f"""SELECT to_jsonb(t)::text AS data
                        FROM {{{{tables.{table}}}}} t
                        WHERE state_source_registry_id=$1
                          AND state_cutover_id=$2
                          AND state_generation=$3""",
                    row["source_registry_id"],
                    row["cutover_id"],
                    row["source_generation"],
                )
                actual_provenance.update(
                    (kind, self._row_key(kind, json.loads(value["data"])))
                    for value in rows
                )
            if actual_provenance != expected_inserted:
                raise RegistryMigrationError(
                    "destination cancellation provenance cohort mismatch"
                )
            for name, value in (
                ("awid.cancel_cleanup_mode", "true"),
                ("awid.cancel_cleanup_cutover_id", str(row["cutover_id"])),
                ("awid.cancel_cleanup_source_registry_id", str(row["source_registry_id"])),
                ("awid.cancel_cleanup_source_generation", str(row["source_generation"])),
            ):
                await tx.fetch_value("SELECT set_config($1,$2,TRUE)", name, value)
            await tx.execute(
                """
                DELETE FROM {{tables.namespace_delegation_read_pages}} p
                USING {{tables.namespace_delegation_read_snapshots}} s
                WHERE p.snapshot_id=s.snapshot_id
                  AND s.child_domain IN (
                    SELECT item_key FROM {{tables.registry_migration_items}}
                    WHERE cutover_id=$1::uuid AND role='destination'
                      AND kind='delegation_head' AND disposition='inserted'
                  )
                """,
                cutover_id,
            )
            await tx.execute(
                """
                DELETE FROM {{tables.namespace_delegation_read_snapshots}}
                WHERE child_domain IN (
                    SELECT item_key FROM {{tables.registry_migration_items}}
                    WHERE cutover_id=$1::uuid AND role='destination'
                      AND kind='delegation_head' AND disposition='inserted'
                )
                """,
                cutover_id,
            )
            counts: dict[str, int] = {}
            for kind in _DELETE_ORDER:
                table = _KIND_TABLE[kind]
                inserted_items = await tx.fetch_all(
                    """
                    SELECT item_key FROM {{tables.registry_migration_items}}
                    WHERE cutover_id=$1::uuid AND role='destination'
                      AND kind=$2 AND disposition='inserted'
                    ORDER BY item_key
                    """,
                    cutover_id,
                    kind,
                )
                counts[kind] = 0
                for item in inserted_items:
                    predicate, key_args = self._key_predicate(kind, item["item_key"])
                    provenance_start = len(key_args) + 1
                    result = await tx.execute(
                        f"""DELETE FROM {{{{tables.{table}}}}}
                            WHERE {predicate}
                              AND state_source_registry_id=${provenance_start}
                              AND state_cutover_id=${provenance_start + 1}
                              AND state_generation=${provenance_start + 2}""",
                        *key_args,
                        row["source_registry_id"],
                        row["cutover_id"],
                        row["source_generation"],
                    )
                    counts[kind] += int(result.rsplit(" ", 1)[-1])
            digest = self._digest(counts)
            await tx.execute(
                "UPDATE {{tables.registry_migration_cutovers}} SET state='canceled',cancel_counts=$2::jsonb,cancel_digest=$3,updated_at=NOW() WHERE cutover_id=$1::uuid AND role='destination'",
                cutover_id, json.dumps(counts, sort_keys=True), digest,
            )
            return {"state": "canceled", "counts": counts, "cancel_digest": digest}

    async def cancel_source(self, cutover_id: str) -> dict[str, Any]:
        async with self.db.transaction() as tx:
            row = await tx.fetch_one(
                "SELECT * FROM {{tables.registry_migration_cutovers}} WHERE cutover_id=$1::uuid AND role='source' FOR UPDATE",
                cutover_id,
            )
            if row is None:
                raise RegistryMigrationError("source cutover not found")
            if row["state"] == "canceled":
                return {
                    "state": "canceled",
                    "counts": self._json_value(row["cancel_counts"]),
                    "cancel_digest": row["cancel_digest"],
                }
            if row["state"] != "frozen":
                raise RegistryMigrationError("source cutover can no longer be canceled")
            counts = {
                value["kind"]: value["count"]
                for value in await tx.fetch_all(
                    """
                    SELECT kind,COUNT(*)::int AS count
                    FROM {{tables.registry_migration_items}}
                    WHERE cutover_id=$1::uuid AND role='source'
                    GROUP BY kind ORDER BY kind
                    """,
                    cutover_id,
                )
            }
            digest = self._digest(counts)
            await tx.execute(
                "DELETE FROM {{tables.registry_migration_items}} WHERE cutover_id=$1::uuid AND role='source'",
                cutover_id,
            )
            await tx.execute(
                """
                UPDATE {{tables.registry_migration_cutovers}}
                SET state='canceled',cancel_counts=$2::jsonb,cancel_digest=$3,updated_at=NOW()
                WHERE cutover_id=$1::uuid AND role='source'
                """,
                cutover_id,
                json.dumps(counts, sort_keys=True),
                digest,
            )
            return {"state": "canceled", "counts": counts, "cancel_digest": digest}

    @staticmethod
    def _json_value(value):
        if value is None or isinstance(value, dict):
            return value
        return json.loads(value)

    @staticmethod
    def _receipt_wire(receipt) -> dict[str, Any]:
        return receipt.model_dump(mode="json")

    @staticmethod
    def _load_stored_receipt(row, payload_column: str, hash_column: str, expected_type, label: str):
        raw_payload = bytes(row[payload_column])
        try:
            receipt = parse_receipt({
                "payload": json.loads(raw_payload.decode()),
                "receipt_hash": row[hash_column],
            })
        except Exception as exc:
            raise RegistryMigrationError(f"invalid stored {label} receipt") from exc
        if not isinstance(receipt.payload, expected_type):
            raise RegistryMigrationError(f"stored {label} receipt has unexpected type")
        if raw_payload != receipt_payload_bytes(receipt.payload):
            raise RegistryMigrationError(f"stored {label} payload is not canonical")
        return receipt

    @staticmethod
    def _bind_destination_complete(row, cutover_id: str, payload, overlap_payload) -> None:
        evidence = RegistryMigrationService._json_value(row["old_selection_evidence"])
        complete_after = row["complete_after"]
        final_observed_at = datetime.fromisoformat(
            payload.destination_final_observed_at.replace("Z", "+00:00")
        )
        destination_completed_at = datetime.fromisoformat(
            payload.destination_completed_at.replace("Z", "+00:00")
        )
        if (
            payload.source_registry_id != str(row["source_registry_id"])
            or payload.destination_registry_id != str(row["destination_registry_id"])
            or payload.cutover_id != cutover_id
            or payload.source_generation != row["source_generation"]
            or payload.snapshot_digest != row["snapshot_digest"]
            or payload.manifest_digest != row["manifest_digest"]
            or payload.old_selection_evidence_hash != evidence["evidence_hash"]
            or payload.destination_registry_origin
            != row["expected_destination_origin"]
            or payload.overlap_receipt_hash != row["overlap_receipt_hash"]
            or payload.destination_dns_name != overlap_payload.destination_dns_name
            or payload.destination_controller_did
            != overlap_payload.destination_controller_did
            or payload.destination_dns_answer_digest
            != overlap_payload.destination_dns_answer_digest
            or payload.complete_after
            != complete_after.isoformat().replace("+00:00", "Z")
            or final_observed_at < complete_after
            or destination_completed_at < final_observed_at
            or destination_completed_at
            > final_observed_at + timedelta(seconds=300)
            or overlap_payload.source_registry_id
            != str(row["source_registry_id"])
            or overlap_payload.destination_registry_id
            != str(row["destination_registry_id"])
            or overlap_payload.cutover_id != cutover_id
            or overlap_payload.source_generation != row["source_generation"]
            or overlap_payload.snapshot_digest != row["snapshot_digest"]
            or overlap_payload.manifest_digest != row["manifest_digest"]
            or overlap_payload.old_selection_evidence_hash
            != evidence["evidence_hash"]
            or overlap_payload.old_registry_origin != evidence["old_registry_origin"]
            or overlap_payload.old_ttl_seconds != evidence["ttl_seconds"]
            or overlap_payload.destination_registry_origin
            != row["expected_destination_origin"]
            or overlap_payload.destination_observation_hash
            != row["destination_observation_hash"]
            or overlap_payload.source_dns_answer_digest
            != overlap_payload.destination_dns_answer_digest
            or overlap_payload.overlap_started_at
            != row["overlap_started_at"].isoformat().replace("+00:00", "Z")
            or overlap_payload.complete_after
            != row["complete_after"].isoformat().replace("+00:00", "Z")
        ):
            raise RegistryMigrationError(
                "destination completion does not match cutover"
            )

    async def confirm_readback(self, cutover_id: str, readback: dict[str, Any]) -> dict[str, Any]:
        async with self.db.transaction() as tx:
            row = await tx.fetch_one(
                "SELECT * FROM {{tables.registry_migration_cutovers}} WHERE cutover_id=$1::uuid AND role='source' FOR UPDATE",
                cutover_id,
            )
            if row is None:
                raise RegistryMigrationError("source cutover not found")
            payload = readback.get("payload", {})
            if payload.get("destination_state") != "verified":
                raise RegistryMigrationError("destination readback is not in verified state")
            source_counts = {
                value["kind"]: value["count"]
                for value in await tx.fetch_all(
                    """
                    SELECT kind,COUNT(*)::int AS count
                    FROM {{tables.registry_migration_items}}
                    WHERE cutover_id=$1::uuid AND role='source'
                    GROUP BY kind ORDER BY kind
                    """,
                    cutover_id,
                )
            }
            readback_counts = payload.get("counts", {})
            if (
                not isinstance(readback_counts, dict)
                or any(
                    not isinstance(dispositions, dict)
                    or set(dispositions) != {"inserted", "reused"}
                    or any(not isinstance(value, int) or value < 0 for value in dispositions.values())
                    for dispositions in readback_counts.values()
                )
            ):
                raise RegistryMigrationError("destination readback disposition counts are malformed")
            if {
                kind: sum(dispositions.values())
                for kind, dispositions in readback_counts.items()
            } != source_counts:
                raise RegistryMigrationError("destination readback disposition counts mismatch")
            if not isinstance(payload.get("semantic_manifest_digest"), str):
                raise RegistryMigrationError("destination readback semantic manifest is missing")
            if (
                readback.get("readback_hash") != self._digest(payload)
                or payload.get("source_registry_id") != str(row["source_registry_id"])
                or payload.get("destination_registry_id") != str(row["destination_registry_id"])
                or payload.get("expected_destination_origin")
                != row["expected_destination_origin"]
                or payload.get("cutover_id") != cutover_id
                or payload.get("source_generation") != row["source_generation"]
                or payload.get("snapshot_digest") != row["snapshot_digest"]
                or payload.get("manifest_digest") != row["manifest_digest"]
            ):
                raise RegistryMigrationError("destination readback does not match frozen source")
            if row["old_selection_evidence"] is None:
                raise RegistryMigrationError("old registry-selection DNS evidence is required")
            if row["dns_authorization_hash"] is not None:
                stored = self._load_stored_receipt(
                    row,
                    "dns_authorization_payload",
                    "dns_authorization_hash",
                    DNSAuthorizationPayload,
                    "DNS authorization",
                )
                stored_payload = stored.payload
                if (
                    stored_payload.source_registry_id != str(row["source_registry_id"])
                    or stored_payload.destination_registry_id
                    != str(row["destination_registry_id"])
                    or stored_payload.cutover_id != cutover_id
                    or stored_payload.source_generation != row["source_generation"]
                    or stored_payload.snapshot_digest != row["snapshot_digest"]
                    or stored_payload.manifest_digest != row["manifest_digest"]
                    or stored_payload.destination_readback_hash
                    != readback["readback_hash"]
                    or stored_payload.expected_destination_origin
                    != row["expected_destination_origin"]
                ):
                    raise RegistryMigrationError(
                        "stored DNS authorization does not match cutover"
                    )
                return self._receipt_wire(stored)
            if row["state"] != "frozen":
                raise RegistryMigrationError("source cutover cannot confirm readback in current state")
            if self.verify_domain is None:
                raise RegistryMigrationError(
                    "fresh source DNS verification is required for authorization"
                )
            authority = await self.verify_domain(row["root_domain"])
            evidence = self._json_value(row["old_selection_evidence"])
            fresh_digest = self._digest({
                "controller_did": authority.controller_did,
                "dns_name": authority.dns_name,
                "registry_origin": authority.registry_url,
            })
            if (
                authority.dns_name != evidence["dns_name"]
                or authority.registry_url != evidence["old_registry_origin"]
                or authority.controller_did != evidence["controller_did"]
                or fresh_digest != evidence["authority_answer_digest"]
            ):
                raise RegistryMigrationError(
                    "fresh source DNS no longer matches frozen old selection"
                )
            authorization_payload = DNSAuthorizationPayload(
                version="awid.registry-migration-dns-authorization.v1",
                source_registry_id=str(row["source_registry_id"]),
                destination_registry_id=str(row["destination_registry_id"]),
                cutover_id=cutover_id,
                source_generation=row["source_generation"],
                snapshot_digest=row["snapshot_digest"],
                manifest_digest=row["manifest_digest"],
                destination_readback_hash=readback["readback_hash"],
                expected_destination_origin=row["expected_destination_origin"],
            )
            receipt = make_receipt(authorization_payload)
            exact = receipt_payload_bytes(authorization_payload)
            await tx.execute(
                """UPDATE {{tables.registry_migration_cutovers}}
                   SET state='dns_authorized',dns_authorization_payload=$2,
                       dns_authorization_hash=$3,updated_at=NOW()
                   WHERE cutover_id=$1::uuid AND role='source'""",
                cutover_id, exact, receipt.receipt_hash,
            )
            return self._receipt_wire(receipt)

    async def apply_dns_authorization(
        self, cutover_id: str, authorization: dict[str, Any]
    ) -> dict[str, Any]:
        try:
            receipt = parse_receipt(authorization)
        except Exception as exc:
            raise RegistryMigrationError("invalid DNS authorization receipt") from exc
        if not isinstance(receipt.payload, DNSAuthorizationPayload):
            raise RegistryMigrationError("expected DNS authorization receipt")
        payload = receipt.payload
        exact = receipt_payload_bytes(payload)
        expected_hash = receipt.receipt_hash
        async with self.db.transaction() as tx:
            row = await tx.fetch_one(
                "SELECT * FROM {{tables.registry_migration_cutovers}} WHERE cutover_id=$1::uuid AND role='destination' FOR UPDATE",
                cutover_id,
            )
            if row is None:
                raise RegistryMigrationError("destination cutover not found")
            if row["dns_authorization_hash"] is not None:
                stored = self._load_stored_receipt(
                    row,
                    "dns_authorization_payload",
                    "dns_authorization_hash",
                    DNSAuthorizationPayload,
                    "DNS authorization",
                )
                stored_payload = stored.payload
                if (
                    stored_payload.source_registry_id
                    != str(row["source_registry_id"])
                    or stored_payload.destination_registry_id
                    != str(row["destination_registry_id"])
                    or stored_payload.cutover_id != cutover_id
                    or stored_payload.source_generation != row["source_generation"]
                    or stored_payload.snapshot_digest != row["snapshot_digest"]
                    or stored_payload.manifest_digest != row["manifest_digest"]
                    or stored_payload.expected_destination_origin
                    != row["expected_destination_origin"]
                ):
                    raise RegistryMigrationError(
                        "stored DNS authorization does not match destination cutover"
                    )
                if (
                    stored.receipt_hash == expected_hash
                    and receipt_payload_bytes(stored_payload) == exact
                ):
                    return self._receipt_wire(stored)
                raise RegistryMigrationError("conflicting destination DNS authorization")
            local_readback = await self.readback(cutover_id, tx=tx)
            if (
                payload.source_registry_id != str(row["source_registry_id"])
                or payload.destination_registry_id != str(row["destination_registry_id"])
                or payload.expected_destination_origin
                != row["expected_destination_origin"]
                or payload.cutover_id != cutover_id
                or payload.source_generation != row["source_generation"]
                or payload.snapshot_digest != row["snapshot_digest"]
                or payload.manifest_digest != row["manifest_digest"]
                or payload.destination_readback_hash != local_readback["readback_hash"]
            ):
                raise RegistryMigrationError("DNS authorization does not match destination readback")
            if row["state"] != "verified":
                raise RegistryMigrationError("destination cannot apply DNS authorization in current state")
            await tx.execute(
                """UPDATE {{tables.registry_migration_cutovers}}
                   SET state='dns_authorized',dns_authorization_payload=$2,
                       dns_authorization_hash=$3,updated_at=NOW()
                   WHERE cutover_id=$1::uuid AND role='destination'""",
                cutover_id, exact, expected_hash,
            )
            return authorization

    async def observe_destination(
        self,
        cutover_id: str,
        *,
        destination_registry_origin: str | None = None,
        destination_dns_name: str | None = None,
        destination_dns_answer_digest: str | None = None,
        observed_at: str | None = None,
    ) -> dict[str, Any]:
        async with self.db.transaction() as tx:
            row = await tx.fetch_one(
                "SELECT * FROM {{tables.registry_migration_cutovers}} WHERE cutover_id=$1::uuid AND role='destination' FOR UPDATE",
                cutover_id,
            )
            if row is None:
                raise RegistryMigrationError("destination cutover not found")
            if row["destination_observation_hash"] is not None:
                stored = self._load_stored_receipt(
                    row,
                    "destination_observation_payload",
                    "destination_observation_hash",
                    OverlapObservationPayload,
                    "destination observation",
                )
                stored_payload = stored.payload
                evidence = self._json_value(row["old_selection_evidence"])
                if (
                    stored_payload.source_registry_id
                    != str(row["source_registry_id"])
                    or stored_payload.destination_registry_id
                    != str(row["destination_registry_id"])
                    or stored_payload.cutover_id != cutover_id
                    or stored_payload.source_generation != row["source_generation"]
                    or stored_payload.snapshot_digest != row["snapshot_digest"]
                    or stored_payload.manifest_digest != row["manifest_digest"]
                    or stored_payload.destination_registry_origin
                    != row["expected_destination_origin"]
                    or evidence is None
                    or stored_payload.old_selection_evidence_hash
                    != evidence["evidence_hash"]
                    or stored_payload.old_registry_origin
                    != evidence["old_registry_origin"]
                    or stored_payload.old_ttl_seconds != evidence["ttl_seconds"]
                ):
                    raise RegistryMigrationError(
                        "stored destination observation does not match cutover"
                    )
                return self._receipt_wire(stored)
            if row["state"] != "dns_authorized":
                raise RegistryMigrationError("destination observation requires DNS authorization")
            evidence = self._json_value(row["old_selection_evidence"])
            if evidence is None:
                raise RegistryMigrationError("old registry-selection DNS evidence is required")
            if self.verify_domain is None or self.public_origin is None:
                raise RegistryMigrationError(
                    "destination DNS verifier and configured public origin are required"
                )
            authority = await self.verify_domain(row["root_domain"])
            if (
                authority.registry_url != row["expected_destination_origin"]
                or authority.registry_url != self.public_origin
            ):
                raise RegistryMigrationError(
                    "live destination DNS does not select expected public origin"
                )
            destination_registry_origin = authority.registry_url
            destination_dns_name = authority.dns_name
            destination_controller_did = authority.controller_did
            destination_dns_answer_digest = self._digest(
                {
                    "controller_did": authority.controller_did,
                    "dns_name": authority.dns_name,
                    "registry_origin": authority.registry_url,
                }
            )
            observed_at = observed_at or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            payload = OverlapObservationPayload(
                version="awid.registry-migration-overlap-observation.v1",
                source_registry_id=str(row["source_registry_id"]),
                destination_registry_id=str(row["destination_registry_id"]),
                cutover_id=cutover_id,
                source_generation=row["source_generation"],
                snapshot_digest=row["snapshot_digest"],
                manifest_digest=row["manifest_digest"],
                old_selection_evidence_hash=evidence["evidence_hash"],
                old_registry_origin=evidence["old_registry_origin"],
                old_ttl_seconds=evidence["ttl_seconds"],
                destination_registry_origin=destination_registry_origin,
                destination_dns_name=destination_dns_name,
                destination_controller_did=destination_controller_did,
                destination_dns_answer_digest=destination_dns_answer_digest,
                destination_observed_at=observed_at,
            )
            receipt = make_receipt(payload)
            exact = receipt_payload_bytes(payload)
            await tx.execute(
                """UPDATE {{tables.registry_migration_cutovers}}
                   SET destination_observation_payload=$2,destination_observation_hash=$3,updated_at=NOW()
                   WHERE cutover_id=$1::uuid AND role='destination'""",
                cutover_id, exact, receipt.receipt_hash,
            )
            return self._receipt_wire(receipt)

    async def establish_overlap(
        self,
        cutover_id: str,
        destination_observation: dict[str, Any],
        *,
        source_dns_answer_digest: str | None = None,
        source_observed_at: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        observation = parse_receipt(destination_observation)
        if not isinstance(observation.payload, OverlapObservationPayload):
            raise RegistryMigrationError("expected destination overlap observation receipt")
        observation_bytes = receipt_payload_bytes(observation.payload)
        async with self.db.transaction() as tx:
            row = await tx.fetch_one(
                "SELECT * FROM {{tables.registry_migration_cutovers}} WHERE cutover_id=$1::uuid AND role='source' FOR UPDATE",
                cutover_id,
            )
            if row is None:
                raise RegistryMigrationError("source cutover not found")
            op = observation.payload
            if (
                op.source_registry_id != str(row["source_registry_id"])
                or op.destination_registry_id != str(row["destination_registry_id"])
                or op.cutover_id != cutover_id
                or op.source_generation != row["source_generation"]
                or op.snapshot_digest != row["snapshot_digest"]
                or op.manifest_digest != row["manifest_digest"]
                or op.destination_registry_origin != row["expected_destination_origin"]
            ):
                raise RegistryMigrationError("destination observation does not match cutover")
            evidence = self._json_value(row["old_selection_evidence"])
            if (
                op.old_selection_evidence_hash != evidence["evidence_hash"]
                or op.old_registry_origin != evidence["old_registry_origin"]
                or op.old_ttl_seconds != evidence["ttl_seconds"]
            ):
                raise RegistryMigrationError(
                    "destination observation old-selection evidence mismatch"
                )
            if row["overlap_receipt_hash"] is not None:
                if (
                    row["destination_observation_hash"] != observation.receipt_hash
                    or bytes(row["destination_observation_payload"]) != observation_bytes
                ):
                    raise RegistryMigrationError(
                        "conflicting destination observation for stored overlap"
                    )
                stored = self._load_stored_receipt(
                    row,
                    "overlap_payload",
                    "overlap_receipt_hash",
                    CanonicalOverlapPayload,
                    "canonical overlap",
                )
                stored_payload = stored.payload
                if (
                    stored_payload.source_registry_id
                    != str(row["source_registry_id"])
                    or stored_payload.destination_registry_id
                    != str(row["destination_registry_id"])
                    or stored_payload.cutover_id != cutover_id
                    or stored_payload.source_generation != row["source_generation"]
                    or stored_payload.snapshot_digest != row["snapshot_digest"]
                    or stored_payload.manifest_digest != row["manifest_digest"]
                    or stored_payload.destination_observation_hash
                    != observation.receipt_hash
                    or stored_payload.destination_registry_origin
                    != row["expected_destination_origin"]
                    or stored_payload.old_selection_evidence_hash
                    != evidence["evidence_hash"]
                    or stored_payload.old_registry_origin
                    != evidence["old_registry_origin"]
                    or stored_payload.old_ttl_seconds != evidence["ttl_seconds"]
                    or stored_payload.destination_dns_name != op.destination_dns_name
                    or stored_payload.destination_controller_did
                    != op.destination_controller_did
                    or stored_payload.destination_dns_answer_digest
                    != op.destination_dns_answer_digest
                    or stored_payload.source_dns_answer_digest
                    != op.destination_dns_answer_digest
                    or stored_payload.destination_observed_at
                    != op.destination_observed_at
                    or stored_payload.overlap_started_at
                    != row["overlap_started_at"].isoformat().replace("+00:00", "Z")
                    or stored_payload.complete_after
                    != row["complete_after"].isoformat().replace("+00:00", "Z")
                ):
                    raise RegistryMigrationError(
                        "stored canonical overlap does not match cutover"
                    )
                return self._receipt_wire(stored)
            if row["state"] != "dns_authorized":
                raise RegistryMigrationError("source cutover is not DNS-authorized")

            if self.verify_domain is not None:
                authority = await self.verify_domain(row["root_domain"])
                source_dns_answer_digest = self._digest({
                    "controller_did": authority.controller_did,
                    "dns_name": authority.dns_name,
                    "registry_origin": authority.registry_url,
                })
                source_observed_at = (
                    now or datetime.now(timezone.utc)
                ).isoformat().replace("+00:00", "Z")
                if (
                    authority.registry_url != op.destination_registry_origin
                    or authority.dns_name.rstrip(".").lower()
                    != op.destination_dns_name.rstrip(".").lower()
                    or authority.controller_did != op.destination_controller_did
                ):
                    raise RegistryMigrationError(
                        "source DNS does not match the observed destination authority"
                    )
            evaluation_now = now or datetime.now(timezone.utc)
            if source_dns_answer_digest is None or source_observed_at is None:
                raise RegistryMigrationError("live source DNS observation is required")
            if source_dns_answer_digest != op.destination_dns_answer_digest:
                raise RegistryMigrationError(
                    "source DNS authority digest differs from destination observation"
                )
            destination_time = datetime.fromisoformat(
                op.destination_observed_at.replace("Z", "+00:00")
            )
            source_time = datetime.fromisoformat(
                source_observed_at.replace("Z", "+00:00")
            )
            if abs((evaluation_now - destination_time).total_seconds()) > 300:
                raise RegistryMigrationError(
                    "destination observation exceeds 300-second clock-skew bound"
                )
            if abs((evaluation_now - source_time).total_seconds()) > 300:
                raise RegistryMigrationError(
                    "source observation exceeds 300-second clock-skew bound"
                )
            overlap_started = max(destination_time, source_time)
            complete_after = overlap_started + timedelta(
                seconds=evidence["ttl_seconds"] + 300
            )
            payload = CanonicalOverlapPayload(
                version="awid.registry-migration-overlap.v1",
                source_registry_id=str(row["source_registry_id"]),
                destination_registry_id=str(row["destination_registry_id"]),
                cutover_id=cutover_id,
                source_generation=row["source_generation"],
                snapshot_digest=row["snapshot_digest"],
                manifest_digest=row["manifest_digest"],
                old_selection_evidence_hash=evidence["evidence_hash"],
                old_registry_origin=evidence["old_registry_origin"],
                old_ttl_seconds=evidence["ttl_seconds"],
                destination_registry_origin=op.destination_registry_origin,
                destination_observation_hash=observation.receipt_hash,
                destination_dns_name=op.destination_dns_name,
                destination_controller_did=op.destination_controller_did,
                destination_dns_answer_digest=op.destination_dns_answer_digest,
                destination_observed_at=op.destination_observed_at,
                source_dns_answer_digest=source_dns_answer_digest,
                source_observed_at=source_observed_at,
                overlap_started_at=overlap_started.isoformat().replace("+00:00", "Z"),
                clock_skew_allowance_seconds=300,
                complete_after=complete_after.isoformat().replace("+00:00", "Z"),
            )
            receipt = make_receipt(payload)
            exact = receipt_payload_bytes(payload)
            await tx.execute(
                """UPDATE {{tables.registry_migration_cutovers}}
                   SET state='overlap',destination_observation_payload=$2,
                       destination_observation_hash=$3,overlap_payload=$4,
                       overlap_receipt_hash=$5,overlap_started_at=$6,
                       complete_after=$7,updated_at=NOW()
                   WHERE cutover_id=$1::uuid AND role='source'""",
                cutover_id,
                observation_bytes,
                observation.receipt_hash,
                exact,
                receipt.receipt_hash,
                overlap_started,
                complete_after,
            )
            return self._receipt_wire(receipt)

    async def apply_overlap(self, cutover_id: str, overlap_value: dict[str, Any]) -> dict[str, Any]:
        receipt = parse_receipt(overlap_value)
        if not isinstance(receipt.payload, CanonicalOverlapPayload):
            raise RegistryMigrationError("expected canonical overlap receipt")
        async with self.db.transaction() as tx:
            row = await tx.fetch_one(
                "SELECT * FROM {{tables.registry_migration_cutovers}} WHERE cutover_id=$1::uuid AND role='destination' FOR UPDATE",
                cutover_id,
            )
            if row is None:
                raise RegistryMigrationError("destination cutover not found")
            payload = receipt.payload
            if (
                payload.source_registry_id != str(row["source_registry_id"])
                or payload.destination_registry_id != str(row["destination_registry_id"])
                or payload.cutover_id != cutover_id
                or payload.source_generation != row["source_generation"]
                or payload.snapshot_digest != row["snapshot_digest"]
                or payload.manifest_digest != row["manifest_digest"]
                or payload.destination_observation_hash != row["destination_observation_hash"]
                or payload.destination_registry_origin
                != row["expected_destination_origin"]
            ):
                raise RegistryMigrationError("canonical overlap receipt does not match destination")
            stored_observation = self._load_stored_receipt(
                row,
                "destination_observation_payload",
                "destination_observation_hash",
                OverlapObservationPayload,
                "destination observation",
            )
            observation = stored_observation.payload
            evidence = self._json_value(row["old_selection_evidence"])
            if (
                observation.source_registry_id != str(row["source_registry_id"])
                or observation.destination_registry_id
                != str(row["destination_registry_id"])
                or observation.cutover_id != cutover_id
                or observation.source_generation != row["source_generation"]
                or observation.snapshot_digest != row["snapshot_digest"]
                or observation.manifest_digest != row["manifest_digest"]
                or observation.old_selection_evidence_hash
                != evidence["evidence_hash"]
                or observation.old_registry_origin != evidence["old_registry_origin"]
                or observation.old_ttl_seconds != evidence["ttl_seconds"]
                or observation.destination_registry_origin
                != row["expected_destination_origin"]
                or payload.old_selection_evidence_hash != evidence["evidence_hash"]
                or payload.old_registry_origin != evidence["old_registry_origin"]
                or payload.old_ttl_seconds != evidence["ttl_seconds"]
                or payload.destination_observation_hash != stored_observation.receipt_hash
                or payload.destination_registry_origin != observation.destination_registry_origin
                or payload.destination_dns_name != observation.destination_dns_name
                or payload.destination_controller_did
                != observation.destination_controller_did
                or payload.destination_dns_answer_digest != observation.destination_dns_answer_digest
                or payload.source_dns_answer_digest
                != observation.destination_dns_answer_digest
                or payload.destination_observed_at != observation.destination_observed_at
            ):
                raise RegistryMigrationError("canonical overlap receipt binding mismatch")
            destination_time = datetime.fromisoformat(
                payload.destination_observed_at.replace("Z", "+00:00")
            )
            source_time = datetime.fromisoformat(payload.source_observed_at.replace("Z", "+00:00"))
            expected_started = max(destination_time, source_time)
            expected_complete = expected_started + timedelta(
                seconds=payload.old_ttl_seconds + payload.clock_skew_allowance_seconds
            )
            if (
                payload.overlap_started_at
                != expected_started.isoformat().replace("+00:00", "Z")
                or payload.complete_after
                != expected_complete.isoformat().replace("+00:00", "Z")
            ):
                raise RegistryMigrationError("canonical overlap timing bound mismatch")
            exact = receipt_payload_bytes(payload)
            if row["overlap_receipt_hash"] is not None:
                stored_overlap = self._load_stored_receipt(
                    row,
                    "overlap_payload",
                    "overlap_receipt_hash",
                    CanonicalOverlapPayload,
                    "canonical overlap",
                )
                if (
                    stored_overlap.receipt_hash != receipt.receipt_hash
                    or receipt_payload_bytes(stored_overlap.payload) != exact
                ):
                    raise RegistryMigrationError("conflicting destination overlap receipt")
                return self._receipt_wire(stored_overlap)
            if row["state"] != "dns_authorized":
                raise RegistryMigrationError("destination cutover cannot apply overlap")
            await tx.execute(
                """UPDATE {{tables.registry_migration_cutovers}}
                   SET state='overlap',overlap_payload=$2,overlap_receipt_hash=$3,
                       overlap_started_at=$4,complete_after=$5,updated_at=NOW()
                   WHERE cutover_id=$1::uuid AND role='destination'""",
                cutover_id, exact, receipt.receipt_hash,
                datetime.fromisoformat(payload.overlap_started_at.replace("Z", "+00:00")),
                datetime.fromisoformat(payload.complete_after.replace("Z", "+00:00")),
            )
            return self._receipt_wire(receipt)

    async def complete_destination(
        self, cutover_id: str, *, completed_at: datetime | None = None
    ) -> dict[str, Any]:
        injected_completion = completed_at
        async with self.db.transaction() as tx:
            row = await tx.fetch_one(
                "SELECT * FROM {{tables.registry_migration_cutovers}} WHERE cutover_id=$1::uuid AND role='destination' FOR UPDATE",
                cutover_id,
            )
            if row is None:
                raise RegistryMigrationError("destination cutover not found")
            if row["state"] == "completed":
                stored = self._load_stored_receipt(
                    row,
                    "destination_complete_payload",
                    "destination_complete_hash",
                    DestinationCompletePayload,
                    "destination complete",
                )
                overlap = self._load_stored_receipt(
                    row,
                    "overlap_payload",
                    "overlap_receipt_hash",
                    CanonicalOverlapPayload,
                    "canonical overlap",
                )
                self._bind_destination_complete(
                    row, cutover_id, stored.payload, overlap.payload
                )
                if (
                    stored.payload.destination_completed_at
                    != row["destination_completed_at"].isoformat().replace("+00:00", "Z")
                ):
                    raise RegistryMigrationError(
                        "stored destination completion time does not match cutover"
                    )
                return self._receipt_wire(stored)
            if row["state"] != "overlap" or row["complete_after"] is None:
                raise RegistryMigrationError("destination cutover is not in overlap")
            if (
                injected_completion is not None
                and injected_completion < row["complete_after"]
            ):
                raise RegistryMigrationError("destination overlap has not elapsed")
            overlap = self._load_stored_receipt(
                row,
                "overlap_payload",
                "overlap_receipt_hash",
                CanonicalOverlapPayload,
                "canonical overlap",
            )
            op = overlap.payload
            evidence = self._json_value(row["old_selection_evidence"])
            if (
                op.source_registry_id != str(row["source_registry_id"])
                or op.destination_registry_id != str(row["destination_registry_id"])
                or op.cutover_id != cutover_id
                or op.source_generation != row["source_generation"]
                or op.snapshot_digest != row["snapshot_digest"]
                or op.manifest_digest != row["manifest_digest"]
                or op.old_selection_evidence_hash != evidence["evidence_hash"]
                or op.old_registry_origin != evidence["old_registry_origin"]
                or op.old_ttl_seconds != evidence["ttl_seconds"]
                or op.destination_registry_origin
                != row["expected_destination_origin"]
                or op.destination_observation_hash
                != row["destination_observation_hash"]
                or op.source_dns_answer_digest
                != op.destination_dns_answer_digest
                or op.overlap_started_at
                != row["overlap_started_at"].isoformat().replace("+00:00", "Z")
                or op.complete_after
                != row["complete_after"].isoformat().replace("+00:00", "Z")
            ):
                raise RegistryMigrationError(
                    "stored canonical overlap does not match destination cutover"
                )
            if self.verify_domain is None or self.public_origin is None:
                raise RegistryMigrationError(
                    "fresh destination DNS verification is required for completion"
                )
            authority = await self.verify_domain(row["root_domain"])
            final_digest = self._digest({
                "controller_did": authority.controller_did,
                "dns_name": authority.dns_name,
                "registry_origin": authority.registry_url,
            })
            if (
                authority.registry_url != row["expected_destination_origin"]
                or authority.registry_url != self.public_origin
                or authority.dns_name != op.destination_dns_name
                or authority.controller_did != op.destination_controller_did
                or final_digest != op.destination_dns_answer_digest
            ):
                raise RegistryMigrationError(
                    "fresh destination DNS authority differs from canonical overlap"
                )
            completed_at = injected_completion or datetime.now(timezone.utc)
            if completed_at < row["complete_after"]:
                raise RegistryMigrationError("destination overlap has not elapsed")
            final_observed_at = completed_at
            payload = DestinationCompletePayload(
                version="awid.registry-migration-destination-complete.v1",
                source_registry_id=str(row["source_registry_id"]),
                destination_registry_id=str(row["destination_registry_id"]),
                cutover_id=cutover_id,
                source_generation=row["source_generation"],
                snapshot_digest=row["snapshot_digest"],
                manifest_digest=row["manifest_digest"],
                old_selection_evidence_hash=op.old_selection_evidence_hash,
                destination_registry_origin=op.destination_registry_origin,
                overlap_receipt_hash=overlap.receipt_hash,
                destination_dns_name=authority.dns_name,
                destination_controller_did=authority.controller_did,
                destination_dns_answer_digest=final_digest,
                destination_final_observed_at=final_observed_at.isoformat().replace("+00:00", "Z"),
                complete_after=op.complete_after,
                destination_completed_at=completed_at.isoformat().replace("+00:00", "Z"),
            )
            self._bind_destination_complete(row, cutover_id, payload, op)
            receipt = make_receipt(payload)
            exact = receipt_payload_bytes(payload)
            await tx.execute(
                """UPDATE {{tables.registry_migration_cutovers}}
                   SET state='completed',destination_complete_payload=$2,
                       destination_complete_hash=$3,destination_completed_at=$4,updated_at=NOW()
                   WHERE cutover_id=$1::uuid AND role='destination'""",
                cutover_id, exact, receipt.receipt_hash, completed_at,
            )
            return self._receipt_wire(receipt)

    async def complete_source(
        self,
        cutover_id: str,
        destination_complete_value: dict[str, Any],
        *,
        completed_at: datetime | None = None,
    ) -> dict[str, Any]:
        receipt = parse_receipt(destination_complete_value)
        if not isinstance(receipt.payload, DestinationCompletePayload):
            raise RegistryMigrationError("expected destination-complete receipt")
        injected_completion = completed_at
        async with self.db.transaction() as tx:
            row = await tx.fetch_one(
                "SELECT * FROM {{tables.registry_migration_cutovers}} WHERE cutover_id=$1::uuid AND role='source' FOR UPDATE",
                cutover_id,
            )
            if row is None:
                raise RegistryMigrationError("source cutover not found")
            if row["state"] == "completed":
                stored = self._load_stored_receipt(
                    row,
                    "destination_complete_payload",
                    "destination_complete_hash",
                    DestinationCompletePayload,
                    "destination complete",
                )
                overlap = self._load_stored_receipt(
                    row,
                    "overlap_payload",
                    "overlap_receipt_hash",
                    CanonicalOverlapPayload,
                    "canonical overlap",
                )
                self._bind_destination_complete(
                    row, cutover_id, stored.payload, overlap.payload
                )
                if (
                    stored.receipt_hash == receipt.receipt_hash
                    and receipt_payload_bytes(stored.payload)
                    == receipt_payload_bytes(receipt.payload)
                ):
                    return {
                        "state": "completed",
                        "destination_complete_hash": stored.receipt_hash,
                    }
                raise RegistryMigrationError("conflicting source completion retry")
            if row["state"] != "overlap" or row["complete_after"] is None:
                raise RegistryMigrationError("source cutover is not in overlap")
            payload = receipt.payload
            destination_completed_at = datetime.fromisoformat(
                payload.destination_completed_at.replace("Z", "+00:00")
            )
            destination_final_observed_at = datetime.fromisoformat(
                payload.destination_final_observed_at.replace("Z", "+00:00")
            )
            canonical_complete_after = row["complete_after"].isoformat().replace("+00:00", "Z")
            overlap = self._load_stored_receipt(
                row,
                "overlap_payload",
                "overlap_receipt_hash",
                CanonicalOverlapPayload,
                "canonical overlap",
            )
            self._bind_destination_complete(
                row, cutover_id, payload, overlap.payload
            )
            if (
                payload.complete_after != canonical_complete_after
                or destination_final_observed_at < row["complete_after"]
                or destination_completed_at < destination_final_observed_at
                or destination_completed_at
                > destination_final_observed_at + timedelta(seconds=300)
                or (
                    injected_completion is not None
                    and injected_completion < row["complete_after"]
                )
            ):
                raise RegistryMigrationError("destination completion does not authorize source release")
            if self.verify_domain is None:
                raise RegistryMigrationError(
                    "fresh source DNS verification is required for completion"
                )
            authority = await self.verify_domain(row["root_domain"])
            final_digest = self._digest({
                "controller_did": authority.controller_did,
                "dns_name": authority.dns_name,
                "registry_origin": authority.registry_url,
            })
            if (
                authority.registry_url != row["expected_destination_origin"]
                or authority.dns_name != payload.destination_dns_name
                or authority.controller_did != payload.destination_controller_did
                or final_digest != payload.destination_dns_answer_digest
            ):
                raise RegistryMigrationError(
                    "fresh source DNS authority differs from destination completion"
                )
            completed_at = injected_completion or datetime.now(timezone.utc)
            if completed_at < row["complete_after"]:
                raise RegistryMigrationError(
                    "source overlap has not elapsed at final DNS observation"
                )
            source_observation = {
                "controller_did": authority.controller_did,
                "dns_name": authority.dns_name,
                "registry_origin": authority.registry_url,
                "answer_digest": final_digest,
                "observed_at": completed_at.isoformat().replace("+00:00", "Z"),
                "consumed_destination_complete_hash": receipt.receipt_hash,
            }
            await tx.execute(
                """UPDATE {{tables.registry_migration_cutovers}}
                   SET state='completed',destination_complete_payload=$2,
                       destination_complete_hash=$3,destination_completed_at=$4,
                       source_final_observation=$5::jsonb,updated_at=NOW()
                   WHERE cutover_id=$1::uuid AND role='source'""",
                cutover_id, receipt_payload_bytes(payload), receipt.receipt_hash,
                datetime.fromisoformat(payload.destination_completed_at.replace("Z", "+00:00")),
                json.dumps(source_observation, sort_keys=True),
            )
            return {"state": "completed", "destination_complete_hash": receipt.receipt_hash}
