"""Team-vouched local return routes, verified from public AWID evidence.

A certificate selects membership; the member signature selects the whole team.
Only that team's current key may name its server. Cached evidence lives in the
existing PostgreSQL authority work store, never in an adapter or process cache.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import logging
from uuid import UUID, uuid4

from awid.external_authority import canonical_protocol_domain
from awid.external_http import escaped_path_component
from awid.federation_errors import FederationAuthorityError
from awid.log import canonical_server_origin
from awid.registry import RegistryError
from awid.team_certificate import (
    TeamCertificateError, decode_team_certificate, verify_team_certificate_signature,
)
from awid.team_ids import build_team_id, parse_team_id
from awid.team_server_record import TeamServerRecordError, verify_team_server_record

from .origins import public_origins
from .errors import TeamRouteError

logger = logging.getLogger(__name__)

TEAM_ROUTE_DEADLINE_SECONDS = 5.0


@dataclass(frozen=True)
class VerifiedTeamRoute:
    team_id: str
    certificate_id: str
    certificate: str
    member_did_key: str
    alias: str
    delivery_origin: str
    expires_at: datetime


def _certificate(encoded: str | None) -> dict:
    if not encoded:
        raise TeamRouteError("local_sender_certificate_required")
    try:
        cert = decode_team_certificate(encoded)
        team = cert.get("team_id")
        domain, name = parse_team_id(team)
        if (build_team_id(canonical_protocol_domain(domain), name) != team
                or cert.get("version") != 1 or cert.get("identity_scope") != "local"
                or cert.get("member_did_aw") or cert.get("member_address")
                or not isinstance(cert.get("alias"), str) or not cert["alias"]
                or "/" in cert["alias"] or not isinstance(cert.get("certificate_id"), str)
                or not cert["certificate_id"] or not isinstance(cert.get("team_did_key"), str)):
            raise ValueError("invalid local certificate")
        return cert
    except (TeamCertificateError, ValueError, TypeError, AttributeError, FederationAuthorityError) as exc:
        raise TeamRouteError("local_sender_certificate_invalid") from exc


def _check_signed_binding(envelope, cert: dict) -> None:
    if cert.get("member_did_key") != envelope.sender_current_did_key:
        raise TeamRouteError("local_sender_certificate_invalid")
    if envelope.content_mode == "encrypted_v2":
        sender = (envelope.encrypted_envelope or {}).get("from") or {}
        team = sender.get("team_id")
        if not team:
            raise TeamRouteError("local_sender_certificate_required")
        if team != cert["team_id"]:
            raise TeamRouteError("local_sender_certificate_invalid")
        label = sender.get("address")
        if label and label != f'{cert["team_id"]}/{cert["alias"]}':
            raise TeamRouteError("local_sender_certificate_invalid")
    else:
        signed = json.loads(envelope.signed_payload)
        label = signed.get("from") or ""
        if "/" not in label or ":" not in label.split("/", 1)[0]:
            raise TeamRouteError("local_sender_certificate_required")
        if label != f'{cert["team_id"]}/{cert["alias"]}':
            raise TeamRouteError("local_sender_certificate_invalid")


async def _cached(work, key: str, read, *, fresh: bool = False):
    result = None if fresh else await work.get_result(key)
    now = datetime.now(timezone.utc)
    if result is not None:
        observed = datetime.fromisoformat(result.evidence["observed_at"])
        if observed + timedelta(seconds=60) > now:
            return result.evidence["value"], min(result.expires_at, observed + timedelta(seconds=60))
    lease = await work.acquire_lease(key, owner_id=uuid4(), ttl_seconds=10)
    if not lease.acquired:
        result = await work.wait_for_result(key, deadline_seconds=5)
        if result is None:
            raise TeamRouteError("federation_authority_coordination_unavailable")
        observed = datetime.fromisoformat(result.evidence["observed_at"])
        expires = min(result.expires_at, observed + timedelta(seconds=60))
        if expires <= datetime.now(timezone.utc):
            raise TeamRouteError("federation_authority_coordination_unavailable")
        return result.evidence["value"], expires
    cancelled = False
    try:
        # Start the bound before the network read and any publication wait.
        observed = datetime.now(timezone.utc)
        value = await read()
        result = await work.publish_result(
            lease, status="verified", evidence={"value": value, "observed_at": observed.isoformat()}, ttl_seconds=60,
        )
        return value, min(result.expires_at, observed + timedelta(seconds=60))
    except asyncio.CancelledError:
        cancelled = True
        raise
    finally:
        # Cancellation must not acquire another pool connection while Phase B
        # holds one. An abandoned lease expires after its existing ten-second TTL.
        if not cancelled:
            await work.release_lease(lease)


async def verify_team_route(request, certificate: str, *, fresh: bool = False, membership_only: bool = False) -> VerifiedTeamRoute:
    """Verify an exact stored certificate without treating custody as authority."""
    try:
        # One wall-clock budget includes home HTTP, DNS, both evidence reads,
        # pool acquisition, lease coordination and result publication.
        async with asyncio.timeout(TEAM_ROUTE_DEADLINE_SECONDS):
            return await _verify_team_route(request, certificate, fresh=fresh, membership_only=membership_only)
    except TimeoutError as exc:
        raise TeamRouteError("federation_authority_coordination_unavailable") from exc


async def _verify_team_route(request, certificate: str, *, fresh: bool, membership_only: bool) -> VerifiedTeamRoute:
    cert = _certificate(certificate)
    team, cert_id = cert["team_id"], cert["certificate_id"]
    domain, name = parse_team_id(team)
    registry = getattr(request.app.state, "awid_registry_client", None)
    authority = getattr(request.app.state, "federation_authority", None)
    if registry is None or authority is None:
        raise TeamRouteError("federation_authority_coordination_unavailable")
    try:
        home = await registry.get_home_namespace(domain)
        if home is not None:
            if home.domain != domain or home.verification_status != "verified" or not home.controller_did:
                raise TeamRouteError("sender_registry_protocol_invalid")
            origin = canonical_server_origin(registry.registry_url)
            async def read(suffix, reason):
                try:
                    return await registry.get_home_team_object(domain, name, suffix)
                except RegistryError as exc:
                    if exc.status_code == 404:
                        raise TeamRouteError(reason) from exc
                    raise
        else:
            selected = await authority._discover_registry_authority(domain)
            if selected.selection != "dns":
                # Address discovery can select the public default. A local
                # team's return route requires its home or DNS-selected AWID.
                raise TeamRouteError("sender_registry_unresolvable")
            origin = selected.registry_origin
            async def read(suffix, reason):
                return await authority.resolver.fetch_team_object(
                    team, suffix, authority=selected, not_found_reason=reason,
                )
        def scope(kind, *parts):
            raw = json.dumps([origin, team, *parts], separators=(",", ":")).encode()
            return f"team-route:{kind}:" + hashlib.sha256(raw).hexdigest()
        status, status_expiry = await _cached(
            authority.work, scope("status", cert_id),
            lambda: read(f"certificates/{escaped_path_component(cert_id)}/status", "local_sender_certificate_revoked"),
            fresh=fresh,
        )
        if not isinstance(status, dict) or status.get("team_id") != team:
            raise TeamRouteError("sender_registry_protocol_invalid")
        if status.get("status") == "revoked":
            raise TeamRouteError("local_sender_certificate_revoked")
        if status.get("status") != "active":
            raise TeamRouteError("sender_registry_protocol_invalid")
        if status.get("team_did_key") != cert["team_did_key"]:
            raise TeamRouteError("local_sender_team_key_stale")
        try:
            verify_team_certificate_signature(cert, status["team_did_key"])
        except TeamCertificateError as exc:
            raise TeamRouteError("local_sender_certificate_invalid") from exc
        if membership_only:
            return VerifiedTeamRoute(team, cert_id, certificate, cert["member_did_key"], cert["alias"], "", status_expiry)
        record, record_expiry = await _cached(
            authority.work, scope("server"),
            lambda: read("server", "local_sender_team_server_missing"), fresh=fresh,
        )
        try:
            verified = verify_team_server_record(
                record.get("record"), record.get("signature"), team_id=team,
                current_team_did_key=status["team_did_key"], now=datetime.now(timezone.utc),
            )
        except (TeamServerRecordError, AttributeError) as exc:
            raise TeamRouteError("local_sender_team_server_missing") from exc
        return VerifiedTeamRoute(
            team, cert_id, certificate, cert["member_did_key"], cert["alias"],
            verified.audience, min(status_expiry, record_expiry),
        )
    except FederationAuthorityError as exc:
        raise TeamRouteError(exc.reason, team=team, domain=domain) from exc
    except Exception as exc:
        logger.warning("Team return-route registry dependency failed", exc_info=True)
        raise TeamRouteError("sender_registry_unavailable") from exc


async def authorize_local_sender(request, envelope, *, stored_team_id=None, outbound=False, fresh=False):
    cert = _certificate(envelope.sender_certificate)
    _check_signed_binding(envelope, cert)
    if stored_team_id and cert["team_id"] != stored_team_id:
        raise TeamRouteError("local_sender_route_mismatch")
    route = await verify_team_route(request, envelope.sender_certificate, fresh=fresh)
    origins = public_origins(request)
    if outbound:
        if route.delivery_origin not in origins:
            raise TeamRouteError("local_sender_team_server_missing")
    elif route.delivery_origin in origins:
        raise TeamRouteError("local_sender_route_mismatch")
    if envelope.sender_delivery_origin and envelope.sender_delivery_origin != route.delivery_origin:
        raise TeamRouteError("local_sender_route_mismatch")
    return route


async def authorize_outbound_local_sender(request, envelope, db):
    """Preflight first contact; existing conversations retain receiver authority.

    A presented certificate on a continuation is forwarded unchanged. Only the
    receiver knows whether its participant is legacy or requires team re-vouching.
    A caller-selected conversation UUID alone does not establish continuation.
    """
    manager = db.get_manager("aweb") if hasattr(db, "get_manager") else db
    established = await manager.fetch_value(
        """
        SELECT EXISTS (
            SELECT 1 FROM {{tables.conversation_participants}} sender
            JOIN {{tables.conversation_participants}} target
              ON target.conversation_id = sender.conversation_id
            JOIN {{tables.conversations}} c ON c.conversation_id = sender.conversation_id
            WHERE c.conversation_id = $1 AND c.conversation_type = $2
              AND sender.did = $3 AND target.did = $4
        )
        """,
        UUID(envelope.conversation_id), envelope.type,
        envelope.sender_did_aw, envelope.target_did_aw,
    ) if envelope.conversation_id else False
    if not established:
        await authorize_local_sender(request, envelope, outbound=True)


def outbound_certificate(request) -> str | None:
    proof = getattr(getattr(request, "state", None), "sender_certificate", None)
    return proof if proof is not None else request.headers.get("X-AWID-Team-Certificate")


async def refresh_recipient_team_route(request, participant: dict) -> dict:
    """Revalidate a learned local route for a reply; never write its projection."""
    if not participant.get("route_team_id"):
        return participant
    try:
        route = await verify_team_route(request, participant.get("route_certificate"))
        did = participant.get("did") or participant.get("did_aw") or participant.get("did_key")
        if (route.team_id != participant["route_team_id"] or route.member_did_key != did
                or route.certificate_id != participant.get("route_certificate_id")):
            raise TeamRouteError("local_recipient_route_missing")
    except FederationAuthorityError as exc:
        if not exc.retryable:
            raise TeamRouteError("local_recipient_route_missing") from exc
        raise
    return {**participant, "delivery_origin": route.delivery_origin,
            "_route_previous_origin": participant.get("_route_previous_origin", participant.get("delivery_origin")),
            "_route_verified_origin": route.delivery_origin,
            "current_did_key": route.member_did_key, "did_key": route.member_did_key,
            "address": None}


async def persist_accepted_team_route(db, participant: dict, conversation_id: str) -> None:
    """Advance a reply route only after delivery, without clobbering a renewal."""
    origin = participant.get("_route_verified_origin")
    if not participant.get("route_team_id") or not origin:
        return
    did = participant.get("did") or participant.get("did_aw") or participant.get("did_key")
    cid = UUID(str(conversation_id))
    proof = (participant["route_team_id"], participant["route_certificate_id"], participant["route_certificate"])
    async with db.get_manager("aweb").transaction() as tx:
        current = await tx.fetch_one(
            "SELECT delivery_origin,route_team_id,route_certificate_id,route_certificate "
            "FROM {{tables.conversation_participants}} WHERE conversation_id=$1 AND did=$2 FOR UPDATE", cid, did,
        )
        if current is None or tuple(current[key] for key in (
            "route_team_id", "route_certificate_id", "route_certificate",
        )) != proof or current["delivery_origin"] != participant.get("_route_previous_origin"):
            return  # An accepted newer message already supplied another route.
        await tx.execute(
            "UPDATE {{tables.conversation_participants}} SET delivery_origin=$3,transport_hint=$4 "
            "WHERE conversation_id=$1 AND did=$2", cid, did, origin, "federation:" + origin,
        )
        await tx.execute(
            "UPDATE {{tables.chat_participants}} SET delivery_origin=$3 "
            "WHERE session_id=$1 AND did=$2 AND route_team_id=$4 AND route_certificate_id=$5 AND route_certificate=$6",
            cid, did, origin, *proof,
        )
