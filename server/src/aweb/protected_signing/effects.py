"""Local typed retention and pinned delivery; no operation-name dispatch."""

import base64
import json
from datetime import UTC, timedelta
from types import MappingProxyType

from aweb_naapp.runtime.protected_signer import SignerRefused
from aweb_naapp.runtime.protected_signer.retention import EffectConfirmation, FrozenDelivery, RetainedEffect
from .legacy_delivery import authenticate_plan, delivery_plan
from awid.protected_effect import HEADER, artifact_digest, encode_proofs, http_consumer, issue_proof
from awid.protected_receipts import PATH


def _raw(signature):
    return base64.b64encode(signature).rstrip(b"=").decode()


def _stamp(value):
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class ProtectedEffectCustody:
    def configure_effects(self, *, registry, clients, clock):
        """Host-owned clients only; never a worker-selected origin or transport."""
        self._effect_registry = registry
        self._effect_clients = MappingProxyType(dict(clients))
        self._effect_clock = clock

    def retain_authorized_effect(self, *, operation, request, artifact, signing, signature, authority, expires_at):
        if operation.context.authority_kind != "team_controller":
            return None  # No team-controller consumer (e.g. human root endorsement).
        observation = getattr(authority, "protection", None)
        if observation is None:
            raise SignerRefused("evidence_unavailable")
        authority.require_fresh()
        if not observation.protected:
            return None
        binding = observation.binding
        if (binding["service_id"] != self.service_id or binding["service_did_key"] != self.service_did_key
            or self._service_key is None):
            raise SignerRefused("custody_not_isolated")
        if operation.audience not in getattr(self, "_effect_clients", {}):
            raise SignerRefused("operation_not_served")
        now = self._effect_clock()
        until = expires_at.astimezone(UTC).replace(microsecond=0)
        if now >= until:
            raise SignerRefused("operation_expired")
        plan = delivery_plan(self, operation, artifact, signing, signature, _stamp(now))
        delivery = authenticate_plan(self, plan)
        digest = artifact_digest(signing, _raw(signature))
        fields = {
            "v": 1, "type": "aweb.protected-effect", "service_id": self.service_id,
            "team_id": observation.team_id, "history_id": binding["history_id"], "generation": binding["generation"],
            "controller_did_key": self.team_key_did, "operation": operation.operation, "variant": operation.variant,
            "operation_id": operation.operation_id, "artifact_type": plan.artifact_type, "artifact_sha256": digest,
            "consumer": http_consumer(audience=delivery.audience, method=delivery.method, path=delivery.path,
                body=delivery.body, controller_envelope=plan.controller_envelope or b""),
            "issued_at": _stamp(now), "expires_at": _stamp(until),
        }
        header = encode_proofs([issue_proof(fields, bytes(self._service_key))])
        frozen = FrozenDelivery(delivery.audience, delivery.method, delivery.path, {**delivery.headers, HEADER: header}, delivery.body)
        authority.require_fresh()
        return RetainedEffect(operation.operation_id, signing, signature, digest, until, frozen, header)

    async def _request_effect(self, delivery, *, receipt=False, operation_id=None):
        client = getattr(self, "_effect_clients", {}).get(delivery.audience)
        if client is None:
            raise SignerRefused("operation_not_served")
        path = PATH + "/" + operation_id if receipt else delivery.path
        headers = {HEADER: delivery.headers[HEADER]} if receipt else dict(delivery.headers)
        # No redirect forwarding, discovery, retry or regenerated authentication.
        async with client.stream("GET" if receipt else delivery.method, delivery.audience + path,
            headers=headers, content=None if receipt else delivery.body, follow_redirects=False) as response:
            if receipt and response.status_code == 404:
                return None
            if not 200 <= response.status_code < 300:
                raise SignerRefused("evidence_unavailable")
            if not receipt:
                return None
            body = bytearray()
            async for chunk in response.aiter_bytes():
                body.extend(chunk)
                if len(body) > 1024:
                    raise SignerRefused("evidence_unavailable")
        return bytes(body)

    async def deliver_retained(self, operation, retained):
        # The engine rechecks current authority before claiming release; the
        # actual consumer independently checks the current proof generation.
        if operation.operation_id != retained.operation_id or self._effect_clock() >= retained.expires_at:
            raise SignerRefused("operation_expired")
        await self._request_effect(retained.delivery)

    async def confirm_retained(self, operation, retained):
        started = self._effect_clock()
        raw = await self._request_effect(retained.delivery, receipt=True, operation_id=operation.operation_id)
        if raw is None:
            return None  # Unresolved, never evidence permitting another release.
        def pairs(items):
            result = {}
            for key, value in items:
                if key in result:
                    raise ValueError()
                result[key] = value
            return result
        try:
            result = json.loads(raw, object_pairs_hook=pairs)
            if (type(result) is not dict or set(result) != {"v", "operation_id", "artifact_sha256"}
                or type(result["v"]) is not int or result["v"] != 1
                or result["operation_id"] != retained.operation_id or operation.operation_id != retained.operation_id
                or result["artifact_sha256"] != retained.artifact_sha256):
                raise ValueError()
        except (ValueError, TypeError, UnicodeError):
            raise SignerRefused("evidence_unavailable") from None
        until = started + timedelta(seconds=60)
        if self._effect_clock() >= until:
            raise SignerRefused("evidence_unavailable")
        return EffectConfirmation(retained.operation_id, retained.artifact_sha256, until)

