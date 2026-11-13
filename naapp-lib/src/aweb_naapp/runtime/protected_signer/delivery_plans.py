"""Closed consumer requests built by operation definitions inside custody.

These builders accept only a typed intent and its verified signed artifact.
They do not accept a caller-selected route, HTTP body or controller envelope.
Authentication and service attestation are retained before any network release.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field

from awid.id_tree_requests import covering_payload
from awid.signing import canonical_json_bytes, verify_did_key_signature
from awid.utc_timestamps import parse_utc_seconds

from .retention import FrozenDelivery


def _raw(signature: bytes) -> str:
    if type(signature) is not bytes or len(signature) != 64:
        raise ValueError("invalid controller signature")
    return base64.b64encode(signature).rstrip(b"=").decode()


@dataclass(frozen=True)
class DeliveryPlan:
    audience: str
    method: str
    path: str
    body: bytes = field(repr=False)
    artifact_type: str
    controller_did: str
    controller_envelope: bytes | None = field(default=None, repr=False)

    def authenticate(self, signature: bytes | None = None) -> FrozenDelivery:
        """Validate the exact prepared envelope; this never signs or sends."""
        headers = {"Content-Type": "application/json"}
        if self.controller_envelope is None:
            if signature is not None:
                raise ValueError("this consumer has no separate controller envelope")
        else:
            fields = json.loads(self.controller_envelope)
            timestamp = fields["timestamp"]
            parse_utc_seconds(timestamp)
            expected = covering_payload(aud=self.audience, path=self.path, domain=fields["domain"],
                operation=fields["operation"], body=self.body, timestamp=timestamp,
                claims={"team_name": fields["team_name"], "certificate_id": fields["certificate_id"]})
            if self.method != "POST" or expected != self.controller_envelope:
                raise ValueError("controller envelope does not bind the exact delivery")
            if signature is None:
                raise ValueError("controller envelope needs request authentication")
            raw = _raw(signature)
            try:
                verify_did_key_signature(did_key=self.controller_did, payload=expected, signature_b64=raw)
            except Exception as error:
                raise ValueError("invalid delivery authentication") from error
            headers.update({"Authorization": f"DIDKey {self.controller_did} {raw}",
                "X-AWEB-Timestamp": timestamp,
                "X-AWEB-Signed-Payload": base64.urlsafe_b64encode(expected).rstrip(b"=").decode()})
        return FrozenDelivery(self.audience, self.method, self.path, headers, self.body)


def _verified(operation, artifact, signing, signature):
    codec = operation.spec.codec
    if type(signing) is not bytes or codec.signing_bytes(operation, artifact) != signing:
        raise ValueError("delivery changed the signed artifact")
    controller = artifact[codec.authority_field]
    try:
        verify_did_key_signature(did_key=controller, payload=signing, signature_b64=_raw(signature))
    except Exception as error:
        raise ValueError("invalid artifact signature") from error
    return controller


def owner_act_delivery(operation, artifact, signing, signature, timestamp):
    controller = _verified(operation, artifact, signing, signature)
    body = canonical_json_bytes({"signing": base64.b64encode(signing).decode(), "signature": _raw(signature)})
    return DeliveryPlan(operation.audience, "POST", "/.well-known/aweb-owner-act", body,
        "owner-act", controller)


def certificate_delivery(operation, artifact, signing, signature, timestamp):
    controller = _verified(operation, artifact, signing, signature)
    parse_utc_seconds(timestamp)
    name, domain = artifact["team_id"].split(":", 1)
    path = f"/v1/namespaces/{domain}/teams/{name}/certificates"
    certificate = {**artifact, "signature": _raw(signature)}
    body = canonical_json_bytes({"certificate_id": artifact["certificate_id"],
        "member_did_key": artifact["member_did_key"], "member_did_aw": artifact.get("member_did_aw"),
        "member_address": None, "alias": artifact["alias"], "identity_scope": artifact["identity_scope"],
        "certificate": base64.b64encode(canonical_json_bytes(certificate)).decode()})
    envelope = covering_payload(aud=operation.audience, path=path, domain=domain,
        operation="register_certificate", body=body, timestamp=timestamp,
        claims={"team_name": name, "certificate_id": artifact["certificate_id"]})
    return DeliveryPlan(operation.audience, "POST", path, body, "team-certificate", controller, envelope)


def revocation_delivery(operation, artifact, signing, signature, timestamp):
    controller = _verified(operation, artifact, signing, signature)
    body = canonical_json_bytes({"certificate_id": operation.intent()["subject"]["certificate_id"]})
    # The artifact already IS the exact covering-v2 revoke envelope. Preserve
    # its timestamp/signature even when a later retention call supplies now.
    return DeliveryPlan(operation.audience, "POST", artifact["request"]["path"], body,
        "controller-request", controller, signing)
