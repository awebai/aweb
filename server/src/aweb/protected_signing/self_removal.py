"""The existing team-auth v2 proof, scoped only to one self-removal.

Current members may leave themselves. A revoked certificate can recover only
its already-retained exact removal; its actor is explicitly read-only and
cannot sign or release a mutation. No ordinary membership is restored.
"""

import hashlib
import re

from aweb_naapp.runtime.protected_signer import ReceiptReader, RestrictedRequester, SignerRefused
from aweb_naapp.runtime.protected_signer.types import _admitted_self_removal
from awid.dns_auth import enforce_timestamp_skew, parse_didkey_auth, require_timestamp
from awid.signing import canonical_json_bytes, verify_did_key_signature
from awid.team_certificate import TeamCertificateError, check_team_certificate, decode_team_certificate, verify_team_certificate_signature

from aweb.team_auth_envelope import team_auth_signature_payload

from .admission import _registry
from .removal import agent_target, current_member, membership_fields

_LABELS = {"prepare": ("POST", "protected_operation_prepare"),
    "execute": ("POST", "protected_operation_execute"), "receipt": ("GET", "protected_operation_receipt")}
_FIELDS = {"v", "aud", "method", "path", "team_id", "timestamp", "body_sha256", "operation", "service_id", "scope_sha256"}


async def self_requester(c, request, operation, *, purpose):
    # These are mutually exclusive proof kinds for this new operation.
    if ("X-AWEB-DID-AW" in request.headers or request.headers.get("cookie")
        or request.scope.get("query_string") or purpose not in _LABELS):
        raise SignerRefused("requester_invalid")
    certificate = request.headers.get("X-AWID-Team-Certificate", "")
    if not certificate or len(certificate) > 16384:
        raise SignerRefused("requester_invalid")
    started = c.authority.timer()
    try:
        key, signature = parse_didkey_auth(request.headers.get("Authorization"))
        if not re.fullmatch(r"[A-Za-z0-9+/]{86}", signature):
            raise ValueError()
        timestamp = require_timestamp(request)
        enforce_timestamp_skew(timestamp)
        # Shared HTTP parsing has already enforced the prepare-body bound.
        # Other accepted methods require genuinely empty body bytes.
        body = await request.body()
        method, label = _LABELS[purpose]
        if request.method != method or (purpose != "prepare" and body):
            raise ValueError()
        envelope = team_auth_signature_payload(request, team_id=c.context.authority_id,
            timestamp=timestamp, body_sha256=hashlib.sha256(body).hexdigest(), allowed_audiences=[c.request_origin])
        payload = envelope.payload
        if (envelope.version != 2 or set(payload) != _FIELDS or type(payload["v"]) is not int
            or payload["aud"] != c.request_origin or payload["team_id"] != c.context.authority_id
            or payload["operation"] != label or payload["service_id"] != c.context.service_id
            or payload["scope_sha256"] != hashlib.sha256(canonical_json_bytes(operation.context.fields())).hexdigest()):
            raise ValueError()
        verify_did_key_signature(did_key=key, payload=envelope.canonical_payload, signature_b64=signature)
        cert = decode_team_certificate(certificate)
        principal = cert.get("member_did_aw") or key
    except (ValueError, TypeError, KeyError, TeamCertificateError):
        raise SignerRefused("requester_invalid") from None
    retained = await c.signer.lookup_owned_self_removal(operation.operation_id, principal=principal,
        key_did=key, certificate_id=cert.get("certificate_id"))
    selected = retained if retained is not None else operation
    intent, context = selected.intent(), selected.context
    expected_context, selected_context = c.context.fields(), context.fields()
    if purpose == "receipt":
        expected_context.pop("generation")
        selected_context.pop("generation")
    subject = intent["subject"]
    if (intent["operation"] != "team.agent.remove" or subject["root_id_or_self"] != "self"
        or subject["member_id"] != principal or subject["certificate_id"] != cert.get("certificate_id")
        or selected_context != expected_context
        or cert.get("team_id") != context.authority_id or cert.get("member_did_key") != key):
        raise SignerRefused("scope_refused")
    if selected.audience != c.registry.registry_url:
        raise SignerRefused("scope_refused")
    name, domain = context.authority_id.split(":", 1)
    controller = await _registry(c.registry.get_team_public_key_fresh(domain, name), missing="authority_changed")
    if controller != c.authority.custody.team_key_did or cert.get("team_did_key") != controller:
        raise SignerRefused("authority_changed")
    record = await current_member(c, selected)
    if record is None:
        raise SignerRefused("subject_ineligible")
    historical = record.revoked_at is not None
    try:
        if historical:
            if retained is None or cert.get("version") != 1 or membership_fields(cert) != membership_fields(record):
                raise SignerRefused("scope_refused")
            # Historical proof is not represented as active membership. The
            # existing key verifies the certificate; exact registry fields and
            # the original owned request bound the read-only recovery port.
            verify_team_certificate_signature(cert, controller)
        else:
            checked = check_team_certificate(certificate, subject_did_key=key, team_did_key=controller,
                revoked_certificate_ids=set(), registered_certificate_ids={record.certificate_id})
            if membership_fields(checked) != membership_fields(record):
                raise SignerRefused("scope_refused")
    except TeamCertificateError:
        raise SignerRefused("requester_invalid") from None
    await agent_target(c, record, self_key=key)
    enforce_timestamp_skew(timestamp)
    deadline = started + 60
    if c.authority.timer() > deadline:
        raise SignerRefused("evidence_unavailable")
    cap = _admitted_self_removal(selected, principal=principal, key_did=key, deadline=deadline, read_only=historical)
    actor = ReceiptReader if purpose == "receipt" else RestrictedRequester
    return actor(principal, context, key_did=key, self_removal=cap)
