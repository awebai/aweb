"""Typed controller operations shared by custody-owning holders.

No caller eligibility or key custody is inferred from a descriptor. A signer
receives a typed immutable operation, never caller-selected bytes or a URL.
Legacy HTTP proofs are intentionally unchanged: their destination/body may
not be signed, so the holder must retain the entire HTTP exchange.
"""

from __future__ import annotations

import base64
import hashlib
import inspect
import json
import re
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Literal
from urllib.parse import quote, urlencode

from awid.did import public_key_from_did
from awid.atomic_claim import (
    ATOMIC_ADDRESS_CLAIM_OPERATION,
    AtomicAddressClaimFields,
    atomic_address_claim_identity_canonical,
    atomic_address_claim_identity_proof_hash,
    atomic_address_claim_namespace_canonical,
    normalize_atomic_address_claim_fields,
)
from awid.id_certificates import (
    id_certificate_signing_bytes,
    validate_id_certificate,
    verify_ed25519,
)
from awid.id_tree_requests import (
    covering_payload,
    revoke_body,
    rotate_body,
    rotate_claims,
)
from awid.log import canonical_server_origin, identity_state_hash, log_entry_payload
from awid.registry_paths import address_segment
from awid.registry_types import RegistryError
from awid.signing import canonical_json_bytes, verify_did_key_signature
from awid.team_certificate import check_team_certificate
from awid.team_ids import build_team_id
from awid.team_server_record import (
    RECORD_FIELDS,
    canonical_team_server_url,
    record_signing_bytes,
)
from awid.utc_timestamps import parse_utc_seconds


class ControllerSigningError(ValueError):
    """Local refusal; no request has been sent. Messages contain no inputs."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class ControllerRequestUncertain(RegistryError):
    """A submitted mutation may have applied. Reconcile; do not retry blindly."""

    def __init__(self, request):
        super().__init__(
            "Controller request outcome is unknown",
            status_code=503,
            code="controller_outcome_unknown",
        )
        self.operation = request.operation
        self.request_digest = request.digest


def _require(condition, code="request_invalid"):
    if not condition:
        raise ControllerSigningError(code)


def _domain_label(value):
    return (
        type(value) is str
        and bool(value)
        and len(value) <= 253
        and re.fullmatch(r"[a-z0-9][a-z0-9_-]*", value) is not None
    )


def _team_name(value):
    return (
        type(value) is str
        and 1 <= len(value) <= 128
        and re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?", value) is not None
    )


def _alias(value):
    # Existing product alias profile (server input_validation, auth, aw).
    return (
        type(value) is str
        and re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}", value) is not None
    )


def _address_name(value):
    # The registry imposes length, not a team/alias character profile.
    return type(value) is str and 1 <= len(value) <= 256


def _domain(value):
    _require(
        type(value) is str
        and len(value) <= 253
        and all(_domain_label(p) and "_" not in p for p in value.split(".")),
        "domain_invalid",
    )


def _key(value):
    try:
        public_key_from_did(value)
    except (TypeError, ValueError) as exc:
        raise ControllerSigningError("key_invalid") from exc


def _portable(value):
    if value is None or type(value) in (str, bool, int):
        return
    if type(value) is list:
        for child in value:
            _portable(child)
        return
    if type(value) is dict and all(type(k) is str for k in value):
        for child in value.values():
            _portable(child)
        return
    raise ControllerSigningError("request_invalid")


def _snapshot(value):
    try:
        _portable(value)
        raw = canonical_json_bytes(value)
        _require(len(raw) <= 4 * 1024 * 1024)
        return raw
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        if isinstance(exc, ControllerSigningError):
            raise
        raise ControllerSigningError("request_invalid") from exc


@dataclass(frozen=True)
class ControllerDescriptor:
    scope: Literal["namespace", "team"]
    domain: str
    did_key: str
    key_reference: str
    generation: int
    team: str | None = None

    def __post_init__(self):
        _domain(self.domain)
        _key(self.did_key)
        _require(self.scope in ("namespace", "team"), "controller_scope")
        _require(
            type(self.key_reference) is str and bool(self.key_reference),
            "controller_invalid",
        )
        _require(
            type(self.generation) is int and self.generation >= 0, "controller_invalid"
        )
        _require(
            (_team_name(self.team) if self.scope == "team" else self.team is None),
            "controller_scope",
        )


# Operation -> (required fields, optional fields, signer scope). These are SDK
# operation names, not a new registry wire format or a holder's permission table.
_REQUESTS = {
    "namespace_register": (
        "controller_did",
        "parent_domain default_delivery_origin",
        "namespace",
    ),
    "namespace_update": ("default_delivery_origin", "", "namespace"),
    "namespace_delete": ("", "reason", "namespace"),
    "namespace_rotate": ("from_seq previous_did_key new_did_key", "", "namespace"),
    "namespace_reset": ("new_controller_did", "parent_domain", "namespace"),
    "team_register": ("name display_name team_did_key visibility", "", "namespace"),
    "team_rotate": ("name new_team_did_key", "resigned_records", "namespace"),
    "team_visibility": ("name visibility", "", "team"),
    "team_delete": ("name", "", "namespace"),
    "certificate_register": ("name certificate", "", "team"),
    "certificate_revoke": ("name certificate_id", "", "team"),
    "address_register": ("name did_aw current_did_key", "", "namespace"),
    "address_update": ("name", "", "namespace"),
    "address_delete": ("name", "", "namespace"),
    "address_reassign": ("name did_aw current_did_key", "", "namespace"),
    "id_revoke": ("id expected_head", "effective_from", "namespace"),
    "team_read": ("name", "", "team"),
    "certificate_list": ("name", "active_only cursor limit", "team"),
    "member_read": ("name alias", "", "team"),
    "revocations_read": ("name", "cursor limit since", "team"),
    "server_publish": ("name record", "", "team"),
    "address_claim": (
        "address_name did_aw current_did_key timestamp dry_run identity_custody namespace_custody identity_signature",
        "did_log_proof",
        "namespace",
    ),
}
_OBJECTS = {
    "team_certificate_issue": ("name certificate", "", "team"),
    "namespace_id_issue": ("kind certificate", "", "namespace"),
    "team_server_sign": ("name record", "", "team"),
    "address_replacement": (
        "address controller_did old_did new_did timestamp",
        "",
        "namespace",
    ),
    "address_claim_proof": (
        "address_name did_aw current_did_key timestamp dry_run identity_custody namespace_custody identity_signature",
        "did_log_proof",
        "namespace",
    ),
}


def _validate(operation, domain, parameters, definitions):
    _domain(domain)
    _require(operation in definitions, "operation_invalid")
    required, optional, _ = definitions[operation]
    _require(
        type(parameters) is dict
        and set(required.split()) <= parameters.keys()
        and parameters.keys() <= set((required + " " + optional).split())
    )
    for name, value in parameters.items():
        if name == "name":
            _require(
                _address_name(value)
                if operation.startswith("address_")
                else _team_name(value)
            )
        elif name == "alias":
            _require(_alias(value))
        elif name == "address_name":
            _require(_address_name(value))
        elif name in (
            "controller_did",
            "new_controller_did",
            "previous_did_key",
            "new_did_key",
            "team_did_key",
            "new_team_did_key",
            "current_did_key",
            "old_did",
            "new_did",
        ):
            _key(value)
        elif name == "parent_domain":
            _domain(value)
            _require(domain.endswith("." + value), "controller_scope")
        elif name == "visibility":
            _require(value in ("public", "private"))
        elif name == "from_seq":
            _require(type(value) is int and value >= 0)
        elif name == "limit":
            _require(type(value) is int and 1 <= value <= 200)
        elif name in ("active_only", "dry_run"):
            _require(type(value) is bool)
        elif name == "default_delivery_origin" and value is not None:
            _require(canonical_server_origin(value) == value)
        elif name in ("timestamp", "since", "effective_from") and value is not None:
            parse_utc_seconds(value)
        elif name in ("id", "did_aw"):
            from awid.did import validate_stable_id

            _require(validate_stable_id(value) == value)
        elif name in ("cursor", "certificate_id", "display_name", "address"):
            _require(type(value) is str and 0 < len(value) <= 8192)
        elif name in ("reason", "expected_head"):
            _require(value is None or type(value) is str)
    if operation == "namespace_id_issue":
        c = parameters["certificate"]
        try:
            validate_id_certificate(c)
            _require(
                parameters["kind"] in ("human", "agent")
                and c["kind"] == parameters["kind"]
                and c["domain"] == domain
                and c["parent"] == {"kind": "namespace", "id": domain},
                "object_invalid",
            )
        except (ValueError, TypeError, KeyError) as exc:
            raise ControllerSigningError("object_invalid") from exc
    if operation in ("team_server_sign", "server_publish"):
        r = parameters["record"]
        _require(
            type(r) is dict
            and set(r) == RECORD_FIELDS
            and r["v"] == 1
            and type(r["v"]) is int
            and r["type"] == "aweb.team-server"
            and r["team_id"] == build_team_id(domain, parameters["name"]),
            "object_invalid",
        )
        canonical_team_server_url(r["server_url"])
        _key(r["team_did_key"])
        parse_utc_seconds(r["issued_at"])
    if operation == "team_certificate_issue":
        c = parameters["certificate"]
        required = {
            "version",
            "certificate_id",
            "team_id",
            "team_did_key",
            "member_did_key",
            "alias",
            "issued_at",
        }
        _require(
            type(c) is dict
            and required <= c.keys()
            and c.keys()
            <= required
            | {
                "member_did_aw",
                "member_address",
                "team_did_key",
                "lifetime",
                "identity_scope",
                "issued_at",
            }
            and type(c["version"]) is int
            and c["version"] == 1
            and c["team_id"] == build_team_id(domain, parameters["name"])
            and c.get("identity_scope", c.get("lifetime")) in ("local", "global")
            and _alias(c["alias"])
            and type(c["certificate_id"]) is str,
            "object_invalid",
        )
        _key(c["member_did_key"])
        if "issued_at" in c:
            parse_utc_seconds(c["issued_at"])
    if operation == "certificate_register":
        from awid.team_certificate import decode_team_certificate

        c = decode_team_certificate(parameters["certificate"])
        _require(
            c["team_id"] == build_team_id(domain, parameters["name"]), "object_invalid"
        )
    if operation == "team_rotate" and parameters.get("resigned_records") is not None:
        records = parameters["resigned_records"]
        _require(
            type(records) is dict
            and records.keys()
            <= {"team_server", "team_custodians", "member_custody", "member_person"}
        )
        for name, entries in records.items():
            entries = [entries] if name == "team_server" else entries
            _require(type(entries) is list)
            for entry in entries:
                if entry is None and name == "team_server":
                    continue
                _require(
                    type(entry) is dict
                    and set(entry) == {"record", "signature"}
                    and type(entry["record"]) is dict
                    and type(entry["signature"]) is str
                )
    if operation == "address_replacement":
        _require(parameters["address"].startswith(domain + "/"), "object_invalid")


@dataclass(frozen=True, init=False)
class ControllerRequest:
    operation: str
    domain: str
    _parameters: bytes = field(repr=False)

    def __init__(self, operation, domain, parameters):
        raw = _snapshot(parameters)
        _validate(operation, domain, json.loads(raw), _REQUESTS)
        object.__setattr__(self, "operation", operation)
        object.__setattr__(self, "domain", domain)
        object.__setattr__(self, "_parameters", raw)

    @property
    def parameters(self):
        return json.loads(self._parameters)

    @property
    def digest(self):
        return hashlib.sha256(
            _snapshot(
                {"operation": self.operation, "domain": self.domain, **self.parameters}
            )
        ).hexdigest()


@dataclass(frozen=True, init=False)
class ControllerObjectRequest:
    operation: str
    domain: str
    _parameters: bytes = field(repr=False)

    def __init__(self, operation, domain, parameters):
        raw = _snapshot(parameters)
        _validate(operation, domain, json.loads(raw), _OBJECTS)
        object.__setattr__(self, "operation", operation)
        object.__setattr__(self, "domain", domain)
        object.__setattr__(self, "_parameters", raw)

    @property
    def parameters(self):
        return json.loads(self._parameters)


def _parse(value, cls):
    try:
        _require(type(value) is dict and {"operation", "domain"} <= value.keys())
        return cls(
            value["operation"],
            value["domain"],
            {k: v for k, v in value.items() if k not in ("operation", "domain")},
        )
    except ControllerSigningError:
        raise
    except (TypeError, ValueError, KeyError) as exc:
        raise ControllerSigningError("request_invalid") from exc


def parse_controller_request(value) -> ControllerRequest:
    return _parse(value, ControllerRequest)


def parse_controller_object(value) -> ControllerObjectRequest:
    return _parse(value, ControllerObjectRequest)


def signature_roles(request):
    if request.operation == "namespace_rotate":
        return ("controller", "new_controller")
    return (
        ("controller", "parent")
        if "parent_domain" in request.parameters
        else ("controller",)
    )


def _check_controller(request, controller, role):
    _require(type(controller) is ControllerDescriptor, "controller_invalid")
    _require(role in signature_roles(request), "controller_role")
    p = request.parameters
    definitions = _REQUESTS if type(request) is ControllerRequest else _OBJECTS
    scope = definitions[request.operation][2]
    domain = p["parent_domain"] if role == "parent" else request.domain
    _require(
        controller.domain == domain
        and controller.scope == scope
        and (scope != "team" or controller.team == p["name"]),
        "controller_scope",
    )
    expected = None
    if request.operation == "namespace_rotate":
        expected = p["new_did_key" if role == "new_controller" else "previous_did_key"]
    elif role == "controller" and request.operation in (
        "namespace_register",
        "namespace_reset",
    ):
        expected = p[
            "controller_did"
            if request.operation == "namespace_register"
            else "new_controller_did"
        ]
    elif request.operation == "namespace_id_issue":
        expected = p["certificate"]["issuer_key"]
    elif request.operation in ("team_server_sign", "server_publish"):
        expected = p["record"]["team_did_key"]
    elif request.operation == "address_replacement":
        expected = p["controller_did"]
    _require(expected is None or controller.did_key == expected, "controller_mismatch")
    if request.operation in ("team_certificate_issue", "certificate_register"):
        if request.operation == "certificate_register":
            from awid.team_certificate import decode_team_certificate

            c = decode_team_certificate(p["certificate"])
            check_team_certificate(
                p["certificate"],
                subject_did_key=c["member_did_key"],
                team_did_key=controller.did_key,
                revoked_certificate_ids=(),
                registered_certificate_ids=None,
            )
        else:
            c = p["certificate"]
        _require(
            c.get("team_did_key", controller.did_key) == controller.did_key,
            "controller_mismatch",
        )


@dataclass(frozen=True)
class ControllerHTTPPlan:
    method: str
    path: str
    body: bytes | None
    wire_operation: str
    claims: bytes
    format: Literal["covering", "path", "object"]


def controller_http_plan(request: ControllerRequest) -> ControllerHTTPPlan:
    _require(type(request) is ControllerRequest, "operation_invalid")
    op, d, p = request.operation, request.domain, request.parameters
    base = f"/v1/namespaces/{d}"
    team = base + "/teams/" + p.get("name", "")
    body, claims, fmt = None, {}, "covering"
    if op == "namespace_register":
        method, path, wire = "POST", "/v1/namespaces", "register"
        body = {"domain": d, "controller_did": p["controller_did"]}
        if p.get("default_delivery_origin") is not None:
            body["default_delivery_origin"] = claims["default_delivery_origin"] = p[
                "default_delivery_origin"
            ]
    elif op == "namespace_update":
        method, path, wire = "PATCH", base, "update_namespace"
        body = {"default_delivery_origin": p["default_delivery_origin"]}
        claims = {"default_delivery_origin": p["default_delivery_origin"] or ""}
    elif op == "namespace_delete":
        method, path, wire = "DELETE", base, "delete_namespace"
        body = {"reason": p["reason"]} if "reason" in p else None
    elif op == "namespace_reset":
        method, path, wire = "PUT", base, "rotate_controller"
        body = claims = {"new_controller_did": p["new_controller_did"]}
    elif op == "namespace_rotate":
        claims = rotate_claims(**p)
        return ControllerHTTPPlan(
            "POST",
            base + "/rotate",
            rotate_body(d, claims),
            "rotate_namespace_controller",
            _snapshot(claims),
            "covering",
        )
    elif op == "team_register":
        method, path, wire, body = "POST", base + "/teams", "create_team", p
        claims = {"name": p["name"]}
    elif op == "team_rotate":
        method, path, wire = "POST", team + "/rotate", "rotate_team_key"
        claims = {"name": p["name"], "new_team_did_key": p["new_team_did_key"]}
        body = {k: v for k, v in p.items() if k != "name"}
    elif op == "team_visibility":
        method, path, wire = "POST", team + "/visibility", "set_team_visibility"
        body = {"visibility": p["visibility"]}
        claims = {"team_name": p["name"], **body}
    elif op == "team_delete":
        method, path, wire = "DELETE", team, "delete_team"
        claims = {"team_name": p["name"]}
    elif op == "certificate_register":
        method, path, wire = "POST", team + "/certificates", "register_certificate"
        certificate = p["certificate"]
        from awid.team_certificate import decode_team_certificate

        c = decode_team_certificate(certificate)
        body = {
            k: c.get(k)
            for k in (
                "certificate_id",
                "member_did_key",
                "member_did_aw",
                "member_address",
                "alias",
                "identity_scope",
            )
        }
        body["identity_scope"] = c.get("identity_scope", c.get("lifetime", "global"))
        body["certificate"] = certificate
        claims = {"team_name": p["name"], "certificate_id": c["certificate_id"]}
    elif op == "certificate_revoke":
        method, path, wire = "POST", team + "/certificates/revoke", "revoke_certificate"
        body = {"certificate_id": p["certificate_id"]}
        claims = {"team_name": p["name"], **body}
    elif op == "address_claim":
        return ControllerHTTPPlan(
            "POST",
            base + "/addresses/claims",
            None,
            ATOMIC_ADDRESS_CLAIM_OPERATION,
            b"{}",
            "object",
        )
    elif op.startswith("address_"):
        claims = {"name": p["name"]}
        if op == "address_register":
            method, path, wire, body = (
                "POST",
                base + "/addresses",
                "register_address",
                p,
            )
        elif op == "address_reassign":
            method, path, wire = (
                "POST",
                base + f"/addresses/{address_segment(p['name'])}/reassign",
                "reassign_address",
            )
            body = {k: p[k] for k in ("did_aw", "current_did_key")}
        else:
            method = "PUT" if op == "address_update" else "DELETE"
            path, wire = (
                base + f"/addresses/{address_segment(p['name'])}",
                op.replace("address_", "") + "_address",
            )
            body = {} if method == "PUT" else None
    elif op == "id_revoke":
        return ControllerHTTPPlan(
            "POST",
            "/v1/id-certificates/revoke",
            revoke_body(
                d,
                p["id"],
                expected_head=p["expected_head"],
                effective_from=p.get("effective_from"),
            ),
            "revoke_id_certificate",
            b"{}",
            "covering",
        )
    elif op in ("team_read", "certificate_list", "member_read", "revocations_read"):
        method, wire, fmt = "GET", "", "path"
        suffix = {
            "team_read": "",
            "certificate_list": "/certificates",
            "member_read": "/members/" + quote(p.get("alias", ""), safe=""),
            "revocations_read": "/revocations",
        }[op]
        path = team + suffix
        query = {
            k: (str(p[k]).lower() if type(p[k]) is bool else p[k])
            for k in ("active_only", "cursor", "limit", "since")
            if k in p
        }
        if query:
            path += "?" + urlencode(query)
    elif op == "server_publish":
        method, path, wire, fmt = "PUT", team + "/server", "", "object"
        body = p["record"]
    else:
        raise ControllerSigningError("operation_invalid")
    return ControllerHTTPPlan(
        method,
        path,
        _snapshot(body) if body is not None else None,
        wire,
        _snapshot(claims),
        fmt,
    )


def build_controller_payload(
    request, *, controller, role="controller", timestamp=None, registry_origin=None
):
    """Rebuild exact signed bytes from a closed operation, never arbitrary input."""
    try:
        return _build_controller_payload(
            request,
            controller=controller,
            role=role,
            timestamp=timestamp,
            registry_origin=registry_origin,
        )
    except ControllerSigningError:
        raise
    except (ValueError, TypeError, KeyError) as exc:
        raise ControllerSigningError("payload_invalid") from exc


def _build_controller_payload(
    request, *, controller, role="controller", timestamp=None, registry_origin=None
):
    _require(
        type(request) in (ControllerRequest, ControllerObjectRequest),
        "operation_invalid",
    )
    _check_controller(request, controller, role)
    p, op = request.parameters, request.operation
    if op in ("address_claim", "address_claim_proof"):
        return atomic_address_claim_namespace_canonical(
            _claim_fields(request, registry_origin),
            atomic_address_claim_identity_proof_hash(
                atomic_address_claim_identity_canonical(
                    _claim_fields(request, registry_origin)
                ),
                p["identity_signature"],
            ),
        )
    if type(request) is ControllerObjectRequest:
        if op == "namespace_id_issue":
            return id_certificate_signing_bytes(p["certificate"])
        if op == "team_certificate_issue":
            return _snapshot(p["certificate"])
        if op == "team_server_sign":
            return record_signing_bytes(p["record"])
        if op == "address_replacement":
            return _snapshot(p)
    parse_utc_seconds(timestamp)
    origin = canonical_server_origin(registry_origin)
    plan = controller_http_plan(request)
    if plan.format == "object":
        return record_signing_bytes(p["record"])
    if plan.format == "path":
        return f"{timestamp}\nGET\n{plan.path.partition('?')[0]}".encode()
    operation, claims = plan.wire_operation, json.loads(plan.claims)
    if role == "parent":
        # The parent authorizes the child's controller over the same request.
        register = op == "namespace_register"
        field = "controller_did" if register else "new_controller_did"
        operation = (
            "authorize_subdomain_registration"
            if register
            else "authorize_subdomain_rotation"
        )
        claims = {"child_domain": request.domain, field: p[field]}
    return covering_payload(
        aud=origin,
        method=plan.method,
        path=plan.path,
        domain=request.domain,
        operation=operation,
        body=plan.body or b"",
        timestamp=timestamp,
        claims=claims,
    )


@dataclass(frozen=True)
class ControllerSigningContext:
    request: ControllerRequest | ControllerObjectRequest
    controller: ControllerDescriptor
    role: str = "controller"
    timestamp: str | None = None
    registry_origin: str | None = None

    def signing_bytes(self):
        return build_controller_payload(
            self.request,
            controller=self.controller,
            role=self.role,
            timestamp=self.timestamp,
            registry_origin=self.registry_origin,
        )


ControllerSigner = Callable[
    [ControllerSigningContext], tuple[str, bytes] | Awaitable[tuple[str, bytes]]
]


async def checked_controller_signature(
    context: ControllerSigningContext, signer: ControllerSigner
):
    expected = context.signing_bytes()
    answer = signer(context)
    if inspect.isawaitable(answer):
        answer = await answer
    try:
        _require(
            type(answer) is tuple
            and len(answer) == 2
            and answer[0] == context.controller.did_key,
            "signer_answer",
        )
        verify_ed25519(context.controller.did_key, expected, answer[1])
    except (ValueError, TypeError) as exc:
        raise ControllerSigningError("signer_answer") from exc
    return answer[1]


async def sign_controller_object(
    request: ControllerObjectRequest, *, controller, signer, registry_origin=None
):
    _require(type(request) is ControllerObjectRequest, "operation_invalid")
    signature = await checked_controller_signature(
        ControllerSigningContext(request, controller, registry_origin=registry_origin),
        signer,
    )
    p = request.parameters
    if request.operation == "namespace_id_issue":
        return {
            "certificate": p["certificate"],
            "signature": base64.urlsafe_b64encode(signature).rstrip(b"=").decode(),
        }
    encoded = base64.b64encode(signature).rstrip(b"=").decode()
    if request.operation == "address_claim_proof":
        return {"namespace_signature": encoded}
    if request.operation == "team_certificate_issue":
        certificate = {**p["certificate"], "signature": encoded}
        header = base64.b64encode(_snapshot(certificate)).decode()
        check_team_certificate(
            header,
            subject_did_key=certificate["member_did_key"],
            team_did_key=controller.did_key,
            revoked_certificate_ids=(),
            registered_certificate_ids=None,
        )
        return {"certificate": certificate, "encoded_certificate": header}
    return {
        "record" if request.operation == "team_server_sign" else "announcement": p[
            "record"
        ]
        if request.operation == "team_server_sign"
        else p,
        "signature": encoded,
    }


def _claim_fields(request, registry_origin):
    """Verify the independent subject proofs before the controller is asked."""
    p = request.parameters
    fields = normalize_atomic_address_claim_fields(
        AtomicAddressClaimFields(
            ATOMIC_ADDRESS_CLAIM_OPERATION,
            request.domain,
            p["address_name"],
            p["did_aw"],
            p["current_did_key"],
            canonical_server_origin(registry_origin),
            p["timestamp"],
            p["dry_run"],
            p["identity_custody"],
            p["namespace_custody"],
        )
    )
    verify_did_key_signature(
        did_key=fields.current_did_key,
        payload=atomic_address_claim_identity_canonical(fields),
        signature_b64=p["identity_signature"],
    )
    proof = p.get("did_log_proof")
    if proof is not None:
        names = {
            "did_aw",
            "seq",
            "operation",
            "previous_did_key",
            "new_did_key",
            "prev_entry_hash",
            "state_hash",
            "authorized_by",
            "timestamp",
            "signature",
        }
        _require(type(proof) is dict and set(proof) == names)
        _require(
            proof["did_aw"] == fields.did_aw
            and proof["new_did_key"] == fields.current_did_key
            and type(proof["seq"]) is int
            and proof["seq"] >= 1
        )
        first = proof["seq"] == 1
        _require(
            proof["operation"] == ("register_did" if first else "rotate_key")
            and proof["authorized_by"]
            == (fields.current_did_key if first else proof["previous_did_key"])
        )
        if first:
            from awid.did import stable_id_from_did_key

            _require(
                proof["previous_did_key"] is None
                and proof["prev_entry_hash"] is None
                and stable_id_from_did_key(fields.current_did_key) == fields.did_aw
            )
        else:
            _key(proof["previous_did_key"])
            _require(
                type(proof["prev_entry_hash"]) is str
                and re.fullmatch(r"[0-9a-f]{64}", proof["prev_entry_hash"]) is not None
            )
        _require(
            proof["state_hash"]
            == identity_state_hash(
                did_aw=fields.did_aw, current_did_key=fields.current_did_key
            )
        )
        parse_utc_seconds(proof["timestamp"])
        verify_did_key_signature(
            did_key=proof["authorized_by"],
            payload=log_entry_payload(
                **{k: v for k, v in proof.items() if k != "signature"}
            ),
            signature_b64=proof["signature"],
        )
    return fields


def atomic_claim_body(request, registry_origin, namespace_signature):
    _claim_fields(request, registry_origin)
    return _snapshot(
        {
            "operation": ATOMIC_ADDRESS_CLAIM_OPERATION,
            "registry_url": canonical_server_origin(registry_origin),
            **request.parameters,
            "namespace_signature": namespace_signature,
        }
    )
