"""Typed controller operations shared by custody-owning holders.

No caller eligibility or key custody is inferred from a descriptor. A signer
receives a typed immutable operation, never caller-selected bytes or a URL.
Path-only read proofs do not sign the destination or body; the holder retains
the full exchange beside those proofs.
"""

from __future__ import annotations

import base64
import hashlib
import inspect
import json
import re
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final, Literal
from urllib.parse import quote, urlencode

from awid.atomic_claim import (
    ATOMIC_ADDRESS_CLAIM_OPERATION,
    AtomicAddressClaimFields,
    atomic_address_claim_identity_canonical,
    atomic_address_claim_identity_proof_hash,
    atomic_address_claim_namespace_canonical,
    normalize_atomic_address_claim_fields,
)
from awid.did import public_key_from_did
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

# These names describe the existing closed SDK profiles, not registry policy.
ControllerOperation = Literal[
    "address_claim",
    "address_claim_proof",
    "address_delete",
    "address_reassign",
    "address_register",
    "address_replacement",
    "address_update",
    "certificate_list",
    "certificate_register",
    "certificate_revoke",
    "id_revoke",
    "member_read",
    "namespace_delete",
    "namespace_id_issue",
    "namespace_register",
    "namespace_reset",
    "namespace_rotate",
    "namespace_update",
    "revocations_read",
    "server_publish",
    "team_certificate_issue",
    "team_delete",
    "team_read",
    "team_register",
    "team_rotate",
    "team_server_sign",
    "team_visibility",
]
ControllerScope = Literal["namespace", "team"]
ControllerRole = Literal["controller", "new_controller", "parent"]
HTTPPlanFormat = Literal["covering", "path", "object"]
ControllerParameters = dict[str, Any]
OperationDefinition = tuple[str, str, ControllerScope]
ROLE_CONTROLLER: Final[ControllerRole] = "controller"
ROLE_NEW_CONTROLLER: Final[ControllerRole] = "new_controller"
ROLE_PARENT: Final[ControllerRole] = "parent"
SCOPE_NAMESPACE: Final[ControllerScope] = "namespace"
SCOPE_TEAM: Final[ControllerScope] = "team"
FORMAT_COVERING: Final[HTTPPlanFormat] = "covering"
FORMAT_PATH: Final[HTTPPlanFormat] = "path"
FORMAT_OBJECT: Final[HTTPPlanFormat] = "object"


class Operation:
    """Named constants for the closed controller operation vocabulary."""

    ADDRESS_CLAIM: Final[ControllerOperation] = "address_claim"
    ADDRESS_CLAIM_PROOF: Final[ControllerOperation] = "address_claim_proof"
    ADDRESS_DELETE: Final[ControllerOperation] = "address_delete"
    ADDRESS_REASSIGN: Final[ControllerOperation] = "address_reassign"
    ADDRESS_REGISTER: Final[ControllerOperation] = "address_register"
    ADDRESS_REPLACEMENT: Final[ControllerOperation] = "address_replacement"
    ADDRESS_UPDATE: Final[ControllerOperation] = "address_update"
    CERTIFICATE_LIST: Final[ControllerOperation] = "certificate_list"
    CERTIFICATE_REGISTER: Final[ControllerOperation] = "certificate_register"
    CERTIFICATE_REVOKE: Final[ControllerOperation] = "certificate_revoke"
    ID_REVOKE: Final[ControllerOperation] = "id_revoke"
    MEMBER_READ: Final[ControllerOperation] = "member_read"
    NAMESPACE_DELETE: Final[ControllerOperation] = "namespace_delete"
    NAMESPACE_ID_ISSUE: Final[ControllerOperation] = "namespace_id_issue"
    NAMESPACE_REGISTER: Final[ControllerOperation] = "namespace_register"
    NAMESPACE_RESET: Final[ControllerOperation] = "namespace_reset"
    NAMESPACE_ROTATE: Final[ControllerOperation] = "namespace_rotate"
    NAMESPACE_UPDATE: Final[ControllerOperation] = "namespace_update"
    REVOCATIONS_READ: Final[ControllerOperation] = "revocations_read"
    SERVER_PUBLISH: Final[ControllerOperation] = "server_publish"
    TEAM_CERTIFICATE_ISSUE: Final[ControllerOperation] = "team_certificate_issue"
    TEAM_DELETE: Final[ControllerOperation] = "team_delete"
    TEAM_READ: Final[ControllerOperation] = "team_read"
    TEAM_REGISTER: Final[ControllerOperation] = "team_register"
    TEAM_ROTATE: Final[ControllerOperation] = "team_rotate"
    TEAM_SERVER_SIGN: Final[ControllerOperation] = "team_server_sign"
    TEAM_VISIBILITY: Final[ControllerOperation] = "team_visibility"


class ControllerFailure(StrEnum):
    """Local controller refusals; their published string codes stay unchanged."""

    CONTROLLER_INVALID = "controller_invalid"
    CONTROLLER_MISMATCH = "controller_mismatch"
    CONTROLLER_ROLE = "controller_role"
    CONTROLLER_SCOPE = "controller_scope"
    DOMAIN_INVALID = "domain_invalid"
    KEY_INVALID = "key_invalid"
    OBJECT_INVALID = "object_invalid"
    OPERATION_INVALID = "operation_invalid"
    PAYLOAD_INVALID = "payload_invalid"
    REQUEST_INVALID = "request_invalid"
    SIGNER_ANSWER = "signer_answer"


class ControllerSigningError(ValueError):
    """Local refusal; no request has been sent. Messages contain no inputs."""

    def __init__(self, code: str) -> None:
        self.code = str(code)
        super().__init__(self.code)


class ControllerRequestUncertain(RegistryError):
    """A submitted mutation may have applied. Reconcile; do not retry blindly."""

    def __init__(self, request: ControllerRequest) -> None:
        super().__init__(
            "Controller request outcome is unknown",
            status_code=503,
            code="controller_outcome_unknown",
        )
        self.operation = request.operation
        self.request_digest = request.digest


def _require(
    condition: bool, code: ControllerFailure = ControllerFailure.REQUEST_INVALID
) -> None:
    if not condition:
        raise ControllerSigningError(code)


def _domain_label(value: object) -> bool:
    return (
        type(value) is str
        and bool(value)
        and len(value) <= 253
        and re.fullmatch(r"[a-z0-9][a-z0-9_-]*", value) is not None
    )


def _team_name(value: object) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= 128
        and re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?", value) is not None
    )


def _alias(value: object) -> bool:
    # Existing product alias profile (server input_validation, auth, aw).
    return (
        type(value) is str
        and re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}", value) is not None
    )


def _address_name(value: object) -> bool:
    # The registry imposes length, not a team/alias character profile.
    return type(value) is str and 1 <= len(value) <= 256


def _domain(value: object) -> None:
    _require(
        type(value) is str
        and len(value) <= 253
        and all(_domain_label(p) and "_" not in p for p in value.split(".")),
        ControllerFailure.DOMAIN_INVALID,
    )


def _key(value: object) -> None:
    try:
        if not isinstance(value, str):
            raise TypeError("controller key must be a did:key string")
        public_key_from_did(value)
    except (TypeError, ValueError) as exc:
        raise ControllerSigningError(ControllerFailure.KEY_INVALID) from exc


def _portable(value: object) -> None:
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
    raise ControllerSigningError(ControllerFailure.REQUEST_INVALID)


def _snapshot(value: ControllerParameters) -> bytes:
    try:
        _portable(value)
        raw = canonical_json_bytes(value)
        _require(len(raw) <= 4 * 1024 * 1024)
        return raw
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        if isinstance(exc, ControllerSigningError):
            raise
        raise ControllerSigningError(ControllerFailure.REQUEST_INVALID) from exc


@dataclass(frozen=True)
class ControllerDescriptor:
    """Current-key selector supplied by the custody owner, not caller eligibility."""

    scope: ControllerScope
    domain: str
    did_key: str
    key_reference: str
    generation: int
    team: str | None = None

    def __post_init__(self) -> None:
        _domain(self.domain)
        _key(self.did_key)
        _require(
            self.scope in (SCOPE_NAMESPACE, SCOPE_TEAM),
            ControllerFailure.CONTROLLER_SCOPE,
        )
        _require(
            type(self.key_reference) is str and bool(self.key_reference),
            ControllerFailure.CONTROLLER_INVALID,
        )
        _require(
            type(self.generation) is int and self.generation >= 0,
            ControllerFailure.CONTROLLER_INVALID,
        )
        _require(
            (_team_name(self.team) if self.scope == SCOPE_TEAM else self.team is None),
            ControllerFailure.CONTROLLER_SCOPE,
        )


# Operation -> (required fields, optional fields, signer scope). These are SDK
# operation names, not a new registry wire format or a holder's permission table.
_REQUESTS: dict[ControllerOperation, OperationDefinition] = {
    Operation.NAMESPACE_REGISTER: (
        "controller_did",
        "parent_domain default_delivery_origin",
        "namespace",
    ),
    Operation.NAMESPACE_UPDATE: ("default_delivery_origin", "", "namespace"),
    Operation.NAMESPACE_DELETE: ("", "reason", "namespace"),
    Operation.NAMESPACE_ROTATE: (
        "from_seq previous_did_key new_did_key",
        "",
        "namespace",
    ),
    Operation.NAMESPACE_RESET: ("new_controller_did", "parent_domain", "namespace"),
    Operation.TEAM_REGISTER: (
        "name display_name team_did_key visibility",
        "",
        "namespace",
    ),
    Operation.TEAM_ROTATE: ("name new_team_did_key", "resigned_records", "namespace"),
    Operation.TEAM_VISIBILITY: ("name visibility", "", "team"),
    Operation.TEAM_DELETE: ("name", "", "namespace"),
    Operation.CERTIFICATE_REGISTER: ("name certificate", "", "team"),
    Operation.CERTIFICATE_REVOKE: ("name certificate_id", "", "team"),
    Operation.ADDRESS_REGISTER: ("name did_aw current_did_key", "", "namespace"),
    Operation.ADDRESS_UPDATE: ("name", "", "namespace"),
    Operation.ADDRESS_DELETE: ("name", "", "namespace"),
    Operation.ADDRESS_REASSIGN: ("name did_aw current_did_key", "", "namespace"),
    Operation.ID_REVOKE: ("id expected_head", "effective_from", "namespace"),
    Operation.TEAM_READ: ("name", "", "team"),
    Operation.CERTIFICATE_LIST: ("name", "active_only cursor limit", "team"),
    Operation.MEMBER_READ: ("name alias", "", "team"),
    Operation.REVOCATIONS_READ: ("name", "cursor limit since", "team"),
    Operation.SERVER_PUBLISH: ("name record", "", "team"),
    Operation.ADDRESS_CLAIM: (
        "address_name did_aw current_did_key timestamp dry_run identity_custody namespace_custody identity_signature",
        "did_log_proof",
        "namespace",
    ),
}
_OBJECTS: dict[ControllerOperation, OperationDefinition] = {
    Operation.TEAM_CERTIFICATE_ISSUE: ("name certificate", "", "team"),
    Operation.NAMESPACE_ID_ISSUE: ("kind certificate", "", "namespace"),
    Operation.TEAM_SERVER_SIGN: ("name record", "", "team"),
    Operation.ADDRESS_REPLACEMENT: (
        "address controller_did old_did new_did timestamp",
        "",
        "namespace",
    ),
    Operation.ADDRESS_CLAIM_PROOF: (
        "address_name did_aw current_did_key timestamp dry_run identity_custody namespace_custody identity_signature",
        "did_log_proof",
        "namespace",
    ),
}


def _validate(
    operation: ControllerOperation,
    domain: str,
    parameters: ControllerParameters,
    definitions: Mapping[ControllerOperation, OperationDefinition],
) -> None:
    _domain(domain)
    _require(operation in definitions, ControllerFailure.OPERATION_INVALID)
    required_names, optional_names, _ = definitions[operation]
    _require(
        type(parameters) is dict
        and set(required_names.split()) <= parameters.keys()
        and parameters.keys() <= set((required_names + " " + optional_names).split())
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
            _require(domain.endswith("." + value), ControllerFailure.CONTROLLER_SCOPE)
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
    if operation == Operation.NAMESPACE_ID_ISSUE:
        certificate = parameters["certificate"]
        try:
            validate_id_certificate(certificate)
            _require(
                parameters["kind"] in ("human", "agent")
                and certificate["kind"] == parameters["kind"]
                and certificate["domain"] == domain
                and certificate["parent"] == {"kind": "namespace", "id": domain},
                ControllerFailure.OBJECT_INVALID,
            )
        except (ValueError, TypeError, KeyError) as exc:
            raise ControllerSigningError(ControllerFailure.OBJECT_INVALID) from exc
    if operation in (Operation.TEAM_SERVER_SIGN, Operation.SERVER_PUBLISH):
        record = parameters["record"]
        _require(
            type(record) is dict
            and set(record) == RECORD_FIELDS
            and record["v"] == 1
            and type(record["v"]) is int
            and record["type"] == "aweb.team-server"
            and record["team_id"] == build_team_id(domain, parameters["name"]),
            ControllerFailure.OBJECT_INVALID,
        )
        canonical_team_server_url(record["server_url"])
        _key(record["team_did_key"])
        parse_utc_seconds(record["issued_at"])
    if operation == Operation.TEAM_CERTIFICATE_ISSUE:
        certificate = parameters["certificate"]
        required_fields = {
            "version",
            "certificate_id",
            "team_id",
            "team_did_key",
            "member_did_key",
            "alias",
            "issued_at",
        }
        _require(
            type(certificate) is dict
            and required_fields <= certificate.keys()
            and certificate.keys()
            <= required_fields
            | {
                "member_did_aw",
                "member_address",
                "team_did_key",
                "lifetime",
                "identity_scope",
                "issued_at",
            }
            and type(certificate["version"]) is int
            and certificate["version"] == 1
            and certificate["team_id"] == build_team_id(domain, parameters["name"])
            and certificate.get("identity_scope", certificate.get("lifetime"))
            in ("local", "global")
            and _alias(certificate["alias"])
            and type(certificate["certificate_id"]) is str,
            ControllerFailure.OBJECT_INVALID,
        )
        _key(certificate["member_did_key"])
        if "issued_at" in certificate:
            parse_utc_seconds(certificate["issued_at"])
    if operation == Operation.CERTIFICATE_REGISTER:
        from awid.team_certificate import decode_team_certificate

        certificate = decode_team_certificate(parameters["certificate"])
        _require(
            certificate["team_id"] == build_team_id(domain, parameters["name"]),
            ControllerFailure.OBJECT_INVALID,
        )
    if (
        operation == Operation.TEAM_ROTATE
        and parameters.get("resigned_records") is not None
    ):
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
    if operation == Operation.ADDRESS_REPLACEMENT:
        _require(
            parameters["address"].startswith(domain + "/"),
            ControllerFailure.OBJECT_INVALID,
        )


@dataclass(frozen=True, init=False)
class ControllerRequest:
    """Closed immutable controller request rebuilt by the SDK before signing."""

    operation: ControllerOperation
    domain: str
    _parameters: bytes = field(repr=False)

    def __init__(
        self,
        operation: ControllerOperation,
        domain: str,
        parameters: ControllerParameters,
    ) -> None:
        raw = _snapshot(parameters)
        _validate(operation, domain, json.loads(raw), _REQUESTS)
        object.__setattr__(self, "operation", operation)
        object.__setattr__(self, "domain", domain)
        object.__setattr__(self, "_parameters", raw)

    @property
    def parameters(self) -> ControllerParameters:
        """Decode the validated immutable snapshot without exposing mutable internal state."""
        return json.loads(self._parameters)

    @property
    def digest(self) -> str:
        """Commit to the immutable closed request using the existing canonical bytes."""
        return hashlib.sha256(
            _snapshot(
                {"operation": self.operation, "domain": self.domain, **self.parameters}
            )
        ).hexdigest()


@dataclass(frozen=True, init=False)
class ControllerObjectRequest:
    """Closed immutable object whose signature carries no HTTP permission."""

    operation: ControllerOperation
    domain: str
    _parameters: bytes = field(repr=False)

    def __init__(
        self,
        operation: ControllerOperation,
        domain: str,
        parameters: ControllerParameters,
    ) -> None:
        raw = _snapshot(parameters)
        _validate(operation, domain, json.loads(raw), _OBJECTS)
        object.__setattr__(self, "operation", operation)
        object.__setattr__(self, "domain", domain)
        object.__setattr__(self, "_parameters", raw)

    @property
    def parameters(self) -> ControllerParameters:
        """Decode the validated immutable snapshot without exposing mutable internal state."""
        return json.loads(self._parameters)


def _parse[RequestType: (ControllerRequest, ControllerObjectRequest)](
    value: object, cls: type[RequestType]
) -> RequestType:
    try:
        if type(value) is not dict or not {"operation", "domain"} <= value.keys():
            raise ControllerSigningError(ControllerFailure.REQUEST_INVALID)
        return cls(
            value["operation"],
            value["domain"],
            {k: v for k, v in value.items() if k not in ("operation", "domain")},
        )
    except ControllerSigningError:
        raise
    except (TypeError, ValueError, KeyError) as exc:
        raise ControllerSigningError(ControllerFailure.REQUEST_INVALID) from exc


def parse_controller_request(value: object) -> ControllerRequest:
    """Validate untrusted JSON into a closed immutable HTTP operation."""
    return _parse(value, ControllerRequest)


def parse_controller_object(value: object) -> ControllerObjectRequest:
    """Validate untrusted JSON into a closed immutable object operation."""
    return _parse(value, ControllerObjectRequest)


def signature_roles(
    request: ControllerRequest | ControllerObjectRequest,
) -> tuple[ControllerRole, ...]:
    """Return exactly the controller roles required by this closed operation."""
    if request.operation == Operation.NAMESPACE_ROTATE:
        return (ROLE_CONTROLLER, ROLE_NEW_CONTROLLER)
    return (
        (ROLE_CONTROLLER, ROLE_PARENT)
        if "parent_domain" in request.parameters
        else (ROLE_CONTROLLER,)
    )


def _check_controller(
    request: ControllerRequest | ControllerObjectRequest,
    controller: ControllerDescriptor,
    role: ControllerRole,
) -> None:
    _require(
        type(controller) is ControllerDescriptor, ControllerFailure.CONTROLLER_INVALID
    )
    _require(role in signature_roles(request), ControllerFailure.CONTROLLER_ROLE)
    parameters = request.parameters
    definitions = _REQUESTS if type(request) is ControllerRequest else _OBJECTS
    scope = definitions[request.operation][2]
    domain = parameters["parent_domain"] if role == ROLE_PARENT else request.domain
    _require(
        controller.domain == domain
        and controller.scope == scope
        and (scope != SCOPE_TEAM or controller.team == parameters["name"]),
        ControllerFailure.CONTROLLER_SCOPE,
    )
    expected = None
    if request.operation == Operation.NAMESPACE_ROTATE:
        expected = parameters[
            "new_did_key" if role == ROLE_NEW_CONTROLLER else "previous_did_key"
        ]
    elif role == ROLE_CONTROLLER and request.operation in (
        Operation.NAMESPACE_REGISTER,
        Operation.NAMESPACE_RESET,
    ):
        expected = parameters[
            "controller_did"
            if request.operation == Operation.NAMESPACE_REGISTER
            else "new_controller_did"
        ]
    elif request.operation == Operation.NAMESPACE_ID_ISSUE:
        expected = parameters["certificate"]["issuer_key"]
    elif request.operation in (Operation.TEAM_SERVER_SIGN, Operation.SERVER_PUBLISH):
        expected = parameters["record"]["team_did_key"]
    elif request.operation == Operation.ADDRESS_REPLACEMENT:
        expected = parameters["controller_did"]
    _require(
        expected is None or controller.did_key == expected,
        ControllerFailure.CONTROLLER_MISMATCH,
    )
    if request.operation in (
        Operation.TEAM_CERTIFICATE_ISSUE,
        Operation.CERTIFICATE_REGISTER,
    ):
        if request.operation == Operation.CERTIFICATE_REGISTER:
            from awid.team_certificate import decode_team_certificate

            certificate = decode_team_certificate(parameters["certificate"])
            check_team_certificate(
                parameters["certificate"],
                subject_did_key=certificate["member_did_key"],
                team_did_key=controller.did_key,
                revoked_certificate_ids=(),
                registered_certificate_ids=None,
            )
        else:
            certificate = parameters["certificate"]
        _require(
            certificate.get("team_did_key", controller.did_key) == controller.did_key,
            ControllerFailure.CONTROLLER_MISMATCH,
        )


@dataclass(frozen=True)
class ControllerHTTPPlan:
    """Exact method, path, body and claims for an existing controller operation."""

    method: str
    path: str
    body: bytes | None
    wire_operation: str
    claims: bytes
    format: HTTPPlanFormat


def controller_http_plan(request: ControllerRequest) -> ControllerHTTPPlan:
    """Reconstruct the existing registry exchange from validated operation fields."""
    _require(type(request) is ControllerRequest, ControllerFailure.OPERATION_INVALID)
    operation, domain, parameters = (
        request.operation,
        request.domain,
        request.parameters,
    )
    base = f"/v1/namespaces/{domain}"
    team = base + "/teams/" + parameters.get("name", "")
    body: ControllerParameters | None = None
    claims: ControllerParameters = {}
    fmt: HTTPPlanFormat = FORMAT_COVERING
    if operation == Operation.NAMESPACE_REGISTER:
        method, path, wire = "POST", "/v1/namespaces", "register"
        body = {"domain": domain, "controller_did": parameters["controller_did"]}
        if parameters.get("default_delivery_origin") is not None:
            body["default_delivery_origin"] = claims["default_delivery_origin"] = (
                parameters["default_delivery_origin"]
            )
    elif operation == Operation.NAMESPACE_UPDATE:
        method, path, wire = "PATCH", base, "update_namespace"
        body = {"default_delivery_origin": parameters["default_delivery_origin"]}
        claims = {
            "default_delivery_origin": parameters["default_delivery_origin"] or ""
        }
    elif operation == Operation.NAMESPACE_DELETE:
        method, path, wire = "DELETE", base, "delete_namespace"
        body = {"reason": parameters["reason"]} if "reason" in parameters else None
    elif operation == Operation.NAMESPACE_RESET:
        method, path, wire = "PUT", base, "rotate_controller"
        body = claims = {"new_controller_did": parameters["new_controller_did"]}
    elif operation == Operation.NAMESPACE_ROTATE:
        claims = rotate_claims(**parameters)
        return ControllerHTTPPlan(
            "POST",
            base + "/rotate",
            rotate_body(domain, claims),
            "rotate_namespace_controller",
            _snapshot(claims),
            FORMAT_COVERING,
        )
    elif operation == Operation.TEAM_REGISTER:
        method, path, wire, body = "POST", base + "/teams", "create_team", parameters
        claims = {"name": parameters["name"]}
    elif operation == Operation.TEAM_ROTATE:
        method, path, wire = "POST", team + "/rotate", "rotate_team_key"
        claims = {
            "name": parameters["name"],
            "new_team_did_key": parameters["new_team_did_key"],
        }
        body = {k: v for k, v in parameters.items() if k != "name"}
    elif operation == Operation.TEAM_VISIBILITY:
        method, path, wire = "POST", team + "/visibility", "set_team_visibility"
        body = {"visibility": parameters["visibility"]}
        claims = {"team_name": parameters["name"], **body}
    elif operation == Operation.TEAM_DELETE:
        method, path, wire = "DELETE", team, "delete_team"
        claims = {"team_name": parameters["name"]}
    elif operation == Operation.CERTIFICATE_REGISTER:
        method, path, wire = "POST", team + "/certificates", "register_certificate"
        certificate = parameters["certificate"]
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
        claims = {
            "team_name": parameters["name"],
            "certificate_id": c["certificate_id"],
        }
    elif operation == Operation.CERTIFICATE_REVOKE:
        method, path, wire = "POST", team + "/certificates/revoke", "revoke_certificate"
        body = {"certificate_id": parameters["certificate_id"]}
        claims = {"team_name": parameters["name"], **body}
    elif operation == Operation.ADDRESS_CLAIM:
        return ControllerHTTPPlan(
            "POST",
            base + "/addresses/claims",
            None,
            ATOMIC_ADDRESS_CLAIM_OPERATION,
            b"{}",
            FORMAT_OBJECT,
        )
    elif operation.startswith("address_"):
        claims = {"name": parameters["name"]}
        if operation == Operation.ADDRESS_REGISTER:
            method, path, wire, body = (
                "POST",
                base + "/addresses",
                "register_address",
                parameters,
            )
        elif operation == Operation.ADDRESS_REASSIGN:
            method, path, wire = (
                "POST",
                base + f"/addresses/{address_segment(parameters['name'])}/reassign",
                "reassign_address",
            )
            body = {k: parameters[k] for k in ("did_aw", "current_did_key")}
        else:
            method = "PUT" if operation == Operation.ADDRESS_UPDATE else "DELETE"
            path, wire = (
                base + f"/addresses/{address_segment(parameters['name'])}",
                operation.replace("address_", "") + "_address",
            )
            body = {} if method == "PUT" else None
    elif operation == Operation.ID_REVOKE:
        return ControllerHTTPPlan(
            "POST",
            "/v1/id-certificates/revoke",
            revoke_body(
                domain,
                parameters["id"],
                expected_head=parameters["expected_head"],
                effective_from=parameters.get("effective_from"),
            ),
            "revoke_id_certificate",
            b"{}",
            FORMAT_COVERING,
        )
    elif operation in (
        Operation.TEAM_READ,
        Operation.CERTIFICATE_LIST,
        Operation.MEMBER_READ,
        Operation.REVOCATIONS_READ,
    ):
        method, wire, fmt = "GET", "", FORMAT_PATH
        suffix = {
            "team_read": "",
            "certificate_list": "/certificates",
            "member_read": "/members/" + quote(parameters.get("alias", ""), safe=""),
            "revocations_read": "/revocations",
        }[operation]
        path = team + suffix
        query = {
            k: (
                str(parameters[k]).lower()
                if type(parameters[k]) is bool
                else parameters[k]
            )
            for k in ("active_only", "cursor", "limit", "since")
            if k in parameters
        }
        if query:
            path += "?" + urlencode(query)
    elif operation == Operation.SERVER_PUBLISH:
        method, path, wire, fmt = "PUT", team + "/server", "", FORMAT_OBJECT
        body = parameters["record"]
    else:
        raise ControllerSigningError(ControllerFailure.OPERATION_INVALID)
    return ControllerHTTPPlan(
        method,
        path,
        _snapshot(body) if body is not None else None,
        wire,
        _snapshot(claims),
        fmt,
    )


def build_controller_payload(
    request: ControllerRequest | ControllerObjectRequest,
    *,
    controller: ControllerDescriptor,
    role: ControllerRole = ROLE_CONTROLLER,
    timestamp: str | None = None,
    registry_origin: str | None = None,
) -> bytes:
    """Rebuild signed bytes under docs/awid-controller-requests.md:27-38.

    The selected origin and external path are signed exactly; neither comes
    from request headers, and caller eligibility remains with the holder.
    """
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
        raise ControllerSigningError(ControllerFailure.PAYLOAD_INVALID) from exc


def _build_controller_payload(
    request: ControllerRequest | ControllerObjectRequest,
    *,
    controller: ControllerDescriptor,
    role: ControllerRole = ROLE_CONTROLLER,
    timestamp: str | None = None,
    registry_origin: str | None = None,
) -> bytes:
    _require(
        type(request) in (ControllerRequest, ControllerObjectRequest),
        ControllerFailure.OPERATION_INVALID,
    )
    _check_controller(request, controller, role)
    parameters, sdk_operation = request.parameters, request.operation
    if sdk_operation in (Operation.ADDRESS_CLAIM, Operation.ADDRESS_CLAIM_PROOF):
        return atomic_address_claim_namespace_canonical(
            _claim_fields(request, registry_origin),
            atomic_address_claim_identity_proof_hash(
                atomic_address_claim_identity_canonical(
                    _claim_fields(request, registry_origin)
                ),
                parameters["identity_signature"],
            ),
        )
    if isinstance(request, ControllerObjectRequest):
        if sdk_operation == Operation.NAMESPACE_ID_ISSUE:
            return id_certificate_signing_bytes(parameters["certificate"])
        if sdk_operation == Operation.TEAM_CERTIFICATE_ISSUE:
            return _snapshot(parameters["certificate"])
        if sdk_operation == Operation.TEAM_SERVER_SIGN:
            return record_signing_bytes(parameters["record"])
        if sdk_operation == Operation.ADDRESS_REPLACEMENT:
            return _snapshot(parameters)
        raise ControllerSigningError(ControllerFailure.OPERATION_INVALID)
    if timestamp is None:
        raise ValueError("controller timestamp is required")
    parse_utc_seconds(timestamp)
    origin = _checked_registry_origin(registry_origin)
    plan = controller_http_plan(request)
    if plan.format == FORMAT_OBJECT:
        return record_signing_bytes(parameters["record"])
    if plan.format == FORMAT_PATH:
        return f"{timestamp}\nGET\n{plan.path.partition('?')[0]}".encode()
    wire_operation, claims = plan.wire_operation, json.loads(plan.claims)
    if role == ROLE_PARENT:
        # The parent authorizes the child's controller over the same request.
        register = sdk_operation == Operation.NAMESPACE_REGISTER
        field = "controller_did" if register else "new_controller_did"
        wire_operation = (
            "authorize_subdomain_registration"
            if register
            else "authorize_subdomain_rotation"
        )
        claims = {"child_domain": request.domain, field: parameters[field]}
    return covering_payload(
        aud=origin,
        method=plan.method,
        path=plan.path,
        domain=request.domain,
        operation=wire_operation,
        body=plan.body or b"",
        timestamp=timestamp,
        claims=claims,
    )


@dataclass(frozen=True)
class ControllerSigningContext:
    """One checked request and its selected controller signing role."""

    request: ControllerRequest | ControllerObjectRequest
    controller: ControllerDescriptor
    role: ControllerRole = ROLE_CONTROLLER
    timestamp: str | None = None
    registry_origin: str | None = None

    def signing_bytes(self) -> bytes:
        """Rebuild the exact operation bytes; the callback cannot select a different act."""
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
) -> bytes:
    """Verify that the callback signed the exact reconstructed bytes with the selected key."""
    expected = context.signing_bytes()
    answer = signer(context)
    if inspect.isawaitable(answer):
        answer = await answer
    try:
        _require(
            type(answer) is tuple
            and len(answer) == 2
            and answer[0] == context.controller.did_key,
            ControllerFailure.SIGNER_ANSWER,
        )
        verify_ed25519(context.controller.did_key, expected, answer[1])
    except (ValueError, TypeError) as exc:
        raise ControllerSigningError(ControllerFailure.SIGNER_ANSWER) from exc
    return answer[1]


async def sign_controller_object(
    request: ControllerObjectRequest,
    *,
    controller: ControllerDescriptor,
    signer: ControllerSigner,
    registry_origin: str | None = None,
) -> ControllerParameters:
    """Return the existing public signed-object format after checking the custody callback."""
    _require(
        type(request) is ControllerObjectRequest, ControllerFailure.OPERATION_INVALID
    )
    signature = await checked_controller_signature(
        ControllerSigningContext(request, controller, registry_origin=registry_origin),
        signer,
    )
    parameters = request.parameters
    if request.operation == Operation.NAMESPACE_ID_ISSUE:
        return {
            "certificate": parameters["certificate"],
            "signature": base64.urlsafe_b64encode(signature).rstrip(b"=").decode(),
        }
    encoded = base64.b64encode(signature).rstrip(b"=").decode()
    if request.operation == Operation.ADDRESS_CLAIM_PROOF:
        return {"namespace_signature": encoded}
    if request.operation == Operation.TEAM_CERTIFICATE_ISSUE:
        certificate = {**parameters["certificate"], "signature": encoded}
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
        "record"
        if request.operation == Operation.TEAM_SERVER_SIGN
        else "announcement": parameters["record"]
        if request.operation == Operation.TEAM_SERVER_SIGN
        else parameters,
        "signature": encoded,
    }


def _checked_registry_origin(origin: str | None) -> str:
    """Require the caller-selected origin before the shared canonical check."""
    if origin is None:
        raise ValueError("controller registry origin is required")
    return canonical_server_origin(origin)


def _claim_fields(
    request: ControllerRequest | ControllerObjectRequest, registry_origin: str | None
) -> AtomicAddressClaimFields:
    """Verify the independent subject proofs before the controller is asked."""
    parameters = request.parameters
    fields = normalize_atomic_address_claim_fields(
        AtomicAddressClaimFields(
            ATOMIC_ADDRESS_CLAIM_OPERATION,
            request.domain,
            parameters["address_name"],
            parameters["did_aw"],
            parameters["current_did_key"],
            _checked_registry_origin(registry_origin),
            parameters["timestamp"],
            parameters["dry_run"],
            parameters["identity_custody"],
            parameters["namespace_custody"],
        )
    )
    verify_did_key_signature(
        did_key=fields.current_did_key,
        payload=atomic_address_claim_identity_canonical(fields),
        signature_b64=parameters["identity_signature"],
    )
    proof = parameters.get("did_log_proof")
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


def atomic_claim_body(
    request: ControllerRequest | ControllerObjectRequest,
    registry_origin: str | None,
    namespace_signature: str,
) -> bytes:
    """Build the atomic address claim body after its independent identity proof is checked."""
    _claim_fields(request, registry_origin)
    return _snapshot(
        {
            "operation": ATOMIC_ADDRESS_CLAIM_OPERATION,
            "registry_url": _checked_registry_origin(registry_origin),
            **request.parameters,
            "namespace_signature": namespace_signature,
        }
    )
