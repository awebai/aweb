"""Closed signer operation registry, frozen human-assurance/1 catalog.

This is executable package data, never loaded from a worker"s request or an
operator-editable catalog. All selectors share one engine; a family selects
its existing wire codec/effect adapter, not another approval implementation.
The cross-contract test pins every row to the public frozen catalog.
"""

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta
from types import MappingProxyType
from typing import Literal

from .operation_codecs import (
    ADMISSION_CODEC,
    REMOVAL_CODEC,
    REVOKE_CODEC,
    ROOT_CODEC,
    OperationCodec,
)
from .operation_display import OperationDisplay
from .operation_effects import (
    ENDORSEMENT,
    LOCAL_SIGNATURE,
    REGISTERED_MEMBERSHIP,
    REVOKED_MEMBERSHIP,
    OperationEffect,
)
from .types import SignerRefused


@dataclass(frozen=True)
class OperationDefinition:
    operation: str
    variant: str
    key_role: Literal["team_controller", "namespace_controller", "human_identity", "protected_key"]
    rule: Literal["live_floor", "bounded_unattended"]
    family: str
    payload_binding: tuple[str, ...]
    bounds: tuple[str, ...]

    codec: OperationCodec
    effect: OperationEffect
    display: OperationDisplay
    binding_paths: tuple[tuple[str, str], ...] = ()
    consumer_available: bool = True
    prepared_fields: frozenset[str] = frozenset()
    signing_port: str = "sign_operation"
    finalize_execution_refusal: bool = False
    receipt_uv_expiry: bool = False
    supports_self_removal: bool = False
    request_window: tuple[tuple[str, ...], int] | None = None

    def effect_deadline(self, artifact, deadline):
        if "expires_at" in artifact:
            deadline = min(deadline, datetime.fromisoformat(artifact["expires_at"].replace("Z", "+00:00")))
        if self.request_window is not None:
            path, seconds = self.request_window
            stamp = artifact
            for field in path:
                stamp = stamp[field]
            deadline = min(deadline, datetime.fromisoformat(stamp.replace("Z", "+00:00")) + timedelta(seconds=seconds))
        return deadline

    def bindings(self):
        overrides = dict(self.binding_paths)
        return {name: overrides.get(name, "/subject/" + name) for name in self.payload_binding}

    def bound_values(self, request):
        """Make the frozen catalog bindings actual required request projections."""
        result = {}
        try:
            for name, path in self.bindings().items():
                value = request
                for field in path.split("/")[1:]:
                    value = value[field]
                result[name] = deepcopy(value)
        except (KeyError, TypeError):
            raise SignerRefused("operation_mismatch") from None
        return result

    @property
    def needs_human(self) -> bool:
        return self.rule == "live_floor"


# Source-compatible metadata type; the object also owns its consumer codec.
OperationSpec = OperationDefinition


_ROWS = (
    OperationDefinition(
        "team.agent.remove",
        "default",
        "team_controller",
        "bounded_unattended",
        "member_revocation",
        (
            "team_id",
            "root_id_or_self",
            "member_id",
            "certificate_id",
            "expected_membership",
        ),
        (
            "Agent target only; no human holding/last-owner bypass",
            "Root same permitted team/scope; self only own membership",
            "Membership removal distinct from ID revocation",
        ),
        codec=REMOVAL_CODEC,
        effect=REVOKED_MEMBERSHIP,
        display=OperationDisplay("Remove {/subject/expected_membership/alias} from {/subject/team_id}?",
            ("This revokes the exact team membership certificate.", "Identity revocation is a separate operation."),
            (("member", "/subject/expected_membership/alias"), ("team", "/subject/team_id")),
            (("member", "/subject/member_id"), ("certificate", "/subject/certificate_id"), ("requester", "/requester")),
            (("subject_ineligible", "This unattended path requires an eligible agent membership."),
             ("issuer_kind_forbidden", "This signer cannot remove that kind of membership."))),
        prepared_fields=frozenset({"requester_key"}),
        finalize_execution_refusal=True,
        supports_self_removal=True,
        request_window=(("request", "timestamp"), 300),
    ),
    OperationDefinition(
        "identity.root.endorse",
        "default",
        "human_identity",
        "live_floor",
        "id_certificate",
        (
            "domain",
            "root_id",
            "root_key",
            "parent",
            "certificate",
            "registry",
            "deployment_label",
            "responsibility_statement",
            "expected_head",
            "service_id",
            "default_admission_policy_digest",
            "default_admission_policy_version",
        ),
        (
            "Child possession and eligible existing identity; no silent remint",
            "Everything it spawns counts as yours describes ancestry, not permissions",
            "Current registered agent mapping and subject proof; local root refuses",
            "Existing chainless registered agent eligible; conflicting/revoked head refuses",
            "No team membership or Cloud login prerequisite",
            "One exact act satisfies bootstrap-provisioned default policy, does not create/widen it",
            "Display listed teams, root selector and finite admission bounds",
            "Server binds pre-existing policy into prepare; missing policy/legacy target refuses before pending/link",
            "Client checks frozen policy against authorized read before displaying link",
            "Execute refuses policy_changed on changed current policy; retry never rebinds",
        ),
        codec=ROOT_CODEC,
        effect=ENDORSEMENT,
        binding_paths=(("parent", "/artifact/parent"), ("certificate", "/artifact"),
            ("registry", "/registry"), ("responsibility_statement", "/responsibility_statement"),
            ("expected_head", "/expected_head"), ("service_id", "/scope/service_id"),
            ("default_admission_policy_digest", "/admission_policy/digest"),
            ("default_admission_policy_version", "/admission_policy/version")),
        display=OperationDisplay("Approve {/subject/deployment_label} as the root agent for {/subject/teams}?",
            ("Admission remains limited by the provisioned policy and its active-count and rate bounds.",
             "This endorsement grants no resource permissions."),
            (("deployment", "/subject/deployment_label"), ("teams", "/subject/teams")),
            (("root", "/subject/root_id"), ("root_key", "/subject/root_key"),
             ("human", "/scope/human/id"), ("policy", "/admission_policy"), ("requester", "/requester")),
            (("subject_ineligible", "This root is not an eligible registered agent of the selected human."),
             ("issuer_kind_forbidden", "The selected protected identity cannot endorse this root.")),
            responsibility_statement="Everything this root spawns counts as yours for human responsibility; this grants no resource permissions."),
        prepared_fields=frozenset({"registry", "expected_head", "responsibility_statement", "admission_policy"}),
        finalize_execution_refusal=True,
        receipt_uv_expiry=True,
    ),
    OperationDefinition(
        "team.agent.admit",
        "default",
        "team_controller",
        "bounded_unattended",
        "member_certificate",
        (
            "root_id",
            "root_key",
            "child_id",
            "child_key",
            "team_id",
            "member_alias",
            "certificate_fields",
            "admission_policy_version",
            "request_id",
            "service_id",
            "admission_policy_digest",
            "expected_policy_version",
        ),
        (
            "Verified eligible agent only; permitted team/scope",
            "No resource rights, owner role or human admission",
            "Membership only; identity issuance remains separate",
            "Exact current endorsed root selector from provisioned policy; no implicit descendant delegation",
            "Agent only; ordinary member role only, never admin/governance scopes",
            "Enforce finite active-count and rate-window/count limits",
            "Every protected-team path including renewal/cache/invite must obey same policy",
            "Exact retry returns original certificate and consumes no second quota",
            "Local did:key or registered agent when allowed by policy; correct local certificate subject",
            "Existing member-invite bypass returns protected_admission_required",
            "Select exact authenticated requesting root, not global unique root",
            "Counters per policy/team/root ID; key rotation retains bucket; aggregate ceiling only if explicit",
        ),
        codec=ADMISSION_CODEC,
        effect=REGISTERED_MEMBERSHIP,
        binding_paths=(("certificate_fields", "/artifact"), ("admission_policy_version", "/admission_policy_version"),
            ("request_id", "/request_id"), ("service_id", "/scope/service_id")),
        display=OperationDisplay("Admit {/subject/member_alias} to {/subject/team_id}?",
            ("This creates one ordinary agent membership under the endorsed root's policy.",
             "It grants no owner role or resource permissions."),
            (("member", "/subject/member_alias"), ("team", "/subject/team_id")),
            (("root", "/subject/root_id"), ("member_key", "/subject/child_key"),
             ("policy_digest", "/subject/admission_policy_digest"), ("requester", "/requester")),
            (("subject_ineligible", "This admission requires a positively verified eligible agent or permitted local agent."),
             ("issuer_kind_forbidden", "The selected controller cannot admit this kind of member."))),
        prepared_fields=frozenset({"request_id", "admission_policy_version"}),
        finalize_execution_refusal=True,
    ),
    OperationDefinition(
        "human-role.revoke",
        "default",
        "team_controller",
        "live_floor",
        "owner_act",
        ("app_id", "installation_id", "role", "principal"),
        (
            "Owner-act lifetime <=600 seconds",
            "Designate: subject own kind human and current member; no existing holding",
            "Revoke: stored holding, no H2 admission check",
            "Last-owner safeguards",
        ),
        codec=REVOKE_CODEC,
        effect=LOCAL_SIGNATURE,
        display=OperationDisplay("Remove {/subject/principal} from {/subject/role}?",
            ("This revokes the exact retained application role holding.", "Last-owner protection still applies."),
            (("application", "/subject/app_id"), ("role", "/subject/role")),
            (("principal", "/subject/principal"), ("installation", "/subject/installation_id"),
             ("team", "/scope/authority/id"), ("requester", "/requester")),
            (("subject_ineligible", "The selected role holding cannot be revoked by this operation."),
             ("issuer_kind_forbidden", "This controller cannot revoke the selected role holding."))),
        signing_port="sign_owner_act",
    ),
)

OPERATIONS = MappingProxyType({(spec.operation, spec.variant): spec for spec in _ROWS})


def operation_spec(operation: str, variant: str = "default") -> OperationSpec:
    if type(operation) is not str or not operation or type(variant) is not str or not variant:
        raise SignerRefused("request_invalid")
    try:
        definition = OPERATIONS[(operation, variant)]
    except KeyError:
        raise SignerRefused("operation_not_served") from None
    if not definition.consumer_available:
        raise SignerRefused("operation_not_served")
    return definition


def presentation_catalog() -> dict[str, dict]:
    """No policy grants/secrets: the page reads the same code-owned table.

    Wire field grammars come from their existing shared codecs, so neither a
    browser allowlist nor a second per-operation schema needs maintaining.
    """
    return {
        f"{spec.operation}|{spec.variant}": {
            "family": spec.family,
            "key_role": spec.key_role,
            "rule": spec.rule,
            "consumer_available": spec.consumer_available,
            "subject_schema": deepcopy(spec.codec.subject_schema),
            "presentation": deepcopy(spec.codec.presentation),
            "display": spec.display.fields(),
            "responsibility_statement": spec.display.responsibility_statement,
        }
        for spec in OPERATIONS.values()
    }


def operation_description():
    """Published versioned description; Go pins generated data, never an HTTP response."""
    return {"v": 1, "type": "aweb.protected-operations", "operations": [
        {"operation": spec.operation, "variant": spec.variant, "family": spec.family,
         "key_role": spec.key_role, "rule": spec.rule,
         "subject_schema": deepcopy(spec.codec.subject_schema),
         "prepared_fields": sorted(spec.prepared_fields), "bindings": spec.bindings(),
         "display": spec.display.fields(), "responsibility_statement": spec.display.responsibility_statement,
         "presentation": deepcopy(spec.codec.presentation)}
        for _, spec in sorted(OPERATIONS.items())]}
