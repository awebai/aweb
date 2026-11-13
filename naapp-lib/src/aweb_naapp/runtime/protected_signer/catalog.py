"""Closed signer operation registry, frozen human-assurance/1 catalog.

This is executable package data, never loaded from a worker"s request or an
operator-editable catalog. All selectors share one engine; a family selects
its existing wire codec/effect adapter, not another approval implementation.
The cross-contract test pins every row to the public frozen catalog.
"""

from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal

from .types import SignerRefused


@dataclass(frozen=True)
class OperationSpec:
    operation: str
    variant: str
    key_role: Literal["team_controller", "namespace_controller", "human_identity", "protected_key"]
    rule: Literal["live_floor", "bounded_unattended"]
    family: str
    payload_binding: tuple[str, ...]
    bounds: tuple[str, ...]

    consumer_available: bool = True

    @property
    def needs_human(self) -> bool:
        return self.rule == "live_floor"


_ROWS = (
    OperationSpec(
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
    ),
    OperationSpec(
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
    ),
    OperationSpec(
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
    ),
    OperationSpec(
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
    ),
)

OPERATIONS = MappingProxyType({(spec.operation, spec.variant): spec for spec in _ROWS})


def operation_spec(operation: str, variant: str = "default") -> OperationSpec:
    try:
        return OPERATIONS[(operation, variant)]
    except (KeyError, TypeError):
        raise SignerRefused("operation_refused") from None


def presentation_catalog() -> dict[str, dict]:
    """No policy grants/secrets: the page reads the same code-owned table.

    Wire field grammars come from their existing shared codecs, so neither a
    browser allowlist nor a second per-operation schema needs maintaining.
    """
    from .codecs import presentation_schema

    return {
        f"{spec.operation}|{spec.variant}": {
            "family": spec.family,
            "key_role": spec.key_role,
            "rule": spec.rule,
            "consumer_available": spec.consumer_available,
            "subject_schema": presentation_schema(spec.operation, spec.variant),
        }
        for spec in OPERATIONS.values()
    }
