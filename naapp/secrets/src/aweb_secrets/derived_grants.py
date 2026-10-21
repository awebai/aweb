"""Frozen child-grant terms and current-definition compatibility at issuance.

Snapshotting takes no template row lock before B2. The dispatch/recording fence
rechecks and locks the current template after the caller's ordered authority
locks. Persist ``canonical`` with the use; retries use those same terms.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass

from awid.signing import canonical_json_bytes
from pgdbm.core import TransactionManager

from aweb_secrets import derived_lineage, records
from aweb_secrets.grant import GrantTemplate


class DerivedGrantRefused(Exception):
    def __init__(self, code: str = "operation_not_allowed") -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class GrantSnapshot:
    canonical: bytes

    @property
    def template(self) -> GrantTemplate:
        return GrantTemplate.from_after(json.loads(self.canonical))


async def _compatible(
    tx: TransactionManager,
    nodes: Sequence[derived_lineage.LineageNode],
    template: GrantTemplate,
) -> None:
    if not nodes:
        raise DerivedGrantRefused()
    parent = nodes[-1].secret.record
    # Decision 80: S15a owns the sole job registry and its resolver. Its absence
    # is an explicit typed refusal, never a guessed job/operation conversion.
    if template.terms["capability"] == "run":
        raise DerivedGrantRefused("job_unavailable")
    policy = await records.policy(tx, nodes[-1].installation_id, template.terms["policy_digest"])
    if policy is None:
        raise DerivedGrantRefused()
    if template.terms["open_request"] and (
        parent.sensitivity == "sensitive" or not policy.body["open_request"]
    ):
        raise DerivedGrantRefused()
    for pin in template.terms["operations"]:
        current = await derived_lineage.current_operation(tx, nodes, pin["operation_id"])
        if (
            current is None
            or current.digest != pin["digest"]
            or (current.operation_id, current.digest) not in policy.allowed_operations
            or (parent.sensitivity == "sensitive" and current.projection is None)
        ):
            raise DerivedGrantRefused()


async def snapshot_grant_template(
    tx: TransactionManager,
    nodes: Sequence[derived_lineage.LineageNode],
    *,
    template_id: str,
    expected_digest: str,
) -> GrantSnapshot:
    """Read and check the issuer operation's complete template pin at admission.

    The caller has locked/checked ancestry and the source grant. A concurrent
    template edit cannot widen these terms: the later fence compares the exact
    complete snapshot with the current locked template.
    """
    if not nodes:
        raise DerivedGrantRefused()
    template = await records.grant_template(tx, nodes[-1].installation_id, template_id)
    if template is None or template.digest != expected_digest:
        raise DerivedGrantRefused()
    await _compatible(tx, nodes, template)
    return GrantSnapshot(canonical_json_bytes(template.after))


async def fence_grant_snapshot(
    tx: TransactionManager,
    nodes: Sequence[derived_lineage.LineageNode],
    snapshot: GrantSnapshot,
    *,
    expected_digest: str,
) -> GrantTemplate:
    """Lock current terms, refuse any edit, and return only the persisted terms.

    Caller takes its installation/role/ancestry/grant/approver/B2 locks first.
    It must recheck live ancestry after later blocking writes before recording.
    """
    if not nodes:
        raise DerivedGrantRefused()
    frozen = snapshot.template
    body = await tx.fetch_value(
        "SELECT record FROM {{tables.grant_templates}}"
        " WHERE installation_id=$1 AND grant_template_id=$2 FOR SHARE",
        nodes[-1].installation_id,
        frozen.grant_template_id,
    )
    if body is None:
        raise DerivedGrantRefused()
    current = GrantTemplate.from_after(json.loads(body))
    if frozen.digest != expected_digest or current.digest != frozen.digest:
        raise DerivedGrantRefused()
    await _compatible(tx, nodes, frozen)
    return frozen
