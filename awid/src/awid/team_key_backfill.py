"""Explicit owner-inventory re-attestation; constructing a report never writes.

Hosted callers supply their own approved inventory and controller signer. The
registry's child/team lists never decide which keys deserve re-attestation.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from awid.controller_signing import parse_controller_request
from awid.external_authority import SystemTXTOutcomeResolver
from awid.registry import RegistryError
from awid.team_key_acts import TeamKeyActError, verify_team_key_change


@dataclass(frozen=True)
class TeamKeyBackfillTarget:
    domain: str
    name: str
    team_did_key: str


async def reaffirm_team_keys(client, inventory, *, controllers, signer, apply=False, resolver=None) -> dict[str, Any]:
    """Readiness counts, optionally followed by guarded same-key writes/readback.

    ``controllers`` maps approved domains to the operator's current controller
    descriptors. ``signer`` is the existing typed controller signer. Callers
    own production authorisation; this function defaults to reads only.
    Re-running it skips ready teams. A conflicting inventory key never writes.
    """
    targets = tuple(inventory)
    if len({(t.domain, t.name) for t in targets}) != len(targets):
        raise ValueError('duplicate team in approved inventory')
    resolver = resolver or SystemTXTOutcomeResolver()

    async def state(target):
        key = await client.get_team_public_key_fresh(target.domain, target.name)
        if key != target.team_did_key:
            return 'conflicted'
        record = await client.get_team_key_act(target.domain, target.name)
        if record is None:
            return 'unready'
        try:
            await verify_team_key_change(record, domain=target.domain, name=target.name,
                team_did_key=target.team_did_key, pinned_at=None, resolver=resolver,
                fetch_namespace_evidence=client.namespace_evidence)
        except TeamKeyActError:
            return 'unready'
        return 'ready'

    before = [await state(target) for target in targets]
    outcomes = []
    for target, initial in zip(targets, before):
        outcome = initial
        if apply and initial == 'unready':
            descriptor = controllers[target.domain]
            request = parse_controller_request({
                'operation': 'team_rotate', 'domain': target.domain, 'name': target.name,
                'new_team_did_key': target.team_did_key, 'expected_team_did_key': target.team_did_key,
            })
            try:
                await client.controller_request(request, controllers={'controller': descriptor}, signer=signer)
            except RegistryError as exc:
                if exc.status_code != 409:
                    raise
                outcome = 'conflicted'
            else:
                outcome = await state(target)
        outcomes.append(outcome)

    def counts(values):
        return {'total': len(targets), **{label: values.count(label) for label in ('ready', 'unready', 'conflicted')}}

    return {'before': counts(before), 'after': counts(outcomes), 'applied': bool(apply),
            'teams': [{'domain': t.domain, 'name': t.name, 'state': outcome}
                      for t, outcome in zip(targets, outcomes)]}
