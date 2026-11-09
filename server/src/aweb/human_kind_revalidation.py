"""Operator revalidation of historical human labels through the public verifier."""
from __future__ import annotations

from fastapi import HTTPException

from aweb.human_kind import IdentityKindObservation, is_verified_human, observe_identity_kind
from aweb.identity_binding import IdentityBinding, observe_identity_binding

OUTCOMES = ('human', 'agent', 'revoked', 'unregistered', 'unavailable', 'invalid')


async def _rows(db):
    return await db.fetch_all(
        """SELECT agent_id, did_key, did_aw, agent_type, human_verified_key, deleted_at
           FROM {{tables.agents}} WHERE agent_type='human' ORDER BY agent_id"""
    )


def _inventory(rows):
    result = {state: {'total': 0, 'verified': 0} for state in ('active', 'retired')}
    for row in rows:
        counts = result['active' if row['deleted_at'] is None else 'retired']
        counts['total'] += 1
        counts['verified'] += int(is_verified_human(row))
    return result


async def _observe_row(registry_client, row):
    if not row['did_key']:
        return 'invalid'
    try:
        binding = (await observe_identity_binding(
            registry_client, did_key=row['did_key'], did_aw=row['did_aw'],
        )) if row['did_aw'] else IdentityBinding(did_key=row['did_key'])
    except HTTPException as exc:
        return 'unavailable' if exc.status_code == 503 else 'invalid'
    observation = await observe_identity_kind(registry_client, binding)
    if (not isinstance(observation, IdentityKindObservation)
            or observation.did_key != row['did_key']
            or observation.did_aw != (row['did_aw'] or '')):
        return 'invalid'
    result = observation.result
    if result['identity_valid'] is True and result['kind'] in ('human', 'agent'):
        return result['kind']
    if result['reason'] == 'revoked':
        return 'revoked'
    if result['reason'] in ('unregistered_identity', 'legacy_no_chain'):
        return 'unregistered'
    return 'unavailable' if result['outcome'] == 'unavailable' else 'invalid'


async def revalidate_human_kind(db, registry_client, *, apply: bool = False):
    """Report all legacy humans; only --apply may stamp live verified subjects.

    Registry work happens outside DB transactions. A compare-and-set binds each
    write to the observed row's key, stable ID, raw type and live status. Failed
    observations never write or clear markers. Retired rows are report-only.
    """
    rows = await _rows(db)
    report = {
        'apply': apply,
        'before': _inventory(rows),
        'outcomes': {state: dict.fromkeys(OUTCOMES, 0) for state in ('active', 'retired')},
        'stamped': 0,
        'changed': 0,
    }
    for row in rows:
        state = 'active' if row['deleted_at'] is None else 'retired'
        outcome = await _observe_row(registry_client, row)
        report['outcomes'][state][outcome] += 1
        if apply and state == 'active' and outcome == 'human':
            stamped = await db.fetch_one(
                """UPDATE {{tables.agents}} SET human_verified_key=$2
                   WHERE agent_id=$1 AND did_key=$2
                     AND did_aw IS NOT DISTINCT FROM $3 AND agent_type='human'
                     AND deleted_at IS NULL RETURNING agent_id""",
                row['agent_id'], row['did_key'], row['did_aw'],
            )
            report['stamped' if stamped else 'changed'] += 1
    report['after'] = _inventory(await _rows(db))
    report['unresolved_active'] = report['changed'] + sum(
        count for outcome, count in report['outcomes']['active'].items() if outcome != 'human'
    )
    return report
