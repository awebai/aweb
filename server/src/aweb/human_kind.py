"""Human classification is a projection of the subject's verified ID kind.

Raw runtime labels remain usable as historical provenance, never as evidence of
current human kind. Acquire observations before opening a projection transaction.
"""
from __future__ import annotations

from dataclasses import dataclass
import logging
from types import MappingProxyType
from typing import Any, Mapping

from awid.id_certificates import IDCertificateError, status_request, verify_id_chain
from aweb.identity_binding import IdentityBinding

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class IdentityKindObservation:
    """Trusted in-process verifier output, not a request DTO or credential."""
    did_key: str
    did_aw: str
    result: Mapping[str, Any]

    @property
    def is_human(self) -> bool:
        return self.result['identity_valid'] is True and self.result['kind'] == 'human'


def unverified_kind(reason: str) -> dict[str, Any]:
    unavailable = reason in ('evidence_unavailable', 'status_expired')
    return {'outcome': 'unavailable' if unavailable else 'unknown', 'human_id': None,
            'identity_valid': None if unavailable or reason == 'unregistered_identity' else False,
            'kind': None, 'reason': reason}


async def observe_identity_kind(registry_client, binding: IdentityBinding, bundle=None) -> IdentityKindObservation:
    """Verify the exact bound subject using the public verifier and cached evidence.

    Original authentication and fresh global identity binding belong to the
    caller. Unknown/unavailable/invalid results are returned for its existing
    disposition policy; none can establish human kind. No registry fallback or
    team/address inference is performed here.
    """
    subject = {'id': binding.did_aw or binding.did_key, 'did_key': binding.did_key}
    try:
        enrollment = binding.id_tree
        if binding.did_aw and enrollment is None:
            result = unverified_kind('evidence_unavailable')
        elif binding.did_aw and not enrollment.enrolled and bundle is None:
            result = unverified_kind('unregistered_identity')
        else:
            domain = enrollment.domain if binding.did_aw and enrollment.enrolled else None
            plan = status_request(bundle, subject, domain=domain)
            evidence = None
            if plan is not None:
                cached_evidence = getattr(registry_client, 'id_chain_evidence', None)
                if callable(cached_evidence):
                    try:
                        evidence = await cached_evidence(bundle, subject, domain=plan['domain'])
                    except Exception:
                        logger.warning('ID-tree cached evidence failed', exc_info=True)
            result = verify_id_chain(bundle, subject=subject, evidence=evidence, domain=domain)
    except IDCertificateError as exc:
        result = unverified_kind(exc.code)
    return IdentityKindObservation(binding.did_key, binding.did_aw, MappingProxyType(result))


def is_verified_human(row: Mapping) -> bool:
    return (row.get('agent_type') == 'human' and bool(row.get('did_key'))
            and row.get('human_verified_key') == row['did_key'])


def effective_agent_type(row: Mapping) -> str:
    runtime = row.get('agent_type') or 'agent'
    return 'unknown' if runtime == 'human' and not is_verified_human(row) else runtime


def human_predicate_sql(alias: str = '') -> str:
    """Null-safe current-human predicate; alias is a source-code SQL identifier."""
    if alias and (not alias.isascii() or not alias.isidentifier()):
        raise ValueError('Invalid SQL alias')
    prefix = alias + '.' if alias else ''
    return (f"COALESCE({prefix}agent_type = 'human' AND "
            f"{prefix}human_verified_key = NULLIF({prefix}did_key, ''), FALSE)")


def agent_listing_predicate_sql(alias: str = '') -> str:
    """Display only: legacy human labels must not turn into agent roster entries."""
    human_predicate_sql(alias)  # Validate the source-code identifier consistently.
    prefix = alias + '.' if alias else ''
    return f"COALESCE({prefix}agent_type, 'agent') <> 'human'"
