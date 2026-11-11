"""Human classification is a projection of the subject's verified ID kind.

Raw runtime labels remain usable as historical provenance, never as evidence of
current human kind. Acquire observations before opening a projection transaction.
"""
from __future__ import annotations

import logging
from collections.abc import Mapping

from awid.identity_observation import (
    IdentityKindObservation as IdentityKindObservation,
)
from awid.identity_observation import (
    observe_identity_kind as observe_identity_kind,
)
from awid.identity_observation import (
    unverified_kind as unverified_kind,
)

logger = logging.getLogger(__name__)


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
