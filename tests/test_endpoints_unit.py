from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from library.models import MaterializeRequest
from library.repository import materialize

_FIXTURE = Path(__file__).parent / "vectors" / "profile-packs" / "engineering"


async def test_materialize_requires_agent_or_profile_ref() -> None:
    # With neither agent_id nor profile_ref, materialize fails before any DB use —
    # "materialize requires a bound profile" at the request boundary.
    with pytest.raises(HTTPException) as excinfo:
        await materialize(
            object(),  # never touched on this path
            principal=SimpleNamespace(team_id="default:atext.aweb.ai"),
            request=MaterializeRequest(runtime_kind="claude-code", target="local"),
        )
    assert excinfo.value.status_code == 422


def test_empty_profile_invariant_is_what_library_honors() -> None:
    invariant = json.loads((_FIXTURE / "expected" / "empty-profile-invariant.json").read_text(encoding="utf-8"))
    assert invariant["schema"] == "aweb.profile-pack.empty-profile-invariant.v1"
    # Library is optional: a team and its agents exist without any Library state.
    assert invariant["team_create"]["must_succeed_without_library"] is True
    assert invariant["team_create"]["profile_pack_required"] is False
    assert invariant["agent_add"]["profile_binding_required"] is False
    # Materialize needs a bound profile, but an all-empty team is not an error.
    assert invariant["materialize"]["requires_bound_profile"] is True
    assert invariant["materialize"]["empty_profile_is_not_error"] is True
