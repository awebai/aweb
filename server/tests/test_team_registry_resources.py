"""Unit resource seam: SDK acquisition and native pin admission stay separate."""

from contextlib import aclosing
from types import SimpleNamespace

import httpx
import pytest
from awid.external_authority import SystemTXTOutcomeResolver
from awid.registry import CachedRegistryClient
from awid.team_key_acts import TeamKeyMemo

from aweb.certificate_evidence import EvidenceMode
from aweb.team_registry import read_team_key
from test_team_key_rotation_cache import _Redis


@pytest.mark.asyncio
async def test_explicit_team_key_reader_uses_borrowed_sdk_strength_and_one_pin_owner(
    monkeypatch,
):
    # Stand-in pin admission records the interface, not controller authority.
    import aweb.team_registry as owner

    key = ["cached-controller"]
    reads, admissions = [], []

    def reply(request):
        reads.append(request.url.path)
        return httpx.Response(
            200,
            json={
                "domain": "example.test",
                "name": "team",
                "team_id": "team:example.test",
                "team_did_key": key[0],
                "created_at": "2026-01-01T00:00:00Z",
            },
        )

    async def record_admission(**kwargs):
        admissions.append(kwargs)
        return kwargs["served_key"]

    monkeypatch.setattr(owner, "pinned_team_key", record_admission)
    db = SimpleNamespace()
    resolver, memo = SystemTXTOutcomeResolver(), TeamKeyMemo()
    async with aclosing(
        CachedRegistryClient(
            registry_url="http://registry.test",
            redis_client=_Redis([1_000_000]),
            transport=httpx.MockTransport(reply),
        )
    ) as client:
        arguments = dict(
            db=db,
            registry_client=client,
            txt_resolver=resolver,
            team_id="team:example.test",
            pin_memo=memo,
        )
        assert (
            await read_team_key(**arguments, evidence=EvidenceMode.CACHED)
            == "cached-controller"
        )
        key[0] = "fresh-controller"
        assert (
            await read_team_key(**arguments, evidence=EvidenceMode.CACHED)
            == "cached-controller"
        )
        assert (
            await read_team_key(**arguments, evidence=EvidenceMode.FRESH)
            == "fresh-controller"
        )
        assert len(reads) == 2
        for admission in admissions:
            assert admission["db"] is db
            assert admission["registry_client"] is client
            assert admission["txt_resolver"] is resolver
            assert admission["pin_memo"] is memo
        with pytest.raises(TypeError, match="named EvidenceMode"):
            await read_team_key(**arguments, evidence="fresh")
