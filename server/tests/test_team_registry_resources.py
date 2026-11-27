"""Unit resource seam: SDK acquisition and native pin admission stay separate."""

from contextlib import aclosing
from types import SimpleNamespace

import httpx
import pytest
from aweb.certificate_evidence import EvidenceMode
from aweb.team_key_reader import read_team_key
from awid.did import did_key_from_signing_key
from awid.external_authority import SystemTXTOutcomeResolver
from awid.registry import CachedRegistryClient
from awid.team_key_acts import TeamKeyMemo
from test_team_key_rotation_cache import _Redis


@pytest.mark.asyncio
async def test_explicit_team_key_reader_uses_borrowed_sdk_strength_and_one_pin_owner(
    monkeypatch,
):
    # Stand-in pin admission records the interface, not controller authority.
    import aweb.team_key_reader as owner

    cached_key = did_key_from_signing_key(b"\x01" * 32)
    fresh_key = did_key_from_signing_key(b"\x02" * 32)
    key = [cached_key]
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
            await read_team_key(**arguments, evidence=EvidenceMode.CACHED) == cached_key
        )
        key[0] = fresh_key
        assert (
            await read_team_key(**arguments, evidence=EvidenceMode.CACHED) == cached_key
        )
        assert (
            await read_team_key(**arguments, evidence=EvidenceMode.FRESH) == fresh_key
        )
        assert len(reads) == 2
        for admission in admissions:
            assert admission["db"] is db
            assert admission["registry_client"] is client
            assert admission["txt_resolver"] is resolver
            assert admission["pin_memo"] is memo
        with pytest.raises(TypeError, match="named EvidenceMode"):
            await read_team_key(**arguments, evidence="fresh")


@pytest.mark.asyncio
async def test_request_registration_uses_the_resource_client_over_the_outer_slot():
    """Unit wiring only: an empty transport response proves no admission rule."""
    from aweb.application_state import application_registry_client
    from aweb.certificate_registration import (
        RegistrationMode,
        observe_certificate_registrations,
    )
    from awid.registry import RegistryClient
    from fastapi import FastAPI
    from starlette.requests import Request

    reads = []

    def reply(request):
        reads.append(request.url.host)
        return httpx.Response(200, json={"certificates": [], "has_more": False})

    app = FastAPI()
    async with aclosing(
        RegistryClient(
            registry_url="https://serving.example", transport=httpx.MockTransport(reply)
        )
    ) as client:
        app.state.native_resources = SimpleNamespace(registry_client=client)
        app.state.awid_registry_client = object()
        request = Request({"type": "http", "app": app})
        facts = await observe_certificate_registrations(
            registry_client=application_registry_client(request.app.state),
            team_id="team:example.test",
            mode=RegistrationMode.REQUIRED,
        )
        assert facts.registered_certificate_ids == set()
    assert reads == ["serving.example"]


@pytest.mark.asyncio
async def test_request_pin_refresh_uses_the_same_borrowed_native_resources(monkeypatch):
    """Unit pin-adapter wiring; the recorder is not controller authority proof."""
    import aweb.team_registry as owner
    from awid.registry import RegistryClient
    from fastapi import FastAPI
    from starlette.requests import Request

    received = []

    async def record_pin(**arguments):
        received.append(arguments)
        return "refreshed-controller"

    monkeypatch.setattr(owner, "read_team_key", record_pin)
    outer, native = FastAPI(), FastAPI()
    db, resolver = object(), SystemTXTOutcomeResolver()
    native.state.public_origin = "https://native.example"
    native.state.awid_txt_resolver = resolver
    outer.state.public_origin = "https://unused-outer.example"
    async with aclosing(
        RegistryClient(registry_url="https://serving.example")
    ) as client:
        outer.state.native_resources = SimpleNamespace(
            api_app=native, registry_client=client
        )
        request = Request({"type": "http", "app": outer})
        assert owner.request_auth_audiences(request) == ["https://native.example"]
        assert (
            await owner.resolve_team_key(
                request, "team:example.test", db=db, rejected_key="stale-controller"
            )
            == "refreshed-controller"
        )
        assert received[0]["registry_client"] is client
        assert received[0]["txt_resolver"] is resolver
        assert received[0]["db"] is db
        assert received[0]["rejected_key"] == "stale-controller"
        assert received[0]["pin_memo"] is native.state.team_key_pin_memo
        assert not hasattr(outer.state, "team_key_pin_memo")
