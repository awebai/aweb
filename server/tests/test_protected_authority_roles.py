"""Every selected key role resolves its own current authority, never a worker key."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from awid.did import did_from_public_key, generate_keypair
from aweb_naapp.runtime.protected_signer import SignerRefused
from aweb.protected_signing.authority import IndependentAuthority
from aweb.protected_signing.profile import ProtectedServiceProfile
from tests.test_protected_service_profile import FIXTURE


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "role", ["team_controller", "namespace_controller", "human_identity"]
)
@pytest.mark.parametrize("matching", [True, False])
async def test_selected_role_uses_its_own_fresh_authority(monkeypatch, role, matching):
    import aweb.protected_signing.authority as module

    original = (
        ProtectedServiceProfile.from_json(FIXTURE.read_bytes()).bindings[0].context()
    )
    authority_id = {
        "team_controller": original.authority_id,
        "namespace_controller": original.authority_domain,
        "human_identity": original.human_id,
    }[role]
    context = replace(original, authority_kind=role, authority_id=authority_id)
    _, public = generate_keypair()
    human_key = did_from_public_key(public)
    _, public = generate_keypair()
    controller_key = (
        human_key if role == "human_identity" else did_from_public_key(public)
    )
    _, public = generate_keypair()
    custody_key = controller_key if matching else did_from_public_key(public)
    reads = []

    async def binding(*args, **kwargs):
        return SimpleNamespace(
            self_derived=False,
            id_tree=SimpleNamespace(enrolled=True, domain=context.human_domain),
        )

    async def kind(*args, **kwargs):
        return SimpleNamespace(
            result={"outcome": "verified", "human_id": context.human_id}, is_human=True
        )

    monkeypatch.setattr(module, "observe_identity_binding", binding)
    monkeypatch.setattr(module, "observe_identity_kind", kind)

    class Registry:
        async def resolve_key_fresh(self, principal):
            reads.append(("human", principal))
            return SimpleNamespace(current_did_key=human_key)

        async def get_team_fresh(self, domain, name):
            reads.append(("team", domain, name))
            return SimpleNamespace(team_id=context.authority_id, team_did_key=controller_key,
                protection={"mode": "legacy"})

        async def get_namespace_fresh(self, domain):
            reads.append(("namespace", domain))
            return SimpleNamespace(controller_did=controller_key)

    authority = IndependentAuthority(
        object(),
        context=context,
        registry=Registry(),
        custody=SimpleNamespace(
            service_id=context.service_id,
            team_id=authority_id,
            authority_kind=role,
            team_key_did=custody_key,
        ),
    )
    if matching:
        result = await authority.observe(context, purpose="prepare")
        assert result.team_key_did == custody_key
    else:
        with pytest.raises(SignerRefused, match="authority_changed"):
            await authority.observe(context, purpose="prepare")
    assert reads[0] == ("human", context.human_id)
    assert len(reads) == (1 if role == "human_identity" else 2)
    if role != "human_identity":
        assert reads[-1][0] == (
            "namespace" if role == "namespace_controller" else "team"
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("evidence", ["missing", "outage"])
async def test_team_authority_never_infers_legacy_from_missing_or_failed_projection(monkeypatch, evidence):
    from awid.registry_types import RegistryError

    context = ProtectedServiceProfile.from_json(FIXTURE.read_bytes()).bindings[0].context()
    _, public = generate_keypair()
    controller = did_from_public_key(public)

    async def current_human(*args):
        return controller

    monkeypatch.setattr(IndependentAuthority, "_own_human", current_human)

    class Registry:
        async def get_team_fresh(self, domain, name):
            if evidence == "outage":
                raise RegistryError("registry unavailable", status_code=503)
            return SimpleNamespace(team_id=context.authority_id, team_did_key=controller, protection=None)

        async def get_team_public_key_fresh(self, *args):
            pytest.fail("key-only evidence cannot substitute for current protection")

    authority = IndependentAuthority(object(), context=context, registry=Registry(),
        custody=SimpleNamespace(service_id=context.service_id, team_id=context.authority_id,
            authority_kind=context.authority_kind, team_key_did=controller))
    with pytest.raises(SignerRefused, match="evidence_unavailable"):
        await authority.observe(context, purpose="prepare")


@pytest.mark.asyncio
async def test_namespace_authority_read_stays_on_profile_registry_and_pin():
    import httpx

    from awid.registry import RegistryClient
    from aweb.protected_signing.registry import PinnedRegistryView

    profile = ProtectedServiceProfile.from_json(FIXTURE.read_bytes())
    domain, pin = next(iter(profile.namespace_keys().items()))
    calls = []
    controller = pin

    async def upstream(request):
        calls.append(request.url)
        return httpx.Response(
            200,
            json={
                "namespace_id": "namespace",
                "domain": domain,
                "controller_did": controller,
                "verification_status": "verified",
                "created_at": "2026-11-12T00:00:00Z",
            },
        )

    async def forbidden_discovery(*args):
        raise AssertionError("a pinned authority read must not rediscover its origin")

    client = RegistryClient(
        registry_url=profile.registry_origin,
        transport=httpx.MockTransport(upstream),
        domain_registry_resolver=forbidden_discovery,
    )
    view = PinnedRegistryView(client, profile=profile)
    try:
        record = await view.get_namespace_fresh(domain)
        assert record.controller_did == pin
        assert str(calls[-1]) == profile.registry_origin + "/v1/namespaces/" + domain
        _, public = generate_keypair()
        controller = did_from_public_key(public)
        with pytest.raises(SignerRefused, match="authority_changed"):
            await view.get_namespace_fresh(domain)
    finally:
        await client.aclose()
