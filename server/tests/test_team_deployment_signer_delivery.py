"""The deployment's rendered service-delivery settings, read by the real host."""

import base64
import json
from pathlib import Path
from time import monotonic
from types import SimpleNamespace

import httpx
import pytest
from awid.did import did_from_public_key, generate_keypair
from awid.protected_membership import TeamProtectionObservation
from aweb_naapp.runtime.protected_signer import CatalogOperation, SignerRefused
from pydantic import ValidationError

from aweb.protected_signing.host import HostSettings, load_custodies
from tests.test_protected_custody_manifest import slots  # noqa: F401  (fixture)
from tests.test_protected_service_profile import FIXTURE
from tests.test_team_deployment_render_env import EXAMPLE, PROFILE, SIGNER, render_env

PRIVATE = "/run/secrets/signer/private-controller"
SECRETS = "https://secrets.example.com"
LOGS = "https://logs.example.com"


@pytest.fixture
def deployment(slots, tmp_path):  # noqa: F811
    """A rendered signer section and the custody files it names, on this machine."""
    settings, profile, paths, member_file, seeds = slots
    custody = Path(next(iter(paths.values()))).parent
    profile_file = tmp_path / "profile.json"
    profile_file.write_text(json.dumps(PROFILE), encoding="utf-8")

    def render(**signer):
        return render_env.render({**EXAMPLE, "signer": {**SIGNER, "profileFile": str(profile_file), **signer}})

    def install(seed):
        path = custody / "service.key"
        path.write_text(seed.hex() + "\n")
        path.chmod(0o400)

    def host(rendered, monkeypatch):
        for name in ("AWEB_PROTECTED_SERVICE_KEY_FILE", "AWEB_PROTECTED_OWNER_ACT_ORIGINS",
                     "AWEB_PROTECTED_EFFECT_RECEIPT_ORIGINS"):
            monkeypatch.delenv(name, raising=False)
            if name in rendered:
                # The container's private-controller/ is the custodian's directory, bind-mounted.
                monkeypatch.setenv(name, rendered[name].replace(PRIVATE, str(custody)))
        actual = HostSettings(profile_file=FIXTURE, scope_file=tmp_path / "scope.json",
            controller_key_file=settings.controller_key_file, controller_keys_file=settings.controller_keys_file,
            member_keys_file=settings.member_keys_file, worker_uids=settings.worker_uids,
            database_url="postgresql://unused", _env_file=None)
        return actual, lambda: load_custodies(actual, profile=profile, scope=profile.bindings[0].scope.model_dump(mode="json"))

    return SimpleNamespace(render=render, install=install, host=host, seeds=seeds, member_file=member_file)


def test_a_rendered_service_delivery_reaches_the_host_and_its_custody(deployment, monkeypatch):
    seed, _ = generate_keypair()
    deployment.install(seed)
    rendered = deployment.render(serviceKey=True, ownerActOrigins=[SECRETS, LOGS], effectReceiptOrigins=[SECRETS])
    settings, custodies = deployment.host(rendered, monkeypatch)
    assert (settings.owner_act_origins, settings.effect_receipt_origins) == ((SECRETS, LOGS), (SECRETS,))
    _, _, custody = custodies()
    assert all(key.service_did_key is not None and key.service_did_key != key.team_key_did for _, key in custody)


def test_without_service_delivery_the_host_has_no_service_key_and_no_consumer(deployment, monkeypatch):
    settings, custodies = deployment.host(deployment.render(), monkeypatch)
    assert (settings.service_key_file, settings.owner_act_origins, settings.effect_receipt_origins) == (None, (), ())
    _, _, custody = custodies()
    assert all(key.service_did_key is None for _, key in custody)


@pytest.mark.parametrize("reused", ["selected_controller", "other_authority", "member"])
def test_a_service_key_that_is_any_served_authority_or_member_key_is_refused(deployment, monkeypatch, reused):
    if reused == "member":
        der = base64.b64decode(b"".join(deployment.member_file.read_bytes().splitlines()[1:-1]))
        seed = der[-32:]
    else:
        seed = deployment.seeds[0 if reused == "selected_controller" else 1]
    deployment.install(seed)
    _, custodies = deployment.host(deployment.render(serviceKey=True), monkeypatch)
    with pytest.raises(SignerRefused, match="custody_not_isolated"):
        custodies()


def test_a_service_key_the_custodian_did_not_install_is_refused_before_any_service_runs(deployment, monkeypatch):
    _, custodies = deployment.host(deployment.render(serviceKey=True), monkeypatch)
    with pytest.raises(SignerRefused):
        custodies()


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("AWEB_PROTECTED_OWNER_ACT_ORIGINS", "https://secrets.example.com"),
        ("AWEB_PROTECTED_OWNER_ACT_ORIGINS", '["https://secrets.example.com/path"]'),
        ("AWEB_PROTECTED_OWNER_ACT_ORIGINS", '["http://secrets.example.com"]'),
        ("AWEB_PROTECTED_EFFECT_RECEIPT_ORIGINS", '[""]'),
    ],
)
def test_the_host_refuses_a_malformed_value_given_around_the_bundle(monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    with pytest.raises(ValidationError):
        HostSettings(profile_file=FIXTURE, scope_file=Path("/nonexistent"), controller_key_file=Path("/nonexistent"),
            member_keys_file=Path("/nonexistent"), worker_uids=[65534], database_url="postgresql://unused",
            _env_file=None)


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["ready", "not_receipt_ready", "unpinned", "other_service_key"])
async def test_rendered_receipt_readiness_decides_what_the_real_custody_serves(deployment, monkeypatch, case):
    seed, _ = generate_keypair()
    deployment.install(seed)
    ready = [] if case == "not_receipt_ready" else [SECRETS]
    rendered = deployment.render(serviceKey=True, ownerActOrigins=[SECRETS], effectReceiptOrigins=ready)
    settings, custodies = deployment.host(rendered, monkeypatch)
    _, _, loaded = custodies()
    binding, custody = loaded[0]
    context = binding.context()
    origin = LOGS if case == "unpinned" else SECRETS
    service_did_key = custody.service_did_key
    if case == "other_service_key":
        service_did_key = did_from_public_key(generate_keypair()[1])
    observation = TeamProtectionObservation(context.authority_id, custody.team_key_did, {
        "mode": "protected", "history_id": "11111111-1111-4111-8111-111111111111", "generation": 1,
        "service_id": context.service_id, "service_did_key": service_did_key}, monotonic() + 60)
    authority = SimpleNamespace(context=context, protection=observation, team_key_did=custody.team_key_did,
        require_fresh=lambda: None)
    operation = CatalogOperation("22222222-2222-4222-8222-222222222222", context, origin,
        "human-role.revoke", "default", {"app_id": "app", "installation_id": "installation",
            "role": "app.owner", "principal": "did:aw:owner"})
    async with httpx.AsyncClient() as client:
        custody.configure_effects(registry=None, clients={o: client for o in settings.owner_act_origins},
            clock=lambda: None, receipt_origins=frozenset(settings.effect_receipt_origins))
        if case == "ready":
            assert custody.require_service_delivery(operation=operation, authority=authority) is None
        else:
            with pytest.raises(SignerRefused, match="operation_not_served"):
                custody.require_service_delivery(operation=operation, authority=authority)
