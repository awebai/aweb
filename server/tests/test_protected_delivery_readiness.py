"""Non-signing capability checks use explicit host consumer readiness."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from time import monotonic
from types import SimpleNamespace

import httpx
import pytest
from aweb_naapp.runtime.protected_signer import CatalogOperation, ProtectedKeyContext, SignerRefused
from awid.protected_membership import TeamProtectionObservation
from nacl.signing import SigningKey

from aweb.protected_signing.custody import ProtectedControllerCustody
from tests.test_independent_protected_signer import did

TEAM = "engineering:example.test"
ORIGIN = "https://consumer.example"


class SealedKey:
    def sign(self, *args):
        pytest.fail("capability checks cannot sign")

    def __bytes__(self):
        pytest.fail("capability checks cannot read key bytes")


@pytest.fixture
def capability(tmp_path):
    controller, service = SigningKey.generate(), SigningKey.generate()
    directory = tmp_path / "custody"
    directory.mkdir(mode=0o700)
    for name, key in (("controller", controller), ("service", service)):
        path = directory / name
        path.write_text(bytes(key).hex())
        path.chmod(0o400)
    custody = ProtectedControllerCustody(service_id="service", team_id=TEAM, domain="example.test",
        key_file=directory / "controller", service_key_file=directory / "service",
        worker_uids=frozenset({65534}))
    context = ProtectedKeyContext("service", "team_controller", TEAM, "example.test",
        "did:aw:owner", "example.test", 1)
    binding = {"mode": "protected", "history_id": "11111111-1111-4111-8111-111111111111",
        "generation": 1, "service_id": "service", "service_did_key": did(service)}
    observation = TeamProtectionObservation(TEAM, did(controller), binding, monotonic() + 60)
    authority = SimpleNamespace(context=context, protection=observation, team_key_did=did(controller),
        require_fresh=lambda: None)
    operation = CatalogOperation("22222222-2222-4222-8222-222222222222", context, ORIGIN,
        "human-role.revoke", "default", {"app_id": "app", "installation_id": "installation",
            "role": "app.owner", "principal": "did:aw:owner"})
    # Startup checked real custody; the capability method may only inspect
    # configured identities and presence, never access either private key.
    custody._key = custody._service_key = SealedKey()
    return SimpleNamespace(custody=custody, operation=operation, authority=authority)


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["ready", "no_receipt", "default_receipt", "no_client", "closed_client", "legacy",
    "wrong_service", "wrong_service_key", "wrong_controller", "wrong_team", "wrong_context",
    "missing_key", "no_protection", "stale", "final_stale"])
async def test_capability_requires_current_isolation_and_explicit_pinned_receipt_consumer(capability, case):
    c = capability
    async with httpx.AsyncClient() as client:
        clients = {} if case == "no_client" else {ORIGIN: client}
        receipts = frozenset() if case == "no_receipt" else frozenset({ORIGIN})
        options = {} if case == "default_receipt" else {"receipt_origins": receipts}
        c.custody.configure_effects(registry=None, clients=clients, clock=lambda: None, **options)
        if case == "closed_client":
            await client.aclose()
        observation = c.authority.protection
        if case == "legacy":
            observation = replace(observation, binding={"mode": "legacy"})
        elif case in {"wrong_service", "wrong_service_key"}:
            binding = dict(observation.binding)
            binding["service_id" if case == "wrong_service" else "service_did_key"] = (
                "other" if case == "wrong_service" else did(SigningKey.generate()))
            observation = replace(observation, binding=binding)
        elif case == "wrong_controller":
            observation = replace(observation, controller_did_key=did(SigningKey.generate()))
        elif case == "wrong_team":
            observation = replace(observation, team_id="other:example.test")
        elif case == "wrong_context":
            c.authority.context = replace(c.operation.context, authority_id="other:example.test")
        elif case == "missing_key":
            c.custody._service_key = None
        elif case == "no_protection":
            observation = None
        elif case == "stale":
            def expired():
                raise SignerRefused("evidence_unavailable")
            c.authority.require_fresh = expired
        elif case == "final_stale":
            checks = 0
            def expires_after_capability_check():
                nonlocal checks
                checks += 1
                if checks == 2:
                    raise SignerRefused("evidence_unavailable")
            c.authority.require_fresh = expires_after_capability_check
        c.authority.protection = observation
        if case == "ready":
            assert c.custody.require_service_delivery(operation=c.operation, authority=c.authority) is None
        else:
            code = "evidence_unavailable" if case in {"stale", "final_stale"} else "operation_not_served"
            with pytest.raises(SignerRefused, match=code):
                c.custody.require_service_delivery(operation=c.operation, authority=c.authority)


@pytest.mark.asyncio
async def test_required_readiness_is_rechecked_at_retention_without_touching_the_artifact(capability, monkeypatch):
    from aweb_naapp.runtime.protected_signer import catalog

    c = capability
    spec = c.operation.spec
    effect = SimpleNamespace(**vars(spec.effect), requires_service_delivery=True)
    monkeypatch.setattr(catalog, "OPERATIONS", {**catalog.OPERATIONS,
        (c.operation.operation, c.operation.variant): replace(spec, effect=effect)})

    class UnreadableArtifact(dict):
        def __getitem__(self, key):
            pytest.fail("missing receipt readiness must refuse before reading an artifact")

        def get(self, *args):
            pytest.fail("missing receipt readiness must refuse before reading an artifact")

    now = datetime.now(UTC)
    async with httpx.AsyncClient() as client:
        # Transport is installed; only the explicit receipt readiness is absent.
        c.custody.configure_effects(registry=None, clients={ORIGIN: client}, clock=lambda: now)
        with pytest.raises(SignerRefused, match="operation_not_served"):
            c.custody.retain_authorized_effect(operation=c.operation, request={}, artifact=UnreadableArtifact(),
                signing=b"unchanged", signature=b"unchanged", authority=c.authority,
                expires_at=now + timedelta(seconds=60))
