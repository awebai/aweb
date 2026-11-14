"""Non-signing capability checks use explicit host consumer readiness."""

from dataclasses import replace
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
        "human-role.revoke", "default", {})
    # Startup checked real custody; the capability method may only inspect
    # configured identities and presence, never access either private key.
    custody._key = custody._service_key = SealedKey()
    return SimpleNamespace(custody=custody, operation=operation, authority=authority)


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["ready", "no_receipt", "no_client", "closed_client", "legacy",
    "wrong_service", "wrong_service_key", "wrong_controller", "wrong_team", "wrong_context",
    "missing_key", "stale"])
async def test_capability_requires_current_isolation_and_explicit_pinned_receipt_consumer(capability, case):
    c = capability
    async with httpx.AsyncClient() as client:
        clients = {} if case == "no_client" else {ORIGIN: client}
        receipts = frozenset() if case == "no_receipt" else frozenset({ORIGIN})
        c.custody.configure_effects(registry=None, clients=clients, receipt_origins=receipts, clock=lambda: None)
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
        elif case == "stale":
            def expired():
                raise SignerRefused("evidence_unavailable")
            c.authority.require_fresh = expired
        c.authority.protection = observation
        if case == "ready":
            assert c.custody.require_service_delivery(operation=c.operation, authority=c.authority) is None
        else:
            code = "evidence_unavailable" if case == "stale" else "operation_not_served"
            with pytest.raises(SignerRefused, match=code):
                c.custody.require_service_delivery(operation=c.operation, authority=c.authority)


def test_required_readiness_is_rechecked_at_retention_without_touching_the_artifact(capability):
    c = capability
    operation = SimpleNamespace(context=c.operation.context, audience=ORIGIN,
        spec=SimpleNamespace(effect=SimpleNamespace(requires_service_delivery=True)))
    with pytest.raises(SignerRefused, match="operation_not_served"):
        c.custody.retain_authorized_effect(operation=operation, request={}, artifact={},
            signing=b"unchanged", signature=b"unchanged", authority=c.authority, expires_at=None)
