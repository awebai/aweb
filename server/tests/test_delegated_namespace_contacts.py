"""Parent-authorized child contacts through real CLI, HTTP, AWID, DB and Redis.

Only DNS is supplied by the test. The registry verifies the parent's actual
registration signature. Negative cases corrupt that real namespace response's
witness to model an inconsistent registry; no auth or policy check is replaced.
"""
from __future__ import annotations

import asyncio
import json
import os

import pytest

from aweb.federation.activation import FederationAuthorityActivation
from aweb.federation.authority import AuthorityClaim, FederationAuthorityCore
from aweb.federation.authority_state import AuthorityRepository
from aweb.federation.authority_work import AuthorityWorkRepository
from awid.external_authority import DNSLookup, OriginContext
from awid.external_registry import StrictExternalRegistry
from awid.federation_errors import FederationAuthorityError
from identity_binding_support import register_global_identity
from test_cli_human_reply import _pem
from test_cli_never_grants import registry_listener
from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401
from test_federation_preactivation_harness import _RecordedDNS
from test_messages_http import _make_certificate, _encode_certificate, _make_keypair


@pytest.mark.asyncio
@pytest.mark.parametrize("route", ["contact", "sender"])
@pytest.mark.parametrize("case,accepted", [
    ("delegated", True), ("exact", True), ("inherited_same_key", True),
    ("missing", False), ("wrong_parent_key", False), ("wrong_child_key", False),
    ("wrong_ancestor", False), ("non_ancestor", False), ("exact_mismatch", False),
])
async def test_delegated_namespace_authority(privacy_app, tmp_path, aw_cli_binary, case, accepted, route):
    env = privacy_app
    domain = "child.example.test"
    address = domain + "/carol"
    child_sk, _, child_key = _make_keypair()
    if case == "inherited_same_key":
        child_sk, child_key = env.team_sk, env.team_did
    exact = case in {"exact", "exact_mismatch"}
    actor = env.actors["bob"]
    target = env.actors["carol"]
    async with registry_listener(env) as (registry, registry_origin):
        owner_did = await register_global_identity(env, actor, "example.test/bob")
        await registry.register_namespace(domain, child_key, child_sk,
                                          parent_signing_key=env.team_sk,
                                          default_delivery_origin=env.app.state.public_origin)
        target_did = await register_global_identity(env, target, address)
        await env.db.execute(
            "UPDATE {{tables.agents}} SET did_aw=$1, did_aw_verified_key=did_key, "
            "address='example.test/bob', identity_scope='global' WHERE agent_id=$2", owner_did, actor.id,
        )

        class DNS(_RecordedDNS):
            async def lookup_txt(self, name):
                if not exact and name == "_awid." + domain:
                    self.queries.append(name)
                    return DNSLookup("nodata")
                return await super().lookup_txt(name)

        dns = DNS(domain if exact else "example.test", child_key if case == "exact" else env.team_did, registry_origin)
        resolver = StrictExternalRegistry(txt_resolver=dns, origin_context=OriginContext(
            app_env="development", federation_test_enabled=True, listener_origin=env.app.state.public_origin,
        ))
        paths = []
        real_factory = resolver.http_factory

        class WitnessFault:
            def __init__(self, inner):
                self.inner = inner

            async def get_json(self, path, **kwargs):
                value = await self.inner.get_json(path, **kwargs)
                paths.append(path)
                if path == "/v1/namespaces/" + domain:
                    assert value["delegation"] == {
                        "parent_domain": "example.test", "parent_controller_key": env.team_did,
                        "controller_key": child_key,
                    }
                    if case in {"missing", "inherited_same_key"}:
                        value.pop("delegation")
                    elif case == "wrong_parent_key":
                        value["delegation"]["parent_controller_key"] = child_key
                    elif case == "wrong_child_key":
                        value["delegation"]["controller_key"] = env.team_did
                    elif case in {"wrong_ancestor", "non_ancestor"}:
                        value["delegation"]["parent_domain"] = "test" if case == "wrong_ancestor" else "other.test"
                return value

            async def aclose(self):
                await self.inner.aclose()

        resolver.http_factory = lambda *args: WitnessFault(real_factory(*args))
        activation = FederationAuthorityActivation(
            core=FederationAuthorityCore(AuthorityRepository(env.db)), work=AuthorityWorkRepository(env.db),
            resolver=resolver, txt_resolver=dns,
        )
        env.app.state.federation_authority = activation
        try:
            if route == "sender":
                claim = AuthorityClaim(canonical_address=address, did_aw=target_did,
                                       current_did_key=target.did, delivery_origin=env.app.state.public_origin)
                if accepted:
                    authorized = await activation.authorize(claim, source_ip="127.0.0.1")
                    assert authorized.canonical_address == address
                    assert authorized.token.controller_did == child_key
                else:
                    with pytest.raises(FederationAuthorityError) as caught:
                        await activation.authorize(claim, source_ip="127.0.0.1")
                    assert caught.value.reason == "sender_address_did_mismatch"
            else:
                cert = _make_certificate(env.team_sk, env.team_did, actor.did, team_id=TEAM,
                                         alias="bob", identity_scope="global", member_did_aw=owner_did,
                                         member_address="example.test/bob", certificate_id="delegation-bob")
                await registry.register_team_certificate(
                    "example.test", TEAM.split(":", 1)[0], team_controller_signing_key=env.team_sk,
                    certificate_id=cert["certificate_id"], member_did_key=actor.did, member_did_aw=owner_did,
                    member_address="example.test/bob", alias="bob", identity_scope="global", certificate=_encode_certificate(cert),
                )
                home = tmp_path / "resident" / ".aw"
                home.mkdir(parents=True, mode=0o700)
                _pem(home / "signing.key", "ED25519 PRIVATE KEY", actor.sk)
                (home / "identity.yaml").write_text(json.dumps(dict(did=actor.did, stable_id=owner_did,
                    address="example.test/bob", custody="self", identity_scope="global")))
                (home / "certificate.json").write_text(json.dumps(cert))
                membership = dict(team_id=TEAM, alias="bob", cert_path="certificate.json")
                (home / "teams.yaml").write_text(json.dumps(dict(active_team=TEAM, memberships=[membership])))
                (home / "workspace.yaml").write_text(json.dumps(dict(aweb_url=str(env.client.base_url),
                    memberships=[dict(membership, workspace_id=str(actor.workspace))])))
                child_env = {k: v for k, v in os.environ.items() if not k.startswith(("AW_", "AWEB_", "AWID_", "OATS_"))}
                child_env.update(HOME=str(tmp_path), XDG_CONFIG_HOME=str(tmp_path / "config"),
                                 AW_NO_UPDATE_CHECK="1", AWID_REGISTRY_URL=registry_origin)

                async def run(selected, *args):
                    process = await asyncio.create_subprocess_exec(str(aw_cli_binary), "--identity-home", str(selected),
                        *args, cwd=tmp_path, env=child_env, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
                    output, _ = await asyncio.wait_for(process.communicate(), 30)
                    return process.returncode, output.decode()

                grant = tmp_path / "grant"
                code, output = await run(home, "id", "grant", "mint", "--scope", "contacts.write", "--ttl", "1h", "--out", str(grant))
                assert code == 0, output
                code, output = await run(grant, "contacts", "add", address, "--json")
                assert (code == 0) is accepted, output
                binding = await env.db.fetch_one("SELECT owner_did, contact_did_aw, binding_controller_did FROM {{tables.contacts}} WHERE contact_address=$1", address)
                if accepted:
                    assert dict(binding) == dict(owner_did=owner_did, contact_did_aw=target_did, binding_controller_did=child_key)
                else:
                    assert "sender_address_did_mismatch" in output, output
                    assert binding is None
            if not accepted:
                assert paths == ["/v1/namespaces/" + domain]
        finally:
            await activation.aclose()
