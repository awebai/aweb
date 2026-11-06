"""Contacts investigation: released CLI, real HTTP/AWID/PostgreSQL/Redis.

Fixture SQL provisions disposable identities. No auth, resolver, policy or
transport is mocked. An optional public probe uses real DNS and public AWID;
it changes only the disposable server's contacts, never a live identity.
"""
from __future__ import annotations

import asyncio
import json
import os
from types import SimpleNamespace

import pytest
import pytest_asyncio

from awid.signing import canonical_json_bytes, sign_message
from aweb.federation.activation import build_federation_authority_activation
from identity_binding_support import register_global_identity
from test_cli_human_reply import _pem
from test_cli_never_grants import registry_listener
from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401
from test_messages_http import _make_certificate, _encode_certificate


@pytest_asyncio.fixture
async def contacts_stack(privacy_app, tmp_path, monkeypatch, aw_cli_binary):
    env = privacy_app
    child_env = {k: v for k, v in os.environ.items() if not k.startswith(("AW_", "AWEB_", "AWID_", "OATS_"))}
    child_env.update(HOME=str(tmp_path), XDG_CONFIG_HOME=str(tmp_path / "config"), AW_NO_UPDATE_CHECK="1")
    async with registry_listener(env) as (registry, registry_origin):
        child_env["AWID_REGISTRY_URL"] = registry_origin
        homes = {}
        for alias in ("alice", "bob", "carol"):
            actor = env.actors[alias]
            address = f"example.test/{alias}" if alias != "alice" else ""
            stable = await register_global_identity(env, actor, address) if address else ""
            scope = "global" if stable else "local"
            if stable:
                await env.db.execute(
                    "UPDATE {{tables.agents}} SET did_aw=$1, did_aw_verified_key=did_key, "
                    "address=$2, identity_scope='global', inbound_mode='contacts_only' WHERE agent_id=$3",
                    stable, address, actor.id,
                )
            cert = _make_certificate(env.team_sk, env.team_did, actor.did, team_id=TEAM,
                                     alias=alias, identity_scope=scope, member_did_aw=stable,
                                     member_address=address, certificate_id=f"contacts-{alias}")
            if not stable:
                for field in ("signature", "member_did_aw", "member_address"):
                    cert.pop(field, None)
                cert["signature"] = sign_message(env.team_sk, canonical_json_bytes(cert))
            await registry.register_team_certificate(
                "example.test", TEAM.split(":", 1)[0], team_controller_signing_key=env.team_sk,
                certificate_id=cert["certificate_id"], member_did_key=actor.did,
                member_did_aw=stable or None, member_address=address or None,
                alias=alias, identity_scope=scope, certificate=_encode_certificate(cert),
            )
            home = tmp_path / alias / ".aw"
            home.mkdir(parents=True, mode=0o700)
            _pem(home / "signing.key", "ED25519 PRIVATE KEY", actor.sk)
            (home / "identity.yaml").write_text(json.dumps(dict(
                did=actor.did, stable_id=stable, address=address, custody="self", identity_scope=scope,
            )))
            (home / "certificate.json").write_text(json.dumps(cert))
            membership = dict(team_id=TEAM, alias=alias, cert_path="certificate.json")
            (home / "teams.yaml").write_text(json.dumps(dict(active_team=TEAM, memberships=[membership])))
            (home / "workspace.yaml").write_text(json.dumps(dict(
                aweb_url=str(env.client.base_url), memberships=[dict(membership, workspace_id=str(actor.workspace))],
            )))
            homes[alias] = home
        await env.registry_db.execute("UPDATE {{tables.dns_namespaces}} SET default_delivery_origin=$1", env.app.state.public_origin)
        monkeypatch.setenv("APP_ENV", "development")
        monkeypatch.setenv("AWEB_FEDERATION_TEST", "1")
        monkeypatch.setenv("AWEB_FEDERATION_TEST_DEFAULT_REGISTRY", "1")
        monkeypatch.setenv("AWID_REGISTRY_URL", registry_origin)
        authority = build_federation_authority_activation(env.infra, public_origin=env.app.state.public_origin)
        env.app.state.federation_authority = authority

        async def run(home, *args, ok=True):
            process = await asyncio.create_subprocess_exec(
                str(aw_cli_binary), "--identity-home", str(home), *args,
                cwd=tmp_path, env=child_env, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            )
            data, _ = await asyncio.wait_for(process.communicate(), 30)
            output = data.decode()
            assert (process.returncode == 0) == ok, output
            return output

        grant = tmp_path / "grant"
        await run(homes["bob"], "id", "grant", "mint", "--scope", "contacts.read", "--scope", "contacts.write",
                  "--ttl", "1h", "--out", str(grant), "--json")
        try:
            yield SimpleNamespace(env=env, homes=homes, grant=grant, run=run)
        finally:
            await authority.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("owner_kind", ["grant", "resident", "local"])
async def test_released_cli_contacts_and_local_delivery(contacts_stack, owner_kind):
    s = contacts_stack
    # Grant and resident share the same contact owner; a local identity can
    # also own a contact to an addressed global target.
    owner = {"grant": s.grant, "resident": s.homes["bob"], "local": s.homes["alice"]}[owner_kind]
    added = json.loads(await s.run(owner, "contacts", "add", "example.test/carol", "--json"))
    assert added["contact_address"] == "example.test/carol"
    binding = await s.env.db.fetch_value("SELECT contact_did_aw FROM {{tables.contacts}} WHERE contact_id=$1::uuid", added["contact_id"])
    assert binding.startswith("did:aw:")
    await s.run(owner, "contacts", "remove", "example.test/carol")
    missing = await s.run(owner, "contacts", "add", "example.test/alice", ok=False)
    assert "recipient_identity_not_found" in missing, missing
    bare = await s.run(owner, "contacts", "add", "alice", ok=False)
    assert "sender_registry_unresolvable" in bare, bare

    denied = await s.run(s.homes["alice"], "mail", "send", "--to", "bob", "--subject", "contacts investigation", "--body", "disposable", ok=False)
    assert "403" in denied and "exact active contacts" in denied, denied
    # Neighboring policy is changed only on this disposable test identity.
    await s.run(s.homes["bob"], "inbound-mode", "team-and-contacts")
    await s.run(s.homes["alice"], "mail", "send", "--to", "bob", "--subject", "contacts investigation", "--body", "disposable")


@pytest.mark.asyncio
@pytest.mark.skipif(not os.environ.get("AW_CONTACTS_PUBLIC_PROBE"), reason="explicit public-address probe only")
@pytest.mark.parametrize("owner_kind", ["grant", "resident", "local"])
async def test_public_address_contact_through_released_grant(contacts_stack, monkeypatch, owner_kind):
    s = contacts_stack
    # Real public DNS/HTTPS, with no test default-registry substitution.
    monkeypatch.delenv("AWEB_FEDERATION_TEST_DEFAULT_REGISTRY")
    authority = build_federation_authority_activation(s.env.infra, public_origin=s.env.app.state.public_origin)
    s.env.app.state.federation_authority = authority
    try:
        owner = {"grant": s.grant, "resident": s.homes["bob"], "local": s.homes["alice"]}[owner_kind]
        await s.run(owner, "contacts", "add", os.environ["AW_CONTACTS_PUBLIC_PROBE"], "--json")
    finally:
        await authority.aclose()
