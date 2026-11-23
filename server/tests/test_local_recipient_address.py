"""Local-address refusals through real aweb/AWID apps, PostgreSQL and HTTP.

The ordinary unit run forbids DNS. Set AWEB_LOCAL_ADDRESS_COREDNS=host:port
for the real-CoreDNS journey, with a server answering SERVFAIL and no forwarder.
"""
import asyncio
import base64
import json
import os
from types import SimpleNamespace

import dns.asyncresolver
import pytest
import pytest_asyncio

from aweb.federation.activation import build_federation_authority_activation
from awid.external_authority import SystemTXTOutcomeResolver
from awid.registry import RegistryClient
from awid.team_certificate import decode_team_certificate
from messaging_actor_support import privacy_actor, register_messaging_actors
from test_dashboard_privacy import privacy_stack
from test_messages_http import _signed_team_headers


@pytest_asyncio.fixture
async def local_mail_world(shared_test_pool, monkeypatch):
    async with privacy_stack(shared_test_pool, monkeypatch, aliases=()) as env:
        yield env


@pytest_asyncio.fixture
async def local_mail(local_mail_world, monkeypatch):
    env = local_mail_world
    actors = {}
    for domain, names in (("local", ("alice", "bob")), ("company.test", ("carol",))):
        team = f"default:{domain}"
        registered = await register_messaging_actors(env, team_id=team, aliases=names, local=True)
        for name, member in registered.items():
            actors[name] = (privacy_actor(member), team, member.certificate)
    activation = build_federation_authority_activation(env.infra, public_origin=env.app.state.public_origin)
    queries = []
    coredns = os.environ.get("AWEB_LOCAL_ADDRESS_COREDNS")
    if coredns:
        host, port = coredns.rsplit(":", 1)
        resolver = dns.asyncresolver.Resolver(configure=False)
        resolver.nameservers = [host]
        resolver.port = int(port)
        resolver.timeout = resolver.lifetime = 1
        monkeypatch.setattr(dns.asyncresolver, "default_resolver", resolver)

    class RecordedDNS(SystemTXTOutcomeResolver):
        async def lookup_txt(self, name):
            queries.append(name)
            if not coredns:
                raise RuntimeError("external DNS is forbidden in the unit test")
            return await super().lookup_txt(name)

    activation.txt_resolver = RecordedDNS()
    env.app.state.federation_authority = activation
    responses = []
    stack = env.app.middleware_stack or env.app.build_middleware_stack()

    async def record_response(scope, receive, send):
        status = None
        chunks = []

        async def observe(message):
            nonlocal status
            if scope.get("path") in {"/v1/messages", "/v1/chat/sessions"} and scope.get("method") == "POST":
                if message["type"] == "http.response.start":
                    status = message["status"]
                elif message["type"] == "http.response.body":
                    chunks.append(message.get("body", b""))
                    if not message.get("more_body", False):
                        body = json.loads(b"".join(chunks))
                        responses.append({"status": status, "reason": body.get("reason"), "retryable": body.get("retryable")})
            await send(message)

        await stack(scope, receive, observe)

    env.app.middleware_stack = record_response

    async def send(actor_name, address, channel="mail"):
        actor, team, certificate = actors[actor_name]
        payload = ({"to_address": address, "subject": "hello", "body": "hello"} if channel == "mail"
                   else {"to_addresses": [address], "message": "hello", "leaving": True})
        body = json.dumps(payload).encode()
        headers = _signed_team_headers(actor.sk, actor.did, team, certificate, body)
        headers["Content-Type"] = "application/json"
        return await env.client.post("/v1/messages" if channel == "mail" else "/v1/chat/sessions", content=body, headers=headers)

    try:
        yield SimpleNamespace(env=env, actors=actors, queries=queries, responses=responses, send=send)
    finally:
        env.app.middleware_stack = stack
        await activation.aclose()


@pytest.mark.asyncio
async def test_local_address_actors_have_native_memberships(local_mail):
    env = local_mail.env
    registry = env.app.state.awid_registry_client
    for actor, team, certificate in local_mail.actors.values():
        fields = decode_team_certificate(certificate)
        assert "member_did_aw" not in fields
        assert "member_address" not in fields
        row = await env.db.fetch_one(
            """SELECT a.certificate_id, a.accepted_team_did_key
               FROM {{tables.agents}} a JOIN {{tables.workspaces}} w USING (agent_id)
               WHERE a.team_id = $1 AND w.team_id = $1
                 AND a.agent_id = $2 AND w.workspace_id = $3""",
            team, actor.id, actor.workspace,
        )
        assert row is not None
        assert row["certificate_id"] == fields["certificate_id"]
        assert row["accepted_team_did_key"] == env.team_did
        name, domain = team.split(":", 1)
        certificates = await registry.list_team_certificates(domain, name, active_only=True)
        assert any(
            item.certificate_id == row["certificate_id"] and item.member_did_key == actor.did
            for item in certificates
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("channel", ["mail", "chat"])
async def test_unknown_local_address_is_not_a_registry_outage(local_mail, channel):
    response = await local_mail.send("alice", "local/bbo", channel)
    assert response.status_code == 404, response.text
    assert response.json()["reason"] == "recipient_identity_not_found"
    assert response.json()["retryable"] is False
    assert local_mail.queries == []
    assert await local_mail.env.db.fetch_value("SELECT COUNT(*) FROM {{tables.messages}}") == 0
    assert await local_mail.env.db.fetch_value("SELECT COUNT(*) FROM {{tables.chat_messages}}") == 0
    assert await local_mail.env.db.fetch_value("SELECT COUNT(*) FROM {{tables.chat_sessions}}") == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("channel", ["mail", "chat"])
async def test_same_team_local_address_remains_reachable(local_mail, channel):
    response = await local_mail.send("alice", "local/bob", channel)
    assert response.status_code == 200, response.text
    assert local_mail.queries == []
    table = "SELECT COUNT(*) FROM {{tables.messages}}" if channel == "mail" else "SELECT COUNT(*) FROM {{tables.chat_messages}}"
    assert await local_mail.env.db.fetch_value(table) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("sender,target", [("carol", "local/alice"), ("alice", "company.test/carol")])
@pytest.mark.parametrize("channel", ["mail", "chat"])
async def test_cross_team_local_address_without_route_refuses_definitely(local_mail, sender, target, channel):
    response = await local_mail.send(sender, target, channel)
    assert response.status_code == 404, response.text
    assert response.json()["reason"] == "local_recipient_route_missing"
    assert response.json()["retryable"] is False
    assert local_mail.queries == []
    assert await local_mail.env.db.fetch_value("SELECT COUNT(*) FROM {{tables.messages}}") == 0
    assert await local_mail.env.db.fetch_value("SELECT COUNT(*) FROM {{tables.chat_messages}}") == 0
    assert await local_mail.env.db.fetch_value("SELECT COUNT(*) FROM {{tables.chat_sessions}}") == 0
    assert await local_mail.env.db.fetch_value("SELECT COUNT(*) FROM {{tables.conversations}}") == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("channel", ["mail", "chat"])
async def test_foreign_discovery_failure_remains_retryable(local_mail, channel):
    response = await local_mail.send("alice", "foreign.example/nobody", channel)
    assert response.status_code == 503, response.text
    assert response.json()["reason"] == "sender_registry_discovery_failed"
    assert response.json()["retryable"] is True
    assert local_mail.queries == ["_awid.foreign.example"]


@pytest.mark.asyncio
@pytest.mark.parametrize("channel", ["mail", "chat"])
async def test_unverified_home_namespace_does_not_supply_authority(local_mail, channel):
    await local_mail.env.registry_db.execute(
        "UPDATE {{tables.dns_namespaces}} SET verification_status = 'unverified' WHERE domain = 'local'",
    )
    response = await local_mail.send("alice", "local/bbo", channel)
    assert response.status_code == 503, response.text
    assert response.json()["reason"] == "sender_registry_discovery_failed"
    assert local_mail.queries == ["_awid.local"]


@pytest.mark.asyncio
async def test_home_registry_outage_remains_retryable(local_mail):
    from aweb.messaging.address_auth import namespace_uses_home_registry
    from aweb.messaging.refusals import DeliveryRefusal

    registry = RegistryClient(registry_url="http://127.0.0.1:1")
    try:
        with pytest.raises(DeliveryRefusal) as refused:
            await namespace_uses_home_registry(local_mail.env.infra, registry, "local")
        assert refused.value.status_code == 503
        assert "Retry when the registry is available" in refused.value.detail
        assert local_mail.queries == []
        assert await local_mail.env.db.fetch_value("SELECT COUNT(*) FROM {{tables.messages}}") == 0
    finally:
        await registry.aclose()


@pytest.mark.asyncio
async def test_selected_foreign_origin_does_not_use_home_namespace(local_mail):
    from aweb.messaging.address_auth import namespace_uses_home_registry

    async def foreign_registry(domain):
        assert domain == "local"
        return "http://127.0.0.1:1"

    registry = RegistryClient(registry_url="http://127.0.0.1:2", domain_registry_resolver=foreign_registry)
    try:
        assert not await namespace_uses_home_registry(local_mail.env.infra, registry, "local")
    finally:
        await registry.aclose()


@pytest.mark.usefixtures("source_cli_binary")
@pytest.mark.asyncio
@pytest.mark.parametrize("sender,target,reason", [
    ("alice", "local/bbo", "recipient_identity_not_found"),
    ("carol", "local/alice", "local_recipient_route_missing"),
    ("alice", "company.test/carol", "local_recipient_route_missing"),
])
@pytest.mark.parametrize("channel", ["mail", "chat"])
async def test_plain_cli_local_address_refusal_does_not_retry(local_mail, tmp_path, sender, target, reason, channel):
    actor, team, certificate = local_mail.actors[sender]
    home = tmp_path / ".aw"
    home.mkdir(mode=0o700)
    (home / "team-certs").mkdir()
    cert_path = "team-certs/" + team.replace(":", "__") + ".pem"
    (home / cert_path).write_bytes(base64.b64decode(certificate))
    (home / "signing.key").write_text(
        "-----BEGIN ED25519 PRIVATE KEY-----\n" + base64.b64encode(actor.sk).decode()
        + "\n-----END ED25519 PRIVATE KEY-----\n",
    )
    (home / "signing.key").chmod(0o600)
    membership = {"team_id": team, "alias": sender, "cert_path": cert_path}
    (home / "teams.yaml").write_text(json.dumps({"active_team": team, "memberships": [membership]}))
    (home / "workspace.yaml").write_text(json.dumps({
        "aweb_url": str(local_mail.env.client.base_url),
        "memberships": [{**membership, "workspace_id": str(actor.workspace)}],
    }))
    child_env = {key: value for key, value in os.environ.items() if not key.startswith(("AWEB_", "AWID_"))}
    child_env.update(AWEB_IDENTITY_HOME=str(home), AWID_REGISTRY_URL="http://127.0.0.1:1",
                     HOME=str(tmp_path), XDG_CONFIG_HOME=str(tmp_path / "config"), AW_NO_UPDATE_CHECK="1")
    command = (["mail", "send", "--to-address", target, "--subject", "hello", "--body", "hello"]
               if channel == "mail" else ["chat", "send-and-leave", target, "hello"])
    process = await asyncio.create_subprocess_exec(
        os.environ["AW_TEST_CLI_BINARY"], *command, cwd=tmp_path, env=child_env,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
    )
    output, _ = await asyncio.wait_for(process.communicate(), 30)
    text = output.decode()
    assert process.returncode != 0, text
    if channel == "mail":
        assert target in text, text
    else:
        assert target in text or reason in text, text
    assert "retrying" not in text.lower(), text
    assert local_mail.responses == [{"status": 404, "reason": reason, "retryable": False}]
    assert local_mail.queries == []
    assert await local_mail.env.db.fetch_value("SELECT COUNT(*) FROM {{tables.messages}}") == 0
