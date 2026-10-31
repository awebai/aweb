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
from awid.signing import canonical_json_bytes, sign_message
from test_dashboard_privacy import privacy_app  # noqa: F401
from test_messages_http import _signed_team_headers, _make_certificate, _encode_certificate


@pytest_asyncio.fixture
async def local_mail(privacy_app, monkeypatch):
    env = privacy_app
    actors = {}
    for domain, names in (("local", ("alice", "bob")), ("company.test", ("carol",))):
        team = f"default:{domain}"
        await env.db.execute(
            "INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key) VALUES ($1, $2, 'default', $3)",
            team, domain, env.team_did,
        )
        await env.registry_db.execute(
            "INSERT INTO {{tables.teams}} (domain, name, team_did_key, visibility) VALUES ($1, 'default', $2, 'public')",
            domain, env.team_did,
        )
        await env.registry_db.execute(
            "INSERT INTO {{tables.dns_namespaces}} (domain, controller_did, verification_status) VALUES ($1, $2, 'verified')",
            domain, env.team_did,
        )
        for name in names:
            actor = env.actors[name]
            await env.db.execute("UPDATE {{tables.agents}} SET team_id = $1 WHERE agent_id = $2", team, actor.id)
            await env.db.execute("UPDATE {{tables.workspaces}} SET team_id = $1 WHERE workspace_id = $2", team, actor.workspace)
            cert = _make_certificate(
                env.team_sk, env.team_did, actor.did, team_id=team, alias=name, identity_scope="local",
            )
            # Match the CLI wire format: absent optional local identity fields.
            for field in ("signature", "member_did_aw", "member_address"):
                cert.pop(field)
            cert["signature"] = sign_message(env.team_sk, canonical_json_bytes(cert))
            certificate = _encode_certificate(cert)
            actors[name] = (actor, team, certificate)
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
    from aweb.routes.messages import _mail_namespace_uses_home_registry
    from awid.federation_errors import FederationAuthorityError

    registry = RegistryClient(registry_url="http://127.0.0.1:1")
    try:
        with pytest.raises(FederationAuthorityError) as refused:
            await _mail_namespace_uses_home_registry(local_mail.env.infra, registry, "local")
        assert refused.value.reason == "sender_registry_unavailable"
        assert refused.value.http_status == 503
        assert refused.value.retryable is True
        assert local_mail.queries == []
        assert await local_mail.env.db.fetch_value("SELECT COUNT(*) FROM {{tables.messages}}") == 0
    finally:
        await registry.aclose()


@pytest.mark.asyncio
async def test_selected_foreign_origin_does_not_use_home_namespace(local_mail):
    from aweb.routes.messages import _mail_namespace_uses_home_registry

    async def foreign_registry(domain):
        assert domain == "local"
        return "http://127.0.0.1:1"

    registry = RegistryClient(registry_url="http://127.0.0.1:2", domain_registry_resolver=foreign_registry)
    try:
        assert not await _mail_namespace_uses_home_registry(local_mail.env.infra, registry, "local")
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
    assert target in text if channel == "mail" else target in text or reason in text, text
    assert "retrying" not in text.lower(), text
    assert local_mail.responses == [{"status": 404, "reason": reason, "retryable": False}]
    assert local_mail.queries == []
    assert await local_mail.env.db.fetch_value("SELECT COUNT(*) FROM {{tables.messages}}") == 0
