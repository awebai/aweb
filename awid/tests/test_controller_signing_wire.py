"""Typed/raw wire comparison; reassign's prerequisite GET uses actual AWID.

No registry answer is fabricated: the observer stops at the outgoing request,
except for reassign's public key lookup, forwarded to the real fixture app.
"""

from datetime import datetime, timezone
import json

import httpx
from nacl.signing import SigningKey
import pytest

import awid.registry as registry_module
import awid.registry_auth as auth_module
from awid.controller_signing import (
    ControllerDescriptor,
    parse_controller_object,
    parse_controller_request,
    sign_controller_object,
)
from awid.registry import RegistryClient
from awid.team_server_record import build_team_server_record
from test_controller_signing import KEY, NEW_KEY, NEW_SEED, SEED, TS

pytestmark = pytest.mark.asyncio
CASES = [
    "namespace_register",
    "namespace_register-origin",
    "namespace_register-parent",
    "namespace_update",
    "namespace_update-null",
    "namespace_reset",
    "namespace_reset-parent",
    "namespace_rotate",
    "team_register",
    "team_visibility",
    "team_delete",
    "address_register",
    "address_update",
    "address_delete",
    "address_reassign",
    "certificate_register",
    "certificate_revoke",
    "certificate_list",
    "certificate_list-inactive",
    "id_revoke",
    "id_revoke-head",
    "server_publish",
]


@pytest.mark.parametrize("case", CASES)
async def test_typed_and_raw_clients_produce_the_same_wire(
    case, controller_app, monkeypatch
):
    env = controller_app
    setup = RegistryClient(
        str(env.client.base_url).rstrip("/"),
        transport=httpx.ASGITransport(app=env.app, client=env.client._transport.client),
    )
    try:
        subject = await setup.register_did(NEW_KEY, NEW_SEED)
    finally:
        await setup.aclose()

    class FrozenDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime.fromisoformat(TS.replace("Z", "+00:00")).astimezone(
                tz or timezone.utc
            )

    monkeypatch.setattr(registry_module, "_utc_timestamp", lambda: TS)
    monkeypatch.setattr(auth_module, "datetime", FrozenDateTime)
    operation = case.split("-", 1)[0]
    domain = "child.local" if case.endswith("-parent") else "local"
    scope = (
        "team"
        if operation
        in {
            "team_visibility",
            "certificate_register",
            "certificate_revoke",
            "certificate_list",
            "server_publish",
        }
        else "namespace"
    )
    controller = ControllerDescriptor(
        scope, domain, KEY, "primary", 0, team="team" if scope == "team" else None
    )
    controllers = {"controller": controller}
    fields, raw_fields = {}, {"domain": domain}
    raw_method = {
        "namespace_register": "register_namespace",
        "namespace_update": "update_namespace_delivery_origin",
        "namespace_reset": "rotate_namespace_controller",
        "namespace_rotate": "rotate_namespace_with_previous_key",
        "team_register": "register_team",
        "team_visibility": "set_team_visibility",
        "team_delete": "delete_team",
        "address_register": "register_address",
        "address_update": "update_address",
        "address_delete": "delete_address",
        "address_reassign": "reassign_address",
        "certificate_register": "register_team_certificate",
        "certificate_revoke": "revoke_team_certificate",
        "certificate_list": "list_team_certificates",
        "id_revoke": "revoke_id_certificate",
        "server_publish": "publish_team_server_record",
    }[operation]

    def ordinary(payload):
        return KEY, SigningKey(SEED).sign(payload).signature

    if operation in {
        "namespace_register",
        "namespace_update",
        "namespace_reset",
        "address_register",
        "address_update",
        "address_delete",
        "address_reassign",
    }:
        raw_fields[
            "controller_signing_key"
            if operation != "namespace_reset"
            else "new_controller_signing_key"
        ] = SEED
    if operation in {"namespace_register", "namespace_reset"}:
        fields[
            "controller_did"
            if operation == "namespace_register"
            else "new_controller_did"
        ] = KEY
        if case.endswith("-parent"):
            fields["parent_domain"] = "local"
            controllers["parent"] = ControllerDescriptor(
                "namespace", "local", NEW_KEY, "other", 0
            )
            raw_fields["parent_signing_key"] = NEW_SEED
    if case == "namespace_register-origin" or operation == "namespace_update":
        fields["default_delivery_origin"] = (
            None if case.endswith("-null") else "https://delivery.example"
        )
    if operation == "namespace_rotate":
        fields.update(from_seq=1, previous_did_key=KEY, new_did_key=NEW_KEY)
        controllers["new_controller"] = ControllerDescriptor(
            "namespace", domain, NEW_KEY, "other", 1
        )
        raw_fields.update(
            previous_signer=ordinary,
            new_signer=lambda b: (NEW_KEY, SigningKey(NEW_SEED).sign(b).signature),
        )
    if (
        operation.startswith("team_")
        or operation.startswith("certificate_")
        or operation == "server_publish"
    ):
        fields["name"] = "team"
    if operation in {"team_register", "team_delete"}:
        raw_fields["namespace_controller_signing_key"] = SEED
    if operation == "team_register":
        fields.update(display_name="Team", team_did_key=NEW_KEY, visibility="private")
    if operation == "team_visibility":
        fields["visibility"] = "public"
        raw_fields["team_controller_signing_key"] = SEED
    if operation.startswith("address_"):
        fields["name"] = "Member_One"
        if operation in {"address_register", "address_reassign"}:
            fields.update(did_aw=subject.did_aw, current_did_key=NEW_KEY)
    if operation in {"certificate_register", "certificate_revoke"}:
        raw_fields["team_controller_signing_key"] = SEED
        fields["certificate_id"] = "00000000-0000-4000-8000-000000000001"
    if operation == "certificate_register":
        c = {
            "version": 1,
            "certificate_id": fields.pop("certificate_id"),
            "team_id": "team:local",
            "team_did_key": KEY,
            "member_did_key": NEW_KEY,
            "alias": "Member_One",
            "identity_scope": "local",
            "issued_at": TS,
        }
        artifact = await sign_controller_object(
            parse_controller_object(
                {
                    "operation": "team_certificate_issue",
                    "domain": domain,
                    "name": "team",
                    "certificate": c,
                }
            ),
            controller=controller,
            signer=lambda ctx: (
                KEY,
                SigningKey(SEED).sign(ctx.signing_bytes()).signature,
            ),
        )
        fields["certificate"] = artifact["encoded_certificate"]
        raw_fields.update(
            {
                k: c.get(k)
                for k in (
                    "certificate_id",
                    "member_did_key",
                    "member_did_aw",
                    "member_address",
                    "alias",
                    "identity_scope",
                )
            }
        )
    if operation == "certificate_list":
        fields.update(active_only=not case.endswith("-inactive"), limit=200)
        raw_fields["signing_key"] = SEED
    if operation == "id_revoke":
        fields.update(
            id=subject.did_aw,
            expected_head="a" * 64 if case.endswith("-head") else None,
        )
        if case.endswith("-head"):
            fields["effective_from"] = TS
        raw_fields["signer"] = ordinary
    if operation == "server_publish":
        record = build_team_server_record(
            "team:local",
            KEY,
            "https://team.example",
            datetime.fromisoformat(TS.replace("Z", "+00:00")),
        )
        envelope = await sign_controller_object(
            parse_controller_object(
                {
                    "operation": "team_server_sign",
                    "domain": domain,
                    "name": "team",
                    "record": record,
                }
            ),
            controller=controller,
            signer=lambda ctx: (
                KEY,
                SigningKey(SEED).sign(ctx.signing_bytes()).signature,
            ),
        )
        fields["record"] = record
        raw_fields["signature"] = envelope["signature"]
    raw_fields.update(
        {k: v for k, v in fields.items() if k not in {"parent_domain", "limit"}}
    )
    if operation == "address_reassign":
        raw_fields["new_did_aw"] = raw_fields.pop("did_aw")
        raw_fields.pop("current_did_key")
    req = parse_controller_request({"operation": operation, "domain": domain, **fields})

    class Captured(Exception):
        pass

    actual = httpx.ASGITransport(app=env.app, client=env.client._transport.client)
    sent = []

    async def record(outgoing):
        if outgoing.method == "GET" and outgoing.url.path.startswith("/v1/did/"):
            return await actual.handle_async_request(outgoing)
        sent.append(outgoing)
        raise Captured()

    sdk = RegistryClient(
        str(env.client.base_url).rstrip("/"), transport=httpx.MockTransport(record)
    )
    try:
        with pytest.raises(Captured):
            await getattr(sdk, raw_method)(**raw_fields)
        with pytest.raises(Captured):
            await sdk.controller_request(
                req,
                controllers=controllers,
                signer=lambda ctx: (
                    ctx.controller.did_key,
                    SigningKey(
                        SEED if ctx.controller.key_reference == "primary" else NEW_SEED
                    )
                    .sign(ctx.signing_bytes())
                    .signature,
                ),
            )

        def wire(outgoing):
            return (
                outgoing.method,
                str(outgoing.url),
                {
                    k: v
                    for k, v in outgoing.headers.items()
                    if k == "authorization" or k.startswith("x-aweb-")
                },
                json.loads(outgoing.content) if outgoing.content else None,
            )

        assert len(sent) == 2
        assert wire(sent[0]) == wire(sent[1])
        if operation in {"namespace_rotate", "id_revoke"}:
            assert sent[0].content == sent[1].content
    finally:
        await sdk.aclose()
        await actual.aclose()
