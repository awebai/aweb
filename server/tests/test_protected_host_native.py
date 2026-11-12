"""The process factory with actual PG, private customer AWID and B3 UV."""

import base64
import json
import os

import httpx
import pytest
from aweb_naapp.runtime.protected_signer import SignerRefused
from pydantic import SecretStr

from aweb.protected_signing.host import HostSettings, create_app
from tests.test_independent_protected_http import headers, profile_for
from tests.test_independent_protected_signer import HUMAN_ORIGIN, ORIGIN
from tests.test_protected_signer_host import CapturedMail

pytest_plugins = ("tests.test_independent_protected_signer",)


def host_for(w, tmp_path):
    profile = profile_for(w)
    private = tmp_path / "host-controller"
    private.mkdir(mode=0o700)
    controller_file = private / "controller.key"
    controller_file.write_text(bytes(w.controller).hex())
    controller_file.chmod(0o400)
    profile_file, scope_file = tmp_path / "profile.json", tmp_path / "scope.json"
    profile_file.write_text(json.dumps(profile.fields()))
    scope_file.write_text(json.dumps(w.context.fields()))
    member_file = tmp_path / "member.pem"
    member_file.write_bytes(
        b"-----BEGIN ED25519 PRIVATE KEY-----\n"
        + base64.b64encode(bytes(w.root))
        + b"\n-----END ED25519 PRIVATE KEY-----\n"
    )
    manifest = tmp_path / "members.json"
    manifest.write_text(json.dumps({w.context.authority_id: member_file.name}))
    settings = HostSettings(
        profile_file=profile_file,
        scope_file=scope_file,
        controller_key_file=controller_file,
        member_keys_file=manifest,
        worker_uids=[65534 if os.geteuid() != 65534 else 65533],
        database_url=SecretStr(w.db.config.get_dsn()),
        database_schema=w.db.schema,
    )
    # Capture only notification transport. Custody, registry, SQL bindings,
    # original B2/B3, LOGIN and exact-act assertions are the real adapters.
    return create_app(
        settings, mailer=CapturedMail(), registry_transport=w.host.transport
    )


@pytest.mark.asyncio
async def test_factory_real_custody_shared_page_login_act_uv_and_exact_receipt(
    world, tmp_path
):
    w = world
    host = host_for(w, tmp_path)
    async with host.api_app.router.lifespan_context(host.api_app):
        c = host.api_app.state.composition
        assert c.db is c.passkeys.db is c.signer.db
        assert c.authority.custody is not w.app.authority.custody
        assert c.authority.custody.team_key_did == w.app.authority.custody.team_key_did
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=host)) as client:
            body = json.dumps(w.operation.intent(), separators=(",", ":")).encode()
            prepared = await client.post(
                ORIGIN + "/protected-operations",
                content=body,
                headers=headers(w, body=body),
            )
            assert prepared.status_code == 200, prepared.text
            data = prepared.json()
            handoff = "/handoff/" + data["handoff_id"]
            page = await client.get(HUMAN_ORIGIN + handoff)
            assert page.status_code == 200, page.text
            assert 'data-purpose="governance"' in page.text
            assert (await client.get(ORIGIN + handoff)).status_code == 404
            assert (
                await client.post(HUMAN_ORIGIN + "/protected-operations")
            ).status_code == 404
            options = await client.post(
                HUMAN_ORIGIN + "/login/options", json={"scope": w.scope}
            )
            assert options.status_code == 200, options.text
            login = await client.post(
                HUMAN_ORIGIN + "/login",
                json={"scope": w.scope, "assertion": w.device.get(options.json())},
            )
            assert login.status_code == 200, login.text
            csrf = {"Origin": HUMAN_ORIGIN, "X-CSRF-Token": login.json()["csrf_token"]}
            governance = HUMAN_ORIGIN + handoff + "/governance"
            options = await client.post(governance + "/options", headers=csrf, json={})
            assert options.status_code == 200, options.text
            executed = await client.post(
                governance + "/execute",
                headers=csrf,
                json={"assertion": w.device.get(options.json())},
            )
            assert executed.status_code == 200, executed.text
            path = "/protected-operations/" + data["operation_id"]
            receipt = await client.get(
                ORIGIN + path, headers=headers(w, method="GET", path=path)
            )
            assert receipt.status_code == 200, receipt.text
            assert receipt.json() == executed.json()
            assert receipt.json()["state"] == "committed"
            assert "set-cookie" not in receipt.headers
    assert not hasattr(host.api_app.state, "composition")


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["missing", "policy", "superseded"])
async def test_factory_refuses_current_provisioning_misses(world, tmp_path, change):
    w = world
    host = host_for(w, tmp_path)
    if change == "missing":
        await w.db.execute(
            "UPDATE {{tables.protected_authorizer_bindings}} SET active=false"
        )
    elif change == "policy":
        await w.db.execute(
            "UPDATE {{tables.protected_authorizer_bindings}} SET policy_version=2"
        )
    else:
        await w.db.execute(
            "UPDATE {{tables.passkey_approvers}} SET superseded_at=now()"
        )
    with pytest.raises(SignerRefused):
        async with host.api_app.router.lifespan_context(host.api_app):
            pytest.fail("missing provisioned authority started")
    assert not host.api_app.router.routes
    assert not host.console_app.router.routes
