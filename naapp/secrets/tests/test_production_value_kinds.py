"""R16/11.11: actual console staging and broker dispatch through create_service.

Only the external 1Password SDK boundary is replaced. It returns actual Item
models; custody, the codec, installation/owner/passkey checks and dispatch use
the production instances. Confirmed configuration is fixture state.
"""

import json
import secrets
from enum import StrEnum
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from aweb_naapp.dispatch import State as DispatchState
from aweb_naapp.egress import InternalDestinations
from aweb_secrets_values import ValueKind
from onepassword import Client

from aweb_secrets import records
from aweb_secrets.destination import DestinationRecord
from aweb_secrets.grant import GrantRecord
from aweb_secrets.policy import Policy
from aweb_secrets.secret import SecretRecord
from tests.custody.test_onepassword import ITEM, VAULT, field, reference, sdk_item
from tests.test_production_bootstrap import enrolled_owner
from tests.test_production_bootstrap import root as root
from tests.test_use_approvals import POLICY_BODY, SECRET


class SDKValueScenario(StrEnum):
    VALID = "valid"
    INVALID = "invalid"
    INVALID_AFTER_DISPATCH = "invalid_after_dispatch"


@pytest.fixture
async def vault(root, monkeypatch):
    service, client, configured, member, installed, *_ = root
    owner = await enrolled_owner(root)
    username, password = secrets.token_hex(12), secrets.token_urlsafe(32)
    backend_token = secrets.token_urlsafe(32)
    state = SimpleNamespace(scenario=SDKValueScenario.VALID, reads=0, opened=False)

    async def get(*, vault_id: str, item_id: str):
        if vault_id != VAULT or item_id != ITEM:
            raise AssertionError("the SDK requested a different item")
        state.reads += 1
        dispatching = await service.runtime.db().fetch_value(
            "SELECT EXISTS(SELECT 1 FROM dispatches WHERE state=$1)",
            DispatchState.DISPATCHING.value,
        )
        state.opened |= dispatching
        invalid = state.scenario is SDKValueScenario.INVALID or (
            state.scenario is SDKValueScenario.INVALID_AFTER_DISPATCH and dispatching
        )
        return sdk_item(
            [field("username", username + (":" if invalid else "")), field("password", password)]
        )

    async def authenticate(*, auth: str, integration_name: str, integration_version: str):
        if not secrets.compare_digest(auth, backend_token):
            raise AssertionError("the SDK did not receive the staged service credential")
        return SimpleNamespace(items=SimpleNamespace(get=get))

    monkeypatch.setattr(Client, "authenticate", authenticate)
    prefix = configured.console_origin + f"/installations/{installed['installation_id']}"
    headers = {"X-CSRF-Token": owner.csrf_token}
    token = await client.post(
        prefix + "/backend-credentials/onepassword/versions",
        json={"value": backend_token},
        headers=headers,
    )
    assert token.status_code == 201
    record = SecretRecord.from_after(
        {**SECRET, "kind": ValueKind.BASIC.value, "backend": "onepassword"}
    )
    request = {
        "secret": record.after,
        "reference": reference(
            ValueKind.BASIC, {"username": "username", "password": "password"}
        ).as_config(),
        "credential_version": token.json()["version"],
    }
    return SimpleNamespace(
        state=state,
        prefix=prefix,
        headers=headers,
        request=request,
        record=record,
        token=token.json(),
        service=service,
        client=client,
        configured=configured,
        member=member,
        installed=installed,
    )


async def test_staging_a_basic_reference_refuses_a_colon_username_without_allocating(vault):
    vault.state.scenario = SDKValueScenario.INVALID
    response = await vault.client.post(
        vault.prefix + "/onepassword/references", json=vault.request, headers=vault.headers
    )
    assert response.status_code == 400, "invalid basic username reached reference staging"
    detail = response.json()["detail"]
    assert "username" in detail.lower() and ":" in detail
    assert (
        await vault.service.runtime.db().fetch_value("SELECT count(*) FROM onepassword_versions")
        == 0
    )


async def configured_basic(vault):
    staged = await vault.client.post(
        vault.prefix + "/onepassword/references", json=vault.request, headers=vault.headers
    )
    assert staged.status_code == 201
    db = vault.service.runtime.db()
    installation, team = vault.installed["installation_id"], vault.member.team_id
    policy = Policy.from_body({**POLICY_BODY, "approval": "none", "approvers": []})
    async with db.transaction() as tx:
        await records.create_secret(tx, installation, team, vault.record)
        await records.set_active_version(
            tx, installation, team, vault.record.secret_id, staged.json()["version"]
        )
        await tx.execute(
            "UPDATE onepassword_credentials SET active_version=$1 WHERE installation_id=$2 AND team_id=$3",
            vault.token["version"],
            installation,
            team,
        )
        await records.create_policy(tx, installation, policy, team_id=team)
        await records.create_grant(
            tx,
            installation,
            team,
            GrantRecord.from_after(
                {
                    "v": 1,
                    "grant_id": "grt_value_kind",
                    "secret_id": vault.record.secret_id,
                    "subject": {"principal": vault.member.extra_cert_fields["member_did_aw"]},
                    "capability": "use",
                    "operations": [],
                    "open_request": True,
                    "jobs": [],
                    "policy_digest": policy.digest,
                }
            ),
        )
        await records.create_destination(
            tx,
            installation,
            team,
            DestinationRecord.from_after(
                {
                    "v": 1,
                    "destination_id": "dst_value_kind",
                    "secret_id": vault.record.secret_id,
                    "scheme": "https",
                    "host": "api.payments.example",
                    "port": 443,
                    "path": "/v1/**",
                    "methods": ["POST"],
                    "query_rules": {},
                    "header_allow": [],
                    "network": "public",
                    "cidr": None,
                },
                internal_destinations=InternalDestinations.DISABLED,
            ),
        )


async def submit(vault, *, request_id: str):
    path = f"/v1/secrets/{vault.record.ref}/requests"
    raw = json.dumps(
        {
            "request_id": request_id,
            "method": "POST",
            "url": "https://api.payments.example/v1/probe",
            "data": "probe",
        }
    ).encode()
    # Preserve an HTTP 500 as the observed response, without a traceback that
    # could include a credential in SDK arguments.
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(vault.service, raise_app_exceptions=False)
    ) as client:
        return await client.post(
            vault.configured.public_origin + path,
            content=raw,
            headers={
                **vault.member.headers(
                    aud=vault.configured.public_origin, method="POST", path=path, body=raw
                ),
                "Content-Type": "application/json",
            },
        )


async def test_invalid_basic_at_post_commit_open_settles_not_sent_and_does_not_fence_the_pair(
    vault,
):
    await configured_basic(vault)
    vault.state.scenario = SDKValueScenario.INVALID_AFTER_DISPATCH
    first = await submit(vault, request_id=uuid4().hex)
    assert vault.state.opened, "the test must reach the post-dispatching pinned SDK read"
    assert first.status_code == 503, "a pre-send injection failure escaped as HTTP 500"
    assert first.json()["state"] == DispatchState.NOT_SENT.value
    assert "username" in first.json()["message"].lower() and ":" in first.json()["message"]
    db = vault.service.runtime.db()
    assert await db.fetch_value("SELECT state FROM dispatches") == DispatchState.NOT_SENT.value
    # Leave the provider invalid. A new request must be admitted and settle the
    # same way, rather than a swept outcome_unknown fencing this secret pair.
    second = await submit(vault, request_id=uuid4().hex)
    assert second.status_code == 503 and second.json()["state"] == DispatchState.NOT_SENT.value
    assert (
        await db.fetch_value("SELECT count(*) FROM dispatches WHERE state='outcome_unknown'") == 0
    )
    assert await db.fetch_value("SELECT count(*) FROM dispatches WHERE state='not_sent'") == 2
