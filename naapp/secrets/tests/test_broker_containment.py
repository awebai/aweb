"""Mounted B1 containment stops another worker's cached OAuth use."""

import json
from dataclasses import replace

import httpx
from aweb_naapp.roles import principal_key
from aweb_naapp_testing import Member
from nacl.signing import SigningKey

from aweb_secrets import records
from aweb_secrets.app import create_app
from aweb_secrets.containment_routes import containment_api_router
from aweb_secrets.custody import encode_value
from aweb_secrets.destination import DestinationRecord
from aweb_secrets.grant import GrantRecord
from aweb_secrets.policy import Policy
from aweb_secrets.secret import SecretRecord
from aweb_secrets.tokens import TokenKey
from aweb_secrets.use_routes import UseServices, use_router
from tests.harness import running_upstream
from tests.test_admission import POLICY_BODY
from tests.test_app import _settings, allow_all, kms_check
from tests.test_broker_approved_service import setup
from tests.test_change_sets import Installations
from tests.test_containment_service import service as containment_service
from tests.test_use_approvals import REQUESTER, SECRET, TEAM
from tests.test_use_approvals import uses as uses
from tests.test_use_approvals import world as world
from tests.test_use_routes import unused_run_service

API = "https://api.localhost"


class InstalledTools(Installations):
    @property
    def grant(self):
        return replace(
            super().grant, scopes=frozenset({"secrets:use", "secrets:admin", "secrets:read"})
        )


async def test_disable_worker_a_stops_worker_b_while_its_actual_token_remains_cached(
    uses, registry, tmp_path
):
    async with running_upstream(tmp_path) as upstream:
        worker_b, _, _, _ = await setup(uses, tmp_path, upstream)
        worker_a = await containment_service(uses)
        assert worker_a.tokens is not worker_b._tokens
        db, scope = uses.world.db, uses.world.admitted
        record = SecretRecord.from_after(
            {
                **SECRET,
                "secret_id": "sec_oauth001",
                "ref": "oauth-service",
                "kind": "oauth2-client-credentials",
                "kind_params": {
                    "token_endpoint": upstream.url("/oauth2/token"),
                    "client_auth": "client_secret_basic",
                    "scope": upstream.creds.oauth_scope,
                },
            }
        )
        policy = Policy.from_body(POLICY_BODY)
        async with db.transaction() as tx:
            await records.create_secret(tx, scope.installation_id, TEAM, record)
            version = await uses.world.custody.sealer.ingest(
                tx,
                installation_id=scope.installation_id,
                team_id=TEAM,
                secret_id=record.secret_id,
                value=encode_value(
                    record.kind,
                    {
                        "client_id": upstream.creds.oauth_client_id,
                        "client_secret": upstream.creds.oauth_client_secret,
                    },
                ),
            )
            await records.set_active_version(
                tx, scope.installation_id, TEAM, record.secret_id, version
            )
            await records.create_policy(tx, scope.installation_id, policy)
            await records.create_grant(
                tx,
                scope.installation_id,
                TEAM,
                GrantRecord.from_after(
                    {
                        "v": 1,
                        "grant_id": "grt_oauth001",
                        "secret_id": record.secret_id,
                        "subject": {"principal": principal_key(REQUESTER).principal_did},
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
                scope.installation_id,
                TEAM,
                DestinationRecord.from_after(
                    {
                        "v": 1,
                        "destination_id": "dst_oauth001",
                        "secret_id": record.secret_id,
                        "scheme": "https",
                        "host": "upstream.secrets.test",
                        "port": upstream.port,
                        "path": "/oauth2/**",
                        "methods": ["GET", "POST"],
                        "query_rules": {},
                        "header_allow": [],
                        "network": "internal",
                        "cidr": f"{upstream.host}/32",
                    },
                    internal_destinations=worker_b._internal_destinations,
                ),
            )
        member = Member(
            team_id=TEAM,
            member_key=SigningKey(bytes([7]) * 32),
            extra_cert_fields={"member_did_aw": REQUESTER.did_aw},
        )
        await registry.add_team(TEAM, member.team_did_key)
        await registry.add_certificate(member.certificate())

        def broker_routes(runtime, authorized):
            return use_router(
                UseServices(
                    broker=lambda: worker_b,
                    runs=unused_run_service,
                    status=lambda: worker_b._status,
                ),
                authorized=authorized,
            )

        def containment_routes(runtime, authorized):
            return containment_api_router(worker_a, authorized=authorized)

        settings = _settings(db.config.get_dsn(), tmp_path).model_copy(
            update={"app_id": "secrets", "public_origin": API, "db_schema": "naapp_test"}
        )
        app = create_app(
            settings,
            grants=InstalledTools(),
            policy=allow_all,
            kms=kms_check(True),
            awid_transport=registry.transport,
            tool_routers=(broker_routes, containment_routes),
        )
        async with app.api_app.router.lifespan_context(app.api_app):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app), base_url=API
            ) as client:
                path = "/v1/secrets/oauth-service/requests"

                async def request(request_id):
                    body = json.dumps(
                        {
                            "request_id": request_id,
                            "method": "GET",
                            "url": upstream.url("/oauth2/echo"),
                        }
                    ).encode()
                    return await client.post(
                        path,
                        content=body,
                        headers=member.headers(aud=API, method="POST", path=path, body=body)
                        | {"Content-Type": "application/json"},
                    )

                first = await request("warm-worker-b")
                assert first.status_code == 200 and first.json()["state"] == "completed", (
                    first.status_code,
                    first.json().get("state"),
                    first.json().get("code"),
                )
                key = TokenKey(
                    scope.installation_id,
                    TEAM,
                    record.secret_id,
                    version,
                    upstream.url("/oauth2/token"),
                    upstream.creds.oauth_scope,
                )
                assert await worker_b._tokens.get(key) is not None
                assert upstream.issued() == 1
                body = json.dumps(
                    {
                        "request_id": "disable-worker-a",
                        "action": "disable-secret",
                        "target": record.secret_id,
                    }
                ).encode()
                disabled = await client.post(
                    "/v1/containment",
                    content=body,
                    headers=member.headers(
                        aud=API, method="POST", path="/v1/containment", body=body
                    )
                    | {"Content-Type": "application/json"},
                )
                assert disabled.status_code == 200
                assert await worker_b._tokens.get(key) is not None
                stopped = await request("after-disable")
                assert stopped.status_code == 403 and stopped.json()["code"] == "secret_disabled"
                assert upstream.paths == ["/oauth2/token", "/oauth2/echo"]
                assert upstream.issued() == 1
