"""S19 targets expose real redirects, delayed replies and broken TLS responses."""

import json

import httpx
import pytest
from aweb_naapp.egress import Bounds, EgressOutcomeUnknown, HeaderRules
from upstream.app import create_upstream

from aweb_secrets.credential_shapes import is_credential_shaped_value
from tests.harness import running_upstream
from tests.test_upstream import ORIGIN, SIMPLE, _credentials, _sigv4_headers, _token


@pytest.mark.parametrize("scheme", [*SIMPLE, "oauth2", "sigv4"])
async def test_fault_targets_require_the_named_credential(scheme):
    creds = _credentials()
    app = create_upstream(creds)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url=ORIGIN) as client:
        for endpoint in ("redirect", "effects", "slow", "reset", "status/proof"):
            method = "GET" if endpoint.startswith(("redirect", "status")) else "POST"
            if scheme == "sigv4":
                wrong = {
                    "headers": _sigv4_headers(
                        creds,
                        method=method,
                        path=f"/sigv4/{endpoint}",
                        body=b"",
                        secret=creds.sigv4_secret_access_key + "x",
                    )
                }
            elif scheme == "oauth2":
                wrong = {"headers": {"Authorization": "Bearer " + creds.bearer}}
            else:
                wrong = SIMPLE[scheme](creds, False)
            wrong["url"] = f"/{scheme}/{endpoint}"
            assert (await client.request(method, **wrong)).status_code == 401
            assert (await client.request(method, f"/{scheme}/{endpoint}")).status_code == 401
        if scheme == "sigv4":
            right = {
                "headers": _sigv4_headers(creds, method="GET", path="/sigv4/redirect", body=b"")
            }
        elif scheme == "oauth2":
            issued = await _token(client, creds)
            right = {"headers": {"Authorization": "Bearer " + issued.json()["access_token"]}}
        else:
            right = SIMPLE[scheme](creds, True)
        right["url"] = f"/{scheme}/redirect"
        assert (await client.get(**right)).status_code == 307


async def test_effect_replay_and_status_lookup_count_one_effect_and_refuse_changed_input():
    creds = _credentials()
    app = create_upstream(creds)
    headers = {"Authorization": f"Bearer {creds.bearer}", "Idempotency-Key": "proof"}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url=ORIGIN) as client:
        assert (await client.get("/bearer/status/proof", headers=headers)).status_code == 404
        for _ in range(2):
            response = await client.post("/bearer/effects", headers=headers, content=b"input")
            assert response.status_code == 200
            assert response.json()["effects"] == 1
        assert (await client.get("/bearer/status/proof", headers=headers)).json() == response.json()
        changed = await client.post("/bearer/effects", headers=headers, content=b"changed")
        assert changed.status_code == 409
        missing = await client.post(
            "/bearer/effects", headers={"Authorization": headers["Authorization"]}
        )
        assert missing.status_code == 400
        other_scheme = await client.get(
            "/basic/status/proof", auth=(creds.basic_username, creds.basic_password)
        )
        assert other_scheme.status_code == 404


async def test_redirect_names_another_host_and_is_observable_without_following(tmp_path):
    async with running_upstream(
        tmp_path, redirect_target="https://other.secrets.test/target"
    ) as target:
        response = await target.egress.send(
            "GET",
            target.url("/bearer/redirect"),
            target.destination(),
            header_rules=HeaderRules(
                injected={"authorization"}, amz_allowed=(), is_credential=is_credential_shaped_value
            ),
            injected=[("Authorization", f"Bearer {target.creds.bearer}")],
        )
        assert response.status == 307
        assert dict(response.headers)["location"] == "https://other.secrets.test/target"
        assert target.paths == ["/bearer/redirect"]


@pytest.mark.parametrize("endpoint", ["slow", "reset"])
async def test_transport_faults_leave_a_reconcilable_effect_over_real_tls(tmp_path, endpoint):
    async with running_upstream(tmp_path, slow_seconds=0.5) as target:
        rules = HeaderRules(
            injected={"authorization"}, amz_allowed=(), is_credential=is_credential_shaped_value
        )
        injected = [("Authorization", f"Bearer {target.creds.bearer}")]
        destination = target.destination(header_allow=["idempotency-key"])
        with pytest.raises(EgressOutcomeUnknown):
            await target.egress.send(
                "POST",
                target.url(f"/bearer/{endpoint}"),
                destination,
                header_rules=rules,
                injected=injected,
                headers=[("Idempotency-Key", "proof")],
                body=b"input",
                bounds=Bounds(total_timeout=0.25),
            )
        status = await target.egress.send(
            "GET",
            target.url("/bearer/status/proof"),
            destination,
            header_rules=rules,
            injected=injected,
        )
        assert status.status == 200
        assert json.loads(status.body)["effects"] == 1
