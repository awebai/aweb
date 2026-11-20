"""A team-server read through the deployment's egress guard, against a real
TLS listener (Antares 1232c21a item 4).

The site listens only on this host's private address, under a name only its
own DNS server answers, with a disposable CA the app trusts through its
settings. Every read is a guarded send: the listener seeing a request at all
means the guard connected to the address it checked.
"""

from __future__ import annotations

import base64
import json
import time

import pytest
from aweb_naapp_testing.team_server_site import TeamServerSite, team_server_site
from awid.did import did_from_public_key
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from nacl.signing import SigningKey

from aweb_naapp.runtime.app_credentials import APP_GRANT_READ, AppCredentialSigner
from aweb_naapp.runtime.app_keys import AppKey
from aweb_naapp.runtime.operator_egress import OperatorNetworkSettings
from aweb_naapp.runtime.team_server import (
    TeamServer,
    TeamServerReach,
    TeamServerRefused,
)

TEAM_ID = "ops:reach.example"
PATH = "/v1/apps/self/grant"


def _coordination_server() -> FastAPI:
    app = FastAPI()

    @app.get(PATH)
    async def grant(request: Request) -> JSONResponse:
        return JSONResponse({"host": request.headers["host"], "path": request.url.path})

    @app.get("/moved")
    async def moved() -> RedirectResponse:
        return RedirectResponse("https://elsewhere.example/next", status_code=302)

    return app


def _server(site: TeamServerSite) -> TeamServer:
    return TeamServer(
        team_id=TEAM_ID,
        server_url=site.origin,
        audience=site.origin,
        team_did_key="did:key:unused",
        expires_at=time.monotonic_ns() + 60_000_000_000,
    )


def _reach(site: TeamServerSite, **settings) -> TeamServerReach:
    egress = site.egress(OperatorNetworkSettings(**settings))
    return TeamServerReach(egress=egress.egress, internal=egress.team_servers)


def _signer(key: SigningKey) -> AppCredentialSigner:
    app_key = AppKey(kid="k1", did_key=did_from_public_key(bytes(key.verify_key)), signing_key=key)
    return AppCredentialSigner(app_id="reader", key=app_key, purpose=APP_GRANT_READ)


@pytest.fixture
async def site(tmp_path):
    async with team_server_site(tmp_path, _coordination_server()) as served:
        yield served


async def test_a_listed_team_server_is_read_through_the_guard_inside_the_operators_network(
    site: TeamServerSite,
) -> None:
    key = SigningKey.generate()
    answer = await _reach(site, **site.settings()).get(
        _server(site), PATH, signer=_signer(key), max_bytes=4096, timeout=5
    )

    assert answer.status == 200
    assert json.loads(answer.body) == {"host": f"{site.name}:{site.tls.port}", "path": PATH}
    [seen] = site.tls.seen
    assert site.tls.connections == 1
    # One connection, to the address the guard checked, over TLS to the
    # team server's own name.
    assert seen.local == site.host
    assert seen.sni == site.name
    method, target, _ = seen.request_line.split(" ")
    assert (method, target) == ("GET", PATH)
    headers = {name.lower(): value for name, value in seen.headers}
    assert headers["host"] == f"{site.name}:{site.tls.port}"
    # The app credential signs exactly the method, target and audience received.
    encoded = headers["x-aweb-signed-payload"]
    signed = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    payload = json.loads(signed)
    assert (payload["method"], payload["path"], payload["aud"]) == (
        method,
        target,
        f"https://{headers['host']}",
    )
    signature_b64 = headers["authorization"].rsplit(" ", 1)[1]
    signature = base64.b64decode(signature_b64 + "=" * (-len(signature_b64) % 4))
    key.verify_key.verify(signed, signature)
    # Resolved for the public attempt the guard refused before connecting,
    # then afresh for the attempt inside the operator's network.
    assert site.dns.queries[(site.name, "A")] == 2


async def test_a_redirect_from_a_listed_team_server_is_returned_not_followed(
    site: TeamServerSite,
) -> None:
    answer = await _reach(site, **site.settings()).get(
        _server(site), "/moved", signer=None, max_bytes=4096, timeout=5
    )
    assert answer.status == 302
    assert len(site.tls.seen) == 1
    assert site.tls.connections == 1


async def test_an_unlisted_team_server_on_a_private_address_is_refused_unsent(
    site: TeamServerSite,
) -> None:
    with pytest.raises(TeamServerRefused):
        await _reach(site, **site.settings(listed=False)).get(
            _server(site), PATH, signer=None, max_bytes=4096, timeout=5
        )
    assert site.tls.seen == []
    assert site.tls.connections == 0


async def test_a_listed_team_server_outside_the_operators_network_is_refused_unsent(
    site: TeamServerSite,
) -> None:
    settings = {**site.settings(), "hook_internal_cidr": "10.231.0.0/16"}
    with pytest.raises(TeamServerRefused):
        await _reach(site, **settings).get(
            _server(site), PATH, signer=None, max_bytes=4096, timeout=5
        )
    assert site.tls.seen == []
    assert site.tls.connections == 0


async def test_a_hook_origin_grants_a_team_server_no_internal_reach(
    site: TeamServerSite,
) -> None:
    # The operator lists the address for hook deliveries only.
    settings = {
        "hook_internal_destinations": "allowed",
        "hook_internal_cidr": f"{site.host}/32",
        "hook_internal_origins": [site.origin],
        "hook_ca_file": site.ca_file,
    }
    with pytest.raises(TeamServerRefused):
        await _reach(site, **settings).get(
            _server(site), PATH, signer=None, max_bytes=4096, timeout=5
        )
    assert site.tls.seen == []
    assert site.tls.connections == 0


async def test_a_denied_network_refuses_even_a_listed_team_server(site: TeamServerSite) -> None:
    # The attempt inside the operator's network still meets the operator's
    # denied networks, as every attempt does.
    settings = {**site.settings(), "egress_denied_networks": [f"{site.host}/32"]}
    with pytest.raises(TeamServerRefused):
        await _reach(site, **settings).get(
            _server(site), PATH, signer=None, max_bytes=4096, timeout=5
        )
    assert site.tls.seen == []
    assert site.tls.connections == 0
