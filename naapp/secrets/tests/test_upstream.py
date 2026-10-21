"""The S19 test upstream verifies each auth scheme against its own copy of the
credential, and refuses a wrong or missing one.

Every credential here is generated when the test runs; none is in the
repository.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from upstream.app import UpstreamCredentials, create_upstream

ORIGIN = "https://upstream.secrets.test"


def _credentials() -> UpstreamCredentials:
    return UpstreamCredentials(
        bearer=secrets.token_urlsafe(24),
        basic_username="svc-" + secrets.token_hex(4),
        basic_password=secrets.token_urlsafe(24),
        header_name="X-Upstream-Key",
        header_prefix="Key ",
        header_value=secrets.token_urlsafe(24),
        query_param="key",
        query_value=secrets.token_urlsafe(24),
        oauth_client_id="client-" + secrets.token_hex(4),
        oauth_client_secret=secrets.token_urlsafe(24),
        oauth_scope="read:things",
        sigv4_access_key_id="AKIA" + secrets.token_hex(8).upper(),
        sigv4_secret_access_key=secrets.token_urlsafe(30),
        sigv4_region="eu-west-1",
        sigv4_service="execute-api",
    )


@pytest.fixture
def creds() -> UpstreamCredentials:
    return _credentials()


@pytest.fixture
async def client(creds):
    app = create_upstream(creds)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN) as c:
        yield c


def _basic(user: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


# --- bearer, basic, header, query ---------------------------------------------

SimpleCase = Callable[[UpstreamCredentials, bool], dict]


def _bearer(c: UpstreamCredentials, right: bool) -> dict:
    token = c.bearer if right else c.bearer + "x"
    return {"url": "/bearer/echo", "headers": {"Authorization": f"Bearer {token}"}}


def _basic_case(c: UpstreamCredentials, right: bool) -> dict:
    password = c.basic_password if right else "wrong"
    return {"url": "/basic/echo", "headers": {"Authorization": _basic(c.basic_username, password)}}


def _header(c: UpstreamCredentials, right: bool) -> dict:
    value = c.header_value if right else c.header_value[::-1]
    return {"url": "/header/echo", "headers": {c.header_name: c.header_prefix + value}}


def _query(c: UpstreamCredentials, right: bool) -> dict:
    value = c.query_value if right else "wrong"
    return {"url": "/query/echo", "params": {c.query_param: value}}


SIMPLE = {"bearer": _bearer, "basic": _basic_case, "header": _header, "query": _query}


@pytest.mark.parametrize("scheme", list(SIMPLE))
async def test_a_scheme_passes_with_its_credential_and_fails_with_a_wrong_one(
    client, creds, scheme: str
) -> None:
    right = await client.get(**SIMPLE[scheme](creds, True))
    assert right.status_code == 200, right.text
    assert right.json()["scheme"] == scheme
    wrong = await client.get(**SIMPLE[scheme](creds, False))
    assert wrong.status_code == 401
    missing = await client.get(f"/{scheme}/echo")
    assert missing.status_code == 401


async def test_a_header_value_without_its_prefix_fails(client, creds) -> None:
    response = await client.get("/header/echo", headers={creds.header_name: creds.header_value})
    assert response.status_code == 401


async def test_one_schemes_credential_does_not_pass_another(client, creds) -> None:
    response = await client.get("/basic/echo", headers={"Authorization": f"Bearer {creds.bearer}"})
    assert response.status_code == 401


async def test_the_echo_reports_what_arrived(client, creds) -> None:
    response = await client.post(
        "/bearer/echo/charges/ch_1",
        params={"expand": "x"},
        content=b'{"amount":500}',
        headers={
            "Authorization": f"Bearer {creds.bearer}",
            "Idempotency-Key": "secrets-d1",
            "Accept-Encoding": "gzip, deflate",
        },
    )
    assert response.status_code == 200
    assert response.json() == {
        "scheme": "bearer",
        "method": "POST",
        "path": "/bearer/echo/charges/ch_1",
        "query": "expand=x",
        "body_sha256": hashlib.sha256(b'{"amount":500}').hexdigest(),
        "idempotency_key": "secrets-d1",
        "accept_encoding": "gzip, deflate",
    }


async def test_the_issuing_endpoint_returns_fresh_temporary_credentials(client, creds) -> None:
    before = datetime.now(UTC)
    responses = [
        await client.post("/bearer/issue", headers={"Authorization": f"Bearer {creds.bearer}"})
        for _ in range(2)
    ]
    assert all(response.status_code == 200 for response in responses)
    bodies = [response.json() for response in responses]
    for body in bodies:
        credential = body["Credentials"]
        assert set(credential) == {"AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration"}
        assert credential["AccessKeyId"].startswith("ASIA")
        assert len(credential["AccessKeyId"]) == 20
        assert len(base64.b64decode(credential["SecretAccessKey"], validate=True)) == 30
        assert len(credential["SessionToken"]) >= 32
        assert datetime.fromisoformat(credential["Expiration"]) > before
        assert body["AssumedRoleUser"]["Arn"].startswith("arn:aws:sts:")
    # Compare inside all() so a failure never prints credential values.
    assert all(
        bodies[0]["Credentials"][key] != bodies[1]["Credentials"][key]
        for key in ("AccessKeyId", "SecretAccessKey", "SessionToken")
    )


async def test_the_issuing_endpoint_refuses_missing_or_wrong_credentials(client, creds) -> None:
    for headers in ({}, {"Authorization": f"Bearer {creds.bearer}x"}):
        response = await client.post("/bearer/issue", headers=headers)
        assert response.status_code == 401
    assert (await client.post("/unknown/issue")).status_code == 404


# --- OAuth2 client credentials -------------------------------------------------


async def _token(client, creds, *, auth: str = "basic", secret: str | None = None, scope=None):
    secret = creds.oauth_client_secret if secret is None else secret
    form = {"grant_type": "client_credentials", "scope": scope or creds.oauth_scope}
    headers = {}
    if auth == "basic":
        headers["Authorization"] = _basic(creds.oauth_client_id, secret)
    else:
        form |= {"client_id": creds.oauth_client_id, "client_secret": secret}
    return await client.post("/oauth2/token", data=form, headers=headers)


@pytest.mark.parametrize("auth", ["basic", "post"])
async def test_the_token_endpoint_issues_a_token_that_the_resource_accepts(client, creds, auth) -> None:
    issued = await _token(client, creds, auth=auth)
    assert issued.status_code == 200, issued.text
    body = issued.json()
    assert body["token_type"].lower() == "bearer"
    assert body["expires_in"] > 60
    echo = await client.get("/oauth2/echo", headers={"Authorization": f"Bearer {body['access_token']}"})
    assert echo.status_code == 200
    assert echo.json()["scheme"] == "oauth2-client-credentials"


@pytest.mark.parametrize("auth", ["basic", "post"])
async def test_the_token_endpoint_refuses_a_wrong_client_secret(client, creds, auth) -> None:
    assert (await _token(client, creds, auth=auth, secret="wrong")).status_code == 401


async def test_the_token_endpoint_refuses_another_scope(client, creds) -> None:
    assert (await _token(client, creds, scope="admin")).status_code == 400


async def test_the_resource_refuses_a_token_it_did_not_issue(client, creds) -> None:
    response = await client.get("/oauth2/echo", headers={"Authorization": f"Bearer {creds.bearer}"})
    assert response.status_code == 401


async def test_the_token_endpoint_counts_issuances(client, creds) -> None:
    for _ in range(2):
        await _token(client, creds)
    stats = await client.get("/oauth2/stats")
    assert stats.json() == {"issued": 2}


# --- AWS SigV4 ------------------------------------------------------------------


def _sigv4_headers(
    creds: UpstreamCredentials,
    *,
    method: str = "POST",
    path: str = "/sigv4/echo",
    body: bytes = b'{"q":1}',
    secret: str | None = None,
    region: str | None = None,
    service: str | None = None,
) -> dict[str, str]:
    request = AWSRequest(
        method=method,
        url=f"{ORIGIN}{path}",
        data=body,
        headers={"Content-Type": "application/json", "X-Amz-Target": "Things.Get"},
    )
    signer = SigV4Auth(
        Credentials(creds.sigv4_access_key_id, secret or creds.sigv4_secret_access_key),
        service or creds.sigv4_service,
        region or creds.sigv4_region,
    )
    request.headers["X-Amz-Content-SHA256"] = hashlib.sha256(body).hexdigest()
    signer.add_auth(request)
    return dict(request.headers.items())


async def _sigv4_send(client, headers: dict[str, str], body: bytes = b'{"q":1}'):
    return await client.post("/sigv4/echo", content=body, headers=headers)


async def test_a_correct_sigv4_signature_passes(client, creds) -> None:
    response = await _sigv4_send(client, _sigv4_headers(creds))
    assert response.status_code == 200, response.text
    assert response.json()["scheme"] == "aws-sigv4"


@pytest.mark.parametrize(
    "change",
    [
        {"secret": "wrong-secret-key"},
        {"region": "us-east-1"},
        {"service": "s3"},
    ],
    ids=["wrong-secret", "other-region", "other-service"],
)
async def test_a_wrong_sigv4_signature_fails(client, creds, change) -> None:
    response = await _sigv4_send(client, _sigv4_headers(creds, **change))
    assert response.status_code == 401


async def test_a_sigv4_request_whose_body_changed_after_signing_fails(client, creds) -> None:
    response = await _sigv4_send(client, _sigv4_headers(creds), body=b'{"q":2}')
    assert response.status_code == 401


async def test_a_sigv4_request_whose_signed_header_changed_fails(client, creds) -> None:
    headers = _sigv4_headers(creds)
    headers["X-Amz-Target"] = "Things.Delete"
    assert (await _sigv4_send(client, headers)).status_code == 401


async def test_a_sigv4_request_without_a_signature_fails(client) -> None:
    assert (await client.post("/sigv4/echo", content=b"{}")).status_code == 401


@pytest.mark.parametrize(("minutes", "status"), [(14, 200), (16, 401), (-16, 401)])
async def test_a_sigv4_signature_is_good_only_within_its_skew(creds, minutes, status) -> None:
    upstream = create_upstream(creds, now=lambda: datetime.now(UTC) + timedelta(minutes=minutes))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=upstream), base_url=ORIGIN) as c:
        assert (await _sigv4_send(c, _sigv4_headers(creds))).status_code == status


async def test_a_sigv4_request_without_a_payload_hash_header_passes(client, creds) -> None:
    body = b'{"q":1}'
    request = AWSRequest(method="POST", url=f"{ORIGIN}/sigv4/echo", data=body, headers={})
    SigV4Auth(
        Credentials(creds.sigv4_access_key_id, creds.sigv4_secret_access_key),
        creds.sigv4_service,
        creds.sigv4_region,
    ).add_auth(request)
    headers = dict(request.headers.items())
    assert "X-Amz-Content-SHA256" not in headers
    assert (await _sigv4_send(client, headers, body)).status_code == 200


async def test_a_sigv4_payload_hash_header_that_does_not_match_the_body_fails(client, creds) -> None:
    headers = _sigv4_headers(creds)
    headers["X-Amz-Content-SHA256"] = hashlib.sha256(b"other").hexdigest()
    assert (await _sigv4_send(client, headers)).status_code == 401
