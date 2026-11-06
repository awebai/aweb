"""The pinned CLI authenticates to the real TLS/password receiver in a child process."""

import asyncio
import os
import secrets
import sys
from pathlib import Path

import pytest
from aweb_naapp_testing.network import make_certificates
from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from upstream.app import create_upstream
from upstream.serve import serving

from tests.test_upstream import creds as creds

CLIENT = Path(__file__).parents[1] / "e2e" / "upstream" / "cli.py"
PASSWORD_ENV = "AWEB_SECRETS_E2E_CLI_PASSWORD"


@pytest.fixture
async def target(tmp_path, creds):
    certs = make_certificates(tmp_path, ["localhost"], ["127.0.0.1"])
    app = create_upstream(creds)
    observed = []

    @app.middleware("http")
    async def record(request, call_next):
        response = await call_next(request)
        observed.append((request.url.path, response.status_code))
        return response

    async with serving(app, certs, "127.0.0.1") as port:
        yield f"https://127.0.0.1:{port}", certs, observed


async def invoke(origin, certs, username, password, *extra):
    environment = {} if password is None else {PASSWORD_ENV: password}
    # The runner starts jobs with only their declared environment. Ambient
    # proxy settings must not divert the password from this TLS receiver.
    environment.update(HTTPS_PROXY="http://127.0.0.1:1", ALL_PROXY="http://127.0.0.1:1")
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-I",
        str(CLIENT),
        "--origin",
        origin,
        "--ca-file",
        str(certs.ca_file),
        "--username",
        username,
        *extra,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=environment,
    )
    try:
        output, errors = await asyncio.wait_for(process.communicate(), 10)
        return process.returncode, output, errors
    finally:
        if process.returncode is None:
            process.kill()
        await process.wait()


def fixed_result(result, *, accepted):
    # Never let a broken client place credential-bearing output in diagnostics.
    expected = (0, b"authenticated\n", b"") if accepted else (1, b"refused\n", b"")
    if result != expected:
        raise AssertionError("CLI did not return the expected fixed result")


@pytest.mark.parametrize("correct", [True, False])
async def test_cli_authenticates_using_only_the_declared_password_environment(
    target, creds, correct
):
    origin, certs, observed = target
    password = creds.basic_password if correct else secrets.token_urlsafe(32)
    fixed_result(await invoke(origin, certs, creds.basic_username, password), accepted=correct)
    assert observed == [("/basic/echo", 200 if correct else 401)]


@pytest.mark.parametrize("password", [None, ""])
async def test_missing_password_refuses_before_any_target_call(target, creds, password):
    origin, certs, observed = target
    fixed_result(await invoke(origin, certs, creds.basic_username, password), accepted=False)
    assert not observed


@pytest.mark.parametrize("change", ["http", "userinfo", "path"])
async def test_invalid_target_origin_refuses_without_sending_the_password(target, creds, change):
    origin, certs, observed = target
    if change == "http":
        origin = origin.replace("https:", "http:")
    elif change == "userinfo":
        origin = origin.replace("://", "://user:input@")
    else:
        origin += "/elsewhere"
    fixed_result(
        await invoke(origin, certs, creds.basic_username, creds.basic_password), accepted=False
    )
    assert not observed


async def test_untrusted_tls_certificate_refuses_without_an_authenticated_call(
    target, creds, tmp_path
):
    origin, _, observed = target
    other = tmp_path / "other-ca"
    other.mkdir()
    certs = make_certificates(other, ["localhost"], ["127.0.0.1"])
    fixed_result(
        await invoke(origin, certs, creds.basic_username, creds.basic_password), accepted=False
    )
    assert not observed


async def test_redirect_is_not_followed_with_the_password(target, creds):
    origin, certs, observed = target
    app = FastAPI()

    @app.get("/basic/echo")
    async def redirect():
        return RedirectResponse(origin + "/basic/echo")

    async with serving(app, certs, "127.0.0.1") as port:
        fixed_result(
            await invoke(
                f"https://127.0.0.1:{port}", certs, creds.basic_username, creds.basic_password
            ),
            accepted=False,
        )
    assert not observed


async def test_bad_arguments_produce_only_the_fixed_refusal(target, creds):
    origin, certs, observed = target
    fixed_result(
        await invoke(
            origin,
            certs,
            creds.basic_username,
            creds.basic_password,
            "--unexpected",
            os.urandom(8).hex(),
        ),
        accepted=False,
    )
    assert not observed
