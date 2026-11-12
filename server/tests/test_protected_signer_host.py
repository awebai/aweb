"""Executable independent host: private configuration and origin isolation."""

import json
import os
from pathlib import Path

import httpx
import pytest
from aweb.protected_signing.host import HostSettings, create_app
from aweb_naapp.runtime.protected_signer import SignerRefused
from pydantic import SecretStr, ValidationError

FIXTURE = Path(__file__).resolve().parents[2] / "docs/vectors/protected-service-profile-v1.json"


def settings(tmp_path, **changes):
    profile = json.loads(FIXTURE.read_bytes())
    profile_file, scope_file = tmp_path / "profile.json", tmp_path / "scope.json"
    profile_file.write_text(json.dumps(profile))
    scope_file.write_text(json.dumps(profile["bindings"][0]["scope"]))
    return HostSettings(
        profile_file=profile_file,
        scope_file=scope_file,
        controller_key_file=tmp_path / "missing/controller.key",
        member_keys_file=tmp_path / "members.json",
        database_url=SecretStr("postgresql://private-password@localhost/missing"),
        worker_uids=[65534 if os.geteuid() != 65534 else 65533],
        **changes,
    )


def test_settings_hide_database_secret_and_require_explicit_inputs(tmp_path, monkeypatch):
    monkeypatch.delenv("AWEB_PROTECTED_DATABASE_URL", raising=False)
    assert "private-password" not in repr(settings(tmp_path))
    with pytest.raises(ValidationError):
        HostSettings(_env_file=None)


def test_same_host_origins_refuse_before_resources_open(tmp_path):
    config = settings(tmp_path)
    fields = json.loads(config.profile_file.read_bytes())
    fields["request_origin"] = fields["human_origin"]
    config.profile_file.write_text(json.dumps(fields))
    with pytest.raises(ValueError, match="distinct"):
        create_app(config, mailer=object())


@pytest.mark.asyncio
async def test_unsafe_custody_fails_startup_before_database_or_mail(tmp_path):
    host = create_app(settings(tmp_path), mailer=object())
    with pytest.raises(SignerRefused, match="custody_not_isolated"):
        async with host.api_app.router.lifespan_context(host.api_app):
            pytest.fail("unsafe custody started")


@pytest.mark.asyncio
async def test_wrong_origin_and_agent_auth_on_human_refuse_before_database(tmp_path):
    host = create_app(settings(tmp_path), mailer=object())
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=host)) as client:
        unknown = await client.get("https://wrong.example/handoff/anything")
        refused = await client.get(
            "https://human.customer.example/handoff/anything",
            headers={"Authorization": "Bearer not-authority"},
        )
        assert unknown.status_code == 421
        assert refused.status_code == 403
        assert refused.json()["code"] == "team_auth_refused"


def test_notification_settings_are_required_not_a_silent_noop(tmp_path, monkeypatch):
    monkeypatch.delenv("AWEB_PROTECTED_EMAIL_SMTP_HOST", raising=False)
    with pytest.raises(ValueError, match="AWEB_PROTECTED_EMAIL_SMTP_HOST"):
        create_app(settings(tmp_path))
