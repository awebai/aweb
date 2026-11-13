"""Executable independent host: private configuration and origin isolation."""

import json
import os
from types import SimpleNamespace

import httpx
import pytest
from datetime import UTC, datetime
from aweb_naapp.email import EmailNotSent
from aweb_naapp.runtime.approvals import DeliveryStatus
from aweb_naapp.runtime.protected_signer import SignerRefused
from pydantic import SecretStr, ValidationError
from starlette.requests import Request

from aweb.protected_signing.host import HostSettings, create_app
from aweb.protected_signing.notifications import ProtectedNotifications
from tests.test_protected_service_profile import FIXTURE


class CapturedMail:
    def __init__(self):
        self.messages = []

    async def send(self, message):
        self.messages.append(message)


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


def test_settings_hide_database_secret_and_require_explicit_inputs(
    tmp_path, monkeypatch
):
    monkeypatch.delenv("AWEB_PROTECTED_DATABASE_URL", raising=False)
    assert "private-password" not in repr(settings(tmp_path))
    with pytest.raises(ValidationError):
        HostSettings(_env_file=None)


def test_incomplete_environment_error_does_not_echo_database_password(monkeypatch):
    for name in os.environ:
        if name.startswith("AWEB_PROTECTED_"):
            monkeypatch.delenv(name)
    secret = "SYNTH"
    monkeypatch.setenv("AWEB_PROTECTED_DATABASE_URL", "postgres://u:" + secret + "@d/x")
    with pytest.raises(ValidationError) as caught:
        HostSettings(_env_file=None)
    assert secret not in str(caught.value)
    assert "input_value" not in str(caught.value)


def file_settings(tmp_path, content=b"postgresql://signer:SYNTH@db/protected\n"):
    fields = settings(tmp_path).model_dump()
    fields.pop("database_url")
    filename = tmp_path / "database-url"
    filename.write_bytes(content)
    filename.chmod(0o400)
    fields["database_url_file"] = filename
    return fields


def test_database_url_file_reuses_whole_dsn_and_keeps_existing_settings_port(tmp_path):
    fields = file_settings(tmp_path)
    config = HostSettings(**fields)
    assert (
        config.database_url.get_secret_value()
        == "postgresql://signer:SYNTH@db/protected"
    )
    assert "SYNTH" not in repr(config)
    assert HostSettings.model_validate(config).database_url == config.database_url


def test_database_url_file_accepts_readonly_projected_file_symlink(tmp_path):
    fields = file_settings(tmp_path)
    projected = tmp_path / "projected-url"
    projected.symlink_to(fields["database_url_file"])
    fields["database_url_file"] = projected
    assert (
        HostSettings(**fields).database_url.get_secret_value().endswith("@db/protected")
    )


@pytest.mark.parametrize(
    "content", [b"", b"\n", b"SYNTH\nsecond", b"\xffSYNTH", b"SYNTH\x00", b"x" * 1025]
)
def test_invalid_database_file_refuses_without_echoing_contents(tmp_path, content):
    with pytest.raises(ValidationError) as caught:
        HostSettings(**file_settings(tmp_path, content))
    assert "SYNTH" not in str(caught.value)
    assert "input_value" not in str(caught.value)
    assert "protected_database_url_file_invalid" in str(caught.value)


@pytest.mark.parametrize("mode", [0o620, 0o602])
def test_writable_database_file_refuses(tmp_path, mode):
    fields = file_settings(tmp_path)
    fields["database_url_file"].chmod(mode)
    with pytest.raises(ValidationError, match="protected_database_url_file_invalid"):
        HostSettings(**fields)


def test_missing_database_file_refuses_without_exposing_the_input(tmp_path):
    fields = file_settings(tmp_path)
    fields["database_url_file"].unlink()
    with pytest.raises(
        ValidationError, match="protected_database_url_file_invalid"
    ) as caught:
        HostSettings(**fields)
    assert "SYNTH" not in str(caught.value)


def test_database_file_and_value_refuse_ambiguous_configuration(tmp_path):
    fields = file_settings(tmp_path)
    fields["database_url"] = SecretStr("postgresql://other:SYNTH@db/other")
    with pytest.raises(
        ValidationError, match="protected_database_url_sources_conflict"
    ) as caught:
        HostSettings(**fields)
    assert "SYNTH" not in str(caught.value)


def test_database_url_file_environment_input(tmp_path, monkeypatch):
    fields = file_settings(tmp_path)
    filename = fields.pop("database_url_file")
    monkeypatch.delenv("AWEB_PROTECTED_DATABASE_URL", raising=False)
    monkeypatch.setenv("AWEB_PROTECTED_DATABASE_URL_FILE", str(filename))
    assert (
        HostSettings(**fields).database_url.get_secret_value().endswith("@db/protected")
    )


@pytest.mark.asyncio
async def test_readiness_is_unavailable_before_startup_and_only_on_request_origin(
    tmp_path,
):
    host = create_app(settings(tmp_path), mailer=CapturedMail())
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=host)) as client:
        response = await client.get("https://signer.customer.example/readyz")
        assert response.status_code == 503
        assert response.json() == {"ready": False}
        assert response.headers["cache-control"] == "no-store"
        assert (
            await client.get("https://human.customer.example/readyz")
        ).status_code == 404


def test_limiter_ignores_spoofed_header_by_default_and_separates_trusted_clients(
    tmp_path,
):
    config = settings(tmp_path)

    def request(address):
        return Request(
            {
                "type": "http",
                "client": ("proxy-peer", 443),
                "headers": [(b"x-real-ip", address.encode())],
            }
        )

    first, second = request("198.51.100.1"), request("198.51.100.2")
    assert config.client_identity().of(first) == "proxy-peer"
    assert config.client_identity().of(second) == "proxy-peer"
    trusted = HostSettings(
        **{**config.model_dump(), "trusted_client_header": "X-Real-IP"}
    )
    assert trusted.client_identity().of(first) == "198.51.100.1"
    assert trusted.client_identity().of(second) == "198.51.100.2"


def test_same_host_origins_refuse_before_resources_open(tmp_path):
    config = settings(tmp_path)
    fields = json.loads(config.profile_file.read_bytes())
    fields["request_origin"] = fields["human_origin"]
    config.profile_file.write_text(json.dumps(fields))
    with pytest.raises(ValueError, match="distinct"):
        create_app(config, mailer=CapturedMail())


@pytest.mark.asyncio
async def test_unsafe_custody_fails_startup_before_database_or_mail(tmp_path):
    host = create_app(settings(tmp_path), mailer=CapturedMail())
    with pytest.raises(SignerRefused, match="custody_not_isolated"):
        async with host.api_app.router.lifespan_context(host.api_app):
            pytest.fail("unsafe custody started")


@pytest.mark.asyncio
async def test_wrong_origin_and_agent_auth_on_human_refuse_before_database(tmp_path):
    host = create_app(settings(tmp_path), mailer=CapturedMail())
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


@pytest.mark.parametrize("uids", [[True], [0], ["1001"], []])
def test_worker_uids_are_explicit_positive_integers(tmp_path, uids):
    config = settings(tmp_path).model_dump()
    config["worker_uids"] = uids
    with pytest.raises(ValidationError):
        HostSettings(**config)


@pytest.mark.asyncio
@pytest.mark.parametrize("mail_fails", [False, True])
async def test_notification_adapter_reuses_b3_and_b2_mail_boundary(mail_fails):
    mail = CapturedMail()
    if mail_fails:

        async def refused(message):
            raise EmailNotSent("connection_failed")

        mail.send = refused

    class Lookup:
        async def fetch_value(self, sql, approval_id):
            assert approval_id == "approval-id"
            return "00000000-0000-0000-0000-000000000001"

    delivery = ProtectedNotifications(
        db=Lookup(), mailer=mail, human_origin="https://human.customer.example"
    )
    approver = SimpleNamespace(contact="fixture@example.test")
    expected = DeliveryStatus.FAILED if mail_fails else DeliveryStatus.DELIVERED
    assert (
        await delivery.deliver_enrolment_link(approver, "enrolment-secret") == expected
    )
    expires = datetime(2026, 11, 14, 9, 30, tzinfo=UTC)
    assert (
        await delivery.deliver_approval_link(
            approver, "candidate-secret",
            SimpleNamespace(approval_id="approval-id", expires_at=expires),
        )
        == expected
    )
    if not mail_fails:
        assert "enrolment#token=enrolment-secret" in mail.messages[0].text
        # The personal link (Juan 2026-11-13, via coordinator): the token rides
        # in the fragment, which browsers never send to a server.
        link = "https://human.customer.example/handoff/00000000-0000-0000-0000-000000000001#k=candidate-secret"
        notice = mail.messages[1]
        assert link in notice.text and link.replace("&", "&amp;") in notice.html
        assert "?" not in link
        # The actual retained expiry, and that Deny also asks for the passkey.
        assert "2026-11-14 09:30 UTC" in notice.text
        assert "Deny also asks for your passkey" in notice.text
        assert all(message.to == approver.contact for message in mail.messages)
