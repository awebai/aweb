"""The shared email sender against a real SMTP server started in the test."""

from __future__ import annotations

import email
import email.policy
from collections.abc import Iterator
from pathlib import Path

import pytest
from aweb_naapp_testing.smtp import SilentServer, SmtpServer

from aweb_naapp.email import EmailNotSent, EmailSettings, Mailer, Message

PREFIX = "APP_"
TOKEN = "link-token-bearer-canary"
MESSAGE = Message(
    to="owner@example.com",
    subject="Approve a request",
    text=f"Open https://app.example/approve#{TOKEN}",
    html=f"<p><a href='https://app.example/approve#{TOKEN}'>Approve</a></p>",
)


def _password_file(directory: Path, password: str, mode: int = 0o600) -> Path:
    path = directory / "smtp-password"
    path.write_text(password + "\n")
    path.chmod(mode)
    return path


def _environ(server: SmtpServer | SilentServer, directory: Path, **changes: str) -> dict[str, str]:
    password = getattr(server, "password", "unused")
    environ = {
        f"{PREFIX}EMAIL_SMTP_HOST": "localhost",
        f"{PREFIX}EMAIL_SMTP_PORT": str(server.port),
        f"{PREFIX}EMAIL_TLS": getattr(server, "mode", "starttls")
        if getattr(server, "mode", "starttls") != "plain"
        else "starttls",
        f"{PREFIX}EMAIL_USERNAME": getattr(server, "username", "mailer"),
        f"{PREFIX}EMAIL_PASSWORD_FILE": str(_password_file(directory, password)),
        f"{PREFIX}EMAIL_FROM": "App <noreply@app.example>",
    }
    ca_file = getattr(server, "certificates", None)
    if ca_file is not None:
        environ[f"{PREFIX}EMAIL_CA_FILE"] = str(server.ca_file)  # type: ignore[union-attr]
    environ.update(changes)
    return environ


def _mailer(environ: dict[str, str], timeout: float = 5.0) -> Mailer:
    return Mailer(EmailSettings.from_env(PREFIX, environ=environ), timeout=timeout)


@pytest.fixture
def server(tmp_path: Path) -> Iterator[SmtpServer]:
    with SmtpServer(tmp_path / "smtp") as running:
        yield running


def _parsed(server: SmtpServer) -> email.message.EmailMessage:
    [received] = server.received
    parsed = email.message_from_bytes(received.content, policy=email.policy.default)
    assert isinstance(parsed, email.message.EmailMessage)
    return parsed


async def test_a_message_is_delivered_over_starttls(server: SmtpServer, tmp_path: Path) -> None:
    await _mailer(_environ(server, tmp_path)).send(MESSAGE)
    [received] = server.received
    assert received.rcpt_tos == ["owner@example.com"]
    assert received.mail_from == "noreply@app.example"
    parsed = _parsed(server)
    assert parsed["Subject"] == "Approve a request"
    assert parsed["To"] == "owner@example.com"
    assert parsed.get_content_type() == "multipart/alternative"
    assert TOKEN in parsed.get_body(("plain",)).get_content()
    assert TOKEN in parsed.get_body(("html",)).get_content()


async def test_a_message_is_delivered_over_implicit_tls(tmp_path: Path) -> None:
    with SmtpServer(tmp_path / "smtp", mode="implicit") as server:
        await _mailer(_environ(server, tmp_path)).send(MESSAGE)
        assert len(server.received) == 1


async def test_nothing_is_sent_without_tls(tmp_path: Path) -> None:
    with SmtpServer(tmp_path / "smtp", mode="plain") as server:
        with pytest.raises(EmailNotSent) as refused:
            await _mailer(_environ(server, tmp_path)).send(MESSAGE)
        assert refused.value.code == "tls_unavailable"
        assert server.received == []


async def test_nothing_is_sent_to_a_server_whose_certificate_is_not_trusted(
    server: SmtpServer, tmp_path: Path
) -> None:
    environ = _environ(server, tmp_path)
    del environ[f"{PREFIX}EMAIL_CA_FILE"]
    with pytest.raises(EmailNotSent) as refused:
        await _mailer(environ).send(MESSAGE)
    assert refused.value.code == "tls_unavailable"
    assert server.received == []


async def test_a_wrong_password_is_auth_failed(server: SmtpServer, tmp_path: Path) -> None:
    environ = _environ(server, tmp_path)
    _password_file(tmp_path, "not-the-password")
    with pytest.raises(EmailNotSent) as refused:
        await _mailer(environ).send(MESSAGE)
    assert refused.value.code == "auth_failed"
    assert server.received == []


async def test_a_refused_recipient_is_reported_as_such(tmp_path: Path) -> None:
    with SmtpServer(tmp_path / "smtp", refuse={"owner@example.com"}) as server:
        with pytest.raises(EmailNotSent) as refused:
            await _mailer(_environ(server, tmp_path)).send(MESSAGE)
        assert refused.value.code == "recipient_refused"
        assert server.received == []


async def test_a_closed_port_is_connection_failed(server: SmtpServer, tmp_path: Path) -> None:
    environ = _environ(server, tmp_path)
    server.__exit__(None, None, None)
    with pytest.raises(EmailNotSent) as refused:
        await _mailer(environ).send(MESSAGE)
    assert refused.value.code == "connection_failed"


async def test_a_server_that_never_answers_is_a_timeout(tmp_path: Path) -> None:
    with SilentServer() as silent:
        with pytest.raises(EmailNotSent) as refused:
            await _mailer(_environ(silent, tmp_path), timeout=0.5).send(MESSAGE)
    assert refused.value.code == "timeout"


@pytest.mark.parametrize(
    "header",
    [{"subject": "Approve\r\nBcc: attacker@example.com"}, {"to": "owner@example.com\r\nBcc: a@b"}],
)
async def test_a_header_with_a_line_break_is_refused_before_connecting(
    server: SmtpServer, tmp_path: Path, header: dict[str, str]
) -> None:
    fields = dict(to=MESSAGE.to, subject=MESSAGE.subject, text=MESSAGE.text, html=MESSAGE.html)
    fields.update(header)
    with pytest.raises(ValueError):
        await _mailer(_environ(server, tmp_path)).send(Message(**fields))
    assert server.received == []


async def test_the_body_never_reaches_errors_logs_or_debug_output(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, capfd: pytest.CaptureFixture[str]
) -> None:
    with SmtpServer(tmp_path / "smtp", refuse={"owner@example.com"}) as refusing:
        with caplog.at_level("DEBUG"), pytest.raises(EmailNotSent) as refused:
            await _mailer(_environ(refusing, tmp_path)).send(MESSAGE)
    with SmtpServer(tmp_path / "smtp2") as accepting:
        with caplog.at_level("DEBUG"):
            await _mailer(_environ(accepting, tmp_path)).send(MESSAGE)
    captured = capfd.readouterr()
    for text in (str(refused.value), repr(refused.value), caplog.text, captured.out, captured.err):
        assert TOKEN not in text
        assert "owner@example.com" not in text
    assert "o***@example.com" in caplog.text


@pytest.mark.parametrize(
    "changes",
    [
        {f"{PREFIX}EMAIL_SMTP_HOST": ""},
        {f"{PREFIX}EMAIL_SMTP_PORT": "smtp"},
        {f"{PREFIX}EMAIL_SMTP_PORT": "70000"},
        {f"{PREFIX}EMAIL_TLS": "none"},
        {f"{PREFIX}EMAIL_FROM": ""},
        {f"{PREFIX}EMAIL_PASSWORD_FILE": "/nonexistent/smtp-password"},
    ],
)
def test_a_bad_setting_fails_at_startup(
    server: SmtpServer, tmp_path: Path, changes: dict[str, str]
) -> None:
    with pytest.raises(ValueError):
        EmailSettings.from_env(PREFIX, environ=_environ(server, tmp_path, **changes))


def test_a_password_file_others_can_write_fails_at_startup(
    server: SmtpServer, tmp_path: Path
) -> None:
    environ = _environ(server, tmp_path)
    _password_file(tmp_path, server.password, mode=0o622)
    with pytest.raises(ValueError):
        EmailSettings.from_env(PREFIX, environ=environ)


def test_a_password_is_never_taken_from_the_environment(server: SmtpServer, tmp_path: Path) -> None:
    environ = _environ(server, tmp_path)
    del environ[f"{PREFIX}EMAIL_PASSWORD_FILE"]
    environ[f"{PREFIX}EMAIL_PASSWORD"] = server.password
    with pytest.raises(ValueError):
        EmailSettings.from_env(PREFIX, environ=environ)


def test_a_startup_error_never_carries_the_password(server: SmtpServer, tmp_path: Path) -> None:
    environ = _environ(server, tmp_path, **{f"{PREFIX}EMAIL_TLS": "none"})
    with pytest.raises(ValueError) as refused:
        EmailSettings.from_env(PREFIX, environ=environ)
    assert server.password not in str(refused.value)
