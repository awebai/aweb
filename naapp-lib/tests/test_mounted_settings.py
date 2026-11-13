"""Mounted service credentials use the normal prefixed settings path, without I/O services."""

import secrets
from pathlib import Path

import pytest
from pydantic_settings import SettingsConfigDict, SettingsError

from aweb_naapp.email import EmailSettings
from aweb_naapp.runtime.settings import NaappSettings


class MountedSettings(NaappSettings):
    database_url: str = "postgresql://localhost/default"
    public_origin: str = "https://app.example"
    app_id: str = "app"
    email_username: str | None = None


class SecretsInputs(MountedSettings):
    model_config = SettingsConfigDict(env_prefix="SECRETS_")


class LogsInputs(MountedSettings):
    model_config = SettingsConfigDict(env_prefix="LOGS_")


def write_private(path: Path, content: str) -> Path:
    path.write_text(content)
    path.chmod(0o400)
    return path


def same_value(actual, expected):
    if actual != expected:
        raise AssertionError("mounted credential did not reach settings")


@pytest.mark.parametrize(
    "settings_type,prefix", [(SecretsInputs, "SECRETS_"), (LogsInputs, "LOGS_")]
)
def test_prefixed_dsn_and_smtp_user_files(settings_type, prefix, tmp_path, monkeypatch):
    dsn = "postgresql://service:" + secrets.token_urlsafe(24) + "@postgres/service"
    username = secrets.token_urlsafe(16)
    for name, value in (("DATABASE_URL", dsn), ("EMAIL_USERNAME", username)):
        monkeypatch.delenv(prefix + name, raising=False)
        monkeypatch.setenv(
            prefix + name + "_FILE", str(write_private(tmp_path / name, value + "\n"))
        )
    settings = settings_type(_env_file=None)
    same_value(settings.database_url, dsn)
    same_value(settings.email_username, username)


def test_fixed_alias_file_is_not_given_an_app_prefix(tmp_path, monkeypatch):
    dsn = "postgresql://deleter:" + secrets.token_urlsafe(24) + "@postgres/service"
    monkeypatch.delenv("AWEB_PAGE_DELETION_DATABASE_URL", raising=False)
    monkeypatch.setenv(
        "AWEB_PAGE_DELETION_DATABASE_URL_FILE", str(write_private(tmp_path / "deletion", dsn))
    )
    same_value(LogsInputs(_env_file=None).page_deletion_database_url, dsn)


def test_explicit_settings_still_override_file_source(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "LOGS_DATABASE_URL_FILE", str(write_private(tmp_path / "dsn", "postgresql://postgres/file"))
    )
    same_value(
        LogsInputs(_env_file=None, database_url="postgresql://postgres/explicit").database_url,
        "postgresql://postgres/explicit",
    )


@pytest.mark.parametrize("content", [b"", b"\xff", b"x" * 1025])
def test_bad_file_refuses_without_credential_contents(tmp_path, monkeypatch, content):
    path = tmp_path / "dsn"
    path.write_bytes(content)
    path.chmod(0o400)
    monkeypatch.setenv("LOGS_DATABASE_URL_FILE", str(path))
    with pytest.raises((SettingsError, ValueError)):
        LogsInputs(_env_file=None)


def test_direct_and_file_credentials_are_ambiguous(tmp_path, monkeypatch):
    credential = secrets.token_urlsafe(24)
    monkeypatch.setenv("LOGS_DATABASE_URL", credential)
    monkeypatch.setenv("LOGS_DATABASE_URL_FILE", str(write_private(tmp_path / "dsn", credential)))
    with pytest.raises((SettingsError, ValueError)) as caught:
        LogsInputs(_env_file=None)
    if credential in str(caught.value):
        raise AssertionError("credential appeared in settings error")


def test_projected_secret_symlink_and_permissions(tmp_path, monkeypatch):
    target = write_private(tmp_path / "projected", "postgresql://postgres/projected\n")
    link = tmp_path / "dsn"
    link.symlink_to(target.name)
    monkeypatch.setenv("LOGS_DATABASE_URL_FILE", str(link))
    same_value(LogsInputs(_env_file=None).database_url, "postgresql://postgres/projected")
    target.chmod(0o666)
    with pytest.raises((SettingsError, ValueError)):
        LogsInputs(_env_file=None)


def test_mail_uses_same_username_file_and_existing_password_reader(tmp_path):
    username = secrets.token_urlsafe(16)
    password = secrets.token_urlsafe(24)
    env = {
        "LOGS_EMAIL_SMTP_HOST": "smtp.example",
        "LOGS_EMAIL_SMTP_PORT": "587",
        "LOGS_EMAIL_FROM": "service@example.com",
        "LOGS_EMAIL_USERNAME_FILE": str(write_private(tmp_path / "username", username + "\n")),
        "LOGS_EMAIL_PASSWORD_FILE": str(write_private(tmp_path / "password", password + "\n")),
    }
    settings = EmailSettings.from_env("LOGS_", environ=env)
    same_value(settings.username, username)
    same_value(settings.password, password)
    with pytest.raises(ValueError):
        EmailSettings.from_env("LOGS_", environ={**env, "LOGS_EMAIL_PASSWORD": password})
