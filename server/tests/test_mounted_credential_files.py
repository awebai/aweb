"""Credential files the server reads pass the shared key-file checks: a
regular file, not writable by group or others, at most 1 KiB."""

import os

import pytest

from aweb.config import get_settings

DATABASE_URL = "postgresql://aweb:s3cret@postgres:5432/aweb"
REDIS_URL = "redis://default:s3cret@redis:6379/0"


@pytest.fixture(autouse=True)
def no_url_environment(monkeypatch):
    for name in (
        "AWEB_DATABASE_URL",
        "DATABASE_URL",
        "AWEB_DATABASE_URL_FILE",
        "AWEB_REDIS_URL",
        "REDIS_URL",
        "AWEB_REDIS_URL_FILE",
        "AWID_MEMBER_KEYS_FILE",
    ):
        monkeypatch.delenv(name, raising=False)


def url_files(monkeypatch, tmp_path):
    files = {}
    for variable, url in (
        ("AWEB_DATABASE_URL_FILE", DATABASE_URL),
        ("AWEB_REDIS_URL_FILE", REDIS_URL),
    ):
        path = tmp_path / variable.lower()
        path.write_text(url + "\n")
        path.chmod(0o600)
        monkeypatch.setenv(variable, str(path))
        files[variable] = path
    return files


@pytest.mark.parametrize("variable", ["AWEB_DATABASE_URL_FILE", "AWEB_REDIS_URL_FILE"])
def test_a_group_writable_url_file_is_refused_without_its_content(
    monkeypatch, tmp_path, variable
):
    url_files(monkeypatch, tmp_path)[variable].chmod(0o620)
    with pytest.raises(ValueError, match=variable) as refused:
        get_settings()
    assert "s3cret" not in str(refused.value)


@pytest.mark.parametrize("variable", ["AWEB_DATABASE_URL_FILE", "AWEB_REDIS_URL_FILE"])
def test_a_url_path_that_is_not_a_regular_file_is_refused(
    monkeypatch, tmp_path, variable
):
    url_files(monkeypatch, tmp_path)
    fifo = tmp_path / "url.fifo"
    os.mkfifo(fifo)
    monkeypatch.setenv(variable, str(fifo))
    with pytest.raises(ValueError, match=variable):
        get_settings()
