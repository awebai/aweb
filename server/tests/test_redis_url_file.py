"""The Redis URL can come from a file, so its password is in no environment."""

import pytest

from aweb.config import get_settings

URL = "redis://:s3cret@redis:6379/0"


@pytest.fixture(autouse=True)
def database_and_no_redis_environment(monkeypatch):
    monkeypatch.setenv("AWEB_DATABASE_URL", "postgresql://aweb@postgres:5432/aweb")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("AWEB_DATABASE_URL_FILE", raising=False)
    for name in ("AWEB_REDIS_URL", "REDIS_URL", "AWEB_REDIS_URL_FILE"):
        monkeypatch.delenv(name, raising=False)


def test_the_redis_url_is_read_from_the_named_file(monkeypatch, tmp_path):
    source = tmp_path / "redis-url"
    source.write_text(URL + "\n")
    monkeypatch.setenv("AWEB_REDIS_URL_FILE", str(source))
    assert get_settings().redis_url == URL


@pytest.mark.parametrize("variable", ["AWEB_REDIS_URL", "REDIS_URL"])
def test_a_file_and_an_environment_url_together_are_refused(monkeypatch, tmp_path, variable):
    source = tmp_path / "redis-url"
    source.write_text(URL)
    monkeypatch.setenv("AWEB_REDIS_URL_FILE", str(source))
    monkeypatch.setenv(variable, URL)
    with pytest.raises(ValueError, match="AWEB_REDIS_URL_FILE") as refused:
        get_settings()
    assert "s3cret" not in str(refused.value)


@pytest.mark.parametrize("content", [None, "", "  \n"])
def test_a_file_that_is_missing_or_empty_is_refused_without_its_content(monkeypatch, tmp_path, content):
    source = tmp_path / "redis-url"
    if content is not None:
        source.write_text(content)
    monkeypatch.setenv("AWEB_REDIS_URL_FILE", str(source))
    with pytest.raises(ValueError, match="AWEB_REDIS_URL_FILE must name a readable file"):
        get_settings()


def test_without_a_file_the_environment_url_is_used(monkeypatch):
    monkeypatch.setenv("AWEB_REDIS_URL", "redis://redis:6379/0")
    assert get_settings().redis_url == "redis://redis:6379/0"
