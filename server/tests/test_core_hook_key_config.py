"""Only a dedicated configured file key matching the published kid can sign."""

import json
import os
from datetime import UTC, datetime, timedelta

import pytest
from awid.did import did_from_public_key
from nacl.signing import SigningKey

from aweb.hook_producer import load_core_hooks
from aweb_naapp.signing_key import SigningKeyError


@pytest.fixture
def configured(monkeypatch, tmp_path):
    key = SigningKey.generate()
    path = tmp_path / "core-hook.key"
    path.write_text(bytes(key).hex())
    path.chmod(0o600)
    now = datetime.now(UTC)
    entry = {
        "kid": "core-current", "did_key": did_from_public_key(bytes(key.verify_key)),
        "valid_from": (now - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"), "valid_until": None,
    }
    monkeypatch.setenv("AWEB_HOOK_PRODUCER_KID", entry["kid"])
    monkeypatch.setenv("AWEB_HOOK_PRODUCER_KEY_FILE", str(path))
    monkeypatch.setenv("AWEB_HOOK_PRODUCER_KEYS", json.dumps([entry]))
    return key, path, entry


def test_only_the_configured_file_key_is_loaded(configured):
    key, _, entry = configured
    hooks = load_core_hooks("https://core.example")
    assert hooks.producer.producer.did_key == entry["did_key"]
    assert hooks.producer.producer.kind == "core"
    assert bytes(key).hex() not in repr(hooks)


@pytest.mark.parametrize("mode", [0o620, 0o602])
def test_writable_key_is_refused(configured, mode):
    _, path, _ = configured
    path.chmod(mode)
    with pytest.raises(SigningKeyError):
        load_core_hooks("https://core.example")


@pytest.mark.parametrize("kind", ["directory", "fifo"])
def test_nonregular_key_is_refused(configured, kind):
    _, path, _ = configured
    path.unlink()
    if kind == "directory":
        path.mkdir()
    else:
        os.mkfifo(path)
    with pytest.raises(SigningKeyError):
        load_core_hooks("https://core.example")


def test_an_unpublished_kid_is_refused(configured, monkeypatch):
    monkeypatch.setenv("AWEB_HOOK_PRODUCER_KID", "another-kid")
    with pytest.raises(ValueError):
        load_core_hooks("https://core.example")


def test_a_different_file_key_is_refused(configured):
    _, path, _ = configured
    path.write_text(bytes(SigningKey.generate()).hex())
    with pytest.raises(ValueError):
        load_core_hooks("https://core.example")


@pytest.mark.parametrize("window", ["future", "expired"])
def test_inactive_key_window_is_refused(configured, monkeypatch, window):
    _, _, entry = configured
    now = datetime.now(UTC)
    if window == "future":
        entry["valid_from"] = (now + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    else:
        entry["valid_until"] = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    monkeypatch.setenv("AWEB_HOOK_PRODUCER_KEYS", json.dumps([entry]))
    with pytest.raises(RuntimeError):
        load_core_hooks("https://core.example")


@pytest.mark.parametrize("missing", ["AWEB_HOOK_PRODUCER_KID", "AWEB_HOOK_PRODUCER_KEY_FILE"])
def test_partial_configuration_is_refused(configured, monkeypatch, missing):
    monkeypatch.delenv(missing)
    with pytest.raises(ValueError):
        load_core_hooks("https://core.example")


def test_public_key_history_does_not_enable_signing(configured, monkeypatch):
    monkeypatch.delenv("AWEB_HOOK_PRODUCER_KID")
    monkeypatch.delenv("AWEB_HOOK_PRODUCER_KEY_FILE")
    assert load_core_hooks("https://core.example") is None


def test_hook_signing_requires_the_servers_https_origin(configured):
    with pytest.raises(ValueError):
        load_core_hooks("http://core.example")
