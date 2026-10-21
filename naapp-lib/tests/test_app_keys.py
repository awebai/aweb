from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Any

import pytest
from awid.did import did_from_public_key
from nacl.signing import SigningKey
from pydantic_settings import SettingsConfigDict

from aweb_naapp.runtime.app_keys import APP_EVENT, AppKeyError, load_app_key
from aweb_naapp.runtime.settings import NaappSettings

_KID = "example:emit-1"


class ExampleSettings(NaappSettings):
    model_config = SettingsConfigDict(env_prefix="EXAMPLE_")

    database_url: str = "postgresql://localhost/example"
    public_origin: str = "https://example.test"
    app_id: str = "example"


@pytest.fixture(autouse=True)
def _clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in list(os.environ):
        if name.startswith("EXAMPLE_"):
            monkeypatch.delenv(name)


def _did_key(seed_hex: str) -> str:
    return did_from_public_key(bytes(SigningKey(bytes.fromhex(seed_hex)).verify_key))


def _manifest(**emitters: str) -> dict[str, Any]:
    return {
        "manifest_version": 1,
        "app": {"id": "example", "origin": "https://example.test"},
        "tools": [],
        "event_emitters": [{"kid": kid, "did_key": did} for kid, did in emitters.items()],
    }


def _key_file(tmp_path: Path, seed_hex: str, *, name: str = "app.key", mode: int = 0o600) -> Path:
    path = tmp_path / name
    path.write_text(seed_hex + "\n", encoding="utf-8")
    path.chmod(mode)
    return path


def _settings(**values: object) -> ExampleSettings:
    return ExampleSettings(_env_file=None, **values)


def test_a_declared_kid_loads_from_its_key_file(tmp_path: Path) -> None:
    seed = secrets.token_hex(32)
    settings = _settings(app_key_files={_KID: _key_file(tmp_path, seed)})
    key = load_app_key(settings, _manifest(**{_KID: _did_key(seed)}), APP_EVENT)
    assert (key.kid, key.did_key) == (_KID, _did_key(seed))
    assert bytes(key.signing_key) == bytes.fromhex(seed)


def test_key_files_are_read_from_the_app_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seed = secrets.token_hex(32)
    monkeypatch.setenv("EXAMPLE_APP_KEY_FILES", f'{{"{_KID}": "{_key_file(tmp_path, seed)}"}}')
    key = load_app_key(_settings(), _manifest(**{_KID: _did_key(seed)}), APP_EVENT)
    assert key.did_key == _did_key(seed)


def test_a_key_file_the_loader_refuses_refuses_the_app_key(tmp_path: Path) -> None:
    seed = secrets.token_hex(32)
    path = _key_file(tmp_path, seed, mode=0o666)
    settings = _settings(app_key_files={_KID: path})
    with pytest.raises(AppKeyError, match=_KID):
        load_app_key(settings, _manifest(**{_KID: _did_key(seed)}), APP_EVENT)


def test_a_key_that_is_not_the_declared_public_key_is_refused(tmp_path: Path) -> None:
    seed = secrets.token_hex(32)
    settings = _settings(app_key_files={_KID: _key_file(tmp_path, seed)})
    with pytest.raises(AppKeyError, match=_KID):
        load_app_key(settings, _manifest(**{_KID: _did_key(secrets.token_hex(32))}), APP_EVENT)


def test_a_configured_kid_the_manifest_does_not_declare_is_not_used(tmp_path: Path) -> None:
    seed = secrets.token_hex(32)
    settings = _settings(app_key_files={"example:other": _key_file(tmp_path, seed)})
    with pytest.raises(AppKeyError, match=APP_EVENT):
        load_app_key(settings, _manifest(**{_KID: _did_key(seed)}), APP_EVENT)


def test_several_declared_and_configured_kids_need_the_emit_kid_to_choose(tmp_path: Path) -> None:
    first, second = secrets.token_hex(32), secrets.token_hex(32)
    files = {
        _KID: _key_file(tmp_path, first, name="first.key"),
        "example:emit-2": _key_file(tmp_path, second, name="second.key"),
    }
    manifest = _manifest(**{_KID: _did_key(first), "example:emit-2": _did_key(second)})
    with pytest.raises(AppKeyError, match="APP_EMIT_KID"):
        load_app_key(_settings(app_key_files=files), manifest, APP_EVENT)
    chosen = load_app_key(
        _settings(app_key_files=files, app_emit_kid="example:emit-2"), manifest, APP_EVENT
    )
    assert chosen.did_key == _did_key(second)


def test_the_emit_kid_must_be_declared(tmp_path: Path) -> None:
    seed = secrets.token_hex(32)
    settings = _settings(
        app_emit_kid="example:undeclared", app_key_files={_KID: _key_file(tmp_path, seed)}
    )
    with pytest.raises(AppKeyError, match="example:undeclared"):
        load_app_key(settings, _manifest(**{_KID: _did_key(seed)}), APP_EVENT)


def test_the_released_seed_value_loads_the_app_event_key() -> None:
    seed = secrets.token_hex(32)
    settings = _settings(app_emit_kid=_KID, app_emit_key_seed_hex=seed)
    key = load_app_key(settings, _manifest(**{_KID: _did_key(seed)}), APP_EVENT)
    assert (key.kid, key.did_key) == (_KID, _did_key(seed))


def test_the_released_seed_value_is_read_from_the_app_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seed = secrets.token_hex(32)
    monkeypatch.setenv("EXAMPLE_APP_EMIT_KID", _KID)
    monkeypatch.setenv("EXAMPLE_APP_EMIT_KEY_SEED_HEX", seed)
    key = load_app_key(_settings(), _manifest(**{_KID: _did_key(seed)}), APP_EVENT)
    assert key.did_key == _did_key(seed)


def test_the_released_seed_value_needs_its_kid() -> None:
    seed = secrets.token_hex(32)
    settings = _settings(app_emit_key_seed_hex=seed)
    with pytest.raises(AppKeyError, match="APP_EMIT_KID"):
        load_app_key(settings, _manifest(**{_KID: _did_key(seed)}), APP_EVENT)


def test_the_released_seed_value_signs_no_other_purpose() -> None:
    seed = secrets.token_hex(32)
    settings = _settings(app_emit_kid=_KID, app_emit_key_seed_hex=seed)
    with pytest.raises(AppKeyError, match="hook-resolve"):
        load_app_key(settings, _manifest(**{_KID: _did_key(seed)}), "hook-resolve")


def test_a_kid_given_both_a_file_and_the_seed_value_is_refused(tmp_path: Path) -> None:
    seed = secrets.token_hex(32)
    settings = _settings(
        app_emit_kid=_KID,
        app_emit_key_seed_hex=seed,
        app_key_files={_KID: _key_file(tmp_path, seed)},
    )
    with pytest.raises(AppKeyError, match=_KID):
        load_app_key(settings, _manifest(**{_KID: _did_key(seed)}), APP_EVENT)


def test_a_malformed_released_seed_value_is_refused_without_echoing_it() -> None:
    seed = secrets.token_hex(32)
    settings = _settings(app_emit_kid=_KID, app_emit_key_seed_hex=seed[:40] + " " + seed[40:])
    with pytest.raises(AppKeyError) as refused:
        load_app_key(settings, _manifest(**{_KID: _did_key(seed)}), APP_EVENT)
    assert seed[:40] not in str(refused.value)
    assert seed[40:] not in str(refused.value)


def test_key_material_appears_in_no_repr_or_settings_dump() -> None:
    seed = secrets.token_hex(32)
    settings = _settings(app_emit_kid=_KID, app_emit_key_seed_hex=seed)
    key = load_app_key(settings, _manifest(**{_KID: _did_key(seed)}), APP_EVENT)
    for rendered in (
        repr(key),
        str(key),
        repr(settings),
        str(settings),
        str(settings.model_dump()),
        settings.model_dump_json(),
    ):
        assert seed not in rendered
        assert seed.upper() not in rendered
        assert str(bytes.fromhex(seed)) not in rendered
    assert _KID in repr(key)
