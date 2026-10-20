from __future__ import annotations

from pathlib import Path

import pytest
from test_e2e_smoke import AWID_URL, aw_workspace_env

_CALLER_AW_SETTINGS = (
    "AWEB_IDENTITY_HOME",
    "AW_HOME",
    "AWEB_ALIAS",
    "AWEB_ROLE",
    "AWEB_ROLE_NAME",
    "AWEB_HUMAN",
    "AWEB_HUMAN_NAME",
    "AWEB_AGENT_TYPE",
    "AWEB_DELIVERY",
    "AW_CONFIG",
)


def _aw_settings(env: dict[str, str]) -> dict[str, str]:
    return {k: v for k, v in env.items() if k.startswith(("AWEB_", "AW_"))}


def test_disposable_aw_workspace_carries_only_the_aw_settings_the_test_sets(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Run from an agent session, the caller's own identity, alias, role or config
    # would otherwise reach every disposable `aw` command.
    for name in _CALLER_AW_SETTINGS:
        monkeypatch.setenv(name, "caller")
    monkeypatch.setenv("AWEB_URL", "http://caller.invalid")

    env = aw_workspace_env(home=tmp_path / "home")

    assert _aw_settings(env) == {"AWEB_URL": "http://127.0.0.1:1"}
    assert env["AWID_REGISTRY_URL"] == AWID_URL
    assert env["HOME"] == str(tmp_path / "home")
