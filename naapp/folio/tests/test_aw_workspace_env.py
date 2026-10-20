from __future__ import annotations

from pathlib import Path

import pytest
from test_e2e_smoke import aw_workspace_env


@pytest.mark.parametrize("name", ["AWEB_IDENTITY_HOME", "AW_HOME"])
def test_disposable_aw_workspace_does_not_inherit_the_callers_aw_selection(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, name: str
) -> None:
    # Run from an agent session, the caller's own identity or config would otherwise
    # be the one every disposable `aw` command resolves to.
    monkeypatch.setenv(name, str(tmp_path / "caller"))

    env = aw_workspace_env(home=tmp_path / "home")

    assert name not in env
    assert env["HOME"] == str(tmp_path / "home")
