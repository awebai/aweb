"""The production AWID fixture starts only from an environment prepared before the
tests run (make production-awid-sync); it never builds one itself."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from aweb_naapp_testing import production_registry
from aweb_naapp_testing.production_registry import running_production_registry

PINNED = Path(production_registry.__file__).resolve().parents[4] / (
    "scripts/test-egress/production-awid"
)


async def test_an_unprepared_production_awid_is_refused_without_syncing_it(tmp_path, monkeypatch):
    project = tmp_path / "production-awid"
    project.mkdir()
    for name in ("pyproject.toml", "uv.lock"):
        shutil.copy(PINNED / name, project / name)
    monkeypatch.setenv("PRODUCTION_AWID_PROJECT", str(project))

    with pytest.raises(RuntimeError, match="make production-awid-sync"):
        async with running_production_registry("postgresql://unused.invalid/none"):
            pass

    assert not (project / ".venv").exists()
