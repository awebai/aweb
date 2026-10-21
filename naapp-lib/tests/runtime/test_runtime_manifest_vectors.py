"""The runtime reads its served manifest as the shared manifest vectors pin."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic_settings import SettingsConfigDict

from aweb_naapp.manifest import ManifestError
from aweb_naapp.runtime.app import NaappRuntime
from aweb_naapp.runtime.settings import NaappSettings

from ..test_manifest_v2_vectors import V2, _manifest_bytes

# Valid manifests whose tool routes overlap: the runtime refuses them, because
# each request must authorize as exactly one tool.
OVERLAPPING_ROUTES = {"agent_catch_all_other_method_allowed", "surface_tool_on_answer_route_allowed"}


class ExampleSettings(NaappSettings):
    model_config = SettingsConfigDict(env_prefix="EXAMPLE_")

    database_url: str = "postgresql://localhost/unused"
    app_id: str = "fixture"


def _runtime(tmp_path: Path, data: bytes) -> NaappRuntime:
    manifest_path = tmp_path / "aweb-app.json"
    manifest_path.write_bytes(data)
    origin = json.loads(data).get("app", {}).get("origin") or "https://fixture.example"
    migrations = tmp_path / "migrations"
    migrations.mkdir()
    return NaappRuntime(
        ExampleSettings(_env_file=None, public_origin=origin),
        module_name="fixture",
        migrations_path=migrations,
        manifest_path=manifest_path,
    )


def _origin_is_a_string(data: bytes) -> bool:
    try:
        return isinstance(json.loads(data)["app"]["origin"], str)
    except (ValueError, KeyError, TypeError):
        return False


@pytest.mark.parametrize("case", V2["cases"], ids=lambda c: c["name"])
def test_the_runtime_reads_each_vector_manifest_as_the_shared_reader_does(
    tmp_path: Path, case: dict[str, Any]
) -> None:
    data = _manifest_bytes(case)
    expected = case["expected"]
    if not _origin_is_a_string(data):
        pytest.skip("the runtime needs the manifest's origin to choose the bytes it serves")
    if not expected["accepted"]:
        with pytest.raises(ManifestError) as refused:
            _runtime(tmp_path, data)
        assert refused.value.code == expected["error"]
        return
    if case["name"] in OVERLAPPING_ROUTES:
        with pytest.raises(ValueError, match="match the same requests"):
            _runtime(tmp_path, data)
        return
    runtime = _runtime(tmp_path, data)
    resolved = expected["resolved"]
    for context in ("agent", "surface", "hook"):
        declared = sorted(tool.name for tool in runtime.declared_tools if context in tool.contexts)
        assert declared == sorted(resolved[f"{context}_tools"]), context
    assert runtime.manifest.view() == resolved
