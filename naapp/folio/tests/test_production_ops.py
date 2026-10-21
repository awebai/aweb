from __future__ import annotations

import re
from pathlib import Path

import pytest
from aweb_naapp.ops.render import ProductionConfig

_FOLIO_ROOT = Path(__file__).resolve().parents[1]
_REPO_ROOT = _FOLIO_ROOT.parents[1]
_MANIFEST = _FOLIO_ROOT / "ops" / "render-production.json"


def _config() -> ProductionConfig:
    return ProductionConfig.load(_MANIFEST)


def test_the_production_manifest_is_valid_and_builds_folio_from_the_repository_root() -> None:
    config = _config()

    assert config.root_dir == ""
    assert config.docker_context == "."
    assert (_REPO_ROOT / config.dockerfile_path).resolve() == _FOLIO_ROOT / "Dockerfile"


def test_the_render_template_builds_the_way_the_manifest_does() -> None:
    config = _config()
    template = (_FOLIO_ROOT / "render.yaml").read_text(encoding="utf-8")

    def value(key: str) -> str:
        match = re.search(rf"^\s+{key}:\s*(\S*)\s*$", template, re.MULTILINE)
        assert match, f"render.yaml has no {key}"
        return match.group(1).strip("'\"")

    assert value("dockerfilePath") == config.dockerfile_path
    assert value("dockerContext") == config.docker_context
    assert value("rootDir") == config.root_dir
    assert value("healthCheckPath") == config.health_path


_MAKEFILE = (_FOLIO_ROOT / "Makefile").read_text(encoding="utf-8")


@pytest.mark.parametrize("command", ["status", "deploy", "wait", "verify", "rollback"])
def test_each_production_operation_is_a_make_target_running_the_shared_tool(command: str) -> None:
    recipe = re.search(rf"^prod-{command}:\n((?:\t.*\n)+)", _MAKEFILE, re.MULTILINE)
    assert recipe, f"Makefile has no prod-{command} target"
    assert re.search(
        rf"uv run python -m aweb_naapp\.ops --config \$\(PROD_CONFIG\) {command}\b", recipe.group(1)
    ), recipe.group(1)
