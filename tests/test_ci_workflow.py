from __future__ import annotations

import tomllib
from pathlib import Path

import yaml

_REPO_ROOT = Path(__file__).parents[1]


def _workflow() -> dict:
    path = _REPO_ROOT / ".github" / "workflows" / "ci.yml"
    assert path.is_file(), "Library has no pull-request CI workflow"
    loaded = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert isinstance(loaded, dict)
    return loaded


def test_pytest_imports_checked_in_operational_modules_without_shell_state() -> None:
    pyproject = tomllib.loads((_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert "." in pyproject["tool"]["pytest"]["ini_options"]["pythonpath"]


def test_make_test_uses_the_locked_uv_environment() -> None:
    makefile = (_REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    test_recipe = makefile.split("test:\n", 1)[1].split("\n\n", 1)[0]

    assert "uv run pytest" in test_recipe
    assert "python3 -m pytest" not in test_recipe


def test_ci_provides_postgres_so_database_tests_cannot_skip() -> None:
    workflow = _workflow()

    assert any("postgres" in job.get("services", {}) for job in workflow["jobs"].values())
    commands = "\n".join(
        step.get("run", "")
        for job in workflow["jobs"].values()
        for step in job["steps"]
    )
    assert "systemctl restart docker" not in commands


def test_ci_runs_every_make_gate_on_push_and_pull_request() -> None:
    workflow = _workflow()

    assert {"push", "pull_request"}.issubset(workflow["on"])
    steps = [step for job in workflow["jobs"].values() for step in job["steps"]]
    commands = "\n".join(step.get("run", "") for step in steps)
    for target in ("lint", "test", "e2e"):
        assert f"make {target}" in commands


def test_ci_pins_the_released_aw_client_used_by_e2e() -> None:
    workflow = _workflow()
    steps = [step for job in workflow["jobs"].values() for step in job["steps"]]
    commands = "\n".join(step.get("run", "") for step in steps)

    assert workflow["env"]["AW_VERSION"]
    assert workflow["env"]["LIBRARY_REQUIRE_TEST_DATABASE"] == "1"
    assert '@awebai/aw@$AW_VERSION' in commands
    assert "aw version" in commands


def test_ci_supplies_the_e2e_aweb_source_as_a_sibling_checkout() -> None:
    workflow = _workflow()
    steps = [step for job in workflow["jobs"].values() for step in job["steps"]]
    checkouts = [step for step in steps if step.get("uses", "").startswith("actions/checkout@")]

    assert any(step.get("with", {}).get("path") == "library" for step in checkouts)
    assert any(
        step.get("with", {}).get("repository") == "awebai/aweb"
        and step.get("with", {}).get("path") == "aweb"
        and step.get("with", {}).get("ref")
        for step in checkouts
    )
