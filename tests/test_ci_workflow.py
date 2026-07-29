from __future__ import annotations

import tomllib
from pathlib import Path

import pytest
import yaml

_REPO_ROOT = Path(__file__).parents[1]


def _workflow() -> dict:
    path = _REPO_ROOT / ".github" / "workflows" / "ci.yml"
    assert path.is_file(), "Library has no pull-request CI workflow"
    loaded = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert isinstance(loaded, dict)
    return loaded


def test_pytest_uses_locked_dependencies_and_rejects_warnings() -> None:
    pyproject = tomllib.loads((_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    pytest_options = pyproject["tool"]["pytest"]["ini_options"]

    assert pytest_options["pythonpath"] == [".", "src"]
    assert pytest_options["filterwarnings"] == ["error"]
    assert pytest_options["addopts"] == ["--basetemp=.pytest_tmp"]
    assert any(dependency.startswith("httpx2") for dependency in pyproject["dependency-groups"]["dev"])


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


def test_ci_break_glass_requires_visible_protection_restoration() -> None:
    readme = (_REPO_ROOT / "README.md").read_text(encoding="utf-8")

    assert "Lint, test, and real-stack e2e" in readme
    assert "temporarily disable" in readme
    assert "re-enable" in readme


_POLICY_SEMANTIC_GROUPS = (
    "the protected gate plus an independent exact-head review is sufficient integration authority",
    "a separate coordinator merge is not required",
    "This policy applies only while all of these conditions hold",
    "the head being merged exactly matches the independently reviewed head",
    "up to date with `main`",
    "change to `main` triggers re-evaluation",
    "the required context remains `Lint, test, and real-stack e2e`",
    "GitHub Actions app with ID `15368`",
    "protection is enforced for administrators, with no bypass",
    "the push to `main` runs the same required check against the integrated commit",
    "push-main run 30437187502",
    "5137334ae2b88c7515c6c080c427fafaf1e71faa",
    "the reviewed head changes",
    "protection is weakened",
    "the required context or app changes",
    "a conflict or manual recombination changes the reviewed result",
    "the change spans repositories",
    "a release tag is being chosen",
    "the deployment boundary moves",
    "fresh review and coordinator routing",
    "authorizes source integration only",
    "does not by itself authorize a release, production mutation, or deployment",
)
_REVISIT_SEMANTIC_GROUPS = (
    "through Jules",
    "only when aweb itself has a protected, green hosted canonical merge-state gate",
    "tracked by `aweb-aatq`",
)


def _assert_gate_policy_contract(readme: str) -> None:
    readme = " ".join(readme.split())
    policy = readme.index("### Gate-authorized integration")
    break_glass = readme.index("The break-glass path")
    revisit = readme.index("Re-evaluate whether this repository-specific policy")
    production = readme.index("## Production operations")

    assert policy < break_glass < revisit < production
    policy_block = readme[policy:break_glass]
    revisit_block = readme[revisit:production]
    for semantic_group in _POLICY_SEMANTIC_GROUPS:
        assert semantic_group in policy_block
    for semantic_group in _REVISIT_SEMANTIC_GROUPS:
        assert semantic_group in revisit_block


def test_ci_documents_when_the_gate_is_integration_authority() -> None:
    readme = (_REPO_ROOT / "README.md").read_text(encoding="utf-8")

    _assert_gate_policy_contract(readme)


@pytest.mark.parametrize("semantic_group", _POLICY_SEMANTIC_GROUPS + _REVISIT_SEMANTIC_GROUPS)
def test_ci_gate_policy_contract_rejects_semantic_weakening(semantic_group: str) -> None:
    readme = " ".join((_REPO_ROOT / "README.md").read_text(encoding="utf-8").split())
    assert semantic_group in readme

    with pytest.raises(AssertionError):
        _assert_gate_policy_contract(readme.replace(semantic_group, "", 1))


def test_ci_runs_every_make_gate_on_push_and_pull_request() -> None:
    workflow = _workflow()

    assert {"push", "pull_request"}.issubset(workflow["on"])
    steps = [step for job in workflow["jobs"].values() for step in job["steps"]]
    commands = "\n".join(step.get("run", "") for step in steps)
    for target in ("lint", "aatk-spec-check", "test", "e2e"):
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
