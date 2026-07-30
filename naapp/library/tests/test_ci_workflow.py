from __future__ import annotations

import tomllib
from pathlib import Path

import pytest
import yaml

_REPO_ROOT = Path(__file__).parents[1]
_AWEB_ROOT = Path(__file__).parents[3]


def _workflow() -> dict:
    # Library's CI lives at the AWEB repository root, not at Library's own root.
    # GitHub Actions reads .github/workflows only at the root of the repository
    # it is running in, so after the subtree move a workflow under
    # naapp/library/.github/workflows never runs at all. Asserting against a
    # file in that location would guard a workflow that cannot fire - the exact
    # shape this programme keeps finding.
    path = _AWEB_ROOT / ".github" / "workflows" / "library-ci.yml"
    assert path.is_file(), "Library has no pull-request CI workflow at the aweb root"
    loaded = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert isinstance(loaded, dict)
    return loaded


def test_library_has_no_buried_workflow_that_cannot_run() -> None:
    """A workflow below the repository root is dead config that reads as live.

    It is not merely inert: a reader who finds it believes Library is covered,
    which is how the coverage gap survived the move.
    """
    buried = _REPO_ROOT / ".github" / "workflows"
    assert not buried.exists(), (
        f"{buried} cannot be reached by GitHub Actions - Library's CI belongs at the aweb root"
    )


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


def test_ci_builds_the_e2e_stack_from_the_commit_under_test() -> None:
    """The e2e must build awid from THIS checkout, never from a pinned copy.

    Before the subtree move Library was its own repository, so a pinned
    external aweb was the only way to get awid and pinning it was correct.
    Now aweb is the repository being tested, and a pinned copy would mean a
    pull request that changes awid/ gets a green Library e2e built against
    some other awid. Measured cost of exactly that mistake elsewhere in this
    repo: ship.yml pins awebai/library at a rev missing 13 files and differing
    in 22 more, so its 'comprehensive' e2e builds a Library with no AATK in it.
    """
    workflow = _workflow()
    steps = [step for job in workflow["jobs"].values() for step in job["steps"]]
    checkouts = [step for step in steps if step.get("uses", "").startswith("actions/checkout@")]

    foreign = [
        step for step in checkouts
        if (step.get("with") or {}).get("repository") not in (None, "", "${{ github.repository }}")
    ]
    assert not foreign, (
        "the e2e stack must be built from the commit under test; "
        f"found external checkout(s): {[s.get('with', {}).get('repository') for s in foreign]}"
    )

    # docker-compose.e2e.yml defaults this to ../aweb, a sibling-checkout path
    # that resolves to naapp/aweb from here and does not exist. It has to be
    # set explicitly, and it has to point at the checkout root.
    contexts = [
        (step.get("env") or {}).get("LIBRARY_E2E_AWEB_CONTEXT")
        for step in steps
        if (step.get("env") or {}).get("LIBRARY_E2E_AWEB_CONTEXT")
    ]
    assert contexts, "the e2e step must set LIBRARY_E2E_AWEB_CONTEXT"
    assert all("github.workspace" in context for context in contexts), contexts


def test_ci_also_covers_naapp_lib() -> None:
    """naapp-lib is a dependency of both movers and had no CI before the move.

    Guarded here rather than in naapp-lib's own suite for two reasons: both jobs
    live in this one workflow file, so a single guard over that file is the right
    granularity; and naapp-lib's dev dependencies are pytest, ruff and mypy with
    no yaml, so asserting there would mean adding a dependency and touching its
    lockfile for one test. The coupling is deliberate and stated - if naapp-lib
    is ever extracted, this assertion moves with its job.
    """
    workflow = _workflow()
    jobs = workflow["jobs"]
    assert "naapp-lib" in jobs, (
        "naapp-lib had no CI before the subtree move; leaving it uncovered in a "
        "repo that has CI is aweb-aavw criterion 5's recorded decision, and that "
        "decision was to cover it"
    )
    steps = jobs["naapp-lib"]["steps"]
    commands = "\n".join(step.get("run", "") for step in steps)
    assert "uv sync --locked" in commands
    assert "uv run pytest" in commands
    assert "uv run ruff check" in commands
    assert "uv run mypy" in commands
    # Every run step must NAME naapp-lib. Allowing None here would have let the
    # field be deleted entirely and still pass - caught by mutation, not review:
    # removing `working-directory` ran the steps at the repository root against
    # aweb's own pyproject, and the permissive form stayed green. Keying on
    # "naapp-lib or absent" instead of "naapp-lib" is the same defect charlie
    # measured in folio's guard, which keys on a spelling rather than a property.
    for step in steps:
        if step.get("run"):
            assert step.get("working-directory") == "naapp-lib", step


def test_ci_runs_library_targets_from_the_subtree_path() -> None:
    """make runs in naapp/library, not at the aweb root, or it runs aweb's Makefile.

    Scoped to the library job on purpose. Iterating every job would force any
    future job that legitimately runs make elsewhere into naapp/library, which
    is an assertion about jobs this test knows nothing about.

    The command test is on the first token rather than `"make " in run`: that
    substring also matches "cmake --build". Only over-constraining, and there is
    no cmake here, but a containment test keyed on a command name is the shape
    that has cost this repo repeatedly - a denylist matching by spelling instead
    of by position is the same defect measured in folio's Makefile guard.
    """
    steps = _workflow()["jobs"]["quality"]["steps"]
    for step in steps:
        commands = step.get("run", "").splitlines()
        if any(line.split()[:1] == ["make"] for line in commands if line.split()):
            assert step.get("working-directory") == "naapp/library", step
