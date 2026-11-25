#!/usr/bin/env python3
"""Exercise the real Docker gate and RC with small Git, SQL, image and Redis stages."""

from __future__ import annotations

import errno
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest

from collections.abc import Callable
from contextlib import contextmanager
from pathlib import Path

from fixture_repo import init_fixture_repo, run_fixture


@contextmanager
def held_library_default():
    with socket.socket() as held:
        try:
            held.bind(("127.0.0.1", 55432))
            held.listen()
        except OSError as error:
            if error.errno != errno.EADDRINUSE:
                raise
        yield


ROOT = Path(__file__).resolve().parents[1]
STAGES = "static checks user-paths unit artifacts integration"
# The targets the fixture gives real recipes: the stage assertions below
# use real tools and services, never a replacement runner.
REAL_RECIPES = frozenset(
    {
        "test-shipping",
        "_candidate-node-deps",
        "build",
        "_candidate-unit-suites",
        "test-server",
        "_candidate-artifact-server",
        "freshness",
        "e2e-naapp",
        "cli-e2e",
    }
)


def source_checks() -> list[str]:
    """Every other product target the candidate suite runs, read from the suite
    itself. The fixture stubs each one to check its committed source, so a
    target a stage adds is stubbed here without anyone editing this list."""
    suite = (ROOT / "scripts" / "candidate-suite.sh").read_text(encoding="utf-8")
    targets = re.findall(r"^\s*run ([A-Za-z0-9_.-]+)\s*$", suite, flags=re.MULTILINE)
    return [target for target in dict.fromkeys(targets) if target not in REAL_RECIPES]


SOURCE_CHECKS = source_checks()


class CompleteGateVerdictTests(unittest.TestCase):
    def suite(self, selection: str, *failures: str):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "host-published-port.log").write_text("host preflight\n")
            for name, command in {
                "make": 'case " $FAILURES " in *" $1 "*) exit 23;; esac\n',
                "docker": "exit 0\n",
            }.items():
                tool = root / name
                tool.write_text("#!/bin/sh\n" + command)
                tool.chmod(0o700)
            env = dict(
                os.environ,
                PATH=f"{root}{os.pathsep}{os.environ['PATH']}",
                FAILURES=" ".join(failures),
                CANDIDATE_LOG_DIR=str(root),
                BUILDX_BUILDER="fixture-only",
            )
            if "host-published-port" in failures:
                env["CANDIDATE_HOST_PORT_STATUS"] = "7"
            else:
                env.pop("CANDIDATE_HOST_PORT_STATUS", None)
            result = run(ROOT, "bash", "scripts/candidate-suite.sh", selection, env=env)
            summary = root / "summary.tsv"
            rows = {}
            if summary.exists():
                rows = dict(
                    line.split("\t")[:2] for line in summary.read_text().splitlines()
                )
            return result, rows

    def test_every_stage_and_independent_target_reports_after_failures(self):
        result, rows = self.suite(
            STAGES,
            "check-product-table-writes",
            "e2e-user-paths",
            "_candidate-node-deps",
            "build",
            "_candidate-artifact-server",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(rows.get("static"), "PASSED", result.stdout)
        for stage in STAGES.split()[1:]:
            self.assertEqual(rows.get(stage), "FAILED", result.stdout)
        self.assertEqual(rows["checks/check-product-table-writes"], "FAILED")
        self.assertEqual(rows["checks/check-go-vulnerability-audit"], "PASSED")
        self.assertEqual(rows["unit/_candidate-unit-suites"], "PASSED")
        self.assertEqual(rows["artifacts/_candidate-artifact-a2a-image"], "PASSED")
        self.assertEqual(rows["integration/e2e-naapp"], "SKIPPED")
        self.assertEqual(rows["integration/e2e-folio-wakes"], "PASSED")
        self.assertEqual(rows["integration/test-oci-exact-publish"], "PASSED")
        self.assertIn("e2e-naapp SKIPPED", result.stdout)
        self.assertIn("build FAILED", result.stdout)

    def test_host_probe_failure_is_reported_inside_checks(self):
        result, rows = self.suite("checks user-paths", "host-published-port")
        self.assertEqual(result.returncode, 7)
        self.assertEqual(rows["checks/host-published-port"], "FAILED")
        self.assertEqual(rows["checks/check-go-vulnerability-audit"], "PASSED")
        self.assertEqual(rows["checks"], "FAILED")
        self.assertEqual(rows["user-paths"], "PASSED")

    def test_isolated_unit_keeps_every_leaf_after_server_failure(self):
        result, rows = self.suite("--isolated-suites", "test-server", "test-cli")
        self.assertNotEqual(result.returncode, 0)
        failed = {leaf for leaf, verdict in rows.items() if verdict == "FAILED"}
        self.assertEqual(failed, {"unit/test-server", "unit/test-cli"})
        self.assertEqual(set(rows.values()), {"FAILED", "PASSED"})
        self.assertEqual(rows["unit/_candidate-unit-pi"], "PASSED")


def run(root: Path, *args: str, env: dict[str, str] | None = None):
    # This fixture pins its own versions. A caller's make command-line values
    # otherwise override them in the nested make, but not in the direct gate.
    environment = dict(os.environ if env is None else env)
    for name in ("MAKEFLAGS", "MAKELEVEL", "MAKEOVERRIDES", "MFLAGS"):
        environment.pop(name, None)
    return run_fixture(
        args, cwd=root, env=environment, text=True, capture_output=True, timeout=900
    )


def checked(root: Path, *args: str):
    result = run(root, *args)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout.strip()


def stage_rows(rows: list[str]) -> list[list[str]]:
    fields = [row.split("\t") for row in rows]
    return [row for row in fields if "/" not in row[1]]


def verify_same_tree_commit_cache(
    *,
    repo: Path,
    ledger: Path,
    run_fixed_baseline_gate: Callable[[], str],
    run_full_gate: Callable[[], str],
    run_reviewed_change_gate: Callable[[], str],
) -> list[str]:
    """Same-tree reuse follows main's reviewed ceilings, not main's commit."""
    previous_rows = ledger.read_text().splitlines()
    previous_main = checked(repo, "git", "rev-parse", "refs/remotes/origin/main")
    previous_tree = checked(repo, "git", "rev-parse", "HEAD^{tree}")
    checked(repo, "git", "commit", "--allow-empty", "-qm", "same tree new commit")
    assert checked(repo, "git", "rev-parse", "HEAD^{tree}") == previous_tree

    # Explicit all-stage selection uses the already synchronized baseline.
    assert "no stages run" in run_fixed_baseline_gate()
    assert (
        checked(repo, "git", "rev-parse", "refs/remotes/origin/main") == previous_main
    )
    assert ledger.read_text().splitlines() == previous_rows

    # The full entry synchronizes the fixture's advanced main. The reviewed
    # ceilings did not change, so the unchanged tree reuses its pass.
    assert "no stages run" in run_full_gate()
    current_main = checked(repo, "git", "rev-parse", "refs/remotes/origin/main")
    assert current_main != previous_main
    assert current_main == checked(repo, "git", "rev-parse", "HEAD")
    assert ledger.read_text().splitlines() == previous_rows

    # Main changes its reviewed ceilings while the candidate tree stays the
    # same: the product-table check has a different input, so every stage runs.
    candidate = checked(repo, "git", "rev-parse", "HEAD")
    checked(repo, "git", "checkout", "-q", "--detach")
    ceilings = repo / "tools/product-table-write-ceilings.json"
    ceilings.parent.mkdir(exist_ok=True)
    ceilings.write_text('{"schema_version":1,"nonliteral_files":{},"files":{}}\n')
    checked(repo, "git", "add", str(ceilings.relative_to(repo)))
    checked(repo, "git", "commit", "-qm", "reviewed ceilings on main")
    checked(
        repo,
        "git",
        "update-ref",
        "refs/remotes/origin/main",
        checked(repo, "git", "rev-parse", "HEAD"),
    )
    checked(repo, "git", "checkout", "-q", "--detach", candidate)
    assert checked(repo, "git", "rev-parse", "HEAD^{tree}") == previous_tree
    assert "no stages run" not in run_reviewed_change_gate()
    rows = ledger.read_text().splitlines()
    assert rows[: len(previous_rows)] == previous_rows
    fresh = stage_rows(rows[len(previous_rows) :])
    assert len(fresh) == len(STAGES.split())
    assert {row[1] for row in fresh} == set(STAGES.split())
    assert all(row[2] == "passed" for row in fresh)
    fresh_keys = {row[0] for row in fresh}
    assert len(fresh_keys) == 1
    assert fresh_keys.isdisjoint(row.split("\t")[0] for row in previous_rows)
    # Later callers synchronize main from the fixture's unchanged main branch.
    checked(repo, "git", "checkout", "-q", "main")
    assert checked(repo, "git", "rev-parse", "HEAD") == candidate
    return rows


def main() -> None:
    # Direct invocation needs the same immediate refusal as the make target.
    preflight = run(ROOT, "bash", "scripts/candidate-docker-gate.sh", "--check-disk")
    if preflight.returncode:
        raise SystemExit(preflight.stdout + preflight.stderr)
    evidence = Path(tempfile.mkdtemp(prefix="aweb-ledger-evidence.")).resolve()
    print(f"Ledger integration evidence: {evidence}", flush=True)
    with tempfile.TemporaryDirectory(prefix="aweb-ledger-proof.") as temporary:
        repo = Path(temporary)
        for name in (
            "candidate-docker-gate.sh",
            "candidate-suite.sh",
            "candidate-cleanup.sh",
            "candidate-record.sh",
            "candidate-host-pressure.py",
            "candidate-network.py",
            "fetch_released_aw.py",
            "next_tag_version.py",
            "product_table_writes.py",
            "release_candidate.py",
            "release_versions.py",
        ):
            destination = repo / "scripts" / name
            destination.parent.mkdir(exist_ok=True)
            shutil.copy2(ROOT / "scripts" / name, destination)
        (repo / "candidate-gate/bin").mkdir(parents=True)
        shutil.copy2(
            ROOT / "candidate-gate/bin/docker", repo / "candidate-gate/bin/docker"
        )
        (repo / "candidate-gate/Dockerfile").write_text(
            "FROM docker:27-cli\n"
            "RUN apk add --no-cache bash git make python3 postgresql-client redis "
            "&& ln -s /usr/local/bin/docker /usr/bin/docker\n"
        )
        (repo / "candidate-gate/proof.Dockerfile").write_text(
            'FROM busybox:1.37\nRUN test "$((6*7))" = 42\n'
        )
        (repo / "naapp/library/test-vectors/blueprints/team").mkdir(parents=True)
        (repo / "naapp/library/test-vectors/blueprints/team/proof").write_text(
            "fixture\n"
        )
        shutil.copy2(ROOT / "docker-compose.e2e.yml", repo / "docker-compose.e2e.yml")
        shutil.copytree(ROOT / "scripts/e2e/initdb", repo / "scripts/e2e/initdb")
        # The real wrapper's host preflight must execute the real probe from
        # this committed fixture checkout, just as it does for a candidate.
        shutil.copy2(
            ROOT / "scripts/e2e/test_candidate_gate_docker_boundaries.py",
            repo / "scripts/e2e/test_candidate_gate_docker_boundaries.py",
        )
        (repo / "server").mkdir()
        (repo / "server/pyproject.toml").write_text(
            '[project]\nname="ledger-proof"\nversion="1.2.3"\n'
        )
        recipes = f".PHONY: candidate-gate {' '.join(SOURCE_CHECKS)}\n{' '.join(SOURCE_CHECKS)}:\n\t@git diff --exit-code\n"
        recipes += """test-shipping:
\t@python3 -c 'assert 6 * 7 == 42'
_candidate-node-deps:
\t@echo node >> "$$CANDIDATE_LOG_DIR/setup.log"
build:
\t@echo cli >> "$$CANDIDATE_LOG_DIR/setup.log"
_candidate-unit-suites:
\t@test "$$(psql -h "$$TEST_DB_HOST" -U postgres -d postgres -Atc 'SELECT 6 * 7')" = 42
\t@mkdir -p "$$CANDIDATE_LOG_DIR/test-egress"
\t@CANDIDATE_LOG_DIR="$$CANDIDATE_LOG_DIR/test-egress" bash scripts/candidate-suite.sh --isolated-suites > "$$CANDIDATE_LOG_DIR/test-egress/suite.log" 2>&1
test-server:
\t@true
_candidate-artifact-server:
\t@docker build -f candidate-gate/proof.Dockerfile -t "$$AWEB_CANDIDATE_RESOURCE_LABEL-proof" candidate-gate
\t@docker run --rm "$$AWEB_CANDIDATE_RESOURCE_LABEL-proof" sh -c 'test "$$(echo 42)" = 42'
\t@test "$$(wc -l < "$$CANDIDATE_LOG_DIR/setup.log")" = 2
cli-e2e:
\t@set -eu; trap 'docker compose -p "$$LIBRARY_E2E_PROJECT" -f docker-compose.e2e.yml down -v --remove-orphans' EXIT; \
\t  docker compose -p "$$LIBRARY_E2E_PROJECT" -f docker-compose.e2e.yml up -d --wait postgres; \
\t  docker compose -p "$$LIBRARY_E2E_PROJECT" -f docker-compose.e2e.yml exec -T postgres pg_isready -U aweb
freshness:
\t@test "$$(redis-cli -u "$$REDIS_URL" PING)" = PONG
naapp-e2e-packages:
\t@printf '%s\\n' proof/first proof/second
e2e-naapp:
\t@python3 -c 'import os; rows=[row.split() for row in os.environ["NAAPP_E2E_ALLOCATIONS"].splitlines()]; assert [row[0] for row in rows] == ["proof/first", "proof/second"]; assert all(row[2:] == ["8010", "5432"] for row in rows); assert all(row[1].startswith("aweb-candidate-") and "-naapp-" in row[1] for row in rows); assert "AWEB_DOCKER_PUBLISHED_HOST" not in os.environ'
candidate-gate:
\tbash scripts/candidate-docker-gate.sh
"""
        (repo / "Makefile").write_text(recipes)
        init_fixture_repo(repo)
        checked(repo, "git", "config", "user.name", "gate integration")
        checked(repo, "git", "config", "user.email", "gate@example.test")
        checked(repo, "git", "add", ".")
        checked(repo, "git", "commit", "-qm", "small real gate stages")
        checked(repo, "git", "remote", "add", "origin", str(repo))
        checked(repo, "git", "fetch", "--quiet", "origin", "main")
        env = {
            key: value
            for key, value in os.environ.items()
            if key in {"AWEB_GATE_MIN_FREE_GB", "AWEB_GATE_RESERVE_GB"}
            or not key.startswith(
                ("AWEB_CANDIDATE_", "AWEB_GATE_", "CANDIDATE_", "GATE_", "LIBRARY_E2E_")
            )
        }
        env.update(
            AWEB_GATE_LEDGER=str(evidence / "ledger.tsv"),
            AWEB_GATE_LOG_DIR=str(evidence / "logs"),
            CLI_VERSION="1.2.3",
            A2A_GATEWAY_VERSION="1.2.3",
            AWEB_CANDIDATE_RUNNER_MEMORY="1g",
            AWEB_CANDIDATE_BUILDER_MEMORY="1g",
        )

        def invoke(
            name: str, *args: str, stages: str | None = None, success: bool = True
        ):
            settings = dict(env)
            if stages is not None:
                settings["AWEB_CANDIDATE_STAGES"] = stages
            result = run(repo, *args, env=settings)
            (evidence / f"{name}.log").write_text(result.stdout + result.stderr)
            assert (result.returncode == 0) == success, (
                f"{name}: see {evidence}/{name}.log"
            )
            return result.stdout + result.stderr

        gate = ("bash", "scripts/candidate-docker-gate.sh")
        ledger = evidence / "ledger.tsv"
        # Library builds from the candidate checkout itself; a separate Library
        # source is no longer an input, so naming one is refused, not ignored.
        env["LIBRARY_E2E_LIBRARY_CONTEXT"] = str(repo / "naapp/library")
        refused_library = invoke(
            "library-context", *gate, stages="checks", success=False
        )
        assert "LIBRARY_E2E_LIBRARY_CONTEXT" in refused_library and not ledger.exists()
        del env["LIBRARY_E2E_LIBRARY_CONTEXT"]
        invoke("first-checks", *gate, stages="checks")
        rows = ledger.read_text().splitlines()
        assert [row[1:3] for row in stage_rows(rows)] == [["checks", "passed"]]
        # Exercise the real gate allocation/runner environment and Library's
        # actual Compose Postgres service while its old host port is occupied.
        with held_library_default():
            invoke("missing-only", "make", "candidate-gate")
        rows = ledger.read_text().splitlines()
        assert {row[1] for row in stage_rows(rows)} == set(STAGES.split())
        assert all(row[2] == "passed" for row in stage_rows(rows))
        unit_target = [row.split("\t") for row in rows if "\tunit/test-server\t" in row]
        if len(unit_target) != 1 or unit_target[0][2] != "passed":
            raise AssertionError(
                f"missing passed isolated test-server row: {unit_target}"
            )
        if "candidate: test-server PASSED" not in Path(unit_target[0][5]).read_text():
            raise AssertionError(
                f"isolated test-server log missing evidence: {unit_target}"
            )
        assert "no stages run" in invoke("same-tree-direct", *gate)
        rows = verify_same_tree_commit_cache(
            repo=repo,
            ledger=ledger,
            run_fixed_baseline_gate=lambda: invoke(
                "same-tree-fixed-baseline", *gate, stages=STAGES
            ),
            run_full_gate=lambda: invoke("same-tree-commit", "make", "candidate-gate"),
            run_reviewed_change_gate=lambda: invoke(
                "reviewed-ceilings-change", *gate, stages=STAGES
            ),
        )
        # A release must require all stages despite an inherited focused selector.
        output = invoke(
            "final-reuse",
            sys.executable,
            "scripts/release_candidate.py",
            "aw-v1.2.3",
            stages="checks",
        )
        assert (
            "no stages run" in output
            and "checks user-paths unit artifacts integration" in output
        )
        assert checked(repo, "git", "rev-parse", "aw-v1.2.3^{commit}") == checked(
            repo, "git", "rev-parse", "HEAD"
        )
        assert ledger.read_text().splitlines() == rows
        # An effective version is an external input, even with an unchanged tree.
        env["CLI_VERSION"] = "1.2.4"
        invoke("version-input", *gate, stages="checks")
        version_rows = ledger.read_text().splitlines()
        assert (
            len(stage_rows(version_rows)) == len(stage_rows(rows)) + 1
            and version_rows[-1].split("\t")[0] != rows[-1].split("\t")[0]
        )
        env["CLI_VERSION"] = "1.2.3"
        (repo / "Makefile").write_text(recipes.replace("6 * 7 == 42", "7 * 6 == 42"))
        checked(repo, "git", "commit", "-qam", "changed tree")
        invoke("changed-tree", *gate, stages="checks")
        changed_rows = ledger.read_text().splitlines()
        assert len(stage_rows(changed_rows)) == len(stage_rows(version_rows)) + 1
        failing_recipes = recipes.replace("6 * 7 == 42", "6 * 7 == 43")
        failing_recipes = failing_recipes.replace(
            'echo cli >> "$$CANDIDATE_LOG_DIR/setup.log"',
            'echo cli >> "$$CANDIDATE_LOG_DIR/setup.log"; exit 23',
        )
        failing_recipes = failing_recipes.replace(
            "test-server:\n\t@true", "test-server:\n\t@exit 23"
        )
        (repo / "Makefile").write_text(failing_recipes)
        checked(repo, "git", "commit", "-qam", "independent failures in one invocation")
        invoke("failed-tree", *gate, stages=STAGES, success=False)
        before = ledger.read_text()
        failed_rows = [
            row.split("\t") for row in before.splitlines()[len(changed_rows) :]
        ]
        verdicts = {row[1]: row[2] for row in failed_rows}
        for entry, verdict in {
            "static": "passed",
            "checks": "failed",
            "checks/test-shipping": "failed",
            "checks/check-go-vulnerability-audit": "passed",
            "user-paths": "passed",
            "unit": "failed",
            "unit/test-server": "failed",
            "unit/_candidate-unit-pi": "passed",
            "artifacts": "failed",
            "artifacts/build": "failed",
            "artifacts/_candidate-artifact-server": "passed",
            "integration": "failed",
            "integration/e2e-naapp": "skipped",
            "integration/cli-e2e": "passed",
            "integration/test-oci-exact-publish": "passed",
        }.items():
            if verdicts.get(entry) != verdict:
                raise AssertionError(f"{entry} expected {verdict}: {verdicts}")
        skipped = next(row for row in failed_rows if row[1] == "integration/e2e-naapp")
        if "build FAILED" not in skipped[9]:
            raise AssertionError(f"skip has no build failure detail: {skipped}")
        refused = invoke("refused-tree", *gate, stages="integration", success=False)
        failure_lines = [
            line for line in refused.splitlines() if "already FAILED" in line
        ]
        expected_failures = [
            (stage, log)
            for _, stage, result, _, _, log, *_ in failed_rows
            if "/" not in stage and result == "failed"
        ]
        if len(failure_lines) != len(expected_failures):
            raise AssertionError(f"incomplete failed-stage refusal: {refused}")
        for line, (stage, log) in zip(failure_lines, expected_failures, strict=True):
            if not line.endswith(f"already FAILED {stage} (log {log})."):
                raise AssertionError(f"failed stage or log omitted: {refused}")
        if "GATE_RERUN_REASON" not in refused:
            raise AssertionError(
                f"infrastructure recovery instructions omitted: {refused}"
            )
        assert ledger.read_text() == before
        # Every executed gate has real cleanup evidence; successful stage rows
        # retain their own logs after later invocations reuse/replace run roots.
        for row in ledger.read_text().splitlines():
            assert Path(row.split("\t")[5]).is_file()
        assert all(
            "candidate gate cleanup PASSED" in (evidence / f"{name}.log").read_text()
            for name in (
                "first-checks",
                "missing-only",
                "reviewed-ceilings-change",
                "version-input",
                "changed-tree",
                "failed-tree",
            )
        )
        # A failed static stage stops the run: no later stage starts or is
        # recorded, the static failure is, and the tree is refused until fixed.
        checks_line = f"{' '.join(SOURCE_CHECKS)}:\n"
        static_failure = (
            recipes.replace(
                checks_line,
                f"{' '.join(t for t in SOURCE_CHECKS if t != 'check-private-boundary')}:\n",
            )
            + "check-private-boundary:\n\t@exit 23\n"
        )
        assert recipes.count(checks_line) == 1 and static_failure != recipes
        (repo / "Makefile").write_text(static_failure)
        checked(repo, "git", "commit", "-qam", "static failure")
        before_static = ledger.read_text().splitlines()
        output = invoke("static-failed-tree", *gate, stages=STAGES, success=False)
        static_rows = [
            row.split("\t")
            for row in ledger.read_text().splitlines()[len(before_static) :]
        ]
        recorded_stages = {row[1].split("/")[0] for row in static_rows}
        if recorded_stages != {"static"}:
            raise AssertionError(f"only static may be recorded: {static_rows}")
        verdicts = {row[1]: row[2] for row in static_rows}
        if (
            verdicts.get("static") != "failed"
            or verdicts.get("static/check-private-boundary") != "failed"
        ):
            raise AssertionError(f"static failure not recorded: {static_rows}")
        for stage in STAGES.split()[1:]:
            if f"candidate: {stage} NOT-RUN" not in output:
                raise AssertionError(f"{stage} not reported as not run: {output}")
        if "candidate gate cleanup PASSED" not in output:
            raise AssertionError(f"static failure skipped gate cleanup: {output}")
        refused = invoke("static-refused-tree", *gate, success=False)
        if "already FAILED static" not in refused:
            raise AssertionError(f"failed static tree was not refused: {refused}")
    print(
        "PASS: real Docker stages, missing-only execution, make/direct/RC reuse, changed main/tree/version, failed-tree refusal, static stop"
    )


if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(CompleteGateVerdictTests)
    )
    if not result.wasSuccessful():
        raise SystemExit(1)
    main()
