#!/usr/bin/env python3
"""Exercise the real Docker gate and RC with small Git, SQL, image and Redis stages."""

from __future__ import annotations

import errno
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
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
STAGES = "checks user-paths unit artifacts integration"
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
                "make": 'printf "make %s\\n" "$*"\ncase " $FAILURES " in *" $1 "*) exit 23;; esac\n',
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

    def test_duplicate_controls_reuse_only_their_own_candidate_proof(self):
        shared_checks = (
            "test-identity-primitives", "test-vector-provenance",
            "test-sot-source-inventories", "test-python-locks", "lint-naapp",
        )
        result, rows = self.suite("checks unit integration")
        lines = result.stdout.splitlines()
        self.assertEqual(result.returncode, 0, result.stdout)
        for target in shared_checks:
            self.assertEqual(lines.count(f"make {target}"), 1)
            self.assertNotIn(f"unit/{target}", rows)
        self.assertIn("make test-federation-harness FEDERATION_HARNESS_IN_UNIT=1", lines)
        self.assertIn("make freshness FRESHNESS_ARGS=--cli-reference-already-tested", lines)
        self.assertIn(
            "make test-npm-exact-publish NPM_EXACT_PUBLISH_TEST_ARGS=--readback-already-tested",
            lines,
        )

        for selection, targets in (
            ("checks", ("test-federation-harness",)),
            ("unit", shared_checks),
            ("integration", ("freshness", "test-npm-exact-publish")),
        ):
            with self.subTest(selection=selection):
                result, _ = self.suite(selection)
                self.assertEqual(result.returncode, 0, result.stdout)
                for target in targets:
                    self.assertIn(f"make {target}", result.stdout.splitlines())

        result, rows = self.suite("checks unit integration", "test-shipping", "test-cli-reference")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(rows["checks"], "FAILED")
        self.assertIn("make test-npm-exact-publish", result.stdout.splitlines())
        self.assertIn("make freshness", result.stdout.splitlines())

    def test_every_stage_and_independent_target_reports_after_failures(self):
        result, rows = self.suite(
            STAGES, "check-python-static", "e2e-user-paths",
            "test-python-locks", "build", "_candidate-artifact-server",
        )
        self.assertNotEqual(result.returncode, 0)
        for stage in STAGES.split():
            self.assertEqual(rows.get(stage), "FAILED", result.stdout)
        self.assertEqual(rows["checks/check-python-static"], "FAILED")
        self.assertEqual(rows["checks/test-release-cli-version"], "PASSED")
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
        self.assertEqual(rows["checks/test-release-cli-version"], "PASSED")
        self.assertEqual(rows["checks"], "FAILED")
        self.assertEqual(rows["user-paths"], "PASSED")

    def test_isolated_unit_keeps_every_leaf_after_server_failure(self):
        result, rows = self.suite("--isolated-suites", "test-server", "test-cli")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(rows, {
            "unit/test-server": "FAILED",
            "unit/test-awid": "PASSED",
            "unit/test-naapp": "PASSED",
            "unit/test-cli": "FAILED",
            "unit/test-cli-auth-v2": "PASSED",
            "unit/_candidate-unit-channel": "PASSED",
            "unit/test-channel-name-live-contract": "PASSED",
            "unit/_candidate-unit-channel-core": "PASSED",
            "unit/_candidate-unit-pi": "PASSED",
        })


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


def interrupted_docker_proof(repo: Path, evidence: Path, env: dict[str, str]) -> None:
    """Exercise the real wrapper, GNU deadline and owned Docker cleanup."""
    supervised = evidence / "supervised"
    supervised.mkdir()
    settings = dict(env, AWEB_CANDIDATE_STAGES="checks unit",
                    PYTHONPATH=str(ROOT / "scripts/vm-gate"))
    command = ["timeout", "--signal=TERM", "--kill-after=130s", "600",
               sys.executable, "-m", "vm_gate.supervisor", "run", str(supervised),
               "120", "bash", str(repo / "scripts/candidate-docker-gate.sh")]
    sha = checked(repo, "git", "rev-parse", "HEAD")
    with (evidence / "deadline-output.log").open("w") as output:
        process = subprocess.Popen(command, cwd=repo, env=settings, stdout=output,
                                   stderr=subprocess.STDOUT)
        try:
            started = time.monotonic()
            log_dir = None
            while time.monotonic() - started < 550 and process.poll() is None:
                active = [path for path in Path('/tmp').glob('aweb-candidate-gate-' + sha + '-*')
                          if (path / 'unit-active').exists()]
                if len(active) == 1:
                    log_dir = active[0]
                    break
                time.sleep(.2)
            if log_dir is None:
                raise AssertionError('real blocked Docker stage was not reached; see deadline-output.log')
            builders = [line.split('\t')[1] for line in (log_dir / 'owned-resources.tsv').read_text().splitlines()
                        if line.startswith('builder\t')]
            assert builders, 'no owned builder manifest'
            label = 'aweb.candidate-gate=' + builders[0]
            before = run(repo, 'docker', 'ps', '-aq', '--filter', 'label=' + label)
            assert before.returncode == 0 and before.stdout.strip(), 'no live owned Docker containers'
            (evidence / 'docker-before-deadline.json').write_text(json.dumps({
                'label': label, 'container_ids': before.stdout.split(), 'builders': builders,
                'unit_active': str(log_dir / 'unit-active')}, indent=2) + '\n')
            from vm_gate.memory import current_bytes, sample, summarize_samples

            memory_sample = sample()
            memory_receipt = summarize_samples([memory_sample])
            (evidence / 'memory.jsonl').write_text(json.dumps(memory_sample) + '\n')
            (evidence / 'memory-receipt.json').write_text(json.dumps(memory_receipt, indent=2) + '\n')
            assert any(
                current_bytes(row) is not None
                and any(row['id'].startswith(cid) for cid in before.stdout.split())
                for row in memory_sample['containers']
            ), 'memory proof did not read a live owned gate container'
            raw = process.wait(timeout=760)
            assert raw == 124, f'GNU timeout raw exit {raw}, expected 124'
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=150)
    receipt = json.loads((supervised / 'supervisor-receipt.json').read_text())
    assert receipt['raw_exit'] == 143 and receipt['child_exit'] != 0, receipt
    assert receipt['finalized'] and not receipt['grace_expired'], receipt
    assert (log_dir / 'unit-active').stat().st_mtime < receipt['term_at']
    interruption = (log_dir / 'interruption.tsv').read_text()
    assert 'cleanup=passed' in interruption and 'writer_exit=0' in interruption
    rows = [line.split('\t') for line in (evidence / 'ledger.tsv').read_text().splitlines()]
    assert [(row[1], row[2]) for row in rows if "/" not in row[1]] == [('cleanup', 'passed'), ('checks', 'passed')], rows
    assert any(row[1:3] == ['checks/test-shipping', 'passed'] for row in rows), rows
    assert not any(row[1] == 'unit/_candidate-unit-suites' for row in rows), rows
    assert 'run\tINTERRUPTED\t' in (log_dir / 'summary.tsv').read_text()
    absence = {}
    for kind, args in [('containers', ['ps', '-aq']), ('networks', ['network', 'ls', '-q']),
                       ('volumes', ['volume', 'ls', '-q'])]:
        result = run(repo, 'docker', *args, '--filter', 'label=' + label)
        assert result.returncode == 0 and not result.stdout.strip(), (kind, result.stdout, result.stderr)
        absence[kind] = result.stdout.split()
    for builder in builders:
        for kind, name in [('container', 'buildx_buildkit_' + builder + '0'),
                           ('volume', 'buildx_buildkit_' + builder + '0_state')]:
            result = run(repo, 'docker', kind, 'inspect', name)
            assert result.returncode != 0, (kind, name, 'still exists')
    (evidence / 'deadline-result.json').write_text(json.dumps({
        'fixture_sha': sha, 'gnu_timeout_exit': raw, 'supervisor': receipt,
        'run_log': str(log_dir), 'owned_absence_before_vm_delete': absence,
        'builder_names_absent': builders, 'memory': memory_receipt}, indent=2) + '\n')
    print('PASS: real deadline TERM preserves checks, completes gate Docker cleanup, and proves own absence', flush=True)


def stage_rows(rows: list[str]) -> list[list[str]]:
    fields = [row.split("\t") for row in rows]
    return [row for row in fields if "/" not in row[1]]


def verify_same_tree_commit_cache(
    *,
    repo: Path,
    ledger: Path,
    run_fixed_baseline_gate: Callable[[], str],
    run_full_gate: Callable[[], str],
) -> list[str]:
    """Same-tree reuse also requires the same reviewed main (docs/python-static-analysis.md)."""
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

    # The full entry synchronizes the fixture's advanced main before key lookup.
    assert "no stages run" not in run_full_gate()
    current_main = checked(repo, "git", "rev-parse", "refs/remotes/origin/main")
    assert current_main != previous_main
    assert current_main == checked(repo, "git", "rev-parse", "HEAD")
    rows = ledger.read_text().splitlines()
    assert rows[: len(previous_rows)] == previous_rows
    fresh = stage_rows(rows[len(previous_rows) :])
    assert len(fresh) == len(STAGES.split())
    assert {row[1] for row in fresh} == set(STAGES.split())
    assert all(row[2] == "passed" for row in fresh)
    fresh_keys = {row[0] for row in fresh}
    assert len(fresh_keys) == 1
    assert fresh_keys.isdisjoint(row.split("\t")[0] for row in previous_rows)
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
        interruption_only = sys.argv[1:] == ["--interruption-only"]
        if interruption_only:
            recipes = recipes.replace(
                "_candidate-unit-suites:\n",
                "_candidate-unit-suites:\n\t@touch \"$$CANDIDATE_LOG_DIR/unit-active\"; sleep 1800\n")
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

        if interruption_only:
            interrupted_docker_proof(repo, evidence, env)
            return

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
            raise AssertionError(f"missing passed isolated test-server row: {unit_target}")
        if "candidate: test-server PASSED" not in Path(unit_target[0][5]).read_text():
            raise AssertionError(f"isolated test-server log missing evidence: {unit_target}")
        assert "no stages run" in invoke("same-tree-direct", *gate)
        rows = verify_same_tree_commit_cache(
            repo=repo,
            ledger=ledger,
            run_fixed_baseline_gate=lambda: invoke(
                "same-tree-fixed-baseline", *gate, stages=STAGES
            ),
            run_full_gate=lambda: invoke("same-tree-commit", "make", "candidate-gate"),
        )
        refused_final = invoke(
            "final-without-rc",
            sys.executable,
            "scripts/release_candidate.py",
            "aw-v1.2.3",
            stages="checks",
            success=False,
        )
        assert "final requires a prior RC" in refused_final
        assert (
            run(repo, "git", "rev-parse", "--verify", "refs/tags/aw-v1.2.3").returncode
            != 0
        )
        assert ledger.read_text().splitlines() == rows
        checked(repo, "git", "tag", "aw-v1.2.3-rc.1")
        # The real RC must require all stages despite an inherited focused selector.
        output = invoke(
            "rc-reuse",
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
        failing_recipes = failing_recipes.replace("test-server:\n\t@true", "test-server:\n\t@exit 23")
        (repo / "Makefile").write_text(failing_recipes)
        checked(repo, "git", "commit", "-qam", "independent failures in one invocation")
        invoke("failed-tree", *gate, stages=STAGES, success=False)
        before = ledger.read_text()
        failed_rows = [row.split("\t") for row in before.splitlines()[len(changed_rows) :]]
        verdicts = {row[1]: row[2] for row in failed_rows}
        for entry, verdict in {
            "checks": "failed",
            "checks/test-shipping": "failed",
            "checks/test-release-cli-version": "passed",
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
        failure_lines = [line for line in refused.splitlines() if "already FAILED" in line]
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
            raise AssertionError(f"infrastructure recovery instructions omitted: {refused}")
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
                "same-tree-commit",
                "version-input",
                "changed-tree",
                "failed-tree",
            )
        )
    print(
        "PASS: real Docker stages, missing-only execution, make/direct/RC reuse, changed main/tree/version, failed-tree refusal"
    )


if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(CompleteGateVerdictTests)
    )
    if not result.wasSuccessful():
        raise SystemExit(1)
    main()
