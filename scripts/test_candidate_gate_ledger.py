#!/usr/bin/env python3
"""Exercise the real Docker gate and RC with small Git, SQL, image and Redis stages."""
from __future__ import annotations

import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
STAGES = "checks unit artifacts integration"
# The targets the fixture gives real recipes: the four stage assertions below
# use real tools and services, never a replacement runner.
REAL_RECIPES = frozenset({
    "test-shipping", "_candidate-node-deps", "build", "_candidate-unit-suites",
    "_candidate-artifact-server", "freshness", "e2e-naapp",
})


def source_checks() -> list[str]:
    """Every other product target the candidate suite runs, read from the suite
    itself. The fixture stubs each one to check its committed source, so a
    target a stage adds is stubbed here without anyone editing this list."""
    suite = (ROOT / "scripts" / "candidate-suite.sh").read_text(encoding="utf-8")
    targets = re.findall(r"^\s*run ([A-Za-z0-9_.-]+)\s*$", suite, flags=re.MULTILINE)
    return [target for target in dict.fromkeys(targets) if target not in REAL_RECIPES]


SOURCE_CHECKS = source_checks()


def run(root: Path, *args: str, env: dict[str, str] | None = None):
    return subprocess.run(args, cwd=root, env=env, text=True, capture_output=True, timeout=900)


def checked(root: Path, *args: str):
    result = run(root, *args)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout.strip()


def main() -> None:
    evidence = Path(tempfile.mkdtemp(prefix="aweb-ledger-evidence.")).resolve()
    print(f"Ledger integration evidence: {evidence}", flush=True)
    with tempfile.TemporaryDirectory(prefix="aweb-ledger-proof.") as temporary:
        repo = Path(temporary)
        for name in ("candidate-docker-gate.sh", "candidate-suite.sh", "candidate-cleanup.sh",
                     "candidate-host-pressure.py", "next_tag_version.py", "release_candidate.py", "release_versions.py"):
            destination = repo / "scripts" / name
            destination.parent.mkdir(exist_ok=True)
            shutil.copy2(ROOT / "scripts" / name, destination)
        (repo / "candidate-gate/bin").mkdir(parents=True)
        shutil.copy2(ROOT / "candidate-gate/bin/docker", repo / "candidate-gate/bin/docker")
        (repo / "candidate-gate/Dockerfile").write_text(
            "FROM docker:27-cli\n"
            "RUN apk add --no-cache bash git make python3 postgresql-client redis "
            "&& ln -s /usr/local/bin/docker /usr/bin/docker\n"
        )
        (repo / "candidate-gate/proof.Dockerfile").write_text(
            'FROM busybox:1.37\nRUN test "$((6*7))" = 42\n'
        )
        (repo / "naapp/library/test-vectors/blueprints/team").mkdir(parents=True)
        (repo / "naapp/library/test-vectors/blueprints/team/proof").write_text("fixture\n")
        (repo / "server").mkdir()
        (repo / "server/pyproject.toml").write_text('[project]\nname="ledger-proof"\nversion="1.2.3"\n')
        recipes = f".PHONY: candidate-gate {' '.join(SOURCE_CHECKS)}\n{' '.join(SOURCE_CHECKS)}:\n\t@git diff --exit-code\n"
        recipes += '''test-shipping:
\t@python3 -c 'assert 6 * 7 == 42'
_candidate-node-deps:
\t@echo node >> "$$CANDIDATE_LOG_DIR/setup.log"
build:
\t@echo cli >> "$$CANDIDATE_LOG_DIR/setup.log"
_candidate-unit-suites:
\t@test "$$(psql -h "$$TEST_DB_HOST" -U postgres -d postgres -Atc 'SELECT 6 * 7')" = 42
_candidate-artifact-server:
\t@docker build -f candidate-gate/proof.Dockerfile -t "$$AWEB_CANDIDATE_RESOURCE_LABEL-proof" candidate-gate
\t@docker run --rm "$$AWEB_CANDIDATE_RESOURCE_LABEL-proof" sh -c 'test "$$(echo 42)" = 42'
\t@test "$$(wc -l < "$$CANDIDATE_LOG_DIR/setup.log")" = 2
freshness:
\t@test "$$(redis-cli -u "$$REDIS_URL" PING)" = PONG
naapp-e2e-packages:
\t@printf '%s\\n' proof/first proof/second
e2e-naapp:
\t@python3 -c 'import os; rows=[row.split() for row in os.environ["NAAPP_E2E_ALLOCATIONS"].splitlines()]; assert [row[0] for row in rows] == ["proof/first", "proof/second"]; assert len({port for row in rows for port in row[2:]}) == 4; assert all(row[1].startswith("aweb-candidate-") and "-naapp-" in row[1] for row in rows); assert os.environ["AWEB_DOCKER_PUBLISHED_HOST"] == "aweb-docker.test"'
candidate-gate:
\tbash scripts/candidate-docker-gate.sh
'''
        (repo / "Makefile").write_text(recipes)
        checked(repo, "git", "init", "-qb", "main")
        checked(repo, "git", "config", "user.name", "gate integration")
        checked(repo, "git", "config", "user.email", "gate@example.test")
        checked(repo, "git", "add", ".")
        checked(repo, "git", "commit", "-qm", "small real gate stages")
        checked(repo, "git", "remote", "add", "origin", str(repo))
        env = {key: value for key, value in os.environ.items()
               if key == "AWEB_GATE_MIN_FREE_GB"
               or not key.startswith(("AWEB_CANDIDATE_", "AWEB_GATE_", "CANDIDATE_", "GATE_", "LIBRARY_E2E_"))}
        env.update(AWEB_GATE_LEDGER=str(evidence / "ledger.tsv"),
                   AWEB_GATE_LOG_DIR=str(evidence / "logs"),
                   CLI_VERSION="1.2.3", A2A_GATEWAY_VERSION="1.2.3",
                   AWEB_CANDIDATE_RUNNER_MEMORY="1g", AWEB_CANDIDATE_BUILDER_MEMORY="1g")

        def invoke(name: str, *args: str, stages: str | None = None, success: bool = True):
            settings = dict(env)
            if stages is not None:
                settings["AWEB_CANDIDATE_STAGES"] = stages
            result = run(repo, *args, env=settings)
            (evidence / f"{name}.log").write_text(result.stdout + result.stderr)
            assert (result.returncode == 0) == success, f"{name}: see {evidence}/{name}.log"
            return result.stdout + result.stderr

        gate = ("bash", "scripts/candidate-docker-gate.sh")
        ledger = evidence / "ledger.tsv"
        # Library builds from the candidate checkout itself; a separate Library
        # source is no longer an input, so naming one is refused, not ignored.
        env["LIBRARY_E2E_LIBRARY_CONTEXT"] = str(repo / "naapp/library")
        refused_library = invoke("library-context", *gate, stages="checks", success=False)
        assert "LIBRARY_E2E_LIBRARY_CONTEXT" in refused_library and not ledger.exists()
        del env["LIBRARY_E2E_LIBRARY_CONTEXT"]
        invoke("first-checks", *gate, stages="checks")
        rows = ledger.read_text().splitlines()
        assert len(rows) == 1 and rows[0].split("\t")[1:3] == ["checks", "passed"]
        invoke("missing-only", "make", "candidate-gate")
        rows = ledger.read_text().splitlines()
        assert len(rows) == 4 and {row.split("\t")[1] for row in rows} == set(STAGES.split())
        assert all(row.split("\t")[2] == "passed" for row in rows)
        assert "no stages run" in invoke("same-tree-direct", *gate)
        # New commit metadata with the identical tree does not invalidate proof.
        checked(repo, "git", "commit", "--allow-empty", "-qm", "same tree new commit")
        assert "no stages run" in invoke("same-tree-commit", "make", "candidate-gate")
        refused_final = invoke("final-without-rc", sys.executable, "scripts/release_candidate.py",
                               "aw-v1.2.3", stages="checks", success=False)
        assert "final requires a prior RC" in refused_final
        assert run(repo, "git", "rev-parse", "--verify", "refs/tags/aw-v1.2.3").returncode != 0
        assert ledger.read_text().splitlines() == rows
        checked(repo, "git", "tag", "aw-v1.2.3-rc.1")
        # The real RC must require all stages despite an inherited focused selector.
        output = invoke("rc-reuse", sys.executable, "scripts/release_candidate.py", "aw-v1.2.3", stages="checks")
        assert "no stages run" in output and "checks unit artifacts integration" in output
        assert checked(repo, "git", "rev-parse", "aw-v1.2.3^{commit}") == checked(repo, "git", "rev-parse", "HEAD")
        assert ledger.read_text().splitlines() == rows
        # An effective version is an external input, even with an unchanged tree.
        env["CLI_VERSION"] = "1.2.4"
        invoke("version-input", *gate, stages="checks")
        version_rows = ledger.read_text().splitlines()
        assert len(version_rows) == 5 and version_rows[-1].split("\t")[0] != rows[0].split("\t")[0]
        env["CLI_VERSION"] = "1.2.3"
        (repo / "Makefile").write_text(recipes.replace("6 * 7 == 42", "7 * 6 == 42"))
        checked(repo, "git", "commit", "-qam", "changed tree")
        invoke("changed-tree", *gate, stages="checks")
        assert len(ledger.read_text().splitlines()) == 6
        (repo / "Makefile").write_text(recipes.replace("6 * 7 == 42", "6 * 7 == 43"))
        checked(repo, "git", "commit", "-qam", "real failing stage")
        invoke("failed-tree", *gate, stages="checks", success=False)
        before = ledger.read_text()
        assert before.splitlines()[-1].split("\t")[1:3] == ["checks", "failed"]
        refused = invoke("refused-tree", *gate, stages="integration", success=False)
        assert "already FAILED checks" in refused and "GATE_RERUN_REASON" in refused
        assert ledger.read_text() == before
        # Every executed gate has real cleanup evidence; successful stage rows
        # retain their own logs after later invocations reuse/replace run roots.
        for row in ledger.read_text().splitlines():
            assert Path(row.split("\t")[5]).is_file()
        assert all("candidate gate cleanup PASSED" in (evidence / f"{name}.log").read_text()
                   for name in ("first-checks", "missing-only", "version-input", "changed-tree", "failed-tree"))
    print("PASS: real Docker stages, missing-only execution, make/direct/RC reuse, changed tree/version, failed-tree refusal")


if __name__ == "__main__":
    main()
