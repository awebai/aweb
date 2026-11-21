#!/usr/bin/env python3
"""One reviewed Linux caller packet: deadline, owned stop, Docker cleanup and memory.

No allocation is performed here. Run only in the coordinator-authorized ephemeral
VM after source review, under its real runuser/GNU timeout chain.
"""

import argparse
import re


def main(expected_sha, evidence):
    """Bounded native process proof; fixture ledgers never enter the release ledger."""
    import json
    import os
    import subprocess
    import sys
    import time
    from pathlib import Path

    repo = Path(__file__).resolve().parents[2]
    out = Path(evidence).resolve()
    assert os.getuid() == 1000, "native operator must be UID1000"
    assert (
        subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repo, text=True
        ).strip()
        == expected_sha
    )
    out.mkdir(mode=0o700)
    sys.path[:0] = [str(repo / "scripts/vm-gate"), str(repo / "scripts/vm-gate/tests")]
    import test_lifecycle
    import vm_gate.executor as executor_module
    from vm_gate.executor import Executor

    # Observe only executable identities, not full process arguments/environment.
    ancestors = []
    pid = os.getppid()
    for _ in range(20):
        if pid <= 1:
            break
        proc = Path("/proc") / str(pid)
        args = proc.joinpath("cmdline").read_bytes().split(b"\0")
        ancestors.append(Path(os.fsdecode(args[0])).name)
        pid = int(
            next(
                x.split()[1]
                for x in proc.joinpath("status").read_text().splitlines()
                if x.startswith("PPid:")
            )
        )
    assert "runuser" in ancestors and "timeout" in ancestors, (
        "outer real runuser/timeout chain missing"
    )
    (out / "outer-chain.json").write_text(
        json.dumps({"uid": os.getuid(), "executables": ancestors}, indent=2) + "\n"
    )
    source = (repo / "scripts/candidate-docker-gate.sh").read_text()
    tail = source[source.index("# The child owns Docker cleanup.") :]
    import ast

    control = ast.parse((repo / "scripts/test_candidate_interruption.py").read_text())
    prefix = next(
        ast.literal_eval(node.value)
        for node in ast.walk(control)
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "child"
            for target in node.targets
        )
    )

    def prepare(name):
        directory = out / name
        directory.mkdir()
        (directory / "stage-logs").mkdir()
        (directory / "ledger-logs").mkdir()
        (directory / "fixture-ledger.tsv").touch()
        script = directory / "fixture.sh"
        script.write_text(prefix + tail)
        env = dict(
            os.environ,
            CONTROL_RUN_ID=name,
            CONTROL_STATUS="143",
            CONTROL_SIGNAL="15",
            CLEANUP_CONTROL="1",
            EMPTY_LOG="0",
            CORRUPT_SUMMARY="0",
            LATE_SUMMARY="0",
            ROOT=str(repo),
            LOG_DIR=str(directory / "stage-logs"),
            LEDGER_LOGS=str(directory / "ledger-logs"),
            LEDGER=str(directory / "fixture-ledger.tsv"),
            KEY="fixture-" + name,
            SOURCE_SHA=expected_sha,
            OWNER="native-proof",
            pending="checks artifacts integration",
            run_id=name,
            PYTHONPATH=str(repo / "scripts/vm-gate"),
        )
        return directory, script, env

    def check(directory):
        receipt = json.loads((directory / "supervisor-receipt.json").read_text())
        assert (
            receipt["raw_exit"] == 143
            and not receipt["grace_expired"]
            and receipt["group_settled"]
            and receipt["finalized"]
        ), receipt
        rows = [
            x.split("\t")
            for x in (directory / "fixture-ledger.tsv").read_text().splitlines()
        ]
        assert [(r[1], r[2]) for r in rows] == [("checks", "passed")], rows
        assert (
            "run\tINTERRUPTED\t" in (directory / "stage-logs/summary.tsv").read_text()
        )
        return receipt

    first, script, env = prepare("timeout")
    result = subprocess.run(
        [
            "timeout",
            "--signal=TERM",
            "--kill-after=130s",
            "2",
            sys.executable,
            "-m",
            "vm_gate.supervisor",
            "run",
            str(first),
            "120",
            "bash",
            str(script),
        ],
        env=env,
        text=True,
        capture_output=True,
        timeout=145,
        check=False,
    )
    (first / "stdout").write_text(result.stdout)
    (first / "stderr").write_text(result.stderr)
    assert result.returncode == 124, ("GNU timeout status", result.returncode)
    receipt = check(first)
    (first / "qualified.json").write_text(
        json.dumps(
            {
                "gnu_timeout_exit": result.returncode,
                "supervised_gate_exit": receipt["raw_exit"],
                "receipt": receipt,
            },
            indent=2,
        )
        + "\n"
    )

    second, script, env = prepare("operator-stop")
    events = []

    class LocalTransport:
        def run(self, command, timeout, check=False):
            return subprocess.run(
                ["bash", "-c", command],
                env=env,
                text=True,
                capture_output=True,
                timeout=timeout,
                check=check,
            )

    class Interrupted(test_lifecycle.Remote):
        def execute(self, server, timeout):
            self.child = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "vm_gate.supervisor",
                    "run",
                    str(second),
                    "120",
                    "bash",
                    str(script),
                ],
                env=env,
                stdout=(second / "stdout").open("w"),
                stderr=(second / "stderr").open("w"),
            )
            deadline = time.monotonic() + 10
            while (
                not (second / "stage-logs/ready").exists()
                and time.monotonic() < deadline
            ):
                time.sleep(0.05)
            assert (second / "stage-logs/ready").exists(), (
                "controlled command not ready"
            )
            raise KeyboardInterrupt

        def stop(self, server, timeout):
            events.append({"event": "stop", "time": time.time()})
            executor_module.LOGS = str(second)
            real = Executor({}, second, {}, "", None)
            real.transport = LocalTransport()
            return real.stop(server, timeout)

        def collect(self, server, timeout):
            events.append({"event": "collect", "time": time.time()})
            check(
                second
            )  # A real receipt + fixture ledger MUST exist before collection.
            return super().collect(server, timeout)

    fixture = test_lifecycle.LifecycleTests()
    fixture.setUp()
    remote = Interrupted()
    try:
        result = fixture.run_session(remote)
        assert result["remote_stop"]["finalized"] and result["partial_evidence"], result
        assert [e["event"] for e in events] == ["stop", "collect"]
        assert remote.child.wait(timeout=5) == 143
        (second / "qualified.json").write_text(
            json.dumps(
                {"events": events, "lifecycle": result, "real_provider_access": False},
                indent=2,
            )
            + "\n"
        )
    finally:
        fixture.doCleanups()
    docker_proof = subprocess.run(
        [
            sys.executable,
            "scripts/test_candidate_gate_ledger.py",
            "--interruption-only",
        ],
        cwd=repo,
        env=dict(os.environ, PYTHONPATH=str(repo / "scripts/vm-gate")),
        text=True,
        capture_output=True,
        timeout=900,
        check=False,
    )
    (out / "docker-proof.stdout").write_text(docker_proof.stdout)
    (out / "docker-proof.stderr").write_text(docker_proof.stderr)
    docker_proof.check_returncode()
    paths = [
        line.removeprefix("Ledger integration evidence: ")
        for line in docker_proof.stdout.splitlines()
        if line.startswith("Ledger integration evidence: ")
    ]
    assert len(paths) == 1, "one invocation must identify its own evidence directory"
    memory = json.loads((Path(paths[0]) / "memory-receipt.json").read_text())
    assert memory["concurrent_cgroup_current_peak"] is not None
    (out / "memory-receipt.json").write_text(json.dumps(memory, indent=2) + "\n")
    (out / "result.json").write_text(
        json.dumps(
            {
                "sha": expected_sha,
                "timeout": "PASS",
                "operator_stop_record_before_collect": "PASS",
                "fixture_ledgers_only": True,
                "real_gate_docker_cleanup_before_delete": "PASS",
            },
            indent=2,
        )
        + "\n"
    )
    print("NATIVE_TIMEOUT_AND_STOP_PROOF_PASS", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--evidence", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_sha):
        parser.error("source SHA must be the exact reviewed commit")
    main(args.source_sha, args.evidence)
