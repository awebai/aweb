#!/usr/bin/env python3
"""Once-only, opt-in real parallel and SIGKILL/reaper acceptance (four VMs)."""

import argparse
from datetime import datetime, timezone
from decimal import Decimal
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from vm_gate.errors import Infrastructure
from vm_gate.config import load
from vm_gate.runtime import Runtime
from vm_gate.source import git
from vm_gate.state import Store
from vm_gate.transport import Transport
from vm_gate.backend import PREFIX


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--config", required=True)
    p.add_argument("--repo", required=True)
    p.add_argument("--sha-a", required=True)
    p.add_argument("--sha-b", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--max-eur", default="1.50")
    args = p.parse_args()
    if os.environ.get("VM_GATE_REAL_PROVIDER") != "1":
        p.error(
            "real-provider acceptance requires VM_GATE_REAL_PROVIDER=1 and the source ACK"
        )
    config = load(args.config, args.repo)
    ceiling = Decimal(str(config.get("run_ceiling_eur", "Infinity")))
    if not Decimal(0) < ceiling * 4 <= Decimal(args.max_eur):
        p.error(
            "four per-run reservation ceilings must fit the separate acceptance cap"
        )
    if any(
        config.get(k) != v
        for k, v in {
            "setup_seconds": 180,
            "pull_seconds": 60,
            "cleanup_seconds": 60,
            "margin_seconds": 30,
        }.items()
    ):
        p.error("acceptance requires setup180/pull60/cleanup60/margin30 seconds")
    if git(args.repo, "status", "--porcelain", "--untracked-files=all").stdout:
        p.error("clean source required")
    trees = [
        git(args.repo, "rev-parse", s + "^{tree}").stdout.strip()
        for s in [args.sha_a, args.sha_b]
    ]
    if trees[0] == trees[1]:
        p.error("parallel acceptance needs two different trees (canonical tree lease)")
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    marker = output / "started.json"
    with marker.open("x") as f:
        json.dump({"created": time.time(), "sha_a": args.sha_a, "sha_b": args.sha_b}, f)
    store = Store(
        Path(config["state_root"]) / "registry.sqlite3",
        config.get("cap_eur", 150),
        seed_eur=config.get("seed_eur", 0),
    )
    baseline = {r["run_id"] for r in store.runs()}
    old_directories = {p.name for p in (Path(config["state_root"]) / "runs").glob("*")}
    config["repo"] = str(Path(args.repo).resolve())
    runtime = Runtime(
        config=config, directory=None, source=None, command=None, args=None, run_id=None
    )
    provider = None
    children = []
    receipt = {
        "started": time.time(),
        "parallel": [],
        "sigkill": {},
        "cap_eur": args.max_eur,
    }
    cli = Path(__file__).resolve().parents[1] / "vm-gate"
    env = {
        k: os.environ[k] for k in ["PATH", "HOME", "LANG", "LC_ALL"] if k in os.environ
    }

    def save():
        (output / "acceptance.json").write_text(json.dumps(receipt, indent=2) + "\n")

    def start(name, sha, command):
        log = (output / (name + ".json")).open("w")
        proc = subprocess.Popen(
            [
                sys.executable,
                str(cli),
                "--config",
                str(Path(args.config).resolve()),
                "run",
                "--repo",
                str(Path(args.repo).resolve()),
                "--sha",
                sha,
                "--type",
                "ccx33",
                "--timeout",
                "180",
                "--command",
                command,
            ],
            stdout=log,
            stderr=subprocess.STDOUT,
            env=env,
            start_new_session=True,
        )
        children.append((proc, log, name))
        return proc

    def wait(proc, seconds=1500):
        until = time.monotonic() + seconds
        while proc.poll() is None:
            if time.monotonic() > until:
                raise RuntimeError(
                    "acceptance controller deadline exceeded; inspect/reap without retry"
                )
            time.sleep(2)
        return proc.returncode

    def summaries():
        return [
            json.loads(p.read_text())
            for p in (Path(config["state_root"]) / "runs").glob("*/summary.json")
            if p.parent.name not in old_directories
        ]

    def focused(seconds):
        label = "vm-gate-acceptance-" + uuid.uuid4().hex
        return f'test "$(id -u)" = 1000 && docker run --rm --cpus=.25 --memory=32m --pids-limit=64 --label aweb.vm-gate-acceptance={label} busybox:1.37.0 sleep {seconds}'

    try:
        a = start("parallel-a", args.sha_a, focused(90))
        b = start("parallel-b", args.sha_b, focused(90))
        if [wait(a), wait(b)] != [0, 0]:
            raise RuntimeError("parallel acceptance failed; no retry")
        parallel = [s for s in summaries() if s.get("gate_exit") == 0]
        if len(parallel) != 2:
            raise RuntimeError("parallel summaries missing or ambiguous")
        if max(s["gate_started"] for s in parallel) >= min(
            s["gate_finished"] for s in parallel
        ):
            raise RuntimeError("VM gate intervals did not overlap")
        if len({s["server_id"] for s in parallel}) != 2:
            raise RuntimeError("parallel runs shared a server")
        if not all(
            s.get("cleanup", {}).get("exact_ids_absent") and s["infrastructure"] is None
            for s in parallel
        ):
            raise RuntimeError("parallel verdict or cleanup not proven")
        receipt["parallel"] = parallel
        save()
        victim = start("kill-victim", args.sha_a, focused(180))
        prior = {s["run_id"] for s in parallel} | baseline
        until = time.monotonic() + 1200
        row = None
        while time.monotonic() < until:
            if victim.poll() is not None:
                raise RuntimeError("victim exited before SIGKILL; no replacement")
            candidates = [
                r
                for r in store.runs()
                if r["run_id"] not in prior and r.get("server_id")
            ]
            if len(candidates) > 1:
                raise RuntimeError("ambiguous victim registry")
            if candidates:
                row = candidates[0]
                if provider is None:
                    provider = runtime.provider()
                info = provider.read("server_info", row["server_id"])
                if info.get("labels", {}).get(PREFIX + "run") != row["run_id"]:
                    raise RuntimeError("victim label differs")
                address = ((info.get("public_net") or {}).get("ipv4") or {}).get("ip")
                if address:
                    transport = Transport(
                        Path(config["state_root"]) / "runs" / row["run_id"],
                        address,
                        row["server_id"],
                    )
                    try:
                        probe = transport.run(
                            'test -s /var/log/vm-gate/gate-start && docker ps --filter label=aweb.vm-gate-acceptance --format "{{.ID}}" | grep .',
                            timeout=10,
                            check=False,
                        )
                        if probe.returncode == 0:
                            break
                    except Infrastructure:
                        pass  # Bounded idempotent SSH readiness only.
            time.sleep(2)
        else:
            raise RuntimeError("victim never reached live Docker command")
        os.killpg(victim.pid, signal.SIGKILL)
        victim.wait(timeout=20)
        if not provider.read("list", row["run_id"]):
            raise RuntimeError("SIGKILL did not leave resources to reap")
        receipt["sigkill"] = {
            "run_id": row["run_id"],
            "server_id": row["server_id"],
            "expires": row["expires"],
            "killed": time.time(),
            "signal": 9,
        }
        save()
        while time.time() <= row["expires"] + 2:
            print(
                "waiting for completion expiry before next invocation: "
                + datetime.now(timezone.utc).isoformat(),
                flush=True,
            )
            time.sleep(min(30, max(0.1, row["expires"] + 3 - time.time())))
        next_run = start(
            "reap-next-invocation",
            args.sha_a,
            'printf "known bad focused control\\n"; exit 7',
        )
        if wait(next_run) != 7:
            raise RuntimeError("next invocation did not preserve planted exit7")
        if provider.read("list", row["run_id"]):
            raise RuntimeError("killed run still labelled after next invocation")
        for resource in row.get("resources", []):
            if provider.read("get", resource["kind"], resource["id"]) is not None:
                raise RuntimeError("killed run exact ID still exists")
        final = store.get(row["run_id"])
        if final.get("settled") is None:
            raise RuntimeError("reaped reservation remains unsettled")
        receipt["sigkill"].update(
            reaped=final.get("reaped"), cost_eur=final["actual"], exact_ids_absent=True
        )
        runs = [r for r in store.runs() if r["run_id"] not in baseline]
        if len(runs) != 4:
            raise RuntimeError("acceptance did not use exactly four runs")
        total = sum(Decimal(r["actual"]) for r in runs if r.get("settled") is not None)
        if any(r.get("settled") is None for r in runs) or total > Decimal(args.max_eur):
            raise RuntimeError("acceptance cost is unknown or exceeded its cap")
        receipt.update(
            result="PASS", finished=time.time(), cost_eur=str(total), runs=runs
        )
        save()
        print(json.dumps(receipt, indent=2))
        return 0
    except BaseException as exc:
        receipt.update(
            result="FAILED",
            error=type(exc).__name__ + ": " + str(exc),
            finished=time.time(),
        )
        save()
        raise
    finally:
        # A test failure never starts a replacement. Graceful termination gives
        # any still-running peer its cleanup; a killed victim relies on expiry.
        for proc, log, name in children:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGTERM)
            if proc.poll() is None:
                try:
                    proc.wait(timeout=360)
                except subprocess.TimeoutExpired:
                    print(
                        "controller cleanup still pending; retain IDs and reap after expiry",
                        file=sys.stderr,
                    )
            log.close()


if __name__ == "__main__":
    raise SystemExit(main())
