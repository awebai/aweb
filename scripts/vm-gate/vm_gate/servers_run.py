"""The guest side of `vm-gate run --project servers`: one reviewed spec, run step by step.

Standard library only: it ships in the operator bundle and runs in the guest as
the gate user. For each source it clones the shipped bundle at the spec's ref and
checks the commit out; it starts the spec's loopback registry; it runs each step
in its source checkout with every output line timestamped as it arrives, keeps
the step's raw exit apart from its verdict, checks the step's required and
forbidden lines and files, and collects only the step's named artifacts; then it
removes the registry. result.json records every outcome, failures included.

    python3 servers_run.py SPEC OUT [--sources DIR] [--bundles DIR] [--runs DIR]
"""

import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path


def sha256(path):
    return "sha256:" + hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(argv, **kwargs):
    return subprocess.run(argv, capture_output=True, text=True, **kwargs)


def check_out(name, source, bundles, sources):
    """Clone the shipped bundle's ref and check out the spec's commit; report what the guest saw."""
    bundle = Path(bundles) / f"{name}.bundle"
    checkout = Path(sources) / name
    record = {
        "shipped_bundle_sha256": sha256(bundle),
        "guest_commit": None,
        "error": None,
    }
    if record["shipped_bundle_sha256"] != source["shipped_bundle_sha256"]:
        record["error"] = (
            "the bundle in the guest is not the bundle the controller shipped"
        )
        return record
    steps = (
        ["git", "init", "--quiet", str(checkout)],
        ["git", "-C", str(checkout), "fetch", "--quiet", str(bundle), source["ref"]],
        [
            "git",
            "-C",
            str(checkout),
            "checkout",
            "--quiet",
            "--detach",
            source["commit"],
        ],
    )
    for argv in steps:
        done = run(argv)
        if done.returncode:
            record["error"] = f"{' '.join(argv[:4])} failed: {done.stderr.strip()}"
            return record
    record["guest_commit"] = run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"]
    ).stdout.strip()
    if record["guest_commit"] != source["commit"]:
        record["error"] = (
            f"checked out {record['guest_commit']}, not {source['commit']}"
        )
    return record


def timestamped(command, cwd, env, log_path):
    """Run one step: each stdout and stderr line is written with its arrival time; return the raw exit."""
    with (
        open(log_path, "w") as log,
        subprocess.Popen(
            ["bash", "-c", command],
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        ) as process,
    ):
        for line in process.stdout:
            stamp = datetime.datetime.now().astimezone().strftime("%Y-%m-%dT%H:%M:%S%z")
            log.write(f"{stamp} {line}")
            log.flush()
        return process.wait()


def untimed(log_path):
    """The step's output without the timestamps, for its line checks."""
    return [
        line.split(" ", 1)[1] if " " in line else ""
        for line in Path(log_path).read_text().splitlines()
    ]


def values(document, path):
    """The values at a dotted path; `*` steps through every value of a mapping."""
    found = [document]
    for part in path.split("."):
        nxt = []
        for item in found:
            if not isinstance(item, dict):
                continue
            if part == "*":
                nxt.extend(item.values())
            elif part in item:
                nxt.append(item[part])
        found = nxt
    return found


def json_check(lines, check):
    """One structured check on the JSON a line prints after its prefix, e.g. LIFECYCLE: {...}.

    Each assertion is one of: equals (every value at path equals it, and there is
    at least one), greater_than (every value is a number above it), keys_include
    (the mapping at path has these keys). The result names what was seen.
    """
    payloads = [
        line[len(check["prefix"]) :].strip()
        for line in lines
        if line.startswith(check["prefix"])
    ]
    if len(payloads) != 1:
        return {
            "ok": False,
            "seen": f"{len(payloads)} lines start with {check['prefix']!r}, not one",
        }
    try:
        document = json.loads(payloads[0])
    except json.JSONDecodeError as error:
        return {"ok": False, "seen": f"not JSON: {error}"}
    outcomes = []
    for assertion in check["assert"]:
        found = (
            values(document, assertion["path"])
            if assertion["path"] != "."
            else [document]
        )
        if "equals" in assertion:
            ok = bool(found) and all(value == assertion["equals"] for value in found)
        elif "greater_than" in assertion:
            ok = bool(found) and all(
                isinstance(value, (int, float))
                and not isinstance(value, bool)
                and value > assertion["greater_than"]
                for value in found
            )
        elif "keys_include" in assertion:
            ok = bool(found) and all(
                isinstance(value, dict) and set(assertion["keys_include"]) <= set(value)
                for value in found
            )
        else:
            ok = False
        outcomes.append({**assertion, "ok": ok, "found": found})
    return {"ok": all(outcome["ok"] for outcome in outcomes), "assert": outcomes}


def run_step(step, results, paths):
    name = step["name"]
    record = {
        "name": name,
        "user": step["user"],
        "uid": None,
        "command": step["command"],
        "expect_exit": step["expect_exit"],
        "exit": None,
        "require": {},
        "forbid": {},
        "files": {},
        "inputs": {},
        "json": {},
        "artifacts": {},
        "verdict": "unrun",
        "reason": None,
        "log": None,
    }
    blocked = [
        need
        for need in step.get("needs", [])
        if (results.get(need) or {}).get("verdict") != "passed"
    ]
    if blocked:
        record["reason"] = f"needs {', '.join(blocked)}, which did not pass"
        return record
    cwd = Path(paths["sources"]) / step["cwd"]
    run_dir = Path(paths["runs"]) / name
    for item in step.get("inputs", []):
        producer = results.get(item["from"]) or {}
        produced = (producer.get("files") or {}).get(item["path"])
        origin = Path(paths["sources"]) / producer.get("cwd", "") / item["path"]
        if produced is None or not origin.is_file() or sha256(origin) != produced:
            record["verdict"] = "failed"
            record["reason"] = (
                f"{item['from']}'s {item['path']} is missing or changed since {item['from']} ran"
            )
            return record
        target = cwd / item["to"]
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(origin, target)
        record["inputs"][item["to"]] = produced
    record["uid"] = os.getuid()
    record["cwd"] = step["cwd"]
    command = step["command"].replace("{run_dir}", str(run_dir))
    env = dict(os.environ, PYTHONUNBUFFERED="1")
    log = Path(paths["out"]) / f"{name}.log"
    record["log"] = str(log)
    record["exit"] = timestamped(command, cwd, env, log)
    record["log_sha256"] = sha256(log)
    lines = untimed(log)
    for pattern in step.get("require", []):
        record["require"][pattern] = any(re.search(pattern, line) for line in lines)
    for pattern in step.get("forbid", []):
        record["forbid"][pattern] = any(re.search(pattern, line) for line in lines)
    for check in step.get("json", []):
        record["json"][check["prefix"]] = json_check(lines, check)
    for relative in step.get("files", []):
        path = cwd / relative
        record["files"][relative] = sha256(path) if path.is_file() else None
    artifacts = Path(paths["out"]) / "artifacts" / name
    for relative in step.get("artifacts", []):
        base = run_dir if relative.startswith("{run_dir}/") else cwd
        pattern = relative.removeprefix("{run_dir}/")
        for found in sorted(base.glob(pattern)):
            if found.is_file():
                target = artifacts / found.relative_to(base)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(found, target)
                record["artifacts"][str(target.relative_to(artifacts))] = sha256(target)
    expected = step["expect_exit"]
    exit_ok = (
        record["exit"] == expected if isinstance(expected, int) else record["exit"] != 0
    )
    failures = []
    if not exit_ok:
        failures.append(f"exit {record['exit']}, expected {expected}")
    failures += [
        f"required line missing: {p}"
        for p, seen in record["require"].items()
        if not seen
    ]
    failures += [
        f"forbidden line present: {p}" for p, seen in record["forbid"].items() if seen
    ]
    failures += [
        f"required file missing: {f}"
        for f, digest in record["files"].items()
        if digest is None
    ]
    failures += [
        f"JSON check failed: {prefix}"
        for prefix, outcome in record["json"].items()
        if not outcome["ok"]
    ]
    record["verdict"] = "failed" if failures else "passed"
    record["reason"] = "; ".join(failures) or None
    return record


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("spec", type=Path)
    parser.add_argument("out", type=Path)
    parser.add_argument("--bundles", default="/opt/vm-gate/bundles")
    parser.add_argument("--sources", default="/opt/vm-gate/sources")
    parser.add_argument("--runs", default="/opt/vm-gate/runs")
    args = parser.parse_args(argv)
    spec = json.loads(args.spec.read_text())
    args.out.mkdir(parents=True, exist_ok=True)
    for directory in (args.sources, args.runs):
        Path(directory).mkdir(parents=True, exist_ok=True)
    paths = {"out": args.out, "sources": args.sources, "runs": args.runs}
    result = {
        "sources": {},
        "registry": None,
        "steps": [],
        "versions": {},
        "error": None,
    }

    def record():
        (args.out / "result.json").write_text(json.dumps(result, indent=2) + "\n")

    registry = spec.get("registry")
    try:
        for tool, argv in (
            ("docker", ["docker", "version", "--format", "{{.Server.Version}}"]),
            ("compose", ["docker", "compose", "version", "--short"]),
        ):
            done = run(argv)
            result["versions"][tool] = (
                done.stdout.strip() if done.returncode == 0 else None
            )
        for name, source in spec["sources"].items():
            result["sources"][name] = check_out(
                name, source, args.bundles, args.sources
            )
        record()
        ready = all(source["error"] is None for source in result["sources"].values())
        if registry and ready:
            started = run(
                [
                    "docker",
                    "run",
                    "-d",
                    "--name",
                    registry["name"],
                    "-p",
                    f"127.0.0.1:{registry['port']}:5000",
                    registry["image"],
                ]
            )
            result["registry"] = {
                "image": registry["image"],
                "started": started.returncode == 0,
                "removed": None,
                "error": started.stderr.strip() or None,
            }
            ready = result["registry"]["started"]
            record()
        results = {}
        for step in spec["steps"]:
            if ready:
                outcome = run_step(step, results, paths)
            else:
                outcome = {
                    "name": step["name"],
                    "verdict": "unrun",
                    "reason": "sources or registry not ready",
                }
            results[step["name"]] = outcome
            result["steps"].append(outcome)
            record()
    except Exception as error:  # The run's record survives the runner's own failure.
        result["error"] = f"{type(error).__name__}: {error}"
    finally:
        if result["registry"] and result["registry"]["started"]:
            removed = run(["docker", "rm", "-f", registry["name"]])
            result["registry"]["removed"] = removed.returncode == 0
        record()
    green = (
        result["error"] is None
        and len(result["steps"]) == len(spec["steps"])
        and all(source["error"] is None for source in result["sources"].values())
        and all(step["verdict"] == "passed" for step in result["steps"])
        and (not result["registry"] or result["registry"]["removed"])
    )
    code = 0 if green else 1
    (args.out / "exit").write_text(f"{code}\n")
    return code


if __name__ == "__main__":
    sys.exit(main())
