"""The guest side of `vm-gate run --project servers`: one reviewed spec, run step by step.

Standard library only: it ships in the operator bundle and runs in the guest as
the gate user. For each source it clones the shipped bundle at the spec's ref and
checks the commit out; it starts the spec's loopback registry; it runs each step
in its source checkout with every output line timestamped as it arrives, keeps
the step's raw exit apart from its verdict, checks the step's required and
forbidden lines and files, and collects only the step's named artifacts; then it
removes the registry. result.json records every outcome, failures included.

The spec arrives as the reviewed bytes; nothing runs unless its sha256 is the
one the controller admitted.

    python3 servers_run.py SPEC OUT --spec-sha256 D [--sources DIR] [--bundles DIR] [--runs DIR]
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
    if record["shipped_bundle_sha256"] != source["bundle_sha256"]:
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


# The first line of every step's log: the effective uid and HOME of the shell
# that runs the step's command, printed by that shell before the command runs.
CHILD = re.compile(r"VMGATE-CHILD uid=(?P<uid>\d+) home=(?P<home>\S*)")


def as_child(command):
    """The step's command behind a line naming the uid and HOME it actually runs with."""
    return 'printf "VMGATE-CHILD uid=%s home=%s\\n" "$(id -u)" "$HOME"; ' + command


def child_of(lines):
    """The uid and HOME the step's own shell reported, from its first line only."""
    found = CHILD.fullmatch(lines[0]) if lines else None
    return (int(found["uid"]), found["home"]) if found else (None, None)


def untimed(log_path):
    """The step's output without the timestamps, for its line checks."""
    return [
        line.split(" ", 1)[1] if " " in line else ""
        for line in Path(log_path).read_text().splitlines()
    ]


class Missing:
    """A path that names nothing in the document: never equal to anything."""

    def __repr__(self):
        return "<missing>"


MISSING = Missing()


def values(document, path):
    """The values at a dotted path; `*` steps through every value of a mapping.

    A part a mapping lacks yields MISSING rather than nothing, so a check over
    every role cannot pass on a role with no value."""
    found = [document]
    for part in path.split("."):
        nxt = []
        for item in found:
            if not isinstance(item, dict):
                nxt.append(MISSING)
            elif part == "*":
                nxt.extend(item.values())
            else:
                nxt.append(item.get(part, MISSING))
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
            # Strict: a JSON 0 is not false, and false is not 0.
            ok = bool(found) and all(
                type(value) is type(assertion["equals"])
                and value == assertion["equals"]
                for value in found
            )
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
        outcomes.append(
            {
                **assertion,
                "ok": ok,
                "found": [repr(v) if v is MISSING else v for v in found],
            }
        )
    return {"ok": all(outcome["ok"] for outcome in outcomes), "assert": outcomes}


def declared(relative, cwd, run_dir):
    """A declared path: under the step's run directory when it starts {run_dir}/, else its checkout."""
    if relative.startswith("{run_dir}/"):
        return Path(run_dir), relative.removeprefix("{run_dir}/")
    return Path(cwd), relative


def contained(path, base):
    """The real path of a regular file inside base, links resolved; None for anything else."""
    try:
        real = Path(path).resolve(strict=True)
        real.relative_to(Path(base).resolve())
    except (OSError, ValueError):
        return None
    return real if real.is_file() else None


def keep(patterns, cwd, run_dir, artifacts, record):
    """Copy each match of the patterns that is a contained regular file; return the patterns matching none."""
    unmatched = []
    for relative in patterns:
        base, pattern = declared(relative, cwd, run_dir)
        matched = False
        for found in sorted(base.glob(pattern)):
            real = contained(found, base)
            if real is None:
                continue
            target = artifacts / found.relative_to(base)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(real, target)
            digest = sha256(target)
            if digest != sha256(real):
                raise OSError(f"the kept copy of {found} differs from it")
            record["artifacts"][str(target.relative_to(artifacts))] = digest
            matched = True
        if not matched:
            unmatched.append(relative)
    return unmatched


def run_step(step, results, paths, record, save):
    name = step["name"]
    record.update(
        {
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
            "collector_error": None,
        }
    )
    blocked = [
        need
        for need in step.get("needs", [])
        if (results.get(need) or {}).get("verdict") != "passed"
    ]
    if blocked:
        record["reason"] = f"needs {', '.join(blocked)}, which did not pass"
        return
    cwd = Path(paths["sources"]) / step["cwd"]
    run_dir = Path(paths["runs"]) / name
    for item in step.get("inputs", []):
        producer = results.get(item["from"]) or {}
        produced = (producer.get("files") or {}).get(item["path"])
        origin = None
        if producer.get("cwd") is not None:
            base, relative = declared(
                item["path"],
                Path(paths["sources"]) / producer["cwd"],
                producer["run_dir"],
            )
            origin = contained(base / relative, base)
        if produced is None or origin is None or sha256(origin) != produced:
            record["verdict"] = "failed"
            record["reason"] = (
                f"{item['from']}'s {item['path']} is missing or changed since {item['from']} ran"
            )
            return
        base, relative = declared(item["to"], cwd, run_dir)
        target = base / relative
        # The destination is a regular file inside the consumer's base, or nothing yet.
        if target.is_symlink() or (target.exists() and not target.is_file()):
            record["verdict"] = "failed"
            record["reason"] = f"input destination {item['to']} is not a regular file"
            return
        # The deepest existing parent must resolve inside the base before
        # anything is created; admission refuses "..", so what is created
        # beneath it stays inside.
        existing = target.parent
        while not existing.exists() and not existing.is_symlink():
            existing = existing.parent
        try:
            existing.resolve(strict=True).relative_to(base.resolve())
        except (OSError, ValueError):
            record["verdict"] = "failed"
            record["reason"] = (
                f"input destination {item['to']} is not inside its checkout or run directory"
            )
            return
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(origin, target)
        placed = contained(target, base)
        if placed is None or sha256(placed) != produced:
            record["verdict"] = "failed"
            record["reason"] = (
                f"input destination {item['to']} does not hold {item['from']}'s file"
            )
            return
        record["inputs"][item["to"]] = sha256(placed)
    record["cwd"] = step["cwd"]
    record["run_dir"] = str(run_dir)
    command = step["command"].replace("{run_dir}", str(run_dir))
    env = dict(os.environ, PYTHONUNBUFFERED="1")
    log = Path(paths["out"]) / f"{name}.log"
    record["log"] = str(log)
    record["exit"] = timestamped(as_child(command), cwd, env, log)
    # The raw exit is on disk before any evidence is read.
    save()
    try:
        evaluate(step, record, cwd, run_dir, paths)
    except Exception as error:
        record["collector_error"] = f"{type(error).__name__}: {error}"
        record["verdict"] = "failed"
        record["reason"] = "the step's evidence could not be collected"
        raise


def evaluate(step, record, cwd, run_dir, paths):
    """The step's checks over its log, files and artifacts, and its verdict."""
    name = step["name"]
    log = Path(record["log"])
    record["log_sha256"] = sha256(log)
    lines = untimed(log)
    record["uid"], record["home"] = child_of(lines)
    for pattern in step.get("require", []):
        record["require"][pattern] = any(re.search(pattern, line) for line in lines)
    for pattern in step.get("forbid", []):
        record["forbid"][pattern] = any(re.search(pattern, line) for line in lines)
    for check in step.get("json", []):
        record["json"][check["prefix"]] = json_check(lines, check)
    for relative in step.get("files", []):
        base, path = declared(relative, cwd, run_dir)
        real = contained(base / path, base)
        record["files"][relative] = sha256(real) if real else None
    artifacts = Path(paths["out"]) / "artifacts" / name
    missing = keep(step.get("artifacts", []), cwd, run_dir, artifacts, record)
    keep(step.get("optional_artifacts", []), cwd, run_dir, artifacts, record)
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
    failures += [f"required artifact missing: {relative}" for relative in missing]
    expected_uid = paths["users"].get(step["user"])
    if expected_uid is None:
        failures.append(f"no expected uid for {step['user']}")
    elif record["uid"] != expected_uid:
        failures.append(
            f"ran as uid {record['uid']}, not {step['user']}'s {expected_uid}"
        )
    failures += [
        f"JSON check failed: {prefix}"
        for prefix, outcome in record["json"].items()
        if not outcome["ok"]
    ]
    record["verdict"] = "failed" if failures else "passed"
    record["reason"] = "; ".join(failures) or None


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("spec", type=Path)
    parser.add_argument("out", type=Path)
    parser.add_argument("--spec-sha256", required=True)
    parser.add_argument("--bundles", default="/opt/vm-gate/bundles")
    parser.add_argument("--sources", default="/opt/vm-gate/sources")
    parser.add_argument("--runs", default="/opt/vm-gate/runs")
    parser.add_argument(
        "--users",
        required=True,
        help="each step user's expected uid, as user=uid[,user=uid]",
    )
    args = parser.parse_args(argv)
    args.out.mkdir(parents=True, exist_ok=True)
    for directory in (args.sources, args.runs):
        Path(directory).mkdir(parents=True, exist_ok=True)
    users = {}
    for pair in args.users.split(","):
        user, _, uid = pair.partition("=")
        users[user] = int(uid)
    paths = {
        "out": args.out,
        "sources": args.sources,
        "runs": args.runs,
        "users": users,
    }
    result = {
        "sources": {},
        "registry": None,
        "steps": [],
        "versions": {},
        "error": None,
        "spec_sha256": sha256(args.spec),
    }

    def record():
        (args.out / "result.json").write_text(json.dumps(result, indent=2) + "\n")

    spec = {"steps": []}
    registry = None
    try:
        if result["spec_sha256"] != args.spec_sha256:
            raise ValueError(
                f"the spec is {result['spec_sha256']}, not the reviewed {args.spec_sha256}"
            )
        spec = json.loads(args.spec.read_text())
        registry = spec.get("registry")
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
            outcome = {
                "name": step["name"],
                "verdict": "unrun",
                "reason": "sources or registry not ready",
            }
            result["steps"].append(outcome)
            results[step["name"]] = outcome
            if ready:
                run_step(step, results, paths, outcome, record)
            record()
    except Exception as error:  # The run's record survives the runner's own failure.
        result["error"] = f"{type(error).__name__}: {error}"
        listed = {step["name"] for step in result["steps"]}
        for step in spec["steps"]:
            if step.get("name") not in listed:
                result["steps"].append(
                    {
                        "name": step.get("name"),
                        "verdict": "unrun",
                        "reason": "the runner stopped",
                    }
                )
    finally:
        if result["registry"] and result["registry"]["started"]:
            removed = run(["docker", "rm", "-f", registry["name"]])
            result["registry"]["removed"] = removed.returncode == 0
        record()
    green = (
        result["error"] is None
        and bool(spec["steps"])
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
