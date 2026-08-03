#!/usr/bin/env python3
"""Fail-closed accounting for Go source inventory and structured test results.

The default suite rejects skips when the canonical ship target selects its Linux
release policy. The separately tagged e2e suite is always exact and skip-free.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


POLICY_PATH = Path("scripts/go_test_accounting_policy.json")
SKIP_RE = re.compile(r"\bt\.(Skip|Skipf|SkipNow)\s*\((.*)\)")
FUNC_RE = re.compile(r"^func\s+([A-Za-z0-9_]+)\s*\(")
BUILD_RE = re.compile(r"^//go:build\s+(.+)$")
LEGACY_BUILD_RE = re.compile(r"^// \+build\s+(.+)$")
KNOWN_ACTIONS = {"start", "run", "pause", "cont", "pass", "bench", "fail", "output", "skip"}


class AccountingError(RuntimeError):
    pass


@dataclass(frozen=True)
class ParseSummary:
    packages_passed: int
    required_tests_passed: int


def load_policy(repo_root: Path) -> dict[str, Any]:
    path = repo_root / POLICY_PATH
    try:
        policy = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AccountingError(f"cannot load Go test accounting policy {path}: {exc}") from exc
    if policy.get("schema_version") != 1:
        raise AccountingError(f"unsupported Go test accounting policy schema: {policy.get('schema_version')!r}")
    return policy


def _runtime_skip_inventory(repo_root: Path) -> list[dict[str, str]]:
    inventory: list[dict[str, str]] = []
    go_root = repo_root / "cli" / "go"
    if not go_root.is_dir():
        raise AccountingError(f"Go source root is missing: {go_root}")
    for path in sorted(go_root.rglob("*.go")):
        lines = path.read_text(encoding="utf-8").splitlines()
        functions: list[tuple[int, str]] = []
        for index, line in enumerate(lines):
            match = FUNC_RE.match(line)
            if match:
                functions.append((index, match.group(1)))
        for index, line in enumerate(lines):
            match = SKIP_RE.search(line)
            if not match:
                continue
            function = next(
                (name for line_index, name in reversed(functions) if line_index < index),
                "<package>",
            )
            guard = next(
                (lines[prior].strip() for prior in range(index - 1, -1, -1) if lines[prior].strip()),
                "",
            )
            inventory.append(
                {
                    "path": path.relative_to(repo_root).as_posix(),
                    "function": function,
                    "guard": guard,
                    "call": f"{match.group(1)}({match.group(2)})",
                }
            )
    return inventory


def _build_constraint_inventory(repo_root: Path) -> list[dict[str, str]]:
    inventory: list[dict[str, str]] = []
    for path in sorted((repo_root / "cli" / "go").rglob("*.go")):
        for line in path.read_text(encoding="utf-8").splitlines()[:10]:
            match = BUILD_RE.match(line)
            if match:
                inventory.append(
                    {
                        "path": path.relative_to(repo_root).as_posix(),
                        "constraint": match.group(1),
                    }
                )
            legacy = LEGACY_BUILD_RE.match(line)
            if legacy:
                inventory.append(
                    {
                        "path": path.relative_to(repo_root).as_posix(),
                        "constraint": "legacy:" + legacy.group(1),
                    }
                )
    return inventory


def _linux_default_includes(constraint: str | None) -> bool:
    if constraint is None:
        return True
    decisions = {
        "!windows": True,
        "!awebtestpinstorecasbarrier": True,
        "windows": False,
        "e2e": False,
        "awebtestpinstorecasbarrier": False,
    }
    if constraint not in decisions:
        raise AccountingError(
            f"unclassified Go build constraint {constraint!r}; add it to the inventory and Linux selector"
        )
    return decisions[constraint]


def _linux_default_packages(repo_root: Path, module: str) -> list[str]:
    go_root = repo_root / "cli" / "go"
    packages: list[str] = []
    directories = sorted({path.parent for path in go_root.rglob("*.go")})
    for directory in directories:
        included = False
        for path in directory.glob("*.go"):
            constraint = None
            for line in path.read_text(encoding="utf-8").splitlines()[:10]:
                match = BUILD_RE.match(line)
                if match:
                    constraint = match.group(1)
                    break
            if _linux_default_includes(constraint):
                included = True
                break
        if included:
            relative = directory.relative_to(go_root).as_posix()
            packages.append(module if relative == "." else f"{module}/{relative}")
    return packages


def _project(items: Sequence[Mapping[str, Any]], keys: Sequence[str]) -> list[dict[str, Any]]:
    return [{key: item[key] for key in keys} for item in items]


def _assert_exact_inventory(label: str, actual: list[dict[str, Any]], expected: list[dict[str, Any]]) -> None:
    if actual == expected:
        return
    actual_lines = {json.dumps(item, sort_keys=True) for item in actual}
    expected_lines = {json.dumps(item, sort_keys=True) for item in expected}
    added = sorted(actual_lines - expected_lines)
    missing = sorted(expected_lines - actual_lines)
    details = []
    if added:
        details.append("unaccounted: " + "; ".join(added))
    if missing:
        details.append("no longer present: " + "; ".join(missing))
    raise AccountingError(f"{label} differs from policy ({' | '.join(details)})")


def verify_source_inventory(repo_root: Path, policy: Mapping[str, Any]) -> None:
    runtime_keys = ("path", "function", "guard", "call")
    actual_runtime = _runtime_skip_inventory(repo_root)
    expected_runtime = _project(policy["runtime_skips"], runtime_keys)
    _assert_exact_inventory("runtime skip inventory", actual_runtime, expected_runtime)

    build_keys = ("path", "constraint")
    actual_builds = _build_constraint_inventory(repo_root)
    expected_builds = _project(policy["build_constraints"], build_keys)
    _assert_exact_inventory("build-constraint inventory", actual_builds, expected_builds)

    counts = policy["inventory_counts"]
    classified_default = sum(
        item["classification"] == "mandatory_linux" for item in policy["runtime_skips"]
    )
    classified_e2e = sum(
        item["classification"] == "separately_exercised_e2e" for item in policy["runtime_skips"]
    )
    measured = {
        "runtime_skip_sites": len(actual_runtime),
        "default_linux_runtime_skip_sites": classified_default,
        "separately_exercised_runtime_skip_sites": classified_e2e,
        "build_constraints": len(actual_builds),
        "default_packages": len(policy["suites"]["default"]["packages"]),
        "default_required_tests": len(policy["suites"]["default"]["required_tests"]),
        "e2e_packages": len(policy["suites"]["e2e"]["packages"]),
        "e2e_required_tests": len(policy["suites"]["e2e"]["required_tests"]),
    }
    if measured != counts:
        raise AccountingError(f"inventory counts differ from their measured values: {measured!r} != {counts!r}")

    actual_packages = _linux_default_packages(repo_root, policy["module"])
    expected_packages = policy["suites"]["default"]["packages"]
    if actual_packages != expected_packages:
        raise AccountingError(
            f"default Linux package inventory differs from policy: {actual_packages!r} != {expected_packages!r}"
        )

    all_functions: dict[str, set[str]] = {}
    go_root = repo_root / "cli" / "go"
    for path in go_root.rglob("*.go"):
        package = policy["module"]
        relative = path.parent.relative_to(go_root).as_posix()
        if relative != ".":
            package += f"/{relative}"
        all_functions.setdefault(package, set()).update(
            match.group(1)
            for line in path.read_text(encoding="utf-8").splitlines()
            if (match := FUNC_RE.match(line))
        )
    for suite_name, suite in policy["suites"].items():
        for required in suite["required_tests"]:
            if required["name"] not in all_functions.get(required["package"], set()):
                raise AccountingError(
                    f"{suite_name} required test is absent from source: "
                    f"{required['package']} {required['name']}"
                )

    e2e_package = policy["suites"]["e2e"]["packages"][0]
    actual_e2e_tests = sorted(
        name for name in all_functions.get(e2e_package, set()) if name.startswith("Test")
    )
    expected_e2e_tests = sorted(
        item["name"] for item in policy["suites"]["e2e"]["required_tests"]
    )
    if actual_e2e_tests != expected_e2e_tests:
        raise AccountingError(
            "e2e required-test inventory differs from tagged source: "
            f"{actual_e2e_tests!r} != {expected_e2e_tests!r}"
        )

    for item in policy["build_constraints"]:
        if item["linux_default"] not in ("included", "excluded"):
            raise AccountingError(f"invalid linux_default classification for {item['path']}")
        if not item.get("owner") or not item.get("reason"):
            raise AccountingError(f"build constraint lacks owner/reason: {item['path']}")
    for item in policy["runtime_skips"]:
        if item["classification"] != "mandatory_linux" and (
            not item.get("owner") or not item.get("reason")
        ):
            raise AccountingError(f"non-mandatory runtime skip lacks owner/reason: {item['path']}")


def verify_invocation_wiring(repo_root: Path) -> None:
    makefile = (repo_root / "Makefile").read_text(encoding="utf-8")
    e2e = (repo_root / "cli" / "scripts" / "e2e.sh").read_text(encoding="utf-8")
    ship_workflow = (repo_root / ".github" / "workflows" / "ship.yml").read_text(encoding="utf-8")
    cli_workflow = (repo_root / ".github" / "workflows" / "cli-e2e.yml").read_text(encoding="utf-8")

    required_once = (
        (
            makefile,
            "python3 scripts/check_go_test_accounting.py run --suite default -- "
            "go test -json ./... -count=1",
            "test-cli must use the accounted default invocation",
        ),
        (
            makefile,
            "ship: override AW_GO_TEST_RELEASE_PLATFORM := linux-amd64",
            "ship must select the non-overridable strict final-Linux policy",
        ),
        (
            makefile,
            'AW_GO_TEST_RELEASE_PLATFORM="$(AW_GO_TEST_RELEASE_PLATFORM)"',
            "test-cli must pass the inherited ship policy into the parser process",
        ),
        (
            e2e,
            'python3 "$REPO_ROOT/scripts/check_go_test_accounting.py" run --suite e2e -- '
            "go test -json -tags e2e ./e2e -count=1",
            "cli e2e must use the accounted exact tagged invocation",
        ),
        (ship_workflow, "run: make ship", "the ship workflow must run the canonical gate"),
        (cli_workflow, "run: make -C cli e2e", "the separate e2e workflow must run the exact e2e gate"),
    )
    for text, anchor, message in required_once:
        if text.count(anchor) != 1:
            raise AccountingError(f"{message}; expected exactly one {anchor!r}")


def verify_command(command: Sequence[str], policy: Mapping[str, Any], suite: str) -> None:
    expected = policy["suites"][suite]["command"]
    if list(command) != expected:
        raise AccountingError(
            f"{suite} exact invocation differs from policy: {list(command)!r} != {expected!r}"
        )


def verify_release_preconditions(
    policy: Mapping[str, Any], *, system: str, machine: str, effective_uid: int, path: str
) -> None:
    required = policy["release_preconditions"]
    if system != required["system"]:
        raise AccountingError(f"release Go accounting requires {required['system']}, found {system}")
    if machine not in required["machines"]:
        raise AccountingError(
            f"release Go accounting requires one of {required['machines']!r}, found {machine}"
        )
    forbidden_uid = required["effective_uid_must_not_be"]
    if effective_uid == forbidden_uid:
        raise AccountingError(
            f"release Go accounting cannot run as effective uid {forbidden_uid}; permission tests would skip"
        )
    missing = [tool for tool in required["tools"] if shutil.which(tool, path=path) is None]
    if missing:
        raise AccountingError(
            "release Go accounting missing mandatory tool precondition(s): " + ", ".join(missing)
        )


def parse_json_stream(
    text: str, policy: Mapping[str, Any], suite: str, *, reject_skips: bool
) -> ParseSummary:
    if not text.endswith("\n"):
        raise AccountingError("malformed go test JSON: truncated final line (missing newline)")
    spec = policy["suites"][suite]
    expected_packages = set(spec["packages"])
    package_started: set[str] = set()
    package_terminal: dict[str, str] = {}
    test_run: set[tuple[str, str]] = set()
    test_terminal: dict[tuple[str, str], str] = {}

    for line_number, line in enumerate(text.splitlines(), 1):
        if not line:
            raise AccountingError(f"malformed go test JSON at line {line_number}: blank record")
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise AccountingError(f"malformed go test JSON at line {line_number}: {exc.msg}") from exc
        if not isinstance(event, dict):
            raise AccountingError(f"malformed go test JSON at line {line_number}: record is not an object")
        action = event.get("Action")
        package = event.get("Package")
        if action not in KNOWN_ACTIONS or not isinstance(package, str):
            raise AccountingError(
                f"malformed go test JSON at line {line_number}: missing/unknown Action or Package"
            )
        if package not in expected_packages:
            raise AccountingError(f"unexpected package in go test JSON: {package}")
        test = event.get("Test")
        if test is not None and not isinstance(test, str):
            raise AccountingError(f"malformed go test JSON at line {line_number}: Test is not a string")

        if action == "start" and test is None:
            if package in package_started:
                raise AccountingError(f"duplicate package start result: {package}")
            package_started.add(package)
        if action in ("pass", "fail", "skip"):
            if test is None:
                if package in package_terminal:
                    raise AccountingError(f"duplicate package terminal result: {package}")
                package_terminal[package] = action
            else:
                key = (package, test)
                if key in test_terminal:
                    raise AccountingError(f"duplicate test terminal result: {package} {test}")
                test_terminal[key] = action
        if action == "run" and test is not None:
            test_run.add((package, test))
        if action == "fail":
            subject = f"{package} {test}" if test else package
            raise AccountingError(f"go test JSON reports failure: {subject}")
        if action == "skip" and reject_skips:
            subject = f"{package} {test}" if test else package
            raise AccountingError(f"unexpected test skip in accounted {suite} suite: {subject}")

    missing_packages = expected_packages - package_started
    if missing_packages:
        raise AccountingError(f"missing package start result(s): {sorted(missing_packages)!r}")
    missing_terminal = expected_packages - package_terminal.keys()
    if missing_terminal:
        raise AccountingError(f"missing package terminal result(s): {sorted(missing_terminal)!r}")
    bad_packages = {
        package: action for package, action in package_terminal.items() if action != "pass"
    }
    if bad_packages:
        raise AccountingError(f"package result was not pass: {bad_packages!r}")

    required_passed = 0
    if reject_skips:
        for required in spec["required_tests"]:
            key = (required["package"], required["name"])
            if key not in test_run or test_terminal.get(key) != "pass":
                raise AccountingError(
                    f"required test lacks exact run/pass result: {required['package']} {required['name']}"
                )
            required_passed += 1
    return ParseSummary(len(package_terminal), required_passed)


def run_accounted_command(
    repo_root: Path,
    policy: Mapping[str, Any],
    suite: str,
    command: Sequence[str],
    *,
    release_platform: str,
    env: Mapping[str, str] | None = None,
) -> ParseSummary:
    verify_source_inventory(repo_root, policy)
    verify_invocation_wiring(repo_root)
    verify_command(command, policy, suite)
    if release_platform not in ("", policy["release_platform"]):
        raise AccountingError(
            f"unknown requested release platform {release_platform!r}; expected {policy['release_platform']!r}"
        )
    strict = suite == "e2e" or release_platform == policy["release_platform"]
    process_env = dict(os.environ if env is None else env)
    if release_platform:
        geteuid = getattr(os, "geteuid", lambda: -1)
        verify_release_preconditions(
            policy,
            system=platform.system(),
            machine=platform.machine(),
            effective_uid=geteuid(),
            path=process_env.get("PATH", ""),
        )
    cwd = repo_root / "cli" / "go"
    try:
        process = subprocess.Popen(
            list(command),
            cwd=cwd,
            env=process_env,
            stdout=subprocess.PIPE,
            stderr=None,
            text=True,
        )
    except OSError as exc:
        raise AccountingError(f"could not start accounted {suite} Go test invocation: {exc}") from exc
    assert process.stdout is not None
    chunks: list[str] = []
    for chunk in iter(process.stdout.readline, ""):
        chunks.append(chunk)
        sys.stdout.write(chunk)
        sys.stdout.flush()
    process.stdout.close()
    status = process.wait()
    summary = parse_json_stream("".join(chunks), policy, suite, reject_skips=strict)
    if status != 0:
        raise AccountingError(f"accounted {suite} Go test invocation exited {status}")
    return summary


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    subparsers.add_parser("check-source")
    subparsers.add_parser("check-wiring")
    run = subparsers.add_parser("run")
    run.add_argument("--suite", choices=("default", "e2e"), required=True)
    run.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)

    repo_root = _repo_root()
    try:
        policy = load_policy(repo_root)
        if args.action == "check-source":
            verify_source_inventory(repo_root, policy)
            print("Go test source inventory matches policy")
        elif args.action == "check-wiring":
            verify_invocation_wiring(repo_root)
            print("Go test invocation wiring matches policy")
        else:
            command = args.command[1:] if args.command[:1] == ["--"] else args.command
            release_platform = os.environ.get("AW_GO_TEST_RELEASE_PLATFORM", "")
            summary = run_accounted_command(
                repo_root,
                policy,
                args.suite,
                command,
                release_platform=release_platform,
            )
            print(
                f"accounted {args.suite} Go suite passed: "
                f"{summary.packages_passed} package(s), "
                f"{summary.required_tests_passed} mandatory test result(s)"
            )
        return 0
    except AccountingError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
