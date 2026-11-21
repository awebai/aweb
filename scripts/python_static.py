"""Run package-owned Python checks and enforce reviewed diagnostic ceilings."""

from __future__ import annotations

import argparse
import ast
import importlib.metadata
import json
import subprocess
import sys
import tokenize
from collections import Counter
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

import tomllib


class Tool(StrEnum):
    RUFF = "ruff"
    MYPY = "mypy"


class MypyDiagnosticSeverity(StrEnum):
    ERROR = "error"
    NOTE = "note"


class SourceSuppressionCode(StrEnum):
    TYPE_IGNORE = "source-type-ignore"
    MYPY_DIRECTIVE = "source-mypy-directive"


VERSIONS = {Tool.RUFF: "0.15.0", Tool.MYPY: "1.19.1"}
PACKAGES = ("server", "awid")
SOURCE_ROOTS = {
    "server": ["src/aweb"],
    "awid": ["src/awid", "src/awid_service"],
}
CEILINGS_PATH = Path("tools/python-static-ceilings.json")
RECOVERY = "Fix the reported findings and lower cleared ceilings in the same change."
SETUP_RECOVERY = "Prepare the frozen package environments and correct the reported configuration, then run make check-python-static."


class StaticCheckError(Exception):
    """A tool, configuration or diagnostic protocol failed before comparison."""


@dataclass(frozen=True, order=True)
class DiagnosticGroup:
    tool: Tool
    file: str
    code: str


@dataclass(frozen=True)
class Package:
    directory: Path
    interpreter: Path


def read_json(path: Path) -> object:
    try:
        return json.loads(path.read_text())
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise StaticCheckError(f"cannot read {path}: {exc}") from exc


def diagnostic_group(value: object) -> DiagnosticGroup:
    if not isinstance(value, dict) or set(value) != {"tool", "file", "code", "count"}:
        raise StaticCheckError("each ceiling needs exactly tool, file, code and count")
    tool, file, code = value["tool"], value["file"], value["code"]
    if not isinstance(tool, str) or tool not in VERSIONS:
        raise StaticCheckError("ceiling tool must be ruff or mypy")
    if not isinstance(file, str) or not isinstance(code, str) or not code:
        raise StaticCheckError("ceiling file and code must be nonempty strings")
    path = Path(file)
    if (
        path.is_absolute()
        or ".." in path.parts
        or not path.parts
        or path.parts[0] not in PACKAGES
        or path.as_posix() != file
        or path.suffix != ".py"
        or any(character in file for character in "*?[]\\")
    ):
        raise StaticCheckError(
            f"ceiling path must name a Python file in a checked package: {file}"
        )
    return DiagnosticGroup(tool=Tool(tool), file=file, code=code)


def parse_ceilings(value: object) -> dict[DiagnosticGroup, int]:
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "versions",
        "groups",
    }:
        raise StaticCheckError(
            "ceilings need exactly schema_version, versions and groups"
        )
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise StaticCheckError("ceiling schema_version must be integer 1")
    if value["versions"] != VERSIONS:
        raise StaticCheckError("ceiling tool versions must match the pinned tools")
    groups = value["groups"]
    if not isinstance(groups, list):
        raise StaticCheckError("ceiling groups must be a list")
    ceilings: dict[DiagnosticGroup, int] = {}
    for value in groups:
        group = diagnostic_group(value)
        # diagnostic_group checks the mapping's shape; check count independently.
        if not isinstance(value, dict):
            raise StaticCheckError("ceiling group must be an object")
        count = value["count"]
        if type(count) is not int or count < 1:
            raise StaticCheckError(
                "ceiling count must be a positive integer; remove cleared groups"
            )
        if group in ceilings:
            raise StaticCheckError(f"duplicate ceiling for {group}")
        ceilings[group] = count
    return ceilings


def load_ceilings(path: Path) -> dict[DiagnosticGroup, int]:
    return parse_ceilings(read_json(path))


def prior_ceilings(root: Path) -> dict[DiagnosticGroup, int] | None:
    """Compare reviewed allowances with synchronized main, without fetching."""
    reference = "refs/remotes/origin/main"
    commands = [
        ["git", "rev-parse", "--verify", reference],
        ["git", "ls-tree", "--name-only", reference, "--", CEILINGS_PATH.as_posix()],
    ]
    try:
        for command in commands:
            result = subprocess.run(
                command, cwd=root, capture_output=True, text=True, timeout=10
            )
            if result.returncode:
                raise StaticCheckError(
                    f"cannot inspect synchronized main ceilings: {result.stderr}"
                )
        if not result.stdout.strip():
            # The first reviewed baseline bootstraps this owner on main.
            return None
        result = subprocess.run(
            ["git", "show", f"{reference}:{CEILINGS_PATH.as_posix()}"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode:
            raise StaticCheckError(
                f"cannot read synchronized main ceilings: {result.stderr}"
            )
        value = json.loads(result.stdout)
    except (
        OSError,
        UnicodeError,
        subprocess.TimeoutExpired,
        json.JSONDecodeError,
    ) as exc:
        raise StaticCheckError(f"cannot compare reviewed ceilings: {exc}") from exc
    return parse_ceilings(value)


def verify_versions() -> None:
    for tool, expected in VERSIONS.items():
        try:
            actual = importlib.metadata.version(tool)
        except importlib.metadata.PackageNotFoundError as exc:
            raise StaticCheckError(f"missing pinned {tool}") from exc
        if actual != expected:
            raise StaticCheckError(f"{tool} version {actual}; expected {expected}")


def verify_package_configuration(package: Package) -> None:
    """Require the shared floor while allowing a package's stronger rules."""
    path = package.directory / "pyproject.toml"
    try:
        config = tomllib.loads(path.read_text()).get("tool")
    except (OSError, UnicodeError, tomllib.TOMLDecodeError, KeyError, TypeError) as exc:
        raise StaticCheckError(
            f"invalid package check configuration {path}: {exc}"
        ) from exc
    if not isinstance(config, dict):
        raise StaticCheckError(f"{path}: tool configuration must be a table")
    ruff, mypy = config.get("ruff"), config.get("mypy")
    if not isinstance(ruff, dict) or not isinstance(mypy, dict):
        raise StaticCheckError(f"{path}: Ruff and mypy configuration must be tables")
    lint = ruff.get("lint")
    if not isinstance(lint, dict):
        raise StaticCheckError(f"{path}: Ruff lint configuration must be a table")
    selected_values = lint.get("select")
    extended_values = lint.get("extend-select", [])
    if (
        not isinstance(selected_values, list)
        or not isinstance(extended_values, list)
        or any(
            not isinstance(value, str) for value in [*selected_values, *extended_values]
        )
    ):
        raise StaticCheckError(f"{path}: Ruff rule selections must be string lists")
    selected = set(selected_values) | set(extended_values)
    if ruff.get("target-version") != "py312" or not {"F", "B", "BLE"}.issubset(
        selected
    ):
        raise StaticCheckError(f"{path}: Ruff must target py312 and select F/B/BLE")
    if not ("E" in selected or {"E4", "E7", "E9"}.issubset(selected)):
        raise StaticCheckError(f"{path}: Ruff must select E or E4/E7/E9")
    if lint.get("per-file-ignores", {}) not in ({}, {"tests/**": ["F811"]}):
        raise StaticCheckError(
            f"{path}: raw scan permits only the pytest F811 exception"
        )
    if lint.get("ignore", []) not in ([], ["E501"]):
        raise StaticCheckError(f"{path}: raw scan cannot suppress defect rules")
    if lint.get("extend-ignore") or lint.get("extend-per-file-ignores"):
        raise StaticCheckError(f"{path}: raw scan cannot extend rule suppressions")
    if ruff.get("exclude") or ruff.get("extend-exclude"):
        raise StaticCheckError(f"{path}: package Python files cannot be excluded")
    if (
        str(mypy.get("python_version")) != "3.12"
        or mypy.get("check_untyped_defs") is not True
    ):
        raise StaticCheckError(
            f"{path}: mypy must target Python 3.12 and check untyped bodies"
        )
    if mypy.get("files") not in (["src"], SOURCE_ROOTS.get(package.directory.name)):
        raise StaticCheckError(
            f"{path}: mypy must cover every declared package source root"
        )
    if mypy.get("exclude") or mypy.get("exclude_gitignore"):
        raise StaticCheckError(f"{path}: mypy source roots cannot be excluded")
    if (
        mypy.get("ignore_errors")
        or mypy.get("disable_error_code")
        or mypy.get("overrides")
    ):
        raise StaticCheckError(
            f"{path}: use diagnostic ceilings instead of module/code suppressions"
        )
    if not package.interpreter.is_file():
        raise StaticCheckError(f"missing prepared interpreter: {package.interpreter}")


def run_tool(
    *, package: Package, tool: Tool, files: tuple[Path, ...] = ()
) -> subprocess.CompletedProcess[str]:
    config = package.directory / "pyproject.toml"
    targets = [str(path.relative_to(package.directory)) for path in files]
    if tool is Tool.RUFF:
        arguments = [
            "check",
            "--config",
            str(config),
            "--no-cache",
            "--ignore-noqa",
            "--output-format",
            "json",
            *(targets or ["."]),
        ]
    else:
        arguments = [
            "--config-file",
            str(config),
            "--python-executable",
            str(package.interpreter),
            "--no-incremental",
            "--no-warn-unused-ignores",
            "--output",
            "json",
            *targets,
        ]
    try:
        result = subprocess.run(
            [sys.executable, "-m", tool.value, *arguments],
            cwd=package.directory,
            capture_output=True,
            text=True,
            timeout=180,
        )
    except (OSError, UnicodeError, subprocess.TimeoutExpired) as exc:
        raise StaticCheckError(
            f"cannot run {tool} for {package.directory}: {exc}"
        ) from exc
    if result.returncode not in (0, 1):
        raise StaticCheckError(
            f"{tool} failed ({result.returncode}): {result.stderr or result.stdout}"
        )
    if result.stderr.strip():
        raise StaticCheckError(
            f"{tool} reported a configuration/runtime diagnostic: {result.stderr}"
        )
    return result


def diagnostic_path(*, root: Path, package: Package, value: object) -> str:
    if not isinstance(value, str):
        raise StaticCheckError("tool diagnostic file must be a string")
    path = Path(value)
    path = path if path.is_absolute() else package.directory / path
    try:
        relative = path.resolve().relative_to(root)
    except ValueError as exc:
        raise StaticCheckError(
            f"tool diagnostic escaped the repository: {value}"
        ) from exc
    if relative.parts[0] not in PACKAGES or relative.suffix != ".py":
        raise StaticCheckError(
            f"tool diagnostic is outside Python package scope: {value}"
        )
    return relative.as_posix()


def production_files(*, package: Package, files: tuple[Path, ...]) -> tuple[Path, ...]:
    roots = tuple(
        package.directory / path for path in SOURCE_ROOTS[package.directory.name]
    )
    return tuple(
        path for path in files if any(path.is_relative_to(root) for root in roots)
    )


def source_suppression_counts(path: Path) -> Counter[SourceSuppressionCode]:
    """Count source opt-outs (docs/python-static-analysis.md, Source exemptions)."""
    try:
        with tokenize.open(path) as stream:
            source = stream.read()
        parsed = ast.parse(source, type_comments=True)
    except (OSError, UnicodeError, SyntaxError) as exc:
        raise StaticCheckError(
            f"cannot inspect source exemptions in {path}: {exc}"
        ) from exc
    counts: Counter[SourceSuppressionCode] = Counter()
    if parsed.type_ignores:
        counts[SourceSuppressionCode.TYPE_IGNORE] = len(parsed.type_ignores)
    # Pinned mypy reads these lines lexically, even inside a multiline string.
    directives = sum(line.startswith("# mypy: ") for line in source.splitlines())
    if directives:
        counts[SourceSuppressionCode.MYPY_DIRECTIVE] = directives
    return counts


def package_source_suppressions(
    *, root: Path, package: Package, files: tuple[Path, ...]
) -> Counter[DiagnosticGroup]:
    targets = (
        production_files(package=package, files=files)
        if files
        else tuple(
            path
            for directory in SOURCE_ROOTS[package.directory.name]
            for path in sorted((package.directory / directory).rglob("*.py"))
        )
    )
    counts: Counter[DiagnosticGroup] = Counter()
    for path in targets:
        file = diagnostic_path(root=root, package=package, value=str(path))
        for code, count in source_suppression_counts(path).items():
            counts[DiagnosticGroup(tool=Tool.MYPY, file=file, code=code)] += count
    return counts


def scan_package(
    *, root: Path, package: Package, files: tuple[Path, ...] = ()
) -> Counter[DiagnosticGroup]:
    verify_package_configuration(package)
    counts = package_source_suppressions(root=root, package=package, files=files)
    for tool in Tool:
        targets = (
            production_files(package=package, files=files)
            if tool is Tool.MYPY
            else files
        )
        if files and not targets:
            continue
        result = run_tool(package=package, tool=tool, files=targets)
        try:
            values = (
                json.loads(result.stdout)
                if tool is Tool.RUFF
                else [
                    json.loads(line)
                    for line in result.stdout.splitlines()
                    if line.strip()
                ]
            )
        except json.JSONDecodeError as exc:
            raise StaticCheckError(
                f"{tool} output is not structured diagnostics: {exc}"
            ) from exc
        if not isinstance(values, list):
            raise StaticCheckError(f"{tool} diagnostics must be a list")
        error_count = 0
        for value in values:
            if not isinstance(value, dict):
                raise StaticCheckError(f"{tool} diagnostic must be an object")
            if (
                tool is Tool.MYPY
                and value.get("severity") == MypyDiagnosticSeverity.NOTE
            ):
                continue
            if (
                tool is Tool.MYPY
                and value.get("severity") != MypyDiagnosticSeverity.ERROR
            ):
                raise StaticCheckError("mypy diagnostic has unknown severity")
            code = value.get("code")
            if not isinstance(code, str) or not code:
                raise StaticCheckError(f"{tool} diagnostic has no rule code")
            file = diagnostic_path(
                root=root,
                package=package,
                value=value.get("filename" if tool is Tool.RUFF else "file"),
            )
            counts[DiagnosticGroup(tool=tool, file=file, code=code)] += 1
            error_count += 1
        if (result.returncode == 1) != (error_count > 0):
            raise StaticCheckError(
                f"{tool} exit status disagrees with its structured diagnostics"
            )
    return counts


def exceeded_ceilings(
    *, observed: Counter[DiagnosticGroup], ceilings: dict[DiagnosticGroup, int]
) -> list[str]:
    return [
        f"{group.tool} {group.file} [{group.code}]: {count} > {ceilings.get(group, 0)}"
        for group, count in sorted(observed.items())
        if count > ceilings.get(group, 0)
    ]


def requested_files(*, root: Path, paths: list[Path] | None) -> tuple[Path, ...]:
    """Select existing package files; package source roots still govern mypy."""
    selected = []
    for value in paths or []:
        try:
            path = (root / value).resolve(strict=True)
            relative = path.relative_to(root)
        except (OSError, ValueError) as exc:
            raise StaticCheckError(f"cannot select Python file {value}: {exc}") from exc
        if (
            not path.is_file()
            or path.suffix != ".py"
            or relative.parts[0] not in PACKAGES
        ):
            raise StaticCheckError(
                f"select an existing server/ or awid/ Python file: {value}"
            )
        selected.append(path)
    return tuple(dict.fromkeys(selected))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument("--ceilings", type=Path, default=CEILINGS_PATH)
    parser.add_argument("--files", type=Path, nargs="+")
    args = parser.parse_args()
    root = args.root.resolve()
    try:
        verify_versions()
        ceilings = load_ceilings(root / args.ceilings)
        files = requested_files(root=root, paths=args.files)
        observed: Counter[DiagnosticGroup] = Counter()
        for name in PACKAGES:
            directory = root / name
            selected = tuple(path for path in files if path.is_relative_to(directory))
            if files and not selected:
                continue
            observed.update(
                scan_package(
                    root=root,
                    package=Package(
                        directory=directory, interpreter=directory / ".venv/bin/python"
                    ),
                    files=selected,
                )
            )
        failures = exceeded_ceilings(observed=observed, ceilings=ceilings)
        if failures:
            print("Python static-analysis ceiling exceeded:", file=sys.stderr)
            print("\n".join(failures), file=sys.stderr)
            print(RECOVERY, file=sys.stderr)
            return 1
        previous = prior_ceilings(root)
        if previous is not None:
            increases = exceeded_ceilings(observed=Counter(ceilings), ceilings=previous)
            previous_total = sum(previous.values())
            current_total = sum(ceilings.values())
            if increases and current_total >= previous_total:
                print(
                    "Reviewed Python diagnostic ceilings cannot increase:",
                    file=sys.stderr,
                )
                print("\n".join(increases), file=sys.stderr)
                print(
                    "Restore the reviewed allowances and fix the additional findings.",
                    file=sys.stderr,
                )
                return 1
            if increases:
                print(
                    f"Reviewed allowance relocation: total {previous_total} -> {current_total} "
                    f"(decrease {previous_total - current_total})."
                )
                for group in sorted(previous.keys() | ceilings.keys()):
                    before = previous.get(group, 0)
                    after = ceilings.get(group, 0)
                    if before != after:
                        print(
                            f"{group.tool} {group.file} [{group.code}]: {before} -> {after}"
                        )
    except StaticCheckError as exc:
        print(f"Python static-analysis setup failed: {exc}", file=sys.stderr)
        print(SETUP_RECOVERY, file=sys.stderr)
        return 2
    print(
        f"Python static-analysis ceilings passed: {sum(observed.values())} diagnostics in {len(observed)} groups."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
