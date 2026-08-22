#!/usr/bin/env python3
"""Generate the public CLI reference from the live Cobra command tree."""

from __future__ import annotations

import argparse
import collections
import subprocess
import sys
from pathlib import Path
from typing import Sequence


class RootCoverageError(RuntimeError):
    """The rendered root-command inventory disagrees with Cobra completion."""


def run_help(binary: Path, path: Sequence[str]) -> str:
    result = subprocess.run(
        [str(binary), *path, "--help"],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def parse_items(lines: list[str], start: int) -> tuple[list[tuple[str, str]], int]:
    items: list[tuple[str, str]] = []
    index = start
    while index < len(lines):
        line = lines[index]
        if not line.startswith("  ") or not line.strip():
            break
        parts = line.strip().split(None, 1)
        items.append((parts[0], parts[1] if len(parts) > 1 else ""))
        index += 1
    return items, index


def parse_flags(lines: list[str], start: int) -> tuple[list[str], int]:
    flags: list[str] = []
    index = start
    while index < len(lines):
        line = lines[index]
        if not line.startswith("  ") or not line.strip():
            break
        stripped = line.strip()
        columns = stripped.split("  ", 1)
        flags.append(" ".join(part.strip() for part in columns if part.strip()))
        index += 1
    return flags, index


def parse_help(text: str) -> dict[str, object]:
    lines = text.splitlines()
    usage_index = next(
        (index for index, line in enumerate(lines) if line.strip() == "Usage:"),
        len(lines),
    )
    description = "\n".join(lines[:usage_index]).strip()
    usage = ""
    subcommands: list[tuple[str, str]] = []
    flags: list[str] = []
    groups: list[tuple[str, list[tuple[str, str]]]] = []
    index = usage_index
    while index < len(lines):
        stripped = lines[index].strip()
        if stripped == "Usage:" and index + 1 < len(lines):
            usage = lines[index + 1].strip()
            index += 2
            continue
        if stripped == "Available Commands:":
            subcommands, index = parse_items(lines, index + 1)
            continue
        if stripped == "Additional Commands:":
            items, index = parse_items(lines, index + 1)
            groups.append(("Additional Commands", items))
            continue
        if stripped in {"Flags:", "Global Flags:"}:
            section = stripped[:-1]
            section_flags, index = parse_flags(lines, index + 1)
            if section == "Flags":
                flags = section_flags
            continue
        if (
            lines[index]
            and not lines[index].startswith(" ")
            and not stripped.endswith(":")
            and index + 1 < len(lines)
            and lines[index + 1].startswith("  ")
        ):
            items, next_index = parse_items(lines, index + 1)
            if items:
                groups.append((lines[index].strip(), items))
                index = next_index
                continue
        index += 1
    return {
        "description": description,
        "usage": usage,
        "subcommands": subcommands,
        "flags": flags,
        "groups": groups,
    }


def visible_root_commands(binary: Path) -> list[str]:
    result = subprocess.run(
        [str(binary), "__complete", ""],
        check=True,
        capture_output=True,
        text=True,
    )
    commands: list[str] = []
    for line in result.stdout.splitlines():
        if "\t" not in line:
            continue
        name, _ = line.split("\t", 1)
        if name:
            commands.append(name)
    if not commands:
        raise RootCoverageError("Cobra completion returned no visible root commands")
    return commands


def validate_root_coverage(
    rendered_commands: Sequence[str], visible_commands: Sequence[str]
) -> None:
    duplicates = sorted(
        name
        for name, count in collections.Counter(rendered_commands).items()
        if count > 1
    )
    if duplicates:
        raise RootCoverageError(
            "root command rendered more than once: " + ", ".join(duplicates)
        )
    rendered = set(rendered_commands)
    visible = set(visible_commands)
    missing = sorted(visible - rendered)
    ghost = sorted(rendered - visible)
    if missing:
        raise RootCoverageError(
            "visible root command not rendered: " + ", ".join(missing)
        )
    if ghost:
        raise RootCoverageError(
            "rendered root command absent from completion: " + ", ".join(ghost)
        )


def command_path(items: Sequence[tuple[str, str]]) -> list[str]:
    return [name for name, _ in items]


def render_reference(binary: Path) -> str:
    root_help = parse_help(run_help(binary, []))
    root_groups = root_help["groups"]
    assert isinstance(root_groups, list)
    root_subcommands = root_help["subcommands"]
    assert isinstance(root_subcommands, list)

    rendered_roots: list[str] = []
    for _, items in root_groups:
        rendered_roots.extend(command_path(items))
    rendered_roots.extend(command_path(root_subcommands))
    validate_root_coverage(rendered_roots, visible_root_commands(binary))

    output: list[str] = [
        "---",
        'title: "CLI command reference"',
        'kicker: "Reference"',
        'description: "Every aw command and flag, generated from the live help tree of the shipped binary."',
        "weight: 90",
        "---",
        "",
        "# CLI Command Reference",
        "",
        "This reference is generated from the live Cobra help tree emitted by the",
        "`aw` binary built from [`cli/go/cmd/aw/`](../cli/go/cmd/aw). Run",
        "[`scripts/regenerate-cli-reference.sh`](../scripts/regenerate-cli-reference.sh)",
        "to refresh it.",
        "",
        "## Command Families",
        "",
        "| Family | Commands |",
        "| --- | --- |",
    ]
    for title, items in root_groups:
        commands = ", ".join(f"`{name}`" for name, _ in items)
        output.append(f"| {title} | {commands} |")
    if root_subcommands:
        commands = ", ".join(f"`{name}`" for name, _ in root_subcommands)
        output.append(f"| Available Commands | {commands} |")

    output.extend(["", "## Global Flags", ""])
    for flag in root_help["flags"]:
        output.append(f"- `{flag}`")

    def emit_tree(path: list[str]) -> None:
        parsed = parse_help(run_help(binary, path))
        title = " ".join(path)
        output.extend(["", f"## `{title}`", "", f"### `{title}`", ""])
        description = str(parsed["description"])
        if description:
            output.extend([description, ""])
        subcommands = parsed["subcommands"]
        assert isinstance(subcommands, list)
        groups = parsed["groups"]
        assert isinstance(groups, list)
        grouped_subcommands = [item for _, items in groups for item in items]
        all_subcommands = [*grouped_subcommands, *subcommands]
        # Cobra's generated `aw help --help` prints the root help page. Those
        # root groups are not children of the help command and recursing through
        # them would produce an infinite `aw help help ...` tree.
        if path == ["help"]:
            all_subcommands = []
        if all_subcommands:
            output.append("Subcommands:")
            for name, description in all_subcommands:
                suffix = f" {description}" if description else ""
                output.append(f"- `{name}`{suffix}")
            output.append("")
        flags = parsed["flags"]
        assert isinstance(flags, list)
        if flags:
            output.append("Flags:")
            for flag in flags:
                output.append(f"- `{flag}`")
        for name, _ in all_subcommands:
            emit_tree([*path, name])

    for name in rendered_roots:
        emit_tree([name])

    return "\n".join(output).rstrip() + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    generated = render_reference(args.binary)
    if args.check:
        if not args.output.exists() or args.output.read_text() != generated:
            print(
                "CLI command reference is stale; run make regenerate-cli-reference",
                file=sys.stderr,
            )
            return 1
        print("CLI command reference is up to date")
        return 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(generated)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
