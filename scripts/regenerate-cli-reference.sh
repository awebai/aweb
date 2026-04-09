#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_FILE="$ROOT/docs/cli-command-reference.md"
TMP_BIN="$(mktemp "${TMPDIR:-/tmp}/aw-cli-ref.XXXXXX")"
TMP_OUT="$(mktemp "${TMPDIR:-/tmp}/aw-cli-ref-doc.XXXXXX")"
MODE="write"

cleanup() {
  rm -f "$TMP_BIN" "$TMP_OUT"
}
trap cleanup EXIT

while [[ $# -gt 0 ]]; do
  case "$1" in
    --check)
      MODE="check"
      shift
      ;;
    --output)
      OUT_FILE="$2"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

(
  cd "$ROOT/cli/go"
  go build -o "$TMP_BIN" ./cmd/aw
)

python3 - "$TMP_BIN" "$TMP_OUT" <<'PY'
import re
import subprocess
import sys
from pathlib import Path

bin_path = Path(sys.argv[1])
out_path = Path(sys.argv[2])


def run_help(path):
    cmd = [str(bin_path), *path, "--help"]
    return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout


def parse_help(text):
    lines = text.splitlines()
    sections = {
        "description": [],
        "subcommands": [],
        "flags": [],
        "groups": [],
    }
    i = 0
    while i < len(lines) and lines[i].strip() != "Usage:":
        sections["description"].append(lines[i].rstrip())
        i += 1

    def parse_command_block(start, mode):
        items = []
        j = start
        while j < len(lines):
            raw = lines[j]
            stripped = raw.strip()
            if not stripped:
                j += 1
                continue
            if not raw.startswith(" "):
                break
            if stripped.endswith(":"):
                break
            if mode == "flag":
                m = re.match(r"^\s{2,}(.+?)\s{2,}(.*)$", raw)
            else:
                m = re.match(r"^\s{2,}(\S+)\s+(.*)$", raw)
            if m:
                items.append((m.group(1), m.group(2).rstrip()))
            j += 1
        return items, j

    while i < len(lines):
        line = lines[i].rstrip()
        stripped = line.strip()

        if not stripped:
            i += 1
            continue

        if stripped == "Available Commands:":
            items, i = parse_command_block(i + 1, "command")
            sections["subcommands"] = items
            continue

        if stripped == "Flags:":
            items, i = parse_command_block(i + 1, "flag")
            sections["flags"] = [f"{name} {desc}".rstrip() for name, desc in items]
            continue

        if stripped == "Global Flags:":
            _, i = parse_command_block(i + 1, "flag")
            continue

        if not line.startswith(" ") and not stripped.endswith(":") and i + 1 < len(lines):
            nxt = lines[i + 1].rstrip().strip()
            if nxt and not nxt.endswith(":") and re.match(r"^\s{2,}\S+\s+", lines[i + 1]):
                items, i = parse_command_block(i + 1, "command")
                sections["groups"].append((stripped, items))
                continue

        i += 1

    description = "\n".join(line for line in sections["description"]).strip()
    sections["description"] = description
    return sections


root_help = parse_help(run_help([]))

command_order = []
for _, items in root_help["groups"]:
    for name, _ in items:
        command_order.append((name,))


def walk(path):
    parsed = parse_help(run_help(path))
    yield path, parsed
    children = parsed["subcommands"]
    if not path:
        children = [item for _, items in parsed["groups"] for item in items]
    for name, _ in children:
        yield from walk((*path, name))


pages = list(walk(tuple()))
by_path = {path: parsed for path, parsed in pages}

lines = [
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

for family, items in root_help["groups"]:
    commands = ", ".join(f"`{name}`" for name, _ in items)
    lines.append(f"| {family} | {commands} |")

lines.extend(["", "## Global Flags", ""])
for flag in root_help["flags"]:
    lines.append(f"- `{flag}`")

def emit_page(path, parsed):
    title = " ".join(path)
    lines.extend(["", f"## `{title}`", "", f"### `{title}`", ""])
    if parsed["description"]:
        lines.append(parsed["description"])
        lines.append("")
    if parsed["subcommands"]:
        lines.append("Subcommands:")
        for name, desc in parsed["subcommands"]:
            lines.append(f"- `{name}` {desc}")
        lines.append("")
    if parsed["flags"]:
        lines.append("Flags:")
        for flag in parsed["flags"]:
            lines.append(f"- `{flag}`")

def emit_tree(path):
    parsed = by_path[path]
    emit_page(path, parsed)
    for child_name, _ in parsed["subcommands"]:
        emit_tree((*path, child_name))

for path in command_order:
    emit_tree(path)

text = "\n".join(lines).rstrip() + "\n"
out_path.write_text(text)
PY

if [[ "$MODE" == "check" ]]; then
  if ! diff -u "$OUT_FILE" "$TMP_OUT"; then
    echo "cli command reference is out of date; run scripts/regenerate-cli-reference.sh" >&2
    exit 1
  fi
  echo "cli command reference is up to date"
else
  mv "$TMP_OUT" "$OUT_FILE"
  echo "wrote $OUT_FILE"
fi
