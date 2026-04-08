#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path


SKIP_DIRS = {
    ".git",
    "node_modules",
    "dist",
    "build",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".cache",
}


FORBIDDEN_SUBSTRINGS: list[tuple[str, str]] = [
    ("api.aweb.ai", "api.aweb.ai has no DNS; use https://app.aweb.ai/api"),
    ("~/.aw/config.yaml", "aw config lives at ~/.config/aw/config.yaml (not ~/.aw/config.yaml)"),
    ("aw init --project-slug", "aw init does not accept project_slug; project comes from the project-scoped API key"),
    ("aw init --project ", "aw init does not accept --project; project comes from the project-scoped API key"),
    ("aw init --namespace", "aw init does not accept --namespace; project comes from the project-scoped API key"),
    ("aw init --" + "cloud-url", "aw init flag is --url"),
    ("aw init --" + "awid-url", "aw init no longer accepts the old registry override flag"),
]


def iter_text_files(root: Path) -> list[Path]:
    out: list[Path] = []
    for path in root.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if not path.is_file():
            continue
        if path.suffix.lower() in {".md", ".txt"}:
            out.append(path)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Fail if known-bad doc strings reappear.")
    parser.add_argument("--root", default=".", help="Repo root (default: .)")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    files = iter_text_files(root)

    failures: list[str] = []
    for file_path in files:
        try:
            data = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            failures.append(f"{file_path}: failed to read: {exc}")
            continue

        for needle, help_text in FORBIDDEN_SUBSTRINGS:
            if needle in data:
                failures.append(f"{file_path}: contains {needle!r} ({help_text})")

    if failures:
        print("Doc regression check failed:\n", file=sys.stderr)
        for line in failures:
            print(f"- {line}", file=sys.stderr)
        return 1

    print(f"OK: scanned {len(files)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
