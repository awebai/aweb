#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python3 - <<'PY'
from pathlib import Path
import re
import sys

root = Path.cwd()

scan_roots = [
    "docs",
    "skills",
    ".claude/skills",
    "channel/skills",
    "packages/claude-skills/skills",
    "packages/codex-plugin/skills",
    "pi-extension/skills",
    "cli/go/cmd/aw",
]

# Normative contracts and runbooks intentionally contain blocked phrases as
# guardrails. Customer/user copy belongs elsewhere and is scanned below.
allowlisted_files = {
    Path("docs/a2a.md"),
    Path("docs/a2a-awid-publication-contract.md"),
    Path("docs/a2a-ac-managed-gateway-contract.md"),
    Path("docs/a2a-release-runbook.md"),
}

suffixes = {".md", ".txt", ".html", ".tsx", ".ts", ".go", ".yaml", ".yml", ".json"}

patterns = [
    ("verified A2A", re.compile(r"\bverified\s+A2A\b", re.IGNORECASE)),
    ("AWID-backed", re.compile(r"\bAWID-backed\b", re.IGNORECASE)),
    ("authorized for address", re.compile(r"\bauthorized\s+for\s+address\b", re.IGNORECASE)),
    (
        "hosted A2A gateway E2EE",
        re.compile(
            r"\bhosted\s+A2A\s+gateway\b[^\n.]{0,120}\b(E2EE|end[\s-]to[\s-]end\s+encrypted)\b"
            r"|\b(E2EE|end[\s-]to[\s-]end\s+encrypted)\b[^\n.]{0,120}\bhosted\s+A2A\s+gateway\b",
            re.IGNORECASE,
        ),
    ),
]

offenders: list[str] = []

for scan_root in scan_roots:
    base = root / scan_root
    if not base.exists():
        continue
    for path in sorted(p for p in base.rglob("*") if p.is_file() and p.suffix in suffixes):
        rel = path.relative_to(root)
        if rel in allowlisted_files:
            continue
        if path.name.endswith("_test.go"):
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for label, pattern in patterns:
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                snippet = " ".join(match.group(0).split())
                offenders.append(f"{rel}:{line}: {label}: {snippet!r}")

if offenders:
    print("A2A copy guardrail failed. Do not publish customer-facing A2A trust/E2EE claims before live gates:", file=sys.stderr)
    for offender in offenders:
        print(f"  {offender}", file=sys.stderr)
    sys.exit(1)

print("A2A copy guardrails passed")
PY
