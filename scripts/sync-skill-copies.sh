#!/usr/bin/env bash
# Generate self-contained runtime skills from the canonical skills/ tree.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

bash "$ROOT/packages/codex-plugin/sync-skills.sh"

source_skill="$ROOT/skills/aweb-coordination"
target_skill="$ROOT/oats/.agents/capabilities/owned/aweb-tasks/skills/aweb-coordination"
test -f "$source_skill/SKILL.md"
mkdir -p "$(dirname "$target_skill")"
rm -rf "$target_skill"
cp -R "$source_skill" "$target_skill"
echo "Generated the OATS aweb.tasks skill from skills/aweb-coordination"
