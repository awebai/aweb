#!/usr/bin/env bash
# Generate self-contained runtime skills from the canonical skills/ tree.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

bash "$ROOT/packages/codex-plugin/sync-skills.sh"

task_skills="$(node -e 'console.log(require(process.argv[1]).skills.join("\n"))' "$ROOT/oats/.agents/capabilities/owned/aweb-tasks/oats.json")"
for path in $task_skills; do
  name="${path##*/}"
  source_skill="$ROOT/skills/$name"
  target_skill="$ROOT/oats/.agents/capabilities/owned/aweb-tasks/skills/$name"
  test -f "$source_skill/SKILL.md"
  mkdir -p "$(dirname "$target_skill")"
  rm -rf "$target_skill"
  cp -R "$source_skill" "$target_skill"
done
echo "Generated the OATS aweb.tasks skills from skills/"
