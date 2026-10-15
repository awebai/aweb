#!/usr/bin/env bash
# Copy every canonical skill directory from ../../skills into ./skills.
# Invoked by make sync-doc-copies and the ordinary/candidate builds.
# Commit the generated files for source-based Codex installs.
#
# Codex's plugin installer does not follow symlinks, and manifest paths must
# stay inside the plugin root — so we copy rather than symlink.
set -euo pipefail
cd "$(dirname "$0")"
entries=(../../skills/*/SKILL.md)
if [ ! -f "${entries[0]}" ]; then
  echo "ERROR: no canonical skills found under ../../skills" >&2
  exit 1
fi
rm -rf skills
mkdir skills
for entry in "${entries[@]}"; do
  source_skill="${entry%/SKILL.md}"
  name="${source_skill##*/}"
  cp -R "$source_skill" "skills/$name"
done
echo "Synced ${#entries[@]} skill(s) into packages/codex-plugin/skills/"
