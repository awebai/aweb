#!/usr/bin/env bash
# Copy canonical skill bodies from ../../skills into ./skills.
# Run before committing changes to packages/codex-plugin/ or aweb/skills/
# so the Codex plugin ships current bodies.
#
# Codex's plugin installer does not follow symlinks, and manifest paths must
# stay inside the plugin root — so we copy rather than symlink.
set -euo pipefail
cd "$(dirname "$0")"
rm -rf skills
mkdir skills
for name in aweb-coordination aweb-messaging aweb-team-membership aweb-bootstrap; do
  cp -R "../../skills/$name" "skills/$name"
done
echo "Synced $(ls skills | wc -l | tr -d ' ') skill(s) into packages/codex-plugin/skills/"
