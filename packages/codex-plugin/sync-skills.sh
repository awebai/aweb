#!/usr/bin/env bash
# Copy the default customer skill bodies from ../../skills into ./skills.
# Invoked by make sync-doc-copies and the ordinary/candidate builds.
# Commit the generated files for source-based Codex installs.
#
# Codex's plugin installer does not follow symlinks, and manifest paths must
# stay inside the plugin root — so we copy rather than symlink.
set -euo pipefail
cd "$(dirname "$0")"
rm -rf skills
mkdir skills
for name in aweb-coordination aweb-messaging aweb-team-membership aweb-bootstrap aweb-identity; do
  cp -R "../../skills/$name" "skills/$name"
done
echo "Synced $(ls skills | wc -l | tr -d ' ') skill(s) into packages/codex-plugin/skills/"
