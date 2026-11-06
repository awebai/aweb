#!/usr/bin/env bash
# Copy each skill listed in skills/shipped.json from ../../skills into ./skills.
# Invoked by make sync-doc-copies and the ordinary/candidate builds.
# Commit the generated files for source-based Codex installs.
#
# Codex's plugin installer does not follow symlinks, and manifest paths must
# stay inside the plugin root — so we copy rather than symlink.
set -euo pipefail
cd "$(dirname "$0")"
node ../../scripts/skill-packaging.mjs sync skills
