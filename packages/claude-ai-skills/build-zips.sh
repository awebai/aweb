#!/usr/bin/env bash
# Build per-skill ZIPs for Claude.ai's Customize > Skills upload UI.
#
# Each ZIP contains ONE skill: SKILL.md at root + references/ subdir.
# (Claude.ai docs document one-skill-per-ZIP. Multi-skill ZIPs are
# undocumented behavior and we don't rely on them.)
#
# Output: dist/<skill-name>.zip for each canonical skill in ../../skills/.
#
# To publish: skills-release.yml workflow attaches these as GH Release
# assets on each skills-v* tag, downloadable at e.g.
# https://github.com/awebai/aweb/releases/download/skills-v0.1.0/aweb-coordination.zip
set -euo pipefail
cd "$(dirname "$0")"
rm -rf dist staging
mkdir -p dist staging

for name in aweb-coordination aweb-messaging aweb-team-membership aweb-bootstrap aweb-identity; do
  src="../../skills/$name"
  if [ ! -d "$src" ]; then
    echo "ERROR: canonical skill source missing at $src"
    exit 1
  fi
  # Stage just this skill at the top level so SKILL.md is at the ZIP root.
  rm -rf "staging/$name"
  mkdir -p "staging/$name"
  cp -R "$src"/* "staging/$name/"
  # zip from inside the staging dir so paths are flat (SKILL.md at root,
  # not nested under skill-name/).
  (cd "staging/$name" && zip -r -q "../../dist/$name.zip" .)
  echo "  ✓ dist/$name.zip ($(du -h "dist/$name.zip" | cut -f1))"
done

rm -rf staging
echo ""
echo "Built $(ls dist | wc -l | tr -d ' ') ZIPs in dist/"
ls -la dist/
