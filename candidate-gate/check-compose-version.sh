#!/usr/bin/env bash
set -euo pipefail

expected="${1:?expected docker-compose-plugin package version is required}"
installed="$(dpkg-query -W -f='${Version}' docker-compose-plugin)"
if [[ "$installed" != "$expected" ]]; then
  printf 'candidate Compose package mismatch: expected %s, installed %s\n' "$expected" "$installed" >&2
  exit 1
fi
printf 'candidate Compose package verified: %s\n' "$installed"
