#!/usr/bin/env bash
# Operator entry point for durable OAS/aweb provisioning reconciliation.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
capability="${AWEB_IDENTITY_ATTACH_CAPABILITY:-$repo_root/oas/.agents/capabilities/owned/aweb-identity-attach}"
entry="$capability/bin/aweb-identity-attach.mjs"

if [[ ! -f "$entry" ]]; then
  echo "aweb identity attach capability entry not found: $entry" >&2
  exit 1
fi

exec "${NODE:-node}" "$entry" reconcile "$@"
