#!/usr/bin/env bash
# Builds every image of the team deployment journey from one clean checkout,
# pushes each to a registry and records its digest.
#
#   scripts/e2e/team-deployment-images.sh <registry> <images file> [<oats checkout>]
#
# <registry> is where the run's images go (a disposable local registry, such
# as localhost:5000); nothing here is published. With an OATS checkout at its
# pinned commit, the agent and egress images are built from it too.
set -euo pipefail

usage() {
  echo "usage: $0 <registry> <images file> [<oats checkout>]" >&2
  exit 2
}
[[ $# -eq 2 || $# -eq 3 ]] || usage
registry="$1"
out="$2"
oats="${3:-}"
src="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

[[ -z "$(git -C "$src" status --porcelain)" ]] || { echo "the aweb checkout has changes" >&2; exit 1; }
sha="$(git -C "$src" rev-parse HEAD)"
: >"$out"

build() {
  local name="$1" tag="$2"
  shift 2
  echo "=== build $name @ $tag" >&2
  docker build -q -t "$registry/$name:$tag" "$@" >/dev/null
  docker push -q "$registry/$name:$tag" >/dev/null
  echo "$name $(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$registry/$name:$tag" \
    | grep "^$registry/$name@" | head -1)" | tee -a "$out"
}

build aweb "$sha" -f "$src/server/Dockerfile" "$src"
build aweb-protected "$sha" -f "$src/server/Dockerfile" --build-arg AWEB_EXTRA=protected "$src"
build secrets "$sha" -f "$src/naapp/secrets/Dockerfile" --build-arg SOURCE_COMMIT="$sha" "$src"
build logs "$sha" -f "$src/naapp/logs/Dockerfile" --build-arg SOURCE_COMMIT="$sha" "$src"
# The journey's test world: its registry, the aw machines and the approver's browser.
build awid "$sha" -f "$src/awid/Dockerfile" "$src"
build cli "$sha" -f "$src/scripts/federation-cli.Dockerfile" "$src"
build chromium "$sha" -f "$src/naapp/secrets/e2e/protected/chromium.Dockerfile" "$src"

if [[ -n "$oats" ]]; then
  [[ -z "$(git -C "$oats" status --porcelain)" ]] || { echo "the OATS checkout has changes" >&2; exit 1; }
  commit="$(git -C "$oats" rev-parse HEAD)"
  build agent "$commit" "$oats/container/agent"
  build egress "$commit" "$oats/container/agent/egress"
fi
