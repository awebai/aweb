#!/usr/bin/env bash
# Build library's and folio's production images from the layout they will have
# inside aweb, so that "the images still build" is a demonstration rather than an
# argument about Docker contexts.
#
# The layout is materialized in a throwaway directory. Nothing is written to the
# aweb worktree, no source repo is modified, and no image is pushed.
#
# Three arrangements are exercised, because the epic's hazard is conditional on a
# choice nobody has made yet:
#
#   pinned  the movers keep the git pins they use in production today. Their
#           build context stays the service directory. This is what the move
#           produces if no dependency source is touched.
#
#   path    the awid and aweb-naapp git pins become in-repo path sources. Now the
#           context has to be the aweb root, which needs a root .dockerignore or
#           the whole repository is sent to the daemon, and the Dockerfile has to
#           copy its own subtree rather than the context root.
#
#   context what a root context costs when aweb has no root .dockerignore:
#           measured in bytes transferred and in whether a planted agent
#           signing key reaches the image.
#
# Usage: check-naapp-move-images.sh [pinned|path|context|both]

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-both}"

# shellcheck source=scripts/lib/naapp-movers.sh
source "$ROOT/scripts/lib/naapp-movers.sh"

if ! docker version --format '{{.Server.Version}}' >/dev/null 2>&1; then
  echo "FAIL: no reachable Docker daemon; this check builds real images and cannot be satisfied without one" >&2
  exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# The aweb tree as committed, plus each mover at its destination.
#
# aweb itself is archived at HEAD, not at a fixed ref, so every figure below
# describes the runner's own checkout. Two runs on different branches will report
# different context sizes for that reason; the properties asserted do not depend
# on it.
#
# The movers and their refs come from scripts/lib/naapp-movers.sh, and
# naapp_assert_pin_agreement has already refused to run if the aweb-naapp commit
# being archived is not the one both live services pin.
materialize() {
  local layout="$1" mover src dest ref n
  mkdir -p "$layout"
  git -C "$ROOT" archive HEAD | tar -x -C "$layout"

  while IFS= read -r mover; do
    IFS=':' read -r src dest ref <<< "$mover"
    mkdir -p "$layout/$dest"
    git -C "$src" archive "$ref" | tar -x -C "$layout/$dest"

    # The layout is only meaningful if the mover actually landed in it.
    n="$(find "$layout/$dest" -type f -o -type l | wc -l | tr -d ' ')"
    if [[ "$n" -lt 10 ]]; then
      printf 'FAIL: %s holds only %s entries; the layout was not materialized\n' "$dest" "$n" >&2
      return 1
    fi
  done < <(naapp_movers)
}

build_one() {
  local name="$1" context="$2" dockerfile="$3" tag="$4" venv="$5"
  local on_disk
  on_disk="$(find "$context" -type f | wc -l | tr -d ' ')"
  printf '     building %-8s context %s, %s files on disk beneath it\n' \
    "$name" "${context#$WORK/}" "$on_disk"

  # --progress=plain keeps buildkit's "transferring context" line, which is what
  # the daemon actually received. That number, not the file count on disk, is
  # what a .dockerignore changes.
  if ! docker build --progress=plain -f "$dockerfile" -t "$tag" "$context" \
      > "$WORK/$name.build.log" 2>&1; then
    printf '  FAIL %-8s image did not build. Last lines:\n' "$name"
    tail -25 "$WORK/$name.build.log" | sed 's/^/         /'
    return 1
  fi
  # Reported, not asserted, and not comparable between runs: buildkit reports only
  # what it actually sent, so a warm context cache shows a few kB where a cold one
  # shows megabytes. Nothing gates on the figure. If buildkit's wording changes it
  # reads "unparsed" rather than silently emptying. The context arrangement below
  # builds --no-cache precisely so its two figures are comparable to each other.
  local transferred
  transferred="$(grep -o 'transferring context: [0-9.]*[kMG]*B' "$WORK/$name.build.log" \
    | tail -1 | sed 's/transferring context: //')"
  printf '  ok   %-8s image built; daemon received %s\n' "$name" "${transferred:-unparsed}"
  verify_image "$name" "$tag" "$venv"
}

# The control on this whole check is verify_image, so it needs both directions
# like every other arm: red for an image without the dependencies, green for the
# real ones. An arm that only ever meets the bare image proves the assertion
# fires, not that it discriminates - which is the distinction it exists to make
# about the build.
verify_control_discriminates() {
  local bare="python:3.12-slim"
  printf '     control: %s must fail the same import check the real images pass\n' "$bare"
  if verify_image "bare" "$bare" "/usr/local" >/dev/null 2>&1; then
    printf 'FAIL: %s passed the dependency check, so that check cannot tell a resolved image from an unresolved one\n' \
      "$bare" >&2
    return 1
  fi
  printf '  ok   control    %s is rejected, so the check discriminates\n' "$bare"
}

# A build that succeeds without resolving awid and aweb-naapp proves nothing
# about the dependency arrangement, and both are exactly what the move changes.
# So the image is asked whether it actually has them.
verify_image() {
  local name="$1" tag="$2" venv="$3"
  local out
  if ! out="$(docker run --rm --entrypoint "$venv/bin/python" "$tag" -c \
    'import importlib.metadata as m; import awid_service, aweb_naapp; print(m.version("awid-service"), m.version("aweb-naapp"))' 2>&1)"; then
    printf '  FAIL %-8s image built but does not import its in-repo dependencies:\n' "$name"
    printf '%s\n' "$out" | tail -8 | sed 's/^/         /'
    return 1
  fi
  printf '       %-8s resolves awid-service and aweb-naapp: %s\n' "$name" "$out"
}

# ----------------------------------------------------------------- pinned mode
#
# Nothing about the move touches a dependency source, so each service keeps the
# service directory as its context and its Dockerfile unchanged.
run_pinned() {
  local layout="$WORK/pinned"
  materialize "$layout" || return 1
  echo "pinned: movers keep today's git pins; context stays the service directory"

  local status=0
  for svc in library folio; do
    build_one "$svc" "$layout/naapp/$svc" "$layout/naapp/$svc/Dockerfile" "aweb-move-check/$svc:pinned" "/app/.venv" || status=1
  done
  return $status
}

# ------------------------------------------------------------------- path mode
#
# Converting the pins to path sources forces the context up to the aweb root.
run_path() {
  local layout="$WORK/path"
  materialize "$layout" || return 1
  echo "path: awid and aweb-naapp become in-repo path sources; context becomes the aweb root"

  # Without this, the context is the entire repository. aweb has no root
  # .dockerignore today, which is the second half of the epic's hazard.
  write_root_dockerignore "$layout/.dockerignore"

  local status=0
  for svc in library folio; do
    # The service resolves awid and aweb-naapp from inside the repo.
    python3 - "$layout" "$svc" <<'PY'
import pathlib, re, sys
layout, svc = sys.argv[1], sys.argv[2]
p = pathlib.Path(layout) / "naapp" / svc / "pyproject.toml"
text = p.read_text()
text = re.sub(
    r'awid-service = \{ git = [^\n]*\}',
    'awid-service = { path = "../../awid", editable = false }',
    text,
)
text = re.sub(
    r'aweb-naapp = \{ git = [^\n]*\}',
    'aweb-naapp = { path = "../../naapp-lib", editable = false }',
    text,
)
p.write_text(text)
PY
    if grep -q 'git = ' "$layout/naapp/$svc/pyproject.toml"; then
      printf 'FAIL: %s still carries a git source after rewriting; the path arrangement was not applied\n' "$svc" >&2
      return 1
    fi

    # A root context means the Dockerfile can no longer copy the context root
    # into /app, and the lock has to be regenerated because it records sources.
    cat > "$layout/naapp/$svc/Dockerfile.root-context" <<DOCKER
# syntax=docker/dockerfile:1
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \\
    PYTHONUNBUFFERED=1 \\
    PORT=8765 \\
    UV_COMPILE_BYTECODE=1 \\
    UV_LINK_MODE=copy \\
    UV_PROJECT_ENVIRONMENT=/app/naapp/$svc/.venv

RUN apt-get update \\
    && apt-get install -y --no-install-recommends ca-certificates \\
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.11.21 /uv /uvx /bin/

WORKDIR /app/naapp/$svc

# The path sources resolve outside the service directory, so awid and naapp-lib
# have to be in the image before the lock can be synced.
COPY awid /app/awid
COPY naapp-lib /app/naapp-lib
COPY naapp/$svc /app/naapp/$svc
RUN uv sync --frozen --no-dev

RUN useradd --create-home --shell /usr/sbin/nologin $svc
USER $svc

EXPOSE 8765
CMD ["sh", "-c", "/app/naapp/$svc/.venv/bin/uvicorn $svc.api:app --host 0.0.0.0 --port \${PORT:-8765}"]
DOCKER

    # uv.lock records the dependency source, so a source change requires a
    # relock. This is a real change to what the image resolves, not a context
    # change, and it is the reason this arrangement is not free.
    ( cd "$layout/naapp/$svc" && uv lock --quiet ) || {
      printf 'FAIL: %s could not relock against the path sources\n' "$svc" >&2
      return 1
    }

    build_one "$svc" "$layout" "$layout/naapp/$svc/Dockerfile.root-context" "aweb-move-check/$svc:path" "/app/naapp/$svc/.venv" || status=1
  done
  return $status
}

# ---------------------------------------------------------------- context mode
#
# What a root build context costs without a root .dockerignore, measured rather
# than asserted. aweb's /agents/instances/ rule keeps every agent's signing key,
# team certificate and encryption key out of git, and .dockerignore is a separate
# file with no knowledge of it. So a root context reaches those keys even though
# git never would, and bakes them into the image.
#
# An agent home is planted rather than read from the real checkout, so the
# measurement never puts a real key into a build context.
run_context() {
  local layout="$WORK/context"
  materialize "$layout" || return 1
  echo "context: what a root context sends, with and without a root .dockerignore"

  local planted="agents/instances/probe/.aw/signing.key"
  mkdir -p "$layout/$(dirname "$planted")"
  head -c 2000000 /dev/urandom > "$layout/$planted"

  printf 'FROM alpine\nCOPY . /context\n' > "$layout/context-probe.Dockerfile"

  local status=0 mode transferred present
  for mode in absent present; do
    rm -f "$layout/.dockerignore"
    [[ "$mode" == "present" ]] && write_root_dockerignore "$layout/.dockerignore"

    docker build --no-cache --progress=plain \
      -f "$layout/context-probe.Dockerfile" -t "aweb-move-check/context:$mode" "$layout" \
      > "$WORK/context-$mode.log" 2>&1 || { echo "  FAIL context probe did not build" >&2; return 1; }

    transferred="$(grep -o 'transferring context: [0-9.]*[kMG]*B' "$WORK/context-$mode.log" \
      | tail -1 | sed 's/transferring context: //')"
    if docker run --rm "aweb-move-check/context:$mode" \
         test -f "/context/$planted" 2>/dev/null; then
      present="YES"
    else
      present="no"
    fi
    printf '  root .dockerignore %-7s daemon received %-10s planted signing key in image: %s\n' \
      "$mode:" "$transferred" "$present"

    # The two directions are the point: absent must expose the key, present must
    # not. Either result coming out the other way means this is not measuring
    # what it claims to.
    if [[ "$mode" == "absent" && "$present" != "YES" ]]; then
      echo "FAIL: without a root .dockerignore the planted key did not reach the image; this probe is not measuring the context" >&2
      status=1
    fi
    if [[ "$mode" == "present" && "$present" != "no" ]]; then
      echo "FAIL: the root .dockerignore did not keep the planted key out of the image" >&2
      status=1
    fi
  done
  return $status
}

write_root_dockerignore() {
  cat > "$1" <<'IGNORE'
**/.git
**/.venv
**/node_modules
**/dist
**/build
**/__pycache__
**/*.py[cod]
**/.pytest_cache
**/.mypy_cache
**/.ruff_cache
**/.coverage
**/.env
**/.env.*
!**/.env.example
**/.DS_Store
**/*.pem
agents
cli/agents
oats/agents
**/.aw
**/.claude
**/.agents
IGNORE
}

naapp_require_movers
naapp_assert_pin_agreement
verify_control_discriminates
echo

status=0
case "$MODE" in
  pinned)  run_pinned  || status=1 ;;
  path)    run_path    || status=1 ;;
  context) run_context || status=1 ;;
  both)    run_pinned || status=1; echo; run_path || status=1; echo; run_context || status=1 ;;
  *) echo "usage: $(basename "$0") [pinned|path|context|both]" >&2; exit 2 ;;
esac

echo
if [[ "$status" -ne 0 ]]; then
  echo "at least one image did not build from the new layout." >&2
  exit 1
fi
echo "every image exercised built from the new layout"
