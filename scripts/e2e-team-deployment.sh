#!/usr/bin/env bash
# The team deployment journey's launch adapter for one machine.
#
#   TEAM_DEPLOYMENT_PROJECT=<compose project> TEAM_DEPLOYMENT_RUN_DIR=<dir> \
#     scripts/e2e-team-deployment.sh compose <up|connect|down> <deployment.yaml>
#
# up       renders deployment.yaml to RUN_DIR/.env, starts deploy/team/compose.yaml
#          and waits until every service is healthy, then checks from inside
#          aweb and each app that its internal origins resolve inside
#          network.servicesCidr. The renderer has already refused a signer
#          profile whose origins or registry differ from the deployment's.
# connect  prints, as JSON, what the journey needs: the origins, the team and
#          registry, the agent container and the command that removes it all.
# down     removes the project's containers, networks and volumes, and
#          checks that none is left.
#
# TEAM_DEPLOYMENT_COMPOSE_FILES names further Compose files, separated by
# colons, that the journey adds (its test registry, DNS and mail).
# No credential is read, printed or passed here: they are files the
# services mount.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEAM_DIR="$REPO_ROOT/deploy/team"
SELF="$REPO_ROOT/scripts/e2e-team-deployment.sh"

usage() {
  echo "usage: TEAM_DEPLOYMENT_PROJECT=<name> TEAM_DEPLOYMENT_RUN_DIR=<dir> $0 compose <up|connect|down> <deployment.yaml>" >&2
  exit 2
}

[[ $# -eq 3 && "$1" == compose ]] || usage
action="$2"
case "$action" in up | connect | down) ;; *) usage ;; esac
[[ -n "${TEAM_DEPLOYMENT_PROJECT:-}" && -n "${TEAM_DEPLOYMENT_RUN_DIR:-}" ]] || usage
deployment="$(cd "$(dirname "$3")" && pwd)/$(basename "$3")"
project="$TEAM_DEPLOYMENT_PROJECT"
run_dir="$TEAM_DEPLOYMENT_RUN_DIR"
env_file="$run_dir/.env"

python_in_server() {
  uv run --quiet --project "$REPO_ROOT/server" python "$@"
}

# The docker compose command of this deployment, one argument per line: the
# files the renderer's COMPOSE_FILE names (compose.yaml and each component the
# deployment has), then the journey's own.
compose_command() {
  python_in_server - "$deployment" "$project" "$env_file" "$TEAM_DIR" "${TEAM_DEPLOYMENT_COMPOSE_FILES:-}" <<'PY'
import importlib.util
import sys
from pathlib import Path

import yaml

path, project, env_file, team_dir, extra = sys.argv[1:]
spec = importlib.util.spec_from_file_location("render_env", Path(team_dir) / "render_env.py")
render_env = importlib.util.module_from_spec(spec)
spec.loader.exec_module(render_env)
files = render_env.render(yaml.safe_load(open(path, encoding="utf-8")))["COMPOSE_FILE"].split(":")
command = ["docker", "compose", "-p", project, "--env-file", env_file]
for file in [str(Path(team_dir) / name) for name in files] + [name for name in extra.split(":") if name]:
    command += ["-f", file]
print("\n".join(command))
PY
}

compose=()
dc() {
  if [[ ${#compose[@]} -eq 0 ]]; then
    while IFS= read -r argument; do compose+=("$argument"); done < <(compose_command)
  fi
  "${compose[@]}" "$@"
}

# One line per service that names internal origins (aweb's apps, the apps'
# hook receivers): the service, the range and the origins' hosts.
internal_hosts() {
  python_in_server - "$deployment" <<'PY'
import sys
from urllib.parse import urlsplit

import yaml

config = yaml.safe_load(open(sys.argv[1], encoding="utf-8"))
cidr = config["network"]["servicesCidr"]
named = {"aweb": config["aweb"].get("appInternalOrigins", [])}
for app in ("secrets", "logs"):
    named[app] = config.get(app, {}).get("hookInternalOrigins", [])
for service, origins in named.items():
    if origins:
        print(service, cidr, *sorted({urlsplit(origin).hostname for origin in origins}))
PY
}

up() {
  mkdir -p "$run_dir"
  python_in_server "$TEAM_DIR/render_env.py" "$deployment" >"$env_file.tmp"
  mv "$env_file.tmp" "$env_file"
  # The resolved model holds no credential: every one is a mounted file.
  dc config >"$run_dir/compose.config.yaml"
  if grep -q AWID_SERVICE_TOKEN "$run_dir/compose.config.yaml"; then
    echo "e2e-team-deployment: a service is given AWID_SERVICE_TOKEN" >&2
    exit 1
  fi
  if ! dc up -d --wait --wait-timeout "${TEAM_DEPLOYMENT_WAIT_SECONDS:-300}"; then
    dc ps --all --format '{{.Service}} {{.Status}}' >&2 || true
    dc logs --no-color --timestamps >"$run_dir/compose.log" 2>&1 || true
    echo "e2e-team-deployment: not every service became healthy; logs in $run_dir/compose.log" >&2
    exit 1
  fi
  # An internal origin is allowed only inside the services range: every
  # address its host resolves to, seen from the service that connects to it.
  while read -r service cidr hosts; do
    # shellcheck disable=SC2086
    if ! dc exec -T "$service" python -c '
import ipaddress, socket, sys
net = ipaddress.ip_network(sys.argv[1])
for host in sys.argv[2:]:
    addresses = {info[4][0] for info in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)}
    outside = sorted(a for a in addresses if ipaddress.ip_address(a) not in net)
    if outside:
        sys.exit(f"{host} resolves outside {net}: {outside}")
' "$cidr" $hosts; then
      echo "e2e-team-deployment: $service's internal origins do not resolve inside $cidr" >&2
      exit 1
    fi
  done < <(internal_hosts)
  dc ps --format '{{.Service}} {{.Status}}'
}

connect() {
  python_in_server - "$deployment" "$project" "$env_file" "$SELF" "$(compose_command)" <<'PY'
import json
import sys

import yaml

path, project, env_file, runner, compose = sys.argv[1:]
config = yaml.safe_load(open(path, encoding="utf-8"))
origins = {"aweb": config["aweb"]["publicOrigin"]}
for app in ("secrets", "logs"):
    if app in config:
        origins[app] = {"api": config[app]["publicOrigin"], "console": config[app]["consoleOrigin"]}
if "signer" in config:
    origins["signer"] = {"request": config["signer"]["requestOrigin"], "human": config["signer"]["humanOrigin"]}
agents = config.get("agents")
print(json.dumps({
    "project": project,
    "envFile": env_file,
    "team": config["team"]["id"],
    "registry": config["team"].get("registryUrl", "https://api.awid.ai"),
    "origins": origins,
    "agent": {"container": f"oats-agent-{agents['compose']['name']}"} if agents else None,
    "compose": compose.split("\n"),
    "down": [runner, "compose", "down", path],
}))
PY
}

down() {
  dc down --volumes --remove-orphans
  local left=0 kind ids
  for kind in container network volume; do
    if [[ "$kind" == container ]]; then
      ids="$(docker container ls -aq --filter "label=com.docker.compose.project=$project")"
    else
      ids="$(docker "$kind" ls -q --filter "label=com.docker.compose.project=$project")"
    fi
    if [[ -n "$ids" ]]; then
      echo "e2e-team-deployment: $kind left after down: $ids" >&2
      left=1
    fi
  done
  return "$left"
}

"$action"
