#!/usr/bin/env bash
# The team deployment journey's launch adapter for one machine.
#
#   TEAM_DEPLOYMENT_PROJECT=<compose project> TEAM_DEPLOYMENT_RUN_DIR=<dir> \
#     scripts/e2e-team-deployment.sh compose <up|connect|down> <deployment.yaml>
#
# up       renders deployment.yaml to RUN_DIR/.env, starts deploy/team/compose.yaml
#          and waits until every service is healthy, then checks from inside
#          aweb and each app that its internal origins resolve inside
#          network.servicesCidr, and that every service answers its own
#          readiness route with 200 for the Host its proxy sends. The renderer has already refused a signer
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

# One line per deployed service: the service, its port, its readiness path
# and the Host it answers to (its public origin's authority).
readiness_targets() {
  python_in_server - "$deployment" <<'PY'
import sys
from urllib.parse import urlsplit

import yaml

config = yaml.safe_load(open(sys.argv[1], encoding="utf-8"))
print("aweb", 8000, "/ready", urlsplit(config["aweb"]["publicOrigin"]).netloc)
for app, port in (("secrets", 8770), ("logs", 8765)):
    if app in config:
        print(app, port, "/ready", urlsplit(config[app]["publicOrigin"]).netloc)
if "signer" in config:
    print("signer", 8080, "/readyz", urlsplit(config["signer"]["requestOrigin"]).netloc)
PY
}

env_value() {
  sed -n "s/^$1=//p" "$env_file"
}

# With agents: the agents' resolv.conf and the path of egress's policy go in
# the env file, and the OATS source must be a clean checkout, whose commit and
# fragment blobs are recorded with the run.
prepare_agents() {
  printf 'nameserver %s\n' "$(env_value AGENT_RESOLVER_IP)" >"$run_dir/resolv.conf"
  printf 'RESOLV_CONF_FILE=%s\nEGRESS_POLICY_FILE=%s\n' "$run_dir/resolv.conf" "$run_dir/egress-policy.json" >>"$env_file"
  local oats
  oats="$(env_value OATS_SOURCE)"
  if [[ -n "$(git -C "$oats" status --porcelain)" ]]; then
    echo "e2e-team-deployment: the OATS source at $oats has changes; it must be the pinned commit as it is" >&2
    exit 1
  fi
  {
    echo "commit $(git -C "$oats" rev-parse HEAD)"
    for file in container/agent/compose.agent.yaml container/agent/egress/compose.egress.yaml; do
      echo "blob $(git -C "$oats" rev-parse "HEAD:$file") $file"
    done
  } >"$run_dir/oats-source.txt"
}

# Egress's policy, from what each of the five origins' hosts resolves to on
# the services network, and the two backends no agent may reach: PostgreSQL
# and Redis, at the addresses aweb itself connects to (Redis's is on aweb's
# backend network alone). The resolved addresses are kept with the run for
# the boundary probe.
derive_egress_policy() {
  local hosts addresses
  hosts="$(python_in_server - "$deployment" <<'PY'
import json
import sys
from urllib.parse import urlsplit

import yaml

config = yaml.safe_load(open(sys.argv[1], encoding="utf-8"))
origins = {
    "aweb": config["aweb"]["publicOrigin"],
    "secrets": config["secrets"]["publicOrigin"],
    "logs": config["logs"]["publicOrigin"],
    "signer": config["signer"]["requestOrigin"],
    "registry": config["team"].get("registryUrl", "https://api.awid.ai"),
}
print(json.dumps({
    "origins": {role: urlsplit(origin).hostname for role, origin in origins.items()},
    "backends": {"postgres": config.get("postgres", {}).get("host", "postgres"), "redis": "redis"},
}))
PY
)"
  addresses="$(dc exec -T aweb python -c '
import json, socket, sys
hosts = json.loads(sys.argv[1])
def resolve(host):
    return sorted({info[4][0] for info in socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)})
backends = {role: resolve(host) for role, host in hosts["backends"].items()}
for role, found in backends.items():
    if len(found) != 1:
        sys.exit(f"{role} resolves to {len(found)} addresses, not one")
print(json.dumps({"origins": {role: resolve(host) for role, host in hosts["origins"].items()},
                  "backends": {role: found[0] for role, found in backends.items()}}))
' "$hosts" </dev/null)"
  printf '%s\n' "$addresses" >"$run_dir/egress-addresses.json"
  python_in_server - "$deployment" "$TEAM_DIR" "$run_dir/egress-policy.json" "$addresses" <<'PY'
import importlib.util
import json
import sys
from pathlib import Path

import yaml

path, team_dir, out, resolved = sys.argv[1:]
resolved = json.loads(resolved)
spec = importlib.util.spec_from_file_location("egress_policy", Path(team_dir) / "egress_policy.py")
egress_policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(egress_policy)
config = yaml.safe_load(open(path, encoding="utf-8"))
profile = json.loads(Path(config["signer"]["profileFile"]).read_text(encoding="utf-8"))
try:
    policy = egress_policy.derive(config, profile, resolved["origins"], list(resolved["backends"].values()))
except egress_policy.Refused as refused:
    sys.exit(f"e2e-team-deployment: no egress policy: {refused}")
Path(out).write_text(json.dumps(policy, indent=2) + "\n", encoding="utf-8")
Path(out).chmod(0o644)
PY
}

# Egress alone, then the agents network as Docker created it: internal, no
# IPv6 and no route to the host's bridge gateway, or no agent starts.
start_egress() {
  derive_egress_policy
  if ! dc up -d --wait --wait-timeout "${TEAM_DEPLOYMENT_WAIT_SECONDS:-300}" egress; then
    dc logs --no-color --timestamps egress >"$run_dir/egress.log" 2>&1 || true
    echo "e2e-team-deployment: egress did not become healthy; logs in $run_dir/egress.log" >&2
    exit 1
  fi
  local inspected
  inspected="$(docker network inspect "${project}_agents" \
    --format '{{.Internal}} {{.EnableIPv6}} {{index .Options "com.docker.network.bridge.gateway_mode_ipv4"}}')"
  echo "agents network: internal ipv6 gateway_mode_ipv4 = $inspected"
  if [[ "$inspected" != "true false isolated" ]]; then
    echo "e2e-team-deployment: the agents network is not internal, IPv6-free and gateway-isolated" >&2
    exit 1
  fi
}

# The signer's human origin has one existing GET route that answers 200: its
# page stylesheet. The ingress probe's human controls use it.
SIGNER_HUMAN_PATH=/handoff-assets/handoff.css

# The OATS ingress probe (egress image, probe-ingress.mjs, full mode), from the
# services side against the actual TLS ingress, for every route egress allows:
# the policy's five origins at their pinned addresses, each with matched H1/H2
# controls that must reach its own backend, and the human origin's Host or
# :authority carried under any of them, which must reach no backend. Each
# backend's own access log is followed from before the first probe request.
# The registry's log is one of them: a deployment whose registry is not one of
# its services cannot be probed here. TEAM_DEPLOYMENT_INGRESS_CA names the
# ingress's trust anchors when a private authority signed it.
INGRESS_ROUTES="aweb:aweb:/ready secrets:secrets:/ready logs:logs:/ready signer:signer:/readyz registry:registry:/health"
# The one path every backend logs, Secrets included (it logs /ready and /live
# alone): the probe sends its extra coverage controls and every forbidden
# request there, so a misrouted request cannot go unseen.
INGRESS_AUDIT_PATH=/ready

ingress_probe() {
  local origins logs followers=() route role service path ca_mount=() ca_flag=() out status services
  read -r -a origins < <(python_in_server - "$run_dir/egress-policy.json" <<'PY'
import json
import sys

policy = json.load(open(sys.argv[1], encoding="utf-8"))
print(policy["targets"]["signer"]["addresses"][0], policy["targets"]["signer"]["origin"], policy["humanOrigin"])
PY
)
  logs="$run_dir/ingress-logs"
  rm -rf "$logs"
  mkdir -p "$logs"
  # Read once: grep -q on a live pipe would end it early, and pipefail fails it.
  services="$(dc config --services)"
  for route in $INGRESS_ROUTES; do
    IFS=: read -r role service path <<<"$route"
    if ! grep -qx "$service" <<<"$services"; then
      echo "e2e-team-deployment: the ingress probe needs $role's backend log, and $service is not a service of this deployment" >&2
      return 1
    fi
    : >"$logs/$role.log"
    dc logs --follow --no-color --no-log-prefix "$service" >>"$logs/$role.log" 2>&1 &
    followers+=($!)
  done
  # Each follower is attached once it has written its log so far.
  for route in $INGRESS_ROUTES; do
    IFS=: read -r role service path <<<"$route"
    for _ in $(seq 1 50); do [[ -s "$logs/$role.log" ]] && break; sleep 0.2; done
  done
  python_in_server - "$logs/route-logs.json" $INGRESS_ROUTES <<'PY'
import json
import sys

out, *routes = sys.argv[1:]
table = {}
for route in routes:
    role, _service, path = route.split(":")
    table[role] = {"path": path, "log": f"/logs/{role}.log"}
open(out, "w", encoding="utf-8").write(json.dumps(table, indent=2) + "\n")
PY
  if [[ -n "${TEAM_DEPLOYMENT_INGRESS_CA:-}" ]]; then
    ca_mount=(-v "$TEAM_DEPLOYMENT_INGRESS_CA:/input/world-ca.pem:ro")
    ca_flag=(--ca-file /input/world-ca.pem)
  fi
  out="$(docker run --rm --network "${project}_services" -v "$logs:/logs:ro" \
    -v "$run_dir/egress-policy.json:/input/egress-policy.json:ro" -v "$logs/route-logs.json:/input/route-logs.json:ro" \
    ${ca_mount[@]+"${ca_mount[@]}"} --entrypoint node "$(env_value EGRESS_IMAGE)" /opt/egress/probe-ingress.mjs \
    --address "${origins[0]}" --request-origin "${origins[1]}" --human-origin "${origins[2]}" \
    --human-log /logs/signer.log --human-path "$SIGNER_HUMAN_PATH" --audit-path "$INGRESS_AUDIT_PATH" \
    ${ca_flag[@]+"${ca_flag[@]}"} \
    --policy /input/egress-policy.json --route-logs /input/route-logs.json </dev/null)" && status=0 || status=$?
  for follower in "${followers[@]}"; do
    kill "$follower" 2>/dev/null || true
    wait "$follower" 2>/dev/null || true
  done
  echo "ingress probe: exit $status, $out"
  [[ "$status" -eq 0 && "$out" == OATS_EGRESS_INGRESS_PASS ]]
}

# The OATS boundary probe (egress probe-compose-boundary.mjs, run on the
# Docker engine host with Node 22) against the actual agents network: an
# inert probe from the agent image, as the agent service with empty state,
# login and authorized keys and the public CA alone, beside egress and
# nothing else. The probe is removed before the agent takes its address.
# Protected sources are each service's secrets directory, Redis's included
# (the agents' own login directory beside them is not one), the backends'
# data volumes, the Docker socket and TEAM_DEPLOYMENT_PROTECTED_SOURCES (colon
# separated), each as the engine host resolves it.
boundary_probe() {
  local node="${TEAM_DEPLOYMENT_NODE:-node}" probe="$project-agent-probe" sources=() out status
  if ! "$node" -e 'process.exit(Number(process.versions.node.split(".")[0]) >= 22 ? 0 : 1)'; then
    echo "e2e-team-deployment: the boundary probe needs Node 22 or later as $node" >&2
    return 1
  fi
  rm -rf "$run_dir/probe"
  mkdir -p "$run_dir/probe/state" "$run_dir/probe/login"
  : >"$run_dir/probe/authorized_keys"
  local secrets_dir component name
  secrets_dir="$(cd "$TEAM_DIR" && realpath "$(env_value SECRETS_DIR)")"
  for component in POSTGRES AWEB SECRETS LOGS SIGNER; do
    name="$(env_value "${component}_SECRETS")"
    [[ -z "$name" || ! -e "$secrets_dir/$name" ]] || sources+=("$(realpath "$secrets_dir/$name")")
  done
  [[ ! -e "$secrets_dir/redis" ]] || sources+=("$(realpath "$secrets_dir/redis")")
  local volume
  for volume in postgres_data redis_data; do
    if docker volume inspect "${project}_$volume" >/dev/null 2>&1; then
      sources+=("$(docker volume inspect --format '{{.Mountpoint}}' "${project}_$volume")")
    fi
  done
  sources+=("$(realpath /var/run/docker.sock)")
  local extra
  while IFS= read -r extra; do
    [[ -z "$extra" ]] || sources+=("$(realpath "$extra")")
  done < <(tr ':' '\n' <<<"${TEAM_DEPLOYMENT_PROTECTED_SOURCES:-}")
  docker rm -f "$probe" >/dev/null 2>&1 || true
  TEAM_STATE_DIR="$run_dir/probe/state" TEAM_LOGIN_DIR="$run_dir/probe/login" \
    AUTHORIZED_KEYS_FILE="$run_dir/probe/authorized_keys" \
    dc run -d --no-deps --name "$probe" --entrypoint sleep agent infinity >/dev/null
  python_in_server - "$deployment" "$TEAM_DIR" "$run_dir" "$project" "$(env_value AGENT_IMAGE)" "$(env_value EGRESS_IMAGE)" \
    "${sources[@]}" >"$run_dir/boundary-plan.json" <<'PY'
import importlib.util
import json
import sys
from pathlib import Path

import yaml

path, team_dir, run_dir, project, agent, egress, *sources = sys.argv[1:]
spec = importlib.util.spec_from_file_location("egress_policy", Path(team_dir) / "egress_policy.py")
egress_policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(egress_policy)
plan = egress_policy.boundary_plan(
    yaml.safe_load(open(path, encoding="utf-8")),
    json.loads(Path(run_dir, "egress-policy.json").read_text(encoding="utf-8")),
    project=project,
    images={"agent": agent, "egress": egress},
    run_dir=run_dir,
    backends=json.loads(Path(run_dir, "egress-addresses.json").read_text(encoding="utf-8"))["backends"],
    protected_sources=sources,
)
print(json.dumps(plan, indent=2))
PY
  out="$("$node" "$(env_value OATS_SOURCE)/container/agent/egress/probe-compose-boundary.mjs" \
    --plan "$run_dir/boundary-plan.json" </dev/null)" && status=0 || status=$?
  docker rm -f "$probe" >/dev/null
  echo "boundary probe: exit $status, $out"
  [[ "$status" -eq 0 && "$out" == OATS_EGRESS_BOUNDARY_PASS ]]
}

# The agent container, from the unchanged pinned service at its own address,
# then OATS's acceptance of it (agent accept.sh, live-lab evidence: this is
# a live run) against the deployment's values: image, user, network and the
# exact mounts. Its report is kept in the run directory.
start_agent() {
  local node="${TEAM_DEPLOYMENT_NODE:-node}" status
  if ! dc up -d --no-deps --wait --wait-timeout "${TEAM_DEPLOYMENT_WAIT_SECONDS:-300}" agent; then
    dc logs --no-color --timestamps agent >"$run_dir/agent.log" 2>&1 || true
    echo "e2e-team-deployment: the agent did not become healthy; logs in $run_dir/agent.log" >&2
    return 1
  fi
  env AGENT_IMAGE="$(env_value AGENT_IMAGE)" AGENT_UID="$(env_value AGENT_UID)" AGENT_GID="$(env_value AGENT_GID)" \
    AGENTS_NETWORK="${project}_agents" AGENT_IP="$(env_value AGENT_IP)" AGENT_PIDS="$(env_value AGENT_PIDS)" \
    AGENT_MEMORY="$(env_value AGENT_MEMORY)" AGENT_CPUS="$(env_value AGENT_CPUS)" \
    TEAM_STATE_DIR="$(env_value TEAM_STATE_DIR)" TEAM_LOGIN_DIR="$(env_value TEAM_LOGIN_DIR)" \
    AUTHORIZED_KEYS_FILE="$(env_value AUTHORIZED_KEYS_FILE)" RESOLV_CONF_FILE="$(env_value RESOLV_CONF_FILE)" \
    AGENT_TMP_SIZE="$(env_value AGENT_TMP_SIZE)" AGENT_CA_FILE="$(env_value AGENT_CA_FILE)" \
    AGENT_MIRRORS_DIR="$(env_value AGENT_MIRRORS_DIR)" \
    PATH="$(dirname "$(command -v "$node")"):$PATH" \
    "$(env_value OATS_SOURCE)/container/agent/accept.sh" "oats-agent-$(env_value TEAM)" --evidence live-lab \
    >"$run_dir/agent-accept.out" 2>&1 </dev/null && status=0 || status=$?
  echo "agent acceptance: exit $status; report in $run_dir/agent-accept.out"
  grep -E '^\[live-lab\] (FAIL|NOT RUN)' "$run_dir/agent-accept.out" || true
  [[ "$status" -eq 0 ]]
}

up() {
  mkdir -p "$run_dir"
  python_in_server "$TEAM_DIR/render_env.py" "$deployment" >"$env_file.tmp"
  mv "$env_file.tmp" "$env_file"
  local with_agents=0 services=()
  if [[ -n "$(env_value EGRESS_ADDRESS)" ]]; then
    with_agents=1
    prepare_agents
  fi
  # The resolved model holds no credential: every one is a mounted file.
  dc config >"$run_dir/compose.config.yaml"
  if grep -q AWID_SERVICE_TOKEN "$run_dir/compose.config.yaml"; then
    echo "e2e-team-deployment: a service is given AWID_SERVICE_TOKEN" >&2
    exit 1
  fi
  # The agent and its egress start last, after their policy is derived.
  if [[ "$with_agents" -eq 1 ]]; then
    while read -r service; do
      [[ "$service" == egress || "$service" == agent ]] || services+=("$service")
    done < <(dc config --services)
  fi
  if ! dc up -d --wait --wait-timeout "${TEAM_DEPLOYMENT_WAIT_SECONDS:-300}" ${services[@]+"${services[@]}"}; then
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
' "$cidr" $hosts </dev/null; then
      echo "e2e-team-deployment: $service's internal origins do not resolve inside $cidr" >&2
      exit 1
    fi
  done < <(internal_hosts)
  # Healthy is the images' liveness checks. Ready is each service's own
  # readiness answer, asked with the Host its proxy sends; anything but 200
  # fails the run.
  # exec gets no stdin: it would read the rest of the list.
  local targets ready=0
  targets="$(readiness_targets)"
  while read -r service port path host; do
    if ! dc exec -T "$service" python -c '
import sys, urllib.error, urllib.request
service, port, path, host = sys.argv[1:]
request = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers={"Host": host})
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
try:
    status = opener.open(request, timeout=10).status
except urllib.error.HTTPError as refused:
    status = refused.code
print(f"{service} {path} {status}")
sys.exit(status != 200)
' "$service" "$port" "$path" "$host" </dev/null; then
      echo "e2e-team-deployment: $service is not ready" >&2
      exit 1
    fi
    ready=$((ready + 1))
  done <<<"$targets"
  if [[ "$ready" -ne "$(grep -c . <<<"$targets")" ]]; then
    echo "e2e-team-deployment: $ready services checked for readiness, not every one" >&2
    exit 1
  fi
  if [[ "$with_agents" -eq 1 ]]; then
    start_egress
    dc ps --format '{{.Service}} {{.Status}}'
    # The signer's request origin is one of egress's five routes. Until the
    # ingress is shown to refuse that origin's SNI carrying the human origin's
    # Host or :authority, no agent is admitted.
    if ! ingress_probe; then
      echo "e2e-team-deployment: agents held: the ingress refusal probe did not pass" >&2
      exit 1
    fi
    if ! boundary_probe; then
      echo "e2e-team-deployment: agents held: the boundary probe did not pass" >&2
      exit 1
    fi
    if ! start_agent; then
      echo "e2e-team-deployment: agents held: the agent container did not pass its acceptance" >&2
      exit 1
    fi
    echo "e2e-team-deployment: agents held: the agent runs credential-free; no seat, deployment or session is admitted" >&2
    exit 3
  fi
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
  # Every profile: a service whose profile is off at down (the journey's aw
  # machines) is still the project's.
  dc --profile '*' down --volumes --remove-orphans
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
