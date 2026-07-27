#!/usr/bin/env bash
# Prove, from a fresh external OAS workspace against a fresh local tmpfs-backed
# stack, that acquisition remains separate from activation/onboarding, attached
# retirement preserves its principal, and two independent developers can run
# the same local worker name as distinct disposable operations. Exercise real
# mail, forged cross-operation cleanup, interrupted handoff reconciliation,
# visible quarantine/remediation, and owning-authority terminal cleanup.
#
# Requirements: Docker Compose, Go, Python 3, curl, Node/npm, Pi, model auth,
# and an OAS source install.
# OAS_TEST_ROOT selects that install. OAS_PROOF_{AWID,AWEB,POSTGRES}_PORT and
# OAS_PROOF_PROJECT isolate concurrent runs. OAS_PROOF_REPORT selects the
# persistent JSON evidence destination; KEEP_OAS_PROOF=1 retains non-secret
# fixtures. OAS_PROOF_MODE defaults to lifecycle (no model or tmux) and accepts
# resident-pi for the reviewed real-Pi wake/reply proof. The latter copies model
# auth into the throwaway root without logging it and removes that copy even
# when other evidence is retained.
set -euo pipefail

canonical_dir() {
  bash -c 'cd "$1" && pwd -P' _ "$1"
}

make_temp_dir() {
  local directory
  directory="$(mktemp -d "${TMPDIR:-/tmp}/aweb-oas-retire-proof.XXXXXX")"
  canonical_dir "$directory"
}

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CLI_DIR="$REPO_ROOT/cli/go"
[[ -z "${AW_BIN+x}" ]] || { echo "FAIL: AW_BIN overrides are outside the declared execution subject" >&2; exit 2; }
AW_BIN="$CLI_DIR/aw"
PROOF_HELPER="$REPO_ROOT/scripts/e2e/oas_principal_proof.py"
CAPABILITY_SOURCE="$REPO_ROOT/oas/.agents/capabilities/owned/aweb-identity-attach"
PI_EXTENSION_DIR="$REPO_ROOT/pi-extension"
COMPOSE_FILE="$REPO_ROOT/docker-compose.e2e.yml"
TMUX_GUARD_DIR="$REPO_ROOT/scripts/guard-bin"
MODE="${OAS_PROOF_MODE:-lifecycle}"
case "$MODE" in
  lifecycle|resident-pi) ;;
  *) echo "FAIL: OAS_PROOF_MODE must be lifecycle or resident-pi (got $MODE)" >&2; exit 2 ;;
esac
HOST_PI_AUTH="${OAS_PROOF_PI_AUTH:-${PI_CODING_AGENT_DIR:-${HOME:-}/.pi/agent}/auth.json}"

preflight() {
  [[ -d "$CLI_DIR" ]] || { echo "FAIL: CLI source not found at $CLI_DIR" >&2; return 1; }
  [[ -f "$PROOF_HELPER" ]] || { echo "FAIL: proof helper not found at $PROOF_HELPER" >&2; return 1; }
  [[ "$AW_BIN" == "$CLI_DIR/aw" ]] || { echo "FAIL: AW_BIN overrides are outside the declared execution subject" >&2; return 1; }
  [[ -f "$COMPOSE_FILE" ]] || { echo "FAIL: compose file not found at $COMPOSE_FILE" >&2; return 1; }
  [[ -f "$CAPABILITY_SOURCE/oas.json" ]] || {
    echo "FAIL: attach capability not found at $CAPABILITY_SOURCE" >&2
    return 1
  }
  [[ -z "${NODE_OPTIONS:-}" ]] || {
    echo "FAIL: NODE_OPTIONS preloads are outside the declared execution subject" >&2
    return 1
  }
  [[ -x "$TMUX_GUARD_DIR/tmux" ]] || {
    echo "FAIL: repository tmux guard not found at $TMUX_GUARD_DIR/tmux" >&2
    return 1
  }
  [[ -f "$PI_EXTENSION_DIR/package.json" ]] || {
    echo "FAIL: Pi extension source not found at $PI_EXTENSION_DIR" >&2
    return 1
  }
}

preflight
if [[ "${1:-}" == "--preflight" ]]; then
  exit
fi

OAS_ROOT="${OAS_TEST_ROOT:-}"
if [[ -z "$OAS_ROOT" ]]; then
  OAS_ROOT="$(oas root)"
fi
OAS_ROOT="$(canonical_dir "$OAS_ROOT")"
OAS_CLI="$OAS_ROOT/bin/oas.mjs"

assert_clean_git_subject() {
  local root="$1" label="$2" top status
  top="$(git -C "$root" rev-parse --show-toplevel 2>/dev/null)" || fail "$label proof subject is not a Git checkout: $root"
  top="$(canonical_dir "$top")"
  [[ "$top" == "$(canonical_dir "$root")" ]] || fail "$label proof subject is misattributed: selected $root but Git top-level is $top"
  status="$(git -C "$root" status --porcelain --untracked-files=no)"
  [[ -z "$status" ]] || fail "$label proof subject has tracked changes"
}

capture_execution_subject() {
  local installed="$FIXTURE_REPO/.agents/capabilities/installed/aweb-identity-attach"
  local resolved_aw
  resolved_aw="$(python3 - "$AW_BIN" <<'PY'
import pathlib, sys
print(pathlib.Path(sys.argv[1]).resolve(strict=True))
PY
)"
  [[ "$resolved_aw" == "$CLI_DIR/aw" ]] || fail "AW_BIN override/resolution escaped the declared aweb subject: $resolved_aw"
  python3 - "$EVIDENCE/executed-esm-trace.log" "$EVIDENCE/execution-subject.json" "$OAS_ROOT" "$installed" "$CAPABILITY_SOURCE" "$OAS_CLI" "$resolved_aw" "$REPO_ROOT" <<'PY'
import hashlib, json, pathlib, re, sys
from urllib.parse import unquote, urlparse
trace, output, oas_root, installed, source, oas_cli, aw_binary, repo_root = sys.argv[1:]
roots = {
    "oas": pathlib.Path(oas_root).resolve(strict=True),
    "aweb-capability": pathlib.Path(installed).resolve(strict=True),
}
node_modules_root = roots["oas"] / "node_modules"
source_root = pathlib.Path(source).resolve(strict=True)
paths = set()
for encoded in re.findall(r"file://[^\s'\]]+", pathlib.Path(trace).read_text(encoding="utf-8", errors="replace")):
    path = pathlib.Path(unquote(urlparse(encoded).path))
    if path.is_file():
        paths.add(path.resolve(strict=True))
rows = []
unknown = []
for path in sorted(paths):
    dependency = node_modules_root in path.parents
    owner = "oas-third-party-dependency" if dependency else next(
        (name for name, root in roots.items() if path == root or root in path.parents), None
    )
    if owner is None:
        unknown.append(str(path))
        continue
    root = node_modules_root if dependency else roots[owner]
    relative = path.relative_to(root).as_posix()
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if owner == "aweb-capability":
        counterpart = source_root / relative
        assert counterpart.is_file(), (path, counterpart)
        assert hashlib.sha256(counterpart.read_bytes()).hexdigest() == digest, (path, counterpart)
    row = {"subject": owner, "resolved_path": str(path), "relative_path": relative, "sha256": digest}
    if dependency:
        components = pathlib.PurePosixPath(relative).parts
        package_parts = components[:2] if components[0].startswith("@") else components[:1]
        package_root = node_modules_root.joinpath(*package_parts)
        metadata = json.loads((package_root / "package.json").read_text(encoding="utf-8"))
        row.update(package=metadata["name"], version=metadata["version"], outside_first_party_subject=True)
    rows.append(row)
assert unknown == [], {"unclassified_loaded_file_modules": unknown}
aw_path = pathlib.Path(aw_binary).resolve(strict=True)
rows.append({
    "subject": "aweb-cli",
    "resolved_path": str(aw_path),
    "relative_path": aw_path.relative_to(pathlib.Path(repo_root).resolve(strict=True)).as_posix(),
    "sha256": hashlib.sha256(aw_path.read_bytes()).hexdigest(),
})
required = {("oas", "bin/oas.mjs"), ("oas", "lib/core.mjs"), ("aweb-capability", "bin/aweb-identity-attach.mjs")}
assert required <= {(row["subject"], row["relative_path"]) for row in rows}, rows
pathlib.Path(output).write_text(json.dumps(rows, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

AWID_PORT="${OAS_PROOF_AWID_PORT:-18110}"
AWEB_PORT="${OAS_PROOF_AWEB_PORT:-18100}"
POSTGRES_PORT="${OAS_PROOF_POSTGRES_PORT:-55433}"
AWID_URL="http://127.0.0.1:$AWID_PORT"
AWEB_URL="http://127.0.0.1:$AWEB_PORT"
PROJECT="${OAS_PROOF_PROJECT:-aweb-oas-retire-proof-$(printf '%s' "$REPO_ROOT" | cksum | cut -d' ' -f1)}"
COMPOSE=(docker compose -p "$PROJECT" -f "$COMPOSE_FILE")

PROOF_ROOT="$(make_temp_dir)"
PROOF_HOME="$PROOF_ROOT/home"
CONFIG_PATH="$PROOF_HOME/.config/aw/config.yaml"
STAGING="$PROOF_ROOT/staging"
PRINCIPAL_WORKSPACE="$PROOF_ROOT/principal-workspace"
OBSERVER="$PROOF_ROOT/observer"
PRINCIPAL_HOME="$PROOF_ROOT/principal-store"
FIXTURE_REPO="$PROOF_ROOT/repo"
AGENTS_ROOT="$PROOF_ROOT/agents"
DEVELOPER_A_AGENTS_ROOT="$PROOF_ROOT/developer-a/agents"
DEVELOPER_B_AGENTS_ROOT="$PROOF_ROOT/developer-b/agents"
PROOF_BIN="$PROOF_ROOT/bin"
EVIDENCE="$PROOF_ROOT/evidence"
REPORT="${OAS_PROOF_REPORT:-${TMPDIR:-/tmp}/aweb-oas-attached-principal-proof-report.json}"
KEEP="${KEEP_OAS_PROOF:-0}"
PROOF_TMUX_DIR="$PROOF_ROOT/tmux"
PROOF_TMUX_SESSION="oas-resident-proof-$(printf '%s' "$PROOF_ROOT" | cksum | cut -d' ' -f1)"
PI_MODEL="${OAS_PROOF_PI_MODEL:-openai-codex/gpt-5.4-mini:minimal}"
[[ "$PI_MODEL" == */* ]] || { echo "FAIL: OAS_PROOF_PI_MODEL must be provider/model[:thinking]" >&2; exit 2; }
PI_PROVIDER="${PI_MODEL%%/*}"
PI_MODEL_ID="${PI_MODEL#*/}"
case "$PI_MODEL_ID" in
  *:off|*:minimal|*:low|*:medium|*:high|*:xhigh|*:max) PI_MODEL_ID="${PI_MODEL_ID%:*}" ;;
esac
mkdir -p "$PROOF_HOME" "$STAGING" "$PRINCIPAL_WORKSPACE" "$OBSERVER" "$PRINCIPAL_HOME" "$FIXTURE_REPO" "$AGENTS_ROOT" "$DEVELOPER_A_AGENTS_ROOT" "$DEVELOPER_B_AGENTS_ROOT" "$PROOF_BIN" "$EVIDENCE" "$PROOF_TMUX_DIR"
: > "$EVIDENCE/executed-esm-trace.log"

# shellcheck source=scripts/e2e/oas_tmux_safety.sh
source "$REPO_ROOT/scripts/e2e/oas_tmux_safety.sh"

assert_default_tmux_topology_unchanged() {
  local phase="$1" observed="$EVIDENCE/tmux-topology-$phase.txt"
  snapshot_default_tmux_topology "$observed" || return 1
  if ! cmp "$EVIDENCE/tmux-topology-before.txt" "$observed" >/dev/null; then
    diff -u "$EVIDENCE/tmux-topology-before.txt" "$observed" >&2 || true
    echo "FAIL: pre-existing tmux session/window/pane topology changed during resident proof" >&2
    return 1
  fi
}

cleanup() {
  local status=$? retain="$KEEP"
  trap - EXIT
  set +e
  rm -f "$PROOF_HOME/.pi/agent/auth.json"
  if [[ "$MODE" == "resident-pi" ]]; then
    if ! remove_proof_tmux_session; then
      status=1
      retain=1
    fi
    if [[ -f "$EVIDENCE/tmux-topology-before.txt" ]] && ! assert_default_tmux_topology_unchanged cleanup; then
      status=1
      retain=1
    fi
  fi
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1
  if [[ "$retain" == "1" ]]; then
    echo "Proof workspace retained for safe remediation at $PROOF_ROOT" >&2
  else
    rm -rf "$PROOF_ROOT"
  fi
  exit "$status"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

assert_clean_git_subject "$REPO_ROOT" aweb
assert_clean_git_subject "$OAS_ROOT" OAS

require_loopback() {
  case "$1" in
    http://127.0.0.1:*|http://localhost:*) ;;
    *) fail "proof endpoint is not loopback: $1" ;;
  esac
}
require_loopback "$AWID_URL"
require_loopback "$AWEB_URL"
[[ -f "$OAS_CLI" ]] || fail "OAS CLI not found at $OAS_CLI"

json_value() {
  local path="$1" dotted="$2"
  python3 - "$path" "$dotted" <<'PY'
import json, sys
path, dotted = sys.argv[1:]
text = open(path, encoding="utf-8").read()
start = text.find("{")
if start < 0:
    raise SystemExit(f"no JSON object in {path}")
decoder = json.JSONDecoder()
document, _ = decoder.raw_decode(text[start:])
if isinstance(document, dict) and document.get("schemaVersion") == 1 and "result" in document:
    document = document["result"]
value = document
for component in dotted.split(".") if dotted else []:
    value = value[component]
if isinstance(value, (dict, list)):
    print(json.dumps(value, sort_keys=True))
else:
    print(value)
PY
}

url_component() {
  python3 - "$1" <<'PY'
import sys
from urllib.parse import quote
print(quote(sys.argv[1], safe=""))
PY
}

binding_operation() {
  python3 - "$1" <<'PY'
import json, sys
meta = json.load(open(sys.argv[1], encoding="utf-8"))
print(meta["capabilityMeta"]["aweb.identity-attach"]["identity_binding"]["journal_operation"])
PY
}

normalize_json() {
  local input="$1" output="$2"
  python3 - "$input" "$output" <<'PY'
import json, sys
source, target = sys.argv[1:]
text = open(source, encoding="utf-8").read()
starts = [position for position in (text.find("{"), text.find("[")) if position >= 0]
if not starts:
    raise SystemExit(f"no JSON value in {source}")
document, _ = json.JSONDecoder().raw_decode(text[min(starts):])
if isinstance(document, dict) and document.get("schemaVersion") == 1 and "result" in document:
    document = document["result"]
with open(target, "w", encoding="utf-8") as stream:
    json.dump(document, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY
}

file_sha256() {
  python3 - "$1" <<'PY'
import hashlib, sys
print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())
PY
}

run_aw_in() {
  local directory="$1"
  shift
  (
    cd "$directory"
    env -u AWEB_IDENTITY_HOME -u AWEB_PRINCIPAL -u AWEB_API_KEY -u AW_HOME \
      HOME="$PROOF_HOME" \
      AW_CONFIG_PATH="$CONFIG_PATH" \
      AWEB_URL="$AWEB_URL" \
      AWID_REGISTRY_URL="$AWID_URL" \
      AWID_SKIP_DNS_VERIFY=1 \
      AW_NO_UPDATE_CHECK=1 \
      "$AW_BIN" "$@"
  )
}

run_observer_aw() {
  (
    cd "$OBSERVER"
    env -u AWEB_IDENTITY_HOME -u AWEB_PRINCIPAL -u AWEB_API_KEY -u AW_HOME \
      HOME="$PROOF_HOME" \
      AW_CONFIG_PATH="$CONFIG_PATH" \
      AWEB_URL="$AWEB_URL" \
      AWID_REGISTRY_URL="$AWID_URL" \
      AWID_SKIP_DNS_VERIFY=1 \
      AW_NO_UPDATE_CHECK=1 \
      "$AW_BIN" "$@"
  )
}

run_target_aw() {
  local identity_home="$1"
  shift
  (
    cd "$FIXTURE_REPO"
    env -u AWEB_IDENTITY_HOME \
      HOME="$PROOF_HOME" \
      AW_CONFIG_PATH="$CONFIG_PATH" \
      AWID_REGISTRY_URL="$AWID_URL" \
      AWID_SKIP_DNS_VERIFY=1 \
      "$AW_BIN" --identity-home "$identity_home" "$@"
  )
}

run_oas_with_agents() {
  local agents_root="$1" directory="$2"
  shift 2
  (
    cd "$directory"
    env -u AWEB_IDENTITY_HOME -u AWEB_PRINCIPAL -u AWEB_API_KEY -u AW_HOME \
      HOME="$PROOF_HOME" \
      AW_CONFIG_PATH="$CONFIG_PATH" \
      AWEB_URL="$AWEB_URL" \
      AWID_REGISTRY_URL="$AWID_URL" \
      AWID_SKIP_DNS_VERIFY=1 \
      AW_NO_UPDATE_CHECK=1 \
      AWEB_PRINCIPAL_HOME="$PRINCIPAL_HOME" \
      PI_AGENTS_ROOT="$agents_root" \
      PI_AGENTS_TMUX_SESSION="$PROOF_TMUX_SESSION" \
      PI_SKIP_VERSION_CHECK=1 \
      PI_TELEMETRY=0 \
      TMUX= \
      TMUX_TMPDIR="$PROOF_TMUX_DIR" \
      PATH="$TMUX_GUARD_DIR:$PROOF_BIN:$CLI_DIR:$PATH" \
      NODE_DEBUG=esm node "$OAS_CLI" "$@" 2> >(tee -a "$EVIDENCE/executed-esm-trace.log" >&2)
  )
}

run_oas_in() {
  local directory="$1"
  shift
  run_oas_with_agents "$AGENTS_ROOT" "$directory" "$@"
}

wait_health() {
  local label="$1" url="$2"
  local attempt
  for attempt in $(seq 1 90); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      echo "  $label healthy"
      return 0
    fi
    sleep 2
  done
  "${COMPOSE[@]}" ps >&2 || true
  "${COMPOSE[@]}" logs --tail=50 >&2 || true
  fail "$label did not become healthy at $url"
}

capture_registry() {
  local phase="$1"
  local prefix="$EVIDENCE/registry-$phase"
  curl -fsS "$AWID_URL/v1/namespaces/proof.local/addresses/resident" > "$prefix-address.raw.json"
  normalize_json "$prefix-address.raw.json" "$prefix-address.json"
  run_observer_aw id resolve "$DID_AW" --json > "$prefix-resolve.raw.json"
  normalize_json "$prefix-resolve.raw.json" "$prefix-resolve-envelope.json"
  python3 - "$prefix-resolve-envelope.json" "$prefix-resolve.json" <<'PY'
import json, sys
document = json.load(open(sys.argv[1], encoding="utf-8"))
if "payload" in document:
    payload = document["payload"]
    projected = {
        "authoritative": document.get("authoritative"),
        "status": payload.get("status"),
        "registry_url": payload.get("registry_url"),
        **payload["did_key"],
    }
else:
    projected = document
with open(sys.argv[2], "w", encoding="utf-8") as stream:
    json.dump(projected, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY
  run_observer_aw id verify "$DID_AW" --json > "$prefix-verify.raw.json"
  normalize_json "$prefix-verify.raw.json" "$prefix-verify.json"
  python3 - "$prefix-address.json" "$prefix-resolve.json" "$prefix-verify.json" "$DID_AW" "$DID_KEY" <<'PY'
import json, sys
address_path, resolve_path, verify_path, expected_stable, expected_key = sys.argv[1:]
address = json.load(open(address_path, encoding="utf-8"))
resolution = json.load(open(resolve_path, encoding="utf-8"))
verification = json.load(open(verify_path, encoding="utf-8"))
assert address["domain"] == "proof.local"
assert address["name"] == "resident"
assert address["did_aw"] == expected_stable
assert address["current_did_key"] == expected_key
assert resolution["did_aw"] == expected_stable
assert resolution["current_did_key"] == expected_key
assert resolution.get("status", "ok").lower() == "ok"
assert resolution.get("authoritative", True) is True
assert verification["did_aw"] == expected_stable
assert verification["current_did_key"] == expected_key
assert verification["status"] == "OK"
assert verification["entry_count"] >= 1
PY
}

compare_registry_to_pre() {
  local phase="$1"
  for kind in address resolve verify; do
    cmp "$EVIDENCE/registry-pre-$kind.json" "$EVIDENCE/registry-$phase-$kind.json" >/dev/null \
      || fail "registry $kind changed between pre and $phase"
  done
}

assert_principal_unchanged() {
  local phase="$1" observed="$EVIDENCE/principal-$phase.json"
  python3 "$PROOF_HELPER" snapshot --root "$PRINCIPAL_DIR" --output "$observed"
  cmp "$EVIDENCE/principal-pre.json" "$observed" >/dev/null \
    || fail "principal file inventory changed at $phase"
  echo "  principal store unchanged at $phase"
}

scan_instance() {
  local phase="$1" observation="$EVIDENCE/instance-$phase-scan.json"
  if [[ "$MODE" == "resident-pi" ]]; then
    # scan-sensitive-material is owned by the shared .28 proof helper. This
    # harness consumes that reviewed detector; it does not fork its policy.
    python3 "$PROOF_HELPER" scan-sensitive-material \
      --principal-snapshot "$EVIDENCE/principal-pre.json" \
      --instance "$INSTANCE_HOME"
    python3 - "$INSTANCE_HOME" "$observation" <<'PY'
import json, os, stat, sys
root, output = sys.argv[1:]
entries = []
for current, directories, files in os.walk(root, followlinks=False):
    for name in sorted([*directories, *files]):
        path = os.path.join(current, name)
        info = os.lstat(path)
        entries.append({
            "path": os.path.relpath(path, root),
            "kind": "symlink" if stat.S_ISLNK(info.st_mode) else "directory" if stat.S_ISDIR(info.st_mode) else "file",
            "device": info.st_dev, "inode": info.st_ino, "size": info.st_size,
        })
with open(output, "w", encoding="utf-8") as stream:
    json.dump({
        "scanner": "shared scan-sensitive-material",
        "forbidden_principal_material_found": False,
        "allowed_runtime_state": sorted(
            entry["path"] for entry in entries if entry["path"].startswith(".aw/")
        ),
        "entries": entries,
    }, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY
  else
    python3 "$PROOF_HELPER" scan-instance \
      --principal-snapshot "$EVIDENCE/principal-pre.json" \
      --instance "$INSTANCE_HOME"
  fi
  echo "  instance contains no principal material at $phase"
}

scan_provisioned_material() {
  local operation="$1" label="$2"
  shift 2
  local intent="$PRINCIPAL_HOME/.provisioning/intents/$operation.json"
  local target snapshot controlled
  target="$(json_value "$intent" resource.identity_home)"
  snapshot="$EVIDENCE/$label-credential-snapshot.json"
  python3 "$PROOF_HELPER" snapshot --root "$target" --output "$snapshot"
  for controlled in "$@"; do
    python3 "$PROOF_HELPER" scan-instance --principal-snapshot "$snapshot" --instance "$controlled"
  done
}

scan_provisioned_sensitive_material() {
  local label="$1"
  shift
  local snapshot="$EVIDENCE/$label-credential-snapshot.json" controlled
  [[ -f "$snapshot" ]] || fail "missing credential snapshot for sensitive scan: $label"
  for controlled in "$@"; do
    [[ -e "$controlled" ]] || continue
    python3 "$PROOF_HELPER" scan-sensitive-material --principal-snapshot "$snapshot" --instance "$controlled"
  done
}

preserve_known_material_for_final_scan() {
  local label="$1" source="$2" vault
  vault="$PROOF_ROOT/known-material/$label"
  mkdir -p "$PROOF_ROOT/known-material"
  chmod 700 "$PROOF_ROOT/known-material"
  cp -R "$source" "$vault"
  python3 "$PROOF_HELPER" snapshot --root "$vault" --output "$EVIDENCE/$label-final-credential-snapshot.json"
}

scan_final_known_material() {
  local label="$1"
  shift
  local snapshot="$EVIDENCE/$label-final-credential-snapshot.json" controlled
  for controlled in "$@"; do
    [[ -e "$controlled" ]] || continue
    python3 "$PROOF_HELPER" scan-sensitive-material --principal-snapshot "$snapshot" --instance "$controlled"
  done
}

capture_owning_state() {
  local label="$1" prefix="$EVIDENCE/owning-$1"
  python3 - "$PRINCIPAL_HOME/.provisioning/intents" "$prefix-intents.json" <<'PY'
import hashlib, json, pathlib, sys
root, output = map(pathlib.Path, sys.argv[1:])
rows = []
if root.is_dir():
    for path in sorted(root.glob("*.json")):
        rows.append({"file": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
output.write_text(json.dumps(rows, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
  local table
  for table in agents workspaces task_claims reservations; do
    docker exec "$POSTGRES_CONTAINER" psql -U aweb -d aweb -At -c \
      "SELECT COALESCE(json_agg(row_to_json(rows) ORDER BY row_to_json(rows)::text)::text, '[]') FROM (SELECT * FROM aweb.$table) rows;" \
      > "$prefix-sql-$table.raw.json"
    normalize_json "$prefix-sql-$table.raw.json" "$prefix-sql-$table.json"
  done
  python3 - "$PROOF_HOME/.config/aw/team-invites" "$prefix-grants.json" <<'PY'
import hashlib, json, pathlib, sys
root, output = map(pathlib.Path, sys.argv[1:])
rows = []
if root.is_dir():
    for path in sorted(root.glob("*.json")):
        rows.append({"file": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
output.write_text(json.dumps(rows, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
  run_observer_aw id team members --team-id "$TEAM_ID" --registry "$AWID_URL" --include-revoked --json > "$prefix-members.raw.json"
  normalize_json "$prefix-members.raw.json" "$prefix-members.json"
  if [[ -e "$PRINCIPAL_HOME/.provisioning" || -L "$PRINCIPAL_HOME/.provisioning" ]]; then
    python3 "$PROOF_HELPER" snapshot-structure --root "$PRINCIPAL_HOME/.provisioning" --output "$prefix-provisioning.json"
  else
    printf '{"state":"absent"}\n' > "$prefix-provisioning.json"
  fi
  python3 - "$REDIS_CONTAINER" "$prefix-redis.json" <<'PY'
import json, pathlib, subprocess, sys
container, output = sys.argv[1:]
def redis(*args):
    return subprocess.check_output(["docker", "exec", container, "redis-cli", "--raw", *args], text=True).splitlines()
rows = []
for key in sorted(redis("KEYS", "*")):
    kind = redis("TYPE", key)[0]
    row = {"key": key, "type": kind, "expire_at_ms": int(redis("PEXPIRETIME", key)[0])}
    if kind == "string": row["value"] = "\n".join(redis("GET", key))
    elif kind == "set": row["value"] = sorted(redis("SMEMBERS", key))
    elif kind == "hash":
        values = redis("HGETALL", key)
        row["value"] = sorted(zip(values[::2], values[1::2]))
    elif kind == "zset": row["value"] = redis("ZRANGE", key, "0", "-1", "WITHSCORES")
    elif kind == "list": row["value"] = redis("LRANGE", key, "0", "-1")
    elif kind == "stream": row["value"] = redis("XRANGE", key, "-", "+")
    else: raise AssertionError((key, kind))
    rows.append(row)
pathlib.Path(output).write_text(json.dumps(rows, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

assert_owning_state_same() {
  local before="$1" after="$2" label="$3" kind
  for kind in intents sql-agents sql-workspaces sql-task_claims sql-reservations grants members provisioning redis; do
    cmp "$EVIDENCE/owning-$before-$kind.json" "$EVIDENCE/owning-$after-$kind.json" >/dev/null \
      || fail "$label mutated owning $kind state"
  done
}

assert_pre_activation_state() {
  local lock="$1" config="$2" artifact="$3"
  python3 - "$lock" "$config" "$artifact" <<'PY'
import json, pathlib, sys
lock_path, config_path, artifact = sys.argv[1:]
manifest = json.load(open(pathlib.Path(artifact, "oas.json"), encoding="utf-8"))
assert manifest["capability"] == "aweb.identity-attach", manifest
lock = json.load(open(lock_path, encoding="utf-8"))["capabilities"]["aweb.identity-attach"]
assert lock["trustedExecutables"] is False, lock
config = pathlib.Path(config_path).read_text(encoding="utf-8")
assert "capabilities:" not in config and "aweb.identity-attach" not in config, config
PY
}

assert_worker_doctor_state() {
  local doctor="$1"
  python3 - "$doctor" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
assert doc["layers"]["messaging"]["integration"] == "aweb.identity-attach", doc
caps = [cap for cap in doc["capabilities"] if cap["id"] == "aweb.identity-attach"]
assert len(caps) == 1, caps
cap = caps[0]
assert cap["trust"]["trusted"] is True, cap
assert cap["origin"].startswith("installed:"), cap
assert "spawn" in cap["hooks"], cap
assert cap["settings"]["identity_binding"] == {
    "schema_version": 2,
    "mode": "provision-disposable",
    "minting_authority": "resident",
    "minting_authority_path": "local-controller",
}, cap
PY
}

capture_operation_grants() {
  local label="$1"
  shift
  python3 - "$PROOF_HOME/.config/aw/team-invites" "$EVIDENCE/grants-$label.json" "$TEAM_ID" "$@" <<'PY'
import hashlib, json, pathlib, sys
root, output, expected_team, *specs = sys.argv[1:]
expected = {}
for spec in specs:
    operation, count = spec.rsplit("=", 1)
    expected[operation] = int(count)
rows = {operation: [] for operation in expected}
unmatched = []
root_path = pathlib.Path(root)
if root_path.is_dir():
    for path in sorted(root_path.glob("*.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        operation = document.get("operation_id")
        projected = {
            "file": path.name,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "invite_id": document.get("invite_id"),
            "operation_id": operation,
            "team_id": f'{document.get("team_name")}:{document.get("domain")}',
            "ephemeral": document.get("ephemeral"),
            "registry_url": document.get("registry_url"),
            "aweb_url": document.get("aweb_url"),
            "bearer_present": bool(document.get("secret")),
            "bearer_sha256": hashlib.sha256(document.get("secret", "").encode()).hexdigest(),
        }
        if operation in rows:
            rows[operation].append(projected)
        else:
            unmatched.append(projected)
assert unmatched == [], unmatched
for operation, count in expected.items():
    assert len(rows[operation]) == count, (operation, rows[operation], count)
    for row in rows[operation]:
        assert row["operation_id"] == operation, row
        assert row["team_id"] == expected_team, row
        assert row["ephemeral"] is True and row["bearer_present"] is True, row
pathlib.Path(output).write_text(json.dumps(rows, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

assert_operation_grant_isolation() {
  local before="$1" after="$2" removed="$3" survivor="${4:-}"
  python3 - "$EVIDENCE/grants-$before.json" "$EVIDENCE/grants-$after.json" "$removed" "$survivor" <<'PY'
import json, sys
before_path, after_path, removed, survivor = sys.argv[1:]
before = json.load(open(before_path, encoding="utf-8"))
after = json.load(open(after_path, encoding="utf-8"))
assert len(before[removed]) == 1 and after[removed] == [], (before, after, removed)
if survivor:
    assert len(before[survivor]) == 1 and after[survivor] == before[survivor], (before, after, survivor)
PY
}

seed_provision_lifecycle_artifacts() {
  local operation="$1"
  local intent="$PRINCIPAL_HOME/.provisioning/intents/$operation.json"
  local alias agent workspace encoded_team encoded_alias coordinates_ttl
  alias="$(json_value "$intent" resource.alias)"
  agent="$(json_value "$intent" resource.agent_id)"
  workspace="$(json_value "$intent" resource.workspace_id)"
  docker exec "$POSTGRES_CONTAINER" psql -U aweb -d aweb -v ON_ERROR_STOP=1 -q -c \
    "INSERT INTO aweb.task_claims(team_id, workspace_id, alias, task_ref) VALUES ('$TEAM_ID', '$workspace', '$alias', 'proof-$operation');
     INSERT INTO aweb.reservations(team_id, resource_key, holder_alias, holder_agent_id) VALUES ('$TEAM_ID', 'proof:$operation', '$alias', '$agent');"
  encoded_team="$(url_component "$TEAM_ID")"
  encoded_alias="$(url_component "$alias")"
  docker exec "$REDIS_CONTAINER" redis-cli HSET "presence:$workspace" workspace_id "$workspace" alias "$alias" team_id "$TEAM_ID" repo_id "" current_branch "" >/dev/null
  docker exec "$REDIS_CONTAINER" redis-cli HSET "presence_coordinates:$workspace" \
    "set:idx:all_workspaces" 1 \
    "set:idx:team_workspaces:$TEAM_ID" 1 \
    "alias:idx:alias:$encoded_team:$encoded_alias" "$workspace" >/dev/null
  docker exec "$REDIS_CONTAINER" redis-cli HSET "presence:$agent" workspace_id "$agent" alias "$alias" team_id "$TEAM_ID" repo_id "" current_branch "" >/dev/null
  docker exec "$REDIS_CONTAINER" redis-cli HSET "presence_coordinates:$agent" \
    "set:idx:all_workspaces" 1 \
    "set:idx:team_workspaces:$TEAM_ID" 1 \
    "alias:idx:alias:$encoded_team:$encoded_alias" "$agent" >/dev/null
  docker exec "$REDIS_CONTAINER" redis-cli SADD idx:all_workspaces "$workspace" "$agent" >/dev/null
  docker exec "$REDIS_CONTAINER" redis-cli SADD "idx:team_workspaces:$TEAM_ID" "$workspace" "$agent" >/dev/null
  docker exec "$REDIS_CONTAINER" redis-cli SET "idx:alias:$encoded_team:$encoded_alias" "$workspace" EX 3600 >/dev/null
  docker exec "$REDIS_CONTAINER" redis-cli EXPIRE idx:all_workspaces 3600 >/dev/null
  docker exec "$REDIS_CONTAINER" redis-cli EXPIRE "idx:team_workspaces:$TEAM_ID" 3600 >/dev/null
  docker exec "$REDIS_CONTAINER" redis-cli PERSIST "presence_coordinates:$workspace" >/dev/null
  docker exec "$REDIS_CONTAINER" redis-cli PERSIST "presence_coordinates:$agent" >/dev/null
  [[ "$(docker exec "$POSTGRES_CONTAINER" psql -U aweb -d aweb -At -c "SELECT COUNT(*) FROM aweb.task_claims WHERE workspace_id = '$workspace';")" == "1" ]] \
    || fail "task-claim positive control was not created for $operation"
  [[ "$(docker exec "$POSTGRES_CONTAINER" psql -U aweb -d aweb -At -c "SELECT COUNT(*) FROM aweb.reservations WHERE holder_agent_id = '$agent';")" == "1" ]] \
    || fail "reservation positive control was not created for $operation"
  [[ "$(docker exec "$REDIS_CONTAINER" redis-cli EXISTS "presence:$workspace")" == "1" ]] \
    || fail "presence positive control was not created for $operation"
  [[ "$(docker exec "$REDIS_CONTAINER" redis-cli SISMEMBER "idx:team_workspaces:$TEAM_ID" "$workspace")" == "1" ]] \
    || fail "team presence index positive control was not created for $operation"
  [[ "$(docker exec "$REDIS_CONTAINER" redis-cli GET "idx:alias:$encoded_team:$encoded_alias")" == "$workspace" ]] \
    || fail "alias presence index positive control was not created for $operation"
  docker exec "$REDIS_CONTAINER" redis-cli DEL "presence:$workspace" "presence:$agent" >/dev/null
  [[ "$(docker exec "$REDIS_CONTAINER" redis-cli EXISTS "presence:$workspace")" == "0" ]] \
    || fail "workspace primary presence did not expire before lifecycle cleanup for $operation"
  [[ "$(docker exec "$REDIS_CONTAINER" redis-cli EXISTS "presence:$agent")" == "0" ]] \
    || fail "agent-heartbeat primary presence did not expire before lifecycle cleanup for $operation"
  [[ "$(docker exec "$REDIS_CONTAINER" redis-cli EXISTS "presence_coordinates:$workspace")" == "1" ]] \
    || fail "durable workspace presence coordinates were not retained after primary expiry for $operation"
  [[ "$(docker exec "$REDIS_CONTAINER" redis-cli EXISTS "presence_coordinates:$agent")" == "1" ]] \
    || fail "durable agent-heartbeat coordinates were not retained after primary expiry for $operation"
  coordinates_ttl="$(docker exec "$REDIS_CONTAINER" redis-cli TTL "presence_coordinates:$workspace")"
  [[ "$coordinates_ttl" == "-1" && "$(docker exec "$REDIS_CONTAINER" redis-cli TTL "presence_coordinates:$agent")" == "-1" ]] \
    || fail "presence cleanup coordinates are not durable until explicit cleanup for $operation"
  [[ "$(docker exec "$REDIS_CONTAINER" redis-cli SISMEMBER idx:all_workspaces "$agent")" == "1" ]] \
    || fail "agent-heartbeat global membership was not created for $operation"
  [[ "$(docker exec "$REDIS_CONTAINER" redis-cli SISMEMBER "idx:team_workspaces:$TEAM_ID" "$agent")" == "1" ]] \
    || fail "agent-heartbeat team membership was not created for $operation"
  if [[ "$operation" == "$VICTIM_OPERATION" ]]; then
    docker exec "$REDIS_CONTAINER" redis-cli DEL "presence_coordinates:$workspace" >/dev/null
    [[ "$(docker exec "$REDIS_CONTAINER" redis-cli EXISTS "presence_coordinates:$workspace")" == "0" ]] \
      || fail "pre-coordinate fallback fixture retained reverse coordinates for $operation"
  fi
  [[ "$(docker exec "$REDIS_CONTAINER" redis-cli SISMEMBER idx:all_workspaces "$workspace")" == "1" ]] \
    || fail "global presence index did not outlive primary for $operation"
  [[ "$(docker exec "$REDIS_CONTAINER" redis-cli SISMEMBER "idx:team_workspaces:$TEAM_ID" "$workspace")" == "1" ]] \
    || fail "team presence index did not outlive primary for $operation"
  [[ "$(docker exec "$REDIS_CONTAINER" redis-cli GET "idx:alias:$encoded_team:$encoded_alias")" == "$workspace" ]] \
    || fail "alias presence index did not outlive primary for $operation"
}

capture_durable_operation_tuple() {
  local label="$1" operation="$2" prefix="$EVIDENCE/tuple-$1"
  local intent alias certificate agent workspace target
  intent="$PRINCIPAL_HOME/.provisioning/intents/$operation.json"
  alias="$(json_value "$intent" resource.alias)"
  certificate="$(json_value "$intent" resource.certificate_id)"
  agent="$(json_value "$intent" resource.agent_id)"
  workspace="$(json_value "$intent" resource.workspace_id)"
  target="$(json_value "$intent" resource.identity_home)"
  run_observer_aw id team members --team-id "$TEAM_ID" --registry "$AWID_URL" --include-revoked --json > "$prefix-members.raw.json"
  normalize_json "$prefix-members.raw.json" "$prefix-members.json"
  python3 - "$prefix-members.json" "$prefix-member.json" "$alias" "$certificate" <<'PY'
import json, pathlib, sys
source, output, alias, certificate = sys.argv[1:]
rows = [row for row in json.load(open(source, encoding="utf-8"))["members"] if row["alias"] == alias and row["certificate_id"] == certificate]
assert len(rows) == 1, rows
pathlib.Path(output).write_text(json.dumps(rows[0], indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
  docker exec "$POSTGRES_CONTAINER" psql -U aweb -d aweb -At -c "SELECT row_to_json(rows)::text FROM (SELECT * FROM aweb.agents WHERE agent_id = '$agent') rows;" > "$prefix-agent.raw.json"
  normalize_json "$prefix-agent.raw.json" "$prefix-agent.json"
  docker exec "$POSTGRES_CONTAINER" psql -U aweb -d aweb -At -c "SELECT row_to_json(rows)::text FROM (SELECT * FROM aweb.workspaces WHERE workspace_id = '$workspace') rows;" > "$prefix-workspace.raw.json"
  normalize_json "$prefix-workspace.raw.json" "$prefix-workspace.json"
  cp "$intent" "$prefix-intent.json"
  python3 "$PROOF_HELPER" snapshot-structure --root "$target" --output "$prefix-target.json"
}

assert_durable_operation_tuple_same() {
  local before="$1" after="$2" suffix
  for suffix in member.json agent.json workspace.json intent.json target.json; do
    cmp -s "$EVIDENCE/tuple-$before-$suffix" "$EVIDENCE/tuple-$after-$suffix" \
      || fail "durable operation tuple changed across isolated cleanup: $before -> $after ($suffix)"
  done
}

capture_provision_resource() {
  local phase="$1" operation="$2" expected="$3"
  local intent="$PRINCIPAL_HOME/.provisioning/intents/$operation.json"
  local alias certificate agent workspace target encoded_team encoded_alias
  alias="$(json_value "$intent" resource.alias)"
  certificate="$(json_value "$intent" resource.certificate_id)"
  agent="$(json_value "$intent" resource.agent_id)"
  workspace="$(json_value "$intent" resource.workspace_id)"
  target="$(json_value "$intent" resource.identity_home)"
  encoded_team="$(url_component "$TEAM_ID")"
  encoded_alias="$(url_component "$alias")"

  run_observer_aw id team members --team-id "$TEAM_ID" --registry "$AWID_URL" \
    --include-revoked --json > "$EVIDENCE/$phase-members.raw.json"
  normalize_json "$EVIDENCE/$phase-members.raw.json" "$EVIDENCE/$phase-members.json"
  python3 - "$EVIDENCE/$phase-members.json" "$alias" "$certificate" "$expected" <<'PY'
import json, sys
path, alias, certificate, expected = sys.argv[1:]
document = json.load(open(path, encoding="utf-8"))
rows = [row for row in document["members"] if row["alias"] == alias and row["certificate_id"] == certificate]
assert len(rows) == 1, rows
revoked = bool(rows[0].get("revoked_at"))
assert revoked == (expected == "deleted"), rows[0]
PY

  local agent_row workspace_row
  agent_row="$(docker exec "$POSTGRES_CONTAINER" psql -U aweb -d aweb -At -F '|' -c \
    "SELECT status, deleted_at IS NOT NULL FROM aweb.agents WHERE agent_id = '$agent';")"
  workspace_row="$(docker exec "$POSTGRES_CONTAINER" psql -U aweb -d aweb -At -F '|' -c \
    "SELECT deleted_at IS NOT NULL FROM aweb.workspaces WHERE workspace_id = '$workspace';")"
  if [[ "$expected" == "active" ]]; then
    [[ "$agent_row" == "active|f" ]] || fail "$phase agent is not active at owning aweb authority: $agent_row"
    [[ "$workspace_row" == "f" ]] || fail "$phase workspace is not active at owning aweb authority: $workspace_row"
  else
    [[ "$agent_row" == "deleted|t" ]] || fail "$phase agent is not soft-deleted at owning aweb authority: $agent_row"
    [[ "$workspace_row" == "t" ]] || fail "$phase workspace is not soft-deleted at owning aweb authority: $workspace_row"
    [[ -f "$target/provision-operation.json" ]] || fail "$phase retained operation audit is missing"
    [[ "$(find "$target" -mindepth 1 -maxdepth 1 -print | wc -l | tr -d ' ')" == "1" ]] \
      || fail "$phase credential tree retains material beyond the operation audit"
    if [[ -d "$PROOF_HOME/.config/aw/team-invites" ]] && grep -R -F -q "$operation" "$PROOF_HOME/.config/aw/team-invites"; then
      fail "$phase still has a usable local invite grant for $operation"
    fi
    [[ "$(docker exec "$POSTGRES_CONTAINER" psql -U aweb -d aweb -At -c "SELECT COUNT(*) FROM aweb.task_claims WHERE workspace_id = '$workspace';")" == "0" ]] \
      || fail "$phase retained a live task claim"
    [[ "$(docker exec "$POSTGRES_CONTAINER" psql -U aweb -d aweb -At -c "SELECT COUNT(*) FROM aweb.reservations WHERE holder_agent_id = '$agent';")" == "0" ]] \
      || fail "$phase retained a live reservation"
    [[ "$(docker exec "$REDIS_CONTAINER" redis-cli EXISTS "presence:$workspace")" == "0" ]] \
      || fail "$phase retained workspace presence"
    [[ "$(docker exec "$REDIS_CONTAINER" redis-cli EXISTS "presence_coordinates:$workspace")" == "0" ]] \
      || fail "$phase retained durable workspace presence cleanup coordinates"
    [[ "$(docker exec "$REDIS_CONTAINER" redis-cli EXISTS "presence:$agent")" == "0" ]] \
      || fail "$phase retained agent-heartbeat presence"
    [[ "$(docker exec "$REDIS_CONTAINER" redis-cli EXISTS "presence_coordinates:$agent")" == "0" ]] \
      || fail "$phase retained durable agent-heartbeat cleanup coordinates"
    [[ "$(docker exec "$REDIS_CONTAINER" redis-cli SISMEMBER idx:all_workspaces "$agent")" == "0" ]] \
      || fail "$phase retained the agent-heartbeat global membership"
    [[ "$(docker exec "$REDIS_CONTAINER" redis-cli SISMEMBER "idx:team_workspaces:$TEAM_ID" "$agent")" == "0" ]] \
      || fail "$phase retained the agent-heartbeat team membership"
    [[ "$(docker exec "$REDIS_CONTAINER" redis-cli SISMEMBER idx:all_workspaces "$workspace")" == "0" ]] \
      || fail "$phase retained the global presence index"
    [[ "$(docker exec "$REDIS_CONTAINER" redis-cli SISMEMBER "idx:team_workspaces:$TEAM_ID" "$workspace")" == "0" ]] \
      || fail "$phase retained the team presence index"
    [[ "$(docker exec "$REDIS_CONTAINER" redis-cli EXISTS "idx:alias:$encoded_team:$encoded_alias")" == "0" ]] \
      || fail "$phase retained the alias presence index"
    [[ "$(json_value "$intent" state)" == "complete" ]] || fail "$phase external journal is not terminal complete"
  fi
}

run_reconcile() {
  (
    cd "$FIXTURE_REPO"
    env -u OAS_EVENT -u OAS_META -u OAS_SETTINGS -u AWEB_IDENTITY_HOME -u AWEB_PRINCIPAL -u AWEB_API_KEY -u AW_HOME \
      HOME="$PROOF_HOME" AW_CONFIG_PATH="$CONFIG_PATH" AWEB_URL="$AWEB_URL" AWID_REGISTRY_URL="$AWID_URL" AWID_SKIP_DNS_VERIFY=1 AW_NO_UPDATE_CHECK=1 \
      AWEB_PRINCIPAL_HOME="$PRINCIPAL_HOME" PATH="$PROOF_BIN:$CLI_DIR:$PATH" \
      NODE_DEBUG=esm node "$OAS_CLI" aweb-identity reconcile "$@" 2> >(tee -a "$EVIDENCE/executed-esm-trace.log" >&2)
  )
}

echo "=== Pin clean tracked proof subjects and build the real aw CLI ==="
[[ "$(git -C "$REPO_ROOT" rev-parse --show-toplevel)" == "$REPO_ROOT" ]] \
  || fail "aweb proof source is not its own git top-level"
[[ "$(git -C "$OAS_ROOT" rev-parse --show-toplevel)" == "$OAS_ROOT" ]] \
  || fail "OAS_TEST_ROOT is not its own git top-level: $OAS_ROOT"
git -C "$REPO_ROOT" diff --quiet && git -C "$REPO_ROOT" diff --cached --quiet \
  || fail "aweb proof source has tracked changes"
git -C "$OAS_ROOT" diff --quiet && git -C "$OAS_ROOT" diff --cached --quiet \
  || fail "local OAS proof source has tracked changes"
SOURCE_SHA="$(git -C "$REPO_ROOT" rev-parse HEAD)"
OAS_SOURCE_SHA="$(git -C "$OAS_ROOT" rev-parse HEAD)"
make -C "$CLI_DIR" build
[[ -x "$AW_BIN" ]] || fail "aw binary was not built at $AW_BIN"
AW_BIN_SHA="$(file_sha256 "$AW_BIN")"
OAS_BIN_SHA="$(file_sha256 "$OAS_CLI")"
OAS_CORE_SHA="$(file_sha256 "$OAS_ROOT/lib/core.mjs")"
PI_LAUNCH_PATH=""
PI_BIN_SHA=""
PI_VERSION=""
PI_EXTENSION_SHA=""

if [[ "$MODE" == "resident-pi" ]]; then
  echo "=== Prepare the source Pi extension and isolated model session ==="
  snapshot_default_tmux_topology "$EVIDENCE/tmux-topology-before.txt" \
    || fail "could not snapshot pre-existing tmux session/window/pane topology"
  [[ -f "$HOST_PI_AUTH" ]] || fail "Pi model authentication not found at $HOST_PI_AUTH"
  PI_LAUNCH_PATH="$(command -v pi)"
  [[ -n "$PI_LAUNCH_PATH" && -x "$PI_LAUNCH_PATH" ]] || fail "real Pi runtime not found on PATH"
  PI_BIN_SHA="$(file_sha256 "$PI_LAUNCH_PATH")"
  PI_VERSION="$(pi --version)"
  npm --prefix "$PI_EXTENSION_DIR" run build > "$EVIDENCE/pi-extension-build.txt"
  PI_EXTENSION_SHA="$(file_sha256 "$PI_EXTENSION_DIR/dist/index.js")"
  mkdir -p "$PROOF_HOME/.pi/agent/sessions"
  install -m 600 "$HOST_PI_AUTH" "$PROOF_HOME/.pi/agent/auth.json"
  env HOME="$PROOF_HOME" PI_CODING_AGENT_DIR="$PROOF_HOME/.pi/agent" \
    PI_SKIP_VERSION_CHECK=1 PI_TELEMETRY=0 \
    pi install "$PI_EXTENSION_DIR" > "$EVIDENCE/pi-install.txt"
  env HOME="$PROOF_HOME" PI_CODING_AGENT_DIR="$PROOF_HOME/.pi/agent" \
    PI_SKIP_VERSION_CHECK=1 PI_TELEMETRY=0 \
    pi list > "$EVIDENCE/pi-list.txt"
  grep -F -q "$PI_EXTENSION_DIR" "$EVIDENCE/pi-list.txt" \
    || fail "isolated Pi config did not resolve the source extension"
  [[ -z "$(find "$PROOF_HOME/.pi/agent/sessions" -type f -name '*.jsonl' -print -quit)" ]] \
    || fail "isolated Pi session store was not empty before production spawn"
else
  printf '#!/bin/sh\nexit 0\n' > "$PROOF_BIN/pi"
  chmod +x "$PROOF_BIN/pi"
fi

echo "=== Start a fresh loopback tmpfs-backed AWID + aweb stack ==="
export LIBRARY_E2E_AWID_PORT="$AWID_PORT"
export LIBRARY_E2E_AWEB_PORT="$AWEB_PORT"
export LIBRARY_E2E_POSTGRES_PORT="$POSTGRES_PORT"
export LIBRARY_E2E_AWID_PUBLIC_REGISTRY_URL="$AWID_URL"
export LIBRARY_E2E_AWEB_PUBLIC_ORIGIN="$AWEB_URL"
"${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
"${COMPOSE[@]}" up --build -d awid aweb
wait_health awid "$AWID_URL/health"
wait_health aweb "$AWEB_URL/health"
POSTGRES_CONTAINER="$("${COMPOSE[@]}" ps -q postgres)"
REDIS_CONTAINER="$("${COMPOSE[@]}" ps -q redis)"
[[ -n "$POSTGRES_CONTAINER" ]] || fail "proof postgres container is missing"
[[ -n "$REDIS_CONTAINER" ]] || fail "proof redis container is missing"
docker inspect -f '{{json .HostConfig.Tmpfs}}' "$POSTGRES_CONTAINER" | grep -q '/var/lib/postgresql/data' \
  || fail "proof postgres does not use tmpfs"

echo "=== Create a new throwaway durable principal only on the local stack ==="
run_aw_in "$STAGING" id create --name resident --domain proof.local --registry "$AWID_URL" --skip-dns-verify --json > "$EVIDENCE/create.json"
DID_AW="$(json_value "$EVIDENCE/create.json" did_aw)"
DID_KEY="$(json_value "$EVIDENCE/create.json" did_key)"
ADDRESS="$(json_value "$EVIDENCE/create.json" address)"
[[ "$DID_AW" == did:aw:* ]] || fail "identity creation returned no did:aw"
[[ "$DID_KEY" == did:key:* ]] || fail "identity creation returned no did:key"
[[ "$ADDRESS" == "proof.local/resident" ]] || fail "unexpected principal address: $ADDRESS"
PRINCIPAL_ID="${DID_AW#did:aw:}"
PRINCIPAL_DIR="$PRINCIPAL_HOME/proofteam/proof.local/$PRINCIPAL_ID"
mkdir -p "$PRINCIPAL_DIR"
mv "$STAGING/.aw" "$PRINCIPAL_WORKSPACE/.aw"

run_aw_in "$PRINCIPAL_WORKSPACE" id team create --name proofteam --namespace proof.local --registry "$AWID_URL" --json > "$EVIDENCE/team-create.json"
TEAM_ID="$(json_value "$EVIDENCE/team-create.json" team_id)"
[[ "$TEAM_ID" == "proofteam:proof.local" ]] || fail "unexpected team id: $TEAM_ID"
run_aw_in "$PRINCIPAL_WORKSPACE" id team invite --team proofteam --namespace proof.local --member-global --json > "$EVIDENCE/principal-invite.json"
PRINCIPAL_INVITE="$(json_value "$EVIDENCE/principal-invite.json" token)"
run_aw_in "$PRINCIPAL_WORKSPACE" id team accept-invite "$PRINCIPAL_INVITE" --global --name resident --json > "$EVIDENCE/principal-accept.json"
run_aw_in "$PRINCIPAL_WORKSPACE" init --url "$AWEB_URL" > "$EVIDENCE/principal-init.txt"

# A distinct initialized workspace triggers the gone-workspace sweep after retire.
run_observer_aw id create --name observer --domain proof.local --registry "$AWID_URL" --skip-dns-verify --json > "$EVIDENCE/observer-create.json"
OBSERVER_DID_AW="$(json_value "$EVIDENCE/observer-create.json" did_aw)"
OBSERVER_DID_KEY="$(json_value "$EVIDENCE/observer-create.json" did_key)"
OBSERVER_ADDRESS="$(json_value "$EVIDENCE/observer-create.json" address)"
[[ "$OBSERVER_DID_AW" == did:aw:* && "$OBSERVER_DID_KEY" == did:key:* ]] \
  || fail "observer was not newly created on the local registry"
[[ "$OBSERVER_ADDRESS" == "proof.local/observer" ]] || fail "unexpected observer address: $OBSERVER_ADDRESS"
run_aw_in "$PRINCIPAL_WORKSPACE" id team invite --team proofteam --namespace proof.local --member-global --json > "$EVIDENCE/observer-invite.json"
OBSERVER_INVITE="$(json_value "$EVIDENCE/observer-invite.json" token)"
run_observer_aw id team accept-invite "$OBSERVER_INVITE" --global --name observer --json > "$EVIDENCE/observer-accept.json"
run_observer_aw init --url "$AWEB_URL" > "$EVIDENCE/observer-init.txt"

mv "$PRINCIPAL_WORKSPACE/.aw" "$PRINCIPAL_DIR/credentials"
mkdir -p "$PRINCIPAL_DIR/state"
printf '{"proof":"durable-principal-state"}\n' > "$PRINCIPAL_DIR/state/proof.json"
CREDENTIALS="$PRINCIPAL_DIR/credentials"
STATE="$PRINCIPAL_DIR/state"

python3 "$PROOF_HELPER" snapshot --root "$PRINCIPAL_DIR" --output "$EVIDENCE/principal-pre.json"
capture_registry pre
capture_owning_state acquisition-before

echo "=== Acquire and onboard from a fresh external OAS workspace ==="
(
  cd "$FIXTURE_REPO"
  git init -q
  git config user.email proof@example.invalid
  git config user.name "OAS customer journey proof"
)
run_oas_in "$FIXTURE_REPO" install "$CAPABILITY_SOURCE" --dir "$FIXTURE_REPO" > "$EVIDENCE/oas-install.txt"
grep -q 'Acquired aweb.identity-attach' "$EVIDENCE/oas-install.txt" || fail "oas install did not acquire the capability"
[[ ! -e "$FIXTURE_REPO/oas-config.yaml" ]] || fail "oas install mutated activation config"
printf 'name: external-proof-workspace\n' > "$FIXTURE_REPO/oas-config.yaml"
assert_pre_activation_state \
  "$FIXTURE_REPO/oas-lock.json" \
  "$FIXTURE_REPO/oas-config.yaml" \
  "$FIXTURE_REPO/.agents/capabilities/installed/aweb-identity-attach"
capture_owning_state acquisition-after
assert_owning_state_same acquisition-before acquisition-after "acquisition owning endpoints"
assert_principal_unchanged after-pure-acquisition
capture_registry after-acquisition
compare_registry_to_pre after-acquisition
echo "=== Materialize the throwaway resident fixture ==="
mkdir -p "$AGENTS_ROOT/proof-resident/soul" "$AGENTS_ROOT/proof-resident/instances"
printf 'name: proof-resident\nkind: persistent\nrepo: %s\nwork: checkout\nruntime: pi\n' "$FIXTURE_REPO" > "$AGENTS_ROOT/proof-resident/soul/soul.yaml"
if [[ "$MODE" == "resident-pi" ]]; then
  printf 'model: %s\n' "$PI_MODEL" >> "$AGENTS_ROOT/proof-resident/soul/soul.yaml"
fi
printf '# Throwaway proof soul\n' > "$AGENTS_ROOT/proof-resident/soul/AGENTS.md"
mkdir -p "$FIXTURE_REPO/oas/agents/proof-resident/principals"
cat > "$FIXTURE_REPO/oas/agents/proof-resident/principals/resident.yaml" <<EOF
schema_version: 1
address: $ADDRESS
stable_id: $DID_AW
team_id: $TEAM_ID
soul: proof-resident
EOF
write_attach_config() {
  local principal="$1"
  cat > "$FIXTURE_REPO/oas-config.yaml" <<EOF
team:
  name: proofteam
  id: $TEAM_ID
capabilities:
  layers:
    messaging:
      capability: aweb.identity-attach
      from: installed
      global:
        enabled: true
        settings:
          identity_binding:
            schema_version: 1
            mode: attach
            principal: $principal
EOF
}
write_attach_config "$([[ "$MODE" == "resident-pi" ]] && printf missing || printf resident)"
run_oas_in "$FIXTURE_REPO" trust aweb.identity-attach --dir "$FIXTURE_REPO" > "$EVIDENCE/oas-trust.txt"
(
  cd "$FIXTURE_REPO"
  git add .
  git commit -qm "onboard the external OAS workspace"
)
run_oas_in "$FIXTURE_REPO" doctor "$FIXTURE_REPO" --soul proof-resident --json > "$EVIDENCE/oas-doctor-attach.json"
python3 - "$EVIDENCE/oas-doctor-attach.json" <<'PY'
import json, sys
text = open(sys.argv[1], encoding="utf-8").read()
doc, _ = json.JSONDecoder().raw_decode(text[text.find("{"):])
if doc.get("schemaVersion") == 1:
    doc = doc["result"]
assert doc["layers"]["messaging"]["integration"] == "aweb.identity-attach", doc
assert any(cap["id"] == "aweb.identity-attach" and cap["trust"]["trusted"] for cap in doc["capabilities"]), doc
PY

if [[ "$MODE" == "lifecycle" ]]; then
  # Diverge the resolved mode and require the corresponding successful binding
  # consequence, then restore the ordinary attach config used by the journey.
  cp "$FIXTURE_REPO/oas-config.yaml" "$EVIDENCE/oas-config-attach.yaml"
python3 - "$FIXTURE_REPO/oas-config.yaml" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
text = text.replace("schema_version: 1", "schema_version: 2").replace("mode: attach", "mode: attach-existing")
path.write_text(text, encoding="utf-8")
PY
run_oas_in "$FIXTURE_REPO" spawn proof-resident --purpose config-divergence --no-launch --json > "$EVIDENCE/config-divergence-spawn.json"
DIVERGENCE_HOME="$(json_value "$EVIDENCE/config-divergence-spawn.json" home)"
DIVERGENCE_INSTANCE="$(json_value "$EVIDENCE/config-divergence-spawn.json" instance)"
DIVERGENCE_MODE="$(python3 - "$DIVERGENCE_HOME/instance.json" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["capabilityMeta"]["aweb.identity-attach"]["identity_binding"]["mode"])
PY
)"
[[ "$DIVERGENCE_MODE" == "attach-existing" ]] \
  || fail "divergent attach-existing setting did not produce its predicted binding mode"
  run_oas_in "$FIXTURE_REPO" retire "$DIVERGENCE_INSTANCE" --json > "$EVIDENCE/config-divergence-retire.json"
  cp "$EVIDENCE/oas-config-attach.yaml" "$FIXTURE_REPO/oas-config.yaml"
fi

echo "=== Spawn the attached-principal instance ==="

if [[ "$MODE" == "resident-pi" ]]; then
  echo "=== Observe broken-binding readiness refusal and the separate advisory gap ==="
  if run_oas_in "$FIXTURE_REPO" aweb-identity status --soul proof-resident --json > "$EVIDENCE/broken-binding-status.json"; then
    fail "broken binding status unexpectedly reported ready"
  else
    BROKEN_STATUS=$?
  fi
  [[ "$BROKEN_STATUS" == "1" ]] || fail "broken binding status exited $BROKEN_STATUS, expected 1"
  python3 - "$EVIDENCE/broken-binding-status.json" "$AGENTS_ROOT/proof-resident/instances" <<'PY'
import json, os, sys
report = json.load(open(sys.argv[1], encoding="utf-8"))
assert report["readiness"] == "needs_setup", report
assert report["message"] == "the selected attached identity could not be verified", report
assert report["identity_resources_created"] is False, report
assert report["instance_or_session_created"] is False, report
assert report["identity"] is None, report
assert os.listdir(sys.argv[2]) == [], os.listdir(sys.argv[2])
PY
  [[ ! -e "$PRINCIPAL_HOME/.provisioning" ]] || fail "broken binding status created provisioning state"
  assert_principal_unchanged after-broken-status
  capture_registry after-broken-status
  compare_registry_to_pre after-broken-status

  run_oas_in "$FIXTURE_REPO" spawn proof-resident --purpose advisory-binding-gap --no-launch --json \
    > "$EVIDENCE/broken-binding-advisory-spawn.json"
  BROKEN_HOME="$(json_value "$EVIDENCE/broken-binding-advisory-spawn.json" home)"
  BROKEN_INSTANCE="$(json_value "$EVIDENCE/broken-binding-advisory-spawn.json" instance)"
  python3 - "$EVIDENCE/broken-binding-advisory-spawn.json" "$BROKEN_HOME/instance.json" <<'PY'
import json, re, sys
spawn = json.load(open(sys.argv[1], encoding="utf-8"))
if spawn.get("schemaVersion") == 1:
    spawn = spawn["result"]
assert spawn["launched"] is False, spawn
assert len(spawn.get("warnings", [])) == 1, spawn
assert re.search(r"selected attached identity could not be verified.*NOTHING CREATED", spawn["warnings"][0], re.I), spawn
meta = json.load(open(sys.argv[2], encoding="utf-8"))
assert "aweb.identity-attach" not in meta.get("capabilityMeta", {}), meta
PY
  run_oas_in "$FIXTURE_REPO" retire "$BROKEN_INSTANCE" --json > "$EVIDENCE/broken-binding-advisory-retire.json"
  [[ ! -e "$BROKEN_HOME" ]] || fail "ordinary retire left the advisory-gap scaffold"
  [[ ! -e "$PRINCIPAL_HOME/.provisioning" ]] || fail "advisory broken spawn created provisioning state"
  assert_principal_unchanged after-broken-advisory-observation
  write_attach_config resident
  (
    cd "$FIXTURE_REPO"
    git add oas-config.yaml
    git commit -qm "select the verified throwaway resident"
  )
fi

READY_SUBJECT="OAS_RESIDENT_READY_$(printf '%s' "$PROOF_ROOT" | cksum | cut -d' ' -f1)"
READY_BODY="READY_FROM_THROWAWAY_RESIDENT"
WAKE_SUBJECT="OAS_RESIDENT_WAKE_$(printf '%s' "$DID_AW" | cksum | cut -d' ' -f1)"
WAKE_BODY="WAKE_PROOF_SENTINEL"
REPLY_BODY="REPLY_PROOF_SENTINEL"
SPAWN_ARGS=(spawn proof-resident --purpose attached-principal-retire-proof --json)
if [[ "$MODE" == "resident-pi" ]]; then
  cat > "$EVIDENCE/resident-task.md" <<EOF
This is a controlled proof against a throwaway principal on a local stack.
On the first turn, run exactly: aw whoami --json
Then run exactly: aw mail send --plaintext --to observer --subject '$READY_SUBJECT' --body '$READY_BODY' --json
After those commands, finish the turn and wait without polling.
When an aweb mail wake arrives whose body contains $WAKE_BODY, inspect its verified metadata and run aw mail reply with that exact message_id and body '$REPLY_BODY'.
Do not invoke any identity create/delete/rotate command, OAS retire, tmux command, or filesystem mutation.
EOF
  SPAWN_ARGS+=(--task-file "$EVIDENCE/resident-task.md")
else
  SPAWN_ARGS+=(--no-launch)
fi
run_oas_in "$FIXTURE_REPO" "${SPAWN_ARGS[@]}" > "$EVIDENCE/oas-spawn.json"
INSTANCE_HOME="$(json_value "$EVIDENCE/oas-spawn.json" home)"
INSTANCE_NAME="$(json_value "$EVIDENCE/oas-spawn.json" instance)"
[[ -d "$INSTANCE_HOME" ]] || fail "OAS did not create the instance home"
python3 - "$EVIDENCE/oas-spawn.json" "$INSTANCE_HOME/instance.json" "$ADDRESS" "$DID_AW" "$TEAM_ID" "$PRINCIPAL_HOME" "$PRINCIPAL_DIR" "$CREDENTIALS" "$STATE" "$MODE" "$PI_LAUNCH_PATH" "$PI_MODEL" <<'PY'
import json, shlex, sys
spawn_path, meta_path, address, stable, team, home, principal, credentials, state, mode, pi_path, pi_model = sys.argv[1:]
spawn = json.load(open(spawn_path, encoding="utf-8"))
if spawn.get("schemaVersion") == 1:
    spawn = spawn["result"]
assert spawn.get("warnings", []) == []
assert spawn["launched"] is (mode == "resident-pi"), spawn
meta = json.load(open(meta_path, encoding="utf-8"))
binding = meta["capabilityMeta"]["aweb.identity-attach"]["identity_binding"]
assert binding["schema_version"] == 1
assert binding["mode"] == "attach"
assert binding["cleanup_owner"] == "external"
assert binding["principal"] == "resident"
assert binding["address"] == address
assert binding["stable_id"] == stable
assert binding["team_id"] == team
assert binding["soul"] == "proof-resident"
assert binding["store"] == {"home": home, "principal": principal, "credentials": credentials, "state": state}
assert f"AWEB_IDENTITY_HOME='{credentials}'" in meta["command"] or f"AWEB_IDENTITY_HOME={credentials}" in meta["command"]
if mode == "resident-pi":
    assert meta["runtime"] == "pi", meta
    assert meta["model"] == pi_model, meta
    assert shlex.quote(pi_path) in meta["command"], (pi_path, meta["command"])
PY
assert_principal_unchanged after-spawn
scan_instance after-spawn

if [[ "$MODE" == "resident-pi" ]]; then
  echo "=== Observe the real resident identify itself, wake, and reply ==="
  SESSION_FILE=""
  READY_SEEN=0
  for _ in $(seq 1 180); do
    SESSION_COUNT="$(find "$PROOF_HOME/.pi/agent/sessions" -type f -name '*.jsonl' 2>/dev/null | wc -l | tr -d ' ')"
    if [[ "$SESSION_COUNT" == "1" ]]; then
      SESSION_FILE="$(find "$PROOF_HOME/.pi/agent/sessions" -type f -name '*.jsonl' 2>/dev/null | LC_ALL=C sort | head -n 1)"
    fi
    if run_observer_aw mail inbox --json --show-all > "$EVIDENCE/observer-ready-inbox.json" 2>/dev/null; then
      if python3 - "$EVIDENCE/observer-ready-inbox.json" "$READY_SUBJECT" "$READY_BODY" "$ADDRESS" "$DID_AW" <<'PY'
import json, sys
path, subject, body, address, stable = sys.argv[1:]
messages = json.load(open(path, encoding="utf-8")).get("messages", [])
match = next((message for message in messages if message.get("subject") == subject and message.get("body") == body), None)
assert match is not None
assert match.get("from_address") == address, match
assert match.get("from_stable_id") == stable, match
assert match.get("verification_status") in ("verified", "verified_custodial"), match
PY
      then
        READY_SEEN=1
        break
      fi
    fi
    sleep 2
  done
  [[ "$READY_SEEN" == "1" ]] || fail "real Pi resident did not send the ready observation"
  [[ -n "$SESSION_FILE" ]] || fail "real Pi resident session JSONL was not found"
  READINESS_OBSERVED=0
  for _ in $(seq 1 90); do
    if python3 "$PROOF_HELPER" verify-resident-readiness \
      --session "$SESSION_FILE" \
      --expected-address "$ADDRESS" \
      --expected-stable-id "$DID_AW" \
      --expected-ready-subject "$READY_SUBJECT" \
      --expected-ready-body "$READY_BODY" \
      --expected-session-cwd "$INSTANCE_HOME" \
      --expected-provider "$PI_PROVIDER" \
      --expected-model "$PI_MODEL_ID" \
      --output "$EVIDENCE/resident-readiness-observation.json" \
      2> "$EVIDENCE/resident-readiness-last-error.txt"; then
      READINESS_OBSERVED=1
      break
    fi
    sleep 1
  done
  [[ "$READINESS_OBSERVED" == "1" ]] || {
    cat "$EVIDENCE/resident-readiness-last-error.txt" >&2 || true
    fail "resident Pi session did not settle after its identity and ready-mail results"
  }

  run_observer_aw mail send --plaintext --to-address "$ADDRESS" \
    --subject "$WAKE_SUBJECT" --body "$WAKE_BODY" --json > "$EVIDENCE/observer-wake-send.json"
  WAKE_MESSAGE_ID="$(json_value "$EVIDENCE/observer-wake-send.json" message_id)"
  WAKE_CONVERSATION_ID="$(json_value "$EVIDENCE/observer-wake-send.json" conversation_id)"
  [[ -n "$WAKE_MESSAGE_ID" && -n "$WAKE_CONVERSATION_ID" ]] || fail "observer wake send returned no message identity"

  SESSION_OBSERVED=0
  for _ in $(seq 1 180); do
    if python3 "$PROOF_HELPER" verify-resident-session \
      --session "$SESSION_FILE" \
      --expected-address "$ADDRESS" \
      --expected-stable-id "$DID_AW" \
      --expected-message-id "$WAKE_MESSAGE_ID" \
      --expected-wake-body "$WAKE_BODY" \
      --expected-reply-body "$REPLY_BODY" \
      --expected-ready-subject "$READY_SUBJECT" \
      --expected-ready-body "$READY_BODY" \
      --expected-session-cwd "$INSTANCE_HOME" \
      --expected-provider "$PI_PROVIDER" \
      --expected-model "$PI_MODEL_ID" \
      --output "$EVIDENCE/resident-session-observation.json" \
      2> "$EVIDENCE/resident-session-last-error.txt"; then
      SESSION_OBSERVED=1
      break
    fi
    sleep 2
  done
  [[ "$SESSION_OBSERVED" == "1" ]] || {
    cat "$EVIDENCE/resident-session-last-error.txt" >&2 || true
    fail "resident session did not contain identity, wake, and successful reply evidence"
  }
  cp "$SESSION_FILE" "$EVIDENCE/resident-session.jsonl"

  REPLY_OBSERVED=0
  for _ in $(seq 1 90); do
    if run_observer_aw mail inbox --json --show-all > "$EVIDENCE/observer-reply-inbox.json" 2>/dev/null; then
      if python3 - "$EVIDENCE/observer-reply-inbox.json" "$WAKE_CONVERSATION_ID" "$REPLY_BODY" "$ADDRESS" "$DID_AW" "$DID_KEY" "$EVIDENCE/resident-reply-observation.json" <<'PY'
import json, sys
path, conversation, body, address, stable, did_key, output = sys.argv[1:]
messages = json.load(open(path, encoding="utf-8")).get("messages", [])
match = next((message for message in messages if message.get("conversation_id") == conversation and message.get("body") == body), None)
assert match is not None
assert match.get("from_address") == address, match
assert match.get("from_stable_id") == stable, match
assert match.get("from_did") == did_key, match
assert match.get("verification_status") in ("verified", "verified_custodial"), match
projection = {key: match.get(key) for key in (
    "message_id", "conversation_id", "from_alias", "from_address", "from_did",
    "from_stable_id", "to_alias", "body", "verification_status",
)}
with open(output, "w", encoding="utf-8") as stream:
    json.dump(projection, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY
      then
        REPLY_OBSERVED=1
        break
      fi
    fi
    sleep 2
  done
  [[ "$REPLY_OBSERVED" == "1" ]] || fail "observer did not receive the resident's exact verified reply"
  env -u TMUX TMUX_TMPDIR="$PROOF_TMUX_DIR" PATH="$TMUX_GUARD_DIR:$PATH" \
    tmux list-panes -t "=$PROOF_TMUX_SESSION:=$INSTANCE_NAME" \
      -F '#{pane_pid}|#{pane_current_command}|#{pane_dead}' > "$EVIDENCE/resident-pane.txt"
  ps -axo pid=,ppid=,lstart=,command= > "$EVIDENCE/process-table-before-retire.txt"
  python3 - "$EVIDENCE/resident-pane.txt" "$EVIDENCE/process-table-before-retire.txt" \
    "$PI_LAUNCH_PATH" "$EVIDENCE/resident-processes.json" <<'PY'
import json, os, re, sys
pane_path, process_path, pi_path, output = sys.argv[1:]
lines = [line for line in open(pane_path, encoding="utf-8").read().splitlines() if line]
assert len(lines) == 1, lines
pane_pid, command, dead = lines[0].split("|", 2)
assert pane_pid.isdigit(), lines
assert re.search(r"(?:^|/)(?:node|pi)$", command), lines
assert dead == "0", lines
processes = []
for line in open(process_path, encoding="utf-8"):
    parts = line.strip().split(None, 7)
    if len(parts) != 8 or not parts[0].isdigit() or not parts[1].isdigit():
        continue
    processes.append({
        "pid": int(parts[0]), "ppid": int(parts[1]),
        "started": " ".join(parts[2:7]), "command": parts[7],
    })
by_parent = {}
for process in processes:
    by_parent.setdefault(process["ppid"], []).append(process)
descendants = []
stack = [int(pane_pid)]
while stack:
    parent = stack.pop()
    for child in by_parent.get(parent, []):
        descendants.append(child)
        stack.append(child["pid"])
hints = {pi_path, os.path.realpath(pi_path), "pi-coding-agent"}
pi_processes = [
    process for process in descendants
    if any(hint and hint in process["command"] for hint in hints)
]
assert pi_processes, {"pane": lines, "descendants": descendants, "pi_path": pi_path}
with open(output, "w", encoding="utf-8") as stream:
    json.dump({
        "pane_pid": int(pane_pid), "pane_current_command": command,
        "descendants": descendants, "pi_processes": pi_processes,
    }, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY
  FINAL_SESSION_COUNT="$(find "$PROOF_HOME/.pi/agent/sessions" -type f -name '*.jsonl' | wc -l | tr -d ' ')"
  [[ "$FINAL_SESSION_COUNT" == "1" ]] || fail "proof Pi created $FINAL_SESSION_COUNT session files, expected exactly one"
  [[ "$(find "$PROOF_HOME/.pi/agent/sessions" -type f -name '*.jsonl' -print -quit)" == "$SESSION_FILE" ]] \
    || fail "proof Pi session file changed before retire"
  cp "$INSTANCE_HOME/instance.json" "$EVIDENCE/resident-instance.json"

  assert_principal_unchanged after-real-pi-session
  scan_instance after-real-pi-session
  capture_registry after-session
  compare_registry_to_pre after-session
else
  echo "=== Use the attached principal directly from the scaffolded instance ==="
  (
    cd "$INSTANCE_HOME"
    env -u AWEB_IDENTITY_HOME -u AWEB_PRINCIPAL -u AWEB_API_KEY -u AW_HOME \
      HOME="$PROOF_HOME" AW_CONFIG_PATH="$CONFIG_PATH" AWEB_URL="$AWEB_URL" \
      AWID_REGISTRY_URL="$AWID_URL" AWID_SKIP_DNS_VERIFY=1 AW_NO_UPDATE_CHECK=1 \
      "$AW_BIN" --identity-home "$CREDENTIALS" whoami --json
  ) > "$EVIDENCE/instance-whoami.raw.json"
  normalize_json "$EVIDENCE/instance-whoami.raw.json" "$EVIDENCE/instance-whoami.json"
  python3 - "$EVIDENCE/instance-whoami.json" "$ADDRESS" "$DID_AW" <<'PY'
import json, sys
identity = json.load(open(sys.argv[1], encoding="utf-8"))
assert identity["address"] == sys.argv[2]
assert identity["stable_id"] == sys.argv[3]
PY
  assert_principal_unchanged after-direct-whoami
  scan_instance after-direct-whoami
fi

echo "=== Retire through the ordinary production lifecycle ==="
run_oas_in "$FIXTURE_REPO" retire "$INSTANCE_NAME" --json > "$EVIDENCE/oas-retire.json"
[[ ! -e "$INSTANCE_HOME" ]] || fail "ordinary retire did not remove the disposable instance"
if [[ "$MODE" == "resident-pi" ]] && env -u TMUX TMUX_TMPDIR="$PROOF_TMUX_DIR" PATH="$TMUX_GUARD_DIR:$PATH" \
  tmux list-windows -t "=$PROOF_TMUX_SESSION" -F '#{window_name}' 2>/dev/null | grep -F -x -q "$INSTANCE_NAME"; then
  fail "ordinary retire left the resident tmux window running"
fi
python3 - "$EVIDENCE/oas-retire.json" "$ADDRESS" "$DID_AW" "$INSTANCE_NAME" <<'PY'
import json, sys
document = json.load(open(sys.argv[1], encoding="utf-8"))
if document.get("schemaVersion") == 1:
    document = document["result"]
assert document.get("warnings", []) == []
assert document["retired"] == sys.argv[4], document
assert document["removedDir"] is True, document
meta = document["capabilityMeta"]["aweb.identity-attach"]
assert meta["identity_binding"]["address"] == sys.argv[2]
assert meta["identity_binding"]["stable_id"] == sys.argv[3]
assert meta["identity_binding"]["cleanup_owner"] == "external"
assert meta["retirement"] == {"action": "preserve_principal", "cleanup_owner": "external"}
PY
if [[ "$MODE" == "resident-pi" ]]; then
  env -u TMUX TMUX_TMPDIR="$PROOF_TMUX_DIR" PATH="$TMUX_GUARD_DIR:$PATH" \
    tmux list-windows -t "=$PROOF_TMUX_SESSION" -F '#{window_name}|#{window_panes}' \
      > "$EVIDENCE/proof-windows-after-retire.txt"
  [[ "$(cat "$EVIDENCE/proof-windows-after-retire.txt")" == "hq|1" ]] \
    || fail "ordinary retire left unexpected proof-session window/pane topology"
  PROCESS_GONE=0
  for _ in $(seq 1 50); do
    ps -axo pid=,ppid=,lstart=,command= > "$EVIDENCE/process-table-after-retire.txt"
    if python3 - "$EVIDENCE/resident-processes.json" "$EVIDENCE/process-table-after-retire.txt" <<'PY'
import json, sys
snapshot_path, process_path = sys.argv[1:]
snapshot = json.load(open(snapshot_path, encoding="utf-8"))
current = {}
for line in open(process_path, encoding="utf-8"):
    parts = line.strip().split(None, 7)
    if len(parts) == 8 and parts[0].isdigit():
        current[int(parts[0])] = " ".join(parts[2:7])
still_alive = [
    process for process in snapshot["pi_processes"]
    if current.get(process["pid"]) == process["started"]
]
assert not still_alive, still_alive
PY
    then
      PROCESS_GONE=1
      break
    fi
    sleep 0.2
  done
  [[ "$PROCESS_GONE" == "1" ]] || fail "captured Pi model process remained alive after ordinary retire"
  TERMINAL_SESSION_COUNT="$(find "$PROOF_HOME/.pi/agent/sessions" -type f -name '*.jsonl' | wc -l | tr -d ' ')"
  [[ "$TERMINAL_SESSION_COUNT" == "1" ]] || fail "terminal Pi session cardinality is $TERMINAL_SESSION_COUNT, expected one"
  [[ "$(find "$PROOF_HOME/.pi/agent/sessions" -type f -name '*.jsonl' -print -quit)" == "$SESSION_FILE" ]] \
    || fail "terminal Pi session is not the spawned run's session"
  cp "$SESSION_FILE" "$EVIDENCE/resident-session.jsonl"
fi
assert_principal_unchanged after-retire
capture_registry after-retire
compare_registry_to_pre after-retire

echo "=== Trigger gone-workspace cleanup from an independent workspace ==="
run_observer_aw workspace status --json > "$EVIDENCE/observer-status.raw.json" 2> "$EVIDENCE/observer-status.stderr"
normalize_json "$EVIDENCE/observer-status.raw.json" "$EVIDENCE/observer-status.json"
python3 - "$EVIDENCE/observer-status.json" "$INSTANCE_HOME" <<'PY'
import json, sys
document = json.load(open(sys.argv[1], encoding="utf-8"))
instance = sys.argv[2]
def walk(value):
    if isinstance(value, dict):
        if value.get("workspace_path") == instance:
            raise AssertionError(f"disposable instance path was registered as a workspace: {instance}")
        for child in value.values():
            walk(child)
    elif isinstance(value, list):
        for child in value:
            walk(child)
walk(document)
PY
assert_principal_unchanged after-gone-workspace-sweep
capture_registry after-cleanup
compare_registry_to_pre after-cleanup

if [[ "$MODE" == "resident-pi" ]]; then
  echo "=== Remove only the isolated proof session and verify every pre-existing session ==="
  if ! remove_proof_tmux_session; then
    KEEP=1
    fail "isolated proof tmux session cleanup could not be verified"
  fi
  assert_default_tmux_topology_unchanged after \
    || fail "pre-existing tmux session/window/pane topology changed"
  rm -f "$PROOF_HOME/.pi/agent/auth.json"
  [[ ! -e "$PROOF_HOME/.pi/agent/auth.json" ]] || fail "throwaway Pi model authentication copy remains"
  git -C "$REPO_ROOT" diff --quiet && git -C "$REPO_ROOT" diff --cached --quiet \
    || fail "aweb proof source changed during the run"
  git -C "$OAS_ROOT" diff --quiet && git -C "$OAS_ROOT" diff --cached --quiet \
    || fail "local OAS proof source changed during the run"
  [[ "$(git -C "$REPO_ROOT" rev-parse HEAD)" == "$SOURCE_SHA" ]] \
    || fail "aweb source HEAD changed during the run"
  [[ "$(git -C "$OAS_ROOT" rev-parse HEAD)" == "$OAS_SOURCE_SHA" ]] \
    || fail "local OAS source HEAD changed during the run"
  [[ "$(file_sha256 "$AW_BIN")" == "$AW_BIN_SHA" ]] \
    || fail "built aw binary changed during the model run"
  [[ "$(file_sha256 "$OAS_CLI")" == "$OAS_BIN_SHA" ]] \
    || fail "OAS CLI binary changed during the model run"
  [[ "$(file_sha256 "$OAS_ROOT/lib/core.mjs")" == "$OAS_CORE_SHA" ]] \
    || fail "OAS core changed during the model run"
  [[ "$(file_sha256 "$PI_LAUNCH_PATH")" == "$PI_BIN_SHA" ]] \
    || fail "Pi executable changed during the model run"
  [[ "$(file_sha256 "$PI_EXTENSION_DIR/dist/index.js")" == "$PI_EXTENSION_SHA" ]] \
    || fail "built Pi extension changed during the model run"
  python3 - "$EVIDENCE/provenance.json" "$SOURCE_SHA" "$AW_BIN" "$AW_BIN_SHA" \
    "$OAS_ROOT" "$OAS_SOURCE_SHA" "$OAS_CLI" "$OAS_BIN_SHA" "$OAS_CORE_SHA" \
    "$PI_LAUNCH_PATH" "$PI_BIN_SHA" "$PI_VERSION" "$PI_PROVIDER" "$PI_MODEL_ID" \
    "$PI_EXTENSION_DIR/dist/index.js" "$PI_EXTENSION_SHA" "$EVIDENCE" <<'PY'
import hashlib, json, os, sys
(
    output, source_sha, aw_path, aw_sha, oas_root, oas_sha, oas_bin, oas_bin_sha,
    oas_core_sha, pi_path, pi_sha, pi_version, pi_provider, pi_model,
    extension_path, extension_sha, evidence,
) = sys.argv[1:]

def sha256(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()

document = {
    "tracked_sources_clean_before_and_after": True,
    "all_executable_and_extension_hashes_reverified_after_model_exit": True,
    "aweb": {
        "source_sha": source_sha,
        "aw_binary_path": os.path.realpath(aw_path),
        "aw_binary_sha256": aw_sha,
    },
    "oas": {
        "source": "local-unpublished-clone",
        "root": oas_root,
        "source_sha": oas_sha,
        "bin_path": oas_bin,
        "bin_sha256": oas_bin_sha,
        "core_sha256": oas_core_sha,
        "published_reproducibility": False,
        "tracking_task": "aweb-oas-aaaa.56",
    },
    "pi": {
        "binary_path": os.path.realpath(pi_path),
        "binary_sha256": pi_sha,
        "version": pi_version,
        "provider": pi_provider,
        "model": pi_model,
        "extension_path": extension_path,
        "extension_sha256": extension_sha,
    },
    "run": {
        "session_store_empty_before_spawn": True,
        "spawn_result_sha256": sha256(os.path.join(evidence, "oas-spawn.json")),
        "instance_metadata_sha256": sha256(os.path.join(evidence, "resident-instance.json")),
        "session_jsonl_sha256": sha256(os.path.join(evidence, "resident-session.jsonl")),
        "session_observation_sha256": sha256(os.path.join(evidence, "resident-session-observation.json")),
        "receiver_observation_sha256": sha256(os.path.join(evidence, "resident-reply-observation.json")),
        "pane_observation_sha256": sha256(os.path.join(evidence, "resident-pane.txt")),
        "captured_model_processes_sha256": sha256(os.path.join(evidence, "resident-processes.json")),
        "terminal_process_table_sha256": sha256(os.path.join(evidence, "process-table-after-retire.txt")),
        "terminal_proof_window_topology_sha256": sha256(os.path.join(evidence, "proof-windows-after-retire.txt")),
        "terminal_session_file_count": 1,
        "captured_model_processes_gone_after_retire": True,
    },
}
with open(output, "w", encoding="utf-8") as stream:
    json.dump(document, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY

  python3 - "$REPORT" "$SOURCE_SHA" "$OAS_SOURCE_SHA" "$OAS_ROOT" "$ADDRESS" "$DID_AW" "$TEAM_ID" \
    "$OBSERVER_ADDRESS" "$OBSERVER_DID_AW" "$OBSERVER_DID_KEY" "$AWEB_URL" "$AWID_URL" \
    "$WAKE_MESSAGE_ID" "$WAKE_CONVERSATION_ID" "$EVIDENCE" <<'PY'
import hashlib, json, os, sys
(
    report, source, oas_source, oas_root, address, stable, team,
    observer_address, observer_stable, observer_did_key, aweb_url, awid_url,
    wake_message, wake_conversation, evidence,
) = sys.argv[1:]

def load(name):
    with open(os.path.join(evidence, name), encoding="utf-8") as stream:
        return json.load(stream)

def sha256(name):
    return hashlib.sha256(open(os.path.join(evidence, name), "rb").read()).hexdigest()

document = {
    "schema": "aweb.oas-pi-resident-proof.v1",
    "source_sha": source,
    "provenance": load("provenance.json"),
    "oas_subject": {
        "source": "local-unpublished-clone",
        "root": oas_root,
        "sha": oas_source,
        "published_oas_reproduces_launch_environment_contract": False,
        "tracking_task": "aweb-oas-aaaa.56",
    },
    "stack": {
        "loopback_only": True,
        "postgres_tmpfs_verified": True,
        "throwaway_principal": True,
        "messaging": "server-readable-plaintext",
    },
    "principal": {"address": address, "stable_id": stable, "team_id": team},
    "isolation_observation": {
        "principal_created_in_proof": True,
        "observer_created_in_proof": True,
        "observer": {
            "address": observer_address,
            "stable_id": observer_stable,
            "did_key": observer_did_key,
        },
        "team_created_in_proof": True,
        "principal_create_sha256": sha256("create.json"),
        "observer_create_sha256": sha256("observer-create.json"),
        "team_create_sha256": sha256("team-create.json"),
        "ambient_identity_home_scrubbed_before_attach": True,
        "ambient_identity_selector_and_service_authority_scrubbed": True,
        "explicit_aweb_origin": aweb_url,
        "explicit_awid_registry": awid_url,
    },
    "broken_binding": {
        "proof_step": {
            "surface": "oas aweb-identity status",
            "readiness": "needs_setup",
            "message": "the selected attached identity could not be verified",
            "identity_resources_created": False,
            "instance_or_session_created": False,
        },
        "known_gap_observation": {
            "surface": "oas spawn --no-launch",
            "binding_warning_observed": True,
            "binding_prevented_launch": False,
            "why_no_process_was_created": "operator supplied --no-launch; not binding enforcement",
            "enforcement_owner": "aweb-oas-aaaa.2",
        },
    },
    "resident_observation": {
        "production_entry": "ordinary oas spawn with launch",
        "identity": load("resident-session-observation.json")["identity"],
        "wake_message_id": wake_message,
        "wake_conversation_id": wake_conversation,
        "wake_observed_at": "resident Pi session custom_message",
        "reply_observed_at": ["resident Pi bash tool call/result", "observer verified inbox"],
        "resident_session_observation": load("resident-session-observation.json"),
        "observer_reply_observation": load("resident-reply-observation.json"),
        "resident_session_sha256": sha256("resident-session.jsonl"),
    },
    "retire_observation": {
        "production_entry": "ordinary oas retire",
        "cleanup_owner": "external",
        "receipt": "preserve_principal",
        "instance_removed": True,
    },
    "independent_observations": {
        "registry_address_unchanged": True,
        "registry_resolution_unchanged": True,
        "did_log_verified_pre_post": True,
        "principal_store_bytes_and_inodes_unchanged_after_session_and_retire": True,
        "principal_inventory_sha256": {
            "before_run": sha256("principal-pre.json"),
            "after_session": sha256("principal-after-real-pi-session.json"),
            "after_retire": sha256("principal-after-retire.json"),
        },
        "registry_record_sha256": {
            "before_run": {
                kind: sha256(f"registry-pre-{kind}.json") for kind in ("address", "resolve", "verify")
            },
            "after_session": {
                kind: sha256(f"registry-after-session-{kind}.json") for kind in ("address", "resolve", "verify")
            },
            "after_retire": {
                kind: sha256(f"registry-after-retire-{kind}.json") for kind in ("address", "resolve", "verify")
            },
        },
        "instance_copy_hardlink_symlink_scan_passed_after_session": True,
        "instance_runtime_state_allowed": load("instance-after-real-pi-session-scan.json")["allowed_runtime_state"],
        "instance_after_session_scan_sha256": sha256("instance-after-real-pi-session-scan.json"),
        "preexisting_tmux_session_window_pane_topology_unchanged": True,
        "tmux_topology_before_sha256": sha256("tmux-topology-before.txt"),
        "tmux_topology_after_sha256": sha256("tmux-topology-after.txt"),
    },
    "limitations": [
        "no fail-closed hook admission",
        "no restart/resume propagation",
        "no lease/fencing/concurrency result",
        "no E2EE result",
        "no universal cannot-harm claim",
        "launch-environment propagation was verified against the named local unpublished OAS clone, not published OAS",
        "the proof observes one initial Pi session and one mail wake/reply on a loopback throwaway stack",
    ],
}
with open(report, "w", encoding="utf-8") as stream:
    json.dump(document, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY
  echo "PROOF PASSED"
  echo "  report: $REPORT"
  echo "  principal: $ADDRESS ($DID_AW)"
  echo "  local OAS subject: $OAS_SOURCE_SHA"
  echo "  pre-existing tmux session/window/pane topology: unchanged"
  exit 0
fi

echo "=== Prepare two independent developers with the same local instance name ==="
for developer_root in "$DEVELOPER_A_AGENTS_ROOT" "$DEVELOPER_B_AGENTS_ROOT"; do
  mkdir -p "$developer_root/proof-worker/soul" "$developer_root/proof-worker/instances"
  printf 'name: proof-worker\nkind: persistent\nrepo: %s\nwork: checkout\nruntime: pi\n' "$FIXTURE_REPO" > "$developer_root/proof-worker/soul/soul.yaml"
  printf '# Independent throwaway customer developer\n' > "$developer_root/proof-worker/soul/AGENTS.md"
done
mkdir -p "$FIXTURE_REPO/oas/agents/proof-worker/principals"
cat > "$FIXTURE_REPO/oas/agents/proof-worker/principals/resident.yaml" <<EOF
schema_version: 1
address: $ADDRESS
stable_id: $DID_AW
team_id: $TEAM_ID
soul: proof-worker
EOF

write_provision_config() {
  local mode="$1" authority_path="${2:-}"
  cat > "$FIXTURE_REPO/oas-config.yaml" <<EOF
team:
  name: proofteam
  id: $TEAM_ID
capabilities:
  layers:
    messaging:
      capability: aweb.identity-attach
      from: installed
      global:
        enabled: true
        settings:
          identity_binding:
            schema_version: 2
            mode: $mode
EOF
  if [[ "$mode" == "provision-disposable" ]]; then
    cat >> "$FIXTURE_REPO/oas-config.yaml" <<EOF
            minting_authority: resident
            minting_authority_path: $authority_path
EOF
  fi
}

(
  cd "$FIXTURE_REPO"
  git add oas/agents/proof-worker
  git commit -qm "declare the customer worker and its minting authority"
)

capture_owning_state refusal-before
for refused_mode in hosted durable; do
  if [[ "$refused_mode" == "hosted" ]]; then
    write_provision_config provision-disposable hosted
    expected_refusal='hosted provision-disposable is refused before creation'
  else
    write_provision_config provision-durable
    expected_refusal='provision-durable is declared but not executable'
  fi
  run_oas_with_agents "$DEVELOPER_A_AGENTS_ROOT" "$FIXTURE_REPO" spawn proof-worker --purpose "refuse-$refused_mode" --no-launch --json > "$EVIDENCE/refuse-$refused_mode-spawn.json"
  grep -q "$expected_refusal" "$EVIDENCE/refuse-$refused_mode-spawn.json" || fail "$refused_mode refusal was not legible"
  capture_owning_state "refusal-after-$refused_mode"
  assert_owning_state_same refusal-before "refusal-after-$refused_mode" "$refused_mode refusal"
  refused_instance="$(json_value "$EVIDENCE/refuse-$refused_mode-spawn.json" instance)"
  run_oas_with_agents "$DEVELOPER_A_AGENTS_ROOT" "$FIXTURE_REPO" retire "$refused_instance" --json > "$EVIDENCE/refuse-$refused_mode-retire.json"
done

write_provision_config provision-disposable local-controller
(
  cd "$FIXTURE_REPO"
  git add oas-config.yaml
  git commit -qm "select local disposable worker provisioning"
)
run_oas_with_agents "$DEVELOPER_A_AGENTS_ROOT" "$FIXTURE_REPO" doctor "$FIXTURE_REPO" --soul proof-worker --json > "$EVIDENCE/oas-doctor-worker.json"
assert_worker_doctor_state "$EVIDENCE/oas-doctor-worker.json"

# Exercise the real transient grant boundary deterministically. An unsupported
# signing-key path makes the production command stop after creating its
# operation-tagged grant but before acceptance. Re-entering the same operation
# adopts that exact grant, consumes it, and cleanup removes only those resources.
INTERRUPTED_OPERATION="oas-AAAAAAAAAAAAAAAAAAAAAA"
INTERRUPTED_ALIAS="interrupted-grant-proof"
INTERRUPTED_TARGET="$PRINCIPAL_HOME/.provisioning/identities/$INTERRUPTED_OPERATION"
TEAM_CONTROLLER_DID="$(json_value "$EVIDENCE/team-create.json" team_did_key)"
mkdir -p "$INTERRUPTED_TARGET/signing.key"
set +e
(
  cd "$FIXTURE_REPO"
  env -u AWEB_IDENTITY_HOME HOME="$PROOF_HOME" AW_CONFIG_PATH="$CONFIG_PATH" \
    AWID_REGISTRY_URL="$AWID_URL" AWID_SKIP_DNS_VERIFY=1 OAS_EVENT=spawn \
    "$AW_BIN" id team provision-local \
      --operation-id "$INTERRUPTED_OPERATION" --team-id "$TEAM_ID" --name "$INTERRUPTED_ALIAS" \
      --authority-identity-home "$CREDENTIALS" --target-identity-home "$INTERRUPTED_TARGET" \
      --authority-address "$ADDRESS" --authority-stable-id "$DID_AW" \
      --controller-did "$TEAM_CONTROLLER_DID" --json
) > "$EVIDENCE/interrupted-grant-create.txt" 2>&1
INTERRUPTED_CREATE_STATUS=$?
set -e
[[ "$INTERRUPTED_CREATE_STATUS" -ne 0 ]] || fail "pre-accept grant interruption unexpectedly completed"
capture_operation_grants interrupted-grant "$INTERRUPTED_OPERATION=1"
rmdir "$INTERRUPTED_TARGET/signing.key"
(
  cd "$FIXTURE_REPO"
  env -u AWEB_IDENTITY_HOME HOME="$PROOF_HOME" AW_CONFIG_PATH="$CONFIG_PATH" \
    AWID_REGISTRY_URL="$AWID_URL" AWID_SKIP_DNS_VERIFY=1 OAS_EVENT=spawn \
    "$AW_BIN" id team provision-local \
      --operation-id "$INTERRUPTED_OPERATION" --team-id "$TEAM_ID" --name "$INTERRUPTED_ALIAS" \
      --authority-identity-home "$CREDENTIALS" --target-identity-home "$INTERRUPTED_TARGET" \
      --authority-address "$ADDRESS" --authority-stable-id "$DID_AW" \
      --controller-did "$TEAM_CONTROLLER_DID" --json
) > "$EVIDENCE/interrupted-grant-recovery.json"
capture_operation_grants interrupted-grant-recovered "$INTERRUPTED_OPERATION=0"
assert_operation_grant_isolation interrupted-grant interrupted-grant-recovered "$INTERRUPTED_OPERATION"
(
  cd "$FIXTURE_REPO"
  env -u AWEB_IDENTITY_HOME HOME="$PROOF_HOME" AW_CONFIG_PATH="$CONFIG_PATH" \
    AWID_REGISTRY_URL="$AWID_URL" AWID_SKIP_DNS_VERIFY=1 OAS_EVENT=retire \
    "$AW_BIN" id team cleanup-local-provision \
      --operation-id "$INTERRUPTED_OPERATION" --team-id "$TEAM_ID" --name "$INTERRUPTED_ALIAS" \
      --authority-identity-home "$CREDENTIALS" --target-identity-home "$INTERRUPTED_TARGET" \
      --authority-address "$ADDRESS" --authority-stable-id "$DID_AW" \
      --controller-did "$TEAM_CONTROLLER_DID" --json
) > "$EVIDENCE/interrupted-grant-cleanup.json"

run_oas_with_agents "$DEVELOPER_A_AGENTS_ROOT" "$FIXTURE_REPO" spawn proof-worker --purpose ordinary-worker --no-launch --json > "$EVIDENCE/provision-victim-spawn.json"
VICTIM_HOME="$(json_value "$EVIDENCE/provision-victim-spawn.json" home)"
VICTIM_INSTANCE="$(json_value "$EVIDENCE/provision-victim-spawn.json" instance)"
VICTIM_OPERATION="$(binding_operation "$VICTIM_HOME/instance.json")"
VICTIM_INTENT="$PRINCIPAL_HOME/.provisioning/intents/$VICTIM_OPERATION.json"
PI_AGENT_HOME="$VICTIM_HOME" run_oas_with_agents "$DEVELOPER_A_AGENTS_ROOT" "$FIXTURE_REPO" aweb-identity status --soul proof-worker --json > "$EVIDENCE/provision-victim-identity-status.json"
python3 - "$EVIDENCE/provision-victim-identity-status.json" "$VICTIM_INTENT" "$PRINCIPAL_HOME" <<'PY'
import json, sys
status_path, intent_path, principal_home = sys.argv[1:]
document = json.load(open(status_path, encoding="utf-8"))
assert document["readiness"] == "ready", document
assert document["identity"] == {
    "address": None,
    "team_member_name": document["identity"]["team_member_name"],
    "did": document["identity"]["did"],
    "type": "disposable",
    "cleanup_owner": "this-instance",
}, document
intent = json.load(open(intent_path, encoding="utf-8"))
assert document["identity"]["team_member_name"] == intent["alias"], (document, intent)
assert document["identity"]["did"] == intent["resource"]["did_key"], (document, intent)
assert document["identity"]["did"].startswith("did:key:z"), document
encoded = json.dumps(document, sort_keys=True)
assert principal_home not in encoded, document
for forbidden in ("identity_binding", "minting_authority", "journal_operation", "operation_id", "identity_home", "credentials"):
    assert forbidden not in json.dumps(document["identity"], sort_keys=True), document
PY
run_oas_with_agents "$DEVELOPER_B_AGENTS_ROOT" "$FIXTURE_REPO" spawn proof-worker --purpose ordinary-worker --no-launch --json > "$EVIDENCE/provision-attacker-spawn.json"
ATTACKER_HOME="$(json_value "$EVIDENCE/provision-attacker-spawn.json" home)"
ATTACKER_INSTANCE="$(json_value "$EVIDENCE/provision-attacker-spawn.json" instance)"
ATTACKER_OPERATION="$(binding_operation "$ATTACKER_HOME/instance.json")"
[[ "$VICTIM_INSTANCE" == "$ATTACKER_INSTANCE" ]] || fail "independent developers did not exercise duplicate local instance names"
[[ "$VICTIM_OPERATION" != "$ATTACKER_OPERATION" ]] || fail "duplicate local names collapsed into one provisioning operation"
[[ "$VICTIM_HOME" != "$ATTACKER_HOME" ]] || fail "independent developer instance homes collapsed"
python3 - "$PRINCIPAL_HOME/.provisioning/intents/$VICTIM_OPERATION.json" "$PRINCIPAL_HOME/.provisioning/intents/$ATTACKER_OPERATION.json" "$VICTIM_OPERATION" "$ATTACKER_OPERATION" <<'PY'
import json, sys
first = json.load(open(sys.argv[1], encoding="utf-8"))
second = json.load(open(sys.argv[2], encoding="utf-8"))
assert first["operation_id"] == sys.argv[3]
assert second["operation_id"] == sys.argv[4]
assert first["alias"] != second["alias"]
assert first["resource"]["operation_id"] == first["operation_id"]
assert second["resource"]["operation_id"] == second["operation_id"]
PY
capture_operation_grants both-active "$VICTIM_OPERATION=0" "$ATTACKER_OPERATION=0"

# These are internal lifecycle observations, not the customer-visible address
# and setup experience owned by aaaa.44/.46.
run_oas_with_agents "$DEVELOPER_A_AGENTS_ROOT" "$FIXTURE_REPO" status --json > "$EVIDENCE/developer-a-status.json"
run_oas_with_agents "$DEVELOPER_B_AGENTS_ROOT" "$FIXTURE_REPO" status --json > "$EVIDENCE/developer-b-status.json"
python3 - "$EVIDENCE/developer-a-status.json" "$EVIDENCE/developer-b-status.json" "$VICTIM_OPERATION" "$ATTACKER_OPERATION" <<'PY'
import json, sys
for path, operation in ((sys.argv[1], sys.argv[3]), (sys.argv[2], sys.argv[4])):
    doc = json.load(open(path, encoding="utf-8"))
    instances = [instance for agent in doc["agents"] for instance in agent["instances"]]
    assert len(instances) == 1, instances
    provisioning = instances[0]["capabilityMeta"]["aweb.identity-attach"]["provisioning"]
    assert provisioning["operation_id"] == operation
    assert provisioning["alias"].startswith("oas-")
    assert provisioning["team_id"] == "proofteam:proof.local"
PY
VICTIM_INTENT="$PRINCIPAL_HOME/.provisioning/intents/$VICTIM_OPERATION.json"
ATTACKER_INTENT="$PRINCIPAL_HOME/.provisioning/intents/$ATTACKER_OPERATION.json"
VICTIM_ALIAS="$(json_value "$VICTIM_INTENT" alias)"
VICTIM_TARGET="$(json_value "$VICTIM_INTENT" identity_home)"
ATTACKER_ALIAS="$(json_value "$ATTACKER_INTENT" alias)"
ATTACKER_TARGET="$(json_value "$ATTACKER_INTENT" identity_home)"
scan_provisioned_material "$VICTIM_OPERATION" victim "$VICTIM_HOME" "$ATTACKER_HOME" "$FIXTURE_REPO"
scan_provisioned_material "$ATTACKER_OPERATION" attacker "$ATTACKER_HOME" "$VICTIM_HOME" "$FIXTURE_REPO"
# Messaging intentionally creates an .aw/interaction-log.jsonl in the
# external workspace, so provision-material copy scans run before this use step.
run_observer_aw mail send --to "$VICTIM_ALIAS" --subject "ordinary worker proof" --body "observer-to-worker-$VICTIM_OPERATION" --plaintext --json > "$EVIDENCE/message-to-worker.json"
run_target_aw "$VICTIM_TARGET" mail inbox --show-all --json > "$EVIDENCE/worker-inbox.json"
grep -q "observer-to-worker-$VICTIM_OPERATION" "$EVIDENCE/worker-inbox.json" || fail "real observer message did not reach developer A worker"
run_target_aw "$VICTIM_TARGET" mail send --to observer --subject "ordinary worker reply" --body "worker-to-observer-$VICTIM_OPERATION" --plaintext --json > "$EVIDENCE/message-from-worker.json"
run_observer_aw mail inbox --show-all --json > "$EVIDENCE/observer-inbox.json"
grep -q "worker-to-observer-$VICTIM_OPERATION" "$EVIDENCE/observer-inbox.json" || fail "real developer A worker reply did not reach observer"
scan_provisioned_sensitive_material victim "$VICTIM_HOME" "$ATTACKER_HOME" "$FIXTURE_REPO"
scan_provisioned_sensitive_material attacker "$ATTACKER_HOME" "$VICTIM_HOME" "$FIXTURE_REPO"
preserve_known_material_for_final_scan victim "$VICTIM_TARGET"
preserve_known_material_for_final_scan attacker "$ATTACKER_TARGET"
capture_provision_resource victim-before-forgery "$VICTIM_OPERATION" active
capture_provision_resource attacker-before-forgery "$ATTACKER_OPERATION" active
capture_durable_operation_tuple attacker-before-victim-cleanup "$ATTACKER_OPERATION"

AUTHORITY_HOME="$(json_value "$VICTIM_INTENT" authority_home)"
AUTHORITY_ADDRESS="$(json_value "$VICTIM_INTENT" authority.intended_creator.address)"
AUTHORITY_STABLE="$(json_value "$VICTIM_INTENT" authority.intended_creator.stable_id)"
CONTROLLER_DID="$(json_value "$VICTIM_INTENT" authority.controller_did)"
set +e
(
  cd "$ATTACKER_HOME"
  env -u AWEB_IDENTITY_HOME -u AWEB_PRINCIPAL -u AWEB_API_KEY -u AW_HOME \
    HOME="$PROOF_HOME" AW_CONFIG_PATH="$CONFIG_PATH" AWEB_URL="$AWEB_URL" \
    AWID_REGISTRY_URL="$AWID_URL" AWID_SKIP_DNS_VERIFY=1 AW_NO_UPDATE_CHECK=1 \
    "$AW_BIN" id team cleanup-local-provision \
      --operation-id "$ATTACKER_OPERATION" --team-id "$TEAM_ID" --name "$VICTIM_ALIAS" \
      --authority-identity-home "$AUTHORITY_HOME" --target-identity-home "$VICTIM_TARGET" \
      --authority-address "$AUTHORITY_ADDRESS" --authority-stable-id "$AUTHORITY_STABLE" \
      --controller-did "$CONTROLLER_DID" --json
) > "$EVIDENCE/forged-execution-cleanup.txt" 2>&1
FORGED_EXECUTION_STATUS=$?
set -e
# Query the owning authorities before checking the local error. Under the guard
# mutation this is the deliberately destructive red assertion.
capture_provision_resource victim-after-forged-execution "$VICTIM_OPERATION" active
[[ "$FORGED_EXECUTION_STATUS" -ne 0 ]] || fail "forged execution cleanup unexpectedly succeeded"
grep -q "target record contradicts the requested operation" "$EVIDENCE/forged-execution-cleanup.txt" \
  || fail "forged execution cleanup was refused by the wrong boundary"

# The instance-side receipt is not cleanup authority. Retarget the attacker's
# valid receipt to the independently provisioned victim while leaving the
# capability corroboration operation-specific.
python3 - "$ATTACKER_HOME/instance.json" "$VICTIM_HOME/instance.json" <<'PY'
import json, sys
attacker_path, victim_path = sys.argv[1:]
attacker = json.load(open(attacker_path, encoding="utf-8"))
victim = json.load(open(victim_path, encoding="utf-8"))
attacker["capabilityMeta"]["aweb.identity-attach"]["identity_binding"] = victim["capabilityMeta"]["aweb.identity-attach"]["identity_binding"]
with open(attacker_path, "w", encoding="utf-8") as stream:
    json.dump(attacker, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY

echo "=== Refuse the forged victim, then execute authorized cleanup ==="
run_oas_with_agents "$DEVELOPER_B_AGENTS_ROOT" "$FIXTURE_REPO" retire "$ATTACKER_INSTANCE" --json > "$EVIDENCE/forged-retire.json"
capture_provision_resource victim-after-forged-retire "$VICTIM_OPERATION" active
capture_provision_resource attacker-after-forged-retire "$ATTACKER_OPERATION" active
python3 - "$EVIDENCE/forged-retire.json" <<'PY'
import json, sys
document = json.load(open(sys.argv[1], encoding="utf-8"))
if document.get("schemaVersion") == 1:
    document = document["result"]
retirement = document["capabilityMeta"]["aweb.identity-attach"]["retirement"]
assert retirement["action"] == "preserve", retirement
assert retirement["cleanup_authorized"] is False, retirement
assert retirement["reason"] == "cleanup_corroboration_missing_or_mismatched", retirement
PY

seed_provision_lifecycle_artifacts "$VICTIM_OPERATION"
run_oas_with_agents "$DEVELOPER_A_AGENTS_ROOT" "$FIXTURE_REPO" retire "$VICTIM_INSTANCE" --json > "$EVIDENCE/authorized-retire.json"
python3 - "$EVIDENCE/authorized-retire.json" <<'PY'
import json, sys
document = json.load(open(sys.argv[1], encoding="utf-8"))
if document.get("schemaVersion") == 1:
    document = document["result"]
assert document.get("warnings", []) == [], document
retirement = document["capabilityMeta"]["aweb.identity-attach"]["retirement"]
assert retirement["action"] == "cleanup_complete", retirement
assert retirement["cleanup"]["status"] == "complete", retirement
PY
capture_provision_resource victim-after-authorized-retire "$VICTIM_OPERATION" deleted
capture_provision_resource attacker-after-victim-retire "$ATTACKER_OPERATION" active
capture_durable_operation_tuple attacker-after-victim-cleanup "$ATTACKER_OPERATION"
assert_durable_operation_tuple_same attacker-before-victim-cleanup attacker-after-victim-cleanup
capture_durable_operation_tuple victim-before-attacker-cleanup "$VICTIM_OPERATION"
capture_operation_grants after-victim "$VICTIM_OPERATION=0" "$ATTACKER_OPERATION=0"

# The forged carrier's ordinary instance is gone, so its genuinely owned bound
# identity is an operator-confirmed unacknowledged handoff. Exercise the
# native active/trust-gated exact-operation command rather than a direct bin.
seed_provision_lifecycle_artifacts "$ATTACKER_OPERATION"
run_reconcile --cleanup-unacknowledged "$ATTACKER_OPERATION" > "$EVIDENCE/operator-reconcile.json"
capture_provision_resource attacker-after-operator-reconcile "$ATTACKER_OPERATION" deleted
capture_operation_grants after-attacker "$VICTIM_OPERATION=0" "$ATTACKER_OPERATION=0"
capture_provision_resource victim-after-attacker-reconcile "$VICTIM_OPERATION" deleted
capture_durable_operation_tuple victim-after-attacker-cleanup "$VICTIM_OPERATION"
assert_durable_operation_tuple_same victim-before-attacker-cleanup victim-after-attacker-cleanup

# Repeat isolation in the opposite order. B retires while A is still active;
# every A owner remains active. A then retires while B's deleted tuple remains
# unchanged, closing the latent direction hidden by the first A-then-B path.
run_oas_with_agents "$DEVELOPER_A_AGENTS_ROOT" "$FIXTURE_REPO" spawn proof-worker --purpose reverse-isolation --no-launch --json > "$EVIDENCE/reverse-a-spawn.json"
REVERSE_A_HOME="$(json_value "$EVIDENCE/reverse-a-spawn.json" home)"
REVERSE_A_INSTANCE="$(json_value "$EVIDENCE/reverse-a-spawn.json" instance)"
REVERSE_A_OPERATION="$(binding_operation "$REVERSE_A_HOME/instance.json")"
run_oas_with_agents "$DEVELOPER_B_AGENTS_ROOT" "$FIXTURE_REPO" spawn proof-worker --purpose reverse-isolation --no-launch --json > "$EVIDENCE/reverse-b-spawn.json"
REVERSE_B_HOME="$(json_value "$EVIDENCE/reverse-b-spawn.json" home)"
REVERSE_B_INSTANCE="$(json_value "$EVIDENCE/reverse-b-spawn.json" instance)"
REVERSE_B_OPERATION="$(binding_operation "$REVERSE_B_HOME/instance.json")"
capture_operation_grants reverse-both-active "$REVERSE_A_OPERATION=0" "$REVERSE_B_OPERATION=0"
[[ "$REVERSE_A_INSTANCE" == "$REVERSE_B_INSTANCE" ]] || fail "reverse isolation did not retain duplicate local names"
capture_provision_resource reverse-a-before-b-retire "$REVERSE_A_OPERATION" active
capture_provision_resource reverse-b-before-b-retire "$REVERSE_B_OPERATION" active
capture_durable_operation_tuple reverse-a-before-b-cleanup "$REVERSE_A_OPERATION"
seed_provision_lifecycle_artifacts "$REVERSE_B_OPERATION"
run_oas_with_agents "$DEVELOPER_B_AGENTS_ROOT" "$FIXTURE_REPO" retire "$REVERSE_B_INSTANCE" --json > "$EVIDENCE/reverse-b-retire.json"
capture_provision_resource reverse-b-after-b-retire "$REVERSE_B_OPERATION" deleted
capture_provision_resource reverse-a-after-b-retire "$REVERSE_A_OPERATION" active
capture_durable_operation_tuple reverse-a-after-b-cleanup "$REVERSE_A_OPERATION"
assert_durable_operation_tuple_same reverse-a-before-b-cleanup reverse-a-after-b-cleanup
capture_durable_operation_tuple reverse-b-before-a-cleanup "$REVERSE_B_OPERATION"
seed_provision_lifecycle_artifacts "$REVERSE_A_OPERATION"
run_oas_with_agents "$DEVELOPER_A_AGENTS_ROOT" "$FIXTURE_REPO" retire "$REVERSE_A_INSTANCE" --json > "$EVIDENCE/reverse-a-retire.json"
capture_provision_resource reverse-a-after-a-retire "$REVERSE_A_OPERATION" deleted
capture_provision_resource reverse-b-after-a-retire "$REVERSE_B_OPERATION" deleted
capture_durable_operation_tuple reverse-b-after-a-cleanup "$REVERSE_B_OPERATION"
assert_durable_operation_tuple_same reverse-b-before-a-cleanup reverse-b-after-a-cleanup

echo "=== Surface terminal quarantine and prove explicit remediation ==="
run_oas_with_agents "$DEVELOPER_A_AGENTS_ROOT" "$FIXTURE_REPO" spawn proof-worker --purpose quarantine-is-not-success --no-launch --json > "$EVIDENCE/quarantine-spawn.json"
QUARANTINE_HOME="$(json_value "$EVIDENCE/quarantine-spawn.json" home)"
QUARANTINE_INSTANCE="$(json_value "$EVIDENCE/quarantine-spawn.json" instance)"
QUARANTINE_OPERATION="$(binding_operation "$QUARANTINE_HOME/instance.json")"
capture_operation_grants quarantine-active "$QUARANTINE_OPERATION=0"
seed_provision_lifecycle_artifacts "$QUARANTINE_OPERATION"
TEAM_KEY_PATH="$(json_value "$EVIDENCE/team-create.json" team_key_path)"
[[ -f "$TEAM_KEY_PATH" ]] || fail "throwaway controller key was not found for quarantine proof"
mv "$TEAM_KEY_PATH" "$TEAM_KEY_PATH.proof-unavailable"
run_oas_with_agents "$DEVELOPER_A_AGENTS_ROOT" "$FIXTURE_REPO" retire "$QUARANTINE_INSTANCE" --json > "$EVIDENCE/quarantine-retire.json"
grep -q 'cleanup remains durably pending' "$EVIDENCE/quarantine-retire.json" || fail "failed cleanup was not visible on ordinary retire"
set +e
run_reconcile --operation "$QUARANTINE_OPERATION" > "$EVIDENCE/quarantine-retry-2.json" 2>&1
QUARANTINE_RETRY_2=$?
run_reconcile --operation "$QUARANTINE_OPERATION" > "$EVIDENCE/quarantine-retry-3.json" 2>&1
QUARANTINE_RETRY_3=$?
set -e
[[ "$QUARANTINE_RETRY_2" -ne 0 && "$QUARANTINE_RETRY_3" -ne 0 ]] || fail "cleanup failure was counted as reconciliation success"
[[ "$(json_value "$PRINCIPAL_HOME/.provisioning/intents/$QUARANTINE_OPERATION.json" state)" == "quarantined" ]] \
  || fail "third failed cleanup did not enter terminal visible quarantine"
grep -q 'quarantined' "$EVIDENCE/quarantine-retry-3.json" || fail "terminal quarantine was not visible to the operator"
mv "$TEAM_KEY_PATH.proof-unavailable" "$TEAM_KEY_PATH"
run_reconcile --retry-quarantine "$QUARANTINE_OPERATION" > "$EVIDENCE/quarantine-remediation.json"
capture_provision_resource quarantine-after-remediation "$QUARANTINE_OPERATION" deleted
scan_final_known_material victim "$FIXTURE_REPO" "$DEVELOPER_A_AGENTS_ROOT" "$DEVELOPER_B_AGENTS_ROOT"
scan_final_known_material attacker "$FIXTURE_REPO" "$DEVELOPER_A_AGENTS_ROOT" "$DEVELOPER_B_AGENTS_ROOT"

assert_clean_git_subject "$REPO_ROOT" aweb
assert_clean_git_subject "$OAS_ROOT" OAS
capture_execution_subject

echo "=== Write proof report ==="
SOURCE_SHA="$(git -C "$REPO_ROOT" rev-parse HEAD)"
OAS_SHA="$(git -C "$OAS_ROOT" rev-parse HEAD)"
OAS_PACKAGE_VERSION="$(python3 - "$OAS_ROOT/package.json" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["version"])
PY
)"
OAS_CLI_SHA="$(file_sha256 "$OAS_ROOT/bin/oas.mjs")"
OAS_CORE_SHA="$(file_sha256 "$OAS_ROOT/lib/core.mjs")"
EXECUTION_CLOSURE_SHA="$(file_sha256 "$EVIDENCE/execution-subject.json")"
AW_BINARY_SHA="$(file_sha256 "$AW_BIN")"
NODE_VERSION="$(node --version)"
PYTHON_VERSION="$(python3 --version 2>&1)"
SNAPSHOT_SHA="$(file_sha256 "$EVIDENCE/principal-pre.json")"
ADDRESS_SHA="$(file_sha256 "$EVIDENCE/registry-pre-address.json")"
RESOLVE_SHA="$(file_sha256 "$EVIDENCE/registry-pre-resolve.json")"
VERIFY_SHA="$(file_sha256 "$EVIDENCE/registry-pre-verify.json")"
mkdir -p "$(dirname "$REPORT")"
python3 - "$REPORT" "$SOURCE_SHA" "$OAS_SHA" "$OAS_PACKAGE_VERSION" "$OAS_CLI_SHA" "$OAS_CORE_SHA" "$EXECUTION_CLOSURE_SHA" "$EVIDENCE/execution-subject.json" "$AW_BINARY_SHA" "$NODE_VERSION" "$PYTHON_VERSION" "$ADDRESS" "$DID_AW" "$TEAM_ID" "$SNAPSHOT_SHA" "$ADDRESS_SHA" "$RESOLVE_SHA" "$VERIFY_SHA" "$EVIDENCE/registry-pre-address.json" "$EVIDENCE/registry-pre-resolve.json" "$EVIDENCE/registry-pre-verify.json" "$VICTIM_OPERATION" "$ATTACKER_OPERATION" "$QUARANTINE_OPERATION" <<'PY'
import json, sys
(report, source, oas_source, oas_version, oas_cli_sha, oas_core_sha, closure_sha, closure_path,
 aw_binary_sha, node_version, python_version, address, stable, team, snapshot_sha, address_sha, resolve_sha,
 verify_sha, address_path, resolve_path, verify_path, victim_operation, attacker_operation,
 quarantine_operation) = sys.argv[1:]
address_observation = json.load(open(address_path, encoding="utf-8"))
resolve_observation = json.load(open(resolve_path, encoding="utf-8"))
verify_observation = json.load(open(verify_path, encoding="utf-8"))
execution_modules = json.load(open(closure_path, encoding="utf-8"))
document = {
    "schema": "aweb.oas-principal-lifecycle-proof.v3",
    "source_sha": source,
    "source_tracked_clean": True,
    "oas_subject": {
        "git_sha": oas_source,
        "version": oas_version,
        "bin_oas_mjs_sha256": oas_cli_sha,
        "lib_core_mjs_sha256": oas_core_sha,
        "executed_module_manifest_sha256": closure_sha,
        "git_top_level_equals_selected_root": True,
        "tracked_clean": True,
    },
    "execution_subject": {
        "aw_binary_sha256": aw_binary_sha,
        "node_version_outside_first_party_subject": node_version,
        "python_version_outside_first_party_subject": python_version,
        "resolved_execution_modules": execution_modules,
    },
    "stack": {"loopback_only": True, "postgres_tmpfs_verified": True},
    "principal": {"address": address, "stable_id": stable, "team_id": team, "throwaway": True},
    "attach_observation": {
        "production_entry": "oas spawn --no-launch",
        "credential_declaration_agreement": True,
        "registry_verification_attributed_to_attach": False,
    },
    "retire_observation": {
        "production_entry": "ordinary oas retire",
        "cleanup_owner": "external",
        "receipt": "preserve_principal",
        "instance_removed": True,
    },
    "customer_journey_observation": {
        "workspace": "fresh external git workspace",
        "acquisition": "on-disk acquired artifact and untrusted lock observed directly; owning endpoints unchanged, with no local monotonic writer signal to exclude create-then-erase",
        "configuration_consumption": "attach-existing divergence spawned successfully and persisted the predicted attach-existing binding before ordinary attach was restored",
        "onboarding": "explicit principal, team, declaration, config, and trust setup",
        "hosted_disposable_refusal_owning_endpoints_unchanged": True,
        "durable_refusal_owning_endpoints_unchanged": True,
        "refusal_temporal_claim_bounded_by_missing_local_allocation_counter": True,
        "duplicate_local_instance_names_both_succeeded": True,
        "duplicate_names_produced_distinct_operations_and_aliases": True,
        "successful_operations_had_zero_local_grant_records_at_local_owner": True,
        "interrupted_pre_accept_observation": "one exhaustive local bearer record matched the operation and target team by content; the record has no grantee field by bearer design; same-operation re-entry left zero local records",
        "each_cleanup_changed_only_its_durable_operation_tuple": True,
        "cleanup_isolation_exercised_in_both_orders": True,
        "both_developers_completed_an_ordinary_retire": True,
    },
    "provision_cleanup_observation": {
        "authority_path": "local-controller",
        "threat_demonstrated": "local-same-uid-accident-and-confused-deputy",
        "victim_operation": victim_operation,
        "forged_execution_refused_by": "target operation-record mismatch",
        "forged_receipt_refused_by": "cleanup_corroboration_missing_or_mismatched",
        "victim_remained_active_after_both_forged_paths": True,
        "authorized_retire_deleted_victim": True,
        "attacker_operation": attacker_operation,
        "native_manifest_command_deleted_unacknowledged_attacker": True,
        "interrupted_handoff_reconciled_instead_of_replayed": True,
        "quarantine_operation": quarantine_operation,
        "third_cleanup_failure_was_visible_terminal_non_success": True,
        "explicit_quarantine_remediation_completed": True,
        "positive_lifecycle_controls_removed": ["PostgreSQL task claim", "PostgreSQL reservation", "Redis expired workspace+agent-heartbeat cleanup coordinates", "Redis global presence index", "Redis team presence index", "Redis alias presence index"],
        "real_plaintext_mail_round_trip_completed": True,
        "not_created_by_no_launch_provision": ["aweb API key"],
        "provisioned_material_copy_hardlink_symlink_scan_passed": True,
        "no_verbatim_copy_of_known_credential_files_in_controlled_roots_after_messaging": True,
        "external_journals_terminal_complete": True,
        "owning_authorities_queried": ["AWID certificate roster", "aweb PostgreSQL lifecycle state", "aweb Redis presence", "local credential and invite stores", "external provision journal"],
    },
    "independent_observations": {
        "registry_address_unchanged": True,
        "registry_resolution_unchanged": True,
        "did_log_verified_pre_post": True,
        "gone_workspace_sweep_completed": True,
        "principal_store_unchanged": True,
        "instance_copy_hardlink_symlink_scan_passed": True,
        "principal_snapshot_sha256": snapshot_sha,
        "registry_address_sha256": address_sha,
        "registry_resolution_sha256": resolve_sha,
        "did_log_verification_sha256": verify_sha,
        "registry_address": address_observation,
        "registry_resolution": resolve_observation,
        "did_log_verification": verify_observation,
    },
    "limitations": [
        "no model session was launched; --no-launch skips only session launch, not lifecycle hooks",
        "OAS_SETTINGS binding is config-scoped",
        "v1 has no admission lease or concurrent-use fencing",
        "attach itself performs no registry resolution or DID-log verification",
        "local cleanup corroboration is same-UID accident/confused-deputy evidence, not hostile-model resistance",
        "refusal mutation evidence is bounded to full owning-namespace endpoint equality; no per-writer known-positive monotonic control ran before the refusals, so the proof does not establish the temporal before-create claim",
        "zero local grant records after success does not independently prove that no copied bearer could be redeemed",
        "credential content scan excludes verbatim known file bytes but not encoded, split, derived, or newly generated bearer material",
        "the exact OAS Git subject is a local unpushed clone; this report does not claim reproduction from published OAS 0.18.6",
    ],
}
with open(report, "w", encoding="utf-8") as stream:
    json.dump(document, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY

echo "PROOF PASSED"
echo "  report: $REPORT"
echo "  principal: $ADDRESS ($DID_AW)"
echo "  principal snapshot sha256: $SNAPSHOT_SHA"
echo "  registry address sha256: $ADDRESS_SHA"
echo "  registry resolution sha256: $RESOLVE_SHA"
echo "  DID-log verification sha256: $VERIFY_SHA"
