#!/usr/bin/env bash
# One disposable first-path composition. Execute only after coordinator plan GO.
set -euo pipefail
umask 0077
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
[[ $# == 1 ]] || { echo 'usage: e2e-adcl6-first-path.sh APPROVAL_GIT_ARCHIVE (aw and holder build from this checkout)' >&2; exit 2; }
APPROVAL_ARCHIVE="$1"
[[ "$APPROVAL_ARCHIVE" = /* && -f "$APPROVAL_ARCHIVE" ]] || { echo 'approval archive must be an existing absolute path' >&2; exit 2; }
PROJECT="aweb-adcl6-${RANDOM}-$$"
BIND_ROOT="${AWEB_DOCKER_BIND_ROOT:-${TMPDIR:-/tmp}}"
[[ "$BIND_ROOT" = /* && -d "$BIND_ROOT" ]] || { echo 'AWEB_DOCKER_BIND_ROOT must be an existing absolute directory' >&2; exit 2; }
RUNTIME="$(mktemp -d "$BIND_ROOT/aweb-adcl6.XXXXXX")"
OUTPUT="${ADCL6_EVIDENCE_DIR:-$ROOT/../reports/$PROJECT}"
mkdir -p "$OUTPUT"
chmod 0700 "$OUTPUT"
IMAGE="$PROJECT-runtime:journey"
case "$(docker info --format '{{.Architecture}}')" in
  aarch64|arm64) ARCHITECTURE=arm64 ;;
  x86_64|amd64) ARCHITECTURE=amd64 ;;
  *) echo 'unsupported Docker server architecture' >&2; exit 2 ;;
esac
compose() { docker compose -p "$PROJECT" -f "$RUNTIME/compose.json" "$@"; }
cleanup() {
  primary=$?
  trap - EXIT
  set +e
  cleanup_status=0
  if [[ -f "$RUNTIME/compose.json" ]]; then
    compose logs --no-color >"$OUTPUT/services.log" 2>&1 || cleanup_status=1
    compose down -v --remove-orphans >"$OUTPUT/docker-cleanup.log" 2>&1 || cleanup_status=1
    if docker image inspect "$IMAGE" >/dev/null 2>&1; then
      docker run --rm --label com.docker.compose.project="$PROJECT" --network none --read-only --user 0:0 -v "$RUNTIME/work:/work" "$IMAGE" python /journey.py retain --uid "$(id -u)" --gid "$(id -g)" >"$OUTPUT/retention.log" 2>&1 || cleanup_status=1
      # An interrupted docker-run client can leave a created one-off behind.
      # These all carry this exact project's label, including UID probes.
      leftovers="$(docker ps -aq --filter label=com.docker.compose.project="$PROJECT")" || cleanup_status=1
      for container in $leftovers; do
        docker rm -f "$container" >>"$OUTPUT/docker-cleanup.log" 2>&1 || cleanup_status=1
      done
      docker image rm "$IMAGE" >>"$OUTPUT/docker-cleanup.log" 2>&1 || cleanup_status=1
    fi
    for kind in container volume network; do
      case "$kind" in
        container) remaining="$(docker ps -aq --filter label=com.docker.compose.project="$PROJECT")" || cleanup_status=1 ;;
        volume) remaining="$(docker volume ls -q --filter label=com.docker.compose.project="$PROJECT")" || cleanup_status=1 ;;
        network) remaining="$(docker network ls -q --filter label=com.docker.compose.project="$PROJECT")" || cleanup_status=1 ;;
      esac
      [[ -z "$remaining" ]] || cleanup_status=1
      printf '%s: %s\n' "$kind" "$remaining" >>"$OUTPUT/inventory.txt"
    done
  fi
  for name in ca.crt adcl6.test.zone; do [[ ! -f "$RUNTIME/public/$name" ]] || cp "$RUNTIME/public/$name" "$OUTPUT/$name" || cleanup_status=1; done
  [[ ! -f "$RUNTIME/tls/server.crt" ]] || cp "$RUNTIME/tls/server.crt" "$OUTPUT/server.crt" || cleanup_status=1
  # Only public evidence and private receipt/act diagnostics are retained.
  # Identity homes, browser profile and the holder's private volume are erased.
  for name in inputs.json; do [[ ! -f "$RUNTIME/$name" ]] || cp "$RUNTIME/$name" "$OUTPUT/$name" || cleanup_status=1; done
  if [[ -d "$RUNTIME/work" ]]; then
    for name in journey.json first-activation.json second-activation.json first-outside.json first-no-evidence-outside.json second-outside.json approval-record.json controller-public.json command-failure.stderr prompt-counts.json retention.json; do
      [[ ! -f "$RUNTIME/work/$name" ]] || cp "$RUNTIME/work/$name" "$OUTPUT/$name" || cleanup_status=1
    done
    [[ ! -d "$RUNTIME/work/public" ]] || cp -R "$RUNTIME/work/public" "$OUTPUT/public-exports" || cleanup_status=1
  fi
  rm -rf "$RUNTIME" || cleanup_status=1
  python3 - "$OUTPUT/outcome.json" "$primary" "$cleanup_status" <<'PY'
import json,sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({'primary_exit':int(sys.argv[2]),'cleanup_exit':int(sys.argv[3])})+'\n')
PY
  [[ $? -eq 0 ]] || exit 1
  [[ "$primary" -eq 0 && "$cleanup_status" -eq 0 ]] || exit 1
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
python3 "$ROOT/scripts/adcl6_first_path.py" prepare --runtime "$RUNTIME" --project "$PROJECT" --approval-archive "$APPROVAL_ARCHIVE" --architecture "$ARCHITECTURE"
mkdir "$RUNTIME/tls"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=adcl6-fixture-CA -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign -addext subjectKeyIdentifier=hash -keyout "$RUNTIME/tls/ca.key" -out "$RUNTIME/public/ca.crt" >"$OUTPUT/tls-build.log" 2>&1
openssl req -newkey rsa:2048 -nodes -subj /CN=approval.adcl6.test -keyout "$RUNTIME/tls/server.key" -out "$RUNTIME/tls/server.csr" >>"$OUTPUT/tls-build.log" 2>&1
cat >"$RUNTIME/tls/extensions" <<'EOF'
subjectAltName=DNS:awid.adcl6.test,DNS:approval.adcl6.test,DNS:holder.adcl6.test
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
openssl x509 -req -days 1 -in "$RUNTIME/tls/server.csr" -CA "$RUNTIME/public/ca.crt" -CAkey "$RUNTIME/tls/ca.key" -CAcreateserial -extfile "$RUNTIME/tls/extensions" -out "$RUNTIME/tls/server.crt" >>"$OUTPUT/tls-build.log" 2>&1
openssl verify -x509_strict -purpose sslserver -verify_hostname awid.adcl6.test -CAfile "$RUNTIME/public/ca.crt" "$RUNTIME/tls/server.crt" >>"$OUTPUT/tls-build.log" 2>&1
chmod 0644 "$RUNTIME/public/ca.crt" "$RUNTIME/tls/server.crt"
cp "$RUNTIME/public/ca.crt" "$RUNTIME/build/fixture-ca.crt"
docker build --platform "linux/$ARCHITECTURE" --label com.docker.compose.project="$PROJECT" -t "$IMAGE" "$RUNTIME/build" >"$OUTPUT/image-build.log" 2>&1
docker image inspect "$IMAGE" >"$OUTPUT/image.json"
docker run --rm --label com.docker.compose.project="$PROJECT" "$IMAGE" cat /package-inventory.txt >"$OUTPUT/package-inventory.txt"
docker run --rm --label com.docker.compose.project="$PROJECT" "$IMAGE" cat /wheel-hashes.txt >"$OUTPUT/wheel-hashes.txt"
for pair in 1001:awid 1002:awsign 1003:aweb-key-holder; do
  docker run --rm --label com.docker.compose.project="$PROJECT" --user "${pair%%:*}:${pair%%:*}" "$IMAGE" "${pair#*:}" --help >>"$OUTPUT/service-uid-entrypoints.log" 2>&1
done
compose config >"$OUTPUT/compose-resolved.yml"
compose run --rm -T --no-deps --user 0:0 holder sh -ec 'chown 1003:1003 /state; chmod 0700 /state' >"$OUTPUT/state-init.log" 2>&1
compose up -d dns pg-awid pg-approval redis awid approval holder https >"$OUTPUT/startup.log" 2>&1
compose run --rm -T --no-deps driver >"$OUTPUT/journey.log" 2>&1
cat "$OUTPUT/journey.log"
