#!/bin/sh
set -eu

cd "$(dirname "$0")/../.."
security_options=$(docker info --format '{{range .SecurityOptions}}{{println .}}{{end}}')
set --
case "$security_options" in
  *name=apparmor*) set -- --security-opt apparmor=aweb-secrets-oci-proof ;;
esac

docker build --build-context runner=. --build-context values=../values \
  --build-context naapp=../../../naapp-lib \
  -t aweb-secrets-runner-oci-proof tests/oci
exec docker run --rm --init --network none --cap-drop ALL "$@" \
  --security-opt no-new-privileges --security-opt seccomp=unconfined \
  --security-opt systempaths=unconfined --user 10000:10000 \
  --tmpfs /memory:rw,exec,nosuid,nodev,mode=0700,uid=10000,gid=10000 \
  --mount "type=bind,source=$(pwd),target=/runner,readonly" \
  --env PYTHONPATH=/runner/src:/runner/tests:/runner/tests/oci \
  --env AWEB_SECRETS_OCI_PROOF=1 \
  aweb-secrets-runner-oci-proof \
  python3 -B -m pytest -c /runner/pyproject.toml -p no:cacheprovider \
    -p verify_oci_collection /runner/tests/oci
