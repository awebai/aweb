#!/bin/sh
set -eu

cd "$(dirname "$0")/../.."
profile=aweb-secrets-oci-proof
profile_sha256=54b49f58839bcb3d71471567f427b4fa7ceb8539354099dd1b5ba9bce84c9e8d
profile_dir=/usr/local/share/aweb-oci-proof
staged_profile=$profile_dir/$profile.apparmor
kernel_profiles=/sys/kernel/security/apparmor/profiles
docker_socket=unix:///var/run/docker.sock

refuse() {
  printf '%s\n' "$1" >&2
  exit 1
}

parse_profile() {
  action=$1
  shift
  parser_status=0
  "$@" /usr/sbin/apparmor_parser "$action" --skip-cache "$staged_profile" ||
    parser_status=$?
  printf 'AppArmor parser %s exit %s\n' "$action" "$parser_status"
  return "$parser_status"
}

cleanup_profile() {
  proof_status=$?
  trap - EXIT
  parse_profile --remove sudo -n --
  if grep -Fq "$profile (" "$kernel_profiles"; then
    refuse "OCI proof AppArmor profile is still loaded after removal"
  fi
  printf 'Removed AppArmor profile: %s\n' "$profile"
  exit "$proof_status"
}

if ! systemd-detect-virt --vm --quiet || systemd-detect-virt --container --quiet; then
  refuse "Run the OCI proof in a disposable Linux VM guest"
fi
security_options=$(docker --host "$docker_socket" info --format '{{json .SecurityOptions}}')
case "$security_options" in
  *name=apparmor*) ;;
  *) refuse "The local Docker daemon must support AppArmor for the OCI proof" ;;
esac
[ -r "$kernel_profiles" ] || refuse "Cannot read the guest AppArmor profiles"
if grep -Fq "$profile (" "$kernel_profiles"; then
  refuse "The OCI proof AppArmor profile is already loaded"
fi
[ ! -L "$profile_dir" ] && [ -d "$profile_dir" ] &&
  [ "$(stat -c '%u:%g:%a' "$profile_dir")" = 0:0:755 ] ||
  refuse "The staged profile directory must be root:root mode 0755"
[ ! -L "$staged_profile" ] && [ -f "$staged_profile" ] &&
  [ "$(stat -c '%u:%g:%a' "$staged_profile")" = 0:0:444 ] ||
  refuse "The staged profile must be a root:root mode 0444 file"
printf '%s  %s\n' "$profile_sha256" "tests/oci/$profile.apparmor" \
  "$profile_sha256" "$staged_profile" | sha256sum --check
printf 'Pinned AppArmor profile SHA-256: %s\n' "$profile_sha256"
parse_profile --skip-kernel-load

docker --host "$docker_socket" build --build-context runner=. --build-context values=../values \
  --build-context naapp=../../../naapp-lib \
  -t aweb-secrets-runner-oci-proof tests/oci
parse_profile --add sudo -n --
trap cleanup_profile EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
grep -Fx "$profile (enforce)" "$kernel_profiles" ||
  refuse "The OCI proof AppArmor profile must be loaded in enforce mode"

docker --host "$docker_socket" run --rm --init --network none --cap-drop ALL \
  --security-opt "apparmor=$profile" \
  --security-opt no-new-privileges --security-opt seccomp=unconfined \
  --security-opt systempaths=unconfined --user 10000:10000 \
  --tmpfs /memory:rw,exec,nosuid,nodev,mode=0700,uid=10000,gid=10000 \
  --mount "type=bind,source=$(pwd),target=/runner,readonly" \
  --env PYTHONPATH=/runner/src:/runner/tests:/runner/tests/oci \
  --env AWEB_SECRETS_OCI_PROOF=1 \
  --env "AWEB_SECRETS_OCI_EXPECTED_APPARMOR=$profile" \
  aweb-secrets-runner-oci-proof \
  python3 -B -m pytest -c /runner/pyproject.toml -p no:cacheprovider \
    -p verify_oci_collection /runner/tests/oci
