#!/bin/sh
# Run a focused test command with an owned, memory-backed PostgreSQL 17.
set -eu
[ "$#" -gt 0 ] || { echo 'usage: test-postgres.sh command [args...]' >&2; exit 2; }
test_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_evidence=$(mktemp -d "${TMPDIR:-/tmp}/aweb-test-postgres.XXXXXX")
chmod 700 "$test_evidence"
test_container=''
cleanup() {
  test_status=$?
  trap - EXIT INT TERM
  if [ -n "$test_container" ]; then
    docker logs "$test_container" > "$test_evidence/postgres.log" 2>&1 || true
    python3 "$test_root/scripts/test-postgres-inspect.py" "$test_container" > "$test_evidence/postgres-inspect.json" || true
    docker exec "$test_container" sh -c 'cat /sys/fs/cgroup/memory.peak; cat /sys/fs/cgroup/memory.events; du -sk /var/lib/postgresql/data' > "$test_evidence/usage.txt" || true
    docker rm -f -v "$test_container" >/dev/null || test_status=1
  fi
  rm -f "$test_evidence/environment"
  printf 'PostgreSQL test evidence: %s\n' "$test_evidence" >&2
  exit "$test_status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
umask 077
test_password=$(openssl rand -hex 24)
printf 'POSTGRES_PASSWORD=%s\nPOSTGRES_USER=postgres\nPOSTGRES_DB=postgres\n' "$test_password" > "$test_evidence/environment"
test_container=$(docker run -d --cpus 1 --memory 4g --memory-swap 4g --pids-limit 512 \
  --tmpfs /var/lib/postgresql/data:rw,nosuid,nodev,size=2g \
  --env-file "$test_evidence/environment" -p 127.0.0.1::5432 postgres:17)
test_ready=false
for test_attempt in $(seq 1 60); do
  if docker exec "$test_container" pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1; then
    test_ready=true
    break
  fi
  sleep .25
done
"$test_ready" || { echo 'PostgreSQL did not become ready' >&2; exit 1; }
docker exec "$test_container" sh -c "$(cat "$test_root/scripts/test-postgres-storage.sh")" \
  || { echo 'PostgreSQL storage or swap accounting is not suitable for tests' >&2; exit 1; }
export PGHOST=127.0.0.1 PGUSER=postgres PGPASSWORD="$test_password" PGDATABASE=postgres
PGPORT=$(docker port "$test_container" 5432/tcp | awk -F: '{print $NF}')
export PGPORT
export TEST_DB_HOST="$PGHOST" TEST_DB_PORT="$PGPORT" TEST_DB_USER="$PGUSER" TEST_DB_PASSWORD="$PGPASSWORD"
"$@"
