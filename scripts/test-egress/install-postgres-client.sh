#!/usr/bin/env bash
# Installs, from PGDG under its pinned signing key, the PostgreSQL client of the
# major version the tests' server runs (postgres:17, scripts/test-egress/docker.py).
# pg_dump refuses a newer server, and a newer client's dump sets parameters an
# older server does not know, so client and server share one major version.
# These are the gate image's commands (scripts/test-egress/Dockerfile, the
# postgresql-client-17 step), on the host's own PGDG suite, for the CI jobs
# whose tests back up and restore.
set -euo pipefail

major=17
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=/dev/null
. /etc/os-release

install -d -m 0755 /etc/apt/keyrings
bash "$here/install-pgdg-key.sh" "$here/keys/ACCC4CF8.asc" /etc/apt/keyrings/pgdg.gpg
echo "deb [signed-by=/etc/apt/keyrings/pgdg.gpg] https://apt.postgresql.org/pub/repos/apt ${VERSION_CODENAME}-pgdg main" \
  > /etc/apt/sources.list.d/pgdg.list
apt-get update
apt-get install -y --no-install-recommends "postgresql-client-$major"
"/usr/lib/postgresql/$major/bin/pg_dump" --version | grep -q " $major\."
