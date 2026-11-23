#!/usr/bin/env bash
# Installs, from PGDG under its pinned signing key, the PostgreSQL client of the
# major version the tests' server runs (postgres:17, scripts/test-egress/docker.py).
# pg_dump refuses a newer server, and a newer client's dump sets parameters an
# older server does not know, so client and server share one major version.
# The gate image (scripts/test-egress/Dockerfile) and the CI jobs whose tests back
# up and restore both run this, on the PGDG suite of their own distribution.
set -euo pipefail

major=17
here=$(cd "$(dirname "$0")" && pwd)
install -d -m 0755 /etc/apt/keyrings
bash "$here/install-pgdg-key.sh" "$here/keys/ACCC4CF8.asc" /etc/apt/keyrings/pgdg.gpg

# shellcheck source=/dev/null
. /etc/os-release
echo "deb [signed-by=/etc/apt/keyrings/pgdg.gpg] https://apt.postgresql.org/pub/repos/apt ${VERSION_CODENAME}-pgdg main" \
  > /etc/apt/sources.list.d/pgdg.list
apt-get update
apt-get install -y --no-install-recommends "postgresql-client-$major"
"/usr/lib/postgresql/$major/bin/pg_dump" --version | grep -q " $major\."
