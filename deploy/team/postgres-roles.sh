#!/bin/sh
# Creates one role and one database per component, at the first start of the
# bundled PostgreSQL. Each file in /run/secrets/postgres/roles/ is named
# after a component and holds that role's password, the same one that is in
# the component's own database-url file.
#
# The password goes from the file to the server inside psql: it is in no
# argument and no environment.
set -eu

for file in /run/secrets/postgres/roles/*; do
  [ -f "$file" ] || continue
  role=$(basename "$file")
  case "$role" in
    *[!a-z]*) echo "postgres-roles: $role is not a component name" >&2; exit 1 ;;
  esac
  psql -v ON_ERROR_STOP=1 --username postgres -v role="$role" -v file="$file" <<'SQL'
\set password `cat :'file'`
CREATE ROLE :"role" LOGIN PASSWORD :'password';
CREATE DATABASE :"role" OWNER :"role";
REVOKE ALL ON DATABASE :"role" FROM PUBLIC;
SQL
done
