#!/bin/sh
# Refuse an unexpected PGDATA, disk-backed WAL, or unavailable swap accounting.
set -eu
test "$(psql -U "${POSTGRES_USER:-postgres}" -d "${POSTGRES_DB:-postgres}" -Atqc 'show data_directory')" = /var/lib/postgresql/data && \
  test "$(readlink -f /var/lib/postgresql/data)" = /var/lib/postgresql/data && \
  test "$(stat -f -c %T /var/lib/postgresql/data)" = tmpfs && \
  test "$(readlink -f /var/lib/postgresql/data/pg_wal)" = /var/lib/postgresql/data/pg_wal && \
  test "$(cat /sys/fs/cgroup/memory.swap.max)" = 0
