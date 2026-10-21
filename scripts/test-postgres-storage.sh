#!/bin/sh
# Refuse an unexpected PGDATA, disk-backed WAL, or unavailable swap accounting.
# CI starts services before checkout and carries six inline copies of the storage
# assertions. Update those copies whenever these assertions change.
set -eu
# The temporary initdb server has only a Unix socket. Wait for the real listener.
pg_isready -h 127.0.0.1 -U "${POSTGRES_USER:-postgres}" -d "${POSTGRES_DB:-postgres}" >/dev/null
test "$(psql -U "${POSTGRES_USER:-postgres}" -d "${POSTGRES_DB:-postgres}" -Atqc 'show data_directory')" = /var/lib/postgresql/data && \
  test "$(readlink -f /var/lib/postgresql/data)" = /var/lib/postgresql/data && \
  test "$(stat -f -c %T /var/lib/postgresql/data)" = tmpfs && \
  test "$(readlink -f /var/lib/postgresql/data/pg_wal)" = /var/lib/postgresql/data/pg_wal && \
  test "$(cat /sys/fs/cgroup/memory.swap.max)" = 0
