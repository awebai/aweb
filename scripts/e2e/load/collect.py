#!/usr/bin/env python3
"""Samples one Compose project's containers, databases, caches and logs into
JSONL while a load ramp runs beside it. See README.md.

It only reads. It runs no statement that writes, enables no extension, resets
no limiter or statistic, and changes no configuration. It passes no credential
in argv or environment and writes none: aweb's Redis password stays inside the
aweb container, where a short script reads the mounted URL file and returns only
counters; PostgreSQL is read as the postgres user over the container's local
socket, which needs no password.
"""

from __future__ import annotations

import argparse
import json
import re
import signal
import subprocess
import sys
import threading
import time
from calendar import timegm
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable

COMMAND_TIMEOUT_SECONDS = 20
ERROR_TEXT_LIMIT = 200

_UNITS = {
    "B": 1,
    "kB": 10**3, "KB": 10**3, "MB": 10**6, "GB": 10**9, "TB": 10**12,
    "KiB": 2**10, "MiB": 2**20, "GiB": 2**30, "TiB": 2**40,
}
_SIZE = re.compile(r"^([0-9.]+)\s*([A-Za-z]+)$")


def parse_size(text: str) -> int | None:
    """A size as `docker stats` prints it, in bytes; None for its placeholder."""
    match = _SIZE.match(text.strip())
    if not match or match.group(2) not in _UNITS:
        return None
    return round(float(match.group(1)) * _UNITS[match.group(2)])


def _pair(text: str) -> tuple[int | None, int | None]:
    left, _, right = text.partition("/")
    return parse_size(left), parse_size(right)


def _number(text: str, convert: Callable[[str], Any]) -> Any:
    try:
        return convert(text.strip().rstrip("%"))
    except ValueError:
        return None


def container_sample(stats_line: str) -> dict[str, Any]:
    """One line of `docker stats --no-stream --format '{{json .}}'`."""
    stats = json.loads(stats_line)
    mem, mem_limit = _pair(stats.get("MemUsage", ""))
    net_rx, net_tx = _pair(stats.get("NetIO", ""))
    block_read, block_write = _pair(stats.get("BlockIO", ""))
    return {
        "name": stats["Name"],
        "cpu_percent": _number(stats.get("CPUPerc", ""), float),
        "mem_bytes": mem,
        "mem_limit_bytes": mem_limit,
        "net_rx_bytes": net_rx,
        "net_tx_bytes": net_tx,
        "block_read_bytes": block_read,
        "block_write_bytes": block_write,
        "pids": _number(stats.get("PIDs", ""), int),
    }


def parse_docker_timestamp(text: str) -> float:
    """An RFC 3339 UTC timestamp as `docker logs --timestamps` writes it, with
    up to nanosecond precision, as Unix seconds."""
    text = text.rstrip("Z")
    whole, _, fraction = text.partition(".")
    seconds = timegm(time.strptime(whole, "%Y-%m-%dT%H:%M:%S"))
    return seconds + (float(f"0.{fraction}") if fraction else 0.0)


_ACCESS = re.compile(r'"[A-Z]+ \S+ HTTP/[0-9.]+" (\d{3})\b')
_PLAIN_LEVEL = re.compile(r"^(WARNING|ERROR|CRITICAL):\s")
_POSTGRES_LEVEL = re.compile(r"\] (WARNING|ERROR|FATAL|PANIC):\s+(.*)$")
_POSTGRES_CLASSES = (
    ("too_many_clients", ("too many clients", "remaining connection slots are reserved")),
    ("lock_timeout", ("lock timeout",)),
    ("statement_timeout", ("statement timeout",)),
    ("idle_in_transaction_timeout", ("idle-in-transaction timeout",)),
    ("deadlock", ("deadlock detected",)),
    ("out_of_memory", ("out of memory",)),
)
_JSON_LEVELS = {"WARNING", "ERROR", "CRITICAL"}


def _postgres_class(message: str) -> str:
    lowered = message.lower()
    for name, needles in _POSTGRES_CLASSES:
        if any(needle in lowered for needle in needles):
            return name
    return "other"


def _count(counts: dict[str, dict[str, int]], firsts: dict[str, float], key: str, at: float) -> None:
    by_second = counts.setdefault(key, {})
    second = str(int(at))
    by_second[second] = by_second.get(second, 0) + 1
    firsts[key] = min(firsts.get(key, at), at)


def totals(counts: dict[str, dict[str, int]]) -> dict[str, int]:
    """Per-second counts summed per key."""
    return {key: sum(by_second.values()) for key, by_second in counts.items()}


def scan_log(text: str, *, since: float, until: float) -> dict[str, Any]:
    """Counts what one container logged in [since, until): HTTP statuses from
    uvicorn access lines, levels from JSON, uvicorn and PostgreSQL lines, and
    PostgreSQL errors by known class. Each count is kept per whole Unix second,
    so a step's window can be cut to the second, with the exact first time of
    each key. It never keeps a message's text."""
    scan: dict[str, Any] = {
        "http": {}, "http_first": {}, "levels": {}, "levels_first": {}, "pg": {}, "pg_first": {},
    }
    for line in text.splitlines():
        stamp, _, rest = line.partition(" ")
        try:
            at = parse_docker_timestamp(stamp)
        except ValueError:
            continue
        if not since <= at < until:
            continue
        access = _ACCESS.search(rest)
        if access:
            _count(scan["http"], scan["http_first"], access.group(1), at)
            continue
        if rest.startswith("{"):
            try:
                level = str(json.loads(rest).get("level", "")).upper()
            except (ValueError, AttributeError):
                level = ""
            if level in _JSON_LEVELS:
                _count(scan["levels"], scan["levels_first"], level, at)
            continue
        postgres = _POSTGRES_LEVEL.search(rest)
        if postgres:
            level = postgres.group(1)
            _count(scan["levels"], scan["levels_first"], level, at)
            if level != "WARNING":
                _count(scan["pg"], scan["pg_first"], _postgres_class(postgres.group(2)), at)
            continue
        plain = _PLAIN_LEVEL.match(rest)
        if plain:
            _count(scan["levels"], scan["levels_first"], plain.group(1), at)
    return scan


REDIS_FIELDS = (
    "connected_clients",
    "blocked_clients",
    "maxclients",
    "used_memory",
    "maxmemory",
    "instantaneous_ops_per_sec",
    "total_commands_processed",
    "rejected_connections",
    "evicted_keys",
)


def parse_redis_info(text: str) -> dict[str, str]:
    info = {}
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and ":" in line:
            key, _, value = line.partition(":")
            info[key] = value
    return info


def redis_fields(info: dict[str, Any]) -> dict[str, int | None]:
    return {field: _number(str(info[field]), int) if field in info else None for field in REDIS_FIELDS}


def redis_info_fields(text: str) -> dict[str, int | None]:
    """The sampled fields of `redis-cli INFO`, which exits 0 even when the
    server refuses it."""
    info = parse_redis_info(text)
    if "redis_version" not in info:
        raise ProbeFailed("redis-cli INFO returned no INFO")
    return redis_fields(info)


# Runs inside the aweb container with that image's Python and redis client.
# It reads the URL from the file aweb itself is given and prints only counters,
# or the name of the exception that stopped it.
AWEB_REDIS_SCRIPT = f"""\
import json, os, redis
fields = {REDIS_FIELDS!r}
path = os.environ.get("AWEB_REDIS_URL_FILE") or "/run/secrets/aweb/redis-url"
try:
    with open(path) as handle:
        client = redis.Redis.from_url(handle.read().strip(), socket_timeout=3)
    info = client.info()
    print(json.dumps({{field: info.get(field) for field in fields}}))
except Exception as exc:
    print(json.dumps({{"error": type(exc).__name__}}))
"""

POSTGRES_SQL = """\
SELECT json_build_object(
  'max_connections', current_setting('max_connections')::int,
  'preload', current_setting('shared_preload_libraries'),
  'databases', (
    SELECT coalesce(json_agg(json_build_object(
      'datname', d.datname,
      'numbackends', s.numbackends,
      'xact_commit', s.xact_commit,
      'xact_rollback', s.xact_rollback,
      'deadlocks', s.deadlocks,
      'active', (SELECT count(*) FROM pg_stat_activity a
                 WHERE a.datid = d.oid AND a.state = 'active' AND a.pid <> pg_backend_pid()),
      'idle_in_transaction', (SELECT count(*) FROM pg_stat_activity a
                 WHERE a.datid = d.oid AND a.state LIKE 'idle in transaction%'),
      'waiting_on_lock', (SELECT count(*) FROM pg_stat_activity a
                 WHERE a.datid = d.oid AND a.wait_event_type = 'Lock'),
      'ungranted_locks', (SELECT count(*) FROM pg_locks l WHERE l.database = d.oid AND NOT l.granted),
      'longest_lock_wait_seconds', (SELECT coalesce(max(extract(epoch FROM now() - a.state_change)), 0)
                 FROM pg_stat_activity a WHERE a.datid = d.oid AND a.wait_event_type = 'Lock')
    ) ORDER BY d.datname), '[]'::json)
    FROM pg_database d JOIN pg_stat_database s ON s.datid = d.oid
    WHERE NOT d.datistemplate
  )
);
"""

POSTGRES_HAS_STATEMENTS_SQL = "SELECT count(*) FROM pg_extension WHERE extname = 'pg_stat_statements';\n"

# Every statement's counters, and no text: comments survive normalisation,
# constants can remain, and a utility statement is kept as written, so no text
# leaves the database. pg_stat_statements(false) does not read the text file.
# dealloc counts entries evicted since the statistics were last reset.
POSTGRES_STATEMENTS_SQL = """\
SELECT json_build_object(
  'dealloc', (SELECT dealloc FROM pg_stat_statements_info),
  'rows', (
    SELECT coalesce(json_agg(json_build_array(
      s.userid, d.datname, s.queryid, s.toplevel, s.calls, s.total_exec_time, s.rows)), '[]'::json)
    FROM pg_stat_statements(false) s JOIN pg_database d ON d.oid = s.dbid
  )
);
"""
STATEMENTS_PER_TICK = 10

Snapshot = dict[tuple, tuple[int, float, int]]


def statement_snapshot(rows: list[list[Any]]) -> Snapshot:
    """pg_stat_statements rows keyed by (user, database, query, top level)."""
    return {(userid, datname, queryid, toplevel): (calls, exec_ms, n_rows)
            for userid, datname, queryid, toplevel, calls, exec_ms, n_rows in rows}


def statement_deltas(previous: Snapshot | None, current: Snapshot, limit: int = STATEMENTS_PER_TICK) -> dict:
    """What each statement did since the previous tick: the `limit` with the
    most execution time, by database and query ID, and the rest summed as
    other. An entry absent before is new in the view since then, so it counts
    from zero; an entry gone is evicted, and what it did before leaving is lost.
    The first snapshot is only a baseline."""
    if previous is None:
        return {"baseline": True}
    by_query: dict[tuple[str, int], list[float]] = {}
    new_entries = 0
    for key, (calls, exec_ms, n_rows) in current.items():
        before = previous.get(key)
        if before is None:
            new_entries += 1
            before = (0, 0.0, 0)
        if calls < before[0]:
            before = (0, 0.0, 0)
        totals = by_query.setdefault((key[1], key[2]), [0, 0.0, 0])
        totals[0] += calls - before[0]
        totals[1] += exec_ms - before[1]
        totals[2] += n_rows - before[2]
    active = sorted(((query, t) for query, t in by_query.items() if t[0] > 0 or t[1] > 0),
                    key=lambda item: item[1][1], reverse=True)
    rest = active[limit:]
    return {
        "top": [{"datname": datname, "queryid": queryid, "calls": t[0], "exec_ms": t[1], "rows": t[2]}
                for (datname, queryid), t in active[:limit]],
        "other": {"calls": sum(t[0] for _, t in rest), "exec_ms": sum(t[1] for _, t in rest),
                  "rows": sum(t[2] for _, t in rest)},
        "new_entries": new_entries,
        "evicted_entries": sum(1 for key in previous if key not in current),
    }


def next_slot(*, elapsed: float, interval: float, slot: int) -> tuple[int, list[int]]:
    """The schedule slot to wait for after slot `slot` finished at `elapsed`
    seconds, and the slots that passed while it ran."""
    following = int(elapsed // interval) + 1
    return following, list(range(slot + 1, following))


def postgres_sample(query_json: str) -> dict[str, Any]:
    result = json.loads(query_json)
    preload = [name.strip() for name in str(result.get("preload") or "").split(",")]
    return {
        "max_connections": result["max_connections"],
        "statements_available": "pg_stat_statements" in preload,
        "databases": result["databases"],
    }


class ProbeFailed(Exception):
    """A probe that returned no usable output; its message is safe to record."""


def _run(argv: list[str], stdin: str | None = None) -> str:
    try:
        done = subprocess.run(
            argv, input=stdin, capture_output=True, text=True, timeout=COMMAND_TIMEOUT_SECONDS, check=False,
        )
    except subprocess.TimeoutExpired:
        raise ProbeFailed(f"timed out after {COMMAND_TIMEOUT_SECONDS}s") from None
    if done.returncode != 0:
        lines = (done.stderr or done.stdout).strip().splitlines() or [""]
        raise ProbeFailed(f"exit {done.returncode}: {lines[-1][:ERROR_TEXT_LIMIT]}")
    return done.stdout


class Collector:
    def __init__(self, args: argparse.Namespace, out: Any) -> None:
        self.args = args
        self.out = out
        self.lock = threading.Lock()
        self.logs_until = time.time()
        self.statements_database: dict[str, str | None] = {}
        self.statement_snapshots: dict[str, Snapshot] = {}

    def write(self, record: dict[str, Any]) -> None:
        line = json.dumps(record, sort_keys=True)
        with self.lock:
            self.out.write(line + "\n")
            self.out.flush()

    def error(self, probe: str, service: str | None, failure: Exception) -> None:
        self.write({"t": time.time(), "kind": "probe_error", "probe": probe, "service": service,
                    "error": str(failure) if isinstance(failure, ProbeFailed) else type(failure).__name__})

    def containers(self) -> dict[str, dict[str, str]]:
        """The project's running containers by service."""
        listing = _run([
            "docker", "ps", "--filter", f"label=com.docker.compose.project={self.args.project}",
            "--format", '{{.ID}}\t{{.Names}}\t{{.Label "com.docker.compose.service"}}',
        ])
        found = {}
        for line in listing.splitlines():
            ident, name, service = line.split("\t")
            found[service] = {"id": ident, "name": name}
        return found

    def meta(self, schedule_start: float) -> None:
        ncpu, memory = _run(["docker", "info", "--format", "{{.NCPU}}\t{{.MemTotal}}"]).strip().split("\t")
        self.write({"t": time.time(), "kind": "meta", "project": self.args.project,
                    "schedule_start": schedule_start, "interval_seconds": self.args.interval,
                    "host_ncpu": int(ncpu), "host_mem_bytes": int(memory),
                    "services": {
                        "aweb": self.args.aweb_service, "redis": self.args.redis_service,
                        "postgres": self.args.postgres_service,
                        "registry_db": self.args.registry_db_service,
                        "registry_redis": self.args.registry_redis_service,
                    }})

    def probe_containers(self, found: dict[str, dict[str, str]]) -> None:
        by_name = {c["name"]: service for service, c in found.items()}
        ids = [c["id"] for c in found.values()]
        stats = _run(["docker", "stats", "--no-stream", "--format", "{{json .}}", *ids])
        inspect = _run(["docker", "inspect", "--format",
                        "{{.Name}}\t{{.RestartCount}}\t{{.State.OOMKilled}}\t{{.HostConfig.NanoCpus}}", *ids])
        state = {}
        for line in inspect.splitlines():
            name, restarts, oom, nano_cpus = line.split("\t")
            state[name.lstrip("/")] = {"restart_count": int(restarts), "oom_killed": oom == "true",
                                       "cpu_limit": int(nano_cpus) / 1e9 if int(nano_cpus) else None}
        at = time.time()
        for line in stats.splitlines():
            sample = container_sample(line)
            self.write({"t": at, "kind": "container", "service": by_name.get(sample["name"]),
                        **sample, **state.get(sample["name"], {})})

    def probe_postgres(self, service: str, container: dict[str, str]) -> None:
        psql = ["docker", "exec", "-i", container["id"], "psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1",
                "-U", "postgres"]
        sample = postgres_sample(_run([*psql, "-d", "postgres"], POSTGRES_SQL))
        record = {"t": time.time(), "kind": "postgres", "service": service, **sample}
        if sample["statements_available"]:
            if service not in self.statements_database:
                self.statements_database[service] = next(
                    (d["datname"] for d in sample["databases"]
                     if _run([*psql, "-d", d["datname"]], POSTGRES_HAS_STATEMENTS_SQL).strip() != "0"),
                    None,
                )
            database = self.statements_database[service]
            if database:
                result = json.loads(_run([*psql, "-d", database], POSTGRES_STATEMENTS_SQL))
                current = statement_snapshot(result["rows"])
                record["statements"] = {**statement_deltas(self.statement_snapshots.get(service), current),
                                        "dealloc": result["dealloc"]}
                self.statement_snapshots[service] = current
        self.write(record)

    def probe_aweb_redis(self, container: dict[str, str]) -> None:
        """aweb's Redis, read through the aweb container that holds its URL."""
        result = json.loads(_run(["docker", "exec", "-i", container["id"], "python", "-"], AWEB_REDIS_SCRIPT))
        if "error" in result:
            raise ProbeFailed(f"redis client: {result['error']}")
        self.write({"t": time.time(), "kind": "redis", "service": self.args.redis_service, **redis_fields(result)})

    def probe_registry_redis(self, service: str, container: dict[str, str]) -> None:
        fields = redis_info_fields(_run(["docker", "exec", container["id"], "redis-cli", "INFO"]))
        self.write({"t": time.time(), "kind": "redis", "service": service, **fields})

    def probe_logs(self, service: str, container: dict[str, str], since: float, until: float) -> None:
        # Docker's own bounds are widened by a second; scan_log keeps [since, until).
        text = subprocess.run(
            ["docker", "logs", "--timestamps", "--since", f"{since - 1:.3f}", "--until", f"{until + 1:.3f}",
             container["id"]],
            capture_output=True, text=True, timeout=COMMAND_TIMEOUT_SECONDS, check=False,
        )
        if text.returncode != 0:
            raise ProbeFailed(f"exit {text.returncode}: docker logs")
        scan = scan_log(text.stdout + text.stderr, since=since, until=until)
        self.write({"t": until, "kind": "log", "service": service, "since": since, "until": until, **scan})

    def tick(self, pool: ThreadPoolExecutor, slot: int | None, scheduled_t: float | None) -> None:
        """One sample of everything, closed by a tick record naming each probe's
        outcome. A final tick at shutdown has no slot."""
        outcomes: dict[str, str] = {}
        try:
            self.sample_all(pool, outcomes)
        finally:
            self.write({"t": time.time(), "kind": "tick", "slot": slot, "scheduled_t": scheduled_t,
                        "probes": outcomes})

    def sample_all(self, pool: ThreadPoolExecutor, outcomes: dict[str, str]) -> None:
        try:
            found = self.containers()
        except Exception as failure:  # noqa: BLE001 - recorded, and the next tick retries
            self.error("containers", None, failure)
            outcomes["containers"] = "failed"
            return
        if not found:
            # Without IDs, docker stats would sample every container on the host.
            self.error("containers", None, ProbeFailed(f"no running container in project {self.args.project}"))
            outcomes["containers"] = "failed"
            return
        since, until = self.logs_until, time.time()
        self.logs_until = until
        jobs: list[tuple[str, str | None, Callable[[], None]]] = [
            ("containers", None, lambda: self.probe_containers(found)),
        ]
        for service in (self.args.postgres_service, self.args.registry_db_service):
            if service in found:
                jobs.append(("postgres", service, lambda s=service: self.probe_postgres(s, found[s])))
        if self.args.aweb_service in found:
            jobs.append(("redis", self.args.redis_service,
                         lambda: self.probe_aweb_redis(found[self.args.aweb_service])))
        registry_redis = self.args.registry_redis_service
        if registry_redis in found:
            jobs.append(("redis", registry_redis,
                         lambda: self.probe_registry_redis(registry_redis, found[registry_redis])))
        for service, container in found.items():
            jobs.append(("logs", service, lambda s=service, c=container: self.probe_logs(s, c, since, until)))

        def run(job: tuple[str, str | None, Callable[[], None]]) -> None:
            probe, service, call = job
            key = probe if service is None else f"{probe}:{service}"
            try:
                call()
                outcomes[key] = "ok"
            except Exception as failure:  # noqa: BLE001 - recorded, and the next tick retries
                self.error(probe, service, failure)
                outcomes[key] = "failed"

        list(pool.map(run, jobs))


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--project", required=True, help="the Compose project name, for example teamcompose")
    parser.add_argument("--out", required=True, type=Path, help="JSONL file to append samples to")
    parser.add_argument("--interval", type=float, default=5.0, help="seconds between samples (default 5)")
    parser.add_argument("--duration", type=float, help="stop after this many seconds (default: at SIGINT/SIGTERM)")
    parser.add_argument("--aweb-service", default="aweb")
    parser.add_argument("--redis-service", default="redis", help="aweb's Redis, read through the aweb container")
    parser.add_argument("--postgres-service", default="postgres")
    parser.add_argument("--registry-db-service", default="registry-db")
    parser.add_argument("--registry-redis-service", default="registry-redis")
    args = parser.parse_args(argv)

    stop = threading.Event()
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, lambda *_: stop.set())
    with args.out.open("a", encoding="utf-8") as out, ThreadPoolExecutor(max_workers=16) as pool:
        collector = Collector(args, out)
        started, schedule_start = time.monotonic(), time.time()
        collector.meta(schedule_start)
        slot = 0
        while not stop.is_set():
            collector.tick(pool, slot, schedule_start + slot * args.interval)
            elapsed = time.monotonic() - started
            # Slots stay on the fixed schedule: a slow tick skips the slots it
            # overran, and says so, rather than bunching them.
            slot, skipped = next_slot(elapsed=elapsed, interval=args.interval, slot=slot)
            for missed in skipped:
                collector.write({"t": time.time(), "kind": "tick_skipped", "slot": missed,
                                 "scheduled_t": schedule_start + missed * args.interval})
            if args.duration is not None and slot * args.interval > args.duration:
                break
            stop.wait(slot * args.interval - elapsed)
        if stop.is_set():
            collector.tick(pool, None, None)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
