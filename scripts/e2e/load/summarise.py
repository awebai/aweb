#!/usr/bin/env python3
"""Turns collect.py's samples and the driver's step marks into one table per
step, per service. See README.md.

It reports what was observed and when; it names no cause. First signals lists,
in time order, the first moment in the step each service showed a limit-shaped
symptom, for whoever reads the report to correlate.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

NEAR_LIMIT = 0.9
ERROR_LEVELS = ("ERROR", "CRITICAL", "FATAL", "PANIC")
TOP_STATEMENTS = 5


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def step_windows(marks: list[dict[str, Any]], samples: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One window per step_start, closed by its step_end. A step the driver
    never ended (it stopped, or the next step began) is open: it runs to the
    next step's start or to the last sample."""
    last_sample = max((s["t"] for s in samples), default=0.0)
    windows: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for mark in sorted(marks, key=lambda m: m["t"]):
        if mark["event"] == "step_start":
            if current is not None:
                windows.append({**current, "end": mark["t"], "open": True})
            current = {"seats": mark["seats"], "start": mark["t"]}
        elif mark["event"] == "step_end" and current is not None and mark["seats"] == current["seats"]:
            windows.append({**current, "end": mark["t"], "open": False})
            current = None
    if current is not None:
        windows.append({**current, "end": last_sample, "open": True})
    return windows


def counter_delta(values: list[Any]) -> float | None:
    """The growth of a cumulative counter over consecutive points; a drop is a
    restart, after which the counter counts from zero."""
    if len(values) < 2 or any(v is None for v in values):
        return None
    return sum(b - a if b >= a else b for a, b in zip(values, values[1:]))


def _series(samples: list[dict[str, Any]], kind: str, start: float, end: float) -> dict[str, list[dict]]:
    """Per service: the last sample before the window, then the samples in it."""
    by_service: dict[str, list[dict]] = {}
    for sample in samples:
        if sample["kind"] == kind and sample["t"] <= end:
            by_service.setdefault(sample.get("service") or "?", []).append(sample)
    series = {}
    for service, points in by_service.items():
        points.sort(key=lambda s: s["t"])
        before = [p for p in points if p["t"] < start][-1:]
        inside = [p for p in points if p["t"] >= start]
        if inside:
            series[service] = before + inside
    return series


def _inside(points: list[dict], start: float) -> list[dict]:
    return [p for p in points if p["t"] >= start]


def _max(values: Iterable[Any]) -> Any:
    present = [v for v in values if v is not None]
    return max(present) if present else None


def _rate(points: list[dict], value) -> float | None:
    delta = counter_delta([value(p) for p in points])
    span = points[-1]["t"] - points[0]["t"]
    return None if delta is None or span <= 0 else delta / span


def _containers(series: dict[str, list[dict]], start: float) -> dict[str, dict]:
    out = {}
    for service, points in series.items():
        inside = _inside(points, start)
        cpu = [p["cpu_percent"] for p in inside if p["cpu_percent"] is not None]
        out[service] = {
            "cpu_percent_mean": sum(cpu) / len(cpu) if cpu else None,
            "cpu_percent_max": max(cpu) if cpu else None,
            "cpu_limit": inside[-1].get("cpu_limit"),
            "mem_bytes_max": _max(p["mem_bytes"] for p in inside),
            "mem_limit_bytes": inside[-1]["mem_limit_bytes"],
            **{field: counter_delta([p[field] for p in points]) for field in
               ("net_rx_bytes", "net_tx_bytes", "block_read_bytes", "block_write_bytes")},
            "restarts": counter_delta([p.get("restart_count") for p in points]) or 0,
            "oom_killed": any(p.get("oom_killed") for p in inside),
        }
    return out


def _statements(points: list[dict]) -> list[dict]:
    """Execution time and calls in the window, for the statements present in
    its first and last top-ten lists."""
    lists = [p["statements"] for p in points if "statements" in p]
    if len(lists) < 2:
        return []
    first = {(s["datname"], s["queryid"]): s for s in lists[0]}
    ranked = []
    for statement in lists[-1]:
        earlier = first.get((statement["datname"], statement["queryid"]))
        if earlier is None:
            continue
        calls = statement["calls"] - earlier["calls"]
        if calls > 0:
            exec_ms = statement["total_exec_time"] - earlier["total_exec_time"]
            ranked.append({"datname": statement["datname"], "calls": calls, "exec_ms": exec_ms,
                           "mean_ms": exec_ms / calls, "query": " ".join(statement["query"].split())})
    return sorted(ranked, key=lambda s: s["exec_ms"], reverse=True)[:TOP_STATEMENTS]


def _postgres(series: dict[str, list[dict]], start: float) -> dict[str, dict]:
    out = {}
    for service, points in series.items():
        inside = _inside(points, start)
        names = sorted({d["datname"] for p in inside for d in p["databases"]})

        def database(point: dict, name: str) -> dict:
            return next((d for d in point["databases"] if d["datname"] == name), {})

        databases = {}
        for name in names:
            rows = [database(p, name) for p in inside]
            databases[name] = {
                "connections_max": _max(r.get("numbackends") for r in rows),
                "active_max": _max(r.get("active") for r in rows),
                "idle_in_transaction_max": _max(r.get("idle_in_transaction") for r in rows),
                "waiting_on_lock_max": _max(r.get("waiting_on_lock") for r in rows),
                "ungranted_locks_max": _max(r.get("ungranted_locks") for r in rows),
                "longest_lock_wait_seconds": _max(r.get("longest_lock_wait_seconds") for r in rows),
                "transactions_per_second": _rate(
                    points, lambda p, n=name: _sum_or_none(database(p, n), "xact_commit", "xact_rollback")),
                "deadlocks": counter_delta([database(p, name).get("deadlocks") for p in points]),
            }
        out[service] = {
            "max_connections": inside[-1]["max_connections"],
            "connections_max": _max(sum(d["numbackends"] for d in p["databases"]) for p in inside),
            "databases": databases,
            "statements": _statements(points),
        }
    return out


def _sum_or_none(row: dict, *fields: str) -> int | None:
    values = [row.get(field) for field in fields]
    present = [v for v in values if v is not None]
    return sum(present) if len(present) == len(values) else None


def _redis(series: dict[str, list[dict]], start: float) -> dict[str, dict]:
    out = {}
    for service, points in series.items():
        inside = _inside(points, start)
        out[service] = {
            "connected_clients_max": _max(p["connected_clients"] for p in inside),
            "maxclients": inside[-1]["maxclients"],
            "blocked_clients_max": _max(p["blocked_clients"] for p in inside),
            "commands_per_second": _rate(points, lambda p: p["total_commands_processed"]),
            "used_memory_max": _max(p["used_memory"] for p in inside),
            "maxmemory": inside[-1]["maxmemory"],
            "rejected_connections": counter_delta([p["rejected_connections"] for p in points]),
            "evicted_keys": counter_delta([p["evicted_keys"] for p in points]),
        }
    return out


def _in_step(second: str, start: float, end: float) -> bool:
    return math.floor(start) <= int(second) < end


def _first_in_step(records: list[dict], field: str, key: str, start: float, end: float) -> float | None:
    """The first time of key in the step: exact when its record began in the
    step, else the first whole second the record counted it in the step."""
    for record in sorted(records, key=lambda r: r["since"]):
        first = record[f"{field}_first"].get(key)
        if first is not None and start <= first < end:
            return first
        seconds = [int(s) for s in record[field].get(key, {}) if _in_step(s, start, end)]
        if seconds:
            return max(start, float(min(seconds)))
    return None


def _logs(samples: list[dict], start: float, end: float) -> tuple[dict[str, dict], dict[str, dict]]:
    records: dict[str, list[dict]] = {}
    for sample in samples:
        if sample["kind"] == "log" and sample["until"] > start and sample["since"] < end:
            records.setdefault(sample["service"], []).append(sample)
    http, logs = {}, {}
    for service, scans in records.items():
        counts: dict[str, dict[str, int]] = {"http": {}, "levels": {}, "pg": {}}
        per_minute: dict[str, dict[str, int]] = {}
        for scan in scans:
            for field in counts:
                for key, by_second in scan[field].items():
                    for second, n in by_second.items():
                        if not _in_step(second, start, end):
                            continue
                        counts[field][key] = counts[field].get(key, 0) + n
                        if field == "http" and (key == "429" or key.startswith("5")):
                            minute = str(max(0, int((int(second) - start) // 60)))
                            bucket = per_minute.setdefault(minute, {})
                            bucket[key] = bucket.get(key, 0) + n
        if counts["http"]:
            http[service] = {
                "counts": counts["http"],
                "per_minute": per_minute,
                "first": {key: _first_in_step(scans, "http", key, start, end) for key in counts["http"]
                          if key == "429" or key.startswith("5")},
            }
        if counts["levels"] or counts["pg"]:
            logs[service] = {
                "levels": counts["levels"],
                "pg": counts["pg"],
                "first": {
                    **{key: _first_in_step(scans, "levels", key, start, end) for key in counts["levels"]},
                    **{f"pg {key}": _first_in_step(scans, "pg", key, start, end) for key in counts["pg"]},
                },
            }
    return http, logs


def _first_signals(samples: list[dict], series: dict[str, dict], http: dict, logs: dict, start: float,
                   end: float, host_ncpu: int | None) -> list[dict]:
    signals: list[tuple[float, str, str]] = []

    def first(points: Iterable[dict], test, service: str, signal: str, when=lambda p: p["t"]) -> None:
        previous = None
        for point in points:
            if point["t"] >= start and test(point, previous):
                signals.append((max(start, when(point)), service, signal))
                return
            previous = point

    for service, entry in http.items():
        if entry["first"].get("429") is not None:
            signals.append((entry["first"]["429"], service, "http 429"))
        fives = [t for key, t in entry["first"].items() if key.startswith("5") and t is not None]
        if fives:
            signals.append((min(fives), service, "http 5xx"))
    for service, entry in logs.items():
        for key, t in entry["first"].items():
            if t is not None and (key in ERROR_LEVELS or (key.startswith("pg ") and key != "pg other")):
                signals.append((t, service, key))

    def grew(field: str):
        return lambda p, prev: prev is not None and (p.get(field) or 0) > (prev.get(field) or 0)

    for service, points in series["container"].items():
        first(points, grew("restart_count"), service, "restart")
        first(points, lambda p, _: p.get("oom_killed"), service, "OOM killed")
        cores: float | None = points[-1].get("cpu_limit") or host_ncpu
        if cores:
            ceiling = NEAR_LIMIT * cores * 100
            first(points, lambda p, _: (p["cpu_percent"] or 0) >= ceiling, service,
                  f"CPU >= {NEAR_LIMIT:.0%} of {cores:g} cores")
    for service, points in series["postgres"].items():
        first(points, lambda p, _: sum(d["numbackends"] for d in p["databases"]) >= NEAR_LIMIT * p["max_connections"],
              service, f"connections >= {NEAR_LIMIT:.0%} of max_connections")
        for name in sorted({d["datname"] for p in points for d in p["databases"]}):
            def waiting(p, _, n=name):
                return any(d["datname"] == n and d["waiting_on_lock"] for d in p["databases"])

            def began(p, n=name):
                row = next(d for d in p["databases"] if d["datname"] == n)
                return p["t"] - row["longest_lock_wait_seconds"]

            first(points, waiting, f"{service}/{name}", "lock wait", when=began)
    for service, points in series["redis"].items():
        first(points, lambda p, _: p["blocked_clients"], service, "blocked clients")
        first(points, grew("rejected_connections"), service, "rejected connections")
        first(points, grew("evicted_keys"), service, "evictions")
        first(points, lambda p, _: p["maxclients"] and p["connected_clients"] >= NEAR_LIMIT * p["maxclients"],
              service, f"clients >= {NEAR_LIMIT:.0%} of maxclients")
        first(points, lambda p, _: p["maxmemory"] and p["used_memory"] >= NEAR_LIMIT * p["maxmemory"],
              service, f"memory >= {NEAR_LIMIT:.0%} of maxmemory")
    for sample in samples:
        if sample["kind"] == "probe_error" and start <= sample["t"] < end:
            signals.append((sample["t"], sample.get("service") or "collector", f"probe failed: {sample['probe']}"))

    seen = set()
    ordered = []
    for t, service, signal in sorted(s for s in signals if start <= s[0] < end):
        if (service, signal) not in seen:
            seen.add((service, signal))
            ordered.append({"t": t, "offset_seconds": t - start, "service": service, "signal": signal})
    return ordered


def summarise(samples: list[dict[str, Any]], window: dict[str, Any]) -> dict[str, Any]:
    start, end = window["start"], window["end"]
    meta = next((s for s in samples if s["kind"] == "meta"), {})
    series = {kind: _series(samples, kind, start, end) for kind in ("container", "postgres", "redis")}
    http, logs = _logs(samples, start, end)
    return {
        **window,
        "duration_seconds": end - start,
        "host_ncpu": meta.get("host_ncpu"),
        "containers": _containers(series["container"], start),
        "postgres": _postgres(series["postgres"], start),
        "redis": _redis(series["redis"], start),
        "http": http,
        "logs": logs,
        "first_signals": _first_signals(samples, series, http, logs, start, end, meta.get("host_ncpu")),
    }


def _bytes(value: Any) -> str:
    if value is None:
        return "-"
    for unit in ("B", "KiB", "MiB", "GiB"):
        if abs(value) < 1024 or unit == "GiB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return "-"


def _num(value: Any, digits: int = 1) -> str:
    if value is None:
        return "-"
    return f"{value:.{digits}f}" if isinstance(value, float) else str(value)


def _clock(t: float) -> str:
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"


def _table(header: list[str], rows: list[list[str]]) -> list[str]:
    return ["| " + " | ".join(header) + " |", "|" + "---|" * len(header),
            *("| " + " | ".join(row) + " |" for row in rows), ""]


def render(step: dict[str, Any]) -> str:
    start = step["start"]
    lines = [f"## Step {step['seats']} seats", "",
             f"{_clock(start)} to {_clock(step['end'])}, {step['duration_seconds']:.1f} s"
             + (" (open: the driver did not mark this step's end)" if step["open"] else "")
             + (f"; host has {step['host_ncpu']} CPUs" if step.get("host_ncpu") else ""), ""]

    lines += ["### Containers", ""] + _table(
        ["service", "CPU % mean", "CPU % max", "CPU limit", "mem max", "net rx", "net tx", "block read",
         "block write", "restarts", "OOM"],
        [[s, _num(c["cpu_percent_mean"]), _num(c["cpu_percent_max"]), _num(c["cpu_limit"]), _bytes(c["mem_bytes_max"]),
          _bytes(c["net_rx_bytes"]), _bytes(c["net_tx_bytes"]), _bytes(c["block_read_bytes"]),
          _bytes(c["block_write_bytes"]), _num(c["restarts"]), "yes" if c["oom_killed"] else ""]
         for s, c in sorted(step["containers"].items())])

    lines += ["### PostgreSQL", ""]
    rows = []
    for service, pg in sorted(step["postgres"].items()):
        rows.append([service, "(all)", f"{pg['connections_max']} of {pg['max_connections']}", "", "", "", "", "", ""])
        for name, d in sorted(pg["databases"].items()):
            rows.append([service, name, _num(d["connections_max"]), _num(d["active_max"]),
                         _num(d["idle_in_transaction_max"]), _num(d["waiting_on_lock_max"]),
                         _num(d["ungranted_locks_max"]), _num(d["longest_lock_wait_seconds"]),
                         _num(d["transactions_per_second"])])
    lines += _table(["service", "database", "connections max", "active max", "idle in tx max", "waiting on lock max",
                     "ungranted locks max", "longest lock wait s", "tx/s"], rows)
    for service, pg in sorted(step["postgres"].items()):
        if pg["statements"]:
            lines += [f"Top statements by time in the step, {service}:", ""] + _table(
                ["database", "calls", "time ms", "mean ms", "statement"],
                [[s["datname"], str(s["calls"]), _num(s["exec_ms"]), _num(s["mean_ms"], 2),
                  "`" + s["query"][:100].replace("|", "\\|").replace("`", "'") + "`"] for s in pg["statements"]])

    lines += ["### Redis", ""] + _table(
        ["service", "clients max", "maxclients", "blocked max", "commands/s", "memory max", "maxmemory", "rejected",
         "evicted"],
        [[s, _num(r["connected_clients_max"]), _num(r["maxclients"]), _num(r["blocked_clients_max"]),
          _num(r["commands_per_second"]), _bytes(r["used_memory_max"]),
          _bytes(r["maxmemory"]) if r["maxmemory"] else "none", _num(r["rejected_connections"]),
          _num(r["evicted_keys"])]
         for s, r in sorted(step["redis"].items())])

    def by_class(counts: dict[str, int], test) -> int:
        return sum(n for status, n in counts.items() if test(status))

    def offset(t: float | None) -> str:
        return "-" if t is None else f"+{t - start:.1f} s"

    lines += ["### HTTP", "", "From access logs; Secrets and the TLS front write none.", ""] + _table(
        ["service", "2xx", "3xx", "4xx other", "429", "5xx", "first 429", "first 5xx"],
        [[s, str(by_class(h["counts"], lambda c: c.startswith("2"))),
          str(by_class(h["counts"], lambda c: c.startswith("3"))),
          str(by_class(h["counts"], lambda c: c.startswith("4") and c != "429")),
          str(h["counts"].get("429", 0)), str(by_class(h["counts"], lambda c: c.startswith("5"))),
          offset(h["first"].get("429")),
          offset(min((t for k, t in h["first"].items() if k.startswith("5") and t is not None), default=None))]
         for s, h in sorted(step["http"].items())])
    minute_rows = [[s, minute, str(counts.get("429", 0)), str(by_class(counts, lambda c: c.startswith("5")))]
                   for s, h in sorted(step["http"].items()) for minute, counts in sorted(
                       h["per_minute"].items(), key=lambda item: int(item[0]))]
    if minute_rows:
        lines += ["Per minute of the step:", ""] + _table(["service", "minute", "429", "5xx"], minute_rows)

    if step["logs"]:
        lines += ["### Log errors", ""] + _table(
            ["service", "levels", "PostgreSQL classes"],
            [[s, ", ".join(f"{k} {n}" for k, n in sorted(entry["levels"].items())) or "-",
              ", ".join(f"{k} {n}" for k, n in sorted(entry["pg"].items())) or "-"]
             for s, entry in sorted(step["logs"].items())])

    lines += ["### First signals", ""]
    lines += [f"{i}. {offset(s['t'])} {s['service']}: {s['signal']}" for i, s in enumerate(step["first_signals"], 1)]
    if not step["first_signals"]:
        lines.append("None observed.")
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> str:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--samples", required=True, type=Path, help="collect.py's JSONL")
    parser.add_argument("--marks", required=True, type=Path, help="the driver's mark file")
    parser.add_argument("--seats", type=int, help="only the step with this many seats")
    parser.add_argument("--json", action="store_true", help="print JSON rather than Markdown")
    args = parser.parse_args(argv)
    samples = load_jsonl(args.samples)
    windows = [w for w in step_windows(load_jsonl(args.marks), samples)
               if args.seats is None or w["seats"] == args.seats]
    steps = [summarise(samples, window) for window in windows]
    if args.json:
        return json.dumps(steps, indent=2, sort_keys=True)
    return "\n".join(render(step) for step in steps)


if __name__ == "__main__":
    print(main(sys.argv[1:]), end="")
