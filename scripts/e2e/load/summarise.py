#!/usr/bin/env python3
"""Turns collect.py's samples and the driver's step marks into one table per
step, per service. See README.md.

It reports what was observed and when; it names no cause. First signals lists,
in time order, the first moment in the step each service showed a limit-shaped
symptom, for whoever reads the report to correlate. Coverage says how much of
the step was measured, so that a quiet table is never mistaken for a quiet
system.
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
# A stretch longer than this many intervals without a complete sample is a gap.
GAP_INTERVALS = 1.5

# How a first time was established:
# exact      the logged timestamp of the first line in the step
# second     the step's first whole second that counted one
# sample     when a sample first showed it; it began up to one interval earlier
# estimated  derived from a sample (a lock wait's start, from its duration)
PRECISIONS = ("exact", "second", "sample", "estimated")


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def step_windows(marks: list[dict[str, Any]], samples: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One window per step_start, closed by its step_end, which may carry the
    driver's operation totals. A step the driver never ended (it stopped, or
    the next step began) is open: it runs to the next step's start or to the
    last sample, and has no totals."""
    last_sample = max((s["t"] for s in samples), default=0.0)
    windows: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for mark in sorted(marks, key=lambda m: m["t"]):
        if mark["event"] == "step_start":
            if current is not None:
                windows.append({**current, "end": mark["t"], "open": True, "workload": None})
            current = {"seats": mark["seats"], "start": mark["t"]}
        elif mark["event"] == "step_end" and current is not None and mark["seats"] == current["seats"]:
            windows.append({**current, "end": mark["t"], "open": False, "workload": mark.get("operations")})
            current = None
    if current is not None:
        windows.append({**current, "end": max(last_sample, current["start"]), "open": True, "workload": None})
    return windows


def counter_delta(values: list[Any]) -> float | None:
    """The growth of a cumulative counter over consecutive points; a drop is a
    restart, after which the counter counts from zero."""
    if len(values) < 2 or any(v is None for v in values):
        return None
    return sum(b - a if b >= a else b for a, b in zip(values, values[1:]))


def _coverage(samples: list[dict], start: float, end: float) -> dict[str, Any]:
    """How much of the step the collector measured: its schedule's slots in the
    step, which it attempted, completed with every probe, skipped because a tick
    overran, or never reached because it was not running; which probes failed;
    and the stretches without a complete sample."""
    meta = next((s for s in samples if s["kind"] == "meta"), None)
    if meta is None:
        return {"available": False, "complete": False}
    origin, interval = meta["schedule_start"], meta["interval_seconds"]
    # Slot k is due at origin + k * interval; the step expects those due in [start, end).
    first_slot = max(0, math.ceil((start - origin) / interval))
    expected = max(0, math.ceil((end - origin) / interval) - first_slot)
    ticks = [s for s in samples if s["kind"] == "tick" and s.get("scheduled_t") is not None
             and start <= s["scheduled_t"] < end]
    skipped = sum(1 for s in samples if s["kind"] == "tick_skipped" and start <= s["scheduled_t"] < end)
    failed: dict[str, int] = {}
    for tick in ticks:
        for probe, outcome in tick["probes"].items():
            if outcome != "ok":
                failed[probe] = failed.get(probe, 0) + 1

    def whole(tick: dict) -> bool:
        return bool(tick["probes"]) and all(outcome == "ok" for outcome in tick["probes"].values())

    completed = [s["t"] for s in samples if s["kind"] == "tick" and start <= s["t"] <= end and whole(s)]
    edges = [start, *sorted(completed), end]
    gaps = [[a, b] for a, b in zip(edges, edges[1:]) if b - a > GAP_INTERVALS * interval]
    missing = max(0, expected - len(ticks) - skipped)
    return {
        "available": True,
        "interval_seconds": interval,
        "expected": expected,
        "attempted": len(ticks),
        "completed": sum(1 for tick in ticks if whole(tick)),
        "skipped": skipped,
        "missing": missing,
        "failed_probes": failed,
        "gaps": gaps,
        "complete": expected > 0 and missing == 0 and skipped == 0 and not failed and not gaps,
    }


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


def _statements(points: list[dict], start: float) -> dict[str, Any] | None:
    """The step's statements by execution time, from the collector's per-tick
    deltas. A statement's time counts only in the ticks where it was among that
    tick's slowest; the rest of each tick is under other. Partial names what
    the ranking cannot include. None when pg_stat_statements is not in use."""
    inside = _inside(points, start)
    if not any(p.get("statements_available") for p in inside):
        return None
    sums: dict[tuple[str, int], list[float]] = {}
    other = 0.0
    partial = []
    baseline = missing = evicted = 0
    deallocs = []
    for point in inside:
        deltas = point.get("statements")
        if deltas is None:
            missing += 1
            continue
        deallocs.append(deltas.get("dealloc"))
        if deltas.get("baseline"):
            baseline += 1
            continue
        evicted += deltas.get("evicted_entries", 0)
        other += deltas["other"]["exec_ms"]
        for entry in deltas["top"]:
            totals = sums.setdefault((entry["datname"], entry["queryid"]), [0, 0.0])
            totals[0] += entry["calls"]
            totals[1] += entry["exec_ms"]
    if baseline:
        partial.append("the collector's baseline reading fell in the step: the time before it is not counted")
    dealloc_growth = counter_delta(deallocs) if len(deallocs) > 1 else None
    if evicted or dealloc_growth:
        partial.append(f"{max(evicted, int(dealloc_growth or 0))} entries were evicted from pg_stat_statements "
                       "in the step: their time before eviction is lost")
    if missing:
        partial.append(f"{missing} readings in the step had no statements")
    ranked = sorted(sums.items(), key=lambda item: item[1][1], reverse=True)
    shown = [{"datname": datname, "queryid": queryid, "calls": int(calls), "exec_ms": exec_ms,
              "mean_ms": exec_ms / calls if calls else None}
             for (datname, queryid), (calls, exec_ms) in ranked[:TOP_STATEMENTS]]
    rest = sum(exec_ms for _, (_, exec_ms) in ranked[TOP_STATEMENTS:])
    return {
        "ranked": shown,
        "other_exec_ms": other + rest,
        "total_exec_ms": other + sum(exec_ms for _, (_, exec_ms) in ranked),
        "partial": partial,
    }


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
            "statements": _statements(points, start),
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


def first_in_step(records: list[dict], field: str, key: str, start: float, end: float) -> dict[str, Any] | None:
    """The first time key was logged in the step. It is exact when the first
    record that counted it in the step logged it no earlier than the step's
    start; when that record began before the step, it is the step's first whole
    second that counted it."""
    for record in sorted(records, key=lambda r: r["since"]):
        seconds = [int(s) for s in record[field].get(key, {}) if _in_step(s, start, end)]
        if not seconds:
            continue
        first = record[f"{field}_first"].get(key)
        if first is not None and start <= first < end:
            return {"t": first, "precision": "exact"}
        return {"t": max(start, float(min(seconds))), "precision": "second"}
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
                "first": {key: first_in_step(scans, "http", key, start, end) for key in counts["http"]
                          if key == "429" or key.startswith("5")},
            }
        if counts["levels"] or counts["pg"]:
            logs[service] = {
                "levels": counts["levels"],
                "pg": counts["pg"],
                "first": {
                    **{key: first_in_step(scans, "levels", key, start, end) for key in counts["levels"]},
                    **{f"pg {key}": first_in_step(scans, "pg", key, start, end) for key in counts["pg"]},
                },
            }
    return http, logs


def _first_signals(samples: list[dict], series: dict[str, dict], http: dict, logs: dict, start: float,
                   end: float, host_ncpu: int | None) -> list[dict]:
    signals: list[tuple[float, str, str, str]] = []

    def first(points: Iterable[dict], test, service: str, signal: str, when=None) -> None:
        previous = None
        for point in points:
            if point["t"] >= start and test(point, previous):
                if when is None:
                    signals.append((point["t"], service, signal, "sample"))
                else:
                    signals.append((max(start, when(point)), service, signal, "estimated"))
                return
            previous = point

    for service, entry in http.items():
        if entry["first"].get("429") is not None:
            signals.append((entry["first"]["429"]["t"], service, "http 429", entry["first"]["429"]["precision"]))
        fives = [found for key, found in entry["first"].items() if key.startswith("5") and found is not None]
        if fives:
            earliest = min(fives, key=lambda found: found["t"])
            signals.append((earliest["t"], service, "http 5xx", earliest["precision"]))
    for service, entry in logs.items():
        for key, found in entry["first"].items():
            if found is not None and (key in ERROR_LEVELS or (key.startswith("pg ") and key != "pg other")):
                signals.append((found["t"], service, key, found["precision"]))

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
            signals.append((sample["t"], sample.get("service") or "collector", f"probe failed: {sample['probe']}",
                            "sample"))

    seen = set()
    ordered = []
    for t, service, signal, precision in sorted(s for s in signals if start <= s[0] < end):
        if (service, signal) not in seen:
            seen.add((service, signal))
            ordered.append({"t": t, "offset_seconds": t - start, "service": service, "signal": signal,
                            "precision": precision})
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
        "coverage": _coverage(samples, start, end),
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


def _coverage_lines(coverage: dict[str, Any], start: float) -> list[str]:
    if not coverage["available"]:
        return ["No collector samples in this step: nothing below is evidence that nothing happened.", ""]
    lines = [f"Samples every {coverage['interval_seconds']:g} s: expected {coverage['expected']}, "
             f"attempted {coverage['attempted']}, completed {coverage['completed']}, "
             f"skipped {coverage['skipped']}, missing {coverage['missing']}.", ""]
    if coverage["failed_probes"]:
        lines += ["Failed probes: " + ", ".join(f"{probe} {n}" for probe, n in sorted(coverage["failed_probes"].items()))
                  + ".", ""]
    if coverage["gaps"]:
        lines += ["Without a complete sample: " + ", ".join(f"+{a - start:.1f} s to +{b - start:.1f} s"
                                                           for a, b in coverage["gaps"]) + ".", ""]
    if not coverage["complete"]:
        lines += ["**Coverage incomplete:** a quiet figure below may mean only that nothing was measured.", ""]
    return lines


def render(step: dict[str, Any]) -> str:
    start = step["start"]
    coverage = step["coverage"]
    lines = [f"## Step {step['seats']} seats", "",
             f"{_clock(start)} to {_clock(step['end'])}, {step['duration_seconds']:.1f} s"
             + (" (open: the driver did not mark this step's end)" if step["open"] else "")
             + (f"; host has {step['host_ncpu']} CPUs" if step.get("host_ncpu") else ""), ""]

    lines += ["### Coverage", ""] + _coverage_lines(coverage, start)

    lines += ["### Workload", ""]
    if step["workload"]:
        lines += ["From the driver's step_end mark: "
                  + ", ".join(f"{key} {value}" for key, value in sorted(step["workload"].items())) + ".", ""]
    else:
        lines += ["Workload accounting: unavailable. The driver's marks for this step carry no operation totals.", ""]

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
        statements = pg["statements"]
        if statements is None:
            continue
        lines += [f"Statements by time in the step, {service} (query IDs; no text is collected). A statement's time "
                  "counts in the ticks where it was among that tick's slowest; the rest is under other:", ""]
        lines += _table(["database", "query ID", "calls", "time ms", "mean ms"],
                        [[s["datname"], str(s["queryid"]), str(s["calls"]), _num(s["exec_ms"]), _num(s["mean_ms"], 2)]
                         for s in statements["ranked"]]
                        + [["", "other", "", _num(statements["other_exec_ms"]), ""],
                           ["", "total", "", _num(statements["total_exec_ms"]), ""]])
        for reason in statements["partial"]:
            lines += [f"Partial: {reason}.", ""]

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

    def when(found: dict | None) -> str:
        return "-" if found is None else f"+{found['t'] - start:.1f} s {found['precision']}"

    lines += ["### HTTP", "", "From access logs; Secrets and the TLS front write none.", ""] + _table(
        ["service", "2xx", "3xx", "4xx other", "429", "5xx", "first 429", "first 5xx"],
        [[s, str(by_class(h["counts"], lambda c: c.startswith("2"))),
          str(by_class(h["counts"], lambda c: c.startswith("3"))),
          str(by_class(h["counts"], lambda c: c.startswith("4") and c != "429")),
          str(h["counts"].get("429", 0)), str(by_class(h["counts"], lambda c: c.startswith("5"))),
          when(h["first"].get("429")),
          when(min((f for k, f in h["first"].items() if k.startswith("5") and f is not None),
                   key=lambda f: f["t"], default=None))]
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

    lines += ["### First signals", "",
              "Times are exact (the logged line), to the second, at a sample (began up to one interval earlier), "
              "or estimated.", ""]
    lines += [f"{i}. {when(s)} {s['service']}: {s['signal']}" for i, s in enumerate(step["first_signals"], 1)]
    if not step["first_signals"]:
        if not coverage["available"]:
            lines.append("No collector samples in this step.")
        elif coverage["complete"]:
            lines.append("None observed.")
        else:
            lines.append("None observed in the samples taken; coverage is incomplete.")
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
