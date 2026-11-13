#!/usr/bin/env python3
"""The collector's parsers, on output recorded from real Docker, PostgreSQL 16,
Redis 7 and the aweb and AWID images of main 544023fdb. Three log lines are
written in the recorded formats for conditions the stack did not produce: the
registry's ERROR record, and PostgreSQL's too-many-clients and lock-timeout
lines."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import collect  # noqa: E402

STATS_LINE = (
    '{"BlockIO":"0B / 17.4MB","CPUPerc":"0.27%","Container":"260c01c8f4bf","ID":"260c01c8f4bf",'
    '"MemPerc":"0.12%","MemUsage":"112.7MiB / 94.12GiB","Name":"loadcollect-test-aweb-1",'
    '"NetIO":"27.3kB / 20.8kB","PIDs":"6"}'
)

REGISTRY_LOG = """\
2026-11-13T04:00:49.435436750Z INFO:     127.0.0.1:53634 - "GET /live HTTP/1.1" 200 OK
2026-11-13T04:01:54.029783628Z INFO:     172.23.0.6:56906 - "GET /v1/namespaces/nope.example HTTP/1.1" 429 Too Many Requests
2026-11-13T04:01:54.034020878Z INFO:     172.23.0.6:56910 - "GET /v1/namespaces/nope.example HTTP/1.1" 429 Too Many Requests
2026-11-13T04:01:54.040000000Z {"timestamp": "2026-11-13T04:01:54.039+00:00", "level": "ERROR", "logger": "awid.db", "message": "pool exhausted", "function": "f", "line": 1}
"""

POSTGRES_LOG = """\
2026-11-13T03:56:40.218479094Z 2026-11-13 03:56:40.218 UTC [1] LOG:  database system is ready to accept connections
2026-11-13T04:01:54.125107419Z 2026-11-13 04:01:54.124 UTC [1343] FATAL:  database "nope" does not exist
2026-11-13T04:01:55.000000000Z 2026-11-13 04:01:55.000 UTC [1344] FATAL:  sorry, too many clients already
2026-11-13T04:01:56.000000000Z 2026-11-13 04:01:56.000 UTC [1345] ERROR:  canceling statement due to lock timeout
"""

REDIS_INFO = (
    "# Server\r\nredis_version:7.4.12\r\n\r\n# Clients\r\nconnected_clients:2\r\nmaxclients:10000\r\n"
    "blocked_clients:0\r\n\r\n# Memory\r\nused_memory:1171152\r\nused_memory_human:1.12M\r\nmaxmemory:0\r\n"
    "\r\n# Stats\r\ninstantaneous_ops_per_sec:3\r\ntotal_commands_processed:140\r\nrejected_connections:0\r\n"
    "evicted_keys:0\r\n\r\n# Keyspace\r\ndb0:keys=12,expires=12,avg_ttl=0\r\n"
)

POSTGRES_JSON = (
    '{"max_connections" : 100, "preload" : "", "databases" : [{"datname" : "aweb", "numbackends" : 10, '
    '"xact_commit" : 216, "xact_rollback" : 0, "deadlocks" : 0, "active" : 0, "idle_in_transaction" : 0, '
    '"waiting_on_lock" : 0, "ungranted_locks" : 0, "longest_lock_wait_seconds" : 0}]}'
)


def ts(text: str) -> float:
    return collect.parse_docker_timestamp(text)


class Sizes(unittest.TestCase):
    def test_docker_units_are_decimal_or_binary_as_written(self):
        self.assertEqual(collect.parse_size("0B"), 0)
        self.assertEqual(collect.parse_size("27.3kB"), 27300)
        self.assertEqual(collect.parse_size("17.4MB"), 17_400_000)
        self.assertEqual(collect.parse_size("112.7MiB"), round(112.7 * 2**20))
        self.assertEqual(collect.parse_size("94.12GiB"), round(94.12 * 2**30))


class ContainerStats(unittest.TestCase):
    def test_a_stats_line_becomes_numbers(self):
        sample = collect.container_sample(STATS_LINE)
        self.assertEqual(sample["name"], "loadcollect-test-aweb-1")
        self.assertEqual(sample["cpu_percent"], 0.27)
        self.assertEqual(sample["mem_bytes"], round(112.7 * 2**20))
        self.assertEqual(sample["mem_limit_bytes"], round(94.12 * 2**30))
        self.assertEqual((sample["net_rx_bytes"], sample["net_tx_bytes"]), (27300, 20800))
        self.assertEqual((sample["block_read_bytes"], sample["block_write_bytes"]), (0, 17_400_000))
        self.assertEqual(sample["pids"], 6)

    def test_a_stopped_containers_placeholders_are_absent_values(self):
        sample = collect.container_sample(
            '{"BlockIO":"--","CPUPerc":"--","MemUsage":"-- / --","Name":"x","NetIO":"--","PIDs":"--"}'
        )
        self.assertIsNone(sample["cpu_percent"])
        self.assertIsNone(sample["mem_bytes"])
        self.assertIsNone(sample["net_rx_bytes"])
        self.assertIsNone(sample["pids"])


class Logs(unittest.TestCase):
    def test_access_lines_are_counted_by_status_with_the_first_time_of_each(self):
        scan = collect.scan_log(REGISTRY_LOG, since=0, until=ts("2026-11-13T05:00:00Z"))
        second = str(int(ts("2026-11-13T04:01:54Z")))
        self.assertEqual(scan["http"], {"200": {str(int(ts("2026-11-13T04:00:49Z"))): 1}, "429": {second: 2}})
        self.assertEqual(scan["http_first"]["429"], ts("2026-11-13T04:01:54.029783628Z"))
        self.assertEqual(scan["levels"], {"ERROR": {second: 1}})
        self.assertEqual(scan["levels_first"]["ERROR"], ts("2026-11-13T04:01:54.040000000Z"))

    def test_the_window_is_half_open(self):
        start = ts("2026-11-13T04:01:54.029783628Z")
        scan = collect.scan_log(REGISTRY_LOG, since=start, until=ts("2026-11-13T04:01:54.040000000Z"))
        self.assertEqual(collect.totals(scan["http"]), {"429": 2})
        self.assertEqual(scan["levels"], {})

    def test_counts_are_kept_per_whole_second_so_a_step_can_be_cut_to_the_second(self):
        scan = collect.scan_log(REGISTRY_LOG, since=0, until=ts("2026-11-13T05:00:00Z"))
        self.assertEqual(collect.totals(scan["http"]), {"200": 1, "429": 2})

    def test_postgres_errors_are_counted_by_known_class_without_their_text(self):
        scan = collect.scan_log(POSTGRES_LOG, since=0, until=ts("2026-11-13T05:00:00Z"))
        self.assertEqual(collect.totals(scan["levels"]), {"FATAL": 2, "ERROR": 1})
        self.assertEqual(collect.totals(scan["pg"]), {"too_many_clients": 1, "lock_timeout": 1, "other": 1})
        self.assertEqual(scan["pg_first"]["too_many_clients"], ts("2026-11-13T04:01:55Z"))
        self.assertNotIn("nope", repr(scan))

    def test_docker_timestamps_keep_their_fraction(self):
        self.assertAlmostEqual(ts("2026-11-13T04:01:54.5Z") - ts("2026-11-13T04:01:54Z"), 0.5)


class Redis(unittest.TestCase):
    def test_info_text_gives_the_sampled_fields_as_numbers(self):
        fields = collect.redis_fields(collect.parse_redis_info(REDIS_INFO))
        self.assertEqual(fields["connected_clients"], 2)
        self.assertEqual(fields["maxclients"], 10000)
        self.assertEqual(fields["used_memory"], 1171152)
        self.assertEqual(fields["total_commands_processed"], 140)
        self.assertNotIn("used_memory_human", fields)
        self.assertNotIn("redis_version", fields)

    def test_a_refused_info_is_a_probe_failure_not_an_empty_sample(self):
        # redis-cli exits 0 when the server refuses it; recorded from aweb's Redis.
        with self.assertRaises(collect.ProbeFailed):
            collect.redis_info_fields("NOAUTH Authentication required.\n")
        self.assertEqual(collect.redis_info_fields(REDIS_INFO)["blocked_clients"], 0)

    def test_the_in_container_reader_names_the_secret_file_but_holds_no_secret(self):
        script = collect.AWEB_REDIS_SCRIPT
        self.assertIn("/run/secrets/aweb/redis-url", script)
        self.assertIn("type(exc).__name__", script)
        self.assertNotIn("print(url", script)


class Postgres(unittest.TestCase):
    def test_the_query_result_is_kept_per_database(self):
        sample = collect.postgres_sample(POSTGRES_JSON)
        self.assertEqual(sample["max_connections"], 100)
        self.assertFalse(sample["statements_available"])
        (aweb,) = sample["databases"]
        self.assertEqual(aweb["datname"], "aweb")
        self.assertEqual(aweb["numbackends"], 10)

    def test_the_query_only_reads(self):
        sql = collect.POSTGRES_SQL.upper()
        for verb in ("INSERT", "UPDATE", "DELETE", "CREATE", "ALTER", "DROP", "SET ", "RESET", "PG_STAT_RESET"):
            self.assertNotIn(verb, sql)


if __name__ == "__main__":
    unittest.main()
