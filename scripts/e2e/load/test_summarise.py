#!/usr/bin/env python3
"""The summariser, on a recorded run.

fixtures/ramp-samples.jsonl is collect.py's real output for a two-step stand-in
ramp against a local stack shaped like one team deployment (main 544023fdb's
aweb and AWID images, PostgreSQL 16 with pg_stat_statements, Redis 7, aweb's
Redis behind an ACL password). fixtures/ramp-marks.jsonl is the stand-in's
marks in the driver's format. Step 10 only polled aweb. Step 20 also held a
PostgreSQL advisory lock that a second session waited on, kept a client blocked
in the registry's Redis, opened a database that does not exist, and drove the
registry past its 60-per-minute namespace limit. The expected counts and the
first 429 were read from `docker logs` between the step's marks, not from the
collector.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import collect  # noqa: E402
import summarise  # noqa: E402

SAMPLES = HERE / "fixtures" / "ramp-samples.jsonl"
MARKS = HERE / "fixtures" / "ramp-marks.jsonl"
FIRST_429 = collect.parse_docker_timestamp("2026-11-13T04:13:13.490808137Z")


def recorded() -> tuple[list[dict], list[dict]]:
    samples = summarise.load_jsonl(SAMPLES)
    windows = summarise.step_windows(summarise.load_jsonl(MARKS), samples)
    return samples, windows


class Windows(unittest.TestCase):
    def test_each_step_is_a_window_between_its_marks(self):
        _, windows = recorded()
        self.assertEqual([w["seats"] for w in windows], [10, 20])
        self.assertFalse(any(w["open"] for w in windows))
        self.assertAlmostEqual(windows[1]["end"] - windows[1]["start"], 19.78, places=1)

    def test_a_step_the_driver_never_ended_runs_to_the_last_sample(self):
        samples, _ = recorded()
        marks = summarise.load_jsonl(MARKS)[:-1]
        (_, last) = summarise.step_windows(marks, samples)
        self.assertTrue(last["open"])
        self.assertEqual(last["end"], max(s["t"] for s in samples))


class StepTwenty(unittest.TestCase):
    def setUp(self):
        samples, windows = recorded()
        self.quiet = summarise.summarise(samples, windows[0])
        self.loaded = summarise.summarise(samples, windows[1])

    def test_http_counts_match_the_logs_between_the_marks(self):
        registry = self.loaded["http"]["registry"]
        self.assertEqual(registry["counts"]["429"], 48)
        self.assertEqual(registry["counts"]["404"], 60)
        self.assertEqual(registry["first"]["429"], FIRST_429)
        self.assertEqual(self.quiet["http"]["aweb"]["counts"], {"200": 16})
        self.assertNotIn("429", self.quiet["http"].get("registry", {}).get("counts", {}))

    def test_429s_are_also_given_per_minute_of_the_step(self):
        per_minute = self.loaded["http"]["registry"]["per_minute"]
        self.assertEqual(sum(minute.get("429", 0) for minute in per_minute.values()), 48)

    def test_the_lock_wait_and_the_blocked_client_belong_to_the_loaded_step_only(self):
        aweb_db = self.loaded["postgres"]["postgres"]["databases"]["aweb"]
        self.assertEqual(aweb_db["waiting_on_lock_max"], 1)
        self.assertGreater(aweb_db["longest_lock_wait_seconds"], 1)
        self.assertEqual(self.quiet["postgres"]["postgres"]["databases"]["aweb"]["waiting_on_lock_max"], 0)
        self.assertEqual(self.loaded["redis"]["registry-redis"]["blocked_clients_max"], 1)
        self.assertEqual(self.quiet["redis"]["registry-redis"]["blocked_clients_max"], 0)

    def test_postgres_errors_are_reported_by_class(self):
        self.assertEqual(self.loaded["logs"]["postgres"]["pg"], {"other": 1})
        self.assertEqual(self.loaded["logs"]["postgres"]["levels"], {"FATAL": 1})
        self.assertNotIn("postgres", self.quiet["logs"])

    def test_cumulative_counters_become_rates_over_the_step(self):
        aweb_db = self.loaded["postgres"]["postgres"]["databases"]["aweb"]
        self.assertGreater(aweb_db["transactions_per_second"], 0)
        self.assertGreater(self.loaded["redis"]["redis"]["commands_per_second"], 0)
        self.assertGreater(self.loaded["containers"]["registry"]["net_rx_bytes"], 0)

    def test_statements_are_ranked_by_time_spent_in_the_step(self):
        statements = self.loaded["postgres"]["postgres"]["statements"]
        self.assertTrue(statements)
        times = [s["exec_ms"] for s in statements]
        self.assertEqual(times, sorted(times, reverse=True))
        self.assertTrue(all(s["calls"] > 0 for s in statements))

    def test_first_signals_are_observations_in_time_order(self):
        signals = self.loaded["first_signals"]
        self.assertEqual([s["t"] for s in signals], sorted(s["t"] for s in signals))
        named = {(s["service"], s["signal"]) for s in signals}
        self.assertIn(("registry", "http 429"), named)
        self.assertIn(("postgres/aweb", "lock wait"), named)
        self.assertIn(("registry-redis", "blocked clients"), named)
        self.assertIn(("postgres", "FATAL"), named)
        first_429 = next(s for s in signals if s["signal"] == "http 429")
        self.assertEqual(first_429["t"], FIRST_429)
        lock = next(s for s in signals if s["signal"] == "lock wait")
        self.assertLess(lock["t"], first_429["t"])
        self.assertEqual(self.quiet["first_signals"], [])


class Counters(unittest.TestCase):
    def test_a_counter_that_restarts_counts_from_zero(self):
        self.assertEqual(summarise.counter_delta([10, 15, 3, 7]), 5 + 3 + 4)
        self.assertIsNone(summarise.counter_delta([10]))
        self.assertIsNone(summarise.counter_delta([None, 4]))


class Report(unittest.TestCase):
    def test_the_markdown_report_names_every_section_and_no_secret(self):
        samples, windows = recorded()
        text = summarise.render(summarise.summarise(samples, windows[1]))
        for heading in ("## Step 20 seats", "### Containers", "### PostgreSQL", "### Redis", "### HTTP",
                        "### First signals"):
            self.assertIn(heading, text)
        self.assertNotIn("canary", text)

    def test_the_command_prints_every_step_or_one(self):
        out = summarise.main(["--samples", str(SAMPLES), "--marks", str(MARKS)])
        self.assertIn("## Step 10 seats", out)
        self.assertIn("## Step 20 seats", out)
        one = json.loads(summarise.main(["--samples", str(SAMPLES), "--marks", str(MARKS), "--seats", "20", "--json"]))
        self.assertEqual([step["seats"] for step in one], [20])


if __name__ == "__main__":
    unittest.main()
