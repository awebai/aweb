#!/usr/bin/env python3
"""The summariser, on a recorded run.

fixtures/ramp-samples.jsonl is collect.py's real output for a two-step stand-in
ramp against a local stack shaped like one team deployment (main 544023fdb's
aweb and AWID images, PostgreSQL 16 with pg_stat_statements, Redis 7, aweb's
Redis behind an ACL password). fixtures/ramp-marks.jsonl is the stand-in's
marks in the driver's format.

Step 10 only polled aweb. Step 20 also:
- held a PostgreSQL advisory lock that a second session waited on;
- kept a client blocked in the registry's Redis;
- opened a database that does not exist;
- ran statements carrying a canary in a comment and in a literal;
- drove the registry past its 60-per-minute namespace limit.

The expected counts and the first 429 were read from `docker logs` between the
step's marks, not from the collector. Tests that need a gap, a skipped slot, a
failed probe or driver totals edit a copy of the recording in memory.
"""

from __future__ import annotations

import copy
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
FIRST_429 = collect.parse_docker_timestamp("2026-11-13T04:27:21.014050710Z")
REGISTRY_429S = 42
REGISTRY_404S = 60
AWEB_200S_STEP_10 = 17
CANARY = "canary-5d1e"


def recorded() -> tuple[list[dict], list[dict], list[dict]]:
    samples = summarise.load_jsonl(SAMPLES)
    marks = summarise.load_jsonl(MARKS)
    return samples, marks, summarise.step_windows(marks, samples)


def step(samples: list[dict], marks: list[dict], seats: int) -> dict:
    (window,) = [w for w in summarise.step_windows(marks, samples) if w["seats"] == seats]
    return summarise.summarise(samples, window)


class Windows(unittest.TestCase):
    def test_each_step_is_a_window_between_its_marks(self):
        _, _, windows = recorded()
        self.assertEqual([w["seats"] for w in windows], [10, 20])
        self.assertFalse(any(w["open"] for w in windows))

    def test_a_step_the_driver_never_ended_runs_to_the_last_sample(self):
        samples, marks, _ = recorded()
        (_, last) = summarise.step_windows(marks[:-1], samples)
        self.assertTrue(last["open"])
        self.assertEqual(last["end"], max(s["t"] for s in samples))


class Recorded(unittest.TestCase):
    def setUp(self):
        samples, marks, _ = recorded()
        self.quiet = step(samples, marks, 10)
        self.loaded = step(samples, marks, 20)

    def test_http_counts_match_the_logs_between_the_marks(self):
        registry = self.loaded["http"]["registry"]
        self.assertEqual(registry["counts"]["429"], REGISTRY_429S)
        self.assertEqual(registry["counts"]["404"], REGISTRY_404S)
        self.assertEqual(registry["first"]["429"], {"t": FIRST_429, "precision": "exact"})
        self.assertEqual(self.quiet["http"]["aweb"]["counts"], {"200": AWEB_200S_STEP_10})
        self.assertNotIn("429", self.quiet["http"].get("registry", {}).get("counts", {}))

    def test_429s_are_also_given_per_minute_of_the_step(self):
        per_minute = self.loaded["http"]["registry"]["per_minute"]
        self.assertEqual(sum(minute.get("429", 0) for minute in per_minute.values()), REGISTRY_429S)

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

    def test_the_recording_covers_every_slot_of_each_step(self):
        for summary in (self.quiet, self.loaded):
            coverage = summary["coverage"]
            self.assertTrue(coverage["complete"], coverage)
            self.assertGreater(coverage["expected"], 2)
            self.assertEqual(coverage["attempted"], coverage["expected"])
            self.assertEqual(coverage["completed"], coverage["expected"])
            self.assertEqual((coverage["skipped"], coverage["missing"], coverage["failed_probes"]), (0, 0, {}))
            self.assertEqual(coverage["gaps"], [])

    def test_without_driver_totals_workload_accounting_is_unavailable(self):
        self.assertIsNone(self.loaded["workload"])
        self.assertIn("Workload accounting: unavailable", summarise.render(self.loaded))


class Statements(unittest.TestCase):
    def test_no_statement_text_is_recorded_or_reported(self):
        # The stand-in ran SELECTs carrying the canary in a comment and in a literal.
        samples, marks, _ = recorded()
        self.assertNotIn(CANARY, SAMPLES.read_text())
        loaded = step(samples, marks, 20)
        self.assertNotIn(CANARY, summarise.render(loaded))
        for entry in loaded["postgres"]["postgres"]["statements"]["ranked"]:
            self.assertEqual(set(entry), {"datname", "queryid", "calls", "exec_ms", "mean_ms"})

    def test_ranked_times_are_the_sum_of_the_steps_per_tick_deltas(self):
        samples, marks, windows = recorded()
        window = windows[1]
        loaded = summarise.summarise(samples, window)
        statements = loaded["postgres"]["postgres"]["statements"]
        self.assertEqual(statements["partial"], [])
        top = statements["ranked"][0]
        expected = sum(
            entry["exec_ms"]
            for s in samples
            if s["kind"] == "postgres" and s["service"] == "postgres" and window["start"] <= s["t"] <= window["end"]
            for entry in s["statements"].get("top", [])
            if (entry["datname"], entry["queryid"]) == (top["datname"], top["queryid"])
        )
        self.assertAlmostEqual(top["exec_ms"], expected)
        times = [s["exec_ms"] for s in statements["ranked"]]
        self.assertEqual(times, sorted(times, reverse=True))
        self.assertGreater(statements["total_exec_ms"], 0)

    def test_a_ranking_with_a_baseline_or_eviction_in_the_step_says_it_is_partial(self):
        samples, marks, windows = recorded()
        window = windows[1]
        edited = copy.deepcopy(samples)
        inside = [s for s in edited if s["kind"] == "postgres" and s["service"] == "postgres"
                  and window["start"] <= s["t"] <= window["end"]]
        inside[0]["statements"] = {"baseline": True, "dealloc": 0}
        inside[-1]["statements"]["evicted_entries"] = 3
        partial = summarise.summarise(edited, window)["postgres"]["postgres"]["statements"]["partial"]
        self.assertEqual(len(partial), 2, partial)
        self.assertIn("baseline", partial[0])
        self.assertIn("evicted", partial[1])


class Coverage(unittest.TestCase):
    def test_no_samples_is_not_reported_as_nothing_observed(self):
        # naapp-review's counterexample: an empty sample set rendered "None observed."
        _, marks, _ = recorded()
        (window,) = [w for w in summarise.step_windows(marks, []) if w["seats"] == 10]
        summary = summarise.summarise([], window)
        self.assertFalse(summary["coverage"]["available"])
        self.assertFalse(summary["coverage"]["complete"])
        text = summarise.render(summary)
        self.assertNotIn("None observed", text)
        self.assertIn("No collector samples in this step", text)

    def test_a_gap_in_collection_is_counted_and_located(self):
        samples, marks, windows = recorded()
        window = windows[1]
        middle = window["start"] + 6, window["start"] + 14
        kept = [s for s in samples if not middle[0] <= s["t"] < middle[1]]
        summary = summarise.summarise(kept, window)
        coverage = summary["coverage"]
        self.assertFalse(coverage["complete"])
        self.assertGreaterEqual(coverage["missing"], 1)
        self.assertEqual(len(coverage["gaps"]), 1)
        self.assertLessEqual(coverage["gaps"][0][0], middle[0])
        self.assertGreaterEqual(coverage["gaps"][0][1], middle[1])
        text = summarise.render(summary)
        self.assertIn("Coverage incomplete", text)
        self.assertNotIn("None observed.", text)

    def test_skipped_slots_and_failed_probes_make_coverage_incomplete(self):
        samples, marks, windows = recorded()
        window = windows[1]
        edited = copy.deepcopy(samples)
        ticks = [s for s in edited if s["kind"] == "tick" and window["start"] <= s["scheduled_t"] < window["end"]]
        ticks[0]["probes"]["postgres:postgres"] = "failed"
        skipped = ticks[-1]
        edited.remove(skipped)
        edited.append({"t": skipped["t"], "kind": "tick_skipped", "slot": skipped["slot"],
                       "scheduled_t": skipped["scheduled_t"]})
        coverage = summarise.summarise(edited, window)["coverage"]
        self.assertFalse(coverage["complete"])
        self.assertEqual(coverage["skipped"], 1)
        self.assertEqual(coverage["failed_probes"], {"postgres:postgres": 1})
        self.assertEqual(coverage["attempted"], coverage["expected"] - 1)
        self.assertEqual(coverage["completed"], coverage["expected"] - 2)


class Workload(unittest.TestCase):
    def test_driver_totals_on_the_step_end_are_reported(self):
        samples, marks, _ = recorded()
        totals = {"attempted": 400, "completed": 391, "failed": 9, "deadline_missed": 4}
        marks = [dict(m, operations=totals) if m["event"] == "step_end" and m["seats"] == 20 else m for m in marks]
        loaded = step(samples, marks, 20)
        self.assertEqual(loaded["workload"], totals)
        text = summarise.render(loaded)
        self.assertIn("deadline_missed 4", text)
        self.assertNotIn("unavailable", text)


class FirstSignals(unittest.TestCase):
    def test_first_signals_are_observations_in_time_order_with_their_precision(self):
        samples, marks, _ = recorded()
        loaded, quiet = step(samples, marks, 20), step(samples, marks, 10)
        signals = loaded["first_signals"]
        self.assertEqual([s["t"] for s in signals], sorted(s["t"] for s in signals))
        named = {(s["service"], s["signal"]): s for s in signals}
        self.assertEqual(named[("registry", "http 429")]["t"], FIRST_429)
        self.assertEqual(named[("registry", "http 429")]["precision"], "exact")
        self.assertEqual(named[("postgres", "FATAL")]["precision"], "exact")
        self.assertEqual(named[("postgres/aweb", "lock wait")]["precision"], "estimated")
        self.assertEqual(named[("registry-redis", "blocked clients")]["precision"], "sample")
        self.assertLess(named[("postgres/aweb", "lock wait")]["t"], FIRST_429)
        self.assertEqual(quiet["first_signals"], [])

    def test_a_first_time_cut_to_the_steps_start_is_rounded_not_exact(self):
        record = {"since": 99.0, "until": 104.0, "http": {"429": {"99": 1, "101": 2}}, "http_first": {"429": 99.2}}
        self.assertEqual(summarise.first_in_step([record], "http", "429", 100.5, 110.0),
                         {"t": 101.0, "precision": "second"})
        self.assertEqual(summarise.first_in_step([record], "http", "429", 99.0, 110.0),
                         {"t": 99.2, "precision": "exact"})


class Counters(unittest.TestCase):
    def test_a_counter_that_restarts_counts_from_zero(self):
        self.assertEqual(summarise.counter_delta([10, 15, 3, 7]), 5 + 3 + 4)
        self.assertIsNone(summarise.counter_delta([10]))
        self.assertIsNone(summarise.counter_delta([None, 4]))


class Report(unittest.TestCase):
    def test_the_markdown_report_names_every_section(self):
        samples, marks, _ = recorded()
        text = summarise.render(step(samples, marks, 20))
        for heading in ("## Step 20 seats", "### Coverage", "### Workload", "### Containers", "### PostgreSQL",
                        "### Redis", "### HTTP", "### First signals"):
            self.assertIn(heading, text)

    def test_the_command_prints_every_step_or_one(self):
        out = summarise.main(["--samples", str(SAMPLES), "--marks", str(MARKS)])
        self.assertIn("## Step 10 seats", out)
        self.assertIn("## Step 20 seats", out)
        one = json.loads(summarise.main(["--samples", str(SAMPLES), "--marks", str(MARKS), "--seats", "20", "--json"]))
        self.assertEqual([s["seats"] for s in one], [20])


if __name__ == "__main__":
    unittest.main()
