import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import go_test_shards as shards

SOURCE = '''package sample

import (
	"syscall"
	"testing"
)

var exit = syscall.Exit

func TestOne(t *testing.T) {}
func TestTwo(t *testing.T) { t.Run("sub", func(t *testing.T) {}) }
func TestThree(t *testing.T) { t.Skip("not here") }
func TestFour(t *testing.T) { %s }
func Example() {
	// Output:
}
'''


class DivisionTests(unittest.TestCase):
    def test_each_name_is_in_exactly_one_process(self):
        names = [f"Test{i}" for i in range(100)]
        parts = shards.divide(names, {"Test7": 30, "Test8": 20}, 3)
        self.assertEqual(sorted(n for part in parts for n in part), sorted(names))
        self.assertEqual(parts, shards.divide(list(reversed(names)), {"Test7": 30, "Test8": 20}, 3))

    def test_longest_tests_are_spread(self):
        parts = shards.divide(["TestA", "TestB", "TestC", "TestD"], {"TestA": 9, "TestB": 8, "TestC": 7}, 3)
        self.assertEqual([part[0] for part in parts], ["TestA", "TestB", "TestC"])
        self.assertIn("TestD", parts[2])

    def test_coverage_names_missing_repeated_and_unlisted_tests(self):
        self.assertEqual(shards.coverage_errors(["TestA", "TestB"], ["TestA", "TestB"]), [])
        self.assertEqual(shards.coverage_errors(["TestA", "TestB"], ["TestB", "TestB", "TestC"]),
                         ["TestA finished 0 times", "TestB finished 2 times", "TestC finished 1 times"])

    def test_each_process_has_its_own_redis_database(self):
        env = {"REDIS_URL": "redis://127.0.0.1:6379/0"}
        self.assertEqual(shards.redis_for_shard(env, 2)["REDIS_URL"], "redis://127.0.0.1:6379/2")
        self.assertEqual(shards.redis_for_shard({}, 2), {})


class RunTests(unittest.TestCase):
    def run_package(self, body):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "go.mod").write_text("module sample\n\ngo 1.22\n")
            Path(root, "sample_test.go").write_text(SOURCE % body)
            Path(root, "weights.json").write_text(json.dumps({"TestOne": 2}))
            return subprocess.run(
                [sys.executable, shards.__file__, ".", "--processes", "3", "--weights", "weights.json"],
                cwd=root, text=True, capture_output=True, check=False, env=dict(os.environ, GOFLAGS="-mod=mod"))

    def test_every_test_runs_once_and_a_skip_is_shown(self):
        result = self.run_package("")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(".: 5 listed tests in 3 processes: PASSED", result.stdout)
        self.assertIn("not here", result.stdout)
        self.assertNotIn("TestTwo", result.stdout)

    def test_a_failure_fails_the_run_with_its_output(self):
        result = self.run_package('t.Fatal("four is broken")')
        self.assertEqual(result.returncode, 1)
        self.assertIn("four is broken", result.stdout)

    def test_a_panic_fails_the_run_with_its_output(self):
        result = self.run_package('panic("four panicked")')
        self.assertEqual(result.returncode, 1)
        self.assertIn("four panicked", result.stdout)

    def test_a_process_that_exits_clean_before_its_tests_finish_fails(self):
        result = self.run_package('exit(0)')
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("GO_SHARDS_COVERAGE: TestFour finished 0 times", result.stdout)


if __name__ == "__main__":
    unittest.main()
