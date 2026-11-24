#!/usr/bin/env python3
"""Run one Go package's tests in several processes, each test exactly once.

The package's serial tests change process-wide state, so they cannot run beside
each other in one process. The test binary's own list is divided by the seconds
in the weights file; a test without a weight counts as DEFAULT_WEIGHT. The run
fails unless every listed test finished in exactly one process.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import threading
import time
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

DEFAULT_WEIGHT = 0.03
RUNNABLE = re.compile(r"(?:Test|Example|Fuzz)\w*")
RESULT = re.compile(r"--- (?P<result>PASS|FAIL|SKIP): (?P<test>\w+) \(")


def listed_tests(output):
    names = [line for line in output.splitlines() if RUNNABLE.fullmatch(line)]
    if not names or len(names) != len(set(names)):
        raise RuntimeError("GO_SHARDS_LIST_INVALID")
    return names


def divide(names, weights, count):
    """Place each test, longest first, in the process with the least time."""
    shards = [[] for _ in range(count)]
    seconds = [0.0] * count
    for name in sorted(names, key=lambda n: (-weights.get(n, DEFAULT_WEIGHT), n)):
        shard = seconds.index(min(seconds))
        shards[shard].append(name)
        seconds[shard] += weights.get(name, DEFAULT_WEIGHT)
    return shards


def redis_for_shard(env, shard):
    """Each process gets its own Redis database on the services it is given."""
    url = env.get("REDIS_URL")
    if not url:
        return env
    return dict(env, REDIS_URL=urlunsplit(urlsplit(url)._replace(path=f"/{shard}")))


def coverage_errors(names, finished):
    """Listed tests that did not finish exactly once, and finished strangers."""
    counts = Counter(finished)
    return sorted(
        f"{name} finished {counts[name]} times"
        for name in set(names) | set(counts)
        if counts[name] != (1 if name in set(names) else 0)
    )


class Shard:
    def __init__(self, number, names, args, env):
        self.number, self.names = number, names
        self.finished, self.skipped, self.passed, self.held = [], [], set(), {}
        self.returncode, self.seconds = None, 0.0
        pattern = "^(?:" + "|".join(names) + ")$"
        self.command = ["go", "test", args.package, "-json", "-count=1",
                        "-timeout", args.timeout, "-run", pattern]
        self.env = redis_for_shard(env, number)

    def run(self, lock):
        started = time.monotonic()
        process = subprocess.Popen(self.command, env=self.env, text=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for line in process.stdout:
            self.event(line, lock)
        self.returncode = process.wait()
        self.seconds = time.monotonic() - started
        with lock:
            # A test the process never finished, as after a panic or timeout,
            # and the subtest results that follow a failed test's own.
            for test, output in self.held.items():
                if test not in self.passed:
                    sys.stdout.write("".join(output))
            print(f"shard {self.number}: {len(self.finished)} tests, {len(self.skipped)} skipped, "
                  f"{self.seconds:.1f}s, exit {self.returncode}", flush=True)

    def event(self, line, lock):
        try:
            event = json.loads(line)
        except ValueError:
            event = {"Action": "output", "Output": line}
        if event["Action"] not in ("output", "build-output"):
            return
        test, output = event.get("Test", "").split("/")[0], event["Output"]
        if not test:
            with lock:
                sys.stdout.write(output)
            return
        self.held.setdefault(test, []).append(output)
        # go test -json also reports a pass for a test the process left
        # running when it exited 0. Only the test's own result line counts.
        result = RESULT.match(output)
        if result and result["test"] == event["Test"]:
            self.finished.append(test)
            held = self.held.pop(test)
            if result["result"] == "SKIP":
                self.skipped.append(test)
            if result["result"] == "PASS":
                self.passed.add(test)
            else:
                with lock:
                    sys.stdout.write("".join(held))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package")
    parser.add_argument("--processes", type=int, required=True)
    parser.add_argument("--weights", type=Path, required=True)
    parser.add_argument("--timeout", default="20m")
    args = parser.parse_args()
    listing = subprocess.run(["go", "test", args.package, "-list", "."],
                             text=True, stdout=subprocess.PIPE, check=True)
    names = listed_tests(listing.stdout)
    weights = json.loads(args.weights.read_text())
    shards = [Shard(number, part, args, dict(os.environ))
              for number, part in enumerate(divide(names, weights, args.processes)) if part]
    lock = threading.Lock()
    threads = [threading.Thread(target=shard.run, args=(lock,)) for shard in shards]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    errors = coverage_errors(names, [name for shard in shards for name in shard.finished])
    for error in errors:
        print(f"GO_SHARDS_COVERAGE: {error}")
    failed = bool(errors) or any(shard.returncode for shard in shards)
    print(f"{args.package}: {len(names)} listed tests in {len(shards)} processes: "
          f"{'FAILED' if failed else 'PASSED'}", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
