"""Actual runner/cleanup fragments with a disposable Docker stand-in, never Docker."""

import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

FAKE_DOCKER = r"""
import json, os, sys, time
from pathlib import Path
p = Path(os.environ['CONTROL_ROOT'])
state = p/'resources.json'
def read(): return json.loads(state.read_text())
def save(v):
    staged = p/'resources.next'
    staged.write_text(json.dumps(v))
    staged.replace(state)
a = sys.argv[1:]
v = read()
if a[0] == 'run':
    (p/'ready').write_text(str(os.getpid()))
    try:
        until = time.monotonic() + float(os.environ.get('CONTROL_SECONDS', '30'))
        while time.monotonic() < until:
            if not read()['container']: sys.exit(137)
            time.sleep(.02)
        (p/'natural-completion').touch()
        sys.exit(int(os.environ.get('CONTROL_EXIT', '0')))
    finally:
        (p/'child-exited').touch()
if a[0] == 'info': sys.exit(0)
kind = 'container' if a[0] == 'ps' else a[0]
if a[0] == 'rm':
    assert a[-1] == 'owned-runner'
    v['container'] = []
    save(v)
    sys.exit(0)
if a[0] == 'images': sys.exit(0)
if len(a) > 1 and a[1] == 'inspect':
    name = a[-1]
    if name not in v.get(kind, []):
        print('No such '+kind+': '+name, file=sys.stderr)
        sys.exit(1)
    item = {'Name': name, 'Labels': {'aweb.candidate-gate': 'owned'}}
    if kind == 'container':
        item.update(Config={'Labels': {'aweb.candidate-gate': 'owned'}},
                    Mounts=[{'Type': 'volume', 'Name': n} for n in v['volume']])
    print(json.dumps([item])); sys.exit(0)
if a[0] == 'ps' or (len(a) > 1 and a[1] == 'ls'):
    print('\n'.join(v.get(kind, []))); sys.exit(0)
if len(a) > 1 and a[1] == 'rm':
    assert a[-1] in v[kind]
    v[kind].remove(a[-1]); save(v); sys.exit(0)
raise RuntimeError('unexpected stand-in command '+repr(a))
"""


class CancellationTests(unittest.TestCase):
    def invoke(self, *, interrupt=True, status=0):
        source = (ROOT / "scripts/candidate-docker-gate.sh").read_text()
        start = source.index("set +e\ndocker run --rm --init")
        end = source.index('\nif [[ "$status" -ne 0 ]]', start)
        fragment = source[start:end]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bins = root / "bin"
            bins.mkdir()
            fake = bins / "docker"
            fake.write_text("#!" + sys.executable + "\n" + FAKE_DOCKER)
            fake.chmod(0o755)
            fixture = root / "source/scripts"
            fixture.mkdir(parents=True)
            # Only host-pressure measurement is outside this cancellation test.
            (fixture / "candidate-host-pressure.py").write_text("raise SystemExit(0)\n")
            (fixture / "candidate-volumes.py").write_bytes(
                (ROOT / "scripts/candidate-volumes.py").read_bytes()
            )
            logs = root / "logs"
            logs.mkdir()
            (logs / "owned-resources.tsv").touch()
            (logs / "host-before.json").write_text("{}")
            work = root / "aweb-candidate-work.control"
            work.mkdir()
            (root / "resources.json").write_text(
                json.dumps(
                    {
                        "container": ["owned-runner"],
                        "network": ["owned-network"],
                        "volume": ["owned-workspace", "owned-postgres", "owned-redis"],
                    }
                )
            )
            variables = set(re.findall(r"\$(?:\{)?([A-Za-z_][A-Za-z_0-9]*)", fragment))
            setup = "\n".join(
                name + "=fixture" for name in sorted(variables - {"PATH", "status"})
            )
            program = root / "control.sh"
            program.write_text(
                "set -euo pipefail\n"
                + setup
                + "\n"
                + "suite_projects=(one two three four five)\n"
                + 'ROOT="$CONTROL_ROOT/source"\nwork="$CONTROL_ROOT/aweb-candidate-work.control"\n'
                + 'LOG_DIR="$CONTROL_ROOT/logs"\nrunner_name=owned-runner\nresource_label=owned\n'
                + 'source "$CLEANUP_SOURCE"\ntrap \'cleanup "$?"\' EXIT\n'
                + "trap 'cleanup 143' TERM\n"
                + fragment
                + '\nexit "$status"\n'
            )
            env = dict(
                os.environ,
                PATH=str(bins) + os.pathsep + os.environ["PATH"],
                CONTROL_ROOT=str(root),
                CLEANUP_SOURCE=str(ROOT / "scripts/candidate-cleanup.sh"),
                CONTROL_SECONDS="30" if interrupt else ".05",
                CONTROL_EXIT=str(status),
            )
            process = subprocess.Popen(
                ["bash", str(program)],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                start_new_session=True,
            )
            try:
                ready_deadline = time.monotonic() + 3
                while (
                    not (root / "ready").exists()
                    and process.poll() is None
                    and time.monotonic() < ready_deadline
                ):
                    time.sleep(0.01)
                self.assertTrue((root / "ready").exists(), "long runner never started")
                sent = time.monotonic()
                if interrupt:
                    os.kill(process.pid, signal.SIGTERM)
                output, _ = process.communicate(timeout=5 if interrupt else 10)
                elapsed = time.monotonic() - sent
                self.assertEqual(
                    process.returncode, 143 if interrupt else status, output
                )
                self.assertIn("candidate gate cleanup PASSED", output)
                self.assertEqual(
                    json.loads((root / "resources.json").read_text()),
                    {"container": [], "network": [], "volume": []},
                )
                self.assertTrue((root / "child-exited").exists())
                self.assertEqual((root / "natural-completion").exists(), not interrupt)
                self.assertIn(
                    "absence-owned-volumes\tnone",
                    (logs / "owned-resources.tsv").read_text(),
                )
                if interrupt:
                    print(
                        f"local stand-in TERM-to-cleanup={elapsed:.3f}s; natural child=30s; owned sets empty"
                    )
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                process.communicate(timeout=3)

    def test_term_stops_long_runner_and_actual_cleanup_before_natural_completion(self):
        self.invoke()

    def test_normal_pipeline_success_keeps_status(self):
        self.invoke(interrupt=False)

    def test_normal_pipeline_failure_survives_successful_tee_and_cleanup(self):
        self.invoke(interrupt=False, status=37)


if __name__ == "__main__":
    unittest.main(verbosity=2)
