#!/usr/bin/env python3
"""Gate cleanup of a runner that Docker is already removing, with real Docker."""

import os
import shutil
import subprocess
import tempfile
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "alpine:3"

# A runner started with docker run --rm is removed by the daemon when its CLI
# is TERMed, so cleanup's own removal can race the daemon's and get "removal
# already in progress". The wrapper below returns that daemon reply after the
# real removal, so the race is deterministic; the runner and every absence
# check are real Docker. Host measurement is a stand-in.
SCRIPT = r"""
set -uo pipefail
source "$ROOT/scripts/candidate-cleanup.sh"
resource_label="$LABEL"
runner_name="$LABEL-runner"
IMAGE="aweb-candidate-gate-absent:$LABEL"
suite_projects=("$LABEL-project")
work="$LOG_DIR/aweb-candidate-work.fixture"
buildx_config="$LOG_DIR/buildx"
mkdir -p "$work"
: > "$LOG_DIR/owned-resources.tsv"
printf '{}\n' > "$LOG_DIR/host-before.json"
python3() { return 0; }
docker run --rm --init --name "$runner_name" --label "aweb.candidate-gate=$resource_label" \
  "$RUNNER_IMAGE" sleep 100 >/dev/null 2>&1 &
until docker container inspect "$runner_name" >/dev/null 2>&1; do sleep .05; done
until [[ "$(docker container inspect --format '{{.State.Running}}' "$runner_name" 2>/dev/null)" == true ]]; do sleep .05; done
if [[ "$RETAIN_WORK" == 1 ]]; then rm() { :; }; fi
docker() {
  if [[ "$1" == rm && " $* " == *" $runner_name "* ]]; then
    if [[ "$KEEP_RUNNER" == 0 ]]; then command docker rm -fv "$runner_name" >/dev/null; fi
    printf 'Error response from daemon: removal of container %s is already in progress\n' "$runner_name" >&2
    return 1
  fi
  command docker "$@"
}
cleanup 0
"""


def docker_ready():
    if shutil.which("docker") is None:
        return False
    probe = subprocess.run(
        ["docker", "image", "inspect", IMAGE], capture_output=True, text=True
    )
    return probe.returncode == 0


@unittest.skipUnless(docker_ready(), f"needs Docker with {IMAGE} already present")
class RunnerCleanup(unittest.TestCase):
    def cleanup(self, keep_runner=False, retain_work=False):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        logs = Path(temporary.name)
        label = "aweb-cleanup-test-" + uuid.uuid4().hex[:12]
        self.addCleanup(
            subprocess.run,
            ["docker", "rm", "-fv", label + "-runner"],
            capture_output=True,
        )
        result = subprocess.run(
            ["bash", "-c", SCRIPT],
            env=dict(
                os.environ,
                ROOT=str(ROOT),
                LOG_DIR=str(logs),
                LABEL=label,
                RUNNER_IMAGE=IMAGE,
                KEEP_RUNNER=str(int(keep_runner)),
                RETAIN_WORK=str(int(retain_work)),
            ),
            capture_output=True,
            text=True,
            timeout=120,
        )
        return result, (logs / "owned-resources.tsv").read_text()

    def test_runner_the_daemon_is_already_removing_passes(self):
        # Absence, not the removal command's exit, is the proof.
        result, manifest = self.cleanup()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr + manifest)
        self.assertIn("candidate gate cleanup PASSED", result.stdout)

    def test_runner_that_stays_fails_and_names_itself(self):
        result, manifest = self.cleanup(keep_runner=True)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("candidate gate cleanup FAILED", result.stderr + result.stdout)
        self.assertIn("cleanup-failure\trunner still present", manifest)


    def test_retained_work_directory_fails_and_names_itself(self):
        result, manifest = self.cleanup(retain_work=True)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("cleanup-failure\twork directory not removed", manifest)


if __name__ == "__main__":
    unittest.main()
