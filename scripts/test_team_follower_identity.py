"""Real shell/procps checks for the kept capture helpers; Docker is a transport fixture."""

import json
import os
from pathlib import Path
import shlex
import signal
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def capture_functions():
    source = (ROOT / "deploy/team/teamctl").read_text()
    functions = []
    for name in (
        "stop_follower",
        "follower_live",
        "capture_egress",
        "capture_still_live",
    ):
        begin = source.index(name + "() {")
        end = source.index("\n}\n", begin) + 3
        functions.append(source[begin:end])
    return "\n".join(functions)


class FollowerIdentity(unittest.TestCase):
    def check_capture(
        self, *, dead=False, wrong_start=False, wrong_project=False, early_identity=None
    ):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / ("long-install-directory-" * 5)
            root.mkdir()
            docker = root / "docker"
            if early_identity:
                real_ps = shlex.quote(shutil.which("ps"))
                ps = root / "ps"
                ps.write_text(
                    '#!/bin/sh\nif [ "$1 $2" = "-o lstart=" ]; then\n'
                    + (
                        "exit 1\n"
                        if early_identity == "missing"
                        else 'if [ -e "'
                        + str(root / "identity-read")
                        + '" ]; then echo "different process start"; exit 0; fi\ntouch "'
                        + str(root / "identity-read")
                        + '"\n'
                    )
                    + "fi\nexec "
                    + real_ps
                    + ' "$@"\n'
                )
                ps.chmod(0o755)
            docker.write_text(
                '#!/bin/sh\ncase "$1" in\n'
                'logs) echo $$ >"'
                + str(root / "follower.pid")
                + '"; echo "2099-01-01T00:00:00.000000000Z fresh line"; '
                + ("exit 0" if dead else "sleep 15")
                + ';;\ninspect) echo "sha256:'
                + "e" * 64
                + "|"
                + ("otherproject" if wrong_project else "teamrun")
                + '|egress|json-file|2026-11-13T18:00:00Z";;\n'
                "*) exit 99;;\nesac\n"
            )
            docker.chmod(0o755)
            # The production capture algorithm is extracted unchanged. Only
            # Docker responses and its stdlib interpreter transport are fixed.
            script = (
                "set -u\nproject=teamrun\n"
                + "python_in_server() { "
                + shlex.quote(sys.executable)
                + ' "$@"; }\n'
                + "utc_now() { python_in_server -c \"import datetime; print(datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ'))\"; }\n"
                + 'dc() { [[ "$*" == "ps -q egress" ]] || return 99; echo egress-container-id; }\n'
                + capture_functions()
                + "\ncapture_egress\nattached=$?\n"
                + ("CAPTURE_STARTED='different process start'\n" if wrong_start else "")
                + 'if [[ "$attached" -eq 0 ]]; then capture_still_live; status=$?; '
                'kill -0 "$CAPTURE_PID" 2>/dev/null; live=$?; '
                'printf "CHECK %s LIVE %s\\n" "$status" "$live"; exit "$status"; '
                'else for unused in 1 2 3 4 5; do [ -f "'
                + str(root / "follower.pid")
                + '" ] && break; sleep 0.01; done; '
                'kill -0 "$(cat "'
                + str(root / "follower.pid")
                + '")" 2>/dev/null; live=$?; '
                'printf "ATTACH %s LIVE %s\\n" "$attached" "$live"; exit "$attached"; fi\n'
            )
            env = dict(
                os.environ,
                PATH=str(root) + os.pathsep + os.environ["PATH"],
                TEAM_DEPLOYMENT_EGRESS_LOG=str(root / "egress.log"),
                TEAM_DEPLOYMENT_CAPTURE_SECONDS="2",
                COLUMNS="80",
            )
            child = subprocess.Popen(
                ["bash", "-c", script],
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            try:
                stdout, stderr = child.communicate(timeout=10)
            finally:
                try:
                    os.killpg(child.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                child.wait(timeout=3)
            receipt_file = root / "egress.log.receipt.json"
            receipt = (
                json.loads(receipt_file.read_text()) if receipt_file.exists() else None
            )
            return child.returncode, stdout, stderr, receipt, root

    def test_long_path_live_follower_under_narrow_columns_is_accepted(self):
        status, stdout, stderr, receipt, root = self.check_capture()
        self.assertEqual(status, 0, stdout + stderr)
        self.assertIn("still streaming before the agent starts", stdout)
        self.assertIn("CHECK 0 LIVE 0", stdout)
        self.assertIn(str(root / "docker"), receipt["follower_command"])
        self.assertIn(
            "logs --timestamps --follow egress-container-id",
            receipt["follower_command"],
        )

    def test_same_pid_with_a_different_start_is_refused_without_killing_it(self):
        status, stdout, stderr, receipt, _ = self.check_capture(wrong_start=True)
        self.assertEqual(status, 1, stdout + stderr)
        self.assertIn("no longer streaming", stderr)
        self.assertIn("CHECK 1 LIVE 0", stdout)
        self.assertIsNotNone(receipt)

    def test_start_change_during_capture_never_signals_the_changed_process(self):
        status, stdout, stderr, receipt, _ = self.check_capture(
            early_identity="changed"
        )
        self.assertEqual(status, 1, stdout + stderr)
        self.assertIn("ATTACH 1 LIVE 0", stdout)
        self.assertIsNone(receipt)

    def test_missing_initial_identity_never_authorizes_a_signal(self):
        status, stdout, stderr, receipt, _ = self.check_capture(
            early_identity="missing"
        )
        self.assertEqual(status, 1, stdout + stderr)
        self.assertIn("ATTACH 1 LIVE 0", stdout)
        self.assertIsNone(receipt)

    def test_a_follower_that_exited_after_a_fresh_line_is_refused(self):
        status, stdout, stderr, receipt, _ = self.check_capture(dead=True)
        self.assertEqual(status, 1, stdout + stderr)
        self.assertIn("egress capture: the follower exited", stderr)
        self.assertIsNone(receipt)

    def test_valid_follower_does_not_authorize_another_projects_container(self):
        status, stdout, stderr, receipt, _ = self.check_capture(wrong_project=True)
        self.assertEqual(status, 1, stdout + stderr)
        self.assertIn("egress capture: no receipt", stderr)
        self.assertIsNone(receipt)


if __name__ == "__main__":
    unittest.main()
