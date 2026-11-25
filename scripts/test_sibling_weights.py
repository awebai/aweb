"""Containers a lane's tests start carry the lane's weight and no CPU cap."""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHIM = ROOT / "candidate-gate/bin/docker"


class SiblingWeights(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.calls = self.tmp / "calls.jsonl"
        real = self.tmp / "real-docker"
        # The real Docker answers Compose's service listing and records calls.
        real.write_text(
            "#!/usr/bin/env python3\n"
            "import json, sys\n"
            f"open({str(self.calls)!r}, 'a').write(json.dumps(sys.argv[1:]) + '\\n')\n"
            "if sys.argv[1:2] == ['compose'] and '--services' in sys.argv:\n"
            "    print('api')\n"
        )
        real.chmod(0o755)
        self.env = {
            "PATH": os.environ["PATH"],
            "AWEB_CANDIDATE_REAL_DOCKER": str(real),
            "AWEB_CANDIDATE_RESOURCE_LABEL": "run-label",
            "AWEB_CANDIDATE_SIBLING_CPU_SHARES": "1431",
            "AWEB_DOCKER_BIND_ROOT": str(self.tmp / "bind"),
        }

    def shim(self, *args):
        result = subprocess.run(
            ["bash", str(SHIM), *args], env=self.env, capture_output=True, text=True, cwd=self.tmp
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return [json.loads(line) for line in self.calls.read_text().splitlines()]

    def test_a_sibling_run_or_create_carries_the_lanes_weight(self):
        for command in ("run", "create"):
            with self.subTest(command=command):
                self.calls.unlink(missing_ok=True)
                args = self.shim(command, "--rm", "postgres:17")[-1]
                self.assertEqual(args[0], command)
                self.assertEqual(args[args.index("--cpu-shares") + 1], "1431")
                self.assertNotIn("--cpus", args)

    def test_a_compose_service_carries_the_lanes_weight(self):
        (self.tmp / "compose.yaml").write_text("services:\n  api:\n    image: x\n")
        calls = self.shim("compose", "up", "-d")
        final = calls[-1]
        overrides = [final[i + 1] for i, a in enumerate(final) if a == "-f" and "limits" in final[i + 1]]
        self.assertEqual(len(overrides), 1, final)
        text = Path(overrides[0]).read_text()
        self.assertIn("cpu_shares: 1431", text)
        self.assertNotIn("cpus:", text)


if __name__ == "__main__":
    unittest.main()
