"""A resource change must leave the actual isolated launch contract intact."""

import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "isolated_docker", Path(__file__).parent / "test-egress" / "docker.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
runner_args = module.runner_args


class RunnerResources(unittest.TestCase):
    def test_ccx33_changes_only_cpu_and_memory(self):
        portable = runner_args("owned-network", "172.20.0.2", "owned-image")
        measured = runner_args("owned-network", "172.20.0.2", "owned-image", "ccx33")
        for option, default, ccx33 in [("--cpus", "2", "7"), ("--memory", "8g", "16g")]:
            at = portable.index(option) + 1
            self.assertEqual(portable[at], default)
            self.assertEqual(measured[at], ccx33)
            measured[at] = portable[at]
        self.assertEqual(portable, measured)
        self.assertEqual(portable[portable.index("--user") + 1], "1000:1000")
        self.assertEqual(portable[portable.index("--network") + 1], "owned-network")
        self.assertEqual(portable[portable.index("--pids-limit") + 1], "2048")
        self.assertEqual(portable[portable.index("--dns-search") + 1], ".")
        self.assertFalse(any("docker.sock" in value for value in portable))


if __name__ == "__main__":
    unittest.main()
