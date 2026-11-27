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
    def test_the_plan_changes_only_the_memory(self):
        small = runner_args("owned-network", "172.20.0.2", "owned-image")
        large = runner_args("owned-network", "172.20.0.2", "owned-image", 11)
        for args in (small, large):
            self.assertFalse(any(a.startswith("--cpu") for a in args), args)
        for option, low, high in [
            ("--memory", f"{module.RUNNER_MEMORY_MIB}m", f"{module.runner_memory_mib(11)}m"),
        ]:
            at = small.index(option) + 1
            self.assertEqual(small[at], low)
            self.assertEqual(large[at], high)
            large[at] = small[at]
        # The worker count adds only its own environment entry.
        at = large.index("AWEB_SERVER_TEST_WORKERS=11")
        self.assertEqual(large[at - 1], "-e")
        del large[at - 1 : at + 1]
        self.assertEqual(small, large)
        self.assertEqual(small[small.index("--user") + 1], "1000:1000")
        self.assertEqual(small[small.index("--network") + 1], "owned-network")
        self.assertEqual(small[small.index("--pids-limit") + 1], "2048")
        self.assertEqual(small[small.index("--dns-search") + 1], ".")
        self.assertFalse(any("docker.sock" in value for value in small))

    def test_each_suite_runner_has_its_own_name(self):
        names = {
            runner_args("net", "172.20.0.2", "image", name=suite)[
                runner_args("net", "172.20.0.2", "image", name=suite).index("--name") + 1
            ]
            for suite in ("test-server", "test-awid", "_candidate-unit-pi")
        }
        self.assertEqual(len(names), 3)


if __name__ == "__main__":
    unittest.main()
