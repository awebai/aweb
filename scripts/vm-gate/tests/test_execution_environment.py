"""The guest runs the gate in a clean environment that sizes from the guest."""

from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

from vm_gate.executor import Executor
from vm_gate.runtime import Runtime


class ExecutionEnvironmentTests(unittest.TestCase):
    def test_every_host_type_gets_the_same_clean_environment(self):
        for host_type in ("ccx33", "ccx43", None):
            with (
                self.subTest(host_type=host_type),
                tempfile.TemporaryDirectory() as tmp,
            ):
                runtime = Runtime(
                    config={"state_root": tmp},
                    directory=None,
                    source=None,
                    command=None,
                    args=SimpleNamespace(type=host_type),
                    run_id=None,
                )
                env = Executor(runtime.config, Path(tmp), {}, "true", None).env()
                self.assertTrue(env.startswith("env -i HOME=/home/gateuser "))
                self.assertIn("GOTOOLCHAIN=local", env)
                # The gate's budget defaults to the guest's own engine size.
                self.assertNotIn("GATE_CPUS", env)


if __name__ == "__main__":
    unittest.main()
