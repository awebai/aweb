"""The selected VM type activates the unit default; portable callers stay serial."""

from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

from vm_gate.executor import Executor
from vm_gate.runtime import Runtime


class UnitProfileTests(unittest.TestCase):
    def test_selected_host_type_reaches_the_real_execution_environment(self):
        for host_type, profile in [
            ("ccx33", "ccx33"),
            ("ccx43", "portable"),
            (None, "portable"),
        ]:
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
                executor = Executor(runtime.config, Path(tmp), {}, "true", None)
                self.assertIn("AWEB_GATE_UNIT_PROFILE=" + profile, executor.env())
                self.assertIn("GOTOOLCHAIN=local", executor.env())
                self.assertTrue(
                    executor.env().startswith("env -i HOME=/home/gateuser ")
                )
