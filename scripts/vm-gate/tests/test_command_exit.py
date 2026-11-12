from pathlib import Path
import subprocess
import tempfile
import unittest
from vm_gate.executor import Executor


class CommandExitTests(unittest.TestCase):
    def test_explicit_focused_exit_cannot_skip_controller_exit_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            remote = Executor({}, Path(tmp), {}, "exit 7", None)
            script = (
                "set +e\n"
                + remote.focused_shell()
                + '\nstatus=$?\nprintf "receipt=%s\\n" "$status"\n'
            )
            result = subprocess.run(
                ["bash", "-c", script], capture_output=True, text=True
            )
        self.assertEqual(
            result.stdout, "receipt=7\n", "focused exit escaped its controller"
        )


if __name__ == "__main__":
    unittest.main()
