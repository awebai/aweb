"""Fault-injection decision controls, not Linux kernel qualification."""
import hashlib
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

import lab_control
from lab_process import Containment


class FaultControls(unittest.TestCase):
    def test_launch_interrupted_without_returned_handle_still_terminates_owned_cgroup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            invocation = root / 'invocation.json'
            output = root / 'result'
            source = {'test_contain.py': 'a' * 64}
            data = dict(schema_version=1, ordinal=1, entry='test_contain.py', args=['-v'], source_sha256=source,
                        containment_id='preserve-control-' + 'a' * 32,
                        window_started_unix_seconds=time.time() - 1, window_ends_unix_seconds=time.time() + 2000,
                        interpreter='/usr/bin/python3', source_directory=str(root),
                        output_directory=str(output), work_directory=str(output / 'private-work'))
            invocation.write_text(json.dumps(data))
            owned = mock.Mock(path=root / 'owned-cgroup', fd=12)
            owned.stop.return_value = {'verdict': 'UNKNOWN', 'populated': False,
                                      'all_children_reaped': True, 'kernel_kill_attempted': True}
            args = ['lab_control.py', '--invocation', str(invocation), '--invocation-sha256',
                    hashlib.sha256(invocation.read_bytes()).hexdigest(), '--source', str(root), '--out', str(output)]
            with mock.patch.object(lab_control.sys, 'argv', args), \
                 mock.patch.object(lab_control.sys, 'version_info', (3, 12)), \
                 mock.patch.object(lab_control.os, 'geteuid', return_value=0), \
                 mock.patch.object(lab_control.os, 'chown'), \
                 mock.patch.object(lab_control, 'snapshot', return_value=source), \
                 mock.patch.object(lab_control, 'Containment', return_value=owned), \
                 mock.patch.object(lab_control.subprocess, 'Popen', side_effect=InterruptedError('after fork')):
                self.assertEqual(lab_control.main(), 1)
            owned.stop.assert_called_once()
            self.assertIsNone(owned.stop.call_args.args[0])
            result = json.loads((output / 'result.json').read_text())
            self.assertEqual(result['primary'], 'INTERRUPTED')
            self.assertEqual(result['process']['verdict'], 'UNKNOWN')
            self.assertEqual(result['final'], 'FAIL')
            self.assertTrue(result['process']['kernel_kill_attempted'])

    def test_failed_preliminary_observation_does_not_skip_kernel_kill(self):
        owned = Containment.__new__(Containment)
        owned.path = mock.MagicMock()
        (owned.path / 'cgroup.procs').read_text.side_effect = PermissionError('observe failed')
        owned.write = mock.Mock()
        owned.populated = mock.Mock(return_value=False)
        owned.close_empty = mock.Mock()
        with mock.patch('lab_process.os.waitpid', side_effect=ChildProcessError()):
            result = owned.stop(None, time.monotonic() + 1)
        owned.write.assert_called_once_with('cgroup.kill', '1')
        self.assertTrue(result['kernel_kill_attempted'])
        self.assertFalse(result['populated'])
        self.assertTrue(result['all_children_reaped'])
        self.assertEqual(result['verdict'], 'UNKNOWN')
        self.assertEqual(result['errors'][0]['phase'], 'preliminary-observation')


if __name__ == '__main__':
    unittest.main()
