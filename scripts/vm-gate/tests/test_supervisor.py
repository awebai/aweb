"""Real process-group termination, bounded escalation and collection ordering."""
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

import test_lifecycle
from vm_gate import supervisor
from vm_gate.executor import Executor


class SupervisorTests(unittest.TestCase):
    def invoke(self, body, *, stop=False, grace=.5):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        command = [sys.executable, '-m', 'vm_gate.supervisor', 'run', str(root), str(grace), 'bash', '-c', body]
        child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            if stop:
                deadline = time.monotonic() + 5
                while not (root / 'ready').exists() and child.poll() is None and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertTrue((root / 'ready').exists())
                child.send_signal(signal.SIGTERM)
            stdout, stderr = child.communicate(timeout=5)
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate()
        receipt = json.loads((root / 'supervisor-receipt.json').read_text())
        return child.returncode, receipt, root, stdout + stderr

    def test_normal_exit_is_preserved(self):
        code, receipt, _, output = self.invoke('exit 7')
        self.assertEqual(code, 7, output)
        self.assertEqual(receipt['child_exit'], 7)
        self.assertFalse(receipt['interrupted'])

    def test_term_allows_finalizer_before_completion_receipt(self):
        code, receipt, root, output = self.invoke(
            'trap \'echo finalized > "$PWD/finalized"; exit 143\' TERM; touch ready; sleep 30', stop=True)
        self.assertEqual(code, 143, output)
        self.assertTrue((root / 'finalized').exists())
        self.assertEqual(receipt['signal'], signal.SIGTERM)
        self.assertFalse(receipt['grace_expired'])
        self.assertTrue(receipt['group_settled'])
        self.assertEqual((root / 'gate-exit').read_text().strip(), '143')

    def test_signal_resistant_group_is_killed_within_grace(self):
        started = time.monotonic()
        code, receipt, _, output = self.invoke("trap '' TERM; touch ready; while :; do sleep 30; done", stop=True, grace=.15)
        self.assertEqual(code, 143, output)
        self.assertTrue(receipt['grace_expired'])
        self.assertEqual(receipt['child_exit'], -signal.SIGKILL)
        self.assertLess(time.monotonic() - started, 4)

    def test_stop_identity_refuses_reused_pid(self):
        with self.assertRaisesRegex(ValueError, 'PID identity changed'):
            supervisor.validate_identity({'pid': os.getpid(), 'uid': 1000, 'start_ticks': 'wrong'}, '/unrelated')

    def test_timeout_is_inside_runuser_and_has_grace(self):
        class Transport:
            def __init__(self):
                self.commands = []

            def run(self, command, **kwargs):
                self.commands.append(command)
                return subprocess.CompletedProcess([], 0, json.dumps({'grace_expired': False, 'raw_exit': 7}) if 'cat /var/log/vm-gate/supervisor' in command else '7\n' if command.startswith('cat ') else '', '')

        with tempfile.TemporaryDirectory() as temporary:
            remote = Executor({'ledger': '/ledger/rows', 'owner': 'operator'}, temporary, {}, 'exit 7', None)
            remote.transport = Transport()
            self.assertEqual(remote.execute({}, 60), 7)
            command = remote.transport.commands[1]
            self.assertLess(command.index('runuser'), command.index('timeout --signal=TERM'))
            self.assertIn('vm_gate.supervisor run', command)
            self.assertIn('--kill-after=130s', command)


class StopOrderingTests(unittest.TestCase):
    def test_operator_interrupt_stops_before_collect_and_delete(self):
        events = []

        class Interrupted(test_lifecycle.Remote):
            def execute(self, server, timeout):
                raise KeyboardInterrupt

            def stop(self, server, timeout):
                events.append('stop')
                return {'finalized': False, 'reason': 'no receipt before bounded grace'}

            def collect(self, server, timeout):
                events.append('collect')
                return super().collect(server, timeout)

        fixture = test_lifecycle.LifecycleTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        result = fixture.run_session(Interrupted())
        self.assertEqual(events, ['stop', 'collect'])
        self.assertFalse(result['remote_stop']['finalized'])
        self.assertTrue(result['partial_evidence'])
        self.assertNotEqual(result['exit'], 0)
        self.assertEqual(fixture.backend.items, [])
