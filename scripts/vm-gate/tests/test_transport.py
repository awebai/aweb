from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
from vm_gate.transport import Transport

class TransportTests(unittest.TestCase):
    def test_alias_is_per_server_and_child_does_not_inherit_token(self):
        with tempfile.TemporaryDirectory() as directory:
            t=Transport(Path(directory),'192.0.2.1',11)
            with patch.dict('os.environ',{'HCLOUD_TOKEN':'fixture-secret'},clear=True),patch('subprocess.run',return_value=SimpleNamespace(returncode=0,stdout='',stderr='')) as run:
                t.run('true',timeout=10)
            args=run.call_args.args[0];kwargs=run.call_args.kwargs
            self.assertIn('HostKeyAlias=aweb-vm-gate-server-11',args)
            self.assertNotIn('HCLOUD_TOKEN',kwargs['env'])
            other=Transport(Path(directory),'192.0.2.1',12)
            self.assertNotEqual(t.options,other.options)
    def test_transfer_is_an_argument_vector_with_same_identity_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            t=Transport(Path(directory),'192.0.2.1',11)
            with patch('subprocess.run',return_value=SimpleNamespace(returncode=0,stdout='',stderr='')) as run:
                t.copy(Path(directory)/'with spaces','/opt/vm-gate/input',timeout=10)
            args=run.call_args.args[0]
            self.assertEqual(args[-2],str(Path(directory)/'with spaces'))
            self.assertIn('HostKeyAlias=aweb-vm-gate-server-11',args)

if __name__=='__main__':unittest.main()
