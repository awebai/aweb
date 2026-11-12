from pathlib import Path
import tempfile,json,unittest
from vm_gate.config_lease import ConfigLease
from vm_gate.errors import Refused

class ConfigLeaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'operator.json';self.path.write_text(json.dumps({'snapshot_id':1}))
        self.config={'config_path':str(self.path),'snapshot_id':1}
    def test_parallel_runs_share_config_but_snapshot_cannot_delete_their_base(self):
        with ConfigLease(self.config),ConfigLease(self.config):
            with self.assertRaisesRegex(Refused,'configuration is in use'):
                with ConfigLease(self.config,exclusive=True):pass
    def test_atomic_config_replacement_does_not_drop_the_lock(self):
        with ConfigLease(self.config,exclusive=True):
            replacement=self.path.with_suffix('.tmp');replacement.write_text(self.path.read_text());replacement.replace(self.path)
            with self.assertRaises(Refused):
                with ConfigLease(self.config):pass
    def test_stale_snapshot_config_refuses_before_provider(self):
        self.path.write_text(json.dumps({'snapshot_id':2}))
        with self.assertRaisesRegex(Refused,'snapshot configuration changed'):
            with ConfigLease(self.config):pass

if __name__=='__main__':unittest.main()
