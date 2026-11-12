from pathlib import Path
import tempfile
import unittest
from vm_gate.snapshot import rebuild
from vm_gate.errors import Infrastructure

class Fake:
    def __init__(self):self.calls=[];self.config='old';self.new='new';self.fail=False
    def reserve(self):self.calls.append('reserve')
    def builder(self):self.calls.append('builder');return 1
    def install(self,server):self.calls.append('install')
    def seal(self,server):self.calls.append('seal-protected-image');return self.new
    def delete_vm(self,server):self.calls.append('delete-vm-'+str(server))
    def restore(self,image):self.calls.append('restore-'+image);return 2
    def verify(self,server):
        self.calls.append('verify')
        if self.fail:raise Infrastructure('host contract mismatch')
        return {'required':{'go':'version'},'commands':{'go':'hash'}}
    def publish_config(self,image,manifest):self.calls.append('publish-config');self.config=image
    def delete_old(self):self.calls.append('delete-old')
    def cleanup(self):self.calls.append('cleanup-transients')
    def settle(self):self.calls.append('settle')

class SnapshotTests(unittest.TestCase):
    def test_restore_verification_precedes_config_and_old_deletion(self):
        f=Fake();result=rebuild(f)
        self.assertEqual(f.config,'new');self.assertEqual(result['snapshot'],'new')
        self.assertLess(f.calls.index('delete-vm-1'),f.calls.index('restore-new'))
        self.assertLess(f.calls.index('verify'),f.calls.index('publish-config'))
        self.assertLess(f.calls.index('publish-config'),f.calls.index('delete-old'))
    def test_failed_restore_preserves_old_and_reports_orphan_new(self):
        f=Fake();f.fail=True
        with self.assertRaises(Infrastructure) as got:rebuild(f)
        self.assertEqual(got.exception.snapshot,'new');self.assertEqual(f.config,'old')
        self.assertNotIn('delete-old',f.calls);self.assertIn('cleanup-transients',f.calls)
    def test_failed_builder_still_cleans_without_deleting_old(self):
        f=Fake()
        def fail(*args):raise Infrastructure('install failed')
        f.install=fail
        with self.assertRaises(Infrastructure):rebuild(f)
        self.assertEqual(f.config,'old');self.assertIn('cleanup-transients',f.calls)
        self.assertNotIn('delete-old',f.calls)

if __name__=='__main__':unittest.main()
