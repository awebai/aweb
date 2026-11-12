import unittest
from vm_gate.host_contract import verify_receipt,verify_recording
from vm_gate.errors import Refused

SHA='a'*40
class HostContractTests(unittest.TestCase):
    def setUp(self):
        self.required={'go':'1.2.3','uv':'0.1','node':'22','python':'3.12'}
        self.receipt={'uid':1000,'sha':SHA,'observed':dict(self.required),
                      'commands':{'go':{'sha256':'hash'}},'dpkg':'pkg=1\n','gotoolchain':'local'}
        self.expected={'commands':{'go':{'sha256':'hash'}},'dpkg':'pkg=1\n'}
    def check(self):return verify_receipt(self.receipt,self.required,self.expected,SHA)
    def test_valid_source_derived_host_receipt(self):self.check()
    def test_root_never_reaches_gate(self):
        self.receipt['uid']=0
        with self.assertRaisesRegex(Refused,'UID 0'):self.check()
    def test_local_toolchain_and_exact_sha_required(self):
        for key,value in [('sha','b'*40),('gotoolchain','auto')]:
            receipt=dict(self.receipt);self.receipt[key]=value
            with self.assertRaises(Refused):self.check()
            self.receipt=receipt
    def test_binary_or_dpkg_changes_refuse_even_with_same_version(self):
        self.receipt['commands']['go']['sha256']='changed'
        with self.assertRaisesRegex(Refused,'binary hashes'):self.check()
        self.receipt['commands']={'go':{'sha256':'hash'}};self.receipt['dpkg']='pkg=2\n'
        with self.assertRaisesRegex(Refused,'package manifest'):self.check()
    def test_mismatch_names_tool_versions_sha_and_snapshot_repair(self):
        self.receipt['observed']['go']='wrong'
        with self.assertRaisesRegex(Refused,'go required 1.2.3, observed wrong.*'+SHA+'.*snapshot'):self.check()

    def test_snapshot_recording_allows_only_pin_tools_and_no_os_package_drift(self):
        self.expected['commands']['docker']={'sha256':'old-docker'}
        self.receipt['commands']['docker']={'sha256':'old-docker'}
        self.receipt['commands']['go']={'sha256':'new-go'}
        verify_recording(self.receipt,self.required,self.expected,SHA)
        self.receipt['commands']['docker']={'sha256':'changed-docker'}
        with self.assertRaisesRegex(Refused,'unrelated binary'):
            verify_recording(self.receipt,self.required,self.expected,SHA)

if __name__=='__main__':unittest.main()
