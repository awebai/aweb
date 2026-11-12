import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from vm_gate.config import load, child_environment
from vm_gate.preflight import read_hcloud_token
from vm_gate.errors import Refused

def hashes():
    return {name:{'path':'/bin/'+name,'target':'/bin/'+name,'sha256':'a'*64}
            for name in ['go','uv','uvx','node','npm','python3','git','make','bash','docker']}

class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.repo=self.root/'repo';self.repo.mkdir()
        self.path=self.root/'config.json'
        self.config={'state_root':str(self.root/'state'),'ledger':str(self.root/'ledger.tsv'),
                     'snapshot_manifest':str(self.root/'manifest.json'),'token_file':str(self.root/'credential'),
                     'owner':'seat','location':'location','datacenter':'datacenter','snapshot_id':1,
                     'cap_eur':'150','seed_eur':'0'}
        (self.root/'manifest.json').write_text(json.dumps({'observed':{'go':'1'},'commands':hashes(),'dpkg':'fixture=1'}))
    def write(self):self.path.write_text(json.dumps(self.config));return self.path
    def test_config_and_state_must_stay_outside_the_repo(self):
        self.config['state_root']=str(self.repo/'state')
        with self.assertRaisesRegex(Refused,'outside'):load(self.write(),self.repo)
    def test_no_default_credential_path_and_no_empty_token(self):
        with patch.dict('os.environ',{},clear=True):
            with self.assertRaisesRegex(Refused,'HCLOUD_TOKEN_FILE'):read_hcloud_token()
        path=self.root/'empty';path.write_text(' ')
        with patch.dict('os.environ',{'HCLOUD_TOKEN_FILE':str(path)},clear=True):
            with self.assertRaisesRegex(Refused,'empty'):read_hcloud_token()
    def test_child_env_cannot_inherit_credentials_or_gate_overrides(self):
        with patch.dict('os.environ',{'HCLOUD_TOKEN_FILE':'private','HCLOUD_TOKEN':'fixture-secret',
                         'AWEB_CANDIDATE_RUNNER_CPUS':'99','SSH_AUTH_SOCK':'agent'},clear=True):
            environment=child_environment()
        for key in ['HCLOUD_TOKEN','HCLOUD_TOKEN_FILE','AWEB_CANDIDATE_RUNNER_CPUS','SSH_AUTH_SOCK']:
            self.assertNotIn(key,environment)
    def test_valid_external_config_loads_recorded_manifest(self):
        result=load(self.write(),self.repo)
        self.assertEqual(result['manifest']['observed']['go'],'1')

    def test_invalid_phase_budget_is_refused_locally(self):
        self.config['setup_seconds']=-1
        with self.assertRaisesRegex(Refused,'setup_seconds'):load(self.write(),self.repo)

    def test_empty_binary_manifest_is_not_a_verified_snapshot(self):
        (self.root/'manifest.json').write_text(json.dumps({'observed':{'go':'1'},'commands':{},'dpkg':'fixture=1'}))
        with self.assertRaisesRegex(Refused,'binary manifest'):load(self.write(),self.repo)

if __name__=='__main__':unittest.main()
