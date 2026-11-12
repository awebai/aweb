import unittest
from vm_gate.toolplan import go_archive, node_archive, uv_archive
from vm_gate.errors import Refused

class ToolPlanTests(unittest.TestCase):
    def test_go_requires_exact_source_version_platform_and_checksum(self):
        metadata=[{'version':'go1.2.3','files':[{'filename':'go1.2.3.linux-amd64.tar.gz','os':'linux','arch':'amd64','kind':'archive','sha256':'a'*64}]}]
        self.assertEqual(go_archive(metadata,'1.2.3')['sha256'],'a'*64)
        with self.assertRaises(Refused):go_archive(metadata,'1.2.4')
        metadata[0]['files'][0]['sha256']='invalid'
        with self.assertRaises(Refused):go_archive(metadata,'1.2.3')
    def test_node_only_selects_source_major_and_linux_x64_archive(self):
        checks='a'*64+'  node-v22.1.2-linux-x64.tar.gz\n'+'b'*64+'  node-v22.1.2-darwin-arm64.tar.gz\n'
        self.assertEqual(node_archive(checks,'22')['version'],'22.1.2')
        with self.assertRaises(Refused):node_archive(checks,'24')
    def test_uv_requires_release_digest_and_exact_asset(self):
        data={'tag_name':'0.1.2','assets':[{'name':'uv-x86_64-unknown-linux-gnu.tar.gz','digest':'sha256:'+'c'*64,
                 'browser_download_url':'https://github.com/astral-sh/uv/releases/download/0.1.2/uv-x86_64-unknown-linux-gnu.tar.gz'}]}
        self.assertEqual(uv_archive(data,'0.1.2')['sha256'],'c'*64)
        data['assets'][0]['digest']=None
        with self.assertRaises(Refused):uv_archive(data,'0.1.2')

if __name__=='__main__':unittest.main()
