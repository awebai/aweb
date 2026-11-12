import hashlib
import io
import tarfile
import unittest
from unittest.mock import patch
from vm_gate.install_tools import install


def archive(files):
    output=io.BytesIO()
    with tarfile.open(fileobj=output,mode='w:gz') as t:
        for name in files:
            data=b'fixture';info=tarfile.TarInfo(name);info.size=len(data);info.mode=0o755
            t.addfile(info,io.BytesIO(data))
    return output.getvalue()

class InstallToolsTests(unittest.TestCase):
    def plans(self):
        data={'go':archive(['go/bin/go']),'uv':archive(['uv/uv','uv/uvx']),
              'node':archive(['node/bin/node'])}
        plans={name:{'filename':name+'.tar.gz','top':name,'url':'https://example.invalid/'+name,
                     'sha256':hashlib.sha256(value).hexdigest(),'version':'fixture'} for name,value in data.items()}
        return data,plans
    def test_bad_checksum_never_replaces_any_tool(self):
        data,plan=self.plans();plan['go']['sha256']='0'*64
        with patch('os.geteuid',return_value=0),patch('urllib.request.urlopen',side_effect=lambda req,**kw:io.BytesIO(data[req.full_url.rsplit('/',1)[-1]])),patch('vm_gate.install_tools.replace_tree') as replace:
            with self.assertRaisesRegex(RuntimeError,'go archive sha256 mismatch'):install(plan)
            replace.assert_not_called()
    def test_verified_downloads_install_without_executing_any_local_binary(self):
        data,plan=self.plans()
        with patch('os.geteuid',return_value=0),patch('urllib.request.urlopen',side_effect=lambda req,**kw:io.BytesIO(data[req.full_url.rsplit('/',1)[-1]])),patch('vm_gate.install_tools.replace_tree') as replace:
            result=install(plan)
        self.assertEqual(len(result),3);self.assertEqual(replace.call_count,3)

if __name__=='__main__':unittest.main()
