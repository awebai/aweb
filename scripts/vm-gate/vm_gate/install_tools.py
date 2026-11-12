"""Run only on the disposable builder. All archives were checksum-planned locally."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import urllib.request


def replace_tree(source,destination):
    destination=Path(destination);backup=destination.with_name(destination.name+'.vm-gate-previous')
    if backup.exists():raise RuntimeError('previous tool install was not cleaned')
    if destination.exists():destination.rename(backup)
    source.rename(destination)
    if backup.exists():shutil.rmtree(backup)


def install(plan):
    if os.geteuid()!=0:raise RuntimeError('tool installation requires builder root')
    records=[]
    with tempfile.TemporaryDirectory(prefix='vm-gate-install-',dir='/var/tmp') as tmp:
        root=Path(tmp)
        for tool in ['go','uv','node']:
            item=plan[tool];archive=root/item['filename'];digest=hashlib.sha256()
            request=urllib.request.Request(item['url'],headers={'User-Agent':'aweb-vm-gate'})
            with urllib.request.urlopen(request,timeout=30) as response,archive.open('wb') as f:
                while block:=response.read(1024*1024):digest.update(block);f.write(block)
            if digest.hexdigest()!=item['sha256']:raise RuntimeError(tool+' archive sha256 mismatch')
            unpack=root/(tool+'-unpack');unpack.mkdir()
            with tarfile.open(archive) as t:t.extractall(unpack,filter='data')
            tree=unpack/item['top']
            if tool=='go':replace_tree(tree,'/usr/local/go')
            elif tool=='node':replace_tree(tree,'/opt/node')
            else:
                stage=root/'uv-installed';stage.mkdir(mode=0o755)
                for name in ['uv','uvx']:
                    shutil.copyfile(tree/name,stage/name);(stage/name).chmod(0o755)
                replace_tree(stage,'/opt/uv')
            records.append({'tool':tool,'version':item['version'],'url':item['url'],'sha256':digest.hexdigest()})
    return records

if __name__=='__main__':
    try:print(json.dumps(install(json.loads(Path(sys.argv[1]).read_text())),indent=2))
    except Exception as exc:
        print('snapshot tool installation failed: '+type(exc).__name__,file=sys.stderr);raise SystemExit(70)
