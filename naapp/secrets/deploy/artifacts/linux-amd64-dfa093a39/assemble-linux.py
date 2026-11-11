"""Unprivileged Lab3 packaging of exact reviewed source; never executes target ELF."""
import hashlib,json,os,shutil,stat,subprocess,tarfile,zipfile
from email.parser import BytesParser
from pathlib import Path
SOURCE='dfa093a396409e4132cf96127a3c30a48e71f7f8'
work=Path.cwd(); out=Path(os.environ['LAB3_OUTPUT']).resolve()
commands=[]
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def run(argv):
    commands.append(argv)
    subprocess.run(argv,check=True)
assert subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()==SOURCE
assert not subprocess.check_output(['git','status','--porcelain'],text=True).strip()
(out/'wheels').mkdir(exist_ok=True)
(out/'build-constraints.txt').write_text('hatchling==1.32.4\n')
for project in ['naapp/secrets/runner','naapp/secrets/values','naapp-lib']:
    run(['uv','build','--wheel','--python','3.13.15','--build-constraints',str(out/'build-constraints.txt'),'--out-dir',str(out/'wheels'),project])
run(['uv','export','--project','naapp/secrets/runner','--frozen','--no-dev','--no-emit-local','--output-file',str(out/'runtime-requirements.txt')])
run(['uv','run','--isolated','--no-project','--python','3.13.15','--with','pip','python','-m','pip','download','--require-hashes','--only-binary=:all:','--no-deps','--platform','manylinux_2_34_x86_64','--platform','manylinux_2_28_x86_64','--platform','manylinux_2_17_x86_64','--platform','manylinux2014_x86_64','--implementation','cp','--python-version','313','--abi','cp313','--abi','abi3','--abi','none','--dest',str(out/'wheels'),'-r',str(out/'runtime-requirements.txt')])
local_source_checks=[]
for package,source_prefix in {'aweb_secrets_runner':'naapp/secrets/runner/src/','aweb_secrets_values':'naapp/secrets/values/src/','aweb_naapp':'naapp-lib/src/'}.items():
    wheel=next((out/'wheels').glob(package+'-*.whl'));count=0
    with zipfile.ZipFile(wheel) as z:
        for member in z.namelist():
            if member.endswith('/') or '.dist-info/' in member:continue
            expected=subprocess.check_output(['git','show',SOURCE+':'+source_prefix+member],cwd=work)
            assert z.read(member)==expected,(wheel.name,member)
            count+=1
    local_source_checks.append({'wheel':wheel.name,'files':count,'source_prefix':source_prefix,'status':'byte-identical-to-git-source'})
archive=out.parent/'linux-runner-candidate/cpython-3.13.15+20260929-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz'
assert digest(archive)=='c552deaf9ed0e678dee4ccc760d6dcd7cab33f1bd43e8037123b4a4db8508e14'
unpacked=out/'unpacked'
if unpacked.exists():shutil.rmtree(unpacked)
unpacked.mkdir()
# Optional terminal databases have case-only aliases on Linux; they collide on
# the macOS build volume. No runner path imports curses or reads terminfo.
with tarfile.open(archive) as tf:
    members=[m for m in tf.getmembers() if not (m.name=='python/share/terminfo' or m.name.startswith('python/share/terminfo/'))]
    tf.extractall(unpacked,members=members,filter='data')
prefix=out/'prefix';prefix.mkdir()
shutil.copytree(unpacked/'python',prefix/'runtime',symlinks=False,ignore=shutil.ignore_patterns('__pycache__'))
requirements=[];wheels={}
for wheel in sorted((out/'wheels').glob('*.whl')):
    with zipfile.ZipFile(wheel) as z:
        md=BytesParser().parsebytes(z.read(next(n for n in z.namelist() if n.endswith('.dist-info/METADATA'))))
    wheels[wheel.name]=digest(wheel)
    requirements.append(f"{md['Name']}=={md['Version']} --hash=sha256:{digest(wheel)}\n")
(out/'wheelhouse-requirements.txt').write_text(''.join(requirements))
site=prefix/'runtime/lib/python3.13/site-packages'
run(['uv','pip','install','--target',str(site),'--python-version','3.13','--python-platform','x86_64-manylinux_2_34','--no-deps','--no-index','--find-links',str(out/'wheels'),'--require-hashes','-r',str(out/'wheelhouse-requirements.txt')])
(prefix/'bin').mkdir();(prefix/'libexec').mkdir()
shebang='#!/opt/aweb-secrets-e2e/runtime/bin/python3.13 -I\n'
(prefix/'bin/aweb-secrets-runner').write_text(shebang+'from aweb_secrets_runner.main import main\nraise SystemExit(main())\n')
(prefix/'bin/aweb-secrets-supervisor').write_text(shebang+(work/'naapp/secrets/e2e/runner_supervisor.py').read_text())
shutil.copyfile(work/'naapp/secrets/e2e/upstream/cli.py',prefix/'libexec/upstream-cli.py')
for path in prefix.rglob('*'):
    if path.is_symlink() or path.name=='pyvenv.cfg':raise RuntimeError('unflattened or venv path')
    if path.is_dir():path.chmod(0o755)
    elif path.is_file():
        raw=path.read_bytes()
        if raw.startswith(b'#!') and b'python' in raw.partition(b'\n')[0]:
            path.write_bytes(shebang.encode()+raw.partition(b'\n')[2])
        path.chmod(0o755 if (path.stat().st_mode & 0o111 or path.parent==prefix/'bin') else 0o644)
files=[];native=[]
for path in sorted(prefix.rglob('*')):
    item={'path':str(path.relative_to(prefix)),'mode':oct(stat.S_IMODE(path.stat().st_mode))}
    if path.is_file():
        item.update(sha256=digest(path),bytes=path.stat().st_size)
        with path.open('rb') as f:header=f.read(20)
        if header.startswith(b'\x7fELF'):
            assert header[4:6]==b'\x02\x01' and int.from_bytes(header[18:20],'little')==62
            native.append(item['path'])
    files.append(item)
manifest={'status':'cross-built-unprivileged-not-installed-not-native-qualified','source_sha':SOURCE,'source_tree':subprocess.check_output(['git','rev-parse','HEAD^{tree}'],text=True).strip(),'omitted_optional_data':['share/terminfo (unused by runner; Linux case aliases collide on macOS builder)'],'target':'linux/amd64 Ubuntu24.04','prefix':'/opt/aweb-secrets-e2e','python_archive_sha256':digest(archive),'interpreter_sha256':digest(prefix/'runtime/bin/python3.13'),'cli_sha256':digest(prefix/'libexec/upstream-cli.py'),'archive_header_owner':{'uid':0,'gid':0,'uname':'root','gname':'root'},'local_wheel_source_parity':local_source_checks,'supervisor_source_sha256':digest(work/'naapp/secrets/e2e/runner_supervisor.py'),'wheels':wheels,'files':files,'elf_x86_64':native,'locks':{p:digest(work/p) for p in ['naapp/secrets/runner/uv.lock','naapp/secrets/values/uv.lock','naapp-lib/uv.lock']}}
(out/'staged-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
(out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
def root_header(member):
    member.uid=member.gid=0;member.uname=member.gname='root'
    return member
with tarfile.open(out/'runner-linux-amd64-dfa093a39.tar.gz','w:gz',dereference=True) as tf:
    tf.add(prefix,arcname='aweb-secrets-e2e',recursive=True,filter=root_header)
with tarfile.open(out/'runner-linux-amd64-dfa093a39.tar.gz') as tf:
    assert all((m.uid,m.gid,m.uname,m.gname)==(0,0,'root','root') and not m.mode & 0o022 for m in tf.getmembers())
(out/'SHA256SUMS').write_text(''.join(f'{digest(p)}  {p.name}\n' for p in [out/'runner-linux-amd64-dfa093a39.tar.gz',out/'staged-manifest.json']))
shutil.rmtree(unpacked)
assert subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()==SOURCE
assert not subprocess.check_output(['git','status','--porcelain'],text=True).strip()
print(json.dumps({'files':len(files),'wheels':len(wheels),'elf_x86_64':len(native),'file_bytes':sum(i.get('bytes',0) for i in files),'interpreter_sha256':manifest['interpreter_sha256']}))
