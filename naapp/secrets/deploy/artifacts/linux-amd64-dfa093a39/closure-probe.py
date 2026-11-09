import hashlib,importlib,importlib.metadata,json,pathlib,platform,subprocess,sys
root=pathlib.Path('/opt/aweb-secrets-e2e')
assert platform.machine()=='x86_64'
paths=[sys.prefix,sys.base_prefix,sys.base_exec_prefix,*sys.path]
assert all(pathlib.Path(p).resolve().is_relative_to(root) for p in paths)
mods={}
for name in ['aweb_secrets_runner','aweb_secrets_values','aweb_naapp','aweb_naapp.pages','httpx','cryptography','cryptography.hazmat.bindings._rust','_ssl','ssl']:
    m=importlib.import_module(name);p=getattr(m,'__file__',None)
    if p:
        q=pathlib.Path(p).resolve();assert q.is_relative_to(root)
        mods[name]={'path':str(q.relative_to(root)),'sha256':hashlib.sha256(q.read_bytes()).hexdigest()}
    else:
        assert m.__spec__.origin in ('built-in','frozen');mods[name]={'origin':m.__spec__.origin}
native={}
for p in sorted(root.rglob('*')):
    if not p.is_file():continue
    with p.open('rb') as f:head=f.read(4)
    if head==b'\x7fELF':
        result=subprocess.run(['ldd',str(p)],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
        assert 'not found' not in result.stdout
        native[str(p.relative_to(root))]=result.stdout.splitlines()
from aweb_naapp.pages import inline_schema_errors,inline_value_valid
assert callable(inline_schema_errors) and callable(inline_value_valid)
print(json.dumps({'status':'emulated-amd64-import-and-ELF-dependency-check-pass','python':sys.version,'machine':platform.machine(),'prefixes':[str(p) for p in paths],'modules':mods,'packages':sorted((d.metadata['Name'],d.version) for d in importlib.metadata.distributions()),'native':native},sort_keys=True))
