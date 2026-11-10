#!/usr/bin/env python3
"""Install selected manifest wheels and prove installed provenance (no sources)."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def selected_wheels(directory, packages):
    document = json.loads((directory / 'manifest.json').read_text())
    selected = []
    for package in packages:
        rows = [row for row in document['files'] if row['package'] == package and row['path'].endswith('.whl')]
        if len(rows) != 1:
            raise ValueError(f'expected one manifest wheel for {package}')
        row = rows[0]
        path = directory / row['path']
        if path.parent.resolve() != directory.resolve():
            raise ValueError(f'invalid manifest wheel path: {path}')
        with path.open('rb') as handle:
            actual = hashlib.file_digest(handle, 'sha256').hexdigest()
        if actual != row['sha256']:
            raise ValueError(f'manifest wheel sha256 mismatch: {path.name}')
        selected.append((row, path))
    return selected


def install(directory, python, packages, *, resolve=False, requirements=()):
    selected = selected_wheels(directory, packages)
    subprocess.run(['uv', 'pip', 'install', '--python', str(python), '--reinstall',
                    *([] if resolve else ['--no-deps']), *requirements, *(str(path) for _, path in selected)], check=True)
    check(directory, python, packages)


def check(directory, python, packages):
    selected = selected_wheels(directory, packages)
    probe = '''
import importlib.metadata as m, json, sys, zipfile
from pathlib import Path
from urllib.parse import unquote, urlparse
import sysconfig
for location in {sysconfig.get_path('purelib'), sysconfig.get_path('platlib')}:
 for pth in Path(location).glob('*.pth'):
  lines = [line.strip() for line in pth.read_text().splitlines() if line.strip() and not line.lstrip().startswith('#')]
  # uv's venv bootstrap is not an editable hook. Every other active .pth
  # fails closed, including unknown executable import hooks and source paths.
  assert not lines or (pth.name == '_virtualenv.pth' and lines == ['import _virtualenv']), ('unapproved .pth', str(pth))
 for direct_path in Path(location).glob('*.dist-info/direct_url.json'):
  provenance = json.loads(direct_path.read_text())
  assert not provenance.get('dir_info', {}).get('editable'), ('editable install', str(direct_path))
for row in json.loads(sys.argv[1]):
 dist = m.distribution(row['package'])
 direct = json.loads(dist.read_text('direct_url.json') or '{}')
 assert not direct.get('dir_info'), (row['package'], 'editable install')
 archive = Path(row['archive'])
 assert Path(unquote(urlparse(direct.get('url', '')).path)).resolve() == archive.resolve(), (row['package'], direct)
 # uv intentionally omits archive hashes for local wheels. Check installed
 # payloads as well as the already-verified input hash and direct URL.
 with zipfile.ZipFile(archive) as wheel:
  for name in wheel.namelist():
   if name.endswith('/') or name.endswith('.dist-info/RECORD'):
    continue
   expected = wheel.read(name)
   target = dist.locate_file(name)
   assert target.read_bytes() == expected, ('installed bytes differ', row['package'], name)
 assert dist.version == row['version'], (row['package'], dist.version, row['version'])
 print('installed manifest wheel: %s %s sha256=%s' % (row['package'], dist.version, row['sha256']), flush=True)
'''
    subprocess.run([str(python), '-I', '-c', probe,
                    json.dumps([{**row, 'archive': str(path)} for row, path in selected])], check=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--python', type=Path, required=True)
    parser.add_argument('--check', action='store_true', help='verify the live environment without installing')
    parser.add_argument('--resolve', action='store_true')
    parser.add_argument('--with', dest='requirements', action='append', default=[])
    parser.add_argument('packages', nargs='+')
    args = parser.parse_args()
    if args.check:
        check(args.directory, args.python, args.packages)
    else:
        install(args.directory, args.python, args.packages, resolve=args.resolve, requirements=args.requirements)
