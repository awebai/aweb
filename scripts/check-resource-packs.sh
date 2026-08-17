#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

python3 - <<'PY'
from pathlib import Path
import re
import sys

root = Path('resource-packs')
if not root.exists():
    raise SystemExit('resource-packs/ not found')

for pack in sorted(p for p in root.iterdir() if p.is_dir()):
    manifest = pack / 'resource-pack.yaml'
    readme = pack / 'README.md'
    if not manifest.exists():
        raise SystemExit(f'{pack}: missing resource-pack.yaml')
    if not readme.exists():
        raise SystemExit(f'{pack}: missing README.md')
    text = manifest.read_text()
    if not re.search(r'^schema_version:\s*1\s*$', text, re.M):
        raise SystemExit(f'{manifest}: schema_version: 1 is required')
    if not re.search(r'^name:\s*[-a-zA-Z0-9_]+\s*$', text, re.M):
        raise SystemExit(f'{manifest}: name is required')

    paths = []
    for line in text.splitlines():
        m = re.match(r'^\s{2,4}[-a-zA-Z0-9_]+:\s+(.+?)\s*$', line)
        if not m:
            continue
        value = m.group(1).strip().strip('"\'')
        if value.startswith(('resources/', 'skills/', 'adapters/', 'examples/')) or value == 'README.md':
            paths.append(value)
    for rel in paths:
        if not (pack / rel).exists():
            raise SystemExit(f'{manifest}: referenced path does not exist: {rel}')

    # And the inverse. Checking only declared-then-exists leaves a file that
    # nobody declared invisible: it ships in the pack, no manifest mentions it,
    # and nothing says whether it is content or debris. Both directions together
    # are what make the manifest a classification of the pack rather than a
    # partial index of it.
    declared = set(paths)
    for path in sorted(pack.rglob('*')):
        if not path.is_file():
            continue
        rel = str(path.relative_to(pack))
        if rel == 'resource-pack.yaml' or rel in declared:
            continue
        raise SystemExit(
            f'{manifest}: {rel} is present in the pack but declared nowhere; '
            f'add it to the manifest or remove it'
        )

    role_files = sorted((pack / 'resources' / 'roles').glob('*.md'))
    if role_files and 'aw roles add' not in readme.read_text():
        raise SystemExit(f'{readme}: packs with Markdown roles must teach aw roles add')

    forbidden_file_parts = {'.aw', 'team-certs', 'signing.key', 'encryption.key'}
    for path in pack.rglob('*'):
        parts = set(path.relative_to(pack).parts)
        if parts & forbidden_file_parts:
            raise SystemExit(f'{pack}: forbidden identity-state path: {path}')
        if path.is_file():
            data = path.read_text(errors='ignore')
            for needle in ('did:key:z', 'did:aw:', 'aw_sk_', 'BEGIN PRIVATE KEY', 'certificate:'):
                if needle in data:
                    raise SystemExit(f'{path}: forbidden identity/certificate material marker {needle!r}')

print('resource pack checks passed')
PY
