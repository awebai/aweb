"""Whole-module Secrets partition, qualified against real pytest collection."""
import json
import os
import subprocess
from pathlib import Path


def load_shards(package: Path, manifest: Path) -> list[list[str]]:
    data = json.loads(manifest.read_text())
    shards = data.get('shards')
    if data.get('version') != 1 or not isinstance(shards, list) or len(shards) != 2:
        raise ValueError('expected version 1 and exactly two shards')
    seen = set()
    for shard in shards:
        if not isinstance(shard, list) or not shard:
            raise ValueError('empty or invalid shard')
        for module in shard:
            if not isinstance(module, str):
                raise ValueError('module must be a path string')
            path = Path(module)
            if (not path.parts or path.is_absolute() or '..' in path.parts or path.parts[0] != 'tests'
                    or path.suffix != '.py' or module in seen
                    or not (package / path).is_file()
                    or not (package / path).resolve().is_relative_to(package.resolve())):
                raise ValueError(f'invalid, duplicate or missing module: {module}')
            seen.add(module)
    return shards


def validate_collections(full: list[str], shards: list[list[str]]) -> list[int]:
    if not full or len(full) != len(set(full)) or len(shards) != 2:
        raise ValueError('empty or duplicate unsharded collection, or invalid partition')
    seen = set()
    for shard in shards:
        nodes = set(shard)
        if not shard or len(nodes) != len(shard) or seen & nodes:
            raise ValueError('empty, duplicate or overlapping shard collection')
        seen.update(nodes)
    if seen != set(full):
        raise ValueError('shard union differs from unsharded collection')
    for shard in shards:
        nodes = set(shard)
        if shard != [node for node in full if node in nodes]:
            raise ValueError('shard changed native collection order')
    return [len(shard) for shard in shards]


def pytest_collection_finish(session):
    """Loaded only in collection subprocesses, retaining exact parametrized IDs."""
    Path(os.environ['AWEB_COLLECTION_RECEIPT']).write_text(
        json.dumps([item.nodeid for item in session.items], indent=2) + '\n')


def collect(package, modules, evidence, name, command):
    receipt = evidence / f'{name}.json'
    receipt.unlink(missing_ok=True)
    env = dict(os.environ, AWEB_COLLECTION_RECEIPT=str(receipt))
    env['PYTHONPATH'] = os.pathsep.join(filter(None, [
        str(Path(__file__).resolve().parent), env.get('PYTHONPATH')]))
    args = [*command, '--collect-only', '-q', '-m', 'not e2e', '-p', 'secrets_shards',
            f'--basetemp={evidence / name / "pytest"}', '-o',
            f'cache_dir={evidence / name / "cache"}', *modules]
    with (evidence / f'{name}.log').open('w') as log:
        result = subprocess.run(args, cwd=package, env=env, stdout=log, stderr=subprocess.STDOUT)
    if result.returncode:
        raise RuntimeError(f'{name} collection failed: exit {result.returncode}')
    nodes = json.loads(receipt.read_text())
    if not isinstance(nodes, list) or not all(isinstance(node, str) for node in nodes):
        raise ValueError(f'invalid collection receipt: {name}')
    return nodes


def qualify(package: Path, manifest: Path, evidence: Path, command=None):
    evidence = evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    command = command or ['uv', 'run', '--frozen', '--offline', 'pytest']
    try:
        shards = load_shards(package, manifest)
        full = collect(package, [], evidence, 'unsharded', command)
        collected = [collect(package, shard, evidence, f'shard-{i}', command)
                     for i, shard in enumerate(shards, 1)]
        counts = validate_collections(full, collected)
    except Exception as error:
        (evidence / 'summary.json').write_text(json.dumps({
            'status': 'FAILED', 'error': str(error)}, indent=2) + '\n')
        raise
    (evidence / 'summary.json').write_text(json.dumps({
        'status': 'PASSED', 'unsharded': len(full), 'counts': counts,
        'intersection': 0, 'native_order': True}, indent=2) + '\n')
    return shards
