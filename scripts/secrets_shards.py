"""Run the measured Secrets partition against two gate-owned service pairs."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
import subprocess
import sys
import tempfile
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


def collect(package, modules, evidence, name, command, environ):
    receipt = evidence / f'{name}.json'
    receipt.unlink(missing_ok=True)
    env = dict(environ, AWEB_COLLECTION_RECEIPT=str(receipt))
    env['PYTHONPATH'] = os.pathsep.join(filter(None, [
        str(Path(__file__).resolve().parent), env.get('PYTHONPATH')]))
    args = [*command, '--collect-only', '-p', 'secrets_shards',
            *scratch_args(evidence / name), *modules]
    with (evidence / f'{name}.log').open('w') as log:
        result = subprocess.run(args, cwd=package, env=env, stdout=log, stderr=subprocess.STDOUT)
    if result.returncode:
        raise RuntimeError(f'{name} collection failed: exit {result.returncode}')
    nodes = json.loads(receipt.read_text())
    if not isinstance(nodes, list) or not all(isinstance(node, str) for node in nodes):
        raise ValueError(f'invalid collection receipt: {name}')
    return nodes


def qualify(package: Path, manifest: Path, evidence: Path, command, environments):
    evidence.mkdir(parents=True, exist_ok=True)
    try:
        shards = load_shards(package, manifest)
        full = collect(package, [], evidence, 'unsharded', command, environments[0])
        collected = [
            collect(package, shard, evidence, f'shard-{number}', command, env)
            for number, (shard, env) in enumerate(zip(shards, environments, strict=True), 1)
        ]
        counts = validate_collections(full, collected)
    except Exception as error:
        (evidence / 'summary.json').write_text(json.dumps({
            'status': 'FAILED', 'error': str(error)}, indent=2) + '\n')
        raise
    (evidence / 'summary.json').write_text(json.dumps({
        'status': 'PASSED', 'unsharded': len(full), 'counts': counts,
        'intersection': 0, 'native_order': True}, indent=2) + '\n')
    return shards


def scratch_args(root: Path) -> list[str]:
    root.mkdir(parents=True, exist_ok=True)
    return [f'--basetemp={root / "pytest"}', '-o', f'cache_dir={root / "cache"}']


def service_environments(plan: str) -> list[dict[str, str]]:
    rows = json.loads(plan)
    keys = {'postgres_port', 'redis_port'}
    if not isinstance(rows, list) or len(rows) != 2 or any(
        not isinstance(row, dict) or set(row) != keys for row in rows
    ):
        raise ValueError('Secrets shards require two owned Postgres and Redis pairs')
    ports = [port for row in rows for port in row.values()]
    if any(type(port) is not int or not 1 <= port <= 65535 for port in ports) or len(set(ports)) != len(ports):
        raise ValueError('Secrets shard service ports must be distinct')
    environments = []
    for row in rows:
        postgres = str(row['postgres_port'])
        redis = f'redis://127.0.0.1:{row["redis_port"]}/0'
        environments.append(dict(
            os.environ, PGHOST='127.0.0.1', PGPORT=postgres,
            TEST_DB_HOST='127.0.0.1', TEST_DB_PORT=postgres,
            REDIS_URL=redis, AWEB_REDIS_URL=redis, AWID_REDIS_URL=redis,
        ))
    return environments


def run_shards(package, shards, environments, evidence, command):
    def run(index, modules, env):
        root = evidence / f'run-{index}'
        args = [*command, *scratch_args(root), *modules]
        log = root / 'pytest.log'
        with log.open('w') as output:
            try:
                status = subprocess.run(
                    args, cwd=package, env=env, stdout=output, stderr=subprocess.STDOUT,
                ).returncode
            except OSError as error:
                output.write(str(error) + '\n')
                status = 126
        return status, log

    with ThreadPoolExecutor(max_workers=2) as pool:
        jobs = [pool.submit(run, index, modules, env)
                for index, (modules, env) in enumerate(zip(shards, environments, strict=True), 1)]
    exit_code = 0
    for index, job in enumerate(jobs, 1):
        status, log = job.result()
        print(f'=== Secrets shard {index} exit {status} ===', flush=True)
        print(log.read_text(), end='', flush=True)
        exit_code = exit_code or status
    return exit_code


def main() -> int:
    if len(sys.argv) < 3 or sys.argv[1] != '--':
        raise SystemExit('usage: secrets_shards.py -- <pytest command>')
    package = Path.cwd()
    manifest = Path(__file__).resolve().parents[1] / 'candidate-gate/secrets-shards.json'
    command = sys.argv[2:]
    environments = service_environments(os.environ['AWEB_SECRETS_SHARD_SERVICES'])
    with tempfile.TemporaryDirectory(prefix='aweb-secrets-shards-') as directory:
        evidence = Path(directory)
        try:
            shards = qualify(package, manifest, evidence, command, environments)
        except (RuntimeError, ValueError):
            for log in sorted(evidence.glob('*.log')):
                print(f'=== Secrets {log.stem} collection ===', flush=True)
                print(log.read_text(), end='', flush=True)
            raise
        print('Secrets collection: ' + (evidence / 'summary.json').read_text(), flush=True)
        return run_shards(package, shards, environments, evidence, command)


if __name__ == '__main__':
    raise SystemExit(main())
