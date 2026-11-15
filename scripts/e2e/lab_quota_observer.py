"""Gate-owned read-only quota capture before Cloud's fixed cleanup handshake."""
import hashlib
import json
import os
import re
import stat
import time
import uuid

from lab_lifecycle import load_json

BINDINGS = {'schema_version', 'fixture_id', 'provider_run_id', 'cloud_source_sha',
            'admission_sha256', 'quota_sha256'}
REDIS_SNAPSHOT = (
    "local cursor='0'; local out={}; local n=0; repeat "
    "local scan=redis.call('SCAN',cursor,'MATCH','aweb:rl:*','COUNT',256); cursor=scan[1]; "
    "for _,key in ipairs(scan[2]) do n=n+1; if n>2048 then return redis.error_reply('snapshot key cap') end; "
    "table.insert(out,{key,redis.call('GET',key),redis.call('TTL',key)}) end; "
    "until cursor=='0'; return cjson.encode(out)"
)


def regular(path):
    info = path.lstat()
    if (path.resolve(strict=True) != path or not stat.S_ISREG(info.st_mode)
            or info.st_size > 1024 * 1024):
        raise ValueError('quota input is not a bounded regular file')
    return path


def write_private(path, value, *, uid=None):
    staging = path.with_name('.' + path.name + '.' + uuid.uuid4().hex + '.staging')
    descriptor = os.open(staging, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(value, stream, indent=2)
            stream.write('\n')
            if uid is not None:
                os.fchown(stream.fileno(), uid, uid)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(staging, path, follow_symlinks=False)  # final name never exposes partial JSON
    finally:
        staging.unlink(missing_ok=True)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def enforcement(quota, values, access_log):
    denied = [r for r in quota['requests'] if r['status'] == 429]
    neighbor = quota['requests'][-1]
    if len(denied) != 1 or neighbor['status'] != 200 or not neighbor['path'].endswith('/head'):
        raise ValueError('quota submission evidence is ambiguous')
    denied = denied[0]
    entries = re.findall(r'(\d+\.\d+\.\d+\.\d+):\d+ - "GET ([^ ]+) HTTP/1\.[01]" (\d{3})', access_log)
    denied_peers = {ip for ip, path, code in entries if path == denied['path'] and code == '429'}
    neighbor_peers = {ip for ip, path, code in entries if path == neighbor['path'] and code == '200'}
    common = denied_peers & neighbor_peers
    if len(common) != 1:
        raise ValueError('stock access-log peers do not establish one actual shared source')
    peer = common.pop()
    mapping = {key: (int(count), ttl) for key, count, ttl in values}
    checks = []
    for row, bucket, limit in ((denied, 'namespace_get', 60), (neighbor, 'did_head', 120)):
        if int(row['headers']['X-RateLimit-Limit']) != limit:
            raise ValueError('actual response rate limit differs from the pinned contract')
        window = int(row['headers']['X-RateLimit-Reset']) // 60 - 1
        key = f'aweb:rl:{bucket}:{peer}:{window}'
        if key not in mapping:
            raise ValueError('matching actual Redis window expired or was not captured')
        count, ttl = mapping[key]
        if ttl < 0 or (bucket == 'namespace_get' and count <= 60) or (bucket == 'did_head' and not 0 < count <= 120):
            raise ValueError('actual Redis count/TTL disagrees with allowed/denied evidence')
        checks.append({'bucket': bucket, 'key': key, 'count': count, 'ttl': ttl})
    return {'verdict': 'PASS', 'actual_access_log_peer': peer, 'buckets': checks}


def periodic(observer):
    """Read-only prerequisites accounting, stopped after the final handshake."""
    project = observer.plan['published_listener']['project']
    if not project:
        return  # standalone has its own pre-cleanup sampling
    for (kind, ref), value in list(observer.observed.items()):
        if kind != 'container' or ref not in observer.started_containers:
            continue
        labels = value['labels']
        if labels.get('com.docker.compose.project') != project:
            continue
        service = labels.get('com.docker.compose.service')
        if service == 'redis':
            call = observer.call(['exec', ref, 'redis-cli', '-n', '0', '--raw', 'EVAL_RO', REDIS_SNAPSHOT, '0'])
            with (observer.root / 'redis-usage.private.jsonl').open('a') as stream:
                stream.write(json.dumps({'time': time.time(), 'id': ref, 'call': call}) + '\n')
            if call['rc'] != 0:
                raise RuntimeError('prerequisite Redis observation is UNKNOWN')
        elif service == 'awid':
            since = str(getattr(observer, 'access_logs_since', int(observer.plan['created_unix_seconds'])))
            now = int(time.time())
            call = observer.call(['logs', '--timestamps', '--since', since, ref])
            with (observer.root / 'awid-access.private.jsonl').open('a') as stream:
                stream.write(json.dumps({'time': time.time(), 'id': ref, 'call': call}) + '\n')
            if call['rc'] != 0:
                raise RuntimeError('prerequisite stock access-log observation is UNKNOWN')
            observer.access_logs_since = now  # same-second duplicates are retained, never discarded


def capture(observer, ready_path, admission, admission_digest):
    """Success means captured raw evidence; enforcement has a separate verdict."""
    ready = load_json(regular(ready_path))
    if set(ready) != BINDINGS | {'kind'} or ready['kind'] != 'adaz-quota-observation-ready':
        raise ValueError('unexpected observation readiness schema')
    wanted = {name: admission[name] for name in ('fixture_id', 'provider_run_id', 'cloud_source_sha')}
    wanted.update(schema_version=1, admission_sha256=admission_digest)
    if any(ready[name] != value for name, value in wanted.items()):
        raise ValueError('quota observation belongs to another admission')
    quota_path = regular(ready_path.with_name('quota.json'))
    if hashlib.sha256(quota_path.read_bytes()).hexdigest() != ready['quota_sha256']:
        raise ValueError('quota input changed before independent capture')
    quota = load_json(quota_path)
    if (quota['verdict'] != 'PASS' or quota['origin'] != 'https://registry.aweb-docker.test:8010'
            or quota['public_ipv4'] != admission['public_ipv4']):
        raise ValueError('quota input differs from admitted origin/address')
    project = observer.plan['published_listener']['project']
    identities = {}
    for service in ('redis', 'awid'):
        references = observer.inventory('container', 'com.docker.compose.project=' + project)
        selected = []
        for ref in references:
            value = observer.inspect('container', ref, exact_from_inventory=True)
            labels, _ = observer.ownership('container', value)
            if labels.get('com.docker.compose.service') == service:
                selected.append(value)
        if len(selected) != 1 or not selected[0]['State']['Running']:
            raise ValueError('actual running quota service is ambiguous')
        value = selected[0]
        identities[service] = {'id': value['Id'], 'created': value['Created'],
                               'image_id': value['Image'], 'labels': value['Config']['Labels']}
        if service == 'awid':
            environment = dict(entry.split('=', 1) for entry in value['Config']['Env'] if '=' in entry)
            if (environment.get('AWID_REDIS_URL') != 'redis://redis:6379/0'
                    or environment.get('AWID_RATE_LIMIT_BACKEND') != 'redis'
                    or environment.get('AWID_RATE_LIMIT_DISABLED') not in ('0', 'false')):
                raise ValueError('actual registry is not the reviewed quota profile')
    redis = observer.call(['exec', identities['redis']['id'], 'redis-cli', '-n', '0', '--raw',
                           'EVAL_RO', REDIS_SNAPSHOT, '0'])
    logs = observer.call(['logs', '--timestamps', identities['awid']['id']])
    if redis['rc'] != 0 or logs['rc'] != 0:
        raise RuntimeError('independent quota capture is UNKNOWN')
    values = json.loads(redis['stdout'])
    if (not isinstance(values, list) or not values or len(values) > 2048
            or any(not isinstance(row, list) or len(row) != 3 or not row[0].startswith('aweb:rl:')
                   or not isinstance(row[1], str) or not row[1].isdigit()
                   or not isinstance(row[2], int) for row in values)):
        raise ValueError('Redis key/count/TTL output is unexpected')
    runner = observer.inspect('container', observer.plan['runner_name'])
    observer.ownership('container', runner)
    node = ("const fs=require('fs'),p=require('path'),h=require('crypto');"
            "const r=p.dirname(p.dirname(fs.realpathSync('/usr/local/bin/aw')));"
            "const w=JSON.parse(fs.readFileSync(p.join(r,'package.json')));"
            "const f=require.resolve('@awebai/aw-linux-x64/package.json',{paths:[r]});"
            "const m=JSON.parse(fs.readFileSync(f)),b=p.join(p.dirname(f),'bin/aw');"
            "console.log(JSON.stringify({wrapper_version:w.version,platform_version:m.version,"
            "source_commit:m.gitHead,entry_sha256:h.createHash('sha256').update(fs.readFileSync(p.join(r,'bin/aw'))).digest('hex'),"
            "binary_path:b,binary_sha256:h.createHash('sha256').update(fs.readFileSync(b)).digest('hex')}))")
    installed = observer.call(['exec', runner['Id'], 'node', '-e', node])
    if installed['rc'] != 0:
        raise RuntimeError('installed published CLI readback is UNKNOWN')
    cli = json.loads(installed['stdout'])
    if (cli['wrapper_version'] != '1.36.59-rc.2' or cli['platform_version'] != '1.36.59-rc.2'
            or cli['source_commit'] != '0072ed1c1c7545c59ce743c9cea431e4ce96afcb'
            or cli['entry_sha256'] not in {'a4ff118eb7f0746804f2d579995607aefcdaf888b68eb17c6d4fe7260ba52545',
                                         '8123a15b04bc4a5881b425b1622355e5a1c8cc4ba8b6b54e144025fee25552cd'}
            or cli['binary_sha256'] != 'a4ff118eb7f0746804f2d579995607aefcdaf888b68eb17c6d4fe7260ba52545'):
        raise ValueError('actual installed Cloud CLI differs from frozen published artifact')
    try:
        assessed = enforcement(quota, values, logs['stdout'] + '\n' + logs['stderr'])
    except Exception as error:
        assessed = {'verdict': 'FAIL', 'error': str(error)}
    artifact = {**{key: ready[key] for key in BINDINGS}, 'kind': 'adaz-independent-quota-observation',
                'observed_unix_seconds': time.time(), 'identities': identities,
                'redis_db': 0, 'redis_key_count_ttl': values, 'redis_call': redis, 'access_log_call': logs,
                'installed_cli': cli, 'candidate_runner_id': runner['Id'],
                'capture_verdict': 'PASS', 'enforcement': assessed}
    private = observer.root / 'post-journey-quota-observation.json'
    write_private(private, artifact)
    digest = hashlib.sha256(private.read_bytes()).hexdigest()
    ack = {**{key: ready[key] for key in BINDINGS}, 'kind': 'adaz-quota-observation-ack',
           'observation_sha256': digest, 'capture_verdict': 'PASS'}
    write_private(observer.root / 'quota-ack.private.json', ack)
    write_private(ready_path.with_name('quota-observed.json'), ack, uid=1000)
    return {'private_artifact': str(private), 'sha256': digest, 'capture_verdict': 'PASS',
            'enforcement': assessed, 'shared_ack': str(ready_path.with_name('quota-observed.json')),
            'private_ack': str(observer.root / 'quota-ack.private.json')}
