#!/usr/bin/env python3
"""Independent supervisor for ONE admitted Linux development invocation.

Preparation only: this program neither allocates a host nor grants execution.
The enclosing operator admits at most three changed-source invocations in a
90-minute window. No Docker, database, network or custody access is supplied.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time

from lab_process import Containment

BODY_SECONDS = 1500
CLEANUP_SECONDS = 300


def write_record(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def snapshot(root):
    """All executable input bytes; root owns an immutable, non-symlink tree."""
    hashes = {}
    for path in [root, *sorted(root.rglob('*'))]:
        info = path.lstat()
        if (stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o222
                or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))):
            raise ValueError('control source must be root-owned, immutable regular files/directories')
        if path.is_file():
            hashes[str(path.relative_to(root))] = hashlib.file_digest(path.open('rb'), 'sha256').hexdigest()
    if not hashes:
        raise ValueError('empty source snapshot')
    return hashes


def validate_invocation(value, source):
    if (value['schema_version'] != 1 or value['ordinal'] not in (1, 2, 3)
            or not isinstance(value['entry'], str) or value['entry'].startswith('/')
            or '..' in Path(value['entry']).parts or value['entry'] not in source
            or not value['entry'].endswith('.py')
            or not isinstance(value['args'], list)
            or not all(isinstance(arg, str) and '\x00' not in arg for arg in value['args'])
            or value['source_sha256'] != source):
        raise ValueError('invocation differs from its frozen source manifest')
    return value


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--invocation', type=Path, required=True)
    parser.add_argument('--invocation-sha256', required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if sys.version_info[:2] != (3, 12) or os.geteuid() != 0:
        parser.error('Linux supervisor requires root Python 3.12')
    raw = args.invocation.read_bytes()
    if hashlib.sha256(raw).hexdigest() != args.invocation_sha256:
        parser.error('invocation digest differs from external admission')
    source = snapshot(args.source)
    invocation = validate_invocation(json.loads(raw), source)
    now = time.time()
    if not (now >= invocation['window_started_unix_seconds']
            and now + BODY_SECONDS + CLEANUP_SECONDS <= invocation['window_ends_unix_seconds']
            and invocation['window_ends_unix_seconds'] - invocation['window_started_unix_seconds'] <= 5400):
        parser.error('invocation does not fit the admitted development window')
    args.out.mkdir(mode=0o700, exist_ok=False)
    work = args.out / 'private-work'
    work.mkdir(mode=0o700)
    os.chown(work, 1000, 1000)
    # The unprivileged child can traverse the one private invocation directory;
    # raw operator logs and admission files stay 0600/root-owned.
    args.out.chmod(0o711)
    start = time.monotonic()
    end = start + BODY_SECONDS + CLEANUP_SECONDS
    result = {'primary': 'NOT RUN', 'process': {'populated': True}, 'source_before': source}
    containment = process = None
    def interrupted(signum, _frame):
        raise InterruptedError(f'signal {signum}')
    old = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        containment = Containment(invocation['containment_id'])
        containment.limits(2, 2 * 1024**3, 128)
        write_record(args.out / 'start.json', {
            'kind': 'start, never a result', 'invocation_sha256': args.invocation_sha256,
            'source': source, 'cgroup': str(containment.path), 'started_unix_seconds': time.time(),
            'body_seconds': BODY_SECONDS, 'cleanup_seconds': CLEANUP_SECONDS,
            'cpu_max': '200000 100000', 'memory_max': 2 * 1024**3, 'pids_max': 128,
            'uid': 1000, 'network': 'unshared; no configured interfaces',
        })
        def enter():
            containment.enter()
            libc = ctypes.CDLL(None, use_errno=True)
            if libc.unshare(0x40000000) != 0:  # CLONE_NEWNET; no inherited external sockets
                raise OSError(ctypes.get_errno(), 'isolated network API unavailable')
            os.setgroups([])
            os.setgid(1000)
            os.setuid(1000)
            containment.parent_death()  # setuid clears the first parent-death setting
        command = ['/usr/bin/python3', '-B', str(args.source / invocation['entry']), *invocation['args']]
        with (args.out / 'body.private.log').open('xb') as log:
            process = subprocess.Popen(command, cwd=work, stdin=subprocess.DEVNULL,
                stdout=log, stderr=subprocess.STDOUT, env={'HOME': str(work), 'TMPDIR': str(work),
                'PATH': '/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE': '1'},
                preexec_fn=enter, pass_fds=(containment.fd,))
            result['child_exit'] = process.wait(timeout=max(0.01, start + BODY_SECONDS - time.monotonic()))
            result['primary'] = 'PASS' if result['child_exit'] == 0 else 'FAIL'
    except BaseException as error:
        result.update(primary='INTERRUPTED' if isinstance(error, (InterruptedError, subprocess.TimeoutExpired)) else 'FAIL',
                      error=type(error).__name__)
    finally:
        for sig in old:
            signal.signal(sig, signal.SIG_IGN)
        try:
            if process is not None:
                result['process'] = containment.stop(process, end)
            elif containment is not None:
                containment.close_empty()
                result['process'] = {'populated': False, 'all_children_reaped': True, 'body_started': False}
        except BaseException as error:
            result['cleanup_error'] = type(error).__name__
        try:
            result['source_after'] = snapshot(args.source)
            result['source_unchanged'] = result['source_after'] == source
        except BaseException as error:
            result['source_error'] = type(error).__name__
        result['elapsed_seconds'] = time.monotonic() - start
        result['final'] = 'PASS' if (result['primary'] == 'PASS' and result.get('source_unchanged')
            and not result['process']['populated'] and result['process'].get('all_children_reaped')
            and not result.get('cleanup_error')) else 'FAIL'
        write_record(args.out / 'result.json', result)
        for sig, handler in old.items():
            signal.signal(sig, handler)
    return 0 if result['final'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
