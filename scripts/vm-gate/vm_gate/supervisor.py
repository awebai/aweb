"""Give an owned command group bounded finalization time before evidence pull."""

import json
import os
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path

GRACE = 120
TIMEOUT_KILL_GRACE = 130
SSH_GRACE = 150


def write(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(value)
    temporary.replace(path)


def start_ticks(pid):
    try:
        return Path(f'/proc/{pid}/stat').read_text().rsplit(') ', 1)[1].split()[19]
    except FileNotFoundError:
        return None  # Non-Linux local process controls do not use remote stop.


def group_alive(pid):
    try:
        os.killpg(pid, 0)
        return True
    except ProcessLookupError:
        return False


def cleanup_receipts(registry, interrupted):
    receipts = []
    for line in registry.read_text().splitlines():
        fields = line.split('\t')
        item = {'status': 'absent'}
        try:
            run_id, directory = fields
            root = Path(directory)
            item.update(run_id=run_id, directory=directory)
            if (root / 'run-id').read_text().strip() != run_id:
                raise ValueError('cleanup run identity mismatch')
            verdict = (root / 'wrapper-verdict.log').read_text().splitlines()
            if 'candidate gate cleanup PASSED' not in verdict:
                raise ValueError('cleanup did not pass')
            if interrupted:
                proof = (root / 'interruption.tsv').read_text().strip().split('\t')
                if proof[0] != run_id or 'cleanup=passed' not in proof or 'writer_exit=0' not in proof:
                    raise ValueError('no matching completed interruption cleanup receipt')
            item['status'] = 'passed'
        except (OSError, ValueError, IndexError) as exc:
            item['reason'] = str(exc)
        receipts.append(item)
    return receipts


def supervise(directory, grace, command):
    directory = Path(directory)
    identity = {'pid': os.getpid(), 'uid': os.getuid(), 'start_ticks': start_ticks(os.getpid())}
    write(directory / 'supervisor-identity.json', json.dumps(identity) + '\n')
    registry = directory / ('candidate-runs-' + uuid.uuid4().hex + '.tsv')
    registry.touch()
    requested = []

    def interrupted(signum, _frame):
        if not requested:
            requested.append((signum, time.monotonic(), time.time()))

    previous = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGTERM, signal.SIGINT)}
    child = None
    receipt = dict(identity, interrupted=False, signal=None, term_at=None, kill_at=None, grace_seconds=grace, grace_expired=False)
    try:
        # Separate group: GNU timeout/runuser can stop the supervisor without
        # killing a parent shell before its child has recorded completed proof.
        child = subprocess.Popen(command, cwd=directory, start_new_session=True,
                                 env=dict(os.environ, AWEB_GATE_RUN_REGISTRY=str(registry)))
        receipt['child_pid'] = child.pid
        forwarded = False
        while True:
            status = child.poll()
            if requested and not forwarded:
                sig, _, observed = requested[0]
                receipt.update(interrupted=True, signal=sig, term_at=observed)
                try:
                    os.killpg(child.pid, sig)
                except ProcessLookupError:
                    pass
                forwarded = True
            if status is not None and (not requested or not group_alive(child.pid)):
                break
            if requested and time.monotonic() >= requested[0][1] + grace:
                receipt.update(grace_expired=True, kill_at=time.time())
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.wait(timeout=5)
                break
            time.sleep(.05)
        status = child.wait()
        result = 128 + requested[0][0] if requested else status if status >= 0 else 128 - status
        cleanups = cleanup_receipts(registry, bool(requested))
        settled = not group_alive(child.pid)
        finalized = (settled and not receipt['grace_expired']
                     and (bool(cleanups) or not requested)
                     and all(item['status'] == 'passed' for item in cleanups))
        receipt.update(child_exit=status, raw_exit=result, group_settled=settled,
                       gate_cleanup=cleanups, finalized=finalized, finished=time.time())
        write(directory / 'supervisor-receipt.json', json.dumps(receipt, indent=2) + '\n')
        write(directory / 'gate-exit', str(result) + '\n')
        return result
    finally:
        if child is not None and child.poll() is None:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def validate_identity(identity, directory):
    pid = identity.get('pid')
    try:
        if type(pid) is not int or pid <= 1 or identity.get('uid') != 1000 or not identity.get('start_ticks'):
            raise ValueError('invalid identity fields')
        if start_ticks(pid) != identity['start_ticks']:
            raise ValueError('PID identity changed')
        status = Path(f'/proc/{pid}/status').read_text()
        uid = next(line.split()[1] for line in status.splitlines() if line.startswith('Uid:'))
        args = Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
        if uid != '1000' or [b'-m', b'vm_gate.supervisor', b'run', os.fsencode(directory)] != args[1:5]:
            raise ValueError('command identity changed')
    except (OSError, StopIteration, IndexError, ValueError) as exc:
        raise ValueError('supervisor identity refused: ' + str(exc)) from exc
    return pid


def stop(directory, timeout):
    directory = Path(directory)
    result = {'requested': time.time(), 'finalized': False}
    deadline = time.monotonic() + timeout
    try:
        identity = json.loads((directory / 'supervisor-identity.json').read_text())
        receipt_path = directory / 'supervisor-receipt.json'
        if not receipt_path.exists():
            pid = validate_identity(identity, str(directory))
            os.kill(pid, signal.SIGTERM)
        while True:
            if receipt_path.exists():
                receipt = json.loads(receipt_path.read_text())
                if any(receipt.get(key) != identity.get(key) for key in ('pid', 'uid', 'start_ticks')):
                    raise ValueError('completion identity mismatch')
                result.update(finalized=receipt.get('finalized') is True,
                              receipt=receipt)
                break
            if time.monotonic() >= deadline:
                result['reason'] = 'no completion receipt before bounded grace'
                break
            time.sleep(.1)
    except (OSError, ValueError, KeyError) as exc:
        result['reason'] = str(exc)
    result['finished'] = time.time()
    write(directory / 'operator-stop.json', json.dumps(result, indent=2) + '\n')
    return result


def main():
    mode, directory, seconds, *command = sys.argv[1:]
    seconds = float(seconds)
    if not 0 < seconds <= SSH_GRACE:
        raise ValueError('invalid bounded grace')
    if mode == 'run':
        return supervise(directory, seconds, command)
    if mode == 'stop':
        print(json.dumps(stop(directory, seconds)))
        return 0
    raise ValueError('unknown supervisor mode')


if __name__ == '__main__':
    raise SystemExit(main())
