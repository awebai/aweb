#!/usr/bin/env python3
"""Fixed serial default-origin then Cloud-discovered-origin lab bodies.

Runs only inside the separately admitted root supervisor. It grants no
placement authority. The outer supervisor owns deadlines and independent
listener/process/resource/Redis observations; provider teardown is separate.
"""
import argparse
import grp
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time

from default_registry_client import BINARY_SHA256
from default_registry_lab import checked
from lab_lifecycle import load_json

CLOUD_SHA = '5c0165a6dc90071d2d4501f3d6421ad2b97cfb52'
CLOUD_BUNDLE_SHA256 = 'ace10e6034eeec30972507f2a8b0724b50314581d230158c7c0e21b20db8b587'
BODY_SHA256 = '331eabdd9dbfcd31635db3b737b7622e39824f4a4dbdac2d4f2026776dab8a41'
PROBE_SHA256 = 'c463f142d9abea0c4c48a1fa70912ad6b612ae226186908b57141d5bf7c825c4'


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--admission-sha256', required=True)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--cloud-bundle', type=Path, required=True)
    parser.add_argument('--cloud-checkout', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or os.uname().sysname != 'Linux':
        parser.error('root on the admitted Linux placement is required')
    admission_path = args.inputs / 'admission.json'
    if hashlib.sha256(admission_path.read_bytes()).hexdigest() != args.admission_sha256:
        parser.error('independent admission digest differs')
    admission = load_json(admission_path)
    if (admission['cloud_source_sha'] != CLOUD_SHA or admission['cloud_bundle_sha256'] != CLOUD_BUNDLE_SHA256
            or hashlib.file_digest(args.cloud_bundle.open('rb'), 'sha256').hexdigest() != CLOUD_BUNDLE_SHA256
            or hashlib.file_digest(args.binary.open('rb'), 'sha256').hexdigest() != BINARY_SHA256
            or '0::/' + admission['fixture_id'] not in Path('/proc/self/cgroup').read_text().splitlines()):
        parser.error('source/artifact/kernel-containment bindings differ')
    args.out.mkdir(mode=0o700, exist_ok=False)
    result = {'default': 'NOT RUN', 'cloud': 'NOT RUN', 'verdict': 'FAIL', 'cloud_source_sha': CLOUD_SHA}
    log = args.out / 'commands.private.jsonl'
    # This child budget is subordinate to the outer absolute whole-body clock.
    end = time.monotonic() + 12600
    if time.time() + 13200 >= admission['execute_before_unix_seconds']:
        parser.error('whole execution and cleanup do not fit the admitted lease')
    try:
        default = [os.sys.executable, '-B', str(Path(__file__).with_name('default_registry_lab.py')),
                   '--admission', str(admission_path), '--admission-sha256', args.admission_sha256,
                   '--binary', str(args.binary), '--out', str(args.out / 'default')]
        checked(default, end, log, timeout=1025)
        standalone = load_json(args.out / 'default/standalone-result.json')
        if standalone['final'] != 'PASS':
            raise ValueError('standalone customer path did not pass; Cloud is NOT RUN')
        result['default'] = 'PASS'
        # Fresh registry/database/Redis epoch for Cloud, never a bucket reset.
        # The prior epoch must have ended CLEAN before any Cloud resource starts.
        checked(['git', 'init', str(args.cloud_checkout)], end, log)
        checked(['git', '-C', str(args.cloud_checkout), 'fetch', str(args.cloud_bundle), 'HEAD'], end, log)
        checked(['git', '-C', str(args.cloud_checkout), 'checkout', '--detach', CLOUD_SHA], end, log)
        for path in [args.cloud_checkout, *args.cloud_checkout.rglob('*')]:
            if not path.is_symlink():
                os.chown(path, 1000, 1000)
        body = (args.cloud_checkout / 'scripts/e2e-cloud-user-journey.sh').read_text()
        body = body[body.index('# A.6d:'):body.index('# A.7:')]
        if hashlib.sha256(body.encode()).hexdigest() != BODY_SHA256:
            raise ValueError('A.6d body differs from the reviewed baseline')
        probe = args.cloud_checkout / 'scripts/fixtures/adaz/registry_quota_probe.py'
        if hashlib.sha256(probe.read_bytes()).hexdigest() != PROBE_SHA256:
            raise ValueError('Cloud quota probe bytes differ')
        ledger = args.out / 'cloud-ledger'
        ledger.mkdir(mode=0o700)
        os.chown(ledger, 1000, 1000)
        # The candidate can traverse its one private outer directory; raw files
        # remain0600. Input metadata/bundle is a separate root-owned0444 mount.
        args.out.chmod(0o711)
        parent = os.getpid()
        docker_gid = grp.getgrnam('docker').gr_gid
        def unprivileged():
            os.setgroups([docker_gid])
            os.setgid(1000)
            os.setuid(1000)
            import ctypes
            libc = ctypes.CDLL(None, use_errno=True)
            if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent:
                os._exit(125)
        environment = {
            'HOME': '/home/gateuser',
            'PATH': '/usr/local/go/bin:/opt/uv:/opt/node/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
            'GOTOOLCHAIN': 'local', 'AC_CANDIDATE_SOURCE_SHA': CLOUD_SHA,
            'AC_CANDIDATE_STAGES': 'cloud-user-journey',
            'ADAZ_CLOUD_INPUT_DIRECTORY': str(args.inputs),
            'ADAZ_CLOUD_ADMISSION_SHA256': args.admission_sha256,
            'ADAZ_CLOUD_SOURCE_BUNDLE': str(args.cloud_bundle),
            'AWEB_GATE_LEDGER': str(ledger / 'candidate-gate-ledger.tsv'),
            'AWEB_GATE_LOG_DIR': str(ledger / 'gate-logs'),
            'GATE_OWNER': 'aweb-protocol-expert-gate-vms',
        }
        with (args.out / 'cloud.private.log').open('xb') as stream:
            code = subprocess.run(['bash', 'scripts/candidate-docker-gate.sh'], cwd=args.cloud_checkout,
                env=environment, stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.STDOUT,
                preexec_fn=unprivileged, timeout=max(0.01, end - time.monotonic())).returncode
        result['cloud_exit'] = code
        if code:
            raise ValueError('Cloud customer journey failed; no repair/retry')
        receipt = Path('/tmp/ac-candidate-gate-' + CLOUD_SHA + '-stages') / 'adaz' / admission['fixture_id'] / 'results/assertions.json'
        evidence = load_json(receipt)
        if (evidence['source_sha'] != CLOUD_SHA or evidence['body_sha256'] != BODY_SHA256
                or evidence['passed'] != 19 or evidence['failed'] != 0
                or evidence['admission_sha256'] != args.admission_sha256
                or evidence['fixture_id'] != admission['fixture_id']
                or evidence['provider_run_id'] != admission['provider_run_id']):
            raise ValueError('executed A.6d evidence differs from this admitted source/run')
        result.update(cloud='PASS', verdict='PASS')
    except BaseException as error:
        result['error'] = type(error).__name__
    finally:
        with (args.out / 'bodies.json').open('x') as stream:
            json.dump(result, stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
    return 0 if result['verdict'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
