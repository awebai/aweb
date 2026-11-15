#!/usr/bin/env python3
"""Fixed entry for a separately source-reviewed and admitted ADAZ placement."""
import argparse
import hashlib
import os
from pathlib import Path
import sys
import time

from adaz_composed_lab import CLOUD_SHA, CLOUD_BUNDLE_SHA256
from lab_lifecycle import load_json, supervise

BODY_SECONDS = 12600
CLEANUP_SECONDS = 600
INPUTS = Path('/opt/vm-gate/adaz-input')
LOGS = Path('/var/log/vm-gate/adaz')


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--admission-sha256', required=True)
    args = parser.parse_args()
    admission_path = INPUTS / 'admission.json'
    if hashlib.sha256(admission_path.read_bytes()).hexdigest() != args.admission_sha256:
        parser.error('externally supplied admission digest differs')
    admission = load_json(admission_path)
    if (admission['cloud_source_sha'] != CLOUD_SHA or admission['cloud_bundle_sha256'] != CLOUD_BUNDLE_SHA256
            or time.time() + BODY_SECONDS + CLEANUP_SECONDS >= admission['execute_before_unix_seconds']):
        parser.error('exact Cloud/whole-budget admission differs')
    LOGS.mkdir(mode=0o711, exist_ok=False)
    LOGS.chmod(0o711)
    command = [sys.executable, '-B', str(Path(__file__).with_name('adaz_composed_lab.py')),
               '--inputs', str(INPUTS), '--admission-sha256', args.admission_sha256,
               '--binary', str(INPUTS / 'aw'), '--cloud-bundle', str(INPUTS / 'cloud.bundle'),
               '--cloud-checkout', '/opt/vm-gate/cloud', '--out', str(LOGS / 'bodies')]
    plans = [LOGS / 'bodies/default/resources.plan.json',
             Path('/tmp/ac-candidate-gate-' + CLOUD_SHA + '-stages/adaz') / admission['fixture_id'] / 'resources.plan.json']
    result = supervise(command, admission, plans, LOGS / 'outer', BODY_SECONDS, CLEANUP_SECONDS,
                       args.admission_sha256)
    return 0 if result['final'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
