#!/usr/bin/env python3
"""Retain native test timings without changing selection, deadlines or status.

The isolated driver sets AWEB_UNIT_REPORT_DIR to a fresh runner-local directory.
Outside that driver the original command executes unchanged. pytest/Vitest emit
JUnit; Go's JSON events and Node's TAP retain their native outcomes/durations.
"""
import argparse
import os
from pathlib import Path
import signal
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('format', choices=('pytest', 'vitest', 'go', 'tap'))
    parser.add_argument('name')
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command
    if command[:1] == ['--']:
        command = command[1:]
    if not command:
        parser.error('a test command is required')
    directory = os.environ.get('AWEB_UNIT_REPORT_DIR')
    if not directory:
        os.execvp(command[0], command)
    root = Path(directory)
    if not root.is_absolute() or Path(args.name).name != args.name or args.name in ('.', '..'):
        parser.error('report directory must be absolute and name must be a basename')
    root.mkdir(parents=True, exist_ok=True)
    if args.format in ('pytest', 'vitest'):
        report = root / (args.name + '.xml')
        if args.format == 'pytest':
            command += ['--junitxml=' + str(report), '-o', 'junit_duration_report=total']
        else:
            command += ['--', '--reporter=default', '--reporter=junit', '--outputFile.junit=' + str(report)]
        os.execvp(command[0], command)
    suffix = '.jsonl' if args.format == 'go' else '.tap'
    if args.format == 'go':
        command += ['-json']
    else:
        # Node's default reporter varies with runtime/TTY. Keep native TAP
        # deterministic, including when npm runs the existing pretest build.
        os.environ['NODE_OPTIONS'] = os.environ.get('NODE_OPTIONS', '') + ' --test-reporter=tap'
    # No shell pipeline: retain the actual child's failure, including signals.
    with (root / (args.name + suffix)).open('wb') as report:
        with subprocess.Popen(command, stdout=subprocess.PIPE) as child:
            for line in child.stdout:
                report.write(line)
                report.flush()
                sys.stdout.buffer.write(line)
                sys.stdout.buffer.flush()
            status = child.wait()
    if status < 0:
        signal.signal(-status, signal.SIG_DFL)
        os.kill(os.getpid(), -status)
    return status


if __name__ == '__main__':
    raise SystemExit(main())
