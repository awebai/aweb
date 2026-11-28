"""Judge one planted-defect run of the TypeScript dist self-test.

    named_negative.py --status N --verdict FILE --name TEST --assertion TEXT < TAP

The run counts as the defect's negative only when bounded_group.py's verdict
says the test process ended on its own with this same non-zero status, and
the TAP stream shows exactly that one test failing on its named assertion.

Exit 0: a confirmed negative. Exit 1: the test passed without its guarded
behaviour. Exit 2: inconclusive (a timeout, an interruption, a missing or
contradictory verdict, or another failure). The reason is printed.
"""

import argparse
from pathlib import Path
import sys

NEGATIVE, PASSED, INCONCLUSIVE = 0, 1, 2


def judge(status, verdict, tap, name, assertion):
    """Return (outcome, reason) for one run."""
    if verdict is None:
        return INCONCLUSIVE, "the runner wrote no verdict"
    if verdict != f"exit {status}":
        return (
            INCONCLUSIVE,
            f"the runner's verdict {verdict!r} contradicts exit status {status}",
        )
    if status == 0:
        return PASSED, f'"{name}" passed without its guarded behaviour'
    lines = tap.splitlines()
    shown = (
        "# tests 1" in lines
        and f"not ok 1 - {name}" in lines
        and "code: 'ERR_ASSERTION'" in tap
        and assertion in tap
    )
    if not shown:
        return INCONCLUSIVE, f'"{name}" did not fail on {assertion}'
    return NEGATIVE, f'"{name}" failed on {assertion}'


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--status", type=int, required=True)
    parser.add_argument("--verdict", type=Path, required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--assertion", required=True)
    args = parser.parse_args()
    verdict = args.verdict.read_text().strip() if args.verdict.is_file() else None
    outcome, reason = judge(
        args.status, verdict, sys.stdin.read(), args.name, args.assertion
    )
    print(reason)
    sys.exit(outcome)


if __name__ == "__main__":
    main()
