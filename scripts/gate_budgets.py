"""Retain stage wall time and its reviewed, initially report-only budget."""
from pathlib import Path
import sys

from gate_settings import load_settings


def record_stage(log_dir, stage, status, elapsed, coverage=''):
    budget = load_settings()['budgets'].get(stage)
    result = 'FAILED' if status else 'PASSED'
    with (log_dir / 'summary.tsv').open('a') as summary:
        summary.write(f'{stage}\t{result}\t{stage}.log\t{elapsed}s\t'
                      f'{str(budget) + "s" if budget is not None else "-"}\t{coverage}\n')
    if budget is not None and elapsed > budget:
        warning = f'BUDGET EXCEEDED: {stage} {elapsed}s > {budget}s (report-only)'
        print(warning, flush=True)
        with (log_dir / 'wrapper-verdict.log').open('a') as verdict:
            verdict.write(warning + '\n')


if __name__ == '__main__':
    record_stage(Path(sys.argv[1]), sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5])
