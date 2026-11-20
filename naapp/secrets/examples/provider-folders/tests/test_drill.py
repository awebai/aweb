"""The replay drill, offline: the package's own modules run as a subprocess
against the TLS stand-in, every case reading the folder back.

The pinned-tree form (a vendored tree from vendor-lock.json and a base
interpreter without httpx) needs the locked wheels; it runs with
`deploy/drill.py --pinned` and is reported with its receipt.
"""

import shutil
import sys

from deploy.drill import run
from deploy.vendor import MODULES, PACKAGE

CASES = [
    "trust root: the lab CA only through ca_bundle",
    "cutover: a queued export carried to a fresh publisher state",
    "lost answer: remote committed, no local receipt",
    "whole ledger removed",
    "output bound: exit 6 is read through its counts",
    "tree unchanged by the replays",
]


def test_every_drill_case_passes_against_the_package_modules(tmp_path):
    root = tmp_path / "install"
    root.mkdir()
    for module in MODULES:
        shutil.copyfile(PACKAGE / module, root / module)
    receipt = run(root, sys.executable, pinned=False)
    assert [record["case"] for record in receipt["cases"]] == CASES
    assert [record for record in receipt["cases"] if not record["passed"]] == []
    assert receipt["result"] == "PASS"
