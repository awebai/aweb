"""The exact page script under a DOM/fetch double, for orderings a browser
test cannot hold still: a decision submitted, its answer delayed, and the
request's local expiry firing in between. Kept from the boundary review of
acxy.16 (security-fixes, d2b5738fa): the page must never say nothing was
signed when a submitted decision may already have committed."""

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]


@pytest.mark.skipif(shutil.which("node") is None, reason="node is required for the page-script probe")
def test_a_local_expiry_never_overrides_a_submitted_decision():
    probe = Path(__file__).with_name("handoff_expiry_probe.cjs")
    result = subprocess.run(["node", str(probe)], cwd=ROOT, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
