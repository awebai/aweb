"""The shipped testing helper imports without its caller's optional browser tooling."""

import subprocess
import sys


def test_browser_capture_import_does_not_require_playwright():
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            """
import sys
def no_network(event, args):
    if event.startswith('socket.'):
        raise RuntimeError('import attempted socket I/O: ' + event)
sys.addaudithook(no_network)
# Model a consumer environment in which Playwright is not installed.
sys.modules['playwright'] = None
from aweb_naapp_testing.browser_capture import capture_enabled_control
assert callable(capture_enabled_control)
""",
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stdout + result.stderr
