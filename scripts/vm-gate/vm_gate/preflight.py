"""Existing B1 preflight read, with its path supplied only by external config.

The former machine-specific fallback is deliberately absent from repository
source. This is the sole credential read; callers never export its return value.
"""

import os
from pathlib import Path
from .errors import Refused


def read_hcloud_token():
    path = os.environ.get("HCLOUD_TOKEN_FILE")
    if not path:
        raise Refused("HCLOUD_TOKEN_FILE is required by preflight")
    try:
        token = Path(path).expanduser().read_text().strip()
    except OSError:
        raise Refused("Hetzner credential file is unreadable") from None
    if not token:
        raise Refused("Hetzner token file is empty")
    return token
