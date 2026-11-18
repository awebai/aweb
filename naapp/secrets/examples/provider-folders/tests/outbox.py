"""Provision a test outbox the way deployment does: the export group, setgid 2750."""

import os
from pathlib import Path


def provision_outbox(path: Path) -> None:
    os.chown(path, -1, os.getgid())
    os.chmod(path, 0o2750)
