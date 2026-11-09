"""Runs inside the packaged image against the lab's real DNS, TLS and AWID.

The lab copies this file to /lab/probe.py, beside the shared packaged_probe.
"""

from aweb_naapp.runtime.hook_egress import HookEgress
from packaged_probe import run

from aweb_logs.app import create_runtime
from aweb_logs.config import LogsSettings

if __name__ == "__main__":
    run(
        lambda: LogsSettings(_env_file=None),
        runtime=lambda settings: create_runtime(settings, HookEgress.from_settings(settings)),
        host="logs.lab.test",
        port=8765,
        health=("database", "outbox"),
        served="packaged root: database/chain key/outbox/manifest PASS",
    )
