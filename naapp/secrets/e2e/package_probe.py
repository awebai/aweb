"""Runs inside the packaged image against the lab's real DNS, TLS and AWID.

The lab copies this file to /lab/probe.py, beside the minimal shared probe package.
"""

from aweb_naapp_testing.packaged_probe import run

from aweb_secrets.deployment import DeploymentSettings, create_deployment

if __name__ == "__main__":
    run(
        lambda: DeploymentSettings(_env_file=None),
        runtime=lambda settings: create_deployment(settings).runtime,
        host="secrets.lab.test",
        port=8770,
        health=("database", "kms", "outbox"),
        served="packaged root: database/local-custody canary/outbox/manifest PASS",
    )
