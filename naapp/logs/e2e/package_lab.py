"""Disposable packaged-service proof; run explicitly under the suite lock.

Uses only generated lab keys, internal Docker networking and real PG/Redis/AWID.
No customer inputs, DNS override hooks, insecure TLS or production access.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from aweb_naapp_testing.package_lab import Lab, PackagedService, run_package_lab


def environment(lab: Lab) -> dict[str, str]:
    keys = lab.keys
    return {
        "LOGS_DATABASE_URL": lab.database_url,
        "LOGS_APP_ID": "lab-logs",
        "LOGS_PUBLIC_ORIGIN": "https://logs.lab.test",
        "LOGS_CONSOLE_ORIGIN": "https://console.lab.test",
        "LOGS_AWID_REGISTRY_URL": lab.registry_url,
        "LOGS_AUTH_CACHE_TTL_SECONDS": "1",
        "LOGS_APP_KEY_FILES": json.dumps(
            {
                "logs-chain": keys["chain"],
                "logs-resolve": keys["resolve"],
                "logs-grants": keys["grants"],
                "logs-governance": keys["governance"],
            }
        ),
        "LOGS_EMAIL_SMTP_HOST": "smtp.lab.test",
        "LOGS_EMAIL_SMTP_PORT": "587",
        "LOGS_EMAIL_USERNAME": "lab",
        "LOGS_EMAIL_PASSWORD_FILE": keys["smtp"],
        "LOGS_EMAIL_FROM": "logs@lab.test",
    }


LOGS = PackagedService(
    name="logs",
    keys=("chain", "resolve", "grants", "governance", "smtp"),
    environment=environment,
    probe=Path(__file__).with_name("package_probe.py"),
)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    run_package_lab(args.image, LOGS)
