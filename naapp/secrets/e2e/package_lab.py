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
        "SECRETS_DATABASE_URL": lab.database_url,
        "SECRETS_APP_ID": "lab-secrets",
        "SECRETS_PUBLIC_ORIGIN": "https://secrets.lab.test",
        "SECRETS_CONSOLE_ORIGIN": "https://console.lab.test",
        "SECRETS_AWID_REGISTRY_URL": lab.registry_url,
        "SECRETS_AUTH_CACHE_TTL_SECONDS": "1",
        "SECRETS_CUSTODY_KEY_FILE": keys["custody"],
        "SECRETS_SECRET_REQUEST_KEY_FILE": keys["request"],
        "SECRETS_SECRET_PARAMS_KEY_FILE": keys["params"],
        "SECRETS_RESPONSE_KEY_FILE": keys["response"],
        "SECRETS_RUNNER_SERVICE_KEY_FILE": keys["runner"],
        "SECRETS_MANIFEST_REQUEST_KEY_FILE": keys["manifest"],
        "SECRETS_APP_KEY_FILES": json.dumps(
            {
                "secrets.hook-event-1": keys["event"],
                "secrets.hook-delivery-1": keys["delivery"],
                "secrets:grant-read-1": keys["grant"],
                "secrets:hook-resolve-1": keys["resolve"],
            }
        ),
        "SECRETS_EMAIL_SMTP_HOST": "smtp.lab.test",
        "SECRETS_EMAIL_USERNAME": "lab",
        "SECRETS_EMAIL_PASSWORD_FILE": keys["smtp"],
        "SECRETS_EMAIL_FROM": "secrets@lab.test",
        "SECRETS_EGRESS_DENIED_NETWORKS": "[]",
    }


SECRETS = PackagedService(
    name="secrets",
    keys=(
        "custody",
        "request",
        "params",
        "response",
        "runner",
        "smtp",
        "manifest",
        "event",
        "delivery",
        "grant",
        "resolve",
    ),
    environment=environment,
    probe=Path(__file__).with_name("package_probe.py"),
)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    run_package_lab(args.image, SECRETS)
