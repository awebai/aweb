#!/usr/bin/env python3
"""Retain container configuration without its disposable database password."""
import json
import subprocess
import sys


def redact(containers):
    for container in containers:
        config = container.get("Config") or {}
        config["Env"] = [
            entry.split("=", 1)[0] + "=[REDACTED]"
            if entry.startswith(("POSTGRES_PASSWORD=", "PGPASSWORD=")) else entry
            for entry in config.get("Env") or []
        ]
    return containers


if __name__ == "__main__":
    result = subprocess.check_output(["docker", "inspect", sys.argv[1]], text=True)
    print(json.dumps(redact(json.loads(result)), indent=2))
