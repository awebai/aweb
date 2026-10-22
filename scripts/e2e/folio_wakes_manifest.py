"""Print the manifest of the wakes harness's Folio deployment.

Run inside the built Folio image: it is Folio's committed manifest for this
disposable deployment's origin and version, declaring the harness's test
emit kid. The runtime derives its public key from the configured seed. Version 2
declares that key as an app-event app key and adds a hook-only tool, whose scope
install must not grant.
Usage: folio_wakes_manifest.py <version> <events: true|false> <manifest version: 1|2> [extra-kid extra-did]
"""

import json
import os
import sys

from folio.aweb_manifest import MANIFEST_PATH

version, events, manifest_version = sys.argv[1], sys.argv[2] == "true", int(sys.argv[3])
manifest = json.loads(MANIFEST_PATH.read_text())
manifest_version = max(manifest_version, manifest["manifest_version"])
manifest["app"]["origin"] = os.environ["FOLIO_WAKES_ORIGIN"]
manifest["app"]["version"] = version
if not events:
    manifest["events"] = []
manifest["event_emitters"] = [{"kid": "folio:emit-test"}]
if len(sys.argv) == 6:
    manifest["event_emitters"].append({"kid": sys.argv[4], "did_key": sys.argv[5]})
if manifest_version == 2:
    manifest["manifest_version"] = 2
    # Keep records' separate grant-read purpose; the emit seed signs events only.
    keys = [key for key in manifest.get("app_keys", []) if "app-event" not in key.get("purposes", [])]
    if not any(key["kid"] == "folio:grant-read-1" for key in keys):
        keys.append({"kid": "folio:grant-read-1", "purposes": ["app-grant-read"]})
    manifest["app_keys"] = keys + [dict(key, purposes=["app-event"]) for key in manifest.pop("event_emitters")]
    manifest["tools"].append(
        {
            "name": "audit-ingest",
            "description": "Hook-only audit ingest.",
            "method": "POST",
            "path": "/v1/hooks/audit",
            "input_schema": {"type": "object", "properties": {}},
            "params": [],
            "body": {"mode": "json"},
            "scopes": ["folio:hook-ingest"],
            "mutation": True,
            "invocation_contexts": ["hook"],
        }
    )
    hooks = manifest.setdefault("hooks", {"registration_version": 1})
    hooks.setdefault("registrations", []).append({
                "catalog": {"id": "folio.hooks", "version": 1},
                "hook": "folio.after-write",
                "tool": "audit-ingest",
                "scopes": ["folio:hook-ingest"],
    })
print(json.dumps(manifest))
