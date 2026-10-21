"""Print the manifest of the wakes harness's Folio deployment.

Run inside the built Folio image: it is Folio's committed manifest for this
disposable deployment's origin and version, declaring the harness's public test
emit key. Version 2 declares that key as an app-event app key and adds a
hook-only tool, whose scope install must not grant.
Usage: folio_wakes_manifest.py <version> <events: true|false> <manifest version: 1|2>
"""

import json
import sys

from awid.did import did_from_public_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from folio.aweb_manifest import MANIFEST

version, events, manifest_version = sys.argv[1], sys.argv[2] == "true", int(sys.argv[3])
manifest = json.loads(json.dumps(MANIFEST))
manifest["app"]["origin"] = "http://127.0.0.1:38765"
manifest["app"]["version"] = version
if not events:
    manifest["events"] = []
key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("01" * 32))
public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
manifest["event_emitters"] = [{"kid": "folio:emit-test", "did_key": did_from_public_key(public)}]
if manifest_version == 2:
    manifest["manifest_version"] = 2
    manifest["app_keys"] = [dict(manifest.pop("event_emitters")[0], purposes=["app-event"])]
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
    manifest["hooks"] = {
        "registration_version": 1,
        "registrations": [
            {
                "catalog": {"id": "folio.hooks", "version": 1},
                "hook": "folio.after-write",
                "tool": "audit-ingest",
                "scopes": ["folio:hook-ingest"],
            }
        ],
    }
print(json.dumps(manifest))
