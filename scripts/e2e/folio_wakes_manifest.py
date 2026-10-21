"""Print the manifest of the wakes harness's Folio deployment.

Run inside the built Folio image: it is Folio's committed manifest for this
disposable deployment's origin and version, declaring the harness's public test
emit key. Usage: folio_wakes_manifest.py <version> <events: true|false>
"""

import json
import sys

from awid.did import did_from_public_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from folio.aweb_manifest import MANIFEST

version, events = sys.argv[1], sys.argv[2] == "true"
manifest = json.loads(json.dumps(MANIFEST))
manifest["app"]["origin"] = "http://127.0.0.1:38765"
manifest["app"]["version"] = version
if not events:
    manifest["events"] = []
key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("01" * 32))
public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
manifest["event_emitters"] = [{"kid": "folio:emit-test", "did_key": did_from_public_key(public)}]
print(json.dumps(manifest))
