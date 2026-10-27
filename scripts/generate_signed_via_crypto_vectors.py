"""Create the new P1 crypto fixture once; never refreeze an existing artifact."""
from datetime import datetime, timezone
import base64
import json
import os
from pathlib import Path
import subprocess
from uuid import NAMESPACE_URL, uuid5

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from nacl.signing import SigningKey
from awid.did import did_from_public_key, stable_id_from_public_key
from awid.e2ee_keys import build_encryption_key_assertion
from aweb.e2ee_messages import encrypt_e2ee_message

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs/vectors/human-channels-signed-via-crypto-v1.json"
NOW = datetime(2026, 5, 27, 12, tzinfo=timezone.utc)


def main():
    if OUTPUT.exists():
        raise SystemExit("Refusing to refreeze existing vectors; a new reviewed version is required")
    identities = {}
    for name, offset in (("alice", 0), ("bob", 32)):
        seed = bytes(range(offset, offset + 32))
        public = bytes(SigningKey(seed).verify_key)
        private = bytes(range(offset + 64, offset + 96))
        encryption_public = X25519PrivateKey.from_private_bytes(private).public_key().public_bytes_raw()
        did, stable = did_from_public_key(public), stable_id_from_public_key(public)
        identities[name] = dict(address=f"example.test/{name}", did=did, stable_id=stable,
            team_id="protocol:example.test", seed_hex=seed.hex(),
            x25519_private=base64.b64encode(private).decode().rstrip("="),
            encryption_key=build_encryption_key_assertion(signing_key=seed, identity_did=did,
                identity_stable_id=stable, encryption_public_key=encryption_public, custody="self", now=NOW))
    cases = []
    for kind in ("mail", "chat"):
        for via in ("", "telegram", "msteams"):
            name = f"python/{kind}/{via or 'absent'}"
            sender = dict(identities["alice"], signing_key=bytes.fromhex(identities["alice"]["seed_hex"]))
            envelope = encrypt_e2ee_message(kind=kind, sender=sender, recipients=[identities["bob"]],
                subject="P1 subject", body="P1 public test body", message_id=str(uuid5(NAMESPACE_URL, name)),
                conversation_id=str(uuid5(NAMESPACE_URL, "conversation/" + name)), created_at=NOW,
                **({"via": via} if via else {}))
            cases.append(dict(producer="python", kind=kind, via=via, envelope=envelope))
    OUTPUT.write_text(json.dumps(dict(description="Public test-only keys and frozen Python/Go encrypted-v2 P1 vectors. Never use these keys outside tests.",
        identities=identities, cases=cases), indent=2, sort_keys=True) + "\n")
    subprocess.run(["go", "test", "./awid", "-run", "^TestSignedViaCrossLanguageCrypto$", "-count=1"],
        cwd=ROOT / "cli/go", env={**os.environ, "AW_GENERATE_SIGNED_VIA_CRYPTO": "1"}, check=True)


if __name__ == "__main__":
    main()
