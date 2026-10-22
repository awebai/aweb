"""The unsigned one-use code exchange, over verified TLS to the chosen origin."""

import http.client
import re
import ssl
from dataclasses import replace
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .errors import Refused
from .protocol import (
    ID,
    canonical,
    decode64,
    encode64,
    origin_is_valid,
    parse_json,
    public_did,
    public_key,
)
from .state import Identity, IdentityStore


def register(*, origin: str, code: str, state_dir: Path, ca_file: Path | None = None) -> Identity:
    try:
        if not origin_is_valid(origin) or len(decode64(code)) != 32:
            raise ValueError("registration")
    except ValueError:
        raise Refused("registration_invalid") from None
    store = IdentityStore(state_dir)
    with store.registration_lock():
        try:
            identity = store.load()
        except Refused as error:
            if error.code != "identity_unavailable":
                raise
            identity = Identity(origin, Ed25519PrivateKey.generate(), X25519PrivateKey.generate())
            store.save(identity)
        if identity.origin != origin:
            raise Refused("registration_invalid")
        if identity.runner_id is not None:
            raise Refused("already_registered")
        body = canonical(
            {
                "code": code,
                "signing_key": public_did(identity.signing_key.public_key()),
                "encryption_key": encode64(identity.encryption_key.public_key().public_bytes_raw()),
            }
        )
        parts = urlsplit(origin)
        if parts.hostname is None:
            raise Refused("registration_invalid")
        connection = None
        try:
            context = ssl.create_default_context(cafile=ca_file)
            connection = http.client.HTTPSConnection(
                parts.hostname, parts.port, timeout=10, context=context
            )
            connection.request(
                "POST", "/runner/v1/register", body, {"Content-Type": "application/json"}
            )
            with connection.getresponse() as response:
                if response.status != 200:
                    raise Refused(
                        "registration_unavailable"
                        if response.status >= 500
                        else "registration_refused"
                    )
                raw = response.read(4097)
        except (OSError, http.client.HTTPException):
            raise Refused("registration_unavailable") from None
        finally:
            if connection is not None:
                connection.close()
        try:
            doc = parse_json(raw)
            if (
                len(raw) > 4096
                or not isinstance(doc, dict)
                or set(doc) != {"origin", "runner_id", "service_kid"}
                or not all(isinstance(v, str) for v in doc.values())
                or doc["origin"] != origin
                or not re.fullmatch("rnr_" + ID, doc["runner_id"])
            ):
                raise ValueError("response")
            public_key(doc["service_kid"])
        except (ValueError, TypeError, RecursionError):
            raise Refused("registration_invalid") from None
        registered = replace(identity, runner_id=doc["runner_id"], service_kid=doc["service_kid"])
        store.save(registered)
        return registered
