"""The naapp app-emit-credential signer.

Produces output byte-identical to the Go signer (awid/signing.go
SignAppEmitCredential) so the Go signer, this Python emitter, and the core
verifier agree on the wire. It is the ``app-event`` purpose of
:mod:`aweb_naapp.runtime.app_credentials`, which reuses the shared awid
canonical-JSON and signing primitives rather than defining a second
canonicalization. This is the v1 stopgap app event emit credential.
"""

from __future__ import annotations

from aweb_naapp.runtime.app_credentials import APP_EVENT, AppCredential, sign_app_credential


def sign_app_emit_credential(
    *,
    private_key: bytes,
    method: str,
    target: str,
    team_id: str,
    app_id: str,
    key_id: str,
    body: bytes,
    timestamp: str,
) -> AppCredential:
    """Sign a v1 app event emit credential.

    ``private_key`` is the 32-byte ed25519 seed. Returns the canonical signed
    payload, body_sha256, the ed25519 signature, and the AWEB-App Authorization
    plus X-AWEB-* headers, byte-identical to the frozen Go vector.
    """
    return sign_app_credential(
        purpose=APP_EVENT,
        private_key=private_key,
        method=method,
        target=target,
        team_id=team_id,
        app_id=app_id,
        key_id=key_id,
        body=body,
        timestamp=timestamp,
    )
