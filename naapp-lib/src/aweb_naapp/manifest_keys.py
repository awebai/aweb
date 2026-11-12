"""The key check every consumer of a loaded manifest makes before acting on its keys.

:func:`aweb_naapp.manifest.load_manifest` checks only a declared did:key's
shape. This decodes each one with awid, which refuses anything that is not a
canonical prime-order Ed25519 key, and refuses the manifest with the code its
version's did:key rule carries. It needs ``awid-service``, which the
``runtime`` and ``hooks`` extras install.
"""

from __future__ import annotations

from awid.did import validate_did

from aweb_naapp.manifest import Manifest, ManifestError


def check_manifest_keys(manifest: Manifest) -> None:
    """Refuse ``manifest`` unless every key it declares is an Ed25519 did:key."""
    for kid, did_key, _purposes in manifest.app_keys:
        if validate_did(did_key):
            continue
        if manifest.manifest_version == 1:
            raise ManifestError(
                "manifest_invalid", f"event emitter kid {kid!r} did_key is not an Ed25519 did:key"
            )
        raise ManifestError("app_keys_invalid", f"app key {kid!r} did_key is not an Ed25519 did:key")
