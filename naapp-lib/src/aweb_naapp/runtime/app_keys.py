"""The app's signing keys, chosen by the manifest and loaded once at startup.

Configuration names key files by kid (``app_key_files``). Which purposes a kid
may sign is the served manifest's declaration, so the key for a purpose is the
configured kid the manifest declares for it, and the loaded key must be the
public key declared there. The declaration is the manifest's resolved
:meth:`~aweb_naapp.manifest.Manifest.app_keys_for`: a v2 manifest's
``app_keys`` by purpose, or a v1 manifest's ``event_emitters`` as app-event
keys.

The app-event key may instead come from the released seed value
(``app_emit_key_seed_hex``), named by ``app_emit_kid``; that value signs no
other purpose. Every key byte is read by :mod:`aweb_naapp.signing_key`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from awid.did import did_from_public_key
from nacl.signing import SigningKey

from aweb_naapp.manifest import Manifest
from aweb_naapp.runtime.settings import NaappSettings
from aweb_naapp.signing_key import SigningKeyError, parse_signing_key_hex, read_signing_key_file

APP_EVENT = "app-event"


class AppKeyError(Exception):
    """The app's key for a purpose is missing, ambiguous or not the declared one.
    The message never carries key material."""


@dataclass(frozen=True)
class AppKey:
    kid: str
    did_key: str
    signing_key: SigningKey = field(repr=False)


def load_app_key(settings: NaappSettings, manifest: Manifest, purpose: str) -> AppKey:
    """The app's key for ``purpose``, or :class:`AppKeyError`."""
    prefix = settings.model_config.get("env_prefix", "")
    files = settings.app_key_files
    seed_value = settings.app_emit_key_seed_hex
    emit_kid = settings.app_emit_kid
    if seed_value is not None:
        if emit_kid is None:
            raise AppKeyError(f"{prefix}APP_EMIT_KEY_SEED_HEX needs {prefix}APP_EMIT_KID")
        if emit_kid in files:
            raise AppKeyError(f"app key {emit_kid} is given both a key file and a seed value")

    declared = manifest.app_keys_for(purpose)
    configured = set(files)
    if purpose == APP_EVENT and seed_value is not None and emit_kid is not None:
        configured.add(emit_kid)
    if purpose == APP_EVENT and emit_kid is not None:
        if emit_kid not in declared:
            raise AppKeyError(
                f"{prefix}APP_EMIT_KID {emit_kid} is not declared by the manifest for {purpose}"
            )
        if emit_kid not in configured:
            raise AppKeyError(f"no key is configured for app key {emit_kid}")
        kid = emit_kid
    else:
        candidates = sorted(configured & declared.keys())
        if not candidates:
            raise AppKeyError(f"no configured app key is declared by the manifest for {purpose}")
        if len(candidates) > 1:
            choose = f"; set {prefix}APP_EMIT_KID to choose" if purpose == APP_EVENT else ""
            raise AppKeyError(
                f"several configured app keys are declared for {purpose} "
                f"({', '.join(candidates)}){choose}"
            )
        kid = candidates[0]

    try:
        if kid in files:
            signing_key = read_signing_key_file(files[kid])
        else:
            assert seed_value is not None
            signing_key = parse_signing_key_hex(seed_value.get_secret_value())
    except SigningKeyError as exc:
        raise AppKeyError(f"app key {kid}: {exc}") from None
    did_key = did_from_public_key(bytes(signing_key.verify_key))
    if did_key != declared[kid]:
        raise AppKeyError(f"app key {kid} is not the public key the manifest declares for it")
    return AppKey(kid=kid, did_key=did_key, signing_key=signing_key)
