"""An app's AWID member credentials, read from the files ``aw`` writes.

Each is an ordinary member certificate of one team and its signing key: the
key as the ``ED25519 PRIVATE KEY`` PEM block holding the 32-byte seed, the
certificate as JSON. The key file passes :mod:`aweb_naapp.key_file`'s checks.
Errors name the team and the file, never key material.
"""

from __future__ import annotations

import json
from collections.abc import Mapping

from awid.signing import load_signing_key_pem

from aweb_naapp.key_file import KeyFileError, read_key_file
from aweb_naapp.runtime.settings import AWIDMemberCredentialFiles
from aweb_naapp.runtime.team_auth import AWIDMemberCredential


def read_member_credential(team_id: str, files: AWIDMemberCredentialFiles) -> AWIDMemberCredential:
    """The credential ``files`` hold for ``team_id``; ValueError naming the team."""
    try:
        content = read_key_file(files.signing_key_file)
    except KeyFileError as exc:
        raise ValueError(f"AWID member credential for {team_id}: {exc}") from None
    try:
        seed = load_signing_key_pem(content)
    except ValueError:
        raise ValueError(
            f"AWID member credential for {team_id}: {files.signing_key_file} must hold one "
            "ED25519 PRIVATE KEY PEM block with a 32-byte seed"
        ) from None
    try:
        certificate = json.loads(files.certificate_file.read_bytes())
    except (OSError, ValueError) as exc:
        raise ValueError(
            f"AWID member credential for {team_id}: cannot read the certificate "
            f"{files.certificate_file}: {type(exc).__name__}"
        ) from None
    if not isinstance(certificate, dict):
        raise ValueError(
            f"AWID member credential for {team_id}: the certificate is not a JSON object"
        )
    try:
        credential = AWIDMemberCredential(signing_key=seed, certificate=certificate)
    except ValueError as exc:
        raise ValueError(f"AWID member credential for {team_id}: {exc}") from None
    if credential.team_id != team_id:
        raise ValueError(
            f"AWID member credential for {team_id}: the certificate is for another team"
        )
    return credential


def read_member_credentials(
    configured: Mapping[str, AWIDMemberCredentialFiles],
) -> dict[str, AWIDMemberCredential]:
    return {
        team_id: read_member_credential(team_id, files) for team_id, files in configured.items()
    }
