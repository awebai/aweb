"""Local protected controller custody for the shared signer's closed port.

Operator provisioning must use a separate OS principal and exclude worker
mounts, ACL grants, backups and debugging access. These startup checks refuse
known unsafe POSIX ownership/modes; they cannot inventory the deployment.
There is no key import/export or general-purpose signing endpoint here.
"""

from __future__ import annotations

import base64
import os
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from aweb_naapp.runtime.protected_signer.codecs import authority_key, signing_bytes
from aweb_naapp.runtime.protected_signer import (
    OwnerActOperation,
    RevokeHumanRole,
    SignerRefused,
)
from aweb_naapp.runtime.protected_signer.types import owner_act_operation
from aweb_naapp.signing_key import parse_signing_key_hex
from awid.did import did_from_public_key
from awid.signing import sign_message


from .legacy_delivery import deliver_legacy


class ProtectedControllerCustody:
    def __init__(
        self,
        *,
        service_id: str,
        team_id: str,
        domain: str,
        key_file: Path,
        worker_uids: frozenset[int],
        authority_kind: str = "team_controller",
    ):
        if (
            os.name != "posix"
            or not worker_uids
            or any(
                type(uid) is not int or uid <= 0 or uid == os.geteuid()
                for uid in worker_uids
            )
        ):
            raise SignerRefused("custody_not_isolated")
        if (
            not service_id
            or not team_id
            or not domain
            or authority_kind
            not in {"team_controller", "namespace_controller", "human_identity"}
            or (
                authority_kind == "team_controller"
                and team_id.partition(":")[2] != domain
            )
            or (authority_kind == "namespace_controller" and team_id != domain)
            or (
                authority_kind == "human_identity" and not team_id.startswith("did:aw:")
            )
        ):
            raise SignerRefused("scope_refused")
        self.service_id, self.team_id, self.domain = service_id, team_id, domain
        self.authority_kind = authority_kind
        self._key = self._read_private_key(key_file)
        self.team_key_did = did_from_public_key(bytes(self._key.verify_key))

    @staticmethod
    def _read_private_key(path: Path):
        # Hold the validated private directory open while opening the key;
        # neither a symlink nor a replaced path may change the checked object.
        directory_fd = key_fd = None
        try:
            directory_fd = os.open(
                path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            )
            directory = os.fstat(directory_fd)
            if (
                directory.st_uid != os.geteuid()
                or stat.S_IMODE(directory.st_mode) != 0o700
            ):
                raise SignerRefused("custody_not_isolated")
            key_fd = os.open(
                path.name,
                os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            key = os.fstat(key_fd)
            if (
                key.st_uid != os.geteuid()
                or not stat.S_ISREG(key.st_mode)
                or stat.S_IMODE(key.st_mode) not in {0o400, 0o600}
                or key.st_size > 65
            ):
                raise SignerRefused("custody_not_isolated")
            return parse_signing_key_hex(os.read(key_fd, 66).decode("ascii"))
        except (OSError, UnicodeError, ValueError) as exc:
            if isinstance(exc, SignerRefused):
                raise
            raise SignerRefused("custody_not_isolated") from None
        finally:
            if key_fd is not None:
                os.close(key_fd)
            if directory_fd is not None:
                os.close(directory_fd)

    def sign_owner_act(
        self, operation: RevokeHumanRole | OwnerActOperation, fields: Mapping[str, Any]
    ) -> bytes:
        return self.sign_operation(operation, fields)

    def sign_operation(self, operation, fields):
        typed = owner_act_operation(operation)
        context = typed.context
        if (
            context.service_id != self.service_id
            or context.authority_kind != self.authority_kind
            or context.authority_id != self.team_id
            or context.authority_domain != self.domain
        ):
            raise SignerRefused("scope_refused")
        if authority_key(typed, fields) != self.team_key_did:
            raise SignerRefused("operation_mismatch")
        payload = signing_bytes(typed, fields)
        # The shared implementation constructs the artifact and verifies this
        # signature. Custody only supplies the one exact local key operation.
        signature = sign_message(bytes(self._key), payload)
        return base64.b64decode(signature + "=" * (-len(signature) % 4), validate=True)

    async def register_admission(self, registry, operation, artifact, result):
        return await deliver_legacy(self, registry, operation, artifact, result)

    async def remove_member(self, registry, operation, artifact, result):
        return await deliver_legacy(self, registry, operation, artifact, result)
