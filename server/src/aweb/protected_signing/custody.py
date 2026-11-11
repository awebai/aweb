"""Local protected controller custody for the shared signer's closed port.

Operator provisioning must use a separate OS principal and exclude worker
mounts, ACL grants, backups and debugging access. These startup checks refuse
known unsafe POSIX ownership/modes; they cannot inventory the deployment.
There is no key import/export or general-purpose signing endpoint here.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from aweb_naapp.hooks.owner_act import owner_act_signing_bytes
from aweb_naapp.runtime.protected_signer import RevokeHumanRole, SignerRefused
from aweb_naapp.signing_key import parse_signing_key_hex
from awid.did import did_from_public_key


class ProtectedControllerCustody:
    def __init__(
        self,
        *,
        service_id: str,
        team_id: str,
        domain: str,
        key_file: Path,
        worker_uids: frozenset[int],
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
            or team_id.partition(":")[2] != domain
        ):
            raise SignerRefused("scope_refused")
        self.service_id, self.team_id, self.domain = service_id, team_id, domain
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
        self, operation: RevokeHumanRole, fields: Mapping[str, Any]
    ) -> bytes:
        if type(operation) is not RevokeHumanRole:
            raise SignerRefused("operation_refused")
        context = operation.context
        if (
            context.service_id != self.service_id
            or context.authority_kind != "team_controller"
            or context.authority_id != self.team_id
            or context.authority_domain != self.domain
        ):
            raise SignerRefused("scope_refused")
        if any(
            fields.get(name) != value
            for name, value in {
                "act": "human-role.revoke",
                "team_id": self.team_id,
                "team_key_did": self.team_key_did,
                "aud": operation.audience,
                "subject": operation.intent()["subject"],
            }.items()
        ):
            raise SignerRefused("operation_mismatch")
        # The shared implementation constructs the artifact and verifies this
        # signature. Custody only supplies the one exact local key operation.
        return self._key.sign(owner_act_signing_bytes(fields)).signature
