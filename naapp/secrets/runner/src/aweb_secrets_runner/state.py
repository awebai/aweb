"""Private, atomic runner identity storage. Never persist a registration code."""

import fcntl
import os
import re
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .errors import Refused
from .protocol import ID, canonical, decode64, encode64, origin_is_valid, parse_json, public_key


@dataclass(frozen=True)
class Identity:
    origin: str
    signing_key: Ed25519PrivateKey = field(repr=False)
    encryption_key: X25519PrivateKey = field(repr=False)
    runner_id: str | None = None
    service_kid: str | None = None

    def public(self) -> dict[str, str | None]:
        return dict(origin=self.origin, runner_id=self.runner_id, service_kid=self.service_kid)


class IdentityStore:
    def __init__(self, directory: Path):
        self.directory = directory

    def _check_directory(self, *, create: bool = False) -> None:
        try:
            if not self.directory.is_absolute():
                raise Refused("state_permissions")
            if create:
                self.directory.mkdir(mode=0o700, exist_ok=True)
            info = self.directory.lstat()
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o077
            ):
                raise Refused("state_permissions")
        except OSError:
            raise Refused("state_permissions") from None

    def _open(self, name: str, flags: int) -> int:
        fd = os.open(self.directory / name, flags | os.O_NOFOLLOW, 0o600)
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
            or info.st_nlink != 1
        ):
            os.close(fd)
            raise Refused("state_permissions")
        return fd

    @contextmanager
    def registration_lock(self) -> Iterator[None]:
        self._check_directory(create=True)
        try:
            fd = self._open("registration.lock", os.O_CREAT | os.O_RDWR)
            try:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise Refused("registration_busy") from None
                yield
            finally:
                os.close(fd)
        except OSError:
            raise Refused("state_permissions") from None

    def load(self) -> Identity:
        self._check_directory()
        try:
            fd = self._open("identity.json", os.O_RDONLY)
            with os.fdopen(fd, "rb") as stream:
                raw = stream.read(4097)
            if len(raw) > 4096:
                raise ValueError("size")
            value = parse_json(raw)
            if not isinstance(value, dict) or set(value) != {
                "v",
                "origin",
                "signing_private",
                "encryption_private",
                "runner_id",
                "service_kid",
            }:
                raise ValueError("shape")
            if (
                type(value["v"]) is not int
                or value["v"] != 1
                or not origin_is_valid(value["origin"])
            ):
                raise ValueError("shape")
            if value["runner_id"] is None:
                if value["service_kid"] is not None:
                    raise ValueError("partial pin")
            else:
                if not re.fullmatch("rnr_" + ID, value["runner_id"]):
                    raise ValueError("runner")
                public_key(value["service_kid"])
            return Identity(
                origin=value["origin"],
                runner_id=value["runner_id"],
                service_kid=value["service_kid"],
                signing_key=Ed25519PrivateKey.from_private_bytes(
                    decode64(value["signing_private"])
                ),
                encryption_key=X25519PrivateKey.from_private_bytes(
                    decode64(value["encryption_private"])
                ),
            )
        except FileNotFoundError:
            raise Refused("identity_unavailable") from None
        except OSError:
            raise Refused("state_permissions") from None
        except (ValueError, TypeError, AttributeError, RecursionError):
            raise Refused("identity_invalid") from None

    def save(self, identity: Identity) -> None:
        """Called while registration_lock is held; replace one complete snapshot."""
        self._check_directory()
        raw = canonical(
            {
                "v": 1,
                **identity.public(),
                "signing_private": encode64(identity.signing_key.private_bytes_raw()),
                "encryption_private": encode64(identity.encryption_key.private_bytes_raw()),
            }
        )
        temporary = None
        try:
            fd, name = tempfile.mkstemp(prefix=".identity-", dir=self.directory)
            temporary = Path(name)
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            temporary.replace(self.directory / "identity.json")
            directory_fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            raise Refused("state_unavailable") from None
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
