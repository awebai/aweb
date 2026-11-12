"""Per-server SSH identity and bounded transfers with a scrubbed child env."""

import ipaddress
import shutil
import os
from pathlib import Path
import subprocess
from .config import child_environment
from .errors import Infrastructure
from .host_keys import public_key


class Transport:
    def __init__(self, directory, address, server_id):
        self.directory = Path(directory)
        self.address = str(ipaddress.IPv4Address(address))
        if type(server_id) is not int or server_id <= 0:
            raise Infrastructure("invalid SSH server identity")
        self.alias = f"aweb-vm-gate-server-{server_id}"
        expected = public_key(self.directory / "ssh-host-key.pub")
        hosts = self.directory / "known_hosts"
        data = hosts.read_text() if hosts.exists() else ""
        matches = [
            line.split()[1:3]
            for line in data.splitlines()
            if line.split() and line.split()[0] == self.alias
        ]
        if any(parts != expected.split() for parts in matches):
            raise Infrastructure("local host key pin differs from this run")
        if not matches:
            with hosts.open("a") as output:
                output.write(self.alias + " " + expected + "\n")
            hosts.chmod(0o600)
        self.options = [
            "-F",
            os.devnull,
            "-i",
            str(self.directory / "ssh-key"),
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "GlobalKnownHostsFile=" + os.devnull,
            "-o",
            "HostKeyAlgorithms=ssh-ed25519",
            "-o",
            "UserKnownHostsFile=" + str(self.directory / "known_hosts"),
            "-o",
            f"HostKeyAlias=aweb-vm-gate-server-{server_id}",
            "-o",
            "ConnectTimeout=5",
            "-o",
            "ForwardAgent=no",
        ]

    @staticmethod
    def invoke(args, timeout, check=True):
        try:
            result = subprocess.run(
                args,
                timeout=timeout,
                text=True,
                capture_output=True,
                env=child_environment(),
            )
        except (OSError, subprocess.TimeoutExpired):
            raise Infrastructure("SSH operation unavailable or timed out") from None
        if check and result.returncode:
            raise Infrastructure(f"SSH operation failed (exit {result.returncode})")
        return result

    def prove_mismatch(self, *, timeout):
        """After positive pinned readiness, require a valid wrong key to refuse."""
        wrong = public_key(self.directory / "ssh-key.pub")
        if wrong == public_key(self.directory / "ssh-host-key.pub"):
            raise Infrastructure(
                "host and client keys must differ for the negative control"
            )
        path = self.directory / "known_hosts-mismatch"
        path.write_text(self.alias + " " + wrong + "\n")
        path.chmod(0o600)
        options = [
            str("UserKnownHostsFile=" + str(path))
            if value.startswith("UserKnownHostsFile=")
            else value
            for value in self.options
        ]
        result = self.invoke(
            [shutil.which("ssh") or "ssh", *options, "root@" + self.address, "true"],
            timeout,
            check=False,
        )
        if (
            result.returncode != 255
            or "host key verification failed" not in result.stderr.lower()
        ):
            raise Infrastructure(
                "mismatched SSH host key did not produce the required refusal"
            )
        return result

    def run(self, command, *, timeout, check=True):
        return self.invoke(
            [
                shutil.which("ssh") or "ssh",
                *self.options,
                "root@" + self.address,
                command,
            ],
            timeout,
            check,
        )

    def copy(self, source, target, *, timeout, download=False):
        remote = "root@" + self.address + ":" + str(source if download else target)
        args = [
            shutil.which("scp") or "scp",
            *self.options,
            remote if download else str(source),
            str(target) if download else remote,
        ]
        return self.invoke(args, timeout)
