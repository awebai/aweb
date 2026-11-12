"""Archive handoff uses the ordinary pinned SSH/lifecycle/registry path."""

import inspect
import json
import re
import shlex
import tomllib
from pathlib import Path

from .errors import Infrastructure, Refused
from .executor import Executor, REMOTE
from . import native_host
from .native_oci import (
    ARCHIVE,
    parse_receipt,
    qualify_pair,
    verify_archive,
    validate_native_receipt,
    inspect_archive,
)
from .source import git

Q = shlex.quote


class ArchiveExecutor(Executor):
    """Also usable with an existing reviewed x86 preparation adapter."""

    def focused_shell(self):
        mode = "IN" if self.config.get("archive_in") else "OUT"
        return (
            f"env AWEB_SERVER_IMAGE_ARCHIVE_{mode}={ARCHIVE} " + super().focused_shell()
        )

    def preflight(self):
        if self.command != "make test-server-image-build":
            raise Refused(
                "archive qualification accepts only make test-server-image-build"
            )
        if self.config.get("archive_in"):
            identity = self.config["amd64_receipt"]
            verify_archive(self.config["archive_in"], identity)
            if identity["source_sha"] != self.source["sha"]:
                raise Refused("input archive source differs from requested source")
            version = tomllib.loads(
                git(
                    self.config["repo"],
                    "show",
                    self.source["sha"] + ":server/pyproject.toml",
                ).stdout
            )["project"]["version"]
            if version != identity["version"]:
                raise Refused("input archive version differs from requested source")
            # A successful x86 receipt alone is necessary, never combined PASS.
            validate_native_receipt(identity, "linux/amd64")
            helper = git(
                self.config["repo"],
                "show",
                self.source["sha"] + ":scripts/oci-exact-publish.sh",
            ).stdout
            inspect_archive(self.config["archive_in"], identity, helper, self.directory)
        super().preflight()

    def prepare(self, server, timeout):
        super().prepare(server, timeout)
        self.run(
            f"install -d -m 0700 -o {Q(self.user)} -g {Q(self.group)} /evidence",
            "archive-directory",
        )
        if self.config.get("archive_in"):
            target = ARCHIVE + ".upload"
            self.upload(
                Path(self.config["archive_in"]),
                target,
                owner=self.user + ":" + self.group,
                mode="0600",
            )
            identity = self.config["amd64_receipt"]
            self.run(
                f'test ! -e {ARCHIVE} && test "$(stat -c %s {target})" = {identity["bytes"]} && '
                f"printf '%s\\n' {Q(identity['sha256'] + '  ' + target)} | sha256sum -c - && mv {target} {ARCHIVE}",
                "archive-transfer-verify",
            )
        else:
            self.run(f"test ! -e {ARCHIVE}", "archive-out-fresh")

    def collect(self, server, timeout):
        result = super().collect(server, timeout)
        output = self.directory / "evidence/var/log/vm-gate/gate-output.log"
        exit_file = self.directory / "evidence/var/log/vm-gate/gate-exit"
        text = output.read_text() if output.exists() else ""
        # Preserve the actual tar even if a later native probe failed. This
        # never promotes an incomplete archive marker to a native PASS.
        markers = re.findall(r"^server image archive receipt=(.*)$", text, re.M)
        if len(markers) == 1:
            identity = json.loads(markers[0])
            local = self.directory / "server.oci.tar"
            self.transport.copy(ARCHIVE, local, timeout=self.remaining(), download=True)
            local.chmod(0o600)
            verify_archive(local, identity)
            result["retained_oci_archive"] = str(local)
            result["oci_archive_identity"] = identity
            # Collection and verification complete before lifecycle deletion.
            (self.directory / "archive-retention.json").write_text(
                json.dumps(
                    {
                        "path": str(local),
                        "mode": "0600",
                        "verified_before_delete": True,
                        **identity,
                    },
                    indent=2,
                )
                + "\n"
            )
        code = int(exit_file.read_text()) if exit_file.exists() else None
        if code == 0:
            platform = "linux/arm64" if self.config.get("archive_in") else "linux/amd64"
            receipt = parse_receipt(text, self.source["sha"], platform, code)
            if "retained_oci_archive" not in result:
                raise Infrastructure(
                    "native PASS lacks a collected, verified OCI archive"
                )
            (self.directory / "native-receipt.json").write_text(
                json.dumps(receipt, indent=2) + "\n"
            )
            result["native_oci_receipt"] = receipt
            if self.config.get("archive_in"):
                result["native_oci_pair"] = qualify_pair(
                    self.config["amd64_receipt"], receipt
                )
        return result


class NativeARMExecutor(ArchiveExecutor):
    def directories_program(self):
        return native_host.preparation_program(self.config["native_profile"])

    def after_directories(self):
        account = (
            self.run("getent passwd 1000", "native-account").stdout.strip().split(":")
        )
        if (
            len(account) != 7
            or account[2] != "1000"
            or not re.fullmatch(r"[a-z_][a-z0-9_-]*", account[0])
        ):
            raise Refused("native UID1000 account is missing or invalid")
        self.user = account[0]
        self.home = account[5]
        if not self.home.startswith("/") or "\n" in self.home:
            raise Refused("native account HOME must be absolute")
        self.group = self.run(f"id -gn {Q(self.user)}", "native-group").stdout.strip()
        if not re.fullmatch(r"[a-z_][a-z0-9_-]*", self.group):
            raise Refused("native primary group is invalid")
        program = "import grp,hashlib,json,os,platform,shutil,subprocess\nfrom pathlib import Path\n"
        program += (
            "PACKAGES="
            + repr(native_host.PACKAGES)
            + "\n"
            + inspect.getsource(native_host.observe)
        )
        program += "\nprint(json.dumps(observe()))\n"
        observed = json.loads(
            self.run("python3 -c " + Q(program), "native-prepared-identity").stdout
        )
        expected = dict(observed, uid=1000, docker_group=True)
        pins = self.config["native_profile"]["apt"]["packages"]
        expected["packages"] = {name: row["Version"] for name, row in pins.items()}
        expected["docker_version"] = (
            pins["docker-ce"]["Version"].split(":", 1)[-1].split("-", 1)[0]
        )
        candidate = dict(observed, uid=1000, docker_group=True)
        native_host.validate_host(candidate, expected)
        self.config["manifest"] = expected

    def host_check(self, root=False):
        return (
            self.env(root)
            + f"python3 -m vm_gate.native_host {REMOTE}/expected-host.json {REMOTE}/source.json {REMOTE}/source"
        )
