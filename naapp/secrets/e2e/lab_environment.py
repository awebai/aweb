"""Explicit BYOT native/KMS lab references, separate from hosted release acceptance.

This loader never opens a credential, starts a service/runner, or claims a
scenario passed. Actor certification/publication is a separate online step.
"""

from __future__ import annotations

import os
import pwd
import re
import stat
import sys
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Literal
from urllib.parse import urlsplit

from awid.team_ids import parse_team_id
from release_environment import PREFIX, _dns_name, _https

PrivateDNS = Literal["included", "excluded"]
LAB_REQUIRED_NAMES = tuple(
    PREFIX + name
    for name in (
        "TEAM_ID",
        "API_ORIGIN",
        "CONSOLE_ORIGIN",
        "LOGS_ORIGIN",
        "LOGS_CONSOLE_ORIGIN",
        "KMS_KEY_ARN",
        "AWS_REGION",
        "KMS_CREDENTIALS_FILE",
        "RUNNER_BINARY",
        "RUNNER_CONFIG_FILE",
        "RUNNER_USER",
        "RUNNER_STATE_DIR",
        "AGENT_A_IDENTITY_HOME",
        "AGENT_B_IDENTITY_HOME",
        "AW_BINARY",
        "AWID_REGISTRY_URL",
        "COORDINATION_ORIGIN",
        "HUMAN_IDENTITY_HOME",
    )
)
ACTORS = ("HUMAN", "AGENT_A", "AGENT_B")
_KMS_ARN = re.compile(
    r"arn:(?:aws|aws-us-gov|aws-cn):kms:([a-z0-9-]+):[0-9]{12}:(?:key|alias)/[A-Za-z0-9/_-]+"
)


class LabConfigurationError(ValueError):
    """Only fixed codes and known selector names, never supplied values."""

    def __init__(self, names: set[str], code: str = "lab_inputs_invalid") -> None:
        self.code = code
        super().__init__(code + ": " + ", ".join(sorted(names)))


def _absolute(value: str) -> bool:
    path = Path(value)
    return path.is_absolute() and ".." not in path.parts and "\0" not in value


def _owned_reference(path: Path, *, directory: bool = False) -> bool:
    try:
        info = path.lstat()
        return (
            (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            and info.st_uid == os.geteuid()
            and info.st_mode & (0o022 if directory else 0o077) == 0
            and (info.st_mode & (0o500 if directory else 0o400)) == (0o500 if directory else 0o400)
        )
    except (OSError, ValueError):
        return False


def runner_uid(environment: Mapping[str, str]) -> int:
    name = PREFIX + "RUNNER_USER"
    try:
        uid = pwd.getpwnam(environment[name]).pw_uid
        if uid <= 0 or uid == os.geteuid():
            raise ValueError
        return uid
    except (KeyError, ValueError):
        raise LabConfigurationError({name}, "lab_runner_user_invalid") from None


def load_lab_environment(
    environ: Mapping[str, str] | None = None, *, private_dns: PrivateDNS
) -> Mapping[str, str]:
    """Read references only; the caller must select DNS coverage explicitly.

    The runner's protected config/state are checked by its existing doctor
    under that UID, not traversed by this driver. A real worker and KMS use
    remain scenario requirements. Hosted/OAuth/1Password inputs are not adopted.
    """
    if private_dns not in ("included", "excluded"):
        raise LabConfigurationError(set(), "lab_dns_coverage_required")
    source = os.environ if environ is None else environ
    selected = {
        name: value.strip() if isinstance(value := source.get(name), str) else ""
        for name in LAB_REQUIRED_NAMES
    }
    invalid = {name for name, value in selected.items() if not value}
    team = PREFIX + "TEAM_ID"
    try:
        parse_team_id(selected[team])
    except ValueError:
        invalid.add(team)
    for suffix in (
        "API_ORIGIN",
        "CONSOLE_ORIGIN",
        "LOGS_ORIGIN",
        "LOGS_CONSOLE_ORIGIN",
        "AWID_REGISTRY_URL",
        "COORDINATION_ORIGIN",
    ):
        name = PREFIX + suffix
        if not _https(selected[name], origin=True):
            invalid.add(name)
    for agent, human, hostname_only in (
        ("API_ORIGIN", "CONSOLE_ORIGIN", False),
        ("LOGS_ORIGIN", "LOGS_CONSOLE_ORIGIN", True),
    ):
        a, b = PREFIX + agent, PREFIX + human
        try:
            first, second = urlsplit(selected[a]), urlsplit(selected[b])
            same_host = (first.hostname or "").rstrip(".") == (second.hostname or "").rstrip(".")
            if same_host and (hostname_only or (first.port or 443) == (second.port or 443)):
                invalid.update((a, b))
        except ValueError:
            invalid.update((a, b))
    name = PREFIX + "KMS_KEY_ARN"
    match = _KMS_ARN.fullmatch(selected[name])
    if match is None or match.group(1) != selected[PREFIX + "AWS_REGION"]:
        invalid.update((name, PREFIX + "AWS_REGION"))
    name = PREFIX + "KMS_CREDENTIALS_FILE"
    if not _absolute(selected[name]) or not _owned_reference(Path(selected[name])):
        invalid.add(name)
    for suffix in ("RUNNER_BINARY", "AW_BINARY", "RUNNER_CONFIG_FILE", "RUNNER_STATE_DIR"):
        name = PREFIX + suffix
        if not _absolute(selected[name]):
            invalid.add(name)
        elif suffix.endswith("BINARY"):
            try:
                if not Path(selected[name]).is_file() or not os.access(selected[name], os.X_OK):
                    invalid.add(name)
            except (OSError, ValueError):
                invalid.add(name)
    homes: dict[Path, str] = {}
    for actor in ACTORS:
        name = PREFIX + actor + "_IDENTITY_HOME"
        path = Path(selected[name])
        if not _absolute(selected[name]) or not _owned_reference(path, directory=True):
            invalid.add(name)
        else:
            resolved = path.resolve()
            if resolved in homes:
                invalid.update((name, homes[resolved]))
            homes[resolved] = name
    try:
        runner_uid(selected)
    except LabConfigurationError:
        invalid.add(PREFIX + "RUNNER_USER")
    if private_dns == "included":
        name = PREFIX + "PRIVATE_DNS_NAME"
        value = source.get(name, "")
        selected[name] = value.strip() if isinstance(value, str) else ""
        if not _dns_name(selected[name]):
            invalid.add(name)
    if invalid:
        raise LabConfigurationError(invalid)
    return MappingProxyType(selected)


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-dns", required=True, choices=("included", "excluded"))
    args = parser.parse_args()
    try:
        environment = load_lab_environment(private_dns=args.private_dns)
    except LabConfigurationError as refused:
        print(str(refused), file=sys.stderr)
        return 2
    print(f"Lab reference checks passed ({len(environment)} inputs; DNS {args.private_dns}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
