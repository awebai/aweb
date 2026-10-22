"""File-backed inputs for explicit first-release E2E execution.

This checks configuration only. S19 owns process launch, M7 doctor validates
runner ownership/isolation, and scenario tests establish live service effects.
No credential file is opened here and no supplied value appears in errors.
"""

from __future__ import annotations

import os
import stat
import sys
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from urllib.parse import urlsplit

PREFIX = "AWEB_SECRETS_E2E_"
_METADATA = (
    "KMS_KEY_ARN",
    "AWS_REGION",
    "ONEPASSWORD_VAULT_ID",
    "ONEPASSWORD_ITEM_ID",
    "ONEPASSWORD_API_FIELD_ID",
    "ONEPASSWORD_CLI_FIELD_ID",
    "RUNNER_USER",
    "TEAM_ID",
    "AGENT_A_ID",
    "AGENT_B_ID",
)
_CREDENTIAL_FILES = (
    "KMS_CREDENTIALS_FILE",
    "ONEPASSWORD_TOKEN_FILE",
    "ONEPASSWORD_WRITER_TOKEN_FILE",
    "AGENT_A_MCP_TOKEN_FILE",
    "AGENT_B_MCP_TOKEN_FILE",
)
_ORIGINS = ("API_ORIGIN", "CONSOLE_ORIGIN", "LOGS_ORIGIN")
_RUNNER_PATHS = ("RUNNER_BINARY", "RUNNER_CONFIG_FILE", "RUNNER_STATE_DIR")
REQUIRED_NAMES = tuple(
    PREFIX + name for name in (*_METADATA, *_CREDENTIAL_FILES, *_ORIGINS, "MCP_URL", *_RUNNER_PATHS)
)


class ConfigurationError(ValueError):
    def __init__(self, names: set[str]) -> None:
        super().__init__("Release E2E requires valid inputs: " + ", ".join(sorted(names)))


def _https(value: str, *, origin: bool) -> bool:
    try:
        parsed = urlsplit(value)
        return (
            parsed.scheme == "https"
            and bool(parsed.hostname)
            and parsed.port != 0
            and parsed.username is None
            and parsed.password is None
            and not parsed.query
            and not parsed.fragment
            and (not origin or parsed.path in {"", "/"})
        )
    except ValueError:
        return False


def load_environment(environ: Mapping[str, str] | None = None) -> Mapping[str, str]:
    """Validate named references, returning only the selected configuration.

    The KMS file follows decision45: AWS shared credentials with [default].
    1Password test files are consumed only by E2E's customer-console ingress or
    fixture writer. No application credential loader is provided.
    """
    source = os.environ if environ is None else environ
    selected = {name: source.get(name, "").strip() for name in REQUIRED_NAMES}
    invalid = {name for name, value in selected.items() if not value}
    for suffix in (*_ORIGINS, "MCP_URL"):
        name = PREFIX + suffix
        if not _https(selected[name], origin=suffix in _ORIGINS):
            invalid.add(name)
    for suffix in _CREDENTIAL_FILES:
        name = PREFIX + suffix
        path = Path(selected[name])
        try:
            mode = path.stat().st_mode
            good = (
                path.is_absolute()
                and stat.S_ISREG(mode)
                and mode & 0o077 == 0
                and mode & 0o400 != 0
            )
        except (OSError, ValueError):
            good = False
        if not good:
            invalid.add(name)
    for suffix in _RUNNER_PATHS:
        name = PREFIX + suffix
        # S19 invokes doctor under the runner UID, which alone can traverse its
        # private state directory and check config/job permissions. Do not try
        # to bypass those permissions from the agent/test driver's account.
        if not Path(selected[name]).is_absolute():
            invalid.add(name)
    a, b = PREFIX + "AGENT_A_MCP_TOKEN_FILE", PREFIX + "AGENT_B_MCP_TOKEN_FILE"
    try:
        distinct = Path(selected[a]).resolve() != Path(selected[b]).resolve()
    except (OSError, ValueError):
        distinct = False
    if not distinct:
        invalid.update((a, b))
    a, b = PREFIX + "AGENT_A_ID", PREFIX + "AGENT_B_ID"
    if selected[a] == selected[b]:
        invalid.update((a, b))
    api, console = PREFIX + "API_ORIGIN", PREFIX + "CONSOLE_ORIGIN"
    try:
        api_url, console_url = urlsplit(selected[api]), urlsplit(selected[console])
        if (api_url.hostname, api_url.port or 443) == (
            console_url.hostname,
            console_url.port or 443,
        ):
            invalid.update((api, console))
    except ValueError:
        invalid.update((api, console))
    if invalid:
        raise ConfigurationError(invalid)
    return MappingProxyType(selected)


def main() -> int:
    try:
        configuration = load_environment()
    except ConfigurationError as error:
        print(str(error), file=sys.stderr)
        return 2
    print(f"Release input checks passed ({len(configuration)} inputs).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
