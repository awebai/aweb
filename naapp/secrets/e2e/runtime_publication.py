"""Private S19 runtime snapshot consumed explicitly by M9.

Enter only after hosted provisioning/both whoami checks and S19 startup are
ready. Stop M9 and exit this context before controller refresh/reprovision;
there is no watcher or concurrent controller writer during a ready session.
Every entry rereads the hosted publication. No credential file is opened.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from release_environment import PREFIX, REQUIRED_NAMES, ConfigurationError, load_environment

_HOSTED_NAMES = frozenset(
    PREFIX + suffix
    for suffix in (
        "TEAM_ID",
        "MCP_URL",
        "AGENT_A_ID",
        "AGENT_B_ID",
        "AGENT_A_MCP_TOKEN_FILE",
        "AGENT_B_MCP_TOKEN_FILE",
    )
)
_HOSTED_INPUT = PREFIX + "HOSTED_RUNTIME_FILE"
_PUBLICATION = PREFIX + "RUNTIME_PUBLICATION"


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    repeated = set()
    for name, value in pairs:
        if name in result:
            repeated.add(name)
        result[name] = value
    if repeated:
        raise ConfigurationError(repeated)
    return result


def _mapping(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping) or any(not isinstance(name, str) for name in value):
        raise ConfigurationError({_HOSTED_INPUT})
    invalid = {
        name
        for name, item in value.items()
        if name not in REQUIRED_NAMES or not isinstance(item, str)
    }
    if invalid:
        raise ConfigurationError(invalid)
    return dict(value)


@contextmanager
def publish_runtime(
    *, hosted_runtime: Path, local: Mapping[str, str], directory: Path
) -> Iterator[Path]:
    """Yield the absolute combined JSON path; remove only this owned snapshot.

    directory must be a new absolute path, distinct from the controller's
    directory. Existing files/directories are never adopted or overwritten.
    On startup failure or teardown, the publication and its empty owned
    directory are removed. The hosted input and raw-token references remain
    untouched; callers JSON-load the yielded path then load_environment(mapping).
    """
    if not hosted_runtime.is_absolute() or not directory.is_absolute():
        raise ConfigurationError({_PUBLICATION})
    try:
        raw = json.loads(hosted_runtime.read_text(encoding="utf-8"), object_pairs_hook=_unique)
    except (OSError, ValueError, UnicodeError) as error:
        if isinstance(error, ConfigurationError):
            raise
        raise ConfigurationError({_HOSTED_INPUT}) from None
    hosted, supplied = _mapping(raw), _mapping(local)
    invalid = set(hosted) ^ _HOSTED_NAMES
    invalid.update(
        name for name in hosted.keys() & supplied.keys() if hosted[name] != supplied[name]
    )
    if invalid:
        raise ConfigurationError(invalid)
    combined = dict(load_environment({**supplied, **hosted}))
    path = directory / "runtime.json"
    try:
        directory.mkdir(mode=0o700)
    except OSError:
        raise ConfigurationError({_PUBLICATION}) from None
    try:
        # O_EXCL creates only our publication; there is no existing-file fallback.
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(combined, output, sort_keys=True)
            output.write("\n")
        yield path
    finally:
        path.unlink(missing_ok=True)
        directory.rmdir()
