"""Immutable public template data, without credential or authority operations."""

import json
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, repr=False)
class JobInputs:
    """Frozen public inputs, not permission to open a value or execute a job.

    Runtime/file checks remain mandatory after this phase. Credential-backed
    environment values remain unknown; no key or plaintext enters this object.
    """

    _definition: bytes
    _params: bytes
    _environment: bytes
    argv: tuple[str, ...]

    @property
    def definition(self) -> dict[str, Any]:
        return dict(json.loads(self._definition))

    @property
    def params(self) -> dict[str, Any]:
        return dict(json.loads(self._params))

    @property
    def environment(self) -> dict[str, str | None]:
        return dict(json.loads(self._environment))
