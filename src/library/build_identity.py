from __future__ import annotations

import os
import re

_FULL_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")


def _validated_sha(name: str) -> str | None:
    value = (os.getenv(name) or "").strip()
    if not value:
        return None
    if not _FULL_GIT_SHA.fullmatch(value):
        raise ValueError(f"{name} must be a full lowercase 40-character Git SHA")
    return value


def resolve_build_identity() -> dict[str, str | None]:
    """Return the source identity injected by Render or a non-Render build.

    Render's platform-provided commit is authoritative when present. The
    Library-specific variable exists for deterministic local image builds and
    tests; it may confirm, but never override, the platform value.
    """
    render_sha = _validated_sha("RENDER_GIT_COMMIT")
    fallback_sha = _validated_sha("LIBRARY_GIT_SHA")
    if render_sha and fallback_sha and render_sha != fallback_sha:
        raise ValueError("RENDER_GIT_COMMIT and LIBRARY_GIT_SHA conflict")
    return {"git_sha": render_sha or fallback_sha}
