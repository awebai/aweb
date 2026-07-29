from __future__ import annotations

import os
import re

_FULL_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_SERVICE_ID = re.compile(r"^srv-[a-z0-9]+$")
_SERVICE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_REPO_SLUG = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_RENDER_DEPLOYMENT_ENV = {
    "service_id": "RENDER_SERVICE_ID",
    "service_name": "RENDER_SERVICE_NAME",
    "hostname": "RENDER_EXTERNAL_HOSTNAME",
    "repo": "RENDER_GIT_REPO_SLUG",
    "branch": "RENDER_GIT_BRANCH",
    "commit": "RENDER_GIT_COMMIT",
}


def _validated_sha(name: str) -> str | None:
    value = (os.getenv(name) or "").strip()
    if not value:
        return None
    if not _FULL_GIT_SHA.fullmatch(value):
        raise ValueError(f"{name} must be a full lowercase 40-character Git SHA")
    return value


def _clean_automatic_value(name: str) -> str | None:
    value = (os.getenv(name) or "").strip()
    if not value:
        return None
    if len(value) > 255 or any(ord(character) < 32 for character in value):
        raise ValueError(f"{name} has an invalid automatic Render metadata value")
    return value


def resolve_render_deployment_identity() -> dict[str, str] | None:
    """Return Render's automatic public deployment metadata when available.

    A commit by itself remains valid build identity for local tests. Once any
    automatic topology field is present, the complete Render-provided identity
    is required. Region is intentionally absent: Render publishes no automatic
    region metadata, and a configured value would not independently attest it.
    """
    values = {
        field: _clean_automatic_value(environment_name)
        for field, environment_name in _RENDER_DEPLOYMENT_ENV.items()
    }
    if not any(values[field] for field in values if field != "commit"):
        return None

    missing = [
        environment_name
        for field, environment_name in _RENDER_DEPLOYMENT_ENV.items()
        if values[field] is None
    ]
    if missing:
        raise ValueError(f"missing automatic Render metadata: {', '.join(missing)}")

    service_id = values["service_id"]
    service_name = values["service_name"]
    hostname = values["hostname"]
    repo = values["repo"]
    branch = values["branch"]
    commit = values["commit"]
    assert service_id is not None
    assert service_name is not None
    assert hostname is not None
    assert repo is not None
    assert branch is not None
    assert commit is not None
    if not _SERVICE_ID.fullmatch(service_id):
        raise ValueError("RENDER_SERVICE_ID has an invalid automatic Render metadata value")
    if not _SERVICE_NAME.fullmatch(service_name):
        raise ValueError("RENDER_SERVICE_NAME has an invalid automatic Render metadata value")
    if not _HOSTNAME.fullmatch(hostname):
        raise ValueError("RENDER_EXTERNAL_HOSTNAME has an invalid automatic Render metadata value")
    if not _REPO_SLUG.fullmatch(repo):
        raise ValueError("RENDER_GIT_REPO_SLUG has an invalid automatic Render metadata value")
    if not _FULL_GIT_SHA.fullmatch(commit):
        raise ValueError("RENDER_GIT_COMMIT must be a full lowercase 40-character Git SHA")

    return {
        "service_id": service_id,
        "service_name": service_name,
        "hostname": hostname,
        "origin_url": f"https://{hostname}",
        "repo": repo,
        "branch": branch,
        "commit": commit,
    }


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
