"""Load default team roles and team instructions from disk."""

from __future__ import annotations

import copy
import logging
import threading
from pathlib import Path
from typing import Any, Dict, Tuple

import yaml

logger = logging.getLogger(__name__)

_DEFAULT_BUNDLE_CACHE: Dict[str, Any] | None = None
_DEFAULT_TEAM_INSTRUCTIONS_CACHE: Dict[str, Any] | None = None
_CACHE_LOCK = threading.Lock()


def parse_frontmatter(content: str) -> Tuple[Dict[str, Any], str]:
    """Parse YAML frontmatter and body from markdown content."""
    content = content.strip()

    if not content.startswith("---"):
        raise ValueError("File is missing YAML frontmatter (must start with ---)")

    end_idx = content.find("---", 3)
    if end_idx == -1:
        raise ValueError("File has invalid YAML frontmatter (missing closing ---)")

    frontmatter_str = content[3:end_idx].strip()
    body = content[end_idx + 3 :].strip()

    try:
        frontmatter = yaml.safe_load(frontmatter_str)
    except yaml.YAMLError as exc:
        raise ValueError(f"File has invalid YAML frontmatter: {exc}") from exc

    if frontmatter is None:
        frontmatter = {}

    if not isinstance(frontmatter, dict):
        raise ValueError("File has invalid YAML frontmatter (must be a mapping)")

    return frontmatter, body


def load_role(file_path: Path) -> Tuple[str, Dict[str, Any]]:
    """Load a role definition from a markdown file."""
    content = file_path.read_text(encoding="utf-8")
    frontmatter, body = parse_frontmatter(content)

    role_id = frontmatter.get("id")
    title = frontmatter.get("title")
    if role_id is None:
        raise ValueError(f"Role file '{file_path}' is missing required 'id' field")
    if not isinstance(role_id, str):
        raise ValueError(
            f"Role file '{file_path}' has invalid 'id' field "
            f"(must be string, got {type(role_id).__name__})"
        )
    if title is None:
        raise ValueError(f"Role file '{file_path}' is missing required 'title' field")
    if not isinstance(title, str):
        raise ValueError(
            f"Role file '{file_path}' has invalid 'title' field "
            f"(must be string, got {type(title).__name__})"
        )

    return role_id, {
        "title": title,
        "playbook_md": body,
    }


def load_default_bundle(defaults_dir: Path) -> Dict[str, Any]:
    """Load the default team roles bundle from disk."""
    roles_dir = defaults_dir / "roles"
    if not roles_dir.is_dir():
        raise ValueError(
            f"Defaults directory '{defaults_dir}' is missing required 'roles' subdirectory"
        )

    roles: Dict[str, Dict[str, Any]] = {}
    for file_path in sorted(roles_dir.glob("*.md")):
        if file_path.name.startswith("."):
            continue
        role_id, role_data = load_role(file_path)
        if role_id in roles:
            raise ValueError(f"Duplicate role ID '{role_id}' found in '{file_path}'")
        roles[role_id] = role_data

    logger.info("Loaded default team roles bundle: %d roles", len(roles))
    return {
        "roles": roles,
        "adapters": {},
    }


def load_default_team_instructions(defaults_dir: Path) -> Dict[str, Any]:
    """Load the default shared team instructions from disk."""
    file_path = defaults_dir / "team_instructions.md"
    if not file_path.is_file():
        raise ValueError(
            f"Defaults directory '{defaults_dir}' is missing required 'team_instructions.md'"
        )

    return {
        "body_md": file_path.read_text(encoding="utf-8").strip(),
        "format": "markdown",
    }


def get_default_bundle(force_reload: bool = False) -> Dict[str, Any]:
    """Get the default team roles bundle, loading from disk if needed."""
    global _DEFAULT_BUNDLE_CACHE

    if force_reload or _DEFAULT_BUNDLE_CACHE is None:
        with _CACHE_LOCK:
            if force_reload or _DEFAULT_BUNDLE_CACHE is None:
                defaults_dir = Path(__file__).parents[1] / "defaults"
                _DEFAULT_BUNDLE_CACHE = load_default_bundle(defaults_dir)

    return copy.deepcopy(_DEFAULT_BUNDLE_CACHE)


def get_default_team_instructions(force_reload: bool = False) -> Dict[str, Any]:
    """Get the default shared team instructions, loading from disk if needed."""
    global _DEFAULT_TEAM_INSTRUCTIONS_CACHE

    if force_reload or _DEFAULT_TEAM_INSTRUCTIONS_CACHE is None:
        with _CACHE_LOCK:
            if force_reload or _DEFAULT_TEAM_INSTRUCTIONS_CACHE is None:
                defaults_dir = Path(__file__).parents[1] / "defaults"
                _DEFAULT_TEAM_INSTRUCTIONS_CACHE = load_default_team_instructions(
                    defaults_dir
                )

    return copy.deepcopy(_DEFAULT_TEAM_INSTRUCTIONS_CACHE)


def clear_default_bundle_cache() -> None:
    """Clear cached defaults (for testing)."""
    global _DEFAULT_BUNDLE_CACHE
    global _DEFAULT_TEAM_INSTRUCTIONS_CACHE
    with _CACHE_LOCK:
        _DEFAULT_BUNDLE_CACHE = None
        _DEFAULT_TEAM_INSTRUCTIONS_CACHE = None
