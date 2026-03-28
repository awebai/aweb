"""Load the default project roles bundle from markdown files.

Default invariants and roles are stored as markdown files with YAML frontmatter
in the `defaults/` directory. This module loads and parses them into a project roles
bundle structure at server startup.

File structure:
    defaults/
    ├── invariants/
    │   ├── tracking-aw-only.md
    │   ├── communication-mail-first.md
    │   └── ...
    └── roles/
        ├── coordinator.md
        ├── developer.md
        └── reviewer.md

Each file has YAML frontmatter:
    ---
    id: tracking.aw-only
    title: Use aw for coordination tracking
    ---

    Markdown body content...

Note: Frontmatter parsing uses simple string matching. Avoid using "---" within
YAML values (e.g., in multi-line strings) as it may be incorrectly detected as
the frontmatter closing delimiter.
"""

import copy
import logging
import threading
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

import yaml

logger = logging.getLogger(__name__)

# Cache for the default bundle (loaded once at startup)
_DEFAULT_BUNDLE_CACHE: Dict[str, Any] | None = None
_CACHE_LOCK = threading.Lock()


def parse_frontmatter(content: str) -> Tuple[Dict[str, Any], str]:
    """Parse YAML frontmatter and body from markdown content.

    Args:
        content: Full markdown file content with frontmatter.

    Returns:
        Tuple of (frontmatter dict, body string).

    Raises:
        ValueError: If frontmatter is missing or malformed.
    """
    content = content.strip()

    if not content.startswith("---"):
        raise ValueError("File is missing YAML frontmatter (must start with ---)")

    # Find the closing ---
    end_idx = content.find("---", 3)
    if end_idx == -1:
        raise ValueError("File has invalid YAML frontmatter (missing closing ---)")

    frontmatter_str = content[3:end_idx].strip()
    body = content[end_idx + 3 :].strip()

    try:
        frontmatter = yaml.safe_load(frontmatter_str)
    except yaml.YAMLError as e:
        raise ValueError(f"File has invalid YAML frontmatter: {e}") from e

    if frontmatter is None:
        frontmatter = {}

    if not isinstance(frontmatter, dict):
        raise ValueError("File has invalid YAML frontmatter (must be a mapping)")

    return frontmatter, body


def load_invariant(file_path: Path) -> Dict[str, Any]:
    """Load an invariant from a markdown file.

    Args:
        file_path: Path to the markdown file.

    Returns:
        Dict with id, title, and body_md keys.

    Raises:
        ValueError: If required fields are missing or have wrong type.
    """
    content = file_path.read_text(encoding="utf-8")
    frontmatter, body = parse_frontmatter(content)

    if "id" not in frontmatter:
        raise ValueError(f"Invariant file '{file_path}' is missing required 'id' field")

    if "title" not in frontmatter:
        raise ValueError(f"Invariant file '{file_path}' is missing required 'title' field")

    invariant_id = frontmatter["id"]
    if not isinstance(invariant_id, str):
        raise ValueError(
            f"Invariant file '{file_path}' has invalid 'id' field "
            f"(must be string, got {type(invariant_id).__name__})"
        )

    title = frontmatter["title"]
    if not isinstance(title, str):
        raise ValueError(
            f"Invariant file '{file_path}' has invalid 'title' field "
            f"(must be string, got {type(title).__name__})"
        )

    return {
        "id": invariant_id,
        "title": title,
        "body_md": body,
    }


def load_role(file_path: Path) -> Tuple[str, Dict[str, Any]]:
    """Load a role from a markdown file.

    Args:
        file_path: Path to the markdown file.

    Returns:
        Tuple of (role_id, role_data dict with title and playbook_md).

    Raises:
        ValueError: If required fields are missing or have wrong type.
    """
    content = file_path.read_text(encoding="utf-8")
    frontmatter, body = parse_frontmatter(content)

    if "id" not in frontmatter:
        raise ValueError(f"Role file '{file_path}' is missing required 'id' field")

    if "title" not in frontmatter:
        raise ValueError(f"Role file '{file_path}' is missing required 'title' field")

    role_id = frontmatter["id"]
    if not isinstance(role_id, str):
        raise ValueError(
            f"Role file '{file_path}' has invalid 'id' field "
            f"(must be string, got {type(role_id).__name__})"
        )

    title = frontmatter["title"]
    if not isinstance(title, str):
        raise ValueError(
            f"Role file '{file_path}' has invalid 'title' field "
            f"(must be string, got {type(title).__name__})"
        )

    role_data = {
        "title": title,
        "playbook_md": body,
    }

    return role_id, role_data


def load_default_bundle(defaults_dir: Path) -> Dict[str, Any]:
    """Load the complete default project roles bundle from a directory.

    Args:
        defaults_dir: Path to the defaults directory containing
            invariants/ and roles/ subdirectories.

    Returns:
        Project roles bundle dict with invariants, roles, and adapters keys.

    Raises:
        ValueError: If required directories are missing or duplicate IDs found.
    """
    invariants_dir = defaults_dir / "invariants"
    roles_dir = defaults_dir / "roles"

    if not invariants_dir.is_dir():
        raise ValueError(
            f"Defaults directory '{defaults_dir}' is missing required 'invariants' subdirectory"
        )

    if not roles_dir.is_dir():
        raise ValueError(
            f"Defaults directory '{defaults_dir}' is missing required 'roles' subdirectory"
        )

    # Load invariants
    invariants: List[Dict[str, Any]] = []
    seen_invariant_ids: Set[str] = set()
    for file_path in sorted(invariants_dir.glob("*.md")):
        # Skip hidden files
        if file_path.name.startswith("."):
            continue
        invariant = load_invariant(file_path)
        if invariant["id"] in seen_invariant_ids:
            raise ValueError(f"Duplicate invariant ID '{invariant['id']}' found in '{file_path}'")
        seen_invariant_ids.add(invariant["id"])
        invariants.append(invariant)

    # Load roles
    roles: Dict[str, Dict[str, Any]] = {}
    for file_path in sorted(roles_dir.glob("*.md")):
        # Skip hidden files
        if file_path.name.startswith("."):
            continue
        role_id, role_data = load_role(file_path)
        if role_id in roles:
            raise ValueError(f"Duplicate role ID '{role_id}' found in '{file_path}'")
        roles[role_id] = role_data

    logger.info(
        "Loaded default project roles bundle: %d invariants, %d roles",
        len(invariants),
        len(roles),
    )

    return {
        "invariants": invariants,
        "roles": roles,
        "adapters": {},
    }


def get_default_bundle(force_reload: bool = False) -> Dict[str, Any]:
    """Get the default project roles bundle, loading from disk if not cached.

    Returns a deep copy to prevent callers from modifying the cached bundle.

    Args:
        force_reload: If True, bypass cache and reload from disk. The reload
            is atomic (protected by lock) so concurrent calls are safe.

    Returns:
        The default project roles bundle dict.
    """
    global _DEFAULT_BUNDLE_CACHE

    if force_reload or _DEFAULT_BUNDLE_CACHE is None:
        with _CACHE_LOCK:
            # Double-check pattern for thread safety
            if force_reload or _DEFAULT_BUNDLE_CACHE is None:
                defaults_dir = Path(__file__).parents[1] / "defaults"
                _DEFAULT_BUNDLE_CACHE = load_default_bundle(defaults_dir)

    # Return a copy to prevent callers from mutating the cache
    return copy.deepcopy(_DEFAULT_BUNDLE_CACHE)


def clear_default_bundle_cache() -> None:
    """Clear the cached default bundle (for testing)."""
    global _DEFAULT_BUNDLE_CACHE
    with _CACHE_LOCK:
        _DEFAULT_BUNDLE_CACHE = None
