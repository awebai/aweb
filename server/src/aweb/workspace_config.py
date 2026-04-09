"""Workspace configuration reading from .aw/workspace.yaml files."""

from dataclasses import dataclass
from pathlib import Path

import yaml

MAX_CONFIG_SIZE = 8192  # 8KB max for .aw/workspace.yaml


@dataclass
class WorkspaceConfig:
    """Configuration loaded from a .aw/workspace.yaml file."""

    workspace_id: str | None = None
    alias: str | None = None
    human_name: str | None = None
    repo_origin: str | None = None


def load_workspace_config(path: Path | None = None) -> WorkspaceConfig | None:
    """Load workspace configuration from .aw/workspace.yaml.

    Args:
        path: Directory containing the `.aw` directory. Defaults to current directory.
              Security note: Caller must ensure this path is trusted.

    Returns:
        WorkspaceConfig if file exists, None if file doesn't exist.

    Raises:
        ValueError: If file is too large or unreadable.
    """
    if path is None:
        path = Path.cwd()

    config_file = path / ".aw" / "workspace.yaml"
    if not config_file.exists():
        return None

    try:
        file_size = config_file.stat().st_size
        if file_size > MAX_CONFIG_SIZE:
            raise ValueError(
                f"{config_file} is too large ({file_size} bytes, max {MAX_CONFIG_SIZE})"
            )
        content = config_file.read_text(encoding="utf-8")
    except PermissionError:
        raise ValueError(f"Cannot read {config_file}: Permission denied")
    except UnicodeDecodeError:
        raise ValueError(f"{config_file} is not valid UTF-8 text")
    except OSError as e:
        raise ValueError(f"Error reading {config_file}: {e}")

    try:
        parsed = yaml.safe_load(content) or {}
    except yaml.YAMLError as e:
        raise ValueError(f"{config_file} is not valid YAML: {e}") from e

    if not isinstance(parsed, dict):
        raise ValueError(f"{config_file} must contain a YAML mapping")

    return WorkspaceConfig(
        workspace_id=str(parsed.get("workspace_id") or "") or None,
        alias=str(parsed.get("alias") or "") or None,
        human_name=str(parsed.get("human_name") or "") or None,
        repo_origin=str(parsed.get("canonical_origin") or parsed.get("repo_origin") or "") or None,
    )


def _get_config_field(
    field: str, override: str | None = None, path: Path | None = None
) -> str | None:
    """Return override if given, otherwise load field from .aw/workspace.yaml."""
    if override:
        return override
    config = load_workspace_config(path)
    if config:
        return getattr(config, field, None)
    return None


def get_workspace_id(override: str | None = None, path: Path | None = None) -> str | None:
    """Get workspace_id, preferring explicit override over .aw/workspace.yaml."""
    return _get_config_field("workspace_id", override, path)


def get_human_name(override: str | None = None, path: Path | None = None) -> str | None:
    """Get human_name, preferring explicit override over .aw/workspace.yaml."""
    return _get_config_field("human_name", override, path)


def get_alias(override: str | None = None, path: Path | None = None) -> str | None:
    """Get alias, preferring explicit override over .aw/workspace.yaml."""
    return _get_config_field("alias", override, path)


def get_repo_origin(override: str | None = None, path: Path | None = None) -> str | None:
    """Get repo_origin, preferring explicit override over .aw/workspace.yaml."""
    return _get_config_field("repo_origin", override, path)
