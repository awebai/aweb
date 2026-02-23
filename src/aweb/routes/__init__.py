"""Route subpackage for aweb FastAPI endpoints."""


def format_agent_address(project_slug: str, alias: str) -> str:
    """Build a display address from a project slug and agent alias.

    Network messages store from_alias as a full address (``org/alias``).
    Local messages store just the bare alias. This helper detects the
    difference so callers never double-prefix.
    """
    if "/" in alias:
        return alias
    if project_slug:
        return f"{project_slug}/{alias}"
    return alias
