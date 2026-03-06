"""Route subpackage for aweb FastAPI endpoints."""


def format_agent_address(namespace_slug: str, alias: str) -> str:
    """Build a display address from a namespace slug and agent alias.

    Network messages store from_alias as a full address (``namespace/alias``).
    Local messages store just the bare alias. This helper detects the
    difference so callers never double-prefix.
    """
    if "/" in alias:
        return alias
    if namespace_slug:
        return f"{namespace_slug}/{alias}"
    return alias
