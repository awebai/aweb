"""URL segments shared by the raw-key and typed registry clients."""

from urllib.parse import quote


def address_segment(name: str) -> str:
    """Preserve a registry address name without URL syntax or dot traversal."""
    # quote always leaves dots literal; HTTP clients normalize bare dot segments.
    return name.replace(".", "%2E") if name in (".", "..") else quote(name, safe="")
