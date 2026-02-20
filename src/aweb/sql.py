from __future__ import annotations


def escape_like(value: str, *, escape_char: str = "\\") -> str:
    """Escape a string for use in a SQL LIKE pattern.

    Escapes:
    - escape_char itself
    - '%' wildcard
    - '_' single-character wildcard
    """
    if len(escape_char) != 1:
        raise ValueError("escape_char must be a single character")

    escaped = value.replace(escape_char, escape_char + escape_char)
    escaped = escaped.replace("%", escape_char + "%")
    escaped = escaped.replace("_", escape_char + "_")
    return escaped
