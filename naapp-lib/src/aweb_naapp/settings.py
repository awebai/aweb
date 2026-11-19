"""Mounted setting values shared by runtime and dependency-light email settings."""

from pathlib import Path

from aweb_naapp.key_file import read_key_file


def mounted_value(name: str, value: str | None, file_path: str | None) -> str | None:
    """Resolve NAME or NAME_FILE, keeping file checks and errors value-free.

    Files use the existing mounted-key reader: regular (including projected
    symlinks), not group/world writable, at most 1 KiB. Remove one trailing LF,
    as the existing mail password reader does; no other whitespace is changed.
    """
    if file_path is None:
        return value
    if value is not None:
        raise ValueError(f"configure only one of {name} and {name}_FILE")
    if not file_path:
        raise ValueError(f"{name}_FILE must name a file")
    content = read_key_file(Path(file_path))
    try:
        text = content.decode("utf-8").removesuffix("\n")
    except UnicodeDecodeError:
        raise ValueError(f"{name}_FILE must hold UTF-8 text") from None
    if not text:
        raise ValueError(f"{name}_FILE is empty")
    return text
