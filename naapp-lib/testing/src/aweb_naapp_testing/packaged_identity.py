"""Image identity assertions shared by the host lab and its in-image probe."""

import re


class PackagedIdentityError(ValueError):
    """Only fixed, public failure codes; never image settings or values."""


def require_commit(expected: str, actual: str | None) -> None:
    if not re.fullmatch(r"[0-9a-f]{40}", expected) or actual != expected:
        raise PackagedIdentityError("packaged build identity mismatch")


def require_user(declared: str, observed: list[int], expected: tuple[int, int]) -> None:
    if (
        not isinstance(declared, str)
        or not re.fullmatch(r"[1-9][0-9]*:[1-9][0-9]*", declared)
        or not isinstance(observed, list)
        or len(observed) != 2
        or any(type(value) is not int for value in observed)
        or tuple(map(int, declared.split(":"))) != expected
        or tuple(observed) != expected
    ):
        raise PackagedIdentityError("packaged image USER mismatch")
