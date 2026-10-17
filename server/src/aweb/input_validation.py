from __future__ import annotations

import re

BRANCH_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9/_.-]{0,254}$")
CANONICAL_ORIGIN_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*(/[a-zA-Z0-9][a-zA-Z0-9._-]*)*$")
ALIAS_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$")
HUMAN_NAME_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9 '\-]{0,63}$")


def is_valid_branch_name(branch: str) -> bool:
    if not branch or not isinstance(branch, str):
        return False
    return BRANCH_NAME_PATTERN.fullmatch(branch) is not None


def is_valid_canonical_origin(origin: str) -> bool:
    if not origin or not isinstance(origin, str):
        return False
    if len(origin) > 255:
        return False
    return CANONICAL_ORIGIN_PATTERN.fullmatch(origin) is not None


def is_valid_alias(alias: str) -> bool:
    if not alias or not isinstance(alias, str):
        return False
    return ALIAS_PATTERN.fullmatch(alias) is not None


def is_valid_human_name(name: str) -> bool:
    if not name or not isinstance(name, str):
        return False
    return HUMAN_NAME_PATTERN.fullmatch(name) is not None
