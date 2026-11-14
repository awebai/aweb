"""Frozen-request display templates exported by the operation definition.

Sources are JSON pointers into the frozen request, never live lookups. New
resolved names require the separately negotiated wire description; this data
does not add members to an existing prepared request.

Every surface (approval page, mail, owner page, CLI) fills the same templates
the same way: a ``{/pointer}`` is read from the frozen request; a string shows
as itself, an integer in decimal and a list of strings joined with ", ".
Technical rows also show any other value as canonical JSON. A row's label is
its key with underscores as spaces and the first letter capitalised. A pointer that is
missing, or a title, consequence or name that is not one of those values,
refuses: a surface never shows a blank or invented word.
"""

import re
from dataclasses import dataclass

from awid.signing import canonical_json_bytes

from .types import SignerRefused

_TEMPLATE = re.compile(r"\{(/[^{}]*)\}")


def _read(request, pointer: str):
    value = request
    for part in pointer.split("/")[1:]:
        if not isinstance(value, dict) or part not in value:
            raise SignerRefused("request_invalid")
        value = value[part]
    return value


def _words(value) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return ", ".join(value)
    raise SignerRefused("request_invalid")


def _technical(value) -> str:
    try:
        return _words(value)
    except SignerRefused:
        return canonical_json_bytes(value).decode()


def _label(key: str) -> str:
    words = key.replace("_", " ")
    return words[:1].upper() + words[1:]


def _fill(template: str, request) -> str:
    return _TEMPLATE.sub(lambda match: _words(_read(request, match.group(1))), template)


@dataclass(frozen=True)
class OperationDisplay:
    title: str
    consequences: tuple[str, ...]
    names: tuple[tuple[str, str], ...]
    technical: tuple[tuple[str, str], ...]
    refusals: tuple[tuple[str, str], ...]
    responsibility_statement: str | None = None

    def fields(self):
        return {"title": self.title,
            "consequences": ([self.responsibility_statement] if self.responsibility_statement else []) + list(self.consequences),
            "names": dict(self.names), "technical": dict(self.technical), "refusals": dict(self.refusals)}

    def render(self, request) -> dict:
        """The words every surface shows for one frozen request."""
        fields = self.fields()
        return {"title": _fill(self.title, request),
            "consequences": [_fill(line, request) for line in fields["consequences"]],
            "names": [[_label(label), _words(_read(request, source))] for label, source in self.names],
            "technical": [[_label(label), _technical(_read(request, source))] for label, source in self.technical]}

    def refusal(self, code: str) -> str | None:
        return dict(self.refusals).get(code)
