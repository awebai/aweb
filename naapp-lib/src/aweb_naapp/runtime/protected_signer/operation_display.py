"""Frozen-request display templates exported by the operation definition.

Sources are JSON pointers into the frozen request, never live lookups. New
resolved names require the separately negotiated wire description; this data
does not add members to an existing prepared request.

Every surface (approval page, mail, owner page, CLI) fills the same templates
the same way: a ``{/pointer}`` is read from the frozen request; a string shows
as itself, an integer in decimal and a list of strings joined with ", ".
Technical rows also show any other value as canonical JSON. A pointer may end
in ``|team`` to show a team id ("name:domain"), or each in a list, by its name,
in ``|kind`` to name a frozen target kind ("agent", "kind not verified"), or in
``|period`` to name a window in seconds ("hour", "day", "N seconds"). A
definition may name its requester: when ``/requester`` equals the value at its
first pointer, the requester shows as the value at its second. A row's label is
its key with underscores as spaces and the first letter capitalised. A pointer that is
missing, or a title, consequence or name that is not one of those values,
refuses: a surface never shows a blank or invented word.
"""

import re
from dataclasses import dataclass

from awid.signing import canonical_json_bytes

from .types import SignerRefused

_TEMPLATE = re.compile(r"\{(/[^{}]*)\}")


def _team_name(team_id):
    if not isinstance(team_id, str) or team_id.count(":") != 1 or not team_id.split(":")[0]:
        raise SignerRefused("request_invalid")
    return team_id.split(":")[0]


# A frozen target kind in the words the owner page uses.
_KINDS = {"agent": "agent", "kind not verified": "agent or person not confirmed"}


def _period(seconds):
    if not isinstance(seconds, int) or isinstance(seconds, bool) or seconds <= 0:
        raise SignerRefused("request_invalid")
    return {3600: "hour", 86400: "day"}.get(seconds, f"{seconds} seconds")


def _formatted(value, formatter):
    """``|team`` shows a team id ("name:domain") by its name, as the owner page
    does; ``|kind`` names a frozen target kind. Any other value refuses."""
    if formatter == "period":
        return _period(value)
    if formatter == "kind":
        if not isinstance(value, str) or value not in _KINDS:
            raise SignerRefused("request_invalid")
        return _KINDS[value]
    if formatter != "team":
        raise SignerRefused("request_invalid")
    if isinstance(value, list):
        return [_team_name(item) for item in value]
    return _team_name(value)


def _read(request, source: str):
    pointer, _, formatter = source.partition("|")
    value = request
    for part in pointer.split("/")[1:]:
        if not isinstance(value, dict) or part not in value:
            raise SignerRefused("request_invalid")
        value = value[part]
    return _formatted(value, formatter) if formatter else value


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
    requester_name: tuple[str, str] | None = None

    def fields(self):
        return {"title": self.title,
            "consequences": ([self.responsibility_statement] if self.responsibility_statement else []) + list(self.consequences),
            "names": dict(self.names), "technical": dict(self.technical), "refusals": dict(self.refusals),
            **({"requester_name": list(self.requester_name)} if self.requester_name else {})}

    def render(self, request) -> dict:
        """The words every surface shows for one frozen request."""
        fields = self.fields()
        return {"title": _fill(self.title, request),
            "consequences": [_fill(line, request) for line in fields["consequences"]],
            "names": [[_label(label), _words(_read(request, source))] for label, source in self.names],
            "technical": [[_label(label), _technical(_read(request, source))] for label, source in self.technical],
            **({"requester": self._requester(request)} if self.requester_name else {})}

    def _requester(self, request) -> str:
        """The requester, by the subject's frozen name when it is that subject."""
        assert self.requester_name is not None
        requester = _words(_read(request, "/requester"))
        who, name = self.requester_name
        return _words(_read(request, name)) if _read(request, who) == requester else requester

    def refusal(self, code: str) -> str | None:
        return dict(self.refusals).get(code)
