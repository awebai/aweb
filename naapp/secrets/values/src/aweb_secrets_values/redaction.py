"""Known-value redaction (secrets §7.6 step 4).

Every value opened or derived in one dispatch is added here: the raw value, an
OAuth access token, the Basic composite. Each is replaced by
``[REDACTED:<secret_ref>]`` wherever it appears, in each encoding it can come
back in:

- raw, and hex in either case;
- base64 and base64url, padded or not, and at any alignment inside a longer
  base64 payload;
- percent-encoded, with ``%20`` or ``+`` for spaces, its hex digits in any case;
- JSON-escaped, with or without ``\\/`` for ``/`` and ``\\uXXXX`` for
  non-ASCII, in either case.

A JSON document is also redacted over its decoded strings, which covers any
escaping a serializer chooses. A body cut short is redacted at its tail, so it
never ends in the first part of a value. Matches are counted.

Redaction does not prove confidentiality: an upstream can transform a value in
ways no list of encodings covers. Projection and the token-issuing policy are
what bound what leaves.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, quote_plus


@dataclass(frozen=True)
class _Form:
    """One encoded form of a value. A percent form matches the two hex digits
    after each ``%`` in either case."""

    literal: bytes
    percent: bool
    replacement: bytes

    def fragment(self) -> bytes:
        if not self.percent:
            return re.escape(self.literal)
        parts: list[bytes] = []
        index = 0
        while index < len(self.literal):
            if self.literal[index : index + 1] == b"%" and index + 3 <= len(self.literal):
                parts.append(b"%")
                for digit in self.literal[index + 1 : index + 3]:
                    char = bytes([digit])
                    parts.append(
                        b"[" + char.upper() + char.lower() + b"]" if char.isalpha() else char
                    )
                index += 3
            else:
                parts.append(re.escape(self.literal[index : index + 1]))
                index += 1
        return b"".join(parts)

    def has_prefix(self, tail: bytes) -> bool:
        prefix = self.literal[: len(tail)]
        return tail == prefix or (self.percent and tail.lower() == prefix.lower())


def _base64_middles(raw: bytes) -> set[bytes]:
    """The part of base64(filler + raw), for 0, 1 and 2 filler bytes, that
    depends on ``raw`` alone: how the value reads inside a longer payload."""
    middles: set[bytes] = set()
    for filler in range(3):
        start = -(-filler * 8 // 6)
        end = (filler + len(raw)) * 8 // 6
        for encode in (base64.b64encode, base64.urlsafe_b64encode):
            middle = encode(b"\x00" * filler + raw)[start:end]
            if middle:
                middles.add(middle)
    return middles


def _json_escapes(value: str) -> set[str]:
    plain = json.dumps(value, ensure_ascii=False)[1:-1]
    ascii_escaped = json.dumps(value, ensure_ascii=True)[1:-1]
    upper = re.sub(r"\\u([0-9a-f]{4})", lambda m: "\\u" + m.group(1).upper(), ascii_escaped)
    forms = {plain, ascii_escaped, upper}
    return forms | {form.replace("/", "\\/") for form in forms}


def _forms(value: str, replacement: bytes) -> list[_Form]:
    raw = value.encode("utf-8")
    b64 = base64.b64encode(raw)
    b64url = base64.urlsafe_b64encode(raw)
    literals = {raw, raw.hex().encode(), raw.hex().upper().encode()}
    literals |= {b64, b64.rstrip(b"="), b64url, b64url.rstrip(b"=")} | _base64_middles(raw)
    literals |= {form.encode("utf-8") for form in _json_escapes(value)}
    percents = {quote(value, safe="").encode(), quote_plus(value).encode()} - literals
    return [_Form(literal, False, replacement) for literal in literals] + [
        _Form(literal, True, replacement) for literal in percents
    ]


class KnownValues:
    """The values to redact from one dispatch's output, each under its ref."""

    def __init__(self) -> None:
        self._forms: list[_Form] = []
        self._pattern: re.Pattern[bytes] | None = None

    def add(self, secret_ref: str, value: str) -> None:
        if not value:
            raise ValueError("a known value must not be empty")
        self._forms += _forms(value, f"[REDACTED:{secret_ref}]".encode())
        # Longest first, so a value never leaves part of a longer one behind.
        self._forms.sort(key=lambda form: len(form.literal), reverse=True)
        self._pattern = None

    def add_basic(self, secret_ref: str, username: str, password: str) -> None:
        """A Basic credential: the password and the ``user:pass`` composite,
        whose base64 is what the Authorization header carries."""
        self.add(secret_ref, password)
        self.add(secret_ref, f"{username}:{password}")

    def redact(self, data: bytes) -> tuple[bytes, int]:
        """``data`` with every known form replaced, and the number replaced."""
        if not self._forms:
            return data, 0
        if self._pattern is None:
            self._pattern = re.compile(
                b"|".join(b"(" + form.fragment() + b")" for form in self._forms)
            )
        count = 0

        def replace(match: re.Match[bytes]) -> bytes:
            nonlocal count
            count += 1
            assert match.lastindex is not None
            return self._forms[match.lastindex - 1].replacement

        return self._pattern.sub(replace, data), count

    def redact_text(self, text: str) -> tuple[str, int]:
        redacted, count = self.redact(text.encode("utf-8"))
        return redacted.decode("utf-8"), count

    def redact_json(self, data: bytes) -> tuple[bytes, int]:
        """A JSON document with every known value redacted from its decoded
        strings, keys included, and re-serialized if anything was. Anything
        else, or a document with nothing to redact, keeps its bytes."""
        try:
            document = json.loads(data)
        except ValueError:
            return data, 0
        count = 0

        def walk(value: Any) -> Any:
            nonlocal count
            if isinstance(value, str):
                redacted, found = self.redact_text(value)
                count += found
                return redacted
            if isinstance(value, list):
                return [walk(item) for item in value]
            if isinstance(value, dict):
                return {walk(key): walk(item) for key, item in value.items()}
            return value

        redacted = walk(document)
        if not count:
            return data, 0
        return json.dumps(redacted, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        ), count

    def redact_tail(self, data: bytes) -> tuple[bytes, int]:
        """A body cut short with its tail replaced when it is the first part,
        of any length, of a known form."""
        for length in range(
            min(len(data), max((len(f.literal) for f in self._forms), default=1) - 1), 0, -1
        ):
            tail = data[-length:]
            for form in self._forms:
                if len(form.literal) > length and form.has_prefix(tail):
                    return data[:-length] + form.replacement, 1
        return data, 0
