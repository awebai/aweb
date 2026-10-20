"""Known-value redaction (secrets §7.6 step 4).

Every value opened or derived in one dispatch is added here: the raw value, an
OAuth access token, the Basic composite. Each is replaced by
``[REDACTED:<secret_ref>]`` wherever it appears, in each encoding it can come
back in: raw, base64 and base64url (padded or not), hex in either case,
percent-encoded in either case or with ``+`` for spaces, and JSON-escaped.
Matches are counted.

Redaction does not prove confidentiality: an upstream can transform a value in
ways no list of encodings covers. Projection and the token-issuing policy are
what bound what leaves.
"""

from __future__ import annotations

import base64
import json
import re
from urllib.parse import quote, quote_plus


def _percent_lower(encoded: str) -> str:
    return re.sub(r"%[0-9A-F]{2}", lambda match: match.group().lower(), encoded)


def _encodings(value: str) -> set[bytes]:
    raw = value.encode("utf-8")
    b64 = base64.b64encode(raw)
    b64url = base64.urlsafe_b64encode(raw)
    texts = {
        value,
        raw.hex(),
        raw.hex().upper(),
        quote(value, safe=""),
        _percent_lower(quote(value, safe="")),
        quote_plus(value),
        _percent_lower(quote_plus(value)),
        json.dumps(value)[1:-1],
        json.dumps(value, ensure_ascii=False)[1:-1],
    }
    return {text.encode("utf-8") for text in texts} | {
        b64,
        b64.rstrip(b"="),
        b64url,
        b64url.rstrip(b"="),
    }


class KnownValues:
    """The values to redact from one dispatch's output, each under its ref."""

    def __init__(self) -> None:
        self._replacements: dict[bytes, bytes] = {}
        self._pattern: re.Pattern[bytes] | None = None

    def add(self, secret_ref: str, value: str) -> None:
        if not value:
            raise ValueError("a known value must not be empty")
        replacement = f"[REDACTED:{secret_ref}]".encode()
        for encoded in _encodings(value):
            self._replacements.setdefault(encoded, replacement)
        self._pattern = None

    def add_basic(self, secret_ref: str, username: str, password: str) -> None:
        """A Basic credential: the password and the ``user:pass`` composite,
        whose base64 is what the Authorization header carries."""
        self.add(secret_ref, password)
        self.add(secret_ref, f"{username}:{password}")

    def redact(self, data: bytes) -> tuple[bytes, int]:
        """``data`` with every known value replaced, and the number replaced."""
        if not self._replacements:
            return data, 0
        if self._pattern is None:
            # Longest first, so a value never leaves part of a longer one behind.
            alternatives = sorted(self._replacements, key=len, reverse=True)
            self._pattern = re.compile(b"|".join(re.escape(item) for item in alternatives))
        count = 0

        def replace(match: re.Match[bytes]) -> bytes:
            nonlocal count
            count += 1
            return self._replacements[match.group()]

        return self._pattern.sub(replace, data), count

    def redact_text(self, text: str) -> tuple[str, int]:
        redacted, count = self.redact(text.encode("utf-8"))
        return redacted.decode("utf-8"), count
