#!/usr/bin/env python3
"""Fail when an AWID site Markdown mirror links to an unpublished relative path."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

MARKDOWN_LINK = re.compile(r"!?\[[^\]]*\]\(([^)\s]+)(?:\s+[^)]*)?\)")


def main() -> int:
    mirrors = [Path(value) for value in sys.argv[1:]]
    if not mirrors:
        print("FAIL: no AWID site Markdown mirrors supplied", file=sys.stderr)
        return 1

    publication_root = mirrors[0].parent.resolve()
    failures: list[str] = []
    for mirror in mirrors:
        text = mirror.read_text(encoding="utf-8")
        for match in MARKDOWN_LINK.finditer(text):
            target = match.group(1).strip("<>")
            parsed = urlsplit(target)
            if parsed.scheme or parsed.netloc or target.startswith(("#", "/")):
                continue
            relative_path = unquote(parsed.path)
            if not relative_path:
                continue
            resolved = (mirror.parent / relative_path).resolve()
            try:
                resolved.relative_to(publication_root)
            except ValueError:
                published = False
            else:
                published = resolved.is_file()
            if not published:
                line = text.count("\n", 0, match.start()) + 1
                failures.append(
                    f"FAIL: {mirror}:{line} broken relative Markdown link in AWID site context: {target}"
                )

    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(f"AWID site document links resolve in publication context ({len(mirrors)} checked)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
