#!/usr/bin/env python3
"""Verify that Markdown cross-references between tracked documents resolve.

WHY THIS EXISTS SEPARATELY FROM check-doc-paths.sh. That gate extracts
backtick-quoted paths beginning with a top-level directory, so it validates
`docs/foo.md` and `server/src/bar.py`. A bare relative link between two
documents in the same directory — `[text](sibling.md)` — carries no such prefix
and is structurally invisible to it. check-extension-docs.py asserts index
completeness, not link targets.

That gap is not theoretical: deleting docs/messaging.md in aweb-aazb.8.2 left
docs/messaging-contract-matrix.md declaring itself subordinate to authorities
"listed in messaging.md", and six green gates said nothing. The document still
read as complete while the route to what overrode it had 404'd.

WHAT THIS CHECKS. Every relative Markdown link in every tracked .md file
resolves to a file that exists, relative to the linking document's own
directory. Anchors are stripped before resolution; a wrong anchor is not
something this can see.

WHAT IT DOES NOT CHECK. Absolute URLs are not fetched — a link to a published
site may still 404 without this noticing. Link *text* is not compared to the
target. And a link that resolves can still point at the wrong document.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path

LINK = re.compile(r"\]\(([^)\s]+?\.md)(#[^)\s]*)?\)")

# Link syntax inside a code span or fenced block is being shown, not followed.
# Without this, any document that explains how links work fails the gate — which
# is how this checker first failed against the contributing guide describing it.
FENCE = re.compile(r"^\s*(```|~~~)", re.M)
CODE_SPAN = re.compile(r"`[^`\n]*`")


def strip_code(text: str) -> str:
    """Blank out fenced blocks and inline code spans, preserving line structure."""
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    in_fence = False
    for line in lines:
        if FENCE.match(line):
            in_fence = not in_fence
            out.append("\n")
            continue
        out.append("\n" if in_fence else CODE_SPAN.sub("", line))
    return "".join(out)


# Public documentation URLs this repository promises. The published site serves
# docs/<name>.md at both /docs/<name>.md and /docs/<name>/, so a rename breaks a
# live URL silently — the epic's "canonical onboarding URLs serve the intended
# content" criterion has no other enforcement.
PUBLIC_DOC_URL = re.compile(r"https?://(?:www\.)?aweb\.ai/docs/([A-Za-z0-9._/-]*)")


def promised_doc_slugs(root: Path) -> dict[str, set[str]]:
    """Public /docs/ URLs named anywhere in the tracked corpus, by referring file."""
    out = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"], check=False, capture_output=True
    )
    promised: dict[str, set[str]] = {}
    for rel in (p for p in out.stdout.decode("utf-8").split("\0") if p):
        path = root / rel
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for match in PUBLIC_DOC_URL.finditer(text):
            slug = match.group(1).rstrip("./").removesuffix(".md")
            if slug:
                promised.setdefault(slug, set()).add(rel)
    return promised


def tracked_markdown(root: Path) -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z", "*.md"], check=False, capture_output=True
    )
    if out.returncode != 0:
        raise SystemExit("cannot derive tracked Markdown with git ls-files")
    return [p for p in out.stdout.decode("utf-8").split("\0") if p]


def check(root: Path, extra: list[str] | None = None) -> tuple[list[str], int]:
    failures: list[str] = []
    checked = 0
    for rel in sorted(set(tracked_markdown(root)) | set(extra or [])):
        path = root / rel
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        base = path.parent
        for match in LINK.finditer(strip_code(text)):
            target = match.group(1)
            if target.startswith(("http://", "https://", "mailto:", "/")):
                continue
            checked += 1
            if not (base / target).resolve().is_file():
                failures.append(f"{rel} links to a missing document: {target}")

    for slug, referrers in sorted(promised_doc_slugs(root).items()):
        if not (root / "docs" / f"{slug}.md").is_file():
            where = ", ".join(sorted(referrers))
            failures.append(
                f"promised public URL /docs/{slug} has no docs/{slug}.md ({where})"
            )
        checked += 1
    return failures, checked


def self_test(root: Path) -> int:
    failures, _ = check(root)
    if failures:
        print("self-test setup is not green:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        subprocess.run(["git", "-C", str(tmp), "init", "-q"], check=True)

        def write(rel: str, body: str) -> None:
            p = tmp / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body, encoding="utf-8")
            subprocess.run(["git", "-C", str(tmp), "add", rel], check=True)

        write("docs/real.md", "# real\n")
        write("docs/sub/deep.md", "# deep\n")
        write("docs/ok.md", "[a](real.md) [b](sub/deep.md) [c](../docs/real.md)\n")
        failures, checked = check(tmp)
        if failures:
            print(f"self-test failed: valid links rejected: {failures[0]}")
            return 1
        if checked != 3:
            print(f"self-test failed: expected 3 links checked, saw {checked}")
            return 1

        # Same directory, subdirectory, and parent traversal each fail when the
        # target is absent. Three shapes because one passing case does not prove
        # the resolver handles the others.
        for name, body in (
            ("sibling", "[x](gone.md)\n"),
            ("subdir", "[x](sub/gone.md)\n"),
            ("parent", "[x](../gone.md)\n"),
        ):
            write("docs/bad.md", body)
            failures, _ = check(tmp)
            if not any("bad.md" in f for f in failures):
                print(f"self-test failed: dangling {name} link was not detected")
                return 1
        (tmp / "docs/bad.md").unlink()
        subprocess.run(["git", "-C", str(tmp), "add", "-A"], check=True)

        # An anchor must not change resolution, and an absolute URL must not be
        # resolved as a path.
        write("docs/anchor.md", "[a](real.md#section) [b](https://example.com/x.md)\n")
        failures, _ = check(tmp)
        if failures:
            print(f"self-test failed: anchor or absolute URL mishandled: {failures[0]}")
            return 1

        # Link syntax being shown rather than followed must not resolve: inside
        # an inline code span, and inside a fenced block. A document explaining
        # how links work is not making those links.
        write(
            "docs/showing.md",
            "inline `[x](does-not-exist.md)` here\n\n"
            "```markdown\n[y](also-missing.md)\n```\n",
        )
        failures, _ = check(tmp)
        if failures:
            print(f"self-test failed: shown link syntax was followed: {failures[0]}")
            return 1
        # ...but a real link on a line after a closed fence still counts.
        write("docs/showing.md", "```\ncode\n```\n\n[real](gone.md)\n")
        if not any("showing.md" in f for f in check(tmp)[0]):
            print("self-test failed: fence handling swallowed a real link")
            return 1
        (tmp / "docs/showing.md").unlink()
        subprocess.run(["git", "-C", str(tmp), "add", "-A"], check=True)

        # A promised public URL must have its document. Both served spellings
        # resolve to the same file, and trailing sentence punctuation must not
        # become part of the slug.
        # Split so this file does not promise these URLs itself when it is
        # scanned as part of the tracked corpus — the gate found that self-match
        # on its own first run.
        site = "https://aweb.ai/" + "docs/"
        write("docs/urls.md",
              f"see {site}real.md and {site}real/ and {site}real.md.\n")
        failures, _ = check(tmp)
        if failures:
            print(f"self-test failed: a valid promised URL was rejected: {failures[0]}")
            return 1
        write("docs/urls.md", f"see {site}never-written/\n")
        failures, _ = check(tmp)
        if not any("never-written" in f for f in failures):
            print("self-test failed: a promised URL with no document was not rejected")
            return 1
        (tmp / "docs/urls.md").unlink()
        subprocess.run(["git", "-C", str(tmp), "add", "-A"], check=True)

    print("self-test passed: valid relative links accepted; sibling, subdirectory and "
          "parent dangling links each rejected; anchors and absolute URLs handled; "
          "code spans and fenced blocks shown rather than followed, without "
          "swallowing a real link after a closed fence")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=Path(__file__).resolve().parents[1], type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return self_test(args.root)

    failures, checked = check(args.root)
    if failures:
        print("documentation cross-references do not resolve:")
        for failure in failures:
            print(f"- {failure}")
        return 1
    print(f"documentation cross-references resolve ({checked} checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
