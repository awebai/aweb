"""Byte-identical gate for the aweb-naapp-generated library surfaces.

The goldens capture library's intended generated copy. Product copy changes such
as the blueprint rename update the goldens deliberately; unrelated toolkit changes
must keep rendering byte-identical to these files.
"""

from __future__ import annotations

from pathlib import Path

from library.surfaces import aweb_css, llms_txt, render_landing_page, render_reference_page

_GOLDEN = Path(__file__).resolve().parent / "golden"
_ORIGIN = "https://library.aweb.ai"


def _golden(name: str) -> str:
    return (_GOLDEN / name).read_text(encoding="utf-8")


def test_landing_is_byte_identical() -> None:
    assert render_landing_page(public_origin=_ORIGIN) == _golden("landing.html")


def test_reference_is_byte_identical() -> None:
    assert render_reference_page(public_origin=_ORIGIN) == _golden("reference.html")


def test_llms_txt_is_byte_identical() -> None:
    assert llms_txt(public_origin=_ORIGIN) == _golden("llms.txt")


def test_aweb_css_is_byte_identical() -> None:
    assert aweb_css() == _golden("aweb.css")
