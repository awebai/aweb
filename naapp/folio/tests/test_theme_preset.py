from __future__ import annotations

from folio.repository import _theme_from_row


def _row(tokens: dict) -> dict:
    return {"tokens": tokens, "logo_asset_id": None, "header": None, "footer": None, "updated_at": None}


def test_theme_from_row_extracts_builtin_preset() -> None:
    theme = _theme_from_row(_row({"preset": "aweb"}), public_origin=None)
    assert theme is not None
    assert theme["preset"] == "aweb"
    # The reserved key never leaks into the color/font/layout tokens.
    assert "preset" not in theme["tokens"]


def test_theme_from_row_drops_unknown_preset_and_returns_none_when_otherwise_empty() -> None:
    assert _theme_from_row(_row({"preset": "bogus"}), public_origin=None) is None


def test_theme_from_row_keeps_custom_tokens_alongside_preset() -> None:
    theme = _theme_from_row(_row({"preset": "aweb", "colors": {"accent": "#ff0000"}}), public_origin=None)
    assert theme is not None
    assert theme["preset"] == "aweb"
    assert theme["tokens"]["colors"]["accent"] == "#ff0000"
