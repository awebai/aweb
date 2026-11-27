"""Anchored patterns refuse a value that ends in a line break.

Python's ``$`` also matches before a final ``"\\n"``, so a pattern checked with
``re.match`` accepts ``"value\\n"``. These are the sites that check a value as
received, without stripping it first.
"""

from __future__ import annotations

import json

import pytest

from aweb import app_registry
from aweb.internal_auth import _is_valid_proxy_team_id

LINE_BREAKS = pytest.mark.parametrize(
    "suffix", ["\n", "\r\n", "\r"], ids=["lf", "crlf", "cr"]
)


def test_proxy_team_id_accepts_the_bare_value():
    assert _is_valid_proxy_team_id("ops:acme.com")


@LINE_BREAKS
def test_proxy_team_id_refuses_a_line_break_after_the_team_name(suffix):
    assert not _is_valid_proxy_team_id(f"ops{suffix}:acme.com")


@pytest.fixture
def reserved_artifact(monkeypatch):
    def use(app_ids: list[str]) -> None:
        payload = json.dumps(
            {
                "schema": app_registry.RESERVED_APP_IDS_SCHEMA,
                "reserved_app_ids": app_ids,
            }
        )
        monkeypatch.setattr(
            app_registry, "_read_reserved_app_ids_artifact", lambda: payload
        )
        app_registry.reserved_app_ids.cache_clear()

    yield use
    app_registry.reserved_app_ids.cache_clear()


def test_reserved_app_ids_artifact_accepts_a_bare_id(reserved_artifact):
    reserved_artifact(["status"])
    assert app_registry.reserved_app_ids() == frozenset({"status"})


@LINE_BREAKS
def test_reserved_app_ids_artifact_refuses_an_id_with_a_trailing_line_break(
    reserved_artifact, suffix
):
    reserved_artifact(["status" + suffix])
    with pytest.raises(RuntimeError):
        app_registry.reserved_app_ids()
