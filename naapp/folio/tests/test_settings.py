from __future__ import annotations

import pytest
from aweb_naapp.runtime.settings import NaappSettings
from aweb_naapp.runtime.team_auth import DidAwProfile

from folio.config import Settings


def test_folio_observes_did_aw_unless_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FOLIO_DID_AW_PROFILE", raising=False)

    assert Settings(_env_file=None).did_aw_profile is DidAwProfile.OBSERVE


def test_folio_settings_are_the_shared_naapp_settings_under_its_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FOLIO_DID_AW_PROFILE", "require")
    monkeypatch.setenv("FOLIO_APP_EVENTS_ORIGIN", "https://core.example")

    settings = Settings(_env_file=None)

    assert isinstance(settings, NaappSettings)
    assert settings.did_aw_profile is DidAwProfile.REQUIRE
    assert settings.app_events_origin == "https://core.example"
