"""The shared display predicate uses the deployment's actual activity window."""

from datetime import UTC, datetime, timedelta

import pytest

from aweb.workspace_activity import WorkspaceActivity


@pytest.mark.parametrize("age,online", [(89, True), (90, False), (91, False)])
def test_display_uses_the_configured_window_for_every_observation(
    monkeypatch, age, online
):
    monkeypatch.setenv("AWEB_PRESENCE_TTL_SECONDS", "90")
    now = datetime.now(UTC)
    observation = WorkspaceActivity(
        last_seen_at=now - timedelta(seconds=age), presence={"status": "busy"}
    )
    assert observation.is_online(now=now) is online
    assert observation.display_status(now=now) == ("busy" if online else "offline")


def test_missing_activity_is_offline_without_inventing_a_timestamp():
    observation = WorkspaceActivity(last_seen_at=None, presence=None)
    assert not observation.is_online(now=datetime.now(UTC))
    assert observation.display_status(now=datetime.now(UTC)) == "offline"
