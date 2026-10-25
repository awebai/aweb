"""Trusted registration-view input for the real signed governance outbox tests."""

from datetime import UTC, datetime, timedelta

from aweb_naapp.hooks.producer import Registration, RegistrationView

TEAM = "backend:acme.com"


def view():
    now = datetime.now(UTC)
    return RegistrationView(
        TEAM,
        "post-governance-hook",
        now,
        timedelta(seconds=60),
        (
            Registration(
                "local-logs-binding",
                "https://logs.example",
                "POST",
                "/hooks/ingest",
                now - timedelta(hours=1),
            ),
        ),
    )
