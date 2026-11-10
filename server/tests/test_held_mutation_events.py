"""Mutation events recorded inside a caller's transaction reach on_mutation only when fired (aweb.hooks.HeldMutationEvents)."""

import logging

import pytest

from aweb.hooks import HeldMutationEvents


@pytest.mark.asyncio
async def test_recorded_events_reach_on_mutation_in_order_only_when_fired():
    delivered: list[tuple[str, dict]] = []

    async def on_mutation(event_type: str, context: dict) -> None:
        delivered.append((event_type, context))

    held = HeldMutationEvents()
    await held.record("task.comment_added", {"comment_id": "c1"})
    await held.record("task.status_changed", {"new_status": "closed"})
    assert delivered == []

    await held.fire(on_mutation)

    assert delivered == [
        ("task.comment_added", {"comment_id": "c1"}),
        ("task.status_changed", {"new_status": "closed"}),
    ]


@pytest.mark.asyncio
async def test_firing_without_on_mutation_delivers_nothing():
    held = HeldMutationEvents()
    await held.record("task.comment_added", {"comment_id": "c1"})

    await held.fire(None)


@pytest.mark.asyncio
async def test_a_failing_on_mutation_is_logged_and_the_later_events_still_fire(caplog):
    delivered: list[str] = []

    async def on_mutation(event_type: str, context: dict) -> None:
        if event_type == "task.comment_added":
            raise RuntimeError("consumer down")
        delivered.append(event_type)

    held = HeldMutationEvents()
    await held.record("task.comment_added", {"comment_id": "c1"})
    await held.record("task.status_changed", {"new_status": "closed"})

    with caplog.at_level(logging.WARNING, logger="aweb.hooks"):
        await held.fire(on_mutation)

    assert delivered == ["task.status_changed"]
    assert [record.getMessage() for record in caplog.records] == [
        "on_mutation callback failed for task.comment_added",
    ]
