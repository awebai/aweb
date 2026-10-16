"""Agent activity frames for one chat session stream (docs/agent-activity.md, Delivery).

A stream subscribes to the activity channel of every other participant agent,
confirms the subscriptions, reads each agent's latest state as a snapshot, and
then accepts relayed events. Ordering uses the relay revision only: an event is
projected when its revision is greater than the last one projected for that
agent, so nothing published before the snapshot can replace it.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from aweb.agent_activity import activity_channel_name, activity_state_key

SUBSCRIBE_CONFIRM_TIMEOUT_SECONDS = 5.0


def _text(value: str | bytes) -> str:
    return value.decode("utf-8") if isinstance(value, bytes) else value


def _sse(data: dict[str, Any]) -> str:
    return f"event: agent_activity\ndata: {json.dumps(data, separators=(',', ':'), ensure_ascii=False)}\n\n"


class SessionActivity:
    """Projects the participant agents' activity into one session's stream."""

    def __init__(self, session_id: str, agents: dict[str, str]):
        self._session_id = session_id
        self._aliases = dict(agents)
        self._agent_by_channel = {activity_channel_name(agent_id): agent_id for agent_id in agents}
        self._last_rev: dict[str, int] = {}

    @property
    def channels(self) -> list[str]:
        return list(self._agent_by_channel)

    def owns(self, channel: str | bytes) -> bool:
        return _text(channel) in self._agent_by_channel

    async def subscribe(self, pubsub) -> list[dict[str, Any]]:
        """Subscribe to every agent channel and wait until Redis confirms each.

        Returns the data messages that arrived meanwhile, on any channel of
        this pubsub, for the caller to handle after the snapshot.
        """
        pending: list[dict[str, Any]] = []
        if not self._agent_by_channel:
            return pending
        await pubsub.subscribe(*self._agent_by_channel)
        unconfirmed = set(self._agent_by_channel)
        async with asyncio.timeout(SUBSCRIBE_CONFIRM_TIMEOUT_SECONDS):
            while unconfirmed:
                message = await pubsub.get_message(timeout=1.0)
                if message is None:
                    continue
                if message["type"] == "subscribe":
                    unconfirmed.discard(_text(message["channel"]))
                elif message["type"] == "message":
                    pending.append(message)
        return pending

    async def snapshot(self, redis) -> list[str]:
        frames = []
        for agent_id in self._aliases:
            value = await redis.get(activity_state_key(agent_id))
            if value is not None:
                frame = self.accept(value)
                if frame is not None:
                    frames.append(frame)
        return frames

    def accept(self, value: str | bytes) -> str | None:
        """Return the frame for one relayed value, or None when it is not newer."""
        relayed = json.loads(_text(value))
        agent_id = relayed["agent_id"]
        alias = self._aliases.get(agent_id)
        if alias is None or relayed["rev"] <= self._last_rev.get(agent_id, 0):
            return None
        self._last_rev[agent_id] = relayed["rev"]
        event = relayed["event"]
        if event["session_id"] == self._session_id:
            data = {
                "agent": alias,
                "signed_payload": relayed["signed_payload"],
                "signature": relayed["signature"],
                "from_did": event["from_did"],
                "phase": event["phase"],
            }
            for name in ("tool", "summary"):
                if name in event:
                    data[name] = event[name]
            data.update(turn_id=event["turn_id"], seq=event["seq"], expires_at=event["expires_at"])
            return _sse(data)
        if event["phase"] == "turn_ended":
            return _sse({"agent": alias, "phase": "cleared"})
        return _sse({"agent": alias, "phase": "busy_elsewhere", "expires_at": event["expires_at"]})
