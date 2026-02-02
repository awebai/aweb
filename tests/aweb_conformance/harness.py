from __future__ import annotations

import os
import uuid
from dataclasses import dataclass
from typing import Any, AsyncIterator, Optional

import httpx
import pytest


@dataclass(frozen=True)
class AwebAgent:
    agent_id: str
    alias: str


@dataclass(frozen=True)
class AwebTarget:
    base_url: str
    agent_1_api_key: str
    agent_2_api_key: str
    agent_1: AwebAgent
    agent_2: AwebAgent


def _require_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required env var: {name}")
    return value


def _get_env(name: str) -> Optional[str]:
    value = os.getenv(name)
    if value is None:
        return None
    value = value.strip()
    return value or None


def _auth_headers(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


async def bootstrap_target(base_url: str) -> AwebTarget:
    """Bootstrap an aweb target for black-box conformance tests.

    This harness is intentionally black-box and does not rely on any bootstrap endpoints.
    You must provide a per-agent API key and agent identity via env vars.
    """
    agent_1 = AwebAgent(
        agent_id=_require_env("AWEB_AGENT_1_ID"),
        alias=_require_env("AWEB_AGENT_1_ALIAS"),
    )
    agent_2 = AwebAgent(
        agent_id=_require_env("AWEB_AGENT_2_ID"),
        alias=_require_env("AWEB_AGENT_2_ALIAS"),
    )
    return AwebTarget(
        base_url=base_url,
        agent_1_api_key=_require_env("AWEB_AGENT_1_API_KEY"),
        agent_2_api_key=_require_env("AWEB_AGENT_2_API_KEY"),
        agent_1=agent_1,
        agent_2=agent_2,
    )


@dataclass(frozen=True)
class AwebOtherTarget:
    base_url: str
    api_key: str
    agent: AwebAgent


def maybe_other_target(base_url: str) -> Optional[AwebOtherTarget]:
    """Optional second-project identity used for cross-project isolation tests."""
    api_key = _get_env("AWEB_OTHER_API_KEY")
    agent_id = _get_env("AWEB_OTHER_AGENT_ID")
    agent_alias = _get_env("AWEB_OTHER_AGENT_ALIAS")
    if not api_key or not agent_id or not agent_alias:
        return None
    return AwebOtherTarget(
        base_url=base_url,
        api_key=api_key,
        agent=AwebAgent(agent_id=agent_id, alias=agent_alias),
    )


@dataclass(frozen=True)
class SSEEvent:
    event: str
    data: str


async def sse_events(
    client: httpx.AsyncClient,
    url: str,
    *,
    params: Optional[dict[str, Any]] = None,
) -> AsyncIterator[SSEEvent]:
    """Minimal SSE reader for conformance tests.

    - Parses `event:` and `data:` lines
    - Emits one SSEEvent per blank-line delimiter
    - Ignores comment lines (`:`)
    """
    async with client.stream("GET", url, params=params) as resp:
        resp.raise_for_status()
        event_type = "message"
        data_lines: list[str] = []

        async for line in resp.aiter_lines():
            if not line:
                if data_lines:
                    yield SSEEvent(event=event_type or "message", data="\n".join(data_lines))
                event_type = "message"
                data_lines = []
                continue

            if line.startswith(":"):
                continue
            if line.startswith("event:"):
                event_type = line[len("event:") :].strip()
                continue
            if line.startswith("data:"):
                data_lines.append(line[len("data:") :].lstrip())
                continue


def require_conformance_enabled() -> None:
    if os.getenv("AWEB_CONFORMANCE", "").strip() not in ("1", "true", "yes", "on"):
        pytest.skip("Set AWEB_CONFORMANCE=1 to run aweb conformance tests")
