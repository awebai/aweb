"""Shared startup and cleanup operations for native serving resources."""

import logging

from awid.registry import RegistryClient, RegistryError
from fastapi import FastAPI
from redis.asyncio import Redis

from aweb.agent_wake import AgentWakeHub, AgentWakePublisher

logger = logging.getLogger(__name__)


async def start_agent_wakes(app: FastAPI, redis: Redis) -> None:
    """Start the process's agent wake publisher and subscriber on ``app.state``.

    The shared native resource owner calls this for both lifespans and the
    public embedded context. Hosts managing a mounted app manually
    must pair this with ``stop_agent_wakes`` at shutdown; without it, writes
    publish no wakes and streams fall back to their 15 s reconcile.
    """
    app.state.agent_wake_publisher = AgentWakePublisher(redis)
    app.state.agent_wake_hub = AgentWakeHub(redis)
    await app.state.agent_wake_hub.start()


async def stop_agent_wakes(app: FastAPI) -> None:
    """Close the native wake subscriber and publisher started on this app."""
    hub = getattr(app.state, "agent_wake_hub", None)
    if hub is not None:
        await hub.close()
    publisher = getattr(app.state, "agent_wake_publisher", None)
    if publisher is not None:
        await publisher.close()


async def validate_awid_registry_client(registry_client: RegistryClient) -> None:
    """Start-up needs the registry to answer. One that answers its health
    report with a failed dependency of its own is reached; refusing to start
    against it would spread its outage to this server."""
    try:
        await registry_client.health()
    except Exception as exc:
        if not _is_unhealthy_report(exc):
            raise RuntimeError(
                f"Failed to reach AWID registry at {registry_client.registry_url}: {exc}"
            ) from exc
        logger.warning(
            "AWID registry at %s reports a failed dependency; starting",
            registry_client.registry_url,
        )


def _is_unhealthy_report(exc: Exception) -> bool:
    return (
        isinstance(exc, RegistryError)
        and exc.status_code == 503
        and isinstance(exc.body, dict)
        and exc.body.get("status") == "unhealthy"
    )
