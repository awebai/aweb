"""Serving dependencies shared by the native MCP tool families."""

from __future__ import annotations

from dataclasses import dataclass

import httpx
from awid.registry import RegistryClient
from redis.asyncio import Redis

from aweb.db import DatabaseInfrastructure
from aweb.federation.activation import FederationAuthorityActivation
from aweb.mcp.signing import (
    HostedMessageDecryptor,
    HostedMessageEncryptor,
    HostedMessageSigner,
)


@dataclass(frozen=True, kw_only=True)
class ToolDependencies:
    """References supplied once by the application registering native tools."""

    db_infra: DatabaseInfrastructure
    redis: Redis | None
    registry_client: RegistryClient
    federation_authority: FederationAuthorityActivation | None
    hosted_signer: HostedMessageSigner | None
    hosted_encryptor: HostedMessageEncryptor | None
    hosted_decryptor: HostedMessageDecryptor | None
    federation_mail_transport: httpx.AsyncBaseTransport | None
    federation_chat_transport: httpx.AsyncBaseTransport | None
    public_origin: str | None
