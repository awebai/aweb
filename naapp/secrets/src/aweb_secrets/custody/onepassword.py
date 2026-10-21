"""Read-only 1Password SDK access for one dispatch (§5.3).

The caller opens the installation's owner-entered, natively sealed service
account token for this use. This adapter accepts only that redacting Plaintext;
it has no environment/file token loader, write operations, or client/value cache.
Every call authenticates and retrieves the exact referenced item afresh. It
projects selected field IDs through custody's shared value codec. SDK messages,
item values and tokens never enter returned errors or reprs.
"""

from __future__ import annotations

import asyncio
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from onepassword import Client, Item

from aweb_secrets.custody.sealing import CustodyUnavailable, Plaintext, SealContext
from aweb_secrets.custody.values import decode_value, encode_value
from aweb_secrets.operation import CAPTURE_FIELDS

_ID = re.compile(r"[a-z0-9]{26}")
_FIELD = re.compile(r"[A-Za-z0-9_-]{1,128}")
_CONFIG = frozenset({"vault_id", "item_id", "fields"})


@dataclass(frozen=True)
class OnePasswordReference:
    """Immutable selectors, with logical field names from the secret's auth kind.

    IDs, rather than mutable vault/item/field titles, make the binding exact.
    Section-local duplicate field IDs refuse rather than choosing a first match.
    """

    kind: str
    vault_id: str
    item_id: str
    fields: tuple[tuple[str, str], ...]

    @classmethod
    def from_config(cls, kind: str, config: Mapping[str, Any]) -> OnePasswordReference:
        try:
            if (
                kind not in CAPTURE_FIELDS
                or not isinstance(config, Mapping)
                or set(config) != _CONFIG
            ):
                raise ValueError
            for name in ("vault_id", "item_id"):
                if not isinstance(config[name], str) or not _ID.fullmatch(config[name]):
                    raise ValueError
            selectors = config["fields"]
            required, optional = CAPTURE_FIELDS[kind]
            if (
                not isinstance(selectors, Mapping)
                or not required <= selectors.keys() <= required | optional
                or any(
                    not isinstance(value, str) or not _FIELD.fullmatch(value)
                    for value in selectors.values()
                )
            ):
                raise ValueError
            return cls(
                kind, config["vault_id"], config["item_id"], tuple(sorted(selectors.items()))
            )
        except (ValueError, TypeError, KeyError):
            raise CustodyUnavailable("invalid 1Password reference") from None

    def as_config(self) -> dict[str, Any]:
        return {"vault_id": self.vault_id, "item_id": self.item_id, "fields": dict(self.fields)}


class SecretVersionChanged(CustodyUnavailable):
    """The fetched item differs from the version authorized for this attempt."""

    code = "secret_version_changed"

    def __init__(self, observed_item_version: int) -> None:
        super().__init__("the 1Password item version changed")
        self.observed_item_version = observed_item_version


@dataclass(frozen=True)
class OnePasswordRead:
    """One transient read; the metadata is safe to describe, the value is not."""

    item_version: int
    updated_at: datetime
    value: Plaintext = field(repr=False)
    reference: OnePasswordReference
    credential_context: SealContext | None = None


def project_item(
    reference: OnePasswordReference,
    item: Item,
    *,
    expected_item_version: int | None = None,
    credential_context: SealContext | None = None,
) -> OnePasswordRead:
    """Check exact item/version/field identity and encode through the shared codec."""
    try:
        if (
            item.vault_id != reference.vault_id
            or item.id != reference.item_id
            or type(item.version) is not int
            or item.version <= 0
        ):
            raise ValueError
        if expected_item_version is not None:
            if type(expected_item_version) is not int or expected_item_version <= 0:
                raise ValueError
            if item.version != expected_item_version:
                raise SecretVersionChanged(item.version)
        values = {}
        for name, selector in reference.fields:
            found = [candidate.value for candidate in item.fields if candidate.id == selector]
            if len(found) != 1:
                raise ValueError
            values[name] = found[0]
        # SDK 0.4 parses its RFC3339 Z timestamp into a naive datetime.
        updated_at = item.updated_at
        if updated_at.tzinfo is None:
            updated_at = updated_at.replace(tzinfo=UTC)
        return OnePasswordRead(
            item.version,
            updated_at.astimezone(UTC),
            Plaintext(encode_value(reference.kind, values)),
            reference,
            credential_context,
        )
    except SecretVersionChanged:
        raise
    except Exception:
        raise CustodyUnavailable("unusable 1Password item") from None


class OnePasswordSDK:
    """The official SDK, deliberately exposing reads only and retaining no token.

    The SDK returns an item version together with its fields in one read. A
    separate field resolve could race a version fetch and bind the wrong value.
    """

    def __init__(self, *, timeout: float = 10.0) -> None:
        if not math.isfinite(timeout) or not 0 < timeout <= 60:
            raise ValueError("1Password timeout must be between zero and 60 seconds")
        self._timeout = timeout

    async def read(
        self,
        reference: OnePasswordReference,
        *,
        token: Plaintext,
        expected_item_version: int | None = None,
        credential_context: SealContext | None = None,
    ) -> OnePasswordRead:
        try:
            reference = OnePasswordReference.from_config(reference.kind, reference.as_config())
            account_token = decode_value("bearer", token.reveal())["value"]
            async with asyncio.timeout(self._timeout):
                client = await Client.authenticate(
                    auth=account_token,
                    integration_name="aweb secrets",
                    integration_version="0.1.0",
                )
                item = await client.items.get(reference.vault_id, reference.item_id)
            return project_item(
                reference,
                item,
                expected_item_version=expected_item_version,
                credential_context=credential_context,
            )
        except CustodyUnavailable:
            raise
        except Exception:
            raise CustodyUnavailable("1Password read unavailable") from None
