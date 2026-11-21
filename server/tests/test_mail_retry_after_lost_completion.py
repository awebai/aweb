"""Exact mail retry after a real completion link is held beyond the skew window."""
# ruff: noqa: F811 -- pytest imports the real shared fixture by name.

from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime, timedelta, timezone
from enum import Enum, auto
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import httpx
import pytest

from awid.signing import canonical_json_bytes, sign_message
from messaging_actor_support import admit_messaging_actor, set_messaging_inbound_mode
from test_dashboard_privacy import TEAM, privacy_app as privacy_app
from test_messages_http import _signed_team_headers

__all__ = ["privacy_app"]

HOLD_COMPLETION_SECONDS = 6
INITIAL_ATTESTATION_AGE_SECONDS = 297


class RetryPath(Enum):
    NAMED_RECIPIENT = auto()
    STORED_CONVERSATION = auto()


class HeldMailCompletions:
    """Forward requests over TCP, hold real response bytes, then cut the link.

    The real server authenticates and commits each request. No product handler,
    signature, database, policy or clock is replaced by the fault injector.
    """

    def __init__(self, *, upstream_url: str, response_count: int):
        target = urlsplit(upstream_url)
        if target.scheme != "http" or target.hostname is None or target.port is None:
            raise ValueError(
                "Completion fault requires the fixture's explicit HTTP endpoint"
            )
        self.host, self.port = target.hostname, target.port
        self.response_count = response_count
        self.responses: list[bytes] = []
        self.response_bodies: list[bytes] = []
        self.failures: list[BaseException] = []
        self.all_held = asyncio.Event()
        self.release = asyncio.Event()
        self.tasks: set[asyncio.Task] = set()
        self.server: asyncio.Server | None = None

    async def start(self) -> str:
        self.server = await asyncio.start_server(self._hold_completion, "127.0.0.1", 0)
        port = self.server.sockets[0].getsockname()[1]
        return f"http://127.0.0.1:{port}"

    async def close(self) -> None:
        self.release.set()
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
        await asyncio.wait_for(asyncio.gather(*self.tasks), timeout=10)

    async def _forward_request(self, reader, writer) -> None:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()

    async def _hold_completion(self, client_reader, client_writer) -> None:
        task = asyncio.current_task()
        if task is None:
            raise RuntimeError("TCP completion handler has no task")
        self.tasks.add(task)
        upstream_writer = None
        request_task = None
        try:
            upstream_reader, upstream_writer = await asyncio.open_connection(
                self.host, self.port
            )
            request_task = asyncio.create_task(
                self._forward_request(client_reader, upstream_writer)
            )
            status_line = await upstream_reader.readuntil(b"\r\n")
            header_block = await upstream_reader.readuntil(b"\r\n\r\n")
            headers = {
                name.strip().lower(): value.strip()
                for line in header_block.split(b"\r\n")
                if b":" in line
                for name, _, value in [line.partition(b":")]
            }
            body = await upstream_reader.readexactly(int(headers[b"content-length"]))
            self.responses.append(status_line)
            self.response_bodies.append(body)
            if len(self.responses) == self.response_count:
                self.all_held.set()
            await self.release.wait()
        except (OSError, asyncio.IncompleteReadError, ValueError, KeyError) as exc:
            self.failures.append(exc)
            self.all_held.set()
        finally:
            client_writer.close()
            if upstream_writer is not None:
                upstream_writer.close()
            if request_task is not None:
                request_task.cancel()
                results = await asyncio.gather(request_task, return_exceptions=True)
                self.failures.extend(
                    result
                    for result in results
                    if isinstance(result, BaseException)
                    and not isinstance(result, asyncio.CancelledError)
                )
            self.tasks.discard(task)


def signed_mail(
    env,
    *,
    path: RetryPath,
    recipient_stable_id: str,
    conversation_id: str | None = None,
    attestation_age_seconds: int = 0,
):
    sender, recipient = env.actors["alice"], env.actors["bob"]
    timestamp = (
        (datetime.now(timezone.utc) - timedelta(seconds=attestation_age_seconds))
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    message_id = str(uuid4())
    signed = {
        "type": "mail",
        "from": "alice",
        "from_did": sender.did,
        "to": "bob",
        "to_did": recipient.did,
        "to_stable_id": recipient_stable_id,
        "subject": "lost completion",
        "body": path.name,
        "message_id": message_id,
        "timestamp": timestamp,
    }
    selector = {"to_alias": "bob"}
    if path is RetryPath.STORED_CONVERSATION:
        if conversation_id is None:
            raise ValueError("Continuation needs its real stored conversation")
        signed["conversation_id"] = conversation_id
        selector = {"conversation_id": conversation_id}
    original = canonical_json_bytes(signed).decode()
    return {
        **selector,
        "from_did": sender.did,
        "message_id": message_id,
        "subject": signed["subject"],
        "body": signed["body"],
        "timestamp": timestamp,
        "signature": sign_message(sender.sk, original.encode()),
        "signed_payload": original,
    }


async def send_signed_mail(client, env, payload):
    body = json.dumps(payload).encode()
    sender = env.actors["alice"]
    return await client.post(
        "/v1/messages",
        content=body,
        headers={
            **_signed_team_headers(
                sender.sk, sender.did, TEAM, sender.certificate, body
            ),
            "Content-Type": "application/json",
        },
    )


@pytest.mark.asyncio
async def test_exact_mail_retry_after_completion_fault_crosses_attestation_window(
    privacy_app,
):
    env = privacy_app
    bob = env.actors["bob"]
    recipient = await admit_messaging_actor(
        env, alias="bob", team_id=TEAM, signing_key=bob.sk, address="example.test/bob"
    )
    stable_id = recipient.stable_id
    opening = signed_mail(
        env, path=RetryPath.NAMED_RECIPIENT, recipient_stable_id=stable_id
    )
    opened = await send_signed_mail(env.client, env, opening)
    assert opened.status_code == 200, opened.text
    payloads = {
        RetryPath.NAMED_RECIPIENT: signed_mail(
            env,
            path=RetryPath.NAMED_RECIPIENT,
            recipient_stable_id=stable_id,
            attestation_age_seconds=INITIAL_ATTESTATION_AGE_SECONDS,
        ),
        RetryPath.STORED_CONVERSATION: signed_mail(
            env,
            path=RetryPath.STORED_CONVERSATION,
            recipient_stable_id=stable_id,
            conversation_id=opened.json()["conversation_id"],
            attestation_age_seconds=INITIAL_ATTESTATION_AGE_SECONDS,
        ),
    }
    proxy = HeldMailCompletions(
        upstream_url=str(env.client.base_url), response_count=len(payloads)
    )
    proxy_url = await proxy.start()
    attempts = []
    try:
        async with httpx.AsyncClient(base_url=proxy_url, timeout=None) as interrupted:
            attempts = [
                asyncio.create_task(send_signed_mail(interrupted, env, payload))
                for payload in payloads.values()
            ]
            await asyncio.wait_for(proxy.all_held.wait(), timeout=20)
            assert not proxy.failures, proxy.failures
            assert proxy.responses == [b"HTTP/1.1 200 OK\r\n"] * len(payloads)
            ids = [UUID(payload["message_id"]) for payload in payloads.values()]
            stored = await env.db.fetch_all(
                "SELECT message_id, conversation_id, created_at, signed_payload FROM {{tables.messages}} WHERE message_id=ANY($1::uuid[]) ORDER BY message_id",
                ids,
            )
            assert len(stored) == len(payloads)
            expected = {str(row["message_id"]): dict(row) for row in stored}
            before = (
                await env.db.fetch_value("SELECT count(*) FROM {{tables.messages}}"),
                list(env.dispatched),
            )
            started = time.monotonic()
            await asyncio.sleep(HOLD_COMPLETION_SECONDS)
            proxy.release.set()
            assert time.monotonic() - started >= HOLD_COMPLETION_SECONDS
            assert all(
                (
                    datetime.now(timezone.utc)
                    - datetime.fromisoformat(
                        payload["timestamp"].replace("Z", "+00:00")
                    )
                ).total_seconds()
                > 300
                for payload in payloads.values()
            )
            losses = await asyncio.wait_for(
                asyncio.gather(*attempts, return_exceptions=True), timeout=10
            )
            assert all(isinstance(loss, httpx.TransportError) for loss in losses), (
                losses
            )

        for payload in payloads.values():
            retried = await send_signed_mail(env.client, env, payload)
            assert retried.status_code == 200, retried.text
            row = expected[payload["message_id"]]
            assert retried.json() == {
                "message_id": payload["message_id"],
                "conversation_id": str(row["conversation_id"]),
                "status": "delivered",
                "delivered_at": row["created_at"].strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            assert row["signed_payload"] == payload["signed_payload"]
            malformed = await send_signed_mail(
                env.client, env, {**payload, "body": "not the signed body"}
            )
            assert malformed.status_code == 422, malformed.text
            changed_fields = json.loads(payload["signed_payload"])
            changed_fields["body"] = "different signed content under the old message ID"
            changed_bytes = canonical_json_bytes(changed_fields)
            changed = await send_signed_mail(
                env.client,
                env,
                {
                    **payload,
                    "body": changed_fields["body"],
                    "signed_payload": changed_bytes.decode(),
                    "signature": sign_message(env.actors["alice"].sk, changed_bytes),
                },
            )
            assert changed.status_code == 422, changed.text
            assert (
                changed.headers["X-AWEB-Error-Code"] == "message_timestamp_outside_skew"
            )

        assert (
            await env.db.fetch_value("SELECT count(*) FROM {{tables.messages}}"),
            env.dispatched,
        ) == before
        await set_messaging_inbound_mode(env, recipient, "contacts_only")
        for payload in payloads.values():
            denied = await send_signed_mail(env.client, env, payload)
            assert denied.status_code == 403, denied.text
        assert (
            await env.db.fetch_value("SELECT count(*) FROM {{tables.messages}}"),
            env.dispatched,
        ) == before
    finally:
        await proxy.close()
        if attempts:
            await asyncio.gather(*attempts, return_exceptions=True)
        assert not proxy.failures, proxy.failures
