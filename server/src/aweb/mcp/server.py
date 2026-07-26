"""aweb MCP server factory.

Creates an MCP-over-Streamable-HTTP ASGI app that exposes aweb coordination
primitives as MCP tools. Designed to be mounted alongside the REST API::

    from aweb.mcp import create_mcp_app
    mcp_app = create_mcp_app(db_infra=infra, redis=redis)
    fastapi_app.mount("/mcp", mcp_app)
"""

from __future__ import annotations

import asyncio
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from redis.asyncio import Redis

from awid.registry import RegistryClient
from aweb.config import get_awid_registry_url
from aweb.db import DatabaseInfra
from aweb.mcp.auth import MCPAuthMiddleware
from aweb.mcp.signing import HostedMessageDecryptor, HostedMessageEncryptor, HostedMessageSigner
from aweb.mcp.tools.agents import heartbeat as _heartbeat_impl
from aweb.mcp.tools.agents import list_agents as _list_agents_impl
from aweb.mcp.tools.chat import chat_history as _chat_history_impl
from aweb.mcp.tools.chat import chat_pending as _chat_pending_impl
from aweb.mcp.tools.chat import chat_read as _chat_read_impl
from aweb.mcp.tools.chat import chat_send as _chat_send_impl
from aweb.mcp.tools.contacts import add_contact_by_email as _add_contact_by_email_impl
from aweb.mcp.tools.contacts import add_contact_by_handle as _add_contact_by_handle_impl
from aweb.mcp.tools.contacts import contacts_add as _contacts_add_impl
from aweb.mcp.tools.contacts import contacts_remove as _contacts_remove_impl
from aweb.mcp.tools.contacts import contacts_list as _contacts_list_impl
from aweb.mcp.tools.contacts import list_contacts_tool as _list_contacts_tool_impl
from aweb.mcp.tools.contacts import send_message_to_contact as _send_message_to_contact_impl
from aweb.mcp.tools.contacts import read_messages_from_contact as _read_messages_from_contact_impl
from aweb.mcp.tools.identity import whoami as _whoami_impl
from aweb.mcp.tools.mail import check_inbox as _check_inbox_impl
from aweb.mcp.tools.mail import send_mail as _send_mail_impl
from aweb.mcp.tools.team_instructions import instructions_history as _instructions_history_impl
from aweb.mcp.tools.team_instructions import instructions_show as _instructions_show_impl
from aweb.mcp.tools.team_roles import roles_show as _roles_show_impl
from aweb.mcp.tools.team_roles import roles_list as _roles_list_impl
from aweb.mcp.tools.tasks import task_claim as _task_claim_impl
from aweb.mcp.tools.tasks import task_close as _task_close_impl
from aweb.mcp.tools.tasks import task_comment_add as _task_comment_add_impl
from aweb.mcp.tools.tasks import task_comment_list as _task_comment_list_impl
from aweb.mcp.tools.tasks import task_create as _task_create_impl
from aweb.mcp.tools.tasks import task_get as _task_get_impl
from aweb.mcp.tools.tasks import task_list as _task_list_impl
from aweb.mcp.tools.tasks import task_reopen as _task_reopen_impl
from aweb.mcp.tools.tasks import task_ready as _task_ready_impl
from aweb.mcp.tools.tasks import task_update as _task_update_impl
from aweb.mcp.tools.work import work_active as _work_active_impl
from aweb.mcp.tools.work import work_blocked as _work_blocked_impl
from aweb.mcp.tools.work import work_ready as _work_ready_impl
from aweb.mcp.tools.workspace import workspace_status as _workspace_status_impl

class NormalizeMountedMCPPathMiddleware:
    """Rewrite exact /mcp requests to /mcp/ before FastAPI routing.

    Some browser MCP clients normalize the advertised resource URL by dropping
    the trailing slash, then send requests to ``/mcp``. FastAPI/Starlette will
    otherwise redirect or mount the sub-app with an empty inner path, which
    breaks FastMCP's expectation that the streamable endpoint lives at ``/``.
    """

    def __init__(self, app: Any, *, mount_path: str = "/mcp") -> None:
        self.app = app
        self.mount_path = mount_path.rstrip("/") or "/mcp"

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") == "http":
            path = scope.get("path") or ""
            if path == self.mount_path:
                scope = dict(scope)
                normalized = f"{self.mount_path}/"
                scope["path"] = normalized
                scope["raw_path"] = normalized.encode("utf-8")
        await self.app(scope, receive, send)


class ManagedMCPApp:
    """ASGI wrapper that lets a mounted FastMCP app manage its own lifecycle.

    Mounted ASGI sub-applications do not have their lifespan handlers invoked by
    the parent FastAPI app, but FastMCP's Streamable HTTP transport depends on
    its session manager running. The parent app must therefore call
    ``startup()`` and ``shutdown()`` explicitly.
    """

    def __init__(self, app: Any, session_manager: Any) -> None:
        self.app = app
        self._session_manager = session_manager
        self._runner_task: asyncio.Task[None] | None = None
        self._started = asyncio.Event()
        self._shutdown = asyncio.Event()

    async def startup(self) -> None:
        if self._runner_task is not None:
            return

        async def _runner() -> None:
            async with self._session_manager.run():
                self._started.set()
                await self._shutdown.wait()

        self._started.clear()
        self._shutdown.clear()
        self._runner_task = asyncio.create_task(_runner())
        while not self._started.is_set():
            if self._runner_task.done():
                await self._runner_task
            await asyncio.sleep(0)

    async def shutdown(self) -> None:
        if self._runner_task is None:
            return
        self._shutdown.set()
        await self._runner_task
        self._runner_task = None

    async def __call__(self, scope, receive, send) -> None:
        normalized_scope = scope
        path = scope.get("path")
        if not path:
            # When mounted at /mcp, some clients hit the exact mount path
            # (/mcp without a trailing slash). Starlette passes that through to
            # the mounted app with an empty inner path, but FastMCP expects the
            # streamable HTTP endpoint at "/". Normalize the empty inner path so
            # /mcp and /mcp/ behave identically.
            normalized_scope = dict(scope)
            normalized_scope["path"] = "/"
            normalized_scope["raw_path"] = b"/"
        await self.app(normalized_scope, receive, send)


def register_tools(
    mcp: FastMCP,
    db_infra: DatabaseInfra,
    redis: Optional[Redis],
    registry_client: RegistryClient,
    hosted_signer: HostedMessageSigner | None = None,
    hosted_encryptor: HostedMessageEncryptor | None = None,
    hosted_decryptor: HostedMessageDecryptor | None = None,
    federation_mail_transport=None,
    federation_chat_transport=None,
    public_origin: str | None = None,
) -> None:
    """Register all aweb MCP tools on *mcp*.

    Call this on your own :class:`FastMCP` instance to compose aweb tools
    alongside additional tools.  Pass ``redis=None`` if Redis is unavailable;
    presence-related tools will degrade gracefully.
    """

    # -- Identity --

    @mcp.tool(
        name="whoami",
        description="Show the authenticated agent identity and team scope.",
    )
    async def whoami() -> str:
        return await _whoami_impl(db_infra)

    # -- Mail --

    @mcp.tool(
        name="send_mail",
        description=(
            "Send async mail with a required body by recipient, or continue an existing "
            "mail conversation by conversation_id. Hosted custodial sends encrypt by "
            "default when the recipient has an E2E key; set plaintext=true only for "
            "explicit server-readable mail."
        ),
    )
    async def send_mail(
        to: str = "",
        body: str = "",
        conversation_id: str = "",
        subject: str = "",
        priority: str = "normal",
        plaintext: bool = False,
    ) -> str:
        return await _send_mail_impl(
            db_infra,
            registry_client=registry_client,
            hosted_signer=hosted_signer,
            hosted_encryptor=hosted_encryptor,
            to=to,
            conversation_id=conversation_id,
            subject=subject,
            body=body,
            priority=priority,
            plaintext=plaintext,
            federation_transport=federation_mail_transport,
            public_origin=public_origin,
        )

    @mcp.tool(
        name="check_mail",
        description=(
            "Check hosted mail. Hosted custodial identities decrypt encrypted E2E "
            "mail for this MCP session; self-custodial encrypted content remains metadata-only."
        ),
    )
    async def check_mail(
        unread_only: bool = True, limit: int = 50, include_bodies: bool = True
    ) -> str:
        return await _check_inbox_impl(
            db_infra,
            hosted_decryptor=hosted_decryptor,
            unread_only=unread_only,
            limit=limit,
            include_bodies=include_bodies,
        )

    # -- Agents --

    @mcp.tool(
        name="list_agents",
        description="List all agents in the current team with online status.",
    )
    async def list_agents() -> str:
        return await _list_agents_impl(db_infra, redis)

    @mcp.tool(
        name="heartbeat",
        description="Send a heartbeat to maintain agent presence (online status).",
    )
    async def heartbeat() -> str:
        return await _heartbeat_impl(db_infra, redis)

    # -- Chat --

    @mcp.tool(
        name="send_chat",
        description=(
            "Send a real-time chat message. Provide to for a routable address, "
            "DID, hosted handle, or same-team local alias, or conversation_id "
            "to reply in an existing conversation. Set wait=true to block until "
            "the other agent replies (recommended for conversations). Hosted "
            "custodial sends encrypt by default; set plaintext=true only for "
            "explicit server-readable chat."
        ),
    )
    async def send_chat(
        to: str = "",
        message: str = "",
        conversation_id: str = "",
        wait: bool = False,
        wait_seconds: int = 120,
        leaving: bool = False,
        hang_on: bool = False,
        plaintext: bool = False,
    ) -> str:
        recipient_ref = to.strip()
        to_alias = ""
        to_did = ""
        to_address = ""
        if recipient_ref.startswith("did:aw:") or recipient_ref.startswith("did:key:"):
            to_did = recipient_ref
        elif "/" in recipient_ref or recipient_ref.startswith("@"):
            to_address = recipient_ref
        else:
            to_alias = recipient_ref
        return await _chat_send_impl(
            db_infra,
            redis,
            registry_client=registry_client,
            hosted_signer=hosted_signer,
            hosted_encryptor=hosted_encryptor,
            hosted_decryptor=hosted_decryptor,
            message=message,
            to_alias=to_alias,
            to_did=to_did,
            to_address=to_address,
            session_id=conversation_id,
            wait=wait,
            wait_seconds=wait_seconds,
            leaving=leaving,
            hang_on=hang_on,
            plaintext=plaintext,
            federation_transport=federation_chat_transport,
            public_origin=public_origin,
        )

    @mcp.tool(
        name="check_chats",
        description="List chat conversations with unread messages waiting for you.",
    )
    async def check_chats() -> str:
        return await _chat_pending_impl(db_infra, redis, hosted_decryptor=hosted_decryptor)

    @mcp.tool(
        name="read_chat",
        description="Get message history for a chat session.",
    )
    async def read_chat(
        conversation_id: str,
        unread_only: bool = False,
        limit: int = 50,
    ) -> str:
        return await _chat_history_impl(
            db_infra,
            session_id=conversation_id,
            unread_only=unread_only,
            limit=limit,
            hosted_decryptor=hosted_decryptor,
        )

    @mcp.tool(
        name="mark_chat_read",
        description="Mark the presented chat message IDs as read.",
    )
    async def mark_chat_read(conversation_id: str, message_ids: list[str]) -> str:
        return await _chat_read_impl(
            db_infra, session_id=conversation_id, message_ids=message_ids
        )

    # -- Tasks --

    @mcp.tool(
        name="task_create",
        description="Create a task in the current team.",
    )
    async def task_create(
        title: str,
        description: str = "",
        notes: str = "",
        priority: int = 2,
        task_type: str = "task",
        labels: list[str] | None = None,
        parent_task_id: str = "",
        assignee: str = "",
    ) -> str:
        return await _task_create_impl(
            db_infra,
            title=title,
            description=description,
            notes=notes,
            priority=priority,
            task_type=task_type,
            labels=labels,
            parent_task_id=parent_task_id,
            assignee=assignee,
        )

    @mcp.tool(
        name="task_list",
        description="List tasks in the current team.",
    )
    async def task_list(
        status: str = "",
        assignee: str = "",
        task_type: str = "",
        priority: int = -1,
        labels: list[str] | None = None,
    ) -> str:
        return await _task_list_impl(
            db_infra,
            status=status,
            assignee=assignee,
            task_type=task_type,
            priority=priority,
            labels=labels,
        )

    @mcp.tool(
        name="task_ready",
        description="List ready tasks in the current team.",
    )
    async def task_ready(unclaimed_only: bool = True) -> str:
        return await _task_ready_impl(db_infra, unclaimed_only=unclaimed_only)

    @mcp.tool(
        name="task_get",
        description="Get a task by ref or UUID.",
    )
    async def task_get(ref: str) -> str:
        return await _task_get_impl(db_infra, ref=ref)

    @mcp.tool(
        name="task_close",
        description="Close a task by ref or UUID.",
    )
    async def task_close(ref: str) -> str:
        return await _task_close_impl(db_infra, ref=ref)

    @mcp.tool(
        name="task_update",
        description="Update task fields such as status, title, notes, assignee, or labels.",
    )
    async def task_update(
        ref: str,
        status: str = "",
        title: str = "",
        description: str = "",
        notes: str = "",
        task_type: str = "",
        priority: int = -1,
        labels: list[str] | None = None,
        assignee: str = "",
    ) -> str:
        return await _task_update_impl(
            db_infra,
            ref=ref,
            status=status,
            title=title,
            description=description,
            notes=notes,
            task_type=task_type,
            priority=priority,
            labels=labels,
            assignee=assignee,
        )

    @mcp.tool(
        name="task_reopen",
        description="Reopen a closed task.",
    )
    async def task_reopen(ref: str) -> str:
        return await _task_reopen_impl(db_infra, ref=ref)

    @mcp.tool(
        name="task_claim",
        description="Claim a task by marking it in progress for the current agent.",
    )
    async def task_claim(ref: str) -> str:
        return await _task_claim_impl(db_infra, ref=ref)

    @mcp.tool(
        name="task_comment_add",
        description="Add a comment to a task.",
    )
    async def task_comment_add(ref: str, body: str) -> str:
        return await _task_comment_add_impl(db_infra, ref=ref, body=body)

    @mcp.tool(
        name="task_comment_list",
        description="List comments on a task.",
    )
    async def task_comment_list(ref: str) -> str:
        return await _task_comment_list_impl(db_infra, ref=ref)

    # -- Roles --

    @mcp.tool(
        name="instructions_show",
        description="Show the active shared team instructions or a requested instructions version.",
    )
    async def instructions_show(team_instructions_id: str = "") -> str:
        return await _instructions_show_impl(
            db_infra, team_instructions_id=team_instructions_id
        )

    @mcp.tool(
        name="instructions_history",
        description="List recent shared team instructions versions.",
    )
    async def instructions_history(limit: int = 20) -> str:
        return await _instructions_history_impl(db_infra, limit=limit)

    @mcp.tool(
        name="roles_show",
        description="Show the active team roles bundle and the current agent's selected role.",
    )
    async def roles_show(only_selected: bool = False) -> str:
        return await _roles_show_impl(db_infra, only_selected=only_selected)

    @mcp.tool(
        name="roles_list",
        description="List available roles from the active team roles bundle.",
    )
    async def roles_list() -> str:
        return await _roles_list_impl(db_infra)

    # -- Work --

    @mcp.tool(
        name="work_ready",
        description="List ready tasks that are not already claimed by another workspace.",
    )
    async def work_ready() -> str:
        return await _work_ready_impl(db_infra)

    @mcp.tool(
        name="work_active",
        description="List active in-progress work across the team.",
    )
    async def work_active() -> str:
        return await _work_active_impl(db_infra)

    @mcp.tool(
        name="work_blocked",
        description="List blocked tasks in the current team.",
    )
    async def work_blocked() -> str:
        return await _work_blocked_impl(db_infra)

    # -- Workspace --

    @mcp.tool(
        name="workspace_status",
        description="Show self/team coordination status for the current agent.",
    )
    async def workspace_status(limit: int = 15) -> str:
        return await _workspace_status_impl(db_infra, redis, limit=limit)

    # -- Contacts --

    @mcp.tool(
        name="list_contacts",
        description="List saved contacts for the authenticated identity.",
    )
    async def list_contacts() -> str:
        return await _list_contacts_tool_impl(db_infra)

    @mcp.tool(
        name="add_contact",
        description="Add a contact by routable address.",
    )
    async def add_contact(address: str, label: str = "") -> str:
        return await _contacts_add_impl(db_infra, contact_address=address, label=label)

    @mcp.tool(
        name="add_contact_by_handle",
        description="Add a pending contact by @handle or @handle/agent.",
    )
    async def add_contact_by_handle(handle: str, label: str = "") -> str:
        return await _add_contact_by_handle_impl(db_infra, handle=handle, label=label)

    @mcp.tool(
        name="remove_contact",
        description="Remove a saved contact.",
    )
    async def remove_contact(contact_id: str) -> str:
        return await _contacts_remove_impl(db_infra, contact_id=contact_id)

    @mcp.tool(
        name="read_contact_messages",
        description=(
            "Read hosted mail or chat messages exchanged with a saved contact. "
            "Encrypted E2E mail content is returned as metadata only; read it in a local aw client."
        ),
    )
    async def read_contact_messages(
        contact_id: str,
        channel: str = "mail",
        limit: int = 50,
    ) -> str:
        return await _read_messages_from_contact_impl(
            db_infra,
            registry_client=registry_client,
            contact_id=contact_id,
            channel=channel,
            limit=limit,
        )

    # -- Legacy compatibility aliases --
    #
    # Hosted MCP clients can cache a tool list across deploys. Keep the old
    # names as thin delegates so existing ChatGPT/Claude sessions do not fail
    # with "Unknown tool" while new docs and clients use the canonical verbs.

    @mcp.tool(
        name="check_inbox",
        description=(
            "Legacy compatibility alias for check_mail. Prefer check_mail. "
            "Hosted custodial identities decrypt encrypted E2E mail for this MCP session."
        ),
    )
    async def check_inbox(
        unread_only: bool = True, limit: int = 50, include_bodies: bool = True
    ) -> str:
        return await _check_inbox_impl(
            db_infra,
            hosted_decryptor=hosted_decryptor,
            unread_only=unread_only,
            limit=limit,
            include_bodies=include_bodies,
        )

    @mcp.tool(
        name="chat_send",
        description="Legacy compatibility alias for send_chat. Prefer send_chat.",
    )
    async def chat_send(
        message: str = "",
        to_alias: str = "",
        to_did: str = "",
        to_address: str = "",
        session_id: str = "",
        wait: bool = False,
        wait_seconds: int = 120,
        leaving: bool = False,
        hang_on: bool = False,
        plaintext: bool = False,
    ) -> str:
        return await _chat_send_impl(
            db_infra,
            redis,
            registry_client=registry_client,
            hosted_signer=hosted_signer,
            hosted_encryptor=hosted_encryptor,
            hosted_decryptor=hosted_decryptor,
            message=message,
            to_alias=to_alias,
            to_did=to_did,
            to_address=to_address,
            session_id=session_id,
            wait=wait,
            wait_seconds=wait_seconds,
            leaving=leaving,
            hang_on=hang_on,
            plaintext=plaintext,
            federation_transport=federation_chat_transport,
            public_origin=public_origin,
        )

    @mcp.tool(
        name="chat_pending",
        description="Legacy compatibility alias for check_chats. Prefer check_chats.",
    )
    async def chat_pending() -> str:
        return await _chat_pending_impl(db_infra, redis, hosted_decryptor=hosted_decryptor)

    @mcp.tool(
        name="chat_history",
        description="Legacy compatibility alias for read_chat. Prefer read_chat.",
    )
    async def chat_history(
        session_id: str,
        unread_only: bool = False,
        limit: int = 50,
    ) -> str:
        return await _chat_history_impl(
            db_infra,
            session_id=session_id,
            unread_only=unread_only,
            limit=limit,
            hosted_decryptor=hosted_decryptor,
        )

    @mcp.tool(
        name="chat_read",
        description="Legacy compatibility alias for mark_chat_read. Prefer mark_chat_read.",
    )
    async def chat_read(session_id: str, message_ids: list[str]) -> str:
        return await _chat_read_impl(
            db_infra, session_id=session_id, message_ids=message_ids
        )

    @mcp.tool(
        name="contacts_list",
        description="Legacy compatibility alias for list_contacts. Prefer list_contacts.",
    )
    async def contacts_list() -> str:
        return await _contacts_list_impl(db_infra)

    @mcp.tool(
        name="contacts_add",
        description="Legacy compatibility alias for add_contact. Prefer add_contact.",
    )
    async def contacts_add(contact_address: str, label: str = "") -> str:
        return await _contacts_add_impl(db_infra, contact_address=contact_address, label=label)

    @mcp.tool(
        name="contacts_remove",
        description="Legacy compatibility alias for remove_contact. Prefer remove_contact.",
    )
    async def contacts_remove(contact_id: str) -> str:
        return await _contacts_remove_impl(db_infra, contact_id=contact_id)

    @mcp.tool(
        name="add_contact_by_email",
        description="Legacy compatibility alias for email contact requests.",
    )
    async def add_contact_by_email(email: str, label: str = "") -> str:
        return await _add_contact_by_email_impl(db_infra, email=email, label=label)

    @mcp.tool(
        name="send_message_to_contact",
        description=(
            "Legacy compatibility alias for hosted server-readable mail or chat to a saved contact. "
            "This hosted MCP tool is not E2E; use local aw clients for E2E messaging."
        ),
    )
    async def send_message_to_contact(
        contact_id: str,
        message: str,
        subject: str = "",
        channel: str = "mail",
        priority: str = "normal",
        wait: bool = False,
        wait_seconds: int = 120,
    ) -> str:
        return await _send_message_to_contact_impl(
            db_infra,
            redis=redis,
            registry_client=registry_client,
            hosted_signer=hosted_signer,
            hosted_encryptor=hosted_encryptor,
            contact_id=contact_id,
            message=message,
            subject=subject,
            channel=channel,
            priority=priority,
            wait=wait,
            wait_seconds=wait_seconds,
            federation_mail_transport=federation_mail_transport,
            federation_chat_transport=federation_chat_transport,
            public_origin=public_origin,
        )

    @mcp.tool(
        name="read_messages_from_contact",
        description=(
            "Legacy compatibility alias for read_contact_messages. "
            "Prefer read_contact_messages. Hosted MCP cannot decrypt E2E contents."
        ),
    )
    async def read_messages_from_contact(
        contact_id: str,
        channel: str = "mail",
        limit: int = 50,
    ) -> str:
        return await _read_messages_from_contact_impl(
            db_infra,
            registry_client=registry_client,
            contact_id=contact_id,
            channel=channel,
            limit=limit,
        )



def create_mcp_app(
    *,
    db_infra: DatabaseInfra,
    redis: Optional[Redis] = None,
    registry_client: RegistryClient | None = None,
    hosted_signer: HostedMessageSigner | None = None,
    hosted_encryptor: HostedMessageEncryptor | None = None,
    hosted_decryptor: HostedMessageDecryptor | None = None,
    federation_mail_transport=None,
    federation_chat_transport=None,
    public_origin: str | None = None,
    streamable_http_path: str = "/",
) -> Any:
    """Create an MCP ASGI app for aweb tools.

    The returned app handles Streamable HTTP transport and can be mounted on
    any ASGI framework (FastAPI, Starlette, etc.)::

        fastapi_app.mount("/mcp", create_mcp_app(db_infra=infra))

    When mounted at ``/mcp`` with the default ``streamable_http_path="/"``,
    the external MCP endpoint is ``/mcp/``.
    """
    normalized_path = streamable_http_path.strip() or "/"
    if not normalized_path.startswith("/"):
        normalized_path = f"/{normalized_path}"
    if normalized_path != "/" and normalized_path.endswith("/"):
        normalized_path = normalized_path.rstrip("/")

    mcp = FastMCP(
        "aweb",
        stateless_http=True,
        json_response=True,
        streamable_http_path=normalized_path,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=False,
        ),
    )

    if registry_client is None:
        registry_client = RegistryClient(registry_url=get_awid_registry_url())

    register_tools(
        mcp,
        db_infra,
        redis,
        registry_client,
        hosted_signer=hosted_signer,
        hosted_encryptor=hosted_encryptor,
        hosted_decryptor=hosted_decryptor,
        federation_mail_transport=federation_mail_transport,
        federation_chat_transport=federation_chat_transport,
        public_origin=public_origin,
    )

    # streamable_http_app() returns a Starlette app with its own lifespan, but
    # mounted sub-applications do not receive lifespan events from FastAPI.
    # Wrap the app so the parent can start/stop the session manager explicitly.
    inner = mcp.streamable_http_app()
    return ManagedMCPApp(MCPAuthMiddleware(inner, db_infra), mcp.session_manager)
