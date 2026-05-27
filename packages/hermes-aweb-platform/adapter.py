"""Aweb platform adapter for Hermes Agent.

This plugin bridges Hermes' messaging gateway to Aweb agent mail/chat by
shelling to the `aw` CLI. It intentionally uses aw as the trust/auth boundary:
workspace selection, DID signatures, team certificates, hosted/BYOT routing,
and E2EE/plaintext policy stay owned by aw.

Inbound flow:
  aw events stream --json -> actionable_mail/actionable_chat -> fetch body with
  aw mail show / aw chat history -> Hermes MessageEvent.

Outbound flow:
  Hermes adapter send() -> aw mail reply / exact aw chat send --session-id -> after a
  successful visible send, aw mail ack / aw chat read marks the triggering
  Aweb message delivered/read.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import tempfile
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from gateway.config import Platform, PlatformConfig
from gateway.platforms.base import BasePlatformAdapter, MessageEvent, MessageType, SendResult

logger = logging.getLogger(__name__)

RECONNECT_BACKOFF = [1, 2, 5, 10, 30]
MAX_MESSAGE_LENGTH = 16_000


def _truthy(value: Any, default: bool = False) -> bool:
    if value is None or value == "":
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _first_mapping_item(payload: dict, key: str) -> Optional[dict]:
    items = payload.get(key)
    if isinstance(items, list) and items:
        first = items[0]
        if isinstance(first, dict):
            return first
    return None


def _event_timestamp(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return datetime.now(timezone.utc)


def check_requirements() -> bool:
    aw_bin = os.getenv("AWEB_PLATFORM_AW_BIN", "aw")
    return bool(shutil.which(aw_bin) or os.path.exists(aw_bin))


def validate_config(config) -> bool:
    extra = getattr(config, "extra", {}) or {}
    aw_bin = extra.get("aw_bin") or os.getenv("AWEB_PLATFORM_AW_BIN", "aw")
    return bool(shutil.which(str(aw_bin)) or os.path.exists(str(aw_bin)))


def is_connected(config) -> bool:
    return validate_config(config)


def _env_enablement() -> dict | None:
    enabled = _truthy(os.getenv("AWEB_PLATFORM_ENABLED"), False)
    workdir = os.getenv("AWEB_PLATFORM_WORKDIR", "").strip()
    home = os.getenv("AWEB_HOME_CHANNEL", "").strip()
    # Do not auto-enable merely because `aw` is installed. The user must opt in
    # with AWEB_PLATFORM_ENABLED=true, set a workspace dir, or configure a home
    # channel. config.yaml `gateway.platforms.aweb.enabled: true` still works.
    if not (enabled or workdir or home):
        return None
    seed: dict[str, Any] = {
        "aw_bin": os.getenv("AWEB_PLATFORM_AW_BIN", "aw"),
        "enable_mail": _truthy(os.getenv("AWEB_PLATFORM_ENABLE_MAIL"), True),
        "enable_chat": _truthy(os.getenv("AWEB_PLATFORM_ENABLE_CHAT"), True),
    }
    if workdir:
        seed["workdir"] = workdir
    if home:
        seed["home_channel"] = {"chat_id": home, "name": os.getenv("AWEB_HOME_CHANNEL_NAME", home)}
    return seed


class AwebAdapter(BasePlatformAdapter):
    """Hermes adapter backed by an aw workspace."""

    MAX_MESSAGE_LENGTH = MAX_MESSAGE_LENGTH

    def __init__(self, config: PlatformConfig):
        super().__init__(config=config, platform=Platform("aweb"))
        extra = getattr(config, "extra", {}) or {}
        self.aw_bin = str(extra.get("aw_bin") or os.getenv("AWEB_PLATFORM_AW_BIN", "aw"))
        self.workdir = str(extra.get("workdir") or os.getenv("AWEB_PLATFORM_WORKDIR", "") or os.getcwd())
        self.enable_mail = bool(extra.get("enable_mail", _truthy(os.getenv("AWEB_PLATFORM_ENABLE_MAIL"), True)))
        self.enable_chat = bool(extra.get("enable_chat", _truthy(os.getenv("AWEB_PLATFORM_ENABLE_CHAT"), True)))
        self._stream_task: Optional[asyncio.Task] = None
        self._stderr_task: Optional[asyncio.Task] = None
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._seen: Dict[str, float] = {}
        self._routes: Dict[str, dict] = {}

    @property
    def name(self) -> str:
        return "Aweb"

    async def connect(self) -> bool:
        if not validate_config(self.config):
            self._set_fatal_error("aw_missing", "aw binary not found; set AWEB_PLATFORM_AW_BIN", retryable=False)
            return False
        if not os.path.isdir(self.workdir):
            self._set_fatal_error("workdir_missing", f"Aweb workdir does not exist: {self.workdir}", retryable=False)
            return False
        self._running = True
        self._stream_task = asyncio.create_task(self._run_event_stream())
        self._mark_connected()
        logger.info("Aweb: listening with %s in %s", self.aw_bin, self.workdir)
        return True

    async def disconnect(self) -> None:
        self._running = False
        self._mark_disconnected()
        if self._proc and self._proc.returncode is None:
            self._proc.terminate()
            try:
                await asyncio.wait_for(self._proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                self._proc.kill()
        if self._stream_task:
            self._stream_task.cancel()
            try:
                await self._stream_task
            except asyncio.CancelledError:
                pass
            self._stream_task = None
        if self._stderr_task:
            self._stderr_task.cancel()
            self._stderr_task = None
        self._proc = None

    async def _run_event_stream(self) -> None:
        backoff_idx = 0
        while self._running:
            started = time.monotonic()
            try:
                self._proc = await asyncio.create_subprocess_exec(
                    self.aw_bin,
                    "events",
                    "stream",
                    "--json",
                    cwd=self.workdir,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                if self._proc.stderr is not None:
                    self._stderr_task = asyncio.create_task(self._log_stderr(self._proc.stderr))
                assert self._proc.stdout is not None
                async for raw in self._proc.stdout:
                    if not self._running:
                        break
                    line = raw.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        logger.debug("Aweb: ignoring non-JSON event line: %.120s", line)
                        continue
                    await self._handle_aw_event(event)
                rc = await self._proc.wait()
                if self._running:
                    logger.warning("Aweb: aw events stream exited rc=%s", rc)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                if self._running:
                    logger.warning("Aweb: event stream failed: %s", exc, exc_info=True)
            finally:
                self._proc = None

            if not self._running:
                break
            if time.monotonic() - started > 60:
                backoff_idx = 0
            delay = RECONNECT_BACKOFF[min(backoff_idx, len(RECONNECT_BACKOFF) - 1)]
            backoff_idx += 1
            await asyncio.sleep(delay)

    async def _log_stderr(self, stream: asyncio.StreamReader) -> None:
        async for raw in stream:
            text = raw.decode("utf-8", errors="replace").strip()
            if text:
                logger.info("Aweb aw stderr: %s", text)

    async def _handle_aw_event(self, event: dict) -> None:
        typ = event.get("type")
        if typ == "actionable_mail" and self.enable_mail:
            await self._dispatch_mail_event(event)
        elif typ == "actionable_chat" and self.enable_chat:
            await self._dispatch_chat_event(event)

    def _dedup(self, key: str) -> bool:
        now = time.time()
        if len(self._seen) > 2000:
            cutoff = now - 3600
            self._seen = {k: v for k, v in self._seen.items() if v > cutoff}
        if key in self._seen:
            return True
        self._seen[key] = now
        return False

    async def _dispatch_mail_event(self, event: dict) -> None:
        message_id = str(event.get("message_id") or "").strip()
        if not message_id or self._dedup("mail:" + message_id):
            return
        payload = await self._run_aw_json("mail", "show", "--message-id", message_id)
        msg = _first_mapping_item(payload, "messages")
        if not msg:
            logger.warning("Aweb: mail %s was actionable but could not be fetched", message_id)
            return
        conversation_id = str(msg.get("conversation_id") or event.get("conversation_id") or message_id)
        chat_id = f"mail:{conversation_id}"
        sender = str(msg.get("from_address") or event.get("from_address") or msg.get("from_alias") or event.get("from_alias") or "aweb")
        subject = str(msg.get("subject") or event.get("subject") or "")
        body = str(msg.get("body") or "")
        text = f"Subject: {subject}\n\n{body}" if subject else body
        self._routes[chat_id] = {
            "kind": "mail",
            "message_id": message_id,
            "conversation_id": conversation_id,
            "sender": sender,
        }
        source = self.build_source(
            chat_id=chat_id,
            chat_name=subject or sender,
            chat_type="dm",
            user_id=sender,
            user_name=sender,
            message_id=message_id,
        )
        await self.handle_message(MessageEvent(
            text=text,
            message_type=MessageType.TEXT,
            source=source,
            message_id=message_id,
            raw_message=msg,
            timestamp=_event_timestamp(msg.get("created_at")),
        ))

    async def _dispatch_chat_event(self, event: dict) -> None:
        session_id = str(event.get("session_id") or "").strip()
        message_id = str(event.get("message_id") or "").strip()
        if not session_id or not message_id or self._dedup("chat:" + session_id + ":" + message_id):
            return
        payload = await self._run_aw_json("chat", "history", "--session-id", session_id, "--message-id", message_id, "--limit", "1")
        msg = _first_mapping_item(payload, "messages")
        if not msg:
            logger.warning("Aweb: chat %s/%s was actionable but could not be fetched", session_id, message_id)
            return
        chat_id = f"chat:{session_id}"
        sender = str(msg.get("from_address") or event.get("from_address") or msg.get("from_agent") or event.get("from_alias") or "aweb")
        body = str(msg.get("body") or "")
        self._routes[chat_id] = {
            "kind": "chat",
            "session_id": session_id,
            "message_id": message_id,
            "sender": sender,
        }
        source = self.build_source(
            chat_id=chat_id,
            chat_name=sender,
            chat_type="dm",
            user_id=sender,
            user_name=sender,
            message_id=message_id,
        )
        await self.handle_message(MessageEvent(
            text=body,
            message_type=MessageType.TEXT,
            source=source,
            message_id=message_id,
            raw_message=msg,
            timestamp=_event_timestamp(msg.get("timestamp")),
        ))

    async def send(self, chat_id: str, content: str, reply_to: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> SendResult:
        if len(content) > self.MAX_MESSAGE_LENGTH:
            logger.warning("Aweb: truncating outbound message from %d to %d chars", len(content), self.MAX_MESSAGE_LENGTH)
            content = content[: self.MAX_MESSAGE_LENGTH]
        route = self._routes.get(chat_id)
        if route and route.get("kind") == "mail":
            return await self._send_mail_reply(route, content)
        if route and route.get("kind") == "chat":
            return await self._send_chat_reply(route, content)
        # Cron/home-channel fallback: treat chat_id as an Aweb alias/address.
        return await self._send_chat_to_target(chat_id, content)

    async def _send_mail_reply(self, route: dict, content: str) -> SendResult:
        body_path = self._write_temp_body(content)
        try:
            payload = await self._run_aw_json("mail", "reply", str(route["message_id"]), "--plaintext", "--body-file", body_path)
            msg_id = str(payload.get("message_id") or payload.get("MessageID") or int(time.time() * 1000))
            # Confirmed visible send happened; now mark the inbound mail read.
            await self._run_aw_json("mail", "ack", str(route["message_id"]))
            return SendResult(success=True, message_id=msg_id, raw_response=payload)
        except Exception as exc:
            return SendResult(success=False, error=str(exc))
        finally:
            try:
                os.unlink(body_path)
            except OSError:
                pass

    async def _send_chat_reply(self, route: dict, content: str) -> SendResult:
        session_id = str(route.get("session_id") or "").strip()
        if not session_id:
            return SendResult(success=False, error="Aweb chat route is missing session_id")
        result = await self._send_chat_to_session(session_id, content, leave=True)
        if result.success:
            try:
                await self._run_aw_json("chat", "read", "--session-id", session_id, "--message-id", str(route["message_id"]))
            except Exception as exc:
                logger.warning("Aweb: reply sent but chat read mark failed: %s", exc)
        return result

    async def _send_chat_to_session(self, session_id: str, content: str, *, leave: bool = False) -> SendResult:
        if not session_id:
            return SendResult(success=False, error="Aweb session_id is empty")
        body_path = self._write_temp_body(content)
        args = ["chat", "send", "--session-id", session_id, "--plaintext", "--body-file", body_path]
        if leave:
            args.append("--leave")
        try:
            payload = await self._run_aw_json(*args)
            msg_id = str(payload.get("message_id") or payload.get("MessageID") or int(time.time() * 1000))
            return SendResult(success=True, message_id=msg_id, raw_response=payload)
        except Exception as exc:
            return SendResult(success=False, error=str(exc))
        finally:
            try:
                os.unlink(body_path)
            except OSError:
                pass

    async def _send_chat_to_target(self, target: str, content: str) -> SendResult:
        if not target:
            return SendResult(success=False, error="Aweb target is empty")
        try:
            payload = await self._run_aw_json("chat", "send-and-leave", "--plaintext", target, content)
            msg_id = str(payload.get("message_id") or payload.get("MessageID") or int(time.time() * 1000))
            return SendResult(success=True, message_id=msg_id, raw_response=payload)
        except Exception as exc:
            return SendResult(success=False, error=str(exc))

    async def send_typing(self, chat_id: str, metadata=None) -> None:
        # Aweb has no typing primitive in the CLI surface.
        return None

    async def get_chat_info(self, chat_id: str) -> Dict[str, Any]:
        return {"chat_id": chat_id, "name": chat_id, "type": "dm"}

    def _write_temp_body(self, content: str) -> str:
        fd, path = tempfile.mkstemp(prefix="hermes-aweb-", suffix=".md")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        return path

    async def _run_aw_json(self, *args: str) -> dict:
        cmd = [self.aw_bin, *args, "--json"]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=self.workdir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        out = stdout.decode("utf-8", errors="replace").strip()
        err = stderr.decode("utf-8", errors="replace").strip()
        if proc.returncode != 0:
            raise RuntimeError(f"aw {' '.join(args)} failed rc={proc.returncode}: {err or out}")
        if not out:
            return {}
        try:
            return json.loads(out)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"aw {' '.join(args)} returned non-JSON: {out[:300]}") from exc


async def _standalone_send(pconfig, chat_id: str, message: str, *, thread_id: Optional[str] = None, media_files: Optional[List[str]] = None, force_document: bool = False) -> Dict[str, Any]:
    adapter = AwebAdapter(pconfig)
    result = await adapter._send_chat_to_target(chat_id, message)
    if result.success:
        return {"success": True, "platform": "aweb", "chat_id": chat_id, "message_id": result.message_id}
    return {"error": result.error or "Aweb send failed"}


def interactive_setup() -> None:
    print()
    print("Aweb setup")
    print("----------")
    print("Requirements:")
    print("  1. aw CLI installed and upgraded to a version with `aw chat send --session-id`, `aw mail ack`, and `aw chat read`.")
    print("  2. A configured aw workspace for the Hermes gateway identity.")
    print()
    try:
        from hermes_cli.config import get_env_value, save_env_value
    except Exception:
        print("Set AWEB_PLATFORM_ENABLED=true and AWEB_PLATFORM_WORKDIR manually in ~/.hermes/.env")
        return

    def prompt(var: str, label: str, default: str = "") -> None:
        current = get_env_value(var) or default
        suffix = f" [{current}]" if current else ""
        value = input(f"{label}{suffix}: ").strip()
        save_env_value(var, value or current)

    save_env_value("AWEB_PLATFORM_ENABLED", "true")
    prompt("AWEB_PLATFORM_WORKDIR", "aw workspace directory", os.getcwd())
    prompt("AWEB_PLATFORM_AW_BIN", "aw binary", "aw")
    prompt("AWEB_ALLOWED_USERS", "allowed Aweb senders (comma-separated; blank=use AWEB_ALLOW_ALL_USERS)", "")
    prompt("AWEB_HOME_CHANNEL", "home Aweb alias/address for cron delivery (optional)", "")
    print("Done. Restart Hermes gateway after confirming `aw workspace status` works in that directory.")


def register(ctx) -> None:
    ctx.register_platform(
        name="aweb",
        label="Aweb",
        adapter_factory=lambda cfg: AwebAdapter(cfg),
        check_fn=check_requirements,
        validate_config=validate_config,
        is_connected=is_connected,
        required_env=["AWEB_PLATFORM_ENABLED"],
        install_hint="Install @awebai/aw and initialize an aw workspace for the Hermes gateway identity",
        setup_fn=interactive_setup,
        env_enablement_fn=_env_enablement,
        cron_deliver_env_var="AWEB_HOME_CHANNEL",
        standalone_sender_fn=_standalone_send,
        allowed_users_env="AWEB_ALLOWED_USERS",
        allow_all_env="AWEB_ALLOW_ALL_USERS",
        max_message_length=MAX_MESSAGE_LENGTH,
        emoji="🕸️",
        pii_safe=True,
        allow_update_command=True,
        platform_hint=(
            "You are communicating through Aweb agent mail/chat. Send concise, agent-to-agent "
            "responses. Aweb handles identity, signatures, team routing, and read/ack state via aw."
        ),
    )
