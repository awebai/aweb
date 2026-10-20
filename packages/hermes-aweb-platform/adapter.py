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
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any, Dict, List, NamedTuple, Optional

from gateway.config import Platform, PlatformConfig
from gateway.platforms.base import BasePlatformAdapter, MessageEvent, MessageType, ProcessingOutcome, SendResult

logger = logging.getLogger(__name__)

RECONNECT_BACKOFF = [1, 2, 5, 10, 30]
MAX_MESSAGE_LENGTH = 16_000


class InputRoute(NamedTuple):
    kind: str
    target: str
    message_id: str
    chat_id: str


# Task-local routing survives Hermes background tasks and its context-preserving
# worker-thread bridge. An inline control must never replace the active turn's
# route. Explicit reply_to anchors also support Hermes final-delivery recovery.
_input_route: ContextVar[Optional[InputRoute]] = ContextVar("aweb_input_route", default=None)
_delivery_state: ContextVar[Optional[dict]] = ContextVar("aweb_delivery_state", default=None)


class _Lane:
    def __init__(self, chat_id: str):
        self.chat_id = chat_id
        self.wake = asyncio.Event()
        self.pending: Dict[str, MessageEvent] = {}
        self.turn: Optional[asyncio.Task] = None
        self.worker: Optional[asyncio.Task] = None
        self.control: Optional[asyncio.Task] = None
        self.control_event: Optional[MessageEvent] = None


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
        self._lanes: Dict[str, _Lane] = {}
        self._queued: set[str] = set()
        self._ignored: set[str] = set()
        self._completed_inputs: set[str] = set()
        self._mail_events: Dict[str, dict] = {}
        self._mail_wake = asyncio.Event()
        self._mail_task: Optional[asyncio.Task] = None
        self._stream_live = False

    @property
    def name(self) -> str:
        return "Aweb"

    @property
    def send_path_degraded(self) -> bool:
        return not self._stream_live

    def _stream_health(self, live: bool) -> None:
        if self._stream_live == live:
            return
        self._stream_live = live
        if self._running:
            if live:
                self._mark_connected()
            else:
                self._mark_degraded()

    async def connect(self, *, is_reconnect: bool = False) -> bool:
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
        self._stream_live = False
        workers = [task for lane in self._lanes.values() for task in (lane.worker, lane.turn, lane.control) if task]
        if self._mail_task:
            workers.append(self._mail_task)
        for task in workers:
            task.cancel()
        if workers:
            await asyncio.gather(*workers, return_exceptions=True)
        await self.cancel_background_tasks()
        self._lanes.clear()
        self._queued.clear()
        self._mail_events.clear()
        self._mail_task = None
        if self._proc and self._proc.returncode is None:
            await self._stop_process(self._proc)
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
                self._stream_health(False)
                if self._proc and self._proc.returncode is None:
                    await self._stop_process(self._proc)
                if self._stderr_task:
                    self._stderr_task.cancel()
                    await asyncio.gather(self._stderr_task, return_exceptions=True)
                    self._stderr_task = None
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
                # aw reconnects HTTP streams inside the same process. Its
                # reconnect diagnostic is observable even before a new frame.
                if text.startswith("aw events stream:") and "reconnecting" in text:
                    self._stream_health(False)
                logger.info("Aweb aw stderr: %s", text)

    async def _handle_aw_event(self, event: dict) -> None:
        typ = event.get("type")
        if typ == "error":
            self._stream_health(False)
        elif typ in {"connected", "heartbeat", "actionable_mail", "actionable_chat"}:
            self._stream_health(True)
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

    @staticmethod
    def _route_for_event(event: MessageEvent) -> InputRoute:
        route = getattr(event, "_aweb_input_route", None)
        if route is None:
            chat_id = str(event.source.chat_id)
            kind, target = chat_id.split(":", 1)
            route = InputRoute(kind, target, str(event.message_id), chat_id)
            event._aweb_input_route = route
        return route

    @staticmethod
    def _input_key(route: InputRoute) -> str:
        if route.kind == "mail":
            return "mail:" + route.message_id
        return f"chat:{route.target}:{route.message_id}"

    def _lane(self, chat_id: str) -> _Lane:
        lane = self._lanes.get(chat_id)
        if lane is None:
            lane = self._lanes[chat_id] = _Lane(chat_id)
        if lane.worker is None or lane.worker.done():
            lane.worker = asyncio.create_task(self._run_lane(lane))
        return lane

    async def _dispatch_mail_event(self, event: dict) -> None:
        message_id = str(event.get("message_id") or "").strip()
        if not message_id or message_id in self._mail_events or "mail:" + message_id in self._queued:
            return
        if "mail:" + message_id in self._seen or "mail:" + message_id in self._ignored:
            return
        self._mail_events[message_id] = event
        self._mail_wake.set()
        if self._mail_task is None or self._mail_task.done():
            self._mail_task = asyncio.create_task(self._fetch_mail())

    async def _fetch_mail(self) -> None:
        # A fetch failure never consumes the input or blocks the event reader.
        while self._running:
            await self._mail_wake.wait()
            self._mail_wake.clear()
            for message_id, hint in list(self._mail_events.items()):
                try:
                    payload = await self._run_aw_json("mail", "show", "--message-id", message_id)
                    msg = _first_mapping_item(payload, "messages")
                    if not msg:
                        raise RuntimeError(f"actionable mail {message_id} was not returned")
                    conversation_id = str(msg.get("conversation_id") or hint.get("conversation_id") or message_id)
                    sender = str(msg.get("from_address") or hint.get("from_address") or msg.get("from_alias") or "aweb")
                    subject, body = str(msg.get("subject") or ""), str(msg.get("body") or "")
                    source = self.build_source(
                        chat_id=f"mail:{conversation_id}", chat_name=subject or sender, chat_type="dm",
                        user_id=sender, user_name=sender, message_id=message_id,
                    )
                    event = MessageEvent(
                        text=f"Subject: {subject}\n\n{body}" if subject else body,
                        message_type=MessageType.TEXT, source=source, message_id=message_id,
                        raw_message=msg, timestamp=_event_timestamp(msg.get("created_at")),
                    )
                    lane = self._lane(str(source.chat_id))
                    lane.pending[message_id] = event
                    self._queued.add("mail:" + message_id)
                    lane.wake.set()
                    self._mail_events.pop(message_id, None)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    logger.exception("Aweb: mail fetch failed; retaining %s for retry", message_id)
            if self._mail_events:
                await asyncio.sleep(RECONNECT_BACKOFF[0])
                self._mail_wake.set()

    async def _dispatch_chat_event(self, event: dict) -> None:
        session_id = str(event.get("session_id") or "").strip()
        if session_id:
            self._lane("chat:" + session_id).wake.set()

    def _is_control(self, event: MessageEvent) -> bool:
        from hermes_cli.commands import is_interrupt_then_dispatch, resolve_command
        if self.gateway_runner is not None and not self.gateway_runner._is_user_authorized_for_source(event.source):
            return False
        cmd = event.get_command()
        definition = resolve_command(cmd) if cmd else None
        if is_interrupt_then_dispatch(cmd) or (definition and definition.name in {"approve", "deny"}):
            return True
        if not event.get_command() and event.allow_gateway_control:
            from tools.clarify_gateway import get_pending_for_session
            return get_pending_for_session(self._event_session_key(event), include_choice_prompts=True) is not None
        return False

    async def _run_lane(self, lane: _Lane) -> None:
        """Keep discovery responsive while ONE ordinary input owns the turn.

        Clear wake BEFORE the history read. A hint received during any await is
        retained by Event, including an empty response. Idle retirement and lane
        removal have no intervening await, so a hint always has a live owner.
        """
        try:
            while self._running:
                busy = any(t is not None and not t.done() for t in (lane.turn, lane.control))
                try:
                    await asyncio.wait_for(lane.wake.wait(), timeout=.1 if busy else (1 if lane.pending else 60))
                except asyncio.TimeoutError:
                    if not busy and not lane.pending and not lane.wake.is_set():
                        self._lanes.pop(lane.chat_id, None)
                        return
                refresh = lane.wake.is_set()
                lane.wake.clear()
                if getattr(self.gateway_runner, "_startup_restore_in_progress", False):
                    await asyncio.sleep(.1)
                    lane.wake.set()
                    continue
                if refresh and lane.chat_id.startswith("chat:"):
                    try:
                        payload = await self._run_aw_json(
                            "chat", "history", "--session-id", lane.chat_id[5:],
                            "--unread-only", "--limit", "2000",
                        )
                        messages = payload.get("messages") or []
                        if len(messages) >= 2000:
                            logger.error("Aweb: session %s reached the 2000-message history limit; refusing ambiguous newest window", lane.chat_id)
                            continue
                        for msg in messages:
                            message_id = str(msg.get("message_id") or "").strip()
                            if not message_id:
                                raise RuntimeError("Aweb unread history omitted message_id")
                            if message_id in lane.pending:
                                continue
                            sender = str(msg.get("from_address") or msg.get("from_agent") or "aweb")
                            source = self.build_source(
                                chat_id=lane.chat_id, chat_name=sender, chat_type="dm",
                                user_id=sender, user_name=sender, message_id=message_id,
                            )
                            lane.pending[message_id] = MessageEvent(
                                text=str(msg.get("body") or ""), message_type=MessageType.TEXT,
                                source=source, message_id=message_id, raw_message=msg,
                                timestamp=_event_timestamp(msg.get("timestamp")),
                            )
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        logger.exception("Aweb: unread history failed; retrying %s", lane.chat_id)
                        await asyncio.sleep(1)
                        lane.wake.set()
                        continue
                for message_id, event in list(lane.pending.items()):
                    route = self._route_for_event(event)
                    key = self._input_key(route)
                    receipt_key = key
                    if receipt_key in self._seen or receipt_key in self._ignored:
                        lane.pending.pop(message_id, None)
                        self._queued.discard(receipt_key)
                        continue
                    busy = any(t is not None and not t.done() for t in (lane.turn, lane.control))
                    if busy:
                        # The active input is still unread until its response;
                        # do not mistake it for an answer to its own clarify.
                        if any(t is not None and not t.done() and getattr(t, "aweb_input_id", None) == message_id
                               for t in (lane.turn, lane.control)):
                            continue
                        if (lane.control is None or lane.control.done()) and self._is_control(event):
                            lane.control_event = event
                            lane.control = asyncio.create_task(self._deliver_input(event, inline=True))
                            lane.control.aweb_input_id = message_id
                            lane.control.add_done_callback(lambda task, wake=lane.wake: wake.set())
                        continue
                    lane.turn = asyncio.create_task(self._deliver_input(event))
                    lane.turn.aweb_input_id = message_id
                    lane.turn.add_done_callback(lambda task, wake=lane.wake: wake.set())
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Aweb: input lane failed; input stays unread: %s", lane.chat_id)

    async def handle_message(self, event: MessageEvent) -> None:
        # Hermes-created tasks inherit this immutable snapshot; another input
        # in the same conversation receives its own independent context.
        route_token = _input_route.set(self._route_for_event(event))
        try:
            await super().handle_message(event)
        finally:
            _input_route.reset(route_token)

    async def _dispatch_inline_reply(self, event: MessageEvent, *, log_cmd: Optional[str] = None) -> None:
        try:
            await super()._dispatch_inline_reply(event, log_cmd=log_cmd)
        except BaseException:
            # Hermes logs/contains inline handler exceptions. Preserve their
            # failed disposition so containment cannot turn into a read ACK.
            state = _delivery_state.get()
            if state is not None:
                state["failed"] = True
            raise

    async def _deliver_input(self, event: MessageEvent, *, inline: bool = False) -> None:
        state = {"failed": False}
        state_token = _delivery_state.set(state)
        route = self._route_for_event(event)
        key = self._input_key(route)
        try:
            if key in self._completed_inputs:
                # This input already completed in this process (visible reply
                # or accepted no-reply processing). Retry only its read receipt.
                await self._ack_input(event)
            else:
                previous = self._session_tasks.get(self._event_session_key(event))
                await self.handle_message(event)
                task = self._session_tasks.get(self._event_session_key(event))
                if task is not None and (not inline or task is not previous):
                    # The public hook precedes guard cleanup. Pin this owner
                    # task boundary so the next ordinary input cannot merge.
                    await asyncio.shield(task)
                elif inline and not state["failed"]:
                    # Inline bypasses have no processing-complete hook. The
                    # real handler has returned (including no-reply clarify).
                    await self._ack_input(event)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Aweb: input failed; retaining %s for retry", event.message_id)
        finally:
            _delivery_state.reset(state_token)
        if self._running and key not in self._seen and key not in self._ignored:
            await asyncio.sleep(1)

    async def _ack_input(self, event: MessageEvent) -> None:
        if not self._running:
            return
        route = self._route_for_event(event)
        key = self._input_key(route)
        if key in self._seen:
            return
        # Hermes returns None for unauthorized input as well as accepted empty
        # commands. Its pinned source-aware authorization gate distinguishes
        # these; do not convert a refusal into a source read receipt.
        runner = self.gateway_runner
        if runner is not None and not runner._is_user_authorized_for_source(event.source):
            self._ignored.add(key)
            return
        self._completed_inputs.add(key)
        await self._ack_route(route)

    async def _ack_route(self, route: InputRoute) -> None:
        key = self._input_key(route)
        if key in self._seen:
            self._completed_inputs.discard(key)
            return
        if not self._running:
            return
        if route.kind == "mail":
            await self._run_aw_json("mail", "ack", route.message_id)
        else:
            await self._run_aw_json("chat", "read", "--session-id", route.target, "--message-id", route.message_id)
        self._dedup(key)
        self._completed_inputs.discard(key)

    async def on_processing_complete(self, event: MessageEvent, outcome: ProcessingOutcome) -> None:
        await super().on_processing_complete(event, outcome)
        if outcome == ProcessingOutcome.SUCCESS:
            await self._ack_input(event)
        elif outcome == ProcessingOutcome.CANCELLED:
            # An explicit successful /stop, /new or /reset retires the old
            # turn. Replaying its still-unread input would immediately undo
            # the user's stop. Shutdown/failure cancellation has no such receipt.
            from hermes_cli.commands import is_interrupt_then_dispatch
            lane = self._lanes.get(str(event.source.chat_id))
            control = lane.control_event if lane else None
            if (control is not None and lane.control is not None and not lane.control.done()
                    and is_interrupt_then_dispatch(control.get_command())):
                route = self._route_for_event(control)
                key = self._input_key(route)
                if key in self._seen:
                    await self._ack_input(event)

    async def send(self, chat_id: str, content: str, reply_to: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> SendResult:
        if len(content) > self.MAX_MESSAGE_LENGTH:
            logger.warning("Aweb: truncating outbound message from %d to %d chars", len(content), self.MAX_MESSAGE_LENGTH)
            content = content[: self.MAX_MESSAGE_LENGTH]
        route = _input_route.get()
        if reply_to and chat_id.startswith(("mail:", "chat:")):
            kind, target = chat_id.split(":", 1)
            route = InputRoute(kind, target, str(reply_to), chat_id)
        if route is not None and route.chat_id == chat_id:
            if route.kind == "mail":
                result = await self._send_mail_reply(route, content)
            else:
                result = await self._send_chat_reply(route, content)
        elif chat_id.startswith(("mail:", "chat:")):
            result = SendResult(success=False, error="Aweb reply requires its triggering input route or reply_to")
        else:
            result = await self._send_chat_to_target(chat_id, content)
        state = _delivery_state.get()
        if state is not None:
            state["failed"] = state["failed"] or not result.success
        return result

    async def _send_mail_reply(self, route: InputRoute, content: str) -> SendResult:
        body_path = self._write_temp_body(content)
        try:
            payload = await self._run_aw_json("mail", "reply", route.message_id, "--plaintext", "--body-file", body_path)
            result = SendResult(success=True, message_id=str(payload.get("message_id") or ""), raw_response=payload)
            self._completed_inputs.add("mail:" + route.message_id)
            try:
                await self._ack_route(route)
            except Exception:
                logger.exception("Aweb: mail reply persisted but read mark failed")
            return result
        except Exception as exc:
            return SendResult(success=False, error=str(exc))
        finally:
            os.unlink(body_path)

    async def _send_chat_reply(self, route: InputRoute, content: str) -> SendResult:
        result = await self._send_chat_to_session(route.target, content, leave=True)
        if result.success:
            self._completed_inputs.add(self._input_key(route))
            try:
                await self._ack_route(route)
            except Exception:
                logger.exception("Aweb: chat reply persisted but read mark failed")
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

    @staticmethod
    async def _stop_process(proc: asyncio.subprocess.Process) -> None:
        if proc.returncode is not None:
            return
        try:
            proc.terminate()
        except ProcessLookupError:
            pass
        try:
            await asyncio.wait_for(proc.wait(), timeout=5)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()

    async def _run_aw_json(self, *args: str) -> dict:
        cmd = [self.aw_bin, *args, "--json"]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=self.workdir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        finally:
            if proc.returncode is None:
                await self._stop_process(proc)
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
