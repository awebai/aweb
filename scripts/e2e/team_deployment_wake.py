#!/usr/bin/env python3
"""Checks that a team deployment's agent session receives a fresh mail's full,
verified event through the real wake broker.

Inside the agent container, over the operator's route, as the agent user:

1. Preflight, each a named failure:
   - HOME is /state/home;
   - the wake daemon runs and holds the receiver's home with session
     delivery, active, and its identity streaming;
   - OATS reports the session present and not stopped, a shell or blocked;
   - the Claude login file is readable;
   - a Claude transcript of the home exists, which a session at the sign-in
     screen never writes. Without one, nothing is sent.
2. Seat A sends one fresh mail to seat B, by alias. Its message ID is kept.
3. The helper polls B's Claude transcript, Claude's own storage and not an
   OATS contract, for the user turn that carries the full event:
   - the "aweb mail event received." header;
   - the message ID, the sender's alias and the subject;
   - trust_status verified and verified: true, with no warning;
   - the exact body.
   The pane, captured as OATS's own kernel does, is secondary evidence. An
   inbox read, a send receipt or an ID-only notice is never success. Every
   event seen must also be unpromoted: verified: true only with a trusted
   status and no warning.

The mail asks for no action, but it is typed into a live Claude session,
which takes one model turn on it.

Two other modes send nothing:

- --preflight-only runs step 1 alone, so a caller with one mail to spend
  learns first whether the session can take it.
- --message-id correlates a mail the caller already sent. The sender's aw
  mail show, which leaves read state alone, binds it to the sender's DID, to
  the receiver's alias and a DID the receiver streams, and to a time after the
  session started. Step 3 then proves its wake. The reply is the receiver's
  first verified mail to the sender in that conversation created after it.
  Other senders, recipients and conversations, and earlier mail, are never the
  reply. A failure carries "partial": what was observed before it, nothing
  inferred.

Transport trust (the live CA negative) is the journey's requalify_agent. Sender
trust is cited from channel-core's existing tests, not tested here.
"""

from __future__ import annotations

import argparse
import json
import secrets
import shlex
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Callable

EVENT_HEADER = "aweb mail event received."
# channel-core's MAIL_THREAD_TEACHING, which closes every mail event.
MAIL_CLOSING = "Answer in the conversation: aw mail reply <message_id>."
TRUSTED_STATUSES = {"verified", "verified_custodial"}
STATE_HOME = "/state/home"
# CLAUDE_CONFIG_DIR of the team-claude launch configuration.
CLAUDE_PROJECTS = "/state/home/.claude/projects"
CLAUDE_LOGIN = "/etc/agent-login/claude-token"
REFUSED_STATES = {"stopped", "not-launched", "shell", "generic shell", "generic-shell", "blocked"}
CALL_TIMEOUT = 60
REPLY_BODY_LIMIT = 4000
SENDER_TRUST = "cited separately: channel-core stable_identity_forgery_repro, trust and terminal-adapter tests"
PANE_LINES = 400

Container = Callable[..., subprocess.CompletedProcess]


class WakeCheckFailed(Exception):
    """A check that did not pass; stage is preflight, send, sent, presentation,
    trust or reply. partial holds what was observed before it, never more."""

    def __init__(self, stage: str, detail: str, partial: dict | None = None) -> None:
        super().__init__(f"{stage}: {detail}")
        self.stage = stage
        self.detail = detail
        self.partial = partial


@dataclass(frozen=True)
class SentMail:
    message_id: str
    sender: str
    subject: str
    body: str
    nonce: str


@dataclass(frozen=True)
class BoundMail:
    """A mail someone else sent, as its sender's aw shows it, bound to the
    sender and the receiver by DID."""
    message_id: str
    conversation_id: str
    sender: str
    sender_did: str
    receiver: str
    receiver_did: str
    subject: str
    body: str
    created_at: str


@dataclass(frozen=True)
class MailEvent:
    meta: dict[str, str]
    warning: str | None
    message: str


def _parse_block(block: str) -> MailEvent | None:
    """One event's text after its header, as channel-core's
    formatAwakeningForAgent lays it out: an optional WARNING line, "Metadata:"
    with "- key: value" lines, then "Message:" and the body up to the closing
    line."""
    lines = block.split("\n")
    warning = None
    meta: dict[str, str] = {}
    index = 0
    while index < len(lines) and lines[index].strip() != "Metadata:":
        if lines[index].startswith("WARNING:"):
            warning = lines[index].strip()
        index += 1
    if index == len(lines):
        return None
    index += 1
    while index < len(lines) and lines[index].startswith("- "):
        key, separator, value = lines[index][2:].partition(": ")
        if separator:
            meta[key] = value
        index += 1
    rest = "\n".join(lines[index:])
    marker = "Message:\n"
    start = rest.find(marker)
    if start == -1:
        return MailEvent(meta, warning, "")
    message = rest[start + len(marker):]
    end = message.rfind("\n\n" + MAIL_CLOSING)
    if end != -1:
        message = message[:end]
    return MailEvent(meta, warning, message.rstrip("\n"))


def parse_mail_events(text: str) -> list[MailEvent]:
    """Every full mail event in text, in order."""
    events = []
    pieces = text.split(EVENT_HEADER)
    for piece in pieces[1:]:
        event = _parse_block(piece)
        if event is not None:
            events.append(event)
    return events


def require_presented(events: list[MailEvent], sent: SentMail | BoundMail) -> dict:
    """The event for the sent mail, presented whole and verified."""
    matching = [event for event in events if event.meta.get("message_id") == sent.message_id]
    if not matching:
        raise WakeCheckFailed("presentation", f"no full mail event carries message_id {sent.message_id}")
    event = matching[0]
    expected = {"type": "mail", "from": sent.sender, "subject": sent.subject}
    for key, value in expected.items():
        if event.meta.get(key) != value:
            raise WakeCheckFailed("presentation", f"{key} is {event.meta.get(key)!r}, the sent mail's is {value!r}")
    if event.message != sent.body:
        raise WakeCheckFailed("presentation", "the presented body is not the sent body")
    status, verified = event.meta.get("trust_status"), event.meta.get("verified")
    if status not in TRUSTED_STATUSES or verified != "true" or event.warning:
        raise WakeCheckFailed(
            "presentation", f"presented without verification: trust_status={status}, verified={verified}"
            + (", with a warning" if event.warning else ""))
    return {"message_id": sent.message_id, "from": event.meta["from"], "subject": event.meta["subject"],
            "trust_status": status, "verified": verified, "body_matched": True}


def require_not_promoted(events: list[MailEvent]) -> None:
    """No event claims verified: true without a trusted status, and none with a
    warning claims anything but verified: false."""
    for event in events:
        status, verified = event.meta.get("trust_status"), event.meta.get("verified")
        if verified == "true" and (status not in TRUSTED_STATUSES or event.warning):
            raise WakeCheckFailed("trust", f"message {event.meta.get('message_id')} is presented as verified "
                                           f"with trust_status={status}" + (" and a warning" if event.warning else ""))
        if event.warning and verified != "false":
            raise WakeCheckFailed("trust", f"message {event.meta.get('message_id')} carries a warning but verified={verified}")


def _instant(text: str) -> datetime:
    return datetime.fromisoformat(str(text).replace("Z", "+00:00"))


def bind_sent_mail(shown: dict, *, message_id: str, sender_did: str, receiver_dids: set[str], receiver_alias: str,
                   session_created_ms: int) -> BoundMail:
    """The mail aw mail show --message-id printed for the sender, bound to the
    sender's DID, one of the receiver's DIDs and alias, and the session: a mail
    from before the session started is not this session's wake."""
    messages = shown.get("messages") or []
    if len(messages) != 1 or messages[0].get("message_id") != message_id:
        raise WakeCheckFailed("sent", f"aw mail show did not return exactly message {message_id}")
    message = messages[0]
    if message.get("from_did") != sender_did:
        raise WakeCheckFailed("sent", f"the mail is from {message.get('from_did')}, not the sender {sender_did}")
    if message.get("to_did") not in receiver_dids or message.get("to_alias") != receiver_alias:
        raise WakeCheckFailed("sent", f"the mail is to {message.get('to_alias')} ({message.get('to_did')}), "
                                      f"not {receiver_alias} ({', '.join(sorted(receiver_dids))})")
    if not message.get("conversation_id"):
        raise WakeCheckFailed("sent", "the mail has no conversation_id")
    if _instant(message["created_at"]).timestamp() * 1000 < session_created_ms:
        raise WakeCheckFailed("sent", f"the mail was created at {message['created_at']}, before the session")
    # channel-core's senderDisplayAddress names the sender in the event: the
    # qualified address when there is one, else the alias.
    sender = (message.get("from_address") or "").strip() or (message.get("from_alias") or "").strip()
    return BoundMail(message_id=message_id, conversation_id=message["conversation_id"],
                     sender=sender, sender_did=sender_did, receiver=receiver_alias,
                     receiver_did=message["to_did"], subject=message.get("subject", ""),
                     body=message.get("body", ""), created_at=message["created_at"])


def find_reply(conversation: dict, sent: BoundMail) -> dict | None:
    """The receiver's first reply to the sender in the sent mail's conversation,
    created after it, as aw mail show --conversation-id printed it; None when
    there is none yet. Messages from anyone else, to anyone else, in another
    conversation or from before the sent mail are never the reply."""
    sent_at = _instant(sent.created_at)
    replies = sorted(
        (message for message in conversation.get("messages") or []
         if message.get("conversation_id") == sent.conversation_id
         and message.get("from_did") == sent.receiver_did and message.get("to_did") == sent.sender_did
         and message.get("message_id") != sent.message_id and _instant(message["created_at"]) > sent_at),
        key=lambda message: _instant(message["created_at"]))
    if not replies:
        return None
    reply = replies[0]
    status = reply.get("verification_status")
    if status not in TRUSTED_STATUSES:
        raise WakeCheckFailed("reply", f"the reply {reply.get('message_id')} is {status}, not verified")
    body = reply.get("body") or ""
    return {"message_id": reply["message_id"], "conversation_id": reply["conversation_id"],
            "from": reply.get("from_alias"), "from_did": reply["from_did"], "verification_status": status,
            "created_at": reply["created_at"], "body": body[:REPLY_BODY_LIMIT],
            "body_truncated": len(body) > REPLY_BODY_LIMIT, "later_replies": len(replies) - 1}


# Runs in the container with its node. OATS's own rule for a home's
# conversation (packages/record lib/last-conversation.mjs): among Claude's
# parent-session transcripts (a session UUID's file, never one under
# subagents/, whose transcripts inherit the home's cwd), the newest modified
# since the home was created whose first recorded cwd is the home itself. A
# session in <home>/work is a helper's. Prints the transcript's path
# and the user-turn texts that contain the needle; an empty needle asks only
# whether the transcript exists.
TRANSCRIPT_READER = r"""
const fs = require("node:fs"), path = require("node:path");
// node -e consumes the "--" that ends its own options; the arguments follow argv[0].
const args = process.argv.slice(1);
const [projects, home, createdMs, needle] = args;
const real = p => { try { return fs.realpathSync(p); } catch { return p; } };
const want = real(home), created = Number(createdMs);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function* files(dir) {
  let entries = [];
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) yield* files(full);
    else if (entry.name.endsWith(".jsonl")) yield full;
  }
}
function records(file) {
  const out = [];
  for (const line of fs.readFileSync(file, "utf8").split("\n")) {
    if (!line.trim()) continue;
    try { out.push(JSON.parse(line)); } catch {}
  }
  return out;
}
let best = null;
for (const file of files(projects)) {
  if (path.basename(path.dirname(file)) === "subagents" || !UUID.test(path.basename(file, ".jsonl"))) continue;
  const mtime = fs.statSync(file).mtimeMs;
  if (mtime < created || (best && (mtime < best.mtime || (mtime === best.mtime && file > best.file)))) continue;
  const first = records(file).find(r => typeof r.cwd === "string");
  if (first && real(first.cwd) === want) best = { file, mtime };
}
const texts = [];
if (best && needle) {
  for (const record of records(best.file)) {
    if (record.type !== "user" || !record.message) continue;
    const content = record.message.content;
    const parts = typeof content === "string" ? [content]
      : Array.isArray(content) ? content.filter(p => p && p.type === "text").map(p => p.text) : [];
    for (const text of parts) if (typeof text === "string" && text.includes(needle)) texts.push(text);
  }
}
console.log(JSON.stringify({ transcript: best ? best.file : null, texts }));
"""


def transcript_command(projects: str, home: str, created_ms: int, needle: str) -> str:
    return (f"node -e {shlex.quote(TRANSCRIPT_READER)} -- {shlex.quote(projects)} {shlex.quote(home)} "
            f"{int(created_ms)} {shlex.quote(needle)}")


def _call(container: Container, stage: str, command: str, what: str, *, ok: bool = True) -> subprocess.CompletedProcess:
    done = container(command, timeout=CALL_TIMEOUT)
    if ok and done.returncode != 0:
        detail = (done.stderr or done.stdout or "").strip().splitlines()[-1:] or [""]
        raise WakeCheckFailed(stage, f"{what} failed (exit {done.returncode}): {detail[0][:300]}")
    return done


def _json(stage: str, text: str, what: str):
    try:
        return json.loads(text)
    except ValueError:
        raise WakeCheckFailed(stage, f"{what} did not print JSON") from None


def _transcript(container: Container, home: str, created_ms: int, needle: str) -> dict:
    done = _call(container, "presentation" if needle else "preflight",
                 transcript_command(CLAUDE_PROJECTS, home, created_ms, needle), "reading the Claude transcript")
    return _json("presentation", done.stdout, "the transcript reader")


def _preflight(container: Container, home: str, signed_in_wait: float, poll: float) -> dict:
    found_home = _call(container, "preflight", 'printf "%s" "$HOME"', "reading HOME").stdout.strip()
    if found_home != STATE_HOME:
        raise WakeCheckFailed("preflight", f"HOME is {found_home!r}, not {STATE_HOME}")
    aw_version = _call(container, "preflight", "aw version", "aw version").stdout.strip()

    status = _json("preflight", _call(container, "preflight", "aw wake status --json", "aw wake status").stdout,
                   "aw wake status")
    if not status.get("daemon_running"):
        raise WakeCheckFailed("preflight", "the wake daemon is not running")
    instance = next((i for i in status.get("instances") or [] if i.get("home") == home), None)
    if instance is None:
        raise WakeCheckFailed("preflight", f"the wake daemon holds no registration for {home}")
    if instance.get("delivery") != "session" or instance.get("phase") != "active" or instance.get("paused"):
        raise WakeCheckFailed("preflight", f"{home} is delivery={instance.get('delivery')}, "
                                           f"phase={instance.get('phase')}, paused={instance.get('paused')}")
    streams = [r for r in instance.get("receive_identities") or []
               if r.get("stream_admitted") and r.get("stream_phase") == "streaming"]
    if not streams:
        raise WakeCheckFailed("preflight", f"no receive identity of {home} is streaming: "
                                           f"{[(r.get('identity_home'), r.get('stream_phase'), r.get('stream_error')) for r in instance.get('receive_identities') or []]}")

    inspected = _json("preflight", _call(container, "preflight", f"oats session inspect --home {shlex.quote(home)} --json",
                                         "oats session inspect", ok=False).stdout, "oats session inspect")
    result = inspected.get("result") or {}
    if not inspected.get("ok") or not result.get("present"):
        raise WakeCheckFailed("preflight", f"OATS reports no present session for {home}: {inspected.get('error') or result}")
    if str(result.get("state", "")).lower() in REFUSED_STATES:
        raise WakeCheckFailed("preflight", f"the session is {result.get('state')}; the broker would not type into it")

    record = _json("preflight", _call(container, "preflight", f"cat {shlex.quote(home + '/instance.json')}",
                                      "reading instance.json").stdout, "instance.json")
    created_ms = int(datetime.fromisoformat(str(record["createdAt"]).replace("Z", "+00:00")).timestamp() * 1000)
    if _call(container, "preflight", f"test -r {CLAUDE_LOGIN}", "the login check", ok=False).returncode != 0:
        raise WakeCheckFailed("preflight", f"{CLAUDE_LOGIN} is not readable: no Claude login")

    # Every OATS launch submits its task, so a signed-in session writes a
    # transcript within seconds; one at the sign-in screen writes none.
    deadline = time.monotonic() + signed_in_wait
    while True:
        transcript = _transcript(container, home, created_ms, "")["transcript"]
        if transcript or time.monotonic() >= deadline:
            break
        time.sleep(poll)
    if not transcript:
        raise WakeCheckFailed("preflight", f"not signed in or not started: no Claude transcript for {home}")
    return {"aw_version": aw_version, "delivery": instance["delivery"], "phase": instance["phase"],
            "streaming_identities": [r.get("identity_home") for r in streams], "session_state": result.get("state"),
            "backend": result.get("backend"), "created_ms": created_ms, "tmux": record.get("tmux") or {},
            "transcript": transcript}


def _send(container: Container, sender_home: str, receiver_alias: str) -> SentMail:
    whoami = _json("send", _call(container, "send", f"aw --identity-home {shlex.quote(sender_home)} --json whoami",
                                 "aw whoami for the sender").stdout, "aw whoami")
    sender = str(whoami.get("alias") or "").strip()
    if not sender:
        raise WakeCheckFailed("send", "the sender has no alias")
    nonce = secrets.token_hex(4)
    subject = f"wake check {nonce}"
    body = f"Automated delivery check {nonce}. No action is needed; do not reply or run any tool."
    command = (
        f'f=$(mktemp) && printf "%s" {shlex.quote(body)} > "$f" && '
        f"aw --identity-home {shlex.quote(sender_home)} --json mail send --to {shlex.quote(receiver_alias)} "
        f'--subject {shlex.quote(subject)} --body-file "$f"; rc=$?; rm -f "$f"; exit $rc'
    )
    sent = _json("send", _call(container, "send", command, "aw mail send").stdout, "aw mail send")
    message_id = str(sent.get("message_id") or "").strip()
    if not message_id:
        raise WakeCheckFailed("send", "aw mail send returned no message_id")
    return SentMail(message_id=message_id, sender=sender, subject=subject, body=body, nonce=nonce)


def _pane(container: Container, tmux: dict) -> str | None:
    """B's pane as OATS's kernel captures it, or None when instance.json names none."""
    socket = tmux.get("socket")
    target = tmux.get("paneId") or tmux.get("pane") or (
        f"{tmux['session']}:{tmux['window']}" if tmux.get("session") and tmux.get("window") else None)
    if not socket or not target:
        return None
    done = container(f"tmux -S {shlex.quote(socket)} capture-pane -p -J -t {shlex.quote(target)} -S -{PANE_LINES}",
                     timeout=CALL_TIMEOUT)
    return done.stdout if done.returncode == 0 else None


def check_full_event_wake(
    container: Container,
    *,
    sender_home: str,
    receiver_instance_home: str,
    receiver_alias: str,
    timeout: float = 180,
    signed_in_wait: float = 60,
    poll: float = 5,
) -> dict:
    """Run the check and return its receipt; raise WakeCheckFailed otherwise.

    container(command, timeout=...) runs one shell command in the agent
    container as the agent user and returns the CompletedProcess. Each call
    here is short; waiting is done by polling."""
    preflight = _preflight(container, receiver_instance_home, signed_in_wait, poll)
    sent = _send(container, sender_home, receiver_alias)
    presented, evidence = _await_presented(container, receiver_instance_home, preflight, sent, timeout, poll)
    return {
        "sent": asdict(sent),
        "preflight": _screened(preflight),
        "presented": presented,
        "evidence": evidence,
        "sender_trust": SENDER_TRUST,
    }


def preflight_only(container: Container, *, receiver_instance_home: str, signed_in_wait: float = 60,
                   poll: float = 5) -> dict:
    """The preflight alone, sending nothing: run before the caller spends its one mail."""
    return _screened(_preflight(container, receiver_instance_home, signed_in_wait, poll))


def correlate_mail_wake(
    container: Container,
    *,
    message_id: str,
    sender_home: str,
    receiver_instance_home: str,
    receiver_alias: str,
    timeout: float = 180,
    reply_timeout: float = 300,
    signed_in_wait: float = 60,
    poll: float = 5,
) -> dict:
    """Correlate a mail the caller already sent with its wake in the receiver's
    session and the receiver's reply; return the receipt or raise
    WakeCheckFailed carrying what was observed before the failure.

    Sends nothing and acknowledges nothing: the sender's mail is read with aw
    mail show, which leaves read state alone."""
    preflight = _preflight(container, receiver_instance_home, signed_in_wait, poll)
    observed: dict = {"preflight": _screened(preflight)}
    try:
        sender_did = _did(container, sender_home, "the sender")
        receiver_dids = {_did(container, home, "the receiver") for home in preflight["streaming_identities"]}
        shown = _json("sent", _call(container, "sent", _sender_aw(sender_home, "mail show --message-id "
                                                                                  + shlex.quote(message_id)),
                                    "aw mail show for the sent mail").stdout, "aw mail show")
        sent = bind_sent_mail(shown, message_id=message_id, sender_did=sender_did, receiver_dids=receiver_dids,
                              receiver_alias=receiver_alias, session_created_ms=preflight["created_ms"])
    except WakeCheckFailed as failed:
        raise WakeCheckFailed(failed.stage, failed.detail, observed) from None
    observed = {"sent": asdict(sent), **observed}
    try:
        presented, evidence = _await_presented(container, receiver_instance_home, preflight, sent, timeout, poll)
    except WakeCheckFailed as failed:
        raise WakeCheckFailed(failed.stage, failed.detail, observed) from None
    observed.update(presented=presented, evidence=evidence)

    deadline = time.monotonic() + reply_timeout
    while True:
        try:
            conversation = _json("reply", _call(
                container, "reply", _sender_aw(sender_home, "mail show --conversation-id "
                                               + shlex.quote(sent.conversation_id) + " --limit 500"),
                "aw mail show for the conversation").stdout, "aw mail show")
            reply = find_reply(conversation, sent)
        except WakeCheckFailed as failed:
            raise WakeCheckFailed(failed.stage, failed.detail, observed) from None
        if reply is not None:
            break
        if time.monotonic() >= deadline:
            raise WakeCheckFailed("reply", f"no reply from {receiver_alias} in conversation "
                                           f"{sent.conversation_id} within {reply_timeout:g}s", observed)
        time.sleep(poll)
    return {**observed, "reply": reply, "sender_trust": SENDER_TRUST}


def _sender_aw(sender_home: str, arguments: str) -> str:
    return f"aw --identity-home {shlex.quote(sender_home)} --json {arguments}"


def _did(container: Container, identity_home: str, who: str) -> str:
    whoami = _json("sent", _call(container, "sent", _sender_aw(identity_home, "whoami"), f"aw whoami for {who}").stdout,
                   "aw whoami")
    did = str(whoami.get("did") or "").strip()
    if not did:
        raise WakeCheckFailed("sent", f"aw whoami for {who} reports no DID")
    return did


def _screened(preflight: dict) -> dict:
    return {key: value for key, value in preflight.items() if key != "tmux"}


def _await_presented(container: Container, home: str, preflight: dict, sent: SentMail | BoundMail, timeout: float,
                     poll: float) -> tuple[dict, dict]:
    """Poll the receiver's transcript for the sent mail's full event until the
    deadline; return the presentation and its evidence."""
    deadline = time.monotonic() + timeout
    while True:
        found = _transcript(container, home, preflight["created_ms"], sent.message_id)
        events = [event for text in found["texts"] for event in parse_mail_events(text)]
        if any(event.meta.get("message_id") == sent.message_id for event in events) or time.monotonic() >= deadline:
            break
        time.sleep(poll)
    pane = _pane(container, preflight["tmux"])
    pane_events = parse_mail_events(pane or "")
    require_not_promoted(events + pane_events)
    try:
        presented = require_presented(events, sent)
    except WakeCheckFailed as failed:
        in_pane = any(event.meta.get("message_id") == sent.message_id for event in pane_events)
        raise WakeCheckFailed(failed.stage, failed.detail + (
            "; the pane shows a block for it" if in_pane else "; the pane shows none either")) from None
    return presented, {
        "surface": "Claude transcript user turn (Claude's own storage, not an OATS contract)",
        "transcript": found["transcript"],
        "block": next(text for text in found["texts"] if sent.message_id in text),
        "pane": None if pane is None else any(e.meta.get("message_id") == sent.message_id for e in pane_events),
    }


def failure_output(failed: WakeCheckFailed) -> dict:
    output = {"failed": failed.stage, "detail": failed.detail}
    if failed.partial is not None:
        output["partial"] = failed.partial
    return output


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--ssh-config", required=True, help="the operator's ssh_config for the agent container")
    parser.add_argument("--host", default="team-agent")
    parser.add_argument("--receiver-home", required=True, help="seat B's absolute OATS instance home")
    parser.add_argument("--receiver-alias", help="seat B's alias; required unless --preflight-only")
    parser.add_argument("--sender-home", help="the sender seat's identity home, /state/seats/<A>/.aw; "
                                              "required unless --preflight-only")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--preflight-only", action="store_true", help="check the session and send nothing")
    mode.add_argument("--message-id", help="correlate this already-sent mail and its reply instead of sending one")
    parser.add_argument("--timeout", type=float, default=180, help="seconds to wait for the wake")
    parser.add_argument("--reply-timeout", type=float, default=300,
                        help="with --message-id, seconds to wait for the reply after the wake")
    args = parser.parse_args(argv)
    if not args.preflight_only and not (args.sender_home and args.receiver_alias):
        parser.error("--sender-home and --receiver-alias are required unless --preflight-only")

    def container(command: str, timeout: int = 120) -> subprocess.CompletedProcess:
        return subprocess.run(["ssh", "-F", args.ssh_config, args.host, command], capture_output=True, text=True,
                              timeout=timeout, check=False)

    try:
        if args.preflight_only:
            receipt = preflight_only(container, receiver_instance_home=args.receiver_home)
        elif args.message_id:
            receipt = correlate_mail_wake(container, message_id=args.message_id, sender_home=args.sender_home,
                                          receiver_instance_home=args.receiver_home,
                                          receiver_alias=args.receiver_alias, timeout=args.timeout,
                                          reply_timeout=args.reply_timeout)
        else:
            receipt = check_full_event_wake(container, sender_home=args.sender_home,
                                            receiver_instance_home=args.receiver_home,
                                            receiver_alias=args.receiver_alias, timeout=args.timeout)
    except WakeCheckFailed as failed:
        print(json.dumps(failure_output(failed), indent=2 if failed.partial is not None else None))
        return 1
    print(json.dumps(receipt, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
