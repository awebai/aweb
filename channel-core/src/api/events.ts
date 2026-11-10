import { APIError, type APIClient } from "./client.js";
import { EventStreamClosedError, STREAM_SILENCE_LIMIT_MS, StreamPolicy, type StreamEnd } from "./stream_policy.js";

export type AgentEventType =
  | "connected"
  | "mail_message"
  | "chat_message"
  | "room_post"
  | "control_pause"
  | "control_resume"
  | "control_interrupt"
  | "work_available"
  | "claim_update"
  | "claim_removed"
  | "app_event"
  | "error";

/**
 * A change of the stream's state (docs/event-stream-client-policy.md, section
 * 8). The stream is streaming after "connected" and "reconnected", retrying
 * after "disconnected" and refused after "refused". A planned close does not
 * leave streaming and a retry that is refused again reports nothing.
 */
export interface EventStreamState {
  state: "connected" | "disconnected" | "reconnected" | "refused";
  /** Why the stream is disconnected, or the HTTP status or terminal event name that refused it. */
  cause?: string;
  retryInMs?: number;
  /** When the next attempt is made, in epoch milliseconds. */
  nextAttemptAt?: number;
  /** On "reconnected": the refusal the confirmed stream ended. */
  endedRefusal?: string;
}

export interface EventStreamOptions {
  /**
   * Reads the stream's credentials again from where they are kept. It is
   * called before each retry of a refused stream and at no other time, with a
   * signal that aborts when the stream stops. When it rejects, the attempt
   * fails without a request.
   */
  reloadCredentials?: (signal: AbortSignal) => Promise<void>;
  /** A uniform draw in [0, 1) for the policy's jitter and planned close. */
  random?: () => number;
}

export interface EventStreamObserver {
  onRead: (openedAt: number, readAt: number) => void;
  onClose: () => Promise<void> | void;
}

export interface AgentEvent {
  type: AgentEventType;
  agent_id?: string;
  team_id?: string;
  message_id?: string;
  room_id?: string;
  conversation_id?: string;
  from_alias?: string;
  session_id?: string;
  subject?: string;
  signal_id?: string;
  task_id?: string;
  title?: string;
  status?: string;
  text?: string;
  sender_waiting?: boolean;
  event_id?: string;
  app_id?: string;
  app_event_type?: string;
  resource_ref?: string;
  delivery_intent?: "wake" | "steer" | "ambient";
  producer_delivery_intent?: "wake" | "steer" | "ambient";
  payload?: Record<string, unknown>;
}

export const EVENT_STREAM_SERVER_HEARTBEAT_MS = 30_000;
export const EVENT_STREAM_INACTIVITY_MS = STREAM_SILENCE_LIMIT_MS;

/**
 * Consume the agent event stream (GET /v1/events/stream).
 * Yields parsed AgentEvent objects. It reconnects for as long as signal is not
 * aborted: no answer from the server ends the stream. What the end of a
 * connection means and how long to wait before the next one are decided by
 * the event stream client policy (stream_policy.ts); this loop owns the
 * connection, its timers and the reporting of state.
 */
export async function* streamAgentEvents(
  client: APIClient,
  signal: AbortSignal,
  onState: (state: EventStreamState) => void = () => {},
  onEvent: (event: AgentEvent) => void = () => {},
  observer?: EventStreamObserver,
  options: EventStreamOptions = {},
): AsyncGenerator<AgentEvent> {
  const policy = new StreamPolicy({ random: options.random });
  let connectedOnce = false;
  let disconnected = false;
  while (!signal.aborted) {
    // Opening the response is not proof that the stream is live: a proxy can
    // answer 200 and close the body. The stream is confirmed by its first
    // heartbeat comment or event.
    const connection = policy.connect((endedRefusal) => {
      if (endedRefusal) onState({ state: "reconnected", endedRefusal });
      else if (disconnected) onState({ state: "reconnected" });
      else if (!connectedOnce) onState({ state: "connected" });
      disconnected = false;
      connectedOnce = true;
    });
    const openedAt = Date.now();
    // The server is asked to end the stream at the connection's planned close.
    const deadline = new Date(connection.plannedCloseAt).toISOString();
    const attemptAbort = new AbortController();
    let deadlineReached = false;
    const abortAttempt = () => attemptAbort.abort(signal.reason);
    signal.addEventListener("abort", abortAttempt, { once: true });
    // The server is required to close at this same deadline. Local enforcement
    // is that planned close: a half-open transport can hide the server's EOF.
    const deadlineTimer = setTimeout(() => {
      deadlineReached = true;
      attemptAbort.abort(new Error("event stream local deadline reached"));
    }, connection.plannedCloseAt - openedAt);
    const finishAttempt = () => {
      clearTimeout(deadlineTimer);
      signal.removeEventListener("abort", abortAttempt);
    };

    let resp: Response | undefined;
    let failed = false;
    let failure: unknown;
    try {
      if (connection.reloadsCredentials && options.reloadCredentials) {
        await untilAborted(options.reloadCredentials(attemptAbort.signal), attemptAbort.signal);
      }
      resp = await client.openSSE(
        `/v1/events/stream?deadline=${encodeURIComponent(deadline)}`,
        attemptAbort.signal,
      );
      connection.opened();
      try {
        for await (const event of parseSSEResponse(resp, attemptAbort.signal, () => {
          try { observer?.onRead(openedAt, Date.now()); } catch { /* Local evidence cannot interrupt delivery. */ }
        }, () => connection.comment())) {
          connection.event(event.type);
          try {
            onEvent(event);
          } catch {
            // Diagnostics must never change event consumption.
          }
          yield event;
        }
      } finally {
        // Remove proof before retry backoff, including errors and planned closes.
        try { await observer?.onClose(); } catch { /* Keep delivery independent of diagnostics. */ }
      }
    } catch (err) {
      failed = true;
      failure = err ?? new Error("event stream failed");
    } finally {
      finishAttempt();
      resp?.body?.cancel().catch(() => {});
    }
    if (signal.aborted) return;

    let end: StreamEnd;
    if (deadlineReached) end = connection.reachedPlannedClose();
    else end = connection.ended(failed ? failure : undefined);
    // A planned close is not an outage: reconnect at once and report nothing.
    if (end.kind === "planned_close") continue;
    if (end.kind === "refused") {
      // Reported once on entering the quarantine; a retry that is refused
      // again moves the next attempt and says nothing.
      if (end.enteredRefused) {
        onState({ state: "refused", cause: end.cause, retryInMs: end.waitMs, nextAttemptAt: end.nextAttemptAt });
      }
    } else if (!disconnected) {
      disconnected = true;
      onState({
        state: "disconnected",
        cause: failed ? streamErrorCause(end.error) : "connection closed",
        retryInMs: end.waitMs,
        nextAttemptAt: end.nextAttemptAt,
      });
    }
    await sleep(end.waitMs, signal);
  }
}

/** Settles as work does, or rejects as soon as signal aborts. */
function untilAborted<T>(work: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise((resolve, reject) => {
    const onAbort = () => reject(signal.reason);
    if (signal.aborted) {
      // The work is abandoned; its own failure has nowhere to be reported.
      work.catch(() => {});
      onAbort();
      return;
    }
    signal.addEventListener("abort", onAbort, { once: true });
    work.then(resolve, reject).finally(() => signal.removeEventListener("abort", onAbort));
  });
}

async function* parseSSEResponse(
  resp: Response,
  signal: AbortSignal,
  onRead: () => void = () => {},
  onComment: () => void = () => {},
): AsyncGenerator<AgentEvent> {
  const reader = resp.body?.getReader();
  if (!reader) return;

  const decoder = new TextDecoder();
  let buffer = "";
  let currentEvent = "";
  let dataLines: string[] = [];

  try {
    while (!signal.aborted) {
      // The server emits an idle comment every 30s. Allow two missed beats plus
      // 15s of scheduling/proxy tolerance, but never wait for the platform's
      // unbounded transport timeout. Every byte chunk resets this watchdog, so
      // comments count as liveness even though they are not agent events.
      const { done, value } = await readWithInactivity(reader, signal);
      if (done) break;
      if (value?.byteLength) onRead();

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n");
      buffer = lines.pop() || "";

      for (const rawLine of lines) {
        const line = rawLine.replace(/\r$/, "");

        if (line === "") {
          // Empty line = event boundary
          if (currentEvent || dataLines.length > 0) {
            const event = parseAgentEvent(currentEvent, dataLines.join("\n"));
            if (event) yield event;
            currentEvent = "";
            dataLines = [];
          }
          continue;
        }

        if (line.startsWith(":")) {
          onComment();
          continue;
        }

        if (line.startsWith("event:")) {
          currentEvent = line.slice(6).trim();
        } else if (line.startsWith("data:")) {
          dataLines.push(line.slice(5).trim());
        }
      }
    }
  } finally {
    reader.releaseLock();
  }
}

function readWithInactivity(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  signal: AbortSignal,
): Promise<{ done: boolean; value?: Uint8Array }> {
  return new Promise((resolve, reject) => {
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const cleanup = () => {
      if (timer) clearTimeout(timer);
      signal.removeEventListener("abort", onAbort);
    };
    const settle = (action: () => void) => {
      if (settled) return;
      settled = true;
      cleanup();
      action();
    };
    const cancelReader = (reason: unknown) => {
      void reader.cancel(reason).catch(() => {});
    };
    const onAbort = () => {
      cancelReader(signal.reason);
      const error = signal.reason instanceof Error
        ? signal.reason
        : new DOMException("The operation was aborted", "AbortError");
      settle(() => reject(error));
    };

    signal.addEventListener("abort", onAbort, { once: true });
    if (signal.aborted) {
      onAbort();
      return;
    }
    timer = setTimeout(() => {
      const error = new Error("event stream heartbeat timed out");
      cancelReader(error);
      settle(() => reject(error));
    }, EVENT_STREAM_INACTIVITY_MS);
    reader.read().then(
      (result) => settle(() => resolve(result)),
      (error) => settle(() => reject(error)),
    );
  });
}

const KNOWN_TYPES: Set<string> = new Set([
  "connected", "mail_message", "chat_message",
  "control_pause", "control_resume", "control_interrupt",
  "work_available", "claim_update", "claim_removed", "app_event", "error",
  "actionable_mail", "actionable_chat", "actionable_room_post", "room_post",
]);

const GRANT_TERMINAL_TYPES = new Set([
  "grant_expired", "grant_revoked", "grant_subject_inactive", "grant_issuer_revoked",
  "verification_unavailable",
]);

export function parseAgentEvent(eventName: string, data: string): AgentEvent | null {
  eventName = eventName.trim();
  if (!eventName) return null;

  if (GRANT_TERMINAL_TYPES.has(eventName)) {
    let detail = eventName;
    try {
      const payload = JSON.parse(data);
      if (typeof payload?.detail === "string" && payload.detail.trim()) detail = payload.detail.trim();
    } catch {
      // The terminal event name remains authoritative if its payload is malformed.
    }
    if (eventName === "verification_unavailable") detail = "identity grant verification unavailable; retry";
    throw new EventStreamClosedError(eventName, detail);
  }

  if (!KNOWN_TYPES.has(eventName)) return null;

  if (eventName === "actionable_mail") eventName = "mail_message";
  if (eventName === "actionable_chat") eventName = "chat_message";
  if (eventName === "actionable_room_post") eventName = "room_post";

  try {
    const payload = JSON.parse(data);
    return { ...payload, type: eventName as AgentEventType };
  } catch {
    return { type: eventName as AgentEventType };
  }
}

export function formatEventStreamState(state: EventStreamState): string {
  if (state.state === "connected") return "aweb: event stream connected";
  if (state.state === "reconnected") {
    return state.endedRefusal
      ? `aweb: event stream accepted again (was refused: ${state.endedRefusal})`
      : "aweb: event stream reconnected";
  }
  if (state.state === "refused") {
    return `aweb: event stream refused: ${state.cause}, next try ${localClockTime(state.nextAttemptAt ?? Date.now())}`;
  }
  const seconds = Math.max(1, Math.round((state.retryInMs || 0) / 1000));
  return `aweb: event stream disconnected (${state.cause || "connection failed"}) — retrying in ${seconds}s`;
}

/** The local time of day, HH:MM, of a moment in epoch milliseconds. */
export function localClockTime(at: number): string {
  const time = new Date(at);
  return `${String(time.getHours()).padStart(2, "0")}:${String(time.getMinutes()).padStart(2, "0")}`;
}

export function streamErrorCause(err: unknown): string {
  if (err instanceof EventStreamClosedError) return err.message;
  if (err instanceof APIError) return `http ${err.statusCode}`;
  const error = err instanceof Error ? err : undefined;
  const nested = error?.cause as { code?: unknown; message?: unknown } | undefined;
  const code = typeof nested?.code === "string" ? nested.code.toUpperCase() : "";
  const detail = [error?.message, typeof nested?.message === "string" ? nested.message : ""]
    .filter(Boolean)
    .join(": ")
    .toLowerCase();
  if (code === "ENOTFOUND" || code === "EAI_AGAIN" || detail.includes("getaddrinfo")) return "DNS lookup failed";
  if (code === "ECONNREFUSED" || detail.includes("connection refused")) return "connection refused";
  if (code === "ETIMEDOUT" || detail.includes("timed out") || detail.includes("timeout")) return "connection timed out";
  if (code.startsWith("CERT_") || detail.includes("certificate") || detail.includes("tls")) return "TLS connection failed";
  if (detail.includes("network") || detail.includes("fetch failed")) return "network unavailable";
  if (detail.includes("terminated") || detail.includes("closed")) return "connection closed";
  return "connection failed";
}

function sleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal.aborted) { resolve(); return; }
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal.removeEventListener("abort", onAbort);
      resolve();
    };
    const onAbort = () => finish();
    const timer = setTimeout(finish, ms);
    signal.addEventListener("abort", onAbort, { once: true });
    // Abort cannot normally interleave between the check and listener install
    // in one JS turn, but re-check so nonstandard EventTarget implementations
    // cannot strand this sleep.
    if (signal.aborted) finish();
  });
}
