import type { APIClient } from "./client.js";

export type AgentEventType =
  | "connected"
  | "mail_message"
  | "chat_message"
  | "control_pause"
  | "control_resume"
  | "control_interrupt"
  | "work_available"
  | "claim_update"
  | "claim_removed"
  | "app_event"
  | "error";

export interface EventStreamState {
  state: "connected" | "disconnected" | "reconnected";
  cause?: string;
  retryInMs?: number;
}

export interface AgentEvent {
  type: AgentEventType;
  agent_id?: string;
  team_id?: string;
  message_id?: string;
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
export const EVENT_STREAM_INACTIVITY_MS = 2 * EVENT_STREAM_SERVER_HEARTBEAT_MS + 15_000;
export const EVENT_STREAM_DEADLINE_MS = 5 * 60 * 1000;
const EVENT_STREAM_PLANNED_CLOSE_MS = 4 * 60 * 1000;

/**
 * Consume the agent event stream (GET /v1/events/stream).
 * Yields parsed AgentEvent objects. Reconnects on stream end.
 */
export async function* streamAgentEvents(
  client: APIClient,
  signal: AbortSignal,
  onState: (state: EventStreamState) => void = () => {},
): AsyncGenerator<AgentEvent> {
  let connectedOnce = false;
  let disconnected = false;
  let retryInMs = 1000;
  const maxRetryInMs = 5000;
  while (!signal.aborted) {
    const openedAt = Date.now();
    const deadline = new Date(openedAt + EVENT_STREAM_DEADLINE_MS).toISOString();
    const attemptAbort = new AbortController();
    let deadlineReached = false;
    const abortAttempt = () => attemptAbort.abort(signal.reason);
    signal.addEventListener("abort", abortAttempt, { once: true });
    const deadlineTimer = setTimeout(() => {
      deadlineReached = true;
      attemptAbort.abort(new Error("event stream local deadline reached"));
    }, EVENT_STREAM_DEADLINE_MS);
    const finishAttempt = () => {
      clearTimeout(deadlineTimer);
      signal.removeEventListener("abort", abortAttempt);
    };

    let resp: Response;
    try {
      resp = await client.openSSE(
        `/v1/events/stream?deadline=${encodeURIComponent(deadline)}`,
        attemptAbort.signal,
      );
    } catch (err) {
      finishAttempt();
      if (signal.aborted) return;
      // The server is required to close at this same deadline. Treat our local
      // enforcement like that planned close: reconnect immediately and do not
      // claim an outage merely because a half-open transport hid server EOF.
      if (deadlineReached) continue;
      const fetchRetryInMs = maxRetryInMs;
      if (!disconnected) {
        disconnected = true;
        onState({ state: "disconnected", cause: streamErrorCause(err), retryInMs: fetchRetryInMs });
      }
      retryInMs = fetchRetryInMs;
      await sleep(retryInMs, signal);
      continue;
    }

    try {
      let streamConfirmed = false;
      for await (const event of parseSSEResponse(resp, attemptAbort.signal)) {
        if (!streamConfirmed) {
          streamConfirmed = true;
          retryInMs = 1000;
          if (disconnected) {
            disconnected = false;
            connectedOnce = true;
            onState({ state: "reconnected" });
          } else if (!connectedOnce) {
            connectedOnce = true;
            onState({ state: "connected" });
          }
        }
        yield event;
      }
      if (!signal.aborted && !deadlineReached
        && Date.now() - openedAt < EVENT_STREAM_PLANNED_CLOSE_MS) {
        if (!disconnected) {
          disconnected = true;
          onState({ state: "disconnected", cause: "connection closed", retryInMs });
        }
        await sleep(retryInMs, signal);
        retryInMs = Math.min(maxRetryInMs, retryInMs * 2);
      }
    } catch (err) {
      if (signal.aborted) return;
      if (deadlineReached) continue;
      if (!disconnected) {
        disconnected = true;
        onState({ state: "disconnected", cause: streamErrorCause(err), retryInMs });
      }
      // AbortError is only expected when our parent signal is aborted (handled
      // above). A read failure, including heartbeat inactivity, reconnects via
      // the existing bounded backoff.
      await sleep(retryInMs, signal);
      retryInMs = Math.min(maxRetryInMs, retryInMs * 2);
    } finally {
      finishAttempt();
      resp.body?.cancel().catch(() => {});
    }
  }
}

async function* parseSSEResponse(
  resp: Response,
  signal: AbortSignal,
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

        if (line.startsWith(":")) continue; // comment

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
  "actionable_mail", "actionable_chat",
]);

export function parseAgentEvent(eventName: string, data: string): AgentEvent | null {
  eventName = eventName.trim();
  if (!eventName) return null;

  if (!KNOWN_TYPES.has(eventName)) return null;

  if (eventName === "actionable_mail") eventName = "mail_message";
  if (eventName === "actionable_chat") eventName = "chat_message";

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
    return "aweb: event stream reconnected; check aw mail inbox and aw chat pending for anything missed";
  }
  const seconds = Math.max(1, Math.round((state.retryInMs || 0) / 1000));
  return `aweb: event stream disconnected (${state.cause || "connection failed"}) — retrying in ${seconds}s`;
}

export function streamErrorCause(err: unknown): string {
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
    const timer = setTimeout(resolve, ms);
    signal.addEventListener("abort", () => { clearTimeout(timer); resolve(); }, { once: true });
  });
}
