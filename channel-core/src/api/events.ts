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
  while (!signal.aborted) {
    const deadline = new Date(Date.now() + 5 * 60 * 1000).toISOString();
    let resp: Response;
    try {
      resp = await client.openSSE(
        `/v1/events/stream?deadline=${encodeURIComponent(deadline)}`,
        signal,
      );
    } catch (err) {
      if (signal.aborted) return;
      if (!disconnected) {
        disconnected = true;
        onState({ state: "disconnected", cause: streamErrorCause(err), retryInMs: 5000 });
      }
      await sleep(5000, signal);
      continue;
    }

    if (disconnected) {
      disconnected = false;
      connectedOnce = true;
      onState({ state: "reconnected" });
    } else if (!connectedOnce) {
      connectedOnce = true;
      onState({ state: "connected" });
    }

    try {
      const openedAt = Date.now();
      yield* parseSSEResponse(resp, signal);
      if (!signal.aborted && Date.now() - openedAt < 4 * 60 * 1000) {
        if (!disconnected) {
          disconnected = true;
          onState({ state: "disconnected", cause: "connection closed", retryInMs: 1000 });
        }
        await sleep(1000, signal);
      }
    } catch (err) {
      if (signal.aborted) return;
      if (!isExpectedStreamTermination(err)) {
        if (!disconnected) {
          disconnected = true;
          onState({ state: "disconnected", cause: streamErrorCause(err), retryInMs: 1000 });
        }
        await sleep(1000, signal);
      }
    } finally {
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
  const onAbort = () => {
    void reader.cancel().catch(() => {});
  };
  signal.addEventListener("abort", onAbort, { once: true });

  const decoder = new TextDecoder();
  let buffer = "";
  let currentEvent = "";
  let dataLines: string[] = [];

  try {
    while (!signal.aborted) {
      const { done, value } = await reader.read();
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
    signal.removeEventListener("abort", onAbort);
    reader.releaseLock();
  }
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

function isExpectedStreamTermination(err: unknown): boolean {
  if (!(err instanceof Error)) return false;
  const name = err.name.toLowerCase();
  return name === "aborterror";
}

function sleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal.aborted) { resolve(); return; }
    const timer = setTimeout(resolve, ms);
    signal.addEventListener("abort", () => { clearTimeout(timer); resolve(); }, { once: true });
  });
}
