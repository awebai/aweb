import type { APIClient } from "./api/client.js";
import type { AgentEvent } from "./api/events.js";

export const RECONCILE_INTERVAL_MS = 30_000;
export const RECONCILE_MAX_BACKOFF_MS = 5 * 60_000;
export const RECONCILE_JITTER_RATIO = 0.25;
export const RECONCILE_MAIL_PAGE_SIZE = 200;
export const RECONCILE_CHAT_PAGE_SIZE = 2000;
export const RECONCILE_MAX_PASSES = 4;
export const RECONCILE_MAX_CHAT_SESSIONS_PER_PASS = 50;

export interface ReconcileEventSink {
  enqueue(event: AgentEvent): Promise<void>;
}

/** One mail lane and one lane per chat session, shared by stream and sweep. */
export class AgentEventScheduler implements ReconcileEventSink {
  private readonly lanes = new Map<string, Promise<void>>();
  private readonly pending = new Set<Promise<void>>();

  constructor(
    private readonly dispatch: (event: AgentEvent) => Promise<void>,
    private readonly log: (message: string) => void = () => {},
  ) {}

  enqueue(event: AgentEvent): Promise<void> {
    const lane = eventDispatchLane(event);
    const previous = lane ? this.lanes.get(lane) : undefined;
    const job = (previous || Promise.resolve())
      .then(() => this.dispatch(event))
      .catch((error) => {
        const detail = error instanceof Error ? error.message : String(error);
        this.log(`aweb: could not process an incoming event: ${detail}; it remains pending`);
      });
    this.pending.add(job);
    if (lane) this.lanes.set(lane, job);
    void job.finally(() => {
      this.pending.delete(job);
      if (lane && this.lanes.get(lane) === job) this.lanes.delete(lane);
    });
    return job;
  }

  async drain(): Promise<void> {
    await Promise.all([...this.pending]);
  }
}

export interface ReconcileSchedule {
  intervalMs?: number;
  maxBackoffMs?: number;
  jitterRatio?: number;
  maxPasses?: number;
  random?: () => number;
  mailAcknowledgment?: "delivery" | "manual";
}

interface InboxSnapshot {
  messages: Array<{ message_id?: string }>;
}

interface PendingChat {
  session_id?: string;
  conversation_id?: string;
  unread_count?: number;
  sender_waiting?: boolean;
}

interface PendingSnapshot {
  pending: PendingChat[];
}

/**
 * Fetch durable communication state independently of the event stream and feed
 * it into the stream's dispatch scheduler. Each pass is bounded to one mail
 * page and 50 chat sessions. At most four passes run per interval, so a busy
 * agent drains backlog without one sweep monopolizing the server or scheduler.
 */
export async function reconcileDurableState(
  client: APIClient,
  sink: ReconcileEventSink,
  signal: AbortSignal,
  log: (message: string) => void = () => {},
  schedule: ReconcileSchedule = {},
): Promise<void> {
  const maxPasses = boundedInteger(schedule.maxPasses, RECONCILE_MAX_PASSES);
  for (let pass = 0; pass < maxPasses && !signal.aborted; pass += 1) {
    const [mailResult, chatResult] = await Promise.allSettled([
      client.get<InboxSnapshot>(
        `/v1/messages/inbox?unread_only=true&limit=${RECONCILE_MAIL_PAGE_SIZE}`,
        signal,
      ),
      client.get<PendingSnapshot>("/v1/chat/pending", signal),
    ]);
    if (signal.aborted) return;

    const events: AgentEvent[] = [];
    let mailBacklog = false;
    let chatBacklog = false;
    if (mailResult.status === "fulfilled") {
      if (mailResult.value.messages.length > 0) {
        // A generic mail event lets the existing dispatcher fetch and process a
        // whole verified page. Enqueuing every ID would turn one snapshot into
        // N additional requests.
        events.push({ type: "mail_message" });
      }
      mailBacklog = schedule.mailAcknowledgment !== "manual"
        && mailResult.value.messages.length >= RECONCILE_MAIL_PAGE_SIZE;
    }
    if (chatResult.status === "fulfilled") {
      const unread = chatResult.value.pending.filter(
        (item) => Boolean(item.session_id) && Number(item.unread_count || 0) > 0,
      );
      for (const item of unread.slice(0, RECONCILE_MAX_CHAT_SESSIONS_PER_PASS)) {
        events.push({
          type: "chat_message",
          session_id: item.session_id,
          conversation_id: item.conversation_id || item.session_id,
          sender_waiting: Boolean(item.sender_waiting),
        });
      }
      chatBacklog = unread.length > RECONCILE_MAX_CHAT_SESSIONS_PER_PASS
        || unread.some((item) => Number(item.unread_count || 0) >= RECONCILE_CHAT_PAGE_SIZE);
    }

    await Promise.all(events.map((event) => sink.enqueue(event)));

    const failures = [mailResult, chatResult].filter(
      (result): result is PromiseRejectedResult => result.status === "rejected",
    );
    if (failures.length > 0) {
      throw new AggregateError(
        failures.map((result) => result.reason),
        "durable communication snapshot failed",
      );
    }
    if (!mailBacklog && !chatBacklog) return;
    log(`aweb: durable reconcile backlog continues after pass ${pass + 1}; draining another bounded page`);
  }
}

/**
 * Run non-overlapping periodic reconciliation. Failures back off exponentially
 * to five minutes; successful sweeps return to a jittered 30-second interval so
 * many resident agents do not poll in lockstep. The abort signal cancels both
 * the current snapshot requests and the sole outstanding timer.
 */
export async function runDurableReconcile(
  client: APIClient,
  sink: ReconcileEventSink,
  signal: AbortSignal,
  log: (message: string) => void = () => {},
  schedule: ReconcileSchedule = {},
): Promise<void> {
  const intervalMs = boundedInteger(schedule.intervalMs, RECONCILE_INTERVAL_MS);
  const maxBackoffMs = Math.max(
    intervalMs,
    boundedInteger(schedule.maxBackoffMs, RECONCILE_MAX_BACKOFF_MS),
  );
  const jitterRatio = boundedRatio(schedule.jitterRatio, RECONCILE_JITTER_RATIO);
  const random = schedule.random || Math.random;
  let failures = 0;

  while (!signal.aborted) {
    const backoff = Math.min(maxBackoffMs, intervalMs * (2 ** failures));
    const delay = jitteredDelay(backoff, jitterRatio, random);
    if (!await waitForDelay(delay, signal)) return;
    try {
      await reconcileDurableState(client, sink, signal, log, schedule);
      failures = 0;
    } catch (error) {
      if (signal.aborted) return;
      failures = Math.min(failures + 1, 30);
      const detail = error instanceof Error ? error.message : String(error);
      log(`aweb: durable reconcile failed: ${detail}; retrying with bounded backoff`);
    }
  }
}

function eventDispatchLane(event: AgentEvent): string {
  switch (event.type) {
    case "mail_message":
      return "mail";
    case "chat_message":
      return `chat:${event.session_id || event.conversation_id || "unknown"}`;
    default:
      return "";
  }
}

function jitteredDelay(baseMs: number, ratio: number, random: () => number): number {
  const unit = Math.max(0, Math.min(1, random()));
  return Math.max(1, Math.round(baseMs * (1 + ((unit * 2) - 1) * ratio)));
}

function boundedInteger(value: number | undefined, fallback: number): number {
  return Number.isInteger(value) && Number(value) > 0 ? Number(value) : fallback;
}

function boundedRatio(value: number | undefined, fallback: number): number {
  return Number.isFinite(value) && Number(value) >= 0 && Number(value) <= 0.5
    ? Number(value)
    : fallback;
}

function waitForDelay(delayMs: number, signal: AbortSignal): Promise<boolean> {
  if (signal.aborted) return Promise.resolve(false);
  return new Promise((resolve) => {
    let settled = false;
    const finish = (elapsed: boolean) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal.removeEventListener("abort", onAbort);
      resolve(elapsed);
    };
    const onAbort = () => finish(false);
    const timer = setTimeout(() => finish(true), delayMs);
    signal.addEventListener("abort", onAbort, { once: true });
  });
}
