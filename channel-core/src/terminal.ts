import { formatAwakeningForAgent, type ChannelAwakening, type ChannelDeliveryIntent } from "./channel.js";

export type TerminalReadinessState = "idle" | "working" | "blocked" | "unknown" | "stopped" | "not-launched";

export interface TerminalInspection {
  present?: boolean;
  state?: string;
  rawState?: string;
}

export interface TerminalSession {
  inspect(home: string): Promise<TerminalInspection>;
  input(home: string, text: string): Promise<void>;
}

export interface TerminalAwakeningHandlerOptions {
  home: string;
  session: TerminalSession;
  signal?: AbortSignal;
  retryDelayMs?: number;
  log?: (message: string) => void;
}

interface PendingTerminalAwakening {
  awakening: ChannelAwakening;
  resolve: () => void;
  reject: (error: Error) => void;
}

const DEFAULT_TERMINAL_RETRY_DELAY_MS = 2_000;

/**
 * Normalize OATS/backend readiness vocabulary for terminal delivery.
 *
 * `unknown` is a conservative terminal state, not an error: tmux-backed
 * sessions may report no useful state, but input is still the only available
 * terminal delivery primitive. `working` and `blocked` defer to avoid injecting
 * a wake into a known-busy turn. `stopped`/`not-launched` never accept input.
 */
export function normalizeTerminalReadiness(raw: string | undefined, present = true): TerminalReadinessState {
  if (!present) return "not-launched";
  switch ((raw || "").trim().toLowerCase()) {
    case "idle":
    case "done":
      return "idle";
    case "working":
    case "busy":
    case "running":
      return "working";
    case "blocked":
      return "blocked";
    case "stopped":
      return "stopped";
    case "not-launched":
    case "not_launched":
      return "not-launched";
    default:
      return "unknown";
  }
}

export function terminalReadyForIntent(state: TerminalReadinessState, intent: ChannelDeliveryIntent): boolean {
  if (intent === "ambient") return false;
  return state === "idle" || state === "unknown";
}

/**
 * Channel-core terminal adapter for host runtimes that accept text through an
 * OATS-like `session input` operation.
 *
 * The returned handler resolves only after terminal input has been accepted.
 * Channel-core therefore owns delivered/read/ack state: mail/chat acknowledgments
 * and app delivered marks happen only after this handler resolves. If the
 * terminal is not ready or input fails, the handler keeps the awakening queued
 * and retries; it does not report success and it does not ask Go/OATS to ack
 * anything. Ambient awakenings are retained but never initiate input by
 * themselves; they piggyback on the next wake/steer delivery.
 */
export function createTerminalAwakeningHandler(options: TerminalAwakeningHandlerOptions) {
  const retryDelayMs = options.retryDelayMs ?? DEFAULT_TERMINAL_RETRY_DELAY_MS;
  const pending: PendingTerminalAwakening[] = [];
  let draining = false;
  let retryTimer: ReturnType<typeof setTimeout> | undefined;

  const abortError = () => new Error("terminal awakening delivery aborted");

  const clearRetry = () => {
    if (retryTimer) clearTimeout(retryTimer);
    retryTimer = undefined;
  };

  const rejectAll = (error: Error) => {
    clearRetry();
    const items = pending.splice(0, pending.length);
    for (const item of items) item.reject(error);
  };

  if (options.signal) {
    if (options.signal.aborted) rejectAll(abortError());
    options.signal.addEventListener("abort", () => rejectAll(abortError()), { once: true });
  }

  const hasTrigger = () => pending.some((item) => item.awakening.deliveryIntent !== "ambient");

  const scheduleDrain = (delay = 0) => {
    if (options.signal?.aborted) {
      rejectAll(abortError());
      return;
    }
    if (!hasTrigger()) return;
    if (retryTimer) return;
    retryTimer = setTimeout(() => {
      retryTimer = undefined;
      void drain();
    }, delay);
  };

  const drain = async (): Promise<void> => {
    if (draining || !hasTrigger()) return;
    draining = true;
    try {
      if (options.signal?.aborted) {
        rejectAll(abortError());
        return;
      }
      const inspection = await options.session.inspect(options.home);
      const triggerIntent = pending.find((item) => item.awakening.deliveryIntent !== "ambient")?.awakening.deliveryIntent || "wake";
      const state = normalizeTerminalReadiness(inspection.state ?? inspection.rawState, inspection.present ?? true);
      if (!terminalReadyForIntent(state, triggerIntent)) {
        options.log?.(`aweb: terminal not ready for ${triggerIntent} delivery (state=${state}); wake remains queued`);
        scheduleDrain(retryDelayMs);
        return;
      }

      const batch = pending.slice();
      const text = batch.map((item) => formatAwakeningForAgent(item.awakening)).join("\n\n---\n\n");
      await options.session.input(options.home, text);
      for (const item of batch) {
        const index = pending.indexOf(item);
        if (index >= 0) pending.splice(index, 1);
        item.resolve();
      }
      scheduleDrain(0);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      options.log?.(`aweb: terminal input failed; wake remains queued: ${detail}`);
      scheduleDrain(retryDelayMs);
    } finally {
      draining = false;
    }
  };

  return (awakening: ChannelAwakening): Promise<void> => {
    if (options.signal?.aborted) return Promise.reject(abortError());
    const promise = new Promise<void>((resolve, reject) => {
      pending.push({ awakening, resolve, reject });
    });
    if (awakening.deliveryIntent !== "ambient") scheduleDrain(0);
    return promise;
  };
}
