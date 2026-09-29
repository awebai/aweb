import { formatAwakeningForAgent, type ChannelAwakening, type ChannelDeliveryIntent } from "./channel.js";

export type TerminalReadinessState = "idle" | "working" | "blocked" | "shell" | "unknown" | "stopped" | "not-launched";

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
  maxAmbient?: number;
  log?: (message: string) => void;
}

export interface TerminalReadinessGateOptions {
  home: string;
  session: TerminalSession;
  signal?: AbortSignal;
  coalesceMs?: number;
  rateLimitMs?: number;
  inspectDelayMs?: number;
  onInactive?: (state: TerminalReadinessState) => void;
  log?: (message: string) => void;
}

export interface TerminalAwakeningStatus {
  ambientQueued: number;
  ambientDropped: number;
}

export type TerminalAwakeningHandler = ((awakening: ChannelAwakening) => Promise<void>) & {
  status: () => TerminalAwakeningStatus;
};

interface AmbientItem {
  key: string;
  awakening: ChannelAwakening;
  resolve: () => void;
  reject: (error: Error) => void;
}

const DEFAULT_TERMINAL_COALESCE_MS = 500;
const DEFAULT_TERMINAL_RATE_LIMIT_MS = 15_000;
const DEFAULT_TERMINAL_INSPECT_DELAY_MS = 2_000;
const DEFAULT_MAX_AMBIENT = 50;

export class TerminalInactiveError extends Error {
  constructor(readonly state: TerminalReadinessState) {
    super(`terminal is inactive (state=${state})`);
  }
}

export class TerminalAbortError extends Error {
  constructor() {
    super("terminal delivery aborted");
  }
}

/**
 * Normalize OATS/backend readiness vocabulary for terminal delivery.
 *
 * `unknown` is a conservative terminal state, not an error: tmux-backed
 * sessions may report no useful state. `shell` is explicitly not a harness and
 * must defer to avoid typing message text into a command shell.
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
    case "shell":
    case "generic shell":
      return "shell";
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

function abortError(): TerminalAbortError {
  return new TerminalAbortError();
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw abortError();
}

function sleep(ms: number, signal: AbortSignal | undefined): Promise<void> {
  if (ms <= 0) return Promise.resolve();
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(abortError());
      return;
    }
    const timer = setTimeout(done, ms);
    function done() {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }
    function onAbort() {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      reject(abortError());
    }
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

function raceAbort<T>(promise: Promise<T>, signal: AbortSignal | undefined): Promise<T> {
  if (!signal) return promise;
  if (signal.aborted) return Promise.reject(abortError());
  return new Promise<T>((resolve, reject) => {
    function onAbort() {
      signal?.removeEventListener("abort", onAbort);
      reject(abortError());
    }
    signal.addEventListener("abort", onAbort, { once: true });
    promise.then(
      (value) => {
        signal.removeEventListener("abort", onAbort);
        resolve(value);
      },
      (error) => {
        signal.removeEventListener("abort", onAbort);
        reject(error);
      },
    );
  });
}

/**
 * Create channel-core's terminal readiness gate. This runs before exact fetch,
 * so messages read out of band while the terminal is busy are dropped by the
 * later unread-only fetch instead of being held as already-fetched content.
 */
export function createTerminalDeliveryReadinessGate(options: TerminalReadinessGateOptions) {
  const coalesceMs = options.coalesceMs ?? DEFAULT_TERMINAL_COALESCE_MS;
  const rateLimitMs = options.rateLimitMs ?? DEFAULT_TERMINAL_RATE_LIMIT_MS;
  const inspectDelayMs = options.inspectDelayMs ?? DEFAULT_TERMINAL_INSPECT_DELAY_MS;
  let confirmedLive = false;
  let firstReadyAt = 0;
  let lastDeliveryAt = 0;

  return async (intent: ChannelDeliveryIntent, signal: AbortSignal = options.signal ?? new AbortController().signal): Promise<void> => {
    if (intent === "ambient") return;
    while (true) {
      throwIfAborted(options.signal);
      throwIfAborted(signal);
      const inspection = await raceAbort(options.session.inspect(options.home), signal);
      throwIfAborted(options.signal);
      throwIfAborted(signal);
      const present = inspection.present ?? true;
      if (present) confirmedLive = true;
      const state = normalizeTerminalReadiness(inspection.state ?? inspection.rawState, present);
      if (confirmedLive && (state === "stopped" || state === "not-launched")) {
        options.onInactive?.(state);
        throw new TerminalInactiveError(state);
      }
      if (!confirmedLive) {
        options.log?.("aweb: terminal has not confirmed live yet; delivery waits before fetch");
        await sleep(inspectDelayMs, signal);
        continue;
      }
      if (!terminalReadyForIntent(state, intent)) {
        options.log?.(`aweb: terminal not ready for ${intent} delivery (state=${state}); delivery waits before fetch`);
        await sleep(inspectDelayMs, signal);
        continue;
      }

      const now = Date.now();
      if (state === "unknown") {
        if (firstReadyAt === 0) firstReadyAt = now;
        const oldestDelay = coalesceMs - (now - firstReadyAt);
        const rateDelay = lastDeliveryAt === 0 ? 0 : rateLimitMs - (now - lastDeliveryAt);
        const delay = Math.max(0, oldestDelay, rateDelay);
        if (delay > 0) {
          await sleep(delay, signal);
          continue;
        }
      } else {
        firstReadyAt = 0;
      }
      lastDeliveryAt = Date.now();
      return;
    }
  };
}

function ambientKey(awakening: ChannelAwakening): string {
  return awakening.meta.event_id || awakening.meta.task_id || awakening.meta.message_id || `${awakening.kind}:${awakening.meta.type || "ambient"}`;
}

function rejectItem(item: AmbientItem, error: Error): void {
  item.reject(error);
}

/**
 * Terminal presentation adapter. It performs no readiness inspection: readiness
 * belongs to `awaitDeliveryReady`, which runs before exact fetch. Wake/steer
 * awakenings are input immediately and reject on input failure so channel-core
 * can re-dispatch and re-fetch unread state. Ambient awakenings are bounded and
 * piggyback on the next wake/steer input.
 */
export function createTerminalAwakeningHandler(options: TerminalAwakeningHandlerOptions): TerminalAwakeningHandler {
  const maxAmbient = options.maxAmbient ?? DEFAULT_MAX_AMBIENT;
  const ambient = new Map<string, AmbientItem>();
  let ambientDropped = 0;

  function rejectAll(error: Error): void {
    for (const item of ambient.values()) rejectItem(item, error);
    ambient.clear();
  }

  if (options.signal) {
    if (options.signal.aborted) rejectAll(abortError());
    options.signal.addEventListener("abort", () => rejectAll(abortError()), { once: true });
  }

  const handler = (async (awakening: ChannelAwakening): Promise<void> => {
    throwIfAborted(options.signal);
    if (awakening.deliveryIntent === "ambient") {
      return new Promise<void>((resolve, reject) => {
        const key = ambientKey(awakening);
        const previous = ambient.get(key);
        if (previous) previous.reject(new Error(`ambient awakening superseded: ${key}`));
        ambient.set(key, { key, awakening, resolve, reject });
        while (ambient.size > maxAmbient) {
          const oldest = ambient.values().next().value as AmbientItem | undefined;
          if (!oldest) break;
          ambient.delete(oldest.key);
          ambientDropped += 1;
          oldest.reject(new Error("ambient awakening dropped because the terminal queue is full"));
        }
      });
    }

    const ambientBatch = [...ambient.values()];
    const text = [...ambientBatch.map((item) => item.awakening), awakening]
      .map((item) => formatAwakeningForAgent(item))
      .join("\n\n---\n\n");
    await options.session.input(options.home, text);
    throwIfAborted(options.signal);
    for (const item of ambientBatch) {
      if (ambient.get(item.key) === item) ambient.delete(item.key);
      item.resolve();
    }
  }) as TerminalAwakeningHandler;

  handler.status = () => ({ ambientQueued: ambient.size, ambientDropped });
  return handler;
}
