import { formatAwakeningForAgent, type ChannelAwakening } from "./channel.js";

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
  isPaused?: () => boolean;
  log?: (message: string) => void;
}

export interface TerminalAwakeningStatus {
  ambientQueued: number;
  ambientDropped: number;
}

// Receiving context is supplied separately by the locally trusted registration
// owner, never read from the awakening's message or metadata.
export type TerminalAwakeningHandler = ((awakening: ChannelAwakening, receivingIdentityHome?: string) => Promise<void>) & {
  status: () => TerminalAwakeningStatus;
};

interface AmbientItem {
  key: string;
  awakening: ChannelAwakening;
  receivingIdentityHome?: string;
  resolve: () => void;
  reject: (error: Error) => void;
}

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
    case "generic-shell":
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

function terminalInputSafeText(text: string): string {
  return text
    .replace(/\r\n?/g, "\n")
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F\u0080-\u009F]/g, "");
}

function validatedNoticeID(value: string | undefined): string | undefined {
  const raw = value || "";
  return /^[0-9a-f]{32}$/i.test(raw) || /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(raw)
    ? raw
    : undefined;
}

function quotedIdentityHome(home: string): string | undefined {
  // Do not strip a path into a different valid path. Refuse terminal controls
  // (including line separators) before shell quoting the exact absolute path.
  if (!home.startsWith("/") || /[\x00-\x1F\x7F-\u009F\u2028\u2029]/.test(home)) return undefined;
  return "'" + home.replace(/'/g, "'\\''") + "'";
}

function messageRecoveryCommand(awakening: ChannelAwakening, awCommand: string): string | undefined {
  const id = validatedNoticeID(awakening.meta.message_id);
  if (awakening.kind === "mail" && id) return `${awCommand} mail show --message-id ${id}`;
  if (awakening.kind === "chat") {
    const sessionID = validatedNoticeID(awakening.meta.session_id);
    if (sessionID && id) return `${awCommand} chat history --session-id ${sessionID} --message-id ${id}`;
    if (sessionID) return `${awCommand} chat history --session-id ${sessionID}`;
  }
  return undefined;
}

function safeAwakeningNotice(awakening: ChannelAwakening, awCommand = "aw"): string {
  const id = validatedNoticeID(awakening.meta.message_id || awakening.meta.event_id || awakening.meta.task_id) || "id-unavailable";
  return `aweb: new event ${id} waiting — run ${awCommand} events stream --json`;
}

function textForTerminalAwakening(awakening: ChannelAwakening, receivingIdentityHome?: string): string {
  const quotedHome = receivingIdentityHome === undefined ? undefined : quotedIdentityHome(receivingIdentityHome);
  const richText = terminalInputSafeText(formatAwakeningForAgent(awakening));
  // Mail/chat present actual content before their accepted-input receipt
  // can mark them read, regardless of harness readiness.
  if (awakening.kind === "mail" || awakening.kind === "chat") {
    const recovery = quotedHome ? messageRecoveryCommand(awakening, `aw --identity-home ${quotedHome}`) : undefined;
    return recovery ? `${richText}\n\nRecovery: ${recovery}` : richText;
  }
  if (receivingIdentityHome !== undefined && quotedHome === undefined) return safeAwakeningNotice(awakening);
  const notice = safeAwakeningNotice(awakening, quotedHome ? `aw --identity-home ${quotedHome}` : "aw");
  return quotedHome ? `${notice}\n\n${richText}` : richText;
}

function abortError(): TerminalAbortError {
  return new TerminalAbortError();
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw abortError();
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

function ambientKey(awakening: ChannelAwakening): string {
  return awakening.meta.event_id || awakening.meta.task_id || awakening.meta.message_id || `${awakening.kind}:${awakening.meta.type || "ambient"}`;
}

function rejectItem(item: AmbientItem, error: Error): void {
  item.reject(error);
}

/**
 * Terminal presentation adapter. Presentation is immediate and serialized
 * across delivery lanes; inspect only guards against typing into a bare shell.
 * Wake/steer awakenings reject on input failure so channel-core
 * can re-dispatch and re-fetch unread state. Ambient awakenings are bounded and
 * piggyback on the next wake/steer input.
 */
export function createTerminalAwakeningHandler(options: TerminalAwakeningHandlerOptions): TerminalAwakeningHandler {
  const maxAmbient = options.maxAmbient ?? DEFAULT_MAX_AMBIENT;
  const ambient = new Map<string, AmbientItem>();
  let ambientDropped = 0;
  let inputTail: Promise<void> = Promise.resolve();

  function rejectAll(error: Error): void {
    for (const item of ambient.values()) rejectItem(item, error);
    ambient.clear();
  }

  if (options.signal) {
    if (options.signal.aborted) rejectAll(abortError());
    options.signal.addEventListener("abort", () => rejectAll(abortError()), { once: true });
  }

  const handler = (async (awakening: ChannelAwakening, receivingIdentityHome?: string): Promise<void> => {
    throwIfAborted(options.signal);
    if (awakening.deliveryIntent === "ambient") {
      return new Promise<void>((resolve, reject) => {
        const key = ambientKey(awakening);
        const previous = ambient.get(key);
        if (previous) {
          ambient.delete(key);
          previous.reject(new Error(`ambient awakening superseded: ${key}`));
        }
        ambient.set(key, { key, awakening, receivingIdentityHome, resolve, reject });
        while (ambient.size > maxAmbient) {
          const oldest = ambient.values().next().value as AmbientItem | undefined;
          if (!oldest) break;
          ambient.delete(oldest.key);
          ambientDropped += 1;
          oldest.reject(new Error("ambient awakening dropped because the terminal queue is full"));
        }
      });
    }

    const delivery = inputTail.then(() => present(awakening, receivingIdentityHome));
    // A failed input must not poison subsequent callers. Ambient work bypasses
    // this queue because it settles only when a wake/steer input carries it.
    inputTail = delivery.catch(() => {});
    return delivery;
  }) as TerminalAwakeningHandler;

  async function present(awakening: ChannelAwakening, receivingIdentityHome?: string): Promise<void> {
    throwIfAborted(options.signal);
    if (options.isPaused?.()) throw new Error("terminal delivery is paused");
    const ambientBatch = [...ambient.values()];
    let inspection: TerminalInspection;
    try {
      inspection = await raceAbort(options.session.inspect(options.home), options.signal);
    } catch (error) {
      if (error instanceof TerminalAbortError) throw error;
      const detail = error instanceof Error ? error.message : String(error);
      throw new Error(`terminal safety inspect failed before input: ${detail}`);
    }
    throwIfAborted(options.signal);
    const state = normalizeTerminalReadiness(inspection.state ?? inspection.rawState, inspection.present ?? true);
    if (state === "shell" || state === "stopped" || state === "not-launched") {
      throw new TerminalInactiveError(state);
    }
    if (options.isPaused?.()) throw new Error("terminal delivery is paused");
    const text = [...ambientBatch, { awakening, receivingIdentityHome }]
      .map((item) => textForTerminalAwakening(item.awakening, item.receivingIdentityHome))
      .join("\n\n---\n\n");
    throwIfAborted(options.signal);
    await options.session.input(options.home, text);
    for (const item of ambientBatch) {
      if (ambient.get(item.key) === item) ambient.delete(item.key);
      item.resolve();
    }
  }

  handler.status = () => ({ ambientQueued: ambient.size, ambientDropped });
  return handler;
}
