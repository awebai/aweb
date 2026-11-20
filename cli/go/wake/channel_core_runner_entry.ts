import { runOATS } from "./oats_command.js";
import { createInterface } from "node:readline";
import { setTimeout as delay } from "node:timers/promises";
import {
  consumeAgentEvents,
  createChannelClient,
  createLocalAWDecryptProvider,
  createLocalAWPinStoreWriter,
  createRegistryResolver,
  createTerminalAwakeningHandler,
  normalizeTerminalReadiness,
  DeliveryStore,
  loadPinStore,
  SenderTrustManager,
  type AgentEvent,
  type TerminalInspection,
  resolveConfig,
} from "../../../channel-core/src/index.js";

interface InitLine {
  type: "init";
  home: string;
  oatsBin?: string;
  awCommand?: string;
  paused?: boolean;
  bindings: BindingConfig[];
}

interface BindingConfig {
  binding_id: string;
  identity_home: string;
  team_id: string;
  delivery_store_path: string;
  pin_store_path?: string;
}

type InputLine = InitLine
  | { type: "event"; binding_id: string; event: AgentEvent }
  | { type: "pause" }
  | { type: "resume" }
  | { type: "shutdown" };


class EventQueue implements AsyncIterable<AgentEvent> {
  private items: AgentEvent[] = [];
  private waiters: Array<(value: IteratorResult<AgentEvent>) => void> = [];
  private closed = false;

  push(event: AgentEvent): void {
    if (this.closed) return;
    const waiter = this.waiters.shift();
    if (waiter) waiter({ value: event, done: false });
    else this.items.push(event);
  }

  close(): void {
    this.closed = true;
    for (const waiter of this.waiters.splice(0)) waiter({ value: undefined as never, done: true });
  }

  [Symbol.asyncIterator](): AsyncIterator<AgentEvent> {
    return {
      next: () => {
        const item = this.items.shift();
        if (item) return Promise.resolve({ value: item, done: false });
        if (this.closed) return Promise.resolve({ value: undefined as never, done: true });
        return new Promise((resolve) => this.waiters.push(resolve));
      },
    };
  }
}

const abort = new AbortController();
let paused = false;
let lastInputAt = "";
let lastError = "";
let inactive = "";
let handlerStatus = { ambientQueued: 0, ambientDropped: 0 };
const queues = new Map<string, EventQueue>();
const bindingCapabilities = new Map<string, { grant: boolean; scopes: Set<string> }>();
const consumers: Promise<void>[] = [];

function emit(payload: Record<string, unknown>): void {
  process.stdout.write(`${JSON.stringify(payload)}\n`);
}

function status(extra: Record<string, unknown> = {}): void {
  emit({
    type: "status",
    paused,
    inactive,
    last_input_at: lastInputAt,
    last_error: lastError,
    ambient_queued: handlerStatus.ambientQueued,
    ambient_dropped: handlerStatus.ambientDropped,
    ...extra,
  });
}

function traceStatus(bindingID: string, entry: { stage?: string; message_id?: string; session_id?: string }): void {
  if (entry.stage === "delivery_retry_exhausted") {
    status({ binding_id: bindingID, request_snapshot: true });
    return;
  }
  emit({
    type: "status",
    binding_id: bindingID,
    trace_stage: entry.stage,
    trace_message_id: entry.message_id,
    trace_session_id: entry.session_id,
  });
}


interface StartupPresenceObserver {
  inspect(): Promise<TerminalInspection>;
  hasObservedReceiver(): boolean;
  signal: AbortSignal;
  reportError(error: unknown): void;
}

async function inspectStartupPresence(observer: StartupPresenceObserver): Promise<void> {
  try {
    await observer.inspect();
  } catch (error) {
    if (!observer.signal.aborted) observer.reportError(error);
  }
}

// A registration may precede launch. Observe only until this runner generation
// sees process presence; ordinary delivery then owns inspection (terminal-wake-broker.md:186-193).
async function observeStartupPresence(observer: StartupPresenceObserver): Promise<void> {
  while (!observer.signal.aborted && !observer.hasObservedReceiver()) {
    try {
      await delay(250, undefined, { signal: observer.signal });
    } catch (error) {
      if (observer.signal.aborted) return;
      throw error;
    }
    if (observer.signal.aborted || observer.hasObservedReceiver()) return;
    await inspectStartupPresence(observer);
  }
}

async function start(init: InitLine): Promise<void> {
  paused = Boolean(init.paused);
  const oatsBin = init.oatsBin || process.env.AW_WAKE_OATS_BIN || "oats";
  const awCommand = init.awCommand || "aw";
  let confirmedLive = false;
  let receiverObserved = false;
  let pendingInspection: Promise<TerminalInspection> | undefined;
  const inspectSession = async (home: string): Promise<TerminalInspection> => {
    if (abort.signal.aborted) throw new Error("runner generation stopped");
    status({ readiness_waiting: "inspect_start" });
    try {
      const envelope = await runOATS(oatsBin, ["session", "inspect", "--home", home, "--json"], "", { signal: abort.signal });
      if (abort.signal.aborted) throw new Error("runner generation stopped");
      const observation = envelope.result;
      if (typeof observation?.present !== "boolean"
        || (observation.state !== undefined && typeof observation.state !== "string")
        || (observation.running !== undefined && typeof observation.running !== "boolean")) {
        throw new Error("oats session inspect did not report valid process presence");
      }
      const state = normalizeTerminalReadiness(observation.state, observation.present);
      if (observation.present) confirmedLive = true;
      if (observation.present && observation.running !== false
        && state !== "shell" && state !== "stopped" && state !== "not-launched") {
        receiverObserved = true;
      }
      status({ readiness_waiting: "inspect_done", readiness_state: state, readiness_error: "" });
      if (confirmedLive && (state === "stopped" || state === "not-launched")) onInactive(state);
      return { present: observation.present, state };
    } catch (error) {
      if (!abort.signal.aborted) {
        status({ readiness_waiting: "inspect_error", readiness_error: error instanceof Error ? error.message : String(error) });
      }
      throw error;
    }
  };
  const session = {
    async inspect(home: string): Promise<TerminalInspection> {
      // Startup and delivery share an in-flight observation, so a slower
      // prelaunch inspect cannot overwrite a later live observation.
      if (pendingInspection) return pendingInspection;
      pendingInspection = inspectSession(home);
      try {
        return await pendingInspection;
      } finally {
        pendingInspection = undefined;
      }
    },
    async input(home: string, text: string): Promise<void> {
      const envelope = await runOATS(oatsBin, ["session", "input", "--home", home, "--json"], text);
      if (!envelope.result?.submitted) throw new Error("oats session input did not report submitted:true");
      lastInputAt = new Date().toISOString();
      status({ delivered: true });
    },
  };
  const onInactive = (state: ReturnType<typeof normalizeTerminalReadiness>) => { inactive = state; status({ inactive: state }); };
  const handler = createTerminalAwakeningHandler({ home: init.home, session, signal: abort.signal, isPaused: () => paused });
  const onAwakening = async (awakening: Parameters<typeof handler>[0], receivingIdentityHome?: string) => {
    await handler(awakening, receivingIdentityHome);
    handlerStatus = handler.status();
    status();
  };

  for (const binding of init.bindings) {
    const queue = new EventQueue();
    queues.set(binding.binding_id, queue);
    const config = await resolveConfig(init.home, { identityHome: binding.identity_home, teamID: binding.team_id });
    const grantScopes = new Set(config.grantScopes || []);
    bindingCapabilities.set(binding.binding_id, { grant: config.authMode === "grant", scopes: grantScopes });
    const client = createChannelClient(config);
    const pinStore = binding.pin_store_path ? await loadPinStore(binding.pin_store_path) : await loadPinStore();
    const trust = new SenderTrustManager(client, createRegistryResolver(config), config.teamID, config.did, config.stableID);
    const deliveryStore = await DeliveryStore.load(binding.delivery_store_path);
    consumers.push(consumeAgentEvents({
      client,
      pinStore,
      pinStoreWriter: createLocalAWPinStoreWriter({ workdir: init.home, awCommand }),
      trust,
      self: { alias: config.alias, address: config.address, did: config.did, stableID: config.stableID },
      signal: abort.signal,
      deliveryStore,
      deliveryStorePath: binding.delivery_store_path,
      localDecrypt: createLocalAWDecryptProvider({ workdir: init.home, awCommand, identityHome: binding.identity_home, teamID: config.teamID }),
      teamID: config.teamID,
      workdir: init.home,
      awCommand,
      onAwakening: (awakening) => onAwakening(awakening, init.bindings.length > 1 ? binding.identity_home : undefined),
      mailAcknowledgment: config.authMode === "grant" && !grantScopes.has("mail.send") ? "manual" : "delivery",
      onTrace: (entry) => traceStatus(binding.binding_id, entry),
    }, new Set<string>(), queue, (message) => {
      lastError = message;
      status({ binding_id: binding.binding_id, error: message });
    }));
  }
  const startup: StartupPresenceObserver = {
    inspect: () => session.inspect(init.home),
    hasObservedReceiver: () => receiverObserved,
    signal: abort.signal,
    reportError: (error) => status({ readiness_error: error instanceof Error ? error.message : String(error) }),
  };
  await inspectStartupPresence(startup);
  if (abort.signal.aborted) return;
  status({ ready: true });
  // Registration must complete before the launcher can create the process.
  // Continue observing in the background without delaying that handshake.
  consumers.push(observeStartupPresence(startup));
}

async function main(): Promise<void> {
  const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
  const shutdown = () => {
    abort.abort();
    rl.close();
    process.stdin.pause();
  };
  process.on("SIGTERM", shutdown);
  let initialized = false;
  for await (const line of rl) {
    if (!line.trim()) continue;
    const msg = JSON.parse(line) as InputLine;
    if (msg.type === "init") {
      if (initialized) throw new Error("runner already initialized");
      initialized = true;
      await start(msg);
    } else if (msg.type === "event") {
      const capabilities = bindingCapabilities.get(msg.binding_id);
      if (capabilities?.grant) {
        const type = String(msg.event.type || "");
        if ((type === "actionable_mail" || type === "mail_message") && !capabilities.scopes.has("mail.read")) {
          lastError = "grant lacks mail.read";
          status({ binding_id: msg.binding_id, error: lastError });
          continue;
        }
        if ((type === "actionable_chat" || type === "chat_message") && !capabilities.scopes.has("chat.read")) {
          lastError = "grant lacks chat.read";
          status({ binding_id: msg.binding_id, error: lastError });
          continue;
        }
        if ((type === "actionable_room_post" || type === "room_post") && !capabilities.scopes.has("chat.read")) {
          lastError = "grant lacks chat.read";
          status({ binding_id: msg.binding_id, error: lastError });
          continue;
        }
      }
      const queue = queues.get(msg.binding_id);
      if (!queue) {
        lastError = `unknown binding_id ${msg.binding_id}`;
        status({ binding_id: msg.binding_id, error: lastError });
        continue;
      }
      queue.push(msg.event);
    } else if (msg.type === "pause") {
      paused = true;
      status({ paused: true });
    } else if (msg.type === "resume") {
      const wasPaused = paused;
      paused = false;
      status({ paused: false });
      if (wasPaused) {
        for (const bindingID of queues.keys()) status({ binding_id: bindingID, request_snapshot: true, snapshot_immediate: true });
      }
    } else if (msg.type === "shutdown") {
      break;
    }
  }
  abort.abort();
  for (const queue of queues.values()) queue.close();
  await Promise.allSettled(consumers);
  status({ stopped: true });
  process.removeListener("SIGTERM", shutdown);
  rl.close();
  process.stdin.pause();
}

main().catch((error) => {
  lastError = error instanceof Error ? error.message : String(error);
  status({ fatal: true });
  process.stdout.write("", () => process.exit(1));
});
