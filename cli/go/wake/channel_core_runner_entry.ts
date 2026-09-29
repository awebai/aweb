import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import {
  consumeAgentEvents,
  createChannelClient,
  createLocalAWDecryptProvider,
  createLocalAWPinStoreWriter,
  createRegistryResolver,
  createTerminalAwakeningHandler,
  createTerminalDeliveryReadinessGate,
  DeliveryStore,
  loadPinStore,
  SenderTrustManager,
  type AgentEvent,
  type ChannelDeliveryIntent,
  type TerminalInspection,
  resolveConfig,
} from "../../../channel-core/src/index.js";

interface InitLine {
  type: "init";
  home: string;
  oatsBin?: string;
  awCommand?: string;
  coalesceMs?: number;
  rateLimitMs?: number;
  inspectDelayMs?: number;
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

interface OATSEnvelope {
  ok?: boolean;
  result?: { home?: string; backend?: string; present?: boolean; state?: string; submitted?: boolean };
  error?: { code?: string; message?: string };
}

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
    inactive,
    last_input_at: lastInputAt,
    last_error: lastError,
    ambient_queued: handlerStatus.ambientQueued,
    ambient_dropped: handlerStatus.ambientDropped,
    ...extra,
  });
}

function traceStatus(bindingID: string, entry: { stage?: string; message_id?: string; session_id?: string }): void {
  emit({
    type: "status",
    binding_id: bindingID,
    trace_stage: entry.stage,
    trace_message_id: entry.message_id,
    trace_session_id: entry.session_id,
  });
}

function runOATS(bin: string, args: string[], input = ""): Promise<OATSEnvelope> {
  return new Promise((resolve, reject) => {
    const hasInput = input.length > 0;
    const child = spawn(bin, args, { stdio: [hasInput ? "pipe" : "ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    let settled = false;
    const fail = (error: Error) => {
      if (settled) return;
      settled = true;
      abort.signal.removeEventListener("abort", onAbort);
      reject(error);
    };
    const onAbort = () => {
      child.kill("SIGTERM");
      fail(new Error("oats command aborted"));
    };
    abort.signal.addEventListener("abort", onAbort, { once: true });
    if (!child.stdout || !child.stderr) {
      fail(new Error("oats subprocess stdout/stderr unavailable"));
      return;
    }
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.on("error", fail);
    child.on("close", () => {
      if (settled) return;
      abort.signal.removeEventListener("abort", onAbort);
      let envelope: OATSEnvelope;
      try {
        envelope = JSON.parse(stdout.trim()) as OATSEnvelope;
      } catch (error) {
        fail(new Error((stderr || stdout || (error instanceof Error ? error.message : String(error))).trim()));
        return;
      }
      if (!envelope.ok) {
        fail(new Error(`${envelope.error?.code || "E_OATS"}: ${envelope.error?.message || "oats command failed"}`));
        return;
      }
      settled = true;
      resolve(envelope);
    });
    if (hasInput && child.stdin) {
      child.stdin.on("error", fail);
      child.stdin.end(input);
    }
  });
}

async function start(init: InitLine): Promise<void> {
  paused = Boolean(init.paused);
  const oatsBin = init.oatsBin || process.env.AW_WAKE_OATS_BIN || "oats";
  const awCommand = init.awCommand || "aw";
  const session = {
    async inspect(home: string): Promise<TerminalInspection> {
      status({ readiness_waiting: "inspect_start" });
      const envelope = await runOATS(oatsBin, ["session", "inspect", "--home", home, "--json"]);
      status({ readiness_waiting: "inspect_done" });
      return { present: envelope.result?.present, state: envelope.result?.state, rawState: envelope.result?.state };
    },
    async input(home: string, text: string): Promise<void> {
      const envelope = await runOATS(oatsBin, ["session", "input", "--home", home, "--json"], text);
      if (!envelope.result?.submitted) throw new Error("oats session input did not report submitted:true");
      lastInputAt = new Date().toISOString();
      status({ delivered: true });
    },
  };
  const awaitReady = createTerminalDeliveryReadinessGate({
    home: init.home,
    session,
    signal: abort.signal,
    coalesceMs: init.coalesceMs,
    rateLimitMs: init.rateLimitMs,
    inspectDelayMs: init.inspectDelayMs,
    isPaused: () => paused,
    onInactive: (state) => { inactive = state; status({ inactive: state }); },
    onReadinessStatus: (readiness) => status({
      readiness_state: readiness.state,
      readiness_error: readiness.error,
      readiness_paused: readiness.paused,
      readiness_waiting: readiness.waiting,
    }),
    log: (message) => {
      if (message.includes("terminal delivery is paused")) status({ paused: true, log: message });
      else { lastError = message; status({ log: message }); }
    },
  });
  const handler = createTerminalAwakeningHandler({ home: init.home, session, signal: abort.signal });
  const onAwakening = async (awakening: Parameters<typeof handler>[0]) => {
    await handler(awakening);
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
      onAwakening,
      awaitDeliveryReady: (intent: ChannelDeliveryIntent, signal: AbortSignal) => awaitReady(intent, signal),
      mailAcknowledgment: config.authMode === "grant" && !grantScopes.has("mail.send") ? "manual" : "delivery",
      onTrace: (entry) => traceStatus(binding.binding_id, entry),
    }, new Set<string>(), queue, (message) => {
      lastError = message;
      status({ binding_id: binding.binding_id, error: message });
    }));
  }
  status({ ready: true });
}

async function main(): Promise<void> {
  const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
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
      paused = false;
      status({ paused: false });
    } else if (msg.type === "shutdown") {
      break;
    }
  }
  abort.abort();
  for (const queue of queues.values()) queue.close();
  await Promise.allSettled(consumers);
  status({ stopped: true });
}

main().catch((error) => {
  lastError = error instanceof Error ? error.message : String(error);
  status({ fatal: true });
  process.exitCode = 1;
});
