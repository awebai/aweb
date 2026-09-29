import { execFile } from "node:child_process";
import { readFileSync } from "node:fs";
import { promisify } from "node:util";
import {
  createChannelClient,
  createLocalAWDecryptProvider,
  createLocalAWPinStoreWriter,
  createRegistryResolver,
  createTerminalAwakeningHandler,
  resolveConfig,
  createTerminalDeliveryReadinessGate,
  DeliveryStore,
  dispatchAgentEvent,
  loadPinStore,
  PinStore,
  SenderTrustManager,
  type AgentEvent,
  type TerminalInspection,
} from "../../../channel-core/src/index.js";

const execFileAsync = promisify(execFile);

interface RunnerRequest {
  event: AgentEvent;
  home: string;
  identityHome: string;
  teamID?: string;
  statePath?: string;
  oatsBin?: string;
  awCommand?: string;
  deliveryStorePath?: string;
  pinStorePath?: string;
  coalesceMs?: number;
  rateLimitMs?: number;
  inspectDelayMs?: number;
}

interface OATSEnvelope {
  ok?: boolean;
  result?: {
    home?: string;
    backend?: string;
    present?: boolean;
    state?: string;
    submitted?: boolean;
  };
  error?: { code?: string; message?: string };
}

async function stdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString("utf8");
}

async function runOATS(bin: string, args: string[], input = ""): Promise<OATSEnvelope> {
  let stdout = "";
  try {
    const result = await execFileAsync(bin, args, { input, maxBuffer: 1024 * 1024 });
    stdout = result.stdout;
  } catch (error) {
    const any = error as { stdout?: string; stderr?: string; message?: string };
    stdout = any.stdout || "";
    if (!stdout.trim()) {
      const detail = (any.stderr || any.message || "oats command failed").trim();
      throw new Error(detail);
    }
  }
  let envelope: OATSEnvelope;
  try {
    envelope = JSON.parse(stdout) as OATSEnvelope;
  } catch (error) {
    throw new Error(`invalid oats JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (!envelope.ok) {
    const code = envelope.error?.code || "E_OATS";
    const message = envelope.error?.message || "oats command failed";
    throw new Error(`${code}: ${message}`);
  }
  return envelope;
}

function paused(statePath: string | undefined): boolean {
  if (!statePath) return false;
  try {
    const raw = JSON.parse(readFileSync(statePath, "utf8")) as { paused?: boolean };
    return raw.paused === true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

async function main(): Promise<void> {
  const request = JSON.parse(await stdin()) as RunnerRequest;
  process.env.AWEB_IDENTITY_HOME = request.identityHome;

  const config = await resolveConfig(request.home);
  const client = createChannelClient(config);
  const pinStore = request.pinStorePath ? await loadPinStore(request.pinStorePath) : await loadPinStore();
  const registry = createRegistryResolver(config);
  const trust = new SenderTrustManager(client, registry, config.teamID, config.did, config.stableID);
  const deliveryStore = await DeliveryStore.load(request.deliveryStorePath);
  const signal = new AbortController();
  const oatsBin = request.oatsBin || process.env.AW_WAKE_OATS_BIN || "oats";
  let inactive = "";

  const session = {
    async inspect(home: string): Promise<TerminalInspection> {
      const envelope = await runOATS(oatsBin, ["session", "inspect", "--home", home, "--json"]);
      return {
        present: envelope.result?.present,
        state: envelope.result?.state,
        rawState: envelope.result?.state,
      };
    },
    async input(home: string, text: string): Promise<void> {
      const envelope = await runOATS(oatsBin, ["session", "input", "--home", home, "--json"], text);
      if (!envelope.result?.submitted) throw new Error("oats session input did not report submitted:true");
    },
  };

  const awaitDeliveryReady = createTerminalDeliveryReadinessGate({
    home: request.home,
    session,
    signal: signal.signal,
    coalesceMs: request.coalesceMs,
    rateLimitMs: request.rateLimitMs,
    inspectDelayMs: request.inspectDelayMs,
    isPaused: () => paused(request.statePath),
    onInactive: (state) => { inactive = state; },
    log: (message) => console.error(message),
  });

  const handler = createTerminalAwakeningHandler({
    home: request.home,
    session,
    signal: signal.signal,
    log: (message) => console.error(message),
  });

  await dispatchAgentEvent({
    client,
    pinStore,
    pinStoreWriter: createLocalAWPinStoreWriter({ workdir: request.home }),
    trust,
    self: {
      alias: config.alias,
      address: config.address,
      did: config.did,
      stableID: config.stableID,
    },
    signal: signal.signal,
    deliveryStore,
    deliveryStorePath: request.deliveryStorePath,
    localDecrypt: createLocalAWDecryptProvider({
      workdir: request.home,
      awCommand: request.awCommand || "aw",
      teamID: config.teamID,
    }),
    teamID: config.teamID,
    workdir: request.home,
    awCommand: request.awCommand,
    onAwakening: handler,
    awaitDeliveryReady: (intent, abort) => awaitDeliveryReady(intent, abort),
    mailAcknowledgment: "delivery",
  }, new Set<string>(), [request.event], (message) => console.error(message));

  console.log(JSON.stringify({ ok: true, inactive, terminal: handler.status() }));
}

main().catch((error) => {
  const detail = error instanceof Error ? error.message : String(error);
  console.error(detail);
  console.log(JSON.stringify({ ok: false, error: detail }));
  process.exitCode = 1;
});
