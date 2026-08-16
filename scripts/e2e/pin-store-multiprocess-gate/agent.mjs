// One resident channel process for the aweb-abdo multi-process gate.
//
// Real OS process, real shared pin-store file, real `aw id pin-store
// compare-and-set` Go binary (createLocalAWPinStoreWriter), real trust,
// coalescing and retry code from the built dist. The message SOURCE is stubbed -
// that is the documented scope: CAS/coalescing/retry mechanics only, no claim
// about live-server or registry behaviour.
//
// Isolation is belt and braces: pinStorePath is passed EXPLICITLY, and the
// orchestrator also overrides HOME, so a fallback to DEFAULT_PIN_STORE_PATH in
// any code path still lands in the dev home rather than the live store.

import { readFile, writeFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

const cfg = JSON.parse(await readFile(process.argv[2], "utf-8"));
const {
  agentIndex, storePath, tracePath, resultPath, workdir, distPath,
  teamID, senderAlias, senderDID, senderStableID, self, messages,
} = cfg;

const {
  consumeAgentEvents, loadPinStore, SenderTrustManager, createLocalAWPinStoreWriter,
} = await import(pathToFileURL(distPath).href);

// Messages arrive pre-signed from the orchestrator so this process needs no
// bare-specifier imports of its own.
const byID = new Map(messages.map((m) => [m.message_id, m]));
let pending = null;

const client = {
  hasTeamCertificateAuth: (id) => id === teamID,
  get: async (path) => {
    if (String(path).includes("/v1/agents")) {
      return {
        team_id: teamID,
        agents: [{
          alias: senderAlias,
          did_key: senderDID,
          did_aw: senderStableID,
          identity_scope: "global",
        }],
      };
    }
    return { messages: pending ? [structuredClone(byID.get(pending))] : [] };
  },
  post: async () => undefined,
};

const pinStore = await loadPinStore(storePath);
const trust = new SenderTrustManager(
  client,
  { verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }) },
  teamID,
  self.did,
  self.stableID,
);

const wakes = [];
const logLines = [];
const stages = [];

const options = {
  client,
  pinStore,
  pinStorePath: storePath,
  pinStoreWriter: createLocalAWPinStoreWriter({ workdir, awCommand: process.env.AW_BIN || "aw" }),
  trust,
  self,
  workdir,
  onAwakening: async (a) => { wakes.push({ at: Date.now(), messageID: a?.meta?.message_id, status: a?.meta?.trust_status }); },
  // onTrace receives ONE ChannelTraceEntry object: {ts, component, stage, event_type, lane, message_id}
  onTrace: (entry) => { stages.push({ at: Date.now(), stage: entry?.stage, lane: entry?.lane, messageID: entry?.message_id }); },
};

const log = (message) => { logLines.push({ at: Date.now(), message }); };

for (const m of messages) {
  if (m.delayMs) await new Promise((r) => setTimeout(r, m.delayMs));
  pending = m.message_id;
  const started = Date.now();
  async function* events() { yield { type: "mail_message", message_id: m.message_id }; }
  try {
    await consumeAgentEvents(options, new Set(), events(), log);
  } catch (error) {
    logLines.push({ at: Date.now(), message: `THREW: ${error?.message || String(error)}` });
  }
  stages.push({ at: Date.now(), stage: "harness_message_done", messageID: m.message_id, ms: Date.now() - started });
}

await writeFile(tracePath, stages.map((s) => JSON.stringify(s)).join("\n") + "\n", "utf-8");
await writeFile(resultPath, JSON.stringify({ agentIndex, wakes, logLines, stages }), "utf-8");
