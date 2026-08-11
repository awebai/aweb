// aweb-abdo verification battery orchestrator.
//
// Spawns N real OS processes contending on ONE dev pin-store file through the
// real `aw id pin-store compare-and-set` binary. Every arm is bracketed by a
// live-store digest check: if the LIVE store moves, the arm is VOID and said so.

import { mkdir, rm, writeFile, readFile, stat } from "node:fs/promises";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { homedir } from "node:os";

const HERE = dirname(fileURLToPath(import.meta.url));
// Repo root from this file's own location: scripts/e2e/<dir>/ -> three up.
const WORKTREE = process.env.ABDO_WORKTREE || join(HERE, "..", "..", "..");
const CHANNEL_CORE = join(WORKTREE, "channel-core");
const DIST = join(CHANNEL_CORE, "dist", "index.js");
const LIVE_STORE = join(homedir(), ".config", "aw", "known_agents.yaml");

const require = createRequire(join(CHANNEL_CORE, "package.json"));
const ed = require("@noble/ed25519");
const { sha512 } = require("@noble/hashes/sha2.js");
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));
const { computeDIDKey } = await import(DIST);

const TEAM = "backend:acme.com";
const SENDER_ALIAS = "grace";
const SENDER_ADDRESS = `${TEAM}/${SENDER_ALIAS}`;
const SENDER_STABLE_ID = "did:aw:graceStableIdentity";
const SEED_BYTE = 23;
const SEED = new Uint8Array(32).fill(SEED_BYTE);
const SELF = {
  alias: "eve",
  address: `${TEAM}/eve`,
  did: "did:key:self-eve",
  stableID: "did:aw:self-eve",
};

async function digest(path) {
  try {
    return createHash("sha256").update(await readFile(path)).digest("hex").slice(0, 16);
  } catch (error) {
    return `UNREADABLE:${error.code}`;
  }
}

async function signedMessage(did, messageID, delayMs) {
  const payload = JSON.stringify({
    from: SENDER_ADDRESS, from_did: did, from_stable_id: SENDER_STABLE_ID,
    to_did: SELF.did, to_stable_id: SELF.stableID, message_id: messageID,
  });
  const signature = await ed.signAsync(new TextEncoder().encode(payload), SEED);
  return {
    signed_payload: payload,
    signature: Buffer.from(signature).toString("base64").replace(/=+$/, ""),
    signing_key_id: did,
    message_id: messageID,
    from_agent_id: "agent-sender",
    from_alias: SENDER_ALIAS,
    from_address: SENDER_ADDRESS,
    from_did: did,
    from_stable_id: SENDER_STABLE_ID,
    to_alias: SELF.alias,
    to_did: SELF.did,
    to_stable_id: SELF.stableID,
    subject: "abdo",
    body: "verification",
    priority: "normal",
    created_at: "2026-02-22T10:00:00Z",
    delayMs,
  };
}

async function seedStore(storePath, did, lastSeen) {
  const { PinStore } = await import(DIST);
  const store = PinStore.fromYAML([
    "pins:",
    `  ${SENDER_STABLE_ID}:`,
    `    address: ${SENDER_ADDRESS}`,
    "    handle: ''",
    `    stable_id: ${SENDER_STABLE_ID}`,
    `    did_key: ${did}`,
    "    first_seen: 2026-02-22T10:00:00Z",
    `    last_seen: ${lastSeen}`,
    "    server: ''",
    "addresses:",
    `  ${SENDER_ADDRESS}: ${SENDER_STABLE_ID}`,
    "",
  ].join("\n"));
  await writeFile(storePath, store.toYAML(), "utf-8");
}

function runAgent(cfgPath, devHome) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [join(HERE, "agent.mjs"), cfgPath], {
      // HOME override is defence in depth: pinStorePath is already explicit, but
      // any fallback to DEFAULT_PIN_STORE_PATH must not reach the live store.
      env: { ...process.env, HOME: devHome, AWEB_CHANNEL_DEBUG: "1" },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let err = "";
    child.stderr.on("data", (d) => { err += d; });
    child.on("close", (code) => resolve({ code, err }));
  });
}

export async function runArm({ name, agents, lastSeenOffsetMs, plan, root }) {
  const armRoot = join(root, name);
  await rm(armRoot, { recursive: true, force: true });
  const devHome = join(armRoot, "devhome");
  await mkdir(join(devHome, ".config", "aw"), { recursive: true });
  const storePath = join(devHome, ".config", "aw", "known_agents.yaml");

  const did = computeDIDKey(await ed.getPublicKeyAsync(SEED));
  const lastSeen = new Date(Date.now() - lastSeenOffsetMs).toISOString().replace(/\.\d{3}Z$/, "Z");
  await seedStore(storePath, did, lastSeen);

  const liveBefore = await digest(LIVE_STORE);
  const devBefore = await digest(storePath);

  const cfgs = [];
  for (let i = 0; i < agents; i++) {
    const messages = [];
    for (const step of plan) {
      messages.push(await signedMessage(did, `${name}-a${i}-${step.id}`, step.delayMs || 0));
    }
    const cfgPath = join(armRoot, `agent${i}.json`);
    const cfg = {
      agentIndex: i,
      storePath,
      tracePath: join(armRoot, `trace-agent${i}.jsonl`),
      resultPath: join(armRoot, `result-agent${i}.json`),
      workdir: armRoot,
      distPath: DIST,
      teamID: TEAM,
      senderAlias: SENDER_ALIAS,
      senderDID: did,
      senderStableID: SENDER_STABLE_ID,
      self: SELF,
      messages,
    };
    await writeFile(cfgPath, JSON.stringify(cfg), "utf-8");
    cfgs.push({ cfgPath, resultPath: cfg.resultPath });
  }

  const started = Date.now();
  const runs = await Promise.all(cfgs.map((c) => runAgent(c.cfgPath, devHome)));
  const elapsedMs = Date.now() - started;

  const liveAfter = await digest(LIVE_STORE);
  const results = [];
  for (const c of cfgs) {
    try { results.push(JSON.parse(await readFile(c.resultPath, "utf-8"))); }
    catch { results.push(null); }
  }

  return {
    name, agents, elapsedMs,
    liveBefore, liveAfter,
    isolationHeld: liveBefore === liveAfter,
    devBefore, devAfter: await digest(storePath),
    exitCodes: runs.map((r) => r.code),
    stderr: runs.map((r) => r.err).filter(Boolean),
    results,
    storePath, armRoot,
  };
}

export { LIVE_STORE, digest };
