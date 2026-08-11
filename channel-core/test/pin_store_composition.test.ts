import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as ed from "@noble/ed25519";
import { consumeAgentEvents, loadPinStore } from "../src/channel.js";
import { PinStore } from "../src/identity/pinstore.js";
import { PinStoreCASConflictError } from "../src/local_aw.js";
import { SenderTrustManager } from "../src/identity/trust.js";
import { computeDIDKey } from "../src/identity/did.js";
import type { AgentEvent } from "../src/types.js";

// COMPOSITION of aweb-abdk (last_seen coalescing) with aweb-abbu (bounded CAS
// retry). Neither change is sufficient alone and the two arms attribute to
// different ones, so a single-arm version would let either carry the result.
//
//   burst 1, all three loaded from the same stale baseline
//     -> each computes a real last_seen advance, so three CAS attempts contend.
//        One wins; abbu absorbs the two typed conflicts, and the losers reload
//        the freshly advanced durable pin and need no second write. THIS ARM IS
//        abbu's - without the retry the losers raise and their wakes are lost.
//
//   burst 2, inside the coalescing window
//     -> nothing changed, so no process even attempts a commit. THIS ARM IS
//        abdk's - without coalescing this is another three-way contention.
//
// The sender is GLOBAL by construction. A local-scope sender is not pinned at
// all, so the same test built from one would produce no commits, no conflicts,
// and pass whatever either change did.

const TEAM = "backend:acme.com";
const SENDER_ALIAS = "grace";
const SENDER_ADDRESS = `${TEAM}/${SENDER_ALIAS}`;
const SENDER_STABLE_ID = "did:aw:graceStableIdentity";
const PROCESS_COUNT = 3;

let dir: string;
let storePath: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "pin-composition-"));
  storePath = join(dir, "known_agents.yaml");
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

const SENDER_SEED = new Uint8Array(32).fill(23);

async function senderDID(): Promise<string> {
  return computeDIDKey(await ed.getPublicKeyAsync(SENDER_SEED));
}

/**
 * A genuinely signed message. fetchInbox recomputes verification_status from the
 * signature and overwrites whatever the fixture claims, so an unsigned message
 * arrives "unverified", never reaches the pinned path, and would make this whole
 * test vacuous while still passing.
 */
async function signedFields(did: string, messageID: string): Promise<Record<string, string>> {
  const payload = JSON.stringify({
    from: SENDER_ADDRESS,
    from_did: did,
    from_stable_id: SENDER_STABLE_ID,
    to_did: self.did,
    to_stable_id: self.stableID,
    message_id: messageID,
  });
  const signature = await ed.signAsync(new TextEncoder().encode(payload), SENDER_SEED);
  return {
    signed_payload: payload,
    signature: Buffer.from(signature).toString("base64").replace(/=+$/, ""),
    signing_key_id: did,
  };
}

/** A pinned global sender whose last_seen is already outside the window. */
async function seedStaleBaseline(did: string): Promise<void> {
  const baseline = PinStore.fromYAML([
    "pins:",
    `  ${SENDER_STABLE_ID}:`,
    `    address: ${SENDER_ADDRESS}`,
    "    handle: ''",
    `    stable_id: ${SENDER_STABLE_ID}`,
    `    did_key: ${did}`,
    "    first_seen: 2026-02-22T10:00:00Z",
    "    last_seen: 2026-02-22T10:00:00Z",
    "    server: ''",
    "addresses:",
    `  ${SENDER_ADDRESS}: ${SENDER_STABLE_ID}`,
    "",
  ].join("\n"));
  await writeFile(storePath, baseline.toYAML(), "utf-8");
}

interface CASCounters {
  attempts: number;
  writes: number;
  conflicts: number;
}

/**
 * One writer shared by every process, serializing against the real file exactly
 * as the aw binary does: the caller's precondition must still describe what is
 * on disk, or the mutation is refused.
 */
function sharedCASWriter(counters: CASCounters) {
  const canonical = (yaml: string) => PinStore.fromYAML(yaml).toYAML();
  let queue: Promise<void> = Promise.resolve();
  return {
    compareAndSet: async (path: string, expectedYAML: string, desiredYAML: string) => {
      counters.attempts += 1;
      const run = queue.then(async () => {
        const current = await readFile(path, "utf-8");
        if (canonical(current) !== canonical(expectedYAML)) {
          counters.conflicts += 1;
          throw new PinStoreCASConflictError("aw refused pin-store mutation: precondition failed");
        }
        await writeFile(path, desiredYAML, "utf-8");
        counters.writes += 1;
      });
      queue = run.catch(() => {});
      return run;
    },
  };
}

function rosterClient(did: string) {
  return {
    hasTeamCertificateAuth: (teamID: string) => teamID === TEAM,
    get: async () => ({
      team_id: TEAM,
      agents: [{
        alias: SENDER_ALIAS,
        did_key: did,
        did_aw: SENDER_STABLE_ID,
        identity_scope: "global",
      }],
    }),
  } as never;
}

/** Distinct message ids per process AND per burst, so delivery dedupe can never
 * skip trust and make the coalescing arm pass without entering it. */
function messageID(burst: number, process: number): string {
  return `mail-b${burst}-p${process}`;
}

async function inboxClient(did: string, burst: number, process: number) {
  const id = messageID(burst, process);
  const signed = await signedFields(did, id);
  return {
    get: vi.fn().mockResolvedValue({
      messages: [{
        ...signed,
        message_id: id,
        from_agent_id: "agent-grace",
        from_alias: SENDER_ALIAS,
        from_address: SENDER_ADDRESS,
        from_did: did,
        from_stable_id: SENDER_STABLE_ID,
        to_alias: "eve",
        to_did: self.did,
        to_stable_id: self.stableID,
        subject: "composition",
        body: "steady state",
        priority: "normal",
        created_at: "2026-02-22T10:00:00Z",
      }],
    }),
    post: vi.fn().mockResolvedValue(undefined),
  };
}

const self = {
  alias: "eve",
  address: `${TEAM}/eve`,
  did: "did:key:self-eve",
  stableID: "did:aw:self-eve",
};

describe("last_seen coalescing composed with the bounded CAS retry", () => {
  test("contention resolves on the first burst and disappears on the second", async () => {
    const did = await senderDID();
    await seedStaleBaseline(did);

    const counters: CASCounters = { attempts: 0, writes: 0, conflicts: 0 };
    const writer = sharedCASWriter(counters);

    // Independently loaded stores: three resident processes, one shared file,
    // each holding its own in-memory map as they do in production.
    const processes = await Promise.all(
      Array.from({ length: PROCESS_COUNT }, async () => ({
        pinStore: await loadPinStore(storePath),
        trust: new SenderTrustManager(
          rosterClient(did),
          { verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }) } as never,
          TEAM,
          "",
        ),
      })),
    );

    const warnings: string[] = [];
    const log = (message: string) => { warnings.push(message); };
    const awakenings: unknown[] = [];
    const onAwakening = vi.fn(async (awakening: unknown) => { awakenings.push(awakening); });

    async function runBurst(burst: number): Promise<void> {
      await Promise.all(processes.map(async (proc, index) => {
        const client = await inboxClient(did, burst, index);
        async function* events(): AsyncGenerator<AgentEvent> {
          yield { type: "mail_message", message_id: messageID(burst, index) } as AgentEvent;
        }
        await consumeAgentEvents(
          {
            client: client as never,
            pinStore: proc.pinStore,
            pinStorePath: storePath,
            pinStoreWriter: writer,
            trust: proc.trust,
            self,
            onAwakening,
          },
          new Set(),
          events(),
          log,
        );
      }));
    }

    // ARM ONE - abbu. All three see a stale last_seen, all three try to commit.
    await runBurst(1);

    expect(counters.attempts).toBe(PROCESS_COUNT);
    expect(counters.writes).toBe(1);
    expect(counters.conflicts).toBe(PROCESS_COUNT - 1);
    expect(awakenings).toHaveLength(PROCESS_COUNT);
    expect(warnings.filter((w) => /remains pending/i.test(w))).toHaveLength(0);

    const afterBurstOne = { ...counters };

    // ARM TWO - abdk. Inside the window nothing changed, so nothing is attempted.
    await runBurst(2);

    expect(counters.attempts).toBe(afterBurstOne.attempts);
    expect(counters.writes).toBe(afterBurstOne.writes);
    expect(counters.conflicts).toBe(afterBurstOne.conflicts);
    expect(awakenings).toHaveLength(PROCESS_COUNT * 2);
    expect(warnings.filter((w) => /remains pending/i.test(w))).toHaveLength(0);

    // The durable pin advanced exactly once and still names the same identity.
    const durable = await loadPinStore(storePath);
    expect(durable.addresses.get(SENDER_ADDRESS)).toBe(SENDER_STABLE_ID);
    expect(durable.pins.get(SENDER_STABLE_ID)?.last_seen).not.toBe("2026-02-22T10:00:00Z");
  });
});
