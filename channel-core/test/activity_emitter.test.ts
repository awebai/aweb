// The activity emitter's decisions (docs/agent-activity.md, "Emitters"):
// opt-in per turn, attribution, coalescing, and what each publish outcome does.
// publish is a recorder that decodes each signed body; HTTP is tested apart.
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import * as ed from "@noble/ed25519";
import { ActivityEmitter, type PublishOutcome } from "../src/activity/emitter.js";
import type { ActivityEvent, SignedActivity } from "../src/activity/event.js";
import { computeDIDKey } from "../src/identity/did.js";

const SEED = Uint8Array.from(Buffer.from("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "hex"));
const DID = computeDIDKey(ed.getPublicKey(SEED));
const SESSION = "6f1c2b3a-4d5e-4f60-8a7b-9c0d1e2f3a4b";

let root: string;
let sent: ActivityEvent[];
let outcomes: PublishOutcome[];
let logs: string[];

function emitter(extra: Partial<ConstructorParameters<typeof ActivityEmitter>[0]> = {}): ActivityEmitter {
  return new ActivityEmitter({
    identityRoot: root,
    workRoot: "/home/ana/project",
    signer: { did: DID, stableID: "did:aw:agent", teamID: "default:acme.aweb.ai", seed: SEED },
    publish: async (body: SignedActivity) => {
      sent.push(JSON.parse(Buffer.from(body.signed_payload, "base64url").toString("utf8")));
      return outcomes.shift() ?? { kind: "accepted" };
    },
    log: (line: string) => logs.push(line),
    ...extra,
  });
}

function optIn(value = "status"): void {
  writeFileSync(join(root, "activity.yaml"), `activity: ${value}\n`);
}

async function settle(ms = 0): Promise<void> {
  await vi.advanceTimersByTimeAsync(ms);
}

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date("2026-10-16T16:20:00Z"));
  root = mkdtempSync(join(tmpdir(), "activity-emitter-"));
  sent = [];
  outcomes = [];
  logs = [];
});
afterEach(() => {
  vi.useRealTimers();
  rmSync(root, { recursive: true, force: true });
});

describe("opt-in", () => {
  test("without the opt-in nothing is published", async () => {
    const e = emitter();
    e.turnStarted();
    e.tool("Bash", { command: "pytest" });
    e.turnEnded();
    await settle(1000);
    expect(sent).toEqual([]);
  });

  test("the opt-in is read at each turn start", async () => {
    const e = emitter();
    e.turnStarted();
    e.turnEnded();
    optIn();
    e.turnStarted();
    e.turnEnded();
    await settle(1000);
    expect(sent.map(event => event.phase)).toEqual(["turn_started", "turn_ended"]);
  });
});

describe("events", () => {
  test("a turn is signed, bound to the signer, and valid for 60 seconds", async () => {
    optIn();
    const e = emitter();
    e.turnStarted();
    await settle();
    expect(sent[0]).toEqual({
      v: 1, type: "agent_activity", from_did: DID, from_stable_id: "did:aw:agent", team_id: "default:acme.aweb.ai",
      session_id: null, turn_id: sent[0].turn_id, seq: 1, phase: "turn_started",
      timestamp: "2026-10-16T16:20:00Z", expires_at: "2026-10-16T16:21:00Z",
    });
    expect(sent[0].turn_id).toMatch(/^[A-Za-z0-9_.:-]{1,64}$/);
  });

  test("an identity without a stable id omits from_stable_id", async () => {
    optIn();
    const e = emitter({ signer: { did: DID, teamID: "default:acme.aweb.ai", seed: SEED } });
    e.turnStarted();
    await settle();
    expect("from_stable_id" in sent[0]).toBe(false);
  });

  test("a tool event carries the tool and its template summary", async () => {
    optIn();
    const e = emitter();
    e.turnStarted();
    await settle(600);
    e.tool("Bash", { command: "pytest -q" });
    await settle(600);
    expect(sent[1]).toMatchObject({ phase: "tool", tool: "Bash", summary: "Running pytest", seq: 2 });
  });

  test("a tool name outside the identifier alphabet is not sent as a tool", async () => {
    optIn();
    const e = emitter();
    e.turnStarted();
    await settle(600);
    e.tool("my tool!", {});
    await settle(600);
    expect(sent[1].phase).toBe("tool");
    expect(sent[1].tool).toBe("unknown");
  });

  test("a phase outside a turn starts one, and announces it", async () => {
    optIn();
    const e = emitter();
    e.tool("Read", { file_path: "/home/ana/project/a.py" });
    await settle(600);
    e.turnEnded();
    await settle();
    expect(sent.map(event => [event.phase, event.seq])).toEqual([["turn_started", 1], ["tool", 2], ["turn_ended", 3]]);
    expect(new Set(sent.map(event => event.turn_id)).size).toBe(1);
  });

  test("each turn has its own turn_id and seq starts again", async () => {
    optIn();
    const e = emitter();
    e.turnStarted();
    e.turnEnded();
    await settle();
    e.turnStarted();
    e.turnEnded();
    await settle();
    expect(sent[0].turn_id).not.toBe(sent[2].turn_id);
    expect(sent.map(event => event.seq)).toEqual([1, 2, 1, 2]);
  });
});

describe("attribution", () => {
  test("the chat wake before a turn attributes that turn", async () => {
    optIn();
    const e = emitter();
    e.chatWakeDelivered(SESSION, { encrypted: false });
    e.turnStarted();
    e.turnEnded();
    await settle();
    expect(sent.map(event => event.session_id)).toEqual([SESSION, SESSION]);
  });

  test("the next turn is unattributed again", async () => {
    optIn();
    const e = emitter();
    e.chatWakeDelivered(SESSION, { encrypted: false });
    e.turnStarted();
    e.turnEnded();
    e.turnStarted();
    await settle();
    expect(sent[2].session_id).toBeNull();
  });

  test("an encrypted wake keeps tool names but sends no summary for the whole turn", async () => {
    optIn();
    const e = emitter();
    e.chatWakeDelivered(SESSION, { encrypted: true });
    e.turnStarted();
    await settle(600);
    e.tool("Bash", { command: "pytest" });
    await settle(600);
    e.writing();
    await settle(600);
    expect(sent.slice(1).map(event => [event.phase, event.tool, event.summary])).toEqual([
      ["tool", "Bash", undefined],
      ["writing", undefined, undefined],
    ]);
  });
});

describe("coalescing", () => {
  test("within 500 ms the latest state wins", async () => {
    optIn();
    const e = emitter();
    e.turnStarted();
    e.thinking();
    e.tool("Read", { file_path: "/home/ana/project/a.py" });
    e.tool("Bash", { command: "pytest" });
    await settle(499);
    expect(sent.map(event => event.phase)).toEqual(["turn_started"]);
    await settle(1);
    expect(sent.map(event => [event.phase, event.summary, event.seq])).toEqual([
      ["turn_started", undefined, 1],
      ["tool", "Running pytest", 2],
    ]);
  });

  test("turn_ended is sent at once, replacing a pending state", async () => {
    optIn();
    const e = emitter();
    e.turnStarted();
    e.tool("Bash", { command: "pytest" });
    e.turnEnded();
    await settle();
    expect(sent.map(event => event.phase)).toEqual(["turn_started", "turn_ended"]);
    await settle(1000);
    expect(sent).toHaveLength(2);
  });
});

describe("publish outcomes", () => {
  test("429 pauses for Retry-After, drops intermediate states, then resends the boundary and the latest state", async () => {
    optIn();
    const e = emitter();
    outcomes = [{ kind: "rate_limited", retryAfterSeconds: 3 }];
    e.turnStarted();
    await settle(600);
    e.thinking();
    await settle(600);
    e.tool("Bash", { command: "pytest" });
    await settle(600);
    expect(sent.map(event => event.phase)).toEqual(["turn_started"]);
    await settle(2000);
    expect(sent.map(event => [event.phase, event.seq])).toEqual([["turn_started", 1], ["turn_started", 2], ["tool", 3]]);
  });

  test("turn_ended waits out a pause and is still sent", async () => {
    optIn();
    const e = emitter();
    outcomes = [{ kind: "rate_limited", retryAfterSeconds: 2 }];
    e.turnStarted();
    await settle();
    e.turnEnded();
    await settle(1000);
    expect(sent.map(event => event.phase)).toEqual(["turn_started"]);
    await settle(1000);
    expect(sent.map(event => event.phase)).toEqual(["turn_started", "turn_started", "turn_ended"]);
  });

  test("events taken together before a 429 keep their order after the pause", async () => {
    optIn();
    const e = emitter();
    outcomes = [{ kind: "rate_limited", retryAfterSeconds: 2 }];
    e.turnStarted();
    e.turnEnded();
    e.turnStarted();
    e.turnEnded();
    await settle();
    expect(sent.map(event => event.phase)).toEqual(["turn_started"]);
    await settle(2000);
    expect(sent.map(event => [event.phase, event.seq])).toEqual([
      ["turn_started", 1], ["turn_started", 2], ["turn_ended", 3], ["turn_started", 1], ["turn_ended", 2],
    ]);
  });

  test("a boundary that draws a 429 is sent once, after Retry-After", async () => {
    optIn();
    const e = emitter();
    outcomes = [{ kind: "accepted" }, { kind: "rate_limited", retryAfterSeconds: 2 }];
    e.turnStarted();
    await settle();
    e.turnEnded();
    await settle();
    expect(sent.map(event => event.phase)).toEqual(["turn_started", "turn_ended"]);
    await settle(1999);
    expect(sent).toHaveLength(2);
    await settle(1);
    expect(sent.map(event => event.phase)).toEqual(["turn_started", "turn_ended", "turn_ended"]);
    await settle(5000);
    expect(sent).toHaveLength(3);
  });

  test("a state that draws a 429 does not come back", async () => {
    optIn();
    const e = emitter();
    outcomes = [{ kind: "accepted" }, { kind: "rate_limited", retryAfterSeconds: 2 }];
    e.turnStarted();
    await settle(600);
    e.tool("Bash", { command: "pytest" });
    await settle();
    await settle(5000);
    expect(sent.map(event => event.phase)).toEqual(["turn_started", "tool"]);
  });

  test("a refused session drops that event only", async () => {
    optIn();
    const e = emitter();
    outcomes = [{ kind: "session_refused" }];
    e.chatWakeDelivered(SESSION, { encrypted: false });
    e.turnStarted();
    e.turnEnded();
    e.turnStarted();
    await settle();
    expect(sent.map(event => event.phase)).toEqual(["turn_started", "turn_ended", "turn_started"]);
  });

  test("an absent route stops publishing for the process and logs once", async () => {
    optIn();
    const e = emitter();
    outcomes = [{ kind: "route_absent" }];
    e.turnStarted();
    e.turnEnded();
    e.turnStarted();
    e.turnEnded();
    await settle(2000);
    expect(sent.map(event => event.phase)).toEqual(["turn_started"]);
    expect(logs.filter(line => line.includes("activity"))).toHaveLength(1);
  });

  test("a failed publish drops the event and publishing continues", async () => {
    optIn();
    const e = emitter();
    outcomes = [{ kind: "failed" }];
    e.turnStarted();
    e.turnEnded();
    await settle();
    expect(sent.map(event => event.phase)).toEqual(["turn_started", "turn_ended"]);
  });
});

describe("drained", () => {
  test("resolves once every queued event has been published", async () => {
    vi.useRealTimers();
    optIn();
    let resolvePublish: (outcome: PublishOutcome) => void = () => {};
    const e = emitter({
      publish: async (body: SignedActivity) => {
        sent.push(JSON.parse(Buffer.from(body.signed_payload, "base64url").toString("utf8")));
        return new Promise<PublishOutcome>(resolve => { resolvePublish = resolve; });
      },
    });
    e.turnStarted();
    let done = false;
    const drained = e.drained().then(() => { done = true; });
    await new Promise(resolve => setTimeout(resolve, 20));
    expect(done).toBe(false);
    resolvePublish({ kind: "accepted" });
    await drained;
    expect(done).toBe(true);
    expect(sent.map(event => event.phase)).toEqual(["turn_started"]);
  });

  test("resolves at once when nothing is queued", async () => {
    vi.useRealTimers();
    await expect(emitter().drained()).resolves.toBeUndefined();
  });
});

