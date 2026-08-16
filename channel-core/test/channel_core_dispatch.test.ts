import { describe, expect, test, vi } from "vitest";
import { readFileSync } from "node:fs";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  consumeAgentEvents,
  DeliveryStore,
  UndeliveredLog,
  dispatchAgentEvent,
  formatAwakeningForAgent,
  PinStore,
  PinStoreCASConflictError,
  type AgentEvent,
  type ChannelAwakening,
  SenderTrustManager,
  startChannelLoop,
} from "../src/index.js";
import { canonicalJSON, signMessage, type MessageEnvelope } from "../src/identity/signing.js";

const testDir = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(
  readFileSync(join(testDir, "vectors.json"), "utf-8"),
) as {
  seed: string;
  did: string;
  stableID: string;
};

function b64ToBytes(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value, "base64"));
}

describe("channel-core dispatchAgentEvent", () => {
  const self = {
    alias: "eve",
    address: "acme.com/eve",
    did: "did:key:self-eve",
    stableID: "did:aw:self-eve",
  };

  const trust = {
    normalizeResolvedTrust: vi.fn(async () => ({ status: "verified", stored: false })),
  } as unknown as SenderTrustManager;
  const acceptingPinStoreWriter = {
    compareAndSet: vi.fn(async () => {}),
  };

  test("pending mid-turn mail does not block control events from the SSE stream", async () => {
    let finishMail: (() => void) | undefined;
    const awakenings: ChannelAwakening[] = [];
    const onAwakening = vi.fn((awakening: ChannelAwakening) => {
      awakenings.push(awakening);
      if (awakening.kind === "mail") {
        return new Promise<void>((resolve) => { finishMail = resolve; });
      }
      return Promise.resolve();
    });
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: "mail-lane-1",
          from_agent_id: "agent-1",
          from_alias: "alice",
          from_address: "acme.com/alice",
          to_alias: "eve",
          subject: "hello",
          body: "mid-turn",
          priority: "normal",
          created_at: "2025-01-01T00:00:00Z",
        }],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };
    async function* events(): AsyncGenerator<AgentEvent> {
      yield { type: "mail_message", message_id: "mail-lane-1" };
      yield { type: "control_interrupt", signal_id: "interrupt-1" };
    }

    const consuming = consumeAgentEvents(
      { client: client as never, pinStore: new PinStore(), trust, self, onAwakening },
      new Set(),
      events(),
    );
    await vi.waitFor(() => expect(awakenings.some((item) => item.kind === "control")).toBe(true));

    expect(awakenings.some((item) => item.kind === "mail")).toBe(true);
    expect(client.post).not.toHaveBeenCalled();
    finishMail?.();
    await consuming;
    expect(client.post).toHaveBeenCalledWith("/v1/messages/mail-lane-1/ack");
  });

  test("traces a blocked mail lane without leaking message content", async () => {
    let finishFirstMail: (() => void) | undefined;
    const traces: Array<Record<string, unknown>> = [];
    const onAwakening = vi.fn((awakening: ChannelAwakening) => {
      if (awakening.meta.message_id === "mail-trace-1") {
        return new Promise<void>((resolve) => { finishFirstMail = resolve; });
      }
      return Promise.resolve();
    });
    const mail = (id: string, body: string) => ({
      message_id: id,
      conversation_id: `conversation-${id}`,
      from_agent_id: "agent-1",
      from_alias: "alice",
      from_address: "acme.com/alice",
      to_alias: "eve",
      subject: `subject-${id}`,
      body,
      priority: "normal",
      created_at: "2025-01-01T00:00:00Z",
    });
    const client = {
      get: vi.fn(async (path: string) => {
        if (path.includes("mail-trace-1")) return { messages: [mail("mail-trace-1", "SECRET-FIRST-BODY")] };
        return { messages: [mail("mail-trace-2", "SECRET-SECOND-BODY")] };
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };
    async function* events(): AsyncGenerator<AgentEvent> {
      yield {
        type: "mail_message",
        message_id: "mail-trace-1",
        subject: "SECRET-FRAME-SUBJECT",
        text: "SECRET-FRAME-TEXT",
        from_alias: "SECRET-FRAME-SENDER",
        title: "SECRET-FRAME-TITLE",
      };
      yield { type: "mail_message", message_id: "mail-trace-2" };
      yield { type: "control_interrupt", signal_id: "control-trace" };
    }

    const consuming = consumeAgentEvents(
      {
        client: client as never,
        pinStore: new PinStore(),
        trust,
        self,
        onAwakening,
        onTrace: (entry: Record<string, unknown>) => traces.push(entry),
      } as never,
      new Set(),
      events(),
    );
    await vi.waitFor(() => expect(onAwakening).toHaveBeenCalledWith(expect.objectContaining({
      kind: "control",
    })));

    expect(traces).toContainEqual(expect.objectContaining({
      stage: "event_enqueued", event_type: "mail_message", message_id: "mail-trace-2", lane: "mail",
    }));
    expect(traces).toContainEqual(expect.objectContaining({
      stage: "lane_job_started", message_id: "mail-trace-1", lane: "mail",
    }));
    expect(traces).not.toContainEqual(expect.objectContaining({
      stage: "lane_job_started", message_id: "mail-trace-2", lane: "mail",
    }));
    expect(traces).toContainEqual(expect.objectContaining({
      stage: "lane_job_started", event_type: "control_interrupt",
    }));
    expect(traces).toContainEqual(expect.objectContaining({
      stage: "notification_started", message_id: "mail-trace-1",
    }));
    expect(traces).not.toContainEqual(expect.objectContaining({
      stage: "notification_accepted", message_id: "mail-trace-1",
    }));
    expect(JSON.stringify(traces)).not.toContain("SECRET-");
    const allowedKeys = new Set([
      "component", "conversation_id", "event_type", "lane", "message_id",
      "session_id", "stage", "ts",
    ]);
    for (const trace of traces) {
      expect(Object.keys(trace).filter((key) => !allowedKeys.has(key))).toEqual([]);
      expect(Object.keys(trace)).toEqual(expect.arrayContaining([
        "component", "event_type", "stage", "ts",
      ]));
    }

    finishFirstMail?.();
    await consuming;
    expect(traces).toContainEqual(expect.objectContaining({
      stage: "notification_accepted", message_id: "mail-trace-1",
    }));
    expect(traces).toContainEqual(expect.objectContaining({
      stage: "lane_job_started", message_id: "mail-trace-2", lane: "mail",
    }));
  });

  test("distinguishes waiting for the trust lock from work after acquisition", async () => {
    const pinStore = new PinStore();
    let releaseLock: (() => void) | undefined;
    const holdingLock = pinStore.runExclusive(() => new Promise<void>((resolve) => {
      releaseLock = resolve;
    }));
    const traces: Array<Record<string, unknown>> = [];
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: "mail-lock-trace",
          conversation_id: "conversation-lock-trace",
          from_agent_id: "agent-1",
          from_alias: "alice",
          from_address: "acme.com/alice",
          to_alias: "eve",
          subject: "hello",
          body: "world",
          priority: "normal",
          created_at: "2025-01-01T00:00:00Z",
        }],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };
    const dispatching = dispatchAgentEvent(
      {
        client: client as never,
        pinStore,
        trust,
        self,
        onAwakening: vi.fn(),
        onTrace: (entry) => traces.push(entry),
      },
      new Set(),
      { type: "mail_message", message_id: "mail-lock-trace" },
    );

    await vi.waitFor(() => expect(traces).toContainEqual(expect.objectContaining({
      stage: "trust_started", message_id: "mail-lock-trace",
    })));
    expect(traces).not.toContainEqual(expect.objectContaining({
      stage: "lock_acquired", message_id: "mail-lock-trace",
    }));

    releaseLock?.();
    await holdingLock;
    await dispatching;
    expect(traces).toContainEqual(expect.objectContaining({
      stage: "lock_acquired", message_id: "mail-lock-trace",
    }));
  });

  test("resolves sender metadata before entering the trust critical section", async () => {
    let finishResolution!: (value: undefined) => void;
    const resolutionPending = new Promise<undefined>((resolve) => {
      finishResolution = resolve;
    });
    const resolvingTrust = {
      resolveTrustMetadata: vi.fn(() => resolutionPending),
      normalizeResolvedTrust: vi.fn(async () => ({ status: "verified", stored: false })),
    } as unknown as SenderTrustManager;
    const pinStore = new PinStore();
    const runExclusive = vi.spyOn(pinStore, "runExclusive");
    const traces: Array<Record<string, unknown>> = [];
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: "mail-resolve-before-lock",
          conversation_id: "conversation-resolve-before-lock",
          from_agent_id: "agent-1",
          from_alias: "alice",
          from_address: "acme.com/alice",
          to_alias: "eve",
          subject: "hello",
          body: "world",
          priority: "normal",
          created_at: "2025-01-01T00:00:00Z",
        }],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };

    const dispatching = dispatchAgentEvent(
      {
        client: client as never,
        pinStore,
        trust: resolvingTrust,
        self,
        onAwakening: vi.fn(),
        onTrace: (entry) => traces.push(entry),
      },
      new Set(),
      { type: "mail_message", message_id: "mail-resolve-before-lock" },
    );

    await vi.waitFor(() => expect(resolvingTrust.resolveTrustMetadata).toHaveBeenCalledTimes(1));
    expect(runExclusive).not.toHaveBeenCalled();
    expect(traces).toContainEqual(expect.objectContaining({
      stage: "trust_started", message_id: "mail-resolve-before-lock",
    }));
    expect(traces).not.toContainEqual(expect.objectContaining({
      stage: "lock_acquired", message_id: "mail-resolve-before-lock",
    }));

    finishResolution(undefined);
    await dispatching;
    expect(runExclusive).toHaveBeenCalledTimes(1);
    expect(resolvingTrust.normalizeResolvedTrust).toHaveBeenCalledTimes(1);
    expect(traces).toContainEqual(expect.objectContaining({
      stage: "lock_acquired", message_id: "mail-resolve-before-lock",
    }));
  });

  test("shares one hanging roster failure across chat lanes and reuses the cached stale verdict", async () => {
    let now = 0;
    let rejectRoster!: (error: Error) => void;
    const rosterPending = new Promise<never>((_resolve, reject) => {
      rejectRoster = reject;
    });
    const neverResolveRoster = new Promise<never>(() => {});
    const rosterRequests = vi.fn()
      .mockImplementationOnce(() => rosterPending)
      .mockImplementationOnce(() => neverResolveRoster);
    const sessionIDs = Array.from({ length: 5 }, (_, index) => `burst-session-${index + 1}`);
    const envelopes = await Promise.all(sessionIDs.map(async (sessionID, index) => {
      const env: MessageEnvelope = {
        from: "alice",
        from_did: vectors.did,
        to: self.alias,
        to_did: self.did,
        type: "chat",
        subject: "",
        body: `burst ${index + 1}`,
        timestamp: `2025-01-01T00:00:0${index}Z`,
        message_id: `burst-message-${index + 1}`,
        conversation_id: sessionID,
      };
      return { env, signature: await signMessage(b64ToBytes(vectors.seed), env) };
    }));
    const client = {
      hasTeamCertificateAuth: (teamID: string) => teamID === "backend:acme.com",
      get: vi.fn(async (path: string) => {
        if (path === "/v1/agents") return rosterRequests();
        const item = envelopes.find(({ env }) => path.includes(env.conversation_id!));
        expect(item).toBeDefined();
        const { env, signature } = item!;
        return {
          messages: [{
            message_id: env.message_id,
            conversation_id: env.conversation_id,
            from_agent: "alice",
            from_address: env.from,
            to_address: env.to,
            body: env.body,
            timestamp: env.timestamp,
            sender_leaving: false,
            from_did: vectors.did,
            to_did: self.did,
            signature,
            signing_key_id: vectors.did,
            signed_payload: canonicalJSON(env),
          }],
        };
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };
    const trust = new SenderTrustManager(
      client as never,
      { verifyStableIdentity: vi.fn() } as never,
      "backend:acme.com",
      self.did,
      self.stableID,
      () => now,
      () => 0,
    );
    const awakenings: ChannelAwakening[] = [];
    const log = vi.fn();
    async function* burstEvents(): AsyncGenerator<AgentEvent> {
      for (const { env } of envelopes.slice(0, 4)) {
        yield {
          type: "chat_message",
          session_id: env.conversation_id,
          conversation_id: env.conversation_id,
          message_id: env.message_id,
        };
      }
    }
    const consuming = consumeAgentEvents(
      {
        client: client as never,
        pinStore: new PinStore(),
        trust,
        self,
        onAwakening: (awakening) => { awakenings.push(awakening); },
      },
      new Set(),
      burstEvents(),
      log,
    );

    await vi.waitFor(() => expect(rosterRequests).toHaveBeenCalledTimes(1));
    expect(awakenings).toHaveLength(0);
    rejectRoster(new Error("roster request timed out"));
    await consuming;

    expect(awakenings).toHaveLength(4);
    expect(awakenings.map((item) => item.meta.trust_status)).toEqual([
      "verification_stale",
      "verification_stale",
      "verification_stale",
      "verification_stale",
    ]);
    expect(log).not.toHaveBeenCalled();

    now = 5_000;
    const fifth = envelopes[4].env;
    const fifthDispatch = dispatchAgentEvent(
      {
        client: client as never,
        pinStore: new PinStore(),
        trust,
        self,
        onAwakening: (awakening) => { awakenings.push(awakening); },
      },
      new Set(),
      {
        type: "chat_message",
        session_id: fifth.conversation_id,
        conversation_id: fifth.conversation_id,
        message_id: fifth.message_id,
      },
    );
    await vi.waitFor(() => expect(awakenings).toHaveLength(5), { timeout: 200 });
    await fifthDispatch;
    expect(awakenings[4].meta.trust_status).toBe("verification_stale");
    expect(rosterRequests).toHaveBeenCalledTimes(1);
  });

  test("acks mail after channel delivery succeeds", async () => {
    const onAwakening = vi.fn();
    const traces: Array<Record<string, unknown>> = [];
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: "mail-1",
          from_agent_id: "agent-1",
          from_alias: "alice",
          from_address: "acme.com/alice",
          to_alias: "eve",
          subject: "hello",
          body: "world",
          priority: "normal",
          created_at: "2025-01-01T00:00:00Z",
        }],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };

    await dispatchAgentEvent(
      {
        client: client as never,
        pinStore: new PinStore(),
        trust,
        self,
        onAwakening,
        onTrace: (entry) => traces.push(entry),
      },
      new Set(),
      { type: "mail_message", message_id: "mail-1" } satisfies AgentEvent,
    );

    expect(onAwakening).toHaveBeenCalledWith(expect.objectContaining<Partial<ChannelAwakening>>({
      kind: "mail",
      content: "world",
    }));
    expect(client.post).toHaveBeenCalledWith("/v1/messages/mail-1/ack");
    expect(traces.map((entry) => entry.stage)).toEqual([
      "exact_fetch_started",
      "exact_fetch_completed",
      "decrypt_started",
      "decrypt_completed",
      "trust_started",
      "lock_acquired",
      "trust_completed",
      "notification_started",
      "notification_accepted",
      "durable_mark_started",
      "durable_mark_completed",
      "ack_started",
      "ack_completed",
    ]);
  });

  test("delivery-store lock failure rejects without creating an in-memory acknowledgment path", { timeout: 15_000 }, async () => {
    const storePath = join(await mkdtemp(join(tmpdir(), "aweb-channel-lock-fail-")), "delivered.json");
    const deliveryStore = await DeliveryStore.load(storePath);
    await mkdir(`${storePath}.lock`);
    const dispatched = new Set<string>();
    const onAwakening = vi.fn();
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: "mail-lock-fail",
          conversation_id: "conv-lock-fail",
          from_agent_id: "agent-1",
          from_alias: "alice",
          from_address: "acme.com/alice",
          to_alias: "eve",
          subject: "hello",
          body: "must remain pending",
          priority: "normal",
          created_at: "2025-01-01T00:00:00Z",
        }],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };

    await expect(dispatchAgentEvent(
      { client: client as never, pinStore: new PinStore(), trust, self, deliveryStore, onAwakening },
      dispatched,
      { type: "mail_message", message_id: "mail-lock-fail" } satisfies AgentEvent,
    )).rejects.toMatchObject({ code: "ELOCKED" });

    expect(onAwakening).toHaveBeenCalledTimes(1);
    expect(dispatched).toHaveLength(0);
    expect(deliveryStore.has("mail:conv-lock-fail:mail-lock-fail")).toBe(false);
    expect(client.post).not.toHaveBeenCalled();
  });

  test("event-loop logs name the quarantined store and leave upstream acknowledgment pending", async () => {
    const storePath = join(await mkdtemp(join(tmpdir(), "aweb-channel-corrupt-")), "delivered.json");
    const deliveryStore = await DeliveryStore.load(storePath);
    await writeFile(storePath, "{corrupt delivery state\n", "utf8");
    const onAwakening = vi.fn();
    const log = vi.fn();
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: "mail-corrupt-store",
          conversation_id: "conv-corrupt-store",
          from_agent_id: "agent-1",
          from_alias: "alice",
          from_address: "acme.com/alice",
          to_alias: "eve",
          subject: "hello",
          body: "must remain pending",
          priority: "normal",
          created_at: "2025-01-01T00:00:00Z",
        }],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };
    async function* events(): AsyncGenerator<AgentEvent> {
      yield { type: "mail_message", message_id: "mail-corrupt-store" };
    }

    await consumeAgentEvents(
      { client: client as never, pinStore: new PinStore(), trust, self, deliveryStore, onAwakening },
      new Set(),
      events(),
      log,
    );

    expect(onAwakening).toHaveBeenCalledTimes(1);
    expect(log).toHaveBeenCalledWith(expect.stringMatching(/quarantined at .*\.corrupt-/i));
    expect(client.post).not.toHaveBeenCalled();
  });

  test("does not deliver or acknowledge a message when pin persistence fails", async () => {
    const onAwakening = vi.fn();
    const pinStore = new PinStore();
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: "mail-pin-failure",
          from_agent_id: "agent-1",
          from_alias: "alice",
          from_address: "acme.com/alice",
          to_alias: "eve",
          subject: "hello",
          body: "must not be delivered",
          priority: "normal",
          created_at: "2025-01-01T00:00:00Z",
        }],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };
    let trustAttempt = 0;
    const storingTrust = {
      normalizeResolvedTrust: vi.fn(async (store: PinStore) => {
        trustAttempt += 1;
        if (trustAttempt === 1) {
          store.storePin("did:key:zAlice", "acme.com/alice", "", "");
          return { status: "verified", stored: true };
        }
        return { status: "verified", stored: false };
      }),
    } as unknown as SenderTrustManager;
    const expectedYAMLs: string[] = [];
    const desiredYAMLs: string[] = [];
    const pinStoreWriter = {
      compareAndSet: vi.fn(async (_path: string, expectedYAML: string, desiredYAML: string) => {
        expectedYAMLs.push(expectedYAML);
        desiredYAMLs.push(desiredYAML);
        throw new Error("aw binary missing");
      }),
    };

    await expect(dispatchAgentEvent(
      { client: client as never, pinStore, pinStoreWriter, trust: storingTrust, self, onAwakening },
      new Set(),
      { type: "mail_message", message_id: "mail-pin-failure" } satisfies AgentEvent,
    )).rejects.toThrow(/aw binary missing/);

    // The failed mutation remains undurable. Even if a retry's trust decision
    // makes no further change, it must retry persistence and stay closed.
    await expect(dispatchAgentEvent(
      { client: client as never, pinStore, pinStoreWriter, trust: storingTrust, self, onAwakening },
      new Set(),
      { type: "mail_message", message_id: "mail-pin-failure" } satisfies AgentEvent,
    )).rejects.toThrow(/aw binary missing/);

    expect(pinStoreWriter.compareAndSet).toHaveBeenCalledTimes(2);
    expect(expectedYAMLs).toHaveLength(2);
    expect(expectedYAMLs[1]).toBe(expectedYAMLs[0]);
    for (const expectedYAML of expectedYAMLs) {
      const expected = PinStore.fromYAML(expectedYAML);
      expect(expected.pins.size).toBe(0);
      expect(expected.addresses.size).toBe(0);
    }
    expect(desiredYAMLs).toHaveLength(2);
    expect(desiredYAMLs[1]).toBe(desiredYAMLs[0]);
    for (const desiredYAML of desiredYAMLs) {
      const desired = PinStore.fromYAML(desiredYAML);
      expect(desired.addresses.get("acme.com/alice")).toBe("did:key:zAlice");
      expect(desired.pins.get("did:key:zAlice")?.address).toBe("acme.com/alice");
    }
    expect(onAwakening).not.toHaveBeenCalled();
    expect(client.post).not.toHaveBeenCalled();
  });

  test("serializes trust decisions through pin persistence", async () => {
    let trustAttempt = 0;
    const trustGate = {
      normalizeResolvedTrust: vi.fn(async (store: PinStore) => {
        trustAttempt += 1;
        if (trustAttempt === 1) {
          store.storePin("did:key:zAlice", "acme.com/alice", "", "");
        } else {
          store.storePin("did:key:zBob", "acme.com/bob", "", "");
        }
        return { status: "verified", stored: true };
      }),
    } as unknown as SenderTrustManager;
    let signalCommitEntered!: () => void;
    const commitEntered = new Promise<void>((resolve) => { signalCommitEntered = resolve; });
    let releaseCommit!: () => void;
    const commitRelease = new Promise<void>((resolve) => { releaseCommit = resolve; });
    let firstDesiredYAML = "";
    const pinStoreWriter = {
      compareAndSet: vi.fn(async (_path: string, expectedYAML: string, desiredYAML: string) => {
        if (!firstDesiredYAML) {
          expect(PinStore.fromYAML(expectedYAML).pins.size).toBe(0);
          firstDesiredYAML = desiredYAML;
          signalCommitEntered();
          await commitRelease;
          return;
        }
        expect(expectedYAML).toBe(firstDesiredYAML);
        const expected = PinStore.fromYAML(expectedYAML);
        expect(expected.addresses.get("acme.com/alice")).toBe("did:key:zAlice");
        const desired = PinStore.fromYAML(desiredYAML);
        expect(desired.addresses.get("acme.com/alice")).toBe("did:key:zAlice");
        expect(desired.addresses.get("acme.com/bob")).toBe("did:key:zBob");
      }),
    };
    const message = (id: string) => ({
      message_id: id,
      from_agent_id: "agent-1",
      from_alias: "alice",
      from_address: "acme.com/alice",
      to_alias: "eve",
      subject: "hello",
      body: id,
      priority: "normal",
      created_at: "2025-01-01T00:00:00Z",
    });
    const client = {
      get: vi.fn()
        .mockResolvedValueOnce({ messages: [message("mail-serialize-1")] })
        .mockResolvedValueOnce({ messages: [message("mail-serialize-2")] }),
      post: vi.fn().mockResolvedValue(undefined),
    };
    const pinStore = new PinStore();
    const runExclusive = vi.spyOn(pinStore, "runExclusive");
    const options = {
      client: client as never,
      pinStore,
      pinStoreWriter,
      trust: trustGate,
      self,
      onAwakening: vi.fn(),
    };

    const first = dispatchAgentEvent(
      options,
      new Set(),
      { type: "mail_message", message_id: "mail-serialize-1" } satisfies AgentEvent,
    );
    await commitEntered;
    const second = dispatchAgentEvent(
      options,
      new Set(),
      { type: "mail_message", message_id: "mail-serialize-2" } satisfies AgentEvent,
    );
    await vi.waitFor(() => expect(runExclusive).toHaveBeenCalledTimes(2));
    expect(trustGate.normalizeResolvedTrust).toHaveBeenCalledTimes(1);

    releaseCommit();
    await Promise.all([first, second]);

    expect(trustGate.normalizeResolvedTrust).toHaveBeenCalledTimes(2);
    expect(pinStoreWriter.compareAndSet).toHaveBeenCalledTimes(2);
  });

  test("retries a whole trust decision after a CAS reload without resolving inside the lock", async () => {
    const onAwakening = vi.fn();
    const dir = await mkdtemp(join(tmpdir(), "aw-pin-conflict-reload-"));
    const pinStorePath = join(dir, "known_agents.yaml");
    const durable = new PinStore();
    durable.storePin("did:key:zBob", "backend:acme.com/bob", "", "");
    await writeFile(pinStorePath, durable.toYAML(), "utf-8");

    const env: MessageEnvelope = {
      from: "backend:acme.com/alice",
      from_did: vectors.did,
      from_stable_id: vectors.stableID,
      to: self.address,
      to_did: self.did,
      to_stable_id: self.stableID,
      type: "mail",
      subject: "hello",
      body: "retry after reload",
      timestamp: "2025-01-01T00:00:00Z",
      message_id: "mail-pin-conflict",
    };
    const signature = await signMessage(b64ToBytes(vectors.seed), env);
    let lockHeld = false;
    const rosterRequests = vi.fn();
    const client = {
      hasTeamCertificateAuth: (teamID: string) => teamID === "backend:acme.com",
      get: vi.fn(async (path: string) => {
        if (path === "/v1/agents") {
          expect(lockHeld).toBe(false);
          rosterRequests();
          return {
            team_id: "backend:acme.com",
            agents: [{
              alias: "alice",
              address: env.from,
              did_key: vectors.did,
              did_aw: vectors.stableID,
              identity_scope: "global",
            }],
          };
        }
        expect(path).toContain("/v1/messages/inbox?");
        return {
          messages: [{
            message_id: env.message_id,
            from_agent_id: "agent-1",
            from_alias: "alice",
            from_address: env.from,
            from_did: vectors.stableID,
            from_stable_id: vectors.stableID,
            to_alias: self.alias,
            to_did: self.stableID,
            to_stable_id: self.stableID,
            subject: env.subject,
            body: env.body,
            priority: "normal",
            created_at: env.timestamp,
            signature,
            signing_key_id: vectors.did,
            signed_payload: canonicalJSON(env),
          }],
        };
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };
    const registry = {
      resolveIdentity: vi.fn(async () => {
        expect(lockHeld).toBe(false);
        throw new Error("team aliases must use the authenticated roster");
      }),
      verifyStableIdentity: vi.fn(async () => {
        expect(lockHeld).toBe(false);
        return { outcome: "OK_DEGRADED" };
      }),
    };
    const trustAfterReload = new SenderTrustManager(
      client as never,
      registry as never,
      "backend:acme.com",
      self.did,
      self.stableID,
    );
    const pinStore = new PinStore();
    const originalRunExclusive = pinStore.runExclusive.bind(pinStore);
    const runExclusive = vi.spyOn(pinStore, "runExclusive").mockImplementation(async (operation) => (
      originalRunExclusive(async () => {
        expect(lockHeld).toBe(false);
        lockHeld = true;
        try {
          return await operation();
        } finally {
          lockHeld = false;
        }
      })
    ));
    const trustInternals = trustAfterReload as unknown as {
      resolveAgentMeta(address: string): Promise<unknown>;
    };
    const originalResolveAgentMeta = trustInternals.resolveAgentMeta.bind(trustAfterReload);
    const resolutionLockStates: boolean[] = [];
    vi.spyOn(trustInternals, "resolveAgentMeta").mockImplementation(async (address) => {
      resolutionLockStates.push(lockHeld);
      return originalResolveAgentMeta(address);
    });
    const prepareMetadata = vi.spyOn(trustAfterReload, "resolveTrustMetadata");

    let writeAttempt = 0;
    const pinStoreWriter = {
      compareAndSet: vi.fn(async (_path: string, expectedYAML: string, desiredYAML: string) => {
        writeAttempt += 1;
        const desired = PinStore.fromYAML(desiredYAML);
        expect(desired.addresses.get(env.from)).toBe(vectors.stableID);
        if (writeAttempt === 1) {
          throw new PinStoreCASConflictError("trust pin store changed since it was read");
        }
        const expected = PinStore.fromYAML(expectedYAML);
        expect(expected.toYAML()).toBe(durable.toYAML());
        expect(expected.addresses.get("backend:acme.com/bob")).toBe("did:key:zBob");
        expect(desired.addresses.get("backend:acme.com/bob")).toBe("did:key:zBob");
        await writeFile(pinStorePath, desiredYAML, "utf-8");
      }),
    };

    await dispatchAgentEvent(
      {
        client: client as never,
        pinStore,
        pinStorePath,
        pinStoreWriter,
        trust: trustAfterReload,
        self,
        onAwakening,
      },
      new Set(),
      { type: "mail_message", message_id: env.message_id } satisfies AgentEvent,
    );

    const persisted = PinStore.fromYAML(await readFile(pinStorePath, "utf-8"));
    expect(persisted.addresses.get("backend:acme.com/bob")).toBe("did:key:zBob");
    expect(persisted.addresses.get(env.from)).toBe(vectors.stableID);
    expect(onAwakening).toHaveBeenCalledTimes(1);
    expect(client.post).toHaveBeenCalledTimes(1);
    expect(runExclusive).toHaveBeenCalledTimes(2);
    expect(prepareMetadata).toHaveBeenCalledTimes(2);
    expect(resolutionLockStates).toEqual([false, false]);
    expect(rosterRequests).toHaveBeenCalledTimes(1);
    expect(registry.resolveIdentity).not.toHaveBeenCalled();
  });

  test("leaves an event pending after three pin-store CAS attempts", async () => {
    const onAwakening = vi.fn();
    const dir = await mkdtemp(join(tmpdir(), "aw-pin-conflict-exhausted-"));
    const pinStorePath = join(dir, "known_agents.yaml");
    await writeFile(pinStorePath, new PinStore().toYAML(), "utf-8");
    const preparedMetadata = new Set<object>();
    const trustWithFreshMetadata = {
      resolveTrustMetadata: vi.fn(async () => {
        const prepared = {};
        preparedMetadata.add(prepared);
        return prepared;
      }),
      normalizeResolvedTrust: vi.fn(async (store: PinStore, ...args: unknown[]) => {
        const prepared = args.at(-1) as object;
        expect(preparedMetadata.delete(prepared)).toBe(true);
        store.storePin("did:key:zAlice", "acme.com/alice", "", "");
        return { status: "verified", stored: true };
      }),
    } as unknown as SenderTrustManager;
    const pinStoreWriter = {
      compareAndSet: vi.fn(async () => {
        throw new PinStoreCASConflictError("trust pin store changed since it was read");
      }),
    };
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: "mail-pin-conflict-exhausted",
          from_agent_id: "agent-1",
          from_alias: "alice",
          from_address: "acme.com/alice",
          to_alias: "eve",
          subject: "hello",
          body: "remain pending",
          priority: "normal",
          created_at: "2025-01-01T00:00:00Z",
        }],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };

    await expect(dispatchAgentEvent(
      {
        client: client as never,
        pinStore: new PinStore(),
        pinStorePath,
        pinStoreWriter,
        trust: trustWithFreshMetadata,
        self,
        onAwakening,
      },
      new Set(),
      { type: "mail_message", message_id: "mail-pin-conflict-exhausted" } satisfies AgentEvent,
    )).rejects.toBeInstanceOf(PinStoreCASConflictError);

    expect(pinStoreWriter.compareAndSet).toHaveBeenCalledTimes(3);
    expect(trustWithFreshMetadata.resolveTrustMetadata).toHaveBeenCalledTimes(3);
    expect(trustWithFreshMetadata.normalizeResolvedTrust).toHaveBeenCalledTimes(3);
    expect(onAwakening).not.toHaveBeenCalled();
    expect(client.post).not.toHaveBeenCalled();
  });

  test("skips and leaves unread only the inbox message whose verification throws", async () => {
    const poisonMessage = {
      message_id: "mail-poison",
      from_agent_id: "agent-1",
      from_alias: "alice",
      from_address: "acme.com/alice",
      to_alias: self.alias,
      to_address: self.address,
      subject: "poison",
      body: "malformed transport record",
      priority: "normal",
      created_at: "2025-01-01T00:00:00Z",
      get signed_payload(): string {
        throw new Error("unexpected per-message verification failure");
      },
    };
    const onAwakening = vi.fn();
    const log = vi.fn();
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [poisonMessage, {
          message_id: "mail-good",
          from_agent_id: "agent-1",
          from_alias: "alice",
          from_address: "acme.com/alice",
          to_alias: self.alias,
          subject: "good",
          body: "still delivered",
          priority: "normal",
          created_at: "2025-01-01T00:00:01Z",
        }],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };
    async function* events(): AsyncGenerator<AgentEvent> {
      yield { type: "mail_message", message_id: "mail-poison" };
    }

    await consumeAgentEvents(
      { client: client as never, pinStore: new PinStore(), trust, self, onAwakening },
      new Set(),
      events(),
      log,
    );

    expect(poisonMessage as Record<string, unknown>).toMatchObject({
      verification_status: "failed",
      verification_error: true,
    });
    expect(onAwakening).toHaveBeenCalledTimes(1);
    expect(onAwakening).toHaveBeenCalledWith(expect.objectContaining<Partial<ChannelAwakening>>({
      kind: "mail",
      content: "still delivered",
    }));
    expect(client.post).not.toHaveBeenCalledWith("/v1/messages/mail-poison/ack");
    expect(client.post).toHaveBeenCalledWith("/v1/messages/mail-good/ack");
    expect(log).toHaveBeenCalledWith(expect.stringContaining("mail-poison"));
    expect(log).toHaveBeenCalledWith(
      "aweb: skipped verification for 1 inbox message; it remains unread",
    );
  });

  test("records a durable entry for the message it declined to present", async () => {
    const undeliveredPath = join(
      await mkdtemp(join(tmpdir(), "aweb-channel-undelivered-")),
      "undelivered.jsonl",
    );
    const undeliveredLog = new UndeliveredLog(undeliveredPath);
    const poisonMessage = {
      message_id: "mail-unrecorded",
      from_agent_id: "agent-1",
      from_alias: "alice",
      from_address: "acme.com/alice",
      to_alias: self.alias,
      to_address: self.address,
      subject: "poison",
      body: "malformed transport record",
      priority: "normal",
      created_at: "2025-01-01T00:00:00Z",
      get signed_payload(): string {
        throw new Error("unexpected per-message verification failure");
      },
    };
    const onAwakening = vi.fn();
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [poisonMessage, {
          message_id: "mail-presented",
          from_agent_id: "agent-1",
          from_alias: "alice",
          from_address: "acme.com/alice",
          to_alias: self.alias,
          subject: "good",
          body: "still delivered",
          priority: "normal",
          created_at: "2025-01-01T00:00:01Z",
        }],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };
    async function* events(): AsyncGenerator<AgentEvent> {
      yield { type: "mail_message", message_id: "mail-unrecorded" };
    }

    await consumeAgentEvents(
      { client: client as never, pinStore: new PinStore(), trust, self, undeliveredLog, onAwakening },
      new Set(),
      events(),
      vi.fn(),
    );

    const entries = (await readFile(undeliveredPath, "utf-8"))
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line) as Record<string, string>);

    expect(entries).toHaveLength(1);
    expect(entries[0]).toMatchObject({
      message_id: "mail-unrecorded",
      reason: "verification_error",
      from: "acme.com/alice",
    });
    expect(Number.isFinite(Date.parse(entries[0].at))).toBe(true);

    // The sibling in the same fetch WAS presented, so it must be absent. Without
    // this, a log that recorded every message would satisfy the assertion above.
    expect(onAwakening).toHaveBeenCalledTimes(1);
    expect(entries.some((entry) => entry.message_id === "mail-presented")).toBe(false);
  });

  test("the real channel loop wires the durable undelivered record into dispatch", async () => {
    const workdir = await mkdtemp(join(tmpdir(), "aweb-channel-wiring-"));
    const controller = new AbortController();
    const poisonMessage = {
      message_id: "mail-wiring-poison",
      from_agent_id: "agent-1",
      from_alias: "alice",
      from_address: "acme.com/alice",
      to_alias: self.alias,
      to_address: self.address,
      subject: "poison",
      body: "malformed transport record",
      priority: "normal",
      created_at: "2025-01-01T00:00:00Z",
      get signed_payload(): string {
        throw new Error("unexpected per-message verification failure");
      },
    };
    const client = {
      openSSE: vi.fn().mockResolvedValue(new Response(
        'event: mail_message\ndata: {"message_id":"mail-wiring-poison"}\n\n',
        { headers: { "content-type": "text/event-stream" } },
      )),
      get: vi.fn().mockResolvedValue({
        messages: [poisonMessage, {
          message_id: "mail-wiring-presented",
          from_agent_id: "agent-1",
          from_alias: "alice",
          from_address: "acme.com/alice",
          to_alias: self.alias,
          subject: "good",
          body: "still delivered",
          priority: "normal",
          created_at: "2025-01-01T00:00:01Z",
        }],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };
    const onAwakening = vi.fn(() => {
      controller.abort();
    });

    await startChannelLoop({
      client: client as never,
      pinStore: new PinStore(),
      trust,
      self,
      signal: controller.signal,
      teamID: "backend:acme.com",
      workdir,
      onAwakening,
    });

    const entries = (await readFile(join(workdir, ".aw", "channel-undelivered.jsonl"), "utf-8"))
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line) as Record<string, string>);
    expect(entries).toEqual([
      expect.objectContaining({
        message_id: "mail-wiring-poison",
        reason: "verification_error",
      }),
    ]);
    expect(onAwakening).toHaveBeenCalledWith(expect.objectContaining({
      kind: "mail",
      content: "still delivered",
    }));
  });

  test("keeps presenting the batch when the undelivered record cannot be written", async () => {
    // The skipped message is deliberately left unread and unacked, so it returns in
    // every unread-only fetch. If a failed audit write aborted the batch, a persistent
    // write failure would livelock: the same message recurs and everything behind it
    // stops being presented, forever. An audit write must not fail the delivery.
    const undeliveredLog = {
      record: vi.fn().mockRejectedValue(new Error("EACCES: permission denied")),
    };
    const poisonMessage = {
      message_id: "mail-unwritable",
      from_agent_id: "agent-1",
      from_alias: "alice",
      from_address: "acme.com/alice",
      to_alias: self.alias,
      to_address: self.address,
      subject: "poison",
      body: "malformed transport record",
      priority: "normal",
      created_at: "2025-01-01T00:00:00Z",
      get signed_payload(): string {
        throw new Error("unexpected per-message verification failure");
      },
    };
    const onAwakening = vi.fn();
    const log = vi.fn();
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [poisonMessage, {
          message_id: "mail-behind-it",
          from_agent_id: "agent-1",
          from_alias: "alice",
          from_address: "acme.com/alice",
          to_alias: self.alias,
          subject: "good",
          body: "must still arrive",
          priority: "normal",
          created_at: "2025-01-01T00:00:01Z",
        }],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };
    async function* events(): AsyncGenerator<AgentEvent> {
      yield { type: "mail_message", message_id: "mail-unwritable" };
    }

    await consumeAgentEvents(
      {
        client: client as never,
        pinStore: new PinStore(),
        trust,
        self,
        undeliveredLog: undeliveredLog as never,
        onAwakening,
      },
      new Set(),
      events(),
      log,
    );

    expect(undeliveredLog.record).toHaveBeenCalledTimes(1);
    // The message behind the unwritable one is still presented.
    expect(onAwakening).toHaveBeenCalledTimes(1);
    expect(onAwakening).toHaveBeenCalledWith(expect.objectContaining<Partial<ChannelAwakening>>({
      kind: "mail",
      content: "must still arrive",
    }));
    // The failure is reported rather than swallowed silently.
    expect(log).toHaveBeenCalledWith(expect.stringContaining("mail-unwritable"));
  });

  test("keeps mail unread while host injection is pending", async () => {
    let finishDelivery: (() => void) | undefined;
    const onAwakening = vi.fn(() => new Promise<void>((resolve) => {
      finishDelivery = resolve;
    }));
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: "mail-pending-injection",
          from_agent_id: "agent-1",
          from_alias: "alice",
          from_address: "acme.com/alice",
          to_alias: "eve",
          subject: "hello",
          body: "wait for turn end",
          priority: "normal",
          created_at: "2025-01-01T00:00:00Z",
        }],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };

    const dispatch = dispatchAgentEvent(
      {
        client: client as never,
        pinStore: new PinStore(),
        trust,
        self,
        onAwakening,
      },
      new Set(),
      { type: "mail_message", message_id: "mail-pending-injection" } satisfies AgentEvent,
    );
    await vi.waitFor(() => expect(onAwakening).toHaveBeenCalledTimes(1));

    expect(client.post).not.toHaveBeenCalled();
    finishDelivery?.();
    await dispatch;
    expect(client.post).toHaveBeenCalledWith("/v1/messages/mail-pending-injection/ack");
  });

  test("keeps captured null-envelope plaintext on the authenticated channel trust path", async () => {
    const onAwakening = vi.fn();
    const env: MessageEnvelope = {
      from: "acme.com/alice",
      from_did: vectors.did,
      to: self.address,
      to_did: self.did,
      to_stable_id: self.stableID,
      type: "mail",
      subject: "plaintext",
      body: "preserved plaintext body",
      timestamp: "2026-05-26T00:00:00Z",
      message_id: "mail-plaintext-null-envelope",
    };
    const signature = await signMessage(b64ToBytes(vectors.seed), env);
    const localDecrypt = { mailMessage: vi.fn(async () => { throw new Error("must not run"); }) };
    const client = {
      hasTeamCertificateAuth: (teamID: string) => teamID === "backend:acme.com",
      get: vi.fn(async (path: string) => path === "/v1/agents" ? {
        team_id: "backend:acme.com",
        agents: [{ alias: "alice", did_key: vectors.did, identity_scope: "local" }],
      } : {
        messages: [{
          message_id: env.message_id,
          from_agent_id: "agent-1",
          from_alias: "alice",
          from_address: env.from,
          from_did: env.from_did,
          to_alias: self.alias,
          to_address: self.address,
          to_did: self.did,
          to_stable_id: self.stableID,
          subject: env.subject,
          body: env.body,
          priority: "normal",
          created_at: env.timestamp,
          signature,
          signing_key_id: vectors.did,
          signed_payload: canonicalJSON(env),
          content_mode: "legacy_plaintext_v1",
          message_version: 1,
          encrypted_envelope: null,
        }],
      }),
      getFresh: vi.fn(),
      post: vi.fn().mockResolvedValue(undefined),
    };
    const authenticatedTrust = new SenderTrustManager(
      client as never,
      { verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }) } as never,
      "backend:acme.com",
      self.did,
      self.stableID,
    );

    await dispatchAgentEvent(
      {
        client: client as never,
        pinStore: new PinStore(),
        trust: authenticatedTrust,
        self,
        onAwakening,
        localDecrypt,
      },
      new Set(),
      { type: "mail_message", message_id: env.message_id } satisfies AgentEvent,
    );

    expect(localDecrypt.mailMessage).not.toHaveBeenCalled();
    expect(client.get).toHaveBeenCalledWith("/v1/agents");
    expect(client.getFresh).not.toHaveBeenCalled();
    expect(onAwakening).toHaveBeenCalledWith(expect.objectContaining<Partial<ChannelAwakening>>({
      kind: "mail",
      content: env.body,
      meta: expect.objectContaining({ trust_status: "verified", verified: "true" }),
    }));
  });

  test("imports only decrypted mail content from local aw", async () => {
    const onAwakening = vi.fn();
    const normalizeTrust = vi.fn(async (_store: PinStore, status: string) => ({ status, stored: false }));
    const localDecrypt = {
      mailMessage: vi.fn(async () => ({
        message_id: "mail-e2ee-trust-boundary",
        subject: "decrypted subject",
        body: "decrypted body",
        verification_status: "verified",
        from_address: "attacker.example/mallory",
        from_did: "did:key:attacker",
        from_stable_id: "did:aw:attacker",
        signed_payload: "attacker payload",
        signature: "attacker signature",
      })),
    };
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: "mail-e2ee-trust-boundary",
          from_agent_id: "agent-1",
          from_alias: "alice",
          from_address: "acme.com/alice",
          from_did: "did:key:original",
          from_stable_id: "did:aw:original",
          to_alias: "eve",
          subject: "",
          body: "",
          priority: "normal",
          created_at: "2026-05-26T00:00:00Z",
          content_mode: "encrypted_v2",
          message_version: 2,
          encrypted_envelope: {},
        }],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };

    await dispatchAgentEvent(
      {
        client: client as never,
        pinStore: new PinStore(),
        trust: { normalizeResolvedTrust: normalizeTrust } as unknown as SenderTrustManager,
        self,
        onAwakening,
        localDecrypt,
      },
      new Set(),
      { type: "mail_message", message_id: "mail-e2ee-trust-boundary" } satisfies AgentEvent,
    );

    expect(normalizeTrust).toHaveBeenCalledWith(
      expect.any(PinStore),
      "unverified",
      "acme.com/alice",
      "did:key:original",
      "did:aw:original",
      undefined,
      undefined,
      undefined,
      undefined,
      "acme.com/alice",
      undefined,
    );
    expect(onAwakening).toHaveBeenCalledWith(expect.objectContaining<Partial<ChannelAwakening>>({
      kind: "mail",
      content: "decrypted body",
      meta: expect.objectContaining({
        from: "acme.com/alice",
        subject: "decrypted subject",
        trust_status: "unverified",
      }),
    }));
  });

  test("decrypts encrypted mail locally before channel delivery", async () => {
    const onAwakening = vi.fn();
    const localDecrypt = {
      mailMessage: vi.fn(async () => ({
        message_id: "mail-e2ee",
        subject: "decrypted subject",
        body: "decrypted mail body",
      })),
    };
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: "mail-e2ee",
          from_agent_id: "agent-1",
          from_alias: "alice",
          from_address: "acme.com/alice",
          to_alias: "eve",
          subject: "",
          body: "",
          priority: "normal",
          created_at: "2026-05-26T00:00:00Z",
          content_mode: "encrypted_v2",
          message_version: 2,
          encrypted_envelope: {},
        }],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };

    await dispatchAgentEvent(
      {
        client: client as never,
        pinStore: new PinStore(),
        trust,
        self,
        onAwakening,
        localDecrypt,
      },
      new Set(),
      { type: "mail_message", message_id: "mail-e2ee" } satisfies AgentEvent,
    );

    expect(localDecrypt.mailMessage).toHaveBeenCalledWith("mail-e2ee");
    expect(onAwakening).toHaveBeenCalledWith(expect.objectContaining<Partial<ChannelAwakening>>({
      kind: "mail",
      content: "decrypted mail body",
      meta: expect.objectContaining({ subject: "decrypted subject" }),
    }));
    expect(client.post).toHaveBeenCalledWith("/v1/messages/mail-e2ee/ack");
  });

  test("does not ack encrypted mail when local decrypt fails", async () => {
    const onAwakening = vi.fn();
    const localDecrypt = {
      mailMessage: vi.fn(async () => {
        throw new Error("missing local encryption key");
      }),
    };
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: "mail-e2ee-fail",
          from_agent_id: "agent-1",
          from_alias: "alice",
          from_address: "acme.com/alice",
          to_alias: "eve",
          subject: "",
          body: "",
          priority: "normal",
          created_at: "2026-05-26T00:00:00Z",
          content_mode: "encrypted_v2",
          message_version: 2,
          encrypted_envelope: {},
        }],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };

    await dispatchAgentEvent(
      {
        client: client as never,
        pinStore: new PinStore(),
        trust,
        self,
        onAwakening,
        localDecrypt,
      },
      new Set(),
      { type: "mail_message", message_id: "mail-e2ee-fail" } satisfies AgentEvent,
    );

    expect(onAwakening).toHaveBeenCalledWith(expect.objectContaining<Partial<ChannelAwakening>>({
      kind: "mail",
      content: "",
      meta: expect.objectContaining({
        encrypted: "true",
        decrypted: "false",
        decrypt_error: "missing local encryption key",
      }),
    }));
    expect(client.post).not.toHaveBeenCalled();
  });

  test("does not call mark-read when chat history presents no messages", async () => {
    const onAwakening = vi.fn();
    const client = {
      get: vi.fn().mockResolvedValue({ messages: [] }),
      post: vi.fn().mockResolvedValue(undefined),
    };

    await dispatchAgentEvent(
      {
        client: client as never,
        pinStore: new PinStore(),
        trust,
        self,
        onAwakening,
      },
      new Set(),
      {
        type: "chat_message",
        session_id: "sess-empty",
        conversation_id: "sess-empty",
      } satisfies AgentEvent,
    );

    expect(onAwakening).not.toHaveBeenCalled();
    expect(client.post).not.toHaveBeenCalled();
  });

  test("marks every presented chat ID read after channel delivery succeeds", async () => {
    const onAwakening = vi.fn();
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: "chat-1",
          conversation_id: "sess-1",
          from_agent: "alice",
          from_address: "acme.com/alice",
          body: "hello",
          timestamp: "2025-01-01T00:00:00Z",
          sender_leaving: false,
        }, {
          message_id: "chat-2",
          conversation_id: "sess-1",
          from_agent: "bob",
          from_address: "acme.com/bob",
          body: "follow-up",
          timestamp: "2025-01-01T00:00:01Z",
          sender_leaving: false,
        }],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };

    await dispatchAgentEvent(
      {
        client: client as never,
        pinStore: new PinStore(),
        trust,
        self,
        onAwakening,
      },
      new Set(),
      {
        type: "chat_message",
        session_id: "sess-1",
        conversation_id: "sess-1",
        message_id: "chat-2",
      } satisfies AgentEvent,
    );

    expect(onAwakening).toHaveBeenCalledWith(expect.objectContaining<Partial<ChannelAwakening>>({
      kind: "chat",
      content: "hello",
    }));
    expect(onAwakening).toHaveBeenCalledWith(expect.objectContaining<Partial<ChannelAwakening>>({
      kind: "chat",
      content: "follow-up",
    }));
    expect(client.post).toHaveBeenCalledWith("/v1/chat/sessions/sess-1/read", { message_ids: ["chat-1", "chat-2"] });
  });

  test("imports only decrypted chat content from local aw", async () => {
    const onAwakening = vi.fn();
    const normalizeTrust = vi.fn(async (_store: PinStore, status: string) => ({ status, stored: false }));
    const localDecrypt = {
      chatMessage: vi.fn(async () => ({
        message_id: "chat-e2ee-trust-boundary",
        body: "decrypted chat body",
        verification_status: "verified",
        from_address: "attacker.example/mallory",
        from_did: "did:key:attacker",
        from_stable_id: "did:aw:attacker",
      })),
    };
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: "chat-e2ee-trust-boundary",
          conversation_id: "sess-e2ee-trust-boundary",
          from_agent: "alice",
          from_address: "acme.com/alice",
          from_did: "did:key:original",
          from_stable_id: "did:aw:original",
          body: "",
          timestamp: "2026-05-26T00:00:00Z",
          sender_leaving: false,
          content_mode: "encrypted_v2",
          message_version: 2,
          encrypted_envelope: {},
        }],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };

    await dispatchAgentEvent(
      {
        client: client as never,
        pinStore: new PinStore(),
        trust: { normalizeResolvedTrust: normalizeTrust } as unknown as SenderTrustManager,
        self,
        onAwakening,
        localDecrypt,
      },
      new Set(),
      {
        type: "chat_message",
        session_id: "sess-e2ee-trust-boundary",
        conversation_id: "sess-e2ee-trust-boundary",
        message_id: "chat-e2ee-trust-boundary",
      } satisfies AgentEvent,
    );

    expect(normalizeTrust).toHaveBeenCalledWith(
      expect.any(PinStore),
      "unverified",
      "acme.com/alice",
      "did:key:original",
      "did:aw:original",
      undefined,
      undefined,
      undefined,
      undefined,
      "acme.com/alice",
      undefined,
    );
    expect(onAwakening).toHaveBeenCalledWith(expect.objectContaining<Partial<ChannelAwakening>>({
      kind: "chat",
      content: "decrypted chat body",
      meta: expect.objectContaining({ from: "acme.com/alice", trust_status: "unverified" }),
    }));
  });

  test("decrypts encrypted chat locally before channel delivery", async () => {
    const onAwakening = vi.fn();
    const localDecrypt = {
      chatMessage: vi.fn(async () => ({
        message_id: "chat-e2ee",
        body: "decrypted chat body",
      })),
    };
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: "chat-e2ee",
          conversation_id: "sess-e2ee",
          from_agent: "alice",
          from_address: "acme.com/alice",
          body: "",
          timestamp: "2026-05-26T00:00:00Z",
          sender_leaving: false,
          content_mode: "encrypted_v2",
          message_version: 2,
          encrypted_envelope: {},
        }],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };

    await dispatchAgentEvent(
      {
        client: client as never,
        pinStore: new PinStore(),
        trust,
        self,
        onAwakening,
        localDecrypt,
      },
      new Set(),
      {
        type: "chat_message",
        session_id: "sess-e2ee",
        conversation_id: "sess-e2ee",
        message_id: "chat-e2ee",
      } satisfies AgentEvent,
    );

    expect(localDecrypt.chatMessage).toHaveBeenCalledWith("sess-e2ee", "chat-e2ee");
    expect(onAwakening).toHaveBeenCalledWith(expect.objectContaining<Partial<ChannelAwakening>>({
      kind: "chat",
      content: "decrypted chat body",
    }));
    expect(client.post).toHaveBeenCalledWith("/v1/chat/sessions/sess-e2ee/read", { message_ids: ["chat-e2ee"] });
  });

  test("does not mark encrypted chat read when local decrypt fails", async () => {
    const onAwakening = vi.fn();
    const localDecrypt = {
      chatMessage: vi.fn(async () => null),
    };
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: "chat-e2ee-fail",
          conversation_id: "sess-e2ee-fail",
          from_agent: "alice",
          from_address: "acme.com/alice",
          body: "",
          timestamp: "2026-05-26T00:00:00Z",
          sender_leaving: false,
          content_mode: "encrypted_v2",
          message_version: 2,
          encrypted_envelope: {},
        }],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };

    await dispatchAgentEvent(
      {
        client: client as never,
        pinStore: new PinStore(),
        trust,
        self,
        onAwakening,
        localDecrypt,
      },
      new Set(),
      {
        type: "chat_message",
        session_id: "sess-e2ee-fail",
        conversation_id: "sess-e2ee-fail",
        message_id: "chat-e2ee-fail",
      } satisfies AgentEvent,
    );

    expect(onAwakening).toHaveBeenCalledWith(expect.objectContaining<Partial<ChannelAwakening>>({
      kind: "chat",
      content: "",
      meta: expect.objectContaining({
        encrypted: "true",
        decrypted: "false",
      }),
    }));
    expect(client.post).not.toHaveBeenCalled();
  });

  test("retries mail ack without re-delivering when previous ack failed after delivery", async () => {
    const onAwakening = vi.fn();
    const deliveryStore = await DeliveryStore.load(join(await mkdtemp(join(tmpdir(), "aweb-channel-test-")), "delivered.json"));
    const dispatched = new Set<string>();
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: "mail-retry",
          conversation_id: "conv-retry",
          from_agent_id: "agent-1",
          from_alias: "alice",
          from_address: "acme.com/alice",
          to_alias: "eve",
          subject: "hello",
          body: "deliver once",
          priority: "normal",
          created_at: "2025-01-01T00:00:00Z",
        }],
      }),
      post: vi.fn()
        .mockRejectedValueOnce(new Error("aweb: http 503"))
        .mockResolvedValueOnce(undefined),
    };
    const options = {
      client: client as never,
      pinStore: new PinStore(),
      trust,
      self,
      deliveryStore,
      onAwakening,
    };
    const event = { type: "mail_message", message_id: "mail-retry" } satisfies AgentEvent;

    await expect(dispatchAgentEvent(options, dispatched, event)).rejects.toThrow("503");
    await dispatchAgentEvent(options, dispatched, event);

    expect(onAwakening).toHaveBeenCalledTimes(1);
    expect(client.post).toHaveBeenCalledTimes(2);
    expect(client.post).toHaveBeenNthCalledWith(1, "/v1/messages/mail-retry/ack");
    expect(client.post).toHaveBeenNthCalledWith(2, "/v1/messages/mail-retry/ack");
  });

  test("manual mail acknowledgment keeps unread reconnect replay deduplicated", async () => {
    const onAwakening = vi.fn();
    const deliveryStore = await DeliveryStore.load(join(await mkdtemp(join(tmpdir(), "aweb-channel-test-")), "delivered.json"));
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: "mail-manual",
          conversation_id: "conv-manual",
          from_agent_id: "agent-1",
          from_alias: "alice",
          from_address: "acme.com/alice",
          to_alias: "eve",
          subject: "hello",
          body: "stay visible",
          priority: "normal",
          created_at: "2025-01-01T00:00:00Z",
        }],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };
    const options = {
      client: client as never,
      pinStore: new PinStore(),
      trust,
      self,
      deliveryStore,
      mailAcknowledgment: "manual" as const,
      onAwakening,
    };
    const event = { type: "mail_message", message_id: "mail-manual" } satisfies AgentEvent;

    await dispatchAgentEvent(options, new Set(), event);
    await dispatchAgentEvent(options, new Set(), event);

    expect(onAwakening).toHaveBeenCalledTimes(1);
    expect(client.post).not.toHaveBeenCalled();
  });

  test("retries chat read receipt without re-delivering when previous read failed after delivery", async () => {
    const onAwakening = vi.fn();
    const deliveryStore = await DeliveryStore.load(join(await mkdtemp(join(tmpdir(), "aweb-channel-test-")), "delivered.json"));
    const dispatched = new Set<string>();
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: "chat-retry",
          conversation_id: "sess-retry",
          from_agent: "alice",
          from_address: "acme.com/alice",
          body: "deliver once",
          timestamp: "2025-01-01T00:00:00Z",
          sender_leaving: false,
        }],
      }),
      post: vi.fn()
        .mockRejectedValueOnce(new Error("aweb: http 503"))
        .mockResolvedValueOnce(undefined),
    };
    const options = {
      client: client as never,
      pinStore: new PinStore(),
      trust,
      self,
      deliveryStore,
      onAwakening,
    };
    const event = {
      type: "chat_message",
      session_id: "sess-retry",
      conversation_id: "sess-retry",
      message_id: "chat-retry",
    } satisfies AgentEvent;

    await expect(dispatchAgentEvent(options, dispatched, event)).rejects.toThrow("503");
    await dispatchAgentEvent(options, dispatched, event);

    expect(onAwakening).toHaveBeenCalledTimes(1);
    expect(client.post).toHaveBeenCalledTimes(2);
    expect(client.post).toHaveBeenNthCalledWith(1, "/v1/chat/sessions/sess-retry/read", { message_ids: ["chat-retry"] });
    expect(client.post).toHaveBeenNthCalledWith(2, "/v1/chat/sessions/sess-retry/read", { message_ids: ["chat-retry"] });
  });

  test("mail trust uses signed-payload did:key when envelope carries stable did:aw", async () => {
    const onAwakening = vi.fn();
    const env: MessageEnvelope = {
      from: "aweb.ai/aida",
      from_did: vectors.did,
      to: self.address,
      to_did: self.did,
      type: "mail",
      subject: "hello",
      body: "signed mail",
      timestamp: "2025-01-01T00:00:00Z",
      from_stable_id: vectors.stableID,
      to_stable_id: self.stableID,
      message_id: "mail-stable-envelope",
      conversation_id: "conv-mail-stable",
    };
    const signature = await signMessage(b64ToBytes(vectors.seed), env);
    const normalizeTrust = vi.fn(async (
      _store,
      status,
      _rawAddress,
      fromDID,
      fromStableID,
      toDID,
      toStableID,
    ) => {
      expect(status).toBe("verified");
      expect(fromDID).toBe(vectors.did);
      expect(fromStableID).toBe(vectors.stableID);
      expect(toDID).toBe(self.did);
      expect(toStableID).toBe(self.stableID);
      return { status, stored: false };
    });
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: env.message_id,
          conversation_id: env.conversation_id,
          from_agent_id: "agent-aida",
          from_alias: "aida",
          from_address: env.from,
          to_alias: self.alias,
          subject: env.subject,
          body: env.body,
          priority: "normal",
          created_at: env.timestamp,
          from_did: vectors.stableID,
          from_stable_id: vectors.stableID,
          to_did: self.stableID,
          to_stable_id: self.stableID,
          signature,
          signing_key_id: vectors.did,
          signed_payload: canonicalJSON(env),
        }],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };

    await dispatchAgentEvent(
      {
        client: client as never,
        pinStore: new PinStore(),
        trust: { normalizeResolvedTrust: normalizeTrust } as unknown as SenderTrustManager,
        self,
        onAwakening,
      },
      new Set(),
      { type: "mail_message", message_id: env.message_id } satisfies AgentEvent,
    );

    expect(onAwakening).toHaveBeenCalledWith(expect.objectContaining<Partial<ChannelAwakening>>({
      kind: "mail",
      content: "signed mail",
      meta: expect.objectContaining({
        trust_status: "verified",
        verified: "true",
      }),
    }));
    expect(client.post).toHaveBeenCalledWith("/v1/messages/mail-stable-envelope/ack");
  });

  test("live verified-legacy projected local address uses authenticated fresh-roster equality", async () => {
    const onAwakening = vi.fn();
    const env: MessageEnvelope = {
      from: "alice",
      from_did: vectors.did,
      to: self.alias,
      to_did: self.did,
      type: "mail",
      subject: "projected local sender",
      body: "must use current roster",
      timestamp: "2025-01-01T00:00:00Z",
      message_id: "mail-projected-local",
    };
    const signature = await signMessage(b64ToBytes(vectors.seed), env);
    const rosterDID = vectors.did.slice(0, -1) + (vectors.did.endsWith("1") ? "2" : "1");
    const wrongRecipientEnv: MessageEnvelope = {
      ...env,
      message_id: "mail-projected-local-wrong-recipient",
      to_did: rosterDID,
    };
    const wrongRecipientSignature = await signMessage(b64ToBytes(vectors.seed), wrongRecipientEnv);
    const client = {
      hasTeamCertificateAuth: (teamID: string) => teamID === "backend:acme.com",
      get: vi.fn(async (path: string) => path === "/v1/agents" ? {
        team_id: "backend:acme.com",
        agents: [{ alias: "alice", did_key: rosterDID, identity_scope: "local" }],
      } : {
        messages: [{
          message_id: env.message_id,
          conversation_id: "legacy-conversation",
          from_alias: "alice",
          from_address: "acme.com/alice",
          to_alias: self.alias,
          subject: env.subject,
          body: env.body,
          priority: "normal",
          created_at: env.timestamp,
          from_did: vectors.did,
          to_did: self.did,
          signature,
          signing_key_id: vectors.did,
          signed_payload: canonicalJSON(env),
        }],
      }),
      getFresh: vi.fn(),
      post: vi.fn().mockResolvedValue(undefined),
    };
    const trust = new SenderTrustManager(
      client as never,
      { verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }) } as never,
      "backend:acme.com",
      self.did,
      self.stableID,
    );

    await dispatchAgentEvent(
      { client: client as never, pinStore: new PinStore(), trust, self, onAwakening },
      new Set(),
      { type: "mail_message", message_id: env.message_id } satisfies AgentEvent,
    );

    expect(client.get).toHaveBeenCalledWith("/v1/agents");
    expect(client.getFresh).not.toHaveBeenCalled();
    expect(onAwakening).toHaveBeenCalledWith(expect.objectContaining<Partial<ChannelAwakening>>({
      meta: expect.objectContaining({ trust_status: "identity_mismatch", verified: "false" }),
    }));

    const wrongRecipientAwakening = vi.fn();
    const wrongRecipientClient = {
      hasTeamCertificateAuth: client.hasTeamCertificateAuth,
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: wrongRecipientEnv.message_id,
          conversation_id: "legacy-conversation",
          from_alias: "alice",
          from_address: "acme.com/alice",
          to_alias: self.alias,
          subject: wrongRecipientEnv.subject,
          body: wrongRecipientEnv.body,
          priority: "normal",
          created_at: wrongRecipientEnv.timestamp,
          from_did: vectors.did,
          to_did: wrongRecipientEnv.to_did,
          signature: wrongRecipientSignature,
          signing_key_id: vectors.did,
          signed_payload: canonicalJSON(wrongRecipientEnv),
        }],
      }),
      getFresh: vi.fn(),
      post: vi.fn().mockResolvedValue(undefined),
    };
    const wrongRecipientTrust = new SenderTrustManager(
      wrongRecipientClient as never,
      { verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }) } as never,
      "backend:acme.com",
      self.did,
      self.stableID,
    );
    await dispatchAgentEvent(
      {
        client: wrongRecipientClient as never,
        pinStore: new PinStore(),
        trust: wrongRecipientTrust,
        self,
        onAwakening: wrongRecipientAwakening,
      },
      new Set(),
      { type: "mail_message", message_id: wrongRecipientEnv.message_id } satisfies AgentEvent,
    );
    expect(wrongRecipientClient.getFresh).not.toHaveBeenCalled();
    expect(wrongRecipientAwakening).toHaveBeenCalledWith(expect.objectContaining<Partial<ChannelAwakening>>({
      meta: expect.objectContaining({ trust_status: "identity_mismatch", verified: "false" }),
    }));
  });

  test("live mail reports stale verifier cache without claiming identity mismatch", async () => {
    const onAwakening = vi.fn();
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: "mail-stale-verifier",
          from_agent_id: "agent-1",
          from_alias: "alice",
          from_address: "acme.com/alice",
          from_did: vectors.did,
          from_stable_id: vectors.stableID,
          to_alias: "eve",
          subject: "hello",
          body: "fresh identity",
          priority: "normal",
          created_at: "2025-01-01T00:00:00Z",
          verification_status: "verified",
        }],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };
    const staleTrust = {
      normalizeResolvedTrust: vi.fn(async () => ({ status: "verification_stale", stored: false })),
    } as unknown as SenderTrustManager;

    await dispatchAgentEvent(
      {
        client: client as never,
        pinStore: new PinStore(),
        trust: staleTrust,
        self,
        onAwakening,
      },
      new Set(),
      { type: "mail_message", message_id: "mail-stale-verifier" } satisfies AgentEvent,
    );

    expect(onAwakening).toHaveBeenCalledWith(expect.objectContaining<Partial<ChannelAwakening>>({
      meta: expect.objectContaining({
        trust_status: "verification_stale",
        verified: "false",
      }),
    }));
  });

  test("surfaces pin migration conflicts in metadata and operator presentation", async () => {
    const awakenings: ChannelAwakening[] = [];
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: "mail-pin-conflict",
          from_agent_id: "agent-1",
          from_alias: "alice",
          from_address: "acme.com/alice",
          to_alias: "eve",
          subject: "hello",
          body: "conflicting identity",
          priority: "normal",
          created_at: "2025-01-01T00:00:00Z",
        }],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };
    const conflictTrust = {
      normalizeResolvedTrust: vi.fn(async () => ({ status: "pin_conflict", stored: false })),
    } as unknown as SenderTrustManager;

    await dispatchAgentEvent(
      {
        client: client as never,
        pinStore: new PinStore(),
        trust: conflictTrust,
        self,
        onAwakening: (awakening) => { awakenings.push(awakening); },
      },
      new Set(),
      { type: "mail_message", message_id: "mail-pin-conflict" } satisfies AgentEvent,
    );

    expect(awakenings[0].meta).toMatchObject({
      trust_status: "pin_conflict",
      verified: "false",
    });
    const rendered = formatAwakeningForAgent(awakenings[0]);
    expect(rendered).toContain("two pin records conflict");
    expect(rendered).toContain("migration was refused");
    expect(rendered).toContain("avoid discarding trust state");
  });

  test("formats stale verification as retryable rather than identity mismatch", () => {
    const rendered = formatAwakeningForAgent({
      kind: "mail",
      content: "hello",
      deliveryIntent: "wake",
      meta: {
        type: "mail",
        from: "acme.com/alice",
        message_id: "mail-stale",
        trust_status: "verification_stale",
        verified: "false",
      },
    });

    expect(rendered).toContain("sender signature verified");
    expect(rendered).toContain("not an identity-mismatch finding");
    expect(rendered).toContain("retry verification");
  });

  test("chat trust uses signed-payload did:key when envelope carries stable did:aw", async () => {
    const onAwakening = vi.fn();
    const env: MessageEnvelope = {
      from: "aweb.ai/ama",
      from_did: vectors.did,
      to: self.address,
      to_did: self.did,
      type: "chat",
      subject: "",
      body: "signed chat",
      timestamp: "2025-01-01T00:00:00Z",
      from_stable_id: vectors.stableID,
      to_stable_id: self.stableID,
      message_id: "chat-stable-envelope",
      conversation_id: "sess-stable",
    };
    const signature = await signMessage(b64ToBytes(vectors.seed), env);
    const normalizeTrust = vi.fn(async (
      _store,
      status,
      _rawAddress,
      fromDID,
      fromStableID,
      toDID,
      toStableID,
    ) => {
      expect(status).toBe("verified");
      expect(fromDID).toBe(vectors.did);
      expect(fromStableID).toBe(vectors.stableID);
      expect(toDID).toBe(self.did);
      expect(toStableID).toBe(self.stableID);
      return { status, stored: false };
    });
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: env.message_id,
          conversation_id: env.conversation_id,
          from_agent: "ama",
          from_address: env.from,
          to_address: env.to,
          body: env.body,
          timestamp: env.timestamp,
          sender_leaving: false,
          from_did: vectors.stableID,
          from_stable_id: vectors.stableID,
          to_did: self.stableID,
          to_stable_id: self.stableID,
          signature,
          signing_key_id: vectors.did,
          signed_payload: canonicalJSON(env),
        }],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };

    await dispatchAgentEvent(
      {
        client: client as never,
        pinStore: new PinStore(),
        trust: { normalizeResolvedTrust: normalizeTrust } as unknown as SenderTrustManager,
        self,
        onAwakening,
      },
      new Set(),
      {
        type: "chat_message",
        session_id: env.conversation_id,
        conversation_id: env.conversation_id,
        message_id: env.message_id,
      } satisfies AgentEvent,
    );

    expect(onAwakening).toHaveBeenCalledWith(expect.objectContaining<Partial<ChannelAwakening>>({
      kind: "chat",
      content: "signed chat",
      meta: expect.objectContaining({
        trust_status: "verified",
        verified: "true",
      }),
    }));
    expect(client.post).toHaveBeenCalledWith("/v1/chat/sessions/sess-stable/read", { message_ids: ["chat-stable-envelope"] });
  });

  test("chat live dispatch resolves public identity and registry evidence outside the pin lock", async () => {
    const onAwakening = vi.fn();
    const env: MessageEnvelope = {
      from: "aweb.ai/ama",
      from_did: vectors.did,
      to: self.stableID,
      to_did: self.stableID,
      type: "chat",
      subject: "",
      body: "legacy stored-route recipient",
      timestamp: "2025-01-01T00:00:00Z",
      from_stable_id: vectors.stableID,
      message_id: "chat-legacy-stable-to-did",
      conversation_id: "sess-legacy-stable",
    };
    const signature = await signMessage(b64ToBytes(vectors.seed), env);
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: env.message_id,
          conversation_id: env.conversation_id,
          from_agent: "ama",
          from_address: env.from,
          to_address: env.to,
          body: env.body,
          timestamp: env.timestamp,
          sender_leaving: false,
          from_did: vectors.did,
          from_stable_id: vectors.stableID,
          to_did: self.stableID,
          signature,
          signing_key_id: vectors.did,
        }],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };
    let lockHeld = false;
    const registry = {
      verifyStableIdentity: vi.fn(async () => {
        expect(lockHeld).toBe(false);
        return { outcome: "OK_VERIFIED", currentDidKey: vectors.did };
      }),
      resolveIdentity: vi.fn(async () => {
        expect(lockHeld).toBe(false);
        return {
          did: vectors.did,
          stableID: vectors.stableID,
          address: env.from,
          custody: "self",
          identityScope: "global",
        };
      }),
    };
    const trust = new SenderTrustManager(
      client as never,
      registry as never,
      "default:aweb.ai",
      self.did,
      self.stableID,
    );
    const pinStore = new PinStore();
    const originalRunExclusive = pinStore.runExclusive.bind(pinStore);
    vi.spyOn(pinStore, "runExclusive").mockImplementation(async (operation) => (
      originalRunExclusive(async () => {
        expect(lockHeld).toBe(false);
        lockHeld = true;
        try {
          return await operation();
        } finally {
          lockHeld = false;
        }
      })
    ));

    await dispatchAgentEvent(
      {
        client: client as never,
        pinStore,
        pinStoreWriter: acceptingPinStoreWriter,
        trust,
        self,
        onAwakening,
      },
      new Set(),
      {
        type: "chat_message",
        session_id: env.conversation_id,
        conversation_id: env.conversation_id,
        message_id: env.message_id,
      } satisfies AgentEvent,
    );

    expect(onAwakening).toHaveBeenCalledWith(expect.objectContaining<Partial<ChannelAwakening>>({
      kind: "chat",
      content: "legacy stored-route recipient",
      meta: expect.objectContaining({
        trust_status: "verified",
        verified: "true",
      }),
    }));
    expect(registry.resolveIdentity).toHaveBeenCalledTimes(1);
    expect(registry.verifyStableIdentity).toHaveBeenCalledTimes(1);
  });

  test("chat live dispatch hydrates trust fields from signed_payload when top-level row has stable did:aw", async () => {
    const onAwakening = vi.fn();
    const env: MessageEnvelope = {
      from: "aweb.ai/ama",
      from_did: vectors.did,
      to: self.stableID,
      to_did: "",
      type: "chat",
      subject: "",
      body: "signed-payload authority",
      timestamp: "2025-01-01T00:00:00Z",
      from_stable_id: vectors.stableID,
      to_stable_id: self.stableID,
      message_id: "chat-signed-payload-authority",
      conversation_id: "sess-signed-payload-authority",
    };
    const signedPayload = canonicalJSON(env);
    const signature = await signMessage(b64ToBytes(vectors.seed), env);
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: env.message_id,
          conversation_id: env.conversation_id,
          from_agent: "ama",
          from_address: env.from,
          to_address: "acme.com/eve",
          body: env.body,
          timestamp: env.timestamp,
          sender_leaving: false,
          from_did: vectors.stableID,
          from_stable_id: vectors.stableID,
          signature,
          signing_key_id: vectors.did,
          signed_payload: signedPayload,
        }],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };
    const trust = new SenderTrustManager(
      client as never,
      {
        verifyStableIdentity: async () => ({ outcome: "OK_VERIFIED", currentDidKey: vectors.did }),
        resolveIdentity: async () => ({
          did: vectors.did,
          stableID: vectors.stableID,
          address: env.from,
          custody: "self",
          identityScope: "global",
        }),
      } as never,
      "default:aweb.ai",
      self.did,
      self.stableID,
    );

    await dispatchAgentEvent(
      {
        client: client as never,
        pinStore: new PinStore(),
        pinStoreWriter: acceptingPinStoreWriter,
        trust,
        self,
        onAwakening,
      },
      new Set(),
      {
        type: "chat_message",
        session_id: env.conversation_id,
        conversation_id: env.conversation_id,
        message_id: env.message_id,
      } satisfies AgentEvent,
    );

    expect(onAwakening).toHaveBeenCalledWith(expect.objectContaining<Partial<ChannelAwakening>>({
      kind: "chat",
      content: "signed-payload authority",
      meta: expect.objectContaining({
        trust_status: "verified",
        verified: "true",
      }),
    }));
  });

  test("persists a verified-head advance when the trust path makes no pin write", async () => {
    const onAwakening = vi.fn();
    const env: MessageEnvelope = {
      from: "aweb.ai/ama",
      from_did: vectors.did,
      from_stable_id: vectors.stableID,
      to: self.stableID,
      to_did: self.did,
      to_stable_id: self.stableID,
      type: "chat",
      subject: "",
      body: "checkpoint-only persistence",
      timestamp: "2025-01-01T00:00:00Z",
      message_id: "chat-checkpoint-only",
      conversation_id: "sess-checkpoint-only",
    };
    const signature = await signMessage(b64ToBytes(vectors.seed), env);
    const client = {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: env.message_id,
          conversation_id: env.conversation_id,
          from_agent: "ama",
          from_address: env.from,
          to_address: env.to,
          body: env.body,
          timestamp: env.timestamp,
          sender_leaving: false,
          from_did: vectors.did,
          from_stable_id: vectors.stableID,
          to_did: self.did,
          to_stable_id: self.stableID,
          signature,
          signing_key_id: vectors.did,
        }],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };
    const entryHash = "a".repeat(64);
    const trust = new SenderTrustManager(
      client as never,
      {
        verifyStableIdentity: async () => ({
          outcome: "OK_VERIFIED",
          currentDidKey: vectors.did,
          verifiedHead: {
            seq: 2,
            entryHash,
            stateHash: "b".repeat(64),
            currentDidKey: vectors.did,
            fetchedAt: Date.now(),
          },
        }),
        resolveIdentity: async () => ({
          did: vectors.did,
          stableID: vectors.stableID,
          address: env.from,
          custody: "self",
          identityScope: "global",
        }),
      } as never,
      "default:aweb.ai",
      self.did,
      self.stableID,
    );

    // The sender's stable identity already has a pin, but the claimed address
    // remains pinned to somebody else. The trust path therefore returns an
    // identity mismatch without writing either pin; checkpoint advance is the
    // only reason dispatch may consider the store dirty.
    const pinStore = new PinStore();
    pinStore.storePin(vectors.stableID, "aweb.ai/original-ama", "", "");
    const senderPin = pinStore.pins.get(vectors.stableID)!;
    senderPin.stable_id = vectors.stableID;
    senderPin.did_key = vectors.did;
    const addressOwner = "did:aw:address-owner";
    pinStore.storePin(addressOwner, env.from, "", "");
    const ownerPin = pinStore.pins.get(addressOwner)!;
    ownerPin.stable_id = addressOwner;
    ownerPin.did_key = "did:key:address-owner";

    const pinStorePath = join(await mkdtemp(join(tmpdir(), "aw-checkpoint-only-")), "known_agents.yaml");
    const pinStoreWriter = {
      compareAndSet: async (path: string, _expectedYAML: string, desiredYAML: string) => {
        await mkdir(dirname(path), { recursive: true });
        await writeFile(path, desiredYAML, "utf-8");
      },
    };
    await dispatchAgentEvent(
      { client: client as never, pinStore, pinStorePath, pinStoreWriter, trust, self, onAwakening },
      new Set(),
      {
        type: "chat_message",
        session_id: env.conversation_id,
        conversation_id: env.conversation_id,
        message_id: env.message_id,
      } satisfies AgentEvent,
    );

    expect(onAwakening).toHaveBeenCalledWith(expect.objectContaining<Partial<ChannelAwakening>>({
      meta: expect.objectContaining({ trust_status: "identity_mismatch" }),
    }));
    const reloaded = PinStore.fromYAML(await readFile(pinStorePath, "utf-8"));
    expect(reloaded.pins.get(vectors.stableID)).toMatchObject({
      log_seq: 2,
      log_entry_hash: entryHash,
    });
    expect(reloaded.addresses.get(env.from)).toBe(addressOwner);
  });

  test("dispatches app events without hydration and de-dupes by event_id", async () => {
    const onAwakening = vi.fn();
    const deliveryStore = await DeliveryStore.load(join(await mkdtemp(join(tmpdir(), "aw-app-event-")), "delivered.json"));
    const event = {
      type: "app_event",
      event_id: "event-1",
      app_id: "folio",
      app_event_type: "folio/doc.changed",
      resource_ref: "aaai-m22-proof-1781686412",
      delivery_intent: "wake",
      producer_delivery_intent: "ambient",
      payload: { version: 8, source: "api" },
    } satisfies AgentEvent;

    const options = {
      client: {} as never,
      pinStore: new PinStore(),
      trust,
      self,
      onAwakening,
      deliveryStore,
    };
    const dispatched = new Set<string>();

    await dispatchAgentEvent(options, dispatched, event);
    await dispatchAgentEvent(options, dispatched, event);

    expect(onAwakening).toHaveBeenCalledTimes(1);
    expect(onAwakening).toHaveBeenCalledWith(expect.objectContaining<Partial<ChannelAwakening>>({
      kind: "app",
      content: "folio/doc.changed — aaai-m22-proof-1781686412 — version=8, source=api",
      deliveryIntent: "wake",
      meta: expect.objectContaining({
        type: "folio/doc.changed",
        app_id: "folio",
        resource_ref: "aaai-m22-proof-1781686412",
        producer_delivery_intent: "ambient",
        payload: '{"version":8,"source":"api"}',
      }),
    }));
  });

  test("formats app event content without empty resource_ref", async () => {
    const onAwakening = vi.fn();
    await dispatchAgentEvent(
      {
        client: {} as never,
        pinStore: new PinStore(),
        trust,
        self,
        onAwakening,
      },
      new Set(),
      {
        type: "app_event",
        event_id: "event-no-resource",
        app_id: "folio",
        app_event_type: "folio/doc.changed",
        resource_ref: "",
        delivery_intent: "wake",
        payload: { version: 8, source: "api" },
      } satisfies AgentEvent,
    );

    expect(onAwakening).toHaveBeenCalledWith(expect.objectContaining<Partial<ChannelAwakening>>({
      kind: "app",
      content: "folio/doc.changed — version=8, source=api",
    }));
  });

  test("formats app awakening for agent with sanitized summary", () => {
    const rendered = formatAwakeningForAgent({
      kind: "app",
      content: "folio/doc.changed — aaai proof — bad key=ok Injected:, source=api",
      deliveryIntent: "wake",
      meta: {
        type: "folio/doc.changed\nInjected:",
        app_event_type: "folio/doc.changed\nInjected:",
        event_id: "event-sanitized",
        resource_ref: "aaai\r\nproof",
        payload: '{"bad\\nkey":"ok\\nInjected:"}',
      },
    });

    expect(rendered).toContain("App event:\nfolio/doc.changed — aaai proof — bad key=ok Injected:, source=api");
    expect(rendered).not.toContain("folio/doc.changed\nInjected:");
    expect(rendered).not.toContain("aaai\r\nproof");
  });

  test("formats app event content as a sanitized single line", async () => {
    const onAwakening = vi.fn();
    await dispatchAgentEvent(
      {
        client: {} as never,
        pinStore: new PinStore(),
        trust,
        self,
        onAwakening,
      },
      new Set(),
      {
        type: "app_event",
        event_id: "event-sanitized",
        app_id: "folio",
        app_event_type: "folio/doc.changed\nInjected:",
        resource_ref: "aaai\r\nproof",
        delivery_intent: "wake",
        payload: { "bad\nkey": "ok\nInjected:", source: "api" },
      } satisfies AgentEvent,
    );

    const awakening = onAwakening.mock.calls[0][0] as ChannelAwakening;
    expect(awakening.content).toBe("folio/doc.changed Injected: — aaai proof — bad key=ok Injected:, source=api");
    expect(awakening.content).not.toMatch(/[\r\n]/);
  });
});
