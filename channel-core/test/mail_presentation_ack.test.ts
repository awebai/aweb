import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test, vi } from "vitest";
import {
  DeliveryStore,
  dispatchAgentEvent,
  PinStore,
  startChannelLoop,
  type AgentEvent,
  type ChannelAwakening,
  type SenderTrustManager,
} from "../src/index.js";

// abbv: a successful MCP notification is only process-local pending delivery.
// A later successful loop iteration promotes it to durable delivery and then
// acknowledges it. That gives a process killed after the callback no authority
// to hide the mail from the next bridge, without returning to aajy's permanent
// unread replay burst.
describe("mail promotion-ack semantic", () => {
  const self = {
    alias: "eve",
    address: "acme.com/eve",
    did: "did:key:self-eve",
    stableID: "did:aw:self-eve",
  };
  const trust = {
    normalizeTrust: vi.fn(async () => ({ status: "verified", stored: false })),
  } as unknown as SenderTrustManager;

  function message(messageID = "m1", conversationID = "c1", readAt?: string) {
    return {
      message_id: messageID,
      conversation_id: conversationID,
      from_agent_id: "agent-1",
      from_alias: "alice",
      from_address: "acme.com/alice",
      to_alias: "eve",
      subject: "hello",
      body: "world",
      priority: "normal",
      read_at: readAt,
      created_at: "2025-01-01T00:00:00Z",
    };
  }

  function clientFor(messages: ReturnType<typeof message>[]) {
    return {
      get: vi.fn().mockResolvedValue({ messages }),
      post: vi.fn(async (path: string) => {
        const id = decodeURIComponent(path.split("/").at(-2) || "");
        const item = messages.find((candidate) => candidate.message_id === id);
        if (item) item.read_at = "2026-08-06T00:00:00Z";
      }),
      openSSE: vi.fn(),
    };
  }

  function options(client: ReturnType<typeof clientFor>, deliveryStore: DeliveryStore, awoke: ChannelAwakening[]) {
    return {
      client: client as never,
      pinStore: new PinStore(),
      trust,
      self,
      deliveryStore,
      onAwakening: (awakening: ChannelAwakening) => { awoke.push(awakening); },
    };
  }

  const event = (messageID = "m1") => (
    { type: "mail_message", message_id: messageID } satisfies AgentEvent
  );

  test("a bridge killed after the notification leaves mail unread for the next process", async () => {
    const store = await DeliveryStore.load(join(await mkdtemp(join(tmpdir(), "abbv-kill-")), "delivered.json"));
    const messages = [message()];
    const client = clientFor(messages);
    const firstAwakenings: ChannelAwakening[] = [];

    await dispatchAgentEvent(options(client, store, firstAwakenings), new Set(), event());

    expect(firstAwakenings).toHaveLength(1);
    expect(client.post).not.toHaveBeenCalled();
    expect(messages[0].read_at).toBeUndefined();
    expect(store.has("mail:c1:m1")).toBe(false);

    // A new Set models the replacement process. The first process left no
    // durable mark, so the replacement must present the still-unread mail.
    const replacementAwakenings: ChannelAwakening[] = [];
    await dispatchAgentEvent(options(client, store, replacementAwakenings), new Set(), event());
    expect(replacementAwakenings).toHaveLength(1);
    expect(client.post).not.toHaveBeenCalled();
  });

  test("the same live process promotes and acknowledges once on a later iteration", async () => {
    const store = await DeliveryStore.load(join(await mkdtemp(join(tmpdir(), "abbv-promote-")), "delivered.json"));
    const messages = [message()];
    const client = clientFor(messages);
    const awakenings: ChannelAwakening[] = [];
    const dispatched = new Set<string>();
    const opts = options(client, store, awakenings);

    await dispatchAgentEvent(opts, dispatched, event());
    expect(client.post).not.toHaveBeenCalled();
    expect(store.has("mail:c1:m1")).toBe(false);

    await dispatchAgentEvent(opts, dispatched, event());
    expect(awakenings).toHaveLength(1);
    expect(client.post).toHaveBeenCalledTimes(1);
    expect(client.post).toHaveBeenCalledWith("/v1/messages/m1/ack");
    expect(store.has("mail:c1:m1")).toBe(true);

    await dispatchAgentEvent(opts, dispatched, event());
    expect(awakenings).toHaveLength(1);
    expect(client.post).toHaveBeenCalledTimes(1);
  });

  test("a promoted durable mark deduplicates without re-notifying", async () => {
    const dir = await mkdtemp(join(tmpdir(), "abbv-dedup-"));
    const path = join(dir, "delivered.json");
    const store = await DeliveryStore.load(path);
    store.mark("mail:c1:m1");
    await store.save();
    const wireStore = JSON.parse(await readFile(path, "utf8")) as Record<string, unknown>;
    expect(wireStore["mail:c1:m1"]).toEqual(expect.any(String));
    expect(Object.values(wireStore).every((value) => typeof value === "string")).toBe(true);
    expect(Object.keys(wireStore)).toHaveLength(2); // delivery mark + old-reader-safe promotion marker
    const client = clientFor([message("m1", "c1", "2026-08-06T00:00:00Z")]);
    const awakenings: ChannelAwakening[] = [];

    await dispatchAgentEvent(options(client, await DeliveryStore.load(path), awakenings), new Set(), event());

    expect(awakenings).toHaveLength(0);
    expect(client.post).not.toHaveBeenCalled();
  });

  test("startup catch-up replays at most twenty ambiguous legacy marks", async () => {
    const workdir = await mkdtemp(join(tmpdir(), "abbv-catch-up-"));
    const storePath = join(workdir, ".aw", "channel-delivered-ids.json");
    const fixtureIDs = [
      "be470668-6b53-476a",
      "e236d3e2-fa4f-47a5",
      "1f00154c-3e3f-4dbd",
      "af8825c1-ea22-4577",
      ...Array.from({ length: 21 }, (_, index) => `legacy-${index}`),
    ];
    const legacyTimestamp = new Date().toISOString();
    const legacy = Object.fromEntries(
      fixtureIDs.map((id) => [`mail:legacy-conversation:${id}`, legacyTimestamp]),
    );
    await mkdir(join(workdir, ".aw"));
    await writeFile(storePath, `${JSON.stringify(legacy)}\n`, { encoding: "utf8", mode: 0o600 });
    const messages = fixtureIDs.map((id) => message(id, "legacy-conversation", "2026-08-06T00:00:01Z"));
    const client = clientFor(messages);
    const awakenings: ChannelAwakening[] = [];
    const controller = new AbortController();
    controller.abort();

    await startChannelLoop({
      ...options(client, await DeliveryStore.load(storePath), awakenings),
      signal: controller.signal,
      teamID: "backend:acme.com",
      workdir,
    });

    expect(client.get).toHaveBeenCalledTimes(1);
    expect(client.get.mock.calls[0][0]).not.toContain("unread_only=true");
    expect(client.get.mock.calls[0][0]).toContain("limit=20");
    expect(awakenings).toHaveLength(20);
    expect(awakenings.map((item) => item.meta.message_id)).toEqual(fixtureIDs.slice(0, 20));
    expect(client.post).not.toHaveBeenCalled();
    expect(client.openSSE).not.toHaveBeenCalled();
  });
});
