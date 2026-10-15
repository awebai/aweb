import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, test, vi } from "vitest";
import { ReceiveStreamReceipt } from "../src/receive.js";
import { streamAgentEvents } from "../src/api/events.js";

const homes: string[] = [];
afterEach(async () => { await Promise.all(homes.map((home) => rm(home, { recursive: true, force: true }))); });

test("a receipt proves a read, uses identity home and stable identity, and never advances by itself", async () => {
  const home = await mkdtemp(join(tmpdir(), "aweb-receive-")); homes.push(home);
  const receipt = new ReceiveStreamReceipt({ identityHome: home, kind: "pi-extension", did: "did:key:resident", stableID: "did:aw:resident" });
  const path = join(home, "receive", "stream.json");
  await expect(readFile(path)).rejects.toThrow();
  const opened = Date.UTC(2026, 9, 15);
  receipt.onRead(opened, opened + 1000); await receipt.flush();
  const first = JSON.parse(await readFile(path, "utf8"));
  expect(first).toEqual({ v: 1, kind: "pi-extension", did: "did:key:resident", stable_id: "did:aw:resident", pid: process.pid, opened_at: new Date(opened).toISOString(), heartbeat_at: new Date(opened + 1000).toISOString() });
  expect((await stat(path)).mode & 0o777).toBe(0o600);
  receipt.onRead(opened, opened + 30_000); await receipt.flush();
  expect(JSON.parse(await readFile(path, "utf8"))).toEqual(first);
  receipt.onRead(opened, opened + 31_000); await receipt.flush();
  expect(JSON.parse(await readFile(path, "utf8")).heartbeat_at).toBe(new Date(opened + 31_000).toISOString());
  // A clock advancing is not a server read.
  await receipt.flush();
  expect(JSON.parse(await readFile(path, "utf8")).heartbeat_at).toBe(new Date(opened + 31_000).toISOString());
  await receipt.onClose();
  await expect(readFile(path)).rejects.toThrow();
});

test("local identities omit stable_id; closing an old stream preserves a replacement owner's receipt", async () => {
  const home = await mkdtemp(join(tmpdir(), "aweb-receive-")); homes.push(home);
  const receipt = new ReceiveStreamReceipt({ identityHome: home, kind: "claude-channel", did: "did:key:local" });
  receipt.onRead(1000, 1000); await receipt.flush();
  const path = join(home, "receive", "stream.json");
  const first = JSON.parse(await readFile(path, "utf8"));
  expect(first).not.toHaveProperty("stable_id");
  const other = { ...first, pid: process.pid + 1 };
  await writeFile(path, JSON.stringify(other));
  await receipt.onClose();
  expect(JSON.parse(await readFile(path, "utf8"))).toEqual(other);
});

test("real stream reads count comments, and disconnect removes proof before reconnect backoff", async () => {
  const home = await mkdtemp(join(tmpdir(), "aweb-receive-")); homes.push(home);
  const receipt = new ReceiveStreamReceipt({ identityHome: home, kind: "claude-channel", did: "did:key:local" });
  const abort = new AbortController();
  let controller!: ReadableStreamDefaultController<Uint8Array>;
  const client = { openSSE: vi.fn(async () => new Response(new ReadableStream<Uint8Array>({ start(c) { controller = c; } }))) };
  const disconnected = Promise.withResolvers<void>();
  const consume = (async () => {
    for await (const _ of streamAgentEvents(client as never, abort.signal, (state) => {
      if (state.state === "disconnected") { disconnected.resolve(); abort.abort(); }
    }, () => {}, receipt)) { /* Comments produce no agent event. */ }
  })();
  await vi.waitFor(() => expect(client.openSSE).toHaveBeenCalledTimes(1));
  controller.enqueue(new TextEncoder().encode(": keepalive\n\n"));
  const path = join(home, "receive", "stream.json");
  await vi.waitFor(async () => expect(JSON.parse(await readFile(path, "utf8")).did).toBe("did:key:local"));
  controller.close();
  await disconnected.promise;
  await expect(readFile(path)).rejects.toThrow();
  await consume;
});
