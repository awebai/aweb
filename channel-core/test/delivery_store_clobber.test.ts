import { afterEach, beforeEach, describe, expect, test } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DeliveryStore } from "../src/channel.js";

let dir: string;
let path: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "delivery-clobber-"));
  path = join(dir, "channel-delivered-ids.json");
  await writeFile(path, "{}\n", "utf-8");
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

// aajy repro: two channel processes sharing a delivery store both load the file
// once, mark different message ids, and save. save() full-overwrites the file
// with only its own in-memory map, so the later save clobbers the earlier
// writer's mark — a delivered message then looks undelivered and is replayed.
describe("DeliveryStore concurrent writers", () => {
  test("a concurrent writer must not clobber another writer's delivery marks", async () => {
    const a = await DeliveryStore.load(path);
    const b = await DeliveryStore.load(path);

    a.mark("msg-from-a");
    b.mark("msg-from-b");

    await a.save();
    await b.save();

    const reloaded = await DeliveryStore.load(path);
    expect(reloaded.has("msg-from-b")).toBe(true);
    // Today this fails: b.save() overwrote a's mark, so the message a delivered
    // is replayed on the next reconnect.
    expect(reloaded.has("msg-from-a")).toBe(true);
  });

  test("overlapping writers that all load the empty file keep every mark", async () => {
    // Eight processes load the shared store at once (all see it empty), each
    // marks a distinct message, then they save. merge-on-save unions with disk,
    // so no mark is lost — the exact temporal clobber the global file produced.
    const writers = await Promise.all(
      Array.from({ length: 8 }, () => DeliveryStore.load(path)),
    );
    writers.forEach((w, i) => w.mark(`msg-${i}`));
    for (const w of writers) await w.save();

    const reloaded = await DeliveryStore.load(path);
    for (let i = 0; i < writers.length; i += 1) {
      expect(reloaded.has(`msg-${i}`), `msg-${i}`).toBe(true);
    }
  });
});
