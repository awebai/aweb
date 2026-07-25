import { afterEach, beforeEach, describe, expect, test } from "vitest";
import { access, mkdir, mkdtemp, readFile, readdir, rm, stat, utimes, writeFile } from "node:fs/promises";
import { spawn, type ChildProcess } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
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

async function waitForFiles(paths: string[]): Promise<void> {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    const ready = await Promise.all(paths.map(async (candidate) => {
      try {
        await access(candidate);
        return true;
      } catch {
        return false;
      }
    }));
    if (ready.every(Boolean)) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error("delivery-store subprocesses did not reach the barrier");
}

function childExit(child: ChildProcess, stderr: () => string): Promise<void> {
  return new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      if (code === 0) resolve();
      else reject(new Error(`delivery-store subprocess exited ${code ?? signal}: ${stderr()}`));
    });
  });
}

async function quarantinePaths(): Promise<string[]> {
  const names = await readdir(dir);
  return names
    .filter((name) => name.startsWith("channel-delivered-ids.json.corrupt-"))
    .map((name) => join(dir, name));
}

// aajy regression: two channel processes sharing a delivery store both load
// the file once, mark different message ids, and save. A full overwrite with
// only one process's in-memory map lets the later save clobber the earlier
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
    // If b.save() overwrites a's mark, the message a delivered is replayed on
    // the next reconnect.
    expect(reloaded.has("msg-from-a")).toBe(true);
  });

  test("overlapping writers that all load the empty file keep every mark", async () => {
    // Sixteen independent stores load the shared file before the barrier, mark
    // distinct messages, then genuinely overlap their production save() calls.
    // Every fulfilled save promises that its mark is durable; all such marks
    // must remain after every concurrent writer completes (default-aajc.10).
    const writers = await Promise.all(
      Array.from({ length: 16 }, () => DeliveryStore.load(path)),
    );
    writers.forEach((w, i) => w.mark(`msg-${i}`));
    await Promise.all(writers.map((writer) => writer.save()));

    const reloaded = await DeliveryStore.load(path);
    for (let i = 0; i < writers.length; i += 1) {
      expect(reloaded.has(`msg-${i}`), `msg-${i}`).toBe(true);
    }
  });

  test("load quarantines malformed bytes, reports the failure, and permits a clean retry", async () => {
    const malformed = "{not valid delivery JSON\n";
    await writeFile(path, malformed, "utf8");

    await expect(DeliveryStore.load(path)).rejects.toThrow(/quarantined.*corrupt/i);
    const quarantined = await quarantinePaths();
    expect(quarantined).toHaveLength(1);
    await expect(readFile(quarantined[0], "utf8")).resolves.toBe(malformed);
    await expect(access(path)).rejects.toMatchObject({ code: "ENOENT" });

    const fresh = await DeliveryStore.load(path);
    fresh.mark("after-load-quarantine");
    await fresh.save();
    expect((await DeliveryStore.load(path)).has("after-load-quarantine")).toBe(true);
  });

  test("save quarantines invalid timestamps byte-identically and succeeds on retry", async () => {
    const store = await DeliveryStore.load(path);
    const malformed = "{\"existing-mark\":\"not-a-timestamp\"}\n";
    await writeFile(path, malformed, "utf8");
    store.mark("after-save-quarantine");

    await expect(store.save()).rejects.toThrow(/quarantined.*corrupt/i);
    const quarantined = await quarantinePaths();
    expect(quarantined).toHaveLength(1);
    await expect(readFile(quarantined[0], "utf8")).resolves.toBe(malformed);
    await expect(access(path)).rejects.toMatchObject({ code: "ENOENT" });

    await store.save();
    expect((await DeliveryStore.load(path)).has("after-save-quarantine")).toBe(true);
  });

  test("save quarantines unreadable state and succeeds on retry", async () => {
    const store = await DeliveryStore.load(path);
    await rm(path);
    await mkdir(path);
    store.mark("after-unreadable-quarantine");

    await expect(store.save()).rejects.toThrow(/quarantined.*corrupt/i);
    const quarantined = await quarantinePaths();
    expect(quarantined).toHaveLength(1);
    expect((await stat(quarantined[0])).isDirectory()).toBe(true);
    await expect(access(path)).rejects.toMatchObject({ code: "ENOENT" });

    await store.save();
    expect((await DeliveryStore.load(path)).has("after-unreadable-quarantine")).toBe(true);
  });

  test("reports failure instead of silently exhausting lock retries", { timeout: 15_000 }, async () => {
    const store = await DeliveryStore.load(path);
    store.mark("must-not-report-success");
    await mkdir(`${path}.lock`);

    await expect(store.save()).rejects.toMatchObject({ code: "ELOCKED" });
    const reloaded = await DeliveryStore.load(path);
    expect(reloaded.has("must-not-report-success")).toBe(false);
  });

  test("recovers a lock abandoned past the stale threshold", async () => {
    const store = await DeliveryStore.load(path);
    store.mark("after-abandoned-lock");
    await mkdir(`${path}.lock`);
    const stale = new Date(Date.now() - 31_000);
    await utimes(`${path}.lock`, stale, stale);

    await store.save();

    const reloaded = await DeliveryStore.load(path);
    expect(reloaded.has("after-abandoned-lock")).toBe(true);
  });

  test("barrier-released Node processes keep repeated and distinct marks", { timeout: 45_000 }, async () => {
    const releasePath = join(dir, "release");
    const helperPath = fileURLToPath(new URL("./helpers/delivery_store_process_writer.mjs", import.meta.url));
    const processes = Array.from({ length: 16 }, (_, index) => {
      const readyPath = join(dir, `ready-${index}`);
      const child = spawn(
        process.execPath,
        [helperPath, path, readyPath, releasePath, "shared-msg", `process-msg-${index}`],
        { stdio: ["ignore", "ignore", "pipe"] },
      );
      let stderr = "";
      child.stderr?.setEncoding("utf8");
      child.stderr?.on("data", (chunk) => { stderr += chunk; });
      return { child, readyPath, exited: childExit(child, () => stderr) };
    });

    try {
      await waitForFiles(processes.map(({ readyPath }) => readyPath));
      await writeFile(releasePath, "go\n", { mode: 0o600 });
      await Promise.all(processes.map(({ exited }) => exited));
    } finally {
      for (const { child } of processes) {
        if (child.exitCode === null && child.signalCode === null) child.kill();
      }
    }

    const reloaded = await DeliveryStore.load(path);
    expect(reloaded.has("shared-msg"), "shared-msg").toBe(true);
    for (let index = 0; index < processes.length; index += 1) {
      expect(reloaded.has(`process-msg-${index}`), `process-msg-${index}`).toBe(true);
    }
  });
});
