import { execFile } from "node:child_process";
import { lstat, mkdtemp, readFile, readdir, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { beforeAll, describe, expect, test } from "vitest";

import {
  createLocalAWPinStoreWriter,
  PinStore,
  PinStoreCASConflictError,
} from "../src/index.js";

const execFileAsync = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "../..");
let awBinary: string;

beforeAll(async () => {
  const dir = await mkdtemp(join(tmpdir(), "aweb-pin-cas-bin-"));
  awBinary = join(dir, "aw");
  await execFileAsync("go", ["build", "-o", awBinary, "./cmd/aw"], {
    cwd: join(repoRoot, "cli/go"),
    timeout: 120_000,
    maxBuffer: 1024 * 1024,
  });
}, 120_000);

describe("pin store compare-and-set delegation", () => {
  test("two stale Node snapshots cannot silently erase one another", async () => {
    const writer = createLocalAWPinStoreWriter({ workdir: repoRoot, awCommand: awBinary });

    for (let iteration = 0; iteration < 24; iteration += 1) {
      const dir = await mkdtemp(join(tmpdir(), "aweb-pin-cas-race-"));
      const path = join(dir, "known_agents.yaml");
      const alice = new PinStore();
      const bob = new PinStore();
      alice.storePin(`did:key:zAlice${iteration}`, `acme.com/alice-${iteration}`, "", "");
      bob.storePin(`did:key:zBob${iteration}`, `acme.com/bob-${iteration}`, "", "");

      const results = await Promise.allSettled([
        alice.commit(writer, path),
        bob.commit(writer, path),
      ]);
      expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
      const rejected = results.filter((result) => result.status === "rejected");
      expect(rejected).toHaveLength(1);
      expect(rejected[0]?.reason).toBeInstanceOf(PinStoreCASConflictError);
      expect(String(rejected[0]?.reason)).toMatch(/changed since it was read/);

      const persisted = PinStore.fromYAML(await readFile(path, "utf-8"));
      expect(persisted.pins.size).toBe(1);
      expect(persisted.addresses.size).toBe(1);
    }
  }, 60_000);

  test("aw writes atomically with restrictive permissions", async () => {
    const dir = await mkdtemp(join(tmpdir(), "aweb-pin-cas-atomic-"));
    const path = join(dir, "known_agents.yaml");
    const store = new PinStore();
    store.storePin("did:key:zAlice", "acme.com/alice", "@alice", "https://app.aweb.ai");
    const writer = createLocalAWPinStoreWriter({ workdir: repoRoot, awCommand: awBinary });

    await store.commit(writer, path);

    expect((await stat(path)).mode & 0o777).toBe(0o600);
    expect(PinStore.fromYAML(await readFile(path, "utf-8")).addresses.get("acme.com/alice"))
      .toBe("did:key:zAlice");
    expect((await readdir(dir)).filter((name) => name.includes(".tmp-"))).toEqual([]);
  });

  test("aw replaces a valid-store symlink without writing through it", async () => {
    const dir = await mkdtemp(join(tmpdir(), "aweb-pin-cas-symlink-"));
    const victim = join(dir, "victim.yaml");
    const emptyStore = new PinStore().toYAML();
    await writeFile(victim, emptyStore, "utf-8");
    const path = join(dir, "known_agents.yaml");
    await symlink(victim, path);
    const store = new PinStore();
    store.storePin("did:key:zAlice", "acme.com/alice", "", "");
    const writer = createLocalAWPinStoreWriter({ workdir: repoRoot, awCommand: awBinary });

    await store.commit(writer, path);

    expect(await readFile(victim, "utf-8")).toBe(emptyStore);
    expect((await lstat(path)).isSymbolicLink()).toBe(false);
  });

  test("a missing aw binary fails closed without writing", async () => {
    const dir = await mkdtemp(join(tmpdir(), "aweb-pin-cas-missing-aw-"));
    const path = join(dir, "known_agents.yaml");
    const store = new PinStore();
    store.storePin("did:key:zAlice", "acme.com/alice", "", "");
    const writer = createLocalAWPinStoreWriter({
      workdir: repoRoot,
      awCommand: join(dir, "does-not-exist"),
    });

    await expect(store.commit(writer, path)).rejects.toThrow();
    await expect(readFile(path, "utf-8")).rejects.toMatchObject({ code: "ENOENT" });
  });
});
