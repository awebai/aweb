import { execFile } from "node:child_process";
import { chmod, lstat, mkdtemp, readFile, readdir, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { afterAll, beforeAll, describe, expect, test } from "vitest";

import {
  createLocalAWPinStoreWriter,
  PinStore,
  PinStoreCASConflictError,
} from "../src/index.js";

const execFileAsync = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "../..");
let awBinaryDir: string;
let awBinary: string;

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

async function createBarrierCommand(
  dir: string,
  name: string,
  readyPath: string,
  releasePath: string,
): Promise<string> {
  const command = join(dir, name);
  await writeFile(command, [
    "#!/bin/sh",
    `export AW_PIN_STORE_CAS_TEST_READY=${shellQuote(readyPath)}`,
    `export AW_PIN_STORE_CAS_TEST_RELEASE=${shellQuote(releasePath)}`,
    `exec ${shellQuote(awBinary)} "$@"`,
    "",
  ].join("\n"), "utf-8");
  await chmod(command, 0o700);
  return command;
}

async function waitForBarrier(paths: string[]): Promise<void> {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    const ready = await Promise.all(paths.map(async (path) => {
      try {
        await stat(path);
        return true;
      } catch {
        return false;
      }
    }));
    if (ready.every(Boolean)) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error(`pin-store CAS contenders did not reach barrier: ${paths.join(", ")}`);
}

beforeAll(async () => {
  awBinaryDir = await mkdtemp(join(tmpdir(), "aweb-pin-cas-bin-"));
  awBinary = join(awBinaryDir, "aw");
  await execFileAsync("go", [
    "build",
    "-tags", "awebtestpinstorecasbarrier",
    "-o", awBinary,
    "./cmd/aw",
  ], {
    cwd: join(repoRoot, "cli/go"),
    timeout: 120_000,
    maxBuffer: 1024 * 1024,
  });
}, 120_000);

afterAll(async () => {
  if (awBinaryDir) await rm(awBinaryDir, { recursive: true, force: true });
});

describe("pin store compare-and-set delegation", () => {
  test("barriers stale Node writers before distinct-address and same-address CAS races", async () => {
    for (const sameAddress of [false, true]) {
      for (let iteration = 0; iteration < 8; iteration += 1) {
        const dir = await mkdtemp(join(tmpdir(), "aweb-pin-cas-race-"));
        const path = join(dir, "known_agents.yaml");
        const releasePath = join(dir, "release");
        const aliceReady = join(dir, "alice.ready");
        const bobReady = join(dir, "bob.ready");
        const aliceCommand = await createBarrierCommand(dir, "aw-alice", aliceReady, releasePath);
        const bobCommand = await createBarrierCommand(dir, "aw-bob", bobReady, releasePath);
        const aliceWriter = createLocalAWPinStoreWriter({ workdir: repoRoot, awCommand: aliceCommand });
        const bobWriter = createLocalAWPinStoreWriter({ workdir: repoRoot, awCommand: bobCommand });
        const addressSuffix = `${sameAddress ? "shared" : "alice"}-${iteration}`;
        const aliceAddress = `acme.com/${addressSuffix}`;
        const bobAddress = sameAddress ? aliceAddress : `acme.com/bob-${iteration}`;
        const aliceDID = `did:key:zAlice${iteration}`;
        const bobDID = `did:key:zBob${iteration}`;
        const alice = new PinStore();
        const bob = new PinStore();
        alice.storePin(aliceDID, aliceAddress, "", "");
        bob.storePin(bobDID, bobAddress, "", "");
        const commits = [alice.commit(aliceWriter, path), bob.commit(bobWriter, path)];

        try {
          await waitForBarrier([aliceReady, bobReady]);
          await writeFile(releasePath, "release\n", "utf-8");
          const results = await Promise.allSettled(commits);
          expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
          const rejected = results.filter((result) => result.status === "rejected");
          expect(rejected).toHaveLength(1);
          expect(rejected[0]?.reason).toBeInstanceOf(PinStoreCASConflictError);
          expect(String(rejected[0]?.reason)).toMatch(/changed since it was read/);

          const persisted = PinStore.fromYAML(await readFile(path, "utf-8"));
          expect(persisted.pins.size).toBe(1);
          expect(persisted.addresses.size).toBe(1);
          if (sameAddress) {
            expect([aliceDID, bobDID]).toContain(persisted.addresses.get(aliceAddress));
          } else {
            const persistedAddresses = [...persisted.addresses.keys()];
            expect(persistedAddresses.some((address) => address === aliceAddress || address === bobAddress)).toBe(true);
          }
        } finally {
          await writeFile(releasePath, "release\n", "utf-8").catch(() => {});
          await Promise.allSettled(commits);
          await rm(dir, { recursive: true, force: true });
        }
      }
    }
  }, 120_000);

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
