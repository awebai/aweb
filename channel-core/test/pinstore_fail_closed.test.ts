import { afterEach, beforeEach, describe, expect, test } from "vitest";
import { mkdtemp, rm, writeFile, chmod, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadPinStore } from "../src/channel.js";
import { PinStore } from "../src/identity/pinstore.js";

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "pinstore-fc-"));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

const VALID_STORE = [
  "pins:",
  "  did:key:zAlice:",
  "    address: acme.com/alice",
  "    handle: '@alice'",
  "    first_seen: 2026-02-22T10:00:00Z",
  "    last_seen: 2026-02-22T11:00:00Z",
  "    server: https://app.aweb.ai",
  "addresses:",
  "  acme.com/alice: did:key:zAlice",
  "",
].join("\n");

// aajc.2: a corrupt or unreadable pin store must NOT be silently discarded
// (fail-open). loadPinStore returns a fresh store only for a genuinely missing
// file; every other failure throws so the corrupt file is never overwritten.
describe("loadPinStore fails closed", () => {
  test("missing file creates a fresh empty store", async () => {
    const store = await loadPinStore(join(dir, "does-not-exist.yaml"));
    expect(store).toBeInstanceOf(PinStore);
    expect(store.pins.size).toBe(0);
    expect(store.addresses.size).toBe(0);
  });

  test("valid current store loads", async () => {
    const path = join(dir, "known_agents.yaml");
    await writeFile(path, VALID_STORE, "utf-8");
    const store = await loadPinStore(path);
    expect(store.pins.get("did:key:zAlice")?.address).toBe("acme.com/alice");
    expect(store.addresses.get("acme.com/alice")).toBe("did:key:zAlice");
  });

  test("malformed YAML throws instead of returning an empty store", async () => {
    const path = join(dir, "known_agents.yaml");
    await writeFile(path, "pins: {: : :}\n:\n  - broken", "utf-8");
    await expect(loadPinStore(path)).rejects.toThrow();
  });

  test("well-formed YAML with wrong types throws", async () => {
    const path = join(dir, "known_agents.yaml");
    await writeFile(path, "pins: [1, 2, 3]\naddresses: 'not-a-map'\n", "utf-8");
    await expect(loadPinStore(path)).rejects.toThrow(/pins.*mapping/i);
  });

  test("unreadable file throws instead of returning an empty store", async () => {
    const path = join(dir, "known_agents.yaml");
    await writeFile(path, VALID_STORE, "utf-8");
    await chmod(path, 0o000);
    let readable = false;
    try {
      await readFile(path, "utf-8");
      readable = true;
    } catch {
      readable = false;
    }
    if (!readable) {
      await expect(loadPinStore(path)).rejects.toThrow(/cannot read/i);
    }
    await chmod(path, 0o600);
  });

  test("a corrupt store is left byte-for-byte unchanged after a failed load", async () => {
    const path = join(dir, "known_agents.yaml");
    const corrupt = "pins:\n  did:key:zAlice:\n    first_seen: 2026-02-22T10:00:00Z\n";
    await writeFile(path, corrupt, "utf-8");
    await expect(loadPinStore(path)).rejects.toThrow();
    expect(await readFile(path, "utf-8")).toBe(corrupt);
  });

  test("error message reports the path without dumping file contents", async () => {
    const path = join(dir, "known_agents.yaml");
    await writeFile(path, "pins: [1]\n", "utf-8");
    await expect(loadPinStore(path)).rejects.toThrow(new RegExp(path.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  });
});
