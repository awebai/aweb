import { describe, expect, test, vi } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
import { computeDIDKey, PinStore, SenderTrustManager } from "../src/index.js";

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

// One anti-rollback checkpoint per (registry, stable ID); the pin keeps only the
// key binding. A move to another registry starts a new checkpoint, and the
// pin's key binding protects across it (Antares 4dbb84a5, 10.15). Go runs the
// same cases in cli/go/awid/identity_checkpoint_test.go.

const address = "acme.com/alice";
const stableID = "did:aw:checkpointAlice";
const registryURL = "https://registry.example";
const oldRegistry = "https://old-registry.example";

async function did(byte: number): Promise<string> {
  return computeDIDKey(await ed.getPublicKeyAsync(new Uint8Array(32).fill(byte)));
}

function head(seq: number, hashChar: string, currentDidKey: string) {
  return { seq, entryHash: hashChar.repeat(64), stateHash: "", currentDidKey, fetchedAt: 0 };
}

interface Answer {
  registryURL: string;
  newCheckpoint: boolean;
  currentDidKey: string;
  verifiedHead: ReturnType<typeof head>;
}

function trustWith(answer: Answer, seen: { seed?: unknown }) {
  return new SenderTrustManager(
    { get: vi.fn() } as never,
    {
      resolveIdentity: vi.fn(async () => ({
        did: answer.currentDidKey, stableID, address, controllerDid: "did:key:zcontroller",
        custody: "self", identityScope: "global",
      })),
      verifyStableIdentity: vi.fn(async (_address: string, _stableID: string, _did: string,
        checkpointFor?: (registry: string) => unknown) => {
        seen.seed = checkpointFor?.(answer.registryURL);
        return { outcome: "OK_VERIFIED", currentDidKey: answer.currentDidKey, verifiedHead: answer.verifiedHead,
          registryURL: answer.registryURL, newCheckpoint: answer.newCheckpoint };
      }),
    } as never,
    "backend:acme.com",
    "",
  );
}

function pinned(store: PinStore, didKey: string, anchor?: ReturnType<typeof head>) {
  store.storePin(stableID, address, "", "");
  const pin = store.pins.get(stableID)!;
  pin.stable_id = stableID;
  pin.did_key = didKey;
  pin.confirmed_by = "registry";
  if (anchor) {
    pin.log_seq = anchor.seq;
    pin.log_entry_hash = anchor.entryHash;
  }
}

describe("identity checkpoints", () => {
  test("a verified head is checkpointed under its registry, not on the pin", async () => {
    const key = await did(71);
    const store = new PinStore();
    const result = await trustWith(
      { registryURL, newCheckpoint: true, currentDidKey: key, verifiedHead: head(1, "a", key) }, {},
    ).normalizeTrust(store, "verified", address, key, stableID, undefined);

    expect(result.status).toBe("verified");
    expect(store.receivedIdentityCheckpoint(registryURL, stableID)?.seq).toBe(1);
    expect(store.pins.get(stableID)?.log_seq).toBeUndefined();
  });

  test("a legacy pin anchor seeds the registry once and is carried into the map", async () => {
    const key = await did(72);
    const store = new PinStore();
    pinned(store, key, head(2, "b", key));
    const seen: { seed?: unknown } = {};
    const result = await trustWith(
      { registryURL, newCheckpoint: false, currentDidKey: key, verifiedHead: head(2, "b", key) }, seen,
    ).normalizeTrust(store, "verified", address, key, stableID, undefined);

    expect(result.status).toBe("verified");
    expect(seen.seed).toMatchObject({ seq: 2, entryHash: "b".repeat(64) });
    expect(store.receivedIdentityCheckpoint(registryURL, stableID)?.seq).toBe(2);
    expect(store.pins.get(stableID)?.log_seq).toBeUndefined();
    expect(store.pins.get(stableID)?.log_entry_hash).toBeUndefined();
  });

  test("a registry move starts a new checkpoint and leaves the old one", async () => {
    const key = await did(73);
    const store = new PinStore();
    pinned(store, key);
    store.advanceReceivedIdentityCheckpoint(oldRegistry, stableID, head(2, "c", key));
    const seen: { seed?: unknown } = {};
    const result = await trustWith(
      { registryURL, newCheckpoint: true, currentDidKey: key, verifiedHead: head(2, "c", key) }, seen,
    ).normalizeTrust(store, "verified", address, key, stableID, undefined);

    expect(result.status).toBe("verified");
    expect(seen.seed).toBeUndefined();
    expect(store.receivedIdentityCheckpoint(registryURL, stableID)?.seq).toBe(2);
    expect(store.receivedIdentityCheckpoint(oldRegistry, stableID)?.entryHash).toBe("c".repeat(64));
  });

  test("a new registry presenting an older key than the pin is a mismatch", async () => {
    const olderKey = await did(74);
    const pinnedKey = await did(75);
    const store = new PinStore();
    pinned(store, pinnedKey);
    store.advanceReceivedIdentityCheckpoint(oldRegistry, stableID, head(2, "d", pinnedKey));
    const result = await trustWith(
      { registryURL, newCheckpoint: true, currentDidKey: olderKey, verifiedHead: head(1, "e", olderKey) }, {},
    ).normalizeTrust(store, "verified", address, olderKey, stableID, undefined);

    expect(result.status).toBe("identity_mismatch");
    expect(store.pins.get(stableID)?.did_key).toBe(pinnedKey);
  });
});
