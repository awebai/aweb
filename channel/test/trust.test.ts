import { describe, expect, test, vi } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
import { mkdtempSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { computeDIDKey } from "../src/identity/did.js";
import { PinStore } from "../src/identity/pinstore.js";
import {
  SenderTrustManager,
  canonicalReplacementJSON,
  canonicalRotationJSON,
  type ReplacementAnnouncement,
  type RotationAnnouncement,
} from "../src/identity/trust.js";

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

function seed(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

async function didFromSeed(byte: number): Promise<{ seed: Uint8Array; did: string }> {
  const priv = seed(byte);
  const pub = await ed.getPublicKeyAsync(priv);
  return { seed: priv, did: computeDIDKey(pub) };
}

function b64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64").replace(/=+$/, "");
}

describe("SenderTrustManager", () => {
  test("marks recipient binding mismatches as identity_mismatch", async () => {
    const { did } = await didFromSeed(1);
    const store = new PinStore();
    const trust = new SenderTrustManager(
      { get: async () => ({ did, lifetime: "persistent", custody: "self" }) } as never,
      { verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }) } as never,
      "backend:acme.com",
      "did:key:zrecipient",
    );

    const result = await trust.normalizeTrust(store, "verified", "alice", did, undefined, "did:key:zwrong");
    expect(result.status).toBe("identity_mismatch");
  });

  test("returns verified_custodial for custodial senders", async () => {
    const { did } = await didFromSeed(2);
    const store = new PinStore();
    const trust = new SenderTrustManager(
      { get: vi.fn() } as never,
      {
        verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }),
        resolveIdentity: async () => ({
          did,
          stableID: "did:aw:custodial",
          address: "acme.com/alice",
          controllerDid: "did:key:zcontroller",
          custody: "custodial",
          lifetime: "persistent",
        }),
      } as never,
      "backend:acme.com",
      "",
    );

    const result = await trust.normalizeTrust(store, "verified", "acme.com/alice", did, undefined, undefined);
    expect(result.status).toBe("verified_custodial");
    expect(store.addresses.get("acme.com/alice")).toBe(did);
  });

  test("removes pins for ephemeral senders", async () => {
    const { did } = await didFromSeed(3);
    const store = new PinStore();
    store.storePin(did, "backend:acme.com/alice", "", "");

    const trust = new SenderTrustManager(
      { get: async () => ({ did, lifetime: "ephemeral", custody: "self" }) } as never,
      { verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }) } as never,
      "backend:acme.com",
      "",
    );

    const result = await trust.normalizeTrust(store, "verified", "alice", did, undefined, undefined);
    expect(result.status).toBe("verified");
    expect(store.addresses.has("backend:acme.com/alice")).toBe(false);
    expect(store.pins.size).toBe(0);
  });

  test("accepts valid rotation announcements", async () => {
    const oldIdentity = await didFromSeed(4);
    const newIdentity = await didFromSeed(5);
    const timestamp = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
    const signature = await ed.signAsync(
      new TextEncoder().encode(canonicalRotationJSON(oldIdentity.did, newIdentity.did, timestamp)),
      oldIdentity.seed,
    );
    const announcement: RotationAnnouncement = {
      old_did: oldIdentity.did,
      new_did: newIdentity.did,
      timestamp,
      old_key_signature: b64(signature),
    };

    const store = new PinStore();
    store.storePin(oldIdentity.did, "backend:acme.com/alice", "", "");
    const trust = new SenderTrustManager(
      { get: async () => ({ did: newIdentity.did, lifetime: "persistent", custody: "self" }) } as never,
      { verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }) } as never,
      "backend:acme.com",
      "",
    );

    const result = await trust.normalizeTrust(
      store,
      "verified",
      "alice",
      newIdentity.did,
      undefined,
      undefined,
      announcement,
    );
    expect(result.status).toBe("verified");
    expect(store.addresses.get("backend:acme.com/alice")).toBe(newIdentity.did);
  });

  test("accepts valid replacement announcements for public addresses", async () => {
    const oldIdentity = await didFromSeed(6);
    const newIdentity = await didFromSeed(7);
    const controller = await didFromSeed(8);
    const timestamp = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
    const signature = await ed.signAsync(
      new TextEncoder().encode(
        canonicalReplacementJSON("acme.com/alice", controller.did, oldIdentity.did, newIdentity.did, timestamp),
      ),
      controller.seed,
    );
    const announcement: ReplacementAnnouncement = {
      address: "acme.com/alice",
      old_did: oldIdentity.did,
      new_did: newIdentity.did,
      controller_did: controller.did,
      timestamp,
      controller_signature: b64(signature),
    };

    const store = new PinStore();
    store.storePin(oldIdentity.did, "acme.com/alice", "", "");
    const trust = new SenderTrustManager(
      { get: async () => ({}) } as never,
      {
        verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }),
        resolveIdentity: async () => ({
          did: newIdentity.did,
          stableID: "did:aw:test",
          address: "acme.com/alice",
          controllerDid: controller.did,
          custody: "self",
          lifetime: "persistent",
        }),
      } as never,
      "backend:acme.com",
      "",
    );

    const result = await trust.normalizeTrust(
      store,
      "verified",
      "acme.com/alice",
      newIdentity.did,
      undefined,
      undefined,
      undefined,
      announcement,
    );
    expect(result.status).toBe("verified");
    expect(store.addresses.get("acme.com/alice")).toBe(newIdentity.did);
  });

  test("pins the local namespace address when registry verification degrades for a public address", async () => {
    const { did } = await didFromSeed(9);
    const stableID = "did:aw:test";
    const store = new PinStore();
    const client = {
      get: vi.fn(async (path: string) => {
        expect(path).toBe("/v1/teams/backend%3Aacme.com/agents/alice");
        return {
          did_key: did,
          did_aw: stableID,
          address: "acme.com/alice",
          lifetime: "persistent",
        };
      }),
    };
    const registry = {
      verifyStableIdentity: vi.fn(async (address: string, stable: string) => {
        expect(address).toBe("acme.com/alice");
        expect(stable).toBe(stableID);
        return { outcome: "OK_DEGRADED" };
      }),
    };
    const trust = new SenderTrustManager(client as never, registry as never, "backend:acme.com", "");

    const result = await trust.normalizeTrust(
      store,
      "verified",
      "alice",
      did,
      stableID,
      undefined,
      undefined,
      undefined,
      "acme.com/alice",
    );

    expect(result.status).toBe("verified");
    expect(store.addresses.get("backend:acme.com/alice")).toBe(stableID);
    expect(store.addresses.has("acme.com/alice")).toBe(false);
    expect(store.pins.get(stableID)?.did_key).toBe(did);
  });

  test("updates a stable-id pin when registry verifies the current did:key", async () => {
    const oldIdentity = await didFromSeed(11);
    const newIdentity = await didFromSeed(12);
    const stableID = "did:aw:amy";
    const store = new PinStore();
    store.storePin(stableID, "acme.com/amy", "", "");
    store.pins.get(stableID)!.stable_id = stableID;
    store.pins.get(stableID)!.did_key = oldIdentity.did;

    const trust = new SenderTrustManager(
      { get: vi.fn() } as never,
      {
        verifyStableIdentity: async () => ({ outcome: "OK_VERIFIED", currentDidKey: newIdentity.did }),
        resolveIdentity: async () => ({
          did: newIdentity.did,
          stableID,
          address: "acme.com/amy",
          controllerDid: "did:key:zcontroller",
          custody: "self",
          lifetime: "persistent",
        }),
      } as never,
      "backend:acme.com",
      "",
    );

    const result = await trust.normalizeTrust(store, "verified", "acme.com/amy", newIdentity.did, stableID, undefined);

    expect(result.status).toBe("verified");
    expect(result.stored).toBe(true);
    expect(store.addresses.get("acme.com/amy")).toBe(stableID);
    expect(store.pins.get(stableID)?.did_key).toBe(newIdentity.did);
  });

  test("replaces a stale address pin when registry verifies a new stable identity", async () => {
    const oldIdentity = await didFromSeed(13);
    const newIdentity = await didFromSeed(14);
    const oldStableID = "did:aw:oldAmy";
    const newStableID = "did:aw:newAmy";
    const store = new PinStore();
    store.storePin(oldStableID, "acme.com/amy", "", "");
    store.pins.get(oldStableID)!.stable_id = oldStableID;
    store.pins.get(oldStableID)!.did_key = oldIdentity.did;

    const trust = new SenderTrustManager(
      { get: vi.fn() } as never,
      {
        verifyStableIdentity: async () => ({ outcome: "OK_VERIFIED", currentDidKey: newIdentity.did }),
        resolveIdentity: async () => ({
          did: newIdentity.did,
          stableID: newStableID,
          address: "acme.com/amy",
          controllerDid: "did:key:zcontroller",
          custody: "self",
          lifetime: "persistent",
        }),
      } as never,
      "backend:acme.com",
      "",
    );

    const result = await trust.normalizeTrust(store, "verified", "acme.com/amy", newIdentity.did, newStableID, undefined);

    expect(result.status).toBe("verified");
    expect(store.pins.has(oldStableID)).toBe(false);
    expect(store.addresses.get("acme.com/amy")).toBe(newStableID);
    expect(store.pins.get(newStableID)?.did_key).toBe(newIdentity.did);
  });

  test("does not replace a stale address pin when registry verification degrades", async () => {
    const oldIdentity = await didFromSeed(15);
    const newIdentity = await didFromSeed(16);
    const oldStableID = "did:aw:oldAmy";
    const newStableID = "did:aw:newAmy";
    const store = new PinStore();
    store.storePin(oldStableID, "acme.com/amy", "", "");
    store.pins.get(oldStableID)!.stable_id = oldStableID;
    store.pins.get(oldStableID)!.did_key = oldIdentity.did;

    const trust = new SenderTrustManager(
      { get: vi.fn() } as never,
      {
        verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }),
        resolveIdentity: async () => ({
          did: newIdentity.did,
          stableID: newStableID,
          address: "acme.com/amy",
          controllerDid: "did:key:zcontroller",
          custody: "self",
          lifetime: "persistent",
        }),
      } as never,
      "backend:acme.com",
      "",
    );

    const result = await trust.normalizeTrust(store, "verified", "acme.com/amy", newIdentity.did, newStableID, undefined);

    expect(result.status).toBe("identity_mismatch");
    expect(store.addresses.get("acme.com/amy")).toBe(oldStableID);
  });

  test("does not create a TOFU pin when public-address resolution fails", async () => {
    const { did } = await didFromSeed(10);
    const stableID = "did:aw:test";
    const store = new PinStore();
    const trust = new SenderTrustManager(
      { get: vi.fn() } as never,
      {
        verifyStableIdentity: vi.fn(async () => ({ outcome: "OK_DEGRADED" })),
        resolveIdentity: vi.fn(async () => {
          throw new Error("registry unavailable");
        }),
      } as never,
      "backend:acme.com",
      "",
    );

    const result = await trust.normalizeTrust(
      store,
      "verified",
      "acme.com/alice",
      did,
      stableID,
      undefined,
      undefined,
      undefined,
      "acme.com/alice",
    );

    expect(result.status).toBe("verified");
    expect(result.stored).toBe(false);
    expect(store.pins.size).toBe(0);
    expect(store.addresses.size).toBe(0);
  });
});

describe("PinStore", () => {
  test("saves YAML to disk atomically", async () => {
    const dir = mkdtempSync(join(tmpdir(), "aweb-channel-"));
    const path = join(dir, "known_agents.yaml");
    const store = new PinStore();
    store.storePin("did:key:zexample", "backend:acme.com/alice", "", "");

    await store.save(path);

    const content = readFileSync(path, "utf-8");
    expect(content).toContain("backend:acme.com/alice");
  });
});
