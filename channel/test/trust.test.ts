import { describe, expect, test } from "vitest";
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
      "acme/self",
      "did:key:zrecipient",
    );

    const result = await trust.normalizeTrust(store, "verified", "alice", did, undefined, "did:key:zwrong");
    expect(result.status).toBe("identity_mismatch");
  });

  test("returns verified_custodial for custodial senders", async () => {
    const { did } = await didFromSeed(2);
    const store = new PinStore();
    const trust = new SenderTrustManager(
      { get: async () => ({ did, lifetime: "persistent", custody: "custodial" }) } as never,
      { verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }) } as never,
      "acme/self",
      "",
    );

    const result = await trust.normalizeTrust(store, "verified", "alice", did, undefined, undefined);
    expect(result.status).toBe("verified_custodial");
    expect(store.addresses.get("acme/alice")).toBe(did);
  });

  test("removes pins for ephemeral senders", async () => {
    const { did } = await didFromSeed(3);
    const store = new PinStore();
    store.storePin(did, "acme/alice", "", "");

    const trust = new SenderTrustManager(
      { get: async () => ({ did, lifetime: "ephemeral", custody: "self" }) } as never,
      { verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }) } as never,
      "acme/self",
      "",
    );

    const result = await trust.normalizeTrust(store, "verified", "alice", did, undefined, undefined);
    expect(result.status).toBe("verified");
    expect(store.addresses.has("acme/alice")).toBe(false);
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
    store.storePin(oldIdentity.did, "acme/alice", "", "");
    const trust = new SenderTrustManager(
      { get: async () => ({ did: newIdentity.did, lifetime: "persistent", custody: "self" }) } as never,
      { verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }) } as never,
      "acme/self",
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
    expect(store.addresses.get("acme/alice")).toBe(newIdentity.did);
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
      "acme/self",
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
});

describe("PinStore", () => {
  test("saves YAML to disk atomically", async () => {
    const dir = mkdtempSync(join(tmpdir(), "aweb-channel-"));
    const path = join(dir, "known_agents.yaml");
    const store = new PinStore();
    store.storePin("did:key:zexample", "acme/alice", "", "");

    await store.save(path);

    const content = readFileSync(path, "utf-8");
    expect(content).toContain("acme/alice");
  });
});
