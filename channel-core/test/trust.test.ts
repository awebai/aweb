import { describe, expect, test, vi } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
import { mkdtempSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import yaml from "js-yaml";
import {
  computeDIDKey,
  PinStore,
  SenderTrustManager,
  canonicalReplacementJSON,
  canonicalRotationJSON,
  type ReplacementAnnouncement,
  type RotationAnnouncement,
} from "../src/index.js";

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
      { get: async () => ({ did, identity_scope: "global", custody: "self" }) } as never,
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
          identityScope: "global",
        }),
      } as never,
      "backend:acme.com",
      "",
    );

    const result = await trust.normalizeTrust(store, "verified", "acme.com/alice", did, undefined, undefined);
    expect(result.status).toBe("verified_custodial");
    expect(store.addresses.get("acme.com/alice")).toBe(did);
  });

  test("removes pins for local-scope senders", async () => {
    const { did } = await didFromSeed(3);
    const store = new PinStore();
    store.storePin(did, "backend:acme.com/alice", "", "");

    const trust = new SenderTrustManager(
      { get: async () => ({ did, identity_scope: "local", custody: "self" }) } as never,
      { verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }) } as never,
      "backend:acme.com",
      "",
    );

    const result = await trust.normalizeTrust(store, "verified", "alice", did, undefined, undefined);
    expect(result.status).toBe("verified");
    expect(store.addresses.has("backend:acme.com/alice")).toBe(false);
    expect(store.pins.size).toBe(0);
  });

  test("relabels stale local metadata after authoritative no-cache row refresh", async () => {
    const oldIdentity = await didFromSeed(32);
    const currentIdentity = await didFromSeed(33);
    const store = new PinStore();
    const getFresh = vi.fn(async () => ({ did_key: currentIdentity.did, identity_scope: "local", custody: "self" }));
    const trust = new SenderTrustManager(
      {
        get: async () => ({ did_key: oldIdentity.did, identity_scope: "global", custody: "self" }),
        getFresh,
      } as never,
      { verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }) } as never,
      "backend:acme.com",
      "",
    );

    expect((await trust.normalizeTrust(store, "verified", "alice", oldIdentity.did, undefined, undefined)).status).toBe("verified");
    expect((await trust.normalizeTrust(store, "verified", "alice", currentIdentity.did, undefined, undefined)).status).toBe("verification_stale");
    expect(getFresh).toHaveBeenCalledTimes(1);
    expect(store.pins.size).toBe(0);
    expect((await trust.normalizeTrust(store, "verified", "alice", currentIdentity.did, undefined, undefined)).status).toBe("verified");
  });

  test("preserves local mismatch when the authoritative roster row has a different key", async () => {
    const oldIdentity = await didFromSeed(34);
    const rosterIdentity = await didFromSeed(35);
    const attacker = await didFromSeed(36);
    const store = new PinStore();
    const trust = new SenderTrustManager(
      {
        get: async () => ({ did_key: oldIdentity.did, identity_scope: "global", custody: "self" }),
        getFresh: async () => ({ did_key: rosterIdentity.did, identity_scope: "local", custody: "self" }),
      } as never,
      { verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }) } as never,
      "backend:acme.com",
      "",
    );

    expect((await trust.normalizeTrust(store, "verified", "alice", oldIdentity.did, undefined, undefined)).status).toBe("verified");
    expect((await trust.normalizeTrust(store, "verified", "alice", attacker.did, undefined, undefined)).status).toBe("identity_mismatch");
  });

  test("preserves local mismatch when the sender is absent from the roster", async () => {
    const oldIdentity = await didFromSeed(37);
    const attacker = await didFromSeed(38);
    const store = new PinStore();
    const trust = new SenderTrustManager(
      {
        get: async () => ({ did_key: oldIdentity.did, identity_scope: "global", custody: "self" }),
        getFresh: async () => { throw Object.assign(new Error("not found"), { statusCode: 404 }); },
      } as never,
      { verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }) } as never,
      "backend:acme.com",
      "",
    );

    expect((await trust.normalizeTrust(store, "verified", "alice", oldIdentity.did, undefined, undefined)).status).toBe("verified");
    expect((await trust.normalizeTrust(store, "verified", "alice", attacker.did, undefined, undefined)).status).toBe("identity_mismatch");
  });

  test("reports local verification stale when authoritative refresh is unavailable", async () => {
    const oldIdentity = await didFromSeed(39);
    const changedIdentity = await didFromSeed(40);
    const store = new PinStore();
    const trust = new SenderTrustManager(
      {
        get: async () => ({ did_key: oldIdentity.did, identity_scope: "global", custody: "self" }),
        getFresh: async () => { throw new TypeError("fetch failed"); },
      } as never,
      { verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }) } as never,
      "backend:acme.com",
      "",
    );

    expect((await trust.normalizeTrust(store, "verified", "alice", oldIdentity.did, undefined, undefined)).status).toBe("verified");
    expect((await trust.normalizeTrust(store, "verified", "alice", changedIdentity.did, undefined, undefined)).status).toBe("verification_stale");
  });

  test("normalizes legacy ephemeral lifetime metadata as local scope", async () => {
    const { did } = await didFromSeed(30);
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

  test("normalizes legacy persistent lifetime metadata as global scope", async () => {
    const { did } = await didFromSeed(31);
    const store = new PinStore();
    const trust = new SenderTrustManager(
      { get: async () => ({ did, lifetime: "persistent", custody: "self" }) } as never,
      { verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }) } as never,
      "backend:acme.com",
      "",
    );

    const result = await trust.normalizeTrust(store, "verified", "alice", did, undefined, undefined);
    expect(result.status).toBe("verified");
    expect(store.addresses.get("backend:acme.com/alice")).toBe(did);
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
      { get: async () => ({ did: newIdentity.did, identity_scope: "global", custody: "self" }) } as never,
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
          identityScope: "global",
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
      undefined,
      announcement,
    );
    expect(result.status).toBe("verified");
    expect(store.addresses.get("acme.com/alice")).toBe(newIdentity.did);
  });

  test("authorized replacement cleanup cannot resurrect removed unknown pin fields", async () => {
    const oldIdentity = await didFromSeed(32);
    const newIdentity = await didFromSeed(33);
    const controller = await didFromSeed(34);
    const address = "acme.com/alice";
    const timestamp = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
    const signature = await ed.signAsync(
      new TextEncoder().encode(
        canonicalReplacementJSON(address, controller.did, oldIdentity.did, newIdentity.did, timestamp),
      ),
      controller.seed,
    );
    const announcement: ReplacementAnnouncement = {
      address,
      old_did: oldIdentity.did,
      new_did: newIdentity.did,
      controller_did: controller.did,
      timestamp,
      controller_signature: b64(signature),
    };
    const store = PinStore.fromYAML([
      "pins:",
      `  ${oldIdentity.did}:`,
      `    address: ${address}`,
      "    first_seen: 2026-02-22T10:00:00Z",
      "    last_seen: 2026-02-22T11:00:00Z",
      "    future_anti_rollback_anchor: {seq: 9, hash: abc}",
      "addresses:",
      `  ${address}: ${oldIdentity.did}`,
      "",
    ].join("\n"));
    const trust = new SenderTrustManager(
      { get: async () => ({}) } as never,
      {
        resolveIdentity: async () => ({
          did: newIdentity.did,
          stableID: "did:aw:newAlice",
          address,
          controllerDid: controller.did,
          custody: "self",
          identityScope: "global",
        }),
      } as never,
      "backend:acme.com",
      "",
    );

    const result = await trust.normalizeTrust(
      store,
      "verified",
      address,
      newIdentity.did,
      undefined,
      undefined,
      undefined,
      undefined,
      announcement,
    );
    expect(result.status).toBe("verified");
    expect(store.addresses.get(address)).toBe(newIdentity.did);

    store.removeAddress(address);
    store.storePin(oldIdentity.did, address, "", "");
    const emitted = yaml.load(store.toYAML(), { schema: yaml.JSON_SCHEMA }) as {
      pins: Record<string, Record<string, unknown>>;
    };
    expect(emitted.pins[oldIdentity.did].future_anti_rollback_anchor).toBeUndefined();
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
          identity_scope: "global",
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
      undefined,
      "acme.com/alice",
    );

    expect(result.status).toBe("verified");
    expect(store.addresses.get("backend:acme.com/alice")).toBe(stableID);
    expect(store.addresses.has("acme.com/alice")).toBe(false);
    expect(store.pins.get(stableID)?.did_key).toBe(did);
  });

  test("stable-id migration refuses an occupied target without losing either pin", async () => {
    const identity = await didFromSeed(36);
    const stableID = "did:aw:stableCollision";
    const address = "acme.com/alice";
    const store = PinStore.fromYAML([
      "pins:",
      `  ${identity.did}:`,
      `    address: ${address}`,
      "    first_seen: 2026-02-22T10:00:00Z",
      "    last_seen: 2026-02-22T11:00:00Z",
      "    future_old: {seq: 1}",
      `  ${stableID}:`,
      `    address: ${address}`,
      "    first_seen: 2026-02-22T09:00:00Z",
      "    last_seen: 2026-02-22T09:30:00Z",
      "    future_stable: {seq: 9}",
      "addresses:",
      `  ${address}: ${identity.did}`,
      "",
    ].join("\n"));
    const trust = new SenderTrustManager(
      { get: async () => ({}) } as never,
      {
        resolveIdentity: async () => ({
          did: identity.did,
          stableID,
          address,
          controllerDid: identity.did,
          custody: "self",
          identityScope: "global",
        }),
        verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }),
      } as never,
      "backend:acme.com",
      "",
    );

    const result = await trust.normalizeTrust(
      store,
      "verified",
      address,
      identity.did,
      stableID,
      undefined,
      undefined,
    );

    expect(result).toEqual({ status: "pin_conflict", stored: false });
    expect(new Set(store.pins.keys())).toEqual(new Set([identity.did, stableID]));
    expect(store.addresses.get(address)).toBe(identity.did);
    const emitted = yaml.load(store.toYAML(), { schema: yaml.JSON_SCHEMA }) as {
      pins: Record<string, Record<string, unknown>>;
    };
    expect(emitted.pins[identity.did].future_old).toEqual({ seq: 1 });
    expect(emitted.pins[stableID].future_stable).toEqual({ seq: 9 });
  });

  test("stable-id migration preserves unknown per-pin fields", async () => {
    const identity = await didFromSeed(35);
    const stableID = "did:aw:stableAlice";
    const address = "acme.com/alice";
    const store = PinStore.fromYAML([
      "pins:",
      `  ${identity.did}:`,
      `    address: ${address}`,
      "    first_seen: 2026-02-22T10:00:00Z",
      "    last_seen: 2026-02-22T11:00:00Z",
      "    future_anti_rollback_anchor: {seq: 9, hash: abc}",
      "addresses:",
      `  ${address}: ${identity.did}`,
      "",
    ].join("\n"));
    const trust = new SenderTrustManager(
      { get: async () => ({}) } as never,
      {
        resolveIdentity: async () => ({
          did: identity.did,
          stableID,
          address,
          controllerDid: identity.did,
          custody: "self",
          identityScope: "global",
        }),
        verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }),
      } as never,
      "backend:acme.com",
      "",
    );

    const result = await trust.normalizeTrust(
      store,
      "verified",
      address,
      identity.did,
      stableID,
      undefined,
      undefined,
    );
    expect(result.status).toBe("verified");
    expect(store.addresses.get(address)).toBe(stableID);

    const emitted = yaml.load(store.toYAML(), { schema: yaml.JSON_SCHEMA }) as {
      pins: Record<string, Record<string, unknown>>;
    };
    expect(emitted.pins[identity.did]).toBeUndefined();
    expect(emitted.pins[stableID].future_anti_rollback_anchor).toEqual({ seq: 9, hash: "abc" });
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
          identityScope: "global",
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

  // A registry-verified DID log for a DIFFERENT stable identity is not authority
  // to take over an address pinned to someone else: the log proves did:aw ->
  // did:key, never address -> did:aw. Without a namespace-controller-signed
  // replacement announcement the existing pin stands (default-aajc.8).
  test("does not replace a stale address pin when registry verifies a different stable identity", async () => {
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
          identityScope: "global",
        }),
      } as never,
      "backend:acme.com",
      "",
    );

    const result = await trust.normalizeTrust(store, "verified", "acme.com/amy", newIdentity.did, newStableID, undefined);

    expect(result.status).toBe("identity_mismatch");
    expect(store.addresses.get("acme.com/amy")).toBe(oldStableID);
    expect(store.pins.get(oldStableID)?.did_key).toBe(oldIdentity.did);
    expect(store.pins.has(newStableID)).toBe(false);
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
          identityScope: "global",
        }),
      } as never,
      "backend:acme.com",
      "",
    );

    const result = await trust.normalizeTrust(store, "verified", "acme.com/amy", newIdentity.did, newStableID, undefined);

    expect(result.status).toBe("identity_mismatch");
    expect(store.addresses.get("acme.com/amy")).toBe(oldStableID);
  });

  test("refuses invalid verified-head sequences before persisting checkpoints", () => {
    const stableID = "did:aw:checkpoint";
    const store = new PinStore();
    store.storePin(stableID, "acme.com/alice", "", "");
    const trust = new SenderTrustManager(
      { get: vi.fn() } as never,
      {} as never,
      "backend:acme.com",
      "",
    ) as SenderTrustManager & {
      persistVerifiedHeadCheckpoint(
        target: PinStore,
        id: string,
        head: {
          seq: number;
          entryHash: string;
          stateHash: string;
          currentDidKey: string;
          fetchedAt: number;
        },
      ): boolean;
    };

    for (const seq of [1.5, Number.NaN, Number.POSITIVE_INFINITY, Number.MAX_SAFE_INTEGER + 1]) {
      expect(trust.persistVerifiedHeadCheckpoint(store, stableID, {
        seq,
        entryHash: "a".repeat(64),
        stateHash: "b".repeat(64),
        currentDidKey: "did:key:zcheckpoint",
        fetchedAt: 0,
      })).toBe(false);
    }

    expect(store.pins.get(stableID)?.log_seq).toBeUndefined();
  });

  test("surfaces stale verifier cache honestly instead of claiming identity mismatch", async () => {
    const { did } = await didFromSeed(17);
    const stableID = "did:aw:freshAlice";
    const trust = new SenderTrustManager(
      { get: vi.fn() } as never,
      {
        verifyStableIdentity: vi.fn(async () => ({ outcome: "STALE_CACHE" })),
        resolveIdentity: vi.fn(async () => ({
          did,
          stableID,
          address: "acme.com/alice",
          controllerDid: "did:key:zcontroller",
          custody: "self",
          identityScope: "global",
        })),
      } as never,
      "backend:acme.com",
      "",
    );

    const result = await trust.normalizeTrust(
      new PinStore(),
      "verified",
      "acme.com/alice",
      did,
      stableID,
      undefined,
    );

    expect(result.status).toBe("verification_stale");
    expect(result.stored).toBe(false);
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
