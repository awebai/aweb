import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, test } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
import { computeDIDKey } from "../src/identity/did.js";
import { PinStore } from "../src/identity/pinstore.js";
import {
  SenderTrustManager,
  canonicalReplacementJSON,
  canonicalRotationJSON,
  type ReplacementAnnouncement,
  type RotationAnnouncement,
} from "../src/identity/trust.js";
import { verifySignedPayload, type VerificationStatus } from "../src/identity/signing.js";

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

interface RecipientBindingVectorFile {
  schema: string;
  vectors: RecipientBindingVector[];
}

interface RecipientBindingVector {
  name: string;
  initial_status: VerificationStatus;
  self_did: string;
  self_stable_id: string;
  to_did: string;
  to_stable_id: string;
  expected_status: VerificationStatus;
}

interface CryptoSignatureVectorFile {
  schema: string;
  vectors: CryptoSignatureVector[];
}

interface CryptoSignatureVector {
  name: string;
  signed_payload: string;
  signature: string;
  from_did: string;
  signing_key_id: string | null;
  expected_status: VerificationStatus;
}

interface RegistryVectorFile {
  schema: string;
  vectors: RegistryVector[];
}

interface RegistryVector {
  name: string;
  initial_status: VerificationStatus;
  trust_address: string;
  from_did: string;
  from_stable_id: string;
  registry_state: Record<string, RegistryStateVerification>;
  expected_status: VerificationStatus;
  expected_confirmed_current_key: boolean;
}

interface RegistryStateVerification {
  outcome: "verified" | "hard_error" | "ok_degraded";
  current_did_key: string;
}

interface TOFUVectorFile {
  schema: string;
  vectors: TOFUVector[];
}

interface TOFUVector {
  name: string;
  initial_status: VerificationStatus;
  raw_address: string;
  trust_address: string;
  from_did: string;
  from_stable_id: string;
  rotation_announcement: RotationAnnouncementVector | null;
  replacement_announcement: ReplacementAnnouncementVector | null;
  agent_meta: AgentMetaVector;
  registry_confirmed_current_key: boolean;
  pin_store_before: PinStoreVector;
  expected_status: VerificationStatus;
  expected_pin_store_after: PinStoreVector | null;
}

interface RotationAnnouncementVector {
  mode: "runtime_generated";
  old_did: string;
  new_did: string;
  timestamp_delta_seconds: number;
  old_seed_byte: number;
  corrupt_signature?: boolean;
}

interface ReplacementAnnouncementVector {
  mode: "runtime_generated";
  address: string;
  old_did: string;
  new_did: string;
  controller_did: string;
  timestamp_delta_seconds: number;
  controller_seed_byte: number;
}

interface AgentMetaVector {
  lifetime: string;
  custody: string;
  controller_did?: string;
}

interface PinStoreVector {
  pins: Record<string, PinVector>;
  addresses: Record<string, string>;
}

interface PinVector {
  address: string;
  stable_id?: string;
  did_key?: string;
  first_seen: string;
  last_seen: string;
  server?: string;
}

const testDir = dirname(fileURLToPath(import.meta.url));

function loadCryptoSignatureVectors(): CryptoSignatureVectorFile {
  return JSON.parse(
    readFileSync(join(testDir, "..", "..", "test-vectors", "trust", "crypto-sig-v1.json"), "utf-8"),
  ) as CryptoSignatureVectorFile;
}

function loadRecipientBindingVectors(): RecipientBindingVectorFile {
  return JSON.parse(
    readFileSync(join(testDir, "..", "..", "test-vectors", "trust", "recipient-binding-v1.json"), "utf-8"),
  ) as RecipientBindingVectorFile;
}

function loadRegistryVectors(): RegistryVectorFile {
  return JSON.parse(
    readFileSync(join(testDir, "..", "..", "test-vectors", "trust", "registry-v1.json"), "utf-8"),
  ) as RegistryVectorFile;
}

function loadTOFUVectors(): TOFUVectorFile {
  return JSON.parse(
    readFileSync(join(testDir, "..", "..", "test-vectors", "trust", "tofu-v1.json"), "utf-8"),
  ) as TOFUVectorFile;
}

describe("trust conformance vectors", () => {
  test("crypto signatures match the shared contract", async () => {
    const vectorFile = loadCryptoSignatureVectors();
    expect(vectorFile.schema).toBe("aweb.trust.crypto-sig.v1");

    for (const vector of vectorFile.vectors) {
      const result = await verifySignedPayload(
        vector.signed_payload,
        vector.signature,
        vector.from_did,
        vector.signing_key_id ?? "",
      );

      expect(result, vector.name).toBe(vector.expected_status);
    }
  });

  test("sender registry checks match the shared contract", async () => {
    const vectorFile = loadRegistryVectors();
    expect(vectorFile.schema).toBe("aweb.trust.registry.v1");

    for (const vector of vectorFile.vectors) {
      const trust = new SenderTrustManager(
        { get: async () => ({}) } as never,
        {
          verifyStableIdentity: async (_address: string, stableID: string) => {
            const entry = vector.registry_state[stableID];
            if (!entry) return { outcome: "HARD_ERROR" };
            switch (entry.outcome) {
              case "verified":
                return { outcome: "OK_VERIFIED", currentDidKey: entry.current_did_key };
              case "hard_error":
                return { outcome: "HARD_ERROR" };
              case "ok_degraded":
                return { outcome: "OK_DEGRADED" };
            }
          },
        } as never,
        "",
        "",
      ) as SenderTrustManager & {
        // Access private method directly for isolated Pass C testing; production instance is real.
        checkStableIdentityRegistry(
          status: VerificationStatus | undefined,
          trustAddress: string,
          fromDID: string | undefined,
          fromStableID: string | undefined,
        ): Promise<{ status: VerificationStatus | undefined; confirmedCurrentKey: boolean }>;
      };

      const result = await trust.checkStableIdentityRegistry(
        vector.initial_status,
        vector.trust_address,
        vector.from_did,
        vector.from_stable_id,
      );

      expect(result.status, vector.name).toBe(vector.expected_status);
      expect(result.confirmedCurrentKey, vector.name).toBe(vector.expected_confirmed_current_key);
    }
  });

  test("TOFU pin continuity matches the shared contract", async () => {
    const vectorFile = loadTOFUVectors();
    expect(vectorFile.schema).toBe("aweb.trust.tofu.v1");

    for (const vector of vectorFile.vectors) {
      const store = pinStoreFromVector(vector.pin_store_before);
      const trust = new SenderTrustManager(
        { get: async () => ({}) } as never,
        { verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }) } as never,
        "",
        "",
      ) as SenderTrustManager & {
        // Access private method directly for isolated Pass D testing; production instance is real.
        checkTOFUPinWithMeta(
          store: PinStore,
          status: VerificationStatus | undefined,
          rawAddress: string,
          trustAddress: string,
          fromDID: string | undefined,
          fromStableID: string | undefined,
          rotationAnnouncement: RotationAnnouncement | undefined,
          replacementAnnouncement: ReplacementAnnouncement | undefined,
          meta: { lifetime: string; custody: string; controllerDid?: string; resolved: boolean },
          registryConfirmedCurrentKey: boolean,
        ): { status: VerificationStatus | undefined; stored: boolean };
      };

      const result = trust.checkTOFUPinWithMeta(
        store,
        vector.initial_status,
        vector.raw_address,
        vector.trust_address,
        vector.from_did,
        vector.from_stable_id,
        await buildRotationAnnouncement(vector.rotation_announcement),
        await buildReplacementAnnouncement(vector.replacement_announcement),
        {
          lifetime: vector.agent_meta.lifetime,
          custody: vector.agent_meta.custody,
          controllerDid: vector.agent_meta.controller_did,
          resolved: true,
        },
        vector.registry_confirmed_current_key,
      );

      expect(result.status, vector.name).toBe(vector.expected_status);
      assertPinStoreMatchesVector(
        store,
        vector.expected_pin_store_after ?? vector.pin_store_before,
        vector.pin_store_before,
        vector.name,
      );
    }
  });

  test("recipient binding matches the shared contract", async () => {
    const vectorFile = loadRecipientBindingVectors();
    expect(vectorFile.schema).toBe("aweb.trust.recipient-binding.v1");

    for (const vector of vectorFile.vectors) {
      const trust = new SenderTrustManager(
        { get: async () => ({}) } as never,
        { verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }) } as never,
        "",
        vector.self_did,
        vector.self_stable_id,
      );

      const result = await trust.normalizeTrust(
        new PinStore(),
        vector.initial_status,
        "sender.example/alice",
        undefined,
        undefined,
        vector.to_did,
        vector.to_stable_id,
      );

      expect(result.status, vector.name).toBe(vector.expected_status);
    }
  });
});

function pinStoreFromVector(vector: PinStoreVector): PinStore {
  const store = new PinStore();
  for (const [key, pin] of Object.entries(vector.pins)) {
    store.pins.set(key, {
      address: pin.address,
      handle: "",
      stable_id: pin.stable_id || undefined,
      did_key: pin.did_key || undefined,
      first_seen: pin.first_seen,
      last_seen: pin.last_seen,
      server: pin.server || "",
    });
  }
  for (const [address, key] of Object.entries(vector.addresses)) {
    store.addresses.set(address, key);
  }
  return store;
}

async function buildRotationAnnouncement(vector: RotationAnnouncementVector | null): Promise<RotationAnnouncement | undefined> {
  if (!vector) return undefined;
  const privateKey = seed(vector.old_seed_byte);
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  expect(computeDIDKey(publicKey)).toBe(vector.old_did);
  const timestamp = timestampFromDelta(vector.timestamp_delta_seconds);
  const signature = await ed.signAsync(
    new TextEncoder().encode(canonicalRotationJSON(vector.old_did, vector.new_did, timestamp)),
    privateKey,
  );
  return {
    old_did: vector.old_did,
    new_did: vector.new_did,
    timestamp,
    old_key_signature: vector.corrupt_signature ? corruptBase64Signature(b64(signature)) : b64(signature),
  };
}

async function buildReplacementAnnouncement(
  vector: ReplacementAnnouncementVector | null,
): Promise<ReplacementAnnouncement | undefined> {
  if (!vector) return undefined;
  const privateKey = seed(vector.controller_seed_byte);
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  expect(computeDIDKey(publicKey)).toBe(vector.controller_did);
  const timestamp = timestampFromDelta(vector.timestamp_delta_seconds);
  const signature = await ed.signAsync(
    new TextEncoder().encode(
      canonicalReplacementJSON(vector.address, vector.controller_did, vector.old_did, vector.new_did, timestamp),
    ),
    privateKey,
  );
  return {
    address: vector.address,
    old_did: vector.old_did,
    new_did: vector.new_did,
    controller_did: vector.controller_did,
    timestamp,
    controller_signature: b64(signature),
  };
}

function assertPinStoreMatchesVector(
  got: PinStore,
  expected: PinStoreVector,
  before: PinStoreVector,
  vectorName: string,
): void {
  expect(Object.fromEntries(got.addresses), `${vectorName} addresses`).toEqual(expected.addresses);
  expect(got.pins.size, `${vectorName} pin count`).toBe(Object.keys(expected.pins).length);
  for (const [key, expectedPin] of Object.entries(expected.pins)) {
    const gotPin = got.pins.get(key);
    expect(gotPin, `${vectorName} pin ${key}`).toBeDefined();
    const beforePin = before.pins[key];
    assertPinField(vectorName, key, "address", gotPin!.address, expectedPin.address, beforePin?.address || "");
    assertPinField(vectorName, key, "stable_id", gotPin!.stable_id || "", expectedPin.stable_id || "", beforePin?.stable_id || "");
    assertPinField(vectorName, key, "did_key", gotPin!.did_key || "", expectedPin.did_key || "", beforePin?.did_key || "");
    assertPinField(vectorName, key, "first_seen", gotPin!.first_seen, expectedPin.first_seen, beforePin?.first_seen || "");
    assertPinField(vectorName, key, "last_seen", gotPin!.last_seen, expectedPin.last_seen, beforePin?.last_seen || "");
    assertPinField(vectorName, key, "server", gotPin!.server || "", expectedPin.server || "", beforePin?.server || "");
  }
}

function assertPinField(
  vectorName: string,
  pinKey: string,
  field: string,
  got: string,
  expected: string,
  before: string,
): void {
  switch (expected) {
    case "$ANY_TIMESTAMP":
      expect(Date.parse(got), `${vectorName} ${pinKey}.${field}`).not.toBeNaN();
      break;
    case "$CHANGED_TIMESTAMP":
      expect(Date.parse(got), `${vectorName} ${pinKey}.${field}`).not.toBeNaN();
      expect(got, `${vectorName} ${pinKey}.${field}`).not.toBe(before);
      break;
    default:
      expect(got, `${vectorName} ${pinKey}.${field}`).toBe(expected);
  }
}

function timestampFromDelta(deltaSeconds: number): string {
  return new Date(Date.now() + deltaSeconds * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
}

function seed(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

function b64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64").replace(/=+$/, "");
}

function corruptBase64Signature(signature: string): string {
  if (!signature) return "A";
  return `${signature.slice(0, -1)}${signature.endsWith("A") ? "B" : "A"}`;
}
