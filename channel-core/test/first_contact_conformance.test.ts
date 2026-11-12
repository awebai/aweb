// A sender outside the reader's team is pinned, and reported verified, only
// after the registry confirms that its address belongs to the signing key.
// The cases are shared with the Go client
// (cli/go/awid/first_contact_conformance_test.go) and run through the two
// calls the channel makes for each message: resolve, then decide.
import { describe, expect, test } from "vitest";
import { readFileSync } from "node:fs";
import { PinStore, SenderTrustManager, type VerificationStatus } from "../src/index.js";

interface Pin {
  address: string;
  stable_id: string;
  did_key: string;
  confirmed_by: string;
}

interface PinStoreVector {
  pins: Record<string, Pin>;
  addresses: Record<string, string>;
}

interface FirstContactVector {
  name: string;
  from_address: string;
  from_did: string;
  from_stable_id: string;
  resolver: "registry" | "none";
  address_resolution: { outcome: "resolved" | "not_found" | "unavailable"; did_key?: string; stable_id?: string } | null;
  stable_identity: { outcome: "verified" | "hard_error" | "ok_degraded"; current_did_key: string } | null;
  pin_store_before: PinStoreVector;
  expected_status: VerificationStatus;
  expected_pin_store_after: PinStoreVector | null;
}

const vectorFile = JSON.parse(
  readFileSync(new URL("../../test-vectors/trust/first-contact-v1.json", import.meta.url), "utf8"),
) as { schema: string; vectors: FirstContactVector[] };

const STABLE_OUTCOMES = { verified: "OK_VERIFIED", hard_error: "HARD_ERROR", ok_degraded: "OK_DEGRADED" } as const;

/** The registry of one vector. */
function registryOf(vector: FirstContactVector) {
  return {
    resolveIdentity: async (address: string) => {
      const resolution = vector.address_resolution!;
      if (resolution.outcome === "resolved") {
        return {
          did: resolution.did_key || "", stableID: resolution.stable_id || undefined, address,
          custody: "self", identityScope: "global",
        };
      }
      if (resolution.outcome === "not_found") {
        throw Object.assign(new Error("address not found"), { statusCode: 404 });
      }
      throw new Error("registry unreachable");
    },
    verifyStableIdentity: async () => {
      if (!vector.stable_identity) return { outcome: "HARD_ERROR", error: "unexpected stable identity lookup" };
      return {
        outcome: STABLE_OUTCOMES[vector.stable_identity.outcome],
        currentDidKey: vector.stable_identity.current_did_key || undefined,
      };
    },
  };
}

function storeFrom(vector: PinStoreVector): PinStore {
  const store = new PinStore();
  for (const [key, pin] of Object.entries(vector.pins)) {
    store.storePin(key, pin.address, "", "");
    const stored = store.pins.get(key)!;
    stored.stable_id = pin.stable_id || undefined;
    stored.did_key = pin.did_key || undefined;
    stored.confirmed_by = pin.confirmed_by || undefined;
  }
  for (const [address, key] of Object.entries(vector.addresses)) store.addresses.set(address, key);
  return store;
}

function pinsOf(store: PinStore): PinStoreVector {
  const pins: Record<string, Pin> = {};
  for (const [key, pin] of store.pins) {
    pins[key] = {
      address: pin.address, stable_id: pin.stable_id || "", did_key: pin.did_key || "",
      confirmed_by: pin.confirmed_by || "",
    };
  }
  return { pins, addresses: Object.fromEntries(store.addresses) };
}

describe("first contact conformance vectors", () => {
  test("the vector file holds cases", () => {
    expect(vectorFile.schema).toBe("aweb.trust.first-contact.v1");
    expect(vectorFile.vectors.length).toBeGreaterThan(0);
  });

  for (const vector of vectorFile.vectors) {
    // The channel is always built with a registry, so the case of a client
    // without one does not arise here.
    if (vector.resolver === "none") continue;

    test(vector.name, async () => {
      const store = storeFrom(vector.pin_store_before);
      const trust = new SenderTrustManager(
        { get: async () => ({}), hasTeamCertificateAuth: () => false } as never,
        registryOf(vector) as never,
        "",
        "",
      );
      const fromStableID = vector.from_stable_id || undefined;
      const resolved = await trust.resolveTrustMetadata(
        "verified", vector.from_address, fromStableID, undefined, undefined,
        { pinStore: store, fromDID: vector.from_did, verificationAddress: vector.from_address },
      );
      const result = await trust.normalizeResolvedTrust(
        store, "verified", vector.from_address, vector.from_did, fromStableID,
        undefined, undefined, undefined, undefined, vector.from_address, resolved,
      );

      expect(result.status).toBe(vector.expected_status);
      expect(pinsOf(store)).toEqual(vector.expected_pin_store_after ?? vector.pin_store_before);
    });
  }
});
