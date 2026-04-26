import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, test } from "vitest";
import { PinStore } from "../src/identity/pinstore.js";
import { SenderTrustManager } from "../src/identity/trust.js";
import { verifySignedPayload, type VerificationStatus } from "../src/identity/signing.js";

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
