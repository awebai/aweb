import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, test } from "vitest";
import { PinStore } from "../src/identity/pinstore.js";
import { SenderTrustManager } from "../src/identity/trust.js";
import type { VerificationStatus } from "../src/identity/signing.js";

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

const testDir = dirname(fileURLToPath(import.meta.url));

function loadRecipientBindingVectors(): RecipientBindingVectorFile {
  return JSON.parse(
    readFileSync(join(testDir, "..", "..", "test-vectors", "trust", "recipient-binding-v1.json"), "utf-8"),
  ) as RecipientBindingVectorFile;
}

describe("trust conformance vectors", () => {
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
