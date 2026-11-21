import { describe, expect, test } from "vitest";
import * as ed from "@noble/ed25519";
import { computeDIDKey, extractPublicKey } from "../src/identity/did.js";
import { decodeRawStdBase64 } from "../src/identity/base64.js";
import { verifyBytes } from "../src/identity/signature_wire.js";
import { canonicalJSON, signMessage, verifyMessage, verifySignedPayload, type MessageEnvelope } from "../src/identity/signing.js";

async function signedEnvelope(): Promise<{ envelope: MessageEnvelope; signature: string }> {
  const seed = new Uint8Array(32).fill(7);
  const did = computeDIDKey(await ed.getPublicKeyAsync(seed));
  const envelope: MessageEnvelope = {
    from: "mycompany/researcher", from_did: did, to: "otherco/monitor", to_did: "",
    type: "mail", subject: "task complete", body: "results attached", timestamp: "2026-02-21T15:30:00Z",
  };
  return { envelope: { ...envelope, signing_key_id: did }, signature: await signMessage(seed, envelope) };
}

describe("message signature spelling is checked before crypto", () => {
  for (const spelling of ["padding", "interior space"] as const) {
    test(`${spelling} refuses although the decoded signature is valid`, async () => {
      const { envelope, signature } = await signedEnvelope();
      const malformed = spelling === "padding" ? `${signature}==` : `${signature.slice(0, 4)} ${signature.slice(4)}`;
      const payload = canonicalJSON(envelope);
      // A lenient decoder would pass this real signature. The strict codec
      // must throw; refusal cannot be credited to invalid cryptographic bytes.
      expect(verifyBytes({
        signature: new Uint8Array(Buffer.from(malformed, "base64")),
        message: new TextEncoder().encode(payload), publicKey: extractPublicKey(envelope.from_did),
      })).toBe(true);
      expect(() => decodeRawStdBase64(malformed)).toThrow();
      expect(await verifyMessage({ ...envelope, signature: malformed })).toBe("failed");
      expect(await verifySignedPayload(payload, malformed, envelope.from_did, envelope.from_did)).toBe("failed");
      expect(await verifyMessage({ ...envelope, signature })).toBe("verified");
      expect(await verifySignedPayload(payload, signature, envelope.from_did, envelope.from_did)).toBe("verified");
    });
  }
  test("nonalphabet input is a decoder refusal", async () => {
    const { envelope } = await signedEnvelope();
    expect(() => decodeRawStdBase64("not-base64!")).toThrow();
    expect(await verifyMessage({ ...envelope, signature: "not-base64!" })).toBe("failed");
  });
});
