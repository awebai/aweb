import { describe, expect, test, vi } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
import { computeDIDKey } from "../src/identity/did.js";
import {
  canonicalJSON,
  signMessage,
  verifyMessage,
  verifySignedPayload,
  type MessageEnvelope,
} from "../src/identity/signing.js";

// docs/vectors/README.md requires that identity/signing.ts throw on malformed
// signature base64 before calling Ed25519 verification, so that rejection does
// not depend on the verifier's treatment of an empty signature. ed.verify
// returns false rather than throwing on garbage, so "failed" alone cannot
// distinguish a decoder rejection from a verifier rejection. These tests
// delegate to the real verifier while counting whether it was reached at all.
const verifyCalls = vi.hoisted(() => vi.fn());
vi.mock("@noble/ed25519", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@noble/ed25519")>();
  return {
    ...actual,
    verify: (...args: Parameters<typeof actual.verify>) => {
      verifyCalls();
      return actual.verify(...args);
    },
  };
});

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

async function signedEnvelope(): Promise<{ envelope: MessageEnvelope; signature: string }> {
  const seed = new Uint8Array(32).fill(7);
  const did = computeDIDKey(await ed.getPublicKeyAsync(seed));
  const envelope: MessageEnvelope = {
    from: "mycompany/researcher",
    from_did: did,
    to: "otherco/monitor",
    to_did: "",
    type: "mail",
    subject: "task complete",
    body: "results attached",
    timestamp: "2026-02-21T15:30:00Z",
  };
  const signature = await signMessage(seed, envelope);
  return { envelope: { ...envelope, signing_key_id: did }, signature };
}

describe("signature decoding rejects malformed base64 before verification", () => {
  // atob accepts padding, so without the strict alphabet check a signature Go
  // rejects would decode to the correct 64 bytes and verify here. Each test
  // ends by verifying the unmodified signature, which proves the fixture is a
  // signature a lenient decoder would accept and that the decode branch is
  // reached at all.
  test("padded signatures never reach the verifier", async () => {
    const { envelope, signature } = await signedEnvelope();

    verifyCalls.mockClear();
    expect(await verifyMessage({ ...envelope, signature: `${signature}==` })).toBe("failed");
    expect(verifyCalls).not.toHaveBeenCalled();

    expect(await verifyMessage({ ...envelope, signature })).toBe("verified");
    expect(verifyCalls).toHaveBeenCalledTimes(1);
  });

  test("padded signatures never reach the verifier via verifySignedPayload", async () => {
    const { envelope, signature } = await signedEnvelope();
    const payload = canonicalJSON(envelope);
    const did = envelope.from_did;

    verifyCalls.mockClear();
    expect(await verifySignedPayload(payload, `${signature}==`, did, did)).toBe("failed");
    expect(verifyCalls).not.toHaveBeenCalled();

    expect(await verifySignedPayload(payload, signature, did, did)).toBe("verified");
    expect(verifyCalls).toHaveBeenCalledTimes(1);
  });

  // Go's RawStdEncoding skips only \r and \n; atob strips all whitespace. A
  // space-bearing signature is therefore accepted by atob and rejected by Go,
  // the same acceptance divergence as padding.
  test("signatures carrying interior whitespace never reach the verifier", async () => {
    const { envelope, signature } = await signedEnvelope();
    const spaced = `${signature.slice(0, 4)} ${signature.slice(4)}`;

    verifyCalls.mockClear();
    expect(await verifyMessage({ ...envelope, signature: spaced })).toBe("failed");
    expect(verifyCalls).not.toHaveBeenCalled();

    expect(await verifyMessage({ ...envelope, signature })).toBe("verified");
    expect(verifyCalls).toHaveBeenCalledTimes(1);
  });

  // Pins the decoder choice at signing.ts b64Decode: Buffer.from(value,
  // "base64") silently drops characters outside the alphabet and would hand
  // the verifier seven bytes of salvage here.
  test("non-alphabet signatures never reach the verifier", async () => {
    const { envelope } = await signedEnvelope();

    verifyCalls.mockClear();
    expect(await verifyMessage({ ...envelope, signature: "not-base64!" })).toBe("failed");
    expect(verifyCalls).not.toHaveBeenCalled();
  });
});
