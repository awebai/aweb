import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";
import { computeDIDKey } from "../src/identity/did.js";
import { idEd25519Verify } from "../src/identity/id_certificates.js";
import { verifyMessage, verifySignedPayload, type MessageEnvelope } from "../src/identity/signing.js";

const vector = JSON.parse(readFileSync(new URL("../../docs/vectors/id-certificates-v1.json", import.meta.url), "utf8"));

const bytes = (hex: string) => Uint8Array.from(Buffer.from(hex, "hex"));
const rawStdBase64 = (hex: string) => Buffer.from(hex, "hex").toString("base64").replace(/=+$/, "");

// The released message family's outcome for each frozen ID-profile Ed25519 case.
// The ID profile refuses all but the control; released message verification
// keeps its own acceptance, so adopting the ID profile is never a silent change.
const RELEASED_MESSAGE_OUTCOME: Record<string, "verified" | "failed"> = {
  "control-root-signs-alice": "verified",
  "small-order-A-0": "verified",
  "small-order-A-1": "verified",
  "small-order-A-2": "verified",
  "small-order-A-3": "verified",
  "small-order-A-4": "verified",
  "small-order-A-5": "verified",
  "small-order-A-6": "verified",
  "small-order-A-7": "verified",
  "noncanonical-A-identity": "verified",
  "noncanonical-A-x0-sign-bit": "verified",
  "mixed-order-A-k-div-8": "verified",
  "mixed-order-A-k-not-div-8": "verified",
  "small-order-R-identity": "failed",
  "noncanonical-R-identity": "failed",
  "noncanonical-R-x0-sign-bit": "failed",
  "mixed-order-R-honest-A": "verified",
  "S-equals-L": "failed",
  "S-plus-L": "failed",
};

describe("ID signature profile does not narrow released message signatures", () => {
  const { cases } = vector.ed25519_verification;

  test("every frozen Ed25519 case has a pinned released outcome", () => {
    expect(cases.map((c: { name: string }) => c.name).sort()).toEqual(Object.keys(RELEASED_MESSAGE_OUTCOME).sort());
  });

  for (const c of cases) {
    test(c.name, async () => {
      const message = bytes(c.message_hex);
      expect(idEd25519Verify(bytes(c.public_key_hex), message, bytes(c.signature_hex)).accepted).toBe(c.expected.accepted);
      const payload = new TextDecoder("utf-8", { fatal: true }).decode(message);
      const did = computeDIDKey(bytes(c.public_key_hex));
      expect(await verifySignedPayload(payload, rawStdBase64(c.signature_hex), did, "")).toBe(RELEASED_MESSAGE_OUTCOME[c.name]);
    });
  }

  test("an envelope signed under a key the ID profile refuses still verifies as a message", async () => {
    // R = identity and S = 0 verifies any message under a small-order key in the released family.
    const smallOrder = cases.find((c: { name: string }) => c.name === "small-order-A-0");
    const env: MessageEnvelope = {
      from: "example.com/sender",
      from_did: computeDIDKey(bytes(smallOrder.public_key_hex)),
      to: "example.com/recipient",
      to_did: "",
      type: "mail",
      subject: "s",
      body: "b",
      timestamp: "2026-10-26T00:00:00Z",
      signature: rawStdBase64(smallOrder.signature_hex),
    };
    expect(idEd25519Verify(bytes(smallOrder.public_key_hex), new TextEncoder().encode("any"), bytes(smallOrder.signature_hex)).accepted).toBe(false);
    expect(await verifyMessage(env)).toBe("verified");
  });
});
