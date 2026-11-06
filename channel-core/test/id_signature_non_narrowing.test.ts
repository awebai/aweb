import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";
import { computeDIDKey, extractPublicKey } from "../src/identity/did.js";
import { idEd25519Verify } from "../src/identity/id_certificates.js";
import { verifyMessage, verifySignedPayload, type MessageEnvelope } from "../src/identity/signing.js";

const vector = JSON.parse(readFileSync(new URL("../../docs/vectors/id-certificates-v1.json", import.meta.url), "utf8"));

const bytes = (hex: string) => Uint8Array.from(Buffer.from(hex, "hex"));
const rawStdBase64 = (hex: string) => Buffer.from(hex, "hex").toString("base64").replace(/=+$/, "");

// The released message family's outcome for each frozen ID-profile Ed25519 case.
// A did:key whose public key is small-order, non-canonical or mixed-order is
// refused at decode (aweb-acmz), so no signature under it verifies. Signature
// checks on R and S keep the released family's own acceptance.
const RELEASED_MESSAGE_OUTCOME: Record<string, "verified" | "failed"> = {
  "control-root-signs-alice": "verified",
  "small-order-A-0": "failed",
  "small-order-A-1": "failed",
  "small-order-A-2": "failed",
  "small-order-A-3": "failed",
  "small-order-A-4": "failed",
  "small-order-A-5": "failed",
  "small-order-A-6": "failed",
  "small-order-A-7": "failed",
  "noncanonical-A-identity": "failed",
  "noncanonical-A-x0-sign-bit": "failed",
  "mixed-order-A-k-div-8": "failed",
  "mixed-order-A-k-not-div-8": "failed",
  "small-order-R-identity": "failed",
  "noncanonical-R-identity": "failed",
  "noncanonical-R-x0-sign-bit": "failed",
  "mixed-order-R-honest-A": "verified",
  "S-equals-L": "failed",
  "S-plus-L": "failed",
};

const DEGENERATE_KEYS = [
  "small-order-A-0", "small-order-A-1", "small-order-A-2", "small-order-A-3",
  "small-order-A-4", "small-order-A-5", "small-order-A-6", "small-order-A-7",
  "noncanonical-A-identity", "noncanonical-A-x0-sign-bit",
  "mixed-order-A-k-div-8", "mixed-order-A-k-not-div-8",
];

describe("released message signatures and degenerate did:key public keys", () => {
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

  test("an envelope signed under a degenerate key does not verify", async () => {
    // R = identity and S = 0 verifies any message under a small-order key, so the key itself is refused.
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
    expect(await verifyMessage(env)).toBe("failed");
  });

  test("the did:key decoder refuses degenerate public keys and accepts an ordinary one", () => {
    for (const name of DEGENERATE_KEYS) {
      const c = cases.find((x: { name: string }) => x.name === name);
      expect(() => extractPublicKey(computeDIDKey(bytes(c.public_key_hex))), name).toThrow();
    }
    const control = cases.find((c: { name: string }) => c.name === "control-root-signs-alice");
    expect(extractPublicKey(computeDIDKey(bytes(control.public_key_hex)))).toEqual(bytes(control.public_key_hex));
  });
});
