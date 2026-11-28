import { readFileSync } from "node:fs";
import { expect, test } from "vitest";
import { canonicalJSON, signMessage, verifySignedPayload } from "../src/identity/signing.js";

const vector = JSON.parse(readFileSync(new URL("../../../docs/vectors/signature-primitives-v1.json", import.meta.url), "utf8"));
for (const c of vector.cases) {
  test(c.name, async () => {
    expect(await verifySignedPayload(c.payload, c.signature, c.did_key, "")).toBe(c.expected.typescript);
  });
}
const messages = JSON.parse(readFileSync(new URL("../../../docs/vectors/message-signing-v1.json", import.meta.url), "utf8"));
for (const c of messages) {
  test(`shared signing ${c.name}`, async () => {
    expect(canonicalJSON(c.message)).toBe(c.canonical_payload);
    expect(await signMessage(Uint8Array.from(Buffer.from(c.signing_seed_hex, "hex")), c.message)).toBe(c.signature_b64);
  });
}

import { decodeRawURLBase64 } from "../src/identity/base64.js";
for (const c of vector.base64url_cases) {
  test(`URL codec ${c.name}`, () => {
    if (c.hex === null) expect(() => decodeRawURLBase64(c.text)).toThrow();
    else expect(Buffer.from(decodeRawURLBase64(c.text)).toString("hex")).toBe(c.hex);
  });
}
