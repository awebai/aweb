// The emitter's producer bytes against the frozen agent-activity-v1 vector
// (docs/agent-activity.md): canonical bytes, base64url signed_payload and the
// Ed25519 signature must equal what the server's verifier was frozen against.
import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";
import { canonicalActivityBytes, signActivityEvent } from "../src/activity/event.js";

const vector = JSON.parse(readFileSync(new URL("../../docs/vectors/agent-activity-v1.json", import.meta.url), "utf8"));

const seeds: Record<string, string> = {
  [vector.agent_did_key]: vector.agent_seed_hex,
  [vector.other_did_key]: vector.other_seed_hex,
  [vector.grant_session_did_key]: vector.grant_session_seed_hex,
};

function signerSeed(testCase: { caller?: { signer_did: string } }): Uint8Array {
  const signer = (testCase.caller ?? vector.default_caller).signer_did;
  return Uint8Array.from(Buffer.from(seeds[signer], "hex"));
}

describe("agent-activity-v1 producer", () => {
  test.each(vector.valid.map((c: { name: string }) => [c.name, c]))("%s: canonical bytes", (_name, testCase) => {
    const bytes = canonicalActivityBytes(testCase.document);
    expect(Buffer.from(bytes).toString("utf8")).toBe(testCase.canonical_payload);
  });

  test.each(vector.valid.map((c: { name: string }) => [c.name, c]))("%s: signed body", (_name, testCase) => {
    expect(signActivityEvent(testCase.document, signerSeed(testCase))).toEqual({
      signed_payload: testCase.signed_payload,
      signature: testCase.signature,
    });
  });

  test("a multibyte summary keeps its UTF-8 bytes unescaped", () => {
    const caps = vector.valid.find((c: { name: string }) => c.name === "caps_multibyte");
    const bytes = canonicalActivityBytes(caps.document);
    expect(Buffer.from(bytes).toString("utf8")).toContain(caps.document.summary);
  });
});
