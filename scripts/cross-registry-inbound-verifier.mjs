// Real DNS/registry journey driver. stdin: {messages:[...], human_id:string|null}.
// Run beside a built channel-core; no substitute DNS, registry or verifier.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { IdStatusClient, readReceivedIdChain, verifySignedPayload } from "../channel-core/dist/index.js";
const input = JSON.parse(readFileSync(0, "utf8"));
assert.ok(input.messages.length > 0, "no received messages");
const status = new IdStatusClient();
for (const message of input.messages) {
  assert.ok(message.signed_payload, "journey requires the real signed payload");
  const authenticated = await verifySignedPayload(message.signed_payload, message.signature, message.from_did, message.signing_key_id || "");
  assert.equal(authenticated, "verified", "original sender signature");
  const result = await readReceivedIdChain(message, true, status);
  assert.equal(result.human_id, input.human_id, JSON.stringify(result));
  assert.equal(result.outcome, input.human_id ? "nearest_human" : "unknown", JSON.stringify(result));
  if (input.human_id) assert.equal(result.identity_valid, true);
  else assert.ok(["legacy_no_chain", "unregistered_identity"].includes(result.reason));
  console.log(`PASS: TS received sender ${message.from_stable_id || message.from_did} ${result.outcome}`);
}
