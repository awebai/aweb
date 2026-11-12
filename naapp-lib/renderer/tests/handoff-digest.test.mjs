// Named no-I/O tests: the shipped serializer and WebCrypto, public vectors.
import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  canonical,
  coveredRequestDigest,
} from "../../src/aweb_naapp/assets/canonical-json.mjs";

const vector = async (name) =>
  JSON.parse(
    await readFile(
      new URL(`../../../docs/vectors/${name}.json`, import.meta.url),
      "utf8",
    ),
  );
const json = await vector("canonical-json-v1");
const approval = await vector("approval-request-v1");

for (const item of [...json.cases, ...json.code_point_key_order_cases]) {
  test(`shipped canonical JSON: ${item.name}`, () => {
    assert.equal(
      Buffer.from(canonical(item.value)).toString("hex"),
      item.canonical_hex,
    );
  });
}
for (const item of approval.requests) {
  test(`shipped B2 covered-request digest: ${item.name}`, async () => {
    const payload = {
      policy: { ref: item.policy_ref, version: item.policy_version },
      request: item.request,
    };
    assert.equal(
      approval.request_prefix + canonical(payload),
      item.covered_canonical,
    );
    assert.equal(await coveredRequestDigest(payload), item.request_sha256);
  });
}
// The service already performs strict lexical parsing. These values also
// remain unrepresentable after JSON.parse; no second parser is introduced.
for (const item of approval.refusals.filter(
  (item) => !["duplicate-key", "non-finite"].includes(item.name),
)) {
  test(`shipped B2 refusal: ${item.name}`, async () => {
    await assert.rejects(coveredRequestDigest(JSON.parse(item.request_json)));
  });
}
for (const item of json.lone_surrogate_cases) {
  test(`shipped UTF-8 refusal: ${item.name}`, () => {
    assert.throws(() => canonical(JSON.parse(item.json)));
  });
}
