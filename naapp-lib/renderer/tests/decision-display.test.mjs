import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { decisionRows } from "../decision-display.mjs";
const vectors = JSON.parse(
  readFileSync(
    new URL("../../../docs/vectors/decision-display-v1.json", import.meta.url),
  ),
);
for (const vector of vectors.cases) {
  test(`signed decision display: ${vector.name}`, () => {
    const render = () =>
      decisionRows(vector.card_options, vector.evidence, vector.record_value);
    if (vector.expect.refuse)
      assert.throws(render, { code: vector.expect.refuse });
    else assert.deepEqual(render(), vector.expect.show);
  });
}
