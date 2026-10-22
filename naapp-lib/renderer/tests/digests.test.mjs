import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { canonical, proposalDigest, bundleDigest } from "../digests.mjs";
const vectors = JSON.parse(
  await readFile(
    new URL("../../../docs/vectors/page-format-v1.json", import.meta.url),
  ),
);
const proposals = JSON.parse(
  await readFile(
    new URL("../../../docs/vectors/page-proposal-v1.json", import.meta.url),
  ),
);
test("browser bundle digests reproduce every frozen C1 vector", async () => {
  for (const vector of vectors.bundle_hash)
    assert.equal(await bundleDigest(vector.items), vector.sha256, vector.name);
});
test("browser proposal digests reproduce C2 framing, non-ASCII, nested keys and safe integer vectors", async () => {
  for (const vector of proposals.cases) {
    const record = { id: vector.record_id, value: vector.value };
    assert.equal(
      "aweb.page-proposal/1\n" +
        canonical({
          collection: vector.collection,
          record_id: record.id,
          value: record.value,
        }),
      vector.canonical,
      vector.name,
    );
    assert.equal(
      await proposalDigest(vector.collection, record),
      vector.proposal_sha256,
      vector.name,
    );
  }
  for (const vector of proposals.refusals.filter(
    (v) => !["exponent", "negative-zero-float"].includes(v.name),
  ))
    assert.throws(
      () => canonical(JSON.parse(vector.value_json)),
      undefined,
      vector.name,
    );
  assert.equal(
    await bundleDigest(proposals.bundle.items),
    proposals.bundle.sha256,
  );
  assert.equal(
    canonical({ "\u{10000}": 1, "\ue000": 2, 10: 3, 2: 4 }),
    "{" + '"10":3,"2":4,"\ue000":2,"\u{10000}":1}',
  );
  assert.throws(() => canonical("\ud800"));
  assert.throws(() => canonical(-0));
});

test("proposal lexical refusals are enforced by the real host validator before bootstrap", () => {
  for (const vector of proposals.refusals.filter((v) =>
    ["exponent", "negative-zero-float"].includes(v.name),
  )) {
    const snapshot = structuredClone(vectors.bases["price-proposal"]);
    snapshot.collections[0].records[0].value = "RAW_VALUE_PLACEHOLDER";
    const raw = JSON.stringify(snapshot).replace(
      '"RAW_VALUE_PLACEHOLDER"',
      vector.value_json,
    );
    const checked = spawnSync(
      fileURLToPath(new URL("../../.venv/bin/python", import.meta.url)),
      [
        "-c",
        "import sys; from aweb_naapp.pages import validate_page_bytes; result = validate_page_bytes(sys.stdin.buffer.read()); assert any(e.code == 'unsafe_number' for e in result.errors), result",
      ],
      { input: raw, encoding: "utf8" },
    );
    assert.equal(checked.status, 0, vector.name + ": " + checked.stderr);
  }
});
