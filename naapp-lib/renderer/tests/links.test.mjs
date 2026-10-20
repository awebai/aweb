import test from "node:test";
import assert from "node:assert/strict";
import { safeLink } from "../sanitize.mjs";

test("scheme checking preserves encoded path delimiters", () => {
  for (const path of ["a%3Fb", "a%23b", "a%2Fb", "%2561"]) {
    assert.equal(
      safeLink(`https://x.test/${path}`).href,
      `https://x.test/${path}`,
    );
  }
});

test("unsafe schemes and credentials stay inert at arbitrary encoding depths", () => {
  for (let depth = 0; depth <= 12; depth++) {
    let scheme = "javascript:alert(1)";
    for (let n = 0; n < depth; n++) scheme = encodeURIComponent(scheme);
    assert.equal(safeLink(scheme), null);
  }
  for (const link of [
    "data:text/html,x",
    "https://user:secret@x.test/",
    "https://x.test%2f@evil.test/",
  ]) {
    assert.equal(safeLink(link), null);
  }
});

test("encoded dot segments follow the same normalization as the browser", () => {
  assert.equal(safeLink("https://x.test/%2e%2e/").href, "https://x.test/");
});
