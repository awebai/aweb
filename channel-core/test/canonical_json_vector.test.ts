// canonicalJSONValue against the shared canonical-json-v1 vector: the bytes a
// signature covers must equal what the Python reference writes for the same
// value. The vector's code_point_key_order_cases are not asserted here:
// canonicalJSONValue sorts object keys by UTF-16 code unit.
import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";
import { canonicalJSONValue } from "../src/identity/canonical.js";

interface VectorCase {
  name: string;
  value: unknown;
  canonical_hex: string;
}

const vector = JSON.parse(readFileSync(new URL("../../docs/vectors/canonical-json-v1.json", import.meta.url), "utf8"));
const cases: VectorCase[] = vector.cases;

describe("canonical-json-v1", () => {
  test("covers the line and paragraph separators", () => {
    const names = cases.map(c => c.name);
    expect(names).toEqual(expect.arrayContaining([
      "line_separator_in_string",
      "paragraph_separator_in_string",
      "line_separator_in_key",
      "paragraph_separator_in_key",
    ]));
  });

  test.each(cases.map(c => [c.name, c] as const))("%s: canonical bytes", (_name, testCase) => {
    const canonical = canonicalJSONValue(testCase.value, "unsupported value");
    expect(Buffer.from(canonical, "utf8").toString("hex")).toBe(testCase.canonical_hex);
  });
});
