// canonicalJSONValue against the shared canonical-json-v1 vector: the bytes a
// signature covers must equal what the Python reference writes for the same
// value, including the cases whose keys order differently by UTF-16 code unit
// than by code point.
import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";
import { canonicalJSONValue } from "../src/identity/canonical.js";

interface VectorCase {
  name: string;
  value: unknown;
  canonical_hex: string;
}

// What an implementation does with an input outside the contract: "refused"
// or the hex of the bytes it writes.
interface BehaviourCase {
  name: string;
  json: string;
  typescript_canonical_json_value: string;
}

const vector = JSON.parse(readFileSync(new URL("../../docs/vectors/canonical-json-v1.json", import.meta.url), "utf8"));
const keyOrderCases: VectorCase[] = vector.code_point_key_order_cases;
const cases: VectorCase[] = [...vector.cases, ...keyOrderCases];
const outOfContractCases: BehaviourCase[] = [...vector.out_of_contract_number_cases, ...vector.lone_surrogate_cases];

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

  test("tells code point order from code unit order", () => {
    expect(keyOrderCases.map(c => c.name)).toEqual(expect.arrayContaining([
      "key_order_non_bmp_after_bmp",
      "key_order_non_bmp_against_u_e000",
      "key_order_non_bmp_against_u_ffff",
      "key_order_non_bmp_pair",
      "key_order_non_bmp_nested",
    ]));
  });

  test.each(cases.map(c => [c.name, c] as const))("%s: canonical bytes", (_name, testCase) => {
    const canonical = canonicalJSONValue(testCase.value, "unsupported value");
    expect(Buffer.from(canonical, "utf8").toString("hex")).toBe(testCase.canonical_hex);
  });

  test("covers the out-of-contract inputs", () => {
    expect(outOfContractCases.map(c => c.name)).toEqual(expect.arrayContaining([
      "number_with_fraction",
      "integral_float",
      "integer_above_safe_range",
      "negative_zero",
      "negative_zero_float",
      "exponent_form",
      "exponent_form_large",
      "lone_surrogate_in_string",
      "lone_surrogate_in_key",
      "lone_surrogate_key_order",
    ]));
  });

  // Inputs outside the contract: the vector records what canonicalJSONValue
  // does with each, so that a change is noticed.
  test.each(outOfContractCases.map(c => [c.name, c] as const))("%s: recorded out-of-contract behaviour", (_name, testCase) => {
    let behaviour: string;
    try {
      behaviour = Buffer.from(canonicalJSONValue(JSON.parse(testCase.json), "unsupported value"), "utf8").toString("hex");
    } catch (error) {
      expect((error as Error).message).toBe("unsupported value");
      behaviour = "refused";
    }
    expect(behaviour).toBe(testCase.typescript_canonical_json_value);
  });
});
