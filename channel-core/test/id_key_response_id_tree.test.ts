import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";
import { keyResponseIdTree } from "../src/identity/id_certificates.js";

const vector = JSON.parse(readFileSync(new URL("../../docs/vectors/id-certificates-v1.json", import.meta.url), "utf8"));

describe("key response id_tree enrollment parse", () => {
  const cases: { name: string; key_response: Record<string, unknown>; expected_parse: unknown }[] = vector.key_response_id_tree;

  test("all 19 frozen cases are present", () => {
    expect(cases).toHaveLength(19);
    expect(new Set(cases.map((c) => c.name)).size).toBe(19);
  });

  for (const c of cases) {
    test(c.name, () => {
      expect(keyResponseIdTree(c.key_response)).toEqual(c.expected_parse);
    });
  }
});
