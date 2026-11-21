import { readFileSync } from "node:fs";
import { expect, test } from "vitest";
import { canonicalPointEncoding } from "../src/identity/signature_wire.js";

const vector: unknown = JSON.parse(
  readFileSync(new URL("../../docs/vectors/signature-point-encoding-v2.json", import.meta.url), "utf8"),
);
if (
  typeof vector !== "object" || vector === null || !("cases" in vector) ||
  !Array.isArray(vector.cases) || vector.cases.length === 0
) throw new Error("point encoding corpus must contain component cases");
for (const component of vector.cases) {
  if (
    typeof component !== "object" || component === null ||
    typeof component.name !== "string" || typeof component.encoded_hex !== "string" ||
    typeof component.canonical !== "boolean"
  ) throw new Error("invalid point encoding component case");
  const { name, encoded_hex, canonical } = component;
  test(`shared point encoding ${name}`, () => {
    expect(canonicalPointEncoding(Buffer.from(encoded_hex, "hex"))).toBe(canonical);
  });
}
