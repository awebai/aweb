import { readFileSync } from "node:fs";
import { expect, test } from "vitest";
import { canonicalPointEncoding } from "../src/identity/signature_wire.js";

interface ComponentCase {
  name: string;
  encoded_hex: string;
  canonical: boolean;
}

const vector: { cases: ComponentCase[] } = JSON.parse(
  readFileSync(new URL("../../docs/vectors/signature-point-encoding-v2.json", import.meta.url), "utf8"),
);
for (const component of vector.cases) {
  test(`shared point encoding ${component.name}`, () => {
    expect(canonicalPointEncoding(Buffer.from(component.encoded_hex, "hex"))).toBe(component.canonical);
  });
}
