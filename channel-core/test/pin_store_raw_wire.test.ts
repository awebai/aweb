import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, test } from "vitest";
import { PinStore } from "../src/identity/pinstore.js";

const testDir = dirname(fileURLToPath(import.meta.url));

interface RuntimeExpectation {
  outcome: "accept" | "reject";
  error_substrings?: string[];
  pins?: number;
  addresses?: number;
}

interface PinStoreRawWireVectors {
  schema: string;
  cases: Array<{
    name: string;
    divergence?: string;
    yaml: string;
    expected: { go: RuntimeExpectation; typescript: RuntimeExpectation };
  }>;
}

const vectors = JSON.parse(
  readFileSync(join(testDir, "..", "..", "docs", "vectors", "pin-store-raw-wire-v1.json"), "utf-8"),
) as PinStoreRawWireVectors;

// The raw bytes are written to a file and read back, so this consumes the same
// on-disk document the Go consumer does rather than a string literal that has
// already been through a second decoder.
describe("pin-store-raw-wire-v1 shared vectors", () => {
  test("uses the raw-wire schema required for decoder-level cases", () => {
    expect(vectors.schema).toBe("aweb.pin-store.raw-wire.v1");
    expect(vectors.cases.length).toBeGreaterThan(0);
  });

  for (const testCase of vectors.cases) {
    test(testCase.name, () => {
      const dir = mkdtempSync(join(tmpdir(), "pin-store-raw-wire-"));
      const path = join(dir, "known_agents.yaml");
      writeFileSync(path, testCase.yaml, "utf-8");
      const content = readFileSync(path, "utf-8");

      const expected = testCase.expected.typescript;
      if (expected.outcome === "reject") {
        expect(expected.error_substrings?.length ?? 0).toBeGreaterThan(0);
        let message = "";
        expect(() => {
          try {
            PinStore.fromYAML(content);
          } catch (error) {
            message = (error as Error).message;
            throw error;
          }
        }).toThrow();
        // Assert WHY it was rejected. Two runtimes rejecting the same document
        // for different reasons reads as agreement while hiding a divergence —
        // which is how the non-string-key divergence in this corpus was found.
        for (const substring of expected.error_substrings!) {
          expect(message).toContain(substring);
        }
        return;
      }

      const store = PinStore.fromYAML(content);
      expect(store.pins.size).toBe(expected.pins);
      expect(store.addresses.size).toBe(expected.addresses);
    });
  }
});
