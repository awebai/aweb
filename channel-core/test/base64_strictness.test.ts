import { describe, expect, test } from "vitest";
import { decodeRawStdBase64 } from "../src/identity/base64.js";

// Go verifies signatures with base64.RawStdEncoding. TypeScript must reject
// exactly what Go rejects: Node's Buffer.from(v, "base64") accepts padding and
// silently DROPS characters outside the alphabet, so a signature Go refuses
// would previously decode here — a verifier divergence (default-aajc.8).
describe("raw std base64 strictness matches Go", () => {
  // Verified against Go: base64.RawStdEncoding.DecodeString errors on each.
  const goRejects = [
    "YWJj=", // padding is not part of the raw encoding
    "YWJjZA==", // padded standard encoding
    "YW!j", // character outside the alphabet
    "YWJ j", // embedded whitespace
    "YWJjZA=", // stray padding
    "Y", // truncated final quantum (length % 4 === 1)
    "YWJj-_", // base64url alphabet is a different encoding
  ];

  for (const value of goRejects) {
    test(`rejects ${JSON.stringify(value)}`, () => {
      expect(() => decodeRawStdBase64(value)).toThrow();
    });
  }

  test("accepts well-formed unpadded values and round-trips", () => {
    expect(Array.from(decodeRawStdBase64("YWJj"))).toEqual([97, 98, 99]);
    expect(Array.from(decodeRawStdBase64("YWJjZA"))).toEqual([97, 98, 99, 100]);
    expect(decodeRawStdBase64("")).toHaveLength(0);
  });

  test("does not silently truncate around an illegal character", () => {
    // The lenient decoder returned 2 bytes here by dropping "!", which is how a
    // malformed signature could survive into verification.
    expect(() => decodeRawStdBase64("YW!j")).toThrow();
  });
});
