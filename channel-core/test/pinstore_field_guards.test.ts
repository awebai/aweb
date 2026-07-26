import { describe, expect, test } from "vitest";
import { PinStore } from "../src/identity/pinstore.js";

// These assert the exact production message. The pre-existing coverage of the
// 'pins' mapping check matched /pins.*mapping/i against loadPinStore's wrapped
// error, which embeds the store path — and the temp directory it was given was
// named "pinstore-fc-", so the regex matched the path rather than the guard and
// held even when the guard was gone. Asserting through PinStore.fromYAML keeps
// the path out of the message entirely.
//
// Each fixture is built from a store that loads cleanly
// (TestValidStoreLoads below) and differs in exactly one field, and the failure
// each guard prevents is a store that loads ANYWAY: a scalar in place of the
// pins or addresses mapping yields a silently empty store, which reopens
// first-contact TOFU for every identity the file was holding.

const VALID_PIN = [
  "  did:key:zAlice:",
  "    address: acme.com/alice",
  "    handle: '@alice'",
  "    first_seen: '2026-02-22T10:00:00Z'",
  "    last_seen: '2026-02-22T11:00:00Z'",
];

function store(options: { pins?: string[]; addresses?: string[]; pinExtra?: string[] } = {}): string {
  const pins = options.pins ?? [...VALID_PIN, ...(options.pinExtra ?? []).map((line) => `    ${line}`)];
  const addresses = options.addresses ?? ["  acme.com/alice: did:key:zAlice"];
  return ["pins:", ...pins, "addresses:", ...addresses, ""].join("\n");
}

describe("pin store field guards", () => {
  test("the shared valid store loads", () => {
    const loaded = PinStore.fromYAML(store());
    expect(loaded.pins.get("did:key:zAlice")?.address).toBe("acme.com/alice");
    expect(loaded.addresses.get("acme.com/alice")).toBe("did:key:zAlice");
  });

  // Without this check Object.entries(42) yields nothing and the store loads as
  // a valid EMPTY store — the silent substitution the module exists to prevent.
  test("a scalar in place of the pins mapping is rejected", () => {
    expect(() => PinStore.fromYAML("pins: 42\naddresses: {}\n"))
      .toThrow("pin store 'pins' must be a mapping");
  });

  test("a scalar in place of the addresses mapping is rejected", () => {
    expect(() => PinStore.fromYAML(["pins:", ...VALID_PIN, "addresses: 42", ""].join("\n")))
      .toThrow("pin store 'addresses' must be a mapping");
  });

  test("an empty pin key is rejected", () => {
    expect(() => PinStore.fromYAML(store({
      pins: ["  '':", ...VALID_PIN.slice(1)],
      addresses: [],
    }))).toThrow("pin store has an empty pin key");
  });

  test("an empty address key is rejected", () => {
    expect(() => PinStore.fromYAML(store({ addresses: ["  '': did:key:zAlice"] })))
      .toThrow("pin store has an empty address key");
  });

  // Pin.handle is typed string. A coerced number loads as a number here while
  // Go's requireString refuses it, so the two runtimes would hold different
  // pins for the same file.
  test("a non-string optional field is rejected rather than coerced", () => {
    expect(() => PinStore.fromYAML(store({ pins: [...VALID_PIN.slice(0, 2), "    handle: 42", ...VALID_PIN.slice(3)] })))
      .toThrow("pin 'did:key:zAlice' field 'handle' must be a string");
  });

  // log_seq is the anti-rollback checkpoint. A zero, a negative, a fraction or
  // a quoted digit must not become a checkpoint value.
  test.each(["0", "-1", "1.5", "'3'"])("log_seq %s is rejected", (value) => {
    expect(() => PinStore.fromYAML(store({ pinExtra: [`log_seq: ${value}`] })))
      .toThrow("pin 'did:key:zAlice' field 'log_seq' must be a positive integer");
  });

  test("a positive integer log_seq is accepted", () => {
    expect(PinStore.fromYAML(store({ pinExtra: ["log_seq: 7"] })).pins.get("did:key:zAlice")?.log_seq).toBe(7);
  });
});
