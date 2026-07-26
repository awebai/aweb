import { describe, expect, test } from "vitest";
import yaml from "js-yaml";
import { PinStore } from "../src/identity/pinstore.js";

describe("PinStore.fromYAML schema validation", () => {
  test("loads a valid current store with stable_id and did_key", () => {
    const yaml = [
      "pins:",
      "  did:aw:2Cbob:",
      "    address: acme.com/bob",
      "    handle: ''",
      "    stable_id: did:aw:2Cbob",
      "    did_key: did:key:zBob",
      "    first_seen: 2026-02-22T10:00:00Z",
      "    last_seen: 2026-02-22T10:00:00Z",
      "    server: ''",
      "addresses:",
      "  acme.com/bob: did:aw:2Cbob",
      "",
    ].join("\n");
    const store = PinStore.fromYAML(yaml);
    const pin = store.pins.get("did:aw:2Cbob");
    expect(pin?.stable_id).toBe("did:aw:2Cbob");
    expect(pin?.did_key).toBe("did:key:zBob");
    expect(store.addresses.get("acme.com/bob")).toBe("did:aw:2Cbob");
  });

  test("loads a minimal legacy store lacking handle/server/did_key", () => {
    const yaml = [
      "pins:",
      "  did:key:zAlice:",
      "    address: acme.com/alice",
      "    first_seen: 2026-02-22T10:00:00Z",
      "    last_seen: 2026-02-22T11:00:00Z",
      "addresses:",
      "  acme.com/alice: did:key:zAlice",
      "",
    ].join("\n");
    const store = PinStore.fromYAML(yaml);
    expect(store.pins.get("did:key:zAlice")?.handle).toBe("");
    expect(store.pins.get("did:key:zAlice")?.server).toBe("");
  });

  test("an explicit empty mapping loads as an empty store", () => {
    expect(PinStore.fromYAML("{}").pins.size).toBe(0);
    expect(PinStore.fromYAML("pins: {}\naddresses: {}\n").pins.size).toBe(0);
  });

  test("a present-but-empty document throws (truncation/corruption)", () => {
    // The serializer always emits pins/addresses mappings, so a present file
    // yielding no document is corruption, not an intentional empty store.
    for (const content of ["", "   \n\t ", "# only a comment\n", "null\n", "~\n"]) {
      expect(() => PinStore.fromYAML(content), JSON.stringify(content)).toThrow(/empty or has no document/i);
    }
  });

  test("parse errors report location without dumping file content", () => {
    const marker = "SUPERSECRETMARKER";
    const bad = `pins:\n  did:key:z${marker}: {oops\n`;
    let message = "";
    try {
      PinStore.fromYAML(bad);
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).toMatch(/invalid/i);
    expect(message).not.toContain(marker);
  });

  test("rejects a dangling address reference", () => {
    const yaml = [
      "pins:",
      "  did:key:zAlice:",
      "    address: acme.com/alice",
      "    first_seen: 2026-02-22T10:00:00Z",
      "    last_seen: 2026-02-22T11:00:00Z",
      "addresses:",
      "  acme.com/ghost: did:key:zGhost",
      "",
    ].join("\n");
    expect(() => PinStore.fromYAML(yaml)).toThrow(/unknown pin/i);
  });

  test("rejects duplicate mapping keys", () => {
    const yaml = [
      "pins:",
      "  did:key:zAlice:",
      "    address: a",
      "    first_seen: x",
      "    last_seen: y",
      "  did:key:zAlice:",
      "    address: b",
      "    first_seen: x",
      "    last_seen: y",
      "",
    ].join("\n");
    expect(() => PinStore.fromYAML(yaml)).toThrow(/invalid|duplicat/i);
  });

  test("rejects a pin missing a required field", () => {
    const yaml = "pins:\n  did:key:zAlice:\n    address: acme.com/alice\n    last_seen: 2026-02-22T11:00:00Z\n";
    expect(() => PinStore.fromYAML(yaml)).toThrow(/first_seen/);
  });

  test("rejects a pin that is not a mapping", () => {
    expect(() => PinStore.fromYAML("pins:\n  did:key:zAlice: 'just a string'\n")).toThrow(/must be a mapping/i);
  });

  test("rejects an address that maps to a non-string", () => {
    const yaml = [
      "pins:",
      "  did:key:zAlice:",
      "    address: acme.com/alice",
      "    first_seen: x",
      "    last_seen: y",
      "addresses:",
      "  acme.com/alice: [1, 2]",
      "",
    ].join("\n");
    expect(() => PinStore.fromYAML(yaml)).toThrow(/non-empty pin key/i);
  });

  test("rejects a non-mapping root", () => {
    expect(() => PinStore.fromYAML("- a\n- b\n")).toThrow(/root must be a mapping/i);
  });

  test("preserves parsed unknown root and per-pin values across load-serialize-reload", () => {
    const source = [
      "future_schema_version: 7",
      "future_root:",
      "  enabled: true",
      "  nested:",
      "    - alpha",
      "    - weight: 2.5",
      "    - null",
      "future_sequence: [1, false, hello]",
      "pins:",
      "  did:aw:2Cbob:",
      "    address: acme.com/bob",
      "    handle: ''",
      "    stable_id: did:aw:2Cbob",
      "    did_key: did:key:zBob",
      "    first_seen: 2026-02-22T10:00:00Z",
      "    last_seen: 2026-02-22T11:00:00Z",
      "    server: ''",
      "    future_anti_rollback_anchor:",
      "      seq: 4",
      "      hashes: [abc, def]",
      "    future_flags: [true, {mode: strict}]",
      "    future_scalar: 42",
      "addresses:",
      "  acme.com/bob: did:aw:2Cbob",
      "",
    ].join("\n");
    const original = yaml.load(source, { schema: yaml.JSON_SCHEMA }) as Record<string, unknown>;

    const store = PinStore.fromYAML(source);
    store.storePin("did:aw:2Cbob", "acme.com/bob", "updated", "");
    const saved = store.toYAML();
    const roundTripped = yaml.load(PinStore.fromYAML(saved).toYAML(), {
      schema: yaml.JSON_SCHEMA,
    }) as Record<string, unknown>;

    expect(roundTripped.future_schema_version).toEqual(original.future_schema_version);
    expect(roundTripped.future_root).toEqual(original.future_root);
    expect(roundTripped.future_sequence).toEqual(original.future_sequence);
    const originalPin = (original.pins as Record<string, Record<string, unknown>>)["did:aw:2Cbob"];
    const roundTrippedPin = (
      roundTripped.pins as Record<string, Record<string, unknown>>
    )["did:aw:2Cbob"];
    expect(roundTrippedPin.future_anti_rollback_anchor)
      .toEqual(originalPin.future_anti_rollback_anchor);
    expect(roundTrippedPin.future_flags).toEqual(originalPin.future_flags);
    expect(roundTrippedPin.future_scalar).toEqual(originalPin.future_scalar);
  });

  test.each([
    ["anchor", "future: &future\n  nested: true\n"],
    ["alias", "future_base: &future [1, 2]\nfuture_alias: *future\n"],
    ["merge key", "future:\n  <<: {nested: true}\n  own: 1\n"],
    ["quoted merge-like key", "future:\n  '<<': {nested: true}\n  own: 1\n"],
  ])("rejects YAML %s syntax", (_name, extra) => {
    const source = `pins: {}\naddresses: {}\n${extra}`;
    expect(() => PinStore.fromYAML(source)).toThrow(/anchor|alias|merge/i);
  });

  test("preserves ordinary scalar values containing YAML graph tokens", () => {
    const source = [
      "future_text: 'literal &anchor *alias <<'",
      "pins: {}",
      "addresses: {}",
      "",
    ].join("\n");
    const saved = PinStore.fromYAML(source).toYAML();
    const parsed = yaml.load(saved, { schema: yaml.JSON_SCHEMA }) as Record<string, unknown>;
    expect(parsed.future_text).toBe("literal &anchor *alias <<");
  });

  test("round-trips through toYAML", () => {
    const store = new PinStore();
    store.storePin("did:key:zAlice", "acme.com/alice", "@alice", "https://app.aweb.ai");
    const loaded = PinStore.fromYAML(store.toYAML());
    expect(loaded.pins.get("did:key:zAlice")?.address).toBe("acme.com/alice");
    expect(loaded.addresses.get("acme.com/alice")).toBe("did:key:zAlice");
  });
});
