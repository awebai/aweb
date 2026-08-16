import { describe, expect, test, vi } from "vitest";
import { LAST_SEEN_COALESCE_MS, PinStore } from "../src/identity/pinstore.js";

// Refreshing last_seen on every accepted message forced a pin-store commit per
// message. With several resident processes sharing one known_agents.yaml that
// made CAS conflicts the steady state, and each conflict defers a wake
// (aweb-abdk). These pin the coalescing: a last_seen-only touch must not reach
// the writer, and everything that IS a continuity claim still must.
//
// The fixture pins a GLOBAL sender. A local-scope sender is never pinned at all
// after the roster-classification fix, so a version built from one would produce
// no commits and pass no matter what this code did.

const ADDRESS = "acme.com/alice";
const PIN_KEY = "did:aw:aliceStableIdentity";
const DID_KEY = "did:key:zAliceCurrentKey";

function storeWithPin(lastSeen: string): PinStore {
  return PinStore.fromYAML([
    "pins:",
    `  ${PIN_KEY}:`,
    `    address: ${ADDRESS}`,
    "    handle: ''",
    `    stable_id: ${PIN_KEY}`,
    `    did_key: ${DID_KEY}`,
    "    first_seen: 2026-02-22T10:00:00Z",
    `    last_seen: ${lastSeen}`,
    "    server: ''",
    "addresses:",
    `  ${ADDRESS}: ${PIN_KEY}`,
    "",
  ].join("\n"));
}

function nowISO(offsetMs = 0): string {
  return new Date(Date.now() + offsetMs).toISOString().replace(/\.\d{3}Z$/, "Z");
}

describe("last_seen coalescing", () => {
  test("an already-pinned sender inside the window reports no change to commit", () => {
    const store = storeWithPin(nowISO(-5_000));

    const changed = store.recordVerifiedIdentity(PIN_KEY, ADDRESS, PIN_KEY, DID_KEY);

    expect(changed).toBe(false);
  });

  test("the pin-store writer is never called for a last_seen-only refresh", async () => {
    const store = storeWithPin(nowISO(-5_000));
    const writer = { compareAndSet: vi.fn(async () => {}) };

    // What the caller does: commit only when something changed, or when an
    // earlier failure left the store undurable (channel.ts).
    const changed = store.recordVerifiedIdentity(PIN_KEY, ADDRESS, PIN_KEY, DID_KEY);
    if (changed || store.hasUndurableChanges()) await store.commit(writer, "/tmp/unused");

    expect(writer.compareAndSet).toHaveBeenCalledTimes(0);
  });

  test("last_seen advances once the window has elapsed", () => {
    const store = storeWithPin(nowISO(-(LAST_SEEN_COALESCE_MS + 1_000)));
    const before = store.pins.get(PIN_KEY)?.last_seen;

    const changed = store.recordVerifiedIdentity(PIN_KEY, ADDRESS, PIN_KEY, DID_KEY);

    expect(changed).toBe(true);
    expect(store.pins.get(PIN_KEY)?.last_seen).not.toBe(before);
  });

  test("a new pin still commits, inside any window", () => {
    const store = new PinStore();

    expect(store.recordVerifiedIdentity(PIN_KEY, ADDRESS, PIN_KEY, DID_KEY)).toBe(true);
  });

  test("a key change still commits, inside the window", () => {
    const store = storeWithPin(nowISO(-5_000));

    const changed = store.recordVerifiedIdentity(PIN_KEY, ADDRESS, PIN_KEY, "did:key:zRotatedKey");

    expect(changed).toBe(true);
    expect(store.pins.get(PIN_KEY)?.did_key).toBe("did:key:zRotatedKey");
  });

  test("an address change still commits, inside the window", () => {
    const store = storeWithPin(nowISO(-5_000));

    const changed = store.recordVerifiedIdentity(PIN_KEY, "acme.com/alice-moved", PIN_KEY, DID_KEY);

    expect(changed).toBe(true);
    expect(store.addresses.get("acme.com/alice-moved")).toBe(PIN_KEY);
  });

  // The contract this change introduces is "returns whether anything changed, so
  // the caller can skip a commit". Every cell of it needs a case where that cell
  // ALONE changes, or the cell can be deleted with the suite green - which is how
  // three of them survived the first round.
  test("a stable_id gained on an existing did:key pin still commits, inside the window", () => {
    // Upgrade-on-first-sight: the pin exists under a did:key, nothing else moves,
    // and only the stable_id appears. Unreported, the upgrade is computed and
    // discarded on every process start and never reaches disk.
    // did_key is ALREADY set, so stable_id is the only cell that moves. With
    // did_key absent too, that cell fires as well and masks this one - which is
    // what the first version of this test did, and it passed under the mutation.
    const store = PinStore.fromYAML([
      "pins:",
      `  ${DID_KEY}:`,
      `    address: ${ADDRESS}`,
      "    handle: ''",
      `    did_key: ${DID_KEY}`,
      "    first_seen: 2026-02-22T10:00:00Z",
      `    last_seen: ${nowISO(-5_000)}`,
      "    server: ''",
      "addresses:",
      `  ${ADDRESS}: ${DID_KEY}`,
      "",
    ].join("\n"));

    const changed = store.recordVerifiedIdentity(DID_KEY, ADDRESS, PIN_KEY, DID_KEY);

    expect(changed).toBe(true);
    expect(store.pins.get(DID_KEY)?.stable_id).toBe(PIN_KEY);
  });

  test("dropping a previous pin still commits even when the recorded pin is unchanged", () => {
    // replaceVerifiedIdentity's `removed` term. Without it the deletion is gone in
    // memory and still present on disk: safe in direction, but a real loss of the
    // behaviour this change introduces.
    const store = storeWithPin(nowISO(-5_000));
    store.storePin("did:key:zSupersededHolder", "acme.com/superseded", "", "");

    const changed = store.replaceVerifiedIdentity(
      "did:key:zSupersededHolder",
      PIN_KEY,
      ADDRESS,
      PIN_KEY,
      DID_KEY,
    );

    expect(changed).toBe(true);
    expect(store.pins.has("did:key:zSupersededHolder")).toBe(false);
  });

  // resolver-review probed five cells and named handle and server as unprobed
  // rather than implying the map was complete. These are those two.
  test("a handle change still commits, inside the window", () => {
    const store = storeWithPin(nowISO(-5_000));

    expect(store.storePin(PIN_KEY, ADDRESS, "@renamed", "")).toBe(true);
    expect(store.pins.get(PIN_KEY)?.handle).toBe("@renamed");
  });

  test("a server change still commits, inside the window", () => {
    const store = storeWithPin(nowISO(-5_000));

    expect(store.storePin(PIN_KEY, ADDRESS, "", "https://elsewhere.example")).toBe(true);
    expect(store.pins.get(PIN_KEY)?.server).toBe("https://elsewhere.example");
  });

  test("an unchanged pin reports no change - the control for the cells above", () => {
    const store = storeWithPin(nowISO(-5_000));

    expect(store.storePin(PIN_KEY, ADDRESS, "", "")).toBe(false);
  });

  test("a checkpoint advance is unaffected by the window", () => {
    const store = storeWithPin(nowISO(-5_000));

    expect(store.advanceLogCheckpoint(PIN_KEY, 7, "hash-7")).toBe(true);
  });

  // The last_seen path is also the recovery path after a failed durable commit
  // (Go states this at client.go commitRefresh). Coalescing must not strand an
  // undurable store: the caller's `stored || hasUndurableChanges()` has to still
  // reach the writer even when this refresh changed nothing.
  test("an undurable store still persists inside the window", async () => {
    const store = storeWithPin(nowISO(-5_000));
    const failing = { compareAndSet: vi.fn(async () => { throw new Error("aw binary missing"); }) };
    await expect(store.commit(failing, "/tmp/unused")).rejects.toThrow(/aw binary missing/);
    expect(store.hasUndurableChanges()).toBe(true);

    const retry = { compareAndSet: vi.fn(async () => {}) };
    const changed = store.recordVerifiedIdentity(PIN_KEY, ADDRESS, PIN_KEY, DID_KEY);
    if (changed || store.hasUndurableChanges()) await store.commit(retry, "/tmp/unused");

    expect(changed).toBe(false);
    expect(retry.compareAndSet).toHaveBeenCalledTimes(1);
  });

  test("a malformed last_seen refreshes rather than pinning the value forever", () => {
    const store = storeWithPin("not-a-timestamp");

    expect(store.recordVerifiedIdentity(PIN_KEY, ADDRESS, PIN_KEY, DID_KEY)).toBe(true);
  });
});
