import { describe, expect, test } from "vitest";
import { loadSessionPinStore } from "../src/channel.js";
import { PinStore } from "../src/identity/pinstore.js";

// aajc.2 adapter guard: both the Claude and Pi adapters load their pin store
// through loadSessionPinStore. It must never substitute a fresh empty store when
// the load fails, so a future "fall back to new PinStore()" regression in either
// adapter cannot silently discard the trust database.
describe("loadSessionPinStore adapter guard", () => {
  test("returns the loaded store on success without reporting an error", async () => {
    const store = new PinStore();
    store.storePin("did:key:zAlice", "acme.com/alice", "@alice", "");
    const errors: string[] = [];
    const result = await loadSessionPinStore((message) => errors.push(message), async () => store);
    expect(result).toBe(store);
    expect(errors).toEqual([]);
  });

  test("returns undefined (never an empty store) and reports the error when the load throws", async () => {
    const errors: string[] = [];
    const result = await loadSessionPinStore(
      (message) => errors.push(message),
      async () => {
        throw new Error("trust pin store at /x is corrupt: bad");
      },
    );
    // undefined, not a fresh PinStore — the adapter must not start the channel.
    expect(result).toBeUndefined();
    expect(result).not.toBeInstanceOf(PinStore);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain("corrupt");
  });
});
