import { describe, expect, test } from "vitest";
import { PinStore } from "../src/identity/pinstore.js";

// A stable id is one key and a pin carries one address, so an identity already
// pinned at another address cannot also migrate onto that key. Go declines the
// migration and keeps both pins; these pin the TypeScript half of that contract.

const DID = "did:key:z6Mks3e5U8apRpvF9c8mpPGZ3TQyeG2gXpv4qcbF8DvnVSpB";
const OTHER_DID = "did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP";
const STABLE_ID = "did:aw:49RVkxsgqYDxawqpb77fvYEmHw1t";

function seenAtBothAddresses(occupantDidKey: string = DID): PinStore {
  const store = new PinStore();
  store.recordVerifiedIdentity(STABLE_ID, "acme.com/bob", STABLE_ID, occupantDidKey || undefined);
  store.recordVerifiedIdentity(DID, "acme.com/alice", undefined, undefined);
  return store;
}

describe("stable-id migration declines rather than destroying a pin", () => {
  test.each([
    ["the same identity at two addresses", DID],
    ["a different identity holding the stable id", OTHER_DID],
  ])("rekey is refused when the key is occupied by %s", (_label, occupantDidKey) => {
    const store = seenAtBothAddresses(occupantDidKey);

    expect(store.rekeyPin(DID, STABLE_ID).status).toBe("conflict");
    expect(store.pins.get(STABLE_ID)?.address).toBe("acme.com/bob");
    expect(store.pins.get(DID)?.address).toBe("acme.com/alice");
    expect(store.addresses.get("acme.com/bob")).toBe(STABLE_ID);
    expect(store.addresses.get("acme.com/alice")).toBe(DID);
  });

  test("the declined state round-trips through this loader", () => {
    const reloaded = PinStore.fromYAML(seenAtBothAddresses().toYAML());
    expect(reloaded.checkPin("acme.com/bob", STABLE_ID, "persistent")).toBe("ok");
    expect(reloaded.checkPin("acme.com/alice", DID, "persistent")).toBe("ok");
    expect(reloaded.checkPin("acme.com/alice", "did:key:zEve", "persistent")).toBe("mismatch");
  });
});

// Go rejects a store whose forward and reverse indexes disagree in EITHER
// direction. This loader only checked that each address resolved to a known
// pin, so it accepted a pin claiming an address the index no longer points at —
// and then reported first contact for an address it holds a pin for.
describe("the loader checks both index directions", () => {
  const pin = [
    "pins:",
    "  did:key:zAlice:",
    "    address: acme.com/alice",
    "    first_seen: '2026-02-22T10:00:00Z'",
    "    last_seen: '2026-02-22T11:00:00Z'",
  ];

  test("a pin claiming an address with no reverse entry is rejected", () => {
    expect(() => PinStore.fromYAML([...pin, "addresses: {}", ""].join("\n")))
      .toThrow("pin store pin 'did:key:zAlice' claims address 'acme.com/alice' with no reverse index entry");
  });

  test("a reverse entry pointing at a pin that holds another address is rejected", () => {
    expect(() => PinStore.fromYAML([...pin, "addresses:", "  acme.com/bob: did:key:zAlice", ""].join("\n")))
      .toThrow("pin store reverse index for 'acme.com/bob' points at a pin whose address is 'acme.com/alice'");
  });

  test("a consistent store still loads", () => {
    const store = PinStore.fromYAML([...pin, "addresses:", "  acme.com/alice: did:key:zAlice", ""].join("\n"));
    expect(store.pins.size).toBe(1);
    expect(store.addresses.get("acme.com/alice")).toBe("did:key:zAlice");
  });
});
