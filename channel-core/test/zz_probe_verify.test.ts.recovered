import { describe, expect, test } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
import { PinStore, SenderTrustManager } from "../src/index.js";

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

const VICTIM_STABLE = "did:aw:zVictimStable";
const VICTIM_KEY = "did:key:zVictimKeyAAA";
const ATTACKER_STABLE = "did:aw:zAttackerStable";
const ATTACKER_KEY = "did:key:zAttackerKeyBBB";

const PINNED_YAML = `pins:
  ${VICTIM_STABLE}:
    address: aweb.ai/alice
    handle: alice
    stable_id: ${VICTIM_STABLE}
    did_key: ${VICTIM_KEY}
    first_seen: "2026-01-01T00:00:00Z"
    last_seen: "2026-01-01T00:00:00Z"
    server: https://api.aweb.ai
addresses:
  aweb.ai/alice: ${VICTIM_STABLE}
`;

function manager(registry: unknown): SenderTrustManager {
  return new SenderTrustManager(
    { get: async () => { throw new Error("should not be called for qualified address"); } } as never,
    registry as never,
    "aweb.ai",
    "did:key:zSelfRecipient",
    "",
  );
}

async function run(registry: unknown) {
  const store = PinStore.fromYAML(PINNED_YAML);
  expect(store.addresses.get("aweb.ai/alice")).toBe(VICTIM_STABLE);
  const result = await manager(registry).normalizeTrust(
    store,
    "verified",
    "aweb.ai/alice",
    ATTACKER_KEY,
    ATTACKER_STABLE,
    undefined,
    undefined,
  );
  return { result, store };
}

describe("probe: resolution failure vs pin check", () => {
  test("registry DOWN (resolveIdentity throws, verifyStableIdentity degrades)", async () => {
    const { result, store } = await run({
      verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED", error: "fetch failed" }),
      resolveIdentity: async () => { throw new Error("fetch failed"); },
    });
    console.log("REGISTRY DOWN ->", JSON.stringify(result), "pin now:", store.addresses.get("aweb.ai/alice"));
    expect(result.status).toBe("verified");
  });

  test("registry UP, address row still names the victim", async () => {
    const { result } = await run({
      verifyStableIdentity: async () => ({ outcome: "HARD_ERROR", error: "registry address did:aw mismatch" }),
      resolveIdentity: async () => ({
        did: ATTACKER_KEY,
        stableID: ATTACKER_STABLE,
        address: "aweb.ai/alice",
        controllerDid: "did:key:zController",
        custody: "self",
        identityScope: "global",
      }),
    });
    console.log("REGISTRY UP ->", JSON.stringify(result));
    expect(result.status).toBe("identity_mismatch");
  });

  test("resolution fails but registry check completes (address/key row disagree throw)", async () => {
    // resolveIdentity throws 'registry address/key mismatch' (registry.ts:283)
    // while verifyStableIdentity does not model that check and degrades.
    const { result } = await run({
      verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }),
      resolveIdentity: async () => { throw new Error("registry address/key mismatch"); },
    });
    console.log("ADDRESS/KEY MISMATCH ->", JSON.stringify(result));
    expect(result.status).toBe("verified");
  });
});
