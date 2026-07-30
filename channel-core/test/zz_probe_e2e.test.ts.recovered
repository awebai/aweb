import { describe, expect, test, vi } from "vitest";
import * as ed from "@noble/ed25519";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { computeDIDKey, computeStableID } from "../src/identity/did.js";
import { canonicalDidLogPayload, RegistryResolver } from "../src/identity/registry.js";
import { PinStore, SenderTrustManager } from "../src/index.js";

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

function seed(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}
function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

// Attacker holds their own key, so their genesis log is genuinely valid.
const atkPriv = seed(0x44);
const atkPub = ed.getPublicKey(atkPriv);
const ATK_DID = computeDIDKey(atkPub);
const ATK_STABLE = computeStableID(atkPub);

// Victim identity, already holding the address pin.
const victimPub = ed.getPublicKey(seed(0x55));
const VICTIM_DID = computeDIDKey(victimPub);
const VICTIM_STABLE = computeStableID(victimPub);

// A decoy key used only to make the ADDRESS row disagree with the KEY row.
const DECOY_DID = computeDIDKey(ed.getPublicKey(seed(0x66)));

function attackerGenesisHead() {
  const head = {
    authorized_by: ATK_DID,
    new_did_key: ATK_DID,
    operation: "register_did",
    prev_entry_hash: "",
    previous_did_key: "",
    seq: 1,
    state_hash: hex(sha256(new TextEncoder().encode(
      `{"current_did_key":"${ATK_DID}","did_aw":"${ATK_STABLE}"}`,
    ))),
    timestamp: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
  };
  const payload = canonicalDidLogPayload(ATK_STABLE, { ...head, entry_hash: "", signature: "" });
  const entry_hash = hex(sha256(new TextEncoder().encode(payload)));
  const signature = Buffer.from(ed.sign(new TextEncoder().encode(payload), atkPriv)).toString("base64").replace(/=+$/, "");
  return { ...head, entry_hash, signature };
}

function pinnedStore(): PinStore {
  return PinStore.fromYAML(`pins:
  ${VICTIM_STABLE}:
    address: acme.com/alice
    handle: alice
    stable_id: ${VICTIM_STABLE}
    did_key: ${VICTIM_DID}
    first_seen: "2026-01-01T00:00:00Z"
    last_seen: "2026-01-01T00:00:00Z"
    server: https://api.acme.com
addresses:
  acme.com/alice: ${VICTIM_STABLE}
`);
}

/** addressRowKey lets the malicious registry make the address row disagree with the key row. */
function maliciousRegistry(addressRowKey: string): RegistryResolver {
  const head = attackerGenesisHead();
  const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url === "https://registry.acme.com/v1/namespaces/acme.com/addresses/alice") {
      return jsonResponse({
        address_id: "addr-1", domain: "acme.com", name: "alice",
        did_aw: ATK_STABLE, current_did_key: addressRowKey,
        reachability: "public", created_at: "2026-01-01T00:00:00Z",
      });
    }
    if (url === `https://registry.acme.com/v1/did/${ATK_STABLE}/key`) {
      return jsonResponse({ did_aw: ATK_STABLE, current_did_key: ATK_DID, log_head: head });
    }
    if (url === `https://registry.acme.com/v1/did/${ATK_STABLE}/log`) {
      return jsonResponse([head]);
    }
    throw new Error(`unexpected url ${url}`);
  }) as unknown as typeof fetch;
  const resolveTxt = vi.fn(async (hostname: string) => {
    if (hostname === "_awid.acme.com") {
      return [[`awid=v1; controller=${DECOY_DID}; registry=https://registry.acme.com;`]];
    }
    const err = new Error("ENOTFOUND") as Error & { code?: string };
    err.code = "ENOTFOUND";
    throw err;
  });
  return new RegistryResolver(fetchImpl, resolveTxt);
}

async function attempt(addressRowKey: string) {
  const store = pinnedStore();
  const registry = maliciousRegistry(addressRowKey);
  const trust = new SenderTrustManager(
    { get: async () => { throw new Error("unexpected local resolution"); } } as never,
    registry,
    "acme.com",
    "did:key:zSelfRecipient",
    "",
  );
  const result = await trust.normalizeTrust(
    store, "verified", "acme.com/alice", ATK_DID, ATK_STABLE, undefined, undefined,
  );
  return { result, pinnedTo: store.addresses.get("acme.com/alice") };
}

describe("probe e2e: malicious registry, real RegistryResolver", () => {
  test("BASELINE address row agrees with key row -> pin check runs", async () => {
    const { result, pinnedTo } = await attempt(ATK_DID);
    console.log("BASELINE (address row == key row) ->", JSON.stringify(result), "pinned:", pinnedTo);
    expect(result.status).toBe("identity_mismatch");
    expect(pinnedTo).toBe(VICTIM_STABLE);
  });

  test("ATTACK address row disagrees with key row -> resolveIdentity throws -> pin skipped", async () => {
    const { result, pinnedTo } = await attempt(DECOY_DID);
    console.log("ATTACK (address row != key row) ->", JSON.stringify(result), "pinned:", pinnedTo);
    expect(result.status).toBe("verified");
    expect(pinnedTo).toBe(VICTIM_STABLE);
  });
});
