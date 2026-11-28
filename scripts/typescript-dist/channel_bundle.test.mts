// Behaviour of the built channel bundle named by AWEB_CHANNEL_DIST. Run by
// scripts/test-typescript-dist-freshness.sh against the production build and
// against bundles rebuilt from a mutated source.
import assert from "node:assert/strict";
import test from "node:test";
import { pathToFileURL } from "node:url";

import { genesisKeyAnswer, json, startLoopbackServer, stableIDOf } from "../../channel-core/test/helpers/dist_fixture.ts";

const distPath = process.env.AWEB_CHANNEL_DIST;
if (!distPath) throw new Error("AWEB_CHANNEL_DIST must name the built channel bundle");
delete process.env.AWID_REGISTRY_URL;
const { createChannelRegistryResolver } = await import(pathToFileURL(distPath).href);

const ADDRESS = "aweb.test/alice";

/** Verify ADDRESS against a loopback registry serving this genesis answer. */
async function verifyGenesis(signer: Uint8Array, stableID: string) {
  const answer = genesisKeyAnswer(signer, stableID);
  const registry = await startLoopbackServer((request, response) => {
    if (request.url === "/v1/namespaces/aweb.test/addresses/alice") {
      json(response, 200, {
        address_id: "address-alice", domain: "aweb.test", name: "alice",
        did_aw: stableID, current_did_key: answer.current_did_key, created_at: "2026-07-26T00:00:00Z",
      });
    } else if (request.url === `/v1/did/${stableID}/key`) {
      json(response, 200, answer);
    } else {
      json(response, 404, { detail: "not found" });
    }
  });
  try {
    const resolver = createChannelRegistryResolver({ registryURL: registry.url, address: ADDRESS });
    return await resolver.verifyStableIdentity(ADDRESS, stableID, answer.current_did_key);
  } finally {
    await registry.close();
  }
}

test("a genesis whose key derives its did:aw verifies", async () => {
  const signer = new Uint8Array(32).fill(61);
  const result = await verifyGenesis(signer, stableIDOf(signer));
  assert.equal(result.outcome, "OK_VERIFIED", `valid genesis was not verified: ${JSON.stringify(result)}`);
});

test("a genesis whose key does not derive its did:aw is a hard error", async () => {
  const signer = new Uint8Array(32).fill(61);
  const claimed = stableIDOf(new Uint8Array(32).fill(62));
  const result = await verifyGenesis(signer, claimed);
  assert.deepEqual(
    { outcome: result.outcome, error: result.error },
    { outcome: "HARD_ERROR", error: "did:aw not derived from genesis key" },
    "S4a: the genesis key must derive the did:aw",
  );
});
