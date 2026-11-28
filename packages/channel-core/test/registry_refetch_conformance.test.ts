import { readFileSync } from "node:fs";

import { describe, expect, test } from "vitest";

import { RegistryResolver } from "../src/identity/registry.js";

// The shared vector for docs/trust-model.md's bounded registry refetch; Go runs
// the same file (cli/go/awid/registry_refetch_vector_test.go).
interface RefetchResponse { status: number; body?: unknown }
interface RefetchStep { advance_seconds: number; from_did: string; expected_status: string }
interface RefetchCase {
  name: string;
  address: string;
  from_stable_id: string;
  responses: Record<string, RefetchResponse[]>;
  steps: RefetchStep[];
  expected_requests: Record<string, number>;
}
interface RefetchVector { schema: string; start_time: string; refetch_interval_seconds: number; vectors: RefetchCase[] }

const vector = JSON.parse(
  readFileSync(new URL("../../../test-vectors/trust/registry-refetch-v1.json", import.meta.url), "utf8"),
) as RefetchVector;

const registryURL = "https://registry.test";

describe("registry refetch conformance", () => {
  test("uses the registry-refetch schema", () => {
    expect(vector.schema).toBe("aweb.trust.registry-refetch.v1");
  });

  test.each(vector.vectors.map((c) => [c.name, c] as const))("%s", async (_name, tc) => {
    const served: Record<string, number> = {};
    const fetchImpl = (async (input: string | URL) => {
      const path = decodeURIComponent(new URL(String(input)).pathname);
      const queue = tc.responses[path];
      const n = served[path] ?? 0;
      served[path] = n + 1;
      if (!queue) return new Response("not found", { status: 404 });
      const answer = queue[Math.min(n, queue.length - 1)];
      return new Response(answer.body === undefined ? "" : JSON.stringify(answer.body), {
        status: answer.status,
        headers: { "Content-Type": "application/json" },
      });
    }) as typeof fetch;
    let now = Date.parse(vector.start_time);
    const resolver = new RegistryResolver(fetchImpl, async () => [], () => now, { fallbackRegistryURL: registryURL });

    for (const [index, step] of tc.steps.entries()) {
      now += step.advance_seconds * 1000;
      const result = await resolver.verifyStableIdentity(tc.address, tc.from_stable_id, step.from_did);
      // The status the trust manager takes from this result
      // (SenderTrustManager.applyPreparedStableIdentityRegistry).
      let status = "verified";
      if (result.outcome === "STALE_CACHE") status = "verification_stale";
      else if (result.outcome === "HARD_ERROR") status = "identity_mismatch";
      else if (result.outcome === "OK_VERIFIED" && result.currentDidKey && result.currentDidKey !== step.from_did) status = "identity_mismatch";
      expect({ step: index, status }).toEqual({ step: index, status: step.expected_status });
    }
    for (const [path, count] of Object.entries(tc.expected_requests)) {
      expect({ path, count: served[path] ?? 0 }).toEqual({ path, count });
    }
  });
});
