import assert from "node:assert/strict";
import test from "node:test";

import { createPiRegistryResolver } from "../src/index.ts";

test("Pi discovers a foreign authority from its concrete identity address", async () => {
  const calls: string[] = [];
  const registry = createPiRegistryResolver({
    registryURL: "https://home.registry.example",
    address: "home.example/alice",
  }, async (hostname) => {
    calls.push(hostname);
    return [["awid=v1; controller=did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd; registry=https://foreign.registry.example;"]];
  });

  assert.equal(await registry.discoverRegistry("foreign.example"), "https://foreign.registry.example");
  assert.deepEqual(calls, ["_awid.foreign.example"]);
});
