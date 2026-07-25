import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, test, vi } from "vitest";
import { RegistryResolver } from "../src/identity/registry.js";

const testDir = dirname(fileURLToPath(import.meta.url));
const identityLogVectors = JSON.parse(
  readFileSync(join(testDir, "..", "..", "docs", "vectors", "identity-log-v1.json"), "utf-8"),
) as {
  mapping: { did_aw: string; initial_did_key: string; rotated_did_key: string };
  entries: {
    name: string;
    entry_payload: Record<string, unknown>;
    entry_hash: string;
    signature_b64: string;
  }[];
};

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

// The TS mirror of the Go anti-rollback repro (default-aajc.8). Verified log
// heads live only in a process-memory cache while the pin persists on disk, so
// after a restart a compromised registry can serve a VALID but TRUNCATED prefix
// of the log and roll a rotated identity back to its retired key. The checkpoint
// persisted with the pin is restored via seedVerifiedHead, and a served log must
// then contain and extend it.
describe("did log anti-rollback checkpoint", () => {
  const { did_aw: didAW, initial_did_key: initialKey, rotated_did_key: rotatedKey } =
    identityLogVectors.mapping;
  const register = identityLogVectors.entries.find((e) => e.name === "register_did")!;
  const rotate = identityLogVectors.entries.find((e) => e.name === "rotate_key")!;

  const wire = (entry: typeof register) => ({
    ...entry.entry_payload,
    entry_hash: entry.entry_hash,
    signature: entry.signature_b64,
  });

  // truncated=true makes the registry serve genesis only — a valid prefix,
  // correctly signed, that omits the rotation we already verified.
  function makeResolver(truncated: boolean) {
    const head = truncated ? register : rotate;
    const currentKey = truncated ? initialKey : rotatedKey;
    const entries = truncated ? [wire(register)] : [wire(register), wire(rotate)];
    const fetchImpl: typeof fetch = vi.fn(async (input) => {
      const url = String(input);
      if (url.endsWith("/v1/namespaces/acme.com/addresses/alice")) {
        return jsonResponse({
          address_id: "addr-1",
          domain: "acme.com",
          name: "alice",
          did_aw: didAW,
          current_did_key: currentKey,
          reachability: "public",
          created_at: "2026-02-01T00:00:00Z",
        });
      }
      if (url.endsWith(`/key`)) {
        return jsonResponse({ did_aw: didAW, current_did_key: currentKey, log_head: wire(head) });
      }
      if (url.endsWith(`/log`)) return jsonResponse(entries);
      throw new Error(`unexpected url ${url}`);
    }) as typeof fetch;
    return new RegistryResolver(
      fetchImpl,
      vi.fn(async () => [[`awid=v1; controller=${initialKey}; registry=https://registry.example.com;`]]),
    );
  }

  test("verifies the rotation and reports the head so it can be checkpointed", async () => {
    const result = await makeResolver(false).verifyStableIdentity("acme.com/alice", didAW, rotatedKey);

    expect(result.outcome).toBe("OK_VERIFIED");
    expect(result.verifiedHead?.seq).toBe(rotate.entry_payload.seq);
    expect(result.verifiedHead?.entryHash).toBe(rotate.entry_hash);
  });

  test("refuses a truncated log that is behind the restored checkpoint", async () => {
    // A fresh resolver stands in for a restarted process: its head cache is
    // empty, and the checkpoint is restored from the persisted pin.
    const resolver = makeResolver(true);
    resolver.seedVerifiedHead(didAW, {
      seq: rotate.entry_payload.seq as number,
      entryHash: rotate.entry_hash,
      stateHash: "",
      currentDidKey: rotatedKey,
      fetchedAt: 0,
    });

    const result = await resolver.verifyStableIdentity("acme.com/alice", didAW, initialKey);

    expect(result.outcome).toBe("HARD_ERROR");
    expect(result.error).toBeTruthy();
  });

  test("without the restored checkpoint the same truncated log is accepted (the bug)", async () => {
    // Documents exactly what the persisted checkpoint buys: identical response,
    // no seeded anchor, and genesis verifies as current — the rollback.
    const result = await makeResolver(true).verifyStableIdentity("acme.com/alice", didAW, initialKey);

    expect(result.outcome).toBe("OK_VERIFIED");
  });

  test("seeding never moves the anchor backwards", async () => {
    const resolver = makeResolver(true);
    resolver.seedVerifiedHead(didAW, {
      seq: rotate.entry_payload.seq as number,
      entryHash: rotate.entry_hash,
      stateHash: "",
      currentDidKey: rotatedKey,
      fetchedAt: 0,
    });
    // A lower sequence must not displace the higher anchor.
    resolver.seedVerifiedHead(didAW, {
      seq: 1,
      entryHash: register.entry_hash,
      stateHash: "",
      currentDidKey: initialKey,
      fetchedAt: 0,
    });

    const result = await resolver.verifyStableIdentity("acme.com/alice", didAW, initialKey);

    expect(result.outcome).toBe("HARD_ERROR");
  });
});
