import { describe, expect, test, vi } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  DEFAULT_AWID_REGISTRY_URL,
  RegistryResolver,
  canonicalDidLogPayload,
  discoverAuthoritativeRegistry,
  parseAwidTXTRecord,
  verifyDidKeyResolution,
  type DidKeyResolution,
} from "../src/identity/registry.js";

const testDir = dirname(fileURLToPath(import.meta.url));
const dnsVectors = JSON.parse(
  readFileSync(join(testDir, "..", "..", "docs", "vectors", "dns-txt-v1.json"), "utf-8"),
) as Array<{
  controller_did: string;
  dns_name: string;
  dns_value: string;
  registry_url: string | null;
}>;
const identityLogVectors = JSON.parse(
  readFileSync(join(testDir, "..", "..", "docs", "vectors", "identity-log-v1.json"), "utf-8"),
) as {
  mapping: {
    did_aw: string;
    initial_did_key: string;
    rotated_did_key: string;
  };
  entries: Array<{
    name: string;
    canonical_entry_payload: string;
    entry_hash: string;
    signature_b64: string;
    entry_payload: {
      authorized_by: string;
      did_aw: string;
      new_did_key: string;
      operation: string;
      prev_entry_hash: string | null;
      previous_did_key: string | null;
      seq: number;
      state_hash: string;
      timestamp: string;
    };
  }>;
};

function txtNotFound(): Error & { code: string } {
  return Object.assign(new Error("not found"), { code: "ENOTFOUND" });
}

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

describe("registry dns", () => {
  test("parses default and explicit registry records from vectors", () => {
    const defaultRecord = parseAwidTXTRecord(dnsVectors[0].dns_value, dnsVectors[0].dns_name);
    expect(defaultRecord.controllerDid).toBe(dnsVectors[0].controller_did);
    expect(defaultRecord.registryURL).toBe(DEFAULT_AWID_REGISTRY_URL);

    const explicitRecord = parseAwidTXTRecord(dnsVectors[1].dns_value, dnsVectors[1].dns_name);
    expect(explicitRecord.controllerDid).toBe(dnsVectors[1].controller_did);
    expect(explicitRecord.registryURL).toBe(dnsVectors[1].registry_url);
  });

  test("discovers nearest ancestor registry within the PSL boundary", async () => {
    const resolveTxt = vi.fn(async (hostname: string) => {
      if (hostname === "_awid.example.com") {
        return [[dnsVectors[1].dns_value]];
      }
      throw txtNotFound();
    });

    const authority = await discoverAuthoritativeRegistry("team.project.example.com", resolveTxt);
    expect(authority.registryURL).toBe(dnsVectors[1].registry_url);
    expect(authority.dnsName).toBe("_awid.example.com");
    expect(authority.inherited).toBe(true);
  });

  test("rejects registry origins with a path", () => {
    expect(() => parseAwidTXTRecord(
      `awid=v1; controller=${dnsVectors[0].controller_did}; registry=https://registry.example.com/api;`,
      "_awid.example.com",
    )).toThrow("server URL must not include a path");
  });
});

describe("registry verification", () => {
  test("verifies signed log-head vectors", () => {
    const rotate = identityLogVectors.entries.find((entry) => entry.name === "rotate_key");
    expect(rotate).toBeDefined();

    const resolution: DidKeyResolution = {
      did_aw: identityLogVectors.mapping.did_aw,
      current_did_key: identityLogVectors.mapping.rotated_did_key,
      log_head: {
        ...rotate!.entry_payload,
        entry_hash: rotate!.entry_hash,
        signature: rotate!.signature_b64,
      },
    };

    expect(canonicalDidLogPayload(identityLogVectors.mapping.did_aw, resolution.log_head!))
      .toBe(rotate!.canonical_entry_payload);

    const result = verifyDidKeyResolution(resolution, undefined, Date.now());
    expect(result.outcome).toBe("OK_VERIFIED");
    expect(result.nextHead?.entryHash).toBe(rotate!.entry_hash);
  });

  test("degrades when log_head is missing", () => {
    const result = verifyDidKeyResolution({
      did_aw: identityLogVectors.mapping.did_aw,
      current_did_key: identityLogVectors.mapping.initial_did_key,
    }, undefined, Date.now());
    expect(result.outcome).toBe("OK_DEGRADED");
  });

  test("fails hard when log_head current key disagrees with body", () => {
    const rotate = identityLogVectors.entries.find((entry) => entry.name === "rotate_key")!;
    const result = verifyDidKeyResolution({
      did_aw: identityLogVectors.mapping.did_aw,
      current_did_key: identityLogVectors.mapping.initial_did_key,
      log_head: {
        ...rotate.entry_payload,
        entry_hash: rotate.entry_hash,
        signature: rotate.signature_b64,
      },
    }, undefined, Date.now());
    expect(result.outcome).toBe("HARD_ERROR");
    expect(result.error).toContain("new_did_key mismatch");
  });
});

describe("registry resolver", () => {
  test("resolves address identity through registry DNS discovery", async () => {
    const rotate = identityLogVectors.entries.find((entry) => entry.name === "rotate_key")!;
    const fetchImpl: typeof fetch = vi.fn(async (input) => {
      const url = String(input);
      if (url === "https://registry.example.com/v1/namespaces/acme.com/addresses/alice") {
        return jsonResponse({
          address_id: "addr-1",
          domain: "acme.com",
          name: "alice",
          did_aw: identityLogVectors.mapping.did_aw,
          current_did_key: identityLogVectors.mapping.rotated_did_key,
          reachability: "public",
          created_at: "2026-04-04T00:00:00Z",
        });
      }
      if (url === `https://registry.example.com/v1/did/${identityLogVectors.mapping.did_aw}/key`) {
        return jsonResponse({
          did_aw: identityLogVectors.mapping.did_aw,
          current_did_key: identityLogVectors.mapping.rotated_did_key,
          log_head: {
            ...rotate.entry_payload,
            entry_hash: rotate.entry_hash,
            signature: rotate.signature_b64,
          },
        });
      }
      throw new Error(`unexpected url ${url}`);
    }) as typeof fetch;
    const resolveTxt = vi.fn(async (hostname: string) => {
      if (hostname === "_awid.acme.com") {
        return [[`awid=v1; controller=${identityLogVectors.mapping.initial_did_key}; registry=https://registry.example.com;`]];
      }
      throw txtNotFound();
    });

    const resolver = new RegistryResolver(fetchImpl, resolveTxt);
    await expect(resolver.resolveAddressIdentity("acme.com/alice")).resolves.toEqual({
      did: identityLogVectors.mapping.rotated_did_key,
      stableID: identityLogVectors.mapping.did_aw,
    });
  });

  test("degrades verification on transient registry failure", async () => {
    const fetchImpl: typeof fetch = vi.fn(async () => {
      throw new Error("timeout");
    }) as typeof fetch;
    const resolveTxt = vi.fn(async (hostname: string) => {
      if (hostname === "_awid.acme.com") {
        return [[`awid=v1; controller=${identityLogVectors.mapping.initial_did_key}; registry=https://registry.example.com;`]];
      }
      throw txtNotFound();
    });

    const resolver = new RegistryResolver(fetchImpl, resolveTxt);
    const result = await resolver.verifyStableIdentity("acme.com/alice", identityLogVectors.mapping.did_aw);
    expect(result.outcome).toBe("OK_DEGRADED");
  });

  test("fails hard when /key returns a different stable identity", async () => {
    const rotate = identityLogVectors.entries.find((entry) => entry.name === "rotate_key")!;
    const fetchImpl: typeof fetch = vi.fn(async (input) => {
      const url = String(input);
      if (url === "https://registry.example.com/v1/namespaces/acme.com/addresses/alice") {
        return jsonResponse({
          address_id: "addr-1",
          domain: "acme.com",
          name: "alice",
          did_aw: identityLogVectors.mapping.did_aw,
          current_did_key: identityLogVectors.mapping.rotated_did_key,
          reachability: "public",
          created_at: "2026-04-04T00:00:00Z",
        });
      }
      if (url === `https://registry.example.com/v1/did/${identityLogVectors.mapping.did_aw}/key`) {
        return jsonResponse({
          did_aw: "did:aw:SomeoneElse",
          current_did_key: identityLogVectors.mapping.rotated_did_key,
          log_head: {
            ...rotate.entry_payload,
            did_aw: undefined,
            entry_hash: rotate.entry_hash,
            signature: rotate.signature_b64,
          },
        });
      }
      throw new Error(`unexpected url ${url}`);
    }) as typeof fetch;
    const resolveTxt = vi.fn(async (hostname: string) => {
      if (hostname === "_awid.acme.com") {
        return [[`awid=v1; controller=${identityLogVectors.mapping.initial_did_key}; registry=https://registry.example.com;`]];
      }
      throw txtNotFound();
    });

    const resolver = new RegistryResolver(fetchImpl, resolveTxt);
    const result = await resolver.verifyStableIdentity("acme.com/alice", identityLogVectors.mapping.did_aw);
    expect(result.outcome).toBe("HARD_ERROR");
    expect(result.error).toContain("registry key did:aw mismatch");
  });

  test("uses path-safe encoding for did:aw lookups", async () => {
    const fetchImpl: typeof fetch = vi.fn(async (input) => {
      const url = String(input);
      if (url === "https://registry.example.com/v1/namespaces/acme.com/addresses/alice") {
        return jsonResponse({
          address_id: "addr-1",
          domain: "acme.com",
          name: "alice",
          did_aw: identityLogVectors.mapping.did_aw,
          current_did_key: identityLogVectors.mapping.rotated_did_key,
          reachability: "public",
          created_at: "2026-04-04T00:00:00Z",
        });
      }
      if (url === "https://registry.example.com/v1/did/did:aw:2CiZ88hVF4JuQim8nnSuyeiV2HF2/key") {
        return jsonResponse({
          did_aw: identityLogVectors.mapping.did_aw,
          current_did_key: identityLogVectors.mapping.rotated_did_key,
        });
      }
      throw new Error(`unexpected url ${url}`);
    }) as typeof fetch;
    const resolveTxt = vi.fn(async () => [[`awid=v1; controller=${identityLogVectors.mapping.initial_did_key}; registry=https://registry.example.com;`]]);

    const resolver = new RegistryResolver(fetchImpl, resolveTxt);
    await resolver.resolveAddressIdentity("acme.com/alice");

    expect(fetchImpl).toHaveBeenCalledWith(
      "https://registry.example.com/v1/did/did:aw:2CiZ88hVF4JuQim8nnSuyeiV2HF2/key",
      expect.anything(),
    );
  });
});
