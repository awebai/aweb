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
  verifyDidLogEntries,
  type DidKeyResolution,
} from "../src/identity/registry.js";

// Delegate to the real verifier while observing whether malformed input reaches it.
const verifyCalls = vi.hoisted(() => vi.fn());
vi.mock("@noble/ed25519", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@noble/ed25519")>();
  return {
    ...actual,
    verify: (...args: Parameters<typeof actual.verify>) => {
      verifyCalls();
      return actual.verify(...args);
    },
  };
});

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
  test("verifies signed rotation adjacent to a cached genesis head", () => {
    const register = identityLogVectors.entries.find((entry) => entry.name === "register_did")!;
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

    // A rotation can only be OK_VERIFIED against the head it continues from.
    const cachedGenesis = {
      seq: 1,
      entryHash: register.entry_hash,
      stateHash: register.entry_payload.state_hash,
      currentDidKey: identityLogVectors.mapping.initial_did_key,
      fetchedAt: Date.now(),
    };
    const result = verifyDidKeyResolution(resolution, cachedGenesis, Date.now());
    expect(result.outcome).toBe("OK_VERIFIED");
    expect(result.nextHead?.entryHash).toBe(rotate!.entry_hash);
  });

  test("degrades an unanchored rotation with no cached head", () => {
    const rotate = identityLogVectors.entries.find((entry) => entry.name === "rotate_key")!;
    const result = verifyDidKeyResolution({
      did_aw: identityLogVectors.mapping.did_aw,
      current_did_key: identityLogVectors.mapping.rotated_did_key,
      log_head: {
        ...rotate.entry_payload,
        entry_hash: rotate.entry_hash,
        signature: rotate.signature_b64,
      },
    }, undefined, Date.now());
    expect(result.outcome).toBe("OK_DEGRADED");
  });

  test("verifies register_did log-head vectors", () => {
    const register = identityLogVectors.entries.find((entry) => entry.name === "register_did");
    expect(register).toBeDefined();

    const resolution: DidKeyResolution = {
      did_aw: identityLogVectors.mapping.did_aw,
      current_did_key: identityLogVectors.mapping.initial_did_key,
      log_head: {
        ...register!.entry_payload,
        entry_hash: register!.entry_hash,
        signature: register!.signature_b64,
      },
    };

    expect(canonicalDidLogPayload(identityLogVectors.mapping.did_aw, resolution.log_head!))
      .toBe(register!.canonical_entry_payload);

    const result = verifyDidKeyResolution(resolution, undefined, Date.now());
    expect(result.outcome).toBe("OK_VERIFIED");
    expect(result.nextHead?.entryHash).toBe(register!.entry_hash);
  });

  test("rejects malformed log-head signatures before invoking the verifier", () => {
    const register = identityLogVectors.entries.find((entry) => entry.name === "register_did")!;
    const resolution: DidKeyResolution = {
      did_aw: identityLogVectors.mapping.did_aw,
      current_did_key: identityLogVectors.mapping.initial_did_key,
      log_head: {
        ...register.entry_payload,
        entry_hash: register.entry_hash,
        signature: "YWJj=",
      },
    };

    verifyCalls.mockClear();
    expect(verifyDidKeyResolution(resolution, undefined, Date.now()).outcome).toBe("HARD_ERROR");
    expect(verifyCalls).not.toHaveBeenCalled();
  });

  test("degrades when log_head is missing", () => {
    const result = verifyDidKeyResolution({
      did_aw: identityLogVectors.mapping.did_aw,
      current_did_key: identityLogVectors.mapping.initial_did_key,
    }, undefined, Date.now());
    expect(result.outcome).toBe("OK_DEGRADED");
  });

  test.each([
    ["zero", 0],
    ["fractional", 1.5],
    ["NaN", Number.NaN],
    ["infinity", Number.POSITIVE_INFINITY],
    ["unsafe integer", Number.MAX_SAFE_INTEGER + 1],
  ])("rejects %s log-head seq before branch selection", (_name, seq) => {
    const register = identityLogVectors.entries.find((entry) => entry.name === "register_did")!;
    const result = verifyDidKeyResolution({
      did_aw: identityLogVectors.mapping.did_aw,
      current_did_key: identityLogVectors.mapping.initial_did_key,
      log_head: {
        ...register.entry_payload,
        seq,
        entry_hash: register.entry_hash,
        signature: register.signature_b64,
      },
    }, undefined, Date.now());

    expect(result).toEqual({
      outcome: "HARD_ERROR",
      error: "log_head seq must be a positive safe integer",
    });
  });

  test.each([
    ["fractional", 1.5],
    ["NaN", Number.NaN],
    ["infinity", Number.POSITIVE_INFINITY],
    ["unsafe integer", Number.MAX_SAFE_INTEGER + 1],
  ])("refuses %s verified-head checkpoint seeds", (_name, seq) => {
    const resolver = new RegistryResolver();
    resolver.seedVerifiedHead(identityLogVectors.mapping.did_aw, {
      seq,
      entryHash: "a".repeat(64),
      stateHash: "b".repeat(64),
      currentDidKey: identityLogVectors.mapping.initial_did_key,
      fetchedAt: 0,
    });

    const cache = (resolver as unknown as { headCache: Map<string, unknown> }).headCache;
    expect(cache.has(identityLogVectors.mapping.did_aw)).toBe(false);
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
  test("pins the concrete identity domain and discovers a foreign registry", async () => {
    const resolveTxt = vi.fn(async (hostname: string) => {
      if (hostname === "_awid.foreign.example") {
        return [[`awid=v1; controller=${identityLogVectors.mapping.initial_did_key}; registry=https://foreign.registry.example;`]];
      }
      throw new Error(`unexpected DNS lookup ${hostname}`);
    });
    const resolver = new RegistryResolver(fetch, resolveTxt, () => Date.now(), {
      fallbackRegistryURL: "https://home.registry.example",
      identityAddress: "home.example/alice",
    });

    await expect(resolver.discoverRegistry("home.example")).resolves.toBe("https://home.registry.example");
    expect(resolveTxt).not.toHaveBeenCalled();
    await expect(resolver.discoverRegistry("foreign.example")).resolves.toBe("https://foreign.registry.example");
    expect(resolveTxt).toHaveBeenCalledTimes(1);
  });

  test.each(["ETIMEOUT", "ESERVFAIL", "EAI_AGAIN"])(
    "falls back for foreign DNS transport failure %s",
    async (code) => {
      const resolveTxt = vi.fn(async () => {
        throw Object.assign(new Error("DNS transport failure"), { code });
      });
      const resolver = new RegistryResolver(fetch, resolveTxt, () => Date.now(), {
        fallbackRegistryURL: "https://home.registry.example",
        identityAddress: "home.example/alice",
      });

      await expect(resolver.discoverRegistry("foreign.example")).resolves.toBe("https://home.registry.example");
    },
  );

  test.each([
    ["malformed version", [[`awid=v2; controller=${identityLogVectors.mapping.initial_did_key}; registry=https://foreign.registry.example;`]], "unsupported awid version"],
    ["multiple records", [
      [`awid=v1; controller=${identityLogVectors.mapping.initial_did_key}; registry=https://one.registry.example;`],
      [`awid=v1; controller=${identityLogVectors.mapping.initial_did_key}; registry=https://two.registry.example;`],
    ], "multiple awid TXT records"],
    ["invalid controller", [["awid=v1; controller=did:key:invalid; registry=https://foreign.registry.example;"]], "invalid did:key"],
    ["invalid registry", [[`awid=v1; controller=${identityLogVectors.mapping.initial_did_key}; registry=https://foreign.registry.example/path;`]], "server URL must not include a path"],
  ])("rejects foreign %s instead of falling back", async (_name, records, error) => {
    const resolver = new RegistryResolver(fetch, vi.fn(async () => records as string[][]), () => Date.now(), {
      fallbackRegistryURL: "https://home.registry.example",
      identityAddress: "home.example/alice",
    });

    await expect(resolver.discoverRegistry("foreign.example")).rejects.toThrow(error as string);
  });

  test("keeps a hard pin when no concrete identity address is available", async () => {
    const resolveTxt = vi.fn(async () => {
      throw new Error("DNS must not be consulted without an own-domain boundary");
    });
    const resolver = new RegistryResolver(fetch, resolveTxt, () => Date.now(), {
      fallbackRegistryURL: "https://home.registry.example",
    });

    await expect(resolver.discoverRegistry("foreign.example")).resolves.toBe("https://home.registry.example");
    expect(resolveTxt).not.toHaveBeenCalled();
  });

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

  test("anchors a first-contact rotated identity via the full log", async () => {
    const register = identityLogVectors.entries.find((entry) => entry.name === "register_did")!;
    const rotate = identityLogVectors.entries.find((entry) => entry.name === "rotate_key")!;
    const logURL = `https://registry.example.com/v1/did/${identityLogVectors.mapping.did_aw}/log`;
    let logCalls = 0;
    const fetchImpl: typeof fetch = vi.fn(async (input) => {
      const url = String(input);
      if (url === "https://registry.example.com/v1/namespaces/acme.com/addresses/alice") {
        return jsonResponse({
          address_id: "addr-1",
          domain: "acme.com",
          name: "alice",
          did_aw: identityLogVectors.mapping.did_aw,
          current_did_key: identityLogVectors.mapping.rotated_did_key,
          created_at: "2026-04-04T00:00:00Z",
        });
      }
      // First contact only ever sees the current (seq>1) head here.
      if (url === `https://registry.example.com/v1/did/${identityLogVectors.mapping.did_aw}/key`) {
        return jsonResponse({
          did_aw: identityLogVectors.mapping.did_aw,
          current_did_key: identityLogVectors.mapping.rotated_did_key,
          log_head: { ...rotate.entry_payload, entry_hash: rotate.entry_hash, signature: rotate.signature_b64 },
        });
      }
      if (url === logURL) {
        logCalls++;
        return jsonResponse([
          { ...register.entry_payload, entry_hash: register.entry_hash, signature: register.signature_b64 },
          { ...rotate.entry_payload, entry_hash: rotate.entry_hash, signature: rotate.signature_b64 },
        ]);
      }
      throw new Error(`unexpected url ${url}`);
    }) as typeof fetch;
    const resolveTxt = vi.fn(async () => [[`awid=v1; controller=${identityLogVectors.mapping.initial_did_key}; registry=https://registry.example.com;`]]);
    const resolver = new RegistryResolver(fetchImpl, resolveTxt);

    const result = await resolver.verifyStableIdentity(
      "acme.com/alice",
      identityLogVectors.mapping.did_aw,
      identityLogVectors.mapping.rotated_did_key,
    );
    expect(result).toMatchObject({
      outcome: "OK_VERIFIED",
      currentDidKey: identityLogVectors.mapping.rotated_did_key,
    });
    expect(logCalls).toBe(1);
  });

  test("rejects a first-contact forged log whose genesis is not the victim's key", async () => {
    const rotate = identityLogVectors.entries.find((entry) => entry.name === "rotate_key")!;
    const logURL = `https://registry.example.com/v1/did/${identityLogVectors.mapping.did_aw}/log`;
    const fetchImpl: typeof fetch = vi.fn(async (input) => {
      const url = String(input);
      if (url === "https://registry.example.com/v1/namespaces/acme.com/addresses/alice") {
        return jsonResponse({
          address_id: "addr-1", domain: "acme.com", name: "alice",
          did_aw: identityLogVectors.mapping.did_aw,
          current_did_key: identityLogVectors.mapping.rotated_did_key,
          created_at: "2026-04-04T00:00:00Z",
        });
      }
      if (url === `https://registry.example.com/v1/did/${identityLogVectors.mapping.did_aw}/key`) {
        return jsonResponse({
          did_aw: identityLogVectors.mapping.did_aw,
          current_did_key: identityLogVectors.mapping.rotated_did_key,
          log_head: { ...rotate.entry_payload, entry_hash: rotate.entry_hash, signature: rotate.signature_b64 },
        });
      }
      if (url === logURL) {
        // Forged: the log starts at the rotation (no valid genesis for this did:aw).
        return jsonResponse([
          { ...rotate.entry_payload, entry_hash: rotate.entry_hash, signature: rotate.signature_b64 },
        ]);
      }
      throw new Error(`unexpected url ${url}`);
    }) as typeof fetch;
    const resolveTxt = vi.fn(async () => [[`awid=v1; controller=${identityLogVectors.mapping.initial_did_key}; registry=https://registry.example.com;`]]);
    const resolver = new RegistryResolver(fetchImpl, resolveTxt);

    const result = await resolver.verifyStableIdentity(
      "acme.com/alice",
      identityLogVectors.mapping.did_aw,
      identityLogVectors.mapping.rotated_did_key,
    );
    expect(result.outcome).not.toBe("OK_VERIFIED");
  });

  test("repeated signed-key mismatches stay stale without bypassing the key cache", async () => {
    const register = identityLogVectors.entries.find((entry) => entry.name === "register_did")!;
    const rotate = identityLogVectors.entries.find((entry) => entry.name === "rotate_key")!;
    let keyCalls = 0;
    const fetchImpl: typeof fetch = vi.fn(async (input) => {
      const url = String(input);
      if (url === "https://registry.example.com/v1/namespaces/acme.com/addresses/alice") {
        return jsonResponse({
          address_id: "addr-1",
          domain: "acme.com",
          name: "alice",
          did_aw: identityLogVectors.mapping.did_aw,
          current_did_key: identityLogVectors.mapping.rotated_did_key,
          created_at: "2026-04-04T00:00:00Z",
        });
      }
      if (url === `https://registry.example.com/v1/did/${identityLogVectors.mapping.did_aw}/key`) {
        keyCalls++;
        const entry = keyCalls === 1 ? register : rotate;
        return jsonResponse({
          did_aw: identityLogVectors.mapping.did_aw,
          current_did_key: entry.entry_payload.new_did_key,
          log_head: {
            ...entry.entry_payload,
            entry_hash: entry.entry_hash,
            signature: entry.signature_b64,
          },
        });
      }
      throw new Error(`unexpected url ${url}`);
    }) as typeof fetch;
    const resolveTxt = vi.fn(async () => [[`awid=v1; controller=${identityLogVectors.mapping.initial_did_key}; registry=https://registry.example.com;`]]);
    const resolver = new RegistryResolver(fetchImpl, resolveTxt);

    const initial = await resolver.verifyStableIdentity(
      "acme.com/alice",
      identityLogVectors.mapping.did_aw,
      identityLogVectors.mapping.initial_did_key,
    );
    expect(initial.outcome).toBe("OK_VERIFIED");

    for (let index = 0; index < 3; index += 1) {
      const result = await resolver.verifyStableIdentity(
        "acme.com/alice",
        identityLogVectors.mapping.did_aw,
        identityLogVectors.mapping.rotated_did_key,
      );
      expect(result).toMatchObject({
        outcome: "STALE_CACHE",
        currentDidKey: identityLogVectors.mapping.initial_did_key,
      });
    }
    expect(keyCalls).toBe(1);
  });

  test("does not make a second key request while reporting a cached mismatch stale", async () => {
    const register = identityLogVectors.entries.find((entry) => entry.name === "register_did")!;
    let keyCalls = 0;
    const fetchImpl: typeof fetch = vi.fn(async (input) => {
      const url = String(input);
      if (url === "https://registry.example.com/v1/namespaces/acme.com/addresses/alice") {
        return jsonResponse({
          address_id: "addr-1",
          domain: "acme.com",
          name: "alice",
          did_aw: identityLogVectors.mapping.did_aw,
          current_did_key: identityLogVectors.mapping.initial_did_key,
          created_at: "2026-04-04T00:00:00Z",
        });
      }
      if (url === `https://registry.example.com/v1/did/${identityLogVectors.mapping.did_aw}/key`) {
        keyCalls++;
        if (keyCalls > 1) throw new Error("registry unavailable during refresh");
        return jsonResponse({
          did_aw: identityLogVectors.mapping.did_aw,
          current_did_key: identityLogVectors.mapping.initial_did_key,
          log_head: {
            ...register.entry_payload,
            entry_hash: register.entry_hash,
            signature: register.signature_b64,
          },
        });
      }
      throw new Error(`unexpected url ${url}`);
    }) as typeof fetch;
    const resolver = new RegistryResolver(fetchImpl, vi.fn(async () => [[`awid=v1; controller=${identityLogVectors.mapping.initial_did_key}; registry=https://registry.example.com;`]]));

    await resolver.verifyStableIdentity(
      "acme.com/alice",
      identityLogVectors.mapping.did_aw,
      identityLogVectors.mapping.initial_did_key,
    );
    const result = await resolver.verifyStableIdentity(
      "acme.com/alice",
      identityLogVectors.mapping.did_aw,
      identityLogVectors.mapping.rotated_did_key,
    );

    expect(result.outcome).toBe("STALE_CACHE");
    expect(result.error).toContain("key cache does not match");
    expect(keyCalls).toBe(1);
  });

  test("repeated stable-id mismatches do not bypass the address cache", async () => {
    const register = identityLogVectors.entries.find((entry) => entry.name === "register_did")!;
    let addressCalls = 0;
    let keyCalls = 0;
    const fetchImpl: typeof fetch = vi.fn(async (input) => {
      const url = String(input);
      if (url === "https://registry.example.com/v1/namespaces/acme.com/addresses/alice") {
        addressCalls += 1;
        return jsonResponse({
          address_id: "addr-1",
          domain: "acme.com",
          name: "alice",
          did_aw: identityLogVectors.mapping.did_aw,
          current_did_key: identityLogVectors.mapping.initial_did_key,
          created_at: "2026-04-04T00:00:00Z",
        });
      }
      if (url === `https://registry.example.com/v1/did/${identityLogVectors.mapping.did_aw}/key`) {
        keyCalls += 1;
        return jsonResponse({
          did_aw: identityLogVectors.mapping.did_aw,
          current_did_key: identityLogVectors.mapping.initial_did_key,
          log_head: {
            ...register.entry_payload,
            entry_hash: register.entry_hash,
            signature: register.signature_b64,
          },
        });
      }
      throw new Error(`unexpected url ${url}`);
    }) as typeof fetch;
    const resolver = new RegistryResolver(
      fetchImpl,
      vi.fn(async () => [[`awid=v1; controller=${identityLogVectors.mapping.initial_did_key}; registry=https://registry.example.com;`]]),
    );

    expect((await resolver.verifyStableIdentity(
      "acme.com/alice",
      identityLogVectors.mapping.did_aw,
      identityLogVectors.mapping.initial_did_key,
    )).outcome).toBe("OK_VERIFIED");
    for (let index = 0; index < 3; index += 1) {
      const result = await resolver.verifyStableIdentity(
        "acme.com/alice",
        "did:aw:different",
        identityLogVectors.mapping.initial_did_key,
      );
      expect(result.outcome).toBe("HARD_ERROR");
    }
    expect(addressCalls).toBe(1);
    expect(keyCalls).toBe(1);
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

  test("uses embedded fallback registry when DNS TXT is missing", async () => {
    const fetchImpl: typeof fetch = vi.fn(async (input) => {
      const url = String(input);
      if (url === "http://127.0.0.1:8000/v1/namespaces/probeproj.aweb.local/addresses/alice") {
        return jsonResponse({
          address_id: "addr-1",
          domain: "probeproj.aweb.local",
          name: "alice",
          did_aw: identityLogVectors.mapping.did_aw,
          current_did_key: identityLogVectors.mapping.rotated_did_key,
          reachability: "nobody",
          created_at: "2026-04-04T00:00:00Z",
        });
      }
      if (url === `http://127.0.0.1:8000/v1/did/${identityLogVectors.mapping.did_aw}/key`) {
        return jsonResponse({
          did_aw: identityLogVectors.mapping.did_aw,
          current_did_key: identityLogVectors.mapping.rotated_did_key,
        });
      }
      throw new Error(`unexpected url ${url}`);
    }) as typeof fetch;

    const resolveTxt = vi.fn(async () => {
      throw txtNotFound();
    });
    const resolver = new RegistryResolver(fetchImpl, resolveTxt, () => Date.now(), {
      fallbackRegistryURL: "http://127.0.0.1:8000",
      identityAddress: "home.aweb.local/local",
    });

    await expect(resolver.resolveAddressIdentity("probeproj.aweb.local/alice")).resolves.toEqual({
      did: identityLogVectors.mapping.rotated_did_key,
      stableID: identityLogVectors.mapping.did_aw,
    });
    expect(resolveTxt).toHaveBeenCalled();
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

interface RawWireVectorFile {
  schema: string;
  cases: Array<{
    name: string;
    resolution_json: string;
    cached_json: string;
    expected_outcome: "HARD_ERROR";
    // Positive per-runtime expectations. The corpus previously carried a
    // nullable known_runtime_gap note that doubled as a branch selector in the
    // Go consumer, so the metadata could change WHICH assertion ran.
    expected_error_substrings: { typescript: string[] };
  }>;
}

const rawWireVectors = JSON.parse(
  readFileSync(join(testDir, "..", "..", "docs", "vectors", "identity-log-raw-wire-v1.json"), "utf-8"),
) as RawWireVectorFile;

describe("identity-log-raw-wire-v1 shared vectors", () => {
  test("uses the raw-wire schema required for decoder-level cases", () => {
    expect(rawWireVectors.schema).toBe("aweb.identity-log.raw-wire.v1");
  });

  for (const testCase of rawWireVectors.cases) {
    test(testCase.name, () => {
      const resolution = JSON.parse(testCase.resolution_json) as DidKeyResolution;
      const cached = JSON.parse(testCase.cached_json) as NonNullable<
        Parameters<typeof verifyDidKeyResolution>[1]
      >;

      const result = verifyDidKeyResolution(resolution, cached, Date.now());

      expect(result.outcome).toBe(testCase.expected_outcome);
      expect(result.nextHead).toBeUndefined();
      // Assert the rejection is the one the corpus names, not merely that some
      // rejection happened — the failure has to be for the right reason.
      expect(testCase.expected_error_substrings.typescript.length).toBeGreaterThan(0);
      for (const substring of testCase.expected_error_substrings.typescript) {
        expect(result.error ?? "").toContain(substring);
      }
    });
  }
});

interface NegativeVectorFile {
  cases: Array<{
    name: string;
    did_aw: string;
    current_did_key: string;
    log_head: DidKeyResolution["log_head"];
    cached: {
      seq: number;
      entry_hash: string;
      state_hash: string;
      current_did_key: string;
    } | null;
    expected_outcome: "OK_VERIFIED" | "OK_DEGRADED" | "HARD_ERROR";
  }>;
  log_cases: Array<{
    name: string;
    did_aw: string;
    entries: NonNullable<DidKeyResolution["log_head"]>[];
    expect_error: boolean;
    expected_current_did_key?: string;
  }>;
}

const negativeVectors = JSON.parse(
  readFileSync(join(testDir, "..", "..", "docs", "vectors", "identity-log-negative-v1.json"), "utf-8"),
) as NegativeVectorFile;

describe("identity-log-negative-v1 shared vectors", () => {
  for (const testCase of negativeVectors.cases) {
    test(testCase.name, () => {
      const cached = testCase.cached
        ? {
            seq: testCase.cached.seq,
            entryHash: testCase.cached.entry_hash,
            stateHash: testCase.cached.state_hash,
            currentDidKey: testCase.cached.current_did_key,
            fetchedAt: Date.now(),
          }
        : undefined;
      const result = verifyDidKeyResolution(
        {
          did_aw: testCase.did_aw,
          current_did_key: testCase.current_did_key,
          log_head: testCase.log_head,
        },
        cached,
        Date.now(),
      );
      expect(result.outcome).toBe(testCase.expected_outcome);
    });
  }

  for (const logCase of negativeVectors.log_cases) {
    test(logCase.name, () => {
      const result = verifyDidLogEntries(logCase.did_aw, logCase.entries, Date.now());
      if (logCase.expect_error) {
        expect(result.error).toBeTruthy();
        expect(result.head).toBeUndefined();
      } else {
        expect(result.error).toBeUndefined();
        expect(result.head?.currentDidKey).toBe(logCase.expected_current_did_key);
      }
    });
  }
});
