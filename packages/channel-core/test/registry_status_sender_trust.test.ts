import * as ed from "@noble/ed25519";
import { afterEach, expect, test, vi } from "vitest";
import { APIClient, computeDIDKey, PinStore, RegistryResolver, SenderTrustManager } from "../src/index.js";
import { verifySignedPayload } from "../src/identity/signing.js";

afterEach(() => vi.unstubAllGlobals());
const team = "backend:acme.com";
const seed = (n: number) => new Uint8Array(32).fill(n);
const did = (key: Uint8Array) => computeDIDKey(ed.getPublicKey(key));

// A namespace address absent from the authenticated roster is resolved through
// the registry. A registry that answers "no such address" is a definitive
// absence; any other failure leaves the sender unconfirmed.
test.each([
  ["absent", "identity_mismatch"],
  ["unavailable", "verification_stale"],
  ["transport", "verification_stale"],
])("roster-absent namespace sender, registry %s => %s", async (variant, expected) => {
  const receiver = seed(81), sender = seed(82);
  const payload = JSON.stringify({ body: "synthetic", from_did: did(sender), to_did: did(receiver) });
  const signature = Buffer.from(ed.sign(Buffer.from(payload), sender)).toString("base64").replace(/=+$/, "");
  const verified = await verifySignedPayload(payload, signature, did(sender), did(sender));
  const client = new APIClient("https://aweb.example", {
    did: did(receiver), stableID: "", signingKey: receiver, teamID: team,
    authMode: "team", teamCertificateHeader: "synthetic-certificate",
  });
  vi.stubGlobal("fetch", vi.fn(async (url: string) => {
    expect(url).toBe("https://aweb.example/v1/agents");
    return new Response(JSON.stringify({ team_id: team, agents: [] }), { status: 200 });
  }));
  const registryRequests: string[] = [];
  const registryFetch = vi.fn(async (input: RequestInfo | URL) => {
    registryRequests.push(String(input));
    if (variant === "transport") throw new TypeError("fetch failed");
    return variant === "absent"
      ? new Response(JSON.stringify({ detail: "Address not found" }), { status: 404 })
      : new Response("unavailable", { status: 503 });
  }) as typeof fetch;
  const resolveTxt = vi.fn(async () => {
    throw Object.assign(new Error("not found"), { code: "ENOTFOUND" });
  });
  const registry = new RegistryResolver(registryFetch, resolveTxt, () => Date.now(), {
    fallbackRegistryURL: "https://registry.example",
  });
  const trust = new SenderTrustManager(client, registry, team, did(receiver));

  const result = await trust.normalizeTrust(new PinStore(), verified, "acme.com/alice", did(sender), undefined, did(receiver));

  expect(result.status).toBe(expected);
  expect(registryRequests).toEqual(["https://registry.example/v1/namespaces/acme.com/addresses/alice"]);
});
