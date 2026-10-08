import { createHash } from "node:crypto";
import * as ed from "@noble/ed25519";
import { afterEach, describe, expect, test, vi } from "vitest";
import { APIClient, computeDIDKey, PinStore, SenderTrustManager } from "../src/index.js";
import { verifySignedPayload } from "../src/identity/signing.js";

afterEach(() => vi.unstubAllGlobals());
const team = "backend:acme.com";
const seed = (n: number) => new Uint8Array(32).fill(n);
const did = (key: Uint8Array) => computeDIDKey(ed.getPublicKey(key));

describe.each(["grant", "team"] as const)("%s receiver authoritative roster", mode => {
  test.each([
    ["matching", "verified"], ["domain-address", "verified"], ["mismatch", "identity_mismatch"],
    ["absent", "identity_mismatch"], ["unavailable", "verification_stale"],
    ["non-member", "verification_stale"], ["wrong-team", "verification_stale"],
    ["forged-message", "failed"],
  ])("%s => %s", async (variant, expected) => {
    const receiver = seed(91), sender = seed(92);
    const payload = JSON.stringify({ body: "synthetic", from_did: did(sender), to_did: did(receiver) });
    const signature = Buffer.from(ed.sign(Buffer.from(payload), variant === "forged-message" ? seed(93) : sender)).toString("base64").replace(/=+$/, "");
    const verified = await verifySignedPayload(payload, signature, did(sender), did(sender));
    const client = new APIClient("https://aweb.example", {
      did: did(receiver), stableID: "", signingKey: receiver, teamID: team,
      authMode: mode, grantID: mode === "grant" ? "synthetic-grant" : undefined,
      teamCertificateHeader: mode === "team" ? "synthetic-certificate" : "",
    });
    const requests: string[] = [];
    vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit) => {
      requests.push(url);
      expect(url).toBe("https://aweb.example/v1/agents");
      expect(init.method).toBe("GET");
      const headers = new Headers(init.headers);
      const auth = headers.get("Authorization")!;
      const signatureBytes = Buffer.from(auth.split(" ").at(-1)!, "base64");
      let signed: string;
      if (mode === "grant") {
        expect(auth).toMatch(/^AWEB-Grant DIDKey /);
        expect(headers.get("X-AWID-Team-Certificate")).toBeNull();
        signed = Buffer.from(headers.get("X-AWEB-Signed-Payload")!, "base64url").toString();
        expect(JSON.parse(signed)).toEqual({ v: 1, auth: "identity-grant", aud: "https://aweb.example",
          method: "GET", path: "/v1/agents", grant_id: "synthetic-grant",
          body_sha256: createHash("sha256").update("").digest("hex"), timestamp: headers.get("X-AWEB-Timestamp") });
      } else {
        expect(auth).toMatch(/^DIDKey /);
        expect(headers.get("X-AWID-Team-Certificate")).toBe("synthetic-certificate");
        signed = JSON.stringify({ body_sha256: createHash("sha256").update("").digest("hex"),
          team_id: team, timestamp: headers.get("X-AWEB-Timestamp") });
      }
      expect(ed.verify(signatureBytes, Buffer.from(signed), ed.getPublicKey(receiver))).toBe(true);
      if (variant === "unavailable") return new Response("unavailable", { status: 503 });
      if (variant === "non-member") return new Response("not a member", { status: 403 });
      return new Response(JSON.stringify({ team_id: variant === "wrong-team" ? "other:acme.com" : team,
        agents: variant === "absent" ? [] : [{ alias: "alice", did_key: did(variant === "mismatch" ? seed(94) : sender), identity_scope: "local" }],
      }), { status: 200 });
    }));
    const registry = { resolveIdentity: vi.fn(async () => { throw new Error("no registry fallback"); }) };
    const trust = new SenderTrustManager(client, registry as never, team, did(receiver));
    const result = await trust.normalizeTrust(new PinStore(), verified, variant === "domain-address" ? "acme.com/alice" : `${team}/alice`, did(sender), undefined, did(receiver));
    expect(result.status).toBe(expected);
    expect(requests).toHaveLength(variant === "forged-message" ? 0 : 1);
    expect(registry.resolveIdentity).not.toHaveBeenCalled();
  });
});

test("grant roster capability never falls back to a certificate on incomplete grant state", () => {
  const auth = { did: did(seed(95)), stableID: "", signingKey: seed(95), teamID: team,
    authMode: "grant" as const, grantID: "synthetic-grant", teamCertificateHeader: "synthetic-certificate" };
  const client = new APIClient("https://aweb.example", auth);
  expect(client.hasTeamRosterAuth(team)).toBe(true);
  expect(client.hasTeamRosterAuth("other:acme.com")).toBe(false);
  for (const change of [{ grantID: "" }, { grantID: "  " }, { signingKey: new Uint8Array() }, { did: "" }]) {
    expect(new APIClient("https://aweb.example", { ...auth, ...change }).hasTeamRosterAuth(team)).toBe(false);
  }
  expect(new APIClient("https://aweb.example", { ...auth, teamCertificateHeader: "" }).hasTeamCertificateAuth(team)).toBe(false);
});
