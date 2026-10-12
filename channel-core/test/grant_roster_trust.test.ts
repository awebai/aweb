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
  test.each([
    ["replacement", "verified"], ["other-key", "identity_mismatch"], ["absent", "identity_mismatch"], ["absent-address", "identity_mismatch"],
    ["unavailable", "verification_stale"], ["wrong-team", "verification_stale"],
    ["global", "identity_mismatch"],
    ["new-member", "verified"], ["new-member-absent", "identity_mismatch"],
    ["new-member-other-key", "identity_mismatch"], ["new-member-unavailable", "verification_stale"],
    ["new-member-wrong-team", "verification_stale"],
  ])("cached local key refresh: %s => %s", async (variant, expected) => {
    const receiver = seed(96), previous = seed(97), sender = seed(98);
    const client = new APIClient("https://aweb.example", {
      did: did(receiver), stableID: "", signingKey: receiver, teamID: team,
      authMode: mode, grantID: mode === "grant" ? "synthetic-grant" : undefined,
      teamCertificateHeader: mode === "team" ? "synthetic-certificate" : "",
    });
    // The external aweb HTTP boundary changes its authoritative roster after
    // the receiver has cached the old local key or an absent member. All auth/signature/trust code
    // is real; this fixture stands only for the remote server response.
    let phase = "before";
    const initiallyAbsent = variant.startsWith("new-member");
    const outcome = variant === "new-member" ? "replacement"
      : initiallyAbsent ? variant.slice("new-member-".length) : variant;
    const freshHeaders: Array<string | null> = [];
    vi.stubGlobal("fetch", vi.fn(async (_url: string, init: RequestInit) => {
      freshHeaders.push(new Headers(init.headers).get("Cache-Control"));
      if (phase !== "before" && outcome === "unavailable") return new Response("unavailable", { status: 503 });
      return new Response(JSON.stringify({
        team_id: phase !== "before" && outcome === "wrong-team" ? "other:acme.com" : team,
        agents: (phase === "before" && initiallyAbsent) || (phase !== "before" && outcome.startsWith("absent")) ? [] : [{ alias: "alice",
          did_key: phase === "before" || outcome === "other-key" ? did(previous) : did(sender),
          identity_scope: phase !== "before" && outcome === "global" ? "global" : "local" }],
      }));
    }));
    let now = 0;
    const trust = new SenderTrustManager(client, {} as never, team, did(receiver), "", () => now, () => 0);
    const store = new PinStore();
    const address = variant === "absent-address" ? "acme.com/alice" : "alice";
    expect((await trust.normalizeTrust(store, "verified", address, did(previous), undefined, did(receiver))).status)
      .toBe(initiallyAbsent ? "identity_mismatch" : "verified");
    phase = "after";
    const payload = JSON.stringify({ from_did: did(sender), to_did: did(receiver), body: "replacement" });
    const signature = Buffer.from(ed.sign(Buffer.from(payload), sender)).toString("base64").replace(/=+$/, "");
    const verified = await verifySignedPayload(payload, signature, did(sender), did(sender));
    const prepare = () => trust.resolveTrustMetadata(verified, address, undefined, did(receiver), undefined,
      { pinStore: store, fromDID: did(sender), verificationAddress: "alice" });
    // Concurrent arrivals coalesce one refresh before any pin lock/decision.
    const metadata = await Promise.all(Array.from({ length: 10 }, prepare));
    for (const resolved of metadata) {
      expect((await trust.normalizeResolvedTrust(store, verified, address, did(sender), undefined, did(receiver),
        undefined, undefined, undefined, undefined, resolved)).status).toBe(expected);
    }
    for (let n = 0; n < 10; n++) {
      expect((await trust.normalizeTrust(store, verified, address, did(sender), undefined, did(receiver))).status).toBe(expected);
    }
    expect(freshHeaders).toEqual([null, "no-cache"]);
    expect(store.pins.size).toBe(0);
    if (outcome === "other-key" || outcome.startsWith("absent")) {
      now = 10_001;
      await trust.normalizeTrust(store, verified, address, did(sender), undefined, did(receiver));
      expect(freshHeaders).toEqual([null, "no-cache", "no-cache"]);
    }
    if (expected === "verified") {
      // After a successful transition, a key outside the current roster still
      // gets only one fresh read per interval. Matching cached traffic cannot
      // clear that unsuccessful refresh's backoff.
      const rejected = () => trust.normalizeTrust(store, "verified", address, did(previous), undefined, did(receiver));
      for (let n = 0; n < 10; n++) expect((await rejected()).status).toBe("identity_mismatch");
      expect((await trust.normalizeTrust(store, "verified", address, did(sender), undefined, did(receiver))).status).toBe("verified");
      expect((await rejected()).status).toBe("identity_mismatch");
      expect(freshHeaders).toEqual([null, "no-cache", "no-cache"]);
      now = 10_001;
      expect((await rejected()).status).toBe("identity_mismatch");
      expect(freshHeaders).toEqual([null, "no-cache", "no-cache", "no-cache"]);
    }
  });

  test.each(["match", "failed-signature", "wrong-recipient", "global-metadata", "stable-sender"])(
    "cached mismatch refresh excludes %s", async variant => {
      const receiver = seed(99), oldSender = seed(100), newSender = seed(101);
      const client = new APIClient("https://aweb.example", {
        did: did(receiver), stableID: "", signingKey: receiver, teamID: team,
        authMode: mode, grantID: mode === "grant" ? "synthetic-grant" : undefined,
        teamCertificateHeader: mode === "team" ? "synthetic-certificate" : "",
      });
      const requests: Array<string | null> = [];
      vi.stubGlobal("fetch", vi.fn(async (_url: string, init: RequestInit) => {
        requests.push(new Headers(init.headers).get("Cache-Control"));
        return new Response(JSON.stringify({ team_id: team, agents: [{ alias: "alice", did_key: did(oldSender),
          identity_scope: variant === "global-metadata" ? "global" : "local" }] }));
      }));
      const trust = new SenderTrustManager(client, {} as never, team, did(receiver));
      const store = new PinStore();
      await trust.normalizeTrust(store, "verified", "alice", did(oldSender), undefined, did(receiver));
      const presented = variant === "match" ? oldSender : newSender;
      const payload = JSON.stringify({ from_did: did(presented), to_did: did(receiver), body: "guard" });
      const signature = Buffer.from(ed.sign(Buffer.from(payload), variant === "failed-signature" ? oldSender : presented)).toString("base64").replace(/=+$/, "");
      const status = await verifySignedPayload(payload, signature, did(presented), did(presented));
      const result = await trust.normalizeTrust(store, status, "alice", did(presented),
        variant === "stable-sender" ? "did:aw:alice" : undefined,
        variant === "wrong-recipient" ? did(oldSender) : did(receiver));
      expect(result.status).toBe(variant === "match" ? "verified" : variant === "failed-signature" ? "failed" : "identity_mismatch");
      expect(requests).toEqual([null]);
    },
  );

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
