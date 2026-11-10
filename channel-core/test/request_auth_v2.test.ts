// Every root-authenticated request is signed with the v2 request envelope
// (docs/team-auth-envelope-v2.md): the signature covers the audience, method,
// path with query, body hash and timestamp, with team_id for a certificate
// request or did_aw for an identity request. The shared vectors are the Go and
// Python signers' too.
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import * as ed from "@noble/ed25519";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { APIClient, signRequestHeaders } from "../src/index.js";
import { computeDIDKey } from "../src/identity/did.js";

interface VectorCase {
  name: string;
  seed_hex: string;
  did_key: string;
  body: string;
  payload: Record<string, string | number>;
  canonical_payload: string;
  signed_payload_b64url: string;
  signature_b64: string;
}

const vectors = JSON.parse(
  readFileSync(join(import.meta.dirname, "..", "..", "docs", "vectors", "team-auth-envelope-v2.json"), "utf8"),
) as { cases: VectorCase[] };
const REQUIRED = ["aud", "body_sha256", "method", "path", "team_id", "timestamp", "v"];

describe("v2 request envelope conformance", () => {
  const plain = vectors.cases.filter((c) => Object.keys(c.payload).sort().join() === REQUIRED.join());

  test("the vector file has a case with only the required claims", () => {
    expect(plain.map((c) => c.name)).toContain("oss_task_create_without_operation");
  });

  test.each(plain)("$name: headers match the shared vector byte for byte", (c) => {
    const signed = signRequestHeaders({
      baseURL: String(c.payload.aud),
      path: String(c.payload.path),
      method: String(c.payload.method).toLowerCase(),
      bodyText: c.body,
      signingKey: Buffer.from(c.seed_hex, "hex"),
      claim: "team_id",
      value: String(c.payload.team_id),
      timestamp: String(c.payload.timestamp),
    });
    expect(signed.canonicalPayload).toBe(c.canonical_payload);
    expect(signed["X-AWEB-Signed-Payload"]).toBe(c.signed_payload_b64url);
    expect(signed.Authorization).toBe(`DIDKey ${c.did_key} ${c.signature_b64}`);
    expect(signed["X-AWEB-Timestamp"]).toBe(c.payload.timestamp);
  });

  test("a mounted base path and the query are part of the signed path", () => {
    const signed = signRequestHeaders({
      baseURL: "https://app.example/api", path: "/v1/tasks?dry_run=true", method: "GET",
      signingKey: new Uint8Array(32).fill(1), claim: "team_id", value: "t:example.com", timestamp: "2026-06-12T10:00:00Z",
    });
    expect(JSON.parse(signed.canonicalPayload)).toMatchObject({ aud: "https://app.example", path: "/api/v1/tasks?dry_run=true", method: "GET" });
  });
});

describe("APIClient request signing", () => {
  const fetchMock = vi.fn<typeof fetch>();
  const signingKey = new Uint8Array(32).fill(1);
  const did = computeDIDKey(ed.getPublicKey(signingKey));
  const auth = { did, stableID: "did:aw:test", signingKey, teamID: "backend:acme.com", teamCertificateHeader: "cert-header" };

  beforeEach(() => {
    fetchMock.mockReset();
    fetchMock.mockImplementation(async () => new Response("{}", { status: 200, headers: { "Content-Type": "application/json" } }));
    vi.stubGlobal("fetch", fetchMock);
  });
  afterEach(() => { vi.unstubAllGlobals(); });

  function sent(): { url: string; headers: Headers; payload: Record<string, unknown>; verified: boolean } {
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const headers = new Headers(init.headers);
    const bytes = Buffer.from(headers.get("X-AWEB-Signed-Payload") || "", "base64url");
    const [scheme, signer, signature] = (headers.get("Authorization") || "").split(" ");
    expect([scheme, signer]).toEqual(["DIDKey", did]);
    return {
      url, headers,
      payload: JSON.parse(bytes.toString("utf8")),
      verified: ed.verify(Buffer.from(signature, "base64"), bytes, ed.getPublicKey(signingKey)),
    };
  }
  const sha256 = (text: string) => createHash("sha256").update(text, "utf8").digest("hex");

  test("a team route is signed for its method, path, body and team", async () => {
    await new APIClient("https://app.example/api", auth).post("/v1/tasks?dry_run=true", { title: "x" });
    const request = sent();
    expect(request.verified).toBe(true);
    expect(request.payload).toEqual({
      aud: "https://app.example", body_sha256: sha256('{"title":"x"}'), method: "POST",
      path: "/api/v1/tasks?dry_run=true", team_id: "backend:acme.com",
      timestamp: request.headers.get("X-AWEB-Timestamp"), v: 2,
    });
    expect(request.headers.get("X-AWID-Team-Certificate")).toBe("cert-header");
    expect(request.headers.get("X-AWEB-DID-AW")).toBeNull();
  });

  test.each(["/v1/messages/inbox?unread_only=true", "/v1/chat/pending"])("%s is signed as the identity", async (path) => {
    await new APIClient("https://app.example", auth).get(path);
    const request = sent();
    expect(request.verified).toBe(true);
    expect(request.payload).toEqual({
      aud: "https://app.example", body_sha256: sha256(""), method: "GET", path,
      did_aw: "did:aw:test", timestamp: request.headers.get("X-AWEB-Timestamp"), v: 2,
    });
    expect(request.headers.get("X-AWEB-DID-AW")).toBe("did:aw:test");
    expect(request.headers.get("X-AWID-Team-Certificate")).toBeNull();
  });

  test("a local identity signs an empty did_aw and sends no stable identity header", async () => {
    await new APIClient("https://app.example", { ...auth, stableID: "" }).get("/v1/messages/inbox");
    const request = sent();
    expect(request.verified).toBe(true);
    expect(request.payload.did_aw).toBe("");
    expect(request.headers.get("X-AWEB-DID-AW")).toBeNull();
  });

  test("the event stream is signed for its own path", async () => {
    fetchMock.mockImplementation(async () => new Response("", { status: 200 }));
    await new APIClient("https://app.example", auth).openSSE("/v1/events/stream?deadline=2026-01-01T00%3A00%3A00Z");
    const request = sent();
    expect(request.verified).toBe(true);
    expect(request.payload).toMatchObject({ method: "GET", path: "/v1/events/stream?deadline=2026-01-01T00%3A00%3A00Z", team_id: "backend:acme.com", v: 2 });
  });
});
