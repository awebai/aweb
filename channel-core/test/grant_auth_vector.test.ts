import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, test } from "vitest";
import { signIdentityGrantHeaders } from "../src/index.js";

interface Vector {
  seed_hex: string;
  method: string;
  url: string;
  grant_id: string;
  body: string;
  timestamp: string;
  did_key: string;
  body_sha256: string;
  canonical_payload: string;
  authorization: string;
  x_aweb_grant_id: string;
  x_aweb_timestamp: string;
  x_aweb_signed_payload: string;
}

describe("identity grant auth conformance", () => {
  test("matches the Go-generated header vector byte-for-byte", () => {
    const vector = JSON.parse(readFileSync(join(import.meta.dirname, "..", "..", "test-vectors", "identity-grant-auth-v1.json"), "utf8")) as Vector;
    const url = new URL(vector.url);
    const signed = signIdentityGrantHeaders({
      baseURL: `${url.protocol}//${url.host}`,
      path: `${url.pathname}${url.search}`,
      method: vector.method,
      bodyText: vector.body,
      signingKey: Buffer.from(vector.seed_hex, "hex"),
      grantID: vector.grant_id,
      timestamp: vector.timestamp,
    });
    expect(signed.Authorization).toBe(vector.authorization);
    expect(signed["X-AWEB-Grant-ID"]).toBe(vector.x_aweb_grant_id);
    expect(signed["X-AWEB-Timestamp"]).toBe(vector.x_aweb_timestamp);
    expect(signed["X-AWEB-Signed-Payload"]).toBe(vector.x_aweb_signed_payload);
    expect(signed.canonicalPayload).toBe(vector.canonical_payload);
    expect(signed.bodySHA256).toBe(vector.body_sha256);
    expect(signed.Authorization).toContain(vector.did_key);
  });
});
