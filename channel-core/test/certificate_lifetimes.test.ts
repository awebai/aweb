import { describe, expect, it } from "vitest";
import * as ed from "@noble/ed25519";
import { computeDIDKey } from "../src/identity/did.js";
import { canonicalJSONValue } from "../src/identity/canonical.js";
import { signBytes } from "../src/identity/signing.js";
import { encodeTeamCertificateHeader, verifyTeamCertificate, type TeamCertificate } from "../src/identity/certificate.js";

const seed = new Uint8Array(32).fill(17);
const did = computeDIDKey(ed.getPublicKey(seed));
const issued = "2026-01-01T00:00:00Z";
const deadline = "2026-02-01T00:00:00Z";
function certificate(fields: Partial<TeamCertificate> = {}): TeamCertificate {
  const payload = { version: 2, certificate_id: "finite", team_id: "ops:example.test",
    team_did_key: did, member_did_key: did, alias: "alice", identity_scope: "local" as const,
    validity_class: "member" as const, issued_at: issued, ...fields };
  if (payload.validity_class === undefined) delete payload.validity_class;
  return { ...payload, signature: signBytes(seed, new TextEncoder().encode(canonicalJSONValue(payload, "invalid"))) };
}

describe("signed optional certificate expiry", () => {
  it("keeps no-expiry certificates valid and preserves the signed v2 wire", async () => {
    for (const cert of [certificate(), certificate({ version: 1, validity_class: undefined })]) {
      // v1 omits the v2 class entirely.
      if (cert.validity_class === undefined) {
        delete cert.validity_class;
        const { signature, ...payload } = cert;
        cert.signature = signBytes(seed, new TextEncoder().encode(canonicalJSONValue(payload, "invalid")));
      }
      await expect(verifyTeamCertificate(cert, did)).resolves.toBeUndefined();
      const transported = JSON.parse(Buffer.from(encodeTeamCertificateHeader(cert), "base64").toString());
      await expect(verifyTeamCertificate(transported, did)).resolves.toBeUndefined();
    }
  });
  it("refuses exactly at expiry, without grace", async () => {
    const cert = certificate({ expires_at: deadline });
    await expect(verifyTeamCertificate(cert, did, Date.parse(deadline) - 1)).resolves.toBeUndefined();
    await expect(verifyTeamCertificate(cert, did, Date.parse(deadline))).rejects.toMatchObject({ code: "certificate_expired" });
  });
  it("authenticates expiry before trusting its value", async () => {
    const cert = certificate({ expires_at: deadline });
    cert.expires_at = "2099-01-01T00:00:00Z";
    await expect(verifyTeamCertificate(cert, did)).rejects.toThrow("signature");
  });
  it.each(["not-a-time", "2026-02-30T00:00:00Z", "2026-02-01T00:00:00", null])("refuses malformed signed expiry %s", async expires_at => {
    const cert = certificate({ expires_at: expires_at as string });
    await expect(verifyTeamCertificate(cert, did)).rejects.toMatchObject({ code: "certificate_malformed" });
  });
});

it("verifies the shared Python/Go/TypeScript signed v2 vectors", async () => {
  const { readFileSync } = await import("node:fs");
  const vectors = JSON.parse(readFileSync(new URL("../../docs/vectors/certificate-lifetimes-v2.json", import.meta.url), "utf8"));
  for (const { certificate, canonical, expected } of vectors.certificates) {
    const { signature, ...payload } = certificate;
    expect(canonicalJSONValue(payload, "invalid")).toBe(canonical);
    if (expected === 'valid') {
      await expect(verifyTeamCertificate(certificate, vectors.team_did_key, Date.parse(vectors.now))).resolves.toBeUndefined();
    } else if (expected === 'signature_invalid') {
      await expect(verifyTeamCertificate(certificate, vectors.team_did_key, Date.parse(vectors.now))).rejects.toThrow('signature');
    } else {
      await expect(verifyTeamCertificate(certificate, vectors.team_did_key, Date.parse(vectors.now))).rejects.toMatchObject({ code: expected });
    }
  }
});
