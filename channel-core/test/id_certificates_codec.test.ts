import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";
import {
  decodeIdChain,
  decodeIdChainHeader,
  encodeIdChainHeader,
  idCertificateId,
  idCertificateSigningBytes,
  idEd25519Verify,
  parseSignedIdCertificate,
  type SignedIdCertificate,
} from "../src/identity/id_certificates.js";

const vector = JSON.parse(readFileSync(new URL("../../docs/vectors/id-certificates-v1.json", import.meta.url), "utf8"));

const utf8 = (text: string) => new TextEncoder().encode(text);
const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString("hex");
const base64url = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");

// Certificates that are signed correctly but must refuse at shape validation,
// keyed to the verification case that names the same refusal.
const SHAPE_REFUSALS: Record<string, string> = {
  "did-key-human": "invalid_shape", // did-key-human-shape-refuses
  "wrong-kind": "invalid_kind", // invalid-kind-refuses
  "readable-email-field": "invalid_shape", // unknown-field-refuses
  "noncanonical-domain": "invalid_domain", // noncanonical-domain-refuses
  "namespace-parent-domain-human": "domain_mismatch", // namespace-parent-domain-human
  "namespace-parent-domain-agent": "domain_mismatch", // namespace-parent-domain-agent
};

describe("id certificate bytes", () => {
  const certificates = Object.entries(vector.certificates) as [string, any][];

  test("the fixture has the certificates this suite was written against", () => {
    expect(certificates).toHaveLength(35);
  });

  test.each(certificates)("%s: signing bytes and certificate id", (_name, entry) => {
    const bytes = idCertificateSigningBytes(entry.signed.certificate);
    expect(hex(bytes)).toBe(entry.signing_bytes_hex);
    expect(new TextDecoder().decode(bytes)).toBe(vector.prefix_utf8 + entry.canonical_utf8);
    expect(idCertificateId(entry.signed.certificate)).toBe(entry.certificate_id);
  });

  test.each(certificates)("%s: shape and signature against its issuer_key", (name, entry) => {
    const parsed = parseSignedIdCertificate(entry.signed);
    if (name in SHAPE_REFUSALS) {
      expect(parsed).toEqual({ ok: false, reason: SHAPE_REFUSALS[name] });
    } else {
      expect(parsed).toEqual({ ok: true, value: entry.signed });
    }
  });
});

describe("id chain presentation", () => {
  const { bundle, header, canonical_utf8 } = vector.presentation;

  test("the header decodes to the frozen bundle", () => {
    expect(decodeIdChainHeader(header)).toEqual({ ok: true, value: bundle });
  });

  test("the bundle encodes to the frozen header and canonical bytes", () => {
    expect(encodeIdChainHeader(bundle)).toBe(header);
    expect(Buffer.from(header, "base64url").toString("utf8")).toBe(canonical_utf8);
    expect(decodeIdChain(utf8(canonical_utf8))).toEqual({ ok: true, value: bundle });
  });
});

describe("id chain raw wire refusals", () => {
  const cases = vector.raw_wire_refusals as any[];

  test("the fixture has the refusals this suite was written against", () => {
    expect(cases).toHaveLength(36);
    expect(new Set(cases.map(c => c.name)).size).toBe(36);
  });

  const accepted = (c: any): string[] => c.allowed_reasons ?? [c.expected_reason];

  test.each(cases)("$name", (c) => {
    const results = [];
    if (c.raw_utf8 !== undefined) {
      results.push(decodeIdChain(utf8(c.raw_utf8)));
      results.push(decodeIdChainHeader(base64url(utf8(c.raw_utf8))));
    }
    if (c.header !== undefined) results.push(decodeIdChainHeader(c.header));
    if (c.header_repeat !== undefined) {
      results.push(decodeIdChainHeader(c.header_repeat.character.repeat(c.header_repeat.count)));
    }
    if (c.decoded_repeat !== undefined) {
      const raw = c.decoded_repeat.character.repeat(c.decoded_repeat.count);
      results.push(decodeIdChain(utf8(raw)));
      results.push(decodeIdChainHeader(base64url(utf8(raw))));
    }
    expect(results.length).toBeGreaterThan(0);
    for (const result of results) {
      expect(result.ok).toBe(false);
      expect(accepted(c)).toContain((result as { reason: string }).reason);
    }
  });
});

// Boundaries chosen independently of the fixture: each refused input sits next
// to the nearest value that must still pass.
describe("id chain primitive boundaries", () => {
  const { bundle, canonical_utf8 } = vector.presentation;
  const alice = vector.certificates.alice.signed as SignedIdCertificate;

  const withCertificate = (patch: Record<string, unknown>) => ({
    ...alice,
    certificate: { ...alice.certificate, ...patch },
  });

  test("nine certificates refuse as depth_exceeded before crypto", () => {
    const canonical = (certificates: SignedIdCertificate[]) =>
      Buffer.from(encodeIdChainHeader({ ...bundle, certificates }), "base64url");
    // Eight copies pass the count check and are refused later, as a chain question.
    expect(decodeIdChain(canonical(Array(8).fill(alice))).ok).toBe(true);
    expect(decodeIdChain(canonical(Array(9).fill(alice)))).toEqual({ ok: false, reason: "depth_exceeded" });
  });

  test("decoded size 6144 is admitted to parsing, 6145 is not", () => {
    // Both are whitespace, so the admitted one fails later, at JSON, not at size.
    expect(decodeIdChain(utf8(" ".repeat(6144)))).toEqual({ ok: false, reason: "invalid_json" });
    expect(decodeIdChain(utf8(" ".repeat(6145)))).toEqual({ ok: false, reason: "bundle_too_large" });
  });

  test("an encoded header of 8192 bytes is admitted to decoding, 8193 is not", () => {
    expect(decodeIdChainHeader("A".repeat(8192))).not.toEqual({ ok: false, reason: "bundle_too_large" });
    expect(decodeIdChainHeader("A".repeat(8193))).toEqual({ ok: false, reason: "bundle_too_large" });
  });

  test("base64url with nonzero unused bits, padding or the standard alphabet refuses", () => {
    // 64 signature bytes encode to 86 characters, leaving 4 unused bits.
    expect(alice.signature).toHaveLength(86);
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const last = alice.signature.at(-1)!;
    const bumped = alice.signature.slice(0, -1) + alphabet[alphabet.indexOf(last) + 1];
    expect(Buffer.from(bumped, "base64url")).toEqual(Buffer.from(alice.signature, "base64url"));
    expect(parseSignedIdCertificate({ ...alice, signature: bumped })).toEqual({ ok: false, reason: "invalid_encoding" });

    expect(alice.signature).toContain("_");
    expect(parseSignedIdCertificate({ ...alice, signature: alice.signature.replaceAll("_", "/") })).toEqual({
      ok: false,
      reason: "invalid_encoding",
    });

    const header = base64url(utf8(canonical_utf8));
    expect(decodeIdChainHeader(header).ok).toBe(true);
    expect(decodeIdChainHeader("+" + header.slice(1))).toEqual({ ok: false, reason: "invalid_encoding" });
  });

  test("lone surrogate escapes and invalid UTF-8 refuse as invalid JSON", () => {
    expect(decodeIdChain(utf8('{"v":1,"type":"\\ud800","certificates":[]}'))).toEqual({
      ok: false,
      reason: "invalid_json",
    });
    expect(decodeIdChain(new Uint8Array([0x7b, 0xff, 0x7d]))).toEqual({ ok: false, reason: "invalid_json" });
  });

  test("an exponent is not an integer", () => {
    const raw = canonical_utf8.replace('"v":1}', '"v":1e0}');
    expect(raw).not.toBe(canonical_utf8);
    expect(decodeIdChain(utf8(raw))).toEqual({ ok: false, reason: "invalid_shape" });
  });

  test("issued_at accepts only ASCII digits of a real UTC second", () => {
    expect(parseSignedIdCertificate(alice).ok).toBe(true);
    for (const issued_at of ["２026-10-26T00:00:00Z", "2026-10-26T00:00:00.0Z", "2026-02-30T00:00:00Z", "2026-10-26T00:00:00+00:00"]) {
      expect(parseSignedIdCertificate(withCertificate({ issued_at }))).toEqual({ ok: false, reason: "invalid_shape" });
    }
  });

  test("domain canonical form: lowercase A-labels, no trailing dot, labels of 1-63", () => {
    expect(parseSignedIdCertificate(withCertificate({ domain: "Example.com" }))).toEqual({ ok: false, reason: "invalid_domain" });
    expect(parseSignedIdCertificate(withCertificate({ domain: "example.com." }))).toEqual({ ok: false, reason: "invalid_domain" });
    expect(parseSignedIdCertificate(withCertificate({ domain: `${"a".repeat(64)}.com` }))).toEqual({ ok: false, reason: "invalid_domain" });
    expect(parseSignedIdCertificate(withCertificate({ domain: "-a.com" }))).toEqual({ ok: false, reason: "invalid_domain" });
  });
});

// The ID-certificate acceptance rule: canonical, nonidentity prime-subgroup A
// and R, S < L, and the cofactorless equation. Mandatory in every CI.
describe("id certificate Ed25519 acceptance", () => {
  const { mode, cases } = vector.ed25519_verification;
  const bytes = (hexText: string) => Uint8Array.from(Buffer.from(hexText, "hex"));

  test("the fixture pins the mode and the cases this suite was written against", () => {
    expect(mode).toBe("canonical-nonidentity-prime-subgroup-cofactorless");
    expect(cases).toHaveLength(19);
  });

  test.each(cases as any[])("$name", c => {
    expect(idEd25519Verify(bytes(c.public_key_hex), bytes(c.message_hex), bytes(c.signature_hex))).toEqual(c.expected);
  });
});
