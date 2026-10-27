// Identity certificates v1 (docs/id-certificates.md): parent-signed human and
// agent certificates and the bounded id chain that presents them. Everything
// here is pure: no DNS, HTTP or cache access.
import * as ed from "@noble/ed25519";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import bs58 from "bs58";
import { canonicalJSONValue } from "./canonical.js";
import { computeDIDKey, extractPublicKey } from "./did.js";
import { parseStrictJSON, StrictJSONError } from "./strict_json.js";

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

export const ID_CERTIFICATE_PREFIX = "aweb.id-certificate/1\n";
export const ID_CHAIN_MAX_CERTIFICATES = 8;
export const ID_CHAIN_MAX_DECODED_BYTES = 6144;
export const ID_CHAIN_MAX_HEADER_BYTES = 8192;

export type IdKind = "human" | "agent";

export interface IdCertificate {
  v: 1;
  type: "aweb.id-certificate";
  id: string;
  domain: string;
  parent: { kind: "namespace" | "identity"; id: string };
  kind: IdKind;
  issuer_key: string;
  issued_at: string;
}

export interface SignedIdCertificate {
  certificate: IdCertificate;
  signature: string;
}

export interface IdChain {
  v: 1;
  type: "aweb.id-chain";
  certificates: SignedIdCertificate[];
}

/** Refusal codes a strict decode of a certificate or chain can produce. */
export type IdDecodeRefusal =
  | "bundle_too_large"
  | "invalid_encoding"
  | "invalid_json"
  | "noncanonical_json"
  | "invalid_shape"
  | "invalid_domain"
  | "invalid_kind"
  | "domain_mismatch"
  | "depth_exceeded"
  | "invalid_signature";

export type IdDecodeResult<T> = { ok: true; value: T } | { ok: false; reason: IdDecodeRefusal };

const refuse = (reason: IdDecodeRefusal): { ok: false; reason: IdDecodeRefusal } => ({ ok: false, reason });

export function idCertificateSigningBytes(certificate: IdCertificate): Uint8Array {
  return new TextEncoder().encode(ID_CERTIFICATE_PREFIX + canonicalJSONValue(certificate, "id certificate is not canonical JSON"));
}

export function idCertificateId(certificate: IdCertificate): string {
  return "sha256:" + Buffer.from(sha256(idCertificateSigningBytes(certificate))).toString("hex");
}

export function encodeIdChainHeader(chain: IdChain): string {
  return Buffer.from(canonicalJSONValue(chain, "id chain is not canonical JSON"), "utf8").toString("base64url");
}

/** Decode the X-AWID-ID-Chain header: size, encoding, then decodeIdChain. */
export function decodeIdChainHeader(header: string): IdDecodeResult<IdChain> {
  if (header.length > ID_CHAIN_MAX_HEADER_BYTES) return refuse("bundle_too_large");
  const bytes = decodeBase64URL(header);
  if (!bytes) return refuse("invalid_encoding");
  return decodeIdChain(bytes);
}

/**
 * Decode canonical id-chain JSON bytes. Size and depth are checked before any
 * cryptography, every certificate's shape before any signature, and each
 * signature against its own issuer_key. Whether that key had authority, and
 * how the links relate, is verifyIdChain's question.
 */
export function decodeIdChain(bytes: Uint8Array): IdDecodeResult<IdChain> {
  if (bytes.length > ID_CHAIN_MAX_DECODED_BYTES) return refuse("bundle_too_large");
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return refuse("invalid_json");
  }
  let value: unknown;
  try {
    // bundle > certificates > signed > certificate > parent
    value = parseStrictJSON(text, 5);
  } catch (error) {
    if (error instanceof StrictJSONError && error.failure !== "syntax") return refuse("invalid_shape");
    return refuse("invalid_json");
  }
  if (canonicalJSONValue(value, "unreachable: strict JSON is canonicalizable") !== text) return refuse("noncanonical_json");
  if (!isRecord(value) || !hasExactKeys(value, ["certificates", "type", "v"])) return refuse("invalid_shape");
  if (value.v !== 1 || value.type !== "aweb.id-chain" || !Array.isArray(value.certificates)) return refuse("invalid_shape");
  if (value.certificates.length === 0) return refuse("invalid_shape");
  if (value.certificates.length > ID_CHAIN_MAX_CERTIFICATES) return refuse("depth_exceeded");
  for (const signed of value.certificates) {
    const reason = signedShapeRefusal(signed);
    if (reason) return refuse(reason);
  }
  for (const signed of value.certificates as SignedIdCertificate[]) {
    const reason = signatureRefusal(signed);
    if (reason) return refuse(reason);
  }
  return { ok: true, value: value as unknown as IdChain };
}

/** Strictly check one signed certificate's shape, then its signature against its issuer_key. */
export function parseSignedIdCertificate(signed: unknown): IdDecodeResult<SignedIdCertificate> {
  const reason = signedShapeRefusal(signed) ?? signatureRefusal(signed as SignedIdCertificate);
  return reason ? refuse(reason) : { ok: true, value: signed as SignedIdCertificate };
}

function signedShapeRefusal(signed: unknown): IdDecodeRefusal | undefined {
  if (!isRecord(signed) || !hasExactKeys(signed, ["certificate", "signature"])) return "invalid_shape";
  if (typeof signed.signature !== "string") return "invalid_shape";
  return certificateShapeRefusal(signed.certificate);
}

function certificateShapeRefusal(certificate: unknown): IdDecodeRefusal | undefined {
  const fields = ["domain", "id", "issued_at", "issuer_key", "kind", "parent", "type", "v"];
  if (!isRecord(certificate) || !hasExactKeys(certificate, fields)) return "invalid_shape";
  const { v, type, id, domain, parent, kind, issuer_key, issued_at } = certificate;
  if (v !== 1 || type !== "aweb.id-certificate") return "invalid_shape";
  if (typeof domain !== "string" || typeof kind !== "string") return "invalid_shape";
  if (!isCanonicalDomain(domain)) return "invalid_domain";
  if (kind !== "human" && kind !== "agent") return "invalid_kind";
  if (typeof id !== "string" || !isCanonicalIdentityId(id)) return "invalid_shape";
  // A human always has a registered did:aw; a did:key human is malformed.
  if (kind === "human" && !id.startsWith("did:aw:")) return "invalid_shape";
  if (typeof issuer_key !== "string" || !isCanonicalDidKey(issuer_key)) return "invalid_shape";
  if (typeof issued_at !== "string" || !isCanonicalSecondTimestamp(issued_at)) return "invalid_shape";
  if (!isRecord(parent) || !hasExactKeys(parent, ["id", "kind"]) || typeof parent.id !== "string") return "invalid_shape";
  if (parent.kind === "namespace") {
    // A namespace parent names this certificate's own domain; another domain
    // would be a cross-domain parent link (R3).
    if (parent.id !== domain) return "domain_mismatch";
  } else if (parent.kind === "identity") {
    if (!isCanonicalIdentityId(parent.id)) return "invalid_shape";
  } else {
    return "invalid_shape";
  }
  return undefined;
}

function signatureRefusal(signed: SignedIdCertificate): IdDecodeRefusal | undefined {
  const signature = decodeBase64URL(signed.signature);
  if (!signature || signature.length !== 64) return "invalid_encoding";
  try {
    const valid = ed.verify(
      signature,
      idCertificateSigningBytes(signed.certificate),
      extractPublicKey(signed.certificate.issuer_key),
      { zip215: false },
    );
    return valid ? undefined : "invalid_signature";
  } catch {
    return "invalid_signature";
  }
}

const BASE64URL = /^[A-Za-z0-9_-]*$/;

/** Strict unpadded base64url: no padding, no other alphabet, no nonzero unused bits. */
function decodeBase64URL(value: string): Uint8Array | undefined {
  if (!BASE64URL.test(value) || value.length % 4 === 1) return undefined;
  const bytes = Buffer.from(value, "base64url");
  if (bytes.toString("base64url") !== value) return undefined;
  return new Uint8Array(bytes);
}

const DOMAIN_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

export function isCanonicalDomain(domain: string): boolean {
  return domain.length > 0 && domain.length <= 253 && domain.split(".").every(label => DOMAIN_LABEL.test(label));
}

export function isCanonicalDidKey(value: string): boolean {
  try {
    return computeDIDKey(extractPublicKey(value)) === value;
  } catch {
    return false;
  }
}

export function isCanonicalDidAw(value: string): boolean {
  if (!value.startsWith("did:aw:")) return false;
  try {
    const suffix = value.slice("did:aw:".length);
    const decoded = bs58.decode(suffix);
    return decoded.length === 20 && bs58.encode(decoded) === suffix;
  } catch {
    return false;
  }
}

function isCanonicalIdentityId(value: string): boolean {
  return isCanonicalDidAw(value) || isCanonicalDidKey(value);
}

const SECOND_TIMESTAMP = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z$/;

function isCanonicalSecondTimestamp(value: string): boolean {
  const match = SECOND_TIMESTAMP.exec(value);
  if (!match) return false;
  const [year, month, day, hour, minute, second] = match.slice(1).map(Number);
  // setUTCFullYear, unlike Date.UTC, does not map years 0-99 to 1900-1999.
  const date = new Date(0);
  date.setUTCFullYear(year, month - 1, day);
  date.setUTCHours(hour, minute, second, 0);
  return (
    year >= 1 &&
    date.getUTCFullYear() === year &&
    date.getUTCMonth() === month - 1 &&
    date.getUTCDate() === day &&
    date.getUTCHours() === hour &&
    date.getUTCMinutes() === minute &&
    date.getUTCSeconds() === second
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, keys: string[]): boolean {
  const actual = Object.keys(value).sort();
  return actual.length === keys.length && actual.every((key, index) => key === keys[index]);
}
