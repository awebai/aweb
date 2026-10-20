import { readFile, writeFile, rename, rm } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { canonicalJSONValue } from "./canonical.js";
import { verifySignedPayload } from "./signing.js";
import { signBytes } from "./signing.js";
import { readBoundedJSON } from "../api/response.js";
import { RegistryResolver } from "./registry.js";

export type CertificateIdentityScope = "global" | "local";
export type LegacyCertificateLifetime = "persistent" | "ephemeral";

export interface TeamCertificate {
  version: number;
  certificate_id: string;
  team_id: string;
  team_did_key: string;
  member_did_key: string;
  member_did_aw?: string;
  member_address?: string;
  alias: string;
  identity_scope?: CertificateIdentityScope;
  /** Legacy certificate field accepted for compatibility with existing team certs. */
  lifetime?: LegacyCertificateLifetime;
  issued_at: string;
  validity_class?: "member" | "ephemeral";
  expires_at?: string;
  signature: string;
}

export function certificateIdentityScope(cert: Pick<TeamCertificate, "identity_scope" | "lifetime">): CertificateIdentityScope {
  if (cert.identity_scope === "global" || cert.identity_scope === "local") return cert.identity_scope;
  if (cert.lifetime === "persistent") return "global";
  if (cert.lifetime === "ephemeral") return "local";
  return "local";
}

export async function loadTeamCertificate(path: string, allowExpired = false): Promise<TeamCertificate> {
  const content = await readFile(path, "utf-8");
  const cert = JSON.parse(content) as TeamCertificate;
  validateCertificateLifetime(cert, allowExpired ? Number.NEGATIVE_INFINITY : Date.now());
  return cert;
}

export function encodeTeamCertificateHeader(cert: TeamCertificate): string {
  validateCertificateLifetime(cert);
  // This transport envelope deliberately uses padded standard base64. The Go
  // header decoder must use StdEncoding so certificates emitted here round-trip.
  return Buffer.from(JSON.stringify(cert), "utf-8").toString("base64");
}

export class CertificateValidityError extends Error {
  constructor(readonly code: "certificate_malformed" | "certificate_expired", message: string) {
    super(message);
  }
}

function certificateTimestamp(value: unknown): number {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/.test(value)) {
    throw new CertificateValidityError("certificate_malformed", "Invalid certificate timestamp");
  }
  const parsed = Date.parse(value);
  const year = Number(value.slice(0, 4)), month = Number(value.slice(5, 7)), day = Number(value.slice(8, 10));
  if (!Number.isFinite(parsed) || month < 1 || month > 12 || day < 1
      || day > new Date(Date.UTC(year, month, 0)).getUTCDate()
      || Number(value.slice(11, 13)) > 23 || Number(value.slice(14, 16)) > 59 || Number(value.slice(17, 19)) > 59) {
    throw new CertificateValidityError("certificate_malformed", "Invalid certificate timestamp");
  }
  return parsed;
}

/** Signature and revocation checks remain the relying service's responsibility. */
export function validateCertificateLifetime(cert: TeamCertificate, now = Date.now()): void {
  if (!cert || (cert.version !== 1 && cert.version !== 2)) {
    throw new CertificateValidityError("certificate_malformed", "Unsupported certificate version");
  }
  if (cert.version === 1 && (Object.hasOwn(cert, "expires_at") || Object.hasOwn(cert, "validity_class"))) {
    throw new CertificateValidityError("certificate_malformed", "Lifetime fields require certificate version 2");
  }
  if (cert.version === 2) {
    if (cert.validity_class !== "member" && cert.validity_class !== "ephemeral") {
      throw new CertificateValidityError("certificate_malformed", "Invalid certificate validity_class");
    }
    certificateTimestamp(cert.issued_at);
  }
  if (!Object.hasOwn(cert, "expires_at")) return;
  const expires = certificateTimestamp(cert.expires_at);
  if (expires <= certificateTimestamp(cert.issued_at)) {
    throw new CertificateValidityError("certificate_malformed", "Certificate expiry must follow issuance");
  }
  if (expires <= now) throw new CertificateValidityError("certificate_expired", "Team certificate expired");
}

/** teamDIDKey must come from current trusted registry state, not the blob itself. */
export async function verifyTeamCertificate(cert: TeamCertificate, teamDIDKey: string, now = Date.now()): Promise<void> {
  const { signature, ...payload } = cert;
  const canonical = canonicalJSONValue(payload, "Invalid certificate payload");
  if (await verifySignedPayload(canonical, signature, teamDIDKey, "") !== "verified") {
    throw new Error("Certificate signature verification failed");
  }
  validateCertificateLifetime(cert, now);
}

export async function fetchReplacementCertificate(old: TeamCertificate, id: string, signingKey: Uint8Array, registryURL: string): Promise<{ certificate: TeamCertificate; teamDIDKey: string }> {
  const split = old.team_id.indexOf(":");
  if (split < 1) throw new Error("Invalid certificate team");
  const team = old.team_id.slice(0, split), domain = old.team_id.slice(split + 1);
  const resolver = new RegistryResolver(fetch, undefined, undefined, registryURL ? { fallbackRegistryURL: registryURL } : undefined);
  const origin = (await resolver.discoverRegistry(domain)).replace(/\/+$/, "");
  const base = `/v1/namespaces/${encodeURIComponent(domain)}/teams/${encodeURIComponent(team)}`;
  const get = async <T>(path: string, signed = false): Promise<T> => {
    const headers: Record<string, string> = { Accept: "application/json" };
    if (signed) {
      const timestamp = new Date().toISOString();
      const signature = signBytes(signingKey, new TextEncoder().encode(`${timestamp}\nGET\n${path}`));
      headers.Authorization = `DIDKey ${old.member_did_key} ${signature}`;
      headers["X-AWEB-Timestamp"] = timestamp;
    }
    const response = await fetch(origin + path, { headers, redirect: "error", signal: AbortSignal.timeout(30_000) });
    if (!response.ok) { await response.body?.cancel(); throw new Error(`Certificate registry refused (${response.status})`); }
    return readBoundedJSON<T>(response);
  };
  if (!id) {
    const member = await get<{ certificate_id: string; member_did_key: string }>(`${base}/members/${encodeURIComponent(old.alias)}`, true);
    if (member.member_did_key !== old.member_did_key || !member.certificate_id) throw new Error("Replacement member mismatch");
    id = member.certificate_id;
  }
  const status = await get<{ team_id: string; team_did_key: string; status: string }>(`${base}/certificates/${encodeURIComponent(id)}/status?include_replacement=true`);
  if (status.team_id !== old.team_id || status.status !== "active") throw new Error("Replacement certificate inactive");
  const artifact = await get<{ certificate: string }>(`${base}/certificates/${encodeURIComponent(id)}`, true);
  const cert = JSON.parse(Buffer.from(artifact.certificate, "base64").toString("utf8")) as TeamCertificate;
  if (cert.certificate_id !== id || cert.team_id !== old.team_id || cert.member_did_key !== old.member_did_key
      || cert.alias !== old.alias || certificateIdentityScope(cert) !== certificateIdentityScope(old)
      || (cert.member_did_aw || "") !== (old.member_did_aw || "") || (cert.member_address || "") !== (old.member_address || "")
      || cert.team_did_key !== status.team_did_key) throw new Error("Replacement certificate binding mismatch");
  await verifyTeamCertificate(cert, status.team_did_key);
  return { certificate: cert, teamDIDKey: status.team_did_key };
}

export async function installTeamCertificate(path: string, cert: TeamCertificate): Promise<void> {
  const temporary = `${path}.refresh-${randomUUID()}`;
  try {
    await writeFile(temporary, JSON.stringify(cert) + "\n", { mode: 0o600, flag: "wx" });
    await rename(temporary, path);
  } finally {
    await rm(temporary, { force: true });
  }
}
