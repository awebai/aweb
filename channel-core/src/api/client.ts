import { createHash } from "node:crypto";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
import { readBoundedJSON, readSafeErrorExcerpt } from "./response.js";
import { canonicalJSONValue } from "../identity/canonical.js";
import { computeDIDKey } from "../identity/did.js";

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

function canonicalTimestamp(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

interface SignedTarget {
  aud: string;
  method: string;
  path: string;
  body_sha256: string;
}

/** The request a signature is bound to: the origin and full path, with query, that the client sends. */
function signedTarget(baseURL: string, path: string, method: string, bodyText: string): SignedTarget {
  const url = new URL(baseURL + path);
  return {
    aud: `${url.protocol}//${url.host}`,
    method: method.toUpperCase(),
    path: `${url.pathname}${url.search}` || "/",
    body_sha256: createHash("sha256").update(bodyText, "utf-8").digest("hex"),
  };
}

function signCanonical(payload: Record<string, string | number>, signingKey: Uint8Array): { did: string; signature: string; canonicalPayload: string; signedPayload: string } {
  const canonicalPayload = canonicalJSONValue(payload, "unsupported request signing value");
  return {
    did: computeDIDKey(ed.getPublicKey(signingKey)),
    signature: Buffer.from(ed.sign(new TextEncoder().encode(canonicalPayload), signingKey)).toString("base64").replace(/=+$/, ""),
    canonicalPayload,
    signedPayload: Buffer.from(canonicalPayload, "utf-8").toString("base64url"),
  };
}

/**
 * Sign one request with the v2 request envelope (docs/team-auth-envelope-v2.md).
 * A certificate request binds `team_id`; an identity request binds `did_aw`,
 * the empty string for a local identity.
 */
export function signRequestHeaders(options: { baseURL: string; path: string; method: string; bodyText?: string; signingKey: Uint8Array; claim: "team_id" | "did_aw"; value: string; timestamp: string }): Record<string, string> & { canonicalPayload: string } {
  const target = signedTarget(options.baseURL, options.path, options.method, options.bodyText || "");
  const signed = signCanonical({ v: 2, ...target, [options.claim]: options.value, timestamp: options.timestamp }, options.signingKey);
  return {
    Authorization: `DIDKey ${signed.did} ${signed.signature}`,
    "X-AWEB-Timestamp": options.timestamp,
    "X-AWEB-Signed-Payload": signed.signedPayload,
    canonicalPayload: signed.canonicalPayload,
  };
}

export function signIdentityGrantHeaders(options: { baseURL: string; path: string; method: string; bodyText?: string; signingKey: Uint8Array; grantID: string; timestamp: string }): Record<string, string> & { canonicalPayload: string; bodySHA256: string } {
  const target = signedTarget(options.baseURL, options.path, options.method, options.bodyText || "");
  const signed = signCanonical({ v: 1, auth: "identity-grant", ...target, grant_id: options.grantID, timestamp: options.timestamp }, options.signingKey);
  return {
    Authorization: `AWEB-Grant DIDKey ${signed.did} ${signed.signature}`,
    "X-AWEB-Grant-ID": options.grantID,
    "X-AWEB-Timestamp": options.timestamp,
    "X-AWEB-Signed-Payload": signed.signedPayload,
    canonicalPayload: signed.canonicalPayload,
    bodySHA256: target.body_sha256,
  };
}

export interface APIClientAuth {
  did: string;
  stableID: string;
  signingKey: Uint8Array;
  teamID: string;
  teamCertificateHeader: string;
  authMode?: "team" | "grant";
  grantID?: string;
}

export class APIClient {
  constructor(
    private baseURL: string,
    private auth: APIClientAuth,
  ) {}

  hasTeamCertificateAuth(teamID: string): boolean {
    return this.auth.teamID === teamID
      && this.auth.teamCertificateHeader.trim() !== ""
      && this.auth.did.trim() !== ""
      && this.auth.signingKey.length > 0;
  }

  // Credential availability only. The service still enforces grant validity,
  // scope and membership for the same authenticated /v1/agents read.
  hasTeamRosterAuth(teamID: string): boolean {
    if (this.auth.authMode !== "grant") return this.hasTeamCertificateAuth(teamID);
    return this.auth.teamID === teamID
      && (this.auth.grantID || "").trim() !== ""
      && this.auth.did.trim() !== ""
      && this.auth.signingKey.length === 32;
  }

  async get<T>(path: string): Promise<T> {
    return this.request("GET", path);
  }

  async getFresh<T>(path: string): Promise<T> {
    return this.request("GET", path, undefined, true);
  }

  async post<T>(path: string, body?: unknown, signal?: AbortSignal): Promise<T> {
    return this.request("POST", path, body, false, signal);
  }

  /** POST to a route that answers without a body, such as a 202. */
  async postAccepted(path: string, body: unknown): Promise<void> {
    const resp = await this.send("POST", path, body);
    await resp.body?.cancel();
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
    noCache: boolean = false,
    signal?: AbortSignal,
  ): Promise<T> {
    return readBoundedJSON<T>(await this.send(method, path, body, noCache, signal));
  }

  private async send(
    method: string,
    path: string,
    body?: unknown,
    noCache: boolean = false,
    signal?: AbortSignal,
  ): Promise<Response> {
    const url = this.baseURL + path;
    const bodyText = body === undefined ? "" : JSON.stringify(body);
    const headers: Record<string, string> = {
      Accept: "application/json",
      ...this.authHeaders(method, path, bodyText),
    };
    if (noCache) headers["Cache-Control"] = "no-cache";
    const init: RequestInit = {
      method,
      headers,
      redirect: "error",
      signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(30_000)]) : AbortSignal.timeout(30_000),
    };

    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      init.body = bodyText;
    }

    const resp = await fetch(url, init);
    if (!resp.ok) {
      const text = await readSafeErrorExcerpt(resp).catch(() => "");
      throw new APIError(resp.status, text, retryAfterSeconds(resp.headers.get("Retry-After")));
    }

    return resp;
  }

  /** Open an SSE stream. Returns the raw Response for streaming. */
  async openSSE(path: string, signal?: AbortSignal): Promise<Response> {
    const url = this.baseURL + path;
    const resp = await fetch(url, {
      signal,
      redirect: "error",
      headers: {
        Accept: "text/event-stream",
        "Cache-Control": "no-cache",
        ...this.authHeaders("GET", path, ""),
      },
    });

    if (!resp.ok) {
      const text = await readSafeErrorExcerpt(resp).catch(() => "");
      throw new APIError(resp.status, text);
    }

    return resp;
  }

  private authHeaders(method: string, path: string, bodyText: string): Record<string, string> {
    if (this.auth.authMode === "grant") {
      return this.grantAuthHeaders(method, path, bodyText);
    }
    return this.usesIdentityMessagingAuth(path)
      ? this.identityAuthHeaders(method, path, bodyText)
      : this.teamAuthHeaders(method, path, bodyText);
  }

  private usesIdentityMessagingAuth(path: string): boolean {
    const cleanPath = path.split("?", 1)[0] ?? path;
    return cleanPath === "/v1/messages"
      || cleanPath.startsWith("/v1/messages/")
      || cleanPath.startsWith("/v1/chat");
  }

  private grantAuthHeaders(method: string, path: string, bodyText: string): Record<string, string> {
    const grantID = (this.auth.grantID || "").trim();
    if (!grantID) throw new Error("grant_id is required for grant authentication");
    const signed = signIdentityGrantHeaders({ baseURL: this.baseURL, path, method, bodyText, signingKey: this.auth.signingKey, grantID, timestamp: canonicalTimestamp() });
    return {
      Authorization: signed.Authorization,
      "X-AWEB-Grant-ID": signed["X-AWEB-Grant-ID"],
      "X-AWEB-Timestamp": signed["X-AWEB-Timestamp"],
      "X-AWEB-Signed-Payload": signed["X-AWEB-Signed-Payload"],
    };
  }

  private rootAuthHeaders(method: string, path: string, bodyText: string, claim: "team_id" | "did_aw", value: string): Record<string, string> {
    const signed = signRequestHeaders({ baseURL: this.baseURL, path, method, bodyText, signingKey: this.auth.signingKey, claim, value, timestamp: canonicalTimestamp() });
    return {
      Authorization: signed.Authorization,
      "X-AWEB-Timestamp": signed["X-AWEB-Timestamp"],
      "X-AWEB-Signed-Payload": signed["X-AWEB-Signed-Payload"],
    };
  }

  private identityAuthHeaders(method: string, path: string, bodyText: string): Record<string, string> {
    const stableID = this.auth.stableID.trim();
    const headers = this.rootAuthHeaders(method, path, bodyText, "did_aw", stableID);
    if (stableID) headers["X-AWEB-DID-AW"] = stableID;
    return headers;
  }

  private teamAuthHeaders(method: string, path: string, bodyText: string): Record<string, string> {
    return {
      ...this.rootAuthHeaders(method, path, bodyText, "team_id", this.auth.teamID),
      "X-AWID-Team-Certificate": this.auth.teamCertificateHeader,
    };
  }
}

export class APIError extends Error {
  constructor(
    public statusCode: number,
    public body: string,
    /** A Retry-After given as whole seconds; absent when missing or another form. */
    public retryAfterSeconds?: number,
  ) {
    super(body ? `aweb: http ${statusCode}: ${body}` : `aweb: http ${statusCode}`);
  }
}

function retryAfterSeconds(header: string | null): number | undefined {
  return header !== null && /^\d+$/.test(header.trim()) ? Number(header.trim()) : undefined;
}
