import { createHash } from "node:crypto";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
import { readBoundedJSON, readSafeErrorExcerpt } from "./response.js";
import { computeDIDKey } from "../identity/did.js";

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

function canonicalTimestamp(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

function canonicalGrantPayload(fields: Record<string, string | number>): string {
  const entries = Object.entries(fields).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0);
  return `{${entries.map(([key, value]) => `${JSON.stringify(key)}:${typeof value === "number" ? String(value) : JSON.stringify(value)}`).join(",")}}`;
}

export function signIdentityGrantHeaders(options: { baseURL: string; path: string; method: string; bodyText?: string; signingKey: Uint8Array; grantID: string; timestamp: string }): Record<string, string> & { canonicalPayload: string; bodySHA256: string } {
  const bodyText = options.bodyText || "";
  const bodyHash = createHash("sha256").update(bodyText, "utf-8").digest("hex");
  const url = new URL(options.baseURL + options.path);
  const canonicalPayload = canonicalGrantPayload({
    v: 1,
    auth: "identity-grant",
    aud: `${url.protocol}//${url.host}`,
    method: options.method.toUpperCase(),
    path: `${url.pathname}${url.search}` || "/",
    grant_id: options.grantID,
    body_sha256: bodyHash,
    timestamp: options.timestamp,
  });
  const signature = Buffer.from(ed.sign(new TextEncoder().encode(canonicalPayload), options.signingKey)).toString("base64").replace(/=+$/, "");
  return {
    Authorization: `AWEB-Grant DIDKey ${computeDIDKey(ed.getPublicKey(options.signingKey))} ${signature}`,
    "X-AWEB-Grant-ID": options.grantID,
    "X-AWEB-Timestamp": options.timestamp,
    "X-AWEB-Signed-Payload": Buffer.from(canonicalPayload, "utf-8").toString("base64url"),
    canonicalPayload,
    bodySHA256: bodyHash,
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

  async post<T>(path: string, body?: unknown): Promise<T> {
    return this.request("POST", path, body);
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
    noCache: boolean = false,
  ): Promise<T> {
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
      signal: AbortSignal.timeout(30_000),
    };

    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      init.body = bodyText;
    }

    const resp = await fetch(url, init);
    if (!resp.ok) {
      const text = await readSafeErrorExcerpt(resp).catch(() => "");
      throw new APIError(resp.status, text);
    }

    return readBoundedJSON<T>(resp);
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
    if (this.usesIdentityMessagingAuth(path)) {
      return this.identityAuthHeaders(bodyText);
    }
    return this.teamAuthHeaders(bodyText);
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

  private identityAuthHeaders(bodyText: string): Record<string, string> {
    const timestamp = canonicalTimestamp();
    const bodyHash = createHash("sha256").update(bodyText, "utf-8").digest("hex");
    const payload = `{"body_sha256":${JSON.stringify(bodyHash)},"did_aw":${JSON.stringify(this.auth.stableID)},"timestamp":${JSON.stringify(timestamp)}}`;
    const signature = Buffer.from(
      ed.sign(new TextEncoder().encode(payload), this.auth.signingKey),
    ).toString("base64").replace(/=+$/, "");
    const headers: Record<string, string> = {
      Authorization: `DIDKey ${this.auth.did} ${signature}`,
      "X-AWEB-Timestamp": timestamp,
    };
    if (this.auth.stableID.trim()) {
      headers["X-AWEB-DID-AW"] = this.auth.stableID;
    }
    return headers;
  }

  private teamAuthHeaders(bodyText: string): Record<string, string> {
    const timestamp = canonicalTimestamp();
    const bodyHash = createHash("sha256").update(bodyText, "utf-8").digest("hex");
    const payload = `{"body_sha256":${JSON.stringify(bodyHash)},"team_id":${JSON.stringify(this.auth.teamID)},"timestamp":${JSON.stringify(timestamp)}}`;
    const signature = Buffer.from(
      ed.sign(new TextEncoder().encode(payload), this.auth.signingKey),
    ).toString("base64").replace(/=+$/, "");
    return {
      Authorization: `DIDKey ${this.auth.did} ${signature}`,
      "X-AWEB-Timestamp": timestamp,
      "X-AWID-Team-Certificate": this.auth.teamCertificateHeader,
    };
  }
}

export class APIError extends Error {
  constructor(
    public statusCode: number,
    public body: string,
  ) {
    super(body ? `aweb: http ${statusCode}: ${body}` : `aweb: http ${statusCode}`);
  }
}
