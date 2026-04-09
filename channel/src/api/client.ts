import { createHash } from "node:crypto";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

export interface APIClientAuth {
  did: string;
  signingKey: Uint8Array;
  teamAddress: string;
  teamCertificateHeader: string;
}

export class APIClient {
  constructor(
    private baseURL: string,
    private auth: APIClientAuth,
  ) {}

  async get<T>(path: string): Promise<T> {
    return this.request("GET", path);
  }

  async post<T>(path: string, body?: unknown): Promise<T> {
    return this.request("POST", path, body);
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<T> {
    const url = this.baseURL + path;
    const bodyText = body === undefined ? "" : JSON.stringify(body);
    const headers: Record<string, string> = {
      Accept: "application/json",
      ...this.authHeaders(bodyText),
    };
    const init: RequestInit = { method, headers };

    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      init.body = bodyText;
    }

    const resp = await fetch(url, init);
    if (!resp.ok) {
      const text = await resp.text().catch(() => "");
      throw new APIError(resp.status, text);
    }

    return resp.json() as Promise<T>;
  }

  /** Open an SSE stream. Returns the raw Response for streaming. */
  async openSSE(path: string): Promise<Response> {
    const url = this.baseURL + path;
    const resp = await fetch(url, {
      headers: {
        Accept: "text/event-stream",
        "Cache-Control": "no-cache",
        ...this.authHeaders(""),
      },
    });

    if (!resp.ok) {
      const text = await resp.text().catch(() => "");
      throw new APIError(resp.status, text);
    }

    return resp;
  }

  private authHeaders(bodyText: string): Record<string, string> {
    const timestamp = new Date().toISOString();
    const bodyHash = createHash("sha256").update(bodyText, "utf-8").digest("hex");
    const payload = `{"body_sha256":${JSON.stringify(bodyHash)},"team":${JSON.stringify(this.auth.teamAddress)},"timestamp":${JSON.stringify(timestamp)}}`;
    const signature = Buffer.from(
      ed.sign(new TextEncoder().encode(payload), this.auth.signingKey),
    ).toString("base64url");
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
