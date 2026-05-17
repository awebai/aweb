import { createHash } from "node:crypto";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));
function canonicalTimestamp() {
    return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}
export class APIClient {
    baseURL;
    auth;
    constructor(baseURL, auth) {
        this.baseURL = baseURL;
        this.auth = auth;
    }
    async get(path) {
        return this.request("GET", path);
    }
    async post(path, body) {
        return this.request("POST", path, body);
    }
    async request(method, path, body) {
        const url = this.baseURL + path;
        const bodyText = body === undefined ? "" : JSON.stringify(body);
        const headers = {
            Accept: "application/json",
            ...this.authHeaders(path, bodyText),
        };
        const init = { method, headers };
        if (body !== undefined) {
            headers["Content-Type"] = "application/json";
            init.body = bodyText;
        }
        const resp = await fetch(url, init);
        if (!resp.ok) {
            const text = await resp.text().catch(() => "");
            throw new APIError(resp.status, text);
        }
        return resp.json();
    }
    /** Open an SSE stream. Returns the raw Response for streaming. */
    async openSSE(path, signal) {
        const url = this.baseURL + path;
        const resp = await fetch(url, {
            signal,
            headers: {
                Accept: "text/event-stream",
                "Cache-Control": "no-cache",
                ...this.authHeaders(path, ""),
            },
        });
        if (!resp.ok) {
            const text = await resp.text().catch(() => "");
            throw new APIError(resp.status, text);
        }
        return resp;
    }
    authHeaders(path, bodyText) {
        if (this.usesIdentityMessagingAuth(path)) {
            return this.identityAuthHeaders(bodyText);
        }
        return this.teamAuthHeaders(bodyText);
    }
    usesIdentityMessagingAuth(path) {
        const cleanPath = path.split("?", 1)[0] ?? path;
        return cleanPath === "/v1/messages"
            || cleanPath.startsWith("/v1/messages/")
            || cleanPath.startsWith("/v1/chat");
    }
    identityAuthHeaders(bodyText) {
        const timestamp = canonicalTimestamp();
        const bodyHash = createHash("sha256").update(bodyText, "utf-8").digest("hex");
        const payload = `{"body_sha256":${JSON.stringify(bodyHash)},"did_aw":${JSON.stringify(this.auth.stableID)},"timestamp":${JSON.stringify(timestamp)}}`;
        const signature = Buffer.from(ed.sign(new TextEncoder().encode(payload), this.auth.signingKey)).toString("base64").replace(/=+$/, "");
        const headers = {
            Authorization: `DIDKey ${this.auth.did} ${signature}`,
            "X-AWEB-Timestamp": timestamp,
        };
        if (this.auth.stableID.trim()) {
            headers["X-AWEB-DID-AW"] = this.auth.stableID;
        }
        return headers;
    }
    teamAuthHeaders(bodyText) {
        const timestamp = canonicalTimestamp();
        const bodyHash = createHash("sha256").update(bodyText, "utf-8").digest("hex");
        const payload = `{"body_sha256":${JSON.stringify(bodyHash)},"team_id":${JSON.stringify(this.auth.teamID)},"timestamp":${JSON.stringify(timestamp)}}`;
        const signature = Buffer.from(ed.sign(new TextEncoder().encode(payload), this.auth.signingKey)).toString("base64").replace(/=+$/, "");
        return {
            Authorization: `DIDKey ${this.auth.did} ${signature}`,
            "X-AWEB-Timestamp": timestamp,
            "X-AWID-Team-Certificate": this.auth.teamCertificateHeader,
        };
    }
}
export class APIError extends Error {
    statusCode;
    body;
    constructor(statusCode, body) {
        super(body ? `aweb: http ${statusCode}: ${body}` : `aweb: http ${statusCode}`);
        this.statusCode = statusCode;
        this.body = body;
    }
}
