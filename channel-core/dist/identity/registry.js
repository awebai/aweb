import * as dns from "node:dns/promises";
import { isIP } from "node:net";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import * as ed from "@noble/ed25519";
import { getDomain } from "tldts";
import { extractPublicKey } from "./did.js";
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));
export const DEFAULT_AWID_REGISTRY_URL = "https://api.awid.ai";
const REGISTRY_DISCOVERY_TTL_MS = 15 * 60 * 1000;
const REGISTRY_ADDRESS_TTL_MS = 5 * 60 * 1000;
const REGISTRY_KEY_TTL_MS = 15 * 60 * 1000;
function pathSafeSegment(value) {
    return encodeURIComponent(value).replace(/%3A/gi, ":");
}
export class RegistryResolver {
    fetchImpl;
    resolveTxtImpl;
    now;
    registryCache = new Map();
    addressCache = new Map();
    keyCache = new Map();
    headCache = new Map();
    fallbackRegistryURL;
    constructor(fetchImpl = fetch, resolveTxtImpl = dns.resolveTxt, now = () => Date.now(), options) {
        this.fetchImpl = fetchImpl;
        this.resolveTxtImpl = resolveTxtImpl;
        this.now = now;
        this.fallbackRegistryURL = options?.fallbackRegistryURL
            ? canonicalServerOrigin(options.fallbackRegistryURL)
            : "";
    }
    async verifyStableIdentity(address, stableID) {
        const split = splitRegistryAddress(address);
        if (!split || !stableID.trim()) {
            return { outcome: "OK_DEGRADED" };
        }
        let resolvedAddress;
        try {
            resolvedAddress = await this.resolveAddress(split.domain, split.name);
        }
        catch (error) {
            return { outcome: "OK_DEGRADED", error: String(error) };
        }
        if (resolvedAddress.response.did_aw !== stableID) {
            return { outcome: "HARD_ERROR", error: "registry address did:aw mismatch" };
        }
        let resolution;
        try {
            resolution = await this.resolveDidKey(resolvedAddress.registryURL, stableID);
        }
        catch (error) {
            return { outcome: "OK_DEGRADED", error: String(error) };
        }
        if (resolution.did_aw !== stableID) {
            return { outcome: "HARD_ERROR", error: "registry key did:aw mismatch" };
        }
        const cached = this.headCache.get(stableID);
        const verification = verifyDidKeyResolution(resolution, cached, this.now());
        if (verification.outcome === "OK_VERIFIED" && verification.nextHead) {
            this.headCache.set(stableID, verification.nextHead);
        }
        return {
            outcome: verification.outcome,
            currentDidKey: resolution.current_did_key,
            error: verification.error,
        };
    }
    async resolveAddressIdentity(address) {
        const identity = await this.resolveIdentity(address);
        return { did: identity.did, stableID: identity.stableID };
    }
    async resolveIdentity(address) {
        const split = splitRegistryAddress(address);
        if (!split) {
            throw new Error(`invalid address ${address}`);
        }
        const authority = await this.discoverAuthority(split.domain);
        const resolvedAddress = await this.resolveAddress(split.domain, split.name);
        const resolution = await this.resolveDidKey(resolvedAddress.registryURL, resolvedAddress.response.did_aw);
        if (resolution.did_aw !== resolvedAddress.response.did_aw) {
            throw new Error("registry key did:aw mismatch");
        }
        if (resolvedAddress.response.current_did_key.trim()
            && resolvedAddress.response.current_did_key !== resolution.current_did_key) {
            throw new Error("registry address/key mismatch");
        }
        const verification = verifyDidKeyResolution(resolution, this.headCache.get(resolvedAddress.response.did_aw), this.now());
        if (verification.outcome === "HARD_ERROR") {
            throw new Error(verification.error || "invalid log head");
        }
        if (verification.outcome === "OK_VERIFIED" && verification.nextHead) {
            this.headCache.set(resolvedAddress.response.did_aw, verification.nextHead);
        }
        return {
            did: resolution.current_did_key,
            stableID: resolution.did_aw,
            address: `${split.domain}/${split.name}`,
            controllerDid: authority.controllerDid,
            custody: "self",
            lifetime: "persistent",
        };
    }
    async discoverRegistry(domain) {
        return (await this.discoverAuthority(domain)).registryURL;
    }
    async discoverAuthority(domain) {
        domain = canonicalizeDomain(domain);
        const cached = this.registryCache.get(domain);
        if (cached && this.now() <= cached.expiresAt) {
            return cached.value;
        }
        const authority = await discoverAuthoritativeRegistry(domain, this.resolveTxtImpl);
        const resolvedAuthority = this.fallbackRegistryURL
            ? { ...authority, registryURL: this.fallbackRegistryURL }
            : authority;
        this.registryCache.set(domain, {
            value: resolvedAuthority,
            expiresAt: this.now() + REGISTRY_DISCOVERY_TTL_MS,
        });
        return resolvedAuthority;
    }
    async resolveAddress(domain, name) {
        const key = `${domain}/${name}`;
        const cached = this.addressCache.get(key);
        if (cached && this.now() <= cached.expiresAt) {
            return cached.value;
        }
        const registryURL = await this.discoverRegistry(domain);
        const response = await this.getJSON(registryURL, `/v1/namespaces/${pathSafeSegment(domain)}/addresses/${pathSafeSegment(name)}`);
        const value = { registryURL, response };
        this.addressCache.set(key, { value, expiresAt: this.now() + REGISTRY_ADDRESS_TTL_MS });
        return value;
    }
    async resolveDidKey(registryURL, stableID) {
        const cached = this.keyCache.get(stableID);
        if (cached && this.now() <= cached.expiresAt) {
            return cached.value;
        }
        const response = await this.getJSON(registryURL, `/v1/did/${pathSafeSegment(stableID)}/key`);
        this.keyCache.set(stableID, {
            value: response,
            expiresAt: this.now() + REGISTRY_KEY_TTL_MS,
        });
        return response;
    }
    async getJSON(baseURL, path) {
        const response = await this.fetchImpl(`${baseURL.replace(/\/+$/, "")}${path}`, {
            method: "GET",
            headers: { Accept: "application/json" },
            signal: AbortSignal.timeout(10_000),
        });
        if (!response.ok) {
            throw new Error(await response.text().catch(() => `${response.status}`));
        }
        return response.json();
    }
}
export async function discoverAuthoritativeRegistry(domain, resolveTxtImpl = dns.resolveTxt) {
    const authority = await lookupDomainAuthority(domain, true, resolveTxtImpl);
    return authority ?? {
        controllerDid: "",
        registryURL: DEFAULT_AWID_REGISTRY_URL,
        dnsName: awidTXTName(domain),
        inherited: false,
    };
}
async function lookupDomainAuthority(domain, allowAncestors, resolveTxtImpl) {
    const canonical = canonicalizeDomain(domain);
    const candidates = candidateDomainsForLookup(canonical, allowAncestors);
    for (const candidate of candidates) {
        const qname = awidTXTName(candidate);
        let records;
        try {
            records = await resolveTxtImpl(qname);
        }
        catch (error) {
            if (isTxtNotFound(error)) {
                if (allowAncestors)
                    continue;
                throw error;
            }
            throw error;
        }
        const awidRecords = records
            .map((parts) => parts.join("").trim())
            .filter((record) => record.startsWith("awid="));
        if (awidRecords.length === 0) {
            if (allowAncestors)
                continue;
            throw new Error(`no awid TXT record found at ${qname}`);
        }
        if (awidRecords.length > 1) {
            throw new Error(`multiple awid TXT records found at ${qname}`);
        }
        const authority = parseAwidTXTRecord(awidRecords[0], qname);
        return {
            ...authority,
            inherited: candidate !== canonical,
        };
    }
    return null;
}
export function parseAwidTXTRecord(record, dnsName) {
    const fields = new Map();
    for (const rawPart of record.split(";")) {
        const part = rawPart.trim();
        if (!part.includes("="))
            continue;
        const idx = part.indexOf("=");
        const key = part.slice(0, idx).trim();
        const value = part.slice(idx + 1).trim();
        if (fields.has(key)) {
            throw new Error(`duplicate ${key} field in awid TXT record`);
        }
        fields.set(key, value);
    }
    if (fields.get("awid") !== "v1") {
        throw new Error(`unsupported awid version: ${fields.get("awid") || ""}`);
    }
    const controller = (fields.get("controller") || "").trim();
    if (!controller) {
        throw new Error("missing controller field in awid TXT record");
    }
    extractPublicKey(controller);
    const registryValue = (fields.get("registry") || "").trim();
    const registryURL = registryValue ? validateRegistryOrigin(registryValue) : DEFAULT_AWID_REGISTRY_URL;
    return {
        controllerDid: controller,
        registryURL,
        dnsName,
        inherited: false,
    };
}
export function awidTXTName(domain) {
    return `_awid.${canonicalizeDomain(domain)}`;
}
export function candidateDomainsForLookup(domain, allowAncestors) {
    const canonical = canonicalizeDomain(domain);
    if (!canonical)
        return [];
    if (!allowAncestors)
        return [canonical];
    const labels = canonical.split(".");
    const boundary = registeredDomainBoundary(canonical);
    const boundaryLabels = boundary.split(".");
    const maxIndex = Math.max(0, labels.length - boundaryLabels.length);
    const out = [];
    for (let index = 0; index <= maxIndex; index += 1) {
        out.push(labels.slice(index).join("."));
    }
    return out;
}
export function registeredDomainBoundary(domain) {
    return canonicalizeDomain(getDomain(domain) || domain);
}
export function verifyDidKeyResolution(resolution, cached, nowMs) {
    if (!resolution.did_aw?.startsWith("did:aw:")) {
        return { outcome: "HARD_ERROR", error: `invalid did:aw ${resolution.did_aw}` };
    }
    try {
        extractPublicKey(resolution.current_did_key);
    }
    catch (error) {
        return { outcome: "HARD_ERROR", error: `invalid current did:key: ${error}` };
    }
    const head = resolution.log_head;
    if (!head) {
        return { outcome: "OK_DEGRADED" };
    }
    if (head.new_did_key !== resolution.current_did_key) {
        return { outcome: "HARD_ERROR", error: "log_head new_did_key mismatch" };
    }
    if (head.seq < 1) {
        return { outcome: "HARD_ERROR", error: "log_head seq must be >= 1" };
    }
    if (head.seq === 1) {
        if (head.operation !== "create") {
            return { outcome: "HARD_ERROR", error: "seq=1 requires create operation" };
        }
        if (head.prev_entry_hash != null) {
            return { outcome: "HARD_ERROR", error: "seq=1 requires null prev_entry_hash" };
        }
        if (head.previous_did_key != null) {
            return { outcome: "HARD_ERROR", error: "create requires null previous_did_key" };
        }
    }
    else {
        if (!head.prev_entry_hash || !isLowerHex(head.prev_entry_hash)) {
            return { outcome: "HARD_ERROR", error: "seq>1 requires hex prev_entry_hash" };
        }
        if (!head.previous_did_key) {
            return { outcome: "HARD_ERROR", error: "seq>1 requires previous_did_key" };
        }
        try {
            extractPublicKey(head.previous_did_key);
        }
        catch (error) {
            return { outcome: "HARD_ERROR", error: `invalid previous_did_key: ${error}` };
        }
    }
    try {
        extractPublicKey(head.authorized_by);
    }
    catch (error) {
        return { outcome: "HARD_ERROR", error: `invalid authorized_by: ${error}` };
    }
    if (!isLowerHex(head.entry_hash) || !isLowerHex(head.state_hash)) {
        return { outcome: "HARD_ERROR", error: "invalid entry/state hash" };
    }
    if (!isCanonicalTimestamp(head.timestamp)) {
        return { outcome: "HARD_ERROR", error: "timestamp must be RFC3339 second precision" };
    }
    const payload = canonicalDidLogPayload(resolution.did_aw, head);
    const computedEntryHash = bytesToHex(sha256(new TextEncoder().encode(payload)));
    if (computedEntryHash !== head.entry_hash) {
        return { outcome: "HARD_ERROR", error: "entry_hash mismatch" };
    }
    let validSignature = false;
    try {
        validSignature = ed.verify(b64Decode(head.signature), new TextEncoder().encode(payload), extractPublicKey(head.authorized_by));
    }
    catch (error) {
        return { outcome: "HARD_ERROR", error: String(error) };
    }
    if (!validSignature) {
        return { outcome: "HARD_ERROR", error: "invalid log_head signature" };
    }
    if (cached) {
        if (head.seq < cached.seq) {
            return { outcome: "HARD_ERROR", error: "log_head seq regression" };
        }
        if (head.seq === cached.seq && head.entry_hash !== cached.entryHash) {
            return { outcome: "HARD_ERROR", error: "log_head split view" };
        }
        if (head.seq === cached.seq + 1 && head.prev_entry_hash !== cached.entryHash) {
            return { outcome: "HARD_ERROR", error: "log_head broken chain" };
        }
        if (head.seq > cached.seq + 1) {
            return { outcome: "OK_DEGRADED" };
        }
    }
    return {
        outcome: "OK_VERIFIED",
        nextHead: {
            seq: head.seq,
            entryHash: head.entry_hash,
            stateHash: head.state_hash,
            currentDidKey: resolution.current_did_key,
            fetchedAt: nowMs,
        },
    };
}
export function canonicalDidLogPayload(didAW, head) {
    const fields = [
        `"authorized_by":"${escapeJSON(head.authorized_by)}"`,
        `"did_aw":"${escapeJSON(didAW)}"`,
        `"new_did_key":"${escapeJSON(head.new_did_key)}"`,
        `"operation":"${escapeJSON(head.operation)}"`,
        `"prev_entry_hash":${head.prev_entry_hash == null ? "null" : `"${escapeJSON(head.prev_entry_hash)}"`}`,
        `"previous_did_key":${head.previous_did_key == null ? "null" : `"${escapeJSON(head.previous_did_key)}"`}`,
        `"seq":${head.seq}`,
        `"state_hash":"${escapeJSON(head.state_hash)}"`,
        `"timestamp":"${escapeJSON(head.timestamp)}"`,
    ];
    return `{${fields.join(",")}}`;
}
function canonicalizeDomain(domain) {
    return domain.trim().toLowerCase().replace(/\.$/, "");
}
function splitRegistryAddress(address) {
    const trimmed = address.trim();
    const idx = trimmed.indexOf("/");
    if (idx <= 0)
        return null;
    const domain = canonicalizeDomain(trimmed.slice(0, idx));
    const name = trimmed.slice(idx + 1).trim();
    if (!domain || !name || name.includes("/"))
        return null;
    return { domain, name };
}
function isTxtNotFound(error) {
    const code = error?.code;
    return code === "ENOTFOUND" || code === "ENODATA" || code === "ENOENT";
}
function validateRegistryOrigin(value) {
    const canonical = canonicalServerOrigin(value);
    const url = new URL(canonical);
    const host = (url.hostname || "").toLowerCase();
    if (!host) {
        throw new Error("registry URL must include a host");
    }
    if (url.protocol !== "https:" && !isExplicitDevelopmentEnvironment()) {
        throw new Error("registry URL must use https unless APP_ENV=development");
    }
    if (host === "localhost" || host.endsWith(".localhost")) {
        throw new Error("registry URL must not target localhost");
    }
    if (isIP(host) !== 0) {
        throw new Error("registry URL must not use a literal IP address");
    }
    return canonical;
}
function isExplicitDevelopmentEnvironment() {
    for (const name of ["APP_ENV", "ENVIRONMENT"]) {
        const value = (process.env[name] || "").trim().toLowerCase();
        if (!value)
            continue;
        return value === "dev" || value === "development" || value === "local";
    }
    return false;
}
function canonicalServerOrigin(raw) {
    const value = raw.trim();
    if (!value) {
        throw new Error("server URL must be non-empty");
    }
    const url = new URL(value);
    const scheme = url.protocol.toLowerCase();
    if (scheme !== "http:" && scheme !== "https:") {
        throw new Error("server URL scheme must be http or https");
    }
    if (url.username || url.password) {
        throw new Error("server URL must not include userinfo");
    }
    if (url.search) {
        throw new Error("server URL must not include query or fragment");
    }
    if (url.hash) {
        throw new Error("server URL must not include query or fragment");
    }
    if (url.pathname && url.pathname !== "/") {
        throw new Error("server URL must not include a path");
    }
    const host = url.hostname.toLowerCase();
    if (!host) {
        throw new Error("server URL must include a host");
    }
    let port = url.port;
    if ((scheme === "http:" && port === "80") || (scheme === "https:" && port === "443")) {
        port = "";
    }
    const hostOut = host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
    return `${scheme}//${hostOut}${port ? `:${port}` : ""}`;
}
function isLowerHex(value) {
    return /^[0-9a-f]+$/.test(value.trim());
}
function isCanonicalTimestamp(value) {
    const trimmed = value.trim();
    if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(Z|[+-]\d{2}:\d{2})$/.test(trimmed)) {
        return false;
    }
    return !Number.isNaN(Date.parse(trimmed));
}
function b64Decode(value) {
    return Uint8Array.from(Buffer.from(value, "base64"));
}
function bytesToHex(bytes) {
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
function escapeJSON(s) {
    let result = "";
    for (const ch of s) {
        const code = ch.codePointAt(0);
        switch (ch) {
            case '"':
                result += '\\"';
                break;
            case "\\":
                result += "\\\\";
                break;
            case "\n":
                result += "\\n";
                break;
            case "\r":
                result += "\\r";
                break;
            case "\t":
                result += "\\t";
                break;
            case "\b":
                result += "\\b";
                break;
            case "\f":
                result += "\\f";
                break;
            default:
                if (code < 0x20) {
                    result += `\\u${code.toString(16).padStart(4, "0")}`;
                }
                else {
                    result += ch;
                }
        }
    }
    return result;
}
