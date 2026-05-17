import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
import { extractPublicKey } from "./did.js";
// @noble/ed25519 v2 requires setting the hash function
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));
/**
 * Build the canonical JSON payload for message signing.
 * Fields are sorted lexicographically, no whitespace, minimal escaping.
 * Optional fields (conversation_id, from_stable_id, message_id, to_stable_id) are omitted when empty.
 */
export function canonicalJSON(env) {
    const fields = [
        ["body", env.body],
        ["from", env.from],
        ["from_did", env.from_did],
        ["subject", env.subject],
        ["timestamp", env.timestamp],
        ["to", env.to],
        ["to_did", env.to_did],
        ["type", env.type],
    ];
    if (env.from_stable_id)
        fields.push(["from_stable_id", env.from_stable_id]);
    if (env.conversation_id)
        fields.push(["conversation_id", env.conversation_id]);
    if (env.message_id)
        fields.push(["message_id", env.message_id]);
    if (env.to_stable_id)
        fields.push(["to_stable_id", env.to_stable_id]);
    fields.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
    let result = "{";
    for (let i = 0; i < fields.length; i++) {
        if (i > 0)
            result += ",";
        result += '"' + fields[i][0] + '":"' + escapeJSON(fields[i][1]) + '"';
    }
    result += "}";
    return result;
}
/** JSON-escape a string value, matching Go's writeEscapedString exactly. */
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
                    result += "\\u" + code.toString(16).padStart(4, "0");
                }
                else {
                    result += ch;
                }
        }
    }
    return result;
}
function b64Encode(bytes) {
    // Build binary string without spread to avoid stack overflow on large inputs
    let bin = "";
    for (let i = 0; i < bytes.length; i++)
        bin += String.fromCharCode(bytes[i]);
    // Base64 RFC 4648 no padding (RawStdEncoding)
    return btoa(bin).replace(/=+$/, "");
}
function b64Decode(s) {
    const bin = atob(s);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++)
        bytes[i] = bin.charCodeAt(i);
    return bytes;
}
/** Sign a message envelope. Returns base64 signature (no padding). */
export async function signMessage(seed, env) {
    const payload = canonicalJSON(env);
    const sig = ed.sign(new TextEncoder().encode(payload), seed);
    return b64Encode(sig);
}
/**
 * Verify a message envelope signature.
 * Returns 'unverified' if DID or signature is missing.
 * Returns 'failed' if signature doesn't verify.
 * Returns 'verified' if valid.
 */
export async function verifyMessage(env) {
    if (!env.from_did || !env.signature) {
        return "unverified";
    }
    if (env.signing_key_id && env.signing_key_id !== env.from_did) {
        return "failed";
    }
    if (!env.from_did.startsWith("did:key:z")) {
        return "unverified";
    }
    let publicKey;
    try {
        publicKey = extractPublicKey(env.from_did);
    }
    catch {
        return "failed";
    }
    let sigBytes;
    try {
        sigBytes = b64Decode(env.signature);
    }
    catch {
        return "failed";
    }
    const payload = canonicalJSON(env);
    const valid = ed.verify(sigBytes, new TextEncoder().encode(payload), publicKey);
    return valid ? "verified" : "failed";
}
/**
 * Verify a signature against a pre-computed canonical payload string.
 * Use when the server returns signed_payload alongside the message.
 */
export async function verifySignedPayload(signedPayload, signatureB64, fromDID, signingKeyID) {
    if (!fromDID || !signatureB64 || !signedPayload) {
        return "unverified";
    }
    if (signingKeyID && signingKeyID !== fromDID) {
        return "failed";
    }
    if (!fromDID.startsWith("did:key:z")) {
        return "unverified";
    }
    let publicKey;
    try {
        publicKey = extractPublicKey(fromDID);
    }
    catch {
        return "failed";
    }
    let sigBytes;
    try {
        sigBytes = b64Decode(signatureB64);
    }
    catch {
        return "failed";
    }
    const valid = ed.verify(sigBytes, new TextEncoder().encode(signedPayload), publicKey);
    return valid ? "verified" : "failed";
}
export function signedPayloadConversationStatus(signedPayload, conversationID) {
    const expected = (conversationID || "").trim();
    if (!expected)
        return "verified";
    try {
        const payload = JSON.parse(signedPayload);
        if (payload.conversation_id === expected)
            return "verified";
        if (payload.conversation_id === undefined || payload.conversation_id === "") {
            return "verified_legacy";
        }
        return "failed";
    }
    catch {
        return "failed";
    }
}
