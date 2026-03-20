import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
import { extractPublicKey } from "./did.js";

// @noble/ed25519 v2 requires setting the hash function
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

export interface MessageEnvelope {
  from: string;
  from_did: string;
  to: string;
  to_did: string;
  type: string;
  subject: string;
  body: string;
  timestamp: string;
  from_stable_id?: string;
  to_stable_id?: string;
  message_id?: string;
  signature?: string;
  signing_key_id?: string;
}

export type VerificationStatus =
  | "verified"
  | "verified_custodial"
  | "unverified"
  | "failed"
  | "identity_mismatch";

/**
 * Build the canonical JSON payload for message signing.
 * Fields are sorted lexicographically, no whitespace, minimal escaping.
 * Optional fields (from_stable_id, message_id, to_stable_id) are omitted when empty.
 */
export function canonicalJSON(env: MessageEnvelope): string {
  const fields: [string, string][] = [
    ["body", env.body],
    ["from", env.from],
    ["from_did", env.from_did],
    ["subject", env.subject],
    ["timestamp", env.timestamp],
    ["to", env.to],
    ["to_did", env.to_did],
    ["type", env.type],
  ];

  if (env.from_stable_id) fields.push(["from_stable_id", env.from_stable_id]);
  if (env.message_id) fields.push(["message_id", env.message_id]);
  if (env.to_stable_id) fields.push(["to_stable_id", env.to_stable_id]);

  fields.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));

  let result = "{";
  for (let i = 0; i < fields.length; i++) {
    if (i > 0) result += ",";
    result += '"' + fields[i][0] + '":"' + escapeJSON(fields[i][1]) + '"';
  }
  result += "}";
  return result;
}

/** JSON-escape a string value, matching Go's writeEscapedString exactly. */
function escapeJSON(s: string): string {
  let result = "";
  for (const ch of s) {
    const code = ch.codePointAt(0)!;
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
        } else {
          result += ch;
        }
    }
  }
  return result;
}

function b64Encode(bytes: Uint8Array): string {
  const bin = String.fromCharCode(...bytes);
  // Base64 RFC 4648 no padding (RawStdEncoding)
  return btoa(bin).replace(/=+$/, "");
}

function b64Decode(s: string): Uint8Array {
  const bin = atob(s);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

/** Sign a message envelope. Returns base64 signature (no padding). */
export async function signMessage(
  seed: Uint8Array,
  env: MessageEnvelope,
): Promise<string> {
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
export async function verifyMessage(
  env: MessageEnvelope,
): Promise<VerificationStatus> {
  if (!env.from_did || !env.signature) {
    return "unverified";
  }

  if (env.signing_key_id && env.signing_key_id !== env.from_did) {
    return "failed";
  }

  if (!env.from_did.startsWith("did:key:z")) {
    return "unverified";
  }

  let publicKey: Uint8Array;
  try {
    publicKey = extractPublicKey(env.from_did);
  } catch {
    return "failed";
  }

  let sigBytes: Uint8Array;
  try {
    sigBytes = b64Decode(env.signature);
  } catch {
    return "failed";
  }

  const payload = canonicalJSON(env);
  const valid = ed.verify(
    sigBytes,
    new TextEncoder().encode(payload),
    publicKey,
  );

  return valid ? "verified" : "failed";
}

/**
 * Verify a signature against a pre-computed canonical payload string.
 * Use when the server returns signed_payload alongside the message.
 */
export async function verifySignedPayload(
  signedPayload: string,
  signatureB64: string,
  fromDID: string,
  signingKeyID: string,
): Promise<VerificationStatus> {
  if (!fromDID || !signatureB64 || !signedPayload) {
    return "unverified";
  }

  if (signingKeyID && signingKeyID !== fromDID) {
    return "failed";
  }

  if (!fromDID.startsWith("did:key:z")) {
    return "unverified";
  }

  let publicKey: Uint8Array;
  try {
    publicKey = extractPublicKey(fromDID);
  } catch {
    return "failed";
  }

  let sigBytes: Uint8Array;
  try {
    sigBytes = b64Decode(signatureB64);
  } catch {
    return "failed";
  }

  const valid = ed.verify(
    sigBytes,
    new TextEncoder().encode(signedPayload),
    publicKey,
  );

  return valid ? "verified" : "failed";
}
