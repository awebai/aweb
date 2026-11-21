import { signBytes as signEd25519, verifyBytes } from "./signature_wire.js";
import { extractPublicKey } from "./did.js";
import { decodeRawStdBase64 } from "./base64.js";
import { canonicalStringObject } from "./canonical.js";

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
  conversation_id?: string;
  signature?: string;
  signing_key_id?: string;
}

export type VerificationStatus =
  | "verified"
  | "verified_legacy"
  | "verified_custodial"
  | "unverified"
  | "failed"
  | "verification_stale"
  | "identity_mismatch"
  | "pin_conflict";

// docs/receiving-events.md, “Autonomous message presentation”. These are
// accepted sender results. Specific protocols can require stronger binding.
const trustedVerificationStatuses = ["verified", "verified_legacy", "verified_custodial"] as const;

export function isTrustedVerificationStatus(status: string | undefined): status is typeof trustedVerificationStatuses[number] {
  return trustedVerificationStatuses.some((trusted) => status === trusted);
}

export function withholdsMessageContent(status: string | undefined): boolean {
  return status === "failed" || status === "identity_mismatch";
}

/**
 * Build the canonical JSON payload for message signing.
 * Fields are sorted lexicographically, no whitespace, minimal escaping.
 * Optional fields (conversation_id, from_stable_id, message_id, to_stable_id) are omitted when empty.
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
  if (env.conversation_id) fields.push(["conversation_id", env.conversation_id]);
  if (env.message_id) fields.push(["message_id", env.message_id]);
  if (env.to_stable_id) fields.push(["to_stable_id", env.to_stable_id]);

  return canonicalStringObject(fields);
}

function b64Encode(bytes: Uint8Array): string {
  // Build binary string without spread to avoid stack overflow on large inputs
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  // Base64 RFC 4648 no padding (RawStdEncoding)
  return btoa(bin).replace(/=+$/, "");
}

function b64Decode(s: string): Uint8Array {
  // Strict, matching Go's RawStdEncoding. This is the message-envelope
  // signature path (verifyMessage / verifySignedPayload) — the most exercised
  // one — so the message profile requires the strict raw standard alphabet.
  // Throws on malformed input: both callers wrap this in a
  // try/catch that reports "failed", so a bad signature must not decode to
  // empty bytes and fall through to the verifier.
  return decodeRawStdBase64(s);
}

/** Sign bytes with an Ed25519 seed. Returns raw standard base64 (no padding). */
export function signBytes(seed: Uint8Array, bytes: Uint8Array): string {
  return b64Encode(signEd25519({ message: bytes, seed }));
}

/** Sign a message envelope. Returns base64 signature (no padding). */
export async function signMessage(
  seed: Uint8Array,
  env: MessageEnvelope,
): Promise<string> {
  return signBytes(seed, new TextEncoder().encode(canonicalJSON(env)));
}

/**
 * Verify a message envelope signature.
 * Returns 'unverified' if DID or signature is missing.
 * Returns 'failed' if signature doesn't verify.
 * Returns 'verified' if the signature is valid. This does not prove that the
 * signer owns the claimed sender address; every inbound path must pass the
 * result through SenderTrustManager.normalizeTrust for that binding decision.
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

  try {
    const sigBytes = b64Decode(env.signature);
    const payload = canonicalJSON(env);
    const valid = verifyBytes({
      signature: sigBytes,
      message: new TextEncoder().encode(payload),
      publicKey,
    });
    return valid ? "verified" : "failed";
  } catch {
    return "failed";
  }
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

  try {
    const sigBytes = b64Decode(signatureB64);
    const valid = verifyBytes({
      signature: sigBytes,
      message: new TextEncoder().encode(signedPayload),
      publicKey,
    });
    return valid ? "verified" : "failed";
  } catch {
    return "failed";
  }
}

export function signedPayloadConversationStatus(
  signedPayload: string,
  conversationID: string | undefined,
): VerificationStatus {
  const expected = (conversationID || "").trim();
  if (!expected) return "verified";
  try {
    const payload: unknown = JSON.parse(signedPayload);
    if (payload === null) return "failed";
    const conversationID =
      typeof payload === "object" && "conversation_id" in payload
        ? payload.conversation_id
        : undefined;
    if (conversationID === expected) return "verified";
    if (conversationID === undefined || conversationID === "") {
      return "verified_legacy";
    }
    return "failed";
  } catch {
    return "failed";
  }
}
