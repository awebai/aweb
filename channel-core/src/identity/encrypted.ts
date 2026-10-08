import { createHash } from "node:crypto";
import { verifySignedPayload } from "./signing.js";
import { decodeRawStdBase64 } from "./base64.js";

export interface DecryptedMessageProof {
  message_id: string;
  conversation_id?: string;
  from_did?: string;
  from_stable_id?: string;
  from_address?: string;
  to_did?: string;
  to_stable_id?: string;
  encrypted_envelope?: unknown;
}

type ObjectValue = Record<string, unknown>;
function object(value: unknown): ObjectValue {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("expected object");
  return value as ObjectValue;
}
function text(value: unknown): string {
  if (value === undefined) return "";
  if (typeof value !== "string") throw new Error("expected string");
  return value;
}

// v2 signs the complete JSON envelope except signature. Object keys are sorted;
// arrays retain their order. Do not project away unknown signed fields.
export function canonicalEncryptedJSON(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalEncryptedJSON).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const obj = object(value);
    return `{${Object.keys(obj).sort().map(key => `${JSON.stringify(key)}:${canonicalEncryptedJSON(obj[key])}`).join(",")}}`;
  }
  if (typeof value === "string" || typeof value === "boolean" || value === null
      || (typeof value === "number" && Number.isSafeInteger(value))) return JSON.stringify(value);
  throw new Error("unsupported encrypted envelope value");
}
// Go/Python v2 canonicalization omits these optional empty strings. In
// particular Python transmits empty routing fields that Go omits on readback.
// Normalize only the documented fields; unknown fields remain signature-bound.
function optionalStrings(value: ObjectValue, keys: string[]): void {
  for (const key of keys) {
    if (value[key] === undefined) continue;
    const normalized = text(value[key]).trim();
    if (normalized) value[key] = normalized;
    else delete value[key];
  }
}
function envelopeForSignature(value: unknown): ObjectValue {
  const envelope = structuredClone(object(value));
  optionalStrings(envelope, ["reply_to_message_id"]);
  const identityKeys = ["address", "did", "stable_id", "team_id", "encryption_key_id"];
  optionalStrings(object(envelope.from), identityKeys);
  if (!Array.isArray(envelope.recipients) || !Array.isArray(envelope.key_wraps)) throw new Error("missing recipient proof");
  for (const ref of envelope.recipients) optionalStrings(object(ref), [...identityKeys, "wrap_id"]);
  optionalStrings(object(envelope.routing), ["to", "to_did", "to_stable_id", "delivery_origin", "sender_observed_inbound_mode"]);
  optionalStrings(object(envelope.crypto), ["ciphertext_hash"]);
  for (const wrap of envelope.key_wraps) optionalStrings(object(wrap), ["recipient_stable_id", "recipient_did", "recipient_address", "sender_stable_id"]);
  if (envelope.sender_encryption_key === null) delete envelope.sender_encryption_key;
  if (envelope.sender_encryption_key !== undefined) {
    const key = object(envelope.sender_encryption_key);
    for (const field of ["identity_stable_id", "previous_encryption_key_id"]) if (key[field] === null) delete key[field];
    optionalStrings(key, ["identity_stable_id", "previous_encryption_key_id", "custody"]);
    for (const field of ["operation", "version", "identity_did", "encryption_key_id", "encryption_public_key", "algorithm", "created_at", "not_before", "expires_at", "signature"]) {
      key[field] = text(key[field]).trim();
    }
  }
  return envelope;
}

const hash = (value: Uint8Array | string) => `sha256:${createHash("sha256").update(value).digest("base64").replace(/=+$/, "")}`;

export interface AuthenticatedEncryptedIdentity {
  from_did: string;
  from_stable_id: string;
  signed_from: string;
  to_did: string;
  to_stable_id: string;
}

/**
 * The local aw process authenticates plaintext via AEAD and the inner-header
 * mirror. TS independently verifies the exact envelope returned by that process,
 * binds it to the fetched record, then passes only signed identities to its own
 * trust manager. A CLI verification_status is never evidence here.
 */
export async function verifyDecryptedMessage(
  fetched: DecryptedMessageProof,
  decrypted: DecryptedMessageProof,
  kind: "mail" | "chat",
  conversationID: string | undefined,
  self: { did: string; stableID: string },
): Promise<AuthenticatedEncryptedIdentity | undefined> {
  try {
    const envelope = envelopeForSignature(decrypted.encrypted_envelope);
    if (canonicalEncryptedJSON(envelope) !== canonicalEncryptedJSON(envelopeForSignature(fetched.encrypted_envelope))) return;
    if (envelope.message_version !== 2 || envelope.envelope_type !== "aweb.e2ee.message" || envelope.kind !== kind) return;
    if (!text(envelope.message_id) || envelope.message_id !== fetched.message_id || envelope.message_id !== decrypted.message_id) return;
    if (!text(envelope.conversation_id) || envelope.conversation_id !== conversationID || envelope.conversation_id !== decrypted.conversation_id) return;
    if (fetched.conversation_id && fetched.conversation_id !== envelope.conversation_id) return;
    const from = object(envelope.from);
    const did = text(from.did);
    const stable = text(from.stable_id);
    const address = text(from.address);
    if (!did || envelope.signing_key_id !== did) return;
    const { signature, ...signed } = envelope;
    if (await verifySignedPayload(canonicalEncryptedJSON(signed), text(signature), did, text(envelope.signing_key_id)) !== "verified") return;
    const crypto = object(envelope.crypto);
    if (crypto.suite !== "aweb-e2ee-v2.x25519-hkdf-sha256-aes256gcm-ed25519") return;
    const ciphertext = decodeRawStdBase64(text(envelope.ciphertext));
    if (crypto.ciphertext_size !== ciphertext.length || crypto.ciphertext_hash !== hash(ciphertext)) return;
    if (!Array.isArray(envelope.key_wraps) || crypto.key_wraps_hash !== hash(canonicalEncryptedJSON(envelope.key_wraps))) return;
    if (!Array.isArray(envelope.recipients)) return;
    const recipients = envelope.recipients.map(object);
    const recipient = recipients.find(ref => self.stableID && text(ref.stable_id)
      ? ref.stable_id === self.stableID
      : !!self.did && ref.did === self.did);
    if (!recipient) return;
    const recipientDID = text(recipient.did);
    const recipientStable = text(recipient.stable_id);
    // aw returns the authenticated sender; chat's released JSON has no inner
    // recipient projection, so its signed recipient set above is authoritative.
    if (decrypted.from_did !== did || text(decrypted.from_stable_id) !== stable) return;
    if (address && decrypted.from_address !== address) return;
    const didMatches = (observed: string | undefined, key: string, stableID: string) => !observed || observed === key || (!!stableID && observed === stableID);
    if (!didMatches(fetched.from_did, did, stable) || (fetched.from_stable_id && fetched.from_stable_id !== stable)) return;
    if (fetched.from_address && address && fetched.from_address !== address) return;
    for (const projection of [fetched, decrypted]) {
      if (!didMatches(projection.to_did, recipientDID, recipientStable)) return;
      if (projection.to_stable_id && projection.to_stable_id !== recipientStable) return;
    }
    return { from_did: did, from_stable_id: stable, signed_from: address,
      to_did: recipientDID, to_stable_id: recipientStable };
  } catch {
    // Missing proof (including older provider JSON), malformed data, and unknown
    // key types must never upgrade the plaintext fetch's unverified result.
    return;
  }
}
