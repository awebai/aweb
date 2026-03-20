import { createHash } from "node:crypto";
import bs58 from "bs58";

const DID_KEY_PREFIX = "did:key:z";
const ED25519_MULTICODEC = new Uint8Array([0xed, 0x01]);

/** Encode an Ed25519 public key as a did:key DID string. */
export function computeDIDKey(publicKey: Uint8Array): string {
  const buf = new Uint8Array(2 + publicKey.length);
  buf.set(ED25519_MULTICODEC);
  buf.set(publicKey, 2);
  return DID_KEY_PREFIX + bs58.encode(buf);
}

/** Decode a did:key DID string to an Ed25519 public key. */
export function extractPublicKey(did: string): Uint8Array {
  if (!did.startsWith(DID_KEY_PREFIX)) {
    throw new Error(`invalid did:key: missing prefix "${DID_KEY_PREFIX}"`);
  }

  const decoded = bs58.decode(did.slice(DID_KEY_PREFIX.length));
  if (decoded.length !== 34) {
    throw new Error(
      `invalid did:key: expected 34 bytes, got ${decoded.length}`,
    );
  }
  if (decoded[0] !== 0xed || decoded[1] !== 0x01) {
    throw new Error(
      `invalid did:key: expected Ed25519 multicodec 0xed01, got 0x${decoded[0].toString(16).padStart(2, "0")}${decoded[1].toString(16).padStart(2, "0")}`,
    );
  }

  return decoded.slice(2);
}

/** Derive the canonical did:aw stable identifier from an Ed25519 public key. */
export function computeStableID(publicKey: Uint8Array): string {
  const hash = createHash("sha256").update(publicKey).digest();
  return "did:aw:" + bs58.encode(hash.subarray(0, 20));
}
