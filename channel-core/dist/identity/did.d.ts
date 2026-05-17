/** Encode an Ed25519 public key as a did:key DID string. */
export declare function computeDIDKey(publicKey: Uint8Array): string;
/** Decode a did:key DID string to an Ed25519 public key. */
export declare function extractPublicKey(did: string): Uint8Array;
/** Derive the canonical did:aw stable identifier from an Ed25519 public key. */
export declare function computeStableID(publicKey: Uint8Array): string;
