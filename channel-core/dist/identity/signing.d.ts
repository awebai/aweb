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
export type VerificationStatus = "verified" | "verified_legacy" | "verified_custodial" | "unverified" | "failed" | "verification_stale" | "identity_mismatch";
/**
 * Build the canonical JSON payload for message signing.
 * Fields are sorted lexicographically, no whitespace, minimal escaping.
 * Optional fields (conversation_id, from_stable_id, message_id, to_stable_id) are omitted when empty.
 */
export declare function canonicalJSON(env: MessageEnvelope): string;
/** Sign a message envelope. Returns base64 signature (no padding). */
export declare function signMessage(seed: Uint8Array, env: MessageEnvelope): Promise<string>;
/**
 * Verify a message envelope signature.
 * Returns 'unverified' if DID or signature is missing.
 * Returns 'failed' if signature doesn't verify.
 * Returns 'verified' if valid.
 */
export declare function verifyMessage(env: MessageEnvelope): Promise<VerificationStatus>;
/**
 * Verify a signature against a pre-computed canonical payload string.
 * Use when the server returns signed_payload alongside the message.
 */
export declare function verifySignedPayload(signedPayload: string, signatureB64: string, fromDID: string, signingKeyID: string): Promise<VerificationStatus>;
export declare function signedPayloadConversationStatus(signedPayload: string, conversationID: string | undefined): VerificationStatus;
