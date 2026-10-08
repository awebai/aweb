import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, test, vi } from "vitest";
import * as ed from "@noble/ed25519";
import { canonicalRotationJSON } from "../src/identity/trust.js";
import { verifyDecryptedMessage } from "../src/identity/encrypted.js";
import { dispatchAgentEvent, PinStore, SenderTrustManager, type ChannelAwakening } from "../src/index.js";

// Existing cross-language keys/envelope shape; no real identity material. AES-GCM
// below models the trusted local decrypt boundary, never a verification status.
const vector = JSON.parse(readFileSync(new URL("../../docs/vectors/e2ee-v2-cross-language.json", import.meta.url), "utf8"));
const alice = vector.identities.alice;
const bob = vector.identities.bob;
const canonical = (value: any): string => Array.isArray(value)
  ? `[${value.map(canonical).join(",")}]`
  : value !== null && typeof value === "object"
    ? `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}`
    : JSON.stringify(value);
const hash = (value: Buffer | string) => `sha256:${createHash("sha256").update(value).digest("base64").replace(/=+$/, "")}`;
const b64 = (value: Uint8Array) => Buffer.from(value).toString("base64").replace(/=+$/, "");

function fixture(kind: "mail" | "chat", forgery = "") {
  const envelope = structuredClone(vector.go_mail_envelope);
  envelope.kind = kind;
  const { encryption_key_id: _senderKey, ...from } = envelope.from;
  const recipients = envelope.recipients.map(({ encryption_key_id: _key, wrap_id: _wrap, ...ref }: any) => ref);
  const header = { inner_version: 2, kind, message_id: envelope.message_id, conversation_id: envelope.conversation_id,
    created_at: envelope.created_at, from, recipients };
  envelope.crypto.inner_header_hash = hash(canonical(header));
  const inner = { ...header, ...(kind === "mail" ? { subject: "test subject" } : {}), body: "authenticated content" };
  if (forgery === "forged-inner") inner.from = { ...from, did: bob.did };
  if (forgery === "forged-recipient") inner.recipients = [{ ...recipients[0], did: alice.did }];
  const cek = randomBytes(32); // Injected at the test-only local key-unwrapping boundary.
  const nonce = randomBytes(12);
  envelope.crypto.content_nonce = b64(nonce);
  const bytes = Buffer.from(canonical(inner));
  envelope.crypto.ciphertext_size = bytes.length + 16;
  const aad = structuredClone(envelope);
  delete aad.signature; delete aad.ciphertext; delete aad.crypto.ciphertext_hash;
  const cipher = createCipheriv("aes-256-gcm", cek, nonce);
  cipher.setAAD(Buffer.from(canonical(aad)));
  const ciphertext = Buffer.concat([cipher.update(bytes), cipher.final(), cipher.getAuthTag()]);
  envelope.ciphertext = b64(ciphertext);
  envelope.crypto.ciphertext_hash = hash(ciphertext);
  delete envelope.signature;
  envelope.signature = b64(ed.sign(Buffer.from(canonical(envelope)), Buffer.from(alice.signing_seed, "base64")));
  function decrypt() {
    const decipher = createDecipheriv("aes-256-gcm", cek, nonce);
    decipher.setAAD(Buffer.from(canonical(aad)));
    decipher.setAuthTag(ciphertext.subarray(-16));
    const plain = JSON.parse(Buffer.concat([decipher.update(ciphertext.subarray(0, -16)), decipher.final()]).toString());
    const { body, subject, ...innerHeader } = plain;
    if (hash(canonical(innerHeader)) !== envelope.crypto.inner_header_hash) throw new Error("inner header hash mismatch");
    if (canonical(innerHeader.from) !== canonical(from) || canonical(innerHeader.recipients) !== canonical(recipients)) throw new Error("inner identity mirror mismatch");
    return { message_id: plain.message_id, conversation_id: plain.conversation_id,
      subject, body, from_did: plain.from.did, from_stable_id: plain.from.stable_id, from_address: plain.from.address,
      ...(kind === "mail" ? { to_did: recipients[0].did, to_stable_id: recipients[0].stable_id } : {}),
      encrypted_envelope: structuredClone(envelope), verification_status: "verified" };
  }
  return { envelope, decrypt };
}

async function dispatch(kind: "mail" | "chat", mutation = "valid") {
  const f = fixture(kind, mutation);
  if (mutation === "invalid-signature") f.envelope.signature = b64(new Uint8Array(64));
  if (mutation === "signed-by-other-key") {
    const { signature: _sig, ...signed } = f.envelope;
    f.envelope.signature = b64(ed.sign(Buffer.from(canonical(signed)), Buffer.from(bob.signing_seed, "base64")));
  }
  if (mutation === "wrong-signing-key") f.envelope.signing_key_id = bob.did;
  if (mutation === "unknown-key") f.envelope.from.did = "did:unknown:sender";
  const fetched = { message_id: f.envelope.message_id, conversation_id: f.envelope.conversation_id,
    from_alias: "alice", from_agent: "alice", from_agent_id: "alice", from_address: alice.address,
    from_did: alice.did, from_stable_id: alice.stable_id, to_did: bob.did, to_stable_id: bob.stable_id,
    subject: "", body: "", priority: "normal", created_at: f.envelope.created_at, timestamp: f.envelope.created_at,
    sender_leaving: false, content_mode: "encrypted_v2", message_version: 2, encrypted_envelope: f.envelope };
  const decrypt = async () => {
    if (mutation === "decrypt-failure") throw new Error("missing local encryption key");
    const result = f.decrypt();
    if (mutation === "provider-id") result.message_id = "wrong-id";
    if (mutation === "provider-thread") result.conversation_id = "wrong-thread";
    if (mutation === "provider-recipient") result.to_did = alice.did;
    if (mutation === "provider-sender") result.from_did = bob.did;
    if (mutation === "provider-envelope") return fixture(kind).decrypt(); // Valid signature, same IDs, different authenticated ciphertext.
    if (mutation === "cli-failed") result.verification_status = "failed";
    if (mutation === "no-proof") delete result.encrypted_envelope;
    return result;
  };
  if (mutation === "rotation-valid") {
    const timestamp = new Date().toISOString();
    Object.assign(fetched, { rotation_announcement: { old_did: bob.did, new_did: alice.did, timestamp,
      old_key_signature: b64(ed.sign(Buffer.from(canonicalRotationJSON(bob.did, alice.did, timestamp)), Buffer.from(bob.signing_seed, "base64"))) } });
  }
  const self = { alias: "bob", address: bob.address, did: bob.did, stableID: bob.stable_id };
  if (mutation === "recipient") self.did = "did:key:unrelated", self.stableID = "did:aw:unrelated";
  const client = { get: vi.fn(async () => ({ messages: [structuredClone(fetched)] })), post: vi.fn(async () => {}) };
  const registry = { resolveIdentity: vi.fn(async () => ({ did: alice.did, stableID: alice.stable_id, address: alice.address, identityScope: "global", custody: "self" })),
    verifyStableIdentity: vi.fn(async () => ({ outcome: "OK_VERIFIED", currentDidKey: alice.did })) };
  if (mutation === "stale") registry.verifyStableIdentity = vi.fn(async () => ({ outcome: "STALE_CACHE" })) as never;
  if (mutation === "stable-mismatch") registry.verifyStableIdentity = vi.fn(async () => ({ outcome: "HARD_ERROR" })) as never;
  if (mutation === "unresolved") registry.resolveIdentity = vi.fn(async () => { throw new Error("unavailable"); });
  if (mutation.startsWith("rotation-")) registry.verifyStableIdentity = vi.fn(async () => ({ outcome: "OK_DEGRADED" })) as never;
  const store = new PinStore();
  if (mutation === "pin-mismatch") store.recordVerifiedIdentity(bob.stable_id, alice.address, bob.stable_id, bob.did);
  if (mutation.startsWith("rotation-")) store.recordVerifiedIdentity(alice.stable_id, alice.address, alice.stable_id, bob.did);
  const trust = new SenderTrustManager(client as never, registry as never, "other:other.example", self.did, self.stableID);
  const awakenings: ChannelAwakening[] = [];
  await dispatchAgentEvent({ client: client as never, trust, pinStore: store, self,
    pinStoreWriter: { compareAndSet: async () => {} }, localDecrypt: { mailMessage: decrypt, chatMessage: decrypt },
    onAwakening: a => { awakenings.push(a); } }, new Set(), {
    type: kind === "mail" ? "mail_message" : "chat_message", message_id: fetched.message_id,
    conversation_id: fetched.conversation_id, ...(kind === "chat" ? { session_id: fetched.conversation_id } : {}),
  });
  return { awakenings, client };
}

describe.each(["mail", "chat"] as const)("encrypted %s trust", kind => {
  test("verifies signed encrypted content through the normal trust manager", async () => {
    const { awakenings } = await dispatch(kind);
    expect(awakenings).toHaveLength(1);
    expect(awakenings[0].content).toBe("authenticated content");
    expect(awakenings[0].meta).toMatchObject({ trust_status: "verified", verified: "true" });
  });
  test.each(["invalid-signature", "signed-by-other-key", "wrong-signing-key", "unknown-key", "provider-id", "provider-thread", "provider-sender", "provider-recipient", "provider-envelope", "no-proof", "recipient", "stale", "stable-mismatch", "unresolved", "pin-mismatch", "rotation-unproven"])("never upgrades %s", async mutation => {
    const { awakenings } = await dispatch(kind, mutation);
    expect(awakenings).toHaveLength(1);
    expect(awakenings[0].meta.verified).not.toBe("true");
  });
  test("ignores even a failed CLI status label when TS proof and trust verify", async () => {
    const { awakenings } = await dispatch(kind, "cli-failed");
    expect(awakenings[0].meta.verified).toBe("true");
  });
  test("preserves authenticated key rotation", async () => {
    const { awakenings } = await dispatch(kind, "rotation-valid");
    expect(awakenings[0].meta.verified).toBe("true");
  });
  test.each(["forged-inner", "forged-recipient", "decrypt-failure"])("preserves failure metadata and does not acknowledge %s", async mutation => {
    const { awakenings, client } = await dispatch(kind, mutation);
    expect(awakenings[0].meta).toMatchObject({ encrypted: "true", decrypted: "false" });
    expect(awakenings[0].content).toBe("");
    expect(client.post).not.toHaveBeenCalled();
  });
});

test.each(["go_mail_envelope", "python_mail_envelope"])("verifies unchanged shared %s signature", async name => {
  const envelope = vector[name];
  const proof = { message_id: envelope.message_id, conversation_id: envelope.conversation_id,
    from_did: envelope.from.did, from_stable_id: envelope.from.stable_id, from_address: envelope.from.address,
    encrypted_envelope: envelope };
  expect(await verifyDecryptedMessage(proof, proof, "mail", envelope.conversation_id, { did: bob.did, stableID: bob.stable_id }))
    .toMatchObject({ from_did: alice.did, to_did: bob.did });
});
