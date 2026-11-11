// A verified signature covers the signed payload. What a reader is shown comes
// from separate response fields, so those fields are compared with the signed
// claims before the message is reported verified. The cases mirror the Go
// client's (cli/go/awid/signed_display_test.go, mail_reader_display_test.go),
// so both clients give one message the same status.
import { describe, expect, test, vi } from "vitest";
import * as ed from "@noble/ed25519";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { dispatchAgentEvent, PinStore, type ChannelAwakening, type SenderTrustManager } from "../src/index.js";
import { fetchHistory, type ChatMessage } from "../src/api/chat.js";
import { fetchInbox, type InboxMessage } from "../src/api/mail.js";
import { computeDIDKey } from "../src/identity/did.js";
import { signBytes } from "../src/identity/signing.js";
import { signedDisplayMatches } from "../src/identity/signed_display.js";

const testDir = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(readFileSync(join(testDir, "vectors.json"), "utf-8")) as { seed: string; did: string };
const seed = Uint8Array.from(Buffer.from(vectors.seed, "base64"));
const did = vectors.did;

type Fields = Record<string, unknown>;
type Kind = "mail" | "chat";

function sign(payload: string): string {
  return signBytes(seed, new TextEncoder().encode(payload));
}

async function read(kind: Kind, raw: Fields, reader = { did, stableID: "" }): Promise<InboxMessage | ChatMessage> {
  const client = { get: async () => ({ messages: [{ ...raw }] }) };
  const messages = kind === "mail"
    ? await fetchInbox(client as never, true, 50, undefined, () => {}, reader)
    : await fetchHistory(client as never, "conversation");
  return messages[0];
}

function signedResponse(signed: Fields, outer: Fields): { raw: Fields; payload: string } {
  const payload = JSON.stringify(signed);
  return { raw: { ...outer, signed_payload: payload, signature: sign(payload) }, payload };
}

describe("displayed fields are bound to the signed claims", () => {
  for (const kind of ["mail", "chat"] as const) {
    const fields = ["body", "message_id", "conversation_id", "from_did", "to_did", ...(kind === "mail" ? ["subject"] : [])];
    for (const field of fields) {
      for (const mode of ["matching", "changed", "absent", "empty_match", "empty_mismatch", "null"] as const) {
        test(`${kind}/${field}/${mode}`, async () => {
          const signed: Fields = { type: kind, body: "body", subject: "subject", message_id: "message", conversation_id: "conversation", from_did: did, to_did: did };
          const outer: Fields = { ...signed };
          let want = "verified";
          if (mode === "changed") {
            outer[field] = "changed";
            want = "failed";
          } else if (mode === "absent") {
            delete signed[field];
            if (field === "conversation_id") want = "verified_legacy";
          } else if (mode === "empty_match") {
            signed[field] = "";
            outer[field] = "";
            if (field === "from_did") want = "unverified";
          } else if (mode === "empty_mismatch") {
            signed[field] = "";
            // An empty recipient-key claim on mail may stand for this reader.
            want = kind === "mail" && field === "to_did" ? "verified" : "failed";
          } else if (mode === "null") {
            signed[field] = null;
            want = "failed";
          }
          const { raw } = signedResponse(signed, outer);
          const message = await read(kind, raw) as unknown as Fields;
          expect(message.verification_status).toBe(want);
          if (want === "failed") {
            for (const name of fields) expect(message[name]).toBe(outer[name]);
          }
        });
      }
    }
  }

  test("a valid signature does not authenticate a different displayed body or message id", async () => {
    const signed = { type: "mail", from_did: did, to_did: did, body: "signed body", message_id: "signed-id", conversation_id: "thread" };
    const { raw } = signedResponse(signed, { message_id: "outer-id", conversation_id: "thread", from_did: did, to_did: did, subject: "", body: "displayed body" });
    const message = await read("mail", raw);
    expect(message.verification_status).toBe("failed");
    expect(message.body).toBe("displayed body");
    expect(message.message_id).toBe("outer-id");
  });

  for (const kind of ["mail", "chat"] as const) {
    for (const field of ["conversation_id", "from_did", "to_did", "body"]) {
      test(`${kind}: a null displayed ${field} is an empty one`, async () => {
        const signed: Fields = { type: kind, body: "body", subject: "subject", message_id: "message", conversation_id: "conversation", from_did: did, to_did: did };
        const { raw } = signedResponse(signed, { ...signed, [field]: null });
        expect((await read(kind, raw)).verification_status).toBe("failed");
        const { raw: unsigned } = signedResponse({ ...signed, [field]: "" }, { ...signed, [field]: null });
        expect((await read(kind, unsigned)).verification_status).toBe(field === "from_did" ? "unverified" : "verified");
      });
    }
  }

  test("a message with no signed payload is verified from its envelope fields", async () => {
    const message = await read("chat", { message_id: "m", conversation_id: "conversation", from_did: did, to_did: did, body: "body", timestamp: "2026-01-01T00:00:00Z" });
    expect(message.verification_status).toBe("unverified");
  });

  test("an encrypted message is not compared with its outer body", async () => {
    const signed = { type: "mail", from_did: did, to_did: did, body: "", message_id: "message", conversation_id: "conversation" };
    const { raw } = signedResponse(signed, { message_id: "message", conversation_id: "conversation", from_did: did, to_did: did, subject: "", body: "ciphertext placeholder", content_mode: "encrypted_v2" });
    expect((await read("mail", raw)).verification_status).toBe("verified");
  });
});

describe("a displayed stable identity stands for the signed key only when it is signed too", () => {
  for (const kind of ["mail", "chat"] as const) {
    for (const side of ["from", "to"] as const) {
      for (const mode of ["signed", "unrelated", "unsigned", "swapped", "changed_body"] as const) {
        test(`${kind}/${side}/${mode}`, async () => {
          const signed: Fields = { type: kind, from_did: did, to_did: did, from_stable_id: "did:aw:sender", to_stable_id: "did:aw:recipient", body: "signed body", conversation_id: "conversation" };
          let outerDID = side === "from" ? "did:aw:sender" : "did:aw:recipient";
          if (mode === "unrelated") outerDID = "did:aw:unrelated";
          if (mode === "unsigned") delete signed[`${side}_stable_id`];
          if (mode === "swapped") outerDID = side === "from" ? "did:aw:recipient" : "did:aw:sender";
          const outer: Fields = { from_did: did, to_did: did, from_stable_id: "did:aw:sender", to_stable_id: "did:aw:recipient", subject: "", body: mode === "changed_body" ? "changed" : "signed body", conversation_id: "conversation" };
          outer[`${side}_did`] = outerDID;
          const { raw } = signedResponse(signed, outer);
          const message = await read(kind, raw) as unknown as Fields;
          expect(message.verification_status).toBe(mode === "signed" ? "verified" : "failed");
          if (mode !== "signed") expect(message[`${side}_did`]).toBe(outerDID);
        });
      }
    }
  }
});

describe("mail to this reader", () => {
  const stable = "did:aw:reader";
  const modes = ["own_key", "own_stable", "other_key", "other_stable", "no_identity", "empty_stable", "null_stable", "number_stable", "other_signed_stable", "null_recipient", "number_recipient", "nonempty_recipient", "empty_sender", "body", "subject", "message_id", "conversation_id", "invalid_signature"] as const;
  for (const mode of modes) {
    test(mode, async () => {
      let identity = { did, stableID: stable };
      const signed: Fields = { type: "mail", from_did: did, to: "reader", to_did: "", body: "body", subject: "subject", message_id: "message", conversation_id: "conversation" };
      const outer: Fields = { from_did: did, to_did: did, body: "body", subject: "subject", message_id: "message", conversation_id: "conversation" };
      if (mode === "own_stable") outer.to_did = stable;
      if (mode === "other_key") outer.to_did = "did:key:other";
      if (mode === "other_stable") outer.to_did = "did:aw:other";
      if (mode === "no_identity") identity = { did: "", stableID: "" };
      if (mode === "empty_stable") signed.to_stable_id = "";
      if (mode === "null_stable") signed.to_stable_id = null;
      if (mode === "number_stable") signed.to_stable_id = 7;
      if (mode === "other_signed_stable") signed.to_stable_id = "did:aw:other";
      if (mode === "null_recipient") signed.to_did = null;
      if (mode === "number_recipient") signed.to_did = 7;
      if (mode === "nonempty_recipient") signed.to_did = "did:key:other";
      if (mode === "empty_sender") signed.from_did = "";
      if (mode === "body" || mode === "subject" || mode === "message_id" || mode === "conversation_id") outer[mode] = "changed";
      const { raw, payload } = signedResponse(signed, outer);
      if (mode === "invalid_signature") raw.signature = Buffer.alloc(64).toString("base64").replace(/=+$/, "");
      const message = await read("mail", raw, identity) as unknown as Fields;
      const accepted = mode === "own_key" || mode === "own_stable";
      expect(message.verification_status).toBe(accepted ? "verified" : "failed");
      expect(message.to_did).toBe(outer.to_did);
      expect(message.body).toBe(outer.body);
      expect(message.message_id).toBe(outer.message_id);
      if (accepted) {
        // The reader's own identity stands for an empty recipient claim on mail only.
        const shown = { type: "mail", from_did: did, to_did: String(outer.to_did), body: "body", subject: "subject", message_id: "message", conversation_id: "conversation" };
        expect(signedDisplayMatches(payload, shown)).toBe(false);
      }
    });
  }
});

describe("dispatched mail", () => {
  const self = { alias: "reader", address: "", did: computeDIDKey(ed.getPublicKey(new Uint8Array(32).fill(7))), stableID: "did:aw:reader" };
  // Reports the status it is given, so the status seen is the one the read produced.
  const trust = { normalizeResolvedTrust: vi.fn(async (_store: unknown, status: unknown) => ({ status, stored: false })) } as unknown as SenderTrustManager;

  async function dispatched(signed: Fields, outer: Fields): Promise<ChannelAwakening> {
    const { raw } = signedResponse(signed, { from_agent_id: "agent", from_alias: "sender", priority: "normal", created_at: "2026-01-01T00:00:00Z", ...outer });
    const client = { get: vi.fn(async () => ({ messages: [{ ...raw }] })), post: vi.fn(async () => undefined) };
    const awoke: ChannelAwakening[] = [];
    await dispatchAgentEvent(
      { client: client as never, pinStore: new PinStore(), trust, self, onAwakening: (a) => { awoke.push(a); }, mailAcknowledgment: "manual" },
      new Set(),
      { type: "mail_message", message_id: String(outer.message_id) },
    );
    expect(awoke).toHaveLength(1);
    return awoke[0];
  }

  const signed = { type: "mail", from_did: did, to: "reader", to_did: "", body: "body", subject: "subject", message_id: "message", conversation_id: "conversation" };
  const outer = { from_did: did, to_did: self.did, body: "body", subject: "subject", message_id: "message", conversation_id: "conversation" };

  test("an empty recipient claim stands for the identity the channel reads as", async () => {
    expect((await dispatched(signed, outer)).meta).toMatchObject({ trust_status: "verified", verified: "true" });
    expect((await dispatched(signed, { ...outer, to_did: self.stableID })).meta).toMatchObject({ trust_status: "verified", verified: "true" });
  });

  test("an empty recipient claim does not stand for another displayed recipient", async () => {
    expect((await dispatched(signed, { ...outer, to_did: did })).meta).toMatchObject({ trust_status: "failed", verified: "false" });
  });

  test("a displayed body the sender did not sign is presented as failed", async () => {
    expect((await dispatched(signed, { ...outer, body: "changed" })).meta).toMatchObject({ trust_status: "failed", verified: "false" });
  });
});
