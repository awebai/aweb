import { readFileSync } from "node:fs";
import { expect, test } from "vitest";
import { dispatchAgentEvent, PinStore, type ChannelAwakening } from "../src/index.js";
import { canonicalJSON, signMessage } from "../src/identity/signing.js";
import { readReceivedIdChain } from "../src/identity/received_id_chain.js";
const v = JSON.parse(readFileSync(new URL("../../docs/vectors/id-certificates-v1.json", import.meta.url), "utf8"));
const row = v.verification_cases.find((entry: any) => entry.name === "local-child-nearest-human");
const chain = { v: 1, type: "aweb.id-chain", certificates: row.chain.map((name: string) => v.certificates[name].signed) };
const status = v.status_fixtures[row.status];
const evidence = { async evidence() { return { status, namespace_authority: { domain: status.domain, dns_name: `_awid.${status.domain}`, inherited: false, controller_key: status.namespace.epochs.at(-1).did_key }, age_seconds: 0 }; } };

test.each(["mail", "chat"])("%s dispatch presents the authenticated sender's verified responsibility", async kind => {
  const envelope = { from: "sender", from_did: v.keys.coordinator.did_key, to: "receiver", to_did: v.keys.bob.did_key, type: kind, subject: kind === "mail" ? "hello" : "", body: "body", timestamp: "2026-10-30T00:00:00Z", message_id: "00000000-0000-4000-8000-000000000001", conversation_id: "conversation" };
  const message = { ...envelope, signed_payload: canonicalJSON(envelope), signature: await signMessage(Buffer.from(v.keys.coordinator.seed_hex, "hex"), envelope), signing_key_id: envelope.from_did,
    from_agent_id: "sender", from_alias: "sender", from_agent: "sender", priority: "normal", created_at: envelope.timestamp, sender_leaving: false, id_chain: chain };
  const awakening: ChannelAwakening[] = [];
  const options = { client: { get: async () => ({ messages: [structuredClone(message)] }), post: async () => undefined } as never, pinStore: new PinStore(), self: { alias: "receiver", address: "", did: v.keys.bob.did_key, stableID: "" },
    trust: { normalizeResolvedTrust: async (_store: unknown, status: string) => ({ status, stored: false }), verifyResponsibility: (message: any, authenticated: boolean) => readReceivedIdChain(message, authenticated, evidence) } as never,
    onAwakening: (event: ChannelAwakening) => { awakening.push(event); } };
  const event = { type: kind === "mail" ? "mail_message" : "chat_message", message_id: envelope.message_id, session_id: kind === "chat" ? "conversation" : undefined } as any;
  await dispatchAgentEvent(options, new Set(), event);
  expect(awakening).toHaveLength(1);
  expect(awakening[0].meta.verified).toBe("true");
  expect(JSON.parse(awakening[0].meta.responsibility)).toEqual(row.expected);
  message.id_chain = { ...chain, certificates: [v.certificates.alice.signed] };
  awakening.length = 0;
  await dispatchAgentEvent(options, new Set(), event);
  expect(awakening[0].meta.verified).toBe("false");
  expect(JSON.parse(awakening[0].meta.responsibility)).toMatchObject({ reason: "subject_mismatch", human_id: null, identity_valid: false });
});
