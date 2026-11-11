// A request envelope is signed by the same key that signs an agent's messages,
// and the server receives one with every request. It is not a message: it
// names no type, body or sender. Presented as the signed payload of mail or
// chat with any displayed text, it must not be reported as verified. The cases
// mirror the Go client's (cli/go/awid/request_envelope_as_message_test.go).
import { describe, expect, test } from "vitest";
import { readFileSync } from "node:fs";
import { fetchHistory } from "../src/api/chat.js";
import { fetchInbox } from "../src/api/mail.js";
import { signedDisplayMatches, signedMailDisplayMatches } from "../src/identity/signed_display.js";

interface RequestCase {
  name: string;
  did_key: string;
  canonical_payload: string;
  signature_b64: string;
}

const vector = JSON.parse(
  readFileSync(new URL("../../docs/vectors/team-auth-envelope-v2.json", import.meta.url), "utf8"),
) as { cases: RequestCase[]; identity_cases: RequestCase[] };
const requests = [...vector.cases, ...vector.identity_cases];
const reader = { did: "did:key:reader", stableID: "" };

describe("a signed request envelope is not a verified message", () => {
  test("the vector holds signed request envelopes", () => {
    expect(requests.length).toBeGreaterThan(0);
  });

  for (const request of requests) {
    for (const kind of ["mail", "chat"] as const) {
      test(`${request.name}/${kind}`, async () => {
        const outer = {
          message_id: "message",
          from_did: request.did_key,
          to_did: reader.did,
          subject: "text the sender never wrote",
          body: "text the sender never wrote",
          signed_payload: request.canonical_payload,
          signature: request.signature_b64,
        };
        const client = { get: async () => ({ messages: [{ ...outer }] }) };
        const messages = kind === "mail"
          ? await fetchInbox(client as never, true, 50, undefined, () => {}, reader)
          : await fetchHistory(client as never, "conversation");
        expect(messages[0].verification_status).toBe("failed");
      });
    }
  }
});

const binding = JSON.parse(
  readFileSync(new URL("../../docs/vectors/message-display-binding-v1.json", import.meta.url), "utf8"),
) as {
  required_claims: Record<"mail" | "chat", string[]>;
  signer_shapes: { name: string; kind: "mail" | "chat"; claims: string[] }[];
};

// Whether a reader accepts the displayed fields of a message against a signed
// payload that carries the given claims, each displayed field being the signed one.
function signerShapeMatchesDisplay(kind: "mail" | "chat", claims: string[], without = ""): boolean {
  const sender = "did:key:sender";
  const value: Record<string, string> = {
    type: kind, from_did: sender, to_did: reader.did,
    from_stable_id: "did:aw:sender", to_stable_id: "did:aw:reader",
  };
  const signed: Record<string, string> = {};
  for (const name of claims) {
    if (name !== without) signed[name] = value[name] ?? name;
  }
  const payload = JSON.stringify(signed);
  const displayed = {
    type: kind, body: "body", message_id: "message_id",
    conversation_id: signed.conversation_id, from_did: sender, to_did: reader.did,
  };
  return kind === "mail"
    ? signedMailDisplayMatches(payload, { ...displayed, subject: "subject" }, reader)
    : signedDisplayMatches(payload, displayed);
}

describe("the claims that make a signed payload a message", () => {
  test("the vector holds signer shapes and required claims", () => {
    expect(binding.signer_shapes.length).toBeGreaterThan(0);
    expect(binding.required_claims.mail.length).toBeGreaterThan(0);
    expect(binding.required_claims.chat.length).toBeGreaterThan(0);
  });

  for (const shape of binding.signer_shapes) {
    test(`a released signer's payload matches its display: ${shape.name}`, () => {
      expect(signerShapeMatchesDisplay(shape.kind, shape.claims)).toBe(true);
    });
    for (const claim of binding.required_claims[shape.kind]) {
      test(`a payload without ${claim} does not match its display: ${shape.name}`, () => {
        expect(signerShapeMatchesDisplay(shape.kind, shape.claims, claim)).toBe(false);
      });
    }
  }
});
