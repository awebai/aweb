// A request envelope is signed by the same key that signs an agent's messages,
// and the server receives one with every request. It is not a message: it
// names no type, body or sender. Presented as the signed payload of mail or
// chat with any displayed text, it must not be reported as verified. The cases
// mirror the Go client's (cli/go/awid/request_envelope_as_message_test.go).
import { describe, expect, test } from "vitest";
import { readFileSync } from "node:fs";
import { fetchHistory } from "../src/api/chat.js";
import { fetchInbox } from "../src/api/mail.js";

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
