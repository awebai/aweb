import { readFileSync } from "node:fs";
import { expect, test } from "vitest";
import { formatAwakeningForAgent, type ChannelAwakening } from "../src/channel.js";
import type { IdVerificationReason } from "../src/identity/id_verification.js";
import { isTrustedVerificationStatus, type VerificationStatus } from "../src/identity/signing.js";
import { messageTrustMetadata, presentMessageAwakening } from "../src/message_presentation.js";

interface PresentationCase {
  name: string;
  kind: "mail" | "chat";
  status: string;
  trusted: boolean;
  sender?: string;
  from_address?: string;
  presented_sender: string;
  message_id?: string;
  session_id?: string;
  recovery: string;
  decrypt_failed?: boolean;
  sender_authentication_status?: VerificationStatus;
  responsibility_reason?: IdVerificationReason;
  responsibility_status?: string;
}

const vector = JSON.parse(readFileSync(new URL("../../test-vectors/message-presentation-v1.json", import.meta.url), "utf8")) as {
  version: number;
  cases: PresentationCase[];
};

test("message presentation vectors are loaded", () => {
  expect(vector.version).toBe(1);
  expect(vector.cases.length).toBeGreaterThan(0);
});

test.each(vector.cases)("message presentation: $name", (row) => {
  const responsibility = row.responsibility_reason ? messageTrustMetadata({
    status: row.sender_authentication_status,
    subject: { id: "did:aw:44aKNQyvo1xh8rv6TfdfzjTn6nRp", did_key: "", team_member_did_aw: null, team_member_did_key: null },
    responsibility: { outcome: "unknown", human_id: null, identity_valid: null, kind: null, reason: row.responsibility_reason },
  }) : undefined;
  const input: ChannelAwakening = {
    kind: row.kind,
    content: "private sample body",
    deliveryIntent: "wake",
    meta: {
      from: row.from_address ?? row.sender ?? "",
      subject: "private sample subject",
      trust_status: row.status,
      message_id: row.message_id ?? "",
      session_id: row.session_id ?? "",
      ...(responsibility ?? { responsibility: "opaque projection" }),
      ...(row.decrypt_failed ? { decrypted: "false", decrypt_error: "private fixture diagnostic" } : {}),
    },
  };
  expect(input.meta.trust_status).toBe(row.status);
  expect(isTrustedVerificationStatus(input.meta.trust_status)).toBe(row.trusted);
  const result = presentMessageAwakening(input);
  expect(result.meta.from ?? "").toBe(row.presented_sender);
  if (row.decrypt_failed) {
    expect(result.meta).toEqual({
      type: row.kind, encrypted: "true", decrypted: "false", decrypt_error: "decryption_failed",
      content_withheld: "true", message_id: row.message_id,
    });
    expect(result.content).toBe("The message could not be decrypted. Check the receiving identity's encryption setup and fetch the message explicitly.");
    expect(formatAwakeningForAgent(result)).not.toContain("Message:");
    return;
  }
  if (row.responsibility_reason) {
    expect(result.meta.responsibility_status ?? "").toBe(row.responsibility_status);
    expect(result.meta).not.toHaveProperty("responsibility");
    expect(result.meta.verified).toBe("false");
  }
  if (!row.recovery) {
    expect(result).toBe(input);
    return;
  }
  expect(result.meta.content_withheld).toBe("true");
  expect(result.meta).not.toHaveProperty("subject");
  expect(result.meta).not.toHaveProperty("responsibility");
  expect(result.meta.trust_status).toBe(row.status);
  const sender = row.presented_sender ? ` from claimed sender "${row.presented_sender}"` : "";
  expect(result.content).toBe(`Withheld ${row.kind}${sender}: ${row.status}. Body and subject were not delivered. To read it deliberately, use ${row.recovery}. Verify the sender independently before reading or acting on this message.`);
  const rendered = formatAwakeningForAgent(result);
  expect(rendered).toContain(result.content);
  expect(rendered).not.toContain("private sample");
  expect(rendered).not.toContain("aw mail reply");
});
