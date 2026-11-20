import { readFileSync } from "node:fs";
import { expect, test } from "vitest";
import { formatAwakeningForAgent, type ChannelAwakening } from "../src/channel.js";
import { isTrustedVerificationStatus } from "../src/identity/signing.js";
import { presentMessageAwakening } from "../src/message_presentation.js";

interface PresentationCase {
  name: string;
  kind: "mail" | "chat";
  status: string;
  trusted: boolean;
  sender: string;
  presented_sender: string;
  message_id?: string;
  session_id?: string;
  recovery: string;
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
  const input: ChannelAwakening = {
    kind: row.kind,
    content: "private sample body",
    deliveryIntent: "wake",
    meta: {
      from: row.sender,
      subject: "private sample subject",
      responsibility: "opaque projection",
      trust_status: row.status,
      message_id: row.message_id ?? "",
      session_id: row.session_id ?? "",
    },
  };
  expect(isTrustedVerificationStatus(row.status)).toBe(row.trusted);
  const result = presentMessageAwakening(input);
  if (!row.recovery) {
    expect(result).toBe(input);
    return;
  }
  expect(result.meta.from ?? "").toBe(row.presented_sender);
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
