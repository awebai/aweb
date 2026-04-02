import { describe, expect, test } from "vitest";
import { parseAgentEvent } from "../src/api/events.js";

describe("parseAgentEvent", () => {
  test("maps actionable_mail to mail_message", () => {
    expect(
      parseAgentEvent(
        "actionable_mail",
        JSON.stringify({ type: "actionable_mail", message_id: "msg-1", from_alias: "alice" }),
      ),
    ).toEqual({
      type: "mail_message",
      message_id: "msg-1",
      from_alias: "alice",
    });
  });

  test("maps actionable_chat to chat_message", () => {
    expect(
      parseAgentEvent(
        "actionable_chat",
        JSON.stringify({ type: "actionable_chat", session_id: "sess-1", from_alias: "alice" }),
      ),
    ).toEqual({
      type: "chat_message",
      session_id: "sess-1",
      from_alias: "alice",
    });
  });
});
