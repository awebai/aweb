import { beforeEach, describe, expect, test, vi } from "vitest";
import type { APIClient } from "../src/api/client.js";

const { fetchInbox, fetchPending } = vi.hoisted(() => ({
  fetchInbox: vi.fn(),
  fetchPending: vi.fn(),
}));

vi.mock("../src/api/mail.js", async () => {
  const actual = await vi.importActual<typeof import("../src/api/mail.js")>("../src/api/mail.js");
  return {
    ...actual,
    fetchInbox,
  };
});

vi.mock("../src/api/chat.js", async () => {
  const actual = await vi.importActual<typeof import("../src/api/chat.js")>("../src/api/chat.js");
  return {
    ...actual,
    fetchPending,
  };
});

import { TOOL_DEFINITIONS, handleToolCall } from "../src/tools.js";

const client = {} as APIClient;
const signing = {
  seed: null,
  did: "",
  stableID: "",
  alias: "eve",
  projectSlug: "demo",
};

describe("TOOL_DEFINITIONS", () => {
  test("registers mail_inbox and chat_pending", () => {
    expect(TOOL_DEFINITIONS.map((tool) => tool.name)).toEqual(
      expect.arrayContaining(["mail_inbox", "chat_pending"]),
    );
  });
});

describe("handleToolCall", () => {
  beforeEach(() => {
    fetchInbox.mockReset();
    fetchPending.mockReset();
  });

  test("mail_inbox returns unread messages", async () => {
    fetchInbox.mockResolvedValue([
      {
        message_id: "msg-1",
        from_agent_id: "agent-1",
        from_alias: "dave",
        subject: "epic briefing",
        body: "start here",
        priority: "high",
        created_at: "2026-04-02T00:00:00Z",
      },
    ]);

    const result = await handleToolCall("mail_inbox", {}, client, signing);

    expect(fetchInbox).toHaveBeenCalledWith(client, true);
    expect(result).toEqual({
      content: [{
        type: "text",
        text: JSON.stringify([{
          from: "dave",
          subject: "epic briefing",
          body: "start here",
          priority: "high",
          message_id: "msg-1",
        }], null, 2),
      }],
    });
  });

  test("chat_pending returns pending conversations", async () => {
    fetchPending.mockResolvedValue([
      {
        session_id: "chat-1",
        participants: ["dave", "eve"],
        last_message: "need your answer",
        last_from: "dave",
        unread_count: 2,
        last_activity: "2026-04-02T00:00:00Z",
        sender_waiting: true,
      },
    ]);

    const result = await handleToolCall("chat_pending", {}, client, signing);

    expect(fetchPending).toHaveBeenCalledWith(client);
    expect(result).toEqual({
      content: [{
        type: "text",
        text: JSON.stringify([{
          session_id: "chat-1",
          participants: ["dave", "eve"],
          unread_count: 2,
          sender_waiting: true,
          last_message: "need your answer",
        }], null, 2),
      }],
    });
  });
});
