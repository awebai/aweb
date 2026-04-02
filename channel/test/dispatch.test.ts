import { describe, expect, test, vi } from "vitest";
import type { AgentEvent } from "../src/api/events.js";
import { PinStore } from "../src/identity/pinstore.js";
import { dispatchEvent } from "../src/index.js";

describe("dispatchEvent", () => {
  test("notifies claim_update events", async () => {
    const notification = vi.fn();
    const mcp = { notification } as unknown as { notification: typeof notification };

    await dispatchEvent(
      mcp as never,
      {} as never,
      new PinStore(),
      "eve",
      new Set(),
      {
        type: "claim_update",
        task_id: "aweb-aabz.2",
        title: "Add chat_pending and mail_inbox tools to channel",
        status: "claimed",
      } satisfies AgentEvent,
    );

    expect(notification).toHaveBeenCalledWith({
      method: "notifications/claude/channel",
      params: {
        content: "Add chat_pending and mail_inbox tools to channel",
        meta: {
          type: "claim",
          task_id: "aweb-aabz.2",
          title: "Add chat_pending and mail_inbox tools to channel",
          status: "claimed",
        },
      },
    });
  });

  test("notifies claim_removed events", async () => {
    const notification = vi.fn();
    const mcp = { notification } as unknown as { notification: typeof notification };

    await dispatchEvent(
      mcp as never,
      {} as never,
      new PinStore(),
      "eve",
      new Set(),
      {
        type: "claim_removed",
        task_id: "aweb-aabz.2",
      } satisfies AgentEvent,
    );

    expect(notification).toHaveBeenCalledWith({
      method: "notifications/claude/channel",
      params: {
        content: "",
        meta: {
          type: "claim_removed",
          task_id: "aweb-aabz.2",
        },
      },
    });
  });
});
