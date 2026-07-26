import { describe, expect, test, vi } from "vitest";

import { markRead } from "../src/api/chat.js";

const messageIds = (count: number): string[] => (
  Array.from({ length: count }, (_, index) => `message-${index}`)
);

describe("chat mark-read batching", () => {
  test("sends exactly 1000 presented IDs in one request", async () => {
    const client = { post: vi.fn().mockResolvedValue(undefined) };
    const ids = messageIds(1000);

    await markRead(client as never, "session-1", ids);

    expect(client.post).toHaveBeenCalledTimes(1);
    expect(client.post).toHaveBeenCalledWith(
      "/v1/chat/sessions/session-1/read",
      { message_ids: ids },
    );
  });

  test("sends 1001 presented IDs as 1000 plus 1", async () => {
    const client = { post: vi.fn().mockResolvedValue(undefined) };
    const ids = messageIds(1001);

    await markRead(client as never, "session-1", ids);

    expect(client.post).toHaveBeenCalledTimes(2);
    expect(client.post).toHaveBeenNthCalledWith(
      1,
      "/v1/chat/sessions/session-1/read",
      { message_ids: ids.slice(0, 1000) },
    );
    expect(client.post).toHaveBeenNthCalledWith(
      2,
      "/v1/chat/sessions/session-1/read",
      { message_ids: ids.slice(1000) },
    );
  });

  test("reports partial progress and stops when a later chunk fails", async () => {
    const client = {
      post: vi.fn()
        .mockResolvedValueOnce(undefined)
        .mockRejectedValueOnce(new Error("aweb: http 503: unavailable")),
    };
    const ids = messageIds(2001);

    await expect(markRead(client as never, "session-1", ids)).rejects.toThrow(
      "aweb: marked 1000 of 2001 presented chat messages; next mark-read chunk failed: aweb: http 503: unavailable",
    );
    expect(client.post).toHaveBeenCalledTimes(2);
    expect(client.post).toHaveBeenNthCalledWith(
      2,
      "/v1/chat/sessions/session-1/read",
      { message_ids: ids.slice(1000, 2000) },
    );
  });
});
