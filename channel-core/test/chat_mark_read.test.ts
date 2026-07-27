import { describe, expect, test, vi } from "vitest";

import { markRead } from "../src/api/chat.js";
import { APIError } from "../src/api/client.js";

const messageIds = (count: number): string[] => (
  Array.from(
    { length: count },
    (_, index) => `00000000-0000-4000-8000-${index.toString(16).padStart(12, "0")}`,
  )
);

const legacyShapeError = (): APIError => new APIError(422, JSON.stringify({
  detail: [
    { type: "missing", loc: ["body", "up_to_message_id"], msg: "Field required" },
    { type: "extra_forbidden", loc: ["body", "message_ids"], msg: "Extra inputs are not permitted" },
  ],
}));

describe("chat mark-read batching", () => {
  test("rejects an empty presented set without making a request", async () => {
    const client = { post: vi.fn().mockResolvedValue(undefined) };

    await expect(markRead(client as never, "session-1", [])).rejects.toThrow(
      "aweb: cannot mark chat read without presented message IDs",
    );
    expect(client.post).not.toHaveBeenCalled();
  });

  test("uses one exact-ID request for a full chunk on a new server", async () => {
    const client = { post: vi.fn().mockResolvedValue(undefined) };
    const ids = messageIds(1000);

    await markRead(client as never, "session-1", ids);

    expect(client.post).toHaveBeenCalledTimes(1);
    expect(client.post).toHaveBeenCalledWith(
      "/v1/chat/sessions/session-1/read",
      { message_ids: ids },
    );
  });

  test("old-server fallback deliberately marks an unpresented gap by watermark", async () => {
    const [first, unpresented, last] = messageIds(3);
    const available = [first, unpresented, last];
    const presented = [first, last];
    const read = new Set<string>();
    const client = {
      post: vi.fn().mockImplementation(async (_path: string, body: Record<string, unknown>) => {
        if ("message_ids" in body) throw legacyShapeError();
        const watermark = body.up_to_message_id;
        if (typeof watermark !== "string") throw new Error("watermark required");
        const end = available.indexOf(watermark);
        if (end < 0) throw new Error("unknown watermark");
        for (const id of available.slice(0, end + 1)) read.add(id);
      }),
    };

    await markRead(client as never, "session-old", presented);

    // Accepted old-client-equivalent behavior: an old server only understands
    // a range watermark, so the unpresented middle message is also marked read.
    expect(read).toEqual(new Set(available));
    expect(read.has(unpresented)).toBe(true);
    expect(client.post).toHaveBeenCalledTimes(2);
    expect(client.post).toHaveBeenNthCalledWith(
      1,
      "/v1/chat/sessions/session-old/read",
      { message_ids: presented },
    );
    expect(client.post).toHaveBeenNthCalledWith(
      2,
      "/v1/chat/sessions/session-old/read",
      { up_to_message_id: last },
    );
  });

  test("falls back by 4xx status when an old server returns an unmeasured error shape", async () => {
    const ids = messageIds(2);
    const unread = new Set(ids);
    const client = {
      post: vi.fn().mockImplementation(async (_path: string, body: Record<string, unknown>) => {
        if ("message_ids" in body) {
          throw new APIError(422, "<html>validation response rewritten by proxy</html>");
        }
        const watermark = body.up_to_message_id as string;
        for (const id of ids.slice(0, ids.indexOf(watermark) + 1)) unread.delete(id);
      }),
    };

    await markRead(client as never, "session-variant", ids);

    expect(unread).toEqual(new Set());
    expect(client.post).toHaveBeenCalledTimes(2);
  });

  test("malformed exact IDs still reach the server but do not trigger fallback", async () => {
    const malformedID = new APIError(422, JSON.stringify({
      detail: [{ type: "uuid_parsing", loc: ["body", "message_ids", 0] }],
    }));
    const client = { post: vi.fn().mockRejectedValue(malformedID) };

    await expect(markRead(client as never, "session-1", ["not-a-uuid"])).rejects.toThrow(
      "next mark-read chunk failed: aweb: http 422",
    );
    expect(client.post).toHaveBeenCalledTimes(1);
    expect(client.post).toHaveBeenCalledWith(
      "/v1/chat/sessions/session-1/read",
      { message_ids: ["not-a-uuid"] },
    );
  });

  test("surfaces the original 4xx when its single fallback also fails", async () => {
    const original = new APIError(403, "permission denied");
    const client = {
      post: vi.fn()
        .mockRejectedValueOnce(original)
        .mockRejectedValueOnce(new APIError(422, "fallback rejected")),
    };

    await expect(markRead(client as never, "session-1", messageIds(1))).rejects.toThrow(
      "aweb: marked 0 of 1 presented chat messages; next mark-read chunk failed: aweb: http 403: permission denied",
    );
    expect(client.post).toHaveBeenCalledTimes(2);
    expect(client.post).toHaveBeenNthCalledWith(
      2,
      "/v1/chat/sessions/session-1/read",
      { up_to_message_id: messageIds(1)[0] },
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

  test("preserves partial progress when a later old-server fallback fails", async () => {
    const ids = messageIds(2001);
    const read = new Set<string>();
    let fallbackCount = 0;
    const client = {
      post: vi.fn().mockImplementation(async (_path: string, body: Record<string, unknown>) => {
        if ("message_ids" in body) throw new APIError(422, "old server rejected exact IDs");
        fallbackCount += 1;
        if (fallbackCount === 2) throw new APIError(503, "unavailable");
        const watermark = body.up_to_message_id as string;
        for (const id of ids.slice(0, ids.indexOf(watermark) + 1)) read.add(id);
      }),
    };

    await expect(markRead(client as never, "session-1", ids)).rejects.toThrow(
      "aweb: marked 1000 of 2001 presented chat messages; next mark-read chunk failed: aweb: http 422: old server rejected exact IDs",
    );
    expect(read).toEqual(new Set(ids.slice(0, 1000)));
    expect(client.post).toHaveBeenCalledTimes(4);
    expect(client.post).toHaveBeenNthCalledWith(
      4,
      "/v1/chat/sessions/session-1/read",
      { up_to_message_id: ids[1999] },
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
