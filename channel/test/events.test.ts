import { describe, expect, test, vi } from "vitest";
import {
  formatEventStreamState,
  streamAgentEvents,
  streamErrorCause,
  type EventStreamState,
} from "@awebai/channel-core";
import { parseAgentEvent } from "../src/api/events.js";

describe("parseAgentEvent", () => {
  test("maps actionable_mail to mail_message", () => {
    expect(
      parseAgentEvent(
        "actionable_mail",
        JSON.stringify({
          type: "actionable_mail",
          message_id: "msg-1",
          conversation_id: "conv-1",
          from_alias: "alice",
        }),
      ),
    ).toEqual({
      type: "mail_message",
      message_id: "msg-1",
      conversation_id: "conv-1",
      from_alias: "alice",
    });
  });

  test("summarizes nested fetch failures without raw TypeError output", () => {
    const error = new TypeError("fetch failed", { cause: Object.assign(new Error("connect ECONNREFUSED"), { code: "ECONNREFUSED" }) });
    const state: EventStreamState = {
      state: "disconnected",
      cause: streamErrorCause(error),
      retryInMs: 5000,
    };

    expect(formatEventStreamState(state)).toBe("aweb: event stream disconnected (connection refused) — retrying in 5s");
    expect(formatEventStreamState(state)).not.toContain("TypeError");
  });

  test("reports one disconnect state and a recovery after steady failed retries", async () => {
    vi.useFakeTimers();
    const states: EventStreamState[] = [];
    const abort = new AbortController();
    let attempts = 0;
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("event: connected\ndata: {}\n\n"));
      },
    });
    const client = {
      openSSE: vi.fn(async () => {
        attempts++;
        if (attempts <= 2) throw new TypeError("fetch failed");
        return new Response(body);
      }),
    };
    const consuming = (async () => {
      for await (const event of streamAgentEvents(client as never, abort.signal, (state) => states.push(state))) {
        if (event.type === "connected") {
          abort.abort();
          break;
        }
      }
    })();
    await vi.waitFor(() => expect(states).toHaveLength(1));

    await vi.advanceTimersByTimeAsync(5000);
    await vi.advanceTimersByTimeAsync(5000);
    await consuming;

    expect(states).toEqual([
      { state: "disconnected", cause: "network unavailable", retryInMs: 5000 },
      { state: "reconnected" },
    ]);
    vi.useRealTimers();
  });

  test("maps actionable_chat to chat_message", () => {
    expect(
      parseAgentEvent(
        "actionable_chat",
        JSON.stringify({
          type: "actionable_chat",
          session_id: "sess-1",
          conversation_id: "sess-1",
          from_alias: "alice",
        }),
      ),
    ).toEqual({
      type: "chat_message",
      session_id: "sess-1",
      conversation_id: "sess-1",
      from_alias: "alice",
    });
  });
});
