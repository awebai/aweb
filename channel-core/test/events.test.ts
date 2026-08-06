import { getEventListeners } from "node:events";
import { describe, expect, test, vi } from "vitest";
import {
  formatEventStreamState,
  streamAgentEvents,
  streamErrorCause,
  type EventStreamState,
} from "../src/index.js";
import {
  EVENT_STREAM_DEADLINE_MS,
  EVENT_STREAM_INACTIVITY_MS,
  EVENT_STREAM_SERVER_HEARTBEAT_MS,
  parseAgentEvent,
} from "../src/api/events.js";

function sseFrame(event: string, payload: object): Uint8Array {
  return new TextEncoder().encode(
    `event: ${event}\ndata: ${JSON.stringify(payload)}\n\n`,
  );
}

function sseComment(): Uint8Array {
  return new TextEncoder().encode(": keepalive\n\n");
}

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

  test("backs off early-EOF flaps without claiming recovery", async () => {
    vi.useFakeTimers();
    const states: EventStreamState[] = [];
    const abort = new AbortController();
    let attempts = 0;
    const client = {
      openSSE: vi.fn(async () => {
        attempts++;
        return new Response(new ReadableStream<Uint8Array>({
          start(controller) {
            controller.close();
          },
        }));
      }),
    };
    const consuming = (async () => {
      for await (const _event of streamAgentEvents(client as never, abort.signal, (state) => states.push(state))) {
        // Empty streams must not yield or prove recovery.
      }
    })();

    await vi.waitFor(() => expect(states).toHaveLength(1));
    expect(attempts).toBe(1);
    expect(states).toEqual([
      { state: "disconnected", cause: "connection closed", retryInMs: 1000 },
    ]);
    await vi.advanceTimersByTimeAsync(500);
    expect(attempts).toBe(1);
    await vi.advanceTimersByTimeAsync(600);
    await vi.waitFor(() => expect(attempts).toBe(2));
    expect(states.some((state) => state.state === "reconnected")).toBe(false);

    abort.abort();
    await vi.runAllTimersAsync();
    await consuming;
    vi.useRealTimers();
  });

  test("reconnects a permanently half-open stream within the inactivity bound and catches the durable snapshot", async () => {
    vi.useFakeTimers();
    const states: EventStreamState[] = [];
    const received: string[] = [];
    const abort = new AbortController();
    let attempts = 0;
    let firstCancelled = 0;
    const client = {
      openSSE: vi.fn(async () => {
        attempts++;
        if (attempts === 1) {
          return new Response(new ReadableStream<Uint8Array>({
            start(controller) {
              controller.enqueue(sseFrame("connected", {}));
            },
            cancel() {
              firstCancelled++;
            },
          }));
        }
        return new Response(new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(sseFrame("connected", {}));
            controller.enqueue(sseFrame("actionable_chat", {
              session_id: "durable-session",
              conversation_id: "durable-session",
            }));
          },
        }));
      }),
    };
    const consuming = (async () => {
      for await (const event of streamAgentEvents(
        client as never,
        abort.signal,
        (state) => states.push(state),
      )) {
        received.push(event.type);
        if (event.type === "chat_message") {
          abort.abort();
          break;
        }
      }
    })();

    await vi.waitFor(() => expect(received).toEqual(["connected"]));
    await vi.advanceTimersByTimeAsync(EVENT_STREAM_INACTIVITY_MS);
    await vi.waitFor(() => expect(states.at(-1)?.state).toBe("disconnected"));
    expect(attempts).toBe(1);
    await vi.advanceTimersByTimeAsync(1000);
    await consuming;

    expect(attempts).toBe(2);
    expect(firstCancelled).toBe(1);
    expect(received).toEqual(["connected", "connected", "chat_message"]);
    expect(states.map((state) => state.state)).toEqual([
      "connected", "disconnected", "reconnected",
    ]);
    await vi.advanceTimersByTimeAsync(EVENT_STREAM_DEADLINE_MS * 2);
    expect(attempts).toBe(2);
    vi.useRealTimers();
  });

  test("counts SSE comments as liveness on a healthy idle stream", async () => {
    vi.useFakeTimers();
    const abort = new AbortController();
    let streamController: ReadableStreamDefaultController<Uint8Array> | undefined;
    let attempts = 0;
    const client = {
      openSSE: vi.fn(async () => {
        attempts++;
        return new Response(new ReadableStream<Uint8Array>({
          start(controller) {
            streamController = controller;
            controller.enqueue(sseFrame("connected", {}));
          },
        }));
      }),
    };
    const consuming = (async () => {
      for await (const _event of streamAgentEvents(client as never, abort.signal)) {
        // Heartbeat comments are liveness bytes, not agent events.
      }
    })();

    await vi.waitFor(() => expect(streamController).toBeDefined());
    for (let elapsed = 0; elapsed < EVENT_STREAM_DEADLINE_MS / 2;
      elapsed += EVENT_STREAM_SERVER_HEARTBEAT_MS) {
      await vi.advanceTimersByTimeAsync(EVENT_STREAM_SERVER_HEARTBEAT_MS);
      streamController!.enqueue(sseComment());
      await Promise.resolve();
      expect(attempts).toBe(1);
    }

    abort.abort();
    await vi.runAllTimersAsync();
    await consuming;
    expect(attempts).toBe(1);
    vi.useRealTimers();
  });

  test("local absolute deadline caps a stream that sends endless heartbeat comments", async () => {
    vi.useFakeTimers();
    const states: EventStreamState[] = [];
    const abort = new AbortController();
    let streamController: ReadableStreamDefaultController<Uint8Array> | undefined;
    let attempts = 0;
    const received: string[] = [];
    const client = {
      openSSE: vi.fn(async () => {
        attempts++;
        if (attempts === 1) {
          return new Response(new ReadableStream<Uint8Array>({
            start(controller) {
              streamController = controller;
              controller.enqueue(sseFrame("connected", {}));
            },
          }));
        }
        return new Response(new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(sseFrame("connected", {}));
            controller.enqueue(sseFrame("actionable_mail", {
              message_id: "deadline-catch-up",
              conversation_id: "deadline-conversation",
            }));
          },
        }));
      }),
    };
    const consuming = (async () => {
      for await (const event of streamAgentEvents(
        client as never,
        abort.signal,
        (state) => states.push(state),
      )) {
        received.push(event.type);
        if (event.type === "mail_message") {
          abort.abort();
          break;
        }
      }
    })();

    await vi.waitFor(() => expect(received).toEqual(["connected"]));
    for (let elapsed = 0;
      elapsed < EVENT_STREAM_DEADLINE_MS - EVENT_STREAM_SERVER_HEARTBEAT_MS;
      elapsed += EVENT_STREAM_SERVER_HEARTBEAT_MS) {
      await vi.advanceTimersByTimeAsync(EVENT_STREAM_SERVER_HEARTBEAT_MS);
      streamController!.enqueue(sseComment());
      await Promise.resolve();
      expect(attempts).toBe(1);
    }
    await vi.advanceTimersByTimeAsync(EVENT_STREAM_SERVER_HEARTBEAT_MS);
    await consuming;

    expect(attempts).toBe(2);
    expect(received).toEqual(["connected", "connected", "mail_message"]);
    expect(states.map((state) => state.state)).toEqual(["connected"]);
    vi.useRealTimers();
  });

  test("cleans the losing inactivity timer when EOF races the watchdog", async () => {
    vi.useFakeTimers();
    const states: EventStreamState[] = [];
    const abort = new AbortController();
    let firstController: ReadableStreamDefaultController<Uint8Array> | undefined;
    let attempts = 0;
    const client = {
      openSSE: vi.fn(async () => {
        attempts++;
        return new Response(new ReadableStream<Uint8Array>({
          start(controller) {
            if (attempts === 1) firstController = controller;
            controller.enqueue(sseFrame("connected", {}));
          },
        }));
      }),
    };
    const consuming = (async () => {
      for await (const _event of streamAgentEvents(
        client as never,
        abort.signal,
        (state) => states.push(state),
      )) {
        // Keep consuming until the one expected reconnect is established.
      }
    })();

    await vi.waitFor(() => expect(firstController).toBeDefined());
    await vi.advanceTimersByTimeAsync(EVENT_STREAM_INACTIVITY_MS - 1);
    firstController!.close();
    await vi.advanceTimersByTimeAsync(1001);
    await vi.waitFor(() => expect(attempts).toBe(2));
    await vi.advanceTimersByTimeAsync(5000);
    expect(attempts).toBe(2);
    expect(states.map((state) => state.state)).toEqual([
      "connected", "disconnected", "reconnected",
    ]);

    abort.abort();
    await vi.runAllTimersAsync();
    await consuming;
    vi.useRealTimers();
  });

  test("keeps parent abort listeners bounded across repeated watchdog backoffs", async () => {
    vi.useFakeTimers();
    const abort = new AbortController();
    let attempts = 0;
    let connectedEvents = 0;
    const client = {
      openSSE: vi.fn(async () => {
        attempts++;
        return new Response(new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(sseFrame("connected", {}));
          },
        }));
      }),
    };
    const consuming = (async () => {
      for await (const event of streamAgentEvents(client as never, abort.signal)) {
        if (event.type === "connected") connectedEvents++;
      }
    })();

    await vi.waitFor(() => expect(connectedEvents).toBe(1));
    const activeListenerCount = getEventListeners(abort.signal, "abort").length;
    expect(activeListenerCount).toBeGreaterThan(0);
    for (let cycle = 0; cycle < 11; cycle++) {
      await vi.advanceTimersByTimeAsync(EVENT_STREAM_INACTIVITY_MS);
      await vi.advanceTimersByTimeAsync(1000);
      await vi.waitFor(() => expect(connectedEvents).toBe(cycle + 2));
    }

    expect(attempts).toBe(12);
    expect(getEventListeners(abort.signal, "abort")).toHaveLength(activeListenerCount);
    abort.abort();
    await vi.runAllTimersAsync();
    await consuming;
    expect(getEventListeners(abort.signal, "abort")).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(EVENT_STREAM_DEADLINE_MS * 2);
    expect(attempts).toBe(12);
    vi.useRealTimers();
  });

  test("preserves immediate planned-EOF reconnect without a false outage state", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-05T00:00:00Z"));
    const states: EventStreamState[] = [];
    const abort = new AbortController();
    let firstController: ReadableStreamDefaultController<Uint8Array> | undefined;
    let attempts = 0;
    const client = {
      openSSE: vi.fn(async () => {
        attempts++;
        return new Response(new ReadableStream<Uint8Array>({
          start(controller) {
            if (attempts === 1) firstController = controller;
            controller.enqueue(sseFrame("connected", {}));
            if (attempts === 2) {
              controller.enqueue(sseFrame("actionable_chat", {
                session_id: "planned-catch-up",
                conversation_id: "planned-catch-up",
              }));
            }
          },
        }));
      }),
    };
    const consuming = (async () => {
      for await (const event of streamAgentEvents(
        client as never,
        abort.signal,
        (state) => states.push(state),
      )) {
        if (event.type === "connected" && attempts === 1) {
          vi.setSystemTime(Date.now() + 4 * 60 * 1000);
          firstController!.close();
        }
        if (event.type === "chat_message") {
          abort.abort();
          break;
        }
      }
    })();

    await consuming;
    expect(attempts).toBe(2);
    expect(states.map((state) => state.state)).toEqual(["connected"]);
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
