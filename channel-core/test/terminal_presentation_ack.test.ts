import { describe, expect, test, vi } from "vitest";
import {
  createTerminalAwakeningHandler, consumeAgentEvents, dispatchAgentEvent, PinStore,
  type SenderTrustManager,
} from "../src/index.js";

const messageID = "12345678-1234-1234-1234-123456789abc";
const sessionID = "87654321-4321-4321-4321-cba987654321";

function fixture(kind: "mail" | "chat", state: string | (() => string), input: (home: string, text: string) => Promise<void>) {
  const client = {
    get: vi.fn().mockResolvedValue({ messages: [{
      message_id: messageID, from_alias: "alice", from_agent: "alice", from_address: "acme.com/alice",
      subject: "full message", body: "hello\x1b[31m\r\nactual\x07\x9b body\tend",
      created_at: "2026-01-01T00:00:00Z", timestamp: "2026-01-01T00:00:00Z",
    }] }),
    post: vi.fn().mockResolvedValue(undefined),
  };
  const options = {
    client: client as never, pinStore: new PinStore(),
    trust: { normalizeResolvedTrust: vi.fn(async () => ({ status: "verified", stored: false })) } as unknown as SenderTrustManager,
    self: { alias: "eve", address: "acme.com/eve", did: "did:key:self", stableID: "" },
    onAwakening: createTerminalAwakeningHandler({ home: "/agent", session: { inspect: async () => ({ present: true, state: typeof state === "function" ? state() : state }), input } }),
    mailAcknowledgment: "delivery" as const,
  };
  return { client, options, deliver: () => dispatchAgentEvent(options, new Set(), { type: kind === "mail" ? "mail_message" : "chat_message", message_id: messageID, session_id: sessionID }) };
}

describe.each(["mail", "chat"] as const)("terminal %s presentation acknowledgment", (kind) => {
  test.each(["idle", "working", "unknown"])("%s delivers full sanitized text and acknowledges only accepted input", async (state) => {
    let accept!: () => void;
    const accepted = new Promise<void>((resolve) => { accept = resolve; });
    const input = vi.fn(async (_home: string, _text: string) => accepted);
    const { client, deliver } = fixture(kind, state, input);
    const pending = deliver();
    void pending.catch(() => {});
    try {
      await vi.waitFor(() => expect(input).toHaveBeenCalledOnce());
      const text = input.mock.calls[0][1];
      expect(text).toContain(`aweb ${kind} event received.`);
      expect(text).toContain("from: acme.com/alice");
      expect(text).toContain("trust_status: verified");
      expect(text).toContain("hello[31m\nactual body\tend");
      expect(text).not.toMatch(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F\u0080-\u009F]/);
      expect(text).not.toContain("waiting — run");
      expect(client.post).not.toHaveBeenCalled();
    } finally {
      accept();
      await pending;
    }
    if (kind === "mail") expect(client.post).toHaveBeenCalledWith(`/v1/messages/${messageID}/ack`);
    else expect(client.post).toHaveBeenCalledWith(`/v1/chat/sessions/${sessionID}/read`, { message_ids: [messageID] });
  });

  test.each(["idle", "unknown"])("blocked remains unmarked and unread until a later %s snapshot", async (nextState) => {
    vi.useFakeTimers();
    try {
      let state = "blocked";
      const input = vi.fn(async () => {});
      const { client, options } = fixture(kind, () => state, input);
      const onTrace = vi.fn();
      const dispatched = new Set<string>();
      const event = { type: kind === "mail" ? "mail_message" : "chat_message", message_id: messageID, session_id: sessionID };
      const snapshot = () => consumeAgentEvents({ ...options, onTrace }, dispatched, (async function* () { yield event; })());
      const refused = snapshot();
      await vi.advanceTimersByTimeAsync(850);
      await refused;
      expect(client.get).toHaveBeenCalledTimes(4);
      expect(input).not.toHaveBeenCalled();
      expect(client.post).not.toHaveBeenCalled();
      expect(dispatched.size).toBe(0);
      const stages = onTrace.mock.calls.map(([entry]) => entry.stage);
      expect(stages.filter((stage) => stage === "delivery_retry_exhausted")).toHaveLength(1);
      expect(stages).not.toContain("durable_mark_started");
      state = nextState;
      await snapshot();
      expect(input).toHaveBeenCalledOnce();
      expect(client.post).toHaveBeenCalledOnce();
      expect(dispatched.size).toBe(1);
      await snapshot();
      expect(input).toHaveBeenCalledOnce();
    } finally { vi.useRealTimers(); }
  });

  test("input failure leaves source unread", async () => {
    const { client, deliver } = fixture(kind, "unknown", async () => { throw new Error("input refused"); });
    await expect(deliver()).rejects.toThrow("input refused");
    expect(client.post).not.toHaveBeenCalled();
  });

  test.each(["blocked", "shell", "generic shell", "generic-shell", "generic_shell", "stopped", "not-launched"])("%s never types or acknowledges", async (state) => {
    const input = vi.fn(async () => {});
    const { client, deliver } = fixture(kind, state, input);
    await expect(deliver()).rejects.toThrow("terminal");
    expect(input).not.toHaveBeenCalled();
    expect(client.post).not.toHaveBeenCalled();
  });
});


describe.each(["mail", "chat"] as const)("exhausted %s presentation", (kind) => {
  test("requests one snapshot only after the four refused attempts", async () => {
    vi.useFakeTimers();
    try {
      const input = vi.fn(async () => { throw new Error("refused"); });
      const { client, options } = fixture(kind, "working", input);
      const onTrace = vi.fn();
      const pending = consumeAgentEvents({ ...options, onTrace }, new Set(), (async function* () {
        yield { type: kind === "mail" ? "mail_message" : "chat_message", message_id: messageID, session_id: sessionID };
      })());
      await vi.advanceTimersByTimeAsync(850);
      await pending;
      expect(input).toHaveBeenCalledTimes(4);
      expect(client.post).not.toHaveBeenCalled();
      expect(onTrace.mock.calls.filter(([entry]) => entry.stage === "delivery_retry_exhausted")).toHaveLength(1);
    } finally { vi.useRealTimers(); }
  });
});
