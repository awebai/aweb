import { describe, expect, test, vi } from "vitest";
import {
  createTerminalAwakeningHandler, dispatchAgentEvent, PinStore,
  type SenderTrustManager,
} from "../src/index.js";

const messageID = "12345678-1234-1234-1234-123456789abc";
const sessionID = "87654321-4321-4321-4321-cba987654321";

function fixture(kind: "mail" | "chat", state: string, input: (home: string, text: string) => Promise<void>) {
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
    onAwakening: createTerminalAwakeningHandler({ home: "/agent", session: { inspect: async () => ({ present: true, state }), input } }),
    mailAcknowledgment: "delivery" as const,
  };
  return { client, deliver: () => dispatchAgentEvent(options, new Set(), { type: kind === "mail" ? "mail_message" : "chat_message", message_id: messageID, session_id: sessionID }) };
}

describe.each(["mail", "chat"] as const)("terminal %s presentation acknowledgment", (kind) => {
  test.each(["idle", "working", "blocked", "unknown"])("%s delivers full sanitized text and acknowledges only accepted input", async (state) => {
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

  test("input failure leaves source unread", async () => {
    const { client, deliver } = fixture(kind, "unknown", async () => { throw new Error("input refused"); });
    await expect(deliver()).rejects.toThrow("input refused");
    expect(client.post).not.toHaveBeenCalled();
  });

  test.each(["shell", "generic shell", "generic-shell", "stopped", "not-launched"])("%s never types or acknowledges", async (state) => {
    const input = vi.fn(async () => {});
    const { client, deliver } = fixture(kind, state, input);
    await expect(deliver()).rejects.toThrow("terminal");
    expect(input).not.toHaveBeenCalled();
    expect(client.post).not.toHaveBeenCalled();
  });
});
