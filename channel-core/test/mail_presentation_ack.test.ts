import { describe, expect, test, vi } from "vitest";
import {
  dispatchAgentEvent,
  PinStore,
  type AgentEvent,
  type ChannelAwakening,
  type SenderTrustManager,
} from "../src/index.js";

// aajy: mail is marked read when presented to the agent. On the Claude surface
// the MCP notification IS the presentation, so mailAcknowledgment "delivery"
// acks right after onAwakening. The withheld-ack ("manual") policy left mail
// unread server-side, which the server re-delivered on reconnect (replay burst).
describe("mail presentation-ack semantic", () => {
  const self = {
    alias: "eve",
    address: "acme.com/eve",
    did: "did:key:self-eve",
    stableID: "did:aw:self-eve",
  };
  const trust = {
    normalizeResolvedTrust: vi.fn(async () => ({ status: "verified", stored: false })),
  } as unknown as SenderTrustManager;

  function mkClient() {
    return {
      get: vi.fn().mockResolvedValue({
        messages: [{
          message_id: "m1",
          from_agent_id: "agent-1",
          from_alias: "alice",
          from_address: "acme.com/alice",
          to_alias: "eve",
          subject: "hello",
          body: "world",
          priority: "normal",
          created_at: "2025-01-01T00:00:00Z",
        }],
      }),
      post: vi.fn().mockResolvedValue(undefined),
    };
  }

  async function run(mailAcknowledgment: "delivery" | "manual") {
    const client = mkClient();
    const awoke: ChannelAwakening[] = [];
    await dispatchAgentEvent(
      {
        client: client as never,
        pinStore: new PinStore(),
        trust,
        self,
        onAwakening: (a) => { awoke.push(a); },
        mailAcknowledgment,
      },
      new Set(),
      { type: "mail_message", message_id: "m1" } satisfies AgentEvent,
    );
    return { client, awoke };
  }

  test("delivery acks the message at presentation (no replay)", async () => {
    const { client, awoke } = await run("delivery");
    expect(awoke.some((a) => a.kind === "mail")).toBe(true); // presented
    expect(client.post).toHaveBeenCalledWith("/v1/messages/m1/ack"); // acked at presentation
  });

  test("manual leaves the presented message un-acked (server re-delivers -> replay)", async () => {
    const { client, awoke } = await run("manual");
    expect(awoke.some((a) => a.kind === "mail")).toBe(true); // still presented
    expect(client.post).not.toHaveBeenCalledWith("/v1/messages/m1/ack"); // never acked
  });
});
