import { expect, test, vi } from "vitest";
import * as ed from "@noble/ed25519";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { computeDIDKey } from "../src/identity/did.js";
import { canonicalJSON, signMessage, type MessageEnvelope } from "../src/identity/signing.js";
import { dispatchAgentEvent, DeliveryStore, formatAwakeningForAgent, type ChannelAwakening } from "../src/channel.js";
import { PinStore } from "../src/identity/pinstore.js";
import { parseAgentEvent } from "../src/api/events.js";
import { createTerminalAwakeningHandler } from "../src/terminal.js";

async function fixture() {
  const key = new Uint8Array(32).fill(23);
  const did = computeDIDKey(ed.getPublicKey(key));
  const team = "ops:example.test", room = "11111111-1111-4111-8111-111111111111", id = "22222222-2222-4222-8222-222222222222";
  const signed: MessageEnvelope = { type:"chat", from:"alice", from_did:did, to:`team-room:${team}`, to_did:"", conversation_id:room, message_id:id, subject:"Release\n\u001b[31m update" + "x".repeat(300), body:"This body must not appear in a light notice", timestamp:"2026-10-31T00:00:00Z" };
  const signature = await signMessage(key, signed);
  const row = { team_id:team, room_id:room, conversation_id:room, message_id:id, from_alias:signed.from, from_did:did, subject:signed.subject, body:signed.body, timestamp:signed.timestamp, signed_payload:canonicalJSON(signed), signature, signing_key_id:did };
  const client = { get:vi.fn(async () => ({...row})), post:vi.fn(async () => ({})) };
  const home = await mkdtemp(join(tmpdir(), "room-notice-"));
  const delivered = await DeliveryStore.load(join(home, "delivered.json"));
  const presented: ChannelAwakening[] = [];
  const options = { client:client as never, teamID:team, self:{alias:"bob",address:"",did:"did:key:bob",stableID:""}, pinStore:new PinStore(), trust:{ normalizeResolvedTrust:vi.fn(async () => ({status:"verified",stored:false})) } as never, deliveryStore:delivered, onAwakening:vi.fn(async (a:ChannelAwakening) => {presented.push(a);}) };
  const event = { type:"room_post" as const, team_id:team, room_id:room, message_id:id, from_alias:"forged SSE label", subject:"forged SSE subject" };
  return {client, row, presented, options, event, home};
}

test("room event parsing is additive", () => {
  expect(parseAgentEvent("actionable_room_post", '{"room_id":"r","message_id":"m"}')).toMatchObject({type:"room_post",room_id:"r",message_id:"m"});
});

test("verified room notice is capped, framed, persistent and acknowledged only after presentation", async () => {
  const f=await fixture();
  let accept!: () => void;
  f.options.onAwakening.mockImplementationOnce(async (a) => {f.presented.push(a); await new Promise<void>(resolve => {accept=resolve;});});
  const run=dispatchAgentEvent(f.options,new Set(),f.event);
  await vi.waitFor(() => expect(f.presented).toHaveLength(1));
  expect(f.client.post).not.toHaveBeenCalled();
  const notice=f.presented[0];
  expect(notice.kind).toBe("room");
  expect(notice.content).toMatch(/^New team room post from alice: Release /);
  expect(notice.content).toContain("Read it: aw room read");
  expect(notice.content).not.toContain(f.row.body);
  expect(notice.content).not.toMatch(/[\n\r\u001b]/);
  expect(notice.content.length).toBeLessThan(400);
  expect(formatAwakeningForAgent(notice)).toContain("Message:\nNew team room post");
  expect(notice.meta.sender_waiting).toBeUndefined();
  accept(); await run;
  expect(f.client.post).toHaveBeenCalledTimes(1);
  expect(f.client.post.mock.calls[0][0]).toContain("/notices/" + f.event.message_id + "/ack");
  const reloaded=await DeliveryStore.load(join(f.home,"delivered.json"));
  await dispatchAgentEvent({...f.options,deliveryStore:reloaded},new Set(),f.event);
  expect(f.presented).toHaveLength(1);
});

test("failed, mismatched and rejected presentations leave room notices pending", async () => {
  for (const failure of ["signature", "room", "presentation"] as const) {
    const f=await fixture();
    if(failure==="signature") f.row.signature="bad";
    if(failure==="room") f.row.room_id="wrong";
    if(failure==="presentation") f.options.onAwakening.mockRejectedValue(new Error("busy"));
    await expect(dispatchAgentEvent(f.options,new Set(),f.event)).rejects.toThrow();
    expect(f.client.post).not.toHaveBeenCalled();
  }
});

test("room wakes defer for known working panes and deliver for unknown readiness", async () => {
  for(const state of ["working","unknown","idle"]) {
    const input=vi.fn(async () => {});
    const handler=createTerminalAwakeningHandler({home:"/test",session:{inspect:async()=>({state,present:true}),input}});
    const awakening={kind:"room" as const,content:"New team room post from alice: Update. Read it: aw room read",meta:{type:"room",trust_status:"verified",message_id:"22222222-2222-4222-8222-222222222222"},deliveryIntent:"wake" as const};
    if(state==="working") {await expect(handler(awakening)).rejects.toThrow();expect(input).not.toHaveBeenCalled();}
    else {await handler(awakening);expect(input).toHaveBeenCalledOnce();}
  }
});

test("room instructions retain each receiving binding and the default-home neighbour", async () => {
  const input = vi.fn(async () => {});
  const handler = createTerminalAwakeningHandler({home:"/instance",session:{inspect:async()=>({state:"idle",present:true}),input}});
  const awakening = {kind:"room" as const,content:"New team room post from alice: Update. Read it: aw room read",meta:{type:"room",trust_status:"verified",message_id:"22222222-2222-4222-8222-222222222222"},deliveryIntent:"wake" as const};
  for (const home of [undefined, "/joined-team/.aw", "/second team's/.aw"]) {
    await handler(awakening, home);
    const text = String(input.mock.calls.at(-1)?.[1]);
    if (home === undefined) {
      expect(text).toContain("Read it: aw room read");
      expect(text).not.toContain("--identity-home");
    } else {
      const quoted = "'" + home.replace(/'/g, "'\\''") + "'";
      expect(text).toContain(`Recovery: aw --identity-home ${quoted} room read`);
    }
  }
});

test("joined-identity room notice retries at idle with its framed content and room recovery", async () => {
  const f = await fixture();
  let state = "working";
  const input = vi.fn(async (_home: string, _text: string) => {});
  const handler = createTerminalAwakeningHandler({
    home: "/instance",
    session: { inspect: async () => ({ state, present: true }), input },
  });
  f.options.onAwakening.mockImplementation(async (awakening) => {
    await handler(awakening, "/joined team/.aw");
  });

  await expect(dispatchAgentEvent(f.options, new Set(), f.event)).rejects.toThrow("working");
  expect(input).not.toHaveBeenCalled();
  expect(f.client.post).not.toHaveBeenCalled();

  state = "idle";
  await dispatchAgentEvent(f.options, new Set(), f.event);
  expect(input).toHaveBeenCalledTimes(1);
  const text = input.mock.calls[0][1];
  expect(text).toContain("Message:\nNew team room post from alice:");
  expect(text).toContain("Recovery: aw --identity-home '/joined team/.aw' room read");
  expect(text).not.toContain("events stream");
  expect(f.client.post).toHaveBeenCalledTimes(1);
});
