// Run the released bundle's real HTTP client, fetchers and verifiers. The test
// appends exports to a byte-identical copy; it replaces no implementation.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const released = await import(pathToFileURL(process.argv[2]));
const input = JSON.parse(readFileSync(0, 'utf8'));
const auth = { ...input.auth, signingKey: Uint8Array.from(Buffer.from(input.auth.signingKey, 'hex')) };
const client = new released.APIClient(input.url, auth);
const verified = [];
async function check(message, kind) {
  const expected = kind === 'mail' && message.message_id === input.messages.mail_next.mid ? input.messages.mail_next : input.messages[kind];
  assert.equal(message.signed_payload, expected.raw);
  assert.equal(await (kind === 'mail' ? released.verifyInboxMessage : released.verifyChatMessage)(message), 'verified');
  verified.push(kind);
}
const mail = input.messages.mail;
const chat = input.messages.chat;
for (const path of [
  `/v1/messages/inbox?unread_only=false`,
  `/v1/messages/conversations/${mail.cid}`,
  `/v1/messages/conversations/${mail.cid}?limit=1&order=asc`,
]) {
  const response = await client.get(path);
  await check(response.messages.find(message => message.message_id === mail.mid), 'mail');
}
await check(await client.get(`/v1/messages/${mail.mid}`), 'mail');
const page = await client.get(`/v1/messages/conversations/${mail.cid}?limit=1`);
await check(page.messages[0], 'mail');
assert(page.next_cursor);
const next = await client.get(`/v1/messages/conversations/${mail.cid}?limit=1&cursor=${encodeURIComponent(page.next_cursor)}`);
await check(next.messages[0], 'mail');
await check((await released.fetchInbox(client, false, 50, mail.mid))[0], 'mail');
await check((await released.fetchHistory(client, chat.cid, false, 50, chat.mid))[0], 'chat');
// Discovery rows hand off to a full retained read, never to reconstruction.
assert((await client.get('/v1/chat/pending')).pending.some(row => row.session_id === chat.cid));
const deadline = new Date(Date.now() - 1000).toISOString();
const signal = AbortSignal.timeout(10000);
const response = await client.openSSE(`/v1/events/stream?deadline=${encodeURIComponent(deadline)}`, signal);
const observed = new Set();
for await (const event of released.parseSSEResponse(response, signal)) {
  if (event.type === 'mail_message' && event.message_id === mail.mid) {
    await check((await released.fetchInbox(client, false, 50, event.message_id))[0], 'mail');
    observed.add('mail');
  }
  if (event.type === 'chat_message' && event.session_id === chat.cid) {
    // Actionable snapshots identify the session; exact-message events may also
    // provide message_id. Follow precisely the released channel's optional hop.
    if (event.message_id !== undefined) assert.equal(event.message_id, chat.mid);
    const fetched = await released.fetchHistory(client, event.session_id, true, 50, event.message_id);
    const message = fetched.find(message => message.message_id === chat.mid);
    assert(message, 'event discovery did not reach the expected retained message');
    assert.equal(message.conversation_id, event.session_id);
    await check(message, 'chat');
    observed.add('chat');
  }
}
assert.deepEqual([...observed].sort(), ['chat', 'mail']);
console.log(JSON.stringify({ verified: verified.length, event_then_fetch: [...observed].sort() }));
