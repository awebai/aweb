// Export-only instrumentation of the digest-checked published plugin bundle.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
const released = await import(pathToFileURL(process.argv[2]));
const input = JSON.parse(readFileSync(0, 'utf8'));
const auth = { ...input.auth, signingKey: Uint8Array.from(Buffer.from(input.auth.signingKey, 'hex')) };
const client = new released.APIClient(input.url, auth);
for (const kind of ['mail', 'chat']) {
  const expected = input.messages[kind];
  const rows = kind === 'mail'
    ? await released.fetchInbox(client, false, 50, expected.message_id)
    : await released.fetchHistory(client, expected.conversation_id, false, 50, expected.message_id);
  const message = rows.find(row => row.message_id === expected.message_id);
  assert(message);
  assert.deepEqual(message.ingress, input.ingress);
  assert.equal(message.signed_payload, input.raw[kind]);
  assert.equal(await (kind === 'mail' ? released.verifyInboxMessage : released.verifyChatMessage)(message), 'verified');
}
const signal = AbortSignal.timeout(10000);
const response = await client.openSSE(`/v1/events/stream?deadline=${encodeURIComponent(new Date(Date.now()-1000).toISOString())}`, signal);
const observed = new Set();
for await (const event of released.parseSSEResponse(response, signal)) {
  if (event.type === 'mail_message' && event.message_id === input.messages.mail.message_id) observed.add('mail');
  if (event.type === 'chat_message' && event.session_id === input.messages.chat.conversation_id) observed.add('chat');
}
assert.deepEqual([...observed].sort(), ['chat', 'mail']);
console.log(JSON.stringify({verified: ['mail', 'chat'], events: [...observed].sort()}));
