// Real OSS HTTP, channel-core trust/pin persistence, and optional real aw decrypt.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
const input = JSON.parse(readFileSync(0, 'utf8'));
const core = await import(pathToFileURL(process.argv[2]));
const auth = {...input.auth, signingKey: Uint8Array.from(Buffer.from(input.auth.signingKey, 'hex'))};
const client = new core.APIClient(input.url, auth);
const trust = new core.SenderTrustManager(client, new core.RegistryResolver(), auth.teamID, auth.did);
const local = core.createLocalAWDecryptProvider({workdir:input.workdir, awCommand:input.aw, identityHome:input.identityHome, teamID:auth.teamID});
const output = [];
for (const kind of ['mail', 'chat']) {
  const expected = input.messages[kind];
  const decrypt = async (...args) => {
    const value = await (kind === 'mail' ? local.mailMessage(...args) : local.chatMessage(...args));
    assert(value && value.body === 'protected channel input');
    if (input.mode === 'failure') throw new Error('deliberate provider delivery failure after real decryption');
    // Fault injection at the untrusted provider-return boundary; no fake aw.
    return input.mode === 'forged' ? {...value, ingress:{...input.ingress, confidentiality:'end_to_end'}} : value;
  };
  const awakenings = [];
  await core.dispatchAgentEvent({client, trust, pinStore:new core.PinStore(),
    pinStorePath:join(input.workdir, `pins-${kind}-${input.mode}.yaml`), awCommand:input.aw, workdir:input.workdir,
    self:{alias:'bob', address:'', did:auth.did, stableID:''}, mailAcknowledgment:'manual',
    localDecrypt:{mailMessage:decrypt, chatMessage:decrypt}, onAwakening:value=>{awakenings.push(value);}},
    new Set(), {type:kind === 'mail' ? 'mail_message':'chat_message', message_id:expected.message_id,
      conversation_id:expected.conversation_id, ...(kind === 'chat' ? {session_id:expected.conversation_id}: {})});
  assert.equal(awakenings.length, 1);
  const awakening = awakenings[0];
  assert.deepEqual(JSON.parse(awakening.meta.ingress || 'null'), input.ingress);
  const line = core.formatAwakeningForAgent(awakening).split("\n").find(line => line.startsWith("- ingress: "));
  assert(line);
  assert.deepEqual(JSON.parse(line.slice("- ingress: ".length)), input.ingress);
  if (input.failed_trust) assert.equal(awakening.meta.verified, 'false');
  if (input.mode === 'failure') assert.equal(awakening.meta.decrypted, 'false');
  else assert.equal(awakening.content, input.mode === 'plaintext' ? 'channel input':'protected channel input');
  output.push(awakening);
}
console.log(JSON.stringify(output));
