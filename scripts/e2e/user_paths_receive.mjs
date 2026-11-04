// A real channel-core receiver. The sink records presentation; it does not read
// the inbox on behalf of the test, invent an event or impersonate OATS.
import { appendFileSync, existsSync, statSync } from 'node:fs';
import { setTimeout } from 'node:timers/promises';
import { resolveConfig, createChannelClient, loadPinStore, SenderTrustManager,
  createRegistryResolver, createLocalAWDecryptProvider, startChannelLoop } from '/journey/channel-core/dist/index.js';
const [home, output, aw] = process.argv.slice(2);
const config = await resolveConfig(home);
const client = createChannelClient(config);
const abort = new AbortController();
process.once('SIGTERM', () => abort.abort());
process.once('SIGINT', () => abort.abort());
const decrypt = createLocalAWDecryptProvider({workdir: home, identityHome: config.identityHome, teamID: config.teamID, awCommand: aw});
function identityState(phase, operation, args = []) {
  let ownerUID = null;
  try { ownerUID = statSync(config.identityHome).uid; } catch {}
  appendFileSync(output, JSON.stringify({type: 'identity-home', phase, operation,
    message_id: args.at(-1), identity_home: config.identityHome,
    process_uid: process.geteuid(), owner_uid: ownerUID}) + '\n');
}
function witnessedDecrypt(operation) {
  return async (...args) => {
    identityState('before', operation, args);
    try { return await decrypt[operation](...args); }
    finally { identityState('after', operation, args); }
  };
}
identityState('receiver-start', 'startup');
await startChannelLoop({
  client, pinStore: await loadPinStore(home + '/pins.json'),
  trust: new SenderTrustManager(client, createRegistryResolver(config), config.teamID, config.did, config.stableID),
  self: {alias: config.alias, address: config.address, did: config.did, stableID: config.stableID},
  teamID: config.teamID, workdir: home, awCommand: aw, signal: abort.signal,
  mailAcknowledgment: 'manual',
  localDecrypt: {mailMessage: witnessedDecrypt('mailMessage'), chatMessage: witnessedDecrypt('chatMessage')},
  onAwakening: async event => {
    appendFileSync(output, JSON.stringify({type: 'awakening', ...event}) + '\n');
    // Keep the actual presentation callback outstanding until the independent
    // CLI list/read assertions finish. The real core performs its own ack next.
    if (['mail', 'chat'].includes(event.kind)) {
      while (!existsSync(output + '.release-' + event.meta.message_id) && !abort.signal.aborted) {
        await setTimeout(10);
      }
    }
  },
  onStreamState: state => appendFileSync(output, JSON.stringify({type: 'stream', ...state}) + '\n'),
  log: console.error,
});
