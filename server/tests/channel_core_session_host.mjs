// Minimal agent host: production channel-core does all streaming and delivery.
import { pathToFileURL } from "node:url";
const [corePath, workdir] = process.argv.slice(2);
const { resolveConfig, createChannelClient, createRegistryResolver, SenderTrustManager, loadPinStore, startChannelLoop } = await import(pathToFileURL(corePath).href);
const config = await resolveConfig(workdir);
const abort = new AbortController();
const consuming = startChannelLoop({
  client: createChannelClient(config), pinStore: await loadPinStore(),
  trust: new SenderTrustManager(createChannelClient(config), createRegistryResolver(config), config.teamID, config.did, config.stableID),
  self: { alias: config.alias, address: config.address, did: config.did, stableID: config.stableID },
  teamID: config.teamID, signal: abort.signal, workdir,
  log: message => process.stderr.write(`${message}\n`),
  onAwakening: async awakening => { process.stdout.write(`${JSON.stringify(awakening)}\n`); },
});
process.stdin.on("end", async () => { abort.abort(); await consuming; process.exit(0); });
process.stdin.resume();
