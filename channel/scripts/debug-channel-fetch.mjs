#!/usr/bin/env node
import {
  createChannelClient,
  createRegistryResolver,
  fetchHistory,
  loadPinStore,
  resolveConfig,
  SenderTrustManager,
} from "../../channel-core/dist/index.js";

function arg(name, fallback = "") {
  const prefix = `--${name}=`;
  for (const value of process.argv.slice(2)) {
    if (value.startsWith(prefix)) return value.slice(prefix.length);
  }
  return fallback;
}

const cwd = arg("cwd", process.cwd());
const sessionID = arg("session");
const messageID = arg("message");

if (!sessionID || !messageID) {
  console.error("usage: node channel/scripts/debug-channel-fetch.mjs --cwd=/path/to/workspace --session=<session_id> --message=<message_id>");
  process.exit(2);
}

const config = await resolveConfig(cwd);
const client = createChannelClient(config);
const raw = await client.get(
  `/v1/chat/sessions/${encodeURIComponent(sessionID)}/messages?unread_only=true&limit=2000&message_id=${encodeURIComponent(messageID)}`,
);
const messages = await fetchHistory(client, sessionID, true, 2000, messageID);
const pinStore = await loadPinStore();
const trust = new SenderTrustManager(
  client,
  createRegistryResolver(config),
  config.teamID,
  config.did,
  config.stableID,
);

const normalized = [];
for (const msg of messages) {
  const from = msg.from_address || msg.from_agent || "";
  const result = await trust.normalizeTrust(
    pinStore,
    msg.verification_status,
    from,
    msg.from_did,
    msg.from_stable_id,
    msg.to_did,
    msg.to_stable_id,
    msg.rotation_announcement,
    msg.replacement_announcement,
    msg.signed_from || from,
  );
  normalized.push({
    message_id: msg.message_id,
    from,
    crypto_status: msg.verification_status,
    normalized_status: result.status,
    from_did: msg.from_did || null,
    from_stable_id: msg.from_stable_id || null,
    to_did: msg.to_did || null,
    to_stable_id: msg.to_stable_id || null,
    signed_payload_present: Boolean(msg.signed_payload),
    signature_present: Boolean(msg.signature),
  });
}

console.log(JSON.stringify({
  self: {
    cwd,
    team_id: config.teamID,
    alias: config.alias,
    did: config.did,
    stable_id: config.stableID,
    address: config.address,
  },
  raw,
  normalized,
}, null, 2));
