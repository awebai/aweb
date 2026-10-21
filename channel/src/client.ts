import metadata from "../package.json" with { type: "json" };
import { createChannelClient } from "@awebai/channel-core";

export const CHANNEL_CLIENT_METADATA = { name: "aweb-channel", version: metadata.version };

export function createClaudeChannelClient(config: Parameters<typeof createChannelClient>[0]) {
  return createChannelClient(config, CHANNEL_CLIENT_METADATA);
}
