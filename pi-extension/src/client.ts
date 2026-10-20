import metadata from "../package.json" with { type: "json" };
import { createChannelClient } from "@awebai/channel-core";

export const PI_CLIENT_METADATA = { name: "aweb-pi", version: metadata.version };

export function createPiChannelClient(config: Parameters<typeof createChannelClient>[0]) {
  return createChannelClient(config, PI_CLIENT_METADATA);
}
