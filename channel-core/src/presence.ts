import type { APIClient } from "./api/client.js";

export const PRESENCE_HEARTBEAT_INTERVAL_MS = 5 * 60 * 1000;

export function startPresenceHeartbeat(client: APIClient, signal: AbortSignal, log: (message: string) => void = () => {}): () => void {
  return () => {};
}
