import type { APIClient } from "./api/client.js";

export const PRESENCE_HEARTBEAT_INTERVAL_MS = 5 * 60 * 1000;

export function startPresenceHeartbeat(client: APIClient, signal: AbortSignal, log: (message: string) => void = () => {}): () => void {
  if (signal.aborted) return () => {};
  const request = new AbortController();
  const beat = () => {
    if (request.signal.aborted) return;
    void client.post("/v1/agents/heartbeat", undefined, request.signal).catch((error) => {
      if (!request.signal.aborted) log(`presence heartbeat failed: ${String(error)}`);
    });
  };
  const timer = setInterval(beat, PRESENCE_HEARTBEAT_INTERVAL_MS);
  timer.unref?.();
  const stop = () => {
    clearInterval(timer);
    request.abort();
    signal.removeEventListener("abort", stop);
  };
  signal.addEventListener("abort", stop, { once: true });
  beat();
  return stop;
}
