// Publishing one signed activity event and reading the route's answer
// (docs/agent-activity.md, "Emitters" and "Refusal codes").
import { APIClient, APIError } from "../api/client.js";
import type { PublishOutcome } from "./emitter.js";
import type { SignedActivity } from "./event.js";

export const ACTIVITY_PATH = "/v1/agents/me/activity";
const RATE_WINDOW_SECONDS = 5;

// The route answers a session the caller cannot see with the shared resource
// 404. Any other 404, such as the framework's "Not Found" for an absent
// route, means the server has no activity route.
function isSharedResource404(body: string): boolean {
  try {
    const parsed = JSON.parse(body);
    return parsed !== null && typeof parsed === "object" && Object.keys(parsed).length === 1 && parsed.detail === "Not found";
  } catch {
    return false;
  }
}

export async function publishActivity(client: APIClient, body: SignedActivity): Promise<PublishOutcome> {
  try {
    await client.postAccepted(ACTIVITY_PATH, body);
    return { kind: "accepted" };
  } catch (err) {
    if (!(err instanceof APIError)) return { kind: "failed" };
    if (err.statusCode === 429) return { kind: "rate_limited", retryAfterSeconds: err.retryAfterSeconds ?? RATE_WINDOW_SECONDS };
    if (err.statusCode === 404) return isSharedResource404(err.body) ? { kind: "session_refused" } : { kind: "route_absent" };
    return { kind: "failed" };
  }
}
