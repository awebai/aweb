// Signed agent activity events (docs/agent-activity.md, "The signed event").
import { canonicalJSONValue } from "../identity/canonical.js";
import { signBytes } from "../identity/signing.js";

export type ActivityPhase = "turn_started" | "thinking" | "tool" | "waiting_permission" | "writing" | "turn_ended";

export interface ActivityEvent {
  v: 1;
  type: "agent_activity";
  from_did: string;
  from_stable_id?: string;
  team_id: string;
  session_id: string | null;
  turn_id: string;
  seq: number;
  phase: ActivityPhase;
  tool?: string;
  summary?: string;
  timestamp: string;
  expires_at: string;
}

export interface SignedActivity {
  signed_payload: string;
  signature: string;
}

export function canonicalActivityBytes(event: ActivityEvent): Uint8Array {
  return new TextEncoder().encode(canonicalJSONValue(event, "unsupported activity event value"));
}

/** The request body for POST /v1/agents/me/activity. */
export function signActivityEvent(event: ActivityEvent, seed: Uint8Array): SignedActivity {
  const bytes = canonicalActivityBytes(event);
  return {
    signed_payload: Buffer.from(bytes).toString("base64url"),
    signature: signBytes(seed, bytes),
  };
}
