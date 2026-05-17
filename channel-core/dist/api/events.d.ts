import type { APIClient } from "./client.js";
export type AgentEventType = "connected" | "mail_message" | "chat_message" | "control_pause" | "control_resume" | "control_interrupt" | "work_available" | "claim_update" | "claim_removed" | "error";
export interface AgentEvent {
    type: AgentEventType;
    agent_id?: string;
    team_id?: string;
    message_id?: string;
    conversation_id?: string;
    from_alias?: string;
    session_id?: string;
    subject?: string;
    signal_id?: string;
    task_id?: string;
    title?: string;
    status?: string;
    text?: string;
    sender_waiting?: boolean;
}
/**
 * Consume the agent event stream (GET /v1/events/stream).
 * Yields parsed AgentEvent objects. Reconnects on stream end.
 */
export declare function streamAgentEvents(client: APIClient, signal: AbortSignal): AsyncGenerator<AgentEvent>;
export declare function parseAgentEvent(eventName: string, data: string): AgentEvent | null;
