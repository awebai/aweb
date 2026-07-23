import type { APIClient } from "./client.js";
export type AgentEventType = "connected" | "mail_message" | "chat_message" | "control_pause" | "control_resume" | "control_interrupt" | "work_available" | "claim_update" | "claim_removed" | "app_event" | "error";
export interface EventStreamState {
    state: "connected" | "disconnected" | "reconnected";
    cause?: string;
    retryInMs?: number;
}
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
    event_id?: string;
    app_id?: string;
    app_event_type?: string;
    resource_ref?: string;
    delivery_intent?: "wake" | "steer" | "ambient";
    producer_delivery_intent?: "wake" | "steer" | "ambient";
    payload?: Record<string, unknown>;
}
/**
 * Consume the agent event stream (GET /v1/events/stream).
 * Yields parsed AgentEvent objects. Reconnects on stream end.
 */
export declare function streamAgentEvents(client: APIClient, signal: AbortSignal, onState?: (state: EventStreamState) => void): AsyncGenerator<AgentEvent>;
export declare function parseAgentEvent(eventName: string, data: string): AgentEvent | null;
export declare function formatEventStreamState(state: EventStreamState): string;
export declare function streamErrorCause(err: unknown): string;
