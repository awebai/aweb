/**
 * Consume the agent event stream (GET /v1/events/stream).
 * Yields parsed AgentEvent objects. Reconnects on stream end.
 */
export async function* streamAgentEvents(client, signal) {
    while (!signal.aborted) {
        const deadline = new Date(Date.now() + 5 * 60 * 1000).toISOString();
        let resp;
        try {
            resp = await client.openSSE(`/v1/events/stream?deadline=${encodeURIComponent(deadline)}`, signal);
        }
        catch (err) {
            if (signal.aborted)
                return;
            console.error(`[aw-channel] events stream connect failed: ${err}`);
            // Back off on connection failure
            await sleep(5000, signal);
            continue;
        }
        try {
            yield* parseSSEResponse(resp, signal);
        }
        catch (err) {
            if (signal.aborted)
                return;
            if (!isExpectedStreamTermination(err)) {
                console.error(`[aw-channel] events stream parse failed: ${err}`);
            }
            // Stream ended or errored — reconnect after brief pause
            await sleep(1000, signal);
        }
        finally {
            resp.body?.cancel().catch(() => { });
        }
    }
}
async function* parseSSEResponse(resp, signal) {
    const reader = resp.body?.getReader();
    if (!reader)
        return;
    const onAbort = () => {
        void reader.cancel().catch(() => { });
    };
    signal.addEventListener("abort", onAbort, { once: true });
    const decoder = new TextDecoder();
    let buffer = "";
    let currentEvent = "";
    let dataLines = [];
    try {
        while (!signal.aborted) {
            const { done, value } = await reader.read();
            if (done)
                break;
            buffer += decoder.decode(value, { stream: true });
            const lines = buffer.split("\n");
            buffer = lines.pop() || "";
            for (const rawLine of lines) {
                const line = rawLine.replace(/\r$/, "");
                if (line === "") {
                    // Empty line = event boundary
                    if (currentEvent || dataLines.length > 0) {
                        const event = parseAgentEvent(currentEvent, dataLines.join("\n"));
                        if (event)
                            yield event;
                        currentEvent = "";
                        dataLines = [];
                    }
                    continue;
                }
                if (line.startsWith(":"))
                    continue; // comment
                if (line.startsWith("event:")) {
                    currentEvent = line.slice(6).trim();
                }
                else if (line.startsWith("data:")) {
                    dataLines.push(line.slice(5).trim());
                }
            }
        }
    }
    finally {
        signal.removeEventListener("abort", onAbort);
        reader.releaseLock();
    }
}
const KNOWN_TYPES = new Set([
    "connected", "mail_message", "chat_message",
    "control_pause", "control_resume", "control_interrupt",
    "work_available", "claim_update", "claim_removed", "app_event", "error",
    "actionable_mail", "actionable_chat",
]);
export function parseAgentEvent(eventName, data) {
    eventName = eventName.trim();
    if (!eventName)
        return null;
    if (!KNOWN_TYPES.has(eventName))
        return null;
    if (eventName === "actionable_mail")
        eventName = "mail_message";
    if (eventName === "actionable_chat")
        eventName = "chat_message";
    try {
        const payload = JSON.parse(data);
        return { ...payload, type: eventName };
    }
    catch {
        return { type: eventName };
    }
}
function isExpectedStreamTermination(err) {
    if (!(err instanceof Error))
        return false;
    const name = err.name.toLowerCase();
    const message = err.message.toLowerCase();
    return name === "aborterror" || message === "terminated";
}
function sleep(ms, signal) {
    return new Promise((resolve) => {
        if (signal.aborted) {
            resolve();
            return;
        }
        const timer = setTimeout(resolve, ms);
        signal.addEventListener("abort", () => { clearTimeout(timer); resolve(); }, { once: true });
    });
}
