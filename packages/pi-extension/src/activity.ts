// Pi's lifecycle events drive the session's activity emitter
// (docs/agent-activity.md, "Emitters"). An agent run, agent_start to
// agent_end, is the activity turn: Pi's turn_start/turn_end fire once per model
// call inside a run. Pi has no permission-prompt event, so waiting_permission
// is never sent.
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import type { ActivityEmitter } from "@awebai/channel-core";

export type ActivityTarget = Pick<ActivityEmitter, "turnStarted" | "thinking" | "writing" | "tool" | "turnEnded">;

/** Register once; the handlers act on whatever emitter the current session has. */
export function registerActivityHandlers(pi: ExtensionAPI, current: () => ActivityTarget | undefined): void {
  pi.on("agent_start", () => {
    current()?.turnStarted();
  });
  pi.on("agent_end", () => {
    current()?.turnEnded();
  });
  pi.on("message_update", (event) => {
    const kind = event.assistantMessageEvent?.type;
    if (kind === "thinking_start") current()?.thinking();
    else if (kind === "text_start") current()?.writing();
  });
  pi.on("tool_execution_start", (event) => {
    current()?.tool(event.toolName, event.args);
  });
  pi.on("tool_execution_end", () => {
    current()?.thinking();
  });
}
