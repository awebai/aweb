import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import {
  formatAwakeningForAgent,
  type ChannelAwakening,
} from "@awebai/channel-core";

type SendMessageOptions = Parameters<ExtensionAPI["sendMessage"]>[1];

export type WakeLogEvent =
  | "diagnostics_installed"
  | "process_exit"
  | "process_warning"
  | "uncaught_exception"
  | "wake_enqueued"
  | "wake_delivering"
  | "wake_delivered"
  | "wake_delivery_failed";

export type WakeLogger = (event: WakeLogEvent, fields?: Record<string, unknown>) => void;

let diagnosticsInstalled = false;

function errorFields(error: unknown): Record<string, unknown> {
  if (error instanceof Error) {
    return {
      name: error.name,
      message: error.message,
      stack: error.stack,
    };
  }
  return { message: String(error) };
}

function awakeningFields(awakening: ChannelAwakening): Record<string, unknown> {
  return {
    kind: awakening.kind,
    delivery_intent: awakening.deliveryIntent,
    message_id: awakening.meta.message_id,
    conversation_id: awakening.meta.conversation_id,
    session_id: awakening.meta.session_id,
    sender_waiting: awakening.meta.sender_waiting,
    sender_leaving: awakening.meta.sender_leaving,
  };
}

export function createWakeLogger(prefix = "aweb-pi-extension"): WakeLogger {
  return (event, fields = {}) => {
    const line = {
      ts: new Date().toISOString(),
      component: prefix,
      event,
      ...fields,
    };
    console.error(JSON.stringify(line));
  };
}

export function installWakeDiagnostics(log: WakeLogger): void {
  if (diagnosticsInstalled) return;
  diagnosticsInstalled = true;
  log("diagnostics_installed");

  process.on("exit", (code) => {
    log("process_exit", { code });
  });
  process.on("warning", (warning) => {
    log("process_warning", errorFields(warning));
  });
  process.on("uncaughtExceptionMonitor", (error) => {
    log("uncaught_exception", errorFields(error));
  });
}

export function deliveryOptionsForAwakening(
  awakening: ChannelAwakening,
  turnActive: boolean,
): SendMessageOptions {
  if (awakening.deliveryIntent === "ambient") {
    return { deliverAs: "nextTurn" };
  }
  if (awakening.deliveryIntent === "steer") {
    return turnActive
      ? { deliverAs: "steer" }
      : { deliverAs: "steer", triggerTurn: true };
  }
  // Pi's followUp queue is explicitly delivered after the current agent work
  // finishes. Use it for active-turn non-waiting mail/chat so a normal wake
  // cannot request a nested triggerTurn while the runtime is still unwinding
  // tool results or assistant output.
  return turnActive
    ? { deliverAs: "followUp" }
    : { triggerTurn: true };
}

export interface WakeDispatcher {
  enqueue(awakening: ChannelAwakening): Promise<void>;
  setTurnActive(active: boolean): void;
  close(reason?: Error): void;
}

interface PendingWake {
  awakening: ChannelAwakening;
  resolve: () => void;
  reject: (error: unknown) => void;
}

export function createWakeDispatcher(
  pi: ExtensionAPI,
  log: WakeLogger,
): WakeDispatcher {
  const queue: PendingWake[] = [];
  let draining = false;
  let turnActive = false;
  let closed: Error | undefined;

  const nextDeliverableIndex = (): number => queue.findIndex(({ awakening }) => (
    !turnActive || awakening.deliveryIntent !== "wake"
  ));

  const drain = () => {
    if (draining || nextDeliverableIndex() < 0) return;
    draining = true;
    setImmediate(async () => {
      try {
        let index: number;
        while ((index = nextDeliverableIndex()) >= 0) {
          const [pending] = queue.splice(index, 1);
          const next = pending.awakening;
          const options = deliveryOptionsForAwakening(next, turnActive);
          const fields = { ...awakeningFields(next), options };
          log("wake_delivering", fields);
          try {
            // Pi's public extension type currently declares sendMessage as void,
            // but the runtime implementation is async. Await thenables here so
            // the channel core does not acknowledge mail until Pi accepted the
            // injection at idle/turn-end.
            const result = (pi.sendMessage as unknown as (
              message: Parameters<ExtensionAPI["sendMessage"]>[0],
              options: SendMessageOptions,
            ) => unknown)(
              {
                customType: "aweb-channel",
                content: formatAwakeningForAgent(next),
                display: true,
                details: next.meta,
              },
              options,
            );
            if (isThenable(result)) await result;
            log("wake_delivered", fields);
            pending.resolve();
          } catch (error) {
            log("wake_delivery_failed", { ...fields, ...errorFields(error) });
            pending.reject(error);
          }
        }
      } finally {
        draining = false;
        if (nextDeliverableIndex() >= 0) drain();
      }
    });
  };

  return {
    enqueue(awakening) {
      if (closed) return Promise.reject(closed);
      const delivered = new Promise<void>((resolve, reject) => {
        queue.push({ awakening, resolve, reject });
      });
      log("wake_enqueued", { ...awakeningFields(awakening), queue_length: queue.length });
      drain();
      return delivered;
    },
    setTurnActive(active) {
      turnActive = active;
      if (!active) drain();
    },
    close(reason = new Error("Pi wake dispatcher closed")) {
      closed = reason;
      for (const pending of queue.splice(0)) pending.reject(reason);
    },
  };
}

function isThenable(value: unknown): value is PromiseLike<unknown> {
  return typeof value === "object" && value !== null && "then" in value
    && typeof (value as { then?: unknown }).then === "function";
}
