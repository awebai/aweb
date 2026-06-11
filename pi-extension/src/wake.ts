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
  | "unhandled_rejection"
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
  process.on("unhandledRejection", (reason) => {
    log("unhandled_rejection", errorFields(reason));
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
  return turnActive
    ? { deliverAs: "followUp" }
    : { triggerTurn: true };
}

export interface WakeDispatcher {
  enqueue(awakening: ChannelAwakening): void;
  setTurnActive(active: boolean): void;
}

export function createWakeDispatcher(
  pi: ExtensionAPI,
  log: WakeLogger,
): WakeDispatcher {
  const queue: ChannelAwakening[] = [];
  let draining = false;
  let turnActive = false;

  const drain = () => {
    if (draining) return;
    draining = true;
    setImmediate(() => {
      try {
        let next: ChannelAwakening | undefined;
        while ((next = queue.shift())) {
          const options = deliveryOptionsForAwakening(next, turnActive);
          const fields = { ...awakeningFields(next), options };
          log("wake_delivering", fields);
          try {
            pi.sendMessage(
              {
                customType: "aweb-channel",
                content: formatAwakeningForAgent(next),
                display: true,
                details: next.meta,
              },
              options,
            );
            log("wake_delivered", fields);
          } catch (error) {
            log("wake_delivery_failed", { ...fields, ...errorFields(error) });
          }
        }
      } finally {
        draining = false;
        if (queue.length > 0) drain();
      }
    });
  };

  return {
    enqueue(awakening) {
      queue.push(awakening);
      log("wake_enqueued", { ...awakeningFields(awakening), queue_length: queue.length });
      drain();
    },
    setTurnActive(active) {
      turnActive = active;
    },
  };
}
