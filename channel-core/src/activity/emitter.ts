// The activity emitter (docs/agent-activity.md, "Emitters"). A runtime calls it
// from its lifecycle events; it decides what is published and when.
//
// - The host owner's opt-in is read at each turn start; an opted-out turn is
//   silent from start to end.
// - The chat wake delivered before a turn attributes it. An encrypted wake
//   keeps tool names but sends no summary for the whole turn.
// - Turn boundaries (turn_started, turn_ended) are always sent, in order.
//   Intermediate phases coalesce: the latest wins, at most one per 500 ms, and
//   a turn_ended replaces its turn's pending state.
// - A 429 pauses publishing for Retry-After; the shared 404 drops one event; an
//   absent route stops publishing for the process; any other failure drops
//   the event.
import { randomBytes } from "node:crypto";
import { signActivityEvent, type ActivityEvent, type ActivityPhase, type SignedActivity } from "./event.js";
import { readActivitySetting } from "./setting.js";
import { summarizeTool } from "./summary.js";

export type PublishOutcome =
  | { kind: "accepted" }
  | { kind: "rate_limited"; retryAfterSeconds: number }
  | { kind: "session_refused" }
  | { kind: "route_absent" }
  | { kind: "failed" };

export interface ActivitySigner {
  /** The did:key of the key that signs requests: the agent's, or the grant session key. */
  did: string;
  stableID?: string;
  teamID: string;
  seed: Uint8Array;
}

export interface ActivityEmitterOptions {
  identityRoot: string;
  workRoot?: string;
  signer: ActivitySigner;
  publish: (body: SignedActivity) => Promise<PublishOutcome>;
  log?: (line: string) => void;
}

const COALESCE_MS = 500;
const VALIDITY_MS = 60_000;
const IDENTIFIER = /^[A-Za-z0-9_.:-]{1,64}$/;
const BOUNDARIES = new Set<ActivityPhase>(["turn_started", "turn_ended"]);

interface Turn {
  id: string;
  seq: number;
  sessionID: string | null;
  encrypted: boolean;
  publishing: boolean;
}

interface Item {
  turn: Turn;
  phase: ActivityPhase;
  tool?: string;
  summary?: string;
}

function timestamp(ms: number): string {
  return new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");
}

export class ActivityEmitter {
  private turn: Turn | undefined;
  private attribution: { sessionID: string; encrypted: boolean } | undefined;
  private queue: Item[] = [];
  private timer: ReturnType<typeof setTimeout> | undefined;
  private lastSentAt = Number.NEGATIVE_INFINITY;
  private pausedUntil = 0;
  private stopped = false;
  // Items taken in one flush and returned by a pause go back to the queue's
  // front in their original order.
  private requeued = 0;
  private sending: Promise<void> = Promise.resolve();
  private flushed: (() => void)[] = [];

  constructor(private readonly options: ActivityEmitterOptions) {}

  /** channel-core delivered a chat wake for this session; the next turn serves it. */
  chatWakeDelivered(sessionID: string, options: { encrypted: boolean }): void {
    this.attribution = { sessionID, encrypted: options.encrypted };
  }

  turnStarted(): void {
    this.beginTurn();
    this.enqueue("turn_started");
  }

  thinking(): void {
    this.enqueue("thinking");
  }

  writing(): void {
    this.enqueue("writing");
  }

  tool(name: string, input: unknown): void {
    const turn = this.currentTurn();
    const summary = turn.encrypted ? undefined : summarizeTool(name, input, this.options.workRoot);
    this.enqueue("tool", IDENTIFIER.test(name) ? name : "unknown", summary);
  }

  waitingPermission(name?: string): void {
    this.enqueue("waiting_permission", name !== undefined && IDENTIFIER.test(name) ? name : undefined);
  }

  /** Resolves when every queued event has been published, or publishing stopped. */
  async drained(): Promise<void> {
    for (;;) {
      await this.sending;
      if (this.queue.length === 0 || this.stopped) return;
      await new Promise<void>(resolve => this.flushed.push(resolve));
    }
  }

  turnEnded(): void {
    if (this.turn === undefined) return;
    this.enqueue("turn_ended");
    this.turn = undefined;
  }

  private beginTurn(): Turn {
    const publishing = !this.stopped && readActivitySetting(this.options.identityRoot) === "status";
    this.turn = {
      id: `t-${randomBytes(8).toString("hex")}`,
      seq: 0,
      sessionID: this.attribution?.sessionID ?? null,
      encrypted: this.attribution?.encrypted ?? false,
      publishing,
    };
    this.attribution = undefined;
    return this.turn;
  }

  private currentTurn(): Turn {
    return this.turn ?? this.beginTurn();
  }

  private enqueue(phase: ActivityPhase, tool?: string, summary?: string): void {
    const turn = this.currentTurn();
    if (!turn.publishing || this.stopped) return;
    const item: Item = { turn, phase, tool, summary };
    const last = this.queue[this.queue.length - 1];
    const lastIsState = last !== undefined && last.turn === turn && !BOUNDARIES.has(last.phase);
    if (BOUNDARIES.has(phase)) {
      if (phase === "turn_ended" && lastIsState) this.queue.pop();
      this.queue.push(item);
    } else if (lastIsState) {
      this.queue[this.queue.length - 1] = item;
    } else {
      this.queue.push(item);
    }
    this.schedule();
  }

  /** When the item may be sent: a boundary at once, a state 500 ms after the last send. */
  private dueAt(item: Item): number {
    const earliest = BOUNDARIES.has(item.phase) ? 0 : this.lastSentAt + COALESCE_MS;
    return Math.max(earliest, this.pausedUntil);
  }

  private schedule(): void {
    if (this.timer !== undefined) clearTimeout(this.timer);
    this.timer = undefined;
    const next = this.queue[0];
    if (next === undefined || this.stopped) return;
    this.timer = setTimeout(() => this.flush(), Math.max(0, this.dueAt(next) - Date.now()));
  }

  /** Send every item that is due now, in order, then wait for the next one. */
  private flush(): void {
    this.timer = undefined;
    this.requeued = 0;
    while (this.queue.length > 0 && this.dueAt(this.queue[0]) <= Date.now()) {
      const item = this.queue.shift() as Item;
      this.lastSentAt = Date.now();
      this.sending = this.sending.then(() => this.send(item));
    }
    const waiting = this.flushed;
    this.flushed = [];
    void this.sending.then(() => waiting.forEach(resolve => resolve()));
    this.schedule();
  }

  private async send(item: Item): Promise<void> {
    if (this.stopped) return;
    if (Date.now() < this.pausedUntil) {
      // A 429 arrived after this item was taken: it waits out the pause.
      this.queue.splice(this.requeued++, 0, item);
      this.schedule();
      return;
    }
    item.turn.seq += 1;
    const now = Date.now();
    const { did, stableID, teamID, seed } = this.options.signer;
    const event: ActivityEvent = {
      v: 1,
      type: "agent_activity",
      from_did: did,
      ...(stableID ? { from_stable_id: stableID } : {}),
      team_id: teamID,
      session_id: item.turn.sessionID,
      turn_id: item.turn.id,
      seq: item.turn.seq,
      phase: item.phase,
      ...(item.tool !== undefined ? { tool: item.tool } : {}),
      ...(item.summary !== undefined ? { summary: item.summary } : {}),
      timestamp: timestamp(now),
      expires_at: timestamp(now + VALIDITY_MS),
    };
    let outcome: PublishOutcome;
    try {
      outcome = await this.options.publish(signActivityEvent(event, seed));
    } catch {
      outcome = { kind: "failed" };
    }
    if (outcome.kind === "rate_limited") {
      this.pausedUntil = Date.now() + outcome.retryAfterSeconds * 1000;
    } else if (outcome.kind === "route_absent") {
      this.stopped = true;
      this.queue = [];
      this.options.log?.("aweb activity: this server has no activity route; publishing stops for this process");
      return;
    }
    this.schedule();
  }
}
