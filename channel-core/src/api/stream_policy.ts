import { APIError } from "./client.js";

// The event stream client policy, docs/event-stream-client-policy.md, sections
// 2 to 6, for the TypeScript client of GET /v1/events/stream (events.ts). The
// client owns its connection, its timers and how it reports its state; every
// decision about when a connection closes, what an end means and how long to
// wait is made here.

/** A connection's planned close is drawn uniformly between these (§2). */
export const STREAM_PLANNED_CLOSE_MIN_MS = 3 * 60_000 + 30_000;
export const STREAM_PLANNED_CLOSE_MAX_MS = 4 * 60_000;

/** The delay after a transient failure doubles between these (§3). */
export const STREAM_RETRY_DELAY_MIN_MS = 1000;
export const STREAM_RETRY_DELAY_MAX_MS = 15_000;

/** The delay after a refusal doubles between these (§4). */
export const STREAM_REFUSED_DELAY_MIN_MS = 60_000;
export const STREAM_REFUSED_DELAY_MAX_MS = 15 * 60_000;

/** Caps Retry-After; a larger or unparsable value is treated as this (§3). */
export const STREAM_RETRY_AFTER_MAX_MS = 5 * 60_000;

/**
 * How long an open stream may deliver no bytes: two missed 30-second
 * heartbeats plus 15 seconds (§6). Every byte counts, including comments.
 */
export const STREAM_SILENCE_LIMIT_MS = 75_000;

/** The server ended an open stream with a grant terminal event. */
export class EventStreamClosedError extends Error {
  constructor(
    /** The terminal event's name. */
    public readonly event: string,
    detail: string,
  ) {
    super(`agent event stream closed: ${detail}`);
  }

  /** verification_unavailable says the server could not check the grant. */
  get retryable(): boolean {
    return this.event === "verification_unavailable";
  }
}

/** What the policy takes from outside. Tests supply a clock they advance by hand. */
export interface StreamPolicyConfig {
  /** The time in epoch milliseconds. */
  now?: () => number;
  /** A uniform draw in [0, 1). */
  random?: () => number;
}

/**
 * What the end of one connection attempt means:
 * - planned_close: reconnect at once; not an outage (§2);
 * - transient: retry on the transient delay (§3);
 * - refused: the stream is quarantined (§4).
 */
export type StreamEndKind = "planned_close" | "transient" | "refused";

/** How one connection attempt ended and what the client does next. */
export interface StreamEnd {
  kind: StreamEndKind;
  /**
   * The HTTP status or the terminal event's name. For a refused stream it is
   * the refusal that holds the quarantine. It is empty for a failure that has
   * no such name; error describes it.
   */
  cause: string;
  error?: unknown;
  /** How long to wait before the next attempt; zero for a planned close. */
  waitMs: number;
  /** When the next attempt is made, in epoch milliseconds. */
  nextAttemptAt: number;
  /**
   * True for the end that starts a quarantine and false for every refused
   * retry inside it (§8).
   */
  enteredRefused: boolean;
  /**
   * True for the refusal that starts a refusal episode (§8). An episode ends
   * only when the server serves this caller: an event other than the opening
   * connected event is read, or an open connection reaches its planned close.
   * A heartbeat or connected ends the quarantine but not the episode, so a
   * server that accepts the open, sends them and refuses again, every time,
   * is one episode however many times the quarantine is entered.
   */
  startedRefusalEpisode: boolean;
}

/**
 * Says whether a failed open or the error that ended an open stream is
 * transient or a refusal, and names its cause.
 *
 * 408, 409, 425 and 429 describe a moment, not the caller: they are transient,
 * as is every answer outside 4xx. Every other 4xx is a refusal. The grant
 * terminal events are refusals, except verification_unavailable. Everything
 * else (a failure to open, an early end, a read error, silence) is transient.
 */
export function classifyStreamFailure(error: unknown): { kind: "transient" | "refused"; cause: string } {
  if (error instanceof APIError) {
    const status = error.statusCode;
    const cause = String(status);
    if (status === 408 || status === 409 || status === 425 || status === 429) return { kind: "transient", cause };
    return { kind: status >= 400 && status < 500 ? "refused" : "transient", cause };
  }
  if (error instanceof EventStreamClosedError) {
    return { kind: error.retryable ? "transient" : "refused", cause: error.event };
  }
  return { kind: "transient", cause: "" };
}

const WEEKDAY = "(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)";
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const MONTH = `(${MONTHS.join("|")})`;
const CLOCK = "(\\d{2}):(\\d{2}):(\\d{2})";
// The three HTTP-date forms of RFC 9110, section 5.6.7.
const IMF_FIXDATE = new RegExp(`^${WEEKDAY}, (\\d{2}) ${MONTH} (\\d{4}) ${CLOCK} GMT$`);
const RFC850_DATE = new RegExp(`^(?:Mon|Tues|Wednes|Thurs|Fri|Satur|Sun)day, (\\d{2})-${MONTH}-(\\d{2}) ${CLOCK} GMT$`);
const ASCTIME_DATE = new RegExp(`^${WEEKDAY} ${MONTH} ([ \\d]\\d) ${CLOCK} (\\d{4})$`);

/** Parses an HTTP-date to epoch milliseconds; undefined when it is not one. */
function parseHTTPDate(value: string): number | undefined {
  let day: string, month: string, year: number, hours: string, minutes: string, seconds: string;
  let match = IMF_FIXDATE.exec(value);
  if (match) {
    [, day, month, , hours, minutes, seconds] = match;
    year = Number(match[3]);
  } else if ((match = RFC850_DATE.exec(value))) {
    [, day, month, , hours, minutes, seconds] = match;
    // A two-digit year below 69 is in this century, as Go's net/http reads it.
    year = Number(match[3]) + (Number(match[3]) >= 69 ? 1900 : 2000);
  } else if ((match = ASCTIME_DATE.exec(value))) {
    [, month, day, hours, minutes, seconds] = match;
    year = Number(match[6]);
  } else {
    return undefined;
  }
  const at = new Date(Date.UTC(year, MONTHS.indexOf(month), Number(day), Number(hours), Number(minutes), Number(seconds)));
  // Date.UTC carries an out-of-range field into the next unit; such a value names no moment.
  const exact = at.getUTCDate() === Number(day) && at.getUTCHours() === Number(hours)
    && at.getUTCMinutes() === Number(minutes) && at.getUTCSeconds() === Number(seconds);
  return exact ? at.getTime() : undefined;
}

/**
 * The minimum wait a failed open's Retry-After asks for: delta-seconds or an
 * HTTP-date, capped at STREAM_RETRY_AFTER_MAX_MS. A value that is neither is
 * treated as the cap. It is zero when the answer has no header.
 */
function retryAfterMs(error: unknown, now: number): number {
  const header = error instanceof APIError ? (error.retryAfter || "").trim() : "";
  if (!header) return 0;
  let wait = STREAM_RETRY_AFTER_MAX_MS;
  if (/^\d+$/.test(header)) {
    // Digits beyond the cap, however many, are larger than it.
    const seconds = Number(header);
    if (seconds < STREAM_RETRY_AFTER_MAX_MS / 1000) wait = seconds * 1000;
  } else {
    const at = parseHTTPDate(header);
    if (at !== undefined) wait = at - now;
  }
  return Math.min(Math.max(wait, 0), STREAM_RETRY_AFTER_MAX_MS);
}

/** Holds one stream's reconnect state across its connections. */
export class StreamPolicy {
  private readonly now: () => number;
  private readonly random: () => number;
  private retryDelay = STREAM_RETRY_DELAY_MIN_MS;
  private refusedDelay = STREAM_REFUSED_DELAY_MIN_MS;
  private refusedCause: string | undefined;
  private inRefusalEpisode = false;

  constructor(config: StreamPolicyConfig = {}) {
    this.now = config.now ?? Date.now;
    this.random = config.random ?? Math.random;
  }

  /** Whether the stream is quarantined. */
  get refused(): boolean {
    return this.refusedCause !== undefined;
  }

  /**
   * Starts a connection attempt and draws its planned close. onConfirm is
   * called once if the stream is confirmed live, with the cause of the
   * quarantine that confirmation ended or "".
   */
  connect(onConfirm: (endedRefusal: string) => void = () => {}): StreamConnection {
    const plannedIn = STREAM_PLANNED_CLOSE_MIN_MS
      + Math.floor(this.random() * (STREAM_PLANNED_CLOSE_MAX_MS - STREAM_PLANNED_CLOSE_MIN_MS));
    const attempt: StreamAttempt = {
      now: this.now,
      confirmed: () => this.confirmed(),
      served: () => this.served(),
      failed: (kind, cause, error) => this.failed(kind, cause, error),
    };
    return new StreamConnection(attempt, this.now() + plannedIn, this.refused, onConfirm);
  }

  /** Draws a wait uniformly between half of delay and all of it. */
  private jittered(delay: number): number {
    const half = delay / 2;
    return half + Math.floor(this.random() * (delay - half));
  }

  /**
   * Records that a stream is streaming: its first event or heartbeat has been
   * read, the opening connected event included. The transient delay returns to
   * its start and the refused state ends. It returns the cause of the refusal
   * it ended, or "".
   *
   * The refused delay is left where it is: the server writes its heartbeat and
   * the connected event before it checks the grant, so it can accept the open,
   * send both and then refuse, every time. If either reset the delay, that
   * stream would be retried once a minute for ever.
   */
  private confirmed(): string {
    this.retryDelay = STREAM_RETRY_DELAY_MIN_MS;
    const ended = this.refusedCause ?? "";
    this.refusedCause = undefined;
    return ended;
  }

  /**
   * Records that the server is serving this caller: an event other than the
   * opening connected event was read, or an open connection reached its
   * planned close. The refused delay returns to its start and the refusal
   * episode, if there is one, ends (§4, §8).
   */
  private served(): void {
    this.refusedDelay = STREAM_REFUSED_DELAY_MIN_MS;
    this.inRefusalEpisode = false;
  }

  /**
   * Records a failure and decides the wait before the next attempt.
   *
   * A quarantine holds until a stream is confirmed, so a transient failure
   * inside one keeps the quarantine's pace and its cause.
   */
  private failed(kind: "transient" | "refused", cause: string, error: unknown): StreamEnd {
    const now = this.now();
    let enteredRefused = false;
    let startedRefusalEpisode = false;
    if (kind === "refused") {
      enteredRefused = !this.refused;
      startedRefusalEpisode = !this.inRefusalEpisode;
      this.inRefusalEpisode = true;
      this.refusedCause = cause;
    }
    let delay: number;
    if (this.refusedCause !== undefined) {
      kind = "refused";
      cause = this.refusedCause;
      delay = this.refusedDelay;
      this.refusedDelay = Math.min(delay * 2, STREAM_REFUSED_DELAY_MAX_MS);
    } else {
      delay = this.retryDelay;
      this.retryDelay = Math.min(delay * 2, STREAM_RETRY_DELAY_MAX_MS);
    }
    const waitMs = retryAfterMs(error, now) + this.jittered(delay);
    return { kind, cause, error, waitMs, nextAttemptAt: now + waitMs, enteredRefused, startedRefusalEpisode };
  }
}

/** What a connection reports to the policy that made it. */
interface StreamAttempt {
  now: () => number;
  confirmed: () => string;
  served: () => void;
  failed: (kind: "transient" | "refused", cause: string, error: unknown) => StreamEnd;
}

/** One connection attempt: its planned close and its confirmation. */
export class StreamConnection {
  private isOpen = false;
  private isConfirmed = false;

  constructor(
    private readonly attempt: StreamAttempt,
    /**
     * When the connection closes itself, in epoch milliseconds. The server is
     * asked to end the stream at this deadline.
     */
    public readonly plannedCloseAt: number,
    /**
     * Whether the credentials are read again from where they are kept before
     * this attempt opens: true for every retry of a refused stream and for no
     * other attempt (§4). When they cannot be read the attempt fails without a
     * request.
     */
    public readonly reloadsCredentials: boolean,
    private readonly onConfirm: (endedRefusal: string) => void,
  ) {}

  /** The open was answered with a stream. */
  opened(): void {
    this.isOpen = true;
  }

  /** A heartbeat comment was read: the stream is streaming (§3). */
  comment(): void {
    if (this.isConfirmed) return;
    this.isConfirmed = true;
    this.onConfirm(this.attempt.confirmed());
  }

  /**
   * An event was read. Any event confirms the stream. An event other than the
   * opening connected event also shows the server is serving this caller,
   * which returns the refused delay to its start and ends a refusal episode;
   * connected does not, because the server sends it before it checks the
   * grant.
   */
  event(type: string): void {
    this.comment();
    if (type !== "connected") this.attempt.served();
  }

  /**
   * The connection closed itself at its planned close. An open stream that
   * lasted until then was served, which returns the refused delay to its
   * start and ends a refusal episode; an attempt that was still opening was
   * not.
   */
  reachedPlannedClose(): StreamEnd {
    if (this.isOpen) this.attempt.served();
    return {
      kind: "planned_close", cause: "", waitMs: 0, nextAttemptAt: this.attempt.now(),
      enteredRefused: false, startedRefusalEpisode: false,
    };
  }

  /**
   * The attempt ended by something other than its own planned close. error is
   * what the open or the reading of the stream failed with; it is absent when
   * the server ended the stream without an error.
   */
  ended(error?: unknown): StreamEnd {
    // A server that closes at the deadline it was asked for may do so at the
    // whole second, up to a second before this connection's own timer. That
    // end is the planned close.
    if (error === undefined && this.isOpen && this.attempt.now() >= Math.floor(this.plannedCloseAt / 1000) * 1000) {
      return this.reachedPlannedClose();
    }
    const { kind, cause } = classifyStreamFailure(error);
    return this.attempt.failed(kind, cause, error);
  }
}
