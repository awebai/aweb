import { describe, expect, test } from "vitest";
import { APIError } from "../src/api/client.js";
import {
  classifyStreamFailure,
  EventStreamClosedError,
  STREAM_SILENCE_LIMIT_MS,
  StreamPolicy,
  type StreamEnd,
} from "../src/api/stream_policy.js";

// These tests state docs/event-stream-client-policy.md one rule at a time, case
// for case with cli/go/run/streampolicy_test.go where the rule is decided by
// the policy module. Rules that need a connection (timers, the silence
// watchdog, the wait, stopping) are stated in events.test.ts.

const SECOND = 1000;
const MINUTE = 60 * SECOND;
const START = Date.UTC(2026, 2, 1, 12, 0, 0);

/** The largest value a uniform random source in [0, 1) returns. */
const ALMOST_ONE = 1 - Number.EPSILON / 2;

interface Clock {
  now: number;
  random: number;
}

function newPolicy(random = 0, now = START): { clock: Clock; policy: StreamPolicy } {
  const clock = { now, random };
  return { clock, policy: new StreamPolicy({ now: () => clock.now, random: () => clock.random }) };
}

function httpFailure(status: number, retryAfter?: string): APIError {
  return new APIError(status, "", undefined, retryAfter);
}

function grantClosed(event: string): EventStreamClosedError {
  return new EventStreamClosedError(event, `identity ${event}`);
}

type Read = "comment" | { event: string };

interface Attempt {
  /** The open fails with this. */
  fail?: unknown;
  /** What an opened stream delivers, in order. */
  reads?: Read[];
  /** What ends an opened stream; absent for an end without an error. */
  error?: unknown;
  /** The connection reaches its planned close instead of ending. */
  plannedClose?: boolean;
}

/** Makes one connection attempt and reports how it ended and what its confirmation said had ended. */
function attempt(policy: StreamPolicy, script: Attempt): { end: StreamEnd; confirmations: string[] } {
  const confirmations: string[] = [];
  const connection = policy.connect((endedRefusal) => confirmations.push(endedRefusal));
  if (script.fail !== undefined) return { end: connection.ended(script.fail), confirmations };
  connection.opened();
  for (const read of script.reads || []) {
    if (read === "comment") connection.comment();
    else connection.event(read.event);
  }
  const end = script.plannedClose ? connection.reachedPlannedClose() : connection.ended(script.error);
  return { end, confirmations };
}

const fails = (error: unknown): Attempt => ({ fail: error });
const CONNECTED: Read = { event: "connected" };
const MAIL: Read = { event: "mail_message" };

function isTransientStatus(status: number): boolean {
  return status === 408 || status === 409 || status === 425 || status === 429;
}

// Sections 3 and 4, and decision 2: 408, 409, 425 and 429 and every 5xx are
// transient; every other 4xx is a refusal; the four grant terminal events are
// refusals and verification_unavailable is transient.
describe("classifies every answer", () => {
  interface Classification {
    name: string;
    error: unknown;
    kind: "transient" | "refused";
    cause: string;
  }
  const cases: Classification[] = [];
  for (let status = 400; status <= 499; status++) {
    cases.push({ name: `http ${status}`, error: httpFailure(status), kind: isTransientStatus(status) ? "transient" : "refused", cause: String(status) });
  }
  for (let status = 500; status <= 599; status++) {
    cases.push({ name: `http ${status}`, error: httpFailure(status), kind: "transient", cause: String(status) });
  }
  for (const event of ["grant_expired", "grant_revoked", "grant_subject_inactive", "grant_issuer_revoked"]) {
    cases.push({ name: event, error: grantClosed(event), kind: "refused", cause: event });
  }
  cases.push(
    { name: "the named refusals 401", error: httpFailure(401), kind: "refused", cause: "401" },
    { name: "the named refusals 403", error: httpFailure(403), kind: "refused", cause: "403" },
    { name: "the named refusals 404", error: httpFailure(404), kind: "refused", cause: "404" },
    { name: "the named refusals 422", error: httpFailure(422), kind: "refused", cause: "422" },
    { name: "other 4xx 400", error: httpFailure(400), kind: "refused", cause: "400" },
    { name: "other 4xx 405", error: httpFailure(405), kind: "refused", cause: "405" },
    { name: "other 4xx 410", error: httpFailure(410), kind: "refused", cause: "410" },
    { name: "other 4xx 451", error: httpFailure(451), kind: "refused", cause: "451" },
    { name: "moment 408", error: httpFailure(408), kind: "transient", cause: "408" },
    { name: "moment 409", error: httpFailure(409), kind: "transient", cause: "409" },
    { name: "moment 425", error: httpFailure(425), kind: "transient", cause: "425" },
    { name: "moment 429", error: httpFailure(429), kind: "transient", cause: "429" },
    { name: "redirect answer", error: httpFailure(302), kind: "transient", cause: "302" },
    { name: "verification_unavailable", error: grantClosed("verification_unavailable"), kind: "transient", cause: "verification_unavailable" },
    { name: "read error", error: new TypeError("terminated"), kind: "transient", cause: "" },
    { name: "failure to open", error: new TypeError("fetch failed", { cause: Object.assign(new Error("connect ECONNREFUSED"), { code: "ECONNREFUSED" }) }), kind: "transient", cause: "" },
    { name: "silence", error: new Error("event stream heartbeat timed out"), kind: "transient", cause: "" },
    { name: "a thrown value that is not an error", error: "closed", kind: "transient", cause: "" },
    { name: "end without an error", error: undefined, kind: "transient", cause: "" },
  );
  test.each(cases)("$name", ({ error, kind, cause }) => {
    expect(classifyStreamFailure(error)).toEqual({ kind, cause });
  });

  test("an end without an error before the planned close is an early end", () => {
    const { policy } = newPolicy();
    const { end } = attempt(policy, { reads: [CONNECTED] });
    expect(end.kind).toBe("transient");
  });
});

// Sections 3 and 4: each wait is drawn uniformly between half of the delay and
// all of it, on both ladders.
describe("jitter bounds", () => {
  const ladders = [
    { name: "transient", error: httpFailure(503), delay: SECOND },
    { name: "refused", error: httpFailure(401), delay: MINUTE },
  ];
  const draws = [
    { name: "lowest draw is half the delay", random: 0, check: (delay: number, wait: number) => wait === delay / 2 },
    { name: "middle draw is three quarters", random: 0.5, check: (delay: number, wait: number) => wait === (delay * 3) / 4 },
    { name: "highest draw is just under the delay", random: ALMOST_ONE, check: (delay: number, wait: number) => wait < delay && wait >= delay - 1 },
  ];
  for (const ladder of ladders) {
    for (const draw of draws) {
      test(`${ladder.name}: ${draw.name}`, () => {
        const { policy } = newPolicy(draw.random);
        const { end } = attempt(policy, fails(ladder.error));
        expect(draw.check(ladder.delay, end.waitMs), `wait=${end.waitMs}`).toBe(true);
        expect(end.nextAttemptAt).toBe(START + end.waitMs);
      });
    }
  }
});

// Section 3: 1 second doubling to 15 seconds. Section 4: 1 minute doubling to
// 15 minutes.
describe("ladders grow to their ceilings", () => {
  test.each([
    { name: "transient", error: httpFailure(503), kind: "transient", unit: SECOND },
    { name: "refused", error: httpFailure(403), kind: "refused", unit: MINUTE },
  ])("$name", ({ error, kind, unit }) => {
    const { policy } = newPolicy();
    for (const delay of [1, 2, 4, 8, 15, 15, 15]) {
      const { end } = attempt(policy, fails(error));
      expect(end.kind).toBe(kind);
      // The lowest draw is half of the delay.
      expect(end.waitMs).toBe((delay * unit) / 2);
    }
  });
});

// Section 3: the delay returns to 1 second only once a stream is confirmed
// live. An open that returns 200 and then closes does not reset it.
describe("the transient delay resets only on a confirmed stream", () => {
  const transientWaits = (policy: StreamPolicy, script: Attempt[], want: number[]) => {
    script.forEach((step, index) => {
      const { end } = attempt(policy, step);
      expect(end.kind, `step ${index}`).toBe("transient");
      expect(end.waitMs, `step ${index}`).toBe((want[index] * SECOND) / 2);
    });
  };

  test("an open that closes without an event does not reset", () => {
    const { policy } = newPolicy();
    transientWaits(policy, [fails(httpFailure(503)), fails(httpFailure(503)), {}, fails(httpFailure(503))], [1, 2, 4, 8]);
  });

  test("the first event resets", () => {
    const { policy } = newPolicy();
    transientWaits(policy, [fails(httpFailure(503)), fails(httpFailure(503)), { reads: [CONNECTED] }, fails(httpFailure(503))], [1, 2, 1, 2]);
  });

  test("the first heartbeat resets and confirms once", () => {
    const { policy } = newPolicy();
    attempt(policy, fails(httpFailure(503)));
    attempt(policy, fails(httpFailure(503)));
    const { end, confirmations } = attempt(policy, { reads: ["comment", "comment"] });
    expect(confirmations).toEqual([""]);
    expect(end.kind).toBe("transient");
    expect(end.waitMs).toBe(SECOND / 2);
  });
});

// Section 3: Retry-After is a minimum wait up to 5 minutes; a larger or
// unparsable value is treated as 5 minutes; the jitter is added to it.
describe("honours Retry-After", () => {
  const httpDate = (offsetMs: number) => new Date(START + offsetMs).toUTCString();
  const cases = [
    { name: "absent", header: undefined, want: 0 },
    { name: "empty", header: "", want: 0 },
    { name: "zero seconds", header: "0", want: 0 },
    { name: "seconds below the cap", header: "120", want: 2 * MINUTE },
    { name: "seconds just below the cap", header: "299", want: 299 * SECOND },
    { name: "seconds at the cap", header: "300", want: 5 * MINUTE },
    { name: "seconds above the cap", header: "301", want: 5 * MINUTE },
    { name: "seconds far above the cap", header: "86400", want: 5 * MINUTE },
    { name: "seconds beyond any integer", header: "99999999999999999999999", want: 5 * MINUTE },
    { name: "padded seconds", header: " 7 ", want: 7 * SECOND },
    { name: "date below the cap", header: httpDate(90 * SECOND), want: 90 * SECOND },
    { name: "date at the cap", header: httpDate(5 * MINUTE), want: 5 * MINUTE },
    { name: "date above the cap", header: httpDate(60 * MINUTE), want: 5 * MINUTE },
    { name: "date in the past", header: httpDate(-60 * MINUTE), want: 0 },
    { name: "date in the obsolete RFC 850 form", header: "Sunday, 01-Mar-26 12:01:30 GMT", want: 90 * SECOND },
    { name: "date in the asctime form", header: "Sun Mar  1 12:01:30 2026", want: 90 * SECOND },
    { name: "date that names no day", header: "Sun, 31 Feb 2026 12:01:30 GMT", want: 5 * MINUTE },
    { name: "date without a zone", header: "2026-03-01T12:01:30", want: 5 * MINUTE },
    { name: "unparsable", header: "soon", want: 5 * MINUTE },
    { name: "negative seconds", header: "-5", want: 5 * MINUTE },
    { name: "fractional seconds", header: "1.5", want: 5 * MINUTE },
  ];
  const answers = [
    { status: 429, delay: SECOND },
    { status: 503, delay: SECOND },
    // Section 4 gives a refusal the same jitter; a Retry-After on a refusal is
    // a minimum in the same way.
    { status: 403, delay: MINUTE },
  ];
  for (const answer of answers) {
    for (const tc of cases) {
      for (const random of [0, 0.5]) {
        test(`${answer.status}: ${tc.name}, draw ${random}`, () => {
          const { policy } = newPolicy(random);
          const { end } = attempt(policy, fails(httpFailure(answer.status, tc.header)));
          const jitter = answer.delay / 2 + random * (answer.delay / 2);
          expect(end.waitMs).toBe(tc.want + jitter);
          expect(end.nextAttemptAt).toBe(START + end.waitMs);
        });
      }
    }
  }

  test("an answer without the header does not carry one over", () => {
    const { policy } = newPolicy();
    attempt(policy, fails(httpFailure(429, "120")));
    expect(attempt(policy, fails(httpFailure(429))).end.waitMs).toBe(SECOND);
  });
});

// Section 2: each connection's planned close is drawn uniformly between
// 3 minutes 30 seconds and 4 minutes, and it is not a failure.
describe("planned close", () => {
  test.each([
    { name: "lowest draw", random: 0, check: (ms: number) => ms === 3 * MINUTE + 30 * SECOND },
    { name: "middle draw", random: 0.5, check: (ms: number) => ms === 3 * MINUTE + 45 * SECOND },
    { name: "highest draw", random: ALMOST_ONE, check: (ms: number) => ms < 4 * MINUTE && ms >= 4 * MINUTE - 1 },
  ])("$name", ({ random, check }) => {
    const { clock, policy } = newPolicy(random);
    const connection = policy.connect();
    const planned = connection.plannedCloseAt - START;
    expect(check(planned), `planned close after ${planned}ms`).toBe(true);
    connection.opened();
    connection.event("connected");
    clock.now = connection.plannedCloseAt;
    const end = connection.reachedPlannedClose();
    expect(end).toMatchObject({ kind: "planned_close", waitMs: 0, enteredRefused: false });
    expect(end.nextAttemptAt).toBe(clock.now);
  });

  test("a draw is made for each connection", () => {
    const { clock, policy } = newPolicy();
    const first = policy.connect().plannedCloseAt;
    clock.random = 0.5;
    expect(policy.connect().plannedCloseAt - first).toBe(15 * SECOND);
  });

  test("a planned close does not move the transient delay", () => {
    const { policy } = newPolicy();
    attempt(policy, fails(httpFailure(503)));
    expect(attempt(policy, { plannedClose: true }).end.kind).toBe("planned_close");
    // A planned close is neither a failure nor a confirmation.
    expect(attempt(policy, fails(httpFailure(503))).end.waitMs).toBe(SECOND);
  });

  test("the server closing at the deadline it was asked for is the planned close", () => {
    // The server may close at the whole second of the deadline, up to a second
    // before the client's own timer.
    const { clock, policy } = newPolicy(0, START + 400);
    const connection = policy.connect();
    connection.opened();
    connection.event("connected");
    clock.now = START + 3 * MINUTE + 30 * SECOND;
    expect(clock.now).toBeLessThan(connection.plannedCloseAt);
    expect(connection.ended().kind).toBe("planned_close");
  });

  test("the server closing before the deadline is an early end", () => {
    const { clock, policy } = newPolicy(0, START + 400);
    const connection = policy.connect();
    connection.opened();
    connection.event("connected");
    clock.now = START + 3 * MINUTE + 30 * SECOND - 1;
    expect(connection.ended().kind).toBe("transient");
  });

  test("a read error at the deadline is a failure", () => {
    const { clock, policy } = newPolicy();
    const connection = policy.connect();
    connection.opened();
    clock.now = connection.plannedCloseAt;
    expect(connection.ended(new TypeError("terminated")).kind).toBe("transient");
  });
});

// Section 6: the limit is two missed 30-second heartbeats plus 15 seconds. The
// watchdog that applies it to every byte read is the connection's
// (events.test.ts).
test("the silence limit is 75 seconds", () => {
  expect(STREAM_SILENCE_LIMIT_MS).toBe(75 * SECOND);
});

// Section 4: a refused stream is quarantined.
describe("quarantine", () => {
  test("a refusal is reported once, on entry", () => {
    const { policy } = newPolicy();
    const first = attempt(policy, fails(httpFailure(401))).end;
    expect(first).toMatchObject({ kind: "refused", cause: "401", enteredRefused: true });
    for (let i = 0; i < 3; i++) {
      expect(attempt(policy, fails(httpFailure(401))).end).toMatchObject({ kind: "refused", enteredRefused: false });
    }
  });

  test("a grant terminal event on an open stream quarantines it", () => {
    const { policy } = newPolicy();
    const { end } = attempt(policy, { reads: [CONNECTED], error: grantClosed("grant_revoked") });
    expect(end).toMatchObject({ kind: "refused", cause: "grant_revoked", enteredRefused: true, waitMs: 30 * SECOND });
  });

  test("the first confirmed stream ends it and names what it ended", () => {
    const { policy } = newPolicy();
    attempt(policy, fails(httpFailure(401)));
    attempt(policy, fails(httpFailure(403)));
    expect(policy.refused).toBe(true);

    // An open that returns 200 and closes is not a confirmed stream.
    const unconfirmed = attempt(policy, {});
    expect(unconfirmed.end).toMatchObject({ kind: "refused", enteredRefused: false, cause: "403", waitMs: 2 * MINUTE });
    expect(unconfirmed.confirmations).toEqual([]);
    expect(policy.refused).toBe(true);

    const confirmed = attempt(policy, { reads: [CONNECTED, MAIL] });
    expect(confirmed.confirmations).toEqual(["403"]);
    expect(policy.refused).toBe(false);
    expect(confirmed.end).toMatchObject({ kind: "transient", waitMs: SECOND / 2 });
    // Both ladders start over.
    expect(attempt(policy, fails(httpFailure(401))).end).toMatchObject({ kind: "refused", enteredRefused: true, waitMs: 30 * SECOND });
  });

  test("a confirmation outside a quarantine names none", () => {
    const { policy } = newPolicy();
    expect(attempt(policy, { reads: [CONNECTED] }).confirmations).toEqual([""]);
  });

  test("a transient failure does not end it", () => {
    const { policy } = newPolicy();
    attempt(policy, fails(httpFailure(401)));
    for (const [step, delay] of [[fails(httpFailure(503)), 2 * MINUTE], [fails(new TypeError("fetch failed")), 4 * MINUTE]] as const) {
      const { end } = attempt(policy, step);
      expect(end).toMatchObject({ kind: "refused", enteredRefused: false, cause: "401", waitMs: delay / 2 });
    }
  });

  test("a failure inside it carries the failure's own Retry-After", () => {
    const { policy } = newPolicy();
    attempt(policy, fails(httpFailure(401)));
    const { end } = attempt(policy, fails(httpFailure(503, "120")));
    expect(end).toMatchObject({ kind: "refused", cause: "401", waitMs: 2 * MINUTE + MINUTE });
  });
});

// Section 4: before each retry of a refused stream the credentials are read
// again from where they are kept, and only then.
describe("reloads credentials before each refused retry", () => {
  test("every connection made in quarantine reloads and no other does", () => {
    const { policy } = newPolicy();
    // Transient failures retry with what the client holds.
    for (let i = 0; i < 2; i++) {
      const connection = policy.connect();
      expect(connection.reloadsCredentials).toBe(false);
      connection.ended(httpFailure(503));
    }
    policy.connect().ended(httpFailure(401));
    for (let i = 0; i < 2; i++) {
      const connection = policy.connect();
      expect(connection.reloadsCredentials).toBe(true);
      connection.ended(i === 0 ? httpFailure(401) : httpFailure(503));
    }
    const accepted = policy.connect();
    expect(accepted.reloadsCredentials).toBe(true);
    accepted.opened();
    accepted.event("connected");
    accepted.ended();
    expect(policy.refused).toBe(false);
    // Streaming again: the next attempt does not reload.
    expect(policy.connect().reloadsCredentials).toBe(false);
  });

  test("credentials that cannot be read fail the attempt at the quarantine pace", () => {
    const { policy } = newPolicy();
    attempt(policy, fails(httpFailure(401)));
    const unreadable = new Error("certificate unreadable");
    const { end } = attempt(policy, fails(unreadable));
    expect(end).toMatchObject({ kind: "refused", enteredRefused: false, cause: "401", waitMs: MINUTE });
    expect(end.error).toBe(unreadable);
  });
});

// Sections 3 and 4: a heartbeat confirms the stream is streaming, which ends
// the refused state and returns the transient delay to 1 second. The refused
// delay returns to 1 minute only after an event that is neither a comment nor
// the opening connected event, or when a connection reaches its planned close.
// A server that accepts the open, sends a heartbeat and then a grant terminal
// event, every time, is retried at a growing interval and not once a minute.
describe("refused delay resets", () => {
  /** A stream that delivers a heartbeat comment, then reads, then a grant terminal event. */
  const flap = (policy: StreamPolicy, ...reads: Read[]) =>
    attempt(policy, { reads: ["comment", ...reads], error: grantClosed("grant_revoked") });

  const refusedWaits = (policy: StreamPolicy, ...minutes: number[]) => {
    minutes.forEach((delay, cycle) => {
      const { end, confirmations } = flap(policy);
      expect(end, `cycle ${cycle}`).toMatchObject({ kind: "refused", cause: "grant_revoked" });
      // The lowest draw is half of the delay.
      expect(end.waitMs, `cycle ${cycle}`).toBe((delay * MINUTE) / 2);
      // Each cycle leaves refused on the heartbeat and enters it again on the
      // terminal event.
      expect(confirmations, `cycle ${cycle}`).toHaveLength(1);
      expect(end.enteredRefused, `cycle ${cycle}`).toBe(true);
    });
  };

  test("a heartbeat then a terminal event, repeated, grows to the ceiling", () => {
    const { policy } = newPolicy();
    const ended: string[] = [];
    for (const delay of [1, 2, 4, 8, 15, 15, 15, 15]) {
      const { end, confirmations } = flap(policy);
      expect(end).toMatchObject({ kind: "refused", enteredRefused: true, waitMs: (delay * MINUTE) / 2 });
      ended.push(...confirmations);
      expect(policy.refused).toBe(true);
    }
    // The first heartbeat ends no refusal; each later one ends the last.
    expect(ended).toEqual(["", ...Array(7).fill("grant_revoked")]);
  });

  test("a heartbeat, the opening connected event, then a terminal event, repeated, grows to the ceiling", () => {
    // What the server sends: it writes its heartbeat and the connected event
    // before it checks the grant.
    const { policy } = newPolicy();
    for (const delay of [1, 2, 4, 8, 15, 15]) {
      const { end, confirmations } = flap(policy, CONNECTED);
      expect(end).toMatchObject({ kind: "refused", enteredRefused: true, waitMs: (delay * MINUTE) / 2 });
      expect(confirmations).toHaveLength(1);
    }
  });

  test("the connected event confirms the stream and leaves the refused delay", () => {
    const { policy } = newPolicy();
    attempt(policy, fails(httpFailure(401)));
    attempt(policy, fails(httpFailure(401)));
    attempt(policy, fails(httpFailure(503)));

    // Refused delay at 8 minutes; no heartbeat, only the connected event.
    const { end, confirmations } = attempt(policy, { reads: [CONNECTED] });
    expect(confirmations).toEqual(["401"]);
    expect(policy.refused).toBe(false);
    expect(end).toMatchObject({ kind: "transient", waitMs: SECOND / 2 });
    expect(attempt(policy, fails(httpFailure(401))).end).toMatchObject({ kind: "refused", enteredRefused: true, waitMs: 4 * MINUTE });
  });

  test("a heartbeat ends the refused state and resets the transient delay", () => {
    const { policy } = newPolicy();
    refusedWaits(policy, 1, 2);
    const { end, confirmations } = attempt(policy, { reads: ["comment"] });
    expect(confirmations).toEqual(["grant_revoked"]);
    expect(end).toMatchObject({ kind: "transient", waitMs: SECOND / 2 });
    // The refused delay is where the flap left it.
    refusedWaits(policy, 4);
  });

  test("an event that is neither a comment nor connected returns the refused delay to 1 minute", () => {
    const { policy } = newPolicy();
    refusedWaits(policy, 1, 2, 4);
    const { end } = flap(policy, MAIL);
    expect(end).toMatchObject({ kind: "refused", enteredRefused: true, waitMs: 30 * SECOND });
    refusedWaits(policy, 2);
  });

  test("reaching the planned close returns the refused delay to 1 minute", () => {
    const { policy } = newPolicy();
    refusedWaits(policy, 1, 2, 4);
    // A connection that delivers only heartbeats, up to its planned close.
    const { end } = attempt(policy, { reads: Array<Read>(7).fill("comment"), plannedClose: true });
    expect(end.kind).toBe("planned_close");
    refusedWaits(policy, 1, 2);
  });

  test("the server closing at the deadline it was asked for returns the refused delay to 1 minute", () => {
    const { clock, policy } = newPolicy();
    refusedWaits(policy, 1, 2, 4);
    const connection = policy.connect();
    connection.opened();
    connection.comment();
    clock.now = connection.plannedCloseAt;
    expect(connection.ended().kind).toBe("planned_close");
    refusedWaits(policy, 1);
  });

  test("an attempt that reaches the deadline without opening does not", () => {
    const { policy } = newPolicy();
    attempt(policy, fails(httpFailure(401)));
    attempt(policy, fails(httpFailure(401)));
    const unopened = policy.connect().reachedPlannedClose();
    expect(unopened.kind).toBe("planned_close");
    expect(policy.refused).toBe(true);
    expect(attempt(policy, fails(httpFailure(401))).end).toMatchObject({ kind: "refused", enteredRefused: false, waitMs: 2 * MINUTE });
  });

  test("a refusal on open after a heartbeat-only stream continues the delay", () => {
    const { policy } = newPolicy();
    expect(attempt(policy, fails(httpFailure(403))).end.waitMs).toBe(30 * SECOND);
    expect(attempt(policy, { reads: ["comment"] }).end.kind).toBe("transient");
    expect(attempt(policy, fails(httpFailure(403))).end).toMatchObject({ kind: "refused", enteredRefused: true, waitMs: MINUTE });
  });
});

// The defaults are the real clock and random source.
test("defaults", () => {
  const policy = new StreamPolicy();
  const before = Date.now();
  const end = policy.connect().ended(httpFailure(503));
  expect(end.waitMs).toBeGreaterThanOrEqual(SECOND / 2);
  expect(end.waitMs).toBeLessThanOrEqual(SECOND);
  expect(end.nextAttemptAt).toBeGreaterThanOrEqual(before + end.waitMs);
});
