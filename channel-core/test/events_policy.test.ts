import { getEventListeners } from "node:events";
import { mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import * as ed from "@noble/ed25519";
import { createActivityEmitter } from "../src/activity/runtime.js";
import { APIError, type APIClient } from "../src/api/client.js";
import { formatEventStreamState, streamAgentEvents, type EventStreamOptions, type EventStreamState } from "../src/api/events.js";
import {
  createChannelClient, createChannelCredentialReload, eventStreamRefusedAwakening, formatAwakeningForAgent, PinStore,
  ReceiveStreamReceipt, SenderTrustManager, startChannelLoop, type ChannelAwakening,
} from "../src/index.js";
import { resolveConfig, type AgentConfig } from "../src/config.js";
import { writeTestPrincipal } from "./helpers/config_fixture.js";

// The event stream client under docs/event-stream-client-policy.md: what the
// client does with the policy's decisions (stream_policy.test.ts states the
// decisions themselves). Time is vitest's fake clock; the random source is
// injected.

const SECOND = 1000;
const MINUTE = 60 * SECOND;
const START = Date.UTC(2026, 2, 1, 12, 0, 0);

/** The largest value a uniform random source in [0, 1) returns. */
const ALMOST_ONE = 1 - Number.EPSILON / 2;

const encoder = new TextEncoder();
const frame = (event: string, payload: object = {}) => encoder.encode(`event: ${event}\ndata: ${JSON.stringify(payload)}\n\n`);
const heartbeat = () => encoder.encode(": keepalive\n\n");

type Answer = () => Response;

/** The open is answered with this status. */
const answers = (status: number, retryAfter?: string): Answer => () => {
  throw new APIError(status, "", undefined, retryAfter);
};

/** The open is answered with a stream that delivers the chunks and stays open. */
const streams = (...chunks: Uint8Array[]): Answer => () => new Response(new ReadableStream<Uint8Array>({
  start(controller) {
    for (const chunk of chunks) controller.enqueue(chunk);
  },
}));

/** The open is answered with a stream that delivers the chunks and ends. */
const closes = (...chunks: Uint8Array[]): Answer => () => new Response(new ReadableStream<Uint8Array>({
  start(controller) {
    for (const chunk of chunks) controller.enqueue(chunk);
    controller.close();
  },
}));

/** A client whose opens are answered in order; the last answer repeats. */
function scriptedClient(...script: Answer[]) {
  let opens = 0;
  const openSSE = vi.fn(async (_path: string, _signal?: AbortSignal) => script[Math.min(opens++, script.length - 1)]());
  return { client: { openSSE } as never, openSSE };
}

function run(client: never, options: EventStreamOptions = {}) {
  const abort = new AbortController();
  const states: EventStreamState[] = [];
  const received: string[] = [];
  let finished = false;
  const done = (async () => {
    for await (const event of streamAgentEvents(client, abort.signal, (state) => states.push(state), undefined, undefined, options)) {
      received.push(event.type);
    }
    finished = true;
  })();
  return { abort, states, received, done, finished: () => finished };
}

/** Lets everything that is ready run without moving the clock. */
const settle = () => vi.advanceTimersByTimeAsync(0);

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] });
  vi.setSystemTime(START);
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("transient failures", () => {
  test("a 429 with Retry-After on open, then a successful open, delivers events again", async () => {
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(new Response("slow down", { status: 429, headers: { "Retry-After": "2" } }))
      .mockResolvedValueOnce(streams(frame("connected"), frame("actionable_mail", { message_id: "m-1" }))());
    vi.stubGlobal("fetch", fetchMock);
    const client = createChannelClient({
      baseURL: "https://aweb.test",
      did: "did:key:z6Mktest",
      stableID: "did:aw:test",
      signingKey: new Uint8Array(32).fill(1),
      teamID: "backend:aweb.test",
      teamCertificateHeader: "certificate",
    });
    const stream = run(client as never, { random: () => 0 });
    await settle();

    // Retry-After is a minimum; the lowest draw adds half of 1 second to it.
    expect(stream.states).toEqual([
      { state: "disconnected", cause: "http 429", retryInMs: 2 * SECOND + 500, nextAttemptAt: START + 2 * SECOND + 500 },
    ]);
    await vi.advanceTimersByTimeAsync(2 * SECOND + 499);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(stream.received).toEqual(["connected", "mail_message"]);
    expect(stream.states.slice(1)).toEqual([{ state: "reconnected" }]);

    stream.abort.abort();
    await stream.done;
  });

  test("an open that returns 200 and closes does not confirm the stream; a heartbeat does", async () => {
    const { client, openSSE } = scriptedClient(closes(), closes(), streams(heartbeat()));
    const stream = run(client, { random: () => 0 });
    await settle();
    expect(stream.states).toEqual([
      { state: "disconnected", cause: "connection closed", retryInMs: 500, nextAttemptAt: START + 500 },
    ]);

    await vi.advanceTimersByTimeAsync(500);
    expect(openSSE).toHaveBeenCalledTimes(2);
    // The delay was not returned to its start: the lowest draw waits half of 2 seconds.
    await vi.advanceTimersByTimeAsync(999);
    expect(openSSE).toHaveBeenCalledTimes(2);
    expect(stream.states).toHaveLength(1);

    await vi.advanceTimersByTimeAsync(1);
    expect(openSSE).toHaveBeenCalledTimes(3);
    expect(stream.received).toEqual([]);
    expect(stream.states.slice(1)).toEqual([{ state: "reconnected" }]);

    stream.abort.abort();
    await stream.done;
  });
});

describe("refusals", () => {
  test("a 401 is retried one minute later and the successful open is reported once", async () => {
    const { client, openSSE } = scriptedClient(answers(401), streams(frame("connected")));
    const stream = run(client, { random: () => ALMOST_ONE });
    await settle();

    // The highest draw waits just under the delay of 1 minute.
    expect(stream.states).toEqual([
      { state: "refused", cause: "401", retryInMs: MINUTE - 1, nextAttemptAt: START + MINUTE - 1, startsEpisode: true },
    ]);
    await vi.advanceTimersByTimeAsync(MINUTE - 2);
    expect(openSSE).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(openSSE).toHaveBeenCalledTimes(2);
    expect(stream.received).toEqual(["connected"]);
    expect(stream.states.slice(1)).toEqual([{ state: "reconnected", endedRefusal: "401" }]);

    stream.abort.abort();
    await stream.done;
  });

  test("several refused retries give one notice on entry and one on exit", async () => {
    const { client, openSSE } = scriptedClient(
      answers(401), answers(401), answers(503), answers(403), streams(frame("connected")),
    );
    const stream = run(client, { random: () => 0 });
    await settle();
    expect(stream.states).toEqual([
      { state: "refused", cause: "401", retryInMs: 30 * SECOND, nextAttemptAt: START + 30 * SECOND, startsEpisode: true },
    ]);

    // The lowest draw waits half of 1, 2, 4 and 8 minutes; a 5xx inside the
    // quarantine keeps its pace.
    let opens = 1;
    for (const wait of [30 * SECOND, MINUTE, 2 * MINUTE]) {
      await vi.advanceTimersByTimeAsync(wait - 1);
      expect(openSSE).toHaveBeenCalledTimes(opens);
      await vi.advanceTimersByTimeAsync(1);
      expect(openSSE).toHaveBeenCalledTimes(++opens);
      expect(stream.states).toHaveLength(1);
    }
    await vi.advanceTimersByTimeAsync(4 * MINUTE);
    expect(openSSE).toHaveBeenCalledTimes(5);
    expect(stream.states.slice(1)).toEqual([{ state: "reconnected", endedRefusal: "403" }]);
    expect(stream.states.map(formatEventStreamState)).toEqual([
      expect.stringMatching(/^aweb: event stream refused: 401, next try \d\d:\d\d$/),
      "aweb: event stream accepted again (was refused: 403)",
    ]);

    stream.abort.abort();
    await stream.done;
  });

  test("a stream that sends its heartbeat and connected event and then a grant terminal event is retried at a growing interval", async () => {
    const { client, openSSE } = scriptedClient(
      closes(heartbeat(), frame("connected"), frame("grant_revoked", { detail: "identity grant revoked" })),
    );
    const stream = run(client, { random: () => 0 });
    await settle();
    await vi.advanceTimersByTimeAsync(30 * SECOND);
    await vi.advanceTimersByTimeAsync(MINUTE);
    expect(openSSE).toHaveBeenCalledTimes(3);
    await vi.advanceTimersByTimeAsync(2 * MINUTE - 1);
    expect(openSSE).toHaveBeenCalledTimes(3);

    // Each connection leaves refused on its heartbeat and enters it again on
    // the terminal event.
    expect(stream.states.map((state) => [state.state, state.cause ?? state.endedRefusal, state.retryInMs])).toEqual([
      ["connected", undefined, undefined],
      ["refused", "grant_revoked", 30 * SECOND],
      ["reconnected", "grant_revoked", undefined],
      ["refused", "grant_revoked", MINUTE],
      ["reconnected", "grant_revoked", undefined],
      ["refused", "grant_revoked", 2 * MINUTE],
    ]);
    expect(stream.received).toEqual(["connected", "connected", "connected"]);
    // The three refusals are one episode: the server never served this caller.
    expect(stream.states.map((state) => state.startsEpisode)).toEqual([undefined, true, undefined, undefined, undefined, undefined]);

    stream.abort.abort();
    await stream.done;
  });

  test("a restart of the channel during a quarantine retries at once and continues from the 1-minute delay", async () => {
    const { client, openSSE } = scriptedClient(answers(401));
    const first = run(client, { random: () => 0 });
    await settle();
    await vi.advanceTimersByTimeAsync(30 * SECOND);
    await vi.advanceTimersByTimeAsync(MINUTE);
    expect(openSSE).toHaveBeenCalledTimes(3);
    first.abort.abort();
    await first.done;

    const restarted = run(client, { random: () => 0 });
    await settle();
    expect(openSSE).toHaveBeenCalledTimes(4);
    expect(restarted.states).toEqual([
      { state: "refused", cause: "401", retryInMs: 30 * SECOND, nextAttemptAt: Date.now() + 30 * SECOND, startsEpisode: true },
    ]);

    restarted.abort.abort();
    await restarted.done;
  });
});

describe("stopping", () => {
  test("during a refused wait returns at once", async () => {
    const { client, openSSE } = scriptedClient(answers(401));
    const stream = run(client, { random: () => 0 });
    await settle();
    expect(stream.states).toHaveLength(1);

    stream.abort.abort();
    await settle();
    expect(stream.finished()).toBe(true);
    expect(vi.getTimerCount()).toBe(0);
    expect(getEventListeners(stream.abort.signal, "abort")).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(15 * MINUTE);
    expect(openSSE).toHaveBeenCalledTimes(1);
  });

  test("during a credential reload returns at once and makes no request", async () => {
    const { client, openSSE } = scriptedClient(answers(401));
    const reloads: AbortSignal[] = [];
    const reloadCredentials = (signal: AbortSignal) => {
      reloads.push(signal);
      return new Promise<void>(() => {});
    };
    const stream = run(client, { random: () => 0, reloadCredentials });
    await settle();
    await vi.advanceTimersByTimeAsync(30 * SECOND);
    expect(reloads).toHaveLength(1);
    expect(reloads[0].aborted).toBe(false);
    expect(stream.finished()).toBe(false);

    stream.abort.abort();
    await settle();
    expect(stream.finished()).toBe(true);
    expect(reloads[0].aborted).toBe(true);
    expect(openSSE).toHaveBeenCalledTimes(1);
    expect(vi.getTimerCount()).toBe(0);
    expect(getEventListeners(stream.abort.signal, "abort")).toHaveLength(0);
  });
});

describe("credentials", () => {
  const TEAM = "backend:aweb.test";
  let workdir: string;
  let certificatePath: string;

  beforeEach(async () => {
    workdir = realpathSync(mkdtempSync(join(tmpdir(), "channel-stream-credentials-")));
    const principal = await writeTestPrincipal(join(workdir, ".aw"), { alias: "agent", seedByte: 9, teamID: TEAM });
    certificatePath = join(principal.identityHome, "team-certs", `${TEAM.replace(/[:.]/g, "_")}.pem`);
  });

  afterEach(() => {
    rmSync(workdir, { recursive: true, force: true });
  });

  /** Replaces the certificate on disk with a renewed one and returns the header it is sent as. */
  async function renewCertificate(id: string): Promise<string> {
    const certificate = JSON.parse(readFileSync(certificatePath, "utf-8"));
    writeFileSync(certificatePath, `${JSON.stringify({ ...certificate, certificate_id: id })}\n`);
    return (await resolveConfig(workdir)).teamCertificateHeader;
  }

  /** What holds the channel's own did:key beside its client. */
  function holders(client: APIClient, config: AgentConfig) {
    return {
      self: { alias: config.alias, address: config.address, did: config.did, stableID: config.stableID },
      trust: new SenderTrustManager(client, {} as never, config.teamID, config.did, config.stableID),
    };
  }

  function stubFetch(...script: Answer[]) {
    const certificates: string[] = [];
    let opens = 0;
    const fetchMock = vi.fn<typeof fetch>(async (_url, init) => {
      certificates.push((init?.headers as Record<string, string>)["X-AWID-Team-Certificate"]);
      const answer = script[Math.min(opens++, script.length - 1)];
      try {
        return answer();
      } catch (error) {
        return new Response("", { status: (error as APIError).statusCode });
      }
    });
    vi.stubGlobal("fetch", fetchMock);
    return { certificates, fetchMock };
  }

  test("are read again from disk before each retry of a refused stream, and only then", async () => {
    const config = await resolveConfig(workdir);
    const client = createChannelClient(config);
    const { certificates, fetchMock } = stubFetch(answers(503), answers(401), answers(401), streams(frame("connected")));
    const stream = run(client as never, {
      random: () => 0,
      reloadCredentials: createChannelCredentialReload({
        client, config, load: () => resolveConfig(workdir), ...holders(client, config),
      }),
    });
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));

    // A transient failure retries with what the client holds.
    const renewed = await renewCertificate("cert-renewed");
    await vi.advanceTimersByTimeAsync(SECOND);
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
    expect(certificates).toEqual([config.teamCertificateHeader, config.teamCertificateHeader]);

    // The second open was refused: its retry reads the certificate again.
    await vi.advanceTimersByTimeAsync(30 * SECOND);
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(3));
    expect(certificates[2]).toBe(renewed);

    const renewedAgain = await renewCertificate("cert-renewed-again");
    await vi.advanceTimersByTimeAsync(MINUTE);
    await vi.waitFor(() => expect(stream.received).toEqual(["connected"]));
    expect(certificates[3]).toBe(renewedAgain);
    expect(new Set(certificates).size).toBe(3);
    expect(stream.states.map((state) => state.state)).toEqual(["disconnected", "refused", "reconnected"]);

    // Every other request of the channel is signed with the renewed certificate.
    fetchMock.mockResolvedValueOnce(new Response("{}", { status: 200, headers: { "Content-Type": "application/json" } }));
    await client.get("/v1/agents");
    expect((fetchMock.mock.calls.at(-1)?.[1]?.headers as Record<string, string>)["X-AWID-Team-Certificate"]).toBe(renewedAgain);

    stream.abort.abort();
    await stream.done;
  });

  test("a rotated key and certificate for the same stable identity are taken", async () => {
    const config = await resolveConfig(workdir);
    const client = createChannelClient(config);
    const { self, trust } = holders(client, config);
    const receipt = new ReceiveStreamReceipt({
      identityHome: config.identityHome!, kind: "claude-channel", did: config.did, stableID: config.stableID,
    });
    const renewReceipt = vi.spyOn(receipt, "renewDID");
    const activity = createActivityEmitter(config, client);
    const renewSigner = vi.spyOn(activity, "renewSigner");
    const { certificates, fetchMock } = stubFetch(answers(401), streams(frame("connected")));
    const stream = run(client as never, {
      random: () => 0,
      reloadCredentials: createChannelCredentialReload({
        client, config, load: () => resolveConfig(workdir), self, trust, receipt, activity: () => activity,
      }),
    });
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));

    // The identity's key is rotated: the home holds another did:key and its
    // certificate, for the same stable identity, team and server.
    const rotatedSeed = new Uint8Array(32).fill(10);
    const rotated = await writeTestPrincipal(join(workdir, ".aw"), { alias: "agent", seedByte: 10, teamID: TEAM });
    const rotatedConfig = await resolveConfig(workdir);
    expect(rotated.did).not.toBe(config.did);
    expect(rotatedConfig.stableID).toBe(config.stableID);

    await vi.advanceTimersByTimeAsync(30 * SECOND);
    await vi.waitFor(() => expect(stream.received).toEqual(["connected"]));
    expect(stream.states.map((state) => state.state)).toEqual(["refused", "reconnected"]);

    // The request that was accepted is signed with the rotated key and carries its certificate.
    const headers = fetchMock.mock.calls[1][1]?.headers as Record<string, string>;
    const [scheme, signingDID, signature] = headers.Authorization.split(" ");
    expect(scheme).toBe("DIDKey");
    expect(signingDID).toBe(rotated.did);
    expect(ed.verify(
      Buffer.from(signature, "base64"),
      Buffer.from(headers["X-AWEB-Signed-Payload"], "base64url"),
      ed.getPublicKey(rotatedSeed),
    )).toBe(true);
    expect(certificates[1]).toBe(rotatedConfig.teamCertificateHeader);
    expect(certificates[1]).not.toBe(config.teamCertificateHeader);

    // Everything else that holds the channel's own did:key follows the rotation.
    expect(self.did).toBe(rotated.did);
    const toRetiredKey = await trust.normalizeTrust(new PinStore(), "verified", "peer", "did:key:zpeer", undefined, config.did, undefined);
    expect(toRetiredKey.status).toBe("identity_mismatch");
    expect(renewReceipt).toHaveBeenCalledWith(rotated.did);
    expect(renewSigner).toHaveBeenCalledWith(expect.objectContaining({ did: rotated.did, seed: rotatedSeed, stableID: config.stableID }));

    stream.abort.abort();
    await stream.done;
  });

  test("that name another stable identity fail the attempt without a request", async () => {
    const config = await resolveConfig(workdir);
    const client = createChannelClient(config);
    const { certificates, fetchMock } = stubFetch(answers(401), streams(frame("connected")));
    const reload = createChannelCredentialReload({
      client, config, load: () => resolveConfig(workdir), ...holders(client, config),
    });
    const reloads: string[] = [];
    const stream = run(client as never, {
      random: () => 0,
      reloadCredentials: (signal) => reload(signal).then(
        () => { reloads.push("taken"); },
        (error) => { reloads.push(String(error.message)); throw error; },
      ),
    });
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));

    // Another agent's key, certificate and stable identity are written into the same home.
    await writeTestPrincipal(join(workdir, ".aw"), { alias: "other", seedByte: 10, teamID: TEAM });
    expect((await resolveConfig(workdir)).stableID).not.toBe(config.stableID);
    await vi.advanceTimersByTimeAsync(30 * SECOND);
    await vi.waitFor(() => expect(reloads).toEqual(["the credentials read again name another identity"]));
    // The lowest draw waits half of 2 minutes: the failed read keeps the quarantine's pace.
    await vi.advanceTimersByTimeAsync(MINUTE - 5 * SECOND);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(stream.states.map((state) => state.state)).toEqual(["refused"]);

    await writeTestPrincipal(join(workdir, ".aw"), { alias: "agent", seedByte: 9, teamID: TEAM });
    await vi.advanceTimersByTimeAsync(5 * SECOND);
    await vi.waitFor(() => expect(stream.received).toEqual(["connected"]));
    expect(reloads).toHaveLength(2);
    expect(certificates).toEqual([config.teamCertificateHeader, config.teamCertificateHeader]);
    expect(stream.states.map((state) => state.state)).toEqual(["refused", "reconnected"]);

    stream.abort.abort();
    await stream.done;
  });

  test.each([
    { name: "another server", change: { baseURL: "https://other.test" }, message: "another server" },
    { name: "another identity home", change: { identityHome: "/elsewhere/.aw" }, message: "another identity home" },
    { name: "another team", change: { teamID: "other:aweb.test" }, message: "another identity" },
    { name: "another stable identity", change: { stableID: "did:aw:other" }, message: "another identity" },
    { name: "no stable identity", change: { stableID: "" }, message: "another identity" },
    { name: "another way to authenticate", change: { authMode: "grant" as const, grantID: "grant-1" }, message: "another identity" },
  ])("that name $name are not taken", async ({ change, message }) => {
    const config = await resolveConfig(workdir);
    const client = createChannelClient(config);
    const { certificates, fetchMock } = stubFetch(answers(401));
    const { self, trust } = holders(client, config);
    const reload = createChannelCredentialReload({ client, config, load: async () => ({ ...config, ...change }), self, trust });
    await expect(reload(new AbortController().signal)).rejects.toThrow(message);
    expect(self.did).toBe(config.did);

    await client.openSSE("/v1/events/stream").catch(() => {});
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(String(fetchMock.mock.calls[0][0])).toBe(`${config.baseURL}/v1/events/stream`);
    expect(certificates).toEqual([config.teamCertificateHeader]);
  });

  test("of a local identity, which has no stable identity, are not taken with another key", async () => {
    // Without a stable identity the did:key is the identity.
    const local = { ...(await resolveConfig(workdir)), stableID: "" };
    const client = createChannelClient(local);
    const { certificates, fetchMock } = stubFetch(answers(401));
    const { self, trust } = holders(client, local);
    const rotated = await writeTestPrincipal(join(workdir, ".aw"), { alias: "agent", seedByte: 10, teamID: TEAM });
    const reload = createChannelCredentialReload({
      client, config: local, load: async () => ({ ...(await resolveConfig(workdir)), stableID: "" }), self, trust,
    });
    await expect(reload(new AbortController().signal)).rejects.toThrow("another identity");
    expect(self.did).toBe(local.did);
    expect(self.did).not.toBe(rotated.did);

    await client.openSSE("/v1/events/stream").catch(() => {});
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(certificates).toEqual([local.teamCertificateHeader]);
    expect((fetchMock.mock.calls[0][1]?.headers as Record<string, string>).Authorization).toContain(` ${local.did} `);
  });

  test("of a local identity are taken when its key is the same", async () => {
    const local = { ...(await resolveConfig(workdir)), stableID: "" };
    const client = createChannelClient(local);
    const { certificates } = stubFetch(answers(401));
    const renewed = await renewCertificate("cert-renewed");
    const reload = createChannelCredentialReload({
      client, config: local, load: async () => ({ ...(await resolveConfig(workdir)), stableID: "" }), ...holders(client, local),
    });
    await reload(new AbortController().signal);

    await client.openSSE("/v1/events/stream").catch(() => {});
    expect(certificates).toEqual([renewed]);
  });

  test("read after the stream stopped are not taken", async () => {
    const config = await resolveConfig(workdir);
    const client = createChannelClient(config);
    const { certificates } = stubFetch(answers(401));
    const stopped = new AbortController();
    const reload = createChannelCredentialReload({
      client,
      config,
      load: async () => {
        const renewed = await renewCertificate("cert-renewed");
        stopped.abort();
        return { ...config, teamCertificateHeader: renewed };
      },
      ...holders(client, config),
    });
    await expect(reload(stopped.signal)).rejects.toThrow();

    await client.openSSE("/v1/events/stream").catch(() => {});
    expect(certificates).toEqual([config.teamCertificateHeader]);
  });

  test("the channel loop reads them again before a refused retry", async () => {
    const { client, openSSE } = scriptedClient(answers(401), streams(frame("connected")));
    const reloadCredentials = vi.fn(async () => {
      expect(openSSE).toHaveBeenCalledTimes(1);
    });
    const abort = new AbortController();
    const states: EventStreamState[] = [];
    const loop = startChannelLoop({
      client,
      pinStore: new PinStore(),
      trust: {} as never,
      self: { alias: "agent", address: "aweb.test/agent", did: "did:key:z6Mktest", stableID: "did:aw:agent" },
      signal: abort.signal,
      teamID: TEAM,
      workdir,
      onAwakening: () => {},
      onStreamState: (state) => states.push(state),
      reloadCredentials,
    });
    await vi.waitFor(() => expect(states.map((state) => state.state)).toEqual(["refused"]));
    expect(reloadCredentials).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(MINUTE);
    await vi.waitFor(() => expect(states.map((state) => state.state)).toEqual(["refused", "reconnected"]));
    expect(reloadCredentials).toHaveBeenCalledTimes(1);
    expect(openSSE).toHaveBeenCalledTimes(2);

    abort.abort();
    await loop;
  });
});

// Stream state is an operator diagnostic and is not presented to the agent,
// with one exception: the start of a refusal episode.
describe("the refused notice to the agent", () => {
  let workdir: string;

  beforeEach(() => {
    workdir = realpathSync(mkdtempSync(join(tmpdir(), "channel-stream-notice-")));
    // The lowest draw waits half of each delay.
    vi.spyOn(Math, "random").mockReturnValue(0);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    rmSync(workdir, { recursive: true, force: true });
  });

  function loop(client: never, onAwakening?: (awakening: ChannelAwakening) => Promise<void> | void) {
    const abort = new AbortController();
    const awakenings: ChannelAwakening[] = [];
    const states: EventStreamState[] = [];
    const logs: string[] = [];
    const done = startChannelLoop({
      client,
      pinStore: new PinStore(),
      trust: {} as never,
      self: { alias: "agent", address: "aweb.test/agent", did: "did:key:z6Mktest", stableID: "did:aw:agent" },
      signal: abort.signal,
      teamID: "backend:aweb.test",
      workdir,
      onAwakening: onAwakening ?? ((awakening) => { awakenings.push(awakening); }),
      onStreamState: (state) => states.push(state),
      log: (message) => logs.push(message),
    });
    const notices = () => awakenings.filter((awakening) => awakening.kind === "channel");
    const stop = async () => {
      abort.abort();
      await done;
    };
    return { awakenings, states, logs, notices, stop };
  }

  const stateNames = (states: EventStreamState[]) => states.map((state) => state.state);

  test("is presented once on entering refused, not on a refused retry and not on leaving", async () => {
    const { client, openSSE } = scriptedClient(answers(401), answers(401), streams(frame("connected")));
    const channel = loop(client);
    await vi.waitFor(() => expect(stateNames(channel.states)).toEqual(["refused"]));
    await settle();

    expect(channel.awakenings).toEqual([{
      kind: "channel",
      content: "The aweb server refused this channel's event stream (401). Mail and chat will not arrive until the stream is accepted again. "
        + `The next attempt is at ${formatEventStreamState(channel.states[0]).slice(-5)}.`,
      deliveryIntent: "wake",
      meta: {
        type: "channel",
        notice: "event_stream_refused",
        cause: "401",
        next_attempt_at: new Date(channel.states[0].nextAttemptAt!).toISOString(),
      },
    }]);

    await vi.advanceTimersByTimeAsync(30 * SECOND);
    expect(openSSE).toHaveBeenCalledTimes(2);
    expect(channel.awakenings).toHaveLength(1);

    await vi.advanceTimersByTimeAsync(MINUTE);
    await vi.waitFor(() => expect(stateNames(channel.states)).toEqual(["refused", "reconnected"]));
    await settle();
    // The operator surface has both transitions; the agent has the one notice.
    expect(channel.awakenings).toHaveLength(1);
    await channel.stop();
  });

  test("is presented once across a heartbeat, connected and a grant terminal event repeated six times", async () => {
    const { client, openSSE } = scriptedClient(
      closes(heartbeat(), frame("connected"), frame("grant_revoked", { detail: "identity grant revoked" })),
    );
    const channel = loop(client);
    await vi.waitFor(() => expect(openSSE).toHaveBeenCalledTimes(1));
    for (const [cycle, wait] of [30 * SECOND, MINUTE, 2 * MINUTE, 4 * MINUTE, 7.5 * MINUTE].entries()) {
      await vi.advanceTimersByTimeAsync(wait);
      await vi.waitFor(() => expect(openSSE).toHaveBeenCalledTimes(cycle + 2));
    }
    await vi.waitFor(() => expect(channel.states.filter((state) => state.state === "refused")).toHaveLength(6));
    await settle();

    // Every transition reaches the operator surface.
    expect(stateNames(channel.states)).toEqual([
      "connected", "refused",
      "reconnected", "refused", "reconnected", "refused", "reconnected", "refused", "reconnected", "refused", "reconnected", "refused",
    ]);
    expect(channel.notices()).toHaveLength(1);
    expect(channel.notices()[0].meta.cause).toBe("grant_revoked");
    expect(channel.awakenings).toHaveLength(1);
    await channel.stop();
  });

  test("is presented again for a refusal after the server served an ordinary event", async () => {
    const { client } = scriptedClient(
      answers(401),
      closes(frame("connected"), frame("work_available", { task_id: "t-1", title: "Review the plan" })),
      answers(403),
    );
    const channel = loop(client);
    await vi.waitFor(() => expect(stateNames(channel.states)).toEqual(["refused"]));
    await vi.advanceTimersByTimeAsync(30 * SECOND);
    await vi.waitFor(() => expect(stateNames(channel.states)).toEqual(["refused", "reconnected", "disconnected"]));
    await vi.advanceTimersByTimeAsync(SECOND);
    await vi.waitFor(() => expect(stateNames(channel.states)).toEqual(["refused", "reconnected", "disconnected", "refused"]));
    await vi.waitFor(() => expect(channel.notices()).toHaveLength(2));

    expect(channel.awakenings.map((awakening) => [awakening.kind, awakening.meta.cause])).toEqual([
      ["channel", "401"], ["work", undefined], ["channel", "403"],
    ]);
    await channel.stop();
  });

  test("that cannot be presented is logged and the stream keeps retrying", async () => {
    const { client, openSSE } = scriptedClient(answers(401));
    const channel = loop(client, () => Promise.reject(new Error("session closed")));
    await vi.waitFor(() => expect(channel.logs).toEqual([
      "aweb: could not present the refused event stream to the agent: session closed",
    ]));
    await vi.advanceTimersByTimeAsync(30 * SECOND);
    expect(openSSE).toHaveBeenCalledTimes(2);
    expect(channel.logs).toHaveLength(1);
    await channel.stop();
  });

  test("is built only from a refusal that starts an episode", () => {
    const nextAttemptAt = new Date(2026, 2, 1, 9, 5, 59).getTime();
    const notice = eventStreamRefusedAwakening({ state: "refused", cause: "grant_revoked", retryInMs: MINUTE, nextAttemptAt, startsEpisode: true });
    expect(notice.content).toBe(
      "The aweb server refused this channel's event stream (grant_revoked). Mail and chat will not arrive until the stream is accepted again. The next attempt is at 09:05.",
    );
    // It carries no sender and no trust status: nothing in it can pass as a verified peer message.
    expect(Object.keys(notice.meta).sort()).toEqual(["cause", "next_attempt_at", "notice", "type"]);
  });

  test("reads as coming from the channel itself where the host formats awakenings as text", () => {
    const nextAttemptAt = new Date(2026, 2, 1, 9, 5).getTime();
    const notice = eventStreamRefusedAwakening({ state: "refused", cause: "401", retryInMs: MINUTE, nextAttemptAt, startsEpisode: true });
    expect(formatAwakeningForAgent(notice)).toBe([
      "aweb channel notice, from the aweb channel itself and not from another agent.",
      "",
      notice.content,
    ].join("\n"));
  });
});

describe("formatEventStreamState", () => {
  test("names the refusal and the local time of the next attempt", () => {
    const nextAttemptAt = new Date(2026, 2, 1, 9, 5, 59).getTime();
    expect(formatEventStreamState({ state: "refused", cause: "grant_revoked", retryInMs: MINUTE, nextAttemptAt }))
      .toBe("aweb: event stream refused: grant_revoked, next try 09:05");
  });

  test("names the refusal a confirmed stream ended", () => {
    expect(formatEventStreamState({ state: "reconnected", endedRefusal: "401" }))
      .toBe("aweb: event stream accepted again (was refused: 401)");
    expect(formatEventStreamState({ state: "reconnected" })).toBe("aweb: event stream reconnected");
  });
});
