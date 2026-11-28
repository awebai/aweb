// Behaviour of the built Pi extension bundle named by AWEB_PI_DIST. Run by
// scripts/test-typescript-dist-freshness.sh against the production build and
// against bundles rebuilt from a mutated source.
//
// The stream cases host the bundle's default export as Pi does (pi_host.mts).
import assert from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

import {
  genesisKeyAnswer,
  json,
  startLoopbackServer,
  stableIDOf,
  writeSigningKey,
  writeTeamCertificate,
  writeTeamState,
  writeWorkspaceBinding,
} from "../../packages/channel-core/test/helpers/dist_fixture.ts";
import {
  beat,
  bundle,
  bundleWith,
  eventually,
  keepOpen,
  owned,
  pause,
  receiptHeartbeat,
  serverWatch,
  startPiSession,
} from "./pi_host.mts";

test("Pi takes the certificate's stable_id over identity.yaml's", async () => {
  async function loadStableID(identityStableID: string): Promise<string> {
    const workdir = owned("config-");
    const awDir = join(workdir, ".aw");
    mkdirSync(join(awDir, "team-certs"), { recursive: true });
    const seed = new Uint8Array(32).fill(23);
    const certPath = "team-certs/backend__acme.com.pem";
    const { did } = await writeTeamCertificate(join(awDir, certPath), seed, {
      team_id: "backend:acme.com", alias: "alice", member_did_aw: "did:aw:cert",
    });
    writeSigningKey(join(awDir, "signing.key"), seed);
    writeWorkspaceBinding(awDir, "backend:acme.com", "alice", certPath);
    writeTeamState(awDir, "backend:acme.com", "alice", certPath);
    writeFileSync(join(awDir, "identity.yaml"), `did: ${did}\nstable_id: ${identityStableID}\n`);
    return (await bundle.loadChannelConfig(workdir)).stableID;
  }
  assert.equal(await loadStableID("did:aw:cert"), "did:aw:cert", "a consistent workspace did not load");
  assert.equal(
    await loadStableID("did:aw:stale"), "did:aw:cert",
    "S4b: the certificate's stable_id must win over identity.yaml's",
  );
});

test("Pi refuses a genesis whose key does not derive its did:aw", async () => {
  async function verify(stableID: string) {
    const signer = new Uint8Array(32).fill(61);
    const answer = genesisKeyAnswer(signer, stableID);
    const registry = await startLoopbackServer((request, response) => {
      if (request.url === "/v1/namespaces/aweb.test/addresses/alice") {
        json(response, 200, {
          address_id: "address-alice", domain: "aweb.test", name: "alice",
          did_aw: stableID, current_did_key: answer.current_did_key, created_at: "2026-07-26T00:00:00Z",
        });
      } else if (request.url === `/v1/did/${stableID}/key`) {
        json(response, 200, answer);
      } else {
        json(response, 404, { detail: "not found" });
      }
    });
    try {
      const resolver = bundle.createPiRegistryResolver({ registryURL: registry.url, address: "aweb.test/alice" });
      return await resolver.verifyStableIdentity("aweb.test/alice", stableID, answer.current_did_key);
    } finally {
      await registry.close();
    }
  }
  const valid = await verify(stableIDOf(new Uint8Array(32).fill(61)));
  assert.equal(valid.outcome, "OK_VERIFIED", `valid genesis was not verified: ${JSON.stringify(valid)}`);
  const forged = await verify(stableIDOf(new Uint8Array(32).fill(62)));
  assert.deepEqual(
    { outcome: forged.outcome, error: forged.error },
    { outcome: "HARD_ERROR", error: "did:aw not derived from genesis key" },
    "S4a: the genesis key must derive the did:aw",
  );
});

test("Pi closes a stream at its requested deadline and reconnects", async (t) => {
  const session = await startPiSession(t, keepOpen);
  try {
    await eventually(() => session.streams.length === 1, "the bundle never opened the event stream");
    const first = session.streams[0];
    assert.ok(Number.isFinite(first.deadline), "the stream request carried no deadline");
    await eventually(() => receiptHeartbeat(session.identityHome) !== undefined, "the stream was never confirmed live");
    // Heartbeats keep the stream live up to one millisecond before its deadline.
    while (first.deadline - Date.now() > 30_000) {
      t.mock.timers.tick(30_000);
      await beat(session, first);
    }
    t.mock.timers.tick(first.deadline - Date.now() - 1);
    await pause(50);
    assert.equal(first.closed, false, "the stream closed before its deadline");
    assert.equal(session.streams.length, 1);
    t.mock.timers.tick(1);
    await eventually(() => first.closed, "S4c: the stream must close at its deadline");
    await eventually(() => session.streams.length === 2, "the bundle did not reconnect after the planned close");
  } finally {
    await session.close();
  }
});

test("Pi gives up on a stream silent for 75 seconds and reconnects after the retry delay", async (t) => {
  const session = await startPiSession(t, keepOpen);
  try {
    await eventually(() => session.streams.length === 1, "the bundle never opened the event stream");
    const first = session.streams[0];
    await eventually(() => receiptHeartbeat(session.identityHome) !== undefined, "the stream was never confirmed live");
    t.mock.timers.tick(75_000 - 1);
    await pause(50);
    assert.equal(first.closed, false, "the stream closed before 75 seconds of silence");
    t.mock.timers.tick(1);
    await eventually(() => first.closed, "S4d: a stream silent for 75 seconds must be closed");
    await eventually(
      () => session.statuses.some((status) => status.includes("aweb events down; retrying")),
      "the silent stream was not reported disconnected",
    );
    assert.deepEqual(session.logs, ["aweb: event stream disconnected (connection timed out) — retrying in 1s"]);
    assert.equal(session.streams.length, 1, "the bundle reconnected without waiting its retry delay");
    // The first retry waits at most the policy's minimum delay of one second.
    t.mock.timers.tick(1_000);
    await eventually(() => session.streams.length === 2, "the bundle did not reconnect after the retry delay");
  } finally {
    await session.close();
  }
});

test("Pi's settled backoff sleeps leave no listener on the session signal", async (t) => {
  const session = await startPiSession(t, (request) => json(request.response, 503, { detail: "unavailable" }));
  try {
    await eventually(() => session.streams.length === 1, "the bundle never opened the event stream");
    // Each refused attempt backs off by at most 15 s; one-second steps keep
    // advancing whichever sleep is pending.
    for (let step = 0; session.streams.length < 8; step += 1) {
      assert.ok(step < 200, `the bundle stopped retrying after ${session.streams.length} attempts`);
      const seen = session.streams.length;
      t.mock.timers.tick(1_000);
      await pause(5);
      if (session.streams.length > seen) await pause(5);
    }
    const counts = session.streams.map((stream) => stream.sessionListeners);
    assert.ok(counts.every((count) => count > 0), `the session signal was not observed: ${counts}`);
    assert.equal(counts[7], counts[1], `S4e: listeners on the session signal grew across backoffs: ${counts}`);
    // A refusal that repeats is reported once.
    assert.deepEqual(session.logs, ["aweb: event stream disconnected (http 503) — retrying in 1s"]);
  } finally {
    await session.close();
  }
});

test("a Pi session whose start fails after opening its stream is released", async (t) => {
  const { watch, observe } = serverWatch();
  const warn = console.warn;
  const extension = bundleWith({
    afterStart: async () => {
      await eventually(() => watch.streamOpened, "the bundle never opened the event stream");
      throw new Error("start failed after the stream opened");
    },
  });
  await assert.rejects(startPiSession(t, keepOpen, { extension, observe }), /start failed after the stream opened/);
  assert.equal(watch.server.listening, false, "the event server outlived a failed start");
  assert.equal(console.warn, warn, "the warning capture outlived a failed start");
});

test("a Pi session whose shutdown fails still releases the server and warning capture", async (t) => {
  const { watch, observe } = serverWatch();
  const warn = console.warn;
  const extension = bundleWith({
    shutdown: async (real) => { await real(); throw new Error("shutdown failed"); },
  });
  const session = await startPiSession(t, keepOpen, { extension, observe });
  await eventually(() => watch.streamOpened, "the bundle never opened the event stream");
  await assert.rejects(session.close(), /shutdown failed/);
  assert.equal(watch.server.listening, false, "the event server outlived a failed shutdown");
  assert.equal(console.warn, warn, "the warning capture outlived a failed shutdown");
});
