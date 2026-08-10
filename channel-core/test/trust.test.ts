import { afterEach, describe, expect, test, vi } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
import yaml from "js-yaml";
import {
  APIClient,
  computeDIDKey,
  PinStore,
  SenderTrustManager,
  canonicalReplacementJSON,
  canonicalRotationJSON,
  type ReplacementAnnouncement,
  type RotationAnnouncement,
} from "../src/index.js";

// Delegate to the real verifier while observing whether malformed input reaches it.
const verifyCalls = vi.hoisted(() => vi.fn());
vi.mock("@noble/ed25519", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@noble/ed25519")>();
  return {
    ...actual,
    verify: (...args: Parameters<typeof actual.verify>) => {
      verifyCalls();
      return actual.verify(...args);
    },
  };
});

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

afterEach(() => vi.unstubAllGlobals());

function seed(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

async function didFromSeed(byte: number): Promise<{ seed: Uint8Array; did: string }> {
  const priv = seed(byte);
  const pub = await ed.getPublicKeyAsync(priv);
  return { seed: priv, did: computeDIDKey(pub) };
}

function b64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64").replace(/=+$/, "");
}

function localRoster(agent: Record<string, unknown>, alias: string = "alice") {
  return {
    team_id: "backend:acme.com",
    agents: [{ alias, ...agent }],
  };
}

function authenticatedTeamClient(methods: Record<string, unknown>) {
  return {
    hasTeamCertificateAuth: (teamID: string) => teamID === "backend:acme.com",
    ...methods,
  } as never;
}

describe("SenderTrustManager", () => {
  test.each(["verified", "verified_legacy", "verified_custodial"] as const)(
    "marks %s recipient binding mismatches as identity_mismatch without roster recovery",
    async (status) => {
      const { did } = await didFromSeed(1);
      const get = vi.fn();
      const getFresh = vi.fn();
      const trust = new SenderTrustManager(
        authenticatedTeamClient({ get, getFresh }),
        { verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }) } as never,
        "backend:acme.com",
        "did:key:zrecipient",
      );

      const result = await trust.normalizeTrust(new PinStore(), status, "alice", did, undefined, "did:key:zwrong");
      expect(result.status).toBe("identity_mismatch");
      expect(get).not.toHaveBeenCalled();
      expect(getFresh).not.toHaveBeenCalled();
    },
  );

  test("returns verified_custodial for custodial senders", async () => {
    const { did } = await didFromSeed(2);
    const store = new PinStore();
    const trust = new SenderTrustManager(
      { get: vi.fn() } as never,
      {
        verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }),
        resolveIdentity: async () => ({
          did,
          stableID: "did:aw:custodial",
          address: "acme.com/alice",
          controllerDid: "did:key:zcontroller",
          custody: "custodial",
          identityScope: "global",
        }),
      } as never,
      "backend:acme.com",
      "",
    );

    const result = await trust.normalizeTrust(store, "verified", "acme.com/alice", did, undefined, undefined);
    expect(result.status).toBe("verified_custodial");
    expect(store.addresses.get("acme.com/alice")).toBe(did);
  });

  test("does not consult the roster after signature verification fails", async () => {
    const { did } = await didFromSeed(48);
    const get = vi.fn();
    const getFresh = vi.fn();
    const trust = new SenderTrustManager(
      { get, getFresh } as never,
      { verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }) } as never,
      "backend:acme.com",
      "",
    );
    const result = await trust.normalizeTrust(new PinStore(), "failed", "alice", did, undefined, undefined);
    expect(result.status).toBe("failed");
    expect(get).not.toHaveBeenCalled();
    expect(getFresh).not.toHaveBeenCalled();
  });

  test("does not use an unauthenticated roster client as local proof", async () => {
    const self = await didFromSeed(49);
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const client = new APIClient("https://aweb.example", {
      did: self.did,
      stableID: "",
      signingKey: self.seed,
      teamID: "backend:acme.com",
      teamCertificateHeader: "",
    });
    const trust = new SenderTrustManager(
      client,
      { verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }) } as never,
      "backend:acme.com",
      "",
    );
    const result = await trust.normalizeTrust(new PinStore(), "verified", "alice", self.did, undefined, undefined);
    expect(result.status).toBe("verification_stale");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  test("removes pins for local-scope senders", async () => {
    const { did } = await didFromSeed(3);
    const store = new PinStore();
    store.storePin(did, "backend:acme.com/alice", "", "");

    const trust = new SenderTrustManager(
      authenticatedTeamClient({ get: async () => localRoster({ did_key: did, identity_scope: "local", custody: "self" }) }),
      { verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }) } as never,
      "backend:acme.com",
      "",
    );

    const result = await trust.normalizeTrust(store, "verified", "alice", did, undefined, undefined);
    expect(result.status).toBe("verified");
    expect(store.addresses.has("backend:acme.com/alice")).toBe(false);
    expect(store.pins.size).toBe(0);
  });

  test("verifies a reissued alias whose pin still names the previous holder", async () => {
    const previousHolder = await didFromSeed(11);
    const currentHolder = await didFromSeed(12);
    const store = new PinStore();
    // The fixture must reuse a name already pinned to a DIFFERENT key. An unused
    // alias has no previous holder to be confused with, so it cannot fail for the
    // reason this test exists (aweb-aava).
    store.storePin(previousHolder.did, "backend:acme.com/alice", "", "");

    const trust = new SenderTrustManager(
      authenticatedTeamClient({
        get: async () => localRoster({ did_key: currentHolder.did, identity_scope: "local", custody: "self" }),
      }),
      { verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }) } as never,
      "backend:acme.com",
      "",
    );

    const result = await trust.normalizeTrust(store, "verified", "alice", currentHolder.did, undefined, undefined);

    expect(result.status).toBe("verified");
    expect(store.addresses.has("backend:acme.com/alice")).toBe(false);
    expect(store.pins.has(previousHolder.did)).toBe(false);
  });

  // Every accepted message from an already-pinned global sender used to refresh
  // last_seen and so report stored=true, forcing a pin-store commit per message.
  // With several resident processes sharing one known_agents.yaml that made CAS
  // conflicts the steady state and each conflict deferred a wake (aweb-abdk).
  // The sender must be GLOBAL: a local-scope sender is not pinned at all, so the
  // same test built from one would pass without exercising this path.
  test("an already-pinned global sender stops forcing a commit on every message", async () => {
    const globalIdentity = await didFromSeed(71);
    const store = new PinStore();
    const trust = new SenderTrustManager(
      authenticatedTeamClient({
        get: async () => localRoster(
          { did_key: globalIdentity.did, did_aw: "did:aw:grace", identity_scope: "global" },
          "grace",
        ),
      }),
      { verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }) } as never,
      "backend:acme.com",
      "",
    );

    const first = await trust.normalizeTrust(store, "verified", "grace", globalIdentity.did, "did:aw:grace", undefined);
    expect(first.status).toBe("verified");
    expect(first.stored).toBe(true);

    const second = await trust.normalizeTrust(store, "verified", "grace", globalIdentity.did, "did:aw:grace", undefined);
    expect(second.status).toBe("verified");
    expect(second.stored).toBe(false);
  });

  test("caches certificate-authenticated local metadata on the message path", async () => {
    const currentIdentity = await didFromSeed(33);
    const store = new PinStore();
    const get = vi.fn(async () => localRoster({ did_key: currentIdentity.did, identity_scope: "local", custody: "self" }));
    const trust = new SenderTrustManager(
      authenticatedTeamClient({ get }),
      { verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }) } as never,
      "backend:acme.com",
      "",
    );

    expect((await trust.normalizeTrust(store, "verified", "alice", currentIdentity.did, undefined, undefined)).status).toBe("verified");
    expect(get).toHaveBeenCalledTimes(1);
    expect(store.pins.size).toBe(0);
    expect((await trust.normalizeTrust(store, "verified", "alice", currentIdentity.did, undefined, undefined)).status).toBe("verified");
    expect(get).toHaveBeenCalledTimes(1);
  });

  test("shares one roster request across concurrent distinct aliases", async () => {
    const alice = await didFromSeed(55);
    const bob = await didFromSeed(56);
    let releaseRoster!: (roster: ReturnType<typeof localRoster>) => void;
    const rosterPending = new Promise<ReturnType<typeof localRoster>>((resolve) => {
      releaseRoster = resolve;
    });
    const get = vi.fn(() => rosterPending);
    const trust = new SenderTrustManager(
      authenticatedTeamClient({ get }),
      { verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }) } as never,
      "backend:acme.com",
      "",
    );

    const aliceTrust = trust.normalizeTrust(new PinStore(), "verified", "alice", alice.did, undefined, undefined);
    const bobTrust = trust.normalizeTrust(new PinStore(), "verified", "bob", bob.did, undefined, undefined);
    await vi.waitFor(() => expect(get).toHaveBeenCalledTimes(1));

    releaseRoster({
      team_id: "backend:acme.com",
      agents: [
        { alias: "alice", did_key: alice.did, identity_scope: "local" },
        { alias: "bob", did_key: bob.did, identity_scope: "local" },
      ],
    });
    await expect(Promise.all([aliceTrust, bobTrust])).resolves.toEqual([
      { status: "verified", stored: false },
      { status: "verified", stored: false },
    ]);
    expect(get).toHaveBeenCalledTimes(1);
  });

  test("shares a roster failure and starts backoff when the request finishes", async () => {
    let now = 0;
    const failure = new Error("roster timed out");
    let rejectRoster!: (error: Error) => void;
    const rosterPending = new Promise<ReturnType<typeof localRoster>>((_resolve, reject) => {
      rejectRoster = reject;
    });
    const get = vi.fn()
      .mockImplementationOnce(() => rosterPending)
      .mockResolvedValueOnce(localRoster({ did_key: "did:key:zretry", identity_scope: "local" }));
    const trust = new SenderTrustManager(
      authenticatedTeamClient({ get }),
      { verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }) } as never,
      "backend:acme.com",
      "",
      "",
      () => now,
    ) as SenderTrustManager & {
      resolveAuthenticatedTeamRoster(): Promise<ReturnType<typeof localRoster>>;
    };

    const requests = [
      trust.resolveAuthenticatedTeamRoster(),
      trust.resolveAuthenticatedTeamRoster(),
      trust.resolveAuthenticatedTeamRoster(),
    ];
    await vi.waitFor(() => expect(get).toHaveBeenCalledTimes(1));
    now = 30_000;
    rejectRoster(failure);
    const settled = await Promise.allSettled(requests);
    expect(settled).toHaveLength(3);
    for (const result of settled) {
      expect(result.status).toBe("rejected");
      if (result.status === "rejected") expect(result.reason).toBe(failure);
    }

    now = 30_999;
    await expect(trust.resolveAuthenticatedTeamRoster()).rejects.toBe(failure);
    expect(get).toHaveBeenCalledTimes(1);

    now = 31_001;
    await expect(trust.resolveAuthenticatedTeamRoster()).resolves.toMatchObject({
      team_id: "backend:acme.com",
    });
    expect(get).toHaveBeenCalledTimes(2);
  });

  test("uses prepared roster metadata without retrying inside the trust decision", async () => {
    let now = 0;
    const currentIdentity = await didFromSeed(57);
    const get = vi.fn()
      .mockRejectedValueOnce(new Error("roster timed out"))
      .mockResolvedValueOnce(localRoster({
        did_key: currentIdentity.did,
        identity_scope: "local",
      }));
    const trust = new SenderTrustManager(
      authenticatedTeamClient({ get }),
      { verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }) } as never,
      "backend:acme.com",
      "",
      "",
      () => now,
    );

    const resolved = await trust.resolveTrustMetadata("verified", "alice", undefined, undefined, undefined);
    now = 2_000;
    const result = await trust.normalizeTrust(
      new PinStore(),
      "verified",
      "alice",
      currentIdentity.did,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      resolved,
    );

    expect(result).toEqual({ status: "verification_stale", stored: false });
    expect(get).toHaveBeenCalledTimes(1);
  });

  test("ignores forged prepared metadata", async () => {
    const rosterIdentity = await didFromSeed(59);
    const attacker = await didFromSeed(60);
    const get = vi.fn(async () => localRoster({
      did_key: rosterIdentity.did,
      identity_scope: "local",
    }));
    const trust = new SenderTrustManager(
      authenticatedTeamClient({ get }),
      { verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }) } as never,
      "backend:acme.com",
      "",
    );

    const result = await trust.normalizeTrust(
      new PinStore(),
      "verified",
      "alice",
      attacker.did,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      {
        trustAddress: "backend:acme.com/alice",
        meta: {
          did: attacker.did,
          identityScope: "local",
          custody: "self",
          resolved: true,
        },
      },
    );

    expect(result.status).toBe("identity_mismatch");
    expect(get).toHaveBeenCalledTimes(1);
  });

  test("accepts prepared metadata only for its address and first decision", async () => {
    let now = 0;
    const previousAlice = await didFromSeed(61);
    const currentAlice = await didFromSeed(62);
    const bob = await didFromSeed(63);
    const get = vi.fn()
      .mockResolvedValueOnce({
        team_id: "backend:acme.com",
        agents: [{ alias: "alice", did_key: previousAlice.did, identity_scope: "local" }],
      })
      .mockResolvedValueOnce({
        team_id: "backend:acme.com",
        agents: [{ alias: "bob", did_key: bob.did, identity_scope: "local" }],
      })
      .mockResolvedValueOnce({
        team_id: "backend:acme.com",
        agents: [{ alias: "alice", did_key: currentAlice.did, identity_scope: "local" }],
      });
    const trust = new SenderTrustManager(
      authenticatedTeamClient({ get }),
      { verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }) } as never,
      "backend:acme.com",
      "",
      "",
      () => now,
    );

    const resolvedAlice = await trust.resolveTrustMetadata(
      "verified",
      "alice",
      undefined,
      undefined,
      undefined,
    );
    now = 6_000;
    const bobResult = await trust.normalizeTrust(
      new PinStore(),
      "verified",
      "bob",
      bob.did,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      resolvedAlice,
    );
    expect(bobResult.status).toBe("verified");
    expect(get).toHaveBeenCalledTimes(2);

    now = (60 * 60 * 1000) + 1;
    const aliceResult = await trust.normalizeTrust(
      new PinStore(),
      "verified",
      "alice",
      currentAlice.did,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      resolvedAlice,
    );
    expect(aliceResult.status).toBe("verified");
    expect(get).toHaveBeenCalledTimes(3);
  });

  test("prepares public identity resolution before the trust decision", async () => {
    const currentIdentity = await didFromSeed(58);
    const resolveIdentity = vi.fn(async () => ({
      did: currentIdentity.did,
      address: "acme.com/alice",
      custody: "self",
      identityScope: "global",
    }));
    const trust = new SenderTrustManager(
      { get: vi.fn() } as never,
      {
        resolveIdentity,
        verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }),
      } as never,
      "backend:acme.com",
      "",
    );

    const resolved = await trust.resolveTrustMetadata(
      "verified",
      "acme.com/alice",
      undefined,
      undefined,
      undefined,
    );
    expect(resolveIdentity).toHaveBeenCalledTimes(1);

    const result = await trust.normalizeTrust(
      new PinStore(),
      "verified",
      "acme.com/alice",
      currentIdentity.did,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      resolved,
    );
    expect(result.status).toBe("verified");
    expect(resolveIdentity).toHaveBeenCalledTimes(1);
  });

  test("reconciles local metadata through a normal cached read after one hour", async () => {
    const previousIdentity = await didFromSeed(53);
    const currentIdentity = await didFromSeed(54);
    let now = 0;
    let rosterDID = previousIdentity.did;
    const get = vi.fn(async () => localRoster({
      did_key: rosterDID,
      identity_scope: "local",
      custody: "self",
    }));
    const trust = new SenderTrustManager(
      authenticatedTeamClient({ get }),
      { verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }) } as never,
      "backend:acme.com",
      "",
      "",
      () => now,
    );

    expect((await trust.normalizeTrust(
      new PinStore(), "verified", "alice", previousIdentity.did, undefined, undefined,
    )).status).toBe("verified");
    rosterDID = currentIdentity.did;
    now = (60 * 60 * 1000) - 1;
    expect((await trust.normalizeTrust(
      new PinStore(), "verified", "alice", currentIdentity.did, undefined, undefined,
    )).status).toBe("identity_mismatch");
    expect(get).toHaveBeenCalledTimes(1);

    now += 2;
    expect((await trust.normalizeTrust(
      new PinStore(), "verified", "alice", currentIdentity.did, undefined, undefined,
    )).status).toBe("verified");
    expect(get).toHaveBeenCalledTimes(2);
  });

  test("repeated local mismatches use the cached roster and remain fail closed", async () => {
    const currentIdentity = await didFromSeed(51);
    const messageIdentity = await didFromSeed(52);
    const get = vi.fn(async () => localRoster({
      did_key: currentIdentity.did,
      identity_scope: "local",
      custody: "self",
    }));
    const getFresh = vi.fn(async () => localRoster({
      did_key: currentIdentity.did,
      identity_scope: "local",
      custody: "self",
    }));
    const trust = new SenderTrustManager(
      authenticatedTeamClient({ get, getFresh }),
      { verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }) } as never,
      "backend:acme.com",
      "",
    );

    for (let index = 0; index < 3; index += 1) {
      const result = await trust.normalizeTrust(
        new PinStore(),
        "verified",
        "alice",
        messageIdentity.did,
        undefined,
        undefined,
      );
      expect(result.status).toBe("identity_mismatch");
    }

    expect(getFresh).not.toHaveBeenCalled();
    expect(get).toHaveBeenCalledTimes(1);
  });

  test("uses a cache-respecting certificate-authenticated roster read before verifying a local sender", async () => {
    const self = await didFromSeed(41);
    const currentIdentity = await didFromSeed(43);
    const globalIdentity = await didFromSeed(50);
    const requests: Array<{ authorization: string; certificate: string; cacheControl: string }> = [];
    vi.stubGlobal("fetch", vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      requests.push({
        authorization: headers.get("Authorization") || "",
        certificate: headers.get("X-AWID-Team-Certificate") || "",
        cacheControl: headers.get("Cache-Control") || "",
      });
      return new Response(JSON.stringify({
        team_id: "backend:acme.com",
        agents: [
          { alias: "alice", did_key: currentIdentity.did, identity_scope: "local" },
          { alias: "grace", did_key: globalIdentity.did, did_aw: "did:aw:grace", identity_scope: "global" },
        ],
      }), { status: 200, headers: { "Content-Type": "application/json" } });
    }));

    const client = new APIClient("https://aweb.example", {
      did: self.did,
      stableID: "",
      signingKey: self.seed,
      teamID: "backend:acme.com",
      teamCertificateHeader: "certificate-header",
    });
    const store = new PinStore();
    const trust = new SenderTrustManager(
      client,
      { verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }) } as never,
      "backend:acme.com",
      "",
    );

    expect((await trust.normalizeTrust(store, "verified", "acme.com/alice", currentIdentity.did, undefined, undefined)).status).toBe("verified");
    expect((await trust.normalizeTrust(store, "verified_legacy", "alice", currentIdentity.did, undefined, undefined)).status).toBe("verified_legacy");
    expect((await trust.normalizeTrust(store, "verified", "acme.com/grace", globalIdentity.did, "did:aw:grace", undefined)).status).toBe("verified");
    expect(requests).toHaveLength(1);
    expect(requests[0].authorization).toMatch(/^DIDKey /);
    expect(requests[0].certificate).toBe("certificate-header");
    expect(requests[0].cacheControl).toBe("");
    expect(store.pins.size).toBe(1);
  });

  test.each([
    ["absent", "identity_mismatch"],
    ["empty", "verification_stale"],
    ["malformed", "verification_stale"],
    ["non-local", "identity_mismatch"],
    ["different-key-with-forged-stable-id", "identity_mismatch"],
    ["verified-legacy-bare-alias", "identity_mismatch"],
    ["unavailable", "verification_stale"],
  ] as const)("rejects %s authenticated roster refreshes", async (variant, expected) => {
    const self = await didFromSeed(44);
    const currentIdentity = await didFromSeed(46);
    const differentIdentity = await didFromSeed(47);
    let requests = 0;
    vi.stubGlobal("fetch", vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
      requests += 1;
      const headers = new Headers(init?.headers);
      expect(headers.get("Authorization")).toMatch(/^DIDKey /);
      expect(headers.get("X-AWID-Team-Certificate")).toBe("certificate-header");
      expect(headers.get("Cache-Control")).toBeNull();
      if (variant === "unavailable") {
        return new Response("unavailable", { status: 503 });
      }
      const agents = variant === "absent" ? [] : [{
        alias: "alice",
        did_key: variant === "empty" ? "" : variant === "malformed" ? "did:key:not-valid" : variant === "different-key-with-forged-stable-id" || variant === "verified-legacy-bare-alias" ? differentIdentity.did : currentIdentity.did,
        identity_scope: variant === "non-local" ? "global" : "local",
      }];
      return new Response(JSON.stringify({ team_id: "backend:acme.com", agents }), { status: 200 });
    }));
    const client = new APIClient("https://aweb.example", {
      did: self.did,
      stableID: "",
      signingKey: self.seed,
      teamID: "backend:acme.com",
      teamCertificateHeader: "certificate-header",
    });
    const store = new PinStore();
    const trust = new SenderTrustManager(
      client,
      { verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }) } as never,
      "backend:acme.com",
      "",
    );
    const projected = variant === "different-key-with-forged-stable-id";
    const stableID = projected ? "did:aw:forged" : undefined;
    const sender = projected ? "acme.com/alice" : "alice";
    const status = variant === "verified-legacy-bare-alias" ? "verified_legacy" : "verified";
    expect((await trust.normalizeTrust(store, status, sender, currentIdentity.did, stableID, undefined)).status).toBe(expected);
  });

  test("preserves local mismatch when the authoritative roster row has a different key", async () => {
    const rosterIdentity = await didFromSeed(35);
    const attacker = await didFromSeed(36);
    const store = new PinStore();
    const trust = new SenderTrustManager(
      authenticatedTeamClient({
        get: async () => localRoster({ did_key: rosterIdentity.did, identity_scope: "local", custody: "self" }),
      }),
      { verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }) } as never,
      "backend:acme.com",
      "",
    );

    expect((await trust.normalizeTrust(store, "verified", "alice", attacker.did, undefined, undefined)).status).toBe("identity_mismatch");
  });

  test("preserves local mismatch when the sender is absent from the roster", async () => {
    const attacker = await didFromSeed(38);
    const store = new PinStore();
    const trust = new SenderTrustManager(
      authenticatedTeamClient({
        get: async () => { throw Object.assign(new Error("not found"), { statusCode: 404 }); },
      }),
      { verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }) } as never,
      "backend:acme.com",
      "",
    );

    expect((await trust.normalizeTrust(store, "verified", "alice", attacker.did, undefined, undefined)).status).toBe("identity_mismatch");
  });

  test("reports local verification stale when the cached roster read is unavailable", async () => {
    const changedIdentity = await didFromSeed(40);
    const store = new PinStore();
    const trust = new SenderTrustManager(
      authenticatedTeamClient({
        get: async () => { throw new TypeError("fetch failed"); },
      }),
      { verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }) } as never,
      "backend:acme.com",
      "",
    );

    expect((await trust.normalizeTrust(store, "verified", "alice", changedIdentity.did, undefined, undefined)).status).toBe("verification_stale");
  });

  test("normalizes legacy ephemeral lifetime metadata as local scope", async () => {
    const { did } = await didFromSeed(30);
    const store = new PinStore();
    store.storePin(did, "backend:acme.com/alice", "", "");

    const trust = new SenderTrustManager(
      authenticatedTeamClient({ get: async () => localRoster({ did_key: did, lifetime: "ephemeral", custody: "self" }) }),
      { verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }) } as never,
      "backend:acme.com",
      "",
    );

    const result = await trust.normalizeTrust(store, "verified", "alice", did, undefined, undefined);
    expect(result.status).toBe("verified");
    expect(store.addresses.has("backend:acme.com/alice")).toBe(false);
    expect(store.pins.size).toBe(0);
  });

  test("does not verify legacy persistent lifetime metadata as local", async () => {
    const { did } = await didFromSeed(31);
    const store = new PinStore();
    const trust = new SenderTrustManager(
      authenticatedTeamClient({ get: async () => localRoster({ did_key: did, lifetime: "persistent", custody: "self" }) }),
      { verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }) } as never,
      "backend:acme.com",
      "",
    );

    const result = await trust.normalizeTrust(store, "verified", "alice", did, undefined, undefined);
    expect(result.status).toBe("identity_mismatch");
    expect(store.addresses.has("backend:acme.com/alice")).toBe(false);
  });

  test("rejects malformed announcement signatures before invoking the verifier", async () => {
    const oldIdentity = await didFromSeed(41);
    const newIdentity = await didFromSeed(42);
    const controller = await didFromSeed(43);
    const timestamp = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
    const trust = new SenderTrustManager(
      {} as never,
      {} as never,
      "backend:acme.com",
      "",
    ) as unknown as {
      verifyRotationAnnouncement(
        announcement: RotationAnnouncement,
        messageDID: string,
        pinnedDID: string,
      ): boolean;
      verifyReplacementAnnouncement(
        address: string,
        announcement: ReplacementAnnouncement,
        messageDID: string,
        pinnedDID: string,
        meta: { controllerDid?: string },
      ): boolean;
    };
    verifyCalls.mockClear();
    expect(trust.verifyRotationAnnouncement({
      old_did: oldIdentity.did,
      new_did: newIdentity.did,
      timestamp,
      old_key_signature: "YWJj=",
    }, newIdentity.did, oldIdentity.did)).toBe(false);
    expect(trust.verifyReplacementAnnouncement("acme.com/alice", {
      address: "acme.com/alice",
      old_did: oldIdentity.did,
      new_did: newIdentity.did,
      controller_did: controller.did,
      timestamp,
      controller_signature: "YWJj=",
    }, newIdentity.did, oldIdentity.did, { controllerDid: controller.did })).toBe(false);
    expect(verifyCalls).not.toHaveBeenCalled();
  });

  test("accepts valid rotation announcements", async () => {
    const oldIdentity = await didFromSeed(4);
    const newIdentity = await didFromSeed(5);
    const timestamp = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
    const signature = await ed.signAsync(
      new TextEncoder().encode(canonicalRotationJSON(oldIdentity.did, newIdentity.did, timestamp)),
      oldIdentity.seed,
    );
    const announcement: RotationAnnouncement = {
      old_did: oldIdentity.did,
      new_did: newIdentity.did,
      timestamp,
      old_key_signature: b64(signature),
    };

    const store = new PinStore();
    store.storePin(oldIdentity.did, "acme.com/alice", "", "");
    const trust = new SenderTrustManager(
      {} as never,
      {
        verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }),
        resolveIdentity: async () => ({
          did: newIdentity.did,
          address: "acme.com/alice",
          custody: "self",
          identityScope: "global",
        }),
      } as never,
      "backend:acme.com",
      "",
    );

    const result = await trust.normalizeTrust(
      store,
      "verified",
      "acme.com/alice",
      newIdentity.did,
      undefined,
      undefined,
      undefined,
      announcement,
    );
    expect(result.status).toBe("verified");
    expect(store.addresses.get("acme.com/alice")).toBe(newIdentity.did);
  });

  test("accepts valid replacement announcements for public addresses", async () => {
    const oldIdentity = await didFromSeed(6);
    const newIdentity = await didFromSeed(7);
    const controller = await didFromSeed(8);
    const timestamp = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
    const signature = await ed.signAsync(
      new TextEncoder().encode(
        canonicalReplacementJSON("acme.com/alice", controller.did, oldIdentity.did, newIdentity.did, timestamp),
      ),
      controller.seed,
    );
    const announcement: ReplacementAnnouncement = {
      address: "acme.com/alice",
      old_did: oldIdentity.did,
      new_did: newIdentity.did,
      controller_did: controller.did,
      timestamp,
      controller_signature: b64(signature),
    };

    const store = new PinStore();
    store.storePin(oldIdentity.did, "acme.com/alice", "", "");
    const trust = new SenderTrustManager(
      { get: async () => ({}) } as never,
      {
        verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }),
        resolveIdentity: async () => ({
          did: newIdentity.did,
          stableID: "did:aw:test",
          address: "acme.com/alice",
          controllerDid: controller.did,
          custody: "self",
          identityScope: "global",
        }),
      } as never,
      "backend:acme.com",
      "",
    );

    const result = await trust.normalizeTrust(
      store,
      "verified",
      "acme.com/alice",
      newIdentity.did,
      undefined,
      undefined,
      undefined,
      undefined,
      announcement,
    );
    expect(result.status).toBe("verified");
    expect(store.addresses.get("acme.com/alice")).toBe(newIdentity.did);
  });

  test("authorized replacement cleanup cannot resurrect removed unknown pin fields", async () => {
    const oldIdentity = await didFromSeed(32);
    const newIdentity = await didFromSeed(33);
    const controller = await didFromSeed(34);
    const address = "acme.com/alice";
    const timestamp = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
    const signature = await ed.signAsync(
      new TextEncoder().encode(
        canonicalReplacementJSON(address, controller.did, oldIdentity.did, newIdentity.did, timestamp),
      ),
      controller.seed,
    );
    const announcement: ReplacementAnnouncement = {
      address,
      old_did: oldIdentity.did,
      new_did: newIdentity.did,
      controller_did: controller.did,
      timestamp,
      controller_signature: b64(signature),
    };
    const store = PinStore.fromYAML([
      "pins:",
      `  ${oldIdentity.did}:`,
      `    address: ${address}`,
      "    first_seen: 2026-02-22T10:00:00Z",
      "    last_seen: 2026-02-22T11:00:00Z",
      "    future_anti_rollback_anchor: {seq: 9, hash: abc}",
      "addresses:",
      `  ${address}: ${oldIdentity.did}`,
      "",
    ].join("\n"));
    const trust = new SenderTrustManager(
      { get: async () => ({}) } as never,
      {
        resolveIdentity: async () => ({
          did: newIdentity.did,
          stableID: "did:aw:newAlice",
          address,
          controllerDid: controller.did,
          custody: "self",
          identityScope: "global",
        }),
      } as never,
      "backend:acme.com",
      "",
    );

    const result = await trust.normalizeTrust(
      store,
      "verified",
      address,
      newIdentity.did,
      undefined,
      undefined,
      undefined,
      undefined,
      announcement,
    );
    expect(result.status).toBe("verified");
    expect(store.addresses.get(address)).toBe(newIdentity.did);

    store.removeAddress(address);
    store.storePin(oldIdentity.did, address, "", "");
    const emitted = yaml.load(store.toYAML(), { schema: yaml.JSON_SCHEMA }) as {
      pins: Record<string, Record<string, unknown>>;
    };
    expect(emitted.pins[oldIdentity.did].future_anti_rollback_anchor).toBeUndefined();
  });

  test("pins the local namespace address when registry verification degrades for a public address", async () => {
    const { did } = await didFromSeed(9);
    const stableID = "did:aw:test";
    const store = new PinStore();
    const client = {
      hasTeamCertificateAuth: (teamID: string) => teamID === "backend:acme.com",
      get: vi.fn(async (path: string) => {
        expect(path).toBe("/v1/agents");
        return localRoster({
          did_key: did,
          did_aw: stableID,
          address: "acme.com/alice",
          identity_scope: "global",
        });
      }),
    };
    const registry = {
      verifyStableIdentity: vi.fn(async (address: string, stable: string) => {
        expect(address).toBe("acme.com/alice");
        expect(stable).toBe(stableID);
        return { outcome: "OK_DEGRADED" };
      }),
    };
    const trust = new SenderTrustManager(client as never, registry as never, "backend:acme.com", "");

    const result = await trust.normalizeTrust(
      store,
      "verified",
      "alice",
      did,
      stableID,
      undefined,
      undefined,
      undefined,
      undefined,
      "acme.com/alice",
    );

    expect(result.status).toBe("verified");
    expect(store.addresses.get("backend:acme.com/alice")).toBe(stableID);
    expect(store.addresses.has("acme.com/alice")).toBe(false);
    expect(store.pins.get(stableID)?.did_key).toBe(did);
  });

  test("stable-id migration declines an occupied target without losing either pin", async () => {
    const identity = await didFromSeed(36);
    const stableID = "did:aw:stableCollision";
    const address = "acme.com/alice";
    // The stable id is occupied because the same agent is already pinned at
    // ANOTHER address. Two pins claiming one address is not a state the loader
    // accepts in either runtime, so it cannot be the fixture here.
    const store = PinStore.fromYAML([
      "pins:",
      `  ${identity.did}:`,
      `    address: ${address}`,
      "    first_seen: 2026-02-22T10:00:00Z",
      "    last_seen: 2026-02-22T11:00:00Z",
      "    future_old: {seq: 1}",
      `  ${stableID}:`,
      "    address: acme.com/bob",
      "    first_seen: 2026-02-22T09:00:00Z",
      "    last_seen: 2026-02-22T09:30:00Z",
      "    future_stable: {seq: 9}",
      "addresses:",
      `  ${address}: ${identity.did}`,
      "  acme.com/bob: did:aw:stableCollision",
      "",
    ].join("\n"));
    const trust = new SenderTrustManager(
      { get: async () => ({}) } as never,
      {
        resolveIdentity: async () => ({
          did: identity.did,
          stableID,
          address,
          controllerDid: identity.did,
          custody: "self",
          identityScope: "global",
        }),
        verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }),
      } as never,
      "backend:acme.com",
      "",
    );

    const result = await trust.normalizeTrust(
      store,
      "verified",
      address,
      identity.did,
      stableID,
      undefined,
      undefined,
    );

    // Declining the migration must not fail the sender: being reachable at two
    // addresses is ordinary operation, not an identity conflict.
    expect(result).toEqual({ status: "verified", stored: true });
    expect(new Set(store.pins.keys())).toEqual(new Set([identity.did, stableID]));
    expect(store.addresses.get(address)).toBe(identity.did);
    expect(store.pins.get(stableID)?.address).toBe("acme.com/bob");
    const emitted = yaml.load(store.toYAML(), { schema: yaml.JSON_SCHEMA }) as {
      pins: Record<string, Record<string, unknown>>;
    };
    expect(emitted.pins[identity.did].future_old).toEqual({ seq: 1 });
    expect(emitted.pins[stableID].future_stable).toEqual({ seq: 9 });
  });

  test("stable-id migration preserves unknown per-pin fields", async () => {
    const identity = await didFromSeed(35);
    const stableID = "did:aw:stableAlice";
    const address = "acme.com/alice";
    const store = PinStore.fromYAML([
      "pins:",
      `  ${identity.did}:`,
      `    address: ${address}`,
      "    first_seen: 2026-02-22T10:00:00Z",
      "    last_seen: 2026-02-22T11:00:00Z",
      "    future_anti_rollback_anchor: {seq: 9, hash: abc}",
      "addresses:",
      `  ${address}: ${identity.did}`,
      "",
    ].join("\n"));
    const trust = new SenderTrustManager(
      { get: async () => ({}) } as never,
      {
        resolveIdentity: async () => ({
          did: identity.did,
          stableID,
          address,
          controllerDid: identity.did,
          custody: "self",
          identityScope: "global",
        }),
        verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }),
      } as never,
      "backend:acme.com",
      "",
    );

    const result = await trust.normalizeTrust(
      store,
      "verified",
      address,
      identity.did,
      stableID,
      undefined,
      undefined,
    );
    expect(result.status).toBe("verified");
    expect(store.addresses.get(address)).toBe(stableID);

    const emitted = yaml.load(store.toYAML(), { schema: yaml.JSON_SCHEMA }) as {
      pins: Record<string, Record<string, unknown>>;
    };
    expect(emitted.pins[identity.did]).toBeUndefined();
    expect(emitted.pins[stableID].future_anti_rollback_anchor).toEqual({ seq: 9, hash: "abc" });
  });

  test("updates a stable-id pin when registry verifies the current did:key", async () => {
    const oldIdentity = await didFromSeed(11);
    const newIdentity = await didFromSeed(12);
    const stableID = "did:aw:amy";
    const store = new PinStore();
    store.storePin(stableID, "acme.com/amy", "", "");
    store.pins.get(stableID)!.stable_id = stableID;
    store.pins.get(stableID)!.did_key = oldIdentity.did;

    const trust = new SenderTrustManager(
      { get: vi.fn() } as never,
      {
        verifyStableIdentity: async () => ({ outcome: "OK_VERIFIED", currentDidKey: newIdentity.did }),
        resolveIdentity: async () => ({
          did: newIdentity.did,
          stableID,
          address: "acme.com/amy",
          controllerDid: "did:key:zcontroller",
          custody: "self",
          identityScope: "global",
        }),
      } as never,
      "backend:acme.com",
      "",
    );

    const result = await trust.normalizeTrust(store, "verified", "acme.com/amy", newIdentity.did, stableID, undefined);

    expect(result.status).toBe("verified");
    expect(result.stored).toBe(true);
    expect(store.addresses.get("acme.com/amy")).toBe(stableID);
    expect(store.pins.get(stableID)?.did_key).toBe(newIdentity.did);
  });

  // A registry-verified DID log for a DIFFERENT stable identity is not authority
  // to take over an address pinned to someone else: the log proves did:aw ->
  // did:key, never address -> did:aw. Without a namespace-controller-signed
  // replacement announcement the existing pin stands (default-aajc.8).
  test("does not replace a stale address pin when registry verifies a different stable identity", async () => {
    const oldIdentity = await didFromSeed(13);
    const newIdentity = await didFromSeed(14);
    const oldStableID = "did:aw:oldAmy";
    const newStableID = "did:aw:newAmy";
    const store = new PinStore();
    store.storePin(oldStableID, "acme.com/amy", "", "");
    store.pins.get(oldStableID)!.stable_id = oldStableID;
    store.pins.get(oldStableID)!.did_key = oldIdentity.did;

    const trust = new SenderTrustManager(
      { get: vi.fn() } as never,
      {
        verifyStableIdentity: async () => ({ outcome: "OK_VERIFIED", currentDidKey: newIdentity.did }),
        resolveIdentity: async () => ({
          did: newIdentity.did,
          stableID: newStableID,
          address: "acme.com/amy",
          controllerDid: "did:key:zcontroller",
          custody: "self",
          identityScope: "global",
        }),
      } as never,
      "backend:acme.com",
      "",
    );

    const result = await trust.normalizeTrust(store, "verified", "acme.com/amy", newIdentity.did, newStableID, undefined);

    expect(result.status).toBe("identity_mismatch");
    expect(store.addresses.get("acme.com/amy")).toBe(oldStableID);
    expect(store.pins.get(oldStableID)?.did_key).toBe(oldIdentity.did);
    expect(store.pins.has(newStableID)).toBe(false);
  });

  test("does not replace a stale address pin when registry verification degrades", async () => {
    const oldIdentity = await didFromSeed(15);
    const newIdentity = await didFromSeed(16);
    const oldStableID = "did:aw:oldAmy";
    const newStableID = "did:aw:newAmy";
    const store = new PinStore();
    store.storePin(oldStableID, "acme.com/amy", "", "");
    store.pins.get(oldStableID)!.stable_id = oldStableID;
    store.pins.get(oldStableID)!.did_key = oldIdentity.did;

    const trust = new SenderTrustManager(
      { get: vi.fn() } as never,
      {
        verifyStableIdentity: async () => ({ outcome: "OK_DEGRADED" }),
        resolveIdentity: async () => ({
          did: newIdentity.did,
          stableID: newStableID,
          address: "acme.com/amy",
          controllerDid: "did:key:zcontroller",
          custody: "self",
          identityScope: "global",
        }),
      } as never,
      "backend:acme.com",
      "",
    );

    const result = await trust.normalizeTrust(store, "verified", "acme.com/amy", newIdentity.did, newStableID, undefined);

    expect(result.status).toBe("identity_mismatch");
    expect(store.addresses.get("acme.com/amy")).toBe(oldStableID);
  });

  test("refuses invalid verified-head sequences before persisting checkpoints", () => {
    const stableID = "did:aw:checkpoint";
    const store = new PinStore();
    store.storePin(stableID, "acme.com/alice", "", "");
    const trust = new SenderTrustManager(
      { get: vi.fn() } as never,
      {} as never,
      "backend:acme.com",
      "",
    ) as SenderTrustManager & {
      persistVerifiedHeadCheckpoint(
        target: PinStore,
        id: string,
        head: {
          seq: number;
          entryHash: string;
          stateHash: string;
          currentDidKey: string;
          fetchedAt: number;
        },
      ): boolean;
    };

    for (const seq of [1.5, Number.NaN, Number.POSITIVE_INFINITY, Number.MAX_SAFE_INTEGER + 1]) {
      expect(trust.persistVerifiedHeadCheckpoint(store, stableID, {
        seq,
        entryHash: "a".repeat(64),
        stateHash: "b".repeat(64),
        currentDidKey: "did:key:zcheckpoint",
        fetchedAt: 0,
      })).toBe(false);
    }

    expect(store.pins.get(stableID)?.log_seq).toBeUndefined();
  });

  test("surfaces stale verifier cache honestly instead of claiming identity mismatch", async () => {
    const { did } = await didFromSeed(17);
    const stableID = "did:aw:freshAlice";
    const trust = new SenderTrustManager(
      { get: vi.fn() } as never,
      {
        verifyStableIdentity: vi.fn(async () => ({ outcome: "STALE_CACHE" })),
        resolveIdentity: vi.fn(async () => ({
          did,
          stableID,
          address: "acme.com/alice",
          controllerDid: "did:key:zcontroller",
          custody: "self",
          identityScope: "global",
        })),
      } as never,
      "backend:acme.com",
      "",
    );

    const result = await trust.normalizeTrust(
      new PinStore(),
      "verified",
      "acme.com/alice",
      did,
      stableID,
      undefined,
    );

    expect(result.status).toBe("verification_stale");
    expect(result.stored).toBe(false);
  });

  test("does not create a TOFU pin when public-address resolution fails", async () => {
    const { did } = await didFromSeed(10);
    const stableID = "did:aw:test";
    const store = new PinStore();
    const trust = new SenderTrustManager(
      { get: vi.fn() } as never,
      {
        verifyStableIdentity: vi.fn(async () => ({ outcome: "OK_DEGRADED" })),
        resolveIdentity: vi.fn(async () => {
          throw new Error("registry unavailable");
        }),
      } as never,
      "backend:acme.com",
      "",
    );

    const result = await trust.normalizeTrust(
      store,
      "verified",
      "acme.com/alice",
      did,
      stableID,
      undefined,
      undefined,
      undefined,
      undefined,
      "acme.com/alice",
    );

    expect(result.status).toBe("verified");
    expect(result.stored).toBe(false);
    expect(store.pins.size).toBe(0);
    expect(store.addresses.size).toBe(0);
  });
});
