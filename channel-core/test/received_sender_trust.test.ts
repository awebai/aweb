import { readFileSync } from "node:fs";
import { afterEach, describe, expect, test, vi } from "vitest";
import { APIClient, PinStore, RegistryResolver, SenderTrustManager } from "../src/index.js";
import type { SenderMembership } from "../src/identity/trust.js";
afterEach(() => vi.restoreAllMocks());
const vectors = JSON.parse(readFileSync(new URL("../../docs/vectors/identity-log-v1.json", import.meta.url), "utf8"));
const { did_aw: stableID, initial_did_key: initialKey, rotated_did_key: rotatedKey } = vectors.mapping;
const register = vectors.entries.find((e: { name: string }) => e.name === "register_did");
const rotate = vectors.entries.find((e: { name: string }) => e.name === "rotate_key");
const wire = (entry: typeof register) => ({ ...entry.entry_payload, entry_hash: entry.entry_hash, signature: entry.signature_b64 });
const team = "support:acme.com";
const membership: SenderMembership = { team_id: team, member_did_aw: stableID, state: "active" };
function setup(enrollment: unknown = { enrolled: false }, now: () => number = () => Date.now()) {
  const client = { get: vi.fn(() => { throw new Error("must not read agent listings"); }) } as unknown as APIClient;
  let key = initialKey, code = 200;
  const requests: string[] = [];
  const registry = new RegistryResolver(vi.fn(async (input) => {
    const url = String(input); requests.push(url);
    if (code !== 200) return new Response("unavailable", { status: code });
    if (url.endsWith("/key")) return Response.json({ did_aw: stableID, current_did_key: key, log_head: wire(key === initialKey ? register : rotate), id_tree: enrollment });
    if (url.endsWith("/log")) return Response.json([wire(register), wire(rotate)]);
    throw new Error(`unexpected registry read ${url}`);
  }) as typeof fetch, vi.fn(async hostname => [[`awid=v1; controller=${initialKey}; registry=https://${hostname.includes("other.com") ? "other" : "team"}.registry.test;`]]),
  now, { identityAddress: "unrelated.com/resident" });
  const store = new PinStore();
  const trust = new SenderTrustManager(client, registry, team, initialKey);
  async function receive({ status = "verified", did = key, member = membership, recipient = initialKey,
    currentStore = store, manager = trust }:
    { status?: "verified" | "failed"; did?: string; member?: SenderMembership | null; recipient?: string;
      currentStore?: PinStore; manager?: SenderTrustManager } = {}) {
    const prepared = await manager.resolveTrustMetadata(status, "human-display-name", stableID, recipient, undefined, {
      pinStore: currentStore, fromDID: did, verificationAddress: "", senderAddress: "", senderMembership: member ?? undefined });
    return manager.normalizeResolvedTrust(currentStore, status, "human-display-name", did, stableID, recipient, undefined, undefined, undefined, "", prepared);
  }
  return { registry, store, trust, receive, requests, client, setKey: (value: string) => { key = value; }, setCode: (value: number) => { code = value; } };
}
describe("addressless received human identity", () => {
  test.each([
    ["active", "verified"], ["missing", "verification_stale"], ["unknown", "verification_stale"],
    ["inactive", "identity_mismatch"], ["wrong-stable", "identity_mismatch"], ["wrong-team", "verification_stale"],
    ["wrong-key", "identity_mismatch"], ["registry-down", "verification_stale"],
    ["registry-absent", "verification_stale"], ["failed-signature", "failed"], ["wrong-recipient", "identity_mismatch"],
  ])("%s => %s", async (variant, expected) => {
    const env = setup();
    vi.spyOn(console, "error").mockImplementation(() => {});
    if (variant === "registry-down") env.setCode(503);
    if (variant === "registry-absent") env.setCode(404);
    const member = variant === "missing" ? null : { ...membership,
      state: variant === "unknown" ? "unknown" : variant === "inactive" ? "inactive" : "active",
      team_id: variant === "wrong-team" ? "other:other.com" : team,
      member_did_aw: variant === "wrong-stable" ? "did:aw:other" : stableID } as SenderMembership;
    const result = await env.receive({ member, did: variant === "wrong-key" ? rotatedKey : initialKey,
      status: variant === "failed-signature" ? "failed" : "verified", recipient: variant === "wrong-recipient" ? rotatedKey : initialKey });
    expect(result.status).toBe(expected);
    expect(env.client.get).not.toHaveBeenCalled();
    expect(env.requests.every(url => url.startsWith("https://team.registry.test/v1/did/"))).toBe(true);
    if (["failed-signature", "wrong-recipient", "missing", "unknown", "inactive", "wrong-stable", "wrong-team"].includes(variant)) expect(env.requests).toEqual([]);
    expect(env.store.pins.size).toBe(0); expect(env.store.addresses.size).toBe(0);
  });
  test("rotation checkpoints survive restart, reject rollback, and are scoped by registry", async () => {
    const env = setup();
    expect((await env.receive()).status).toBe("verified");
    env.setKey(rotatedKey); expect((await env.receive()).status).toBe("verified");
    const restored = PinStore.fromYAML(env.store.toYAML());
    expect(restored.receivedIdentityCheckpoint("https://team.registry.test", stableID)?.seq).toBe(2);
    const restarted = setup();
    vi.spyOn(console, "error").mockImplementation(() => {});
    expect((await restarted.receive({ currentStore: restored })).status).toBe("identity_mismatch");
    const other = new SenderTrustManager(restarted.client, restarted.registry, "support:other.com", initialKey);
    expect((await restarted.receive({ currentStore: restored, manager: other, member: { ...membership, team_id: "support:other.com" } })).status).toBe("verified");
    expect(restored.receivedIdentityCheckpoint("https://other.registry.test", stableID)?.seq).toBe(1);
    expect(restored.receivedIdentityCheckpoint("https://team.registry.test", stableID)?.seq).toBe(2);
  });
  test("checkpoint changed while verification awaited cannot apply old evidence", async () => {
    const env = setup();
    const prepared = await env.trust.resolveTrustMetadata("verified", "human", stableID, initialKey, undefined,
      { pinStore: env.store, fromDID: initialKey, verificationAddress: "", senderAddress: "", senderMembership: membership });
    env.store.advanceReceivedIdentityCheckpoint("https://team.registry.test", stableID, {
      seq: 2, entryHash: rotate.entry_hash, currentDidKey: rotatedKey, stateHash: "", fetchedAt: 0 });
    expect((await env.trust.normalizeResolvedTrust(env.store, "verified", "human", initialKey, stableID,
      initialKey, undefined, undefined, undefined, "", prepared)).status).toBe("verification_stale");
  });
  test("malformed shared checkpoint fails closed", async () => {
    const env = setup();
    vi.spyOn(console, "error").mockImplementation(() => {});
    expect((await env.receive({ currentStore: PinStore.fromYAML("pins: {}\naddresses: {}\nreceived_identity_heads: null\n") })).status).toBe("verification_stale");
  });
});

// Same decision matrix as TestReceivedLocalSenderMatrix in Go.
describe("cross-team received local sender", () => {
  test.each([
    ["active", "verified"], ["missing", "verification_stale"], ["unknown", "verification_stale"],
    ["empty-team", "verification_stale"], ["inactive", "identity_mismatch"], ["wrong-team", "identity_mismatch"],
    ["wrong-label", "identity_mismatch"], ["global-projection", "identity_mismatch"],
    ["wrong-projected-key", "identity_mismatch"], ["missing-projected-key", "verification_stale"],
    ["failed-signature", "failed"], ["wrong-recipient", "identity_mismatch"],
    ["plaintext-label", "verified"], ["qualified-team-label", "verified"],
  ])("%s => %s", async (variant, expected) => {
    const env = setup();
    const member: SenderMembership | undefined = variant === "missing" ? undefined : {
      team_id: variant === "empty-team" ? "" : variant === "wrong-team" ? "another:another.test" : "outbound:sender.test",
      state: variant === "unknown" ? "unknown" : variant === "inactive" ? "inactive" : "active",
      member_did_aw: variant === "global-projection" ? stableID : "",
    };
    const raw = variant === "plaintext-label" ? "sender.test/alice"
      : variant === "qualified-team-label" ? "outbound:sender.test/alice" : "alice";
    const status = variant === "failed-signature" ? "failed" : "verified";
    const recipient = variant === "wrong-recipient" ? rotatedKey : initialKey;
    const prepared = await env.trust.resolveTrustMetadata(status, raw, undefined, recipient, undefined, {
      pinStore: env.store, fromDID: initialKey,
      projectedSenderDID: variant === "wrong-projected-key" ? rotatedKey : variant === "missing-projected-key" ? undefined : initialKey,
      verificationAddress: variant === "wrong-label" ? "wrong.test/alice" : raw,
      senderTeamID: variant.includes("label") && variant !== "wrong-label" ? "" : "outbound:sender.test",
      senderMembership: member,
    });
    const got = await env.trust.normalizeResolvedTrust(env.store, status, raw, initialKey, undefined, recipient, undefined,
      undefined, undefined, raw, prepared);
    expect(got.status).toBe(expected);
    expect(env.client.get).not.toHaveBeenCalled();
    expect(env.requests).toEqual([]);
    expect(env.store.pins.size).toBe(0); expect(env.store.addresses.size).toBe(0);
  });
});


test("addressless chainless global sender keeps verified trust and unknown accountability through the same registry", async () => {
  const env = setup();
  expect((await env.receive()).status).toBe("verified");
  const before = [...env.requests];
  const accountability = await env.trust.verifyResponsibility({ from_did: initialKey, from_stable_id: stableID }, true);
  expect(accountability).toMatchObject({ outcome: "unknown", reason: "unregistered_identity", human_id: null });
  expect(env.requests).toEqual(before); // Reuse the actual verified key-resolution snapshot.
});


test.each([undefined, null, { enrolled: true, domain: "other.example" }])("addressless enrollment remains unknown or follows its authoritative domain: %j", async enrollment => {
  const env = setup(enrollment === undefined ? {} : enrollment);
  expect((await env.receive()).status).toBe("verified");
  if (enrollment && typeof enrollment === "object" && "domain" in enrollment) {
    expect(await env.registry.receivedIdEnrollment(team, stableID, initialKey)).toEqual({ state: "enrolled", domain: "other.example" });
  }
  const responsibility = await env.trust.verifyResponsibility({ from_did: initialKey, from_stable_id: stableID }, true);
  expect(responsibility.human_id).toBeNull();
  expect(responsibility.outcome).toBe("unavailable");
});

test("addressless enrollment key snapshots expire beyond 60 seconds and cannot be rebound to another key", async () => {
  let now = Date.now();
  const env = setup({ enrolled: false }, () => now);
  expect((await env.receive()).status).toBe("verified");
  const sender = { from_did: initialKey, from_stable_id: stableID };
  now += 60_000;
  expect((await env.trust.verifyResponsibility(sender, true)).reason).toBe("unregistered_identity");
  now += 1000;
  expect((await env.trust.verifyResponsibility(sender, true)).reason).toBe("evidence_unavailable");
  now -= 61_000;
  expect((await env.trust.verifyResponsibility({ ...sender, from_did: rotatedKey }, true)).reason).toBe("evidence_unavailable");
});
