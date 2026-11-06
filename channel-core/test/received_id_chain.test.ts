import { readFileSync } from "node:fs";
import { expect, test, vi, afterEach } from "vitest";
import { readReceivedIdChain } from "../src/identity/received_id_chain.js";
import { IdStatusClient } from "../src/identity/id_status.js";
afterEach(() => vi.unstubAllEnvs());
const v = JSON.parse(readFileSync(new URL("../../docs/vectors/id-certificates-v1.json", import.meta.url), "utf8"));
const c = v.verification_cases.find((row: any) => row.name === "local-child-nearest-human");
const chain = { v: 1, type: "aweb.id-chain", certificates: c.chain.map((name: string) => v.certificates[name].signed) };
const status = v.status_fixtures[c.status];
const authority = { domain: status.domain, dns_name: `_awid.${status.domain}`, inherited: false, controller_key: status.namespace.epochs.at(-1).did_key };
const sender = { from_did: c.subject.did_key, id_chain: chain };
const evidence = { async evidence() { return { status, namespace_authority: authority, age_seconds: 0 }; } };

test("a verified sender's chain establishes its human with the shared verifier", async () => {
  expect(await readReceivedIdChain(sender, true, evidence)).toEqual(c.expected);
});
test("chainless messages stay legacy without DNS or status reads", async () => {
  expect(await readReceivedIdChain({ from_did: c.subject.did_key }, true, { evidence() { throw Error("unexpected lookup"); } })).toMatchObject({ outcome: "unknown", reason: "legacy_no_chain", human_id: null });
});
test.each([false, true])("another sender's chain refuses before lookup (authenticated=%s)", async authenticated => {
  const result = await readReceivedIdChain({ ...sender, from_did: v.keys.bob.did_key }, authenticated, { evidence() { throw Error("unexpected lookup"); } });
  expect(result).toMatchObject({ outcome: "unknown", reason: "subject_mismatch", identity_valid: false, human_id: null });
});
test("unverified original signatures never acquire human authority", async () => {
  expect(await readReceivedIdChain(sender, false, evidence)).toMatchObject({ identity_valid: false, human_id: null });
});
test("oversized message metadata refuses before cryptography or lookup", async () => {
  expect(await readReceivedIdChain({ ...sender, id_chain: { ...chain, padding: "x".repeat(6144) } }, true, evidence)).toMatchObject({ reason: "bundle_too_large", identity_valid: false });
});
test("status cache includes age 60, refreshes after, and never reuses failed stale evidence", async () => {
  vi.stubEnv("APP_ENV", "development");
  let now = 100_000, reads = 0, offline = false;
  const client = new IdStatusClient(async () => { reads++; if (offline) throw Error("closed"); return new Response(JSON.stringify(status)); }, async () => [[`awid=v1;controller=${authority.controller_key};registry=https://registry.example.com`]], () => now);
  expect((await client.evidence(chain as any, c.subject))?.age_seconds).toBe(0);
  now += 60_000;
  expect((await client.evidence(chain as any, c.subject))?.age_seconds).toBe(60);
  expect(reads).toBe(1);
  now += 1000;
  offline = true;
  expect(await client.evidence(chain as any, c.subject)).toBeNull();
  expect(reads).toBe(2);
});

test.each(["old-local-signature-after-parent-rotation", "human-revocation-cascades-to-local-agent", "root-replacement-registered-agent-refuses", "humanless-root-agent"])("received chain preserves shared current-status result: %s", async name => {
  const row = v.verification_cases.find((entry: any) => entry.name === name);
  const snapshot = v.status_fixtures[row.status];
  const result = await readReceivedIdChain({ from_did: row.subject.did_key, from_stable_id: row.subject.id.startsWith("did:aw:") ? row.subject.id : undefined,
    id_chain: { v: 1, type: "aweb.id-chain", certificates: row.chain.map((name: string) => v.certificates[name].signed) } }, true,
    { async evidence() { return { status: snapshot, namespace_authority: row.namespace_authority ?? { domain: snapshot.domain, dns_name: `_awid.${snapshot.domain}`, inherited: false, controller_key: snapshot.namespace.epochs.at(-1).did_key }, age_seconds: 0 }; } });
  expect(result).toEqual(row.expected);
});

test("enrolled global omission verifies its current chain instead of claiming legacy", async () => {
  const row = v.verification_cases.find((entry: any) => entry.name === "registered-agent");
  const snapshot = v.status_fixtures[row.status];
  const result = await readReceivedIdChain({ from_did: row.subject.did_key, from_stable_id: row.subject.id, from_address: "example.com/agent" }, true,
    { async enrollmentFor() { return { state: "enrolled", domain: "example.com" }; }, async evidence() { return { status: snapshot, namespace_authority: authority, age_seconds: 0 }; } });
  expect(result).toEqual(row.expected);
});

test("unenrolled global omission is unknown and missing enrollment evidence is unavailable", async () => {
  const sender = { from_did: v.keys.alice.did_key, from_stable_id: v.keys.alice.did_aw, from_address: "example.com/alice" };
  expect(await readReceivedIdChain(sender, true, { ...evidence, async enrollmentFor() { return { state: "not_enrolled", domain: null }; } })).toMatchObject({ outcome: "unknown", reason: "unregistered_identity", human_id: null });
  expect(await readReceivedIdChain(sender, true, { ...evidence, async enrollmentFor() { return { state: "unknown", domain: null }; } })).toMatchObject({ outcome: "unavailable", reason: "evidence_unavailable", human_id: null });
});

test("stored carrier with a bogus parent signature never names a human, even with matching leaf", async () => {
  const bogus = structuredClone(chain);
  bogus.certificates[0].signature = Buffer.alloc(64).toString("base64").replace(/=+$/, "");
  expect(await readReceivedIdChain({ ...sender, id_chain: bogus }, true, { evidence() { throw Error("invalid signature must refuse before lookup"); } })).toMatchObject({ reason: "invalid_signature", identity_valid: false, human_id: null });
});
