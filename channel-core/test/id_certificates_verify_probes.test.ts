// Single-fault probes for verifier rules that no frozen case isolates: each
// starts from a verified control and changes exactly one fact. New
// certificates are signed with the fixture's public synthetic seeds.
import { readFileSync } from "node:fs";
import * as ed from "@noble/ed25519";
import { describe, expect, test } from "vitest";
import { idCertificateId, idCertificateSigningBytes, type IdCertificate, type SignedIdCertificate } from "../src/identity/id_certificates.js";
import { verifyIdChain, type IdChain, type IdStatusEvidence, type IdSubject } from "../src/identity/id_verification.js";

const vector = JSON.parse(readFileSync(new URL("../../docs/vectors/id-certificates-v1.json", import.meta.url), "utf8"));
const keys = vector.keys;
const signedOf = (name: string): SignedIdCertificate => vector.certificates[name].signed;

function sign(certificate: IdCertificate, keyName: string): SignedIdCertificate {
  const seed = Uint8Array.from(Buffer.from(keys[keyName].seed_hex, "hex"));
  const signature = ed.sign(idCertificateSigningBytes(certificate), seed);
  return { certificate, signature: Buffer.from(signature).toString("base64url") };
}

const chainOf = (...certificates: SignedIdCertificate[]): IdChain => ({ v: 1, type: "aweb.id-chain", certificates });

function evidence(status: any, authority: Partial<IdStatusEvidence["namespace_authority"]> = {}): IdStatusEvidence {
  return {
    status,
    namespace_authority: {
      domain: "example.com",
      dns_name: "_awid.example.com",
      inherited: false,
      controller_key: keys.root.did_key,
      ...authority,
    },
    age_seconds: 0,
    refresh_failed: false,
  };
}

const normal = () => structuredClone(vector.status_fixtures.normal);
const identity = (status: any, did: string) => status.identities.find((row: any) => row.id === did);

const verified = (human: string, kind: "human" | "agent") => ({
  outcome: "nearest_human",
  human_id: human,
  identity_valid: true,
  kind,
  reason: "verified",
});
const refused = (reason: string) => ({ outcome: "unknown", human_id: null, identity_valid: false, kind: null, reason });
const unavailable = { outcome: "unavailable", human_id: null, identity_valid: null, kind: null, reason: "evidence_unavailable" };

describe("subject binding probes", () => {
  const coordinator = signedOf("coordinator").certificate.id;
  const local: IdSubject = { id: coordinator, did_key: coordinator, team_member_did_aw: null, team_member_did_key: null };
  const chain = chainOf(signedOf("alice"), signedOf("coordinator"));

  test("control: a local leaf matching its authenticated key verifies", () => {
    expect(verifyIdChain(chain, local, evidence(normal()))).toEqual(verified(keys.alice.did_aw, "agent"));
  });

  test("a subject ID other than the leaf refuses even when the key matches", () => {
    expect(verifyIdChain(chain, { ...local, id: keys.bob.did_aw }, evidence(normal()))).toEqual(refused("subject_mismatch"));
  });

  test("a local leaf authenticated by another key refuses with no team certificate in play", () => {
    expect(verifyIdChain(chain, { ...local, did_key: keys.bob.did_key }, evidence(normal()))).toEqual(refused("subject_mismatch"));
  });
});

describe("status consistency probes", () => {
  const globalAgent: IdSubject = {
    id: keys.global_agent.did_aw,
    did_key: keys.global_agent.did_key,
    team_member_did_aw: keys.global_agent.did_aw,
    team_member_did_key: keys.global_agent.did_key,
  };
  const chain = chainOf(signedOf("alice"), signedOf("global-agent"));

  test("control: the unmodified snapshot verifies", () => {
    expect(verifyIdChain(chain, globalAgent, evidence(normal()))).toEqual(verified(keys.alice.did_aw, "agent"));
  });

  test("a registered chain ID that is neither returned nor missing is unavailable", () => {
    const status = normal();
    status.identities = status.identities.filter((row: any) => row.id !== keys.alice.did_aw);
    expect(verifyIdChain(chain, globalAgent, evidence(status))).toEqual(unavailable);
  });

  test("a witnessed issuer key sequence that names another key is unavailable", () => {
    const status = structuredClone(vector.status_fixtures["alice-rotated"]);
    identity(status, keys.global_agent.did_aw).certificates[0].issuer_key_seq = 2;
    expect(verifyIdChain(chain, globalAgent, evidence(status))).toEqual(unavailable);
  });

  test("current_key_seq that is not the verified log head is unavailable", () => {
    const status = structuredClone(vector.status_fixtures["alice-rotated"]);
    identity(status, keys.alice.did_aw).current_key_seq = 1;
    expect(verifyIdChain(chain, globalAgent, evidence(status))).toEqual(unavailable);
  });

  test("current_certificate_id that is not the head revision is unavailable", () => {
    const status = normal();
    identity(status, keys.global_agent.did_aw).current_certificate_id = vector.certificates.alice.certificate_id;
    expect(verifyIdChain(chain, globalAgent, evidence(status))).toEqual(unavailable);
  });

  test("a registered ID whose kind changes between revisions is unavailable (R2)", () => {
    const status = normal();
    const row = identity(status, keys.global_agent.did_aw);
    const asHuman = sign({ ...row.certificates[0].signed.certificate, kind: "human", issued_at: "2026-10-26T00:01:00Z" }, "alice");
    row.certificates.unshift({ signed: asHuman, registered_at: "2026-10-26T00:02:00.000000Z", superseded_at: "2026-10-26T00:04:00.000000Z", issuer_key_seq: 1 });
    expect(verifyIdChain(chain, globalAgent, evidence(status))).toEqual(unavailable);
  });

  test("a snapshot for another domain is unavailable", () => {
    const status = normal();
    status.domain = "other.example";
    expect(verifyIdChain(chain, globalAgent, evidence(status))).toEqual(unavailable);
  });

  test("an inherited authority record is unavailable even at the exact name", () => {
    expect(verifyIdChain(chain, globalAgent, evidence(normal(), { inherited: true }))).toEqual(unavailable);
  });

  test("a DNS controller key that disagrees with the current namespace epoch is unavailable", () => {
    expect(verifyIdChain(chain, globalAgent, evidence(normal(), { controller_key: keys.bob.did_key }))).toEqual(unavailable);
  });
});

describe("historical human-link probes", () => {
  // Alice is re-signed by the root at 00:10. Bob, registered at 00:03, is
  // evaluated against Alice's revision in force then, not her head.
  const aliceHead = sign({ ...signedOf("alice").certificate, issued_at: "2026-10-26T00:10:00Z" }, "root");
  const bob: IdSubject = {
    id: keys.bob.did_aw,
    did_key: keys.bob.did_key,
    team_member_did_aw: null,
    team_member_did_key: null,
  };

  function withAliceRevisions() {
    const status = normal();
    const row = identity(status, keys.alice.did_aw);
    row.certificates[0].superseded_at = "2026-10-26T00:10:00.000000Z";
    row.certificates.push({ signed: aliceHead, registered_at: "2026-10-26T00:10:00.000000Z", superseded_at: null, issuer_key_seq: 1 });
    row.current_certificate_id = idCertificateId(aliceHead.certificate);
    return status;
  }

  test("control: a human registered under a since-superseded parent revision verifies", () => {
    expect(verifyIdChain(chainOf(aliceHead, signedOf("bob")), bob, evidence(withAliceRevisions()))).toEqual(verified(keys.bob.did_aw, "human"));
  });

  test("a historical parent revision whose witnessed issuer key disagrees is unavailable", () => {
    const status = withAliceRevisions();
    identity(status, keys.alice.did_aw).certificates[0].issuer_key_seq = 2;
    expect(verifyIdChain(chainOf(aliceHead, signedOf("bob")), bob, evidence(status))).toEqual(unavailable);
  });

  test("a historical human parent revision issued by an agent refuses (R1 on every link)", () => {
    // Bob's earlier revision claims the global agent as issuer; Bob is then
    // re-signed by Alice. The other human registers under Bob while the
    // agent-issued revision is in force.
    const status = normal();
    const bobRow = identity(status, keys.bob.did_aw);
    const agentIssued = sign(
      { ...signedOf("bob").certificate, parent: { kind: "identity", id: keys.global_agent.did_aw }, issuer_key: keys.global_agent.did_key },
      "global_agent",
    );
    const bobHead = sign({ ...signedOf("bob").certificate, issued_at: "2026-10-26T00:12:00Z" }, "alice");
    bobRow.certificates = [
      { signed: agentIssued, registered_at: "2026-10-26T00:05:00.000000Z", superseded_at: "2026-10-26T00:12:00.000000Z", issuer_key_seq: 1 },
      { signed: bobHead, registered_at: "2026-10-26T00:12:00.000000Z", superseded_at: null, issuer_key_seq: 1 },
    ];
    bobRow.current_certificate_id = idCertificateId(bobHead.certificate);
    const carol = sign(
      { ...signedOf("other-human").certificate, parent: { kind: "identity", id: keys.bob.did_aw }, issuer_key: keys.bob.did_key, issued_at: "2026-10-26T00:06:00Z" },
      "bob",
    );
    const carolRow = identity(status, keys.other_human.did_aw);
    carolRow.certificates = [{ signed: carol, registered_at: "2026-10-26T00:06:00.000000Z", superseded_at: null, issuer_key_seq: 1 }];
    carolRow.current_certificate_id = idCertificateId(carol.certificate);
    const subject: IdSubject = { id: keys.other_human.did_aw, did_key: keys.other_human.did_key, team_member_did_aw: null, team_member_did_key: null };

    expect(verifyIdChain(chainOf(signedOf("alice"), bobHead, carol), subject, evidence(status))).toEqual(refused("human_issuer_is_agent"));
  });
});

describe("namespace epoch probes", () => {
  const coordinator = signedOf("coordinator").certificate.id;
  const local: IdSubject = { id: coordinator, did_key: coordinator, team_member_did_aw: null, team_member_did_key: null };
  const chain = chainOf(signedOf("alice"), signedOf("coordinator"));

  // Alice is registered at 00:01 under epoch 1; the root then rotates.
  function rotatedAt(retiredAt: string) {
    const status = normal();
    status.namespace.epochs = [
      { ...status.namespace.epochs[0], retired_at: retiredAt },
      { seq: 2, did_key: keys.root_rotated.did_key, registered_at: retiredAt, retired_at: null, continuity: "rotated" },
    ];
    return evidence(status, { controller_key: keys.root_rotated.did_key });
  }

  test("control: a revision registered before its epoch retires verifies after a signed rotation", () => {
    expect(verifyIdChain(chain, local, rotatedAt("2026-10-26T00:02:00.000000Z"))).toEqual(verified(keys.alice.did_aw, "agent"));
  });

  test("a revision registered at its epoch's retirement is unavailable", () => {
    expect(verifyIdChain(chain, local, rotatedAt("2026-10-26T00:01:00.000000Z"))).toEqual(unavailable);
  });

  test("a revision registered after its epoch's retirement is unavailable", () => {
    expect(verifyIdChain(chain, local, rotatedAt("2026-10-26T00:00:30.000000Z"))).toEqual(unavailable);
  });
});

describe("namespace replacement probes", () => {
  // A human registered under Alice after the namespace was replaced: its own
  // registration is new, but Alice's revision in force then predates it.
  const child = signedOf("post-replacement-child-of-old-owner");
  const subject: IdSubject = {
    id: keys.replacement_human.did_aw,
    did_key: keys.replacement_human.did_key,
    team_member_did_aw: null,
    team_member_did_key: null,
  };

  function withChild(fixture: string) {
    const status = structuredClone(vector.status_fixtures[fixture]);
    const row = structuredClone(identity(vector.status_fixtures["lost-human-replaced"], keys.replacement_human.did_aw));
    row.certificates = [{ signed: child, registered_at: "2026-10-26T00:11:00.000000Z", superseded_at: null, issuer_key_seq: 1 }];
    row.current_certificate_id = idCertificateId(child.certificate);
    status.identities.push(row);
    return status;
  }

  test("control: without a replacement the human verifies", () => {
    expect(verifyIdChain(chainOf(signedOf("alice"), child), subject, evidence(withChild("normal")))).toEqual(verified(keys.replacement_human.did_aw, "human"));
  });

  test("a historical human-parent revision admitted before the replacement refuses", () => {
    const status = withChild("root-replaced");
    expect(verifyIdChain(chainOf(signedOf("alice"), child), subject, evidence(status, { controller_key: keys.root_rotated.did_key }))).toEqual(refused("root_replaced"));
  });
});
