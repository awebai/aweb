import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";
import {
  idRequestDisposition,
  verifyIdChain,
  type IdChain,
  type IdStatusEvidence,
  type IdSubject,
} from "../src/identity/id_verification.js";

const vector = JSON.parse(readFileSync(new URL("../../docs/vectors/id-certificates-v1.json", import.meta.url), "utf8"));
const cases = vector.verification_cases as any[];

function bundle(names: string[]): IdChain | null {
  if (names.length === 0) return null;
  return { v: 1, type: "aweb.id-chain", certificates: names.map(name => vector.certificates[name].signed) };
}

function evidenceOf(c: any): IdStatusEvidence | null {
  if (c.status_source === "caller") return null;
  const status = vector.status_fixtures[c.status];
  const current = status.namespace.epochs.find((epoch: any) => epoch.retired_at === null);
  return {
    status,
    namespace_authority: c.namespace_authority ?? {
      domain: status.domain,
      dns_name: `_awid.${status.domain}`,
      inherited: false,
      controller_key: current.did_key,
    },
    age_seconds: c.cache ? c.cache.age_seconds : 0,
    refresh_failed: c.cache ? c.cache.refresh === "failed" : false,
  };
}

describe("id chain request disposition (the same on all five lanes)", () => {
  test("every verification case freezes a disposition", () => {
    expect(cases.every(c => c.expected_request && c.original_auth)).toBe(true);
  });

  test.each(cases)("$name", c => {
    const subject: IdSubject = { ...c.subject, ...(c.subject_patch ?? {}) };
    const presented = c.presented_chain === false ? null : bundle(c.chain);
    const result = verifyIdChain(presented, subject, evidenceOf(c));
    expect(idRequestDisposition(result, subject, c.original_auth === "passed")).toEqual(c.expected_request);
  });

  // The R7 split: identical results, different leaves.
  test("stale or unavailable ancestry continues for a local leaf and refuses for an enrolled one", () => {
    const local: IdSubject = {
      id: "did:key:z6Mkon22vwz9JoNpGDxCrGZRgeNFTdRTwXYYN3fvAhA3K19x",
      did_key: "did:key:z6Mkon22vwz9JoNpGDxCrGZRgeNFTdRTwXYYN3fvAhA3K19x",
      team_member_did_aw: null,
      team_member_did_key: null,
    };
    const enrolled: IdSubject = {
      id: "did:aw:44aKNQyvo1xh8rv6TfdfzjTn6nRp",
      did_key: "did:key:z6MkwVDfCg9LbbY6xjH3EZk8YSFQZujV5Y4y1ZWeER9tDiN3",
      team_member_did_aw: null,
      team_member_did_key: null,
    };
    for (const reason of ["stale_issuer_key", "status_expired", "evidence_unavailable"] as const) {
      const outcome = reason === "stale_issuer_key" ? "unknown" : "unavailable";
      const result = { outcome, human_id: null, identity_valid: reason === "stale_issuer_key" ? false : null, kind: null, reason } as const;
      expect(idRequestDisposition(result, local, true)).toEqual({ ordinary: "continue", human_required: "refuse" });
      expect(idRequestDisposition(result, enrolled, true)).toEqual({ ordinary: "refuse", human_required: "refuse" });
    }
  });
});
