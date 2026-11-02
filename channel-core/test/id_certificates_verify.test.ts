import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";
import { decodeIdChainHeader, encodeIdChainHeader } from "../src/identity/id_certificates.js";
import {
  idStatusCacheMode,
  idStatusRequest,
  verifyIdChain,
  type IdChain,
  type IdNamespaceAuthority,
  type IdStatusEvidence,
  type IdSubject,
} from "../src/identity/id_verification.js";

const vector = JSON.parse(readFileSync(new URL("../../docs/vectors/id-certificates-v1.json", import.meta.url), "utf8"));
const cases = vector.verification_cases as any[];

function bundle(names: string[]): IdChain | null {
  if (names.length === 0) return null;
  return { v: 1, type: "aweb.id-chain", certificates: names.map(name => vector.certificates[name].signed) };
}

function subjectOf(c: any): IdSubject {
  return { ...c.subject, ...(c.subject_patch ?? {}) };
}

// No namespace_authority in a case means the exact-domain DNS authority agrees
// with the snapshot's current namespace epoch (agreed harness mapping C).
function defaultAuthority(status: any): IdNamespaceAuthority {
  const current = status.namespace.epochs.at(-1);
  return { domain: status.domain, dns_name: `_awid.${status.domain}`, inherited: false, controller_key: current.did_key };
}

function evidenceOf(c: any): IdStatusEvidence | null {
  // A status body supplied by the caller is never evidence.
  if (c.status_source === "caller") return null;
  const status = vector.status_fixtures[c.status];
  return {
    status,
    namespace_authority: c.namespace_authority ?? defaultAuthority(status),
    age_seconds: c.cache ? c.cache.age_seconds : 0,
  };
}

describe("id chain verification cases", () => {
  test("the fixture has the cases this suite was written against", () => {
    expect(cases).toHaveLength(127);
    expect(new Set(cases.map(c => c.name)).size).toBe(127);
  });

  test.each(["delegated-child-authorized", "delegated-child-without-record", "delegated-child-parent-unsigned", "delegated-child-no-dns-anchor", "delegated-child-exact-record-wins"])("mandatory delegation boundary %s is present", name => {
    expect(cases.find(c => c.name === name)).toBeDefined();
  });

  // R1-R3, the namespace replacement cutoff and the did:key-human shape
  // negative are required in every CI.
  test.each([
    "did-key-human-shape-refuses",
    "agent-cannot-issue-human",
    "registry-admission-does-not-excuse-R1",
    "superseded-head-refuses",
    "domain-disagreement-refuses",
    "namespace-parent-domain-human",
    "namespace-parent-domain-agent",
    "root-replacement-old-human-refuses",
    "replacement-then-rotation-does-not-restore-old-tree",
    "namespace-first-epoch-rotated-unavailable",
  ])("mandatory negative %s is present and refuses", name => {
    const c = cases.find(entry => entry.name === name);
    expect(c).toBeDefined();
    expect(c.expected.outcome).not.toBe("nearest_human");
    expect(c.expected.outcome).not.toBe("no_human");
  });

  test.each(cases)("$name", c => {
    const presented = c.presented_chain === false ? null : bundle(c.chain);
    const subject = subjectOf(c);
    const evidence = evidenceOf(c);

    expect(verifyIdChain(presented, subject, evidence)).toEqual(c.expected);

    // Where the strict wire decoder already refuses the bundle, it refuses for
    // the same reason the verifier reports.
    if (presented) {
      const decoded = decodeIdChainHeader(encodeIdChainHeader(presented));
      if (!decoded.ok) expect(decoded.reason).toBe(c.expected.reason);
    }

    if (c.expected_cache_mode !== undefined) {
      expect(idStatusCacheMode(c.cache.age_seconds)).toBe(c.expected_cache_mode);
    }

    // A chainless local subject needs no tree lookup, so no evidence can change it.
    if (c.tree_lookup === false) {
      expect(idStatusRequest(presented, subject)).toEqual({ lookup: "none" });
      expect(verifyIdChain(presented, subject, null)).toEqual(c.expected);
    }

    // An enrolled ID that omits its chain gets the same answer as presenting it.
    if (c.resolve_current_head) {
      expect(verifyIdChain(bundle(c.chain), subject, evidence)).toEqual(c.expected);
    }
  });
});

describe("id status request planning", () => {
  const coordinator = cases.find(c => c.name === "local-child-nearest-human");
  const globalAgent = cases.find(c => c.name === "registered-agent");
  const rootAgent = cases.find(c => c.name === "humanless-root-agent");

  test("a presented chain asks for its registered IDs in its own signed domain", () => {
    expect(idStatusRequest(bundle(globalAgent.chain), subjectOf(globalAgent))).toEqual({
      lookup: "status",
      request: { v: 1, domain: "example.com", ids: ["did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w", "did:aw:44aKNQyvo1xh8rv6TfdfzjTn6nRp"] },
    });
  });

  test("local IDs are never submitted; a root-to-local chain asks for namespace evidence only", () => {
    expect(idStatusRequest(bundle(coordinator.chain), subjectOf(coordinator))).toEqual({
      lookup: "status",
      request: { v: 1, domain: "example.com", ids: ["did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w"] },
    });
    expect(idStatusRequest(bundle(rootAgent.chain), subjectOf(rootAgent))).toEqual({
      lookup: "status",
      request: { v: 1, domain: "example.com", ids: [] },
    });
  });

  test("an omitted stable ID needs an independently selected domain, else evidence is unavailable", () => {
    expect(idStatusRequest(null, subjectOf(globalAgent), "example.com")).toEqual({
      lookup: "status",
      request: { v: 1, domain: "example.com", ids: ["did:aw:44aKNQyvo1xh8rv6TfdfzjTn6nRp"] },
    });
    expect(idStatusRequest(null, subjectOf(globalAgent))).toEqual({ lookup: "unavailable" });
  });

  test("a chainless local subject needs no lookup, whatever domain is offered", () => {
    expect(idStatusRequest(null, subjectOf(coordinator), "example.com")).toEqual({ lookup: "none" });
  });
});

describe("id status cache mode", () => {
  // Evidence is fresh through 60 seconds inclusive; past that it is refreshed
  // or unavailable.
  test.each([
    [0, "fresh"],
    [60, "fresh"],
    [61, "unavailable"],
    [null, "unavailable"],
    [-1, "unavailable"],
    [Number.NaN, "unavailable"],
  ] as const)("age %s -> %s", (age, mode) => {
    expect(idStatusCacheMode(age)).toBe(mode);
  });
});
