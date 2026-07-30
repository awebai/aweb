import assert from "node:assert/strict";
import { test } from "node:test";

import { parseLocalCleanupOutput } from "../.agents/capabilities/owned/aweb-identity-attach/lib/local-cleanup-tuple.mjs";

const OPERATION = "oas-AAAAAAAAAAAAAAAAAAAAAA";

function tuple(overrides) {
  return JSON.stringify({
    status: "complete",
    operation_id: OPERATION,
    grants: "physically-absent",
    workspace: "soft-deleted",
    identity: "soft-deleted",
    certificate: "revoked",
    credentials: "physically-absent",
    audit: "intentionally-retained-operation-record",
    ...overrides,
  });
}

// The positive control. Without it, a check that rejects everything looks
// identical to one that rejects the right things.
test("a cleanup that established every outcome is accepted", () => {
  assert.equal(parseLocalCleanupOutput(tuple({}), OPERATION).operation_id, OPERATION);
});

// This is the case that mattered: the CLI used to print identity "soft-deleted"
// from a hardcoded literal, so this verifier compared a constant against the same
// constant and could never see a failed identity deletion.
test("a failed identity deletion is refused", () => {
  assert.throws(
    () => parseLocalCleanupOutput(tuple({ identity: "not-deleted" }), OPERATION),
    /contradictory cleanup tuple/,
  );
});

// Unknown is not the good outcome. A retirement must not be declared complete on
// a field the CLI said it could not establish.
test("an unestablished outcome is refused rather than assumed", () => {
  for (const field of ["identity", "workspace", "audit"]) {
    assert.throws(
      () => parseLocalCleanupOutput(tuple({ [field]: "could-not-establish" }), OPERATION),
      /contradictory cleanup tuple/,
      `${field}=could-not-establish was accepted`,
    );
  }
});
