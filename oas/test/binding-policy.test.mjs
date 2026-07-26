import assert from "node:assert/strict";
import { test } from "node:test";

import {
  bindingModes,
  cleanupJudgement,
  cleanupOwnerForMode,
  pendingProvisionReceipt,
  validateBindingReceipt,
  validateBindingSettings,
} from "../.agents/capabilities/owned/aweb-identity-attach/lib/binding-policy.mjs";

const disposableProvisioned = {
  schema_version: 2,
  mode: "provision-disposable",
  lifecycle: "provisioned",
  cleanup_owner: "instance",
  resource_identity: {
    kind: "provision-operation",
    operation_id: "operation-1",
    stable_id: null,
    reference: "operation:operation-1",
  },
  journal_operation: "operation-1",
};

test("binding modes are an exact declared vocabulary with independent cleanup ownership", () => {
  assert.deepEqual(bindingModes, ["provision-disposable", "provision-durable", "attach-existing"]);
  assert.equal(cleanupOwnerForMode("provision-disposable"), "instance");
  assert.equal(cleanupOwnerForMode("provision-durable"), "external");
  assert.equal(cleanupOwnerForMode("attach-existing"), "external");
  assert.throws(() => validateBindingSettings({ schema_version: 2 }), /mode must be one of/);
  assert.throws(() => validateBindingSettings({ schema_version: 2, mode: "none", operation_id: "operation-1" }), /mode must be one of/);
  assert.throws(() => validateBindingSettings({ schema_version: 2, mode: "provision-disposable" }), /operation_id/);
});

test("receipt validity matrix rejects contradictory combinations", () => {
  assert.equal(validateBindingReceipt(disposableProvisioned), disposableProvisioned);
  const pendingDurable = pendingProvisionReceipt({ schema_version: 2, mode: "provision-durable", operation_id: "durable-1" });
  assert.equal(pendingDurable.cleanup_owner, "external");
  assert.throws(() => validateBindingReceipt({ ...disposableProvisioned, cleanup_owner: "external" }), /contradicts mode/);
  assert.throws(() => validateBindingReceipt({ ...disposableProvisioned, lifecycle: "bound" }), /contradictory lifecycle/);
  assert.throws(() => validateBindingReceipt({ ...disposableProvisioned, journal_operation: "other" }), /does not match/);
  assert.throws(() => validateBindingReceipt({ ...disposableProvisioned, schema_version: 99 }), /invalid schema/);
  assert.throws(() => validateBindingReceipt({ ...disposableProvisioned, unexpected: true }), /invalid schema or fields/);
  assert.throws(() => validateBindingReceipt({
    ...disposableProvisioned,
    mode: "provision-durable",
    cleanup_owner: "external",
  }), /requires a locatable did:aw declaration/);
});

test("mutable metadata can withhold cleanup but cannot grant it", () => {
  const authority = { schema_version: 1, instance_id: "instance-1", receipt: disposableProvisioned };
  assert.deepEqual(cleanupJudgement(disposableProvisioned, authority, "instance-1"), {
    action: "authorize_cleanup",
    cleanup_authorized: true,
    reason: "capability_evidence_matches_disposable_resource",
  });

  const durableReceipt = {
    ...disposableProvisioned,
    mode: "provision-durable",
    cleanup_owner: "external",
    resource_identity: {
      ...disposableProvisioned.resource_identity,
      kind: "declared-principal",
      stable_id: "did:aw:Durable1",
      reference: "/capability-owned/declarations/durable.yaml",
    },
  };
  assert.deepEqual(cleanupJudgement(durableReceipt, {
    schema_version: 1,
    instance_id: "instance-1",
    receipt: durableReceipt,
  }, "instance-1"), {
    action: "preserve",
    cleanup_authorized: false,
    reason: "instance_metadata_withholds_cleanup",
  });

  for (const [name, receipt, record, instanceID, reason] of [
    ["missing", undefined, authority, "instance-1", "missing_or_invalid_instance_receipt"],
    ["partial", { schema_version: 2, mode: "provision-disposable" }, authority, "instance-1", "missing_or_invalid_instance_receipt"],
    ["unknown version", { ...disposableProvisioned, schema_version: 99 }, authority, "instance-1", "missing_or_invalid_instance_receipt"],
    ["external owner withholds", durableReceipt, authority, "instance-1", "instance_metadata_withholds_cleanup"],
    ["no authority", disposableProvisioned, null, "instance-1", "capability_authority_missing_or_mismatched"],
    ["wrong instance", disposableProvisioned, authority, "instance-2", "capability_authority_missing_or_mismatched"],
    ["target substitution", { ...disposableProvisioned, resource_identity: { ...disposableProvisioned.resource_identity, reference: "operation:other", operation_id: "other" }, journal_operation: "other" }, authority, "instance-1", "capability_authority_missing_or_mismatched"],
  ]) {
    const decision = cleanupJudgement(receipt, record, instanceID);
    assert.equal(decision.action, "preserve", name);
    assert.equal(decision.cleanup_authorized, false, name);
    assert.equal(decision.reason, reason, name);
  }
});
