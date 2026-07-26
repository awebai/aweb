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

const OPERATION_A = "oas-AAAAAAAAAAAAAAAAAAAAAA";
const OPERATION_B = "oas-BBBBBBBBBBBBBBBBBBBBBQ";

const disposableProvisioned = {
  schema_version: 2,
  mode: "provision-disposable",
  lifecycle: "provisioned",
  cleanup_owner: "instance",
  resource_identity: {
    kind: "provision-operation",
    operation_id: OPERATION_A,
    stable_id: null,
    reference: `operation:${OPERATION_A}`,
    cleanup_authority: "local-controller",
  },
  journal_operation: OPERATION_A,
};

test("binding modes are an exact declared vocabulary with independent cleanup ownership", () => {
  assert.deepEqual(bindingModes, ["provision-disposable", "provision-durable", "attach-existing"]);
  assert.equal(cleanupOwnerForMode("provision-disposable"), "instance");
  assert.equal(cleanupOwnerForMode("provision-durable"), "external");
  assert.equal(cleanupOwnerForMode("attach-existing"), "external");
  assert.throws(() => validateBindingSettings({ schema_version: 2 }), /mode must be one of/);
  assert.throws(() => validateBindingSettings({ schema_version: 2, mode: "none" }), /mode must be one of/);
  assert.deepEqual(validateBindingSettings({ schema_version: 2, mode: "provision-disposable" }).mode, "provision-disposable");
  assert.throws(() => validateBindingSettings({ schema_version: 2, mode: "provision-disposable", operation_id: "shared" }), /exactly schema_version and mode/);
  assert.throws(() => validateBindingSettings({ schema_version: 1, mode: "attach", principal: 123 }), /legacy identity_binding/);
  assert.throws(() => validateBindingSettings({ schema_version: 2, mode: "attach-existing", principal: 123 }), /attach-existing requires/);
  const firstIntent = pendingProvisionReceipt({ schema_version: 2, mode: "provision-disposable" });
  const secondIntent = pendingProvisionReceipt({ schema_version: 2, mode: "provision-disposable" });
  assert.notEqual(firstIntent.journal_operation, secondIntent.journal_operation);
  for (const intent of [firstIntent, secondIntent]) {
    assert.match(intent.journal_operation, /^oas-[A-Za-z0-9_-]{21}[AQgw]$/);
    assert.ok(intent.journal_operation.length <= 64);
  }
});

test("receipt validity matrix rejects contradictory combinations", () => {
  assert.equal(validateBindingReceipt(disposableProvisioned), disposableProvisioned);
  const pendingDurable = pendingProvisionReceipt({ schema_version: 2, mode: "provision-durable" });
  assert.equal(pendingDurable.cleanup_owner, "external");
  assert.throws(() => validateBindingReceipt({ ...disposableProvisioned, cleanup_owner: "external" }), /contradicts mode/);
  assert.throws(() => validateBindingReceipt({ ...disposableProvisioned, lifecycle: "bound" }), /contradictory lifecycle/);
  assert.throws(() => validateBindingReceipt({ ...disposableProvisioned, journal_operation: "other" }), /does not match/);
  assert.throws(() => validateBindingReceipt({
    ...disposableProvisioned,
    journal_operation: 123,
    resource_identity: { ...disposableProvisioned.resource_identity, operation_id: 123 },
  }), /does not match/);
  for (const invalidOperation of ["short", "dotted.operation", "x".repeat(65)]) {
    assert.throws(() => validateBindingReceipt({
      ...disposableProvisioned,
      journal_operation: invalidOperation,
      resource_identity: {
        ...disposableProvisioned.resource_identity,
        operation_id: invalidOperation,
        reference: `operation:${invalidOperation}`,
      },
    }), /hosted alias carrier/);
  }
  assert.throws(() => validateBindingReceipt({ ...disposableProvisioned, schema_version: 99 }), /invalid schema/);
  assert.throws(() => validateBindingReceipt({ ...disposableProvisioned, unexpected: true }), /invalid schema or fields/);
  assert.throws(() => validateBindingReceipt({
    ...disposableProvisioned,
    mode: "provision-durable",
    cleanup_owner: "external",
  }), /requires a locatable did:aw declaration/);
});

test("instance receipt alone cannot grant cleanup and may withhold it", () => {
  const authority = { schema_version: 1, corroboration_class: "local-same-uid", instance_id: "instance-1", receipt: disposableProvisioned };
  assert.deepEqual(cleanupJudgement(disposableProvisioned, authority, "instance-1"), {
    action: "authorize_cleanup",
    cleanup_authorized: true,
    reason: "corroborating_local_record_matches_disposable_resource",
    authority_scope: "local_same_uid_accident_guard",
  });

  assert.deepEqual(cleanupJudgement(disposableProvisioned, {
    ...authority,
    instance_id: 123,
  }, 123), {
    action: "preserve",
    cleanup_authorized: false,
    reason: "cleanup_corroboration_missing_or_mismatched",
  });

  const remoteReceipt = {
    ...disposableProvisioned,
    resource_identity: { ...disposableProvisioned.resource_identity, cleanup_authority: "remote-authority" },
  };
  assert.equal(cleanupJudgement(remoteReceipt, {
    ...authority,
    receipt: remoteReceipt,
  }, "instance-1").reason, "required_remote_authority_corroboration_unavailable");
  assert.deepEqual(cleanupJudgement(remoteReceipt, {
    ...authority,
    corroboration_class: "remote-authority",
    receipt: remoteReceipt,
  }, "instance-1"), {
    action: "authorize_cleanup",
    cleanup_authorized: true,
    reason: "remote_authority_confirms_provisioned_resource",
    authority_scope: "remote_authority_boundary",
  });

  const durableReceipt = {
    ...disposableProvisioned,
    mode: "provision-durable",
    cleanup_owner: "external",
    resource_identity: {
      ...disposableProvisioned.resource_identity,
      kind: "declared-principal",
      stable_id: "did:aw:Durable1",
      reference: "/external/declarations/durable.yaml",
      cleanup_authority: "none",
    },
  };
  assert.deepEqual(cleanupJudgement(durableReceipt, {
    schema_version: 1,
    corroboration_class: "local-same-uid",
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
    ["no authority", disposableProvisioned, null, "instance-1", "cleanup_corroboration_missing_or_mismatched"],
    ["wrong instance", disposableProvisioned, authority, "instance-2", "cleanup_corroboration_missing_or_mismatched"],
    ["target substitution", { ...disposableProvisioned, resource_identity: { ...disposableProvisioned.resource_identity, reference: `operation:${OPERATION_B}`, operation_id: OPERATION_B }, journal_operation: OPERATION_B }, authority, "instance-1", "cleanup_corroboration_missing_or_mismatched"],
  ]) {
    const decision = cleanupJudgement(receipt, record, instanceID);
    assert.equal(decision.action, "preserve", name);
    assert.equal(decision.cleanup_authorized, false, name);
    assert.equal(decision.reason, reason, name);
  }
});
