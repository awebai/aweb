import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, realpathSync, rmSync, statSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  createProvisionIntent,
  listRecoverableProvisionIntents,
  loadProvisionIntent,
  markProvisionIntentPrepared,
  markProvisionIntentProvisioning,
  withProvisionIntentLock,
} from "../.agents/capabilities/owned/aweb-identity-attach/lib/provisioning-journal.mjs";

const OPERATION_A = "oas-AAAAAAAAAAAAAAAAAAAAAA";
const OPERATION_B = "oas-BBBBBBBBBBBBBBBBBBBBBQ";
const AUTHORITY = Object.freeze({
  schema_version: 2,
  path: "local-controller",
  authority_class: "machine-wide-awid-team-controller-key",
  intended_creator: {
    principal: "provisioner",
    declaration_path: "/repo/oas/agents/developer/principals/provisioner.yaml",
    address: "acme.test/provisioner",
    stable_id: "did:aw:Provisioner",
    team_id: "backend:acme.test",
  },
  controller_did: "did:key:z6MkiController",
  authority_scope: "machine-wide-same-uid",
  grant_enumeration: "known-location-files",
  grant_lifetime: "indefinite-no-expiry-or-use-counter",
  creator_loss_effect: "grants-remain-enumerable",
  grant_cleanup_rule: "enumerate-and-remove-abandoned-grants",
  rule_enforcement: "declarative_no_universal_retirement_choke_point",
});

function tempRoot(t, prefix) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), prefix)));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return root;
}

test("provision intent is durable before side effects and contains no bearer secret", (t) => {
  const root = tempRoot(t, "aweb-provision-journal-");

  const intent = createProvisionIntent(root, {
    operationID: OPERATION_A,
    instanceID: "developer-one",
    teamID: "backend:acme.test",
    authority: AUTHORITY,
    now: new Date("2026-07-26T00:00:00Z"),
  });
  assert.equal(intent.state, "allocated");
  assert.equal(intent.alias, OPERATION_A);
  assert.equal(intent.identity_home, join(root, ".provisioning", "identities", OPERATION_A));
  assert.equal(intent.authority.controller_did, AUTHORITY.controller_did);
  assert.equal(statSync(join(root, ".provisioning", "intents", `${OPERATION_A}.json`)).mode & 0o777, 0o600);
  assert.doesNotMatch(readFileSync(join(root, ".provisioning", "intents", `${OPERATION_A}.json`), "utf8"), /token|secret/i);
  assert.deepEqual(loadProvisionIntent(root, OPERATION_A), intent);
  assert.throws(() => createProvisionIntent(root, {
    operationID: OPERATION_A,
    instanceID: "different-instance",
    teamID: "backend:acme.test",
    authority: AUTHORITY,
    now: new Date("2026-07-26T00:00:01Z"),
  }), /already belongs to instance/);
});

test("scanner owns stale incomplete work but never infers that prepared means launched", (t) => {
  const root = tempRoot(t, "aweb-provision-scan-");
  const start = new Date("2026-07-26T00:00:00Z");
  createProvisionIntent(root, { operationID: OPERATION_A, instanceID: "instance-a", teamID: "backend:acme.test", authority: AUTHORITY, now: start });
  createProvisionIntent(root, { operationID: OPERATION_B, instanceID: "instance-b", teamID: "backend:acme.test", authority: AUTHORITY, now: start });
  markProvisionIntentProvisioning(root, OPERATION_A, start);
  markProvisionIntentProvisioning(root, OPERATION_B, start);
  markProvisionIntentPrepared(root, OPERATION_B, {
    status: "provisioned",
    operation_id: OPERATION_B,
    team_id: "backend:acme.test",
    alias: OPERATION_B,
    identity_home: join(root, ".provisioning", "identities", OPERATION_B),
    did_key: "did:key:z6MkiWorker",
    certificate_id: "certificate-b",
    agent_id: "agent-b",
    workspace_id: "workspace-b",
    registry_url: "https://registry.test",
    aweb_url: "https://aweb.test",
  }, start);

  assert.deepEqual(listRecoverableProvisionIntents(root, {
    now: new Date("2026-07-26T00:00:29Z"), staleAfterMs: 30_000,
  }), [], "fresh no-op has a stale positive control below");
  assert.deepEqual(listRecoverableProvisionIntents(root, {
    now: new Date("2026-07-26T00:00:31Z"), staleAfterMs: 30_000,
  }).map((intent) => intent.operation_id), [OPERATION_A]);
});

test("per-intent lock excludes a concurrent scanner and rejects symlink substitution", (t) => {
  const root = tempRoot(t, "aweb-provision-lock-");
  createProvisionIntent(root, {
    operationID: OPERATION_A, instanceID: "instance-a", teamID: "backend:acme.test", authority: AUTHORITY,
    now: new Date("2026-07-26T00:00:00Z"),
  });
  withProvisionIntentLock(root, OPERATION_A, () => {
    assert.throws(() => withProvisionIntentLock(root, OPERATION_A, () => {}), /already locked/);
  });

  const record = join(root, ".provisioning", "intents", `${OPERATION_A}.json`);
  const target = join(root, "substituted.json");
  writeFileSync(target, readFileSync(record));
  // Replace only the final component; same-material links must still be refused.
  unlinkSync(record);
  symlinkSync(target, record);
  assert.throws(() => loadProvisionIntent(root, OPERATION_A), /symbolic link/);
});
