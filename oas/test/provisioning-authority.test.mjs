import assert from "node:assert/strict";
import { test } from "node:test";

import {
  hostedMintingAuthorityReceipt,
  localControllerMintingAuthorityReceipt,
  validateMintingAuthorityReceipt,
} from "../.agents/capabilities/owned/aweb-identity-attach/lib/provisioning-authority.mjs";

const declaration = {
  schema_version: 1,
  address: "example.test/provisioner",
  stable_id: "did:aw:2ProvisioningAuthority123",
  team_id: "test-team:example.test",
  soul: "developer",
};
const creator = {
  principal: "provisioner",
  declaration_path: "/repo/oas/agents/developer/principals/provisioner.yaml",
  address: declaration.address,
  stable_id: declaration.stable_id,
  team_id: declaration.team_id,
};

const hosted = {
  schema_version: 2,
  path: "hosted",
  authority_class: "hosted-creator-agent",
  creator,
  grant_listing_scope: "creator-agent-only",
  grant_retirement_rule: "grants_terminal_before_creator_retirement",
  known_id_recovery: "admin-revoke",
  unreceived_id_residual: "server-expiry-bounded-self-terminating",
  default_expiry_hours: 24,
  maximum_expiry_days: 30,
  rule_enforcement: "declarative_no_universal_retirement_choke_point",
};

const localController = {
  schema_version: 2,
  path: "local-controller",
  authority_class: "machine-wide-awid-team-controller-key",
  intended_creator: creator,
  controller_did: "did:key:z6MkiLocalController123",
  authority_scope: "machine-wide-same-uid",
  grant_enumeration: "known-location-files",
  grant_lifetime: "indefinite-no-expiry-or-use-counter",
  creator_loss_effect: "grants-remain-enumerable",
  grant_cleanup_rule: "enumerate-and-remove-abandoned-grants",
  rule_enforcement: "declarative_no_universal_retirement_choke_point",
};

const input = {
  principal: creator.principal,
  declarationPath: creator.declaration_path,
  declaration,
};

test("hosted minting authority receipt declares creator-scoped bounded grant semantics", () => {
  assert.deepEqual(hostedMintingAuthorityReceipt(input), hosted);
  assert.deepEqual(validateMintingAuthorityReceipt(hosted), hosted);
});

test("local minting authority receipt declares machine-wide indefinite grant semantics", () => {
  assert.deepEqual(localControllerMintingAuthorityReceipt({
    ...input,
    controllerDID: localController.controller_did,
  }), localController);
  assert.deepEqual(validateMintingAuthorityReceipt(localController), localController);
});

test("minting authority receipts reject path conflation and contradictory semantics", () => {
  for (const mutation of [
    { ...hosted, creator: { ...creator, principal: 123 } },
    { ...hosted, creator: { ...creator, principal: "other" } },
    { ...hosted, creator: { ...creator, declaration_path: "relative.yaml" } },
    { ...hosted, creator: { ...creator, stable_id: "did:key:z6NotStable" } },
    { ...hosted, creator: { ...creator, team_id: "not-a-team" } },
    { ...hosted, authority_class: "machine-wide-awid-team-controller-key" },
    { ...hosted, unreceived_id_residual: "permanent" },
    { ...hosted, maximum_expiry_days: 31 },
    { ...localController, controller_did: "did:aw:NotAController" },
    { ...localController, authority_scope: "external-principal" },
    { ...localController, grant_lifetime: "expires" },
    { ...localController, known_id_recovery: "admin-revoke" },
  ]) {
    assert.throws(() => validateMintingAuthorityReceipt(mutation), /minting authority receipt/);
  }
});
