import assert from "node:assert/strict";
import { test } from "node:test";

import {
  mintingAuthorityReceipt,
  validateMintingAuthorityReceipt,
} from "../.agents/capabilities/owned/aweb-identity-attach/lib/provisioning-authority.mjs";

const declaration = {
  schema_version: 1,
  address: "example.test/provisioner",
  stable_id: "did:aw:2ProvisioningAuthority123",
  team_id: "test-team:example.test",
  soul: "developer",
};

const expected = {
  schema_version: 1,
  kind: "external-declared-principal",
  principal: "provisioner",
  declaration_path: "/repo/oas/agents/developer/principals/provisioner.yaml",
  address: declaration.address,
  stable_id: declaration.stable_id,
  team_id: declaration.team_id,
  grant_retirement_rule: "grants_terminal_before_authority_retirement",
  rule_enforcement: "declarative_no_universal_retirement_choke_point",
  creator_loss_recovery: "known_invite_id_admin_revocation_only",
};

test("minting authority receipt declares the creator and outstanding-grant retirement interval", () => {
  assert.deepEqual(mintingAuthorityReceipt({
    principal: "provisioner",
    declarationPath: expected.declaration_path,
    declaration,
  }), expected);
  assert.deepEqual(validateMintingAuthorityReceipt(expected), expected);
});

test("minting authority receipt rejects ambiguous or contradictory creator policy", () => {
  for (const mutation of [
    { principal: 123 },
    { principal: "other" },
    { declaration_path: "relative.yaml" },
    { stable_id: "did:key:z6NotStable" },
    { address: "not-an-address" },
    { team_id: "not-a-team" },
    { kind: "instance" },
    { grant_retirement_rule: "preflight-only" },
    { rule_enforcement: "enforced" },
    { creator_loss_recovery: "list-as-admin" },
    { unexpected: true },
  ]) {
    assert.throws(() => validateMintingAuthorityReceipt({ ...expected, ...mutation }), /minting authority receipt/);
  }
});
