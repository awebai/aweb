import { isAbsolute, normalize, resolve, sep } from "node:path";

import { validatePrincipalDeclaration } from "./principals.mjs";

const FIELDS = [
  "schema_version",
  "kind",
  "principal",
  "declaration_path",
  "address",
  "stable_id",
  "team_id",
  "grant_retirement_rule",
  "rule_enforcement",
  "creator_loss_recovery",
];
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const DID_AW = /^did:aw:[A-Za-z0-9]+$/;
const ADDRESS = /^[^\s/\\]+\/[^\s/\\]+$/;
const TEAM_NAME_PATTERN = "[a-z0-9](?:[a-z0-9-]*[a-z0-9])?";
const DOMAIN_LABEL_PATTERN = "[a-z0-9](?:[a-z0-9-]*[a-z0-9])?";
const TEAM_ID = new RegExp(`^${TEAM_NAME_PATTERN}:${DOMAIN_LABEL_PATTERN}(?:\\.${DOMAIN_LABEL_PATTERN})*$`);

function exactFields(value, fields) {
  return value && typeof value === "object" && !Array.isArray(value)
    && Object.keys(value).sort().join(",") === [...fields].sort().join(",");
}

function canonicalAbsolutePath(value) {
  return typeof value === "string" && isAbsolute(value) && normalize(resolve(value)) === value;
}

export function validateMintingAuthorityReceipt(receipt) {
  if (!exactFields(receipt, FIELDS)
      || receipt.schema_version !== 1
      || receipt.kind !== "external-declared-principal"
      || typeof receipt.principal !== "string" || !SAFE_ID.test(receipt.principal)
      || !canonicalAbsolutePath(receipt.declaration_path)
      || !receipt.declaration_path.endsWith(`${sep}principals${sep}${receipt.principal}.yaml`)
      || typeof receipt.address !== "string" || !ADDRESS.test(receipt.address)
      || typeof receipt.stable_id !== "string" || !DID_AW.test(receipt.stable_id)
      || typeof receipt.team_id !== "string" || !TEAM_ID.test(receipt.team_id)
      || receipt.grant_retirement_rule !== "grants_terminal_before_authority_retirement"
      || receipt.rule_enforcement !== "declarative_no_universal_retirement_choke_point"
      || receipt.creator_loss_recovery !== "known_invite_id_admin_revocation_only") {
    throw new TypeError("minting authority receipt is invalid or contradictory");
  }
  return receipt;
}

// This receipt declares the lifecycle rule; it does not claim to intercept every
// authority retirement or revocation path. A recovery executor must persist each
// known invite id so an administrator can revoke it if creator-scoped listing is
// lost, and must treat an unreceived id as creator-dependent.
export function mintingAuthorityReceipt({ principal, declarationPath, declaration }) {
  validatePrincipalDeclaration(declaration);
  return validateMintingAuthorityReceipt({
    schema_version: 1,
    kind: "external-declared-principal",
    principal,
    declaration_path: declarationPath,
    address: declaration.address,
    stable_id: declaration.stable_id,
    team_id: declaration.team_id,
    grant_retirement_rule: "grants_terminal_before_authority_retirement",
    rule_enforcement: "declarative_no_universal_retirement_choke_point",
    creator_loss_recovery: "known_invite_id_admin_revocation_only",
  });
}
