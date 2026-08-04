import { isAbsolute, normalize, resolve, sep } from "node:path";

import { validatePrincipalDeclaration } from "./principals.mjs";

const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const DID_AW = /^did:aw:[A-Za-z0-9]+$/;
const DID_KEY = /^did:key:z[A-Za-z0-9]+$/;
const ADDRESS = /^[^\s/\\]+\/[^\s/\\]+$/;
const TEAM_NAME_PATTERN = "[a-z0-9](?:[a-z0-9-]*[a-z0-9])?";
const DOMAIN_LABEL_PATTERN = "[a-z0-9](?:[a-z0-9-]*[a-z0-9])?";
const TEAM_ID = new RegExp(`^${TEAM_NAME_PATTERN}:${DOMAIN_LABEL_PATTERN}(?:\\.${DOMAIN_LABEL_PATTERN})*$`);
const CREATOR_FIELDS = ["principal", "declaration_path", "address", "stable_id", "team_id"];
const HOSTED_FIELDS = [
  "schema_version",
  "path",
  "authority_class",
  "creator",
  "grant_listing_scope",
  "grant_retirement_rule",
  "known_id_recovery",
  "unreceived_id_residual",
  "default_expiry_hours",
  "maximum_expiry_days",
  "rule_enforcement",
];
const LOCAL_FIELDS = [
  "schema_version",
  "path",
  "authority_class",
  "intended_creator",
  "controller_did",
  "authority_scope",
  "grant_enumeration",
  "grant_lifetime",
  "creator_loss_effect",
  "grant_cleanup_rule",
  "rule_enforcement",
];

function exactFields(value, fields) {
  return value && typeof value === "object" && !Array.isArray(value)
    && Object.keys(value).sort().join(",") === [...fields].sort().join(",");
}

function canonicalAbsolutePath(value) {
  return typeof value === "string" && isAbsolute(value) && normalize(resolve(value)) === value;
}

function validCreator(creator) {
  return exactFields(creator, CREATOR_FIELDS)
    && typeof creator.principal === "string" && SAFE_ID.test(creator.principal)
    && canonicalAbsolutePath(creator.declaration_path)
    && creator.declaration_path.endsWith(`${sep}principals${sep}${creator.principal}.yaml`)
    && typeof creator.address === "string" && ADDRESS.test(creator.address)
    && typeof creator.stable_id === "string" && DID_AW.test(creator.stable_id)
    && typeof creator.team_id === "string" && TEAM_ID.test(creator.team_id);
}

export function validateMintingAuthorityReceipt(receipt) {
  const hosted = receipt?.path === "hosted";
  const local = receipt?.path === "local-controller";
  if (hosted) {
    if (!exactFields(receipt, HOSTED_FIELDS)
        || receipt.schema_version !== 2
        || receipt.authority_class !== "hosted-creator-agent"
        || !validCreator(receipt.creator)
        || receipt.grant_listing_scope !== "creator-agent-only"
        || receipt.grant_retirement_rule !== "grants_terminal_before_creator_retirement"
        || receipt.known_id_recovery !== "admin-revoke"
        || receipt.unreceived_id_residual !== "server-expiry-bounded-self-terminating"
        || receipt.default_expiry_hours !== 24
        || receipt.maximum_expiry_days !== 30
        || receipt.rule_enforcement !== "declarative_no_universal_retirement_choke_point") {
      throw new TypeError("hosted minting authority receipt is invalid or contradictory");
    }
  } else if (local) {
    if (!exactFields(receipt, LOCAL_FIELDS)
        || receipt.schema_version !== 2
        || receipt.authority_class !== "machine-wide-awid-team-controller-key"
        || !validCreator(receipt.intended_creator)
        || typeof receipt.controller_did !== "string" || !DID_KEY.test(receipt.controller_did)
        || receipt.authority_scope !== "machine-wide-same-uid"
        || receipt.grant_enumeration !== "known-location-files"
        || receipt.grant_lifetime !== "indefinite-no-expiry-or-use-counter"
        || receipt.creator_loss_effect !== "grants-remain-enumerable"
        || receipt.grant_cleanup_rule !== "enumerate-and-remove-abandoned-grants"
        || receipt.rule_enforcement !== "declarative_no_universal_retirement_choke_point") {
      throw new TypeError("local-controller minting authority receipt is invalid or contradictory");
    }
  } else {
    throw new TypeError("minting authority receipt must declare hosted or local-controller path");
  }
  return receipt;
}

function creatorReceipt({ principal, declarationPath, declaration }) {
  validatePrincipalDeclaration(declaration);
  // A receipt that emitted undefined address/stable_id for a local would record a
  // verified attachment that never happened. Refuse until the local shape has a
  // receipt of its own keyed by member name and certificate.
  if (declaration.scope === "local") {
    throw new TypeError("creator receipts do not yet support durable local principals: a local has no address or stable_id to record");
  }
  return {
    principal,
    declaration_path: declarationPath,
    address: declaration.address,
    stable_id: declaration.stable_id,
    team_id: declaration.team_id,
  };
}

// Hosted listing depends on the exact creator agent. If that creator disappears,
// only a known invite id remains admin-revocable; an unreceived id instead waits
// for AC's bounded server-side expiry.
export function hostedMintingAuthorityReceipt(input) {
  return validateMintingAuthorityReceipt({
    schema_version: 2,
    path: "hosted",
    authority_class: "hosted-creator-agent",
    creator: creatorReceipt(input),
    grant_listing_scope: "creator-agent-only",
    grant_retirement_rule: "grants_terminal_before_creator_retirement",
    known_id_recovery: "admin-revoke",
    unreceived_id_residual: "server-expiry-bounded-self-terminating",
    default_expiry_hours: 24,
    maximum_expiry_days: 30,
    rule_enforcement: "declarative_no_universal_retirement_choke_point",
  });
}

// Local intent names the external principal, but the actual authority is the
// machine-wide same-UID team-controller key. Local grant files remain directly
// enumerable and grant mint authority indefinitely until removed.
export function localControllerMintingAuthorityReceipt({ controllerDID, ...input }) {
  return validateMintingAuthorityReceipt({
    schema_version: 2,
    path: "local-controller",
    authority_class: "machine-wide-awid-team-controller-key",
    intended_creator: creatorReceipt(input),
    controller_did: controllerDID,
    authority_scope: "machine-wide-same-uid",
    grant_enumeration: "known-location-files",
    grant_lifetime: "indefinite-no-expiry-or-use-counter",
    creator_loss_effect: "grants-remain-enumerable",
    grant_cleanup_rule: "enumerate-and-remove-abandoned-grants",
    rule_enforcement: "declarative_no_universal_retirement_choke_point",
  });
}
