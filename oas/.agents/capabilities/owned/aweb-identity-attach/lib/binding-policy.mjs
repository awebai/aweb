import { createHash, randomBytes } from "node:crypto";
import { existsSync, linkSync, lstatSync, readFileSync, unlinkSync } from "node:fs";
import { isAbsolute, join, normalize, parse, relative, resolve, sep } from "node:path";

// User-configurable modes only. Durable provisioning remains internal receipt
// vocabulary until aaaa.39 delivers a production authority path.
export const bindingModes = Object.freeze([
  "provision-disposable",
  "attach-existing",
]);
const receiptModes = Object.freeze([...bindingModes, "provision-durable"]);

const MODE_CLEANUP_OWNER = Object.freeze({
  "provision-disposable": "instance",
  "provision-durable": "external",
  "attach-existing": "external",
});
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const safeID = (value) => typeof value === "string" && SAFE_ID.test(value);
// "oas-" plus the unpadded base64url encoding of 128 random bits.
const PROVISION_OPERATION_ID = /^oas-[A-Za-z0-9_-]{21}[AQgw]$/;
const provisionOperationID = (value) => typeof value === "string" && PROVISION_OPERATION_ID.test(value);
const DID_AW = /^did:aw:[A-Za-z0-9]+$/;

function exactFields(value, fields) {
  return value && typeof value === "object" && !Array.isArray(value)
    && Object.keys(value).sort().join(",") === [...fields].sort().join(",");
}

function canonicalAbsolutePath(value) {
  return typeof value === "string" && isAbsolute(value) && normalize(resolve(value)) === value;
}

export function cleanupOwnerForMode(mode) {
  const owner = MODE_CLEANUP_OWNER[mode];
  if (!owner) throw new TypeError(`unknown identity binding mode ${JSON.stringify(mode)}`);
  return owner;
}

export function validateBindingSettings(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("identity_binding settings are required");
  }
  if (value.schema_version === 1) {
    if (!exactFields(value, ["schema_version", "mode", "principal"]) || value.mode !== "attach" || !safeID(value.principal)) {
      throw new TypeError("legacy identity_binding v1 must declare mode attach and a principal basename");
    }
    return { ...value, legacy: true };
  }
  if (value.schema_version !== 2) throw new TypeError("identity_binding.schema_version must be 1 or 2");
  if (value.mode === "provision-durable") {
    throw new TypeError("durable resident provisioning is experimental and not configurable until aaaa.39");
  }
  if (!bindingModes.includes(value.mode)) throw new TypeError(`identity_binding.mode must be one of ${bindingModes.join(", ")}`);
  if (value.mode === "attach-existing") {
    if (!exactFields(value, ["schema_version", "mode", "principal"]) || !safeID(value.principal)) {
      throw new TypeError("attach-existing requires exactly schema_version, mode, and principal");
    }
  } else if (value.mode === "provision-disposable") {
    if (!exactFields(value, ["schema_version", "mode", "minting_authority", "minting_authority_path"])
        || !safeID(value.minting_authority)) {
      throw new TypeError("provision-disposable requires exactly schema_version, mode, minting_authority, and minting_authority_path");
    }
    if (!["hosted", "local-controller"].includes(value.minting_authority_path)) {
      throw new TypeError("minting_authority_path must be hosted or local-controller");
    }
  }
  return { ...value, legacy: false };
}

export function pendingProvisionReceipt(settings) {
  const validated = settings?.legacy === false ? settings : validateBindingSettings(settings);
  if (!validated.mode.startsWith("provision-")) throw new TypeError("pending provisioning receipt requires a provision mode");
  // A fresh intent gets an opaque 128-bit identifier in the hosted alias_hint
  // carrier domain. Recovery resumes a durable journal intent; it never
  // re-derives this identifier from an instance name.
  const operationID = `oas-${randomBytes(16).toString("base64url")}`;
  return validateBindingReceipt({
    schema_version: 2,
    mode: validated.mode,
    lifecycle: "provision-pending",
    cleanup_owner: cleanupOwnerForMode(validated.mode),
    resource_identity: {
      kind: "provision-operation",
      operation_id: operationID,
      stable_id: null,
      reference: `operation:${operationID}`,
      cleanup_authority: null,
    },
    journal_operation: operationID,
  });
}

export function provisionedDisposableReceipt(pendingReceipt, { cleanupAuthority }) {
  const pending = validateBindingReceipt(pendingReceipt);
  if (pending.mode !== "provision-disposable" || pending.lifecycle !== "provision-pending") {
    throw new TypeError("provisioned disposable receipt requires a pending disposable intent");
  }
  if (cleanupAuthority !== "local-controller") {
    throw new TypeError("this execution path requires local-controller cleanup authority");
  }
  return validateBindingReceipt({
    ...pending,
    lifecycle: "provisioned",
    resource_identity: {
      ...pending.resource_identity,
      cleanup_authority: cleanupAuthority,
    },
  });
}

export function validateBindingReceipt(receipt) {
  const fields = ["schema_version", "mode", "lifecycle", "cleanup_owner", "resource_identity", "journal_operation"];
  if (!exactFields(receipt, fields) || receipt.schema_version !== 2 || !receiptModes.includes(receipt.mode)) {
    throw new TypeError("identity binding receipt has invalid schema or fields");
  }
  if (receipt.cleanup_owner !== cleanupOwnerForMode(receipt.mode)) {
    throw new TypeError("identity binding receipt contradicts mode cleanup ownership");
  }
  if (!exactFields(receipt.resource_identity, ["kind", "operation_id", "stable_id", "reference", "cleanup_authority"])) {
    throw new TypeError("identity binding resource identity has invalid fields");
  }
  const resource = receipt.resource_identity;
  if (!safeID(receipt.journal_operation) || !safeID(resource.operation_id) || resource.operation_id !== receipt.journal_operation) {
    throw new TypeError("identity binding journal operation does not match its resource identity");
  }
  if (receipt.mode !== "attach-existing" && !provisionOperationID(resource.operation_id)) {
    throw new TypeError("provision operation identity must be an opaque 128-bit id in the hosted alias carrier");
  }
  if (receipt.mode === "attach-existing") {
    if (receipt.lifecycle !== "bound" || receipt.cleanup_owner !== "external" || resource.kind !== "declared-principal"
        || !DID_AW.test(resource.stable_id) || !canonicalAbsolutePath(resource.reference) || resource.cleanup_authority !== "none") {
      throw new TypeError("attach-existing receipt has a contradictory lifecycle or resource identity");
    }
  } else {
    if (!["provision-pending", "provisioned"].includes(receipt.lifecycle)) {
      throw new TypeError("provision receipt has a contradictory lifecycle or resource identity");
    }
    if (receipt.lifecycle === "provision-pending") {
      if (resource.kind !== "provision-operation" || resource.reference !== `operation:${resource.operation_id}` || resource.stable_id !== null || resource.cleanup_authority !== null) {
        throw new TypeError("pending provision receipt must name only its operation");
      }
    } else if (receipt.mode === "provision-durable") {
      if (resource.kind !== "declared-principal" || !DID_AW.test(resource.stable_id) || !canonicalAbsolutePath(resource.reference) || resource.cleanup_authority !== "none") {
        throw new TypeError("durable provisioned receipt requires a locatable did:aw declaration");
      }
    } else if (resource.kind !== "provision-operation" || resource.reference !== `operation:${resource.operation_id}`
        || (resource.stable_id !== null && !DID_AW.test(resource.stable_id))
        || !["local-controller", "remote-authority"].includes(resource.cleanup_authority)) {
      throw new TypeError("disposable provisioned receipt has an invalid operation identity");
    }
  }
  return receipt;
}

export function attachmentReceipt({ declarationPath, stableID }) {
  if (!canonicalAbsolutePath(declarationPath) || !DID_AW.test(stableID)) {
    throw new TypeError("attach-existing receipt requires a canonical declaration and did:aw");
  }
  const operation = `attach-${stableID.slice("did:aw:".length)}`;
  if (!safeID(operation)) throw new TypeError("attach-existing operation identity is invalid");
  return validateBindingReceipt({
    schema_version: 2,
    mode: "attach-existing",
    lifecycle: "bound",
    cleanup_owner: "external",
    resource_identity: {
      kind: "declared-principal",
      operation_id: operation,
      stable_id: stableID,
      reference: declarationPath,
      cleanup_authority: "none",
    },
    journal_operation: operation,
  });
}

// corroborationRecord is a decision-layer input. The production local loader
// can produce only local-same-uid records; a future remote-authority record must
// be verified by the remote authority adapter before it reaches this function.
export function cleanupJudgement(instanceReceipt, corroborationRecord, instanceID) {
  let receipt;
  try {
    receipt = validateBindingReceipt(instanceReceipt);
  } catch {
    return { action: "preserve", cleanup_authorized: false, reason: "missing_or_invalid_instance_receipt" };
  }
  if (receipt.cleanup_owner !== "instance" || receipt.mode !== "provision-disposable" || receipt.lifecycle !== "provisioned") {
    return { action: "preserve", cleanup_authorized: false, reason: "instance_metadata_withholds_cleanup" };
  }
  const requiredCorroboration = receipt.resource_identity.cleanup_authority;
  const corroborationClass = requiredCorroboration === "remote-authority" ? "remote-authority" : "local-same-uid";
  if (!cleanupCorroborationMatches(corroborationRecord, receipt, instanceID, corroborationClass)) {
    const reason = requiredCorroboration === "remote-authority"
      ? "required_remote_authority_corroboration_unavailable"
      : "cleanup_corroboration_missing_or_mismatched";
    return { action: "preserve", cleanup_authorized: false, reason };
  }
  const local = corroborationClass === "local-same-uid";
  return {
    action: "authorize_cleanup",
    cleanup_authorized: true,
    reason: local ? "corroborating_local_record_matches_disposable_resource" : "remote_authority_confirms_provisioned_resource",
    authority_scope: local ? "local_same_uid_accident_guard" : "remote_authority_boundary",
  };
}

function cleanupCorroborationMatches(corroborationRecord, receipt, instanceID, corroborationClass) {
  if (!safeID(instanceID) || !exactFields(corroborationRecord, ["schema_version", "corroboration_class", "instance_id", "receipt"])
      || corroborationRecord.schema_version !== 1 || corroborationRecord.corroboration_class !== corroborationClass
      || !safeID(corroborationRecord.instance_id) || corroborationRecord.instance_id !== instanceID) return false;
  try {
    return JSON.stringify(validateBindingReceipt(corroborationRecord.receipt)) === JSON.stringify(receipt);
  } catch {
    return false;
  }
}

function assertNoSymlink(path) {
  const root = parse(path).root;
  let current = root;
  for (const component of relative(root, path).split(sep).filter(Boolean)) {
    current = join(current, component);
    if (!existsSync(current)) return;
    if (lstatSync(current).isSymbolicLink()) throw new Error(`cleanup corroboration path contains a symbolic link: ${current}`);
  }
}

export function cleanupCorroborationPayload({ schema_version: schemaVersion, corroboration_class: corroborationClass, instance_id: instanceID, receipt }) {
  return Buffer.from(JSON.stringify({ schema_version: schemaVersion, corroboration_class: corroborationClass, instance_id: instanceID, receipt }), "utf8");
}

function readCleanupCorroboration(path, operationID) {
  assertNoSymlink(path);
  const encoded = JSON.parse(readFileSync(path, "utf8"));
  if (!exactFields(encoded, ["schema_version", "corroboration_class", "instance_id", "receipt", "digest"])
      || encoded.corroboration_class !== "local-same-uid" || typeof encoded.digest !== "string") {
    throw new TypeError("cleanup corroboration record has invalid digest fields");
  }
  const record = {
    schema_version: encoded.schema_version,
    corroboration_class: encoded.corroboration_class,
    instance_id: encoded.instance_id,
    receipt: encoded.receipt,
  };
  const digest = createHash("sha256").update(cleanupCorroborationPayload(record)).digest("hex");
  if (digest !== encoded.digest) throw new Error("cleanup corroboration digest is invalid");
  const receipt = validateBindingReceipt(record.receipt);
  if (receipt.journal_operation !== operationID) throw new Error("cleanup corroboration receipt operation does not match its key");
  return { record: { ...record, receipt }, encoded };
}

export function loadCleanupCorroboration(corroborationHome, operationID, instanceID = null) {
  if (!canonicalAbsolutePath(corroborationHome)) throw new TypeError("cleanup corroboration home must be canonical and absolute");
  if (!provisionOperationID(operationID)) throw new TypeError("cleanup corroboration operation id is invalid");
  const path = join(corroborationHome, `${operationID}.json`);
  if (existsSync(path)) {
    const current = readCleanupCorroboration(path, operationID);
    // Bounded migration for the instance-id → operation-id transition only.
    // Delete once no store can contain merged-main instance-keyed records.
    if (instanceID !== null && safeID(instanceID)) {
      const legacyPath = join(corroborationHome, `${instanceID}.json`);
      if (existsSync(legacyPath)) {
        const legacy = readCleanupCorroboration(legacyPath, operationID);
        if (JSON.stringify(legacy.encoded) !== JSON.stringify(current.encoded)) throw new Error("legacy cleanup corroboration contradicts operation-keyed authority");
        unlinkSync(legacyPath);
      }
    }
    return current.record;
  }
  if (instanceID === null) return null;
  if (!safeID(instanceID)) throw new TypeError("OAS_INSTANCE must be filesystem-safe");
  const legacyPath = join(corroborationHome, `${instanceID}.json`);
  if (!existsSync(legacyPath)) return null;
  const legacy = readCleanupCorroboration(legacyPath, operationID);
  try {
    // link(2) is the no-replace cutover claim. A concurrent destination winner
    // yields EEXIST and must compare equal; authority is never overwritten.
    linkSync(legacyPath, path);
  } catch (error) {
    if (error?.code !== "EEXIST") throw error;
    const current = readCleanupCorroboration(path, operationID);
    if (JSON.stringify(current.encoded) !== JSON.stringify(legacy.encoded)) throw new Error("cleanup corroboration adoption found contradictory authority");
  }
  try { unlinkSync(legacyPath); } catch (error) { if (error?.code !== "ENOENT") throw error; }
  return legacy.record;
}
