// The cleanup tuple `aw id team cleanup-local-provision` prints is this capability's
// evidence that an attached principal was cleaned. It is verified here rather than in
// bin/ so the refusal can be tested without executing the CLI entry point.
//
// Until the CLI derived them, identity and audit were literals the CLI itself always
// printed, so the comparisons below were a constant against the same constant: they
// could not fail, and could not see a failed identity deletion. They can now, which is
// only worth something if something demonstrates it - see
// test/local-cleanup-verification.test.mjs.

function exactFields(value, fields) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  return keys.length === fields.length && fields.every((field) => keys.includes(field));
}

export function parseLocalCleanupOutput(stdout, operationID) {
  let result;
  try {
    result = JSON.parse(stdout);
  } catch {
    throw new Error("aw id team cleanup-local-provision returned invalid JSON");
  }
  if (!exactFields(result, ["status", "operation_id", "grants", "workspace", "identity", "certificate", "credentials", "audit"])
      || result.status !== "complete"
      || result.operation_id !== operationID
      || result.grants !== "physically-absent"
      || result.workspace !== "soft-deleted"
      || result.identity !== "soft-deleted"
      || result.certificate !== "revoked"
      || result.credentials !== "physically-absent"
      || result.audit !== "intentionally-retained-operation-record") {
    throw new Error("aw id team cleanup-local-provision returned a contradictory cleanup tuple");
  }
  return result;
}
