// Version sentinel for the security-relevant channel-core surface. The
// claude-channel freshness gate (channel/scripts/check-package-dist.mjs)
// asserts this value is present in the built plugin bundle. It declares which
// revision of the security contract the bundle intends to carry — the
// hardened DID-log verifier (genesis/rotation authorization binding + full-log
// walk) and the fail-closed trust pin store. It does NOT by itself prove that
// code is present: the same gate additionally asserts fix-specific code markers
// (e.g. stableIdentityStateHash, the rotate_key authorization error, the
// present-empty pin-store rejection) that vanish on a revert, and the CI test
// suite exercises the verifier and pin store directly.
//
// Unlike matching error-message text, this value only changes when the security
// contract is intentionally revised — bump the version suffix then, and never
// for unrelated edits. So this sentinel flags an unbuilt/stale bundle without
// churning on unrelated error-wording edits.
export const CHANNEL_CORE_SECURITY_CONTRACT =
  "aweb-channel-core-security/did-log-genesis-bound-v2+full-log-v1+pinstore-fail-closed-v1";
