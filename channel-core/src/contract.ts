// Stable sentinel for the security-relevant channel-core surface. The
// claude-channel freshness gate (channel/scripts/check-package-dist.mjs)
// asserts this value is present in the built plugin bundle, proving the bundle
// was built from a channel-core that carries the hardened DID-log verifier
// (genesis/rotation authorization binding + full-log walk) and the fail-closed
// trust pin store.
//
// Unlike matching error-message text, this value only changes when the security
// contract is intentionally revised — bump the version suffix then, and never
// for unrelated edits. The gate cannot silently weaken because unrelated error
// wording changed.
export const CHANNEL_CORE_SECURITY_CONTRACT =
  "aweb-channel-core-security/did-log-genesis-bound-v2+full-log-v1+pinstore-fail-closed-v1";
