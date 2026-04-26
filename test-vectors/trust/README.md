# Trust Conformance Vectors

These vectors define shared trust-verification contract cases that must pass in
both the Go CLI verifier and the channel TypeScript verifier.

The first vector file covers recipient binding only. Later files should extend
the same pattern for crypto signature handling, sender registry verification,
and TOFU pin continuity.

Recipient-binding vectors start after crypto verification and assert that a
verified message is bound to the local receiver by stable `did:aw` first, with
current `did:key` fallback. Non-verified statuses must pass through unchanged.
