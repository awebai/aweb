# Pinned released message payload bytes

Used by `server/tests/test_released_message_signature_http.py` for ordinary
aw-v1.0.25 and resident-custody aw-v1.36.58 mail/chat compatibility. The JSON
stores original signed-payload strings, not objects to reserialize. Substitution
changes only DID/UUID/UTC-time scalar markers from the real test actors. The
literal body includes HTML punctuation, a newline and a Unicode line separator;
the server must verify exactly these UTF-8 bytes.

Provenance (exact tag commits and source SHA256 are in payloads.json):

- Ordinary: the complete `MessageEnvelope`, `CanonicalJSON` and
  `writeEscapedString` definitions were extracted unchanged from
  `aw-v1.0.25:cli/go/awid/signing.go` and executed with the standard Go toolchain.
- Resident custody: `aw-v1.36.58:cli/go/cmd/aw/custody.go:596-600` signs the
  resident envelope with `SignMessage` and returns `CanonicalJSON(&env)`.
  Templates were emitted by that release's `awid.CanonicalJSON` implementation;
  the local SDK signing.go used for generation differs from the released file
  only in an unrelated comment, with all declarations/statement ASTs unchanged.
  The test signs the returned bytes with the real resident test key while the
  HTTP request is authenticated with a separate freshly minted grant key.

Neither fixture simulates a running released binary or verifies a production
custody service. The HTTP tests exercise actual authentication, grant minting,
server admission, storage and refusal neighbors. Fresh timestamps avoid a fixed
fixture date silently aging out; signatures always cover the instantiated
original string. These are new compatibility fixtures, not replacements for
frozen conformance vectors.
