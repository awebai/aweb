# Identity creation coverage and primitive boundary

[identity-tree-coverage.json](identity-tree-coverage.json) contains the identity
creation paths and one list of existing legacy primitive files. Call counts,
public-API inventories and per-function conversion bookkeeping are removed by
Juan's cut 4. Cloud coverage belongs in the application repository.

A path is `converted` only when its constructor and a real journey show the
required chain or refusal. A `candidate` path has its constructor but not yet
that journey. A `legacy` path states why it retains its existing behavior: the
shared codec, registry and client pieces do not by themselves convert a
constructor. Key
rotation, team/session/encryption keys and projection reuse do not create new
identity ancestry. Public external runtime paths retain their repository owner.

`make test-identity-primitives` is the single CI check, run by candidate checks
and ordinary tests. It uses the existing Python, Go and TypeScript parsers to
find raw primitive calls/references in tracked and new nonignored source. Tests
and fixture paths are excluded; production test-like names under `src/` stay
included. The shared verifier and point predicate are named exceptions. Python's
shared key generator is also named; creating keys is separate from verifying
certificates. Existing released signed families and key-custody helpers have
explicit legacy-file reasons in the JSON. Adding a raw primitive elsewhere
refuses; using the public shared verifier does not require any inventory update.
There are no exact counts, stale-site checks or public-API allowlists.

The parser resolves ordinary imports/aliases, callback references and CommonJS
loaders. The JS check classifies WebCrypto roots consistently; ordinary hashing
and randomness are outside the Ed25519 boundary. It does not prove dynamic
control flow or identify every possible crypto package. In particular `jose`
is a known package-discovery limit; this check is not an adversarial repository
sandbox. Reviews and real journey tests establish the behavior that ships.
