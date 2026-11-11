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

## Creation-path evidence audit (2026-11-11)

Audited against OSS main `1aea4e7bcce092afaea1c0fcf7444626df173a01`.
The JSON updates the reasons for the **13 aweb-owned legacy rows**; its four
converted aweb rows and three external OATS rows retain their status. There
are still 20 paths, four converted and 16 legacy. This is a source/journey
inspection, not a new execution or published-release qualification.

An intentionally bare DID/key operation and a constructor awaiting qualification
are different reasons for remaining legacy. A journey that proves honest
`unknown` is valuable compatibility evidence, but is not a parent chain or an
ancestry refusal. Likewise, the landed shared gate does not by itself prove
that every entry point enforces it. In particular, `SERVER.CONNECT` now calls
the gate (`server/src/aweb/team_auth_deps.py:285–294`,
`server/src/aweb/routes/connect.py:483–503`), and the real journey connects both
human-parented and root-parented identities
(`scripts/e2e-cross-registry-messaging.sh:480–497`). Its before/after `aw who`
comparisons read the local installed chain, however; they do not expose a
connect-specific ancestry bypass. The inventory therefore records that
remaining journey gap rather than claiming the verifier is absent.

### Outsider verification and real DNS (acmj.14 items 3–4)

Both are covered by a landed real-stack journey:

- `scripts/e2e-cross-registry-messaging.sh:181–235,298–307` starts authoritative
  CoreDNS and sets both AWID services, both aweb services and the CLI to its
  resolver. The AWID configurations contain no DNS-skip flag.
- `scripts/e2e-cross-registry-messaging.sh:355–401` proves wrong-controller
  AWID refusal with no namespace created, CLI TXT mismatch refusal, and the
  matching-controller positive. `scripts/cross-registry-human-journey.py:518–560`
  then creates the root-issued human and human/root-issued agents through
  actual CLI processes and a Secret Service keyring, with no DNS skip.
- `scripts/e2e-cross-registry-messaging.sh:475–477` runs the public Go verifier
  and the anonymous Python verifier in the foreign AWID container. Go binds
  the installed public bundle to the expected subject, fetches evidence and
  checks the complete verdict (`scripts/cross-registry-id-verifier.go:34–68`).
  Python takes only public bundle/subject/domain input, obtains its own
  DNS/registry evidence and checks the verdict
  (`scripts/cross-registry-python-verifier.py:11–28`). Neither needs a private
  membership or an issuer's signing key.
- The local-invite case is exercised by
  `scripts/cross-registry-human-journey.py:179–200,258–266,561–578` and included
  in those outsider cases; a revoked inviter refuses both accept and fresh
  issuance without writing a child or changing issuer records
  (`scripts/cross-registry-human-journey.py:380–417`). The complete driver also
  includes human-to-human admission, revocation and scoped J10 replacement
  (`scripts/cross-registry-human-journey.py:324–360,428–473`).

These source anchors answer items 3–4, not the whole of acmj.14 or every
creation row. The suite builds the CLI from source
(`scripts/federation-cli.Dockerfile:6–13`); it is not evidence of a published
CLI/Cloud cohort.

### Hosted consumers and published-cohort qualification (acmj.22)

OSS main contains the consumer/registration/recovery code. It does **not**
contain a real published-cohort Cloud constructor journey qualifying these
four rows:

| Row | Landed consumer | Missing journey on OSS main |
| --- | --- | --- |
| `CLI.CREATE.OWNER` | `cli/go/cmd/aw/id_create_hosted.go:163–166,210–227,294–300` | Real native-owner `id create --org --owner-identity-home` with the correct nearest-human or no-human chain, independent outsider verification, unchanged recovery, and independently registered identity versus refused Cloud membership. |
| `CLI.INIT.APIKEY` | `cli/go/cmd/aw/init_apikey.go:169–176,276–293` | Real API-key local/global `init` with the selected hosted-root chain and `no_human`, original key/certificate retained across failed AWID registration/resume, and anonymous verification. No human may be inferred from the key's user. |
| `CLI.CREATE.HOSTED` | `cli/go/cmd/aw/id_create_hosted.go:168–171,266–302` | Real logged-in human `id create --org` selecting the account human, no fallback on required-parent refusal, unchanged key/certificate resume after registry failure, and independent verification of that human. |
| `CLI.INVITE.HOSTED` | `cli/go/cmd/aw/hosted_invite_creation.go:70–110`; `cli/go/cmd/aw/id_team.go:2198,2303–2328` | Real Cloud issue/preview/accept for native and host-managed agents with local/global children, pinned issuer/domain/kind/mode and per-child registration UUID; unavailable preview refusal and registry-only resume without a second accept. |

The shared install regression uses vector status responses, an HTTP handler
standing in for AWID, and static TXT
(`cli/go/cmd/aw/hosted_creation_install_test.go:151–238`). The typed-invite
regression likewise uses fixture servers and a static resolver
(`cli/go/cmd/aw/hosted_invite_creation_test.go:115–145`). Those are consumer
tests, not the missing real Cloud journeys. They do not justify converting
these four inventory rows.

Cloud owns its constructor journeys and deployment evidence in its application
repository. A deployed enrollment count, or the OSS consumer landing, cannot
substitute for a paired journey receipt identifying the actual published CLI,
Cloud and AWID cohort. This audit does not infer that Cloud has no such evidence;
it establishes the gap in OSS main and names what the closure owner must
reconcile with the Cloud journey owner.
