# Customer release procedure: proposed lanes

This is the `aweb-acwd.6` proposal for review. The Secrets, Logs and runner
lanes below are **not implemented** in the release scripts yet. Do not invoke
the proposed tags or treat the packaging proofs as a customer release. The
existing [OSS release procedure](../../../docs/release.md) remains authoritative.

## Artifacts and versions

Extend the existing tag parser, candidate creator and publisher; do not create
a separate publisher or release ledger.

| Proposed immutable tag | Version input | Published artifact |
| --- | --- | --- |
| `secrets-vX.Y.Z` | `naapp/secrets/pyproject.toml` | `ghcr.io/awebai/secrets:X.Y.Z`, with the OCI index and platform digests recorded |
| `logs-vX.Y.Z` | `naapp/logs/pyproject.toml`, supplied by Logs | `ghcr.io/awebai/logs:X.Y.Z`, with the OCI index and platform digests recorded |
| `aweb-secrets-runner-vX.Y.Z` | `naapp/secrets/runner/pyproject.toml` and `naapp/secrets/values/pyproject.toml`, lockstep | PyPI wheels and source distributions for `aweb-secrets-values`, then `aweb-secrets-runner`, with SHA-256 checksums |

The runner proposal uses Python distributions rather than a new platform
archive publisher. The values package is a runtime dependency that is not
covered by today's PyPI lanes. Publish it first at the same version; the runner
must require that exact values version. Use reviewed published dependency floors
for the shared toolkit, following the existing release conventions. An editable
checkout installation is not the released artifact.

The Python lane should accept the existing `X.Y.ZrcN` spelling and promotion
checks. Scope promotion to both runner and values source/build trees, manifests,
locks and their shared build inputs. Only the allowed version/dependency changes
may differ from the selected RC. The proposed image lanes follow today's
final-version OCI lanes; this proposal does not add an OCI prerelease policy.
Each component may have its own version. A release record binds the compatible
component versions and their exact source SHAs; matching version numbers alone
do not establish compatibility.

## Bounded release-tooling changes

1. Add these prefixes and manifest mappings to `scripts/release_versions.py`
   and `scripts/release_candidate.py`, including the runner/values lockstep and
   Python promotion scope. Keep the existing clean, landed-source, immutable-tag
   and complete candidate-gate requirements.
2. Extend `scripts/publish_release.py` with two OCI mappings. Use repository-root
   build contexts, `naapp/secrets/Dockerfile` and `naapp/logs/Dockerfile`, the
   required full `SOURCE_COMMIT`, and version/revision OCI labels. Model the
   workflows on `.github/workflows/awid-image-release.yml`; they call the same
   publisher used without GitHub Actions.
3. Reuse its staged OCI inspection, exact immutable-tag adoption/refusal and
   post-publication digest verification. Keep registry publication usable
   without GitHub. Record the published digest; customers deploy by digest.
4. Add runner/values to the existing Python publication path in dependency
   order. Inspect each built archive's name, version and dependency metadata;
   retain its checksum and refuse an existing version with different bytes.
   Resume identical publication rather than rebuilding a replacement version.
5. Add behavioral release-tooling regressions for tag/manifest mismatch,
   unlanded or dirty source, absent full qualification, unequal runner/values
   versions, changed RC source, immutable-version byte conflicts and resumable
   identical publication. These are additions to the existing release tests.

Whether the two images can advertise both Linux architectures must be proved
by their packaged-image tests. Do not inherit AWID's platform list as evidence.
Logs supplies its version and image qualification; its build-identity and
customer recipe work must land before release. The runner wheel is not a
bundled interpreter, OCI runtime, job image or privileged installation.

## Qualification and publication sequence

The release owner executes this sequence only after the lane implementation
and component source have landed:

1. Select exact landed source, component versions and the supported platform
   list. Verify the candidate checkout and tag manifests using the existing
   release entry point. Include release notes and the dependency compatibility
   record in the reviewed tree before qualification.
2. Establish the inputs for the ordinary candidate gate and the complete Secrets
   release journey in [the acceptance map](../e2e/RELEASE.md), including real
   Logs, genuine vault access, the selected custody provider and the separately
   installed runner. A prerequisite publication, health response, ingest-only
   proof or isolated unit run does not satisfy that journey. Missing prerequisites
   fail it; leave qualification pending until step 4.
3. Record `local_key_file` and `kms` qualifications separately. Publish only the
   support claims actually covered. A local SDK refusal is not successful KMS
   execution. Obtain R and supply-chain/security review at the exact release
   tree. Qualification receipts must name that tree and artifact inputs.
4. Build once and stage through the existing publisher. Retain the OCI archives
   and Python distributions with source/version, dependency/build inputs and
   checksums. Install the staged runner distributions in a clean environment
   using registry dependencies, not repository editable sources. Exercise the
   packaged service images and runner through the ordinary candidate and full
   Secrets gate before creating release tags or publishing. Reuse an existing
   gate receipt only when the exact qualified inputs match; preserve the
   qualified bytes for publication and retries.
5. The release owner publishes the selected immutable tags/artifacts through
   the existing lane. Read back remote versions/digests/checksums and verify
   them against the staged bytes. Do not replace an existing version or qualify
   one build and publish another. Any alias promotion follows verified immutable
   publication; an alias is never the customer's identity check.
6. Hand over the release record, verification instructions and supported
   [operations/evidence matrix](OPERATIONS.md). A failed publication is resumed
   from retained artifacts. Hosted release assets may resume independently of
   package/registry publication, as in the existing conventions.

Step 4 requires the bounded lane implementation to expose retained staged
artifacts to qualification and publication. Do not claim today's OCI publisher,
which builds within its temporary staging context, already implements a
customer-image build-once handoff. This is part of the proposal to review.

## Customer verification in the qualified procedure

The release record contains the source SHA, version/tag, target platform,
registry digest or distribution filename/checksum, dependency versions,
release notes, qualification receipt and custody/backend support matrix.
It contains no environment files, tokens, keys, registration codes or state.

After receiving that record, the customer can verify an image by immutable
digest and inspect its identity without starting it:

```sh
docker pull 'ghcr.io/awebai/secrets@sha256:<published-index-digest>'
docker image inspect 'ghcr.io/awebai/secrets@sha256:<published-index-digest>' \
  --format '{{json .Config.Labels}}'
```

Repeat for `ghcr.io/awebai/logs`. Check the revision and version against the
record and check that the selected platform is qualified. For Python artifacts,
the record supplies a `SHA256SUMS` file for the exact downloaded distributions:

```sh
sha256sum -c SHA256SUMS
```

Checksums must come from the trusted release record; a checksum downloaded from
the same untrusted location as an altered archive does not authenticate it.
Check installed distribution versions and run dependency validation before
operator provisioning. A wheel alone does not prove ownership of its Python
import closure or separate-user execution. Follow the reviewed
[supervisor installation contract](../e2e/SUPERVISOR.md) where that adapter is
used; private registration and the real sudo acceptance remain operator actions.
After operator configuration, compare service build identity with the record
and assess readiness using the operations runbook. Health is not full release
qualification.
