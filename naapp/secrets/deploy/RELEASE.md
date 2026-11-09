# Customer release procedure

The Secrets, Logs and runner lanes use the existing release scripts. They may
publish a customer release only after their source has landed and passed the
ordinary candidate gate and full Secrets gate. Packaging proofs or recognition
of a tag alone do not establish that qualification. The
[OSS release procedure](../../../docs/release.md) remains authoritative.

## Artifacts and versions

Use the existing tag parser, candidate creator, publisher and qualification
ledger. There is no separate customer publisher.

| Immutable tag | Version input | Published artifact |
| --- | --- | --- |
| `secrets-vX.Y.Z` | `naapp/secrets/pyproject.toml` | `ghcr.io/awebai/secrets:X.Y.Z`, with the OCI index and platform digests recorded |
| `logs-vX.Y.Z` | `naapp/logs/pyproject.toml`, supplied by Logs | `ghcr.io/awebai/logs:X.Y.Z`, with the OCI index and platform digests recorded |
| `aweb-secrets-runner-vX.Y.Z` | `naapp/secrets/runner/pyproject.toml` and `naapp/secrets/values/pyproject.toml`, lockstep | PyPI wheels and source distributions for `aweb-secrets-values`, then `aweb-secrets-runner`, with SHA-256 checksums |

The runner uses Python distributions rather than a platform archive publisher.
The values package is its lockstep runtime dependency. Publish it first at the
same version; the runner must require that exact values version. Use reviewed published dependency floors
for the shared toolkit, following the existing release conventions. An editable
checkout installation is not the released artifact.

The Python lane accepts the existing `X.Y.ZrcN` spelling and promotion checks.
Promotion covers both runner and values source/build trees, manifests, locks and
their shared build inputs. Only the allowed version/dependency changes may
differ from the selected RC. The image lanes follow the existing final-version
OCI lanes; there is no additional OCI prerelease policy.
Following the existing Python RC convention, publish the values RC to PyPI
before qualifying the runner RC installed from registry dependencies, then
publish the runner RC through the same lane. Do not introduce a private index.
Final promotion and customer publication still require the full Secrets gate.
Each component may have its own version. A release record binds the compatible
component versions and their exact source SHAs; matching version numbers alone
do not establish compatibility.

## Release-tooling boundaries

1. `scripts/release_versions.py` and `scripts/release_candidate.py` bind prefixes
   to manifests, enforce runner/values lockstep and Python promotion scope, and
   retain clean, landed-source, immutable-tag and complete candidate-gate requirements.
2. `scripts/publish_release.py` uses the two OCI mappings with repository-root
   build contexts, `naapp/secrets/Dockerfile` and `naapp/logs/Dockerfile`, the
   required full `SOURCE_COMMIT`, and version/revision OCI labels. The shared
   `.github/workflows/service-image-release.yml` handles AWID, Secrets and Logs tags
   and calls the same publisher used without GitHub Actions.
3. The publisher reuses staged OCI inspection, exact immutable-tag adoption/refusal and
   post-publication digest verification. Keep registry publication usable
   without GitHub. Record the published digest; customers deploy by digest.
4. Runner/values use the existing Python publication path in dependency order.
   Inspect archive name/version and exact dependency metadata, retain checksums,
   and refuse an existing version with different bytes. Resume identical
   publication under the existing conventions.
5. The existing release tests and customer-lane regressions cover tag/manifest mismatch,
   unlanded or dirty source, absent full qualification, unequal runner/values
   versions, changed RC source, immutable-version byte conflicts and resumable
   identical publication. These are release-tooling checks, not the full customer journey.

Whether the two images can advertise both Linux architectures must be proved
by their packaged-image tests. Do not inherit AWID's platform list as evidence.
Logs supplies its version and image qualification; its build-identity and
customer recipe work must land before release. The runner wheel is not a
bundled interpreter, OCI runtime, job image or privileged installation.

## Qualification and publication sequence

The release owner executes this sequence only after component source and lane
implementation have landed:

1. Select exact landed RC source, component versions and the supported platform
   list. Verify the candidate checkout and tag manifests using the existing
   release entry point. Include release notes and the dependency compatibility
   record in the reviewed tree before qualification.
2. Qualify that exact landed RC through the ordinary candidate gate and the
   complete Secrets release journey in [the acceptance map](../e2e/RELEASE.md), including real
   Logs, genuine vault access, the selected custody provider and the separately
   installed runner. A prerequisite publication, health response, ingest-only
   proof or isolated unit run does not satisfy that journey. Missing prerequisites
   fail it. Retain the gate receipts for that exact source and configuration.
3. Record `local_key_file` and `kms` qualifications separately. Publish only the
   support claims actually covered. A local SDK refusal is not successful KMS
   execution. Obtain R and supply-chain/security review at the exact release
   tree. Qualification receipts must name that tree and artifact inputs.
4. Promote the same qualified source with only version/dependency changes
   allowed by the existing RC promotion checks. The qualification includes
   actual packaged service images and the runner installed in a clean
   environment using registry dependencies, not repository editable sources.
   Create the release tags through the existing candidate entry point. Tag to
   live must stay under 45 minutes; qualification precedes final tagging, rather
   than starting a full journey inside that window.
5. The release owner publishes the selected immutable tags/artifacts through
   the existing lane. Read back remote versions/digests/checksums and verify
   them using the existing publisher's verification. Do not replace an existing
   version. This follows source qualification; byte-identical OCI rebuilds are
   not a release requirement. Any alias promotion follows verified immutable
   publication; an alias is never the customer's identity check.
6. Hand over the release record, verification instructions and supported
   [operations/evidence matrix](OPERATIONS.md). A failed publication is resumed
   through the existing publisher. Hosted release assets may resume independently of
   package/registry publication, as in the existing conventions.

## Customer verification in the qualified procedure

The release record contains the source SHA, version/tag, target platform,
registry digest or distribution filename/checksum, dependency versions,
release notes, qualification receipt and custody/backend support matrix.
It contains no environment files, tokens, keys, registration codes or state.
Deliver the record through authenticated aweb mail from the identified release
owner to the customer operator, independently of mutable downloaded release
assets. The operator verifies the sender using the established aweb trust
relationship. An attacker able to replace an asset could also replace a record
hosted alongside it; that mutable copy alone is not an authenticated record.

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
