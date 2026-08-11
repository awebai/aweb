# Provenance audit precision

Resolver-review independently verified against remote refs:

- `channel-v1.7.5` -> `e80bfe45885405d6c3ace872eeab211723ccb93e`;
- `pi-v0.3.5` -> `e80bfe45885405d6c3ace872eeab211723ccb93e`;
- reviewed fix `0de8fcba0d59dde332e2ca44e7c34c06b5054d1e` is an ancestor;
- package versions at that commit are Channel 1.7.5 and Pi 0.3.5.

A bare version search is ambiguous: unrelated CLI tag `aw-v1.7.5` points to `32f0e797` and does not contain the Channel/Pi fix. Audits must use product-prefixed tags.

## Measured versus attested links

Measured independently:

- reviewed fix ancestry into the product-prefixed tagged commit;
- staged-candidate and registry tarball byte-digest equality;
- registry download integrity and bundle digests;
- exact shipped-prefix loader control;
- four concurrent aliases -> one roster request in both bundles.

Attested by release-lane's stage record:

- the retained staged candidates were built from tagged commit `e80bfe45885405d6c3ace872eeab211723ccb93e`.

The stage manifest is the appropriate instrument for that build-source binding. This proof does not claim a reproducible rebuild from the tag, whose tar/gzip metadata may differ even for equivalent package payloads.
