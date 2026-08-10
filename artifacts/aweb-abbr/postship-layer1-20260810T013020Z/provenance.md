# Build-once provenance closure

Release-lane retained both staged candidates and reported their stage-manifest SHA-256 values:

| Package | Staged candidate | Staged SHA-256 | Registry SHA-256 | Result |
|---|---|---|---|---|
| Channel 1.7.5 | `awebai-claude-channel-1.7.5.tgz` | `fc1229baf0bf84a25e28d772a80f534971c2a0293fab37ebccd86bf6d76e68c5` | same | byte-identical |
| Pi 0.3.5 | `awebai-pi-0.3.5.tgz` | `99e05902bd3b66fe75bd0984a922ad9bf8e87900cd073415a5ce024812af8a13` | same | byte-identical |

Release-lane further verified that the stage-only artifact manifests bound those candidates to source commit `e80bfe45885405d6c3ace872eeab211723ccb93e` and that publish used the same staged files without repacking.

Wake-fix independently rechecked:

- `channel-v1.7.5` and `pi-v0.3.5` both resolve remotely to exact `e80bfe45885405d6c3ace872eeab211723ccb93e`;
- the tag contains Channel version 1.7.5 and Pi version 0.3.5;
- reviewed fix head `0de8fcba0d59dde332e2ca44e7c34c06b5054d1e` is an ancestor of the tagged source.

Raw candidate and registry digests are identical, so the canonical payload-manifest fallback was not needed. For this release npm preserved the published tarball bytes exactly.

Measured chain:

`reviewed fix -> tagged source -> staged candidate bytes -> same published/registry bytes -> imported bundle -> four aliases / one roster request`
