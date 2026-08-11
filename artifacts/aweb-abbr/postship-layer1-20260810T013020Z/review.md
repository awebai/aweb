# Independent review addendum

Resolver-review independently fetched both registry tarballs and reproduced their SHA-256 digests without using this artifact directory:

- Channel 1.7.5: `fc1229baf0bf84a25e28d772a80f534971c2a0293fab37ebccd86bf6d76e68c5` — match
- Pi 0.3.5: `99e05902bd3b66fe75bd0984a922ad9bf8e87900cd073415a5ce024812af8a13` — match

The loader-control calibration was accepted: the first run failed on `/tmp` versus canonical `/private/tmp`; the successful harness corrected the expected value through `realpath` without weakening the sentinel, prefix, or independently-defined suffix checks.

## Provenance refinement

Candidate-to-registry equality is not required to transfer this behavior result because the behavior was measured directly on registry bytes. Layer 1 proves both published bundles exhibit four-alias-to-one-request collapse.

A different residual remains: this arm does not measure whole-bundle source-content correspondence or claim a reproducible rebuild. Release-lane's stage manifest later attested the candidate's `source_sha`, product tag, version, stage-only mode, and file digest, and the publish authority rechecked that bound digest (see `provenance.md` and `audit.md`). That attributes the tested registry bytes to the tagged source record, but it does not prove independently that compiling the source produces the complete bundle payload. The direct published-byte behavior PASS does not depend on that residual.
