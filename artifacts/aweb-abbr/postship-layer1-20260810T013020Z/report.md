# aweb-abbr post-ship Layer 1 artifact proof

Run completed: 2026-08-10T01:30:20.880Z

## Subject

Published registry artifacts:

- `@awebai/claude-channel@1.7.5`
- `@awebai/pi@0.3.5`

This arm tests the bytes users download, not a workspace build.

## Provenance and loader controls

For each package the harness:

1. fetched registry metadata and the exact `dist.tarball` URL;
2. verified the downloaded tarball against both registry `dist.integrity` (SHA-512 SRI) and `dist.shasum` (SHA-1);
3. rejected unsafe or duplicate normalized archive paths and read `package/dist/index.js` directly from the tarball;
4. recorded SHA-256 for the tarball and original shipped bundle;
5. constructed an observable copy from raw buffers as `original + independently-defined suffix`;
6. proved exact length, original-prefix equality, and suffix equality before import;
7. imported only the canonical real path of that copy and required its unique `import.meta.url` sentinel to equal the canonical bundle URL.

The suffix only exports bundle-internal test seams (`SenderTrustManager`, `PinStore`, and `computeDIDKey`) plus the loader sentinel. No byte inside the shipped bundle prefix is edited.

The first attempted run stopped before behavior because the sentinel correctly exposed the macOS `/tmp` -> `/private/tmp` canonical-path alias. The expected URL was corrected to the filesystem real path; no loader assertion was removed or weakened.

## Behavior result

Each shipped bundle was instantiated with a stub certificate-authenticated team client. Four concurrent distinct aliases began sender-metadata resolution while one roster promise remained pending.

| Artifact | Aliases | `GET /v1/agents` calls before response | Total roster calls | Trust decisions |
|---|---:|---:|---:|---|
| Channel 1.7.5 | 4 | 1 | 1 | 4 verified |
| Pi 0.3.5 | 4 | 1 | 1 | 4 verified |

Primary acceptance criterion passed for both published packages: **4 concurrent aliases -> 1 roster request**.

## Exact digests

- Channel tarball SHA-256: `fc1229baf0bf84a25e28d772a80f534971c2a0293fab37ebccd86bf6d76e68c5`
- Channel shipped bundle SHA-256: `2abbd3a943f808b413816de5fd18da0b619bb15811b3dc31559ad573a885399d`
- Pi tarball SHA-256: `99e05902bd3b66fe75bd0984a922ad9bf8e87900cd073415a5ce024812af8a13`
- Pi shipped bundle SHA-256: `23c76ba4ed63254392cbbfda23de656f14709cbe8c9ee7bcf8a40dd33bcc0830`

## Bounds

- This proves request collapse in the published Channel and Pi bundle payloads.
- No pre-publish candidate tarballs were supplied to this verifier, so candidate-to-registry raw equality is not claimed here. Registry download integrity and shipped behavior are proven independently.
- Layer 2 live presentation remains separate and requires Juan's authorized runtime restart.
- No installed runtime, plugin cache, release tag, or registry artifact was mutated.
