# Installation and release integrity

The release publisher authorizes executable bytes. HTTPS transports artifacts;
a checksum detects corruption but does not independently authenticate a publisher.

1. An archive needs exactly one well-formed SHA-256 entry for its exact name in
   checksums.txt. Missing, duplicate, malformed or mismatched entries refuse before
   extraction or replacement. Refusals name the artifact and explain how to retry.
2. The shell installer builds the exact selected `vVERSION` tag when the
   release archive for its platform returns HTTP 404. It never falls back to
   source on checksum, signature, or other download errors.
3. Replacement stages a complete executable in the destination directory, then
   renames it over the serving path. A failed verification leaves the old executable.
4. [Wake runner integrity](wake-runner-integrity.md) owns cache-byte authorization,
   repair and state-directory rules.
5. [Runtime hook configuration](runtime-hook-configuration.md) owns lossless edits,
   migration confirmation and atomic settings/instruction updates.
6. Before dispatch, aw compares a managed plugin with its installed provenance
   digest. If the bytes differ, aw warns on stderr, explains how to reinstall, and
   runs the locally changed executable. Manually placed executables without
   provenance remain supported.
7. [Runtime hook configuration](runtime-hook-configuration.md) also owns private
   notification cooldown files and failure handling.

## Signed release manifest rollout

release-manifest.json contains schema `aw-release-manifest-v1`, `version`,
`source_commit`, and `artifacts`: a map from file names to `sha256` and `size`.
release-manifest.sig is JSON with `key_id`, base64 `statement` bytes and a base64
raw Ed25519 `signature`. The signature covers a canonical ASCII statement of at
most 256 bytes, with exactly these four LF-terminated lines, in this order:
`aw-release-statement-v1`, `version=VERSION`, `source_commit=COMMIT`, and
`manifest_sha256=LOWERCASE_SHA256`. The version uses the release version syntax;
the commit is a full lowercase 40- or 64-digit source object id. No extra lines,
spaces or alternative encodings are accepted.

Verification checks the signature over those statement bytes first, then the
SHA-256 of the exact manifest file bytes, then exact equality of statement and
manifest version/source commit, then artifact digests and sizes. Nothing
re-serializes the manifest between staging, signing, upload or readback. The
short statement stays below the PIV message-size limit as the artifact list grows.

The verifier accepts only public release keys pinned in
cli/go/internal/releaseverify/keys.json. The rollout starts with no authority in
that file; no placeholder or automatically generated production key is allowed.
The release operator supplies two distinct Ed25519 public keys: active and
successor. Key replacement and retirement require a reviewed client release.
Active and successor private keys are generated on two separate YubiKey PIV
slots 9c, firmware 5.7 or later, under the operator's custody; they never leave
the devices. A third device runs the proof before production provisioning.
[The single operator command document](release-key-setup.md) covers credentials,
raw signing with ykman, device effects and recovery. Publication consumes only
public keys, statement and detached signature. No real pins or release manifests
are published until the real-device positive/tampered-manifest proof is accepted.

A signed manifest must match the requested release and cannot be older than the
running aw version. An explicitly requested version is the shell installer's
version floor. A valid signature on an older release does not authorize rollback.

An archive install requires checksums. When both signing files are absent, the
installer warns that publisher authentication is unavailable. When both files
are present, the shell installer verifies the signature, artifact digest, and size
if Python 3 and OpenSSL with Ed25519 support are available. Otherwise it warns on
stderr and uses the verified archive checksum. The Go upgrade verifier needs no
external tools. An incomplete pair, a fetch error that prevents establishing
the pair, or a failed verification refuses.

The publisher stages all archives and npm tarballs, creates the manifest once,
obtains its detached signature, verifies it locally, and uploads those same bytes
to two independent HTTPS hosts. Readback compares raw manifest and signature bytes
and every artifact's size and digest at both hosts. Signing and staging work
without a hosting-provider API or CI service.

## Publisher commands

From cli/go, after building all platform archives and npm tarballs once:

```sh
python3 release_manifest.py create --version VERSION --commit COMMIT \
  --output STAGE/release-manifest.json STAGE/*.tar.gz STAGE/*.zip STAGE/*.tgz
python3 release_manifest.py statement --manifest STAGE/release-manifest.json \
  --output STAGE/release-statement.txt
# The operator signs that exact short statement using the reviewed ykman adapter.
# Attach its 64-byte raw signature without rewriting the manifest:
python3 release_manifest.py attach-signature --key-id active \
  --statement STAGE/release-statement.txt --raw-signature STAGE/release-statement.rawsig \
  --output STAGE/release-manifest.sig
python3 release_manifest.py verify --requested VERSION \
  --manifest STAGE/release-manifest.json --signature STAGE/release-manifest.sig
# Upload the staged bytes, then check both independent hosts:
python3 release_manifest.py readback --requested VERSION \
  --manifest STAGE/release-manifest.json --signature STAGE/release-manifest.sig \
  --url https://FIRST/vVERSION --url https://SECOND/vVERSION
```

Run `python3 cli/go/generate_install_verifier.py` after updating real pins or the
publisher verifier. Its `--check` gate ensures the bootstrap shell uses that
owner's code and pins. The hardware proof requires a successful signature check
in both verifiers, including Python 3 and Ed25519-capable OpenSSL for the shell.

The shell supports an explicit `AW_VERSION` and `AW_RELEASE_BASE_URL` for a
published version on another HTTPS mirror. Its release URLs append `/vVERSION/`.

## Runtime compatibility

cli/go/internal/releaseverify/channels.json owns the independently versioned Pi,
Claude channel and Claude marketplace compatibility mapping. Setup and emitted
MCP configuration consume it. The release coordinator supplies the immutable
marketplace revision at the release cut. An aw final refuses publication until
all mapped exact npm versions and that marketplace revision are published.
Existing installed Pi packages continue to work; setup installs the mapped
version when the extension is missing.

Claude supports an immutable git URL with a `#ref` suffix, as described in its
[plugin installation reference](https://code.claude.com/docs/en/plugins/install.md#add-a-marketplace).

## Explicitly select an older release

`aw upgrade --version X.Y.Z` (or `X.Y.Z-rc.N`) requests that exact published
release. Selecting an older release deliberately permits a downgrade and prints
this warning before any replacement: `Warning: downgrading aw vCURRENT to vTARGET
because --version TARGET was explicitly requested. Older releases may contain
known vulnerabilities.` No additional confirmation or bypass flag is required.
Checksums and any present signed manifest remain required. The manifest must
match the explicitly requested version; the running-version floor is relaxed
only for that deliberate older-version request. `aw upgrade` without `--version`
never selects an older release. The shell's explicit `AW_VERSION` similarly
selects its version floor.
