# Linux OCI prerequisites

These local installed-runtime capability checks are separate from the S19
operator launcher and release journey. They grant no execution authority, open no
service credential, and do not lift the runner's OCI refusal. Test values are
synthetic public strings. Normal host tests skip these checks; the explicit
Linux proof must run before any OCI integration is called complete.

From the runner package directory:

```sh
docker build --build-context runner=. --build-context values=../values \
  --build-context naapp=../../../naapp-lib \
  -t aweb-secrets-runner-oci-proof tests/oci
docker run --rm --init --network none --cap-drop ALL \
  --security-opt no-new-privileges --security-opt seccomp=unconfined \
  --security-opt systempaths=unconfined --user 10000:10000 \
  --tmpfs /memory:rw,exec,nosuid,nodev,mode=0700,uid=10000,gid=10000 \
  --mount "type=bind,source=$(pwd),target=/runner,readonly" \
  --env PYTHONPATH=/runner/src --env AWEB_SECRETS_OCI_PROOF=1 \
  aweb-secrets-runner-oci-proof \
  python3 -m unittest discover -s /runner/tests/oci
```

The image installs Python 3.12 and the runner’s locked dependencies from the
three explicit package contexts. Only those package sources enter the build;
instance state and repository metadata are not copied.

The disposable outer container has no capabilities or network, and the runner
source is mounted read-only. Its syscall/proc restrictions are relaxed solely to
permit nested rootless user/PID/mount namespaces. Its writable disk-backed
`/disk` directory supplies a negative storage control. No host users, release
launcher, privilege policy or deployment settings are provisioned by this test.
The explicit proof flag is a test switch, not another S19 runner input.

`require_memory_directory` checks actual Linux filesystem type through an opened
directory descriptor, in addition to runner ownership, mode 0700 and protected
ancestors. A directory's name is insufficient. Both future runtime bundle and
internal state directories must pass separately. Linux tmpfs may be swapped by
the trusted host; this adds no secure-erasure claim. Disk-backed private storage,
public directories, symbolic-link leaves and invalid paths refuse.

The real umoci/runc fixture constructs an image with conflicting command,
environment and working-directory defaults. A direct `/bin/env` avoids shell-added
variables. The installed runc preserves the complete environment when a nonempty
`HOME` is explicit; absent or empty `HOME` causes an extra `HOME=/`. Those latter
environments are unsupported on that runtime under the accepted exact-env rule.
The provider must establish capability before credential opening, including for
validated parameter-bound HOME; credential-bound HOME cannot be opened merely to
check capability. No default is injected into a job definition and no shim or
image modification replaces the pinned executable.

Tests also check explicit cwd and runtime-state cleanup after normal exit and
startup failure. The preparation tests also consume real frozen RunnerConfig parameters, qualify
HOME before any credential input exists, check runtime/unpacker hashes, remove
implicit host binds and execute declared read-only mounts. They exercise tool
cancellation and private cleanup, including mode-000 image directories and
symlinks. Worker credential injection, job timeout/cancellation/restart cleanup
and the separate-user journey remain required integration proofs. The Dockerfile pins its Debian base digest;
tooling packages can receive distro updates, so the capability checks must be
repeated on the exact operator-pinned runtime before activation.

## Pinned image staging

`ImageStore.stage(reference, workspace)` reads an operator-provisioned standard
OCI content store. It selects only the job's fixed `@sha256` digest; source tag
names and the mutable `index.json` never choose a different image. A pinned index
uses native Linux platform matching and the first matching entry in its pinned
order, including nested indexes. Baseline architecture variants are supported;
unknown required OS features/versions or unsupported variants refuse. Both the
index and the selected manifest/configuration/layers are hash-checked, and every
descriptor size is checked as an integer, excluding booleans. Metadata and index
depth/count bounds prevent unbounded parsing. There is no registry fetch or
fallback for an incomplete cache.

Before unpacking, exact verified bytes are copied into a fresh runner-private
memory-backed layout. Its local `verified` label only points to the selected
immutable manifest. Changing the original cache afterward cannot change the
snapshot. Creation uses checked directory descriptors with exclusive files;
failed staging deletes only its own newly created directory. Existing workspaces
survive a name collision. Files remain 0600 and directories 0700. The shared
`FileGuard` supplies protected-file handles rather than a second permission
policy. No archive extraction is implemented here; real umoci consumes the
standard snapshot in the proof.

This is the OCI [image layout](https://github.com/opencontainers/image-spec/blob/main/image-layout.md)
and [index ordering](https://github.com/opencontainers/image-spec/blob/main/image-index.md)
contract, with no job or wire format change. Tests cover corrupt content, invalid
sizes, wrong platforms, pinned ordering, nested indexes, mutable-tag poisoning,
cache changes after staging and agent-writeable content. Actual worker runtime
composition, runtime-binary pins, mounts, HOME capability before HPKE and lifecycle
cleanup remain separate requirements. This staging module has no production
caller yet and does not lift the OCI execution guard.

## Public bundle preparation

`RuncPreparation.prepare(JobInputs)` checks the pinned runtime and unpacker,
requires a verified private tmpfs workspace, and validates explicit host mount
sources before unpacking the verified image snapshot with umoci. It preserves
the image user only when that identity fits the rootless UID/GID mappings.
Implicit host bind mounts are removed; explicit sources must be protected by
the shared FileGuard and cannot expose the workspace or contain nested mounts.
The effective args, cwd and known environment come from the frozen job inputs;
credential-backed values remain unknown and are omitted from the public
template. Runtime/file checks are repeated after unpacking.

Both bundle and runtime-internal state live below the private memory-backed
workspace. The transient public config is 0600. Cleanup traverses only its own
FD-anchored tree, handles mode-000 directories, and never follows image symlinks.
Cancellation joins an in-progress OS spawn, kills the unpacker process group
and reaps before deletion. If internal runtime state remains, preparation
refuses cleanup and retains it for the execution owner to stop and reconcile.
The eventual execution owner must stop/reap before releasing this context.

The production worker still refuses OCI. This component does not inject a
credential, launch a job, clean stale restart state or grant execution authority.
Those lifecycle and separate-user integration checks remain required.
