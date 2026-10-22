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

## Credential-bearing execution library

`execute_oci` composes preparation with the existing whole-mapping HPKE/value
opening and bounded capture/redaction implementation. It rechecks the current
local pin with the frozen original parameters after unpacking, and checks expiry
both before opening and immediately before launching the runtime. Only the
0600 transient config receives the declared credential environment; the runc
command line and its environment contain no credential. The process has
`noNewPrivileges=true` and empty capability sets.

The qualified runtime's launch PID file distinguishes initial launch failures
from a normal job exit (including exit code 1). See the pinned runc
[launch handshake](https://github.com/opencontainers/runc/blob/v1.1.15/utils_linux.go#L268-L302).
The library uses the existing combined stream bound, strict UTF-8 checks,
known-value redaction and six-field report. Runtime logging is sent to /dev/null.
A runtime-start failure returns a fixed refusal, without a fabricated job exit.

On cancellation or timeout it joins the CLI child watcher, then explicitly kills
all container processes and force-deletes runtime state before private bundle
cleanup. Linux tests observe the actual init/child PIDs and prove they disappear,
and inspect the private config plus the CLI's argv/environment. The cleanup
commands use the same pinned engine. Failure to clear runtime state retains the
private tree with `oci_cleanup_required` for reconciliation.

This library is not yet called by the production worker. Operator runtime
configuration, stale restart cleanup and the dedicated-user S19 acceptance must
be integrated and reviewed before lifting that guard.

## Restart recovery

`recover(runtime)` takes an exclusive nonblocking lock on the checked tmpfs
workspace directory inode. Preparation holds that same lock through the whole
run and cleanup, so another worker or recovery attempt refuses with
`runner_busy`. The descriptor is close-on-exec and releases on worker death.
No lock file or release authority is added.

Each exclusive job directory has a 0600 atomic `run.json` cleanup marker. It
contains only a format version, the originally checked engine path/hash, a
completed-preparation flag, and the random local container name. It contains no
credential, job/parameter body, assignment or dispatch state. The container name
is bound before opening credentials or starting a runtime. Recovery checks that
marker against the original pinned engine, stops the container namespace,
deletes runtime state, then removes the private tree. It never opens another
value, runs a job again, fabricates a report or changes the identity/journal.
The real SIGKILL tests retain an accepted SQLite dispatch and prove it still
refuses replay after recovery.

Unknown entries, nonempty unmarked directories, symbolic links, changed engine
bindings and incomplete preparation return `oci_recovery_required` and retain
state. An empty directory from the initial mkdir can be removed safely. A
SIGKILL during unpacking may leave a public-data tool alive; without proof that
preparation completed, recovery does not guess a PID or delete under it. The
operator must stop/reconcile that tool before removing its quarantined private
workspace. Never delete journal state as a recovery step.

This recovery library is not yet wired into startup. Operator configuration,
worker composition, independent deadline enforcement after a worker hard crash,
and dedicated-user S19 acceptance remain activation requirements.
