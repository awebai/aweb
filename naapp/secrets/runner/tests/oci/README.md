# Linux OCI prerequisites

These local installed-runtime capability checks are separate from the S19
operator launcher and release journey. They grant no execution authority, open no
service credential, and do not lift the runner's OCI refusal. Test values are
synthetic public strings. Normal host tests skip these checks; the explicit
Linux proof must run before any OCI integration is called complete.

From the runner package directory:

```sh
docker build -t aweb-secrets-runner-oci-proof tests/oci
docker run --rm --init --network none --cap-drop ALL \
  --security-opt no-new-privileges --security-opt seccomp=unconfined \
  --security-opt systempaths=unconfined --user 10000:10000 \
  --tmpfs /memory:rw,exec,nosuid,nodev,mode=0700,uid=10000,gid=10000 \
  --mount "type=bind,source=$(pwd),target=/runner,readonly" \
  --env PYTHONPATH=/runner/src --env AWEB_SECRETS_OCI_PROOF=1 \
  aweb-secrets-runner-oci-proof \
  python3 -m unittest discover -s /runner/tests/oci
```

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
startup failure. They do not yet prove M7 runtime composition, pre-HPKE capability
checks, timeout/cancellation/restart cleanup, frozen parameter expansion, image
pin verification, declared mounts or the separate-user worker journey. Those
remain required integration proofs. The Dockerfile pins its Debian base digest;
tooling packages can receive distro updates, so the capability checks must be
repeated on the exact operator-pinned runtime before activation.
