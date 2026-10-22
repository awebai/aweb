# Release runner fixture

`runner_harness.RunnerHarness` is the single S19 runner lifecycle fixture used by
the release journey. It consumes these four explicit inputs:

- `AWEB_SECRETS_E2E_RUNNER_BINARY`
- `AWEB_SECRETS_E2E_RUNNER_CONFIG_FILE`
- `AWEB_SECRETS_E2E_RUNNER_USER`
- `AWEB_SECRETS_E2E_RUNNER_STATE_DIR`

Paths must be absolute. Missing configuration fails; it does not skip a release
journey. The default `UnavailableLauncher` refuses with
`runner_launch_unavailable` and creates no process. A privileged launcher is
not implemented here. The operator must supply its supported invocation,
ownership, worker PID/UID observation and signal contract before that adapter
can be implemented and reviewed. No sudo, root, setuid, container or user-creation
permission is inferred from an input.

The one injected `RunnerLauncher` boundary resolves the provisioned user's UID,
starts the exact invocation, and returns `ProcessControl` for the **actual
worker**, including kernel-observed identity. Identity from requested arguments
or a sudo/container monitor is insufficient. The harness compares the observed
UID with the adapter's resolved user UID and the observed PID with the process
handle. Signal and wait must address that same worker; the adapter owns cleanup
of partial launches and suppresses all command streams. Local adapter tests run
real processes under the existing test UID; they do not prove separate-user
runner execution or the operator adapter's policy.

The supported M7 commands are:

```text
register --origin <service-origin> --state-dir <absolute-state-dir>
doctor --config <absolute-config-file> --state-dir <absolute-state-dir>
run --config <absolute-config-file> --state-dir <absolute-state-dir>
```

`register(origin, code=...)` sends exactly one owner-issued code line through a
private stdin pipe. The code never enters argv, environment, repr or harness
output; the fixture suppresses even the command's public registration output.
An optional explicit `ca_file` argument applies to register/run, not doctor,
and adds no required environment input. No service credential is loaded by the
fixture. `start()` runs doctor first, then returns `RunningRunner` with `pid`,
`uid`, `returncode`, `wait()` and `stop(SIGTERM|SIGINT)`. `restart()` stops the
old process and uses the same configuration/state, without registration or
deleting, rewriting or copying its journal. There is no automatic restart.
Timeouts do not escalate to SIGKILL; a failed stop is visible to the caller.

```python
from runner_harness import RunnerHarness

fixture = RunnerHarness.from_env(launcher=operator_adapter)
# Once only, with the code obtained from the real owner-confirmation path:
await fixture.register(service_origin, code=owner_issued_code)
worker = await fixture.start()
try:
    # The real release journey uses the service, upstream, vault and logs here.
    ...
finally:
    await worker.stop()
# An explicit restart preserves pending report bytes and replay history:
worker = await fixture.restart()
await worker.stop()
```

The operator adapter and M7's doctor must enforce the actual dedicated UID,
runner-owned private state (0700/files 0600), and configuration, installation,
executable and declared-file ownership outside agent write authority. Config
`agent_uids` must be actual agent UIDs distinct from runner/root, never fabricated
test numbers. Use `--init`/tini if the worker would be container PID1. Keep the
same journal on restart; pending sanitized reports must flush before new claims.
The current runner supports fixed-selector exec; OCI remains guarded.

This boundary is prepared against reviewed worker
`f892843552522cca7417863110cc871276157127`. It imports no runner implementation
or dispatcher and grants no release authority. Actual operator launch,
separate-user execution, S13 composition, vault/upstream interactions and logs
ingest remain release acceptance requirements. M9 consumes this fixture instead
of adding another launcher or provisioning users.
