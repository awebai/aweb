# HO6 supervised runner contract

Source: `runner_supervisor.py` (standalone standard library program) and
`supervised_launcher.py` (the existing RunnerLauncher adapter). Installation
and the real sudo/PTY/separate-UID acceptance happen after exact-source review
and the staged artifact handoff; local process tests do not establish those.

The operator installs the entire noneditable Python distribution below
`/opt/aweb-secrets-e2e`. These fixed paths are the only launch targets:

| Path under that prefix | Ownership and mode |
| --- | --- |
| `bin/aweb-secrets-supervisor` | root, 0755; no arguments |
| `bin/aweb-secrets-runner` | root, 0755 |
| `runtime/` and all code/import/native dependencies | root, no group/other write |
| `supervisor-config.json` | root, no group/other write; only `origin`, an HTTPS service origin |
| `runner-config.json` | aweb-runner, exactly 0600; gid is immaterial |
| `service-ca.pem` (optional) | root, no group/other write |
| `runner-state/` | aweb-runner, exactly 0700; unchanged across restart |

Every ancestor directory is root-owned with no group/other write. The
supervisor lstat-checks these and the whole runtime tree before forking;
symlinks are refused. State contents and the one explicitly runner-owned config
are excluded from root ownership checks. M7 still checks its actual config,
job pins and identity/journal files. Its `agent_uids` must be the real agent
UIDs, excluding root and the runner UID. Config format is unchanged; the public
service origin lives in the separate root-owned supervisor config.

The two executable scripts must name the protected interpreter with `-I` in
their shebangs. Flatten the standalone distribution's symlinks into copies;
do not create a venv. The supervisor refuses `pyvenv.cfg` and requires its actual
`sys.prefix`, `sys.base_prefix`, `sys.base_exec_prefix` and every resolved
`sys.path` entry to remain under the prefix. The installed-file manifest covers the interpreter, site-packages,
any `.pth` files, native libraries and every installed file. A checkout-created
venv or an editable installation is unsuitable.

The proposed sudoers command is (replace `<agent>` with the actual driver user):

```text
<agent> ALL=(aweb-runner) NOPASSWD: NOSETENV: NOLOG_INPUT: NOLOG_OUTPUT: /opt/aweb-secrets-e2e/bin/aweb-secrets-supervisor ""
Defaults!/opt/aweb-secrets-e2e/bin/aweb-secrets-supervisor env_reset, !log_input, !log_output
```

The operator validates the exact syntax/policy, installs it only after the
reviewed artifact/config, and retains `sudo -l` output as evidence. Agents do
not install or enable the rule. Driver argv is exactly:

```text
/usr/bin/sudo -n -u aweb-runner -- /opt/aweb-secrets-e2e/bin/aweb-secrets-supervisor
```

Only stdin/stdout cross sudo; `closefrom 3` is compatible. The supervisor
refuses any argv. Initial stdin is one UTF-8 JSON line, at most 4096 bytes
excluding LF, with duplicate/unknown keys refused. The allowed objects are:

- `{"command":"register","code":"<transient owner-issued code>","ca":false}`
- `{"command":"doctor"}`
- `{"command":"run","ca":false}`

`ca` is optional and boolean, forbidden when true for doctor. True selects
only the fixed `service-ca.pem`; no input contains a path or origin. The
registration code is at most 254 UTF-8 bytes with no NUL/CR/LF. Only its one
line is written to a **separate** child stdin pipe, then that pipe closes.
The run/doctor child stdin is empty. Code never enters argv, environment,
stdout/stderr or evidence. Disable sudo input logging for this command;
supervisor suppression cannot prevent sudo from recording its own input or
PTY-echoed output.

The guardian reports `{"pid":<worker PID>,"uid":<kernel effective UID>}` on
stdout from the child's pre-exec kernel observation. A following
`{"exec":true}` means exec succeeded; false is a failed launch, never readiness.
Worker stdout/stderr go to `/dev/null`. Final `{"exit":<worker returncode>}`
is emitted only after the guardian reaps it. Nonzero status, including signal
statuses, remains nonzero. Register/run use the fixed state and optional CA;
doctor/run use the fixed runner config. The worker has an empty inherited
environment except PATH/LANG, cwd `/`, core dumps disabled, and no control or
readiness descriptors after exec.

Subsequent stdin lines are only `{"signal":15}` or `{"signal":2}`. They
address that owned child, never a supplied PID. TERM/INT to the sudo process
must relay through the supervisor to the child; other relayed HUP/USR1/USR2/
QUIT/TSTP/CONT signals are ignored by the supervisor, then reset to default in
the worker before exec so job signal behavior is preserved. EOF stops and reaps the child. After a
three-second grace period, the guardian sends SIGKILL to its unreaped child.

macOS has no PR_SET_PDEATHSIG. A separate guardian owns the worker and monitors
a private pipe whose sole writer is the supervisor. Supervisor death closes
that pipe, triggering the same stop/reap path. The supervisor also observes
its kernel parent changing, covering sudo death. No private descriptor is
inherited by the exec'd worker, and no PID can be reused while that worker
remains an unreaped child.

Separate-UID acceptance must run the **real sudo line**, including actual
`use_pty` defaults. It must prove the private JSON round trip, actual worker
PID/UID, suppressed command streams, EOF reaping, TERM/INT relayed from the
driver's sudo PID, forced cleanup after the grace period, same journal on
restart, and M7 doctor/job success. The staged and installed manifests plus
whole-exec-chain ownership and `sudo -l` output are retained public evidence;
registration codes, state files, credentials and I/O bodies are not evidence.
