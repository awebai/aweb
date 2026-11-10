# Lab3 runner: native installation and read-only verification

**Review draft. Do not execute until Secrets forwards this exact reviewed file
through aweb to Hestia.** Target: server175356165, Ubuntu 24.04, linux/amd64.
Hestia is the trusted administrator. The existing agents, registry,
coordination, Secrets and Logs containers remain unchanged. This handoff does
not establish protection from Hestia or per-agent isolation within oatsagent.

This is a separate continuation of the runner-install STOP in
[the service handoff](LAB3-HEALTH-HANDOFF.md). It installs the native code and
empty local configuration and runs the reviewed read-only verifier. It does
not install a sudo rule, register a runner, start a worker, create authority or
release the first-owner STOP. Missing prerequisites stop the sequence.

## 1. Deliver the exact inputs

Secrets/aweb arranges the existing authenticated artifact transfer to the
administrator. No new download service is needed. Root retains the archive at
`artifacts/lab3-dfa/runner-linux-amd64-dfa093a39.tar.gz`; the other three files
are in this directory at the pinned commits below. If Hestia cannot obtain
these bytes through that route, STOP and return the missing transfer to
Secrets. Do not rebuild or substitute an archive.

The administrator stages these four files under the new, root-owned,
non-writable-by-others directory `/root/lab/runner-stage/`:

| File | SHA256 |
| --- | --- |
| `runner-linux-amd64-dfa093a39.tar.gz` | `bb4d2b384d3f0096ee96daa0fa94f5c2c376bc8dea6deac4ca25a6077fc8ea0a` |
| `staged-manifest.json` | `2c5ef2b1dd7742bc57730b9cf94d67e3cdf6fd93e8d0d358f606378c260481b7` |
| `closure-probe.py` | `08ba6bb5779d9e36e847d81d9f14d6a79c6af97b23cbed613b1ea4351d6f681f` |
| `verify-installed.py` | `4f048947725d621bf2ab046651e39b86890f0222d6ef989efe56d6e06ccfc8e7` |

The archive payload source is **dfa093a396409e4132cf96127a3c30a48e71f7f8**, tree
**dafd78d3d05aeb66f21df47ed8ba35598bd5cdd5**: reviewed, ungated, unmerged at the
time of its qualification. The manifest and probe are from
**60f428ebd36ce74dd3e9acf5d73b1c8bdb60cf94**; the verifier must be the exact
**19087b978d53c5351fc752673acd2cffcb232b04** bytes above. Later train movement
does not silently replace these inputs. This is source-candidate evidence,
not a published-artifact receipt.

The archive carries CPython 3.13.15, runner 0.1.0, values 0.1.0 and
aweb-naapp 0.5.1 plus their frozen dependencies. It installs no server or AWID
registry. The running e3a1d9f76 registry/coordination cohort stays pinned.

Also prepare `supervisor-config.json` in the staging directory: exactly one
JSON member, `origin`, containing the already configured Secrets **API** HTTPS
origin. Use the actual service mapping from the completed health receipt,
not the registry or console origin. This contains public configuration only.
No token, registration code, password or identity is an input to this phase.
If a private service CA is required, STOP for its explicit reviewed mapping;
this phase assumes the already verified service certificate uses system trust.

## 2. Administrator preflight and input verification

Run the following in the administrator's root Bash shell on the named target,
without shell tracing or a terminal recording that captures private input.
Commands below contain public paths and account names only. Retain the result
privately and share only the listed receipt fields. Do not run these commands
on the development host or inside the service container.

```bash
set -euo pipefail
[ "$(id -u)" -eq 0 ]
[ "$(uname -s)" = Linux ]
[ "$(uname -m)" = x86_64 ]
grep -qx 'ID=ubuntu' /etc/os-release
grep -qx 'VERSION_ID="24.04"' /etc/os-release
for tool in python3 sudo visudo ldd sha256sum tar useradd; do
  command -v "$tool" >/dev/null
done
uname -r
getconf GNU_LIBC_VERSION
id oatsagent
visudo -c
runner_sudo_inventory=$(mktemp /root/lab/runner-sudo-oatsagent.XXXXXX)
if LC_ALL=C sudo -n -l -U oatsagent >"$runner_sudo_inventory" 2>&1; then
  runner_sudo_status=0
else
  runner_sudo_status=$?
  # Exit 1 is acceptable only for the explicit no-permissions result.
  # Extra diagnostics, including policy/PAM/authentication errors, STOP.
  if [ "$runner_sudo_status" -ne 1 ] || ! LC_ALL=C awk '
    NF { if ($0 ~ /^User oatsagent is not allowed to run sudo on .+\.$/) seen++;
         else bad=1 }
    END { exit !(seen == 1 && !bad) }
  ' "$runner_sudo_inventory"; then
    echo "STOP: sudo inventory error; inspect $runner_sudo_inventory"
    exit 1
  fi
fi
printf 'oatsagent sudo listing exit=%s; private inventory=%s\n' \
  "$runner_sudo_status" "$runner_sudo_inventory"

# Fresh installation only: never adopt or overwrite an existing account/tree.
if getent passwd aweb-runner; then echo 'STOP: existing runner account'; exit 1; fi
[ ! -e /opt/aweb-secrets-e2e ] && [ ! -L /opt/aweb-secrets-e2e ]
[ ! -e /opt/aweb-secrets-e2e-inputs ] && [ ! -L /opt/aweb-secrets-e2e-inputs ]

python3 -I - <<'PY'
import grp, hashlib, json, os, pathlib, pwd, runpy, stat, tarfile
from urllib.parse import urlsplit
stage = pathlib.Path('/root/lab/runner-stage')
pins = {
    'runner-linux-amd64-dfa093a39.tar.gz': 'bb4d2b384d3f0096ee96daa0fa94f5c2c376bc8dea6deac4ca25a6077fc8ea0a',
    'staged-manifest.json': '2c5ef2b1dd7742bc57730b9cf94d67e3cdf6fd93e8d0d358f606378c260481b7',
    'closure-probe.py': '08ba6bb5779d9e36e847d81d9f14d6a79c6af97b23cbed613b1ea4351d6f681f',
    'verify-installed.py': '4f048947725d621bf2ab046651e39b86890f0222d6ef989efe56d6e06ccfc8e7',
}
for path in [pathlib.Path('/'), pathlib.Path('/opt'), *reversed(stage.parents), stage]:
    info = path.lstat()
    assert stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022
for name in [*pins, 'supervisor-config.json']:
    path = stage / name
    info = path.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022
    if name in pins:
        with path.open('rb') as stream:
            assert hashlib.file_digest(stream, 'sha256').hexdigest() == pins[name]
agent = pwd.getpwnam('oatsagent')
privileged_groups = {0}
for name in ('docker', 'sudo', 'adm', 'lxd', 'incus'):
    try:
        privileged_groups.add(grp.getgrnam(name).gr_gid)
    except KeyError:
        pass
assert not privileged_groups.intersection(os.getgrouplist(agent.pw_name, agent.pw_gid))
# Reuse the hash-verified UID-attested wrapper; never interpret sudo's own
# failure to launch as a denial by the agent.
checked = runpy.run_path(str(stage / 'verify-installed.py'), run_name='preflight_verifier')
identity = checked['as_user']('oatsagent', ['/usr/bin/id', '-u'])
assert identity.returncode == 0 and identity.stdout.strip() == str(agent.pw_uid)
root_probe = checked['as_user']('oatsagent', ['/usr/bin/sudo', '-n', '-u', 'root', '--', '/usr/bin/true'])
assert root_probe.returncode != 0
with tarfile.open(stage / 'runner-linux-amd64-dfa093a39.tar.gz') as archive:
    for member in archive.getmembers():
        path = pathlib.PurePosixPath(member.name)
        assert not path.is_absolute() and '..' not in path.parts
        assert path.parts and path.parts[0] == 'aweb-secrets-e2e'
        assert member.isdir() or member.isfile()
config = json.loads((stage / 'supervisor-config.json').read_text())
assert set(config) == {'origin'} and isinstance(config['origin'], str)
origin = urlsplit(config['origin'])
assert origin.scheme == 'https' and origin.hostname and not origin.username and not origin.password
assert origin.path in ('', '/') and not origin.query and not origin.fragment
print('Fresh-prefix and input checks PASS')
PY
```

The administrator must confirm that the supervisor origin is the actual API
origin already exercised over verified TLS. Syntax alone is not that mapping.
Review the retained inventory before continuing, including when listing exits
0. Any listed permission requires operator review; general sudo or a
policy/authentication diagnostic is a STOP regardless of the listing status.
Exit 1 continues only for the single explicit no-permissions message accepted
above; other output needs diagnosis, not a new sudo grant. Keep the listing
status with the inventory. The groups of oatsagent
must exclude gid 0 and any docker/sudo/adm/lxd/incus groups. If either condition
fails, STOP; do not silently change the OATS account or host policy to pass.

## 3. Install the protected closure and empty local configuration

Only after section 2 passes, continue in that same root shell:

```bash
umask 022
install -d -o root -g root -m 0755 /opt/aweb-secrets-e2e-inputs
for file in runner-linux-amd64-dfa093a39.tar.gz staged-manifest.json closure-probe.py verify-installed.py; do
  install -o root -g root -m 0644 "/root/lab/runner-stage/$file" "/opt/aweb-secrets-e2e-inputs/$file"
done
tar --extract --gzip --no-same-owner --same-permissions \
  --file /opt/aweb-secrets-e2e-inputs/runner-linux-amd64-dfa093a39.tar.gz \
  --directory /opt

# Before adding the explicitly runner-owned config/state exceptions, this
# must print nothing. A nonempty result is a STOP, never a recursive repair.
find /opt/aweb-secrets-e2e \( ! -user root -o -perm /022 -o -type l \) -print
[ -z "$(find /opt/aweb-secrets-e2e \( ! -user root -o -perm /022 -o -type l \) -print -quit)" ]

useradd --system --user-group --no-create-home \
  --home-dir /nonexistent --shell /usr/sbin/nologin aweb-runner
passwd -S aweb-runner
id aweb-runner
install -o root -g root -m 0644 /root/lab/runner-stage/supervisor-config.json \
  /opt/aweb-secrets-e2e/supervisor-config.json
install -d -o aweb-runner -g aweb-runner -m 0700 /opt/aweb-secrets-e2e/runner-state
python3 -I - <<'PY'
import json, os, pathlib, pwd
agent = pwd.getpwnam('oatsagent')
runner = pwd.getpwnam('aweb-runner')
assert agent.pw_uid not in (0, 10001) and runner.pw_uid not in (0, 10001, agent.pw_uid)
path = pathlib.Path('/opt/aweb-secrets-e2e/runner-config.json')
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'w') as stream:
    json.dump({'v': 1, 'agent_uids': [agent.pw_uid], 'jobs': {}}, stream)
os.chown(path, runner.pw_uid, runner.pw_gid)
print('Empty runner configuration created; no jobs or identity')
PY
```

Require the `passwd -S` status to be `L` (locked), a non-login shell and no
privileged runner groups. Record the actual UID instead of choosing 499 or
10001. The empty `jobs` mapping is local executable configuration only; it is
not a fixture grant, approval, registration or an installation record at the
service. No credential or identity file is created.

## 4. Run the exact read-only verifier and STOP

The existing service environment/key files and Docker socket from the
completed service-install phase must still exist. The verifier tests their
inaccessibility from oatsagent using owner-side existence controls; it never
reads their values. If a prerequisite is absent, return that result rather
than creating an empty replacement on the target.

```bash
python3 -I -B /opt/aweb-secrets-e2e-inputs/verify-installed.py \
  /opt/aweb-secrets-e2e-inputs/runner-linux-amd64-dfa093a39.tar.gz \
  /opt/aweb-secrets-e2e-inputs/staged-manifest.json \
  /opt/aweb-secrets-e2e-inputs/closure-probe.py root \
  > /root/lab/runner-native-verification.json
```

Require exit 0 and outer status `readonly installed-code/UID/denial checks
PASS`. Retain the JSON privately. It checks every installed hash/mode, protected
ancestors, actual UID controls, private-path/socket/root-sudo denials, installed
Policy and RunnerConfig, native imports, ELF dependencies and help. The pinned
probe's historical internal status contains `emulated`; do not edit it or use
that string to label this native run. The outer verifier's platform/node and
the target preflight identify where this invocation actually executed.

Return source/verifier SHA, archive/manifest hashes, target OS/architecture,
glibc, actual account UID/groups and the exact sudo inventories, public
configuration hash, verifier exit/status and any failing stage through
**Hestia -> aweb -> Secrets -> root**. Never attach environment files, state,
keys or registration codes. An absent identity file is expected and is
reported as pending; it is not a demonstrated identity-file denial.

**STOP here even if verification passes.** No sudoers file is installed by
this phase, and neither the supervisor nor a worker has been launched. The
next separately reviewed handoff must cover the exact no-argument supervisor
rule from [SUPERVISOR.md](../../../e2e/SUPERVISOR.md), real owner-issued
registration through its supported private input, real use_pty defaults,
PID/UID, EOF/death, TERM/INT/grace cleanup and same-journal recovery. First-owner
bootstrap remains shared4.2 -> console4.4/app4.5 -> shared16.41 -> app16.43.
Receiver/CA/username mapping, real runner ID and job/local pins require the
runner owner's FIT before the fixed synthetic TLS workload. No Oracle or
billable-token test is included.

## 5. Footprint and stopped-install disposition

The staged payload is 214314207 bytes, plus the retained compressed archive,
small inputs/configuration and future state. No daemon, service unit, worker,
database or container is started by this phase; its memory measurements are
temporary verification-process measurements, not runner workload capacity.

If a stage fails, leave the runner stopped, retain the exact new prefix,
inputs, locked account and sanitized failure stage for root review. Do not
retry over the partially installed tree, delete state, recursively repair
ownership, alter AppArmor/groups, or change the existing service/cohort. No
new sudo rule or persistent process exists to disable. Any removal or retry
is a separate operator disposition of those exact new paths/account.
