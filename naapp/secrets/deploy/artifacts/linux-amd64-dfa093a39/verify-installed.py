"""Read-only post-install operator verification; never installs, registers or runs a job.

Run as the Lab3 administrator via sudo, after a separately reviewed installation:
  sudo python3 verify-installed.py ARCHIVE MANIFEST CLOSURE_PROBE OPERATOR_USER
Only public file paths/user names are arguments. Store the receipt privately;
review the exact sudo inventory before accepting the narrow invocation policy.
"""
import grp
import hashlib
import json
import os
import platform
import pwd
import socket
import stat
import subprocess
import sys
import tarfile
from pathlib import Path

PREFIX = Path('/opt/aweb-secrets-e2e')
ARCHIVE_SHA = 'bb4d2b384d3f0096ee96daa0fa94f5c2c376bc8dea6deac4ca25a6077fc8ea0a'
MANIFEST_SHA = '2c5ef2b1dd7742bc57730b9cf94d67e3cdf6fd93e8d0d358f606378c260481b7'
PROBE_SHA = '08ba6bb5779d9e36e847d81d9f14d6a79c6af97b23cbed613b1ea4351d6f681f'
SOURCE = 'dfa093a396409e4132cf96127a3c30a48e71f7f8'
STAGE = 'arguments'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}


def require(value):
    if not value:
        raise ValueError(STAGE)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run(argv):
    return subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True, cwd='/', env=ENV, timeout=60)


def as_user(user, argv):
    return run(['/usr/bin/sudo', '-n', '-u', user, '--', *argv])


def main():
    global STAGE
    require(len(sys.argv) == 5 and os.geteuid() == 0)
    require(sys.platform == 'linux' and platform.machine() == 'x86_64')
    archive, manifest_path, probe = map(Path, sys.argv[1:4])
    operator = sys.argv[4]
    require(all(p.is_absolute() and p.is_file() for p in (archive, manifest_path, probe)))
    STAGE = 'archive-and-input-hashes'
    require(digest(archive) == ARCHIVE_SHA and digest(manifest_path) == MANIFEST_SHA)
    require(digest(probe) == PROBE_SHA)
    manifest = json.loads(manifest_path.read_text())
    require(manifest['source_sha'] == SOURCE and manifest['prefix'] == str(PREFIX))
    with tarfile.open(archive) as tar:
        require(all((m.uid, m.gid, m.uname, m.gname) == (0, 0, 'root', 'root')
                    and not m.mode & 0o022 and not (m.issym() or m.islnk())
                    for m in tar.getmembers()))
    STAGE = 'code-ownership-and-payload'
    for path in [Path('/'), Path('/opt'), PREFIX]:
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022)
    expected = set()
    for item in manifest['files']:
        relative = Path(item['path'])
        require(not relative.is_absolute() and '..' not in relative.parts)
        expected.add(relative.as_posix())
        path = PREFIX / relative
        info = path.lstat()
        require(info.st_uid == 0 and not stat.S_ISLNK(info.st_mode))
        require(stat.S_IMODE(info.st_mode) == int(item['mode'], 8) and not info.st_mode & 0o022)
        if 'sha256' in item:
            require(stat.S_ISREG(info.st_mode) and digest(path) == item['sha256'])
        else:
            require(stat.S_ISDIR(info.st_mode))
    extras = set()
    for current, directories, files in os.walk(PREFIX, followlinks=False):
        relative = Path(current).relative_to(PREFIX)
        if relative == Path('.'):
            directories[:] = [d for d in directories if d != 'runner-state']
        for name in directories + files:
            rel = (relative / name).as_posix()
            if rel == 'runner-config.json':
                continue
            if rel not in expected:
                extras.add(rel)
    require(extras <= {'supervisor-config.json', 'service-ca.pem'})
    require('supervisor-config.json' in extras)
    public_configs = {}
    for relative in sorted(extras):
        path = PREFIX / relative
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022)
        public_configs[relative] = digest(path)
    STAGE = 'observed-identities-and-private-paths'
    actors = {name: pwd.getpwnam(name) for name in ('oatsagent', 'aweb-runner', operator)}
    agent, runner = actors['oatsagent'], actors['aweb-runner']
    require(agent.pw_uid not in (0, 10001) and runner.pw_uid not in (0, 10001, agent.pw_uid))
    require(actors[operator].pw_uid != agent.pw_uid)
    actor_metadata = {}
    for name, actor in actors.items():
        groups = sorted(os.getgrouplist(name, actor.pw_gid))
        actor_metadata[name] = {'uid': actor.pw_uid, 'gid': actor.pw_gid, 'groups': groups}
    docker_group = grp.getgrnam('docker')
    require(docker_group.gr_gid not in actor_metadata['oatsagent']['groups'])
    config, state = PREFIX / 'runner-config.json', PREFIX / 'runner-state'
    for path, mode, directory in [(config, 0o600, False), (state, 0o700, True)]:
        info = path.lstat()
        require(info.st_uid == runner.pw_uid and stat.S_IMODE(info.st_mode) == mode)
        require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
    denied = []
    for path in [config, state, Path('/etc/aweb-lab3/secrets.env'), Path('/etc/aweb-lab3/logs.env')]:
        require(path.exists())  # Positive control in the operator context, no value read.
        require(as_user('oatsagent', ['/usr/bin/test', '-r', str(path)]).returncode == 1)
        denied.append(str(path))
    for path in [Path('/etc/aweb-lab3/secrets-keys'), Path('/etc/aweb-lab3/logs-keys')]:
        require(path.is_dir())
        require(as_user('oatsagent', ['/usr/bin/test', '-x', str(path)]).returncode == 1)
        denied.append(str(path))
    identity = state / 'identity.json'
    identity_read = 'pending: no identity file yet'
    if identity.exists():
        require(as_user('oatsagent', ['/usr/bin/test', '-r', str(identity)]).returncode == 1)
        identity_read = 'denied; operator confirmed file exists, no value read'
    STAGE = 'sudo-and-socket-denials'
    require(as_user('oatsagent', ['/usr/bin/sudo', '-n', '-u', 'root', '--', '/usr/bin/id', '-u']).returncode != 0)
    socket_path = '/run/docker.sock'
    require(stat.S_ISSOCK(os.stat(socket_path).st_mode))
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(2)
        connection.connect(socket_path)  # Operator positive control; send no Docker request.
    socket_check = "import socket,sys\ns=socket.socket(socket.AF_UNIX);s.settimeout(2)\ntry:s.connect('/run/docker.sock')\nexcept PermissionError:sys.exit(1)\nexcept OSError:sys.exit(2)\nelse:sys.exit(0)"
    require(as_user('oatsagent', ['/usr/bin/python3', '-I', '-B', '-c', socket_check]).returncode == 1)
    require(run(['/usr/sbin/visudo', '-c']).returncode == 0)
    inventories = {}
    for name in actors:
        result = run(['/usr/bin/sudo', '-n', '-l', '-U', name])
        require(result.returncode in (0, 1))
        inventories[name] = {'exit': result.returncode, 'policy': result.stdout, 'diagnostic': result.stderr}
    STAGE = 'native-policy-imports-and-help'
    python = str(PREFIX / 'runtime/bin/python3.13')
    policy_check = "import importlib.machinery,importlib.util,sys,json,pathlib\np=pathlib.Path('/opt/aweb-secrets-e2e')\nl=importlib.machinery.SourceFileLoader('checked_supervisor',str(p/'bin/aweb-secrets-supervisor'))\ns=importlib.util.spec_from_loader(l.name,l);m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;l.exec_module(m);m.Policy.deployed().check()\nfrom aweb_secrets_runner.jobs import RunnerConfig\nRunnerConfig.load(p/'runner-config.json')\nc=json.loads((p/'runner-config.json').read_text());assert int(sys.argv[1]) in c['agent_uids']\nprint('installed Policy and runner config PASS')"
    require(as_user('aweb-runner', [python, '-I', '-B', '-c', policy_check, str(agent.pw_uid)]).returncode == 0)
    closure = as_user('aweb-runner', [python, '-I', '-B', str(probe)])
    require(closure.returncode == 0)
    closure_metadata = json.loads(closure.stdout)
    help_result = as_user('aweb-runner', [python, '-I', '-B', '-m', 'aweb_secrets_runner', '--help'])
    require(help_result.returncode == 0)
    print(json.dumps({'status': 'readonly installed-code/UID/denial checks PASS',
                      'source_sha': SOURCE, 'manifest_sha256': MANIFEST_SHA,
                      'archive_sha256': ARCHIVE_SHA, 'platform': platform.platform(),
                      'node': platform.node(), 'actors': actor_metadata,
                      'public_config_hashes': public_configs, 'agent_reads_denied': denied,
                      'identity_read_control': identity_read, 'sudo_inventory': inventories,
                      'closure': closure_metadata,
                      'limits': 'Operator must check the exact narrow sudo policy. No registration, worker, job, signal/grace or journal-recovery acceptance ran.'}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('STOP: verification failed at ' + STAGE, file=sys.stderr)
        raise SystemExit(1)
