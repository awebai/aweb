#!/usr/bin/env python3
"""Give the fixture's numeric Docker user a passwd/group identity at build time."""
from pathlib import Path
import sys


def install_user(uid, gid, etc=Path('/etc')):
    if not all(value.isascii() and value.isdecimal() for value in (uid, gid)):
        raise ValueError('fixture UID and GID must be nonnegative decimal integers')
    uid, gid = str(int(uid)), str(int(gid))
    passwd = (etc / 'passwd').read_text()
    groups = (etc / 'group').read_text()
    users = [line.split(':') for line in passwd.splitlines() if line]
    group_rows = [line.split(':') for line in groups.splitlines() if line]
    existing = next((row for row in users if row[2] == uid), None)
    if existing and existing[3] != gid:
        raise ValueError('fixture UID already exists with a different primary GID')
    user_name, group_name = 'fixture-user-' + uid, 'fixture-group-' + gid
    if not existing and any(row[0] == user_name for row in users):
        raise ValueError('fixture username already exists with a different UID')
    existing_group = any(row[2] == gid for row in group_rows)
    if not existing_group and any(row[0] == group_name for row in group_rows):
        raise ValueError('fixture group name already exists with a different GID')
    if not existing_group:
        with (etc / 'group').open('a') as stream:
            stream.write(f'{group_name}:x:{gid}:\n')
    if not existing:
        with (etc / 'passwd').open('a') as stream:
            stream.write(f'{user_name}:x:{uid}:{gid}:Disposable fixture:/work/home:/sbin/nologin\n')


if __name__ == '__main__':
    install_user(*sys.argv[1:])
