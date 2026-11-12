"""Operator data is external; subprocess environments are explicitly constructed."""
import json
import os
from pathlib import Path
import re
from .errors import Refused
from .state import money


def child_environment():
    return {'PATH':os.defpath,'LANG':'C.UTF-8','LC_ALL':'C.UTF-8'}


def load(path,repo):
    path=Path(path).expanduser().resolve();repo=Path(repo).resolve()
    if path.is_relative_to(repo):raise Refused('config must be outside the repository')
    try:config=json.loads(path.read_text())
    except (OSError,ValueError):raise Refused('external config is unreadable or invalid JSON') from None
    for name in ['state_root','ledger','snapshot_manifest','token_file']:
        value=config.get(name)
        if not isinstance(value,str) or not Path(value).is_absolute():
            raise Refused(f'external config requires absolute {name}')
        if Path(value).resolve().is_relative_to(repo):
            raise Refused(f'{name} must remain outside the repository')
    for name in ['owner','location','datacenter']:
        if not isinstance(config.get(name),str) or not re.fullmatch('[a-zA-Z0-9_.-]{1,63}',config[name]):
            raise Refused(f'external config has invalid {name}')
    if type(config.get('snapshot_id')) is not int or config['snapshot_id']<=0:
        raise Refused('external config requires a snapshot ID')
    money(config.get('cap_eur','150'));money(config.get('seed_eur','0'))
    try:manifest=json.loads(Path(config['snapshot_manifest']).read_text())
    except (OSError,ValueError):raise Refused('snapshot manifest is unavailable') from None
    if not isinstance(manifest.get('observed'),dict) or not isinstance(manifest.get('commands'),dict) or not isinstance(manifest.get('dpkg'),str):
        raise Refused('snapshot manifest lacks versions, binary hashes or package manifest')
    config['manifest']=manifest;config['config_path']=str(path)
    return config
