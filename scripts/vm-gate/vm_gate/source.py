"""Freeze exact local Git bytes; credentials and live remotes never go to a VM."""
from pathlib import Path
import json
import re
import subprocess
import uuid

from .admission import aweb_requirements, validate_bundle_heads, validate_snapshot
from .errors import Refused


def git(repo, *args, check=True):
    try:
        result = subprocess.run(['git','-C',str(repo),*args],text=True,
                                capture_output=True,timeout=120)
    except (OSError,subprocess.TimeoutExpired):
        raise Refused('local Git operation unavailable or timed out') from None
    if check and result.returncode:
        # Git diagnostics can contain remote credentials; do not echo them.
        raise Refused(f'local Git {args[0]} failed (exit {result.returncode})')
    return result


def verify_train_main(repo, source):
    if source['scope'] != 'train candidate':
        return
    lines = git(repo,'ls-remote','origin','refs/heads/main').stdout.splitlines()
    oid = lines[0].split()[0] if len(lines)==1 else None
    if oid != source['real_main']:
        raise Refused('stale train candidate: real origin/main moved since source admission')


def prepare(repo, sha, out, *, observed, intent='branch'):
    repo=Path(repo).resolve();out=Path(out).resolve()
    if intent not in {'train','branch'}:
        raise Refused('source intent must be train or branch')
    if not re.fullmatch('[0-9a-f]{40}',sha) or git(repo,'cat-file','-e',sha+'^{commit}',check=False).returncode:
        raise Refused(f'unknown SHA: {sha}')
    if git(repo,'status','--porcelain','--untracked-files=all').stdout:
        raise Refused('dirty checkout refused at source admission')
    required=aweb_requirements(git(repo,'show',sha+':cli/go/go.mod').stdout,
                               git(repo,'show',sha+':candidate-gate/Dockerfile').stdout,sha)
    validate_snapshot(required,observed,sha)
    git(repo,'fetch','--no-tags','origin','+refs/heads/main:refs/remotes/origin/main')
    real_main=git(repo,'rev-parse','refs/remotes/origin/main').stdout.strip()
    main_ancestor=git(repo,'merge-base','--is-ancestor',real_main,sha,check=False).returncode==0
    sha_on_main=git(repo,'merge-base','--is-ancestor',sha,real_main,check=False).returncode==0
    if intent=='train' and not main_ancestor:
        raise Refused('origin/main is not an ancestor of train SHA')
    scope='train candidate' if intent=='train' else ('main qualification' if sha_on_main else 'branch qualification')
    source_ref='refs/vm-gate/'+uuid.uuid4().hex
    bundle=out/'source.bundle'
    out.mkdir(parents=True,mode=0o700,exist_ok=True)
    git(repo,'update-ref',source_ref,sha,'0'*40)
    try:
        git(repo,'bundle','create',str(bundle),source_ref,'refs/remotes/origin/main','--tags')
        git(repo,'bundle','verify',str(bundle))
        heads=git(repo,'bundle','list-heads',str(bundle)).stdout
        validate_bundle_heads(heads,sha,source_ref)
    finally:
        git(repo,'update-ref','-d',source_ref,sha)
    result={'sha':sha,'tree':git(repo,'rev-parse',sha+'^{tree}').stdout.strip(),'real_main':real_main,'main_is_ancestor':main_ancestor,
            'sha_is_on_main':sha_on_main,'scope':scope,'source_ref':source_ref,
            'frozen_main':sha if scope=='branch qualification' else real_main,
            'bundle':str(bundle),'requirements':required}
    verify_train_main(repo,result)
    (out/'source.json').write_text(json.dumps(result,indent=2)+'\n')
    return result
