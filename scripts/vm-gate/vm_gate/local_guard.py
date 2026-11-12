"""Run source-declared lint/format guards on an exact temporary checkout."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time

from .config import child_environment
from .errors import Refused
from .source import git


def targets(source):
    section=re.search(r'^checks\(\)\s*\{\s*\n(.*?)^\}',source,re.M|re.S)
    if not section:raise Refused('selected SHA has no checks target list')
    names=re.findall(r'^\s*run\s+([A-Za-z0-9_-]+)\s*$',section[1],re.M)
    selected=[n for n in names if re.search(r'(^|[-_])(lint|format|fmt|gofmt|prettier|eslint|ruff|black|isort)([-_]|$)',n)]
    if not selected:raise Refused('selected checks list has no lint/format targets')
    return list(dict.fromkeys(selected))


def run_guard(source,directory,timeout=600):
    directory=Path(directory);receipt={'sha':source['sha'],'targets':[],'results':[],'pass_lines':[]}
    started=time.monotonic()
    with tempfile.TemporaryDirectory(prefix='local-lint-',dir=directory) as tmp:
        root=Path(tmp);checkout=root/'checkout';checkout.mkdir();shim=root/'bin';shim.mkdir()
        docker=shim/'docker';docker.write_text('#!/bin/sh\nprintf "%s\\n" "local guard: containers are forbidden" >&2\nexit 78\n');docker.chmod(0o700)
        git(checkout,'init','-q')
        git(checkout,'fetch','--quiet',source['bundle'],'+refs/*:refs/*')
        git(checkout,'checkout','--quiet','--detach',source['sha'])
        suite=(checkout/'scripts/candidate-suite.sh').read_text()
        selected=targets(suite);receipt['targets']=selected
        env={**child_environment(),'PATH':str(shim)+os.pathsep+os.environ.get('PATH',os.defpath),
             'HOME':str(Path.home()),'GOTOOLCHAIN':'local','UV_FROZEN':'1',
             'UV_PYTHON':source['requirements']['python'],'NO_COLOR':'1',
             'DOCKER_HOST':'unix://'+str(root/'no-docker.sock')}
        for target in selected:
            log=directory/('local-'+target+'.log');step=time.monotonic()
            try:
                result=subprocess.run([shutil.which('make') or 'make','--no-print-directory',target],cwd=checkout,
                    env=env,text=True,capture_output=True,timeout=max(.01,timeout-(step-started)))
                output=result.stdout+result.stderr;status=result.returncode
            except subprocess.TimeoutExpired as exc:
                def decoded(value):
                    return value.decode(errors='replace') if isinstance(value,bytes) else (value or '')
                output=decoded(exc.stdout)+decoded(exc.stderr)
                output+='\nlocal lint/format timeout\n';status=124
            log.write_text(output)
            receipt['results'].append({'target':target,'exit':status,'seconds':time.monotonic()-step,'log':str(log)})
            if status:
                error=Refused(f'local guard {target} failed before provider access; output {log}:\n'+output[-16384:])
                error.local_checks=receipt;raise error
            receipt['pass_lines'].extend(line for line in output.splitlines() if re.search(r'All checks passed|Success: no issues found|already formatted|left unchanged',line))
            receipt['pass_lines'].append(f'local guard PASS: {target} at {source["sha"]}')
        if git(checkout,'status','--porcelain','--untracked-files=all').stdout:
            error=Refused('local lint/format target changed the checkout; selected SHA was not dispatched')
            error.local_checks=receipt;raise error
    receipt['seconds']=time.monotonic()-started
    (directory/'local-checks.json').write_text(json.dumps(receipt,indent=2)+'\n')
    return receipt
