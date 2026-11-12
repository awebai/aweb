"""Aweb's test-only entry mapping; resource settings remain source-owned."""
import shlex
from .admission import validate_command
from .errors import Refused

STAGES=('checks','user-paths','unit','artifacts','integration')


def command(*,stages=None,focused=None,intent='branch'):
    if focused is not None and stages is not None:
        raise Refused('choose stages or a focused command')
    if intent=='train':
        if focused is not None or stages not in (None,' '.join(STAGES)):
            raise Refused('train candidate requires the complete five-stage gate')
        stages=' '.join(STAGES)
    if focused is not None:
        validate_command(focused)
        return focused
    if stages is None:
        return 'make candidate-gate'
    names=stages.split()
    if not names or names != [x for x in STAGES if x in names]:
        raise Refused('unknown, duplicate or out-of-order gate stages')
    return 'AWEB_CANDIDATE_STAGES='+shlex.quote(' '.join(names))+' make candidate-gate'
