"""Aweb's test-only entry mapping; resource settings remain source-owned."""

import shlex
from .admission import validate_command
from .errors import Refused
from .aweb_stages import STAGES, select


def command(*, stages=None, focused=None, intent="branch"):
    if focused is not None and stages is not None:
        raise Refused("choose stages or a focused command")
    if intent == "train":
        if focused is not None or stages not in (None, "all", " ".join(STAGES)):
            raise Refused("train candidate requires the complete five-stage gate")
        stages = " ".join(STAGES)
    if focused is not None:
        validate_command(focused)
        return focused
    if stages is None:
        return "make candidate-gate"
    try:
        names = select(stages)
    except ValueError as error:
        raise Refused(str(error)) from error
    return (
        "AWEB_CANDIDATE_STAGES=" + shlex.quote(" ".join(names)) + " make candidate-gate"
    )
