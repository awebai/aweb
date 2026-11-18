"""Aweb's test-only entry mapping; resource settings remain source-owned."""

import shlex
from enum import Enum
from .admission import validate_command
from .errors import Refused
from .aweb_stages import STAGES, select_stages


class GateIntent(str, Enum):
    BRANCH = "branch"
    TRAIN = "train"


def command(
    *,
    stages: str | None = None,
    focused: str | None = None,
    intent: GateIntent | str = GateIntent.BRANCH,
) -> str:
    # The CLI supplies a validated string; retain that public adapter boundary.
    try:
        gate_intent = GateIntent(intent)
    except ValueError as error:
        raise Refused("Invalid gate intent. Choose branch or train.") from error
    if focused is not None and stages is not None:
        raise Refused("choose stages or a focused command")
    if gate_intent is GateIntent.TRAIN:
        if focused is not None or stages not in (None, "all", " ".join(STAGES)):
            raise Refused("train candidate requires the complete five-stage gate")
        stages = " ".join(STAGES)
    if focused is not None:
        validate_command(focused)
        return focused
    if stages is None:
        return "make candidate-gate"
    try:
        names = select_stages(stages)
    except ValueError as error:
        raise Refused(str(error)) from error
    return (
        "AWEB_CANDIDATE_STAGES=" + shlex.quote(" ".join(names)) + " make candidate-gate"
    )
