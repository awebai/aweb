"""OSS gate stage selection shared by the runner, wrapper and VM adapter."""

import argparse
from enum import Enum
import sys


class Stage(str, Enum):
    CHECKS = "checks"
    USER_PATHS = "user-paths"
    UNIT = "unit"
    ARTIFACTS = "artifacts"
    INTEGRATION = "integration"


class Coverage(str, Enum):
    FULL = "full"
    PARTIAL = "partial"


class OutputFormat(Enum):
    STAGES = "stages"
    COVERAGE = "coverage"
    BATCHES = "batches"


STAGES = tuple(Stage)


def select_stages(value: str | None = None) -> tuple[Stage, ...]:
    """docs/release.md:190–200: default to all; explicit subsets are partial."""
    if value is None or value == "all":
        return STAGES
    names = tuple(value.split())
    if not names or names != tuple(name for name in STAGES if name in names):
        raise ValueError(
            "Invalid gate stages. Choose all or an ordered subset of: "
            + " ".join(STAGES)
            + "."
        )
    return tuple(Stage(name) for name in names)


def selection_coverage(stages: tuple[Stage, ...]) -> Coverage:
    return Coverage.FULL if stages == STAGES else Coverage.PARTIAL


def execution_batches(stages: tuple[Stage, ...]) -> tuple[tuple[Stage, ...], ...]:
    """docs/release.md: finish shared preparation before the isolated long lanes."""
    if Stage.UNIT in stages and Stage.INTEGRATION in stages:
        preceding = tuple(
            (stage,) for stage in stages if stage not in (Stage.UNIT, Stage.INTEGRATION)
        )
        return (*preceding, (Stage.UNIT, Stage.INTEGRATION))
    return tuple((stage,) for stage in stages)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--coverage",
        dest="output_format",
        action="store_const",
        const=OutputFormat.COVERAGE,
        default=OutputFormat.STAGES,
    )
    parser.add_argument(
        "--batches",
        dest="output_format",
        action="store_const",
        const=OutputFormat.BATCHES,
    )
    parser.add_argument("selection", nargs="?")
    args = parser.parse_args()
    try:
        names = select_stages(args.selection)
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 2
    if args.output_format is OutputFormat.COVERAGE:
        print(selection_coverage(names).value)
    elif args.output_format is OutputFormat.BATCHES:
        print("\n".join(" ".join(batch) for batch in execution_batches(names)))
    else:
        print(" ".join(names))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
