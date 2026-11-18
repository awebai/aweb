"""OSS gate stage selection shared by the runner, wrapper and VM adapter."""

import argparse
import sys


STAGES = ("checks", "user-paths", "unit", "artifacts", "integration")


def select(value=None):
    if value is None or value == "all":
        return STAGES
    names = tuple(value.split())
    if not names or names != tuple(name for name in STAGES if name in names):
        raise ValueError(
            "Invalid gate stages. Choose all or an ordered subset of: "
            + " ".join(STAGES)
            + "."
        )
    return names


def coverage(names):
    return "full" if tuple(names) == STAGES else "partial"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--coverage", action="store_true")
    parser.add_argument("selection", nargs="?")
    args = parser.parse_args()
    try:
        names = select(args.selection)
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 2
    print(coverage(names) if args.coverage else " ".join(names))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
