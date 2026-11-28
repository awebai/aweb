"""Check that the released-writer lane exercised every required reader."""

import sys
from pathlib import Path

PARENT = "TestRegistryUpgradeFrom13658/implicit_local_init"
READERS = ("later_command", "wake_identity", "wake_after_team_state_rewrite")


def require_upgrade_results(output: str) -> None:
    if "released aw wrote the home" not in output:
        raise ValueError("Released writer did not write the home")

    passed = set()
    for line in output.splitlines():
        case, separator, _ = line.lstrip().partition(" (")
        if separator and case.startswith("--- PASS: "):
            passed.add(case.removeprefix("--- PASS: "))

    if PARENT not in passed:
        raise ValueError(f"Released-home test did not pass: {PARENT}")
    for reader in READERS:
        if f"{PARENT}/{reader}" not in passed:
            raise ValueError(f"Released-home reader did not pass: {reader}")


if __name__ == "__main__":
    try:
        require_upgrade_results(Path(sys.argv[1]).read_text(encoding="utf-8"))
    except ValueError as error:
        sys.exit(str(error))
