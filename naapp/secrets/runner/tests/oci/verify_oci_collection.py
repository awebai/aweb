"""Enforce the expected collection for the documented OCI proof command."""

from pathlib import Path

import pytest


def pytest_collection_finish(session: pytest.Session) -> None:
    if session.testsfailed:
        # Preserve pytest's original collection traceback.
        return

    expected_path = Path(__file__).with_name("expected-cases.txt")
    expected = set(expected_path.read_text(encoding="utf-8").splitlines())
    collected = {item.nodeid for item in session.items}
    missing = sorted(expected - collected)
    unexpected = sorted(collected - expected)
    if not missing and not unexpected:
        return

    details = [f"Missing: {case}" for case in missing]
    details.extend(f"Unexpected: {case}" for case in unexpected)
    pytest.exit(
        "OCI proof collection does not match expected-cases.txt\n" + "\n".join(details),
        returncode=pytest.ExitCode.TESTS_FAILED,
    )
