"""This suite's test databases are refused when the run names no Postgres server."""

from __future__ import annotations

from pathlib import Path

import pytest
from awid_service.testing import run_without_a_named_server


def test_wants_a_database(test_db_factory) -> None:
    """Sets the factory up, which creates no database; run alone below."""


def test_an_unnamed_server_is_refused(request: pytest.FixtureRequest, tmp_path: Path) -> None:
    child = run_without_a_named_server(
        f"{__file__}::test_wants_a_database",
        cwd=request.config.invocation_params.dir,
        scratch=tmp_path,
    )
    assert child.returncode == 1, child.stdout + child.stderr
    assert "PostgresNotSelected" in child.stdout, child.stdout + child.stderr
