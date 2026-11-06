"""Real PostgreSQL databases for Folio's tests (pgdbm's test_db_factory)."""

import json
import tempfile
from pathlib import Path
from typing import Any

import pytest
from aweb_naapp_testing.databases import SchemaDatabases
from manifest_config import TEST_EMIT_SEED_HEX

pytest_plugins = ["pgdbm.fixtures.conftest"]


@pytest.fixture
async def test_db_factory(test_db_factory: Any) -> SchemaDatabases:
    return SchemaDatabases(test_db_factory)


def pytest_configure(config: pytest.Config) -> None:
    # folio.api constructs its real runtime during collection. Give every test
    # process an actual disposable signing-key file before importing that module.
    directory = tempfile.TemporaryDirectory(prefix="folio-test-key-")
    path = Path(directory.name) / "emit.hex"
    path.write_text(TEST_EMIT_SEED_HEX)
    path.chmod(0o600)
    grant = Path(directory.name) / "grant.hex"
    grant.write_text("02" * 32)
    grant.chmod(0o600)
    env = pytest.MonkeyPatch()
    env.setenv("FOLIO_APP_KEY_FILES", json.dumps({"folio:emit-1": str(path), "folio:grant-read-1": str(grant)}))
    for name in ("FOLIO_APP_EMIT_KID", "FOLIO_APP_EMIT_KEY_SEED_HEX", "FOLIO_APP_EVENTS_ORIGIN"):
        env.delenv(name, raising=False)
    config.add_cleanup(directory.cleanup)
    config.add_cleanup(env.undo)
