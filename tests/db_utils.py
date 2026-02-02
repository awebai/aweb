"""Shared database utilities for tests."""

from pgdbm.testing import DatabaseTestConfig


def build_database_url(config: DatabaseTestConfig, db_name: str) -> str:
    """Build a PostgreSQL connection URL from test config and database name."""
    return f"postgresql://{config.user}:{config.password}@" f"{config.host}:{config.port}/{db_name}"
