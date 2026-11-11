"""Explicit service configuration shared by the AWID, server and naapp tests."""

from __future__ import annotations

import os

from pgdbm.testing import DatabaseTestConfig


def postgres_config() -> DatabaseTestConfig:
    """Require a named test server, including its port, before allocating a DB."""
    if (
        not os.environ.get("TEST_DB_HOST", "").strip()
        or not os.environ.get("TEST_DB_PORT", "").strip()
    ):
        raise RuntimeError(
            "Set TEST_DB_HOST and TEST_DB_PORT explicitly for the private test PostgreSQL service"
        )
    return DatabaseTestConfig(
        host=os.environ["TEST_DB_HOST"],
        port=int(os.environ["TEST_DB_PORT"]),
        user=os.environ.get("TEST_DB_USER", "postgres"),
        password=os.environ.get("TEST_DB_PASSWORD", "postgres"),
        verbose=os.environ.get("TEST_DB_VERBOSE", "").lower() in ("1", "true", "yes"),
        log_sql=os.environ.get("TEST_DB_LOG_SQL", "").lower() in ("1", "true", "yes"),
    )


def redis_url() -> str:
    """Require an explicit Redis target without disclosing it in an error."""
    value = os.environ.get("REDIS_URL", "")
    if not value.strip():
        raise RuntimeError(
            "Set REDIS_URL explicitly for the private test Redis service"
        )
    return value
