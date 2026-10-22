"""Live prerequisite checks for release acceptance, not the six-step scenario.

Explicit `pytest e2e` execution requires HO6 configuration and reaches real
HTTPS readiness endpoints. Unit tests under tests/ do not collect this file.
"""

from collections.abc import Mapping

import httpx
import pytest
from release_environment import ConfigurationError, load_environment


@pytest.fixture(scope="session")
def release_environment() -> Mapping[str, str]:
    try:
        return load_environment()
    except ConfigurationError as error:
        failure = str(error)
    pytest.fail(failure, pytrace=False)


@pytest.mark.parametrize("service", ["API_ORIGIN", "CONSOLE_ORIGIN", "LOGS_ORIGIN"])
def test_release_services_are_ready(release_environment: Mapping[str, str], service: str):
    name = "AWEB_SECRETS_E2E_" + service
    url = release_environment[name].rstrip("/") + "/ready"
    try:
        # Verified TLS, no redirects or inherited proxy authority. Errors name
        # only the service input/status, never response bodies or credentials.
        with httpx.Client(timeout=10, trust_env=False, follow_redirects=False) as client:
            response = client.get(url)
    except httpx.HTTPError as error:
        failure = f"{name}: readiness transport failed ({type(error).__name__})"
    else:
        if response.status_code == 200:
            return
        failure = f"{name}: readiness returned HTTP {response.status_code}"
    pytest.fail(failure, pytrace=False)
