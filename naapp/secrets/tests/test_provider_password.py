"""Provider-generated passwords stay behind the existing output boundary."""

import json
import secrets

import pytest

from tests.test_responses import _handle


@pytest.mark.parametrize("projection", [None, ["/root_password"]])
def test_provider_password_is_withheld_even_when_explicitly_projected(projection) -> None:
    password = secrets.token_urlsafe(24)
    document = {"server": {"id": 7}, "root_password": password}
    result = _handle(json.dumps(document).encode(), projection=projection)
    assert result.disposition == "withheld"
    assert result.body is None
    assert result.withheld_reason == "credential_shaped"
    assert result.undeclared_credential is True


def test_a_safe_projection_can_drop_the_provider_password() -> None:
    password = secrets.token_urlsafe(24)
    document = {"server": {"id": 7}, "root_password": password}
    result = _handle(json.dumps(document).encode(), projection=["/server/id"])
    assert result.disposition == "returned"
    assert json.loads(result.body) == {"/server/id": 7}

