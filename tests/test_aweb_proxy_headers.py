import uuid
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

from aweb.auth import (
    INTERNAL_BEADHUB_AUTH_HEADER,
    INTERNAL_ACTOR_ID_HEADER,
    INTERNAL_PROJECT_HEADER,
    INTERNAL_USER_HEADER,
    _internal_auth_header_value,
    get_project_from_auth,
)


class TestAwebProxyHeaders:
    @pytest.mark.asyncio
    async def test_internal_auth_used_when_trust_flag_enabled(self, monkeypatch):
        monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "1")
        monkeypatch.setenv("AWEB_INTERNAL_AUTH_SECRET", "test-secret")

        project_id = str(uuid.uuid4())
        principal_id = str(uuid.uuid4())
        actor_id = str(uuid.uuid4())
        internal_auth = _internal_auth_header_value(
            secret="test-secret",
            project_id=str(uuid.UUID(project_id)),
            principal_type="u",
            principal_id=principal_id,
            actor_id=actor_id,
        )

        request = MagicMock()
        request.headers = {
            INTERNAL_BEADHUB_AUTH_HEADER: internal_auth,
            INTERNAL_PROJECT_HEADER: project_id,
            INTERNAL_USER_HEADER: principal_id,
            INTERNAL_ACTOR_ID_HEADER: actor_id,
            "Authorization": "Bearer bh_sk_should_be_ignored",
        }

        db = MagicMock()
        got = await get_project_from_auth(request, db)
        assert got == str(uuid.UUID(project_id))

    @pytest.mark.asyncio
    async def test_internal_auth_ignored_when_trust_flag_disabled(self, monkeypatch):
        monkeypatch.delenv("AWEB_TRUST_PROXY_HEADERS", raising=False)
        monkeypatch.setenv("AWEB_INTERNAL_AUTH_SECRET", "test-secret")

        project_id = str(uuid.uuid4())
        principal_id = str(uuid.uuid4())
        actor_id = str(uuid.uuid4())
        internal_auth = _internal_auth_header_value(
            secret="test-secret",
            project_id=str(uuid.UUID(project_id)),
            principal_type="u",
            principal_id=principal_id,
            actor_id=actor_id,
        )

        request = MagicMock()
        request.headers = {
            INTERNAL_BEADHUB_AUTH_HEADER: internal_auth,
            INTERNAL_PROJECT_HEADER: project_id,
            INTERNAL_USER_HEADER: principal_id,
            INTERNAL_ACTOR_ID_HEADER: actor_id,
        }

        db = MagicMock()
        with pytest.raises(HTTPException) as exc_info:
            await get_project_from_auth(request, db)
        assert exc_info.value.status_code == 401
