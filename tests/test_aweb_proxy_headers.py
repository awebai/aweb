import uuid
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

from aweb.auth import (
    INTERNAL_ACTOR_ID_HEADER,
    INTERNAL_BEADHUB_AUTH_HEADER,
    INTERNAL_PROJECT_HEADER,
    INTERNAL_USER_HEADER,
    AuthConfigurationError,
    _get_aweb_internal_auth_secret,
    _internal_auth_header_value,
    _parse_internal_auth_context,
    get_project_from_auth,
    validate_auth_config,
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

    def test_internal_auth_secret_does_not_fallback_to_session_secret(self, monkeypatch):
        """Verify SESSION_SECRET_KEY is NOT used as fallback for internal auth secret."""
        monkeypatch.delenv("AWEB_INTERNAL_AUTH_SECRET", raising=False)
        monkeypatch.delenv("BEADHUB_INTERNAL_AUTH_SECRET", raising=False)
        monkeypatch.setenv("SESSION_SECRET_KEY", "session-secret-should-not-be-used")

        secret = _get_aweb_internal_auth_secret()
        assert secret is None

    def test_validate_auth_config_raises_when_proxy_headers_trusted_but_no_secret(
        self, monkeypatch
    ):
        """Validate that startup check fails when proxy headers trusted but secret missing."""
        monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "1")
        monkeypatch.delenv("AWEB_INTERNAL_AUTH_SECRET", raising=False)
        monkeypatch.delenv("BEADHUB_INTERNAL_AUTH_SECRET", raising=False)
        monkeypatch.delenv("SESSION_SECRET_KEY", raising=False)

        with pytest.raises(AuthConfigurationError) as exc_info:
            validate_auth_config()
        assert "AWEB_TRUST_PROXY_HEADERS is enabled" in str(exc_info.value)

    def test_validate_auth_config_passes_when_proxy_headers_trusted_with_secret(self, monkeypatch):
        """Validate that startup check passes when proxy headers trusted with secret configured."""
        monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "1")
        monkeypatch.setenv("AWEB_INTERNAL_AUTH_SECRET", "test-secret")

        validate_auth_config()  # Should not raise

    def test_validate_auth_config_passes_when_proxy_headers_not_trusted(self, monkeypatch):
        """Validate that startup check passes when proxy headers are not trusted."""
        monkeypatch.delenv("AWEB_TRUST_PROXY_HEADERS", raising=False)
        monkeypatch.delenv("AWEB_INTERNAL_AUTH_SECRET", raising=False)
        monkeypatch.delenv("BEADHUB_INTERNAL_AUTH_SECRET", raising=False)

        validate_auth_config()  # Should not raise - proxy headers not trusted

    @pytest.mark.asyncio
    async def test_request_fails_500_when_proxy_headers_trusted_but_no_secret(self, monkeypatch):
        """Verify runtime request fails with 500 when proxy headers trusted but secret missing."""
        monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "1")
        monkeypatch.delenv("AWEB_INTERNAL_AUTH_SECRET", raising=False)
        monkeypatch.delenv("BEADHUB_INTERNAL_AUTH_SECRET", raising=False)
        monkeypatch.delenv("SESSION_SECRET_KEY", raising=False)

        project_id = str(uuid.uuid4())
        principal_id = str(uuid.uuid4())
        actor_id = str(uuid.uuid4())

        request = MagicMock()
        request.headers = {
            INTERNAL_BEADHUB_AUTH_HEADER: "some-auth-header",
            INTERNAL_PROJECT_HEADER: project_id,
            INTERNAL_USER_HEADER: principal_id,
            INTERNAL_ACTOR_ID_HEADER: actor_id,
        }

        db = MagicMock()
        with pytest.raises(HTTPException) as exc_info:
            await get_project_from_auth(request, db)
        assert exc_info.value.status_code == 500
        assert "Internal auth secret not configured" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_public_reader_principal_type_returns_project(self, monkeypatch):
        """Public reader ('p') principal type is accepted when no user/key headers present."""
        monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "1")
        monkeypatch.setenv("AWEB_INTERNAL_AUTH_SECRET", "test-secret")

        project_id = str(uuid.uuid4())
        principal_id = str(uuid.uuid4())
        actor_id = str(uuid.uuid4())
        internal_auth = _internal_auth_header_value(
            secret="test-secret",
            project_id=str(uuid.UUID(project_id)),
            principal_type="p",
            principal_id=principal_id,
            actor_id=actor_id,
        )

        request = MagicMock()
        request.headers = {
            INTERNAL_BEADHUB_AUTH_HEADER: internal_auth,
            INTERNAL_PROJECT_HEADER: project_id,
            INTERNAL_ACTOR_ID_HEADER: actor_id,
        }

        db = MagicMock()
        got = await get_project_from_auth(request, db)
        assert got == str(uuid.UUID(project_id))

    @pytest.mark.asyncio
    async def test_public_reader_returns_correct_context(self, monkeypatch):
        """Public reader ('p') returns correct principal_type and principal_id."""
        monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "1")
        monkeypatch.setenv("AWEB_INTERNAL_AUTH_SECRET", "test-secret")

        project_id = str(uuid.uuid4())
        principal_id = str(uuid.uuid4())
        actor_id = str(uuid.uuid4())
        internal_auth = _internal_auth_header_value(
            secret="test-secret",
            project_id=str(uuid.UUID(project_id)),
            principal_type="p",
            principal_id=principal_id,
            actor_id=actor_id,
        )

        request = MagicMock()
        request.headers = {
            INTERNAL_BEADHUB_AUTH_HEADER: internal_auth,
            INTERNAL_PROJECT_HEADER: project_id,
            INTERNAL_ACTOR_ID_HEADER: actor_id,
        }

        ctx = _parse_internal_auth_context(request)
        assert ctx is not None
        assert ctx["principal_type"] == "p"
        assert ctx["principal_id"] == principal_id
        assert ctx["project_id"] == str(uuid.UUID(project_id))
        assert ctx["actor_id"] == actor_id

    @pytest.mark.asyncio
    async def test_unknown_principal_type_still_rejected(self, monkeypatch):
        """Unknown principal type (not u/k/p) with no user/key headers is rejected."""
        monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "1")
        monkeypatch.setenv("AWEB_INTERNAL_AUTH_SECRET", "test-secret")

        project_id = str(uuid.uuid4())
        principal_id = str(uuid.uuid4())
        actor_id = str(uuid.uuid4())
        internal_auth = _internal_auth_header_value(
            secret="test-secret",
            project_id=str(uuid.UUID(project_id)),
            principal_type="x",
            principal_id=principal_id,
            actor_id=actor_id,
        )

        request = MagicMock()
        request.headers = {
            INTERNAL_BEADHUB_AUTH_HEADER: internal_auth,
            INTERNAL_PROJECT_HEADER: project_id,
            INTERNAL_ACTOR_ID_HEADER: actor_id,
        }

        db = MagicMock()
        with pytest.raises(HTTPException) as exc_info:
            await get_project_from_auth(request, db)
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_public_reader_tampered_principal_id_rejected(self, monkeypatch):
        """Tampered principal_id in a 'p' auth header is rejected by HMAC verification."""
        monkeypatch.setenv("AWEB_TRUST_PROXY_HEADERS", "1")
        monkeypatch.setenv("AWEB_INTERNAL_AUTH_SECRET", "test-secret")

        project_id = str(uuid.uuid4())
        real_principal_id = str(uuid.uuid4())
        fake_principal_id = str(uuid.uuid4())
        actor_id = str(uuid.uuid4())

        # Sign with the real principal_id
        internal_auth = _internal_auth_header_value(
            secret="test-secret",
            project_id=str(uuid.UUID(project_id)),
            principal_type="p",
            principal_id=real_principal_id,
            actor_id=actor_id,
        )

        # Tamper: replace real principal_id with fake one in the header
        tampered_auth = internal_auth.replace(real_principal_id, fake_principal_id)

        request = MagicMock()
        request.headers = {
            INTERNAL_BEADHUB_AUTH_HEADER: tampered_auth,
            INTERNAL_PROJECT_HEADER: project_id,
            INTERNAL_ACTOR_ID_HEADER: actor_id,
        }

        db = MagicMock()
        with pytest.raises(HTTPException) as exc_info:
            await get_project_from_auth(request, db)
        assert exc_info.value.status_code == 401
