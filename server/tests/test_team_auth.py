"""Tests for team certificate auth and dashboard JWT auth."""

from __future__ import annotations

import base64
import json
import time
from datetime import datetime, timezone

import jwt
import pytest

from nacl.signing import SigningKey

from awid.did import did_from_public_key
from awid.signing import canonical_json_bytes, sign_message


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_keypair():
    sk = SigningKey.generate()
    pk = bytes(sk.verify_key)
    did_key = did_from_public_key(pk)
    return bytes(sk), pk, did_key


def _make_certificate(
    team_sk: bytes,
    team_did_key: str,
    member_did_key: str,
    *,
    team_address: str = "acme.com/backend",
    alias: str = "alice",
    lifetime: str = "permanent",
    certificate_id: str = "cert-001",
    member_did_aw: str = "",
    member_address: str = "",
):
    cert = {
        "version": 1,
        "certificate_id": certificate_id,
        "team": team_address,
        "team_did_key": team_did_key,
        "member_did_key": member_did_key,
        "member_did_aw": member_did_aw,
        "member_address": member_address,
        "alias": alias,
        "lifetime": lifetime,
        "issued_at": datetime.now(timezone.utc).isoformat(),
    }
    # Sign the cert without the signature field (canonical JSON, sorted keys)
    payload = canonical_json_bytes(cert)
    sig = sign_message(team_sk, payload)
    cert["signature"] = sig
    return cert


def _encode_certificate(cert: dict) -> str:
    return base64.b64encode(json.dumps(cert).encode()).decode()


# ---------------------------------------------------------------------------
# Certificate verification
# ---------------------------------------------------------------------------


class TestCertificateSignature:
    def test_valid_certificate(self):
        from aweb.team_auth import _verify_certificate_signature

        team_sk, _, team_did_key = _make_keypair()
        _, _, agent_did_key = _make_keypair()

        cert = _make_certificate(
            team_sk, team_did_key, agent_did_key,
            team_address="acme.com/backend",
            alias="alice",
        )

        assert _verify_certificate_signature(cert, team_did_key) is True

    def test_invalid_signature_rejected(self):
        from aweb.team_auth import _verify_certificate_signature

        _, _, team_did_key = _make_keypair()
        _, _, agent_did_key = _make_keypair()
        other_sk, _, _ = _make_keypair()

        cert = _make_certificate(other_sk, team_did_key, agent_did_key)

        assert _verify_certificate_signature(cert, team_did_key) is False

    def test_tampered_certificate_rejected(self):
        from aweb.team_auth import _verify_certificate_signature

        team_sk, _, team_did_key = _make_keypair()
        _, _, agent_did_key = _make_keypair()

        cert = _make_certificate(team_sk, team_did_key, agent_did_key)
        cert["alias"] = "mallory"

        assert _verify_certificate_signature(cert, team_did_key) is False


class TestParseAndVerifyCertificate:
    def test_member_did_key_mismatch_rejected(self):
        from aweb.team_auth import parse_and_verify_certificate

        team_sk, _, team_did_key = _make_keypair()
        _, _, agent_did_key = _make_keypair()
        _, _, other_did_key = _make_keypair()

        cert = _make_certificate(team_sk, team_did_key, agent_did_key)
        encoded = _encode_certificate(cert)

        with pytest.raises(ValueError, match="did_key mismatch"):
            parse_and_verify_certificate(
                encoded,
                request_did_key=other_did_key,
                team_public_key_resolver=lambda _ta: team_did_key,
                revocation_checker=lambda _ta, _cid: False,
            )

    def test_revoked_certificate_rejected(self):
        from aweb.team_auth import parse_and_verify_certificate

        team_sk, _, team_did_key = _make_keypair()
        _, _, agent_did_key = _make_keypair()

        cert = _make_certificate(
            team_sk, team_did_key, agent_did_key,
            certificate_id="revoked-cert",
        )
        encoded = _encode_certificate(cert)

        with pytest.raises(ValueError, match="revoked"):
            parse_and_verify_certificate(
                encoded,
                request_did_key=agent_did_key,
                team_public_key_resolver=lambda _ta: team_did_key,
                revocation_checker=lambda _ta, _cid: True,
            )

    def test_valid_full_flow(self):
        from aweb.team_auth import parse_and_verify_certificate

        team_sk, _, team_did_key = _make_keypair()
        _, _, agent_did_key = _make_keypair()

        cert = _make_certificate(
            team_sk, team_did_key, agent_did_key,
            team_address="acme.com/backend",
            alias="alice",
            lifetime="permanent",
        )
        encoded = _encode_certificate(cert)

        result = parse_and_verify_certificate(
            encoded,
            request_did_key=agent_did_key,
            team_public_key_resolver=lambda _ta: team_did_key,
            revocation_checker=lambda _ta, _cid: False,
        )

        assert result["team_address"] == "acme.com/backend"
        assert result["alias"] == "alice"
        assert result["did_key"] == agent_did_key
        assert result["lifetime"] == "permanent"
        assert result["certificate_id"] == "cert-001"

    def test_malformed_base64_rejected(self):
        from aweb.team_auth import parse_and_verify_certificate

        with pytest.raises(ValueError, match="Malformed certificate"):
            parse_and_verify_certificate(
                "not-valid-base64!!!",
                request_did_key="did:key:z6Mkfake",
                team_public_key_resolver=lambda _ta: "",
                revocation_checker=lambda _ta, _cid: False,
            )

    def test_malformed_json_rejected(self):
        from aweb.team_auth import parse_and_verify_certificate

        encoded = base64.b64encode(b"this is not json").decode()

        with pytest.raises(ValueError, match="Malformed certificate"):
            parse_and_verify_certificate(
                encoded,
                request_did_key="did:key:z6Mkfake",
                team_public_key_resolver=lambda _ta: "",
                revocation_checker=lambda _ta, _cid: False,
            )

    def test_unsupported_version_rejected(self):
        from aweb.team_auth import parse_and_verify_certificate

        team_sk, _, team_did_key = _make_keypair()
        _, _, agent_did_key = _make_keypair()

        cert = _make_certificate(team_sk, team_did_key, agent_did_key)
        cert["version"] = 99
        encoded = _encode_certificate(cert)

        with pytest.raises(ValueError, match="Unsupported certificate version"):
            parse_and_verify_certificate(
                encoded,
                request_did_key=agent_did_key,
                team_public_key_resolver=lambda _ta: team_did_key,
                revocation_checker=lambda _ta, _cid: False,
            )


# ---------------------------------------------------------------------------
# Dashboard JWT auth
# ---------------------------------------------------------------------------

_JWT_SECRET = "test-dashboard-secret-at-least-32bytes!"


class TestDashboardJWT:
    def test_valid_jwt(self):
        from aweb.team_auth import verify_dashboard_token

        payload = {
            "user_id": "user-123",
            "team_addresses": ["acme.com/backend", "acme.com/frontend"],
            "exp": int(time.time()) + 3600,
        }
        token = jwt.encode(payload, _JWT_SECRET, algorithm="HS256")

        result = verify_dashboard_token(token, _JWT_SECRET)
        assert result["user_id"] == "user-123"
        assert "acme.com/backend" in result["team_addresses"]

    def test_expired_jwt_rejected(self):
        from aweb.team_auth import verify_dashboard_token

        payload = {
            "user_id": "user-123",
            "team_addresses": ["acme.com/backend"],
            "exp": int(time.time()) - 3600,
        }
        token = jwt.encode(payload, _JWT_SECRET, algorithm="HS256")

        with pytest.raises(ValueError, match="expired"):
            verify_dashboard_token(token, _JWT_SECRET)

    def test_invalid_secret_rejected(self):
        from aweb.team_auth import verify_dashboard_token

        payload = {
            "user_id": "user-123",
            "team_addresses": ["acme.com/backend"],
            "exp": int(time.time()) + 3600,
        }
        token = jwt.encode(payload, "real-secret-at-least-thirty-two-bytes!", algorithm="HS256")

        with pytest.raises(ValueError, match="invalid"):
            verify_dashboard_token(token, "wrong-secret-at-least-thirty-two-bytes!")

    def test_team_address_authorization(self):
        from aweb.team_auth import verify_dashboard_token

        payload = {
            "user_id": "user-123",
            "team_addresses": ["acme.com/backend"],
            "exp": int(time.time()) + 3600,
        }
        token = jwt.encode(payload, _JWT_SECRET, algorithm="HS256")

        result = verify_dashboard_token(token, _JWT_SECRET, required_team="acme.com/backend")
        assert result["user_id"] == "user-123"

    def test_team_address_unauthorized(self):
        from aweb.team_auth import verify_dashboard_token

        payload = {
            "user_id": "user-123",
            "team_addresses": ["acme.com/backend"],
            "exp": int(time.time()) + 3600,
        }
        token = jwt.encode(payload, _JWT_SECRET, algorithm="HS256")

        with pytest.raises(ValueError, match="not authorized"):
            verify_dashboard_token(token, _JWT_SECRET, required_team="acme.com/frontend")

    def test_empty_secret_rejected(self):
        import warnings

        from aweb.team_auth import verify_dashboard_token

        payload = {
            "user_id": "user-123",
            "team_addresses": ["acme.com/backend"],
            "exp": int(time.time()) + 3600,
        }
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            token = jwt.encode(payload, "", algorithm="HS256")

        with pytest.raises(ValueError, match="not configured"):
            verify_dashboard_token(token, "")
