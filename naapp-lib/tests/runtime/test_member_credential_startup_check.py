"""The startup check of a customer-hosted app's own member certificates.

The registry's answers are the shared certificate cases' own; the credential
is the case's certificate with its member's signing key.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from awid.team_certificate import decode_team_certificate

from aweb_naapp.runtime.team_auth import AWIDMemberCredential, AWIDTeamCache

VECTORS = json.loads(
    (Path(__file__).resolve().parents[3] / "docs/vectors/team-certificate-verification-v1.json").read_text()
)
REGISTRY = "https://registry.example.com"
CASES = {case["name"]: case for case in VECTORS["cases"]}
MEMBER_SEED = bytes.fromhex(VECTORS["keys"]["member"]["seed_hex"])


def _cache(case: dict) -> AWIDTeamCache:
    revoked = set(case["revoked_certificate_ids"])

    def answer(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/status"):
            certificate_id = request.url.path.split("/")[-2]
            if certificate_id not in case["registered_certificate_ids"]:
                return httpx.Response(404)
            response = {
                "team_id": VECTORS["team_id"],
                "team_did_key": case["team_did_key"],
                "status": "revoked" if certificate_id in revoked else "active",
                "revoked_at": "2026-11-02T00:00:00Z" if certificate_id in revoked else None,
            }
            if request.url.params.get("protection") == "1":
                response.update(protection={"mode": "legacy"}, certificate_sha256=None)
            return httpx.Response(200, json=response)
        if request.url.path.endswith("/certificates"):
            page = [
                {"certificate_id": certificate_id, "revoked_at": "2026-11-02T00:00:00Z" if certificate_id in revoked else None}
                for certificate_id in case["registered_certificate_ids"]
            ]
            return httpx.Response(200, json={"certificates": page, "has_more": False})
        return httpx.Response(200, json={"team_did_key": case["team_did_key"]})

    credential = AWIDMemberCredential(
        signing_key=MEMBER_SEED, certificate=decode_team_certificate(case["certificate_header"])
    )
    return AWIDTeamCache(
        registry_url=REGISTRY,
        ttl_seconds=60,
        member_credentials={VECTORS["team_id"]: credential},
        transport=httpx.MockTransport(answer),
    )


async def test_a_current_certificate_passes() -> None:
    await _cache(CASES["valid"]).check_member_credentials()


@pytest.mark.parametrize(
    ("name", "reason"),
    [
        ("signed_by_another_key", "bad_signature"),
        ("revoked", "revoked"),
        ("unregistered", "unregistered"),
        ("version_2", "unsupported_version"),
    ],
)
async def test_a_certificate_the_one_check_refuses_stops_the_app(name: str, reason: str) -> None:
    with pytest.raises(RuntimeError) as refused:
        await _cache(CASES[name]).check_member_credentials()
    message = str(refused.value)
    assert f"awid_member_credentials[{VECTORS['team_id']}]" in message
    assert message.endswith(f"({reason})")
