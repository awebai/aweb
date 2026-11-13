"""The real policy HTTP adapter: covering proof, current key and named root."""

import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import httpx
import pytest
from awid.did import did_from_public_key, generate_keypair, stable_id_from_public_key
from awid.signing import canonical_json_bytes, sign_message
from fastapi import FastAPI

from aweb.protected_signing.composition import IndependentProtectedSigner
from aweb.protected_signing.profile import ProtectedServiceProfile
from aweb_naapp.runtime.protected_signer.admission_policy import AdmissionPolicy
from tests.test_protected_service_profile import FIXTURE

PROFILE = ProtectedServiceProfile.from_json(FIXTURE.read_bytes())
CONTEXT = PROFILE.bindings[0].context()
TEAM = CONTEXT.authority_id


def configured_policy():
    return AdmissionPolicy.from_unsigned({
        "version": 1, "teams": [TEAM],
        "root_selector": {"kind": "service_endorsed_root", "service_id": CONTEXT.service_id},
        "subject_kinds": ["local_agent", "registered_agent"], "member_role": "member",
        "bounds": {"max_active": 10, "rate_window_seconds": 60, "max_per_window": 2},
    }, service_id=CONTEXT.service_id)


class Tx:
    def __init__(self, *, policy, allowed=True):
        self.policy, self.allowed, self.writes = policy, allowed, []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def fetch_one(self, sql, *args):
        assert "protected_admission_policies" in sql
        return None if self.policy is None else {"policy": json.dumps(self.policy.fields())}

    def transaction(self):
        return self


class Authority:
    def __init__(self, tx):
        self.tx = tx
        self.calls = []

    async def observe(self, context, *, purpose):
        assert context == CONTEXT
        self.calls.append(purpose)
        return self

    async def prepare(self, tx, actor):
        from aweb_naapp.runtime.protected_signer import SignerRefused
        assert tx is self.tx and actor.context == CONTEXT
        if not tx.allowed:
            raise SignerRefused("scope_refused")

    async def check(self, tx, actor):
        await self.prepare(tx, actor)

    def require_fresh(self):
        pass


async def http(policy, *, allowed=True, current=True):
    """Use real production request verifier; narrow authority/DB port doubles."""
    seed, public = generate_keypair()
    principal, did = stable_id_from_public_key(public), did_from_public_key(public)
    tx = Tx(policy=policy, allowed=allowed)

    class Registry:
        async def resolve_key_fresh(self, selected):
            assert selected == principal
            return SimpleNamespace(did_aw=principal, current_did_key=did if current else PROFILE.bindings[0].authority_key_did)

    c = object.__new__(IndependentProtectedSigner)
    c.db, c.context, c.registry = tx, CONTEXT, Registry()
    c.request_origin = PROFILE.request_origin
    c.authority = Authority(tx)
    app = FastAPI()
    # Production callback is installed into the one shared mount; no second
    # JSON parser, auth implementation, or policy route exists in this test.
    from aweb_naapp.runtime.protected_signer import ProtectedOperationsHTTP

    class Limiter:
        async def admit(self, *args, **kwargs):
            pass

    signer = SimpleNamespace(passkeys=SimpleNamespace(rp=SimpleNamespace(origin=PROFILE.human_origin)))
    mount = ProtectedOperationsHTTP(signer, request_origin=PROFILE.request_origin,
        requester=None, reader=None, limiter=Limiter(), policy_reader=c.read_admission_policy)
    app.include_router(mount.api_router())
    path = "/protected-admission-policies?team_id=" + TEAM.replace(":", "%3A")

    def headers(*, scope=None, selected_path=path, timestamp=None):
        stamp = timestamp or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        raw = canonical_json_bytes({"v": 2, "type": "aweb.awid-controller-request", "aud": PROFILE.request_origin,
            "operation": "protected_admission_policy_read", "domain": CONTEXT.authority_domain,
            "timestamp": stamp, "method": "GET", "path": selected_path,
            "body_sha256": hashlib.sha256(b"").hexdigest(), "service_id": CONTEXT.service_id,
            "scope_sha256": hashlib.sha256(canonical_json_bytes(scope or {"service_id": CONTEXT.service_id, "team_id": TEAM})).hexdigest()})
        signature = sign_message(seed, raw).rstrip("=")
        return {"Authorization": "DIDKey " + did + " " + signature,
            "X-AWEB-DID-AW": principal, "X-AWEB-Timestamp": stamp,
            "X-AWEB-Signed-Payload": base64.urlsafe_b64encode(raw).rstrip(b"=").decode()}

    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=PROFILE.request_origin), path, headers, tx


@pytest.mark.asyncio
async def test_named_prospective_root_reads_the_exact_policy_without_creating_one():
    policy = configured_policy()
    client, path, headers, tx = await http(policy)
    async with client:
        response = await client.get(path, headers=headers())
        assert response.status_code == 200, response.text
        assert response.json() == {"service_id": CONTEXT.service_id, "team_id": TEAM, "mode": "protected", "policy": policy.fields()}
    assert not tx.writes


@pytest.mark.asyncio
async def test_only_a_known_team_with_no_stored_policy_answers_null():
    client, path, headers, tx = await http(None)
    async with client:
        response = await client.get(path, headers=headers())
        assert response.status_code == 200, response.text
        assert response.json()["policy"] is None
    assert not tx.writes


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["not_named", "stale_key", "scope", "path", "cookie", "body", "duplicate_team", "other_team", "old_proof"])
async def test_policy_read_refuses_invalid_proof_or_unknown_authority(case):
    client, path, headers, tx = await http(configured_policy(), allowed=case != "not_named", current=case != "stale_key")
    selected = path
    h = headers(scope={"service_id": "wrong", "team_id": TEAM}) if case == "scope" else headers()
    if case == "path":
        h = headers(selected_path=path + "&extra=1")
    if case == "cookie":
        h["Cookie"] = "session=ambient"
    if case == "duplicate_team":
        selected += "&team_id=" + TEAM
    if case == "other_team":
        selected = path.replace(TEAM.partition(":")[0], "other")
    if case == "old_proof":
        h = headers(timestamp=(datetime.now(UTC) - timedelta(minutes=20)).strftime("%Y-%m-%dT%H:%M:%SZ"))
    async with client:
        response = await client.request("GET", selected, headers=h, content=b"{}" if case == "body" else b"")
        assert response.status_code in (400, 401, 403), response.text
        assert "policy" not in response.json()
    assert not tx.writes
