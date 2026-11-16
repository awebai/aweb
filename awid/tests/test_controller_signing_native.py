"""Typed SDK through actual AWID routes, PostgreSQL and the Redis limiter.

The reserved local namespace needs no fabricated DNS authority. No transport
answers or authentication/registry functions are replaced.
"""

from datetime import datetime, timezone

import httpx
import pytest
from nacl.signing import SigningKey

from awid.controller_signing import ControllerDescriptor, parse_controller_object, parse_controller_request, sign_controller_object
from awid.did import did_key_from_signing_key
from awid.registry import RegistryClient, RegistryError
from awid.team_server_record import build_team_server_record, verify_team_server_record
pytest_plugins = ("test_controller_request_v2_http",)


async def test_typed_team_membership_and_address_lifecycle(controller_app):
    env = controller_app
    namespace = ControllerDescriptor("namespace", "local", env.controller[1], "namespace", 0)
    team = ControllerDescriptor("team", "local", env.team[1], "team", 0, team="typed")
    keys = {"namespace": env.controller[0], "team": env.team[0]}

    def signer(context):
        seed = keys[context.controller.key_reference]
        return did_key_from_signing_key(seed), SigningKey(seed).sign(context.signing_bytes()).signature

    sdk = RegistryClient(str(env.client.base_url).rstrip("/"),
                         transport=httpx.ASGITransport(app=env.app, client=("127.9.8.7", 12345)))

    async def run(op, controller=namespace, **parameters):
        return await sdk.controller_request(
            parse_controller_request({"operation": op, "domain": "local", **parameters}),
            controllers={"controller": controller}, signer=signer)

    try:
        created = await run("team_register", name="typed", display_name="Typed",
                            team_did_key=team.did_key, visibility="private")
        assert created["team_did_key"] == team.did_key
        attacker_seed = bytes(range(32))
        keys["attacker"] = attacker_seed
        attacker = ControllerDescriptor("namespace", "local", did_key_from_signing_key(attacker_seed), "attacker", 0)
        with pytest.raises(RegistryError) as failure:
            await run("team_register", attacker, name="intruder", display_name="Intruder",
                      team_did_key=team.did_key, visibility="public")
        assert failure.value.status_code == 401
        assert await sdk.get_team("local", "intruder") is None

        subject_seed = bytes(range(2, 34))
        subject_key = did_key_from_signing_key(subject_seed)
        subject = await sdk.register_did(subject_key, subject_seed)
        certificate_id = "00000000-0000-4000-8000-000000000002"
        obj = parse_controller_object({"operation": "team_certificate_issue", "domain": "local", "name": "typed",
            "certificate": {"version": 1, "certificate_id": certificate_id, "team_id": "typed:local",
                "team_did_key": team.did_key, "member_did_key": subject_key, "member_did_aw": subject.did_aw,
                "alias": "person", "identity_scope": "global"}})
        artifact = await sign_controller_object(obj, controller=team, signer=signer)
        await run("certificate_register", team, name="typed", certificate=artifact["encoded_certificate"])
        page = await run("certificate_list", team, name="typed", active_only=True, limit=1)
        assert [c["certificate_id"] for c in page["certificates"]] == [certificate_id]
        read = await run("team_read", team, name="typed")
        assert read["visibility"] == "private"
        await run("team_visibility", team, name="typed", visibility="public")

        address = await run("address_register", name="person", did_aw=subject.did_aw, current_did_key=subject_key)
        assert address["did_aw"] == subject.did_aw
        await run("address_update", name="person")
        other_seed = bytes(range(3, 35))
        other_key = did_key_from_signing_key(other_seed)
        other = await sdk.register_did(other_key, other_seed)
        reassigned = await run("address_reassign", name="person", did_aw=other.did_aw, current_did_key=other_key)
        assert reassigned["did_aw"] == other.did_aw
        await run("address_delete", name="person")
        assert await sdk.resolve_address("local", "person") is None

        record = build_team_server_record("typed:local", team.did_key, "https://team.example", datetime.now(timezone.utc))
        published = await run("server_publish", team, name="typed", record=record)
        assert published["record"] == record
        await run("certificate_revoke", team, name="typed", certificate_id=certificate_id)
        revoked = await run("revocations_read", team, name="typed", limit=200)
        assert certificate_id in {r["certificate_id"] for r in revoked["revocations"]}

        new_seed = bytes(range(4, 36))
        new_key = did_key_from_signing_key(new_seed)
        new_team = ControllerDescriptor("team", "local", new_key, "new-team", 1, team="typed")
        keys["new-team"] = new_seed
        new_record = {**record, "team_did_key": new_key}
        new_obj = parse_controller_object({"operation": "team_server_sign", "domain": "local", "name": "typed", "record": new_record})
        envelope = await sign_controller_object(new_obj, controller=new_team, signer=signer)
        rotated = await sdk.rotate_team_key("local", "typed", new_team_did_key=new_key,
                     namespace_controller_signing_key=env.controller[0], resigned_records={"team_server": envelope})
        assert rotated["key_changed"] is True
        stored = await sdk.get_team_server_record("local", "typed")
        verify_team_server_record(stored["record"], stored["signature"], team_id="typed:local",
                                   current_team_did_key=new_key, now=datetime.now(timezone.utc))
        await run("team_delete", name="typed")
        assert await sdk.get_team("local", "typed") is None
    finally:
        await sdk.aclose()


async def test_new_namespace_delete_method_is_real_and_has_wrong_authority_neighbor(controller_app):
    env = controller_app
    sdk = RegistryClient(str(env.client.base_url).rstrip("/"), transport=httpx.ASGITransport(app=env.app))
    try:
        with pytest.raises(RegistryError) as failure:
            await sdk.delete_namespace("local", bytes(range(32)))
        assert failure.value.status_code == 403
        assert await sdk.get_namespace("local") is not None
        await sdk.delete_team("local", "base", env.controller[0])
        result = await sdk.delete_namespace("local", env.controller[0], reason="test lifecycle complete")
        assert result["deleted"] is True
        assert await sdk.get_namespace("local") is None
    finally:
        await sdk.aclose()
