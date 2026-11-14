"""Folio's retained creator fields use real AWID and the production runtime."""

import base64
import json
from dataclasses import replace

import pytest
from aweb_naapp.manifest import write_manifest_file
from aweb_naapp.runtime.app import NaappRuntime
from aweb_naapp.runtime.settings import NaappSettings
from aweb_naapp_testing import Member, did_key
from awid_service.testing import REGISTRY_URL, SERVICE_TOKEN, running_registry
from fastapi import HTTPException
from nacl.signing import SigningKey

from folio.edit_sessions import member_proof, require_proof


@pytest.mark.parametrize("change", ["genuine", "subject", "alias"])
async def test_editor_retains_the_original_creator_subject_and_alias(test_db_factory, tmp_path, change):
    db = await test_db_factory.create_db(suffix="folio_protected_membership")
    async with running_registry(db.config.get_dsn()) as registry:
        member = Member(team_id="editors:example.com")
        await registry.add_team(member.team_id, member.team_did_key)
        await registry.add_certificate(member.certificate())
        await registry.db.execute(
            "UPDATE {{tables.team_certificates}} SET certificate=$1",
            base64.b64encode(json.dumps(member.certificate()).encode()).decode(),
        )
        await registry.db.execute(
            "INSERT INTO {{tables.team_protection}} "
            "(domain,name,service_id,service_did_key,generation) VALUES ('example.com','editors','test-signer',$1,1)",
            did_key(SigningKey.generate()),
        )
        manifest = tmp_path / "aweb-app.json"
        write_manifest_file(manifest, {
            "manifest_version": 1, "app": {"id": "editor-test", "origin": "https://folio.test"}, "tools": [],
        })
        runtime = NaappRuntime(
            NaappSettings(_env_file=None, app_id="editor-test", public_origin="https://folio.test",
                          database_url=db.config.get_dsn(), awid_registry_url=REGISTRY_URL,
                          awid_service_token=SERVICE_TOKEN),
            module_name="editor-test", migrations_path=tmp_path, manifest_path=manifest,
            awid_transport=registry.transport,
        )
        row = {"team_id": member.team_id, "creator_team_did_key": member.team_did_key,
               "certificate_id": member.certificate_id, "created_by_did_aw": None,
               "created_by_did_key": member.did_key, "created_by_alias": member.alias}
        if change == "subject":
            row["created_by_did_key"] = did_key(SigningKey.generate())
        elif change == "alias":
            row["created_by_alias"] = "impostor"
        if change != "genuine":
            with pytest.raises(HTTPException) as refused:
                await member_proof(runtime, row)
            assert refused.value.status_code == 401
        else:
            proof = await member_proof(runtime, row)
            require_proof(row, proof)
            for changed in (replace(proof, principal=did_key(SigningKey.generate())),
                            replace(proof, member_alias="impostor")):
                with pytest.raises(HTTPException) as refused:
                    require_proof(row, changed)
                assert refused.value.status_code == 404
