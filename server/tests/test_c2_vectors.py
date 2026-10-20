"""Frozen C2 cases run through the server's validators and answer routes."""

import base64
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from awid.did import did_from_public_key
from aweb_naapp.runtime.task_requests import sign_stage_receipt
import hashlib
import json
from pathlib import Path

import pytest
from fastapi import FastAPI, HTTPException
from starlette.requests import Request

from awid.signing import canonical_json_bytes, sign_message
from aweb.app_credentials import APP_REQUEST, verify_app_credential
from aweb.coordination.app_tasks import validate_task_authorization, validate_stage_receipt
from aweb.coordination.tasks_service import answer_comment_projection
from aweb.service_errors import ValidationError, ForbiddenError
from aweb.task_contracts import strict_json_bytes, validate_app_task
from test_app_task_requests import (
    _app_http, _body, _sign, _stage, _verified_install, app_request_context,  # noqa: F401
)
from test_task_answers import _v2_request
from test_tasks_http import _seed_team
from test_dashboard_privacy import privacy_app  # noqa: F401

VECTORS = Path(__file__).resolve().parents[2] / "docs" / "vectors"
AUTH = json.loads((VECTORS / "app-task-authorization-v1.json").read_text())
CREDENTIAL = json.loads((VECTORS / "app-request-credential-v1.json").read_text())
ANSWERS = json.loads((VECTORS / "task-answer-v1.json").read_text())


@pytest.mark.parametrize("case", AUTH["verification_cases"], ids=lambda c: c["name"])
def test_server_authorization_vectors(case):
    args = dict(expected=case["expected"], now=datetime.fromisoformat(case["now"]))
    if case["expect"] is None:
        validate_task_authorization(case["payload"], case["signature"], **args)
    else:
        with pytest.raises(HTTPException) as caught:
            validate_task_authorization(case["payload"], case["signature"], **args)
        assert caught.value.detail == case["expect"]
        assert caught.value.status_code == (403 if case["expect"] == "target_mismatch" else 401)


@pytest.mark.parametrize("case", ANSWERS["stage_receipt"]["verification_cases"], ids=lambda c: c["name"])
def test_server_stage_receipt_vectors(case):
    args = dict(expected=case["expected"], now=datetime.fromisoformat(case["now"]))
    if case["expect"] is None:
        validate_stage_receipt(case["payload"], case["signature"], **args)
    else:
        with pytest.raises((HTTPException, ForbiddenError)) as caught:
            validate_stage_receipt(case["payload"], case["signature"], **args)
        code = "authorization_expired" if case["expect"] == "authorization_expired" else "target_mismatch"
        assert caught.value.detail == code


@pytest.mark.parametrize("case", AUTH["task_body_refusals"], ids=lambda c: c["name"])
def test_server_task_refusal_vectors(case):
    with pytest.raises(ValidationError, match=case["expect"]):
        validate_app_task(case["task"])


@pytest.mark.parametrize("case", AUTH["valid"] + AUTH["task_body_valid"], ids=lambda c: c["name"])
def test_server_valid_task_digest_vectors(case):
    task = validate_app_task(case["task"])
    assert hashlib.sha256(canonical_json_bytes(task)).hexdigest() == case["task_body_sha256"]


@pytest.mark.parametrize("case", AUTH["raw_json_cases"], ids=lambda c: c["name"])
def test_server_strict_json_vectors(case):
    with pytest.raises(ValidationError, match=case["expect"]):
        strict_json_bytes(case["json"].encode())


@pytest.mark.parametrize("case", ANSWERS["bodies"], ids=lambda c: c["name"])
def test_server_exact_answer_comment_vectors(case):
    assert answer_comment_projection(body_md=case["body_md"], answer_sha256=case["answer_sha256"]) == case["body_md"]


@pytest.mark.asyncio
@pytest.mark.parametrize("case", [{"name": "valid", "status": 200}, *CREDENTIAL["refusals"]], ids=lambda c: c["name"])
async def test_server_app_credential_vectors(aweb_cloud_db, monkeypatch, case):
    # Only the clock is pinned. Signature, key registration, installation and
    # the entire production verifier run normally against PostgreSQL.
    import awid.dns_auth

    pinned = datetime.fromisoformat(CREDENTIAL["payload"]["timestamp"])
    monkeypatch.setattr(awid.dns_auth, "_utc_now", lambda: pinned)
    db = aweb_cloud_db.aweb_db
    await _seed_team(db)
    payload = deepcopy(CREDENTIAL["payload"])
    installation = await _verified_install(db, team_id=payload["team_id"], app_id=payload["app_id"],
        did_key=payload["did_key"], kid=payload["kid"], installation_id=payload["installation_id"],
        generation=payload["installation_generation"], origin="https://pages.example.com")
    raw = CREDENTIAL["request"]["body"].encode()
    prefix = "AWEB-App-Request DIDKey "
    name = case["name"]
    if name == "event-credential":
        prefix = "AWEB-App DIDKey "
        payload["auth"] = "app-event"
    elif name == "auth-field-app-event":
        payload["auth"] = "app-event"
    elif name == "missing-installation":
        del payload["installation_id"], payload["installation_generation"]
    elif name == "body-changed":
        raw += b" "
    elif name == "key-not-declared-for-app-request":
        await db.execute("UPDATE {{tables.team_app_keys}} SET purposes=ARRAY['app-event']")
    elif name == "generation-moved":
        payload["installation_generation"] = 2
    elif name == "installation-retired":
        installation["state"] = "uninstalled"
    elif name == "timestamp-skew":
        payload["timestamp"] = (pinned + timedelta(seconds=301)).isoformat()
    canonical = canonical_json_bytes(payload)
    signature = sign_message(bytes.fromhex(CREDENTIAL["keys"]["app"]["seed_hex"]), canonical)
    if name == "valid":
        assert canonical.decode() == CREDENTIAL["canonical_payload"]
        assert signature == CREDENTIAL["signature"]
    headers = dict(CREDENTIAL["headers"])
    headers.update(Authorization=prefix+payload["did_key"]+" "+signature,
        **{"X-AWEB-Timestamp": payload["timestamp"], "X-AWEB-Signed-Payload": base64.urlsafe_b64encode(canonical).decode().rstrip("=")})
    app = FastAPI()
    app.state.public_origin = payload["aud"]
    request = Request({"type": "http", "method": "POST", "path": CREDENTIAL["request"]["path"],
                       "raw_path": CREDENTIAL["request"]["path"].encode(), "query_string": b"",
                       "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()], "app": app})
    request.state.body_sha256 = hashlib.sha256(raw).hexdigest()
    try:
        result = await verify_app_credential(request, db, APP_REQUEST, installation=installation)
        status, code = 200, None
        assert result.installation_id == CREDENTIAL["payload"]["installation_id"]
    except HTTPException as exc:
        status, code = exc.status_code, exc.detail
    assert status == case["status"], (name, code)
    if "code" in case:
        assert code == case["code"]


@pytest.mark.asyncio
@pytest.mark.parametrize("sequence_name", ["sequence", "plain_sequence"])
async def test_task_answer_vector_sequence_over_real_signed_http(app_request_context, sequence_name):
    env, *_ = app_request_context
    bodies = {c["name"]: c for c in ANSWERS["bodies"]}
    receipts = {}
    task = None
    expected_comments = []
    actors = {"assignee": "bob", "colleague": "carol", "former_holder": "alice", "other_member": "dave"}
    proposal = ANSWERS[sequence_name][0]["task"]
    for index, step in enumerate(ANSWERS[sequence_name]):
        expected = step["result"]
        if step["step"] == "create":
            if sequence_name == "plain_sequence":
                response = await _v2_request(env, "alice", "POST", "/v1/tasks", {"title": "Plain question", "assignee_alias": "bob"})
            else:
                body = _body(env)
                body["task"]["app_request"].update({k:v for k,v in proposal.items() if k != "eligible"})
                body["task"]["app_request"]["eligible_dids"] = sorted(env.actors[actors[x]].did for x in proposal["eligible"])
                body["task_authorization"]["payload"].update(
                    proposal_rev=proposal["proposal_rev"], proposal_sha256=proposal["proposal_sha256"],
                    target_dids=body["task"]["app_request"]["eligible_dids"], task_body_sha256=hashlib.sha256(canonical_json_bytes(body["task"])).hexdigest())
                response = await _app_http(app_request_context, "POST", "/v1/tasks/app-requests", _sign(env, body))
            assert response.status_code == expected["status"], (index, response.text)
            task = response.json()
            current = await _v2_request(env, "alice", "GET", f'/v1/tasks/{task["task_ref"]}')
            assert current.json()["question_rev"] == expected["question_rev"]
            continue
        ref = f'/v1/tasks/{task["task_ref"]}'
        current = await _v2_request(env, "alice", "GET", ref)
        if step["step"] == "reopen":
            response = await _v2_request(env, "alice", "PATCH", ref, {"status": "open"})
        elif step["step"] == "read_receipt":
            response = await _v2_request(env, "bob", "GET", ref + "/answer?answer_key=" + step["answer_key"])
        else:
            text = bodies[step["body"]]
            body = dict(answer_key=step["answer_key"], choice=step["choice"], body_md=text["body_md"],
                answer_sha256=text["answer_sha256"], proposal_rev=proposal.get("proposal_rev"), proposal_sha256=proposal.get("proposal_sha256"))
            if step["expected_task_rev"] != "missing":
                body["expected_task_rev"] = current.json()["rev"] if step["expected_task_rev"] == "current" else 1
            if step["proposal"] == "changed":
                body["proposal_sha256"] = "sha256:" + "0"*64
            if step.get("answer_sha256") == "mismatch":
                body["answer_sha256"] = "0"*64
            actor = actors[step["as"]]
            stage_kind = step.get("stage_receipt", "valid")
            if stage_kind not in {"missing", "not_issued"}:
                overrides = {}
                if "nonce" in step:
                    overrides["nonce"] = hashlib.sha256(step["nonce"].encode()).hexdigest()[:32]
                if stage_kind == "expired":
                    old = datetime.now(timezone.utc).replace(microsecond=0)-timedelta(minutes=10)
                    overrides.update(issued_at=old.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        expires_at=(old+timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"))
                proof = _stage(app_request_context, current.json(), actor, body, **overrides)
                if stage_kind == "wrong_key":
                    proof["payload"].update(kid="event-only", did_key=did_from_public_key(bytes(env.event_signing_key.verify_key)))
                    proof["signature"] = sign_stage_receipt(proof["payload"], env.event_signing_key)
                body["stage_receipt"] = proof
            before_nonces = await env.db.fetch_value("SELECT count(*) FROM {{tables.task_answer_stage_nonces}}")
            response = await _v2_request(env, actor, "POST", ref+"/answer", body)
            if response.status_code >= 400:
                after = await _v2_request(env, "alice", "GET", ref)
                assert after.json()["rev"] == current.json()["rev"], (index, after.text)
                assert await env.db.fetch_value("SELECT count(*) FROM {{tables.task_answer_stage_nonces}}") == before_nonces
            if response.status_code == 201:
                expected_comments.append(text["body_md"])
        assert response.status_code == expected["status"], (index, step, response.text)
        result = response.json()
        if "code" in expected:
            assert result["detail"] == expected["code"], (index, result)
        else:
            for key in ("question_rev", "current"):
                if key in expected:
                    assert result[key] == expected[key], (index, result)
            if "answered_by" in expected:
                assert result["answered_by"]["principal_did"] == env.actors[actors[expected["answered_by"]]].did
            if "same_receipt_as" in expected:
                original = receipts[expected["same_receipt_as"]]
                assert result == {**original, "current": expected.get("current", original["current"])}, index
            if step["step"] in {"answer", "read_receipt"}:
                receipts[index] = result
    comments = await _v2_request(env, "alice", "GET", ref+"/comments")
    assert [c["body"] for c in comments.json()["comments"]] == expected_comments
