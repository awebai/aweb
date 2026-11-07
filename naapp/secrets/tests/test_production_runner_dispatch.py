"""The production root hands one genuinely approved run to its registered runner.

Uses app's real LOGIN/APPROVE/member-admission helper and the production root's
own RunDispatch. Actual worker execution and separate-UID evidence belong to
the S19 RunnerHarness journey; this test is the server protocol boundary.
"""

import hashlib
import json
import secrets
from datetime import UTC, datetime

from aweb_naapp.crypto import open_sealed
from aweb_naapp.hooks.strictjson import decode_base64url, encode_base64url
from aweb_naapp.signing_key import read_signing_key_file
from awid.did import did_from_public_key

from aweb_secrets.custody import decode_value
from aweb_secrets.runner_protocol import canonical
from tests.test_production_bootstrap import root as root
from tests.test_production_dispatch import admitted_run
from tests.test_run_dispatch_service import report


def runner_headers(request, origin, path, body=b"{}"):
    key = request.runner_signing_key
    raw = canonical(
        {
            "v": 1,
            "type": "aweb.secrets.runner-request",
            "origin": origin,
            "runner_id": request.runner_id,
            "kid": did_from_public_key(bytes(key.verify_key)),
            "method": "POST",
            "path": path,
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "nonce": secrets.token_urlsafe(16),
        }
    )
    signature = key.sign(b"aweb.secrets.runner-request/1\n" + raw).signature
    return {
        "Content-Type": "application/json",
        "X-Aweb-Secrets-Runner-Request": encode_base64url(raw) + "." + encode_base64url(signature),
    }


async def test_approved_production_run_reaches_signed_sealed_assignment_and_member_result(root):
    service, client, configured, member, *_ = root
    request = await admitted_run(root)
    origin = configured.public_origin
    db = service.runtime.db()
    claim_path = "/runner/v1/claim"
    claimed = await client.post(
        origin + claim_path,
        content=b"{}",
        headers=runner_headers(request, origin, claim_path),
    )
    assert claimed.status_code == 200
    assert claimed.headers["cache-control"] == "no-store"
    wire = claimed.json()
    assignment = wire["assignment"]
    assert assignment["runner_id"] == request.runner_id
    assert assignment["job_id"] == request.job_id
    assert assignment["job_digest"] == await db.fetch_value(
        "SELECT digest FROM current_jobs WHERE installation_id=$1 AND job_id=$2",
        root[4]["installation_id"],
        request.job_id,
    )
    assert assignment["origin"] == origin
    assert wire["params"] == json.loads(request.raw)["params"]
    pin = read_signing_key_file(configured.runner_service_key_file).verify_key
    assert assignment["service_kid"] == did_from_public_key(bytes(pin))
    pin.verify(
        b"aweb.secrets.runner-assignment/1\n" + canonical(assignment),
        decode_base64url(wire["signature"], "signature"),
    )
    assert assignment["params_sha256"] == hashlib.sha256(canonical(wire["params"])).hexdigest()
    assert (
        assignment["credentials_sha256"]
        == hashlib.sha256(canonical(wire["credentials"])).hexdigest()
    )
    assert len(wire["credentials"]) == 1
    plaintext = open_sealed(
        request.runner_encryption_key.private_bytes_raw(),
        decode_base64url(wire["credentials"][0]["sealed"], "credential"),
        info=assignment["dispatch_id"].encode(),
    )
    # Fixed failure text keeps generated values out of assertion diagnostics.
    if decode_value("bearer", plaintext) != {"value": request.credential}:
        raise AssertionError("production assignment did not carry the approved credential")
    target = "/runner/v1/dispatches/" + assignment["dispatch_id"]
    started = await client.post(
        origin + target + "/started",
        content=b"{}",
        headers=runner_headers(request, origin, target + "/started"),
    )
    assert started.status_code == 204 and started.content == b""
    raw = report(request.credential)

    async def stream():
        for index in range(0, len(raw), 7):
            yield raw[index : index + 7]

    reported = await client.post(
        origin + target + "/result",
        content=stream(),
        headers=runner_headers(request, origin, target + "/result", raw),
    )
    assert reported.status_code == 204 and reported.content == b""
    assert reported.headers["cache-control"] == "no-store"
    path = "/v1/status/" + request.reply["request_ref"]
    status = await client.get(
        origin + path, headers=member.headers(aud=origin, method="GET", path=path, body=b"")
    )
    assert status.status_code == 200
    assert status.json()["state"] == "completed"
    assert status.json()["result"]["exit_code"] == 0
    assert status.json()["result"]["redaction_count"] >= 1
    if request.credential in status.text:
        raise AssertionError("production member result released the original credential")
    assert await db.fetch_value("SELECT attempts FROM dispatches") == 1
    assert (
        await db.fetch_value("SELECT report_sha256 FROM run_deliveries")
        == hashlib.sha256(raw).digest()
    )
