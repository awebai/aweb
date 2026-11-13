"""Historical exact-header matching is separate from current effect authority."""

import json
from pathlib import Path

import pytest
from awid.protected_effect import HEADER, EffectRefused
from awid.protected_receipts import PATH, read_receipt, record_receipt, header_digest
from test_controller_request_v2_http import controller_app as controller_app

VECTOR = json.loads(
    (Path(__file__).resolve().parents[2] / "docs/vectors/protected-effect-receipt-v1.json").read_text()
)


@pytest.mark.asyncio
async def test_exact_historical_receipt_is_immutable_and_rolls_back(controller_app):
    env = controller_app
    f, h = VECTOR["reference"], VECTOR["header"]
    assert VECTOR["path"] == PATH + "/" + f["operation_id"]
    assert await read_receipt(env.db, f["operation_id"], h) is None
    with pytest.raises(RuntimeError):
        async with env.db.transaction() as tx:
            await record_receipt(tx, f, h)
            raise RuntimeError("business effect rolled back")
    assert await read_receipt(env.db, f["operation_id"], h) is None
    async with env.db.transaction() as tx:
        await record_receipt(tx, f, h)
        await record_receipt(tx, f, h)
    # This vector's proof has long expired: no new effect is authorized.
    assert await read_receipt(env.db, f["operation_id"], h) == VECTOR["response"]
    with pytest.raises(EffectRefused):
        async with env.db.transaction() as tx:
            await record_receipt(tx, {**f, "artifact_sha256": "0" * 64}, h)
    assert await read_receipt(env.db, f["operation_id"], h) == VECTOR["response"]
    for bad in (None, "", "malformed", header_digest(h), h + "x"):
        response = await env.client.get(VECTOR["path"], headers={} if bad is None else {HEADER: bad})
        assert response.status_code == 404
        assert response.headers["cache-control"] == VECTOR["cache_control"]
    response = await env.client.get(VECTOR["path"], headers={HEADER: h})
    assert response.status_code == 200 and response.json() == VECTOR["response"]
    assert response.headers["cache-control"] == VECTOR["cache_control"]


@pytest.mark.asyncio
async def test_receipt_storage_failure_is_unavailable(controller_app, monkeypatch):
    env = controller_app
    async def unavailable(*args, **kwargs):
        raise RuntimeError("unavailable")
    monkeypatch.setattr(env.db, "fetch_all", unavailable)
    response = await env.client.get(VECTOR["path"], headers={HEADER: VECTOR["header"]})
    assert response.status_code == 503
    assert response.headers["cache-control"] == "no-store"
