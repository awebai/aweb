"""An open request returns a safe entity without a named media-type contract."""

import hashlib
import json
import secrets
from uuid import uuid4

from aweb_naapp.egress import InternalDestinations

from aweb_secrets import records
from aweb_secrets.admission import UseRequest
from aweb_secrets.broker import broker_operation
from aweb_secrets.broker_fence import BrokerFence
from aweb_secrets.destination import DestinationRecord
from aweb_secrets.response_audit import ResponseKey
from aweb_secrets.use_approval import BrokerOpen
from tests.harness import running_upstream
from tests.test_admission import ALICE, INSTALLATION, NOW, SECRET, TEAM, _admit, _install
from tests.test_admission import db as db
from tests.test_admission import fence as fence


async def test_open_request_returns_upstream_json_without_a_named_media_type_policy(
    db, fence, tmp_path
):
    async with running_upstream(tmp_path) as upstream:
        await _install(db)
        destination = DestinationRecord.from_after(
            {
                "v": 1,
                "destination_id": "dst_open001",
                "secret_id": SECRET["secret_id"],
                "scheme": "https",
                "host": "upstream.secrets.test",
                "port": upstream.port,
                "path": "/bearer/**",
                "methods": ["POST"],
                "query_rules": {},
                "header_allow": [],
                "network": "internal",
                "cidr": f"{upstream.host}/32",
            },
            internal_destinations=InternalDestinations.ALLOWED,
        )
        async with db.transaction() as tx:
            await records.create_destination(tx, INSTALLATION, TEAM, destination)
        request = UseRequest(
            SECRET["ref"], "open-result", hashlib.sha256(b"open-result").digest(), None, None
        )
        admission = await _admit(db, fence, request=request, clock=lambda: NOW)
        prepared = BrokerFence(
            fence,
            admission=admission,
            principal=ALICE,
            request=request,
            dispatch_id=uuid4(),
            headers=(),
            attestation=None,
            clock=lambda: NOW,
            derived_max_ttl_s=3600,
            internal_destinations=InternalDestinations.ALLOWED,
            open_call=BrokerOpen("POST", upstream.url("/bearer/echo"), (), b"hello"),
        )
        async with db.transaction() as tx:
            await prepared.prepare(tx)
        call = await broker_operation(
            upstream.egress,
            prepared.call.rendered,
            kind="bearer",
            value={"value": upstream.creds.bearer},
            kind_params={},
            secret_ref=SECRET["ref"],
            response_key=ResponseKey(secrets.token_bytes(32)),
        )
        assert call.result.status == 200
        assert call.result.disposition == "returned", call.result.withheld_reason
        assert call.result.body is not None
        assert json.loads(call.result.body)["scheme"] == "bearer"
        assert upstream.paths == ["/bearer/echo"]
