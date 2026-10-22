"""N5's checked callback boundary; real AWID facts/cache tests belong to .42.1."""

import json
from dataclasses import FrozenInstanceError

import pytest
from fastapi import HTTPException

from aweb_naapp.runtime.capability_links import LinkRefused, mint

from . import test_lifecycle
from .conftest import CREATOR, DEFAULT_LINK, SCOPE, T0, TEAM_KEY, mint_link, request_from
from .test_exchange import _exchange, body
from .test_exchange_route import _client, _has_link_headers
from .test_lifecycle import get_projection, holder, revoke_link, submit

action_app = test_lifecycle.action_app


class CheckedAuthority:
    """The host composition: membership first, then creator-scoped store calls."""

    def __init__(self, source, refusal=None):
        self.source = source
        self.refusal = refusal
        self.calls = []
        self.contexts = []

    async def require_current_creator(self, tx, *, creator, proof):
        self.calls.append("member")
        self.contexts.append(creator)
        assert creator.scope == SCOPE
        assert creator.principal_did == CREATOR
        assert creator.certificate_id
        assert creator.team_did_key == TEAM_KEY
        if self.refusal:
            raise self.refusal

    def __getattr__(self, name):
        async def checked(tx, **kwargs):
            assert self.calls and self.calls[0] == "member"
            self.calls.append(name)
            return await getattr(self.source, name)(tx, **kwargs)

        return checked


async def test_mint_retains_trusted_membership_evidence_separate_from_acl_identity(db, authority):
    async with db.transaction() as tx:
        link = await mint(
            tx,
            authority,
            scope=SCOPE,
            creator=CREATOR,
            creator_certificate_id="cert-minted",
            creator_team_did_key=TEAM_KEY,
            request=request_from(DEFAULT_LINK),
            now=T0,
        )
    record = await db.fetch_value(
        "SELECT record FROM {{tables.capability_links}} WHERE link_id=$1", link.link_id
    )
    record = json.loads(record) if isinstance(record, str) else record
    assert record["created_by"] == {
        "team_id": SCOPE.team_id,
        "principal_did": CREATOR,
        "certificate_id": "cert-minted",
        "team_did_key": TEAM_KEY,
    }


@pytest.mark.parametrize("operation", ["exchange", "read", "admit"])
async def test_the_checked_creator_callback_precedes_store_authority(
    db, authority, action_app, operation
):
    link = await mint_link(db, authority)
    session = await _exchange(db, authority, link.link_id, body(link.secret))
    from aweb_naapp.runtime.capability_links import LinkCaller

    caller = LinkCaller(link.link_id, session.session_id)
    checked = CheckedAuthority(authority)
    if operation == "exchange":
        result = await _exchange(db, checked, link.link_id, body(link.secret))
        assert "certificate_id" not in repr(result.link)
    elif operation == "read":
        result = await get_projection(db, checked, caller)
        assert result.created_by == checked.contexts[0]
        assert result.creator == CREATOR
    else:

        class Actions:
            async def lookup(self, tx, **kwargs):
                assert checked.calls == ["member"]
                return await action_app.lookup(tx, **kwargs)

            async def apply(self, tx, *, action):
                assert action.created_by == checked.contexts[0]
                return await action_app.apply(tx, action=action)

        await submit(db, checked, Actions(), caller)
    assert checked.calls[0] == "member"
    with pytest.raises(FrozenInstanceError):
        checked.contexts[0].certificate_id = "replacement"


@pytest.mark.parametrize(
    "status,code", [(403, "current_member_required"), (503, "current_membership_unavailable")]
)
@pytest.mark.parametrize("operation", ["exchange", "read", "admit"])
async def test_current_membership_refusal_preserves_status_and_stops_store_calls(
    db, authority, action_app, status, code, operation
):
    link = await mint_link(db, authority)
    session = await _exchange(db, authority, link.link_id, body(link.secret))
    from aweb_naapp.runtime.capability_links import LinkCaller

    caller = LinkCaller(link.link_id, session.session_id)
    checked = CheckedAuthority(authority, HTTPException(status_code=status, detail={"code": code}))
    with pytest.raises(HTTPException) as refused:
        if operation == "exchange":
            await _exchange(db, checked, link.link_id, body(link.secret))
        elif operation == "read":
            await get_projection(db, checked, caller)
        else:
            await submit(db, checked, action_app, caller)
    assert refused.value.status_code == status and refused.value.detail == {"code": code}
    assert checked.calls == ["member"]
    assert await db.fetch_value("SELECT count(*) FROM {{tables.test_link_actions}}") == 0


async def test_membership_loss_also_refuses_a_matching_receipt_retry(db, authority, action_app):
    caller = await holder(db, authority)
    await submit(db, authority, action_app, caller)
    checked = CheckedAuthority(
        authority, HTTPException(status_code=403, detail={"code": "current_member_required"})
    )

    class NoLookup:
        async def lookup(self, tx, **kwargs):
            raise AssertionError("membership must precede the receipt")

    with pytest.raises(HTTPException) as refused:
        await submit(db, checked, NoLookup(), caller)
    assert refused.value.status_code == 403
    assert await db.fetch_value("SELECT count(*) FROM {{tables.test_link_actions}}") == 1
    # Owner revocation still works after the creator departs.
    await revoke_link(db, caller, actor="did:aw:owner", owner=True)


@pytest.mark.parametrize("missing", ["certificate_id", "team_did_key", "principal_did", "team_id"])
async def test_old_incomplete_creator_metadata_fails_closed_before_callback(db, authority, missing):
    caller = await holder(db, authority)
    await db.execute(
        "UPDATE {{tables.capability_links}} SET record=jsonb_set(record, '{created_by}', (record->'created_by') - $1::text)",
        missing,
    )
    checked = CheckedAuthority(authority)
    with pytest.raises(LinkRefused) as refused:
        await get_projection(db, checked, caller)
    assert (refused.value.code, refused.value.status) == ("current_member_required", 403)
    assert checked.calls == []


@pytest.mark.parametrize(
    "status,code", [(403, "current_member_required"), (503, "current_membership_unavailable")]
)
async def test_exchange_http_preserves_membership_refusal_and_link_headers(
    db, authority, status, code
):
    link = await mint_link(db, authority)
    checked = CheckedAuthority(authority, HTTPException(status_code=status, detail={"code": code}))
    async with _client(db, checked) as client:
        response = await client.post(f"/v1/links/{link.link_id}/session", content=body(link.secret))
    assert response.status_code == status
    assert response.json() == {"detail": {"code": code}}
    assert _has_link_headers(response)
    assert TEAM_KEY not in response.text and "certificate_id" not in response.text


@pytest.mark.parametrize("field", ["creator_certificate_id", "creator_team_did_key"])
@pytest.mark.parametrize("value", ["", None])
async def test_mint_never_persists_incomplete_trusted_evidence(db, authority, field, value):
    evidence = {"creator_certificate_id": "cert-test", "creator_team_did_key": TEAM_KEY}
    evidence[field] = value
    with pytest.raises(ValueError, match="creator membership evidence"):
        async with db.transaction() as tx:
            await mint(
                tx,
                authority,
                scope=SCOPE,
                creator=CREATOR,
                **evidence,
                request=request_from(DEFAULT_LINK),
                now=T0,
            )
    assert await db.fetch_value("SELECT count(*) FROM {{tables.capability_links}}") == 0
