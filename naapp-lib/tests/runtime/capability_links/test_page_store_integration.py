"""Final N5/runtime/PageStore composition on real AWID and PostgreSQL.

The adapter calls only public APIs. Creator Principals come from the actual
request verifier; holder paths use the canonical identity and a preflight proof.
"""

from dataclasses import dataclass

import pytest
from asyncpg.exceptions import LockNotAvailableError
from aweb_naapp_testing import Member

from aweb_naapp.page_store import Access, StoreError, principal_id
from aweb_naapp.ratelimit import apply_ratelimit_migrations
from aweb_naapp.runtime.capability_links import (
    LinkCaller,
    LinkScope,
    Readable,
    apply_capability_link_migrations,
    exchange,
    load_link_creator,
    mint,
    read,
)
from tests.page_store.test_query_api import table
from tests.page_store.test_store import SCOPE  # noqa: F401
from tests.page_store.test_store import store as store
from tests.runtime.conftest import relying_app

from .conftest import DEFAULT_LINK, T0, request_from
from .test_exchange import body

ORIGIN = "https://integration.example"
LINK_SCOPE = LinkScope(SCOPE.team_id, SCOPE.installation_id, SCOPE.page_id)


class Authority:
    def __init__(self, store, creator_id):
        self.store = store
        self.creator_id = creator_id
        self.gated_tx = None
        self.holder = False

    async def require_current_creator(self, tx, *, creator, proof):
        # N5 has already validated the original runtime proof locally.
        assert creator.scope == LINK_SCOPE
        assert creator.principal_did == self.creator_id
        assert proof.team_id == creator.scope.team_id
        self.gated_tx = tx

    async def readable(self, tx, *, creator, page_id, collection, link_mode, record_ids):
        assert creator == self.creator_id and page_id == SCOPE.page_id
        if self.holder:
            assert tx is self.gated_tx  # Membership gate before the real store callback.
        result = await self.store.collection_access_on(
            tx,
            SCOPE,
            creator_id=creator,
            collection=collection,
            link_mode=link_mode,
            record_ids=record_ids,
        )
        if result is None:
            return None
        records = result["record_ids"]
        return Readable(None if records is None else tuple(records), frozenset(result["fields"]))


class SnapshotSource:
    def __init__(self, store):
        self.store = store
        self.tx = None

    async def capture_link_snapshot_on(self, tx, *, scope, **context):
        assert scope == LINK_SCOPE
        self.tx = tx
        return await self.store.capture_link_snapshot_on(tx, SCOPE, **context)


@dataclass
class Joined:
    store: object
    owner: object
    creator: object
    cache: object
    authority: Authority

    async def proof(self, link_id):
        creator = await load_link_creator(self.store.db, link_id=link_id)
        return await self.cache.check_current_member(
            creator.scope.team_id,
            certificate_id=creator.certificate_id,
            team_did_key=creator.team_did_key,
        )

    async def link(self, *, mode="live", records="*", rollback=False):
        request = request_from(DEFAULT_LINK)
        request.update(
            mode=mode, page_rev=1 if mode == "pinned" else None, actions=[], intent_sponsor_did=None
        )
        request["projection"] = {
            "collections": [
                {"collection": "items", "record_ids": records, "fields": ["label", "checked"]}
            ],
            "assets": [],
        }
        source = SnapshotSource(self.store)
        self.authority.holder = False  # Mint uses the verified request Principal.
        async with self.store.db.transaction() as tx:
            link = await mint(
                tx,
                self.authority,
                scope=LINK_SCOPE,
                creator=principal_id(self.creator, SCOPE),
                creator_certificate_id=self.creator.certificate_id,
                creator_team_did_key=self.creator.team_did_key,
                request=request,
                now=T0,
                snapshot_source=source,
            )
            if mode == "pinned":
                assert source.tx is tx
            if rollback:
                raise RuntimeError("abort outer mint transaction")
        self.authority.holder = True
        proof = await self.proof(link.link_id)  # Actual AWID preflight outside SQL tx.
        session = await exchange(
            self.store.db,
            self.authority,
            link_id=link.link_id,
            body=body(link.secret),
            client="203.0.113.7",
            now=T0,
            proof=proof,
        )
        return LinkCaller(link.link_id, session.session_id)

    async def checked(self, tx, caller, proof):
        return await read(
            tx, self.authority, caller=caller, page_id=SCOPE.page_id, now=T0, proof=proof
        )


@pytest.fixture
async def joined(store, registry):
    owner_member = Member(team_id=SCOPE.team_id, certificate_id="owner", alias="owner")
    creator_member = Member(
        team_id=SCOPE.team_id,
        team_key=owner_member.team_key,
        certificate_id="creator",
        alias="creator",
    )
    await registry.add_team(SCOPE.team_id, owner_member.team_did_key)
    for member in (owner_member, creator_member):
        await registry.add_certificate(member.certificate())
    verified = []

    async def retain(request, principal):
        verified.append(principal)
        return {"ok": True}

    async with relying_app(registry, public_origin=ORIGIN, on_principal=retain) as (client, cache):
        for member in (owner_member, creator_member):
            response = await client.get(
                "/mint-context",
                headers=member.headers(aud=ORIGIN, method="GET", path="/mint-context"),
            )
            assert response.status_code == 200
        owner, creator = verified
        await apply_ratelimit_migrations(store.db)
        await apply_capability_link_migrations(store.db)
        yield Joined(store, owner, creator, cache, Authority(store, principal_id(creator, SCOPE)))


async def seed(joined, rows):
    await joined.store.create(
        SCOPE,
        joined.owner,
        table(rows),
        access=Access(
            owner=principal_id(joined.owner, SCOPE), readers={principal_id(joined.creator, SCOPE)}
        ),
        key="create",
    )


async def test_empty_pinned_wildcard_mints_and_reads_the_same_redacted_snapshot(joined):
    await seed(joined, 0)
    caller = await joined.link(mode="pinned")
    proof = await joined.proof(caller.link_id)
    async with joined.store.db.transaction() as tx:
        checked = await joined.checked(tx, caller, proof)
        assert checked.projection["collections"][0]["record_ids"] == []
        assert checked.source_snapshot["collections"][0]["records"] == []
        view = await joined.store.project_link_snapshot_on(
            tx,
            SCOPE,
            creator_id=checked.created_by.principal_did,
            projection=checked.projection,
            allowed_action_ids=checked.allowed_action_ids,
            source_snapshot=checked.source_snapshot,
            expected_page_rev=checked.page_rev,
        )
        assert view["rev"] == 1 and view["collections"][0]["records"] == []
        assert set(view["collections"][0]["schema"]["properties"]) == {"label", "checked"}
    await joined.store.add_record(
        SCOPE,
        joined.owner,
        collection="items",
        record_id="later",
        key="add",
        values={"label": "later", "checked": False},
    )
    proof = await joined.proof(caller.link_id)
    async with joined.store.db.transaction() as tx:
        checked = await joined.checked(tx, caller, proof)
        assert checked.source_snapshot["rev"] == 1
        assert checked.source_snapshot["collections"][0]["records"] == []


async def test_live_named_rows_narrow_to_empty_before_store_values_count_and_cursor(joined):
    await seed(joined, 1)
    caller = await joined.link(records=["row-000"])
    await joined.store.change_access(
        SCOPE,
        joined.owner,
        expected_rev=1,
        key="hide",
        access=Access(
            owner=principal_id(joined.owner, SCOPE),
            readers={principal_id(joined.creator, SCOPE)},
            hidden_rows={principal_id(joined.creator, SCOPE): {"items": {"row-000"}}},
        ),
    )
    proof = await joined.proof(caller.link_id)
    async with joined.store.db.transaction() as tx:
        checked = await joined.checked(tx, caller, proof)
        assert checked.projection["collections"][0]["record_ids"] == []
        result = await joined.store.read_projection_on(
            tx, SCOPE, creator_id=checked.created_by.principal_did, projection=checked.projection
        )
        assert result["collections"][0]["records"] == []
        query = await joined.store.query_widget_on(
            tx,
            SCOPE,
            creator_id=checked.created_by.principal_did,
            widget_id="items",
            bind={"collection": "items"},
            link_id=caller.link_id,
            projection=checked.projection,
        )
        assert query["records"] == [] and query["count"] == 0 and query["next_cursor"] is None
        # Read and all projection SQL finish before releasing N5's FOR SHARE.
        async with joined.store.db.transaction() as other:
            await other.execute("SET LOCAL lock_timeout='100ms'")
            with pytest.raises(LockNotAvailableError):
                await other.execute(
                    "UPDATE {{tables.capability_links}} SET revoked_at=$1 WHERE link_id=$2",
                    T0,
                    caller.link_id,
                )


async def test_live_wildcard_follows_new_rows_only_through_checked_query(joined):
    await seed(joined, 0)
    caller = await joined.link()
    await joined.store.add_record(
        SCOPE,
        joined.owner,
        collection="items",
        record_id="later",
        key="add",
        values={"label": "later", "checked": False},
    )
    proof = await joined.proof(caller.link_id)
    async with joined.store.db.transaction() as tx:
        checked = await joined.checked(tx, caller, proof)
        assert checked.projection["collections"][0]["record_ids"] == "*"
        query = await joined.store.query_widget_on(
            tx,
            SCOPE,
            creator_id=checked.created_by.principal_did,
            widget_id="items",
            bind={"collection": "items"},
            link_id=caller.link_id,
            projection=checked.projection,
        )
        assert query["count"] == 1 and query["records"][0]["id"] == "later"
        for operation in (
            "read_projection_on",
            "capture_link_snapshot_on",
            "project_link_snapshot_on",
        ):
            context = dict(
                creator_id=checked.created_by.principal_did, projection=checked.projection
            )
            if operation != "read_projection_on":
                context.update(allowed_action_ids=[], expected_page_rev=query["page_rev"])
            if operation == "project_link_snapshot_on":
                context["source_snapshot"] = table(0)
            with pytest.raises(StoreError, match="schema_invalid"):
                await getattr(joined.store, operation)(tx, SCOPE, **context)


async def test_outer_rollback_removes_real_capture_and_link_together(joined):
    await seed(joined, 0)
    with pytest.raises(RuntimeError, match="abort outer mint"):
        await joined.link(mode="pinned", rollback=True)
    assert (
        await joined.store.db.fetch_value("SELECT count(*) FROM {{tables.capability_links}}") == 0
    )
    assert (
        await joined.store.db.fetch_value(
            "SELECT count(*) FROM {{tables.capability_link_snapshots}}"
        )
        == 0
    )
    assert (await joined.store.read(SCOPE, joined.owner))["rev"] == 1
