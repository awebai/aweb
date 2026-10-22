"""Runtime hook composition: purpose keys, real PG atomicity and guarded delivery."""

import asyncio
import time
from datetime import UTC, datetime
from ipaddress import ip_network
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI
from nacl.signing import SigningKey

from aweb_naapp.egress import AddressPolicy
from aweb_naapp.hooks.commitment import CommitmentError, Purpose
from aweb_naapp.hooks.envelope import verify
from aweb_naapp.manifest import canonical_bytes
from aweb_naapp.runtime.app import NaappRuntime
from aweb_naapp.runtime.app_keys import AppKeyError
from aweb_naapp.runtime.hook_resolver import HookBinding, Resolution
from tests.hooks.test_producer import SYSTEM, TEAM
from tests.hooks.test_transport import SECRET_USE
from tests.hooks.test_transport import target as target
from tests.runtime.test_served_manifest import ExampleSettings, _key_file, _v2_template

SECRET_HOOK = "post-secret-use-hook"
MANIFEST_HOOK = "post-manifest-command-hook"
INSTALLATION = "1b4e28ba-2fa1-4d3b-a3f5-ef19b5a7633b"


def runtime(
    tmp_path,
    *,
    hook=SECRET_HOOK,
    keys=None,
    egress=None,
    internal=None,
    registry=None,
    tools=None,
    reads=(),
    extra_productions=(),
    key_files=None,
    root_path="",
    **settings,
):
    if keys is None:
        keys = (("events", ["hook-event"]), ("resolve", ["hook-resolve"]))
    files = (
        key_files
        if key_files is not None
        else {kid: _key_file(tmp_path, kid, bytes(SigningKey.generate()).hex()) for kid, _ in keys}
    )
    template = _v2_template(*keys)
    if tools is not None:
        template["tools"] = tools
    if registry is not None:
        from aweb_naapp_testing import REGISTRY_URL, SERVICE_TOKEN

        settings.update(awid_registry_url=REGISTRY_URL, awid_service_token=SERVICE_TOKEN)
    if hook is not None:
        template["hooks"] = {
            "registration_version": 1,
            "productions": [
                {"catalog": {"id": "aweb.hooks", "version": 1}, "hook": hook, "reads": list(reads)}
            ],
        }
        for extra in extra_productions:
            template["hooks"]["productions"].append(
                {
                    "catalog": {"id": "aweb.hooks", "version": 1},
                    "hook": extra,
                    "reads": [],
                }
            )
    manifest = tmp_path / "manifest.json"
    manifest.write_bytes(canonical_bytes(template))
    migrations = tmp_path / "migrations"
    migrations.mkdir()
    (migrations / "001_effect.sql").write_text(
        "CREATE TABLE {{tables.fixture_effect}} (id int PRIMARY KEY);"
    )
    return NaappRuntime(
        ExampleSettings(_env_file=None, app_key_files=files, **settings),
        module_name="hook_fixture",
        migrations_path=migrations,
        manifest_path=manifest,
        hook_egress=egress,
        hook_internal_cidr=internal,
        awid_transport=registry.transport if registry is not None else None,
        root_path=root_path,
    )


def test_no_production_needs_no_hook_configuration(tmp_path):
    app = runtime(tmp_path, hook=None, keys=())
    assert app._hooks.key is None
    with pytest.raises(AppKeyError, match="no hook production"):
        app.hook_producer(installation_id=INSTALLATION, generation=2)
    with pytest.raises(AppKeyError, match="no hook production"):
        app.hook_registrations()


@pytest.mark.parametrize("missing", ["hook-event", "hook-resolve"])
def test_declared_production_cannot_start_without_its_purpose_key(tmp_path, missing):
    remaining = "hook-event" if missing == "hook-resolve" else "hook-resolve"
    with pytest.raises(AppKeyError, match=missing):
        runtime(tmp_path, keys=(("only", [remaining]),))


def test_multiple_hook_event_keys_are_not_silently_chosen(tmp_path):
    with pytest.raises(AppKeyError, match="several configured app keys"):
        runtime(
            tmp_path,
            keys=(
                ("one", ["hook-event"]),
                ("two", ["hook-event"]),
                ("resolve", ["hook-resolve"]),
            ),
        )


def test_key_is_loaded_once_and_producers_use_the_actual_installation(tmp_path):
    app = runtime(tmp_path)
    for path in app.settings.app_key_files.values():
        path.unlink()
    first = app.hook_producer(installation_id=INSTALLATION, generation=2)
    other_id = str(uuid4())
    second = app.hook_producer(installation_id=other_id, generation=5)
    assert first.producer.fields(1)["installation_id"] == INSTALLATION
    assert second.producer.fields(1)["installation_id"] == other_id
    assert second.producer.fields(1)["generation"] == 5
    assert first.producer.did_key == app.manifest.app_keys_for("hook-event")["events"]
    assert first.producer.did_key != app.manifest.app_keys_for("hook-resolve")["resolve"]
    registrations = app.hook_registrations()
    assert registrations is app.hook_registrations()
    assert registrations._resolver is app.hook_resolver()
    assert app._hooks.transport._registrations is registrations
    assert app._hooks.transport._seed == first.producer.seed


@pytest.mark.parametrize("material", [None, "malformed", "00" * 31])
def test_manifest_commitment_key_is_required_and_never_falls_back_to_signing(tmp_path, material):
    path = None if material is None else _key_file(tmp_path, "commitment", material)
    with pytest.raises((AppKeyError, CommitmentError)):
        runtime(tmp_path, hook=MANIFEST_HOOK, manifest_request_key_file=path)


def test_manifest_commitment_key_uses_the_shared_purpose_loader(tmp_path):
    path = _key_file(tmp_path, "commitment", "a4" * 32)
    app = runtime(tmp_path, hook=MANIFEST_HOOK, manifest_request_key_file=path)
    path.unlink()
    assert app._hooks.manifest_request_key.purpose is Purpose.MANIFEST_REQUEST
    assert "a4" * 32 not in app.manifest_bytes.decode()
    assert "a4" * 32 not in repr(app._hooks.manifest_request_key)


async def test_effect_and_runtime_producer_event_share_commit_and_rollback(
    tmp_path, test_db_factory
):
    db = await test_db_factory.create_db(suffix="runtime_hook_effect")
    app = runtime(tmp_path, database_url=db.config.get_dsn(), db_schema=db.config.schema_name)
    server = FastAPI(lifespan=app.lifespan)
    producer = app.hook_producer(installation_id=INSTALLATION, generation=2)
    async with server.router.lifespan_context(server):
        with pytest.raises(RuntimeError):
            async with app.db().transaction() as tx:
                await tx.execute("INSERT INTO {{tables.fixture_effect}} VALUES (1)")
                await producer.enqueue_refusal(
                    tx,
                    team_id=TEAM,
                    payload=SECRET_USE,
                    actor=SYSTEM,
                    occurred_at=datetime.now(UTC),
                )
                raise RuntimeError("effect rolled back")
        assert await app.db().fetch_value("SELECT count(*) FROM {{tables.fixture_effect}}") == 0
        assert await app.db().fetch_value("SELECT count(*) FROM {{tables.outbox_events}}") == 0
        async with app.db().transaction() as tx:
            await tx.execute("INSERT INTO {{tables.fixture_effect}} VALUES (2)")
            await producer.enqueue_refusal(
                tx,
                team_id=TEAM,
                payload=SECRET_USE,
                actor=SYSTEM,
                occurred_at=datetime.now(UTC),
            )
        row = await app.db().fetch_one("SELECT * FROM {{tables.outbox_events}}")
        event = verify(bytes(row["payload"]), row["signature"], team_id=TEAM)
        assert event.fields["producer"]["seq"] == 1
        assert event.fields["producer"]["installation_id"] == INSTALLATION
        assert await app.db().fetch_value("SELECT count(*) FROM {{tables.fixture_effect}}") == 1
    assert app.connected_db() is None


@pytest.mark.parametrize("allow_private", [False, True])
async def test_runtime_lifespan_drains_through_one_resolver_and_guarded_real_tls(
    tmp_path,
    test_db_factory,
    target,
    allow_private,
):
    db = await test_db_factory.create_db(suffix="runtime_hook_drain")
    app = runtime(
        tmp_path,
        database_url=db.config.get_dsn(),
        db_schema=db.config.schema_name,
        egress=target.egress() if allow_private else target.egress(AddressPolicy()),
        internal=ip_network(f"{target.host}/32") if allow_private else None,
    )
    source = app.hook_resolver()
    calls = []

    async def registrations(team_id, catalog_id, catalog_version, hook):
        calls.append((team_id, catalog_id, catalog_version, hook))
        registration = target.registration()
        return Resolution(
            team_id=team_id,
            server_url="https://coord.example.com",
            items=(
                HookBinding(
                    binding_id=UUID(registration.binding_id),
                    kind="registration",
                    app_id="logs",
                    installation_id=str(uuid4()),
                    generation=1,
                    origin=registration.origin,
                    method=registration.method,
                    path=registration.path,
                    digest="sha256:" + "ab" * 32,
                    active_from=registration.active_from,
                ),
            ),
            fresh_until=time.monotonic() + 60,
            as_of=datetime.now(UTC),
            max_age_seconds=60,
        )

    source.registrations = registrations
    target.replies = [(200, {"event_id": "", "disposition": "appended"})]
    server = FastAPI(lifespan=app.lifespan)
    before = asyncio.all_tasks()
    async with server.router.lifespan_context(server):
        producer = app.hook_producer(installation_id=INSTALLATION, generation=2)
        async with app.db().transaction() as tx:
            event_id = await producer.enqueue_refusal(
                tx,
                team_id=TEAM,
                payload=SECRET_USE,
                actor=SYSTEM,
                occurred_at=datetime.now(UTC),
            )
        async with asyncio.timeout(5):
            while True:
                delivery = await app.db().fetch_one(
                    "SELECT state, attempts FROM {{tables.outbox_deliveries}} WHERE event_id=$1",
                    event_id,
                )
                if delivery is not None and delivery["attempts"] > 0:
                    break
                await asyncio.sleep(0.01)
        if allow_private:
            assert delivery["state"] == "delivered"
            assert target.verified == [str(event_id)]
            assert target.refusals == []
        else:
            assert delivery["state"] != "delivered"
            assert target.tls.seen == []
        assert calls and all(call == (TEAM, "aweb.hooks", 1, SECRET_HOOK) for call in calls)
        assert app.hook_registrations()._resolver is source
    # The runtime owns and joins its background drain before disconnecting.
    assert app.connected_db() is None
    assert not {task for task in asyncio.all_tasks() - before if not task.done()}


async def test_enqueue_failure_rolls_back_the_callers_effect(tmp_path, test_db_factory):
    db = await test_db_factory.create_db(suffix="runtime_hook_rollback")
    app = runtime(tmp_path, database_url=db.config.get_dsn(), db_schema=db.config.schema_name)
    server = FastAPI(lifespan=app.lifespan)
    async with server.router.lifespan_context(server):
        producer = app.hook_producer(installation_id=INSTALLATION, generation=2)
        with pytest.raises(ValueError):
            async with app.db().transaction() as tx:
                await tx.execute("INSERT INTO {{tables.fixture_effect}} VALUES (3)")
                await producer.enqueue_refusal(
                    tx,
                    team_id=TEAM,
                    payload=SECRET_USE,
                    actor={"authority_mode": "system"},
                    occurred_at=datetime.now(UTC),
                )
        assert await app.db().fetch_value("SELECT count(*) FROM {{tables.fixture_effect}}") == 0
        assert await app.db().fetch_value("SELECT count(*) FROM {{tables.outbox_events}}") == 0


@pytest.mark.parametrize(
    "mapping",
    [
        {"unknown": "post-secret-use-hook"},
        {"create": "post-command-hook"},
        {"create": "post-governance-hook"},
    ],
)
def test_specific_hook_mapping_must_name_a_declared_tool_and_specific_production(tmp_path, mapping):
    with pytest.raises(AppKeyError, match="hook_tool_effects"):
        runtime(tmp_path, hook_tool_effects=mapping)
