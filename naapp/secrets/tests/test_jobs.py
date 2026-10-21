"""Owner-defined job pins, safe argument slots and one CURRENT registry."""

from __future__ import annotations

import copy
from collections.abc import AsyncIterator

import pytest
from pgdbm import AsyncDatabaseManager

from aweb_secrets.jobs import (
    JobDefinition,
    JobInvalid,
    apply_job_migrations,
    create_job,
    current_job,
    job_by_digest,
)
from aweb_secrets.runners import mint_runner_id


def after():
    return {
        "v": 1,
        "job_id": "nightly-backup",
        "runner_ids": [mint_runner_id()],
        "kind": "exec",
        "exec": {"path": "/usr/local/bin/backup", "sha256": "a" * 64, "files": []},
        "oci": None,
        "argv": ["--", {"$param": "database", "slot": "positional"}],
        "env": {"DB_ADMIN": {"$credential": "db-admin"}},
        "cwd": "/srv/backup",
        "timeout_s": 60,
        "output": {"max_bytes": 4096, "projection": ["/exit_code"]},
        "params": {"database": {"schema": {"type": "string", "maxLength": 32}, "charset": None}},
        "credentials": [{"secret_ref": "db-admin", "delivery": "durable", "mint": None}],
        "allow_durable": True,
    }


def test_positional_and_option_value_have_different_leading_dash_boundaries():
    body = after()
    job = JobDefinition.from_after(body)
    assert job.params_valid({"database": "orders"})
    assert not job.params_valid({"database": "-oProxyCommand=bad"})
    body["argv"] = ["--database", {"$param": "database", "slot": "option_value"}]
    assert JobDefinition.from_after(body).params_valid({"database": "-x"})
    body["argv"] = [{"$param": "database", "slot": "option_value"}]
    with pytest.raises(JobInvalid):
        JobDefinition.from_after(body)


@pytest.mark.parametrize(
    "name",
    [
        "LD_PRELOAD",
        "DYLD_INSERT_LIBRARIES",
        "PATH",
        "GIT_SSH_COMMAND",
        "NODE_OPTIONS",
        "PYTHONPATH",
        "ENV",
        "IFS",
    ],
)
def test_code_loading_env_targets_are_refused(name):
    body = after()
    body["env"] = {name: {"$credential": "db-admin"}}
    with pytest.raises(JobInvalid):
        JobDefinition.from_after(body)


def test_durable_flag_and_all_template_references_are_checked():
    body = after()
    body["allow_durable"] = False
    with pytest.raises(JobInvalid):
        JobDefinition.from_after(body)
    body = after()
    body["argv"] = [{"$param": "database", "slot": "positional"}]
    with pytest.raises(JobInvalid):
        JobDefinition.from_after(body)
    body = after()
    body["env"] = {"DB_ADMIN": {"$credential": "other-secret"}}
    with pytest.raises(JobInvalid):
        JobDefinition.from_after(body)


def test_oci_requires_a_digest_and_only_declared_readonly_paths():
    body = after()
    body.update(
        kind="oci",
        exec=None,
        oci={
            "image": "registry.example/backup@sha256:" + "b" * 64,
            "read_only_paths": ["/srv/config"],
        },
    )
    JobDefinition.from_after(body)
    body["oci"]["image"] = "registry.example/backup:latest"
    with pytest.raises(JobInvalid):
        JobDefinition.from_after(body)


@pytest.fixture
async def db(test_db_factory) -> AsyncIterator[AsyncDatabaseManager]:
    database = await test_db_factory.create_db(suffix="jobs")
    await apply_job_migrations(database)
    yield database


async def test_current_pin_is_installation_scoped_and_old_definition_is_immutable(db):
    first = JobDefinition.from_after(after())
    edited = copy.deepcopy(dict(first.after))
    edited["timeout_s"] = 61
    second = JobDefinition.from_after(edited)
    assert first.digest != second.digest
    async with db.transaction() as tx:
        await create_job(tx, "install-one", "team:acme.test", first)
        await create_job(tx, "install-one", "team:acme.test", second)
        assert (await current_job(tx, "install-one", first.job_id)).digest == second.digest
        assert (
            await job_by_digest(tx, "install-one", first.job_id, first.digest)
        ).after == first.after
        assert await current_job(tx, "install-two", first.job_id) is None
        assert await job_by_digest(tx, "install-two", first.job_id, first.digest) is None


def test_job_snapshot_does_not_change_when_input_or_returned_mapping_is_edited():
    body = after()
    job = JobDefinition.from_after(body)
    digest = job.digest
    body["exec"]["path"] = "/other"
    returned = job.after
    returned["exec"]["path"] = "/also-other"
    assert job.digest == digest
    assert job.after["exec"]["path"] == "/usr/local/bin/backup"


@pytest.mark.parametrize("value", [float("nan"), 2**53, "\ud800", {"nested": "object"}, True])
def test_job_string_parameter_refuses_values_outside_its_schema_or_json_domain(value):
    assert not JobDefinition.from_after(after()).params_valid({"database": value})


async def test_job_write_rolls_back_immutable_definition_and_current_pointer_together(db):
    job = JobDefinition.from_after(after())
    with pytest.raises(RuntimeError):
        async with db.transaction() as tx:
            await create_job(tx, "install-one", "team:acme.test", job)
            raise RuntimeError("failed confirmation")
    async with db.transaction() as tx:
        assert await current_job(tx, "install-one", job.job_id) is None
        assert await job_by_digest(tx, "install-one", job.job_id, job.digest) is None


def test_short_lived_recipe_is_explicit_and_maps_only_declared_job_params():
    body = after()
    body["allow_durable"] = False
    body["credentials"] = [
        {
            "secret_ref": "db-admin",
            "delivery": "short_lived",
            "mint": {
                "operation_id": "mint-session",
                "digest": "c" * 64,
                "params": {"db": {"$param": "database"}, "ttl": {"value": 600}},
            },
        }
    ]
    JobDefinition.from_after(body)
    body["credentials"][0]["mint"]["params"]["db"] = {"$param": "unknown"}
    with pytest.raises(JobInvalid):
        JobDefinition.from_after(body)
    body["credentials"][0]["mint"] = None
    with pytest.raises(JobInvalid):
        JobDefinition.from_after(body)


def test_durable_recipe_is_null_and_no_unapproved_mint_is_inferred():
    body = after()
    body["credentials"][0]["mint"] = {
        "operation_id": "mint-session",
        "digest": "c" * 64,
        "params": {},
    }
    with pytest.raises(JobInvalid):
        JobDefinition.from_after(body)


async def test_current_job_pin_refuses_history_after_an_edit(db):
    from aweb_secrets.jobs import JobRefused, resolve_job_pin

    first = JobDefinition.from_after(after())
    revised = first.after
    revised["timeout_s"] += 1
    second = JobDefinition.from_after(revised)
    async with db.transaction() as tx:
        await create_job(tx, "install-one", "team:acme.test", first)
        assert (
            await resolve_job_pin(tx, "install-one", first.job_id, first.digest)
        ).digest == first.digest
        await create_job(tx, "install-one", "team:acme.test", second)
        with pytest.raises(JobRefused) as refused:
            await resolve_job_pin(tx, "install-one", first.job_id, first.digest)
        assert refused.value.code == "job_not_allowed"
        assert (
            await resolve_job_pin(tx, "install-one", first.job_id, second.digest)
        ).digest == second.digest


async def test_job_definition_row_is_immutable_in_postgresql(db):
    import asyncpg

    job = JobDefinition.from_after(after())
    async with db.transaction() as tx:
        await create_job(tx, "install-one", "team:acme.test", job)
    from pgdbm.errors import QueryError

    with pytest.raises(QueryError) as refused:
        await db.execute(
            "UPDATE {{tables.job_definitions}} SET record=record WHERE installation_id=$1",
            "install-one",
        )
    assert isinstance(refused.value.__cause__, asyncpg.RaiseError)


def test_job_after_shape_binds_ref_and_expands_mint_without_coercion():
    from aweb_secrets.change import ChangeRefused, validate_change
    from tests.test_change_records import _change

    body = after()
    body["credentials"] = [
        {
            "secret_ref": "db-admin",
            "delivery": "short_lived",
            "mint": {
                "operation_id": "mint-session",
                "digest": "c" * 64,
                "params": {"database": {"$param": "database"}, "ttl": {"value": 600}},
            },
        }
    ]
    job = JobDefinition.from_after(body)
    draft = _change({"kind": "job", "op": "create", "ref": job.job_id, "after": job.after})
    validate_change(draft)
    assert job.expand_mint_params(0, {"database": "orders"}) == {"database": "orders", "ttl": 600}
    draft["changes"][0]["ref"] = "other-job"
    with pytest.raises(ChangeRefused):
        validate_change(draft)
