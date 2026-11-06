"""Owner-defined job pins, safe argument slots and one CURRENT registry."""

from __future__ import annotations

import copy
from collections.abc import AsyncIterator

import pytest
from pgdbm import AsyncDatabaseManager

from aweb_secrets.jobs import (
    JobDefinition,
    JobInvalid,
    JobRefused,
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
        "env": {"DB_ADMIN": {"$credential": "db-admin", "field": "value"}},
        "cwd": "/srv/backup",
        "timeout_s": 60,
        "output": {"max_bytes": 4096, "projection": ["/exit_code"]},
        "params": {"database": {"schema": {"type": "string", "maxLength": 32}, "charset": None}},
        "credentials": [{"secret_ref": "db-admin", "delivery": "durable", "mint": None}],
        "allow_durable": True,
    }


@pytest.mark.parametrize(
    "fields",
    [
        ["value"],
        ["username"],
        ["password"],
        ["username", "password", "password"],
        ["client_id", "client_secret"],
        ["client_secret"],
        ["access_key_id", "secret_access_key", "session_token"],
        ["session_token"],
    ],
)
def test_credential_env_fields_select_one_whole_mapping_family(fields):
    body = after()
    body["env"] = {
        "CRED_" + str(i): {"$credential": "db-admin", "field": field}
        for i, field in enumerate(fields)
    }
    job = JobDefinition.from_after(body)
    assert job.after["env"] == body["env"]


@pytest.mark.parametrize(
    "binding",
    [
        {"$credential": "db-admin"},
        {"$credential": "db-admin", "field": "token"},
        {"$credential": "db-admin", "field": ""},
        {"$credential": "db-admin", "field": None},
        {"$credential": "db-admin", "field": ["value"]},
        {"$credential": "db-admin", "field": "value", "default": ""},
        {"$credential": "unknown", "field": "value"},
    ],
)
def test_credential_env_fields_refuse_implicit_unknown_or_extended_bindings(binding):
    body = after()
    body["env"] = {"DB_ADMIN": binding}
    with pytest.raises(JobInvalid):
        JobDefinition.from_after(body)


@pytest.mark.parametrize("fields", [["value", "password"], ["client_id", "access_key_id"]])
def test_credential_slot_cannot_mix_decoder_families(fields):
    body = after()
    body["env"] = {
        "CRED_" + str(i): {"$credential": "db-admin", "field": field}
        for i, field in enumerate(fields)
    }
    with pytest.raises(JobInvalid):
        JobDefinition.from_after(body)


def test_different_credential_slots_can_select_different_families():
    body = after()
    body["credentials"].append({"secret_ref": "other", "delivery": "durable", "mint": None})
    body["env"] = {
        "DB_ADMIN": {"$credential": "db-admin", "field": "password"},
        "API_KEY": {"$credential": "other", "field": "value"},
    }
    first = JobDefinition.from_after(body)
    body["env"]["DB_ADMIN"]["field"] = "username"
    second = JobDefinition.from_after(body)
    assert second.digest != first.digest
    assert first.after["env"]["DB_ADMIN"]["field"] == "password"


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
    body["env"] = {name: {"$credential": "db-admin", "field": "value"}}
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
    body["env"] = {"DB_ADMIN": {"$credential": "other-secret", "field": "value"}}
    with pytest.raises(JobInvalid):
        JobDefinition.from_after(body)


def oci_after():
    body = after()
    body.update(
        kind="oci",
        exec=None,
        oci={
            "image": "registry.example/backup@sha256:" + "b" * 64,
            "read_only_paths": ["/srv/config"],
        },
    )
    body["argv"].insert(0, "/usr/bin/backup")
    return body


def test_oci_requires_a_digest_and_only_declared_readonly_paths():
    body = oci_after()
    JobDefinition.from_after(body)
    body["oci"]["image"] = "registry.example/backup:latest"
    with pytest.raises(JobInvalid):
        JobDefinition.from_after(body)


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["backup"],
        [""],
        ["--"],
        ["/usr/../bin/backup"],
        [{"$param": "database", "slot": "positional"}],
    ],
)
def test_oci_argv_requires_its_own_fixed_absolute_executable(argv):
    body = oci_after()
    body["argv"] = argv
    # Keep the declared parameter used independently of argv, so an absent
    # executable cannot be refused merely as an unused-parameter side effect.
    body["env"]["DATABASE"] = {"$param": "database"}
    with pytest.raises(JobInvalid):
        JobDefinition.from_after(body)


def test_oci_command_is_pinned_without_rewriting_exec_argument_semantics():
    body = oci_after()
    first = JobDefinition.from_after(body)
    assert first.after["argv"] == body["argv"]
    assert first.params_valid({"database": "orders"})
    body["argv"][0] = "/opt/backup"
    edited = JobDefinition.from_after(body)
    assert edited.digest != first.digest
    assert first.after["argv"][0] == "/usr/bin/backup"
    # Exec argv remains arguments only: exec.path supplies its executable.
    ordinary = after()
    assert JobDefinition.from_after(ordinary).after["argv"][0] == "--"
    ordinary["argv"] = []
    ordinary["params"] = {}
    assert JobDefinition.from_after(ordinary).after["argv"] == []


def test_oci_change_draft_never_inherits_an_image_executable():
    from aweb_secrets.change import ChangeRefused, validate_change
    from tests.test_change_records import _change

    body = oci_after()
    validate_change(_change({"kind": "job", "op": "create", "ref": body["job_id"], "after": body}))
    body["argv"] = []
    body["params"] = {}
    with pytest.raises(ChangeRefused):
        validate_change(
            _change({"kind": "job", "op": "create", "ref": body["job_id"], "after": body})
        )
    assert body["argv"] == []


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


@pytest.mark.parametrize("refs", [["db-admin"], ["root-admin"], ["fresh-child"]])
def test_durable_descendant_substitution_returns_the_unique_slot(refs):
    from aweb_secrets.jobs import unique_durable_slot

    body = after()
    body["credentials"][0]["secret_ref"] = refs[0]
    body["env"] = {"DB_ADMIN": {"$credential": refs[0], "field": "value"}}
    job = JobDefinition.from_after(body)
    assert unique_durable_slot(job, lineage_refs=["root-admin", "db-admin", "fresh-child"]) == 0


def test_two_matching_ancestors_and_exact_child_plus_ancestor_are_ambiguous():
    from aweb_secrets.jobs import JobRefused, unique_durable_slot

    for selectors in [["root-admin", "db-admin"], ["root-admin", "fresh-child"]]:
        body = after()
        body["credentials"] = [
            {"secret_ref": ref, "delivery": "durable", "mint": None} for ref in selectors
        ]
        body["env"] = {
            "CRED_" + str(i): {"$credential": ref, "field": "value"}
            for i, ref in enumerate(selectors)
        }
        job = JobDefinition.from_after(body)
        with pytest.raises(JobRefused) as refused:
            unique_durable_slot(job, lineage_refs=["root-admin", "db-admin", "fresh-child"])
        assert refused.value.code == "job_not_allowed"


def test_unmatched_or_short_lived_slots_never_authorize_durable_substitution():
    from aweb_secrets.jobs import JobRefused, unique_durable_slot

    body = after()
    body["credentials"][0].update(
        delivery="short_lived",
        mint={"operation_id": "mint-session", "digest": "c" * 64, "params": {}},
    )
    job = JobDefinition.from_after(body)
    with pytest.raises(JobRefused) as refused:
        unique_durable_slot(job, lineage_refs=["db-admin", "fresh-child"])
    assert refused.value.code == "job_not_allowed"
    with pytest.raises(JobRefused) as refused:
        unique_durable_slot(
            JobDefinition.from_after(after()), lineage_refs=["unrelated", "fresh-child"]
        )
    assert refused.value.code == "job_not_allowed"


def test_unique_slot_keeps_other_slots_fixed_and_preserves_the_ordinal():
    from aweb_secrets.jobs import unique_durable_slot

    body = after()
    body["credentials"].insert(0, {"secret_ref": "unrelated", "delivery": "durable", "mint": None})
    body["env"]["OTHER_ADMIN"] = {"$credential": "unrelated", "field": "value"}
    job = JobDefinition.from_after(body)
    assert unique_durable_slot(job, lineage_refs=["db-admin", "fresh-child"]) == 1
    assert job.after == body


@pytest.mark.parametrize(
    "name",
    [
        "PATH",
        "GIT_SSH_COMMAND",
        "NODE_PATH",
        "PERL5LIB",
        "PERLLIB",
        "RUBYLIB",
        "PYTHONHOME",
        "PYTHONBREAKPOINT",
        "CLASSPATH",
        "GCONV_PATH",
        "BASHOPTS",
        "SHELLOPTS",
        "PS4",
        "PROMPT_COMMAND",
        "HTTP_PROXY",
        "https_proxy",
        "NO_PROXY",
    ],
)
def test_additional_loader_and_proxy_env_names_are_refused_for_all_values(name):
    for value in [
        "fixed-owner-value",
        {"$param": "database"},
        {"$credential": "db-admin", "field": "value"},
    ]:
        body = after()
        body["env"][name] = value
        with pytest.raises(JobInvalid):
            JobDefinition.from_after(body)


def test_option_with_attached_value_cannot_take_a_parameter_as_another_argument():
    body = after()
    body["argv"] = ["--database=orders", {"$param": "database", "slot": "option_value"}]
    with pytest.raises(JobInvalid):
        JobDefinition.from_after(body)
    body["argv"][0] = "--database"
    assert JobDefinition.from_after(body).params_valid({"database": "-x"})


@pytest.mark.parametrize(
    "path", ["/", "//etc", "/etc/", "/etc//config", "/etc/./config", "/etc/../config"]
)
def test_oci_mount_paths_are_normalized_nonroot_paths(path):
    body = oci_after()
    body["oci"]["read_only_paths"] = [path]
    with pytest.raises(JobInvalid):
        JobDefinition.from_after(body)
    body["oci"]["read_only_paths"] = ["/etc/config"]
    JobDefinition.from_after(body)


def test_job_timeout_has_an_exported_bound_for_dispatch_sweeping():
    from aweb_secrets.jobs import MAX_TIMEOUT_S

    body = after()
    body["timeout_s"] = MAX_TIMEOUT_S
    JobDefinition.from_after(body)
    body["timeout_s"] += 1
    with pytest.raises(JobInvalid):
        JobDefinition.from_after(body)


@pytest.mark.parametrize("field", ["cwd", "output", "env", "params", "credentials"])
def test_nul_is_refused_in_all_record_strings_before_jsonb(field):
    body = after()
    if field == "cwd":
        body["cwd"] = "/tmp/\0"
    elif field == "output":
        body["output"]["projection"] = ["/bad\0field"]
    elif field == "env":
        body["env"]["VISIBLE"] = "bad\0value"
    elif field == "params":
        body["params"]["database"]["schema"]["enum"] = ["bad\0value"]
    else:
        body["credentials"][0].update(
            delivery="short_lived",
            mint={
                "operation_id": "mint-session",
                "digest": "c" * 64,
                "params": {"argument": {"value": "bad\0value"}},
            },
        )
    with pytest.raises(JobInvalid):
        JobDefinition.from_after(body)


def _mapping_job_and_parameter_source(mapping):
    from aweb_secrets.operation import OperationTemplate
    from tests.test_change_records import OPERATION

    source = OperationTemplate.from_after(copy.deepcopy(OPERATION))
    body = after()
    body["credentials"][0].update(
        delivery="short_lived",
        mint={
            "operation_id": source.operation_id,
            "digest": source.digest,
            "params": {"charge": mapping},
        },
    )
    return JobDefinition.from_after(body), source


def test_mint_mapping_checks_literal_constraints_and_matching_reference_types():
    job, source = _mapping_job_and_parameter_source({"value": "orders"})
    job.validate_mint_mapping(0, source)
    for literal in ["x", "+invalid", 600, False]:
        job, source = _mapping_job_and_parameter_source({"value": literal})
        with pytest.raises(JobRefused) as refused:
            job.validate_mint_mapping(0, source)
        assert refused.value.code == "params_invalid"
    job, source = _mapping_job_and_parameter_source({"$param": "database"})
    job.validate_mint_mapping(0, source)
    body = job.after
    body["params"]["database"]["schema"] = {"type": "integer", "minimum": 1, "maximum": 10}
    with pytest.raises(JobRefused) as refused:
        JobDefinition.from_after(body).validate_mint_mapping(0, source)
    assert refused.value.code == "params_invalid"


def test_mint_mapping_has_exact_issuer_parameter_coverage_and_pin():
    job, source = _mapping_job_and_parameter_source({"$param": "database"})
    for params in [{}, {"charge": {"value": "orders"}, "unknown": {"value": "orders"}}]:
        body = job.after
        body["credentials"][0]["mint"]["params"] = params
        with pytest.raises(JobRefused) as refused:
            JobDefinition.from_after(body).validate_mint_mapping(0, source)
        assert refused.value.code == "params_invalid"
    body = job.after
    body["credentials"][0]["mint"]["digest"] = "d" * 64
    with pytest.raises(JobRefused) as refused:
        JobDefinition.from_after(body).validate_mint_mapping(0, source)
    assert refused.value.code == "operation_not_allowed"


def test_matching_mint_parameter_types_still_require_actual_issuer_validation():
    job, source = _mapping_job_and_parameter_source({"$param": "database"})
    job.validate_mint_mapping(0, source)
    expanded = job.expand_mint_params(0, {"database": "+invalid"})
    assert not source.params_valid(expanded)
    assert source.params_valid(job.expand_mint_params(0, {"database": "orders"}))
