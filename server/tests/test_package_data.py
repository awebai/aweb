"""Packaging + final-schema assertions for the canonical aweb migration set.

The current line is a reset-only rebaseline: aapm.6 and the aapq
team-and-contacts correction are consolidated into `001_initial.sql`.
The single baseline is intentional for the pre-distribution hosted reset;
normal future product migrations must be added as ordered forward files.
"""

from importlib.resources import files
from pathlib import Path
import shutil
import subprocess
import tarfile
import tomllib
import zipfile

import pytest
from pgdbm.errors import QueryError
from packaging.requirements import Requirement
from packaging.version import Version


AWEB_MIGRATIONS = files("aweb") / "migrations" / "aweb"
AWID_ENCRYPTION_KEY_API_VERSION = Version("0.5.9")
MCP_FASTMCP_API_VERSION = Version("1.26.0")
MCP_INCOMPATIBLE_API_VERSION = Version("2.0.0")


def test_defaults_migrations_and_reserved_app_ids_are_packaged():
    package_root = files("aweb")

    assert (package_root / "defaults" / "team_instructions.md").is_file()
    assert (package_root / "defaults" / "roles" / "backend.md").is_file()
    assert (AWEB_MIGRATIONS / "001_initial.sql").is_file()

    packaged_reserved = package_root / "data" / "reserved-app-ids-v1.json"
    source_reserved = (
        Path(__file__).resolve().parents[2]
        / "test-vectors"
        / "reserved-app-ids-v1.json"
    )
    assert packaged_reserved.is_file()
    assert packaged_reserved.read_text() == source_reserved.read_text()


def test_server_distributions_ship_reserved_app_ids_without_vector_copies(tmp_path):
    uv = shutil.which("uv")
    if uv is None:
        pytest.skip("uv is required to build the wheel for package-data inspection")

    server_root = Path(__file__).resolve().parents[1]
    subprocess.run(
        [uv, "build", "--out-dir", str(tmp_path)],
        cwd=server_root,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    wheels = list(tmp_path.glob("aweb-*.whl"))
    assert wheels
    with zipfile.ZipFile(wheels[0]) as wheel:
        names = wheel.namelist()
        assert "aweb/data/reserved-app-ids-v1.json" in names
        assert "aweb/migrations/__init__.py" in names
        for attachment_path in (
            "inbound_modes.py",
            "attachments.py",
            "attachment_service.py",
            "migrations/aweb/022_message_attachments.sql",
            "audit.py",
            "migrations/aweb/023_operator_audit.sql",
            "migrations/aweb/033_typed_chat_participants.sql",
            "identity_binding.py",
            "migrations/aweb/034_agent_identity_binding.sql",
            "migrations/aweb/037_contacts_only.sql",
            "migrations/aweb/041_native_send_ingress.sql",
            "human_kind.py",
            "human_kind_revalidation.py",
            "migrations/aweb/047_verified_human_kind.sql",
            "migrations/aweb/057_legacy_mail_index.sql",
        ):
            assert f"aweb/{attachment_path}" in names
        assert not any(
            "/docs/vectors/" in name or name.startswith("docs/vectors/")
            for name in names
        )

    sdists = list(tmp_path.glob("aweb-*.tar.gz"))
    assert sdists
    with tarfile.open(sdists[0]) as sdist:
        names = sdist.getnames()
        assert any(
            name.endswith("/src/aweb/data/reserved-app-ids-v1.json") for name in names
        )
        assert any(name.endswith("/src/aweb/migrations/__init__.py") for name in names)
        for attachment_path in (
            "inbound_modes.py",
            "attachments.py",
            "attachment_service.py",
            "migrations/aweb/022_message_attachments.sql",
            "audit.py",
            "migrations/aweb/023_operator_audit.sql",
            "migrations/aweb/033_typed_chat_participants.sql",
            "identity_binding.py",
            "migrations/aweb/034_agent_identity_binding.sql",
            "migrations/aweb/037_contacts_only.sql",
            "migrations/aweb/041_native_send_ingress.sql",
            "human_kind.py",
            "human_kind_revalidation.py",
            "migrations/aweb/047_verified_human_kind.sql",
            "migrations/aweb/057_legacy_mail_index.sql",
        ):
            assert any(name.endswith(f"/src/aweb/{attachment_path}") for name in names)
        assert not any("/docs/vectors/" in name for name in names)


def test_awid_service_floor_covers_encryption_key_api():
    """aapv requires awid.e2ee_keys, introduced with awid-service 0.5.9."""
    pyproject = tomllib.loads(
        (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text()
    )
    dependencies = pyproject["project"]["dependencies"]
    parsed_requirements = [Requirement(dep) for dep in dependencies]
    awid_req = next(
        (req for req in parsed_requirements if req.name == "awid-service"), None
    )
    assert awid_req is not None
    lower_bounds = [
        Version(specifier.version)
        for specifier in awid_req.specifier
        if specifier.operator in {">=", "==", "~="}
    ]
    assert lower_bounds
    assert max(lower_bounds) >= AWID_ENCRYPTION_KEY_API_VERSION


def test_mcp_dependency_excludes_api_incompatible_v2():
    pyproject = tomllib.loads(
        (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text()
    )
    dependencies = pyproject["project"]["dependencies"]
    mcp_req = next(
        Requirement(dep) for dep in dependencies if Requirement(dep).name == "mcp"
    )

    assert MCP_FASTMCP_API_VERSION in mcp_req.specifier
    assert MCP_INCOMPATIBLE_API_VERSION not in mcp_req.specifier


# The migration files main has shipped. pgdbm keys its receipts by file
# name, so a shipped file is never renamed, removed or reordered, and the
# reset-only baseline stays 001.
SHIPPED_MIGRATIONS = (
    "001_initial.sql",
    "002_agent_encryption_keys.sql",
    "003_messages_encrypted_v2.sql",
    "004_chat_messages_encrypted_v2.sql",
    "005_messages_encrypted_v2_shape_legacy_fields.sql",
    "006_chat_participants_left_at.sql",
    "007_agent_encryption_key_custody.sql",
    "008_app_registry_grants.sql",
    "009_app_events.sql",
    "010_session_admission_leases.sql",
    "010a_chat_message_reads_orphan_guard.sql",
    "011_chat_message_reads.sql",
    "012_chat_message_reads_orphan_backfill.sql",
    "013_lifecycle_side_effect_outbox.sql",
    "014_federation_authority.sql",
    "015_federation_delivery_policy.sql",
    "016_identity_session_grants.sql",
    "017_agents_certificate_id.sql",
    "018_identity_grant_liveness.sql",
    "019_chat_participant_lookup.sql",
    "020_agent_status_hosts.sql",
    "021_agent_status.sql",
    "022_message_attachments.sql",
    "023_operator_audit.sql",
    "024_team_app_emit_keys.sql",
    "025_team_scoped_app_origin.sql",
    "026_team_app_event_types.sql",
    "027_team_app_keys.sql",
    "028_team_app_install_bytes.sql",
    "032_app_hook_bindings.sql",
    "033_typed_chat_participants.sql",
    "034_agent_identity_binding.sql",
    "035_team_app_installation_identity.sql",
    "036_app_installation_management.sql",
    "037_contacts_only.sql",
    "038_task_revisions.sql",
    "039_app_task_requests.sql",
    "040_task_answer_stages.sql",
    "041_native_send_ingress.sql",
    "042_message_id_chains.sql",
    "043_team_room.sql",
    "044_room_post_notices.sql",
    "045_canonical_participant_dids.sql",
    "046_local_human_succession.sql",
    "047_verified_human_kind.sql",
    "048_chat_session_seq.sql",
    "049_dead_row_indexes.sql",
    "050_one_active_team_document.sql",
    "051_team_key_pin_act.sql",
    "052_member_accepted_team_key.sql",
    "053_drop_retired_signer.sql",
    "055_chat_conversation_coverage.sql",
    "056_inbound_mode_default.sql",
    "057_legacy_mail_index.sql",
)


def test_shipped_migrations_stay_and_new_ones_only_append():
    """New product schema changes are forward migrations after the shipped
    chain, never edits or insertions into it."""
    sql_files = sorted(
        p.name for p in AWEB_MIGRATIONS.iterdir() if p.name.endswith(".sql")
    )
    assert sql_files[: len(SHIPPED_MIGRATIONS)] == list(SHIPPED_MIGRATIONS)
    assert all(
        name > SHIPPED_MIGRATIONS[-1] for name in sql_files[len(SHIPPED_MIGRATIONS) :]
    )


@pytest.mark.asyncio
async def test_agents_table_accepts_strict_contacts_only_after_forward_migration(
    aweb_cloud_db,
):
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'Backend', 'did:key:team')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (team_id, did_key, did_aw, address, alias, identity_scope, inbound_mode)
        VALUES ('backend:acme.com', 'did:key:alice', 'did:aw:alice', 'acme.com/alice', 'alice', 'global', 'team_and_contacts')
        """
    )

    await aweb_cloud_db.aweb_db.execute(
        "UPDATE {{tables.agents}} SET inbound_mode = 'contacts_only' WHERE alias = 'alice'"
    )


@pytest.mark.asyncio
async def test_contacts_only_forward_migration_preserves_legacy_rows(
    shared_test_pool, tmp_path
):
    from tests.product_migration_support import stage_aweb_upgrade

    async with stage_aweb_upgrade(
        shared_test_pool, tmp_path / "contacts-policy", "037_contacts_only.sql"
    ) as upgrade:
        manager = upgrade.infra.get_manager()
        # Reproduce an older database that allowed the legacy spelling.
        await manager.execute(
            "ALTER TABLE {{tables.agents}} DROP CONSTRAINT agents_inbound_mode_valid"
        )
        await manager.execute("""
            ALTER TABLE {{tables.agents}} ADD CONSTRAINT agents_inbound_mode_valid
            CHECK (inbound_mode IS NULL OR inbound_mode IN ('open', 'team_and_contacts', 'contacts_only'))
        """)
        await manager.execute("""
            INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
            VALUES ('default:legacy.example', 'legacy.example', 'default', 'did:key:team')
        """)
        for alias, mode in [
            ("legacy", "contacts_only"),
            ("team", "team_and_contacts"),
            ("all", "open"),
            ("unset", None),
        ]:
            await manager.execute(
                """
                INSERT INTO {{tables.agents}} (team_id, alias, did_key, inbound_mode)
                VALUES ('default:legacy.example', $1, $2, $3)
            """,
                alias,
                f"did:key:{alias}",
                mode,
            )
        assert await upgrade.apply() == ["037_contacts_only.sql"]
        modes = await manager.fetch_all(
            "SELECT alias, inbound_mode FROM {{tables.agents}} ORDER BY alias"
        )
        assert {row["alias"]: row["inbound_mode"] for row in modes} == {
            "legacy": "team_and_contacts",
            "team": "team_and_contacts",
            "all": "open",
            "unset": None,
        }
        await manager.execute(
            "UPDATE {{tables.agents}} SET inbound_mode = 'contacts_only' WHERE alias = 'legacy'"
        )
        with pytest.raises(QueryError):
            await manager.execute(
                "UPDATE {{tables.agents}} SET inbound_mode = 'unknown' WHERE alias = 'legacy'"
            )
