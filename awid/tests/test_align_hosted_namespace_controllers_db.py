from __future__ import annotations

import hashlib
import json
import stat
from pathlib import Path

import asyncpg
import pytest
import pytest_asyncio

from scripts import align_hosted_namespace_controllers_db as alignment


PARENT_DID = "did:key:z6Mkgpop9yzY4dK8MA8CgUZevCsNxsAWP4ThHTASKkZsEuVn"
OLD_DID = "did:key:z6Mkkdd8WrwRrvn8QmHxcFnbXPHgkCUqpYVqRkuSgPKmTqHg"


def _canonical(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode()


def _manifest_value(count: int) -> dict:
    domains = sorted(f"tenant-{index:03d}.aweb.ai" for index in range(count))
    return {
        "schema_version": 1,
        "base_domain": "aweb.ai",
        "expected_count": count,
        "target_controller_did": PARENT_DID,
        "targets": [
            {
                "domain": domain,
                "expected_old_controller_did": OLD_DID,
                "new_controller_did": PARENT_DID,
            }
            for domain in domains
        ],
    }


def _write_manifest(path: Path, count: int) -> tuple[alignment.Manifest, str]:
    raw = _canonical(_manifest_value(count))
    path.write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    manifest = alignment.load_manifest(
        path,
        required_sha256=digest,
        required_count=count,
        required_parent_controller_did=PARENT_DID,
    )
    return manifest, digest


@pytest_asyncio.fixture
async def alignment_database(test_db_factory):
    database = await test_db_factory.create_db(suffix="controller_alignment")
    database_url = database.config.get_dsn()
    connection = await asyncpg.connect(database_url)
    await connection.execute(
        """
        CREATE SCHEMA awid;
        CREATE TABLE awid.dns_namespaces (
            namespace_id uuid PRIMARY KEY,
            domain text NOT NULL,
            controller_did text,
            verification_status text NOT NULL,
            last_verified_at timestamptz,
            created_at timestamptz NOT NULL DEFAULT now(),
            deleted_at timestamptz,
            scope_id uuid,
            default_delivery_origin text
        );
        CREATE UNIQUE INDEX dns_namespaces_active_domain
            ON awid.dns_namespaces(domain) WHERE deleted_at IS NULL;
        """
    )
    try:
        yield database_url, connection
    finally:
        await connection.close()


async def _seed(connection: asyncpg.Connection, count: int) -> None:
    await connection.execute(
        """
        INSERT INTO awid.dns_namespaces
            (namespace_id, domain, controller_did, verification_status,
             last_verified_at, scope_id, default_delivery_origin)
        VALUES
            ('00000000-0000-0000-0000-000000000001', 'aweb.ai', $1,
             'verified', '2026-08-27T12:00:00Z', NULL, 'https://aweb.ai')
        """,
        PARENT_DID,
    )
    await connection.executemany(
        """
        INSERT INTO awid.dns_namespaces
            (namespace_id, domain, controller_did, verification_status,
             last_verified_at, scope_id, default_delivery_origin)
        VALUES ($1::uuid, $2, $3, 'verified', '2026-08-27T12:00:00Z',
                $1::uuid, 'https://aweb.ai')
        """,
        [
            (f"00000000-0000-0000-0001-{index:012d}", domain, OLD_DID)
            for index, domain in enumerate(
                sorted(f"tenant-{item:03d}.aweb.ai" for item in range(count)),
                start=1,
            )
        ],
    )


def test_manifest_requires_exact_canonical_reviewed_bytes(tmp_path: Path) -> None:
    path = tmp_path / "manifest.json"
    value = _manifest_value(2)
    raw = json.dumps(value, indent=2).encode() + b"\n"
    path.write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()

    with pytest.raises(alignment.AlignmentError, match="not canonical JSON"):
        alignment.load_manifest(
            path,
            required_sha256=digest,
            required_count=2,
            required_parent_controller_did=PARENT_DID,
        )

    raw = _canonical(value)
    path.write_bytes(raw)
    with pytest.raises(alignment.AlignmentError, match="SHA-256 mismatch"):
        alignment.load_manifest(
            path,
            required_sha256="0" * 64,
            required_count=2,
            required_parent_controller_did=PARENT_DID,
        )

    value["targets"][0]["unexpected"] = True
    raw = _canonical(value)
    path.write_bytes(raw)
    with pytest.raises(alignment.AlignmentError, match="keys mismatch"):
        alignment.load_manifest(
            path,
            required_sha256=hashlib.sha256(raw).hexdigest(),
            required_count=2,
            required_parent_controller_did=PARENT_DID,
        )


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda value: value["targets"].reverse(), "sorted by domain"),
        (
            lambda value: value["targets"].__setitem__(
                1, dict(value["targets"][0])
            ),
            "unique",
        ),
        (
            lambda value: value["targets"][0].__setitem__(
                "domain", "nested.tenant.aweb.ai"
            ),
            "canonical direct child",
        ),
        (
            lambda value: value["targets"][0].__setitem__(
                "new_controller_did", OLD_DID
            ),
            "differs from parent DID",
        ),
    ],
)
def test_manifest_rejects_ambiguous_targets(tmp_path: Path, mutate, message: str) -> None:
    path = tmp_path / "manifest.json"
    value = _manifest_value(2)
    mutate(value)
    raw = _canonical(value)
    path.write_bytes(raw)

    with pytest.raises(alignment.AlignmentError, match=message):
        alignment.load_manifest(
            path,
            required_sha256=hashlib.sha256(raw).hexdigest(),
            required_count=2,
            required_parent_controller_did=PARENT_DID,
        )


@pytest.mark.asyncio
async def test_170_row_backup_apply_verify_retry_and_restore(
    alignment_database, tmp_path: Path
) -> None:
    database_url, connection = alignment_database
    await _seed(connection, 170)
    await connection.execute(
        """
        INSERT INTO awid.dns_namespaces
            (namespace_id, domain, controller_did, verification_status,
             last_verified_at, scope_id, default_delivery_origin)
        VALUES ('00000000-0000-0000-0002-000000000001',
                'unmanaged.aweb.ai', $1, 'verified',
                '2026-08-27T12:00:00Z', NULL, 'https://elsewhere.example')
        """,
        OLD_DID,
    )
    outside_before = await connection.fetchval(
        """
        SELECT row_to_json(n)::text FROM awid.dns_namespaces AS n
        WHERE domain = 'unmanaged.aweb.ai'
        """
    )
    manifest, _digest = _write_manifest(tmp_path / "manifest.json", 170)
    backup = tmp_path / "before.json"

    plan = await alignment.run_operation(
        command="plan",
        database_url=database_url,
        schema="awid",
        manifest=manifest,
    )
    assert plan["needs_alignment"] == 170

    backed_up = await alignment.run_operation(
        command="backup",
        database_url=database_url,
        schema="awid",
        manifest=manifest,
        backup_path=backup,
    )
    assert backed_up["needs_alignment"] == 170
    backup_sha256 = backed_up["backup_sha256"]
    assert backup_sha256 == hashlib.sha256(backup.read_bytes()).hexdigest()
    assert stat.S_IMODE(backup.stat().st_mode) == 0o600
    before_rows = json.loads(backup.read_text())["rows"]
    assert len(before_rows) == 170
    assert "namespace_id" in before_rows[0]
    assert "default_delivery_origin" in before_rows[0]

    with pytest.raises(FileExistsError):
        await alignment.run_operation(
            command="backup",
            database_url=database_url,
            schema="awid",
            manifest=manifest,
            backup_path=backup,
        )

    with pytest.raises(alignment.AlignmentError, match="backup SHA-256 mismatch"):
        await alignment.run_operation(
            command="apply",
            database_url=database_url,
            schema="awid",
            manifest=manifest,
            backup_path=backup,
            backup_sha256="0" * 64,
        )

    applied = await alignment.run_operation(
        command="apply",
        database_url=database_url,
        schema="awid",
        manifest=manifest,
        backup_path=backup,
        backup_sha256=backup_sha256,
    )
    assert applied["updated"] == 170
    assert applied["needs_alignment"] == 0
    assert await connection.fetchval(
        """
        SELECT row_to_json(n)::text FROM awid.dns_namespaces AS n
        WHERE domain = 'unmanaged.aweb.ai'
        """
    ) == outside_before

    retried = await alignment.run_operation(
        command="apply",
        database_url=database_url,
        schema="awid",
        manifest=manifest,
        backup_path=backup,
        backup_sha256=backup_sha256,
    )
    assert retried["updated"] == 0
    assert retried["needs_alignment"] == 0

    verified = await alignment.run_operation(
        command="verify",
        database_url=database_url,
        schema="awid",
        manifest=manifest,
    )
    assert verified["already_aligned"] == 170

    restored = await alignment.run_operation(
        command="restore",
        database_url=database_url,
        schema="awid",
        manifest=manifest,
        backup_path=backup,
        backup_sha256=backup_sha256,
    )
    assert restored["restored"] == 170
    rows = await connection.fetch(
        "SELECT controller_did FROM awid.dns_namespaces WHERE domain LIKE '%.aweb.ai'"
    )
    assert {row["controller_did"] for row in rows} == {OLD_DID}
    outside_after = await connection.fetchval(
        """
        SELECT row_to_json(n)::text FROM awid.dns_namespaces AS n
        WHERE domain = 'unmanaged.aweb.ai'
        """
    )
    assert outside_after == outside_before

    with pytest.raises(
        alignment.AlignmentError, match="restore requires current target controller"
    ):
        await alignment.run_operation(
            command="restore",
            database_url=database_url,
            schema="awid",
            manifest=manifest,
            backup_path=backup,
            backup_sha256=backup_sha256,
        )


@pytest.mark.asyncio
async def test_apply_rejects_mismatch_without_partial_update(
    alignment_database, tmp_path: Path
) -> None:
    database_url, connection = alignment_database
    await _seed(connection, 3)
    manifest, _digest = _write_manifest(tmp_path / "manifest.json", 3)
    backup = tmp_path / "before.json"
    backed_up = await alignment.run_operation(
        command="backup",
        database_url=database_url,
        schema="awid",
        manifest=manifest,
        backup_path=backup,
    )
    await connection.execute(
        """
        UPDATE awid.dns_namespaces
        SET default_delivery_origin = 'https://changed.example'
        WHERE domain = 'tenant-001.aweb.ai'
        """
    )

    with pytest.raises(alignment.AlignmentError, match="non-controller columns changed"):
        await alignment.run_operation(
            command="apply",
            database_url=database_url,
            schema="awid",
            manifest=manifest,
            backup_path=backup,
            backup_sha256=backed_up["backup_sha256"],
        )
    controllers = await connection.fetchval(
        """
        SELECT count(*) FROM awid.dns_namespaces
        WHERE domain LIKE '%.aweb.ai' AND controller_did = $1
        """,
        PARENT_DID,
    )
    assert controllers == 0


@pytest.mark.asyncio
async def test_failed_postcondition_rolls_back_every_controller(
    alignment_database, tmp_path: Path
) -> None:
    database_url, connection = alignment_database
    await _seed(connection, 3)
    manifest, _digest = _write_manifest(tmp_path / "manifest.json", 3)
    backup = tmp_path / "before.json"
    backed_up = await alignment.run_operation(
        command="backup",
        database_url=database_url,
        schema="awid",
        manifest=manifest,
        backup_path=backup,
    )
    await connection.execute(
        """
        CREATE FUNCTION awid.break_alignment_postcondition() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.domain = 'tenant-001.aweb.ai' THEN
                NEW.default_delivery_origin = 'https://triggered.example';
            END IF;
            RETURN NEW;
        END;
        $$;
        CREATE TRIGGER break_alignment_postcondition
        BEFORE UPDATE OF controller_did ON awid.dns_namespaces
        FOR EACH ROW EXECUTE FUNCTION awid.break_alignment_postcondition();
        """
    )

    with pytest.raises(alignment.AlignmentError, match="non-controller columns changed"):
        await alignment.run_operation(
            command="apply",
            database_url=database_url,
            schema="awid",
            manifest=manifest,
            backup_path=backup,
            backup_sha256=backed_up["backup_sha256"],
        )
    rows = await connection.fetch(
        """
        SELECT controller_did, default_delivery_origin
        FROM awid.dns_namespaces WHERE domain LIKE '%.aweb.ai'
        """
    )
    assert {row["controller_did"] for row in rows} == {OLD_DID}
    assert {row["default_delivery_origin"] for row in rows} == {"https://aweb.ai"}


@pytest.mark.asyncio
async def test_restore_refuses_unrelated_changes(
    alignment_database, tmp_path: Path
) -> None:
    database_url, connection = alignment_database
    await _seed(connection, 2)
    manifest, _digest = _write_manifest(tmp_path / "manifest.json", 2)
    backup = tmp_path / "before.json"
    backed_up = await alignment.run_operation(
        command="backup",
        database_url=database_url,
        schema="awid",
        manifest=manifest,
        backup_path=backup,
    )
    await alignment.run_operation(
        command="apply",
        database_url=database_url,
        schema="awid",
        manifest=manifest,
        backup_path=backup,
        backup_sha256=backed_up["backup_sha256"],
    )
    await connection.execute(
        """
        UPDATE awid.dns_namespaces SET scope_id = NULL
        WHERE domain = 'tenant-001.aweb.ai'
        """
    )
    # scope_id was non-NULL in the full before image even though this is not a
    # column the alignment itself ever writes.
    with pytest.raises(alignment.AlignmentError, match="non-controller columns changed"):
        await alignment.run_operation(
            command="restore",
            database_url=database_url,
            schema="awid",
            manifest=manifest,
            backup_path=backup,
            backup_sha256=backed_up["backup_sha256"],
        )
    controllers = await connection.fetchval(
        """
        SELECT count(*) FROM awid.dns_namespaces
        WHERE domain LIKE '%.aweb.ai' AND controller_did = $1
        """,
        PARENT_DID,
    )
    assert controllers == 2
