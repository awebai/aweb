import pytest
from pgdbm.testing import AsyncTestDatabase

from awid_service.testing_templates import _migration_digest, migrated_test_database


def test_template_digest_tracks_migration_names_and_content(tmp_path):
    first = tmp_path / "001_first.sql"
    first.write_text("SELECT 1;\n")
    modules = (("example", tmp_path),)
    original = _migration_digest(modules)

    first.write_text("SELECT 2;\n")
    edited = _migration_digest(modules)
    assert edited != original

    first.rename(tmp_path / "001_renamed.sql")
    renamed = _migration_digest(modules)
    assert renamed not in {original, edited}

    second = tmp_path / "002_second.sql"
    second.write_text("SELECT 1;\n")
    assert _migration_digest(modules) not in {original, edited, renamed}
    second.unlink()
    assert _migration_digest(modules) == renamed


@pytest.mark.asyncio
async def test_template_name_over_63_bytes_is_refused_before_database_creation(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("TEST_DB_HOST", "unused.invalid")
    monkeypatch.setenv("TEST_DB_PORT", "15432")
    monkeypatch.setenv("PYTEST_XDIST_WORKER", "serial")
    (tmp_path / "001_first.sql").write_text("SELECT 1;\n")

    async def unexpected_create(self, *, suffix):
        pytest.fail("an oversized template name reached database creation")

    async def unexpected_migrate(pool):
        pytest.fail("an oversized template name reached migration")

    monkeypatch.setattr(AsyncTestDatabase, "create_test_database", unexpected_create)
    # With pgdbm's default prefix and eight-hex token, this suffix makes 64 bytes.
    with pytest.raises(
        ValueError, match=r"template name is 64 bytes; PostgreSQL allows 63"
    ):
        async with migrated_test_database(
            "x" * 14, (("example", tmp_path),), unexpected_migrate
        ):
            pytest.fail("an oversized template was returned")


@pytest.mark.asyncio
async def test_database_clones_are_isolated_and_cleaned_up(awid_database_template):
    template = awid_database_template
    scratch_table = (
        "CREATE TABLE public.a2_probe (id bigint GENERATED ALWAYS AS IDENTITY)"
    )
    advance = "INSERT INTO public.a2_probe DEFAULT VALUES RETURNING id"

    class ProbeFailure(Exception):
        pass

    async with template.clone() as sibling:
        assert await sibling.fetchval("SELECT count(*) FROM awid.schema_migrations") > 0
        with pytest.raises(ProbeFailure):
            async with template.clone() as dirty:
                dirty_name = await dirty.fetchval("SELECT current_database()")
                await dirty.execute(scratch_table)
                assert await dirty.fetchval(advance) == 1
                assert await dirty.fetchval(advance) == 2
                assert (
                    await sibling.fetchval("SELECT to_regclass('public.a2_probe')")
                    is None
                )
                raise ProbeFailure

        assert not await sibling.fetchval(
            "SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)", dirty_name
        )

        async with template.clone() as fresh:
            assert await fresh.fetchval("SELECT to_regclass('public.a2_probe')") is None
            await fresh.execute(scratch_table)
            assert await fresh.fetchval(advance) == 1
